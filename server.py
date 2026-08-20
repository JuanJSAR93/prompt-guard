import os
import gc
import time
import asyncio
import threading
from typing import List, Optional
from contextlib import asynccontextmanager

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ==========================================
# Configuración y Variables de Entorno
# ==========================================
MODEL_ID = os.getenv("MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M")
HF_TOKEN = os.getenv("HF_TOKEN", None)
DEFAULT_THRESHOLD = float(os.getenv("THRESHOLD", "0.5"))
DEFAULT_CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "512"))
DEFAULT_STRIDE = int(os.getenv("STRIDE", "64"))
ENABLE_QUANTIZATION = os.getenv("ENABLE_QUANTIZATION", "false").lower() in ("true", "1", "yes")

# Auto-descarga por inactividad (300 segundos = 5 minutos por defecto)
# 0 o negativo desactiva la descarga automática
IDLE_TIMEOUT_SECONDS = int(os.getenv("IDLE_TIMEOUT_SECONDS", "300"))

# Configurar hilos de CPU para PyTorch
CPU_CORES = os.cpu_count() or 4
TORCH_THREADS = int(os.getenv("TORCH_THREADS", str(min(CPU_CORES, 4))))
torch.set_num_threads(TORCH_THREADS)

# Selección de dispositivo
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Variables globales para modelo, tokenizador y control de inactividad
tokenizer = None
model = None
malicious_class_index = 1
last_active_time = time.time()
model_lock = threading.Lock()


def load_model_and_tokenizer():
    global tokenizer, model, malicious_class_index, last_active_time
    with model_lock:
        if model is not None:
            return

        print(f"[*] Cargando tokenizador para: {MODEL_ID}...")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, token=HF_TOKEN)

        print(f"[*] Cargando modelo en dispositivo: {DEVICE}...")
        loaded_model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_ID,
            token=HF_TOKEN
        )

        # Identificar el índice de la clase MALICIOUS en id2label
        id2label = getattr(loaded_model.config, "id2label", {0: "BENIGN", 1: "MALICIOUS"})
        for idx, label_name in id2label.items():
            if "MALICIOUS" in str(label_name).upper() or "INJECTION" in str(label_name).upper():
                malicious_class_index = int(idx)
                break

        # Optimización: Cuantización Dinámica INT8 en CPU si está habilitada
        if DEVICE.type == "cpu" and ENABLE_QUANTIZATION:
            print("[*] Aplicando Cuantización Dinámica INT8 para CPU (menor uso de RAM)...")
            loaded_model = torch.ao.quantization.quantize_dynamic(
                loaded_model,
                {torch.nn.Linear},
                dtype=torch.qint8
            )

        loaded_model.to(DEVICE)
        loaded_model.eval()
        model = loaded_model
        last_active_time = time.time()
        print(f"[✓] Modelo listo en RAM. Índice clase maliciosa: {malicious_class_index} ({id2label.get(malicious_class_index, 'MALICIOUS')})")


def unload_model():
    global model, tokenizer
    with model_lock:
        if model is not None:
            print(f"[*] Inactividad detectada (> {IDLE_TIMEOUT_SECONDS}s). Descargando modelo de la memoria RAM...")
            del model
            del tokenizer
            model = None
            tokenizer = None
            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            print("[✓] Modelo descargado. Memoria RAM liberada al sistema operativo.")


def ensure_model_loaded():
    global last_active_time
    if model is None:
        load_model_and_tokenizer()
    last_active_time = time.time()


async def idle_cleanup_worker():
    """Tarea en segundo plano que vigila el tiempo de inactividad"""
    while True:
        await asyncio.sleep(15)
        if model is not None and IDLE_TIMEOUT_SECONDS > 0:
            elapsed = time.time() - last_active_time
            if elapsed >= IDLE_TIMEOUT_SECONDS:
                unload_model()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Carga inicial al arranque para verificar archivos y caché
    load_model_and_tokenizer()
    # Iniciar monitor de inactividad
    cleanup_task = asyncio.create_task(idle_cleanup_worker())
    yield
    cleanup_task.cancel()
    unload_model()


app = FastAPI(
    title="Llama Prompt Guard 2 API",
    description="Microservicio de seguridad para detección de Prompt Injections y Jailbreaks con soporte dinámico de tokens y auto-descarga de RAM por inactividad.",
    version="2.1.0",
    lifespan=lifespan
)


# ==========================================
# Esquemas Pydantic
# ==========================================
class ScanRequest(BaseModel):
    text: str = Field(..., description="Texto o prompt a analizar")
    threshold: Optional[float] = Field(
        default=None,
        description=f"Umbral de decisión para clasificar como MALICIOUS (por defecto {DEFAULT_THRESHOLD})"
    )
    chunk_size: Optional[int] = Field(
        default=None,
        description=f"Tamaño máximo de ventana de tokens por bloque (por defecto {DEFAULT_CHUNK_SIZE})"
    )
    stride: Optional[int] = Field(
        default=None,
        description=f"Solapamiento de tokens entre bloques contiguos (por defecto {DEFAULT_STRIDE})"
    )


class BatchScanRequest(BaseModel):
    texts: List[str] = Field(..., description="Lista de textos o prompts a analizar")
    threshold: Optional[float] = Field(default=None)


class ScanResponse(BaseModel):
    label: str
    score: float
    blocked: bool
    malicious_score: float
    chunks_analyzed: int


class BatchScanResponse(BaseModel):
    results: List[ScanResponse]


# ==========================================
# Lógica de Inferencia con Sliding Window
# ==========================================
def scan_text(
    text: str,
    threshold: Optional[float] = None,
    chunk_size: Optional[int] = None,
    stride: Optional[int] = None
) -> ScanResponse:
    # Asegurar que el modelo esté cargado en RAM (Carga perezosa si estaba descargado)
    ensure_model_loaded()

    eff_threshold = threshold if threshold is not None else DEFAULT_THRESHOLD
    eff_chunk_size = chunk_size if chunk_size is not None else DEFAULT_CHUNK_SIZE
    eff_stride = stride if stride is not None else DEFAULT_STRIDE

    # Manejo de textos vacíos o solo espacios
    cleaned_text = text.strip()
    if not cleaned_text:
        return ScanResponse(
            label="BENIGN",
            score=1.0,
            blocked=False,
            malicious_score=0.0,
            chunks_analyzed=0
        )

    # Tokenización con ventana deslizante (Sliding Window / Stride)
    encoded = tokenizer(
        cleaned_text,
        return_overflowing_tokens=True,
        truncation=True,
        max_length=eff_chunk_size,
        stride=eff_stride,
        padding=True,
        return_tensors="pt"
    )

    input_ids = encoded["input_ids"].to(DEVICE)
    attention_mask = encoded["attention_mask"].to(DEVICE)
    num_chunks = input_ids.size(0)

    # Inferencia optimizada en PyTorch
    with torch.inference_mode():
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        probs = torch.softmax(outputs.logits, dim=-1)

    # Extraer probabilidad de clase MALICIOUS para todos los chunks
    malicious_probs = probs[:, malicious_class_index].cpu().tolist()
    max_malicious_prob = max(malicious_probs)

    # Decisión de bloqueo
    is_blocked = max_malicious_prob >= eff_threshold
    label = "MALICIOUS" if is_blocked else "BENIGN"
    score = max_malicious_prob if is_blocked else (1.0 - max_malicious_prob)

    return ScanResponse(
        label=label,
        score=round(score, 4),
        blocked=is_blocked,
        malicious_score=round(max_malicious_prob, 4),
        chunks_analyzed=num_chunks
    )


# ==========================================
# Endpoints de la API
# ==========================================
@app.get("/health")
def health():
    is_loaded = model is not None
    seconds_idle = int(time.time() - last_active_time) if is_loaded else 0
    seconds_left = max(0, IDLE_TIMEOUT_SECONDS - seconds_idle) if is_loaded and IDLE_TIMEOUT_SECONDS > 0 else None

    return {
        "status": "ok",
        "model": MODEL_ID,
        "device": str(DEVICE),
        "model_loaded_in_ram": is_loaded,
        "idle_timeout_seconds": IDLE_TIMEOUT_SECONDS,
        "seconds_until_unload": seconds_left,
        "quantization": ENABLE_QUANTIZATION,
        "torch_threads": TORCH_THREADS
    }


@app.post("/scan", response_model=ScanResponse)
def scan_endpoint(request: ScanRequest):
    return scan_text(
        text=request.text,
        threshold=request.threshold,
        chunk_size=request.chunk_size,
        stride=request.stride
    )


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch_endpoint(request: BatchScanRequest):
    results = [
        scan_text(t, threshold=request.threshold)
        for t in request.texts
    ]
    return BatchScanResponse(results=results)