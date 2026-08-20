import os
import time
import asyncio
import threading
import multiprocessing as mp
from typing import List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

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


# ==========================================
# Proceso Aislado de Inferencia (Worker)
# ==========================================
def inference_worker_main(conn, model_id, hf_token, torch_threads, enable_quantization):
    """
    Proceso hijo dedicado a la inferencia.
    Al matar este proceso, el kernel de Linux libera el 100.0% de la RAM.
    """
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    torch.set_num_threads(torch_threads)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    try:
        print(f"[*] [Worker PID {os.getpid()}] Cargando tokenizador para: {model_id}...")
        tokenizer = AutoTokenizer.from_pretrained(model_id, token=hf_token)

        print(f"[*] [Worker PID {os.getpid()}] Cargando modelo en dispositivo: {device}...")
        model = AutoModelForSequenceClassification.from_pretrained(model_id, token=hf_token)

        # Identificar clase maliciosa
        id2label = getattr(model.config, "id2label", {0: "BENIGN", 1: "MALICIOUS"})
        malicious_class_index = 1
        for idx, label_name in id2label.items():
            if "MALICIOUS" in str(label_name).upper() or "INJECTION" in str(label_name).upper():
                malicious_class_index = int(idx)
                break

        if device.type == "cpu" and enable_quantization:
            print(f"[*] [Worker PID {os.getpid()}] Aplicando cuantización dinámica INT8...")
            model = torch.ao.quantization.quantize_dynamic(model, {torch.nn.Linear}, dtype=torch.qint8)

        model.to(device)
        model.eval()
        print(f"[✓] [Worker PID {os.getpid()}] Modelo listo en RAM. Clase maliciosa: {malicious_class_index}")
        conn.send(("READY", {"status": "ok", "malicious_index": malicious_class_index, "device": str(device)}))
    except Exception as e:
        print(f"[!] [Worker PID {os.getpid()}] Error al cargar modelo: {e}")
        conn.send(("ERROR", str(e)))
        return

    # Bucle de escucha de peticiones
    while True:
        try:
            msg = conn.recv()
        except EOFError:
            break

        cmd = msg[0]
        if cmd == "SCAN":
            _, text, threshold, chunk_size, stride = msg
            try:
                cleaned_text = text.strip()
                if not cleaned_text:
                    conn.send(("RESULT", {
                        "label": "BENIGN",
                        "score": 1.0,
                        "blocked": False,
                        "malicious_score": 0.0,
                        "chunks_analyzed": 0
                    }))
                    continue

                encoded = tokenizer(
                    cleaned_text,
                    return_overflowing_tokens=True,
                    truncation=True,
                    max_length=chunk_size,
                    stride=stride,
                    padding=True,
                    return_tensors="pt"
                )

                input_ids = encoded["input_ids"].to(device)
                attention_mask = encoded["attention_mask"].to(device)
                num_chunks = input_ids.size(0)

                with torch.inference_mode():
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                    probs = torch.softmax(outputs.logits, dim=-1)

                malicious_probs = probs[:, malicious_class_index].cpu().tolist()
                max_malicious_prob = max(malicious_probs)

                is_blocked = max_malicious_prob >= threshold
                label = "MALICIOUS" if is_blocked else "BENIGN"
                score = max_malicious_prob if is_blocked else (1.0 - max_malicious_prob)

                conn.send(("RESULT", {
                    "label": label,
                    "score": round(score, 4),
                    "blocked": is_blocked,
                    "malicious_score": round(max_malicious_prob, 4),
                    "chunks_analyzed": num_chunks
                }))
            except Exception as ex:
                conn.send(("ERROR", str(ex)))

        elif cmd == "EXIT":
            break


# ==========================================
# Gestor de Procesos del Modelo (ModelManager)
# ==========================================
class ModelManager:
    def __init__(self):
        self.process: Optional[mp.Process] = None
        self.conn = None
        self.lock = threading.Lock()
        self.last_active_time = time.time()
        self.device_info = "cpu"

    def is_running(self) -> bool:
        return self.process is not None and self.process.is_alive()

    def start_worker(self):
        with self.lock:
            if self.is_running():
                return

            print("[*] Iniciando nuevo proceso worker para el modelo...")
            parent_conn, child_conn = mp.Pipe()
            p = mp.Process(
                target=inference_worker_main,
                args=(child_conn, MODEL_ID, HF_TOKEN, TORCH_THREADS, ENABLE_QUANTIZATION),
                daemon=True
            )
            p.start()
            self.process = p
            self.conn = parent_conn

            # Esperar confirmación de READY
            if self.conn.poll(timeout=120):
                status, data = self.conn.recv()
                if status == "READY":
                    self.device_info = data.get("device", "cpu")
                    self.last_active_time = time.time()
                    print(f"[✓] Proceso worker iniciado exitosamente (PID {self.process.pid}).")
                else:
                    self.terminate_worker()
                    raise RuntimeError(f"Error iniciando worker: {data}")
            else:
                self.terminate_worker()
                raise TimeoutError("Tiempo de espera agotado cargando el modelo en el worker.")

    def terminate_worker(self):
        with self.lock:
            if self.process is not None:
                pid = self.process.pid
                print(f"[*] Inactividad detectada (> {IDLE_TIMEOUT_SECONDS}s). Terminando proceso worker (PID {pid})...")
                try:
                    if self.conn:
                        self.conn.send(("EXIT",))
                except Exception:
                    pass

                self.process.join(timeout=2)
                if self.process.is_alive():
                    self.process.terminate()
                    self.process.join(timeout=1)

                self.process = None
                self.conn = None
                print(f"[✓] Worker terminado. El kernel de Linux liberó el 100% de la memoria RAM.")

    def scan(self, text: str, threshold: float, chunk_size: int, stride: int) -> dict:
        if not self.is_running():
            self.start_worker()

        with self.lock:
            self.last_active_time = time.time()
            self.conn.send(("SCAN", text, threshold, chunk_size, stride))
            status, data = self.conn.recv()
            if status == "RESULT":
                return data
            else:
                raise RuntimeError(f"Error en inferencia worker: {data}")


model_mgr = ModelManager()


async def idle_cleanup_worker():
    """Tarea en segundo plano que vigila el tiempo de inactividad"""
    while True:
        await asyncio.sleep(15)
        if model_mgr.is_running() and IDLE_TIMEOUT_SECONDS > 0:
            elapsed = time.time() - model_mgr.last_active_time
            if elapsed >= IDLE_TIMEOUT_SECONDS:
                model_mgr.terminate_worker()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Carga inicial al arranque para verificar modelo y calentar caché
    try:
        model_mgr.start_worker()
    except Exception as e:
        print(f"[!] Advertencia al inicializar modelo en arranque: {e}")

    cleanup_task = asyncio.create_task(idle_cleanup_worker())
    yield
    cleanup_task.cancel()
    model_mgr.terminate_worker()


app = FastAPI(
    title="Llama Prompt Guard 2 API",
    description="Microservicio de seguridad para detección de Prompt Injections y Jailbreaks con aislamiento por subproceso (100% liberación de RAM por inactividad).",
    version="2.2.0",
    lifespan=lifespan
)


# ==========================================
# Esquemas Pydantic
# ==========================================
class ScanRequest(BaseModel):
    text: str = Field(..., description="Texto o prompt a analizar")
    threshold: Optional[float] = Field(default=None)
    chunk_size: Optional[int] = Field(default=None)
    stride: Optional[int] = Field(default=None)


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
# Endpoints de la API
# ==========================================
@app.get("/health")
def health():
    is_loaded = model_mgr.is_running()
    seconds_idle = int(time.time() - model_mgr.last_active_time) if is_loaded else 0
    seconds_left = max(0, IDLE_TIMEOUT_SECONDS - seconds_idle) if is_loaded and IDLE_TIMEOUT_SECONDS > 0 else None

    return {
        "status": "ok",
        "model": MODEL_ID,
        "device": model_mgr.device_info,
        "model_loaded_in_ram": is_loaded,
        "idle_timeout_seconds": IDLE_TIMEOUT_SECONDS,
        "seconds_until_unload": seconds_left,
        "quantization": ENABLE_QUANTIZATION,
        "torch_threads": TORCH_THREADS
    }


@app.post("/scan", response_model=ScanResponse)
def scan_endpoint(request: ScanRequest):
    eff_threshold = request.threshold if request.threshold is not None else DEFAULT_THRESHOLD
    eff_chunk_size = request.chunk_size if request.chunk_size is not None else DEFAULT_CHUNK_SIZE
    eff_stride = request.stride if request.stride is not None else DEFAULT_STRIDE

    res = model_mgr.scan(
        text=request.text,
        threshold=eff_threshold,
        chunk_size=eff_chunk_size,
        stride=eff_stride
    )
    return ScanResponse(**res)


@app.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch_endpoint(request: BatchScanRequest):
    eff_threshold = request.threshold if request.threshold is not None else DEFAULT_THRESHOLD
    results = [
        ScanResponse(**model_mgr.scan(
            text=t,
            threshold=eff_threshold,
            chunk_size=DEFAULT_CHUNK_SIZE,
            stride=DEFAULT_STRIDE
        ))
        for t in request.texts
    ]
    return BatchScanResponse(results=results)