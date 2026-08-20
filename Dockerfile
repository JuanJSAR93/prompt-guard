FROM python:3.12-slim

# Instalar curl para healthchecks de Docker/Coolify y certificados
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar PyTorch CPU-only (reduce la imagen en más de 2.5 GB) y dependencias
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir \
    transformers \
    fastapi \
    "uvicorn[standard]" \
    pydantic

COPY server.py .

# Variables de entorno por defecto
ENV PORT=8000
ENV HOST=0.0.0.0
ENV TORCH_THREADS=4

EXPOSE 8000

# Healthcheck nativo
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["sh", "-c", "uvicorn server:app --host ${HOST} --port ${PORT} --workers 1"]