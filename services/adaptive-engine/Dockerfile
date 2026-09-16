# CloudDecept Adaptive Engine - ARM64 compatible
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip check && \
    python -c "import uvicorn; print('uvicorn version:', uvicorn.__version__)"

# Runtime stage
FROM python:3.11-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Verify uvicorn is available in runtime
RUN python -c "import uvicorn; print('uvicorn version:', uvicorn.__version__)"
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

COPY src/ ./src/

RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

EXPOSE 8002

CMD ["python", "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8002"]