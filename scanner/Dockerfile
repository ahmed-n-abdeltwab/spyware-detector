# ---- Builder Stage ----
FROM python:3.9-slim AS builder

# Set build arguments with defaults
ARG MODEL_URL=https://github.com/ahmed-n-abdeltwab/spyware-detector-training/releases/latest/download/model_release.tar.gz

# Core environment configuration
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MODEL_URL=${MODEL_URL}

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libmagic1 \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- Runtime Stage ----
FROM python:3.9-slim

# Runtime environment (compose will override these)
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    FLASK_PORT=5000 \
    MODEL_URL=unset \
    MODEL_REFRESH_INTERVAL=3600 \
    LOG_LEVEL=INFO \
    PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libmagic1 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m appuser && \
    mkdir -p /app/models /app/logs && \
    chown appuser:appuser /app /app/models /app/logs

# Ensure log directory is writable
RUN mkdir -p /app/logs && \
    chown appuser:appuser /app/logs

WORKDIR /app
USER appuser

# Copy virtual environment and application
COPY --from=builder --chown=appuser /opt/venv /opt/venv
COPY --chown=appuser:appuser . .

# Health check and verification
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import sys, os; assert os.path.exists('server.py'), 'Server file missing'" || exit 1

EXPOSE ${FLASK_PORT}
CMD ["python", "server.py"]
