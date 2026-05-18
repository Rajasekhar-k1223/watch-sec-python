# [v2.3.0] Monitorix Enterprise Hardened Dockerfile
# Stage 1: Build Environment
FROM python:3.11-slim as builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime Environment (Zero-Trust)
FROM python:3.11-slim as runtime

WORKDIR /app

# Install runtime-only dependencies (e.g. Tesseract for OCR)
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Create an unprivileged system user
RUN groupadd -g 1001 monitorix && \
    useradd -u 1001 -g monitorix -s /bin/sh monitorix && \
    chown -R monitorix:monitorix /app

# Copy application code with correct ownership
COPY --chown=monitorix:monitorix . .

# Ensure start script is executable
RUN chmod +x start.sh

# Labeling for SBOM and Artifact Trust
LABEL org.opencontainers.image.source="https://github.com/monitorix/watch-sec-python"
LABEL org.opencontainers.image.description="Monitorix Enterprise Backend - Hardened Runtime"
LABEL com.monitorix.security.signed="true"

# Switch to non-root user
USER monitorix

EXPOSE 8000
CMD ["./start.sh"]
