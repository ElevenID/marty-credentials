# Dockerfile for Verification Service
# 
# Multi-stage build: Rust compilation -> Python service
# Build context: workspace root (parent of marty-credentials)

# Stage 1: Build Rust bindings (reuse from issuance service)
FROM rust:1.75-slim AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages maturin

WORKDIR /build

# Copy vendored Rust crates required by marty-core workspace patches.
# The build target is marty-core/vendor because marty-core/Cargo.toml patches
# crates.io core2 to vendor/core2-0.4.0, but the checked-in vendor copy lives
# in marty-credentials/vendor for shared service builds.
COPY marty-credentials/vendor/core2-0.4.0 ./marty-core/vendor/core2-0.4.0/

# Copy marty-core workspace
COPY marty-core/Cargo.toml ./marty-core/
COPY marty-core/Cargo.lock* ./marty-core/
COPY marty-core/marty-bindings ./marty-core/marty-bindings/
COPY marty-core/marty-crypto ./marty-core/marty-crypto/
COPY marty-core/marty-types ./marty-core/marty-types/
COPY marty-core/marty-verification ./marty-core/marty-verification/
COPY marty-core/marty-secure-storage ./marty-core/marty-secure-storage/
COPY marty-core/marty-biometrics ./marty-core/marty-biometrics/
COPY marty-core/marty-iso18013 ./marty-core/marty-iso18013/
COPY marty-core/marty-zkp ./marty-core/marty-zkp/
COPY marty-core/marty-oid4vci ./marty-core/marty-oid4vci/
COPY marty-core/marty-didcomm ./marty-core/marty-didcomm/

# Build marty-bindings Python wheel
WORKDIR /build/marty-core/marty-bindings
RUN maturin build --release --out /wheels

# Stage 2: Python base
FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install Rust-built Python wheel
COPY --from=rust-builder /wheels/*.whl /tmp/
RUN if [ -n "$(ls -A /tmp/*.whl 2>/dev/null)" ]; then \
        pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl; \
    else \
        echo "WARNING: No Rust bindings available"; \
    fi

# Install MMF
COPY marty-microservices-framework /tmp/mmf
RUN pip install --no-cache-dir /tmp/mmf && rm -rf /tmp/mmf

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi==0.109.0 \
    uvicorn[standard]==0.27.0 \
    sqlalchemy[asyncio]==2.0.25 \
    asyncpg==0.29.0 \
    pydantic==2.5.3 \
    pydantic-settings==2.1.0 \
    httpx==0.26.0 \
    redis==5.0.1 \
    python-multipart==0.0.6

# Stage 3: Final service
FROM base AS final

# Copy verification service code
COPY marty-credentials/services/verification /app/services/verification

ENV PYTHONPATH=/app:/app/services

WORKDIR /app/services/verification

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8006/health || exit 1

EXPOSE 8006

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8006"]
