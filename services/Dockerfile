# Dockerfile for Issuance Service with Rust bindings
# 
# Multi-stage build: Rust compilation -> Python services
# Build context: marty-credentials directory
# External dependencies: marty-core, marty-microservices-framework (via build args)

# Stage 1: Build Rust bindings for Python (marty-bindings)
# Using nightly because edition2024 is required by aligned-0.4.3 dependency
FROM rustlang/rust:nightly-slim AS rust-builder

ARG MARTY_CORE_PATH=../marty-core
ARG MMF_PATH=../marty-microservices-framework

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libzstd-dev \
    python3-dev \
    python3-pip \
    build-essential \
    g++ \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Install maturin for building Python packages from Rust
RUN pip3 install --break-system-packages maturin[patchelf]

WORKDIR /build

# Copy vendored Rust crates required by marty-core workspace patches.
# The build target is marty-core/vendor because marty-core/Cargo.toml patches
# crates.io core2 to vendor/core2-0.4.0, but the checked-in vendor copy lives
# in marty-credentials/vendor for shared service builds.
COPY marty-credentials/vendor/core2-0.4.0 ./marty-core/vendor/core2-0.4.0/

# Copy marty-core workspace for building Python bindings
# Build context is workspace root, so paths are relative to /Volumes/Heart of Gold/Github/work/
COPY marty-core/Cargo.toml ./marty-core/
# Copy Cargo.lock if it exists (optional for workspace builds)
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

# Copy longfellow-zk C++ library (required by marty-zkp build.rs)
COPY longfellow-zk/lib ./longfellow-zk/lib

# Build marty-bindings Python wheel
WORKDIR /build/marty-core/marty-bindings
RUN CXX=clang++ CC=clang maturin build --release --out /wheels

# Clean up build artifacts to save space
WORKDIR /build
RUN rm -rf marty-core

# Stage 2: Python base with dependencies  
FROM python:3.12-slim AS base

ARG MMF_PATH=../marty-microservices-framework

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install Rust-built Python wheel (marty-rs/marty-bindings)
COPY --from=rust-builder /wheels/*.whl /tmp/ 
RUN if [ -n "$(ls -A /tmp/*.whl 2>/dev/null)" ]; then \
        pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl; \
    else \
        echo "WARNING: No Rust bindings available - service will fail at runtime"; \
    fi

# Install marty-microservices-framework from local path
COPY marty-microservices-framework /tmp/mmf
RUN pip install --no-cache-dir /tmp/mmf && rm -rf /tmp/mmf

# Install shared package dependencies used by the issuance runtime.
COPY marty-ui/packages/marty_common /app/packages/marty_common
RUN pip install --no-cache-dir -e /app/packages/marty_common

# Install Python dependencies for issuance service
RUN pip install --no-cache-dir \
    fastapi==0.109.0 \
    uvicorn[standard]==0.27.0 \
    sqlalchemy[asyncio]==2.0.25 \
    asyncpg==0.29.0 \
    pydantic==2.5.3 \
    pydantic-settings==2.1.0 \
    httpx==0.26.0 \
    redis==5.0.1 \
    python-multipart==0.0.6 \
    grpcio>=1.62.0 \
    grpcio-health-checking>=1.62.0 \
    grpcio-reflection>=1.62.0 \
    googleapis-common-protos>=1.63.0 \
    protobuf>=4.25.0 \
    cryptography>=41.0.0 \
    cbor2>=5.6.0

# Stage 3: Final service image
FROM base AS final

# Copy issuance service code
COPY marty-credentials/services/issuance /app/services/issuance

# Copy shared proto stubs
COPY marty-credentials/packages /app/packages
COPY marty-ui/packages/marty_common /app/packages/marty_common

# Copy shared runtime helpers
COPY marty-ui/scripts/load-secrets-env.sh /app/load-secrets-env.sh

# Copy status_list (required by issuance for SymmetricEncryption)
COPY marty-credentials/python/status_list /app/status_list

# Set Python path
ENV PYTHONPATH=/app:/app/services:/app/packages

# Working directory
WORKDIR /app/services/issuance

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8005/health || exit 1

# Expose port
EXPOSE 8005

# Run the service
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005"]
