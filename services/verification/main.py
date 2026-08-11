"""Main entry point for verification service."""

import logging

import uvicorn
from fastapi import FastAPI
from marty_credentials.native_backend import marty_rs_diagnostic
from verification.application.did_resolver import validate_internal_resolver_configuration
from verification.application.governance import load_governance
from verification.application.rust_verifier import (
    REQUIRED_MARTY_RS_CAPABILITIES,
    validate_marty_rs_capabilities,
)
from verification.infrastructure.api.routes import verification_router
from verification.infrastructure.persistence.database import close_database

# Setup logging without relying on an optional framework namespace.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="Verification Service",
    description="OID4VP credential verification service",
    version="1.0.0",
)

# Include routes
app.include_router(verification_router)


@app.on_event("startup")
async def startup():
    """Initialize service on startup."""
    validate_marty_rs_capabilities()
    load_governance()
    validate_internal_resolver_configuration()
    logger.info("Starting verification-service...")
    # Database tables will be created by migrations


@app.on_event("shutdown")
async def shutdown():
    """Release service-owned database connections."""
    await close_database()


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "verification",
        "native_backend": marty_rs_diagnostic(REQUIRED_MARTY_RS_CAPABILITIES),
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8006, reload=False)
