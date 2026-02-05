"""Main FastAPI application for issuance service."""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository
from issuance.infrastructure.api.application_routes import (
    application_router,
    application_template_router,
)
from issuance.infrastructure.api.routes import issuance_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "issuance-service"
SERVICE_PORT = int(os.environ.get("ISSUANCE_SERVICE_PORT", "8005"))

# Global repository instance
_repo: IIssuanceRepository | None = None


def get_config() -> dict[str, Any]:
    """Get database configuration from environment."""
    database_url = os.environ.get("DATABASE_URL", "postgresql://marty:marty_dev@postgres:5432/marty_credentials")
    if not database_url.startswith("postgresql+asyncpg://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return {"database_url": database_url}


def get_repo() -> IIssuanceRepository:
    """Dependency injection for repository."""
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle management."""
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    
    # Initialize PostgreSQL adapter
    config = get_config()
    engine = create_async_engine(
        config["database_url"],
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        echo=False
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    _repo = PostgresIssuanceRepository(session_factory)
    logger.info("PostgreSQL adapter initialized for issuance service")
    
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await engine.dispose()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Issuance Service",
        description="OID4VCI credential issuance service",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Register routers
    app.include_router(issuance_router)
    app.include_router(application_template_router)
    app.include_router(application_router)
    
    # Override FastAPI dependency injection
    app.dependency_overrides[IIssuanceRepository] = get_repo
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}
    
    @app.get("/.well-known/openid-credential-issuer")
    async def get_issuer_metadata_root() -> dict:
        """Return OID4VCI issuer metadata (root endpoint for compliance)."""
        from infrastructure.api.routes import ISSUER_BASE_URL
        return {
            "credential_issuer": ISSUER_BASE_URL,
            "credential_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/credential",
            "token_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/token",
            "credential_configurations_supported": {
                "default": {
                    "format": "jwt_vc_json",
                    "cryptographic_binding_methods_supported": ["did"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported": ["ES256"]
                        }
                    },
                    "display": [
                        {
                            "name": "Verifiable Credential",
                            "locale": "en-US"
                        }
                    ]
                }
            }
        }
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
