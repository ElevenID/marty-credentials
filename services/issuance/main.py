"""Main FastAPI application for issuance service."""

import logging
import os
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from issuance.domain.ports import IIssuanceRepository

# ---------------------------------------------------------------------------
# Request-ID context
# ---------------------------------------------------------------------------

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    """Inject the current request ID into every log record."""
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get("-")
        return True


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assign/propagate X-Request-ID on every request."""
    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            request_id_var.reset(token)
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository
from issuance.infrastructure.api.application_routes import (
    application_router,
    application_template_router,
)
from issuance.infrastructure.api.routes import issuance_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(request_id)s] %(levelname)s %(name)s: %(message)s",
)
for handler in logging.root.handlers:
    handler.addFilter(RequestIdFilter())
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
    app.add_middleware(RequestIdMiddleware)

    # Register routers
    app.include_router(issuance_router)
    app.include_router(application_template_router)
    app.include_router(application_router)
    
    # Override FastAPI dependency injection
    app.dependency_overrides[IIssuanceRepository] = get_repo
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}

    # ------------------------------------------------------------------
    # OID4VCI v1 §12.2.2 — Credential Issuer Metadata
    #
    # Per-org issuer URL: {ISSUER_BASE_URL}/org/{org_id}
    # Well-known URL (v1 insertion rule):
    #   {host}/.well-known/openid-credential-issuer/org/{org_id}
    #
    # We also keep a global fallback at the root well-known path for
    # wallets that probe without an org context.
    # ------------------------------------------------------------------

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}/spruce")
    async def get_org_issuer_metadata_spruce(org_id: str) -> dict:
        """Return per-org OID4VCI issuer metadata compatible with SpruceID mobile-sdk-rs.

        SpruceID's ``oid4vci-rs @ e97b01e`` uses a custom ``ProfilesCredentialConfiguration``
        untagged serde enum whose only SD-JWT variant requires ``format: "spruce-vc+sd-jwt"``.
        Any ``vc+sd-jwt`` entry in the same document causes the entire metadata deserialisation
        to fail, so SpruceID credential offers point to the ``/org/{id}/spruce`` issuer URL and
        this endpoint emits *only* ``spruce-vc+sd-jwt`` (+ ``jwt_vc_json``) entries.

        Walt.id and every other OID4VCI-conformant wallet use the normal ``/org/{id}`` path.
        """
        from issuance.infrastructure.api.routes import ISSUER_BASE_URL

        issuer_url = f"{ISSUER_BASE_URL}/org/{org_id}/spruce"
        credential_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/credential"
        token_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/token"
        authorization_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/authorize"

        _proof_types = {"jwt": {"proof_signing_alg_values_supported": ["ES256", "EdDSA"]}}
        _binding = ["did:key", "jwk"]
        _signing_algs = ["ES256", "EdDSA"]

        repo = get_repo()
        known_types = await repo.get_credential_types_for_org(org_id)

        credential_configurations: dict = {}
        for ctype in known_types:
            # JWT-VC (Walt.id-style CoreProfilesCredentialConfiguration parses this fine)
            credential_configurations[ctype] = {
                "format": "jwt_vc_json",
                "scope": ctype,
                "cryptographic_binding_methods_supported": _binding,
                "credential_signing_alg_values_supported": _signing_algs,
                "proof_types_supported": _proof_types,
                "credential_definition": {"type": ["VerifiableCredential"]},
                "display": [{"name": ctype.replace("_", " ").title(), "locale": "en-US"}],
            }
            # spruce-vc+sd-jwt: matches vc_sd_jwt::CredentialConfiguration in oid4vci-rs @ e97b01e.
            # The `vct` field is REQUIRED (no serde default) and `format` MUST be "spruce-vc+sd-jwt".
            credential_configurations[f"{ctype}#spruce-sd-jwt"] = {
                "format": "spruce-vc+sd-jwt",
                "vct": f"https://marty.example/credentials/{ctype}",
                "scope": ctype,
                "cryptographic_binding_methods_supported": _binding,
                "credential_signing_alg_values_supported": _signing_algs,
                "proof_types_supported": _proof_types,
                "display": [{"name": ctype.replace("_", " ").title(), "locale": "en-US"}],
            }

        if "default" not in credential_configurations:
            credential_configurations["default"] = {
                "format": "jwt_vc_json",
                "scope": "default",
                "cryptographic_binding_methods_supported": _binding,
                "credential_signing_alg_values_supported": _signing_algs,
                "proof_types_supported": _proof_types,
                "credential_definition": {"type": ["VerifiableCredential"]},
                "display": [{"name": "Verifiable Credential", "locale": "en-US"}],
            }

        nonce_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/nonce"

        return {
            "credential_issuer": issuer_url,
            "authorization_endpoint": authorization_endpoint,
            "credential_endpoint": credential_endpoint,
            "token_endpoint": token_endpoint,
            "nonce_endpoint": nonce_endpoint,
            "credential_configurations_supported": credential_configurations,
        }

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}")
    async def get_org_issuer_metadata(org_id: str) -> dict:
        """Return per-org OID4VCI v1 issuer metadata (dynamic, org-scoped).

        ``credential_configurations_supported`` is built from the distinct
        ``credential_type`` values recorded in the local issuance DB for this
        org — no cross-service calls needed.  The keys match exactly what the
        issuance service puts in ``credential_configuration_ids`` of every
        offer it creates, satisfying OID4VCI v1 §11.2.3 without enumerating
        every credential type statically.
        """
        from issuance.infrastructure.api.routes import ISSUER_BASE_URL, org_issuer_url

        issuer_url = org_issuer_url(org_id)
        credential_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/credential"
        token_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/token"
        authorization_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/authorize"

        _proof_types = {"jwt": {"proof_signing_alg_values_supported": ["ES256", "EdDSA"]}}
        _binding = ["did:key", "jwk"]
        _signing_algs = ["ES256", "EdDSA"]

        # Pull distinct credential types from the issuance DB — self-contained,
        # no external auth required, and grows automatically with new templates.
        repo = get_repo()
        known_types = await repo.get_credential_types_for_org(org_id)

        credential_configurations: dict = {}
        for ctype in known_types:
            # JWT-VC format entry (primary — used by most wallets by default)
            credential_configurations[ctype] = {
                "format": "jwt_vc_json",
                "scope": ctype,
                "cryptographic_binding_methods_supported": _binding,
                "credential_signing_alg_values_supported": _signing_algs,
                "proof_types_supported": _proof_types,
                "credential_definition": {"type": ["VerifiableCredential"]},
                # OID4VCI §11.2.3 — display is at the top level of the config object
                "display": [{"name": ctype.replace("_", " ").title(), "locale": "en-US"}],
            }
            # SD-JWT: use standard "vc+sd-jwt" (RFC 9596 §3.1) for all wallets.
            # Both Walt.id and the Marty native wallet handle this format.
            # NOTE: do NOT emit a "spruce-vc+sd-jwt" entry — Walt.id's
            # CredentialFormatSerializer rejects any unknown format string in
            # the entire metadata document, causing a 400 on all requests.
            credential_configurations[f"{ctype}#sd-jwt"] = {
                "format": "vc+sd-jwt",
                "vct": f"https://marty.example/credentials/{ctype}",
                "scope": ctype,
                "cryptographic_binding_methods_supported": _binding,
                "credential_signing_alg_values_supported": _signing_algs,
                "proof_types_supported": _proof_types,
                "display": [{"name": ctype.replace("_", " ").title(), "locale": "en-US"}],
            }

        # Always include a generic "default" entry so that offer fallbacks work too.
        if "default" not in credential_configurations:
            credential_configurations["default"] = {
                "format": "jwt_vc_json",
                "scope": "default",
                "cryptographic_binding_methods_supported": _binding,
                "credential_signing_alg_values_supported": _signing_algs,
                "proof_types_supported": _proof_types,
                "credential_definition": {"type": ["VerifiableCredential"]},
                "display": [{"name": "Verifiable Credential", "locale": "en-US"}],
            }

        nonce_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/nonce"

        return {
            "credential_issuer": issuer_url,
            "authorization_endpoint": authorization_endpoint,
            "credential_endpoint": credential_endpoint,
            "token_endpoint": token_endpoint,
            "nonce_endpoint": nonce_endpoint,
            "credential_configurations_supported": credential_configurations,
        }

    @app.get("/.well-known/openid-credential-issuer")
    async def get_issuer_metadata_root() -> dict:
        """Fallback global issuer metadata (no org context).

        Returns minimal metadata pointing at the shared endpoints.  Wallets
        initiating a flow from a per-org credential offer will use the per-org
        endpoint above instead.
        """
        from issuance.infrastructure.api.routes import ISSUER_BASE_URL
        _proof_types = {"jwt": {"proof_signing_alg_values_supported": ["ES256", "EdDSA"]}}
        return {
            "credential_issuer": ISSUER_BASE_URL,
            "authorization_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/authorize",
            "credential_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/credential",
            "token_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/token",
            "nonce_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/nonce",
            "credential_configurations_supported": {
                "default": {
                    "format": "jwt_vc_json",
                    "scope": "default",
                    "cryptographic_binding_methods_supported": ["did:key", "jwk"],
                    "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
                    "proof_types_supported": _proof_types,
                    "credential_definition": {"type": ["VerifiableCredential"]},
                    "display": [{"name": "Verifiable Credential", "locale": "en-US"}],
                }
            },
        }

    # ------------------------------------------------------------------
    # OAuth 2.0 Authorization Server Metadata (RFC 8414)
    #
    # OID4VCI v1 §12.2.4: when authorization_servers is omitted in issuer
    # metadata the Credential Issuer itself acts as the AS and wallets
    # discover its metadata via the oauth-authorization-server well-known.
    # ------------------------------------------------------------------

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}")
    async def get_org_as_metadata(org_id: str) -> dict:
        """Per-org OAuth 2.0 Authorization Server metadata (RFC 8414)."""
        from issuance.infrastructure.api.routes import ISSUER_BASE_URL, org_issuer_url
        issuer_url = org_issuer_url(org_id)
        return {
            "issuer": issuer_url,
            "authorization_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/authorize",
            "token_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/token",
            "token_endpoint_auth_methods_supported": ["none"],
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "authorization_code",
            ],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "pre-authorized_grant_anonymous_access_supported": True,
        }

    @app.get("/.well-known/oauth-authorization-server")
    async def get_as_metadata() -> dict:
        """Global OAuth 2.0 Authorization Server metadata (RFC 8414)."""
        from issuance.infrastructure.api.routes import ISSUER_BASE_URL
        return {
            "issuer": ISSUER_BASE_URL,
            "authorization_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/authorize",
            "token_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/token",
            "token_endpoint_auth_methods_supported": ["none"],
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "authorization_code",
            ],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "pre-authorized_grant_anonymous_access_supported": True,
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
