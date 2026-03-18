"""Main FastAPI application for issuance service."""

import logging
import os
import re
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


def _friendly_ctype_name(ctype: str) -> str:
    """Convert a credential type identifier to a human-readable display name.

    Handles:
    - camelCase / PascalCase: "MemberCredential"  → "Member Credential"
    - snake_case:             "open_badge"         → "Open Badge"
    - dotted ISO types:       "org.iso.18013.5.1.mDL" → returned as-is
    """
    if "." in ctype:
        return ctype  # ISO dotted type — leave as-is

    # snake_case → words
    name = ctype.replace("_", " ")
    # Insert a space before each uppercase letter that follows a lowercase letter
    # (PascalCase / camelCase splitting)
    name = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", name)
    # Capitalise each word
    return name.title()

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


ISSUANCE_GRPC_PORT = int(os.environ.get("ISSUANCE_GRPC_PORT", "9005"))
ISSUANCE_GRPC_ENABLED = os.environ.get("ISSUANCE_GRPC_ENABLED", "true").lower() in ("1", "true", "yes")


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

    # Start gRPC server
    grpc_server = None
    if ISSUANCE_GRPC_ENABLED:
        import grpc.aio as grpc_aio
        from issuance.infrastructure.adapters.grpc_adapter import IssuanceServiceGrpc
        from marty_proto.v1 import issuance_service_pb2_grpc

        grpc_server = grpc_aio.server()
        servicer = IssuanceServiceGrpc(get_repo_fn=get_repo)
        issuance_service_pb2_grpc.add_IssuanceServiceServicer_to_server(servicer, grpc_server)
        grpc_server.add_insecure_port(f"[::]:{ISSUANCE_GRPC_PORT}")
        await grpc_server.start()
        logger.info(f"gRPC server started on port {ISSUANCE_GRPC_PORT}")
    
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    if grpc_server:
        await grpc_server.stop(grace=5)
        logger.info("gRPC server stopped")
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
            if ctype.startswith("org.iso.18013"):
                # ISO 18013-5 mDoc — SpruceKit's ProfilesCredentialConfiguration supports
                # mso_mdoc natively. Only emit the mso_mdoc entry; jwt_vc_json and
                # spruce-vc+sd-jwt entries for other types cause the SpruceID SDK's
                # untagged-enum deserialisation to fail for the whole metadata document.
                credential_configurations[f"{ctype}#mdoc"] = {
                    "format": "mso_mdoc",
                    "doctype": ctype,
                    "scope": ctype,
                    "cryptographic_binding_methods_supported": _binding,
                    "credential_signing_alg_values_supported": _signing_algs,
                    "proof_types_supported": _proof_types,
                    "display": [{"name": _friendly_ctype_name(ctype), "locale": "en-US"}],
                }
            else:
                # Non-ISO SD-JWT credential — emit as spruce-vc+sd-jwt so
                # SpruceKit's ProfilesCredentialConfiguration enum can parse it.
                # Only spruce-vc+sd-jwt (and mso_mdoc above) are valid variants in
                # that enum; vc+sd-jwt or jwt_vc_json would cause the whole document
                # to fail to deserialise in the SpruceID Rust SDK.
                credential_configurations[f"{ctype}#spruce-sd-jwt"] = {
                    "format": "spruce-vc+sd-jwt",
                    "vct": f"{ISSUER_BASE_URL}/credentials/{ctype}",
                    "scope": ctype,
                    "cryptographic_binding_methods_supported": _binding,
                    "credential_signing_alg_values_supported": _signing_algs,
                    "proof_types_supported": _proof_types,
                    "display": [{"name": _friendly_ctype_name(ctype), "locale": "en-US"}],
                }

        nonce_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/nonce"
        deferred_credential_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/deferred-credential"
        notification_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/notification"

        return {
            "credential_issuer": issuer_url,
            "authorization_endpoint": authorization_endpoint,
            "credential_endpoint": credential_endpoint,
            "token_endpoint": token_endpoint,
            "nonce_endpoint": nonce_endpoint,
            "deferred_credential_endpoint": deferred_credential_endpoint,
            "notification_endpoint": notification_endpoint,
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
                "display": [{"name": _friendly_ctype_name(ctype), "locale": "en-US"}],
            }
            if ctype.startswith("org.iso.18013"):
                # ISO 18013-5 mDoc — emit mso_mdoc format entry.
                # All OID4VCI-conformant wallets (including SpruceKit) use this entry.
                credential_configurations[f"{ctype}#mdoc"] = {
                    "format": "mso_mdoc",
                    "doctype": ctype,
                    "scope": ctype,
                    "cryptographic_binding_methods_supported": _binding,
                    "credential_signing_alg_values_supported": _signing_algs,
                    "proof_types_supported": _proof_types,
                    "display": [{"name": _friendly_ctype_name(ctype), "locale": "en-US"}],
                }
            else:
                # SD-JWT: use "dc+sd-jwt" per OID4VCI-1FINAL Appendix A (Final spec format ID).
                # "vc+sd-jwt" was the Draft identifier; "dc+sd-jwt" is the Final spec name.
                # NOTE: do NOT emit a "spruce-vc+sd-jwt" entry — Walt.id's
                # CredentialFormatSerializer rejects any unknown format string in
                # the entire metadata document, causing a 400 on all requests.
                credential_configurations[f"{ctype}#sd-jwt"] = {
                    "format": "dc+sd-jwt",
                    "vct": f"{ISSUER_BASE_URL}/credentials/{ctype}",
                    "scope": ctype,
                    "cryptographic_binding_methods_supported": _binding,
                    "credential_signing_alg_values_supported": _signing_algs,
                    "proof_types_supported": _proof_types,
                    "display": [{"name": _friendly_ctype_name(ctype), "locale": "en-US"}],
                }

        # OID4VCI-1FINAL Appendix A.2: mso_mdoc MUST appear in credential_configurations_supported
        # so conformant wallets can discover mDoc support. This generic entry covers all
        # non-ISO-typed credentials that request mso_mdoc format; the Rust signing engine
        # defaults the doctype to org.iso.18013.5.1.mDL when not explicitly set.
        if not any(v.get("format") == "mso_mdoc" for v in credential_configurations.values()):
            credential_configurations["generic_mdoc"] = {
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL",
                "scope": "mso_mdoc",
                "cryptographic_binding_methods_supported": _binding,
                "credential_signing_alg_values_supported": _signing_algs,
                "proof_types_supported": _proof_types,
                "display": [{"name": "Mobile Document (mDL)", "locale": "en-US"}],
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
        deferred_credential_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/deferred-credential"
        notification_endpoint = f"{ISSUER_BASE_URL}/v1/issuance/notification"

        return {
            "credential_issuer": issuer_url,
            "authorization_endpoint": authorization_endpoint,
            "credential_endpoint": credential_endpoint,
            "token_endpoint": token_endpoint,
            "nonce_endpoint": nonce_endpoint,
            "deferred_credential_endpoint": deferred_credential_endpoint,
            "notification_endpoint": notification_endpoint,
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
            "deferred_credential_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/deferred-credential",
            "notification_endpoint": f"{ISSUER_BASE_URL}/v1/issuance/notification",
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

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}/spruce")
    async def get_org_spruce_as_metadata(org_id: str) -> dict:
        """Per-org OAuth 2.0 AS metadata for SpruceID SDK (RFC 8414).

        SpruceID's oid4vci-rs derives the AS metadata URL from the
        ``credential_issuer`` field of the issuer metadata.  When
        ``credential_issuer = https://host/org/{id}/spruce`` the SDK fetches:
            /org/{id}/spruce/.well-known/oauth-authorization-server
        nginx rewrites that to:
            /.well-known/oauth-authorization-server/org/{id}/spruce
        The ``issuer`` value MUST match ``credential_issuer`` exactly.
        """
        from issuance.infrastructure.api.routes import ISSUER_BASE_URL
        issuer_url = f"{ISSUER_BASE_URL}/org/{org_id}/spruce"
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
