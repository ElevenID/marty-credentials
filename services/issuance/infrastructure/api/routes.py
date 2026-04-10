"""OID4VCI HTTP API endpoints."""

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Form, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from issuance.application.rust_integration import (
    get_marty_rs,
    get_or_generate_issuer_key,
    create_verifiable_credential_wrapper,
    postprocess_sd_jwt_x5c,
    oid4vci_create_credential_offer,
    oid4vci_create_token_response,
    oid4vci_create_authorization_response,
    oid4vci_exchange_auth_code_for_token,
    oid4vci_verify_pkce_s256,
    verify_proof_jwt,
    didcomm_resolve_did,
    didcomm_extract_endpoint,
    didcomm_pack_credential,
    didcomm_encrypt,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    AuthorizationSession,
    CredentialStatus,
    EventType,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.domain.ports import IIssuanceRepository

logger = logging.getLogger(__name__)

# Configuration — no localhost fallback; services must be explicitly configured.
REVOCATION_PROFILE_SERVICE_URL = os.environ.get("REVOCATION_PROFILE_SERVICE_URL", "")
CREDENTIAL_TEMPLATE_SERVICE_URL = os.environ.get("CREDENTIAL_TEMPLATE_SERVICE_URL", "")
if not REVOCATION_PROFILE_SERVICE_URL:
    logger.warning("REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail")
if not CREDENTIAL_TEMPLATE_SERVICE_URL:
    logger.warning("CREDENTIAL_TEMPLATE_SERVICE_URL not set — template calls will fail")
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

# Routers
issuance_router = APIRouter(prefix="/v1/issuance", tags=["issuance"])
application_template_router = APIRouter(prefix="/v1/application-templates", tags=["application-templates"])
application_router = APIRouter(prefix="/v1/applications", tags=["applications"])
issued_credential_router = APIRouter(prefix="/v1/issued-credentials", tags=["issued-credentials"])

# ---------------------------------------------------------------------------
# TLS-aware gRPC channel helper
# ---------------------------------------------------------------------------
_GRPC_CA_CERT = os.environ.get("GRPC_CA_CERT", "")


def _create_grpc_channel(target: str):
    """Create a gRPC channel, using TLS when GRPC_CA_CERT is set."""
    import grpc.aio as _grpc_aio

    if _GRPC_CA_CERT:
        with open(_GRPC_CA_CERT, "rb") as f:
            creds = _grpc_aio.ssl_channel_credentials(root_certificates=f.read())
        return _grpc_aio.secure_channel(target, creds)
    return _grpc_aio.insecure_channel(target)


# ---------------------------------------------------------------------------
# In-memory rate limiter for OAuth endpoints (token, authorize)
# ---------------------------------------------------------------------------
_TOKEN_RATE_LIMIT = int(os.environ.get("TOKEN_RATE_LIMIT", "30"))  # requests
_TOKEN_RATE_WINDOW = int(os.environ.get("TOKEN_RATE_WINDOW", "60"))  # seconds


class _InMemoryRateLimiter:
    """Simple per-IP sliding-window rate limiter (no Redis dependency)."""

    def __init__(self, limit: int, window: int) -> None:
        self._limit = limit
        self._window = window
        self._hits: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> None:
        now = time.monotonic()
        async with self._lock:
            timestamps = self._hits.get(key, [])
            # Prune expired entries
            cutoff = now - self._window
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= self._limit:
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(self._window)},
                )
            timestamps.append(now)
            self._hits[key] = timestamps


_token_limiter = _InMemoryRateLimiter(_TOKEN_RATE_LIMIT, _TOKEN_RATE_WINDOW)


async def _enforce_token_rate_limit(request: Request) -> None:
    """FastAPI Depends() guard for OAuth endpoints."""
    client_ip = request.client.host if request.client else "unknown"
    await _token_limiter.check(f"token:{client_ip}")


# ---------------------------------------------------------------------------
# In-memory Pushed Authorization Request (PAR) store — RFC 9126
# ---------------------------------------------------------------------------
_PAR_TTL_SECONDS = 90


class _PARStore:
    """Thread-safe in-memory store for PAR requests with TTL expiry.

    PAR requests are ephemeral (90s lifetime) so an in-memory dict with
    lazy cleanup is sufficient.  If the server restarts, wallets simply
    re-send the PAR — no durability needed.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[float, dict]] = {}  # uri → (expires_at, params)
        self._lock = asyncio.Lock()

    async def save(self, request_uri: str, params: dict) -> None:
        async with self._lock:
            self._store[request_uri] = (time.monotonic() + _PAR_TTL_SECONDS, params)

    async def pop(self, request_uri: str) -> dict | None:
        """Retrieve and delete a PAR request (single-use)."""
        async with self._lock:
            entry = self._store.pop(request_uri, None)
            # Lazy cleanup of expired entries
            now = time.monotonic()
            expired = [k for k, (exp, _) in self._store.items() if exp < now]
            for k in expired:
                del self._store[k]
        if entry is None:
            return None
        expires_at, params = entry
        if time.monotonic() > expires_at:
            return None  # expired
        return params


_par_store = _PARStore()


# ---------------------------------------------------------------------------
# In-memory nonce pool — OID4VCI v1 §7.3
# ---------------------------------------------------------------------------
# The EUDI Wallet Kit (and other spec-compliant wallets) calls the nonce
# endpoint WITHOUT an Authorization header.  The resulting nonce is not
# bound to any transaction at the time of issuance.  When the wallet later
# submits a credential request with proof containing that nonce, the
# credential endpoint must be able to validate it.
#
# This pool stores all recently-issued nonces so the proof validator can
# accept them even when they don't match tx.nonce.
_NONCE_POOL_TTL_SECONDS = 300  # 5 minutes — matches c_nonce_expires_in


class _NoncePool:
    """Thread-safe single-use nonce pool with TTL expiry."""

    def __init__(self) -> None:
        self._nonces: dict[str, float] = {}   # nonce → expires_at
        self._lock = asyncio.Lock()

    async def add(self, nonce: str) -> None:
        async with self._lock:
            self._nonces[nonce] = time.monotonic() + _NONCE_POOL_TTL_SECONDS
            # Lazy cleanup
            now = time.monotonic()
            expired = [k for k, exp in self._nonces.items() if exp < now]
            for k in expired:
                del self._nonces[k]

    async def consume(self, nonce: str) -> bool:
        """Check and consume a nonce (single-use). Returns True if valid."""
        async with self._lock:
            exp = self._nonces.pop(nonce, None)
            if exp is None:
                return False
            if time.monotonic() > exp:
                return False
            return True


_nonce_pool = _NoncePool()


# ---------------------------------------------------------------------------
# API key authentication for management endpoints
# ---------------------------------------------------------------------------
_ISSUANCE_API_KEY = os.environ.get("ISSUANCE_API_KEY", "")
_api_key_header = Header(None, alias="X-API-Key")


async def _verify_management_api_key(
    x_api_key: str | None = _api_key_header,
) -> str:
    """Verify X-API-Key header for management endpoints."""
    import hmac as _hmac

    if not _ISSUANCE_API_KEY:
        raise HTTPException(status_code=503, detail="ISSUANCE_API_KEY not configured on server")
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header is missing")
    if not _hmac.compare_digest(x_api_key, _ISSUANCE_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key


# ============================================================================
# Request/Response Models
# ============================================================================

class InitiateIssuanceRequest(BaseModel):
    organization_id: str
    credential_template_id: str | None = None  # Optional — falls back to default type
    applicant_id: str | None = None
    subject_did: str | None = None
    holder_did: str | None = None  # DIDComm v2: holder's DID for push delivery
    claims: dict[str, Any] = {}


class IssuanceResponse(BaseModel):
    id: str
    organization_id: str
    credential_template_id: str
    status: str
    credential_offer_uri: str
    credential_offer_uris: dict[str, str] = {}   # wallet_id → URI for each configured wallet
    credential_offer_labels: dict[str, str] = {}  # wallet_id → display_name from template
    pre_auth_code: str
    expires_at: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    # OID4VCI spec §6.2 — spec-compliant wallets (Walt.id) require c_nonce.
    # SpruceID kit wallet reads the legacy "nonce" field instead.
    # Emit both with the same value so all clients are satisfied.
    c_nonce: str
    # OID4VCI §6.2: c_nonce_expires_in MUST be included per spec (integer seconds).
    # NOTE: SpruceID mobile-sdk-rs ExtraResponseTokenFields deserializes this as
    # serde Duration {"secs":N,"nanos":N} — sending a plain integer causes a
    # deserialization error.  SpruceID-specific metadata endpoints omit this field
    # via the /spruce well-known paths; standard wallets receive it correctly.
    c_nonce_expires_in: int | None = 300
    nonce: str          # alias for c_nonce — SpruceID kit compatibility


class CredentialRequest(BaseModel):
    format: str = "jwt_vc_json"
    # OID4VCI v1 §8.2: proofs is an object mapping proof_type -> list[str]
    proofs: dict[str, list[str]] | None = None
    # Legacy draft support — kept for backward compatibility
    proof: dict[str, Any] | None = None
    # v1: identify credential by config id or credential_identifier from token response
    credential_configuration_id: str | None = None
    credential_identifier: str | None = None


class CredentialResponse(BaseModel):
    # OID4VCI v1 / Draft-12 hybrid: SpruceID mobile-sdk-rs expects each element
    # of "credentials" to be an Oid4vciCredential struct {"format": ..., "credential": ...}.
    # Walt.id / Draft-11 clients read the singular "credential" (bare string) instead.
    # Emit BOTH so all clients are satisfied.
    credentials: list[str | dict]
    credential: str | None = None     # Walt.id / Draft-11 compatibility alias
    notification_id: str | None = None
    # Both field names emitted — spec (c_nonce) + SpruceID kit legacy (nonce)
    c_nonce: str | None = None
    c_nonce_expires_in: int | None = None
    nonce: str | None = None          # SpruceID kit compatibility alias
    nonce_expires_in: int | None = None


class ApplicationTemplateCreate(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    credential_template_id: str | None = None
    form_fields: list[dict[str, Any]] = []
    evidence_requirements: list[str] = []
    claim_collection_rules: list[dict[str, Any]] = []
    # Pluggable vetting checks: {check_type, custom_name, is_required, order, config, external_provider, webhook_url}
    required_checks: list[dict[str, Any]] = []
    approval_strategy: str = "auto"
    application_validity_days: int = 30
    auto_approval_rules: list[dict[str, Any]] = []
    ui_config: dict[str, Any] = {}
    notification_config: dict[str, Any] = {}


# ── DIDComm v2 models ─────────────────────────────────────────────────────

class DidcommDeliverRequest(BaseModel):
    transaction_id: str
    holder_did: str
    universal_resolver_url: str | None = None


class DidcommDeliveryResponse(BaseModel):
    transaction_id: str
    credential_id: str
    holder_did: str
    service_endpoint: str
    didcomm_message_id: str
    status: str  # "delivered" or "delivery_failed"
    error: str | None = None


class DidcommAckResponse(BaseModel):
    status: str  # "acknowledged"
    message_id: str
    transaction_id: str | None = None


class ApplicationTemplateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    credential_template_id: str | None
    form_fields: list[dict[str, Any]]
    evidence_requirements: list[str]
    claim_collection_rules: list[dict[str, Any]]
    required_checks: list[dict[str, Any]]
    approval_strategy: str
    application_validity_days: int
    auto_approval_rules: list[dict[str, Any]]
    ui_config: dict[str, Any]
    notification_config: dict[str, Any]
    status: str
    created_at: str
    updated_at: str


class ApplicationCreate(BaseModel):
    application_template_id: str
    applicant_data: dict[str, Any]


class ApplicationResponse(BaseModel):
    id: str
    organization_id: str
    application_template_id: str
    applicant_identifier: str
    form_data: dict[str, Any]
    evidence_submissions: list[dict[str, Any]]
    status: str
    review_notes: str | None
    reviewer_id: str | None
    submitted_at: str
    reviewed_at: str | None
    expires_at: str
    issuance_transaction_id: str | None


class EvidenceSubmission(BaseModel):
    evidence_type: str
    evidence_data: dict[str, Any]


class ApplicationApproval(BaseModel):
    review_notes: str | None = None
    reviewer_id: str | None = None


class ApplicationRejection(BaseModel):
    review_notes: str
    reviewer_id: str | None = None


class CredentialStatusRequest(BaseModel):
    reason: str | None = None


class CredentialStatusResponse(BaseModel):
    id: str
    status: str
    status_updated_at: str
    reason: str | None = None


class IssuedCredentialStatusListEntryResponse(BaseModel):
    status_list_id: str
    index: int
    status_list_uri: str | None = None


class IssuedCredentialRecordResponse(BaseModel):
    id: str
    credential_id: str
    credential_type: str
    credential_format: str
    flow_execution_id: str
    credential_template_id: str
    application_id: str | None = None
    revocation_profile_id: str | None = None
    subject_id: str
    subject_claims_hash: str | None = None
    issued_at: str
    valid_from: str | None = None
    valid_until: str | None = None
    status: str
    status_list_entries: list[IssuedCredentialStatusListEntryResponse] = Field(default_factory=list)
    credential_hash: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    revoked_by: str | None = None
    created_at: str
    updated_at: str | None = None


# ============================================================================
# Helpers
# ============================================================================

def org_issuer_url(org_id: str) -> str:
    """Return the per-org OID4VCI credential_issuer URL.

    Per OID4VCI v1 §12.2.1, wallets derive the metadata URL by inserting
    ``/.well-known/openid-credential-issuer`` between the host and path:
      credential_issuer = https://issuer.example.com/org/<id>
      well-known URL   = https://issuer.example.com/.well-known/openid-credential-issuer/org/<id>
    """
    return f"{ISSUER_BASE_URL}/org/{org_id}"


def org_issuer_url_spruce(org_id: str) -> str:
    """Return the SpruceID-compatible per-org OID4VCI credential_issuer URL.

    SpruceID's ``oid4vci-rs @ e97b01e`` requires ``format: "spruce-vc+sd-jwt"`` for all
    SD-JWT credential configurations.  Any ``vc+sd-jwt`` entry in the same metadata document
    causes the entire metadata deserialisation to fail.  We therefore use a distinct issuer
    path for SpruceID credential offers so the metadata endpoint can emit only the
    ``spruce-vc+sd-jwt`` format without affecting Walt.id and other wallets.

      credential_issuer = https://issuer.example.com/org/<id>/spruce
      well-known URL   = https://issuer.example.com/.well-known/openid-credential-issuer/org/<id>/spruce
    """
    return f"{ISSUER_BASE_URL}/org/{org_id}/spruce"


def org_issuer_url_credential_manager(org_id: str) -> str:
    """Return the Google CredentialManager-compatible per-org issuer URL.

    Google's CredentialManager SDK (Android) only supports ``dc+sd-jwt`` format
    entries.  Any ``jwt_vc_json`` or ``spruce-vc+sd-jwt`` entry in the same
    metadata document causes the SDK's format parser to fail.  We therefore use
    a distinct issuer path for CredentialManager offers so the metadata endpoint
    can emit only ``dc+sd-jwt`` entries.

      credential_issuer = https://issuer.example.com/org/<id>/credential-manager
      well-known URL   = https://issuer.example.com/.well-known/openid-credential-issuer/org/<id>/credential-manager
    """
    return f"{ISSUER_BASE_URL}/org/{org_id}/credential-manager"


def org_issuer_url_apple_wallet(org_id: str) -> str:
    """Return the Apple Wallet-compatible per-org issuer URL.

    Apple's Verify with Wallet / ISO 18013-5 issuance path only supports
    ``mso_mdoc`` format entries.  Any ``jwt_vc_json``, ``dc+sd-jwt``, or
    ``spruce-vc+sd-jwt`` entry in the same metadata document may confuse
    the wallet's format parser.  We use a distinct issuer path so the metadata
    endpoint can emit only ``mso_mdoc`` entries.

      credential_issuer = https://issuer.example.com/org/<id>/apple-wallet
      well-known URL   = https://issuer.example.com/.well-known/openid-credential-issuer/org/<id>/apple-wallet
    """
    return f"{ISSUER_BASE_URL}/org/{org_id}/apple-wallet"


def _credential_status_to_protocol(status: CredentialStatus, expires_at: datetime | None) -> str:
    if status == CredentialStatus.ACTIVE and expires_at and expires_at < datetime.now(timezone.utc):
        return "EXPIRED"
    return status.value.upper()


def _credential_format_to_protocol(tx: IssuanceTransaction | None, cred: IssuedCredential) -> str:
    payload_format = (tx.credential_payload_format if tx else None) or ""
    if payload_format == "mso_mdoc":
        return "MDOC"
    return "SD_JWT_VC"


def _subject_claims_hash(tx: IssuanceTransaction | None) -> str | None:
    if tx is None:
        return None
    clean_claims = {
        key: value
        for key, value in tx.claims.items()
        if key not in {
            "credential_offer_uri",
            "credential_offer_uris",
            "offer_expires_at",
            "issuance_transaction_id",
            "issuance_fallback",
            "credential_type",
            "credential_display_name",
            "rejection_reason",
            "review_notes",
            "info_requests",
            "applicant_id",
            "_vct",
        }
    }
    canonical = json.dumps(clean_claims, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _issued_credential_to_protocol(
    cred: IssuedCredential,
    repo: IIssuanceRepository,
) -> IssuedCredentialRecordResponse:
    tx = await repo.get_transaction(cred.transaction_id)
    subject_id = cred.subject_did or cred.applicant_id or (tx.subject_did if tx else None) or (tx.applicant_id if tx else None) or cred.id
    issued_at = cred.issued_at
    valid_until = cred.expires_at
    protocol_status = _credential_status_to_protocol(cred.status, valid_until)
    credential_type = (tx.credential_type if tx and tx.credential_type else "unknown")
    updated_at = cred.status_updated_at if cred.status_updated_at else cred.issued_at
    return IssuedCredentialRecordResponse(
        id=cred.id,
        credential_id=cred.id,
        credential_type=credential_type,
        credential_format=_credential_format_to_protocol(tx, cred),
        flow_execution_id=cred.transaction_id,
        credential_template_id=cred.credential_template_id,
        application_id=tx.application_id if tx else None,
        revocation_profile_id=None,
        subject_id=subject_id,
        subject_claims_hash=_subject_claims_hash(tx),
        issued_at=issued_at.isoformat(),
        valid_from=issued_at.isoformat(),
        valid_until=valid_until.isoformat() if valid_until else None,
        status=protocol_status,
        status_list_entries=[],
        credential_hash=cred.credential_hash,
        revoked_at=cred.revoked_at.isoformat() if cred.revoked_at else None,
        revocation_reason=cred.revocation_reason,
        revoked_by=None,
        created_at=issued_at.isoformat(),
        updated_at=updated_at.isoformat() if updated_at else None,
    )


# ============================================================================
# OID4VCI Endpoints
# ============================================================================

@issuance_router.post("/initiate", response_model=IssuanceResponse, dependencies=[Depends(_verify_management_api_key)])
async def initiate_issuance(
    request: InitiateIssuanceRequest,
    repo: IIssuanceRepository = Depends(),
) -> IssuanceResponse:
    """Initiate a credential issuance transaction.

    Client errors from the org or template services (4xx) are hard failures
    so callers receive a proper 4xx response.  Network / 5xx failures are
    logged and allowed to proceed for internal service-to-service resilience.
    """

    # Validate organization exists via gRPC
    try:
        from marty_proto.v1 import organization_service_pb2 as org_pb2
        from marty_proto.v1 import organization_service_pb2_grpc as org_grpc

        org_grpc_target = os.environ.get("ORG_GRPC_TARGET", "organization:9002")
        async with _create_grpc_channel(org_grpc_target) as channel:
            org_stub = org_grpc.OrganizationServiceStub(channel)
            org_resp = await org_stub.GetOrganization(
                org_pb2.GetOrganizationRequest(organization_id=request.organization_id)
            )
            if not org_resp.id:
                raise HTTPException(
                    status_code=404,
                    detail=f"Organization not found: {request.organization_id}",
                )
    except HTTPException:
        raise  # Hard fail — propagate to caller
    except Exception as e:
        logger.warning(f"Could not validate organization {request.organization_id} (proceeding): {e}")

    # Resolve credential type from template via gRPC (preferred) with HTTP fallback.
    credential_type = "org.iso.18013.5.1.mDL"  # Default fallback
    credential_vct: str | None = None
    zk_predicate_claims: list[str] = []
    selective_disclosure_claims: list[str] = []
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    wallet_configs: list[dict] = []
    if request.credential_template_id:
        _tmpl_resolved = False
        # Try gRPC first
        try:
            from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
            from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc

            ct_grpc_target = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")
            async with _create_grpc_channel(ct_grpc_target) as channel:
                ct_stub = ct_grpc.CredentialTemplateServiceStub(channel)
                tmpl_resp = await ct_stub.GetTemplate(
                    ct_pb2.GetTemplateRequest(template_id=request.credential_template_id)
                )
            if not tmpl_resp.id:
                raise HTTPException(status_code=404, detail=f"Credential template not found: {request.credential_template_id}")
            credential_type = tmpl_resp.credential_type or credential_type
            raw_vct = tmpl_resp.vct or ""
            credential_vct = (
                raw_vct if raw_vct.startswith("http")
                else f"{ISSUER_BASE_URL}/credentials/{credential_type}"
            )
            zk_predicate_claims = list(tmpl_resp.zk_predicate_claims) or []
            selective_disclosure_claims = list(tmpl_resp.selective_disclosure_fields) if tmpl_resp.selective_disclosure_fields else []
            credential_payload_format = tmpl_resp.credential_payload_format or "w3c_vcdm_v2_sd_jwt"
            wallet_configs = json.loads(tmpl_resp.wallet_configs_json) if tmpl_resp.wallet_configs_json else []
            _tmpl_resolved = True
            logger.info(f"Fetched credential type from template (gRPC): {credential_type} vct={credential_vct}")
        except HTTPException:
            raise
        except Exception as _grpc_err:
            logger.warning(f"gRPC template fetch failed, falling back to HTTP: {_grpc_err}")

        # HTTP fallback
        if not _tmpl_resolved:
            url = f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/credential-templates/{request.credential_template_id}"
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(url)
                if resp.status_code == 404:
                    raise HTTPException(status_code=404, detail=f"Credential template not found: {request.credential_template_id}")
                if resp.status_code >= 400:
                    raise HTTPException(status_code=resp.status_code, detail=resp.text)
                tmpl = resp.json()
            except HTTPException:
                raise
            except httpx.ConnectError:
                raise HTTPException(status_code=503, detail="Credential template service unavailable")
            except httpx.TimeoutException:
                raise HTTPException(status_code=504, detail="Credential template service timeout")
            credential_type = tmpl.get("credential_type") or credential_type
            raw_vct = tmpl.get("vct") or ""
            credential_vct = (
                raw_vct if raw_vct.startswith("http")
                else f"{ISSUER_BASE_URL}/credentials/{credential_type}"
            )
            logger.info(f"Fetched credential type from template (HTTP): {credential_type} vct={credential_vct}")
            zk_predicate_claims = tmpl.get("zk_predicate_claims") or []
            selective_disclosure_claims = tmpl.get("selective_disclosure_fields") or []
            credential_payload_format = tmpl.get("credential_payload_format") or "w3c_vcdm_v2_sd_jwt"
            wallet_configs = tmpl.get("wallet_configs") or []

    # Derive vct fallback if not already resolved
    if not credential_vct:
        credential_vct = f"{ISSUER_BASE_URL}/credentials/{credential_type}"

    # Store vct in claims under a reserved key so the credential endpoint can
    # use it at signing time without a second template lookup.
    merged_claims = {**request.claims, "_vct": credential_vct}

    # DB column is NOT NULL; when callers omit template id, persist a stable fallback.
    effective_credential_template_id = request.credential_template_id or "default"

    tx = IssuanceTransaction(
        organization_id=request.organization_id,
        credential_template_id=effective_credential_template_id,
        applicant_id=request.applicant_id,
        subject_did=request.subject_did,
        claims=merged_claims,
        credential_type=credential_type,
        zk_predicate_claims=zk_predicate_claims,
        selective_disclosure_claims=selective_disclosure_claims,
        credential_payload_format=credential_payload_format,
        wallet_configs=wallet_configs,
    )
    await repo.save_transaction(tx)
    
    # OID4VCI: Pass credential offer inline for better wallet compatibility.
    # Delegate offer construction entirely to the Rust engine.
    from urllib.parse import quote

    credential_config_id = credential_type or "default"

    def _config_id_for_format_variant(base: str, variant: str | None) -> str:
        """Return the credential_configuration_id for the given base type and format variant.

        - Standard wallets (Walt.id, Marty native, etc.): ``{base}#sd-jwt``
          (``format: vc+sd-jwt`` in the standard metadata document).
        - SpruceID mobile SDK (``variant == "spruce-vc+sd-jwt"``): ``{base}#spruce-sd-jwt``
          which maps to the ``spruce-vc+sd-jwt`` entry in the ``/org/{id}/spruce``
          metadata document.
        - ISO 18013-5 mDoc (``variant == "mso_mdoc"``): ``{base}#mdoc``
          which maps to the ``mso_mdoc`` entry in the standard issuer metadata.
        """
        if base == "default":
            return base
        if variant == "spruce-vc+sd-jwt":
            return f"{base}#spruce-sd-jwt"
        if variant == "mso_mdoc":
            return f"{base}#mdoc"
        if variant == "credential-manager":
            return f"{base}#credential-manager"
        if variant == "apple-wallet":
            return f"{base}#apple-wallet"
        return f"{base}#sd-jwt"

    # Default offer uses the standard vc+sd-jwt config (works with Walt.id and
    # most OID4VCI-compliant wallets).  For mso_mdoc templates, use the #mdoc
    # config id so the default offer also resolves to the correct metadata entry.
    # credential_payload_format may be "MDOC" (enum value), "mso_mdoc", or "mdoc"
    # depending on which code path stored the template — all three indicate mdoc.
    _MDOC_PAYLOAD_FORMATS = {"mso_mdoc", "MDOC", "mdoc"}
    default_fmt_variant = "mso_mdoc" if credential_payload_format in _MDOC_PAYLOAD_FORMATS else None
    default_config_id = _config_id_for_format_variant(credential_config_id, default_fmt_variant)
    offer_json_str = oid4vci_create_credential_offer(
        issuer_url=org_issuer_url(request.organization_id),
        credential_types=[default_config_id],
        pre_authorized_code=tx.pre_auth_code,
        user_pin_required=False,
    )

    # Encode offer as inline JSON in openid-credential-offer URI
    offer_uri = f"openid-credential-offer://?credential_offer={quote(offer_json_str)}"

    # Build per-wallet offer URIs.  Each wallet entry may carry an optional
    # "format_variant" key (e.g. "spruce-vc+sd-jwt") that selects the right
    # credential_configuration_id for that wallet's SDK.
    credential_offer_uris: dict[str, str] = {}
    credential_offer_labels: dict[str, str] = {}  # wallet_id → display_name from template
    didcomm_delivery_results: list[dict] = []
    for wc in tx.wallet_configs:
        wid = wc.get("wallet_id", "")
        scheme = wc.get("deep_link_scheme", "openid-credential-offer://")
        fmt_variant = wc.get("format_variant")
        if not wid:
            continue

        # DIDComm v2 wallets: push delivery instead of offer URI
        if fmt_variant == "didcomm_v2":
            holder_did_for_delivery = request.holder_did or request.subject_did
            if holder_did_for_delivery:
                try:
                    delivery = await _didcomm_sign_and_deliver(
                        tx=tx, holder_did=holder_did_for_delivery, repo=repo,
                    )
                    didcomm_delivery_results.append(delivery.model_dump())
                    credential_offer_uris[wid] = f"didcomm://{delivery.service_endpoint}"
                except Exception as dc_err:
                    logger.warning(f"DIDComm auto-delivery to {holder_did_for_delivery} failed: {dc_err}")
                    credential_offer_uris[wid] = f"didcomm://pending?transaction_id={tx.id}"
            else:
                # No holder_did — caller must use /didcomm/deliver later
                credential_offer_uris[wid] = f"didcomm://pending?transaction_id={tx.id}"
            if wc.get("display_name"):
                credential_offer_labels[wid] = wc["display_name"]
            continue

        if wid:
            wallet_config_id = _config_id_for_format_variant(credential_config_id, fmt_variant)
            # SpruceID SDK requires a dedicated issuer URL whose metadata document
            # only emits formats its ProfilesCredentialConfiguration enum can parse.
            # This applies to both spruce-vc+sd-jwt AND mso_mdoc — any unrecognised
            # entry in the standard metadata causes the whole fetch to fail.
            wallet_issuer_url = (
                org_issuer_url_spruce(request.organization_id)
                if fmt_variant in ("spruce-vc+sd-jwt", "mso_mdoc")
                else org_issuer_url_credential_manager(request.organization_id)
                if fmt_variant == "credential-manager"
                else org_issuer_url_apple_wallet(request.organization_id)
                if fmt_variant == "apple-wallet"
                else org_issuer_url(request.organization_id)
            )
            wallet_offer_json = oid4vci_create_credential_offer(
                issuer_url=wallet_issuer_url,
                credential_types=[wallet_config_id],
                pre_authorized_code=tx.pre_auth_code,
                user_pin_required=False,
            )
            encoded = quote(wallet_offer_json)
            sep = "&" if "?" in scheme else "?"
            credential_offer_uris[wid] = f"{scheme}{sep}credential_offer={encoded}"
            if wc.get("display_name"):
                credential_offer_labels[wid] = wc["display_name"]
    
    return IssuanceResponse(
        id=tx.id,
        organization_id=tx.organization_id,
        credential_template_id=tx.credential_template_id,
        status=tx.status.value,
        credential_offer_uri=offer_uri,
        credential_offer_uris=credential_offer_uris,
        credential_offer_labels=credential_offer_labels,
        pre_auth_code=tx.pre_auth_code,
        expires_at=tx.expires_at.isoformat(),
    )


# ── Authorization Endpoint (OID4VCI §5) ──────────────────────────────────

@issuance_router.get("/authorize", dependencies=[Depends(_enforce_token_rate_limit)])
async def authorize(
    response_type: str = Query(None),
    client_id: str = Query(None),
    redirect_uri: str = Query(None),
    state: str = Query(None),
    code_challenge: str = Query(None),
    code_challenge_method: str = Query(None),
    issuer_state: str = Query(None),
    authorization_details: str = Query(None),
    scope: str = Query(None),
    organization_id: str = Query(None),
    request_uri: str = Query(None),
    repo: IIssuanceRepository = Depends(),
):
    """OAuth 2.0 authorization endpoint for OID4VCI authorization code flow.

    The authorization request parameters arrive as query params (RFC 6749 §4.1.1).
    When ``request_uri`` is present (RFC 9126 PAR flow), the stored PAR parameters
    are used instead of inline query params.
    We delegate all protocol validation (response_type, PKCE, etc.) to the Rust
    engine and only handle DB persistence here.
    """
    import json as _json

    # ── RFC 9126: resolve PAR request_uri ────────────────────────────
    if request_uri:
        par_params = await _par_store.pop(request_uri)
        if par_params is None:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "request_uri is invalid or expired",
                },
            )
        # PAR params override inline query params (RFC 9126 §3)
        response_type = par_params.get("response_type") or response_type
        client_id = par_params.get("client_id") or client_id
        redirect_uri = par_params.get("redirect_uri") or redirect_uri
        state = par_params.get("state") or state
        code_challenge = par_params.get("code_challenge") or code_challenge
        code_challenge_method = par_params.get("code_challenge_method") or code_challenge_method
        issuer_state = par_params.get("issuer_state") or issuer_state
        authorization_details = par_params.get("authorization_details") or authorization_details
        scope = par_params.get("scope") or scope
        organization_id = par_params.get("organization_id") or organization_id

    if not response_type or not client_id:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "response_type and client_id are required",
            },
        )

    # ── Redirect URI allowlist (RFC 6749 §3.1.2.2) ──────────────────
    if redirect_uri:
        allowed_raw = os.environ.get("ALLOWED_REDIRECT_URIS", "")
        if allowed_raw:
            allowed_uris = [u.strip() for u in allowed_raw.split(",") if u.strip()]
            if redirect_uri not in allowed_uris:
                logger.warning(
                    "Rejected unregistered redirect_uri=%s (client_id=%s)",
                    redirect_uri, client_id,
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "redirect_uri is not registered",
                    },
                )
        else:
            # No allowlist configured — enforce basic safety: must be HTTPS
            # (except localhost for development).
            parsed = urlparse(redirect_uri)
            is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1")
            if parsed.scheme != "https" and not is_localhost:
                logger.warning(
                    "Rejected non-HTTPS redirect_uri=%s (client_id=%s)",
                    redirect_uri, client_id,
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "redirect_uri must use HTTPS",
                    },
                )

    # Build the authorization request JSON for the Rust engine
    auth_details = None
    if authorization_details:
        try:
            auth_details = _json.loads(authorization_details)
        except _json.JSONDecodeError:
            pass

    request_json = _json.dumps({
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "issuer_state": issuer_state,
        "authorization_details": auth_details,
        "scope": scope,
    })

    try:
        auth_resp, rust_session = oid4vci_create_authorization_response(
            request_json, session_lifetime_secs=600,
        )
    except (ValueError, RuntimeError) as exc:
        if redirect_uri:
            from urllib.parse import urlencode
            params = {"error": "invalid_request", "error_description": str(exc)}
            if state:
                params["state"] = state
            return RedirectResponse(f"{redirect_uri}?{urlencode(params)}")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": str(exc)},
        )

    # Create a Python AuthorizationSession entity for DB persistence,
    # seeded with the Rust-generated code and session data.
    from datetime import timedelta
    auth_session = AuthorizationSession(
        code=rust_session["code"],
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        issuer_state=issuer_state,
        credential_configuration_ids=rust_session.get("credential_configuration_ids", []),
        organization_id=organization_id,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    await repo.save_authorization_session(auth_session)

    # If a redirect_uri was provided, redirect the user agent back
    if redirect_uri:
        from urllib.parse import urlencode
        params = {"code": auth_resp["code"]}
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}")

    # Otherwise return JSON (useful for testing / programmatic clients)
    return auth_resp


# ── Pushed Authorization Request Endpoint (RFC 9126) ─────────────────────

@issuance_router.post("/par", dependencies=[Depends(_enforce_token_rate_limit)])
async def pushed_authorization_request(
    http_request: Request,
    response_type: str = Form(None),
    client_id: str = Form(None),
    redirect_uri: str = Form(None),
    scope: str = Form(None),
    state: str = Form(None),
    code_challenge: str = Form(None),
    code_challenge_method: str = Form(None),
    issuer_state: str = Form(None),
    authorization_details: str = Form(None),
    organization_id: str = Form(None),
) -> JSONResponse:
    """Pushed Authorization Request endpoint (RFC 9126 §2).

    Accepts the same parameters as the authorization endpoint via POST form body.
    Stores the request and returns a ``request_uri`` that the client presents
    at the authorization endpoint instead of inline parameters.

    Response (201):
        {"request_uri": "urn:ietf:params:oauth:request_uri:<uuid>", "expires_in": 90}
    """
    import uuid as _uuid

    request_uri = f"urn:ietf:params:oauth:request_uri:{_uuid.uuid4()}"

    await _par_store.save(request_uri, {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "issuer_state": issuer_state,
        "authorization_details": authorization_details,
        "organization_id": organization_id,
    })

    logger.info(
        "[par] client_id=%s request_uri=%s",
        client_id, request_uri[:60],
    )

    return JSONResponse(
        status_code=201,
        content={"request_uri": request_uri, "expires_in": _PAR_TTL_SECONDS},
    )


@issuance_router.post("/token", response_model=TokenResponse, dependencies=[Depends(_enforce_token_rate_limit)])
async def exchange_token(
    http_request: Request,
    grant_type: str = Form(...),
    pre_authorized_code: str = Form(None, alias="pre-authorized_code"),
    code: str = Form(None),
    redirect_uri: str = Form(None),
    client_id: str = Form(None),
    code_verifier: str = Form(None),
    repo: IIssuanceRepository = Depends(),
) -> TokenResponse:
    """Exchange pre-authorized code or authorization code for access token (OID4VCI)."""
    rid = http_request.headers.get("X-Request-ID", "-")
    logger.info(
        f"[token] rid={rid} grant_type={grant_type!r} "
        f"pre_authorized_code={pre_authorized_code!r} code={code!r}"
    )

    # ── Authorization code flow ────────────────────────────────────
    if grant_type == "authorization_code":
        if not code:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "code is required"},
            )

        auth_session = await repo.get_authorization_session_by_code(code)
        if not auth_session:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid authorization code"},
            )

        if auth_session.is_expired:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Authorization code expired"},
            )

        if auth_session.status != "pending":
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Authorization code already used"},
            )

        # Build JSON payloads for the Rust engine which handles all
        # protocol validation (redirect_uri match, PKCE, etc.).
        import json as _json
        request_payload = _json.dumps({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id or auth_session.client_id,
            "code_verifier": code_verifier,
        })
        session_payload = _json.dumps({
            "code": auth_session.code,
            "client_id": auth_session.client_id,
            "redirect_uri": auth_session.redirect_uri,
            "code_challenge": auth_session.code_challenge,
            "code_challenge_method": auth_session.code_challenge_method,
            "issuer_state": auth_session.issuer_state,
            "credential_configuration_ids": auth_session.credential_configuration_ids,
            "created_at": int(auth_session.created_at.timestamp()),
            "expires_in": 600,
        })

        try:
            token_resp = oid4vci_exchange_auth_code_for_token(
                request_payload, session_payload, 1800,
            )
        except RuntimeError as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": str(exc)},
            )

        # Persist the Rust-generated tokens on the session
        auth_session.mark_exchanged(
            access_token=token_resp["access_token"],
            nonce=token_resp.get("nonce", ""),
        )
        await repo.save_authorization_session(auth_session)

        return TokenResponse(
            access_token=token_resp["access_token"],
            expires_in=token_resp.get("expires_in", 1800),
            c_nonce=token_resp.get("nonce", ""),
            nonce=token_resp.get("nonce", ""),
        )

    # ── Pre-authorized code flow ───────────────────────────────────
    if not pre_authorized_code:
        logger.warning(f"[token] rid={rid} 400 pre-authorized_code missing (grant_type={grant_type!r})")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "pre-authorized_code is required"},
        )
    
    if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        logger.warning(f"[token] rid={rid} 400 unsupported_grant_type {grant_type!r}")
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_grant_type", "error_description": "Unsupported grant type"},
        )
    
    tx = await repo.get_by_pre_auth_code(pre_authorized_code)
    if not tx:
        logger.warning(f"[token] rid={rid} 400 invalid pre-authorized_code (not found)")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Invalid pre-authorized code"},
        )
    
    if tx.is_expired:
        logger.warning(f"[token] rid={rid} 400 tx {tx.id} expired")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Transaction expired"},
        )
    
    # OID4VCI Final §6.1: The pre-authorized code MUST be single-use.
    # Reject any attempt to reuse it after a token has already been issued.
    if tx.status in (IssuanceStatus.AUTHORIZED, IssuanceStatus.ISSUED):
        logger.warning(
            f"[token] rid={rid} tx_id={tx.id} pre-auth code replay rejected (status={tx.status.value})"
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "Pre-authorized code has already been used and is single-use only",
            },
        )

    if tx.status != IssuanceStatus.PENDING:
        logger.warning(f"[token] rid={rid} 400 tx {tx.id} wrong state={tx.status.value}")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Invalid transaction state"},
        )

    # Delegate token + nonce generation to Rust
    token_resp = oid4vci_create_token_response(pre_authorized_code, 1800)

    # Persist the Rust-generated tokens on the transaction
    tx.access_token = token_resp["access_token"]
    tx.nonce = token_resp.get("nonce", "")
    tx.status = IssuanceStatus.AUTHORIZED
    await repo.save_transaction(tx)

    # Also store the token nonce in the global pool for wallets that call the
    # nonce endpoint separately (EUDI Wallet Kit replaces it via /nonce).
    if tx.nonce:
        await _nonce_pool.add(tx.nonce)

    logger.info(
        f"[token] rid={rid} tx_id={tx.id} org={tx.organization_id} "
        f"cred_type={tx.credential_type}"
    )

    return TokenResponse(
        access_token=token_resp["access_token"],
        expires_in=token_resp.get("expires_in", 1800),
        c_nonce=token_resp.get("nonce", ""),
        nonce=token_resp.get("nonce", ""),
    )


@issuance_router.post("/nonce")
async def nonce_endpoint(
    response: Response,
    authorization: str | None = Header(None),
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """OID4VCI v1 §7.3 — Nonce Endpoint.

    Returns a fresh nonce for use in credential proof JWTs.
    If the caller presents a Bearer access token, the stored nonce for that
    transaction/session is also refreshed so proof validation passes.

    All nonces are also stored in an in-memory pool so that wallets which
    call the nonce endpoint without an access token (e.g. EUDI Wallet Kit)
    can still have their proof validated at the credential endpoint.
    """
    import secrets as _secrets
    new_nonce = _secrets.token_urlsafe(32)

    # Always add to the global nonce pool for fallback validation
    await _nonce_pool.add(new_nonce)

    if authorization and authorization.startswith("Bearer "):
        access_token = authorization.split(" ", 1)[1]
        tx = await repo.get_by_access_token(access_token)
        if tx:
            tx.nonce = new_nonce
            await repo.save_transaction(tx)
        else:
            auth_session = await repo.get_authorization_session_by_access_token(access_token)
            if auth_session:
                auth_session.nonce = new_nonce
                await repo.save_authorization_session(auth_session)

    # OID4VCI §7.3: Cache-Control MUST be no-store to prevent nonce caching
    response.headers["Cache-Control"] = "no-store"
    # OID4VCI v1 §7.2 uses "c_nonce"; include "nonce" alias for draft wallets
    return {"c_nonce": new_nonce, "nonce": new_nonce, "c_nonce_expires_in": 300}


@issuance_router.post("/credential", response_model=CredentialResponse)
async def issue_credential(
    http_request: Request,
    request: CredentialRequest,
    authorization: str = Header(None),
    repo: IIssuanceRepository = Depends(),
) -> CredentialResponse:
    """Issue a credential (OID4VCI credential endpoint)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization")
    
    access_token = authorization.split(" ", 1)[1]
    
    # Try pre-auth flow first (transaction-based), then auth code flow (session-based)
    tx = await repo.get_by_access_token(access_token)
    auth_session = None
    if not tx:
        auth_session = await repo.get_authorization_session_by_access_token(access_token)
        if not auth_session:
            raise HTTPException(status_code=401, detail="Invalid access token")
        # For auth-code flow the credential endpoint still needs an
        # IssuanceTransaction to carry the claims + org context.  Look one up
        # by issuer_state if the authorization session was started from an
        # existing offer, otherwise create a minimal stub transaction.
        if auth_session.issuer_state:
            tx = await repo.get_by_pre_auth_code(auth_session.issuer_state)
        if not tx:
            # Stub transaction for auth-code-only issuance.
            # Strip the "#sd-jwt" suffix that may be present on the config ID
            # (added to the offer for SpruceID wallet compatibility) so the
            # signing code receives the bare credential type (e.g. "access_badge").
            raw_config_id = (
                auth_session.credential_configuration_ids[0]
                if auth_session.credential_configuration_ids
                else "default"
            )
            bare_ctype = raw_config_id.split("#")[0]  # strips #sd-jwt, #spruce-sd-jwt, etc.
            tx = IssuanceTransaction(
                organization_id=auth_session.organization_id or "",
                status=IssuanceStatus.AUTHORIZED,
                access_token=access_token,
                nonce=auth_session.nonce,
                credential_type=bare_ctype,
            )
            await repo.save_transaction(tx)
    
    # OID4VCI Final §7.3: The access token is single-use for credential issuance.
    # §8 errors use 400 invalid_credential_request, not 401.
    if tx.status == IssuanceStatus.ISSUED:
        existing_cred = await repo.get_credential_by_transaction_id(tx.id)
        if existing_cred:
            response_format = request.format or "vc+sd-jwt"
            credential_obj = {"format": response_format, "credential": existing_cred.credential_jwt}
            import uuid as _uuid
            notification_id = str(_uuid.uuid4())
            return CredentialResponse(
                credentials=[credential_obj],
                credential=existing_cred.credential_jwt,
                notification_id=notification_id,
            )
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_credential_request",
                "error_description": "Credential already issued — access token is single-use",
            },
        )
    if tx.status != IssuanceStatus.AUTHORIZED:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_credential_request", "error_description": "Invalid transaction state"},
        )

    # OID4VCI §8.2: Validate credential_configuration_id if provided.
    # It must correspond to a configuration supported by this issuer for the transaction.
    if request.credential_configuration_id is not None:
        cred_type_base = tx.credential_type or "default"
        valid_config_ids = {
            cred_type_base,
            f"{cred_type_base}#sd-jwt",
            f"{cred_type_base}#mdoc",
            f"{cred_type_base}#spruce-sd-jwt",
            "default",
            "default#sd-jwt",
        }
        # Also include org's published credential types so validation is
        # consistent with GET /.well-known/openid-credential-issuer/org/{org_id}.
        tx_own_ids = set(valid_config_ids)
        if tx.organization_id:
            for _ctype in await repo.get_credential_types_for_org(tx.organization_id):
                valid_config_ids.update({
                    _ctype,
                    f"{_ctype}#sd-jwt",
                    f"{_ctype}#mdoc",
                    f"{_ctype}#spruce-sd-jwt",
                })
        if request.credential_configuration_id not in valid_config_ids:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_credential_request",
                    "error_description": f"Unknown credential_configuration_id: {request.credential_configuration_id!r}",
                },
            )
        # If the config ID was validated via org DB (not tx's stored type),
        # fix credential_type on the transaction so signing uses the correct type.
        if request.credential_configuration_id not in tx_own_ids:
            tx.credential_type = request.credential_configuration_id.split("#")[0]
            await repo.save_transaction(tx)

    # OID4VCI §8.2: Validate credential_identifier if provided.
    # credential_identifier is only valid in auth-code flows where the AS issued it.
    # Pre-auth code flow does not issue credential_identifiers.
    if request.credential_identifier is not None:
        valid_identifiers: set[str] = set()
        if auth_session:
            valid_identifiers = set(getattr(auth_session, "credential_configuration_ids", []) or [])
        if request.credential_identifier not in valid_identifiers:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_credential_request",
                    "error_description": f"Unknown credential_identifier: {request.credential_identifier!r}",
                },
            )
    
    # Get issuer key for organization
    try:
        issuer_key = await get_or_generate_issuer_key(tx.organization_id)
    except ImportError as e:
        logger.error(f"Rust bindings not available: {e}")
        tx.fail("Rust bindings not available")
        await repo.save_transaction(tx)
        raise HTTPException(status_code=500, detail="Credential signing service unavailable")
    except RuntimeError as e:
        logger.error(f"Issuer key storage unavailable: {e}")
        tx.fail("Issuer key storage unavailable")
        await repo.save_transaction(tx)
        raise HTTPException(status_code=500, detail="Credential issuer key unavailable")
    
    # Get credential type from transaction (stored during initiation)
    credential_type = tx.credential_type or "org.iso.18013.5.1.mDL"
    rid = http_request.headers.get("X-Request-ID", "-")
    logger.info(
        f"[credential] rid={rid} tx_id={tx.id} org={tx.organization_id} "
        f"cred_type={credential_type} status={tx.status}"
    )

    # Extract holder DID (subject) from the proof JWT sent by the wallet.
    # OID4VCI v1 §8.2: proofs is {"jwt": ["eyJ...", ...]} (object with type -> list).
    # Legacy draft format used proof: {"proof_type": "jwt", "jwt": "eyJ..."} (single object).
    # We resolve the first jwt proof from either format.
    holder_did: str | None = None

    def _extract_proof_jwt(req: CredentialRequest) -> str | None:
        """Return the first JWT proof string regardless of v1/legacy format."""
        # v1: proofs.jwt is a list of JWT strings
        if req.proofs:
            jwt_list = req.proofs.get("jwt", [])
            if jwt_list:
                return jwt_list[0]
        # Legacy: proof.proof_type == "jwt" and proof.jwt is a string
        if req.proof and req.proof.get("proof_type") == "jwt":
            return req.proof.get("jwt")
        return None

    proof_jwt = _extract_proof_jwt(request)
    logger.info(f"[credential] rid={rid} proof present: {proof_jwt is not None}")

    # OID4VCI §7.2: proof of possession is required for credential binding.
    if not proof_jwt:
        logger.warning(f"[credential] rid={rid} tx_id={tx.id} rejecting — proof of possession missing")
        return JSONResponse(
            status_code=400,
            content={"error": "proof_missing", "error_description": "Proof of possession is required per OID4VCI §7.2"},
        )

    # OID4VCI-1FINAL Appendix F.4: aud in proof JWT MUST be the credential_issuer URL.
    # We validate that aud ends with /org/{org_id} to accept both localhost and
    # production hostnames (PUBLIC_API_URL may differ between dev and prod).
    if tx.organization_id:
        try:
            import base64 as _b64, json as _json
            _proof_parts = proof_jwt.split('.')
            _pad = '=' * ((-len(_proof_parts[1])) % 4)
            _proof_payload = _json.loads(_b64.urlsafe_b64decode(_proof_parts[1] + _pad))
            _proof_aud = _proof_payload.get('aud') or ''
            _expected_aud_suffix = f'/org/{tx.organization_id}'
            if not _proof_aud.endswith(_expected_aud_suffix):
                logger.warning(
                    f"[credential] rid={rid} aud mismatch: got {_proof_aud!r}, "
                    f"expected URL ending in {_expected_aud_suffix!r}"
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_proof",
                        "error_description": (
                            f"OID4VCI §8.2: proof JWT aud MUST be the credential_issuer URL "
                            f"(ending in {_expected_aud_suffix}), got {_proof_aud!r}"
                        ),
                    },
                )
        except Exception as _aud_err:
            logger.warning(f"[credential] rid={rid} could not decode proof aud: {_aud_err}")
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_proof", "error_description": "Could not decode proof JWT audience"},
            )

    # Verify proof JWT signature via Rust + extract holder DID
    # Pass issuer_url as None to let the Rust layer use the URL embedded in the proof's aud;
    # full aud validation requires the public gateway URL which is available via ISSUER_BASE_URL.
    ok, did_from_proof, verify_err = verify_proof_jwt(
        proof_jwt, expected_nonce=tx.nonce or None
    )
    if not ok and verify_err and "nonce" in verify_err.lower():
        # Fallback: the wallet may have fetched a nonce from the nonce endpoint
        # without an access token (e.g. EUDI Wallet Kit).  Extract the nonce
        # from the proof JWT and check the global nonce pool.
        try:
            import base64 as _b64n, json as _json_n
            _proof_parts_n = proof_jwt.split('.')
            _pad_n = '=' * ((-len(_proof_parts_n[1])) % 4)
            _payload_n = _json_n.loads(_b64n.urlsafe_b64decode(_proof_parts_n[1] + _pad_n))
            _proof_nonce = _payload_n.get('nonce')
            logger.info(f"[credential] rid={rid} nonce pool fallback: proof_nonce={_proof_nonce!r}")
            if _proof_nonce and await _nonce_pool.consume(_proof_nonce):
                logger.info(f"[credential] rid={rid} nonce pool hit — retrying proof verification with pool nonce")
                ok, did_from_proof, verify_err = verify_proof_jwt(
                    proof_jwt, expected_nonce=_proof_nonce
                )
            else:
                logger.info(f"[credential] rid={rid} nonce pool miss — nonce not found in pool")
        except Exception as _nonce_err:
            logger.warning(f"[credential] rid={rid} nonce pool fallback failed: {_nonce_err}")
    if ok:
        holder_did = did_from_proof
        logger.info(f"[credential] rid={rid} proof OK, holder_did={holder_did}")
    else:
        logger.warning(f"[credential] rid={rid} tx_id={tx.id} proof verification failed: {verify_err}")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_proof", "error_description": verify_err or "Proof of possession verification failed"},
        )

    # Filter internal workflow fields out of claims — these are metadata used by the
    # applicant service and must never appear as credential subject attributes.
    _INTERNAL_CLAIM_FIELDS = {
        "credential_offer_uri",
        "credential_offer_uris",
        "offer_expires_at",
        "issuance_transaction_id",
        "issuance_fallback",
        "credential_type",
        "credential_display_name",
        "rejection_reason",
        "review_notes",
        "info_requests",
        # Applicant system fields — internal identifiers, not credential attributes
        "applicant_id",
        # Reserved internal key for the vct URI used at signing time
        "_vct",
    }
    clean_claims = {k: v for k, v in tx.claims.items() if k not in _INTERNAL_CLAIM_FIELDS}
    logger.info(f"[credential] rid={rid} claims={list(clean_claims.keys())} subject={holder_did or tx.subject_did or 'none'}")

    # Use the stored vct URI for the SD-JWT `vct` claim (RFC 9596 §3.1).
    # This ensures the wallet sees a proper URI rather than the raw abbreviated credential_type.
    vct_for_signing = (
        tx.claims.get("_vct")
        or (f"{ISSUER_BASE_URL}/credentials/{credential_type}" if credential_type and not credential_type.startswith("http") else credential_type)
    )

    # Get Rust bindings and create signed credential
    # For mso_mdoc templates, force the signing format regardless of what the
    # wallet sends in the credential request — ensures CBOR mdoc output.
    credential_payload_fmt = tx.credential_payload_format or "w3c_vcdm_v2_sd_jwt"
    # Determine the format string to pass to the Rust signer.
    # Template-declared format wins — mirrors the mso_mdoc override pattern.
    # mso_mdoc: always forced regardless of what the wallet requests.
    # SD-JWT templates: force vc+sd-jwt so Rust dispatches to the SD-JWT signer
    #   rather than falling through to plain JWT-VC.
    # spruce-vc+sd-jwt: SpruceKit's custom alias — normalise to vc+sd-jwt for Rust;
    #   the response uses the original request.format so SpruceKit parses it correctly.
    _SD_JWT_PAYLOAD_FORMATS = {
        "w3c_vcdm_v2_sd_jwt", "ietf_sd_jwt",
        "SD_JWT_VC", "sd_jwt_vc",       # Python enum value / lowercase alias
        "vc+sd-jwt", "dc+sd-jwt",       # IANA media type variants
    }
    _MDOC_PAYLOAD_FORMATS_LOCAL = {"mso_mdoc", "MDOC", "mdoc"}
    if credential_payload_fmt in _MDOC_PAYLOAD_FORMATS_LOCAL:
        signing_format = "mso_mdoc"
    elif credential_payload_fmt in _SD_JWT_PAYLOAD_FORMATS:
        signing_format = "vc+sd-jwt"
    elif request.format == "spruce-vc+sd-jwt":
        signing_format = "vc+sd-jwt"
    else:
        signing_format = request.format
    # For mdoc, credential_type is the doctype; Rust defaults to org.iso.18013.5.1.mDL
    # when mdoc_doctype is None, so tx.credential_type is passed through directly.
    signing_credential_type = tx.credential_type if signing_format == "mso_mdoc" else vct_for_signing

    # For SD-JWT, if no explicit selective disclosure claims were configured
    # on the template, default to all top-level claim keys (EUDI compliance).
    sd_claims = tx.selective_disclosure_claims or []
    if signing_format == "vc+sd-jwt" and not sd_claims:
        sd_claims = [k for k in clean_claims if not k.startswith("_")]

    try:
        jwt_credential, credential_id = create_verifiable_credential_wrapper(
            issuer_did=issuer_key["did"],
            issuer_jwk_json=issuer_key["jwk_json"],
            subject_id=holder_did or tx.subject_did,
            credential_type=signing_credential_type,
            claims_json=json.dumps(clean_claims),
            expiration_seconds=31536000,  # 1 year
            organization_id=tx.organization_id,
            format=signing_format,
            selective_disclosure_claims=sd_claims,
            zk_predicate_claims=tx.zk_predicate_claims or [],
            credential_payload_format=credential_payload_fmt,
        )

        # EUDI compliance: inject x5c header and HTTPS iss for SD-JWT credentials.
        # The EUDI reference verifier only supports X.509-based verification.
        if signing_format == "vc+sd-jwt":
            jwt_credential = postprocess_sd_jwt_x5c(
                jwt_credential, issuer_key, tx.organization_id, ISSUER_BASE_URL,
            )
        
        # Only update state and emit event on first issuance; allow idempotent
        # wallet retries (wallets sometimes re-request after a network timeout).
        if tx.status == IssuanceStatus.AUTHORIZED:
            # MIP §20.5.2: invalidate nonce immediately upon first use
            tx.nonce = None
            tx.complete()
            await repo.save_transaction(tx)
            expires_at = (tx.issued_at or datetime.now(timezone.utc)) + timedelta(days=365)
            issued_credential = IssuedCredential(
                id=credential_id,
                transaction_id=tx.id,
                organization_id=tx.organization_id,
                credential_template_id=tx.credential_template_id,
                applicant_id=tx.applicant_id,
                subject_did=holder_did or tx.subject_did,
                credential_jwt=jwt_credential,
                credential_hash=hashlib.sha256(jwt_credential.encode("utf-8")).hexdigest(),
                status=CredentialStatus.ACTIVE,
                issued_at=tx.issued_at or datetime.now(timezone.utc),
                expires_at=expires_at,
            )
            await repo.save_credential(issued_credential)
            await repo.save_event(IssuanceEvent(
                transaction_id=tx.id,
                application_id=tx.application_id,
                event_type=EventType.CREDENTIAL_ISSUED,
                metadata={"credential_id": credential_id, "credential_type": credential_type},
            ))

        logger.info(f"[credential] rid={rid} tx_id={tx.id} issued credential_id={credential_id} cred_type={credential_type}")
        # OID4VCI hybrid response:
        # - "credentials" as object array for SpruceID mobile-sdk-rs (expects Oid4vciCredential struct)
        # - "credential" as bare string for Walt.id / Draft-11 clients
        # Use the request format in the response object (not signing_format which may
        # have been normalised from spruce-vc+sd-jwt → vc+sd-jwt for Rust).
        response_format = request.format or signing_format or "vc+sd-jwt"
        credential_obj = {"format": response_format, "credential": jwt_credential}
        import uuid as _uuid
        notification_id = str(_uuid.uuid4())
        return CredentialResponse(
            credentials=[credential_obj],
            credential=jwt_credential,
            notification_id=notification_id,
        )
        
    except Exception as e:
        logger.error(f"[credential] rid={rid} tx_id={tx.id} Rust credential creation failed: {e}")
        tx.fail(str(e))
        await repo.save_transaction(tx)
        raise HTTPException(status_code=500, detail="Credential creation failed")


# ── DIDComm v2 Push Delivery ─────────────────────────────────────────────

async def _didcomm_sign_and_deliver(
    tx: "IssuanceTransaction",
    holder_did: str,
    repo: "IIssuanceRepository",
    universal_resolver_url: str | None = None,
) -> DidcommDeliveryResponse:
    """Sign a credential and deliver it to the holder via DIDComm v2.

    1. Sign the credential using the same Rust signer as OID4VCI.
    2. Pack the signed credential into a DIDComm v2 issue-credential/3.0 message.
    3. Resolve the holder's DID Document to find their DIDComm service endpoint.
    4. POST the DIDComm message to that endpoint.
    """
    issuer_key = await get_or_generate_issuer_key(tx.organization_id)

    credential_type = tx.credential_type or "VerifiableCredential"
    _INTERNAL_CLAIM_FIELDS = {
        "credential_offer_uri", "credential_offer_uris", "offer_expires_at",
        "issuance_transaction_id", "issuance_fallback", "credential_type",
        "credential_display_name", "rejection_reason", "review_notes",
        "info_requests", "applicant_id", "_vct",
    }
    clean_claims = {k: v for k, v in tx.claims.items() if k not in _INTERNAL_CLAIM_FIELDS}

    credential_payload_fmt = tx.credential_payload_format or "w3c_vcdm_v2_sd_jwt"
    if credential_payload_fmt == "mso_mdoc":
        signing_format = "mso_mdoc"
    elif credential_payload_fmt in ("w3c_vcdm_v2_sd_jwt", "ietf_sd_jwt"):
        signing_format = "vc+sd-jwt"
    else:
        signing_format = "vc+sd-jwt"

    vct_for_signing = (
        tx.claims.get("_vct")
        or (f"{ISSUER_BASE_URL}/credentials/{credential_type}"
            if credential_type and not credential_type.startswith("http")
            else credential_type)
    )
    signing_credential_type = tx.credential_type if signing_format == "mso_mdoc" else vct_for_signing

    # SD-JWT default: all top-level claims if none configured
    sd_claims_dc = tx.selective_disclosure_claims or []
    if signing_format == "vc+sd-jwt" and not sd_claims_dc:
        sd_claims_dc = [k for k in clean_claims if not k.startswith("_")]

    # Step 1: Sign the credential (same Rust signer as OID4VCI)
    jwt_credential, credential_id = create_verifiable_credential_wrapper(
        issuer_did=issuer_key["did"],
        issuer_jwk_json=issuer_key["jwk_json"],
        subject_id=holder_did,
        credential_type=signing_credential_type,
        claims_json=json.dumps(clean_claims),
        expiration_seconds=31536000,
        organization_id=tx.organization_id,
        format=signing_format,
        selective_disclosure_claims=sd_claims_dc,
        zk_predicate_claims=tx.zk_predicate_claims or [],
        credential_payload_format=credential_payload_fmt,
    )

    # EUDI compliance: inject x5c header and HTTPS iss for SD-JWT credentials.
    if signing_format == "vc+sd-jwt":
        jwt_credential = postprocess_sd_jwt_x5c(
            jwt_credential, issuer_key, tx.organization_id, ISSUER_BASE_URL,
        )

    # Step 2: Pack into DIDComm v2 envelope
    didcomm_message_json = didcomm_pack_credential(
        credential=jwt_credential,
        credential_format=credential_payload_fmt,
        issuer_did=issuer_key["did"],
        holder_did=holder_did,
        credential_id=credential_id,
    )
    didcomm_msg = json.loads(didcomm_message_json)
    didcomm_message_id = didcomm_msg.get("id", "")

    # Step 3: Resolve holder DID → service endpoint
    did_doc = didcomm_resolve_did(holder_did, universal_resolver_url)
    service_endpoint = didcomm_extract_endpoint(did_doc)
    if not service_endpoint:
        raise HTTPException(
            status_code=422,
            detail=f"Holder DID {holder_did} has no DIDComm service endpoint",
        )

    # Step 3b: Encrypt if the holder has an X25519 key agreement key
    # (anoncrypt: ECDH-ES+A256KW + A256GCM per DIDComm v2 §4.1)
    delivery_content = didcomm_message_json
    delivery_content_type = "application/didcomm-plain+json"
    try:
        encrypted = didcomm_encrypt(didcomm_message_json, did_doc)
        delivery_content = encrypted
        delivery_content_type = "application/didcomm-encrypted+json"
        logger.info(f"DIDComm message encrypted for {holder_did}")
    except Exception as enc_err:
        # No key agreement key or encryption failure — fall back to plaintext
        logger.info(f"DIDComm encryption not available for {holder_did}, sending plaintext: {enc_err}")

    # Step 4: POST the DIDComm message to the holder's endpoint
    delivery_status = "delivered"
    delivery_error = None
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                service_endpoint,
                content=delivery_content,
                headers={"Content-Type": delivery_content_type},
            )
            if resp.status_code >= 400:
                delivery_status = "delivery_failed"
                delivery_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        delivery_status = "delivery_failed"
        delivery_error = str(e)

    # Update transaction state
    if delivery_status == "delivered" and tx.status != IssuanceStatus.ISSUED:
        tx.nonce = None
        tx.complete()
        await repo.save_transaction(tx)
        expires_at = (tx.issued_at or datetime.now(timezone.utc)) + timedelta(days=365)
        issued_credential = IssuedCredential(
            id=credential_id,
            transaction_id=tx.id,
            organization_id=tx.organization_id,
            credential_template_id=tx.credential_template_id,
            applicant_id=tx.applicant_id,
            subject_did=holder_did,
            credential_jwt=jwt_credential,
            credential_hash=hashlib.sha256(jwt_credential.encode("utf-8")).hexdigest(),
            status=CredentialStatus.ACTIVE,
            issued_at=tx.issued_at or datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        await repo.save_credential(issued_credential)
        await repo.save_event(IssuanceEvent(
            transaction_id=tx.id,
            application_id=tx.application_id,
            event_type=EventType.CREDENTIAL_ISSUED,
            metadata={
                "credential_id": credential_id,
                "credential_type": credential_type,
                "delivery_protocol": "didcomm_v2",
                "service_endpoint": service_endpoint,
            },
        ))

    return DidcommDeliveryResponse(
        transaction_id=tx.id,
        credential_id=credential_id,
        holder_did=holder_did,
        service_endpoint=service_endpoint,
        didcomm_message_id=didcomm_message_id,
        status=delivery_status,
        error=delivery_error,
    )


@issuance_router.post("/didcomm/deliver", response_model=DidcommDeliveryResponse, dependencies=[Depends(_verify_management_api_key)])
async def didcomm_deliver(
    request: DidcommDeliverRequest,
    repo: IIssuanceRepository = Depends(),
) -> DidcommDeliveryResponse:
    """Deliver a credential to a holder via DIDComm v2 push.

    Signs the credential, wraps it in a DIDComm v2 issue-credential/3.0
    message, resolves the holder's DID Document for their service endpoint,
    and POSTs the message.
    """
    tx = await repo.get_transaction(request.transaction_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if tx.status == IssuanceStatus.ISSUED:
        raise HTTPException(status_code=409, detail="Credential already issued")
    if tx.status not in (IssuanceStatus.PENDING, IssuanceStatus.AUTHORIZED):
        raise HTTPException(status_code=400, detail=f"Transaction in {tx.status.value} state")

    return await _didcomm_sign_and_deliver(
        tx=tx,
        holder_did=request.holder_did,
        repo=repo,
        universal_resolver_url=request.universal_resolver_url,
    )


@issuance_router.post("/didcomm/receive")
async def didcomm_receive(
    http_request: Request,
    repo: IIssuanceRepository = Depends(),
) -> JSONResponse:
    """Receive a DIDComm v2 message (acknowledgments, problem-reports, etc.).

    This is the **inbound** DIDComm endpoint — other agents POST messages
    here. Handles:
    - `https://didcomm.org/notification/1.0/ack` — delivery acknowledgment
    - `https://didcomm.org/report-problem/2.0/problem-report` — error report
    """
    body = await http_request.body()
    content_type = http_request.headers.get("content-type", "")

    if "didcomm-encrypted" in content_type:
        # For now, we don't decrypt inbound JWE — log and accept
        logger.info("Received encrypted DIDComm message (encrypted ack processing not yet supported)")
        return JSONResponse(status_code=202, content={"status": "accepted"})

    try:
        msg = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})

    msg_type = msg.get("type", "")
    msg_id = msg.get("id", "")
    thid = msg.get("thid", "")  # Thread ID — correlates to the original message

    if "ack" in msg_type or "notification" in msg_type:
        logger.info(f"DIDComm ack received: msg_id={msg_id} thid={thid}")
        # Record the ack as an event if we can find the transaction
        if thid:
            # Try to find a credential with this message ID
            # The thid should match the didcomm_message_id from delivery
            try:
                await repo.save_event(IssuanceEvent(
                    transaction_id=thid,
                    application_id=None,
                    event_type=EventType.CREDENTIAL_ISSUED,
                    metadata={
                        "didcomm_ack": True,
                        "ack_message_id": msg_id,
                        "original_message_id": thid,
                        "ack_from": msg.get("from", ""),
                    },
                ))
            except Exception as e:
                logger.warning(f"Could not record DIDComm ack event: {e}")

        return JSONResponse(
            status_code=200,
            content={"status": "acknowledged", "message_id": msg_id},
        )

    if "problem-report" in msg_type:
        problem_code = msg.get("body", {}).get("code", "unknown")
        problem_comment = msg.get("body", {}).get("comment", "")
        logger.warning(
            f"DIDComm problem-report: msg_id={msg_id} thid={thid} "
            f"code={problem_code} comment={problem_comment}"
        )
        return JSONResponse(
            status_code=200,
            content={"status": "received", "message_id": msg_id},
        )

    logger.info(f"DIDComm message received: type={msg_type} id={msg_id}")
    return JSONResponse(status_code=202, content={"status": "accepted", "message_id": msg_id})


@issuance_router.post("/deferred-credential")
async def deferred_credential(
    http_request: Request,
    authorization: str | None = Header(None),
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """OID4VCI-1FINAL §9.1 — Deferred Credential Endpoint.

    Accepts a transaction_id and returns the credential if it has been issued,
    or an appropriate status to indicate the credential is still pending.
    """
    if not authorization or not authorization.startswith("Bearer "):
        from fastapi.responses import JSONResponse as _JSONResponse
        return _JSONResponse(
            status_code=401,
            content={"error": "invalid_token", "error_description": "Bearer token required"},
        )
    body = await http_request.json()
    transaction_id = body.get("transaction_id")
    if not transaction_id:
        from fastapi.responses import JSONResponse as _JSONResponse
        return _JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "transaction_id is required"},
        )
    # Look up the transaction to check if it has been completed
    tx = await repo.get_transaction(transaction_id)
    if not tx:
        from fastapi.responses import JSONResponse as _JSONResponse
        return _JSONResponse(
            status_code=400,
            content={"error": "invalid_transaction_id", "error_description": "No transaction found for the given ID"},
        )
    # If credential was already issued, return it
    if tx.status == IssuanceStatus.ISSUED:
        existing_cred = await repo.get_credential_by_transaction_id(tx.id)
        if existing_cred:
            return {
                "credential": existing_cred.credential_jwt,
                "c_nonce": tx.nonce,
                "c_nonce_expires_in": 300,
            }
    # If still pending/authorized, indicate the credential is not yet ready
    if tx.status in (IssuanceStatus.PENDING, IssuanceStatus.AUTHORIZED):
        from fastapi.responses import JSONResponse as _JSONResponse
        return _JSONResponse(
            status_code=202,
            content={"transaction_id": transaction_id},
            headers={"Retry-After": "5"},
        )
    # For any other status (failed, revoked, etc.), the transaction is invalid
    from fastapi.responses import JSONResponse as _JSONResponse
    return _JSONResponse(
        status_code=400,
        content={"error": "invalid_transaction_id", "error_description": f"Transaction is in {tx.status.value} state"},
    )


@issuance_router.post("/notification", status_code=204)
async def notification_endpoint(
    http_request: Request,
    authorization: str | None = Header(None),
) -> None:
    """OID4VCI-1FINAL §11 — Notification Endpoint.

    Wallets POST here after credential lifecycle events (accepted, deleted, etc.).
    The server acknowledges with 204 No Content.
    Requires a valid Bearer token in the Authorization header.
    """
    if not authorization or not authorization.startswith("Bearer "):
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "Bearer token required"},
        )
    return None


@issuance_router.get("/offers/{tx_id}")
async def get_credential_offer(
    tx_id: str,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Get OID4VCI credential offer for a transaction."""
    tx = await repo.get_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Offer not found")
    
    if tx.is_expired:
        raise HTTPException(status_code=410, detail="Offer expired")
    
    # Delegate offer construction to Rust — no manual dict building in Python.
    import json as _json
    offer_json_str = oid4vci_create_credential_offer(
        issuer_url=org_issuer_url(tx.organization_id),
        credential_types=[tx.credential_type or "default"],
        pre_authorized_code=tx.pre_auth_code,
        user_pin_required=False,
    )
    return _json.loads(offer_json_str)


@issuance_router.get("/transactions", response_model=list[dict])
async def list_transactions(
    organization_id: str = Query(...),
    repo: IIssuanceRepository = Depends(),
) -> list[dict]:
    """List issuance transactions for an organization."""
    transactions = await repo.list_transactions(organization_id)
    return [
        {
            "id": tx.id,
            "organization_id": tx.organization_id,
            "credential_template_id": tx.credential_template_id,
            "applicant_id": tx.applicant_id,
            "application_id": tx.application_id,
            "subject_did": tx.subject_did,
            "status": tx.status.value,
            "created_at": tx.created_at.isoformat(),
        }
        for tx in transactions
    ]


@issuance_router.get("/transactions/{tx_id}")
async def get_transaction(
    tx_id: str,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Get a specific issuance transaction."""
    tx = await repo.get_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return {
        "id": tx.id,
        "organization_id": tx.organization_id,
        "credential_template_id": tx.credential_template_id,
        "applicant_id": tx.applicant_id,
        "subject_did": tx.subject_did,
        "status": tx.status.value,
        "created_at": tx.created_at.isoformat(),
        "expires_at": tx.expires_at.isoformat(),
        "issued_at": tx.issued_at.isoformat() if tx.issued_at else None,
        "revoked_at": tx.revoked_at.isoformat() if tx.revoked_at else None,
        "revocation_reason": tx.revocation_reason,
    }


class TransactionRevokeRequest(BaseModel):
    reason: str | None = None


@issuance_router.post("/transactions/{tx_id}/revoke", dependencies=[Depends(_verify_management_api_key)])
async def revoke_transaction(
    tx_id: str,
    request: TransactionRevokeRequest,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Revoke an issuance transaction (and its associated credential if present)."""
    tx = await repo.get_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if tx.status == IssuanceStatus.REVOKED:
        # Idempotent — already revoked, return current state
        return {
            "id": tx.id,
            "status": tx.status.value,
            "revoked_at": tx.revoked_at.isoformat() if tx.revoked_at else None,
            "revocation_reason": tx.revocation_reason,
        }

    tx.revoke(reason=request.reason)
    await repo.save_transaction(tx)

    logger.info(f"Revoked issuance transaction {tx_id}: {request.reason}")
    return {
        "id": tx.id,
        "status": tx.status.value,
        "revoked_at": tx.revoked_at.isoformat() if tx.revoked_at else None,
        "revocation_reason": tx.revocation_reason,
    }


@issuance_router.get("/transactions/{tx_id}/revocation-status")
async def get_transaction_revocation_status(
    tx_id: str,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Get the revocation status of an issuance transaction."""
    tx = await repo.get_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    is_revoked = tx.status == IssuanceStatus.REVOKED
    return {
        "id": tx.id,
        "revoked": is_revoked,
        "status": tx.status.value,
        "revoked_at": tx.revoked_at.isoformat() if tx.revoked_at else None,
        "revocation_reason": tx.revocation_reason,
    }


# ============================================================================
# Credential Lifecycle Management
# ============================================================================

async def _delegate_to_revocation_profile(
    credential_id: str,
    action: str,
    reason: str | None = None,
) -> dict:
    """Delegate revocation action to RevocationProfile service."""
    # Call RevocationProfile internal endpoint
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{REVOCATION_PROFILE_SERVICE_URL}/internal/revocation-profiles/default/process-revocation",
                json={
                    "credential_id": credential_id,
                    "action": action,
                    "credential_format": "sd_jwt",
                    "status_list_index": 0,
                    "reason": reason,
                },
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"RevocationProfile service error: {e}")
            raise HTTPException(
                status_code=503,
                detail="Revocation service unavailable"
            )


@issuance_router.post("/credentials/{credential_id}/revoke", response_model=CredentialStatusResponse, dependencies=[Depends(_verify_management_api_key)])
async def revoke_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Revoke a credential."""
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    if cred.status == CredentialStatus.REVOKED:
        raise HTTPException(status_code=400, detail="Credential already revoked")
    
    try:
        await _delegate_to_revocation_profile(
            credential_id=credential_id,
            action="revoke",
            reason=request.reason,
        )
    except HTTPException:
        logger.warning("RevocationProfile service unavailable, using local revocation")
    
    cred.status = CredentialStatus.REVOKED
    cred.status_updated_at = datetime.now(timezone.utc)
    cred.revoked = True
    cred.revoked_at = cred.status_updated_at
    cred.revocation_reason = request.reason
    await repo.save_credential(cred)
    
    logger.info(f"Revoked credential {credential_id}: {request.reason}")
    
    return {
        "id": cred.id,
        "status": cred.status.value,
        "status_updated_at": cred.status_updated_at.isoformat(),
        "reason": request.reason,
    }


@issuance_router.post("/credentials/{credential_id}/suspend", response_model=CredentialStatusResponse, dependencies=[Depends(_verify_management_api_key)])
async def suspend_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Suspend a credential temporarily."""
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    if cred.status == CredentialStatus.REVOKED:
        raise HTTPException(status_code=400, detail="Cannot suspend revoked credential")
    
    try:
        await _delegate_to_revocation_profile(
            credential_id=credential_id,
            action="suspend",
            reason=request.reason,
        )
    except HTTPException:
        logger.warning("RevocationProfile service unavailable, using local suspension")
    
    cred.status = CredentialStatus.SUSPENDED
    cred.status_updated_at = datetime.now(timezone.utc)
    await repo.save_credential(cred)
    
    logger.info(f"Suspended credential {credential_id}: {request.reason}")
    
    return {
        "id": cred.id,
        "status": cred.status.value,
        "status_updated_at": cred.status_updated_at.isoformat(),
        "reason": request.reason,
    }


@issuance_router.post("/credentials/{credential_id}/reinstate", response_model=CredentialStatusResponse, dependencies=[Depends(_verify_management_api_key)])
async def reinstate_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Reinstate a suspended credential."""
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    if cred.status == CredentialStatus.REVOKED:
        raise HTTPException(status_code=400, detail="Cannot reinstate revoked credential")
    
    if cred.status != CredentialStatus.SUSPENDED:
        raise HTTPException(status_code=400, detail="Only suspended credentials can be reinstated")
    
    try:
        await _delegate_to_revocation_profile(
            credential_id=credential_id,
            action="reinstate",
            reason=request.reason,
        )
    except HTTPException:
        logger.warning("RevocationProfile service unavailable, using local reinstatement")
    
    cred.status = CredentialStatus.ACTIVE
    cred.status_updated_at = datetime.now(timezone.utc)
    await repo.save_credential(cred)
    
    logger.info(f"Reinstated credential {credential_id}: {request.reason}")
    
    return {
        "id": cred.id,
        "status": cred.status.value,
        "status_updated_at": cred.status_updated_at.isoformat(),
        "reason": request.reason,
    }


@issuance_router.get("/credentials/{credential_id}/status", response_model=CredentialStatusResponse)
async def get_credential_status(
    credential_id: str,
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """Get current status of a credential."""
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    return {
        "id": cred.id,
        "status": cred.status.value,
        "status_updated_at": cred.status_updated_at.isoformat(),
        "reason": cred.revocation_reason,
    }


@issuance_router.get("/credentials", response_model=list[dict])
async def list_credentials(
    organization_id: str = Query(...),
    status: str = Query(None),
    repo: IIssuanceRepository = Depends(),
) -> list[dict]:
    """List all credentials for an organization with optional status filter."""
    creds = await repo.list_credentials_by_org(organization_id)
    
    if status:
        creds = [c for c in creds if c.status.value == status]
    
    return [
        {
            "id": c.id,
            "credential_template_id": c.credential_template_id,
            "applicant_id": c.applicant_id,
            "subject_did": c.subject_did,
            "status": c.status.value,
            "issued_at": c.issued_at.isoformat(),
            "status_updated_at": c.status_updated_at.isoformat(),
        }
        for c in creds
    ]


@issued_credential_router.get("", response_model=list[IssuedCredentialRecordResponse])
async def list_issued_credentials(
    organization_id: str = Query(...),
    status: str | None = Query(None),
    repo: IIssuanceRepository = Depends(),
) -> list[IssuedCredentialRecordResponse]:
    creds = await repo.list_credentials_by_org(organization_id)
    records = [await _issued_credential_to_protocol(cred, repo) for cred in creds]
    if status:
        normalized = status.upper()
        records = [record for record in records if record.status == normalized]
    return records


@issued_credential_router.get("/{credential_id}", response_model=IssuedCredentialRecordResponse)
async def get_issued_credential(
    credential_id: str,
    repo: IIssuanceRepository = Depends(),
) -> IssuedCredentialRecordResponse:
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Issued credential not found")
    return await _issued_credential_to_protocol(cred, repo)


@issued_credential_router.post("/{credential_id}/revoke", response_model=IssuedCredentialRecordResponse, dependencies=[Depends(_verify_management_api_key)])
async def revoke_issued_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> IssuedCredentialRecordResponse:
    await revoke_credential(credential_id, request, repo)
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Issued credential not found")
    return await _issued_credential_to_protocol(cred, repo)


@issued_credential_router.post("/{credential_id}/suspend", response_model=IssuedCredentialRecordResponse, dependencies=[Depends(_verify_management_api_key)])
async def suspend_issued_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> IssuedCredentialRecordResponse:
    await suspend_credential(credential_id, request, repo)
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Issued credential not found")
    return await _issued_credential_to_protocol(cred, repo)


@issued_credential_router.post("/{credential_id}/reinstate", response_model=IssuedCredentialRecordResponse, dependencies=[Depends(_verify_management_api_key)])
async def reinstate_issued_credential(
    credential_id: str,
    request: CredentialStatusRequest,
    repo: IIssuanceRepository = Depends(),
) -> IssuedCredentialRecordResponse:
    await reinstate_credential(credential_id, request, repo)
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Issued credential not found")
    return await _issued_credential_to_protocol(cred, repo)


# Continued in next part...
