"""OID4VCI HTTP API endpoints."""

import asyncio
import copy
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Form, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from issuance.application.canvas_issuance_guard import (
    CanvasIssuanceGuardError,
    require_canvas_issuance_ready,
)
from issuance.application.canvas_sync_service import record_canvas_credential_claim
from issuance.application.rust_integration import (
    create_sd_jwt_vc_with_remote_signing,
    oid4vci_create_credential_offer,
    oid4vci_create_token_response,
    oid4vci_create_authorization_response,
    oid4vci_exchange_auth_code_for_token,
    verify_proof_jwt,
    didcomm_resolve_did,
    didcomm_extract_endpoint,
    didcomm_pack_credential,
    didcomm_encrypt,
)
from issuance.infrastructure.api.signing_context import (
    resolve_remote_issuer_context,
    sign_payload_with_remote_service,
)
from issuance.domain.entities import (
    AuthorizationSession,
    CanvasPlatform,
    CanvasProgramBinding,
    CredentialDeliveryRecord,
    CredentialDeliveryStatus,
    DeliveryTarget,
    CredentialStatus,
    EventType,
    IssuanceEvent,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.domain.ports import IIssuanceRepository
from issuance.infrastructure.adapters.delivery_records import (
    canvas_delivery_feature_enabled,
    canvas_deployment_profile_delivery_metadata,
    normalize_delivery_mode,
    record_post_issuance_deliveries,
)
from issuance.infrastructure.adapters.canvas_credentials_adapter import (
    publish_canvas_credential_mirror,
    sync_canvas_credential_status,
)

logger = logging.getLogger(__name__)

_CANVAS_ISSUANCE_DENIAL = {
    "error": "invalid_credential_request",
    "error_description": "Credential eligibility requirements are not satisfied",
}


def _authorization_session_transaction_id(session_id: str) -> str:
    """Return the single canonical issuance transaction for an auth-code grant."""

    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"marty:oid4vci:authorization-session:{session_id}"))


async def _canvas_pre_signing_guard_response(
    *,
    tx: IssuanceTransaction,
    repo: IIssuanceRepository,
    resolved_issuer_context: dict[str, Any] | None = None,
) -> JSONResponse | None:
    """Return one sanitized denial for every Canvas authorization failure."""

    try:
        await require_canvas_issuance_ready(
            repo=repo,
            tx=tx,
            resolved_issuer_context=resolved_issuer_context,
        )
    except CanvasIssuanceGuardError as exc:
        logger.warning(
            "[credential] Canvas pre-signing guard denied tx_id=%s code=%s",
            tx.id,
            exc.code,
        )
        return JSONResponse(status_code=400, content=_CANVAS_ISSUANCE_DENIAL)
    except Exception:  # noqa: BLE001 - an unavailable guard dependency must deny
        logger.exception(
            "[credential] Canvas pre-signing guard failed tx_id=%s",
            tx.id,
        )
        return JSONResponse(status_code=400, content=_CANVAS_ISSUANCE_DENIAL)
    return None


@dataclass(frozen=True)
class CanvasMirrorTarget:
    platform: CanvasPlatform
    binding: CanvasProgramBinding

try:
    from marty_common import MARTY_DEFAULT_REVOCATION_PROFILE_ID
except Exception:  # pragma: no cover - local fallback for isolated issuance tests
    MARTY_DEFAULT_REVOCATION_PROFILE_ID = "70000000-0000-0000-0000-000000000001"

# Configuration — no localhost fallback; services must be explicitly configured.
REVOCATION_PROFILE_SERVICE_URL = os.environ.get("REVOCATION_PROFILE_SERVICE_URL", "")
CREDENTIAL_TEMPLATE_SERVICE_URL = os.environ.get("CREDENTIAL_TEMPLATE_SERVICE_URL", "")
if not REVOCATION_PROFILE_SERVICE_URL:
    logger.warning("REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail")
if not CREDENTIAL_TEMPLATE_SERVICE_URL:
    logger.warning("CREDENTIAL_TEMPLATE_SERVICE_URL not set — template calls will fail")
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

_MDOC_PAYLOAD_FORMATS = {"mso_mdoc", "mdoc"}
_VDS_NC_PAYLOAD_FORMATS = {"vds_nc", "vdsnc"}

# Staged-rollout flag — mirrors the one in main.py.  Set VDSNC_RUST_ENABLED=false
# to disable VDS-NC signing and return an error for VDS-NC credential requests.
_VDSNC_RUST_ENABLED: bool = os.environ.get("VDSNC_RUST_ENABLED", "true").lower() not in (
    "false", "0", "no", "off"
)
_SD_JWT_PAYLOAD_FORMATS = {
    "w3c_vcdm_v2_sd_jwt", "ietf_sd_jwt",
    "sd_jwt_vc", "vc+sd_jwt", "dc+sd_jwt",
}

_ISSUER_MODES = {"org_managed", "elevenid_managed", "elevenid_alias_for_org"}


def _normalize_issuer_mode(value: str | None) -> str:
    mode = (value or "org_managed").strip() or "org_managed"
    if mode not in _ISSUER_MODES:
        raise HTTPException(status_code=422, detail=f"Invalid issuer_mode '{mode}'. Must be one of {sorted(_ISSUER_MODES)}")
    return mode


def _normalize_payload_format(value: str | None) -> str:
    return (value or "").strip().lower().replace("-", "_")


def _credential_format_for_remote_context(payload_format: str | None, request_format: str | None = None) -> str:
    normalized_payload = _normalize_payload_format(payload_format)
    normalized_request = _normalize_payload_format(request_format)
    if normalized_payload in _MDOC_PAYLOAD_FORMATS:
        return "mso_mdoc"
    if normalized_payload in _VDS_NC_PAYLOAD_FORMATS:
        return "vds_nc"
    if normalized_request in {"jwt_vc_json", "jwt_vc"}:
        return "jwt_vc_json"
    return "dc+sd-jwt"


def _format_from_configuration_id(configuration_id: str | None) -> str | None:
    """Infer a request format alias from an OID4VCI credential configuration id."""
    normalized = (configuration_id or "").strip().lower()
    if not normalized:
        return None
    if normalized.endswith("#spruce-sd-jwt"):
        return "spruce-vc+sd-jwt"
    if normalized.endswith("#credential-manager"):
        return "dc+sd-jwt"
    if normalized.endswith("#sd-jwt"):
        # OID4VCI 1.0 SD-JWT VC configurations use the final media type.  The
        # older ``vc+sd-jwt`` spelling remains an internal payload alias only;
        # it must not escape in a wallet-facing response or JWT ``typ``.
        return "dc+sd-jwt"
    if normalized.endswith("#mdoc") or normalized.endswith("#apple-wallet"):
        return "mso_mdoc"
    if normalized.endswith("#vds-nc"):
        return "vds_nc"
    return None


def _default_request_format_for_payload(payload_format: str | None) -> str:
    normalized_payload = _normalize_payload_format(payload_format)
    if normalized_payload in _MDOC_PAYLOAD_FORMATS:
        return "mso_mdoc"
    if normalized_payload in _VDS_NC_PAYLOAD_FORMATS:
        return "vds_nc"
    if normalized_payload in _SD_JWT_PAYLOAD_FORMATS:
        return "vc+sd-jwt"
    return "jwt_vc_json"


def _effective_request_format(
    request: "CredentialRequest",
    tx: IssuanceTransaction | None = None,
) -> str:
    """Resolve the effective wallet-request format when ``format`` is omitted."""
    return (
        request.format
        or _format_from_configuration_id(request.credential_configuration_id)
        or _format_from_configuration_id(request.credential_identifier)
        or _default_request_format_for_payload(tx.credential_payload_format if tx else None)
    )


def _requests_legacy_credential_alias(request: "CredentialRequest") -> bool:
    """Whether a caller explicitly selected the pre-final response shape."""
    if request.credential_configuration_id or request.credential_identifier:
        return False
    return _normalize_payload_format(request.format) in {"vc+sd_jwt", "jwt_vc", "jwt_vc_json"}


def _key_purpose_for_credential_format(credential_format: str) -> str:
    if credential_format in {"mso_mdoc", "zk_mdoc"}:
        return "mdoc_dsc"
    if credential_format == "vds_nc":
        return "vdsnc_signing"
    return "vc_jwt_issuer"


def _unsupported_remote_signing_format_detail(signing_format: str, credential_format: str | None = None) -> str:
    """Return a fail-closed detail for formats without remote-signing support."""
    fmt = credential_format or signing_format
    return (
        "DID-backed remote signing currently supports SD-JWT VC issuance only. "
        f"Requested format {fmt!r} resolves to signing format {signing_format!r}, "
        "which requires remote COSE/VDS signing support before it can be issued safely."
    )


async def apply_remote_issuer_context(
    tx: IssuanceTransaction,
    *,
    credential_format: str | None = None,
    force: bool = False,
    raise_on_error: bool = False,
) -> dict[str, Any] | None:
    """Attach the org's active DID issuer profile to a transaction when available."""
    if not tx.organization_id:
        return None

    resolved_format = credential_format or _credential_format_for_remote_context(tx.credential_payload_format)
    try:
        context = await resolve_remote_issuer_context(
            tx.organization_id,
            issuer_profile_id=tx.issuer_profile_id,
            issuer_mode=_normalize_issuer_mode(tx.issuer_mode),
            credential_format=resolved_format,
            key_purpose=_key_purpose_for_credential_format(resolved_format),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unable to resolve remote issuer context for org=%s: %s", tx.organization_id, exc)
        if raise_on_error:
            raise
        return None

    if not context:
        return None

    resolved_issuer_did = context.get("issuer_did")
    resolved_service_id = context.get("signing_service_id")
    resolved_profile_id = context.get("issuer_profile_id") or (context.get("issuer_profile") or {}).get("id")
    resolved_issuer_mode = context.get("issuer_mode") or (context.get("issuer_profile") or {}).get("issuer_mode")
    if resolved_profile_id and resolved_profile_id != tx.issuer_profile_id:
        tx.issuer_profile_id = str(resolved_profile_id)
    if resolved_issuer_mode:
        tx.issuer_mode = _normalize_issuer_mode(str(resolved_issuer_mode))
    if resolved_issuer_did and resolved_issuer_did != tx.issuer_did_override:
        logger.info(
            "Resolved issuer DID for tx=%s org=%s format=%s: %s -> %s",
            tx.id,
            tx.organization_id,
            resolved_format,
            tx.issuer_did_override,
            resolved_issuer_did,
        )
        tx.issuer_did_override = resolved_issuer_did
    if resolved_service_id and resolved_service_id != tx.signing_service_id:
        logger.info(
            "Resolved signing service for tx=%s org=%s format=%s: %s -> %s",
            tx.id,
            tx.organization_id,
            resolved_format,
            tx.signing_service_id,
            resolved_service_id,
        )
        tx.signing_service_id = resolved_service_id
    return context


async def apply_required_remote_issuer_context(
    tx: IssuanceTransaction,
    *,
    credential_format: str | None = None,
) -> dict[str, Any]:
    """Resolve the exact KMS-backed issuer context or fail the issuance path.

    Integration-driven approval must never fall back to an in-process/default
    issuer.  The issuer profile, remote service, key reference and published DID
    verification method are one atomic readiness contract.
    """

    context = await apply_remote_issuer_context(
        tx,
        credential_format=credential_format,
        force=True,
        raise_on_error=True,
    )
    if not isinstance(context, dict):
        raise RuntimeError("An active KMS-backed issuer profile is required")

    profile = context.get("issuer_profile") if isinstance(context.get("issuer_profile"), dict) else {}
    required = {
        "issuer_profile_id": context.get("issuer_profile_id") or profile.get("id"),
        "issuer_did": context.get("issuer_did") or profile.get("issuer_did"),
        "signing_service_id": context.get("signing_service_id") or profile.get("signing_service_id"),
        "signing_key_reference": context.get("signing_key_reference") or profile.get("signing_key_reference"),
        "verification_method_id": context.get("verification_method_id") or profile.get("verification_method_id"),
    }
    missing = sorted(name for name, value in required.items() if not str(value or "").strip())
    if missing:
        raise RuntimeError(
            "KMS issuer context is incomplete: missing " + ", ".join(missing)
        )
    if profile and str(profile.get("status") or "").lower() != "active":
        raise RuntimeError("KMS issuer profile is not active")
    if tx.issuer_profile_id != str(required["issuer_profile_id"]):
        raise RuntimeError("Resolved issuer profile was not attached to the issuance transaction")
    if tx.issuer_did_override != str(required["issuer_did"]):
        raise RuntimeError("Resolved issuer DID was not attached to the issuance transaction")
    if tx.signing_service_id != str(required["signing_service_id"]):
        raise RuntimeError("Resolved signing service was not attached to the issuance transaction")
    return context


def _did_resolution_failure_detail(tx: IssuanceTransaction, exc: Exception) -> str:
    issuer_label = tx.issuer_did_override or "active issuer profile"
    return (
        f"DID resolution failed for issuer {issuer_label}: "
        f"remote signing key could not be resolved ({exc})"
    )


# Routers
issuance_router = APIRouter(prefix="/v1/issuance", tags=["issuance"])
application_template_router = APIRouter(prefix="/v1/application-templates", tags=["application-templates"])
internal_application_router = APIRouter(prefix="/internal/applications", tags=["internal-applications"])
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
_NONCE_POOL_TTL_SECONDS = 300


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
    issuer_profile_id: str | None = None
    issuer_mode: str = "org_managed"
    delivery_mode: str = "wallet_only"
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


class CredentialRenewalOfferResponse(BaseModel):
    source_credential_id: str
    transaction_id: str
    credential_offer_uri: str
    credential_offer_uris: dict[str, str] = {}
    credential_offer_labels: dict[str, str] = {}
    expires_at: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


class NonceResponse(BaseModel):
    c_nonce: str


class CredentialRequest(BaseModel):
    # OID4VCI §8 requires receivers to ignore extension parameters. The
    # official conformance suite deliberately adds one to verify this.
    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def reject_legacy_singular_proof(cls, value: Any) -> Any:
        """Reject the deprecated singular proof object without rejecting extensions."""
        if isinstance(value, dict) and "proof" in value:
            raise ValueError("use the OID4VCI 'proofs' object instead of legacy 'proof'")
        return value

    format: str | None = None
    # OID4VCI v1 §8.2: proofs is an object mapping proof_type -> list[str]
    proofs: dict[str, list[str]] | None = None
    # v1: identify credential by config id or credential_identifier from token response
    credential_configuration_id: str | None = None
    credential_identifier: str | None = None


class CredentialResponse(BaseModel):
    # Final OID4VCI uses ``credentials``. ``credential`` is retained only for
    # an explicit legacy-format request and omitted from final responses.
    credentials: list[str | dict]
    credential: str | None = None     # Walt.id / Draft-11 compatibility alias
    notification_id: str | None = None


class ApplicationFormField(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field_id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    label: str = Field(min_length=1, max_length=256)
    field_type: Literal[
        "TEXT", "DATE", "DATETIME", "SELECT", "FILE_UPLOAD",
        "INTEGER", "NUMBER", "BOOLEAN", "EMAIL", "URL",
    ]
    required: bool
    claim_mapping: str | None = None
    validation_pattern: str | None = None
    options: list[str] | None = None
    minimum: float | None = None
    maximum: float | None = None
    placeholder: str | None = None
    hint: str | None = None


class RequiredApplicationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_type: str = Field(min_length=1)
    is_required: bool = True
    order: int = Field(ge=1)
    config: dict[str, Any] = Field(default_factory=dict)
    external_provider: str | None = None


class ApplicationEvidenceRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    evidence_type: Literal[
        "DOCUMENT_SCAN", "BIOMETRIC", "SELFIE", "THIRD_PARTY_VERIFICATION",
        "EXTERNAL_FACT", "EXTERNAL_API",
    ]
    description: str
    required: bool
    accepted_formats: list[str] | None = None
    max_file_size_bytes: int | None = Field(default=None, ge=1)
    provider: str | None = None
    fact_type: str | None = None
    scope: dict[str, Any] | None = None
    pass_rule: dict[str, Any] | None = None
    verification_method: str | None = None
    freshness: dict[str, Any] | None = None
    manual_fallback: bool | None = None
    api: dict[str, Any] | None = None
    expected_response: dict[str, Any] | None = None
    response_mapping: dict[str, Any] | None = None
    auto_issue_on_permit: bool | None = None


class ClaimCollectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_name: str = Field(min_length=1)
    source: Literal["FORM_FIELD", "EVIDENCE_EXTRACTION", "EXTERNAL_API", "SYSTEM"]
    source_config: dict[str, Any] = Field(default_factory=dict)


class ApplicationTemplateCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    credential_template_id: str | None = None
    form_fields: list[ApplicationFormField] = Field(default_factory=list)
    evidence_requirements: list[ApplicationEvidenceRequirement] = Field(default_factory=list)
    claim_collection_rules: list[ClaimCollectionRule] = Field(default_factory=list)
    required_checks: list[RequiredApplicationCheck] = Field(default_factory=list)
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] = "MANUAL"
    approval_policy_set_id: str | None = None
    application_validity_days: int = Field(default=30, ge=1, le=3650)
    ui_config: dict[str, Any] = Field(default_factory=dict)
    notification_config: dict[str, Any] = Field(default_factory=dict)


class ApplicationTemplatePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    credential_template_id: str | None = None
    form_fields: list[ApplicationFormField] | None = None
    evidence_requirements: list[ApplicationEvidenceRequirement] | None = None
    claim_collection_rules: list[ClaimCollectionRule] | None = None
    required_checks: list[RequiredApplicationCheck] | None = None
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] | None = None
    approval_policy_set_id: str | None = None
    application_validity_days: int | None = Field(default=None, ge=1, le=3650)
    ui_config: dict[str, Any] | None = None
    notification_config: dict[str, Any] | None = None


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
    evidence_requirements: list[Any]
    claim_collection_rules: list[dict[str, Any]]
    required_checks: list[dict[str, Any]]
    approval_strategy: str
    approval_policy_set_id: str | None = None
    application_validity_days: int
    ui_config: dict[str, Any]
    notification_config: dict[str, Any]
    status: str
    created_at: str
    updated_at: str


class ApplicationCreate(BaseModel):
    application_template_id: str
    applicant_data: dict[str, Any]
    integration_context: dict[str, Any] = {}


class ApplicationResponse(BaseModel):
    id: str
    organization_id: str
    application_template_id: str
    applicant_identifier: str
    form_data: dict[str, Any]
    evidence_submissions: list[dict[str, Any]]
    integration_context: dict[str, Any] = {}
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
    model_config = ConfigDict(extra="forbid")

    review_notes: str | None = None


class ApplicationRejection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_notes: str


class CredentialStatusRequest(BaseModel):
    reason: str | None = None


class CredentialStatusResponse(BaseModel):
    id: str
    issuer_did: str | None = None
    status: str
    status_updated_at: str
    reason: str | None = None


class IssuedCredentialStatusListEntryResponse(BaseModel):
    status_list_id: str
    index: int
    status_list_uri: str | None = None
    type: str | None = None
    status_purpose: str | None = None
    status_list_credential: str | None = None


class CredentialDeliveryRecordResponse(BaseModel):
    id: str
    delivery_target: str
    delivery_mode: str
    status: str
    canvas_account_id: str | None = None
    external_credential_id: str | None = None
    external_issuer_id: str | None = None
    last_error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class CanvasMirrorBatchProcessResponse(BaseModel):
    delivery_target: str = "canvas_credentials"
    organization_id: str | None = None
    retry_failed: bool = False
    processed_count: int = 0
    delivered_count: int = 0
    failed_count: int = 0
    blocked_count: int = 0
    metrics: dict[str, int] = Field(default_factory=dict)
    records: list[CredentialDeliveryRecordResponse] = Field(default_factory=list)


class CanvasMirrorStatusSyncBatchResponse(BaseModel):
    delivery_target: str = "canvas_credentials"
    organization_id: str | None = None
    processed_count: int = 0
    synced_count: int = 0
    failed_count: int = 0
    blocked_count: int = 0
    metrics: dict[str, int] = Field(default_factory=dict)
    records: list[CredentialDeliveryRecordResponse] = Field(default_factory=list)


class CanvasMirrorAutomationCycleResponse(BaseModel):
    delivery_target: str = "canvas_credentials"
    organization_id: str | None = None
    retry_failed: bool = True
    publish: CanvasMirrorBatchProcessResponse
    status_sync: CanvasMirrorStatusSyncBatchResponse
    processed_count: int = 0
    failed_count: int = 0
    blocked_count: int = 0
    metrics: dict[str, int] = Field(default_factory=dict)
    started_at: str
    completed_at: str


class CanvasMirrorAlertResponse(BaseModel):
    alert_type: str
    severity: str
    delivery_record_id: str
    credential_id: str
    transaction_id: str
    canvas_account_id: str | None = None
    attempt_count: int = 0
    last_error: str | None = None
    last_error_at: str | None = None
    message: str
    recommended_action: str


class CanvasMirrorHealthResponse(BaseModel):
    organization_id: str
    pending_publish_count: int = 0
    failed_publish_count: int = 0
    delivered_count: int = 0
    lifecycle_sync_failed_count: int = 0
    lifecycle_sync_ok_count: int = 0
    repeated_publish_failure_count: int = 0
    repeated_lifecycle_sync_failure_count: int = 0
    warning_alert_count: int = 0
    critical_alert_count: int = 0
    alert_count: int = 0
    alert_thresholds: dict[str, int] = Field(default_factory=dict)
    metrics: dict[str, int] = Field(default_factory=dict)
    alerts: list[CanvasMirrorAlertResponse] = Field(default_factory=list)
    last_successful_publish_at: str | None = None
    last_lifecycle_sync_failure_at: str | None = None
    last_lifecycle_sync_success_at: str | None = None


class CanvasMirrorProvenanceResponse(BaseModel):
    delivery_record_id: str
    organization_id: str
    canvas_account_id: str | None = None
    mirror: dict[str, Any]
    canonical_credential: dict[str, Any]
    canonical_issuance: dict[str, Any]
    issuer: dict[str, Any]
    trust_basis: dict[str, Any]
    delivery_record: CredentialDeliveryRecordResponse


class IssuedCredentialRecordResponse(BaseModel):
    id: str
    organization_id: str
    credential_id: str
    credential_type: str
    credential_format: str
    flow_execution_id: str
    credential_template_id: str
    application_id: str | None = None
    revocation_profile_id: str | None = None
    renewed_from_credential_id: str | None = None
    renewed_to_credential_id: str | None = None
    renewable: bool = False
    renewal_eligible_at: str | None = None
    can_renew: bool = False
    subject_id: str
    subject_claims_hash: str | None = None
    issued_at: str
    valid_from: str | None = None
    valid_until: str | None = None
    status: str
    status_list_entries: list[IssuedCredentialStatusListEntryResponse] = Field(default_factory=list)
    credential_hash: str | None = None
    deliveries: list[CredentialDeliveryRecordResponse] = Field(default_factory=list)
    revoked_at: str | None = None
    revocation_reason: str | None = None
    issuer_did: str | None = None
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


def _allowed_credential_issuer_audience_paths(org_id: str) -> tuple[str, ...]:
    """Credential issuer URL paths accepted in holder proof JWT audiences."""
    return (
        f"/org/{org_id}",
        f"/org/{org_id}/spruce",
        f"/org/{org_id}/credential-manager",
        f"/org/{org_id}/apple-wallet",
        f"/org/{org_id}/waltid",
    )


def _proof_audience_matches_org_issuer(audience: str | None, org_id: str) -> bool:
    """Return True when a proof JWT aud matches a supported per-org issuer URL."""
    normalized = (audience or "").strip().rstrip("/")
    if not normalized:
        return False

    parsed = urlparse(normalized)
    candidate_path = (parsed.path if (parsed.scheme or parsed.netloc) else normalized).rstrip("/")
    allowed_paths = _allowed_credential_issuer_audience_paths(org_id)
    return any(candidate_path == path or candidate_path.endswith(path) for path in allowed_paths)


def _credential_status_to_protocol(status: CredentialStatus, expires_at: datetime | None) -> str:
    if status == CredentialStatus.ACTIVE and expires_at and expires_at < datetime.now(timezone.utc):
        return "EXPIRED"
    return status.value.upper()


def _credential_format_to_protocol(tx: IssuanceTransaction | None, cred: IssuedCredential) -> str:
    payload_format = _normalize_payload_format(tx.credential_payload_format if tx else None)
    if payload_format in _MDOC_PAYLOAD_FORMATS:
        return "MDOC"
    if payload_format in _VDS_NC_PAYLOAD_FORMATS:
        return "VDS_NC"
    return "SD_JWT_VC"


def _default_revocation_profile_id() -> str:
    return (
        os.environ.get("MARTY_DEFAULT_REVOCATION_PROFILE_ID")
        or os.environ.get("REVOCATION_PROFILE_ID")
        or MARTY_DEFAULT_REVOCATION_PROFILE_ID
    )


def _credential_format_for_revocation_profile(tx: IssuanceTransaction | None, request_format: str | None = None) -> str:
    payload_format = _normalize_payload_format(tx.credential_payload_format if tx else None)
    normalized_request = _normalize_payload_format(request_format)
    if payload_format in _MDOC_PAYLOAD_FORMATS or normalized_request in _MDOC_PAYLOAD_FORMATS:
        return "mdoc"
    return "sd_jwt_vc"


def _status_list_entries_to_protocol(
    entries: list[dict[str, Any]] | None,
) -> list[IssuedCredentialStatusListEntryResponse]:
    result: list[IssuedCredentialStatusListEntryResponse] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        status_list_id = entry.get("status_list_id") or entry.get("revocation_profile_id")
        index = entry.get("index")
        if status_list_id is None or index is None:
            continue
        result.append(
            IssuedCredentialStatusListEntryResponse(
                status_list_id=str(status_list_id),
                index=int(index),
                status_list_uri=entry.get("status_list_uri") or entry.get("statusListCredential"),
                type=entry.get("type"),
                status_purpose=entry.get("status_purpose") or entry.get("statusPurpose"),
                status_list_credential=entry.get("status_list_credential") or entry.get("statusListCredential"),
            )
        )
    return result


def _status_list_entry_to_credential_status_claim(entry: dict[str, Any]) -> dict[str, Any]:
    status_list_uri = str(entry.get("status_list_uri") or entry.get("status_list_credential") or "")
    status_purpose = str(entry.get("status_purpose") or "revocation")
    index = int(entry.get("index") or 0)
    status_entry = {
        "id": f"{status_list_uri}#{index}" if status_list_uri else f"urn:marty:status-list-entry:{index}",
        "type": entry.get("type") or "BitstringStatusListEntry",
        "statusPurpose": status_purpose,
        "statusListIndex": str(index),
        "statusListCredential": status_list_uri,
    }
    return status_entry


def _status_list_entries_to_credential_status_claim(entries: list[dict[str, Any]]) -> list[dict[str, Any]] | dict[str, Any] | None:
    claims = [_status_list_entry_to_credential_status_claim(entry) for entry in entries if isinstance(entry, dict)]
    if not claims:
        return None
    if len(claims) == 1:
        return claims[0]
    return claims


def _revocation_index_from_credential(credential: IssuedCredential) -> int | None:
    for entry in credential.status_list_entries or []:
        if not isinstance(entry, dict):
            continue
        purpose = str(entry.get("status_purpose") or entry.get("statusPurpose") or "revocation")
        if purpose != "revocation":
            continue
        index = entry.get("index")
        if index is not None:
            return int(index)
    return None


async def _allocate_credential_status_list_entries(
    *,
    credential_id: str,
    organization_id: str,
    credential_format: str,
    revocation_profile_id: str | None = None,
) -> tuple[str | None, list[dict[str, Any]]]:
    profile_id = (revocation_profile_id or "").strip()
    if not profile_id:
        raise HTTPException(
            status_code=422,
            detail="The Credential Template has no Revocation Profile.",
        )
    service_url = (
        os.environ.get("REVOCATION_PROFILE_SERVICE_URL", REVOCATION_PROFILE_SERVICE_URL) or ""
    ).strip().rstrip("/")
    if not service_url:
        raise HTTPException(
            status_code=503,
            detail="Revocation Profile service is unavailable.",
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{service_url}/internal/revocation-profiles/{profile_id}/allocate-index",
                json={
                    "organization_id": organization_id,
                    "credential_format": credential_format,
                },
            )
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Status-list allocation failed for credential %s via profile %s: %s",
            credential_id,
            profile_id,
            exc,
        )
        raise HTTPException(
            status_code=503,
            detail="Credential status allocation failed.",
        ) from exc

    index = payload.get("index")
    status_list_url = payload.get("status_list_url")
    response_organization_id = payload.get("organization_id")
    if response_organization_id != organization_id:
        logger.error(
            "Status-list allocation organization mismatch for credential %s: expected=%s actual=%s",
            credential_id,
            organization_id,
            response_organization_id,
        )
        raise HTTPException(
            status_code=503,
            detail="Credential status allocation returned the wrong organization.",
        )
    if index is None or not status_list_url:
        logger.warning(
            "Status-list allocation response for credential %s was incomplete: %s",
            credential_id,
            payload,
        )
        raise HTTPException(
            status_code=503,
            detail="Credential status allocation returned an incomplete response.",
        )

    return profile_id, [
        {
            "status_list_id": profile_id,
            "index": int(index),
            "status_list_uri": str(status_list_url),
            "status_list_credential": str(status_list_url),
            "type": "BitstringStatusListEntry" if credential_format != "mdoc" else "TokenStatusListEntry",
            "status_purpose": "revocation",
        }
    ]


async def _require_active_revocation_profile_binding(
    *,
    organization_id: str,
    revocation_profile_id: str | None,
) -> None:
    profile_id = str(revocation_profile_id or "").strip()
    if not profile_id:
        raise HTTPException(
            status_code=422,
            detail="Credential Templates must reference an active Revocation Profile before issuance.",
        )

    import grpc
    from marty_proto.v1 import revocation_profile_service_pb2 as rp_pb2
    from marty_proto.v1 import revocation_profile_service_pb2_grpc as rp_grpc

    target = os.environ.get("RP_GRPC_TARGET", "revocation-profile:9013")
    try:
        async with grpc.aio.insecure_channel(target) as channel:
            response = await rp_grpc.RevocationProfileServiceStub(channel).GetRevocationProfile(
                rp_pb2.GetRevocationProfileRequest(profile_id=profile_id),
                timeout=3.0,
            )
    except grpc.aio.AioRpcError as exc:
        if exc.code() == grpc.StatusCode.NOT_FOUND:
            raise HTTPException(status_code=422, detail="Revocation Profile not found.") from exc
        raise HTTPException(status_code=503, detail="Revocation Profile validation is unavailable.") from exc

    if response.organization_id != organization_id:
        raise HTTPException(
            status_code=422,
            detail="The Revocation Profile belongs to another organization.",
        )
    if str(response.status or "").strip().lower() != "active":
        raise HTTPException(
            status_code=422,
            detail="Credential Templates must reference an active Revocation Profile before issuance.",
        )


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
    delivery_records = await repo.list_delivery_records_for_credential(cred.id)
    subject_id = cred.subject_did or cred.applicant_id or (tx.subject_did if tx else None) or (tx.applicant_id if tx else None) or cred.id
    issued_at = cred.issued_at
    valid_until = cred.expires_at
    protocol_status = _credential_status_to_protocol(cred.status, valid_until)
    credential_type = (tx.credential_type if tx and tx.credential_type else "unknown")
    updated_at = cred.status_updated_at if cred.status_updated_at else cred.issued_at
    renewal_eligible_at = (
        valid_until - timedelta(days=tx.renewal_window_days)
        if tx and tx.renewable and valid_until
        else None
    )
    return IssuedCredentialRecordResponse(
        id=cred.id,
        organization_id=cred.organization_id,
        credential_id=cred.id,
        credential_type=credential_type,
        credential_format=_credential_format_to_protocol(tx, cred),
        flow_execution_id=cred.transaction_id,
        credential_template_id=cred.credential_template_id,
        application_id=tx.application_id if tx else None,
        revocation_profile_id=cred.revocation_profile_id,
        renewed_from_credential_id=cred.renewed_from_credential_id,
        renewed_to_credential_id=cred.renewed_to_credential_id,
        renewable=bool(tx and tx.renewable),
        renewal_eligible_at=renewal_eligible_at.isoformat() if renewal_eligible_at else None,
        can_renew=bool(
            tx
            and tx.renewable
            and renewal_eligible_at
            and datetime.now(timezone.utc) >= renewal_eligible_at
            and cred.status == CredentialStatus.ACTIVE
            and not cred.renewed_to_credential_id
        ),
        subject_id=subject_id,
        subject_claims_hash=_subject_claims_hash(tx),
        issued_at=issued_at.isoformat(),
        valid_from=issued_at.isoformat(),
        valid_until=valid_until.isoformat() if valid_until else None,
        status=protocol_status,
        status_list_entries=_status_list_entries_to_protocol(cred.status_list_entries),
        credential_hash=cred.credential_hash,
        deliveries=[_delivery_record_to_protocol(record) for record in delivery_records],
        revoked_at=cred.revoked_at.isoformat() if cred.revoked_at else None,
        revocation_reason=cred.revocation_reason,
        issuer_did=cred.issuer_did or (tx.issuer_did_override if tx else None),
        revoked_by=None,
        created_at=issued_at.isoformat(),
        updated_at=updated_at.isoformat() if updated_at else None,
    )


def _delivery_record_to_protocol(record: CredentialDeliveryRecord) -> CredentialDeliveryRecordResponse:
    return CredentialDeliveryRecordResponse(
        id=record.id,
        delivery_target=record.delivery_target.value,
        delivery_mode=record.delivery_mode,
        status=record.status.value,
        canvas_account_id=record.canvas_account_id,
        external_credential_id=record.external_credential_id,
        external_issuer_id=record.external_issuer_id,
        last_error=record.last_error,
        metadata=record.metadata,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
    )


def _subject_id_hash(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _public_canvas_metadata(record: CredentialDeliveryRecord) -> dict[str, Any]:
    metadata = record.metadata or {}
    allowed_keys = {
        "published_at",
        "publish_attempts",
        "request_id",
        "canvas_response_status",
        "last_attempted_at",
        "status_synced_at",
        "status_sync_attempts",
        "last_status_sync_action",
        "last_status_sync_attempted_at",
        "last_status_sync_error",
        "last_status_sync_error_at",
        "last_synced_credential_status",
    }
    return {key: metadata.get(key) for key in allowed_keys if key in metadata}


def _canvas_mirror_record_matches(
    record: CredentialDeliveryRecord,
    *,
    canvas_account_id: str | None = None,
    organization_id: str | None = None,
) -> bool:
    if record.delivery_target != DeliveryTarget.CANVAS_CREDENTIALS:
        return False
    if canvas_account_id is not None and record.canvas_account_id != canvas_account_id:
        return False
    if organization_id is not None and record.organization_id != organization_id:
        return False
    return True


async def _resolve_canvas_mirror_delivery_record(
    *,
    repo: IIssuanceRepository,
    delivery_record_id: str | None = None,
    external_credential_id: str | None = None,
    credential_id: str | None = None,
    canvas_account_id: str | None = None,
    organization_id: str | None = None,
) -> CredentialDeliveryRecord:
    if not any([delivery_record_id, external_credential_id, credential_id]):
        raise HTTPException(
            status_code=400,
            detail="Provide delivery_record_id, external_credential_id, or credential_id",
        )

    record: CredentialDeliveryRecord | None = None
    if delivery_record_id:
        record = await repo.get_delivery_record(delivery_record_id)
        if record is not None and not _canvas_mirror_record_matches(
            record,
            canvas_account_id=canvas_account_id,
            organization_id=organization_id,
        ):
            record = None
    elif external_credential_id:
        record = await repo.get_canvas_delivery_record_by_external_credential_id(
            external_credential_id,
            canvas_account_id=canvas_account_id,
            organization_id=organization_id,
        )
    elif credential_id:
        records = await repo.list_delivery_records_for_credential(credential_id)
        record = next(
            (
                candidate
                for candidate in records
                if _canvas_mirror_record_matches(
                    candidate,
                    canvas_account_id=canvas_account_id,
                    organization_id=organization_id,
                )
            ),
            None,
        )

    if record is None:
        raise HTTPException(status_code=404, detail="Canvas mirror delivery record not found")
    return record


async def _canvas_mirror_provenance_to_protocol(
    record: CredentialDeliveryRecord,
    repo: IIssuanceRepository,
) -> CanvasMirrorProvenanceResponse:
    credential = await repo.get_credential(record.credential_id)
    if credential is None:
        raise HTTPException(status_code=409, detail="Canonical issued credential not found for Canvas mirror record")
    transaction = await repo.get_transaction(record.transaction_id)
    subject_id = (
        credential.subject_did
        or credential.applicant_id
        or (transaction.subject_did if transaction else None)
        or (transaction.applicant_id if transaction else None)
    )
    credential_status = _credential_status_to_protocol(credential.status, credential.expires_at)
    issuer_did = credential.issuer_did or (transaction.issuer_did_override if transaction else None)
    credential_format = _credential_format_to_protocol(transaction, credential)
    organization_consistent = (
        credential.organization_id == record.organization_id
        and (transaction is None or transaction.organization_id == record.organization_id)
    )

    return CanvasMirrorProvenanceResponse(
        delivery_record_id=record.id,
        organization_id=record.organization_id,
        canvas_account_id=record.canvas_account_id,
        mirror={
            "provider": "canvas",
            "delivery_target": record.delivery_target.value,
            "delivery_status": record.status.value,
            "delivery_mode": record.delivery_mode,
            "external_credential_id": record.external_credential_id,
            "external_issuer_id": record.external_issuer_id,
            "metadata": _public_canvas_metadata(record),
            "last_error": record.last_error,
        },
        canonical_credential={
            "credential_id": credential.id,
            "credential_template_id": credential.credential_template_id,
            "credential_format": credential_format,
            "credential_status": credential_status,
            "credential_hash": credential.credential_hash,
            "revocation_profile_id": credential.revocation_profile_id,
            "status_list_entries": [
                entry.model_dump(exclude_none=True)
                for entry in _status_list_entries_to_protocol(credential.status_list_entries)
            ],
            "subject_id_hash": _subject_id_hash(subject_id),
            "issued_at": credential.issued_at.isoformat(),
            "valid_until": credential.expires_at.isoformat() if credential.expires_at else None,
            "status_updated_at": credential.status_updated_at.isoformat(),
            "revocation_reason": credential.revocation_reason,
        },
        canonical_issuance={
            "transaction_id": credential.transaction_id,
            "application_id": transaction.application_id if transaction else None,
            "credential_type": transaction.credential_type if transaction else "unknown",
            "delivery_mode": transaction.delivery_mode if transaction else record.delivery_mode,
        },
        issuer={
            "issuer_did": issuer_did,
            "issuer_profile_id": transaction.issuer_profile_id if transaction else None,
            "issuer_mode": transaction.issuer_mode if transaction else None,
            "credential_issuer_url": org_issuer_url(record.organization_id),
        },
        trust_basis={
            "canonical_issuance_backed": True,
            "mirror_backed_by_delivery_record": True,
            "organization_consistent": organization_consistent,
            "distribution_channel": "canvas_credentials",
            "status_source": "canonical_credential_status",
            "credential_status": credential_status,
            "issuer_trust_anchor": issuer_did,
        },
        delivery_record=_delivery_record_to_protocol(record),
    )


def _next_canvas_publish_metadata(
    record: CredentialDeliveryRecord,
    attempted_at: datetime,
) -> dict[str, Any]:
    return {
        **(record.metadata or {}),
        "publish_attempts": int((record.metadata or {}).get("publish_attempts") or 0) + 1,
        "last_attempted_at": attempted_at.isoformat(),
    }


async def _hydrate_canvas_gate_metadata(
    record: CredentialDeliveryRecord,
    transaction: IssuanceTransaction | None,
    repo: IIssuanceRepository,
) -> None:
    if not transaction or not transaction.application_id:
        return
    existing = record.metadata or {}
    if existing.get("deployment_profile_id") and existing.get("canvas_feature_flags"):
        return
    app = await repo.get_application(transaction.application_id)
    profile_metadata = canvas_deployment_profile_delivery_metadata(app)
    if profile_metadata:
        record.metadata = {
            **existing,
            **profile_metadata,
        }


def _metadata_text(metadata: dict[str, Any] | None, key: str) -> str | None:
    value = (metadata or {}).get(key)
    if value is None or not str(value).strip():
        return None
    return str(value).strip()


async def _resolve_canvas_mirror_target(
    record: CredentialDeliveryRecord,
    transaction: IssuanceTransaction | None,
    repo: IIssuanceRepository,
) -> tuple[CanvasMirrorTarget | None, str | None]:
    await _hydrate_canvas_gate_metadata(record, transaction, repo)
    binding_id = _metadata_text(record.metadata, "canvas_program_binding_id")
    if not binding_id:
        return None, "Canvas mirror delivery record is missing canvas_program_binding_id"

    binding = await repo.get_canvas_program_binding(binding_id)
    if binding is None:
        return None, f"Canvas program binding {binding_id} was not found"
    if not binding.enabled:
        return None, f"Canvas program binding {binding_id} is disabled"
    if binding.canvas_credentials:
        record.metadata = {
            **(record.metadata or {}),
            "canvas_credentials": dict(binding.canvas_credentials),
        }

    platform = await repo.get_canvas_platform(binding.platform_id)
    if platform is None:
        return None, f"Canvas platform {binding.platform_id} was not found"
    if not platform.enabled:
        return None, f"Canvas platform {binding.platform_id} is disabled"

    record.canvas_account_id = platform.canvas_account_id
    record.metadata = {
        **(record.metadata or {}),
        "canvas_platform_id": platform.id,
        "canvas_program_binding_id": binding.id,
    }
    return CanvasMirrorTarget(platform=platform, binding=binding), None


def _canvas_gate_blocked_error(flag: str) -> str:
    if flag == "enable_canvas_mirror_ops":
        return "Canvas mirror operations are disabled by deployment profile"
    labels = {
        "enable_canvas_mirror_publish": "Canvas mirror publish",
    }
    return f"{labels.get(flag, flag)} is disabled by deployment profile"


def _canvas_gate_blocked_metadata(
    record: CredentialDeliveryRecord,
    *,
    flag: str,
    blocked_at: datetime,
) -> dict[str, Any]:
    return {
        **(record.metadata or {}),
        "canvas_feature_gate_blocked": True,
        "canvas_feature_gate": flag,
        "canvas_feature_gate_blocked_at": blocked_at.isoformat(),
        "retryable": False,
    }


def _canvas_delivery_failure_status_code(error_detail: str | None) -> int:
    detail = (error_detail or "").lower()
    if any(token in detail for token in ("missing", "not found", "disabled", "no canvas mirror")):
        return 409
    return 502


def _parse_iso_datetime(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _max_iso_datetime(values: list[Any]) -> str | None:
    parsed_values = [parsed for value in values if (parsed := _parse_iso_datetime(value)) is not None]
    if not parsed_values:
        return None
    return max(parsed_values).isoformat()


def _delivery_record_has_status_sync_failure(record: CredentialDeliveryRecord) -> bool:
    return bool((record.metadata or {}).get("last_status_sync_error"))


def _metadata_int(metadata: dict[str, Any] | None, key: str) -> int:
    try:
        return int((metadata or {}).get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _canvas_mirror_alert_for_record(
    record: CredentialDeliveryRecord,
    *,
    alert_type: str,
    attempt_key: str,
    error_at_key: str,
    warning_threshold: int,
    critical_threshold: int,
) -> CanvasMirrorAlertResponse | None:
    metadata = record.metadata or {}
    attempt_count = _metadata_int(metadata, attempt_key)
    if attempt_count < warning_threshold:
        return None

    severity = "critical" if attempt_count >= critical_threshold else "warning"
    is_publish = alert_type == "publish_failure"
    action = (
        "Check Canvas Credentials publish configuration and rerun the Canvas mirror automation cycle."
        if is_publish
        else "Check Canvas Credentials lifecycle status sync configuration and rerun failed status syncs."
    )
    noun = "publish" if is_publish else "lifecycle status sync"
    return CanvasMirrorAlertResponse(
        alert_type=alert_type,
        severity=severity,
        delivery_record_id=record.id,
        credential_id=record.credential_id,
        transaction_id=record.transaction_id,
        canvas_account_id=record.canvas_account_id,
        attempt_count=attempt_count,
        last_error=record.last_error or metadata.get("last_status_sync_error"),
        last_error_at=metadata.get(error_at_key),
        message=f"Canvas mirror {noun} has failed {attempt_count} times for delivery record {record.id}.",
        recommended_action=action,
    )


def _canvas_mirror_alert_to_dict(alert: CanvasMirrorAlertResponse) -> dict[str, Any]:
    if hasattr(alert, "model_dump"):
        return alert.model_dump()
    return alert.dict()


def _canvas_mirror_publish_metrics(
    *,
    processed_count: int,
    delivered_count: int,
    failed_count: int,
    blocked_count: int,
) -> dict[str, int]:
    return {
        "publish.processed": processed_count,
        "publish.delivered": delivered_count,
        "publish.failed": failed_count,
        "publish.blocked": blocked_count,
    }


def _canvas_mirror_status_sync_metrics(
    *,
    processed_count: int,
    synced_count: int,
    failed_count: int,
    blocked_count: int,
) -> dict[str, int]:
    return {
        "status_sync.processed": processed_count,
        "status_sync.synced": synced_count,
        "status_sync.failed": failed_count,
        "status_sync.blocked": blocked_count,
        "status_sync.retry_outcomes": processed_count,
        "status_sync.retry_succeeded": synced_count,
        "status_sync.retry_failed": failed_count,
        "status_sync.retry_blocked": blocked_count,
    }


def _log_canvas_mirror_metrics(
    *,
    operation: str,
    organization_id: str | None,
    metrics: dict[str, int],
) -> None:
    logger.info(
        "canvas_mirror_metrics",
        extra={
            "mip_event": "canvas_mirror_metrics",
            "canvas_mirror_operation": operation,
            "organization_id": organization_id,
            "metrics": metrics,
        },
    )


async def _post_canvas_mirror_alert_webhook(
    *,
    organization_id: str,
    alerts: list[CanvasMirrorAlertResponse],
) -> None:
    webhook_url = (os.environ.get("CANVAS_MIRROR_ALERT_WEBHOOK_URL") or "").strip()
    if not webhook_url or not alerts:
        return
    timeout_seconds = float(os.environ.get("CANVAS_MIRROR_ALERT_WEBHOOK_TIMEOUT_SECONDS", "5"))
    payload = {
        "event": "canvas_mirror_critical_alert",
        "organization_id": organization_id,
        "alerts": [_canvas_mirror_alert_to_dict(alert) for alert in alerts],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=max(1.0, min(timeout_seconds, 20.0))) as client:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Canvas mirror alert webhook failed for organization=%s: %s",
            organization_id,
            exc,
        )


async def _emit_canvas_mirror_alert_observability(
    *,
    repo: IIssuanceRepository,
    organization_id: str | None,
    alerts: list[CanvasMirrorAlertResponse],
) -> None:
    if not alerts:
        return
    org_id = organization_id or alerts[0].canvas_account_id or ""
    critical_alerts = [alert for alert in alerts if alert.severity == "critical"]
    for alert in alerts:
        payload = _canvas_mirror_alert_to_dict(alert)
        payload["organization_id"] = org_id
        logger.warning(
            "canvas_mirror_alert",
            extra={
                "mip_event": "canvas_mirror_alert",
                "canvas_mirror_alert": payload,
                "organization_id": org_id,
                "severity": alert.severity,
            },
        )
        await repo.save_event(
            IssuanceEvent(
                transaction_id=alert.transaction_id,
                application_id=None,
                event_type=EventType.CANVAS_MIRROR_ALERT_EMITTED,
                metadata=payload,
            )
        )
    if critical_alerts and organization_id:
        await _post_canvas_mirror_alert_webhook(
            organization_id=organization_id,
            alerts=critical_alerts,
        )


async def _emit_canvas_mirror_alerts_for_records(
    *,
    repo: IIssuanceRepository,
    organization_id: str | None,
    records: list[CredentialDeliveryRecord],
    alert_type: str,
) -> None:
    effective_organization_id = organization_id or (records[0].organization_id if records else None)
    warning_threshold = _env_int("CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS", 3)
    critical_threshold = max(
        warning_threshold,
        _env_int("CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS", 5),
    )
    if alert_type == "publish_failure":
        attempt_key = "publish_attempts"
        error_at_key = "last_error_at"
    else:
        attempt_key = "status_sync_attempts"
        error_at_key = "last_status_sync_error_at"
    alerts = [
        alert
        for record in records
        if (alert := _canvas_mirror_alert_for_record(
            record,
            alert_type=alert_type,
            attempt_key=attempt_key,
            error_at_key=error_at_key,
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
        )) is not None
    ]
    await _emit_canvas_mirror_alert_observability(
        repo=repo,
        organization_id=effective_organization_id,
        alerts=alerts,
    )


def _next_canvas_status_sync_metadata(
    record: CredentialDeliveryRecord,
    attempted_at: datetime,
    *,
    lifecycle_action: str,
    credential_status: str | None,
) -> dict[str, Any]:
    metadata = {
        **(record.metadata or {}),
        "status_sync_attempts": int((record.metadata or {}).get("status_sync_attempts") or 0) + 1,
        "last_status_sync_action": lifecycle_action,
        "last_status_sync_attempted_at": attempted_at.isoformat(),
    }
    if credential_status:
        metadata["last_synced_credential_status"] = credential_status
    return metadata


async def _sync_canvas_lifecycle_delivery_record(
    record: CredentialDeliveryRecord,
    credential: IssuedCredential,
    repo: IIssuanceRepository,
    *,
    lifecycle_action: str,
    reason: str | None = None,
    transaction: IssuanceTransaction | None = None,
) -> CredentialDeliveryRecord:
    tx = transaction or await repo.get_transaction(credential.transaction_id)
    now = datetime.now(timezone.utc)
    await _hydrate_canvas_gate_metadata(record, tx, repo)
    if not canvas_delivery_feature_enabled(record.metadata, "enable_canvas_mirror_ops"):
        record.last_error = _canvas_gate_blocked_error("enable_canvas_mirror_ops")
        record.metadata = {
            **_canvas_gate_blocked_metadata(
                record,
                flag="enable_canvas_mirror_ops",
                blocked_at=now,
            ),
            "last_status_sync_error": record.last_error,
            "last_status_sync_error_at": now.isoformat(),
        }
        record.updated_at = now
        await repo.save_delivery_record(record)
        return record

    target, target_error = await _resolve_canvas_mirror_target(record, tx, repo)
    sync_metadata = _next_canvas_status_sync_metadata(
        record,
        now,
        lifecycle_action=lifecycle_action,
        credential_status=credential.status.value,
    )
    if target_error or target is None:
        record.last_error = f"Canvas lifecycle sync skipped: {target_error}"
        record.metadata = {
            **(record.metadata or {}),
            **sync_metadata,
            "last_status_sync_error": record.last_error,
            "last_status_sync_error_at": now.isoformat(),
        }
        record.updated_at = now
        await repo.save_delivery_record(record)
        logger.warning(record.last_error)
        return record

    try:
        sync_result = await sync_canvas_credential_status(
            credential=credential,
            platform=target.platform,
            delivery_record=record,
            lifecycle_action=lifecycle_action,
            reason=reason,
            secret_resolver=repo.get_integration_secret_value,
        )
    except Exception as exc:  # noqa: BLE001
        record.last_error = str(exc)
        record.metadata = {
            **sync_metadata,
            "last_status_sync_error": str(exc),
            "last_status_sync_error_at": now.isoformat(),
        }
        record.updated_at = now
        await repo.save_delivery_record(record)
        logger.warning(
            "Canvas lifecycle sync failed for credential=%s delivery_record=%s: %s",
            credential.id,
            record.id,
            exc,
        )
        return record

    record.last_error = None
    record.metadata = {
        **sync_metadata,
        **(sync_result.metadata or {}),
        "last_status_sync_error": None,
    }
    record.updated_at = now
    await repo.save_delivery_record(record)
    return record


async def _sync_canvas_lifecycle_delivery_records(
    credential: IssuedCredential,
    repo: IIssuanceRepository,
    *,
    lifecycle_action: str,
    reason: str | None = None,
) -> list[CredentialDeliveryRecord]:
    tx = await repo.get_transaction(credential.transaction_id)
    delivery_records = await repo.list_delivery_records_for_credential(credential.id)
    canvas_records = [
        record
        for record in delivery_records
        if record.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS
        and record.status == CredentialDeliveryStatus.DELIVERED
    ]
    updated_records: list[CredentialDeliveryRecord] = []

    for record in canvas_records:
        updated_records.append(
            await _sync_canvas_lifecycle_delivery_record(
                record,
                credential,
                repo,
                lifecycle_action=lifecycle_action,
                reason=reason,
                transaction=tx,
            )
        )

    return updated_records


async def _process_canvas_mirror_delivery_record(
    record: CredentialDeliveryRecord,
    repo: IIssuanceRepository,
    *,
    credential: IssuedCredential | None = None,
    transaction: IssuanceTransaction | None = None,
) -> CredentialDeliveryRecord:
    if record.status == CredentialDeliveryStatus.DELIVERED:
        return record

    now = datetime.now(timezone.utc)
    credential = credential or await repo.get_credential(record.credential_id)
    if credential is None:
        metadata = _next_canvas_publish_metadata(record, now)
        record.status = CredentialDeliveryStatus.FAILED
        record.last_error = f"Issued credential {record.credential_id} was not found"
        record.updated_at = now
        record.metadata = {
            **metadata,
            "last_error_at": now.isoformat(),
        }
        await repo.save_delivery_record(record)
        return record

    transaction = transaction or await repo.get_transaction(record.transaction_id)
    if transaction is None:
        metadata = _next_canvas_publish_metadata(record, now)
        record.status = CredentialDeliveryStatus.FAILED
        record.last_error = f"Issuance transaction {record.transaction_id} was not found"
        record.updated_at = now
        record.metadata = {
            **metadata,
            "last_error_at": now.isoformat(),
        }
        await repo.save_delivery_record(record)
        return record

    await _hydrate_canvas_gate_metadata(record, transaction, repo)
    for feature_flag in ("enable_canvas_mirror_publish", "enable_canvas_mirror_ops"):
        if not canvas_delivery_feature_enabled(record.metadata, feature_flag):
            record.status = CredentialDeliveryStatus.FAILED
            record.last_error = _canvas_gate_blocked_error(feature_flag)
            record.updated_at = now
            record.metadata = _canvas_gate_blocked_metadata(
                record,
                flag=feature_flag,
                blocked_at=now,
            )
            await repo.save_delivery_record(record)
            return record

    target, target_error = await _resolve_canvas_mirror_target(record, transaction, repo)
    metadata = _next_canvas_publish_metadata(record, now)
    if target_error or target is None:
        record.status = CredentialDeliveryStatus.FAILED
        record.last_error = target_error or "Canvas mirror target could not be resolved"
        record.updated_at = now
        record.metadata = {
            **(record.metadata or {}),
            **metadata,
            "last_error_at": now.isoformat(),
        }
        await repo.save_delivery_record(record)
        return record

    try:
        publish_result = await publish_canvas_credential_mirror(
            credential=credential,
            transaction=transaction,
            platform=target.platform,
            delivery_record=record,
            secret_resolver=repo.get_integration_secret_value,
        )
    except Exception as exc:  # noqa: BLE001
        record.status = CredentialDeliveryStatus.FAILED
        record.last_error = str(exc)
        record.updated_at = now
        record.metadata = {
            **metadata,
            "last_error_at": now.isoformat(),
        }
        await repo.save_delivery_record(record)
        return record

    record.status = CredentialDeliveryStatus.DELIVERED
    record.external_credential_id = publish_result.external_credential_id
    record.external_issuer_id = publish_result.external_issuer_id
    record.last_error = None
    record.updated_at = now
    record.metadata = {
        **metadata,
        **(publish_result.metadata or {}),
    }
    await repo.save_delivery_record(record)
    return record


_TRUE_ENV_VALUES = {"1", "true", "yes", "on"}
_FALSE_ENV_VALUES = {"0", "false", "no", "off"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_ENV_VALUES:
        return True
    if normalized in _FALSE_ENV_VALUES:
        return False
    logger.warning("Ignoring invalid boolean %s=%r; using %s", name, raw, default)
    return default


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Ignoring invalid integer %s=%r; using %s", name, raw, default)
        return default
    if value < minimum:
        logger.warning("Ignoring %s=%r below minimum %s; using %s", name, raw, minimum, default)
        return default
    return value


@dataclass(frozen=True)
class CanvasMirrorAutomationConfig:
    enabled: bool = False
    organization_id: str | None = None
    publish_interval_seconds: int = 300
    status_sync_interval_seconds: int = 900
    batch_limit: int = 25
    retry_failed_publish: bool = True
    run_on_startup: bool = True

    @classmethod
    def from_env(cls) -> "CanvasMirrorAutomationConfig":
        organization_id = (os.environ.get("CANVAS_MIRROR_WORKER_ORGANIZATION_ID") or "").strip() or None
        return cls(
            enabled=_env_bool("CANVAS_MIRROR_WORKER_ENABLED", False),
            organization_id=organization_id,
            publish_interval_seconds=_env_int("CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS", 300),
            status_sync_interval_seconds=_env_int("CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS", 900),
            batch_limit=_env_int("CANVAS_MIRROR_WORKER_BATCH_LIMIT", 25),
            retry_failed_publish=_env_bool("CANVAS_MIRROR_WORKER_RETRY_FAILED", True),
            run_on_startup=_env_bool("CANVAS_MIRROR_WORKER_RUN_ON_STARTUP", True),
        )


async def run_canvas_mirror_publish_batch(
    repo: IIssuanceRepository,
    *,
    organization_id: str | None = None,
    limit: int = 25,
    retry_failed: bool = False,
) -> CanvasMirrorBatchProcessResponse:
    statuses = [CredentialDeliveryStatus.PENDING]
    if retry_failed:
        statuses.append(CredentialDeliveryStatus.FAILED)

    records = await repo.list_delivery_records(
        delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
        statuses=statuses,
        organization_id=organization_id,
        limit=limit,
    )
    processed_records: list[CredentialDeliveryRecordResponse] = []
    processed_domain_records: list[CredentialDeliveryRecord] = []
    delivered_count = 0
    failed_count = 0
    blocked_count = 0

    for record in records:
        updated = await _process_canvas_mirror_delivery_record(record, repo)
        processed_domain_records.append(updated)
        processed_records.append(_delivery_record_to_protocol(updated))
        if (updated.metadata or {}).get("canvas_feature_gate_blocked"):
            blocked_count += 1
        if updated.status == CredentialDeliveryStatus.DELIVERED:
            delivered_count += 1
        elif updated.status == CredentialDeliveryStatus.FAILED:
            failed_count += 1

    metrics = _canvas_mirror_publish_metrics(
        processed_count=len(processed_records),
        delivered_count=delivered_count,
        failed_count=failed_count,
        blocked_count=blocked_count,
    )
    _log_canvas_mirror_metrics(
        operation="publish",
        organization_id=organization_id,
        metrics=metrics,
    )
    await _emit_canvas_mirror_alerts_for_records(
        repo=repo,
        organization_id=organization_id,
        records=[
            record for record in processed_domain_records
            if record.status == CredentialDeliveryStatus.FAILED
        ],
        alert_type="publish_failure",
    )

    return CanvasMirrorBatchProcessResponse(
        organization_id=organization_id,
        retry_failed=retry_failed,
        processed_count=len(processed_records),
        delivered_count=delivered_count,
        failed_count=failed_count,
        blocked_count=blocked_count,
        metrics=metrics,
        records=processed_records,
    )


async def run_canvas_mirror_status_sync_batch(
    repo: IIssuanceRepository,
    *,
    organization_id: str | None = None,
    limit: int = 25,
) -> CanvasMirrorStatusSyncBatchResponse:
    records = await repo.list_delivery_records(
        delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
        statuses=[CredentialDeliveryStatus.DELIVERED],
        organization_id=organization_id,
    )
    records_to_process = [
        record for record in records
        if _delivery_record_has_status_sync_failure(record)
    ][:limit]

    processed_records: list[CredentialDeliveryRecordResponse] = []
    processed_domain_records: list[CredentialDeliveryRecord] = []
    synced_count = 0
    failed_count = 0
    blocked_count = 0

    for record in records_to_process:
        credential = await repo.get_credential(record.credential_id)
        if credential is None:
            now = datetime.now(timezone.utc)
            lifecycle_action = (record.metadata or {}).get("last_status_sync_action") or "reinstate"
            record.last_error = f"Issued credential {record.credential_id} was not found for Canvas lifecycle resync"
            record.metadata = {
                **_next_canvas_status_sync_metadata(
                    record,
                    now,
                    lifecycle_action=str(lifecycle_action),
                    credential_status=None,
                ),
                "last_status_sync_error": record.last_error,
                "last_status_sync_error_at": now.isoformat(),
            }
            record.updated_at = now
            await repo.save_delivery_record(record)
            failed_count += 1
            processed_domain_records.append(record)
            processed_records.append(_delivery_record_to_protocol(record))
            continue

        lifecycle_action = (record.metadata or {}).get("last_status_sync_action") or {
            CredentialStatus.REVOKED: "revoke",
            CredentialStatus.SUSPENDED: "suspend",
            CredentialStatus.ACTIVE: "reinstate",
        }.get(credential.status, "reinstate")
        updated = await _sync_canvas_lifecycle_delivery_record(
            record,
            credential,
            repo,
            lifecycle_action=str(lifecycle_action),
            reason=credential.revocation_reason,
        )
        processed_domain_records.append(updated)
        processed_records.append(_delivery_record_to_protocol(updated))
        if (updated.metadata or {}).get("canvas_feature_gate_blocked"):
            blocked_count += 1
        if _delivery_record_has_status_sync_failure(updated):
            failed_count += 1
        else:
            synced_count += 1

    metrics = _canvas_mirror_status_sync_metrics(
        processed_count=len(processed_records),
        synced_count=synced_count,
        failed_count=failed_count,
        blocked_count=blocked_count,
    )
    _log_canvas_mirror_metrics(
        operation="status_sync",
        organization_id=organization_id,
        metrics=metrics,
    )
    await _emit_canvas_mirror_alerts_for_records(
        repo=repo,
        organization_id=organization_id,
        records=[
            record for record in processed_domain_records
            if _delivery_record_has_status_sync_failure(record)
        ],
        alert_type="lifecycle_sync_failure",
    )

    return CanvasMirrorStatusSyncBatchResponse(
        organization_id=organization_id,
        processed_count=len(processed_records),
        synced_count=synced_count,
        failed_count=failed_count,
        blocked_count=blocked_count,
        metrics=metrics,
        records=processed_records,
    )


async def run_canvas_mirror_automation_cycle(
    repo: IIssuanceRepository,
    *,
    organization_id: str | None = None,
    limit: int = 25,
    retry_failed: bool = True,
) -> CanvasMirrorAutomationCycleResponse:
    started_at = datetime.now(timezone.utc)
    publish = await run_canvas_mirror_publish_batch(
        repo,
        organization_id=organization_id,
        limit=limit,
        retry_failed=retry_failed,
    )
    status_sync = await run_canvas_mirror_status_sync_batch(
        repo,
        organization_id=organization_id,
        limit=limit,
    )
    completed_at = datetime.now(timezone.utc)
    metrics = {
        **{f"publish.{key.removeprefix('publish.')}": value for key, value in publish.metrics.items()},
        **{f"status_sync.{key.removeprefix('status_sync.')}": value for key, value in status_sync.metrics.items()},
        "automation.processed": publish.processed_count + status_sync.processed_count,
        "automation.failed": publish.failed_count + status_sync.failed_count,
        "automation.blocked": publish.blocked_count + status_sync.blocked_count,
    }
    _log_canvas_mirror_metrics(
        operation="automation_cycle",
        organization_id=organization_id,
        metrics=metrics,
    )
    return CanvasMirrorAutomationCycleResponse(
        organization_id=organization_id,
        retry_failed=retry_failed,
        publish=publish,
        status_sync=status_sync,
        processed_count=publish.processed_count + status_sync.processed_count,
        failed_count=publish.failed_count + status_sync.failed_count,
        blocked_count=publish.blocked_count + status_sync.blocked_count,
        metrics=metrics,
        started_at=started_at.isoformat(),
        completed_at=completed_at.isoformat(),
    )


async def run_canvas_mirror_automation_loop(
    get_repo: Callable[[], IIssuanceRepository],
    config: CanvasMirrorAutomationConfig,
) -> None:
    if not config.enabled:
        return

    logger.info(
        "Canvas mirror automation worker enabled: organization_id=%s batch_limit=%s retry_failed=%s",
        config.organization_id,
        config.batch_limit,
        config.retry_failed_publish,
    )
    now = time.monotonic()
    next_publish_at = now if config.run_on_startup else now + config.publish_interval_seconds
    next_status_sync_at = now if config.run_on_startup else now + config.status_sync_interval_seconds

    while True:
        current = time.monotonic()
        if current >= next_publish_at:
            try:
                publish = await run_canvas_mirror_publish_batch(
                    get_repo(),
                    organization_id=config.organization_id,
                    limit=config.batch_limit,
                    retry_failed=config.retry_failed_publish,
                )
                if publish.processed_count:
                    logger.info(
                        "Canvas mirror publish worker processed=%s delivered=%s failed=%s blocked=%s",
                        publish.processed_count,
                        publish.delivered_count,
                        publish.failed_count,
                        publish.blocked_count,
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Canvas mirror publish worker cycle failed")
            finally:
                next_publish_at = time.monotonic() + config.publish_interval_seconds

        current = time.monotonic()
        if current >= next_status_sync_at:
            try:
                status_sync = await run_canvas_mirror_status_sync_batch(
                    get_repo(),
                    organization_id=config.organization_id,
                    limit=config.batch_limit,
                )
                if status_sync.processed_count:
                    logger.info(
                        "Canvas mirror status-sync worker processed=%s synced=%s failed=%s blocked=%s",
                        status_sync.processed_count,
                        status_sync.synced_count,
                        status_sync.failed_count,
                        status_sync.blocked_count,
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Canvas mirror status-sync worker cycle failed")
            finally:
                next_status_sync_at = time.monotonic() + config.status_sync_interval_seconds

        sleep_for = max(1.0, min(next_publish_at, next_status_sync_at) - time.monotonic())
        await asyncio.sleep(sleep_for)


# ============================================================================
# OID4VCI Endpoints
# ============================================================================

@issuance_router.post("/initiate", response_model=IssuanceResponse, dependencies=[Depends(_verify_management_api_key)])
async def initiate_issuance(
    request: InitiateIssuanceRequest,
    http_request: Request = None,
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
    revocation_profile_id: str | None = None
    wallet_configs: list[dict] = []
    validity_days = 365
    renewable = False
    renewal_window_days = 30
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
            revocation_profile_id = tmpl_resp.revocation_profile_id or None
            wallet_configs = json.loads(tmpl_resp.wallet_configs_json) if tmpl_resp.wallet_configs_json else []
            validity_days = tmpl_resp.validity_rules.default_validity_days or 365
            renewable = bool(tmpl_resp.validity_rules.renewable)
            renewal_window_days = tmpl_resp.validity_rules.renewal_window_days or 30
            logger.info(f"Fetched credential type from template (gRPC): {credential_type} vct={credential_vct}")
            logger.info(f"Template wallet_configs_json: {tmpl_resp.wallet_configs_json}")
            logger.info(f"Parsed wallet_configs ({len(wallet_configs)} entries): {[wc.get('wallet_id') for wc in wallet_configs]}")
            _tmpl_resolved = True
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
            revocation_profile_id = tmpl.get("revocation_profile_id") or None
            wallet_configs = tmpl.get("wallet_configs") or []
            validity_rules = tmpl.get("validity_rules") or {}
            validity_days = int(validity_rules.get("default_validity_days") or 0)
            if validity_days <= 0:
                ttl_seconds = int(validity_rules.get("ttl_seconds") or 0)
                validity_days = max(ttl_seconds // 86400, 1) if ttl_seconds else 365
            renewable = bool(validity_rules.get("renewable", False))
            renewal_window_days = int(validity_rules.get("renewal_window_days") or 0)
            if renewal_window_days <= 0:
                reissue_seconds = int(validity_rules.get("reissue_within_seconds") or 0)
                renewal_window_days = max(reissue_seconds // 86400, 1) if reissue_seconds else 30

    # Derive vct fallback if not already resolved
    if not credential_vct:
        credential_vct = f"{ISSUER_BASE_URL}/credentials/{credential_type}"

    await _require_active_revocation_profile_binding(
        organization_id=request.organization_id,
        revocation_profile_id=revocation_profile_id,
    )
    # Store vct in claims under a reserved key so the credential endpoint can
    # use it at signing time without a second template lookup.
    merged_claims = {**request.claims, "_vct": credential_vct}
    # MIP §8.3 – if the caller deferred claims resolution (only sent
    # _application_id), resolve actual claim values from the application's
    # form_data.
    _resolved_application = merged_claims.pop("_application_id", None)
    if _resolved_application and (
        not merged_claims or list(merged_claims.keys()) == ["_vct"]
    ):
        try:
            app = await repo.get_application(str(_resolved_application))
            if app and app.form_data:
                merged_claims = {**app.form_data, "_vct": credential_vct}
                logger.info(
                    "[initiate] resolved claims from application %s: keys=%s",
                    _resolved_application, list(app.form_data.keys()),
                )
            else:
                logger.warning(
                    "[initiate] application %s not found or has empty form_data",
                    _resolved_application,
                )
        except Exception as _app_err:
            logger.warning(
                "[initiate] could not resolve application %s: %s", _resolved_application, _app_err,
            )
    logger.info(
        "[initiate] org=%s template=%s cred_type=%s received_claims=%s merged_claims=%s",
        request.organization_id,
        request.credential_template_id,
        credential_type,
        list(request.claims.keys()),
        list(merged_claims.keys()),
    )

    # DB column is NOT NULL; when callers omit template id, persist a stable fallback.
    effective_credential_template_id = request.credential_template_id or "default"

    # Extract issuer identity headers injected by the gateway when an
    # IssuerProfile is configured for the organization.
    issuer_did_override: str | None = None
    signing_service_id: str | None = None
    issuer_profile_id = request.issuer_profile_id
    issuer_mode = _normalize_issuer_mode(request.issuer_mode)
    try:
        delivery_mode = normalize_delivery_mode(request.delivery_mode)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if http_request is not None:
        issuer_did_override = http_request.headers.get("x-issuer-did")
        signing_service_id = http_request.headers.get("x-signing-service-id")
        issuer_profile_id = issuer_profile_id or http_request.headers.get("x-issuer-profile-id")
        issuer_mode = _normalize_issuer_mode(http_request.headers.get("x-issuer-mode") or issuer_mode)

    tx = IssuanceTransaction(
        organization_id=request.organization_id,
        credential_template_id=effective_credential_template_id,
        revocation_profile_id=revocation_profile_id,
        applicant_id=request.applicant_id,
        subject_did=request.subject_did,
        issuer_profile_id=issuer_profile_id or None,
        issuer_mode=issuer_mode,
        issuer_did_override=issuer_did_override or None,
        signing_service_id=signing_service_id or None,
        delivery_mode=delivery_mode,
        claims=merged_claims,
        credential_type=credential_type,
        zk_predicate_claims=zk_predicate_claims,
        selective_disclosure_claims=selective_disclosure_claims,
        credential_payload_format=credential_payload_format,
        wallet_configs=wallet_configs,
        validity_days=validity_days,
        renewable=renewable,
        renewal_window_days=renewal_window_days,
    )
    if not (tx.issuer_did_override and tx.signing_service_id):
        await apply_remote_issuer_context(
            tx,
            credential_format=_credential_format_for_remote_context(credential_payload_format),
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
        - ICAO VDS-NC (``variant == "vds_nc"``): ``{base}#vds-nc``
          which maps to the ``vds_nc`` entry in issuer metadata.
        """
        normalized_variant = _normalize_payload_format(variant)
        # The root issuer metadata intentionally exposes distinct default
        # configurations: JWT VC JSON, Credential Manager SD-JWT, and mdoc.
        # An offer must name the configuration whose representation it will
        # issue; returning bare ``default`` here selected the JWT VC JSON
        # metadata while later processing inferred an SD-JWT representation.
        if base == "default":
            if normalized_variant in _MDOC_PAYLOAD_FORMATS:
                return "default#mdoc"
            return "default#credential-manager"
        if normalized_variant == "spruce_vc+sd_jwt":
            return f"{base}#spruce-sd-jwt"
        if normalized_variant in _MDOC_PAYLOAD_FORMATS:
            return f"{base}#mdoc"
        if normalized_variant in _VDS_NC_PAYLOAD_FORMATS:
            return f"{base}#vds-nc"
        if normalized_variant == "credential_manager":
            return f"{base}#credential-manager"
        if normalized_variant == "apple_wallet":
            return f"{base}#apple-wallet"
        return f"{base}#sd-jwt"

    # Default offer uses the standard vc+sd-jwt config (works with Walt.id and
    # most OID4VCI-compliant wallets).  For mso_mdoc templates, use the #mdoc
    # config id so the default offer also resolves to the correct metadata entry.
    normalized_payload_format = _normalize_payload_format(credential_payload_format)
    if normalized_payload_format in _MDOC_PAYLOAD_FORMATS:
        default_fmt_variant = "mso_mdoc"
    elif normalized_payload_format in _VDS_NC_PAYLOAD_FORMATS:
        default_fmt_variant = "vds_nc"
    else:
        default_fmt_variant = None
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
    logger.info(f"Building credential_offer_uris from {len(tx.wallet_configs)} wallet configs: {tx.wallet_configs}")
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


async def _finalize_credential_renewal(
    tx: IssuanceTransaction,
    renewed_credential: IssuedCredential,
    repo: IIssuanceRepository,
) -> None:
    source_id = str(tx.renewal_of_credential_id or "").strip()
    if not source_id:
        return

    source = await repo.get_credential(source_id)
    if not source:
        raise HTTPException(status_code=409, detail="Renewal source credential no longer exists.")
    if source.organization_id != renewed_credential.organization_id:
        raise HTTPException(status_code=409, detail="Renewal source organization mismatch.")
    if source.status != CredentialStatus.ACTIVE:
        raise HTTPException(status_code=409, detail="Only an active credential can complete renewal.")

    await revoke_credential(
        source.id,
        CredentialStatusRequest(reason="Superseded by renewed credential"),
        repo,
    )
    source = await repo.get_credential(source.id)
    if not source:
        raise HTTPException(status_code=409, detail="Renewal source credential no longer exists.")
    source.renewed_to_credential_id = renewed_credential.id
    renewed_credential.renewed_from_credential_id = source.id
    await repo.save_credential(source)
    await repo.save_credential(renewed_credential)


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
        auth_session.mark_exchanged(access_token=token_resp["access_token"])
        await repo.save_authorization_session(auth_session)

        return TokenResponse(
            access_token=token_resp["access_token"],
            expires_in=token_resp.get("expires_in", 1800),
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
    
    # OID4VCI Final §4.1.1: the pre-authorized code MUST be short lived and
    # single-use.  Do not turn a second wallet redemption into an unbounded
    # issuance capability; multi-wallet authorization belongs to the
    # authorization-code flow or an explicitly modelled product policy.
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

    # Delegate access-token generation to Rust. OID4VCI Final obtains proof
    # freshness independently from the advertised Nonce Endpoint.
    token_resp = oid4vci_create_token_response(pre_authorized_code, 1800)

    # Persist the Rust-generated tokens on the transaction
    tx.access_token = token_resp["access_token"]
    tx.nonce = None
    tx.status = IssuanceStatus.AUTHORIZED
    await repo.save_transaction(tx)

    logger.info(
        f"[token] rid={rid} tx_id={tx.id} org={tx.organization_id} "
        f"cred_type={tx.credential_type}"
    )

    return TokenResponse(
        access_token=token_resp["access_token"],
        expires_in=token_resp.get("expires_in", 1800),
    )


@issuance_router.post("/nonce", response_model=NonceResponse)
async def nonce_endpoint(
    response: Response,
) -> NonceResponse:
    """Return an OID4VCI Final proof nonce without client authentication."""
    import secrets as _secrets
    new_nonce = _secrets.token_urlsafe(32)

    # The pool makes accepted proofs one-time while allowing issuer metadata to
    # expose an unauthenticated nonce endpoint as required by OID4VCI Final.
    await _nonce_pool.add(new_nonce)

    # OID4VCI §7.3: Cache-Control MUST be no-store to prevent nonce caching
    response.headers["Cache-Control"] = "no-store"
    return NonceResponse(c_nonce=new_nonce)


@issuance_router.post(
    "/credential",
    response_model=CredentialResponse,
    response_model_exclude_none=True,
)
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
            # Strip any format suffix (e.g. #sd-jwt, #mdoc, #vds-nc) that may be
            # present on the config ID so signing receives the bare credential type
            # (e.g. "access_badge").
            raw_config_id = (
                auth_session.credential_configuration_ids[0]
                if auth_session.credential_configuration_ids
                else "default"
            )
            bare_ctype = raw_config_id.split("#")[0]  # strips #sd-jwt, #spruce-sd-jwt, etc.
            tx = IssuanceTransaction(
                id=_authorization_session_transaction_id(auth_session.id),
                organization_id=auth_session.organization_id or "",
                status=IssuanceStatus.AUTHORIZED,
                access_token=access_token,
                nonce=auth_session.nonce,
                credential_type=bare_ctype,
            )
            try:
                await repo.save_transaction(tx)
            except ValueError:
                # A concurrent request may have created and claimed this same
                # deterministic transaction between our reads. Never fall back
                # to a second transaction identity.
                concurrent_tx = await repo.get_transaction(tx.id)
                if concurrent_tx is None:
                    raise
                tx = concurrent_tx
    
    # OID4VCI Final §7.3: The access token is single-use for credential issuance.
    # §8 errors use 400 invalid_credential_request, not 401.
    if tx.status == IssuanceStatus.ISSUED:
        existing_cred = await repo.get_credential_by_transaction_id(tx.id)
        if existing_cred:
            response_format = _effective_request_format(request, tx)
            credential_obj = {"format": response_format, "credential": existing_cred.credential_jwt}
            import uuid as _uuid
            notification_id = str(_uuid.uuid4())
            return CredentialResponse(
                credentials=[credential_obj],
                credential=(
                    existing_cred.credential_jwt
                    if _requests_legacy_credential_alias(request)
                    else None
                ),
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

    # Repository reads are detached in PostgreSQL but the development adapter
    # stores objects in-process. Work on a private snapshot so resolving issuer
    # context cannot mutate the durable AUTHORIZED row before the signing CAS.
    tx = copy.deepcopy(tx)

    # OID4VCI §8.2: Validate credential_configuration_id if provided.
    # It must correspond to a configuration supported by this issuer for the transaction.
    if request.credential_configuration_id is not None:
        cred_type_base = tx.credential_type or "default"
        valid_config_ids = {
            cred_type_base,
            f"{cred_type_base}#sd-jwt",
            f"{cred_type_base}#mdoc",
            f"{cred_type_base}#vds-nc",
            f"{cred_type_base}#spruce-sd-jwt",
            "default",
            "default#sd-jwt",
            "default#credential-manager",
            "default#mdoc",
            "default#vds-nc",
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
                    f"{_ctype}#vds-nc",
                    f"{_ctype}#spruce-sd-jwt",
                })
        if request.credential_configuration_id not in valid_config_ids:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "unknown_credential_configuration",
                    "error_description": f"Unknown credential_configuration_id: {request.credential_configuration_id!r}",
                },
            )
        # If the config ID was validated via org DB (not tx's stored type),
        # fix credential_type on the transaction so signing uses the correct type.
        if request.credential_configuration_id not in tx_own_ids:
            tx.credential_type = request.credential_configuration_id.split("#")[0]

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
                    "error": "unknown_credential_identifier",
                    "error_description": f"Unknown credential_identifier: {request.credential_identifier!r}",
                },
            )

    effective_request_format = _effective_request_format(request, tx)
    
    # Resolve issuer DID + remote signing service before proof validation. The
    # actual signing key is loaded only if we must fall back to legacy local
    # signing after determining the credential format below.
    issuer_context = await apply_remote_issuer_context(
        tx,
        credential_format=_credential_format_for_remote_context(tx.credential_payload_format, effective_request_format),
    )
    
    # Get credential type from transaction (stored during initiation)
    credential_type = tx.credential_type or "org.iso.18013.5.1.mDL"
    rid = http_request.headers.get("X-Request-ID", "-")
    logger.info(
        f"[credential] rid={rid} tx_id={tx.id} org={tx.organization_id} "
        f"cred_type={credential_type} status={tx.status}"
    )

    # Extract holder DID (subject) from the OID4VCI v1 proof JWT.
    holder_did: str | None = None

    def _extract_proof_jwt(req: CredentialRequest) -> str | None:
        """Return the first JWT from the canonical proofs object."""
        if req.proofs:
            jwt_list = req.proofs.get("jwt", [])
            if jwt_list:
                return jwt_list[0]
        return None

    proof_jwt = _extract_proof_jwt(request)
    logger.info(f"[credential] rid={rid} proof present: {proof_jwt is not None}")

    # OID4VCI §7.2: proof of possession is required for credential binding.
    if not proof_jwt:
        logger.warning(f"[credential] rid={rid} tx_id={tx.id} rejecting — proof of possession missing")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_proof", "error_description": "Proof of possession is required per OID4VCI §7.2"},
        )

    # OID4VCI-1FINAL Appendix F.4: aud in proof JWT MUST be the credential_issuer URL.
    # We validate the issuer URL path to accept both localhost and production
    # hostnames while honoring wallet-specific issuer paths such as /spruce.
    if tx.organization_id:
        try:
            import base64 as _b64, json as _json
            _proof_parts = proof_jwt.split('.')
            _pad = '=' * ((-len(_proof_parts[1])) % 4)
            _proof_payload = _json.loads(_b64.urlsafe_b64decode(_proof_parts[1] + _pad))
            _proof_aud = _proof_payload.get('aud') or ''
            _expected_aud_paths = _allowed_credential_issuer_audience_paths(tx.organization_id)
            if not _proof_audience_matches_org_issuer(_proof_aud, tx.organization_id):
                logger.warning(
                    f"[credential] rid={rid} aud mismatch: got {_proof_aud!r}, "
                    f"expected issuer path in {_expected_aud_paths!r}"
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_proof",
                        "error_description": (
                            f"OID4VCI §8.2: proof JWT aud MUST be the credential_issuer URL "
                            f"(path in {_expected_aud_paths}), got {_proof_aud!r}"
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
    try:
        import base64 as _b64n, json as _json_n
        _proof_parts_n = proof_jwt.split('.')
        _pad_n = '=' * ((-len(_proof_parts_n[1])) % 4)
        _payload_n = _json_n.loads(_b64n.urlsafe_b64decode(_proof_parts_n[1] + _pad_n))
        _proof_nonce = _payload_n.get('nonce')
    except Exception as _nonce_err:
        logger.warning(f"[credential] rid={rid} could not decode proof nonce: {_nonce_err}")
        _proof_nonce = None

    if not _proof_nonce or not await _nonce_pool.consume(_proof_nonce):
        # OID4VCI Final §8.2 distinguishes a nonce failure from a malformed
        # or invalidly-signed proof.  Keeping this mapping precise lets
        # wallets request a fresh nonce instead of treating the holder key as
        # invalid.
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_nonce", "error_description": "Proof nonce is missing, expired, or already used"},
        )

    ok, did_from_proof, holder_jwk, verify_err = verify_proof_jwt(
        proof_jwt, expected_nonce=_proof_nonce
    )
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
    normalized_payload_format = _normalize_payload_format(credential_payload_fmt)
    if normalized_payload_format in _MDOC_PAYLOAD_FORMATS:
        signing_format = "mso_mdoc"
    elif normalized_payload_format in _VDS_NC_PAYLOAD_FORMATS:
        if not _VDSNC_RUST_ENABLED:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="VDS-NC credential issuance is temporarily disabled (VDSNC_RUST_ENABLED=false)",
            )
        signing_format = "vds_nc"
    elif normalized_payload_format in _SD_JWT_PAYLOAD_FORMATS:
        signing_format = "vc+sd-jwt"
    elif effective_request_format == "spruce-vc+sd-jwt":
        signing_format = "vc+sd-jwt"
    else:
        signing_format = effective_request_format
    # For mdoc/vds_nc, pass the stored credential_type directly. SD-JWT uses vct URI.
    signing_credential_type = tx.credential_type if signing_format in ("mso_mdoc", "vds_nc") else vct_for_signing

    # For SD-JWT, if no explicit selective disclosure claims were configured
    # on the template, default to all top-level claim keys (EUDI compliance).
    sd_claims = tx.selective_disclosure_claims or []
    if signing_format == "vc+sd-jwt" and not sd_claims:
        sd_claims = [k for k in clean_claims if not k.startswith("_")]

    remote_credential_format = _credential_format_for_remote_context(credential_payload_fmt, effective_request_format)
    if signing_format != "vc+sd-jwt":
        detail = _unsupported_remote_signing_format_detail(signing_format, remote_credential_format)
        logger.error("[credential] rid=%s tx_id=%s %s", rid, tx.id, detail)
        raise HTTPException(status_code=503, detail=detail)

    remote_context = issuer_context if isinstance(issuer_context, dict) else None
    if signing_format == "vc+sd-jwt":
        try:
            remote_context = await apply_remote_issuer_context(
                tx,
                credential_format=remote_credential_format,
                force=True,
                raise_on_error=True,
            )
        except Exception as exc:  # noqa: BLE001
            detail = _did_resolution_failure_detail(tx, exc)
            logger.error("[credential] rid=%s tx_id=%s %s", rid, tx.id, detail)
            raise HTTPException(status_code=503, detail=detail) from exc
        if not (tx.issuer_did_override and tx.signing_service_id):
            detail = (
                "Issuer identity is not configured for this organization. "
                "Create an active DID issuer profile backed by a remote signing service before issuing credentials."
            )
            logger.error("[credential] rid=%s tx_id=%s %s", rid, tx.id, detail)
            raise HTTPException(status_code=503, detail=detail)

        if not remote_context or not isinstance(remote_context.get("service"), dict):
            try:
                remote_context = await resolve_remote_issuer_context(
                    tx.organization_id,
                    issuer_profile_id=tx.issuer_profile_id,
                    issuer_mode=_normalize_issuer_mode(tx.issuer_mode),
                    credential_format=remote_credential_format,
                    key_purpose=_key_purpose_for_credential_format(remote_credential_format),
                )
            except Exception as exc:  # noqa: BLE001
                detail = _did_resolution_failure_detail(tx, exc)
                logger.error("[credential] rid=%s tx_id=%s %s", rid, tx.id, detail)
                raise HTTPException(status_code=503, detail=detail) from exc
            if remote_context:
                tx.issuer_did_override = remote_context.get("issuer_did") or tx.issuer_did_override
                tx.signing_service_id = remote_context.get("signing_service_id") or tx.signing_service_id
                tx.issuer_profile_id = remote_context.get("issuer_profile_id") or (remote_context.get("issuer_profile") or {}).get("id") or tx.issuer_profile_id
                tx.issuer_mode = _normalize_issuer_mode(remote_context.get("issuer_mode") or (remote_context.get("issuer_profile") or {}).get("issuer_mode") or tx.issuer_mode)
        if not remote_context:
            detail = (
                "Unable to resolve the remote DID issuer profile for this organization. "
                "Verify the DID identity is active and its signing service is available."
            )
            logger.error("[credential] rid=%s tx_id=%s %s", rid, tx.id, detail)
            raise HTTPException(status_code=503, detail=detail)

    # Approval and offer creation are not durable authorization for a Canvas
    # claim.  Re-bind the transaction to the active readiness snapshot and
    # current authoritative evidence immediately before status allocation and
    # the remote KMS signing call.
    canvas_guard_denial = await _canvas_pre_signing_guard_response(
        tx=tx,
        repo=repo,
        resolved_issuer_context=remote_context,
    )
    if canvas_guard_denial is not None:
        return canvas_guard_denial

    try:
        # All credentials require remote signing (all keys in KMS)
        if not (tx.issuer_did_override and tx.signing_service_id):
            detail = (
                "Remote signing configuration is required. "
                "Issuer identity and signing service must be configured for this organization."
            )
            logger.error("[credential] rid=%s tx_id=%s %s", rid, tx.id, detail)
            raise HTTPException(status_code=503, detail=detail)

        service = remote_context.get("service") if isinstance(remote_context, dict) else {}
        service = service if isinstance(service, dict) else {}
        signing_algorithm = str(service.get("algorithm") or remote_context.get("algorithm") or "ES256")
        signing_key_reference = (
            remote_context.get("signing_key_reference")
            if isinstance(remote_context, dict)
            else None
        )
        verification_method_id = (
            remote_context.get("verification_method_id")
            if isinstance(remote_context, dict)
            else None
        )
        effective_issuer_did = tx.issuer_did_override

        async def _remote_sign(payload: bytes, algorithm: str | None) -> dict[str, Any]:
            return await sign_payload_with_remote_service(
                organization_id=tx.organization_id,
                signing_service_id=tx.signing_service_id or "",
                payload=payload,
                algorithm=algorithm or signing_algorithm,
                key_reference=signing_key_reference,
            )

        # Claim the transaction before allocating status or calling the KMS.
        # A deterministic reserved ID makes a crashed signing attempt explicit
        # and prevents a retry from minting a second credential identity.
        credential_id = tx.reserved_credential_id or (
            f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'marty:issuance:{tx.id}')}"
        )
        signing_tx = await repo.claim_transaction_for_signing(tx, credential_id)
        if signing_tx is None:
            current_tx = await repo.get_transaction(tx.id)
            existing_credential = await repo.get_credential_by_transaction_id(tx.id)
            if current_tx and current_tx.status == IssuanceStatus.ISSUED and existing_credential:
                existing_format = effective_request_format or signing_format or "vc+sd-jwt"
                return CredentialResponse(
                    credentials=[
                        {"format": existing_format, "credential": existing_credential.credential_jwt}
                    ],
                    credential=(
                        existing_credential.credential_jwt
                        if _requests_legacy_credential_alias(request)
                        else None
                    ),
                    notification_id=str(uuid.uuid4()),
                )
            return JSONResponse(
                status_code=409,
                content={
                    "error": "issuance_in_progress",
                    "error_description": "Credential signing is already in progress for this transaction",
                },
            )
        tx = signing_tx
        revocation_profile_id, status_list_entries = await _allocate_credential_status_list_entries(
            credential_id=credential_id,
            organization_id=tx.organization_id,
            credential_format=_credential_format_for_revocation_profile(tx, effective_request_format),
            revocation_profile_id=tx.revocation_profile_id,
        )
        signing_claims = dict(clean_claims)
        credential_status_claim = _status_list_entries_to_credential_status_claim(status_list_entries)
        if credential_status_claim:
            signing_claims["credentialStatus"] = credential_status_claim

        logger.info(f"[credential] rid={rid} signing_path=remote format={effective_request_format} jwt_typ_will_be={effective_request_format}")
        jwt_credential, signed_credential_id = await create_sd_jwt_vc_with_remote_signing(
            issuer_did=effective_issuer_did,
            signing_service_id=tx.signing_service_id,
            remote_sign=_remote_sign,
            subject_id=holder_did or tx.subject_did,
            holder_jwk=holder_jwk,
            credential_type=signing_credential_type,
            claims_json=json.dumps(signing_claims),
            expiration_seconds=31536000,  # 1 year
            selective_disclosure_claims=sd_claims,
            algorithm=signing_algorithm,
            signing_key_reference=signing_key_reference,
            verification_method_id=verification_method_id,
            credential_format=effective_request_format,
            credential_id=credential_id,
        )
        if signed_credential_id != credential_id:
            raise RuntimeError("Remote credential builder changed the reserved credential ID")

        # Only update state and emit event on first issuance; allow idempotent
        # wallet retries (wallets sometimes re-request after a network timeout).
        response_format = effective_request_format or signing_format or "vc+sd-jwt"
        if tx.status == IssuanceStatus.SIGNING:
            issued_at = datetime.now(timezone.utc)
            expires_at = issued_at + timedelta(days=tx.validity_days)
            issued_credential = IssuedCredential(
                id=credential_id,
                transaction_id=tx.id,
                organization_id=tx.organization_id,
                credential_template_id=tx.credential_template_id,
                applicant_id=tx.applicant_id,
                subject_did=holder_did or tx.subject_did,
                issuer_did=effective_issuer_did,
                revocation_profile_id=revocation_profile_id,
                renewed_from_credential_id=tx.renewal_of_credential_id,
                status_list_entries=status_list_entries,
                credential_jwt=jwt_credential,
                credential_hash=hashlib.sha256(jwt_credential.encode("utf-8")).hexdigest(),
                status=CredentialStatus.ACTIVE,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            await repo.finalize_credential_issuance(tx, issued_credential)
            # MIP §20.5.2: nonce invalidation and the ISSUED transition are part
            # of finalize_credential_issuance's database transaction. Mirror
            # the committed state locally only after it succeeds.
            tx.nonce = None
            tx.status = IssuanceStatus.ISSUED
            tx.issued_at = issued_at
            await record_canvas_credential_claim(
                repo=repo,
                application_id=tx.application_id,
                credential_id=issued_credential.id,
            )
            await _finalize_credential_renewal(tx, issued_credential, repo)
            await repo.save_event(IssuanceEvent(
                transaction_id=tx.id,
                application_id=tx.application_id,
                event_type=EventType.CREDENTIAL_ISSUED,
                metadata={"credential_id": credential_id, "credential_type": credential_type},
            ))
            await record_post_issuance_deliveries(
                repo,
                tx,
                issued_credential,
                delivered_target=DeliveryTarget.WALLET,
                delivery_metadata={
                    "protocol": "oid4vci",
                    "requested_format": response_format,
                },
            )

        logger.info(f"[credential] rid={rid} tx_id={tx.id} issued credential_id={credential_id} cred_type={credential_type}")
        # OID4VCI hybrid response:
        # - "credentials" as object array for SpruceID mobile-sdk-rs (expects Oid4vciCredential struct)
        # - "credential" as bare string for Walt.id / Draft-11 clients
        # Use the request format in the response object (not signing_format which may
        # have been normalised from spruce-vc+sd-jwt → vc+sd-jwt for Rust).
        credential_obj = {"format": response_format, "credential": jwt_credential}
        import uuid as _uuid
        notification_id = str(_uuid.uuid4())
        return CredentialResponse(
            credentials=[credential_obj],
            credential=(jwt_credential if _requests_legacy_credential_alias(request) else None),
            notification_id=notification_id,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[credential] rid={rid} tx_id={tx.id} credential creation failed: {e}")
        current_tx = await repo.get_transaction(tx.id)
        if current_tx is not None and current_tx.status == IssuanceStatus.SIGNING:
            current_tx.fail(str(e))
            await repo.save_transaction(current_tx)
        if signing_format == "vc+sd-jwt" and (tx.issuer_did_override or tx.signing_service_id):
            raise HTTPException(status_code=503, detail=_did_resolution_failure_detail(tx, e)) from e
        raise HTTPException(status_code=500, detail=f"Credential creation failed: {e}") from e


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
    credential_type = tx.credential_type or "VerifiableCredential"
    _INTERNAL_CLAIM_FIELDS = {
        "credential_offer_uri", "credential_offer_uris", "offer_expires_at",
        "issuance_transaction_id", "issuance_fallback", "credential_type",
        "credential_display_name", "rejection_reason", "review_notes",
        "info_requests", "applicant_id", "_vct",
    }
    clean_claims = {k: v for k, v in tx.claims.items() if k not in _INTERNAL_CLAIM_FIELDS}

    credential_payload_fmt = tx.credential_payload_format or "w3c_vcdm_v2_sd_jwt"
    normalized_payload_format = _normalize_payload_format(credential_payload_fmt)
    if normalized_payload_format in _MDOC_PAYLOAD_FORMATS:
        signing_format = "mso_mdoc"
    elif normalized_payload_format in _VDS_NC_PAYLOAD_FORMATS:
        if not _VDSNC_RUST_ENABLED:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="VDS-NC credential issuance is temporarily disabled (VDSNC_RUST_ENABLED=false)",
            )
        signing_format = "vds_nc"
    elif normalized_payload_format in _SD_JWT_PAYLOAD_FORMATS:
        signing_format = "vc+sd-jwt"
    else:
        signing_format = "vc+sd-jwt"

    vct_for_signing = (
        tx.claims.get("_vct")
        or (f"{ISSUER_BASE_URL}/credentials/{credential_type}"
            if credential_type and not credential_type.startswith("http")
            else credential_type)
    )
    signing_credential_type = tx.credential_type if signing_format in ("mso_mdoc", "vds_nc") else vct_for_signing

    # SD-JWT default: all top-level claims if none configured
    sd_claims_dc = tx.selective_disclosure_claims or []
    if signing_format == "vc+sd-jwt" and not sd_claims_dc:
        sd_claims_dc = [k for k in clean_claims if not k.startswith("_")]

    # Step 1: Sign the credential - all credentials require remote signing
    remote_credential_format = _credential_format_for_remote_context(credential_payload_fmt)
    effective_request_format = remote_credential_format
    if signing_format != "vc+sd-jwt":
        raise HTTPException(
            status_code=503,
            detail=_unsupported_remote_signing_format_detail(signing_format, remote_credential_format),
        )

    remote_context: dict[str, Any] | None = None

    # Ensure remote signing is configured for all credentials
    try:
        remote_context = await apply_remote_issuer_context(
            tx,
            credential_format=remote_credential_format,
            force=True,
            raise_on_error=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=_did_resolution_failure_detail(tx, exc)) from exc
    if remote_context:
        await repo.save_transaction(tx)

    if not (tx.issuer_did_override and tx.signing_service_id):
        raise HTTPException(
            status_code=503,
            detail=(
                "Remote signing configuration is required. "
                "Issuer identity and signing service must be configured for this organization."
            ),
        )

    if not remote_context or not isinstance(remote_context.get("service"), dict):
        try:
            remote_context = await resolve_remote_issuer_context(
                tx.organization_id,
                issuer_profile_id=tx.issuer_profile_id,
                issuer_mode=_normalize_issuer_mode(tx.issuer_mode),
                credential_format=remote_credential_format,
                key_purpose=_key_purpose_for_credential_format(remote_credential_format),
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=503, detail=_did_resolution_failure_detail(tx, exc)) from exc
        if remote_context:
            tx.issuer_did_override = remote_context.get("issuer_did") or tx.issuer_did_override
            tx.signing_service_id = remote_context.get("signing_service_id") or tx.signing_service_id
            tx.issuer_profile_id = remote_context.get("issuer_profile_id") or (remote_context.get("issuer_profile") or {}).get("id") or tx.issuer_profile_id
            tx.issuer_mode = _normalize_issuer_mode(remote_context.get("issuer_mode") or (remote_context.get("issuer_profile") or {}).get("issuer_mode") or tx.issuer_mode)
            await repo.save_transaction(tx)
    if not remote_context:
        raise HTTPException(status_code=503, detail="Unable to resolve the remote DID issuer profile for this organization.")

    service = remote_context.get("service") if isinstance(remote_context, dict) else {}
    service = service if isinstance(service, dict) else {}
    signing_algorithm = str(service.get("algorithm") or remote_context.get("algorithm") or "ES256")
    signing_key_reference = remote_context.get("signing_key_reference") if isinstance(remote_context, dict) else None
    verification_method_id = remote_context.get("verification_method_id") if isinstance(remote_context, dict) else None
    effective_issuer_did_dc = tx.issuer_did_override

    async def _remote_sign(payload: bytes, algorithm: str | None) -> dict[str, Any]:
        return await sign_payload_with_remote_service(
            organization_id=tx.organization_id,
            signing_service_id=tx.signing_service_id or "",
            payload=payload,
            algorithm=algorithm or signing_algorithm,
            key_reference=signing_key_reference,
        )

    credential_id = f"urn:uuid:{uuid.uuid4()}"
    revocation_profile_id, status_list_entries = await _allocate_credential_status_list_entries(
        credential_id=credential_id,
        organization_id=tx.organization_id,
        credential_format=_credential_format_for_revocation_profile(tx, effective_request_format),
        revocation_profile_id=tx.revocation_profile_id,
    )
    signing_claims = dict(clean_claims)
    credential_status_claim = _status_list_entries_to_credential_status_claim(status_list_entries)
    if credential_status_claim:
        signing_claims["credentialStatus"] = credential_status_claim

    logger.info(
        "[credential] tx_id=%s signing_path=didcomm format=%s jwt_typ_will_be=%s",
        tx.id,
        effective_request_format,
        effective_request_format,
    )
    jwt_credential, credential_id = await create_sd_jwt_vc_with_remote_signing(
        issuer_did=effective_issuer_did_dc,
        signing_service_id=tx.signing_service_id,
        remote_sign=_remote_sign,
        subject_id=holder_did,
        credential_type=signing_credential_type,
        claims_json=json.dumps(signing_claims),
        expiration_seconds=31536000,
        selective_disclosure_claims=sd_claims_dc,
        algorithm=signing_algorithm,
        signing_key_reference=signing_key_reference,
        verification_method_id=verification_method_id,
        credential_format=effective_request_format,
        credential_id=credential_id,
    )

    # Step 2: Pack into DIDComm v2 envelope
    didcomm_message_json = didcomm_pack_credential(
        credential=jwt_credential,
        credential_format=credential_payload_fmt,
        issuer_did=effective_issuer_did_dc,
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
        expires_at = (tx.issued_at or datetime.now(timezone.utc)) + timedelta(days=tx.validity_days)
        issued_credential = IssuedCredential(
            id=credential_id,
            transaction_id=tx.id,
            organization_id=tx.organization_id,
            credential_template_id=tx.credential_template_id,
            applicant_id=tx.applicant_id,
            subject_did=holder_did,
            issuer_did=effective_issuer_did_dc,
            revocation_profile_id=revocation_profile_id,
            renewed_from_credential_id=tx.renewal_of_credential_id,
            status_list_entries=status_list_entries,
            credential_jwt=jwt_credential,
            credential_hash=hashlib.sha256(jwt_credential.encode("utf-8")).hexdigest(),
            status=CredentialStatus.ACTIVE,
            issued_at=tx.issued_at or datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        await repo.save_credential(issued_credential)
        await record_canvas_credential_claim(
            repo=repo,
            application_id=tx.application_id,
            credential_id=issued_credential.id,
        )
        await _finalize_credential_renewal(tx, issued_credential, repo)
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
        await record_post_issuance_deliveries(
            repo,
            tx,
            issued_credential,
            delivered_target=DeliveryTarget.DIDCOMM_V2,
            delivery_metadata={
                "protocol": "didcomm_v2",
                "service_endpoint": service_endpoint,
                "didcomm_message_id": didcomm_message_id,
            },
        )

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


class RetentionRecordCounts(BaseModel):
    issuance_transactions: int = 0
    applications: int = 0
    authorization_sessions: int = 0
    issuance_events: int = 0
    issued_credentials: int = 0
    total: int = 0


class IssuanceRetentionSummaryResponse(BaseModel):
    organization_id: str
    retention_days: int
    cutoff_at: str
    oldest_retained_record_at: str | None = None
    next_expiry_at: str | None = None
    eligible_for_purge: RetentionRecordCounts
    tracked_scope: list[str] = Field(default_factory=list)


class IssuanceRetentionPurgeResponse(BaseModel):
    organization_id: str
    retention_days: int
    cutoff_at: str
    purged_at: str
    purged_records: RetentionRecordCounts
    next_expiry_at: str | None = None
    oldest_retained_record_at: str | None = None
    tracked_scope: list[str] = Field(default_factory=list)


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


@issuance_router.get("/organizations/{organization_id}/retention", response_model=IssuanceRetentionSummaryResponse)
async def get_organization_retention_summary(
    organization_id: str,
    retention_days: int = Query(30, ge=1, le=3650),
    repo: IIssuanceRepository = Depends(),
) -> IssuanceRetentionSummaryResponse:
    """Return Hosted Pilot retention status for an organization."""
    summary = await repo.get_retention_summary(organization_id, retention_days)
    return IssuanceRetentionSummaryResponse(
        organization_id=summary["organization_id"],
        retention_days=summary["retention_days"],
        cutoff_at=summary["cutoff_at"],
        oldest_retained_record_at=summary.get("oldest_retained_record_at"),
        next_expiry_at=summary.get("next_expiry_at"),
        eligible_for_purge=RetentionRecordCounts(**summary.get("eligible_for_purge", {})),
        tracked_scope=list(summary.get("tracked_scope", [])),
    )


@issuance_router.post("/organizations/{organization_id}/retention/purge", response_model=IssuanceRetentionPurgeResponse)
async def purge_organization_retention_data(
    organization_id: str,
    retention_days: int = Query(30, ge=1, le=3650),
    repo: IIssuanceRepository = Depends(),
) -> IssuanceRetentionPurgeResponse:
    """Purge Hosted Pilot data that has aged past the retention window."""
    purge_result = await repo.purge_retention_records(organization_id, retention_days)
    return IssuanceRetentionPurgeResponse(
        organization_id=purge_result["organization_id"],
        retention_days=purge_result["retention_days"],
        cutoff_at=purge_result["cutoff_at"],
        purged_at=purge_result["purged_at"],
        purged_records=RetentionRecordCounts(**purge_result.get("purged_records", {})),
        next_expiry_at=purge_result.get("next_expiry_at"),
        oldest_retained_record_at=purge_result.get("oldest_retained_record_at"),
        tracked_scope=list(purge_result.get("tracked_scope", [])),
    )


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
    credential: IssuedCredential | None = None,
) -> dict:
    """Delegate revocation action to RevocationProfile service."""
    service_url = (
        os.environ.get("REVOCATION_PROFILE_SERVICE_URL", REVOCATION_PROFILE_SERVICE_URL) or ""
    ).strip().rstrip("/")
    if not service_url:
        raise HTTPException(status_code=503, detail="RevocationProfile service URL is not configured")

    profile_id = credential.revocation_profile_id if credential else None
    if not profile_id:
        raise HTTPException(
            status_code=503,
            detail="Credential has no active credential-status profile binding",
        )
    status_list_index = _revocation_index_from_credential(credential) if credential else None
    if status_list_index is None:
        raise HTTPException(status_code=503, detail="Credential has no allocated status-list entry")

    status_value = {
        "revoke": "revoked",
        "suspend": "suspended",
        "reinstate": "reinstated",
    }.get(action, action)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{service_url}/internal/revocation-profiles/{profile_id}/process-revocation",
                json={
                    "organization_id": credential.organization_id if credential else "",
                    "credential_id": credential_id,
                    "index": status_list_index,
                    "status": status_value,
                    "credential_format": "sd_jwt",
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
    
    # Status changes fail closed: local state must never diverge from the
    # credential's published status-list profile.
    await _delegate_to_revocation_profile(
        credential_id=credential_id,
        action="revoke",
        reason=request.reason,
        credential=cred,
    )
    
    cred.status = CredentialStatus.REVOKED
    cred.status_updated_at = datetime.now(timezone.utc)
    cred.revoked = True
    cred.revoked_at = cred.status_updated_at
    cred.revocation_reason = request.reason
    await repo.save_credential(cred)
    await _sync_canvas_lifecycle_delivery_records(
        cred,
        repo,
        lifecycle_action="revoke",
        reason=request.reason,
    )
    
    logger.info(f"Revoked credential {credential_id}: {request.reason}")
    
    return {
        "id": cred.id,
        "issuer_did": cred.issuer_did,
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
    
    await _delegate_to_revocation_profile(
        credential_id=credential_id,
        action="suspend",
        reason=request.reason,
        credential=cred,
    )
    
    cred.status = CredentialStatus.SUSPENDED
    cred.status_updated_at = datetime.now(timezone.utc)
    await repo.save_credential(cred)
    await _sync_canvas_lifecycle_delivery_records(
        cred,
        repo,
        lifecycle_action="suspend",
        reason=request.reason,
    )
    
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
    
    await _delegate_to_revocation_profile(
        credential_id=credential_id,
        action="reinstate",
        reason=request.reason,
        credential=cred,
    )
    
    cred.status = CredentialStatus.ACTIVE
    cred.status_updated_at = datetime.now(timezone.utc)
    await repo.save_credential(cred)
    await _sync_canvas_lifecycle_delivery_records(
        cred,
        repo,
        lifecycle_action="reinstate",
        reason=request.reason,
    )
    
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
        "issuer_did": cred.issuer_did,
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


@issued_credential_router.post(
    "/{credential_id}/deliveries/canvas-credentials/publish",
    response_model=CredentialDeliveryRecordResponse,
    dependencies=[Depends(_verify_management_api_key)],
)
async def publish_issued_credential_canvas_mirror(
    credential_id: str,
    repo: IIssuanceRepository = Depends(),
) -> CredentialDeliveryRecordResponse:
    cred = await repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Issued credential not found")

    tx = await repo.get_transaction(cred.transaction_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Issuance transaction not found for credential")

    delivery_records = await repo.list_delivery_records_for_credential(cred.id)
    canvas_record = next(
        (record for record in delivery_records if record.delivery_target == DeliveryTarget.CANVAS_CREDENTIALS),
        None,
    )
    if canvas_record is None:
        raise HTTPException(status_code=409, detail="No Canvas mirror delivery record exists for this credential")
    canvas_record = await _process_canvas_mirror_delivery_record(
        canvas_record,
        repo,
        credential=cred,
        transaction=tx,
    )
    if canvas_record.status != CredentialDeliveryStatus.DELIVERED:
        raise HTTPException(
            status_code=_canvas_delivery_failure_status_code(canvas_record.last_error),
            detail=canvas_record.last_error or "Canvas Credentials publish failed",
        )
    return _delivery_record_to_protocol(canvas_record)


@issuance_router.post(
    "/delivery-records/canvas-credentials/process-pending",
    response_model=CanvasMirrorBatchProcessResponse,
    dependencies=[Depends(_verify_management_api_key)],
)
async def process_pending_canvas_mirror_deliveries(
    organization_id: str | None = Query(None),
    limit: int = Query(25, ge=1, le=200),
    retry_failed: bool = Query(False),
    repo: IIssuanceRepository = Depends(),
) -> CanvasMirrorBatchProcessResponse:
    return await run_canvas_mirror_publish_batch(
        repo,
        organization_id=organization_id,
        limit=limit,
        retry_failed=retry_failed,
    )


@issuance_router.post(
    "/delivery-records/canvas-credentials/process-status-sync-failures",
    response_model=CanvasMirrorStatusSyncBatchResponse,
    dependencies=[Depends(_verify_management_api_key)],
)
async def process_failed_canvas_mirror_status_syncs(
    organization_id: str | None = Query(None),
    limit: int = Query(25, ge=1, le=200),
    repo: IIssuanceRepository = Depends(),
) -> CanvasMirrorStatusSyncBatchResponse:
    return await run_canvas_mirror_status_sync_batch(
        repo,
        organization_id=organization_id,
        limit=limit,
    )


@issuance_router.post(
    "/delivery-records/canvas-credentials/run-automation-cycle",
    response_model=CanvasMirrorAutomationCycleResponse,
    dependencies=[Depends(_verify_management_api_key)],
)
async def run_canvas_mirror_automation_cycle_endpoint(
    organization_id: str | None = Query(None),
    limit: int = Query(25, ge=1, le=200),
    retry_failed: bool = Query(True),
    repo: IIssuanceRepository = Depends(),
) -> CanvasMirrorAutomationCycleResponse:
    return await run_canvas_mirror_automation_cycle(
        repo,
        organization_id=organization_id,
        limit=limit,
        retry_failed=retry_failed,
    )


@issuance_router.get(
    "/organizations/{organization_id}/canvas-mirror-health",
    response_model=CanvasMirrorHealthResponse,
    dependencies=[Depends(_verify_management_api_key)],
)
async def get_canvas_mirror_health(
    organization_id: str,
    repo: IIssuanceRepository = Depends(),
) -> CanvasMirrorHealthResponse:
    records = await repo.list_delivery_records(
        delivery_target=DeliveryTarget.CANVAS_CREDENTIALS,
        organization_id=organization_id,
    )

    pending_publish_count = sum(1 for record in records if record.status == CredentialDeliveryStatus.PENDING)
    failed_publish_records = [record for record in records if record.status == CredentialDeliveryStatus.FAILED]
    failed_publish_count = len(failed_publish_records)
    delivered_records = [record for record in records if record.status == CredentialDeliveryStatus.DELIVERED]
    blocked_records = [
        record for record in records
        if (record.metadata or {}).get("canvas_feature_gate_blocked")
    ]
    lifecycle_sync_failed_records = [
        record for record in delivered_records
        if _delivery_record_has_status_sync_failure(record)
    ]
    lifecycle_sync_ok_records = [
        record for record in delivered_records
        if not _delivery_record_has_status_sync_failure(record)
    ]
    warning_threshold = _env_int("CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS", 3)
    critical_threshold = max(
        warning_threshold,
        _env_int("CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS", 5),
    )
    publish_failure_alerts = [
        alert
        for record in failed_publish_records
        if (alert := _canvas_mirror_alert_for_record(
            record,
            alert_type="publish_failure",
            attempt_key="publish_attempts",
            error_at_key="last_error_at",
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
        )) is not None
    ]
    lifecycle_sync_alerts = [
        alert
        for record in lifecycle_sync_failed_records
        if (alert := _canvas_mirror_alert_for_record(
            record,
            alert_type="lifecycle_sync_failure",
            attempt_key="status_sync_attempts",
            error_at_key="last_status_sync_error_at",
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
        )) is not None
    ]
    alerts = sorted(
        [*publish_failure_alerts, *lifecycle_sync_alerts],
        key=lambda alert: (
            0 if alert.severity == "critical" else 1,
            -alert.attempt_count,
            alert.delivery_record_id,
        ),
    )
    critical_alert_count = sum(1 for alert in alerts if alert.severity == "critical")
    warning_alert_count = sum(1 for alert in alerts if alert.severity == "warning")
    publish_attempts = [
        _metadata_int(record.metadata, "publish_attempts")
        for record in failed_publish_records
    ]
    status_sync_attempts = [
        _metadata_int(record.metadata, "status_sync_attempts")
        for record in lifecycle_sync_failed_records
    ]

    return CanvasMirrorHealthResponse(
        organization_id=organization_id,
        pending_publish_count=pending_publish_count,
        failed_publish_count=failed_publish_count,
        delivered_count=len(delivered_records),
        lifecycle_sync_failed_count=len(lifecycle_sync_failed_records),
        lifecycle_sync_ok_count=len(lifecycle_sync_ok_records),
        repeated_publish_failure_count=len(publish_failure_alerts),
        repeated_lifecycle_sync_failure_count=len(lifecycle_sync_alerts),
        warning_alert_count=warning_alert_count,
        critical_alert_count=critical_alert_count,
        alert_count=len(alerts),
        alert_thresholds={
            "warning_attempts": warning_threshold,
            "critical_attempts": critical_threshold,
        },
        metrics={
            "publish.pending": pending_publish_count,
            "publish.failed": failed_publish_count,
            "publish.delivered": len(delivered_records),
            "publish.blocked": len(blocked_records),
            "status_sync.retry_pending": len(lifecycle_sync_failed_records),
            "status_sync.ok": len(lifecycle_sync_ok_records),
            "publish_failure_attempts_total": sum(publish_attempts),
            "status_sync_failure_attempts_total": sum(status_sync_attempts),
            "max_publish_failure_attempts": max(publish_attempts, default=0),
            "max_status_sync_failure_attempts": max(status_sync_attempts, default=0),
            "repeated_publish_failure_count": len(publish_failure_alerts),
            "repeated_lifecycle_sync_failure_count": len(lifecycle_sync_alerts),
        },
        alerts=alerts,
        last_successful_publish_at=_max_iso_datetime([
            (record.metadata or {}).get("published_at")
            for record in delivered_records
        ]),
        last_lifecycle_sync_failure_at=_max_iso_datetime([
            (record.metadata or {}).get("last_status_sync_error_at")
            for record in lifecycle_sync_failed_records
        ]),
        last_lifecycle_sync_success_at=_max_iso_datetime([
            (record.metadata or {}).get("status_synced_at")
            for record in lifecycle_sync_ok_records
        ]),
    )


@issuance_router.get(
    "/delivery-records/canvas-credentials/provenance",
    response_model=CanvasMirrorProvenanceResponse,
)
async def get_canvas_mirror_provenance(
    delivery_record_id: str | None = None,
    external_credential_id: str | None = None,
    credential_id: str | None = None,
    canvas_account_id: str | None = None,
    organization_id: str | None = None,
    repo: IIssuanceRepository = Depends(),
) -> CanvasMirrorProvenanceResponse:
    record = await _resolve_canvas_mirror_delivery_record(
        repo=repo,
        delivery_record_id=delivery_record_id,
        external_credential_id=external_credential_id,
        credential_id=credential_id,
        canvas_account_id=canvas_account_id,
        organization_id=organization_id,
    )
    return await _canvas_mirror_provenance_to_protocol(record, repo)


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


@issued_credential_router.post(
    "/{credential_id}/renew",
    response_model=CredentialRenewalOfferResponse,
    dependencies=[Depends(_verify_management_api_key)],
)
async def renew_issued_credential(
    credential_id: str,
    http_request: Request,
    repo: IIssuanceRepository = Depends(),
) -> CredentialRenewalOfferResponse:
    source = await repo.get_credential(credential_id)
    if not source:
        raise HTTPException(status_code=404, detail="Issued credential not found")
    if source.status != CredentialStatus.ACTIVE:
        raise HTTPException(status_code=409, detail="Only active credentials can be renewed.")
    if source.renewed_to_credential_id:
        raise HTTPException(status_code=409, detail="Credential has already been renewed.")

    source_tx = await repo.get_transaction(source.transaction_id)
    if not source_tx:
        raise HTTPException(status_code=409, detail="Source issuance transaction is unavailable.")
    if not source_tx.renewable:
        raise HTTPException(status_code=409, detail="Credential Template does not allow renewal.")
    if not source.expires_at:
        raise HTTPException(status_code=409, detail="Credential has no renewal eligibility date.")

    eligible_at = source.expires_at - timedelta(days=source_tx.renewal_window_days)
    if datetime.now(timezone.utc) < eligible_at:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "RENEWAL_NOT_YET_AVAILABLE",
                "message": "Credential is outside its renewal window.",
                "eligible_at": eligible_at.isoformat(),
            },
        )

    offer = await initiate_issuance(
        InitiateIssuanceRequest(
            organization_id=source.organization_id,
            credential_template_id=source.credential_template_id,
            applicant_id=source.applicant_id,
            subject_did=source.subject_did,
            issuer_profile_id=source_tx.issuer_profile_id,
            issuer_mode=source_tx.issuer_mode,
            delivery_mode=source_tx.delivery_mode,
            claims=dict(source_tx.claims),
        ),
        http_request=http_request,
        repo=repo,
    )
    renewal_tx = await repo.get_transaction(offer.id)
    if not renewal_tx:
        raise HTTPException(status_code=503, detail="Renewal transaction was not persisted.")
    renewal_tx.renewal_of_credential_id = source.id
    renewal_tx.application_id = source_tx.application_id
    await repo.save_transaction(renewal_tx)
    return CredentialRenewalOfferResponse(
        source_credential_id=source.id,
        transaction_id=offer.id,
        credential_offer_uri=offer.credential_offer_uri,
        credential_offer_uris=offer.credential_offer_uris,
        credential_offer_labels=offer.credential_offer_labels,
        expires_at=offer.expires_at,
    )


# Continued in next part...
