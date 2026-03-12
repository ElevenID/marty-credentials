"""OID4VCI HTTP API endpoints."""

import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Form, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from issuance.application.rust_integration import (
    get_marty_rs,
    get_or_generate_issuer_key,
    create_verifiable_credential_wrapper,
    oid4vci_create_credential_offer,
    oid4vci_create_token_response,
    oid4vci_create_authorization_response,
    oid4vci_exchange_auth_code_for_token,
    oid4vci_verify_pkce_s256,
    verify_proof_jwt,
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
)
from issuance.domain.ports import IIssuanceRepository

logger = logging.getLogger(__name__)

# Configuration
REVOCATION_PROFILE_SERVICE_URL = os.environ.get(
    "REVOCATION_PROFILE_SERVICE_URL", "http://localhost:8013"
)
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

# Routers
issuance_router = APIRouter(prefix="/v1/issuance", tags=["issuance"])
application_template_router = APIRouter(prefix="/v1/application-templates", tags=["application-templates"])
application_router = APIRouter(prefix="/v1/applications", tags=["applications"])


# ============================================================================
# Request/Response Models
# ============================================================================

class InitiateIssuanceRequest(BaseModel):
    organization_id: str
    credential_template_id: str | None = None  # Optional — falls back to default type
    applicant_id: str | None = None
    subject_did: str | None = None
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
    # c_nonce_expires_in intentionally omitted: the SpruceID mobile-sdk-rs
    # ExtraResponseTokenFields has `c_nonce_expires_in: Option<Duration>` which
    # uses serde's native Duration format `{"secs":N,"nanos":N}` — NOT a plain
    # integer.  Sending `300` causes a deserialization error that manifests as
    # "HTTP request error: failed to exchange code".  The field is Optional so
    # absent == None == accepted by all clients (SpruceKit, Walt.id, etc.).
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


# ============================================================================
# OID4VCI Endpoints
# ============================================================================

@issuance_router.post("/initiate", response_model=IssuanceResponse)
async def initiate_issuance(
    request: InitiateIssuanceRequest,
    repo: IIssuanceRepository = Depends(),
) -> IssuanceResponse:
    """Initiate a credential issuance transaction.

    Client errors from the org or template services (4xx) are hard failures
    so callers receive a proper 4xx response.  Network / 5xx failures are
    logged and allowed to proceed for internal service-to-service resilience.
    """

    # Validate organization exists — treat any 4xx from the org service as a
    # hard failure so that callers with invalid org IDs get a proper error
    # rather than a silently created transaction.  Network / 5xx failures are
    # logged and allowed to proceed (internal service-to-service resilience).
    try:
        org_url = f"http://organization:8002/internal/v1/organizations/{request.organization_id}"
        async with httpx.AsyncClient(timeout=5.0) as client:
            org_response = await client.get(org_url)
            if org_response.status_code >= 400:
                raise HTTPException(
                    status_code=404,
                    detail=f"Organization not found: {request.organization_id}",
                )
    except HTTPException:
        raise  # Hard fail — propagate to caller
    except Exception as e:
        logger.warning(f"Could not validate organization {request.organization_id} (proceeding): {e}")

    # Resolve credential type from template — treat 4xx as hard failures.
    credential_type = "org.iso.18013.5.1.mDL"  # Default fallback
    credential_vct: str | None = None
    zk_predicate_claims: list[str] = []
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    wallet_configs: list[dict] = []
    if request.credential_template_id:
        try:
            template_url = f"http://credential-template:8003/v1/credential-templates/{request.credential_template_id}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(template_url)
                if response.status_code == 404:
                    raise HTTPException(status_code=404, detail=f"Credential template not found: {request.credential_template_id}")
                if 400 <= response.status_code < 500:
                    raise HTTPException(status_code=404, detail=f"Credential template not found: {request.credential_template_id}")
                response.raise_for_status()
                template = response.json()
                credential_type = template.get("credential_type", credential_type)
                # RFC 9596: vct MUST be a URI.  Prefer the template's explicit vct field;
                # fall back to building a URI from the credential_type.
                raw_vct = template.get("vct") or ""
                credential_vct = (
                    raw_vct if raw_vct.startswith("http")
                    else f"{ISSUER_BASE_URL}/credentials/{credential_type}"
                )
                logger.info(f"Fetched credential type from template: {credential_type} vct={credential_vct}")
                zk_predicate_claims = template.get("zk_predicate_claims") or []
                credential_payload_format = template.get("credential_payload_format") or "w3c_vcdm_v2_sd_jwt"
                wallet_configs = template.get("wallet_configs") or []
        except HTTPException:
            raise  # Hard fail — propagate to caller
        except Exception as e:
            logger.warning(f"Could not fetch credential template {request.credential_template_id} (using default type): {e}")

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
        return f"{base}#sd-jwt"

    # Default offer uses the standard vc+sd-jwt config (works with Walt.id and
    # most OID4VCI-compliant wallets).  For mso_mdoc templates, use the #mdoc
    # config id so the default offer also resolves to the correct metadata entry.
    default_fmt_variant = "mso_mdoc" if credential_payload_format == "mso_mdoc" else None
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
    for wc in tx.wallet_configs:
        wid = wc.get("wallet_id", "")
        scheme = wc.get("deep_link_scheme", "openid-credential-offer://")
        fmt_variant = wc.get("format_variant")
        if wid:
            wallet_config_id = _config_id_for_format_variant(credential_config_id, fmt_variant)
            # SpruceID SDK requires a dedicated issuer URL whose metadata document
            # only emits formats its ProfilesCredentialConfiguration enum can parse.
            # This applies to both spruce-vc+sd-jwt AND mso_mdoc — any unrecognised
            # entry in the standard metadata causes the whole fetch to fail.
            wallet_issuer_url = (
                org_issuer_url_spruce(request.organization_id)
                if fmt_variant in ("spruce-vc+sd-jwt", "mso_mdoc")
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

@issuance_router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(None),
    state: str = Query(None),
    code_challenge: str = Query(None),
    code_challenge_method: str = Query(None),
    issuer_state: str = Query(None),
    authorization_details: str = Query(None),
    scope: str = Query(None),
    organization_id: str = Query(None),
    repo: IIssuanceRepository = Depends(),
):
    """OAuth 2.0 authorization endpoint for OID4VCI authorization code flow.

    The authorization request parameters arrive as query params (RFC 6749 §4.1.1).
    We delegate all protocol validation (response_type, PKCE, etc.) to the Rust
    engine and only handle DB persistence here.
    """
    import json as _json

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


@issuance_router.post("/token", response_model=TokenResponse)
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

    logger.info(
        f"[token] rid={rid} tx_id={tx.id} org={tx.organization_id} "
        f"cred_type={tx.credential_type} access_token={tx.access_token[:16]}... "
        f"nonce={tx.nonce[:8]}..."
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
    """
    import uuid as _uuid
    new_nonce = str(_uuid.uuid4())

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
        if request.credential_configuration_id not in valid_config_ids:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_credential_request",
                    "error_description": f"Unknown credential_configuration_id: {request.credential_configuration_id!r}",
                },
            )

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
        issuer_key = get_or_generate_issuer_key(tx.organization_id)
    except ImportError as e:
        logger.error(f"Rust bindings not available: {e}")
        tx.fail("Rust bindings not available")
        await repo.save_transaction(tx)
        raise HTTPException(status_code=500, detail="Credential signing service unavailable")
    
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
    # mso_mdoc: always forced regardless of what the wallet requests.
    # spruce-vc+sd-jwt: SpruceKit's custom alias — normalise to vc+sd-jwt for Rust;
    #   the response uses the original request.format so SpruceKit parses it correctly.
    if credential_payload_fmt == "mso_mdoc":
        signing_format = "mso_mdoc"
    elif request.format == "spruce-vc+sd-jwt":
        signing_format = "vc+sd-jwt"
    else:
        signing_format = request.format
    # For mdoc, credential_type is the doctype; Rust defaults to org.iso.18013.5.1.mDL
    # when mdoc_doctype is None, so tx.credential_type is passed through directly.
    signing_credential_type = tx.credential_type if signing_format == "mso_mdoc" else vct_for_signing
    try:
        jwt_credential, credential_id = create_verifiable_credential_wrapper(
            issuer_did=issuer_key["did"],
            issuer_jwk_json="",  # Not used - kept for API compatibility
            subject_id=holder_did or tx.subject_did,
            credential_type=signing_credential_type,
            claims_json=json.dumps(clean_claims),
            expiration_seconds=31536000,  # 1 year
            organization_id=tx.organization_id,
            format=signing_format,
            zk_predicate_claims=tx.zk_predicate_claims or [],
            credential_payload_format=credential_payload_fmt,
        )
        
        # Only update state and emit event on first issuance; allow idempotent
        # wallet retries (wallets sometimes re-request after a network timeout).
        if tx.status == IssuanceStatus.AUTHORIZED:
            tx.complete()
            await repo.save_transaction(tx)
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
        raise HTTPException(status_code=500, detail=f"Credential creation failed: {e}")


@issuance_router.post("/deferred-credential")
async def deferred_credential(
    http_request: Request,
    authorization: str | None = Header(None),
    repo: IIssuanceRepository = Depends(),
) -> dict:
    """OID4VCI-1FINAL §9.1 — Deferred Credential Endpoint.

    Accepts a transaction_id and returns the credential if available.
    All credentials in this service are issued synchronously, so this endpoint
    always returns 400 (no pending deferred transactions).  The endpoint itself
    MUST exist so that wallets can discover it via metadata and so that the
    conformance test ``deferred_credential_endpoint_present`` passes.
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
    # All credentials are issued synchronously; no deferred transactions exist.
    from fastapi.responses import JSONResponse as _JSONResponse
    return _JSONResponse(
        status_code=400,
        content={"error": "invalid_transaction_id", "error_description": "No deferred transaction found"},
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
                detail=f"Revocation service unavailable: {str(e)}"
            )


@issuance_router.post("/credentials/{credential_id}/revoke", response_model=CredentialStatusResponse)
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


@issuance_router.post("/credentials/{credential_id}/suspend", response_model=CredentialStatusResponse)
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


@issuance_router.post("/credentials/{credential_id}/reinstate", response_model=CredentialStatusResponse)
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


# Continued in next part...
