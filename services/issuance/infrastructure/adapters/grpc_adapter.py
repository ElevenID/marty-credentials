"""
Issuance Service gRPC Adapter (Inbound)

Implements the IssuanceService gRPC servicer, delegating to the same
PostgreSQL repository and Rust FFI that back the REST endpoints.
Includes server streaming for real-time credential lifecycle events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import grpc

from marty_proto.v1 import (
    issuance_service_pb2 as pb2,
    issuance_service_pb2_grpc,
)

logger = logging.getLogger(__name__)

REVOCATION_PROFILE_SERVICE_URL = os.environ.get(
    "REVOCATION_PROFILE_SERVICE_URL", "http://localhost:8013"
)
CREDENTIAL_TEMPLATE_SERVICE_URL = os.environ.get(
    "CREDENTIAL_TEMPLATE_SERVICE_URL", "http://localhost:8003"
)
ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

_MDOC_PAYLOAD_FORMATS = {"mso_mdoc", "MDOC", "mdoc"}
_VDS_NC_PAYLOAD_FORMATS = {"vds_nc", "VDS_NC", "vdsnc"}
_SD_JWT_PAYLOAD_FORMATS = {
    "w3c_vcdm_v2_sd_jwt", "ietf_sd_jwt",
    "SD_JWT_VC", "sd_jwt_vc",
    "vc+sd-jwt", "dc+sd-jwt", "spruce-vc+sd-jwt",
}


def _org_issuer_url(org_id: str) -> str:
    return f"{ISSUER_BASE_URL}/org/{org_id}"


def _credential_format_for_remote_context(payload_format: str | None, request_format: str | None = None) -> str:
    normalized_payload = (payload_format or "").strip().lower().replace("-", "_")
    normalized_request = (request_format or "").strip().lower().replace("-", "_")
    if normalized_payload in {"mso_mdoc", "mdoc"}:
        return "mso_mdoc"
    if normalized_payload in {"vds_nc", "vdsnc"}:
        return "vds_nc"
    if normalized_request in {"jwt_vc_json", "jwt_vc"}:
        return "jwt_vc_json"
    return "dc+sd-jwt"


def _key_purpose_for_credential_format(credential_format: str) -> str:
    if credential_format in {"mso_mdoc", "zk_mdoc"}:
        return "mdoc_dsc"
    if credential_format == "vds_nc":
        return "vdsnc_signing"
    return "vc_jwt_issuer"


async def _resolve_remote_signing_context_for_tx(
    tx: Any,
    *,
    credential_format: str,
) -> dict[str, Any]:
    """Resolve and attach the org-scoped DID issuer context for gRPC issuance."""
    from issuance.infrastructure.api.signing_context import resolve_remote_issuer_context

    context = await resolve_remote_issuer_context(
        tx.organization_id,
        issuer_profile_id=getattr(tx, "issuer_profile_id", None),
        issuer_mode=getattr(tx, "issuer_mode", "org_managed"),
        credential_format=credential_format,
        key_purpose=_key_purpose_for_credential_format(credential_format),
    )
    if not context:
        raise RuntimeError("No active DID issuer profile is configured for this organization")

    issuer_did = context.get("issuer_did")
    signing_service_id = context.get("signing_service_id")
    if not issuer_did or not signing_service_id:
        raise RuntimeError("Resolved DID issuer context is missing issuer_did or signing_service_id")

    tx.issuer_did_override = issuer_did
    tx.signing_service_id = signing_service_id
    tx.issuer_profile_id = context.get("issuer_profile_id") or (context.get("issuer_profile") or {}).get("id") or getattr(tx, "issuer_profile_id", None)
    tx.issuer_mode = context.get("issuer_mode") or (context.get("issuer_profile") or {}).get("issuer_mode") or getattr(tx, "issuer_mode", "org_managed")
    return context


async def _create_remote_signed_sd_jwt_for_tx(
    tx: Any,
    *,
    subject_id: str | None,
    credential_type: str,
    claims_json: str,
    credential_format: str,
    selective_disclosure_claims: list[str] | None = None,
) -> tuple[str, str, dict[str, Any]]:
    """Create an SD-JWT credential signed by the org-scoped remote DID key."""
    from issuance.application.rust_integration import create_sd_jwt_vc_with_remote_signing
    from issuance.infrastructure.api.signing_context import sign_payload_with_remote_service

    remote_context = await _resolve_remote_signing_context_for_tx(tx, credential_format=credential_format)
    service = remote_context.get("service") if isinstance(remote_context.get("service"), dict) else {}
    algorithm = str(service.get("algorithm") or remote_context.get("algorithm") or "ES256")
    signing_key_reference = remote_context.get("signing_key_reference") if isinstance(remote_context, dict) else None
    verification_method_id = remote_context.get("verification_method_id") if isinstance(remote_context, dict) else None

    async def _remote_sign(payload: bytes, algorithm_hint: str | None) -> dict[str, Any]:
        return await sign_payload_with_remote_service(
            organization_id=tx.organization_id,
            signing_service_id=tx.signing_service_id,
            payload=payload,
            algorithm=algorithm_hint or algorithm,
            key_reference=signing_key_reference,
        )

    credential, credential_id = await create_sd_jwt_vc_with_remote_signing(
        issuer_did=tx.issuer_did_override,
        signing_service_id=tx.signing_service_id,
        remote_sign=_remote_sign,
        subject_id=subject_id,
        credential_type=credential_type,
        claims_json=claims_json,
        expiration_seconds=31536000,
        selective_disclosure_claims=selective_disclosure_claims or [],
        algorithm=algorithm,
        signing_key_reference=signing_key_reference,
        verification_method_id=verification_method_id,
        credential_format=credential_format,
    )
    return credential, credential_id, remote_context


def _tx_to_pb(tx: Any) -> pb2.TransactionResponse:
    """Map IssuanceTransaction → protobuf TransactionResponse."""
    return pb2.TransactionResponse(
        id=tx.id,
        organization_id=tx.organization_id,
        credential_template_id=tx.credential_template_id or "",
        status=tx.status.value if hasattr(tx.status, "value") else str(tx.status),
        applicant_id=tx.applicant_id or "",
        subject_did=tx.subject_did or "",
        created_at=tx.created_at.isoformat() if tx.created_at else "",
        updated_at=tx.created_at.isoformat() if tx.created_at else "",
    )


class IssuanceServiceGrpc(issuance_service_pb2_grpc.IssuanceServiceServicer):
    """gRPC inbound adapter for the issuance service."""

    def __init__(self, get_repo_fn: Any) -> None:
        self._get_repo = get_repo_fn
        # Active streaming subscribers: subscriber_id → asyncio.Queue
        self._stream_queues: dict[str, asyncio.Queue] = {}

    # ------------------------------------------------------------------ #
    # InitiateIssuance
    # ------------------------------------------------------------------ #

    async def InitiateIssuance(self, request, context):
        """Initiate a credential offer (OID4VCI)."""
        try:
            from issuance.domain.entities import IssuanceTransaction
            from issuance.application.rust_integration import oid4vci_create_credential_offer

            repo = self._get_repo()

            # Validate organization exists via gRPC (best-effort)
            try:
                import grpc.aio as grpc_aio
                from marty_proto.v1 import organization_service_pb2 as org_pb2
                from marty_proto.v1 import organization_service_pb2_grpc as org_grpc

                org_grpc_target = os.environ.get("ORG_GRPC_TARGET", "organization:9002")
                async with grpc_aio.insecure_channel(org_grpc_target) as channel:
                    org_stub = org_grpc.OrganizationServiceStub(channel)
                    org_resp = await org_stub.GetOrganization(
                        org_pb2.GetOrganizationRequest(organization_id=request.organization_id)
                    )
                    if not org_resp.id:
                        context.set_code(grpc.StatusCode.NOT_FOUND)
                        context.set_details(f"Organization not found: {request.organization_id}")
                        return pb2.IssuanceResponse()
            except grpc.RpcError as e:
                if e.code() in (grpc.StatusCode.NOT_FOUND,):
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details(f"Organization not found: {request.organization_id}")
                    return pb2.IssuanceResponse()
                logger.warning(f"Could not validate org {request.organization_id}: {e}")
            except Exception as e:
                logger.warning(f"Could not validate org {request.organization_id}: {e}")

            # Resolve credential type from template via HTTP
            credential_type = "org.iso.18013.5.1.mDL"
            credential_vct: str | None = None
            zk_predicate_claims: list[str] = []
            credential_payload_format = "w3c_vcdm_v2_sd_jwt"
            wallet_configs: list[dict] = []

            if request.credential_template_id:
                # Fetch template via gRPC (CredentialTemplateService.GetTemplate)
                try:
                    import grpc.aio as grpc_aio
                    from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
                    from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc

                    ct_grpc_target = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")
                    async with grpc_aio.insecure_channel(ct_grpc_target) as channel:
                        ct_stub = ct_grpc.CredentialTemplateServiceStub(channel)
                        tmpl_resp = await ct_stub.GetTemplate(
                            ct_pb2.GetTemplateRequest(template_id=request.credential_template_id)
                        )
                    if not tmpl_resp.id:
                        context.set_code(grpc.StatusCode.NOT_FOUND)
                        context.set_details(f"Credential template not found: {request.credential_template_id}")
                        return pb2.IssuanceResponse()

                    credential_type = tmpl_resp.credential_type or credential_type
                    raw_vct = tmpl_resp.vct or ""
                    credential_vct = (
                        raw_vct if raw_vct.startswith("http")
                        else f"{ISSUER_BASE_URL}/credentials/{credential_type}"
                    )
                    zk_predicate_claims = list(tmpl_resp.zk_predicate_claims) or []
                    credential_payload_format = tmpl_resp.credential_payload_format or "w3c_vcdm_v2_sd_jwt"
                    wallet_configs = json.loads(tmpl_resp.wallet_configs_json) if tmpl_resp.wallet_configs_json else []
                except grpc.RpcError as e:
                    if hasattr(e, 'code') and e.code() == grpc.StatusCode.NOT_FOUND:
                        context.set_code(grpc.StatusCode.NOT_FOUND)
                        context.set_details(f"Credential template not found: {request.credential_template_id}")
                        return pb2.IssuanceResponse()
                    logger.warning(f"gRPC template fetch failed, falling back to HTTP: {e}")
                    # HTTP fallback
                    import httpx
                    url = f"{CREDENTIAL_TEMPLATE_SERVICE_URL}/v1/credential-templates/{request.credential_template_id}"
                    try:
                        async with httpx.AsyncClient(timeout=10.0) as client:
                            resp = await client.get(url)
                        if resp.status_code == 404:
                            context.set_code(grpc.StatusCode.NOT_FOUND)
                            context.set_details(f"Credential template not found: {request.credential_template_id}")
                            return pb2.IssuanceResponse()
                        if resp.status_code >= 400:
                            context.set_code(grpc.StatusCode.INTERNAL)
                            context.set_details(f"Template service error: {resp.text}")
                            return pb2.IssuanceResponse()
                        tmpl = resp.json()
                    except (httpx.ConnectError, httpx.TimeoutException) as http_err:
                        context.set_code(grpc.StatusCode.UNAVAILABLE)
                        context.set_details(f"Credential template service unavailable: {http_err}")
                        return pb2.IssuanceResponse()
                    credential_type = tmpl.get("credential_type") or credential_type
                    raw_vct = tmpl.get("vct") or ""
                    credential_vct = (
                        raw_vct if raw_vct.startswith("http")
                        else f"{ISSUER_BASE_URL}/credentials/{credential_type}"
                    )
                    zk_predicate_claims = tmpl.get("zk_predicate_claims") or []
                    credential_payload_format = tmpl.get("credential_payload_format") or "w3c_vcdm_v2_sd_jwt"
                    wallet_configs = tmpl.get("wallet_configs") or []

            if not credential_vct:
                credential_vct = f"{ISSUER_BASE_URL}/credentials/{credential_type}"

            merged_claims = {**dict(request.claims), "_vct": credential_vct}
            # MIP §8.3 – if the caller deferred claims resolution (only sent
            # _application_id), resolve actual claim values from the application's
            # form_data stored in the issuance service.
            _resolved_application = merged_claims.pop("_application_id", None)
            if _resolved_application and (
                not merged_claims or list(merged_claims.keys()) == ["_vct"]
            ):
                try:
                    app = await repo.get_application(str(_resolved_application))
                    if app and app.form_data:
                        merged_claims = {**app.form_data, "_vct": credential_vct}
                        logger.info(
                            "[grpc-initiate] resolved claims from application %s: keys=%s",
                            _resolved_application, list(app.form_data.keys()),
                        )
                    else:
                        logger.warning(
                            "[grpc-initiate] application %s not found or has empty form_data",
                            _resolved_application,
                        )
                except Exception as _app_err:
                    logger.warning(
                        "[grpc-initiate] could not resolve application %s: %s",
                        _resolved_application, _app_err,
                    )
            effective_template_id = request.credential_template_id or "default"

            tx = IssuanceTransaction(
                organization_id=request.organization_id,
                credential_template_id=effective_template_id,
                applicant_id=request.applicant_id or None,
                subject_did=request.subject_did or None,
                claims=merged_claims,
                credential_type=credential_type,
                zk_predicate_claims=zk_predicate_claims,
                credential_payload_format=credential_payload_format,
                wallet_configs=wallet_configs,
            )
            await repo.save_transaction(tx)

            credential_config_id = credential_type or "default"
            # credential_payload_format may be the enum value "MDOC", the alias
            # "mso_mdoc", or the raw string "mdoc" depending on the code path that
            # stored the template.  All three indicate an mso_mdoc offer.
            _MDOC_PAYLOAD_FORMATS = {"mso_mdoc", "MDOC", "mdoc"}
            default_fmt_variant = "mso_mdoc" if credential_payload_format in _MDOC_PAYLOAD_FORMATS else None
            default_config_id = _config_id_for_format_variant(credential_config_id, default_fmt_variant)

            offer_json_str = oid4vci_create_credential_offer(
                issuer_url=_org_issuer_url(request.organization_id),
                credential_types=[default_config_id],
                pre_authorized_code=tx.pre_auth_code,
                user_pin_required=False,
            )
            offer_uri = f"openid-credential-offer://?credential_offer={quote(offer_json_str)}"

            # Per-wallet offer URIs
            credential_offer_uris: dict[str, str] = {}
            credential_offer_labels: dict[str, str] = {}
            for wc in tx.wallet_configs:
                wid = wc.get("wallet_id", "")
                scheme = wc.get("deep_link_scheme", "openid-credential-offer://")
                fmt_variant = wc.get("format_variant")
                if wid:
                    wallet_config_id = _config_id_for_format_variant(credential_config_id, fmt_variant)
                    wallet_issuer_url = (
                        f"{ISSUER_BASE_URL}/org/{request.organization_id}/spruce"
                        if fmt_variant in ("spruce-vc+sd-jwt", "mso_mdoc")
                        else f"{ISSUER_BASE_URL}/org/{request.organization_id}/credential-manager"
                        if fmt_variant == "credential-manager"
                        else f"{ISSUER_BASE_URL}/org/{request.organization_id}/apple-wallet"
                        if fmt_variant == "apple-wallet"
                        else _org_issuer_url(request.organization_id)
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

            response = pb2.IssuanceResponse(
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

            await self._emit_credential_event(
                "offer_created",
                transaction_id=tx.id,
                organization_id=tx.organization_id,
                credential_template_id=tx.credential_template_id,
                status=tx.status.value,
            )

            return response
        except Exception as exc:
            logger.exception("InitiateIssuance failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.IssuanceResponse()

    # ------------------------------------------------------------------ #
    # ExchangeToken
    # ------------------------------------------------------------------ #

    async def ExchangeToken(self, request, context):
        """Exchange pre-authorized code or authorization code for access token."""
        try:
            from issuance.domain.entities import IssuanceStatus
            from issuance.application.rust_integration import (
                oid4vci_create_token_response,
                oid4vci_exchange_auth_code_for_token,
            )

            repo = self._get_repo()

            # Authorization code flow
            if request.grant_type == "authorization_code":
                if not request.code:
                    context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                    context.set_details("code is required for authorization_code grant")
                    return pb2.TokenResponse()

                auth_session = await repo.get_authorization_session_by_code(request.code)
                if not auth_session:
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details("Invalid authorization code")
                    return pb2.TokenResponse()

                if auth_session.is_expired:
                    context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                    context.set_details("Authorization code expired")
                    return pb2.TokenResponse()

                if auth_session.status != "pending":
                    context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                    context.set_details("Authorization code already used")
                    return pb2.TokenResponse()

                request_payload = json.dumps({
                    "grant_type": "authorization_code",
                    "code": request.code,
                    "redirect_uri": request.redirect_uri or None,
                    "client_id": request.client_id or auth_session.client_id,
                    "code_verifier": request.code_verifier or None,
                })
                session_payload = json.dumps({
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
                    context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                    context.set_details(str(exc))
                    return pb2.TokenResponse()

                auth_session.mark_exchanged(
                    access_token=token_resp["access_token"],
                    nonce=token_resp.get("nonce", ""),
                )
                await repo.save_authorization_session(auth_session)

                return pb2.TokenResponse(
                    access_token=token_resp["access_token"],
                    token_type="Bearer",
                    expires_in=token_resp.get("expires_in", 1800),
                    c_nonce=token_resp.get("nonce", ""),
                    nonce=token_resp.get("nonce", ""),
                )

            # Pre-authorized code flow
            if request.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(f"Unsupported grant type: {request.grant_type}")
                return pb2.TokenResponse()

            if not request.pre_authorized_code:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("pre_authorized_code is required")
                return pb2.TokenResponse()

            tx = await repo.get_by_pre_auth_code(request.pre_authorized_code)
            if not tx:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Invalid pre-authorized code")
                return pb2.TokenResponse()

            if tx.is_expired:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Transaction expired")
                return pb2.TokenResponse()

            if tx.status in (IssuanceStatus.AUTHORIZED, IssuanceStatus.ISSUED):
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Pre-authorized code already used (single-use)")
                return pb2.TokenResponse()

            if tx.status != IssuanceStatus.PENDING:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details(f"Invalid transaction state: {tx.status.value}")
                return pb2.TokenResponse()

            token_resp = oid4vci_create_token_response(request.pre_authorized_code, 1800)

            tx.access_token = token_resp["access_token"]
            tx.nonce = token_resp.get("nonce", "")
            tx.status = IssuanceStatus.AUTHORIZED
            await repo.save_transaction(tx)

            return pb2.TokenResponse(
                access_token=token_resp["access_token"],
                token_type="Bearer",
                expires_in=token_resp.get("expires_in", 1800),
                c_nonce=token_resp.get("nonce", ""),
                nonce=token_resp.get("nonce", ""),
            )
        except Exception as exc:
            logger.exception("ExchangeToken failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.TokenResponse()

    # ------------------------------------------------------------------ #
    # IssueCredential
    # ------------------------------------------------------------------ #

    async def IssueCredential(self, request, context):
        """Issue a credential (requires valid access token and proof JWT)."""
        try:
            from issuance.domain.entities import IssuanceStatus, IssuanceTransaction, EventType, IssuanceEvent
            from issuance.application.rust_integration import (
                verify_proof_jwt,
            )

            repo = self._get_repo()

            if not request.access_token:
                context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                context.set_details("access_token is required")
                return pb2.IssueCredentialResponse()

            tx = await repo.get_by_access_token(request.access_token)
            auth_session = None
            if not tx:
                auth_session = await repo.get_authorization_session_by_access_token(request.access_token)
                if not auth_session:
                    context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                    context.set_details("Invalid access token")
                    return pb2.IssueCredentialResponse()
                if auth_session.issuer_state:
                    tx = await repo.get_by_pre_auth_code(auth_session.issuer_state)
                if not tx:
                    raw_config_id = (
                        auth_session.credential_configuration_ids[0]
                        if auth_session.credential_configuration_ids
                        else "default"
                    )
                    bare_ctype = raw_config_id.split("#")[0]
                    tx = IssuanceTransaction(
                        organization_id=auth_session.organization_id or "",
                        status=IssuanceStatus.AUTHORIZED,
                        access_token=request.access_token,
                        nonce=auth_session.nonce,
                        credential_type=bare_ctype,
                    )
                    await repo.save_transaction(tx)

            if tx.status == IssuanceStatus.ISSUED:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Credential already issued — access token is single-use")
                return pb2.IssueCredentialResponse()

            if tx.status != IssuanceStatus.AUTHORIZED:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details(f"Invalid transaction state: {tx.status.value}")
                return pb2.IssueCredentialResponse()

            # Extract proof JWT
            proof_jwt: str | None = None
            if request.proofs:
                for p in request.proofs:
                    if p.proof_type == "jwt" and p.jwt:
                        proof_jwt = p.jwt
                        break

            if not proof_jwt:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Proof of possession is required (OID4VCI §7.2)")
                return pb2.IssueCredentialResponse()

            # Verify proof JWT
            ok, holder_did, verify_err = verify_proof_jwt(
                proof_jwt, expected_nonce=tx.nonce or None
            )
            if not ok:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(verify_err or "Proof verification failed")
                return pb2.IssueCredentialResponse()

            credential_type = tx.credential_type or "org.iso.18013.5.1.mDL"
            _INTERNAL_CLAIM_FIELDS = {
                "credential_offer_uri", "credential_offer_uris", "offer_expires_at",
                "issuance_transaction_id", "issuance_fallback", "credential_type",
                "credential_display_name", "rejection_reason", "review_notes",
                "info_requests", "applicant_id", "_vct",
            }
            clean_claims = {k: v for k, v in tx.claims.items() if k not in _INTERNAL_CLAIM_FIELDS}

            vct_for_signing = (
                tx.claims.get("_vct")
                or (f"{ISSUER_BASE_URL}/credentials/{credential_type}"
                    if credential_type and not credential_type.startswith("http")
                    else credential_type)
            )

            credential_payload_fmt = tx.credential_payload_format or "w3c_vcdm_v2_sd_jwt"
            fmt = request.format or "vc+sd-jwt"
            _SD_JWT_PAYLOAD_FORMATS = {
                "w3c_vcdm_v2_sd_jwt", "ietf_sd_jwt",
                "SD_JWT_VC", "sd_jwt_vc",
                "vc+sd-jwt", "dc+sd-jwt",
            }
            if credential_payload_fmt == "mso_mdoc":
                signing_format = "mso_mdoc"
            elif credential_payload_fmt in _SD_JWT_PAYLOAD_FORMATS:
                signing_format = "vc+sd-jwt"
            elif fmt == "spruce-vc+sd-jwt":
                signing_format = "vc+sd-jwt"
            else:
                signing_format = fmt

            signing_credential_type = tx.credential_type if signing_format == "mso_mdoc" else vct_for_signing
            if signing_format != "vc+sd-jwt":
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details(
                    "gRPC issuance requires DID-backed remote signing; "
                    f"format {signing_format!r} is not yet supported on this adapter"
                )
                return pb2.IssueCredentialResponse()

            remote_credential_format = _credential_format_for_remote_context(credential_payload_fmt, fmt)
            try:
                jwt_credential, credential_id, _ = await _create_remote_signed_sd_jwt_for_tx(
                    tx,
                    subject_id=holder_did or tx.subject_did,
                    credential_type=signing_credential_type,
                    claims_json=json.dumps(clean_claims),
                    credential_format=remote_credential_format,
                    selective_disclosure_claims=tx.selective_disclosure_claims or [],
                )
            except Exception as signing_err:  # noqa: BLE001
                logger.error("gRPC DID-backed signing failed for tx=%s org=%s: %s", tx.id, tx.organization_id, signing_err)
                context.set_code(grpc.StatusCode.UNAVAILABLE)
                context.set_details(f"DID-backed remote signing failed: {signing_err}")
                return pb2.IssueCredentialResponse()

            if tx.status == IssuanceStatus.AUTHORIZED:
                tx.complete()
                await repo.save_transaction(tx)
                await repo.save_event(IssuanceEvent(
                    transaction_id=tx.id,
                    application_id=tx.application_id,
                    event_type=EventType.CREDENTIAL_ISSUED,
                    metadata={"credential_id": credential_id, "credential_type": credential_type},
                ))

            import uuid as _uuid
            response_format = fmt or signing_format or "vc+sd-jwt"
            response = pb2.IssueCredentialResponse(
                credentials=[pb2.CredentialEntry(format=response_format, credential=jwt_credential)],
                notification_id=str(_uuid.uuid4()),
                c_nonce=tx.nonce or "",
            )

            await self._emit_credential_event(
                "issued",
                credential_id=credential_id if credential_id else "",
                transaction_id=tx.id,
                organization_id=tx.organization_id,
                credential_template_id=tx.credential_template_id or "",
                status="issued",
            )

            return response
        except Exception as exc:
            logger.exception("IssueCredential failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.IssueCredentialResponse()

    # ------------------------------------------------------------------ #
    # DidcommDeliver — DIDComm v2 push delivery
    # ------------------------------------------------------------------ #

    async def DidcommDeliver(self, request, context):
        """Deliver a credential to a holder via DIDComm v2 push.

        Signs the credential, wraps it in a DIDComm v2 issue-credential/3.0
        message, resolves the holder's DID Document, and POSTs the message
        to the holder's DIDComm service endpoint.
        """
        try:
            import hashlib
            import httpx
            from issuance.domain.entities import (
                IssuanceStatus, IssuanceEvent, EventType,
                IssuedCredential, CredentialStatus,
            )
            from issuance.application.rust_integration import (
                didcomm_resolve_did,
                didcomm_extract_endpoint,
                didcomm_pack_credential,
            )
            from datetime import timedelta

            repo = self._get_repo()

            if not request.transaction_id:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("transaction_id is required")
                return pb2.DidcommDeliverResponse()

            if not request.holder_did:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("holder_did is required")
                return pb2.DidcommDeliverResponse()

            tx = await repo.get_transaction(request.transaction_id)
            if not tx:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Transaction not found")
                return pb2.DidcommDeliverResponse()

            if tx.status == IssuanceStatus.ISSUED:
                context.set_code(grpc.StatusCode.ALREADY_EXISTS)
                context.set_details("Credential already issued")
                return pb2.DidcommDeliverResponse()

            if tx.status not in (IssuanceStatus.PENDING, IssuanceStatus.AUTHORIZED):
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details(f"Transaction in {tx.status.value} state")
                return pb2.DidcommDeliverResponse()

            credential_type = tx.credential_type or "VerifiableCredential"
            _INTERNAL_CLAIM_FIELDS = {
                "credential_offer_uri", "credential_offer_uris", "offer_expires_at",
                "issuance_transaction_id", "issuance_fallback", "credential_type",
                "credential_display_name", "rejection_reason", "review_notes",
                "info_requests", "applicant_id", "_vct",
            }
            clean_claims = {k: v for k, v in tx.claims.items() if k not in _INTERNAL_CLAIM_FIELDS}

            ISSUER_BASE_URL = os.environ.get("ISSUER_BASE_URL", "http://localhost:8080")
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

            if signing_format != "vc+sd-jwt":
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details(
                    "gRPC DIDComm delivery requires DID-backed remote signing; "
                    f"format {signing_format!r} is not yet supported on this adapter"
                )
                return pb2.DidcommDeliverResponse()

            remote_credential_format = _credential_format_for_remote_context(credential_payload_fmt)
            try:
                jwt_credential, credential_id, _ = await _create_remote_signed_sd_jwt_for_tx(
                    tx,
                    subject_id=request.holder_did,
                    credential_type=signing_credential_type,
                    claims_json=json.dumps(clean_claims),
                    credential_format=remote_credential_format,
                    selective_disclosure_claims=tx.selective_disclosure_claims or [],
                )
                await repo.save_transaction(tx)
            except Exception as signing_err:  # noqa: BLE001
                logger.error("gRPC DIDComm DID-backed signing failed for tx=%s org=%s: %s", tx.id, tx.organization_id, signing_err)
                context.set_code(grpc.StatusCode.UNAVAILABLE)
                context.set_details(f"DID-backed remote signing failed: {signing_err}")
                return pb2.DidcommDeliverResponse()

            didcomm_message_json = didcomm_pack_credential(
                credential=jwt_credential,
                credential_format=credential_payload_fmt,
                issuer_did=tx.issuer_did_override,
                holder_did=request.holder_did,
                credential_id=credential_id,
            )
            didcomm_msg = json.loads(didcomm_message_json)
            didcomm_message_id = didcomm_msg.get("id", "")

            did_doc = didcomm_resolve_did(
                request.holder_did,
                request.universal_resolver_url or None,
            )
            service_endpoint = didcomm_extract_endpoint(did_doc)
            if not service_endpoint:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details(f"Holder DID {request.holder_did} has no DIDComm service endpoint")
                return pb2.DidcommDeliverResponse()

            delivery_status = "delivered"
            delivery_error = ""
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        service_endpoint,
                        content=didcomm_message_json,
                        headers={"Content-Type": "application/didcomm-plain+json"},
                    )
                    if resp.status_code >= 400:
                        delivery_status = "delivery_failed"
                        delivery_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            except Exception as e:
                delivery_status = "delivery_failed"
                delivery_error = str(e)

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
                    subject_did=request.holder_did,
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

            return pb2.DidcommDeliverResponse(
                transaction_id=tx.id,
                credential_id=credential_id,
                holder_did=request.holder_did,
                service_endpoint=service_endpoint,
                didcomm_message_id=didcomm_message_id,
                status=delivery_status,
                error=delivery_error,
            )
        except Exception as exc:
            logger.exception("DidcommDeliver failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.DidcommDeliverResponse()

    # ------------------------------------------------------------------ #
    # GetOffer
    # ------------------------------------------------------------------ #

    async def GetOffer(self, request, context):
        """Get a credential offer by transaction ID."""
        try:
            from issuance.application.rust_integration import oid4vci_create_credential_offer

            repo = self._get_repo()
            tx = await repo.get_transaction(request.transaction_id)
            if not tx:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Offer not found")
                return pb2.OfferResponse()

            if tx.is_expired:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Offer expired")
                return pb2.OfferResponse()

            offer_json_str = oid4vci_create_credential_offer(
                issuer_url=_org_issuer_url(tx.organization_id),
                credential_types=[tx.credential_type or "default"],
                pre_authorized_code=tx.pre_auth_code,
                user_pin_required=False,
            )
            return pb2.OfferResponse(offer_json=offer_json_str)
        except Exception as exc:
            logger.exception("GetOffer failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.OfferResponse()

    # ------------------------------------------------------------------ #
    # ListTransactions
    # ------------------------------------------------------------------ #

    async def ListTransactions(self, request, context):
        """List issuance transactions for an organization."""
        try:
            repo = self._get_repo()
            txs = await repo.list_transactions(request.organization_id)

            # Apply status filter if provided
            if request.status:
                txs = [t for t in txs if t.status.value == request.status]

            total = len(txs)

            # Apply pagination
            offset = request.offset or 0
            limit = request.limit or 100
            txs = txs[offset:offset + limit]

            return pb2.ListTransactionsResponse(
                transactions=[_tx_to_pb(t) for t in txs],
                total=total,
            )
        except Exception as exc:
            logger.exception("ListTransactions failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.ListTransactionsResponse()

    # ------------------------------------------------------------------ #
    # GetTransaction
    # ------------------------------------------------------------------ #

    async def GetTransaction(self, request, context):
        """Get a single issuance transaction by ID."""
        try:
            repo = self._get_repo()
            tx = await repo.get_transaction(request.transaction_id)
            if not tx:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Transaction not found")
                return pb2.TransactionResponse()
            return _tx_to_pb(tx)
        except Exception as exc:
            logger.exception("GetTransaction failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.TransactionResponse()

    # ------------------------------------------------------------------ #
    # Credential Lifecycle: Revoke / Suspend / Reinstate / GetStatus
    # ------------------------------------------------------------------ #

    async def _credential_lifecycle(self, credential_id: str, action: str, reason: str, context):
        """Shared logic for revoke/suspend/reinstate."""
        from issuance.domain.entities import CredentialStatus

        repo = self._get_repo()
        cred = await repo.get_credential(credential_id)
        if not cred:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Credential not found")
            return pb2.CredentialStatusResponse()

        if action == "revoke":
            if cred.status == CredentialStatus.REVOKED:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Credential already revoked")
                return pb2.CredentialStatusResponse()
            cred.status = CredentialStatus.REVOKED
            cred.revoked = True
            cred.revoked_at = datetime.now(timezone.utc)
            cred.revocation_reason = reason or None

        elif action == "suspend":
            if cred.status == CredentialStatus.REVOKED:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Cannot suspend revoked credential")
                return pb2.CredentialStatusResponse()
            cred.status = CredentialStatus.SUSPENDED

        elif action == "reinstate":
            if cred.status == CredentialStatus.REVOKED:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Cannot reinstate revoked credential")
                return pb2.CredentialStatusResponse()
            if cred.status != CredentialStatus.SUSPENDED:
                context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
                context.set_details("Only suspended credentials can be reinstated")
                return pb2.CredentialStatusResponse()
            cred.status = CredentialStatus.ACTIVE

        cred.status_updated_at = datetime.now(timezone.utc)
        await repo.save_credential(cred)

        # Best-effort delegation to RevocationProfile service
        # Map action to status for RevocationProfile contract
        action_to_status = {"revoke": "revoked", "suspend": "suspended", "reinstate": "reinstated"}
        revocation_status = action_to_status.get(action, action)
        try:
            import grpc.aio as grpc_aio
            from marty_proto.v1 import revocation_profile_service_pb2 as rp_pb2
            from marty_proto.v1 import revocation_profile_service_pb2_grpc as rp_grpc

            rp_grpc_target = os.environ.get("RP_GRPC_TARGET", "revocation-profile:9013")
            async with grpc_aio.insecure_channel(rp_grpc_target) as channel:
                rp_stub = rp_grpc.RevocationProfileServiceStub(channel)
                resp = await rp_stub.ProcessRevocation(
                    rp_pb2.ProcessRevocationRequest(
                        profile_id="default",
                        credential_id=credential_id,
                        index=0,
                        status=revocation_status,
                        reason=reason or "",
                        credential_format="sd_jwt",
                    )
                )
            if not resp.success:
                logger.warning(f"RevocationProfile gRPC returned error for {action}: {resp.error}")
        except Exception as e:
            logger.warning(f"RevocationProfile gRPC failed for {action}, falling back to HTTP: {e}")
            try:
                import httpx
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(
                        f"{REVOCATION_PROFILE_SERVICE_URL}/internal/revocation-profiles/default/process-revocation",
                        json={
                            "credential_id": credential_id,
                            "index": 0,
                            "status": revocation_status,
                            "credential_format": "sd_jwt",
                            "reason": reason or None,
                        },
                    )
            except Exception as http_e:
                logger.warning(f"RevocationProfile HTTP also unavailable for {action}: {http_e}")

        logger.info(f"{action.title()}d credential {credential_id}: {reason}")

        # Emit lifecycle event to stream subscribers
        event_type_map = {"revoke": "revoked", "suspend": "suspended", "reinstate": "reinstated"}
        await self._emit_credential_event(
            event_type_map.get(action, action),
            credential_id=credential_id,
            organization_id=cred.organization_id if hasattr(cred, "organization_id") else "",
            credential_template_id=cred.credential_template_id if hasattr(cred, "credential_template_id") else "",
            status=cred.status.value,
        )

        return pb2.CredentialStatusResponse(
            id=cred.id,
            status=cred.status.value,
            status_updated_at=cred.status_updated_at.isoformat(),
            reason=reason or "",
        )

    async def RevokeCredential(self, request, context):
        try:
            return await self._credential_lifecycle(request.credential_id, "revoke", request.reason, context)
        except Exception as exc:
            logger.exception("RevokeCredential failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.CredentialStatusResponse()

    async def SuspendCredential(self, request, context):
        try:
            return await self._credential_lifecycle(request.credential_id, "suspend", request.reason, context)
        except Exception as exc:
            logger.exception("SuspendCredential failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.CredentialStatusResponse()

    async def ReinstateCredential(self, request, context):
        try:
            return await self._credential_lifecycle(request.credential_id, "reinstate", request.reason, context)
        except Exception as exc:
            logger.exception("ReinstateCredential failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.CredentialStatusResponse()

    async def GetCredentialStatus(self, request, context):
        """Get credential status."""
        try:
            repo = self._get_repo()
            cred = await repo.get_credential(request.credential_id)
            if not cred:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Credential not found")
                return pb2.CredentialStatusResponse()
            return pb2.CredentialStatusResponse(
                id=cred.id,
                status=cred.status.value,
                status_updated_at=cred.status_updated_at.isoformat(),
                reason=cred.revocation_reason or "",
            )
        except Exception as exc:
            logger.exception("GetCredentialStatus failed")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.CredentialStatusResponse()

    # ------------------------------------------------------------------ #
    # Streaming
    # ------------------------------------------------------------------ #

    async def _emit_credential_event(
        self,
        event_type: str,
        credential_id: str = "",
        transaction_id: str = "",
        organization_id: str = "",
        credential_template_id: str = "",
        status: str = "",
    ) -> None:
        """Push a credential lifecycle event to all active stream subscribers."""
        event = pb2.CredentialEvent(
            event_type=event_type,
            credential_id=credential_id,
            transaction_id=transaction_id,
            organization_id=organization_id,
            credential_template_id=credential_template_id,
            status=status,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        stale: list[str] = []
        for sub_id, q in self._stream_queues.items():
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Dropping credential event for slow subscriber %s", sub_id)
            except Exception:
                stale.append(sub_id)
        for sid in stale:
            self._stream_queues.pop(sid, None)

    async def StreamCredentialEvents(self, request, context):
        """Server-streaming: push credential lifecycle events to the caller."""
        import uuid as _uuid

        sub_id = str(_uuid.uuid4())
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._stream_queues[sub_id] = q
        logger.info("StreamCredentialEvents: subscriber %s connected", sub_id)

        try:
            while not context.cancelled():
                try:
                    event = await asyncio.wait_for(q.get(), timeout=30.0)
                    # Apply filters
                    if request.organization_id and event.organization_id != request.organization_id:
                        continue
                    if request.credential_template_id and event.credential_template_id != request.credential_template_id:
                        continue
                    if request.event_types and event.event_type not in list(request.event_types):
                        continue
                    yield event
                except asyncio.TimeoutError:
                    continue
        finally:
            self._stream_queues.pop(sub_id, None)
            logger.info("StreamCredentialEvents: subscriber %s disconnected", sub_id)

    # ------------------------------------------------------------------ #
    # HealthCheck
    # ------------------------------------------------------------------ #

    async def HealthCheck(self, request, context):
        return pb2.HealthCheckResponse(status="serving")


# ── Helpers ────────────────────────────────────────────────────────────────

def _config_id_for_format_variant(base: str, variant: str | None) -> str:
    """Return the credential_configuration_id for the given base type and format variant."""
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
