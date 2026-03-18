"""
DocumentSigner gRPC Client

Optional external signing backend. When DOCUMENT_SIGNER_GRPC_TARGET is set,
the issuance service delegates SD-JWT credential signing to the Marty backend
DocumentSigner service instead of using local Rust FFI.

This enables centralized key management (Key Vault) in production deployments
while keeping the local Rust FFI as the default for development.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Tuple

logger = logging.getLogger(__name__)

DOCUMENT_SIGNER_GRPC_TARGET = os.environ.get("DOCUMENT_SIGNER_GRPC_TARGET", "")


def is_external_signer_enabled() -> bool:
    """Check if external DocumentSigner is configured."""
    return bool(DOCUMENT_SIGNER_GRPC_TARGET)


async def sign_credential_via_document_signer(
    subject_id: str,
    credential_type: str,
    claims_json: str,
    selective_disclosure_claims: list[str] | None = None,
    organization_id: str | None = None,
) -> Tuple[str, str]:
    """Sign a credential via the external DocumentSigner gRPC service.

    Uses CreateCredentialOffer + IssueSdJwtCredential flow to produce
    a signed SD-JWT credential.

    Returns:
        Tuple of (credential_jwt, credential_id)

    Raises:
        RuntimeError: If signing fails or DocumentSigner returns an error.
    """
    import grpc.aio as grpc_aio
    from marty_proto.v1 import document_signer_pb2 as ds_pb2
    from marty_proto.v1 import document_signer_pb2_grpc as ds_grpc

    async with grpc_aio.insecure_channel(DOCUMENT_SIGNER_GRPC_TARGET) as channel:
        stub = ds_grpc.DocumentSignerStub(channel)

        # Step 1: Create a credential offer (registers claims + gets pre-auth code)
        offer_resp = await stub.CreateCredentialOffer(
            ds_pb2.CreateCredentialOfferRequest(
                subject_id=subject_id or "",
                credential_type=credential_type,
                base_claims_json=claims_json,
                selective_disclosures_json=json.dumps(selective_disclosure_claims or []),
                metadata_json=json.dumps({"organization_id": organization_id or ""}),
            )
        )

        if offer_resp.error and offer_resp.error.code != 0:
            raise RuntimeError(
                f"DocumentSigner CreateCredentialOffer failed: {offer_resp.error.message}"
            )

        if not offer_resp.pre_authorized_code:
            raise RuntimeError("DocumentSigner returned empty pre_authorized_code")

        # Step 2: Redeem pre-authorized code for access token
        redeem_resp = await stub.RedeemPreAuthorizedCode(
            ds_pb2.RedeemPreAuthorizedCodeRequest(
                pre_authorized_code=offer_resp.pre_authorized_code,
            )
        )

        if redeem_resp.error and redeem_resp.error.code != 0:
            raise RuntimeError(
                f"DocumentSigner RedeemPreAuthorizedCode failed: {redeem_resp.error.message}"
            )

        if not redeem_resp.access_token:
            raise RuntimeError("DocumentSigner returned empty access_token")

        # Step 3: Issue the SD-JWT credential
        issue_resp = await stub.IssueSdJwtCredential(
            ds_pb2.IssueSdJwtCredentialRequest(
                access_token=redeem_resp.access_token,
                disclose_claims=selective_disclosure_claims or [],
                nonce=redeem_resp.c_nonce or "",
            )
        )

        if issue_resp.error and issue_resp.error.code != 0:
            raise RuntimeError(
                f"DocumentSigner IssueSdJwtCredential failed: {issue_resp.error.message}"
            )

        credential = issue_resp.credential
        credential_id = issue_resp.credential_id

        if not credential:
            raise RuntimeError("DocumentSigner returned empty credential")

        logger.info(
            "Signed credential via DocumentSigner: type=%s id=%s",
            credential_type, credential_id,
        )

        return credential, credential_id or ""
