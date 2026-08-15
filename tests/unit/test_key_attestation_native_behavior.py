"""Cross-language conformance for the canonical key-attestation vectors."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

import pytest

from services.issuance.application.key_attestation import (
    KeyAttestationError,
    KeyAttestationPolicy,
    verify_oid4vci_proof_with_issuer_policy,
)
from services.issuance.application.rust_integration import get_marty_rs


def _jsonable_policy(policy: KeyAttestationPolicy) -> dict[str, Any]:
    value = asdict(policy)
    for name in (
        "allowed_algorithms",
        "required_key_storage",
        "required_user_authentication",
        "status_list_allowed_algorithms",
    ):
        value[name] = sorted(value[name])
    for name in (
        "trusted_root_certificates_pem",
        "status_list_allowed_origins",
        "status_list_trusted_root_certificates_pem",
        "status_list_tls_ca_certificates_pem",
    ):
        value[name] = list(value[name])
    return value


def _fixture() -> dict[str, Any]:
    return json.loads(get_marty_rs().key_attestation_behavior_fixture())


def test_python_policy_adapter_matches_shared_rust_vectors() -> None:
    for case in _fixture()["policy_cases"]:
        request = case["request"]
        if "error" in case:
            with pytest.raises(KeyAttestationError) as exc:
                KeyAttestationPolicy.from_issuer_context(
                    request["issuer_context"],
                    organization_id=request["organization_id"],
                )
            assert str(exc.value) == case["error"], case["name"]
        else:
            policy = KeyAttestationPolicy.from_issuer_context(
                request["issuer_context"],
                organization_id=request["organization_id"],
            )
            assert _jsonable_policy(policy) == case["expected"], case["name"]


@pytest.mark.asyncio
async def test_python_proof_adapter_matches_shared_rust_routing_vectors() -> None:
    def ordinary(*_args: object) -> tuple[bool, str, dict[str, Any] | None, str | None]:
        return True, "did:key:holder", {"kty": "EC"}, None

    def bound(*_args: object) -> tuple[bool, str, dict[str, Any] | None, str | None]:
        raise AssertionError("fixture routing failures must not reach bound verification")

    for case in _fixture()["route_cases"]:
        request = case["request"]
        result = await verify_oid4vci_proof_with_issuer_policy(
            request["proof_jwt"],
            issuer_context=request["issuer_context"],
            organization_id=request["organization_id"],
            expected_nonce=None,
            proof_verifier=ordinary,
            bound_proof_verifier=bound,
        )
        if "error" in case:
            assert result == (False, "", None, case["error"]), case["name"]
        else:
            assert result == (True, "did:key:holder", {"kty": "EC"}, None), case["name"]
