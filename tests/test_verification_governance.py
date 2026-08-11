from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest
from pydantic import ValidationError
from verification.application.canonical_result import (
    build_canonical_result,
    canonical_result_from_evidence,
)
from verification.application.did_resolver import validate_internal_resolver_configuration
from verification.application.governance import (
    DIRECT_VERIFY_PURPOSE,
    GOVERNANCE_ENV,
    SESSION_CREATE_PURPOSE,
    VDS_NC_VERIFY_PURPOSE,
    GovernanceAuthorizationError,
    GovernanceConfigurationError,
    GovernancePolicyMismatchError,
    canonical_digest,
    governance_from_snapshot,
    load_governance,
    parse_governance,
)
from verification.infrastructure.api.models import (
    CreateSessionRequest,
    VerifyDirectRequest,
    VerifyVdsNcRequest,
)

ORGANIZATION_ID = "123e4567-e89b-42d3-a456-426614174000"
API_KEY = "purpose-scoped-test-key"
ARTIFACT_DIGEST = "sha256:" + "1" * 64
DEFINITION = {"id": "pd-1", "input_descriptors": [{"id": "employee"}]}


def _configuration() -> dict[str, object]:
    policy_content = {
        "verifier_id": "did:web:verifier.example",
        "presentation_definition_digest": canonical_digest(DEFINITION),
        "required_checks": [
            "presentation.structure",
            "presentation.proof",
            "credential.proof",
            "issuer.trust",
            "credential.status",
            "holder.binding",
            "transaction.binding",
            "claim.constraints",
        ],
    }
    trust_content = {
        "trusted_issuers": ["did:web:issuer.example"],
        "allow_public_did_fallback": False,
    }
    return {
        "component": {
            "component_id": "marty-credentials",
            "version": "0.1.53",
            "artifact_digest": ARTIFACT_DIGEST,
            "adapter_id": "verification-service",
            "adapter_version": "1.0.0",
        },
        "policies": [
            {
                "organization_id": ORGANIZATION_ID,
                "id": "policy:employee",
                "version": "1.0.0",
                "content_digest": canonical_digest(policy_content),
                "content": policy_content,
            }
        ],
        "trust_profiles": [
            {
                "organization_id": ORGANIZATION_ID,
                "id": "trust:employee",
                "version": "1.0.0",
                "content_digest": canonical_digest(trust_content),
                "content": trust_content,
            }
        ],
        "clients": [
            {
                "client_id": "employee-verifier",
                "api_key_sha256": hashlib.sha256(API_KEY.encode()).hexdigest(),
                "organization_id": ORGANIZATION_ID,
                "purposes": {
                    SESSION_CREATE_PURPOSE: {
                        "policy_id": "policy:employee",
                        "trust_profile_id": "trust:employee",
                    },
                    DIRECT_VERIFY_PURPOSE: {
                        "policy_id": "policy:employee",
                        "trust_profile_id": "trust:employee",
                    },
                },
            }
        ],
    }


def _registry():
    return parse_governance(json.dumps(_configuration()))


def test_runtime_configuration_is_required_before_service_startup(monkeypatch) -> None:
    monkeypatch.delenv(GOVERNANCE_ENV, raising=False)
    monkeypatch.delenv("SIGNING_KEYS_INTERNAL_API_KEY", raising=False)
    monkeypatch.delenv("SIGNING_KEYS_INTERNAL_API_KEY_FILE", raising=False)

    with pytest.raises(GovernanceConfigurationError, match="not configured"):
        load_governance()
    with pytest.raises(ValueError, match="SIGNING_KEYS_INTERNAL_API_KEY"):
        validate_internal_resolver_configuration()

    monkeypatch.setenv(GOVERNANCE_ENV, json.dumps(_configuration()))
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "dedicated-workload-secret")
    assert load_governance().authorize(API_KEY, DIRECT_VERIFY_PURPOSE).client_id
    validate_internal_resolver_configuration()


def test_api_key_is_bound_to_one_organization_and_exact_profiles() -> None:
    governance = _registry().authorize(API_KEY, DIRECT_VERIFY_PURPOSE)

    assert governance.organization_id == ORGANIZATION_ID
    assert governance.policy.reference.id == "policy:employee"
    assert governance.trust_profile.reference.id == "trust:employee"
    assert governance.trust_profile.trusted_issuers == ("did:web:issuer.example",)
    assert governance.component.artifact_digest == ARTIFACT_DIGEST


def test_each_purpose_selects_its_own_exact_policy_and_trust_profile() -> None:
    configuration = _configuration()
    vds_policy_content = {
        "verifier_id": "did:web:vds-verifier.example",
        "presentation_definition_digest": ARTIFACT_DIGEST,
        "required_checks": ["credential.proof", "issuer.trust"],
    }
    vds_trust_content = {
        "trusted_issuers": ["did:web:vds-issuer.example"],
        "allow_public_did_fallback": False,
    }
    configuration["policies"].append(
        {
            "organization_id": ORGANIZATION_ID,
            "id": "policy:vds",
            "version": "2.0.0",
            "content_digest": canonical_digest(vds_policy_content),
            "content": vds_policy_content,
        }
    )
    configuration["trust_profiles"].append(
        {
            "organization_id": ORGANIZATION_ID,
            "id": "trust:vds",
            "version": "2.0.0",
            "content_digest": canonical_digest(vds_trust_content),
            "content": vds_trust_content,
        }
    )
    configuration["clients"][0]["purposes"][VDS_NC_VERIFY_PURPOSE] = {
        "policy_id": "policy:vds",
        "trust_profile_id": "trust:vds",
    }

    registry = parse_governance(json.dumps(configuration))
    direct = registry.authorize(API_KEY, DIRECT_VERIFY_PURPOSE)
    vds = registry.authorize(API_KEY, VDS_NC_VERIFY_PURPOSE)

    assert direct.policy.reference.id == "policy:employee"
    assert direct.trust_profile.reference.id == "trust:employee"
    assert vds.policy.reference.id == "policy:vds"
    assert vds.trust_profile.reference.id == "trust:vds"


def test_unknown_key_or_ungranted_purpose_is_rejected() -> None:
    registry = _registry()

    with pytest.raises(GovernanceAuthorizationError):
        registry.authorize("wrong-key", DIRECT_VERIFY_PURPOSE)
    with pytest.raises(GovernanceAuthorizationError):
        registry.authorize(API_KEY, "verification.vds-nc")


def test_profile_content_digest_is_verified_instead_of_fabricated() -> None:
    configuration = _configuration()
    configuration["policies"][0]["content"]["required_checks"] = ["credential.proof"]

    with pytest.raises(GovernanceConfigurationError, match="does not match content"):
        parse_governance(json.dumps(configuration))


@pytest.mark.parametrize(
    "raw",
    [
        '{"component":{},"component":{},"policies":[],"trust_profiles":[],"clients":[]}',
        '{"component":NaN,"policies":[],"trust_profiles":[],"clients":[]}',
    ],
)
def test_governance_rejects_ambiguous_noncanonical_json(raw) -> None:
    with pytest.raises(GovernanceConfigurationError):
        parse_governance(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("component_id", "attacker-verifier"),
        ("adapter_id", "caller-selected-adapter"),
    ],
)
def test_component_provenance_identity_is_not_operator_selectable(field, value) -> None:
    configuration = _configuration()
    configuration["component"][field] = value

    with pytest.raises(GovernanceConfigurationError, match=field):
        parse_governance(json.dumps(configuration))


def test_purpose_policy_cannot_omit_mandatory_security_checks() -> None:
    configuration = _configuration()
    policy = configuration["policies"][0]
    policy["content"]["required_checks"] = ["credential.proof", "issuer.trust"]
    policy["content_digest"] = canonical_digest(policy["content"])

    with pytest.raises(GovernanceConfigurationError, match="missing mandatory checks"):
        parse_governance(json.dumps(configuration))


def test_persisted_snapshot_is_revalidated_and_tampering_fails_closed() -> None:
    governance = _registry().authorize(API_KEY, SESSION_CREATE_PURPOSE)
    snapshot = governance.snapshot()
    restored = governance_from_snapshot(snapshot)

    assert restored.organization_id == governance.organization_id
    assert restored.policy == governance.policy
    snapshot["trust_profile"]["content"]["trusted_issuers"] = ["did:web:attacker.example"]
    with pytest.raises(GovernanceConfigurationError, match="does not match content"):
        governance_from_snapshot(snapshot)


def test_session_resume_requires_registered_profiles_and_uses_current_component() -> None:
    registry = _registry()
    snapshot = registry.authorize(API_KEY, SESSION_CREATE_PURPOSE).snapshot()
    snapshot["component"]["version"] = "0.1.50"
    snapshot["component"]["artifact_digest"] = "sha256:" + "0" * 64

    resumed = registry.resume_session(snapshot)

    assert resumed.component == registry.component
    assert resumed.component.version == "0.1.53"

    snapshot["policy"]["content"]["verifier_id"] = "did:web:attacker.example"
    snapshot["policy"]["content_digest"] = canonical_digest(snapshot["policy"]["content"])
    with pytest.raises(GovernanceConfigurationError, match="registered authority"):
        registry.resume_session(snapshot)


def test_request_must_match_caller_bound_policy() -> None:
    governance = _registry().authorize(API_KEY, DIRECT_VERIFY_PURPOSE)
    governance.validate_request(
        verifier_id="did:web:verifier.example",
        presentation_definition=DEFINITION,
    )

    with pytest.raises(GovernancePolicyMismatchError):
        governance.validate_request(
            verifier_id="did:web:attacker.example",
            presentation_definition=DEFINITION,
        )
    with pytest.raises(GovernancePolicyMismatchError):
        governance.validate_request(
            verifier_id="did:web:verifier.example",
            presentation_definition={"id": "weaker", "input_descriptors": [], "format": None},
        )
    with pytest.raises(GovernancePolicyMismatchError, match="canonical JSON"):
        governance.validate_request(
            verifier_id="did:web:verifier.example",
            presentation_definition={"id": "invalid", "score": float("nan")},
        )


@pytest.mark.parametrize("model", [CreateSessionRequest, VerifyDirectRequest])
def test_public_requests_reject_caller_selected_authority(model) -> None:
    payload = {
        "verifier_did": "did:web:verifier.example",
        "presentation_definition": DEFINITION,
        "organization_id": ORGANIZATION_ID,
        "trusted_issuers": ["did:web:attacker.example"],
    }
    if model is VerifyDirectRequest:
        payload["presentation"] = "header.payload.signature"

    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("organization_id", ORGANIZATION_ID),
        ("trusted_issuers", ["did:web:attacker.example"]),
        ("issuer_jwk_json", '{"kty":"oct","k":"attacker"}'),
        ("allow_public_did_fallback", True),
    ],
)
def test_vds_request_rejects_caller_selected_authority(field, value) -> None:
    payload = {
        "barcode": "header~{}~signature",
        "issuer_did": "did:web:issuer.example",
        field: value,
    }

    with pytest.raises(ValidationError):
        VerifyVdsNcRequest.model_validate(payload)


def test_persisted_pass_is_rebuilt_and_bound_to_frozen_governance() -> None:
    governance = _registry().authorize(API_KEY, DIRECT_VERIFY_PURPOSE)
    evidence = build_canonical_result(
        governance=governance,
        verification_id="verification:test",
        transaction_id="transaction:test",
        presentation="header.payload.signature",
        adapter_result={
            "presentation_structure_valid": True,
            "presentation_proof_valid": True,
            "credential_proofs_valid": True,
            "trust_chain_valid": True,
            "revocation_checked": True,
            "revocation_status": "VALID",
            "holder_binding_valid": True,
            "transaction_binding_valid": True,
            "presentation_constraints_valid": True,
        },
    )

    result = canonical_result_from_evidence(evidence)
    assert result is not None
    assert result["decision"] == "PASS"

    tampered = deepcopy(evidence)
    tampered["canonical_result"]["decision"] = "FAIL"
    assert canonical_result_from_evidence(tampered) is None

    tampered = deepcopy(evidence)
    tampered["governance"]["policy"]["content"]["verifier_id"] = "did:web:attacker.example"
    assert canonical_result_from_evidence(tampered) is None

    tampered = deepcopy(evidence)
    tampered["unexpected"] = "caller-controlled"
    assert canonical_result_from_evidence(tampered) is None

    tampered = deepcopy(evidence)
    tampered["governance"]["component"]["artifact_digest"] = "sha256:" + "2" * 64
    assert canonical_result_from_evidence(tampered) is None

    tampered = deepcopy(evidence)
    tampered["canonical_result"]["checks"][0]["check_id"] = "credential.proof"
    assert canonical_result_from_evidence(tampered) is None

    tampered = deepcopy(evidence)
    tampered["evidence_records"][0]["code"] = "CALLER_SELECTED_SUCCESS"
    assert canonical_result_from_evidence(tampered) is None
