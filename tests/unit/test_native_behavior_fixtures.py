"""Cross-language adapter checks driven by canonical native JSON vectors."""

from __future__ import annotations

import json
from datetime import datetime
from types import SimpleNamespace

import pytest
from issuance.application.evidence_policy import evaluate_application_evidence_policy
from issuance.domain.vcdm_validation import (
    VcdmValidationError,
    validate_credential_document,
)
from marty_credentials.native_backend import require_marty_rs
from verification.application.governance import (
    GovernanceAuthorizationError,
    parse_governance,
)

_native = require_marty_rs(("verification_behavior_fixture",))


def _fixture(name: str) -> dict:
    return json.loads(_native.verification_behavior_fixture(name))


def _namespace(value: dict | None) -> SimpleNamespace | None:
    return SimpleNamespace(**value) if value is not None else None


def _fact(value: dict) -> SimpleNamespace:
    payload = dict(value)
    for field in ("effective_at", "observed_at", "created_at"):
        if payload.get(field) is not None:
            payload[field] = datetime.fromisoformat(payload[field].replace("Z", "+00:00"))
    return SimpleNamespace(**payload)


def test_evidence_policy_adapter_matches_native_behavior_fixture() -> None:
    for case in _fixture("evidence_policy")["cases"]:
        request = case["request"]
        app_value = request["app"]
        app = SimpleNamespace(
            id=app_value["id"],
            organization_id=app_value["organization_id"],
            status=SimpleNamespace(value=app_value["status"]),
        )
        decision = evaluate_application_evidence_policy(
            app=app,
            template=_namespace(request.get("template")),
            binding=_namespace(request.get("binding")),
            requirements=request.get("requirements", []),
            facts=[_fact(value) for value in request.get("facts", [])],
            policy_set=_namespace(request.get("policy_set")),
        )

        assert decision.allowed is case["allowed"], case["name"]
        assert decision.engine == case["engine"], case["name"]
        assert (
            decision.context["required_evidence_count"] == case["required_count"]
        ), case["name"]
        assert (
            decision.context["satisfied_requirement_count"]
            == case["satisfied_count"]
        ), case["name"]
        assert (
            decision.context["evidence_scope_matched"] is case["scope_matched"]
        ), case["name"]


def test_vcdm_adapter_matches_native_behavior_fixture() -> None:
    for case in _fixture("vcdm_issuance")["document_cases"]:
        if case["expected_error"] is None:
            validate_credential_document(
                case["credential"], issuer_did=case["issuer_did"]
            )
            continue
        with pytest.raises(VcdmValidationError) as failure:
            validate_credential_document(
                case["credential"], issuer_did=case["issuer_did"]
            )
        assert failure.value.code == case["expected_error"], case["name"]


def test_governance_adapter_matches_native_authorization_fixture() -> None:
    fixture = _fixture("governance")
    registry = parse_governance(json.dumps(fixture["governance"]))
    for case in fixture["authorization_cases"]:
        if case["expected_client_id"] is not None:
            context = registry.authorize(case["api_key"], case["purpose"])
            assert context.client_id == case["expected_client_id"], case["name"]
            continue
        with pytest.raises(GovernanceAuthorizationError) as failure:
            registry.authorize(case["api_key"], case["purpose"])
        assert case["expected_error"] in str(failure.value), case["name"]
