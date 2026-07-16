"""MIP 0.3 Application Template lifecycle contract tests."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_SERVICES = os.path.join(_REPO_ROOT, "services")

if _SERVICES not in sys.path:
    sys.path.insert(0, _SERVICES)

for _module_name in (
    "status_list",
    "status_list.infrastructure",
    "status_list.infrastructure.security",
    "status_list.infrastructure.security.encryption",
):
    sys.modules.setdefault(_module_name, MagicMock())

from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import application_routes
from issuance.infrastructure.api.routes import (
    ApplicationTemplateCreate,
    ApplicationTemplatePatch,
)
from issuance.domain.entities import ApprovalPolicySet, Application, ApplicationStatus


class _CredentialTemplateResponse:
    status_code = 200

    def __init__(self, revocation_profile_id: str | None):
        self._revocation_profile_id = revocation_profile_id

    def json(self):
        return {
            "organization_id": "org-123",
            "status": "active",
            "claims": [{"name": "email"}],
            "revocation_profile_id": self._revocation_profile_id,
        }


class _CredentialTemplateClient:
    def __init__(self, revocation_profile_id: str | None):
        self._response = _CredentialTemplateResponse(revocation_profile_id)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, _url):
        return self._response


def _create_request(**overrides) -> ApplicationTemplateCreate:
    values = {
        "organization_id": "org-123",
        "name": "Membership application",
        "credential_template_id": "credential-template-1",
        "form_fields": [
            {
                "field_id": "email",
                "label": "Email",
                "field_type": "EMAIL",
                "required": True,
                "claim_mapping": "email",
            }
        ],
        "required_checks": [
            {"check_type": "EMAIL_VERIFICATION", "is_required": True, "order": 1}
        ],
    }
    values.update(overrides)
    return ApplicationTemplateCreate(**values)


async def test_create_is_draft_and_uses_only_canonical_fields() -> None:
    repo = InMemoryIssuanceRepository()

    response = await application_routes.create_application_template(_create_request(), repo=repo)

    assert response.status == "DRAFT"
    assert response.approval_strategy == "MANUAL"
    assert response.form_fields[0]["field_id"] == "email"
    assert response.required_checks[0]["check_type"] == "EMAIL_VERIFICATION"

    with pytest.raises(ValidationError):
        _create_request(status="ACTIVE")
    with pytest.raises(ValidationError):
        _create_request(form_fields=[{"name": "email", "type": "text", "label": "Email", "required": True}])
    with pytest.raises(ValidationError):
        _create_request(auto_approval_rules=[])


def test_evidence_requirement_rejects_removed_auto_approval_alias() -> None:
    evidence = {
        "evidence_id": "membership-proof",
        "evidence_type": "EXTERNAL_FACT",
        "description": "Confirm membership eligibility",
        "required": True,
        "auto_issue_on_permit": True,
    }

    request = _create_request(evidence_requirements=[evidence])
    assert request.evidence_requirements[0].auto_issue_on_permit is True

    with pytest.raises(ValidationError, match="auto_approve_on_evidence"):
        _create_request(
            evidence_requirements=[{**evidence, "auto_approve_on_evidence": True}],
        )


def test_claim_collection_rule_rejects_removed_source_field_alias() -> None:
    rule = {
        "claim_name": "email",
        "source": "FORM_FIELD",
        "source_config": {"field_id": "email"},
    }

    request = _create_request(claim_collection_rules=[rule])
    assert request.claim_collection_rules[0].source_config == {"field_id": "email"}

    with pytest.raises(ValidationError, match="source_field"):
        _create_request(claim_collection_rules=[{**rule, "source_field": "email"}])


async def test_only_drafts_can_be_patched() -> None:
    repo = InMemoryIssuanceRepository()
    created = await application_routes.create_application_template(_create_request(), repo=repo)

    updated = await application_routes.update_application_template(
        created.id,
        ApplicationTemplatePatch(name="Updated membership application"),
        repo=repo,
    )
    assert updated.name == "Updated membership application"

    template = await repo.get_application_template(created.id)
    assert template is not None
    template.status = "ACTIVE"
    await repo.save_application_template(template)
    with pytest.raises(HTTPException) as exc:
        await application_routes.update_application_template(
            created.id,
            ApplicationTemplatePatch(name="Forbidden update"),
            repo=repo,
        )
    assert exc.value.status_code == 409


async def test_validate_returns_section_scoped_errors() -> None:
    repo = InMemoryIssuanceRepository()
    created = await application_routes.create_application_template(
        _create_request(
            credential_template_id=None,
            form_fields=[],
            approval_strategy="RULES_BASED",
            approval_policy_set_id=None,
        ),
        repo=repo,
    )

    result = await application_routes.validate_application_template(created.id, repo=repo)

    assert result["valid"] is False
    assert {error["section"] for error in result["errors"]} == {
        "credential_template",
        "form_fields",
        "approval",
    }


async def test_validate_rejects_active_credential_template_without_revocation_profile(
    monkeypatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    created = await application_routes.create_application_template(_create_request(), repo=repo)
    monkeypatch.setattr(
        application_routes.httpx,
        "AsyncClient",
        lambda **_kwargs: _CredentialTemplateClient(None),
    )

    result = await application_routes.validate_application_template(created.id, repo=repo)

    assert result["valid"] is False
    assert any(
        error["code"] == "REVOCATION_PROFILE_REQUIRED"
        for error in result["errors"]
    )


async def test_validate_covers_evidence_claim_checks_and_configuration(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    created = await application_routes.create_application_template(_create_request(), repo=repo)
    template = await repo.get_application_template(created.id)
    assert template is not None
    template.evidence_requirements = [{"evidence_type": "EXTERNAL_API"}]
    template.claim_collection_rules = [
        {"claim_name": "email", "source": "FORM_FIELD", "source_config": {"field_id": "missing"}}
    ]
    template.required_checks = [
        {"check_type": "ONE", "is_required": True, "order": 1},
        {"check_type": "TWO", "is_required": True, "order": 1},
    ]
    template.notification_config = []
    template.ui_config = []
    await repo.save_application_template(template)
    monkeypatch.setattr(
        application_routes.httpx,
        "AsyncClient",
        lambda **_kwargs: _CredentialTemplateClient("revocation-profile-1"),
    )

    result = await application_routes.validate_application_template(created.id, repo=repo)

    sections = {error["section"] for error in result["errors"]}
    assert {"evidence", "claim_mappings", "required_checks", "notifications", "preview"} <= sections


async def test_rules_based_activation_requires_active_approval_policy_set(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    created = await application_routes.create_application_template(
        _create_request(
            approval_strategy="RULES_BASED",
            approval_policy_set_id="policy-set-1",
        ),
        repo=repo,
    )
    monkeypatch.setattr(
        application_routes.httpx,
        "AsyncClient",
        lambda **_kwargs: _CredentialTemplateClient("revocation-profile-1"),
    )

    missing = await application_routes.validate_application_template(created.id, repo=repo)
    assert any(error["code"] == "NOT_FOUND" for error in missing["errors"])

    await repo.save_approval_policy_set(ApprovalPolicySet(
        id="policy-set-1",
        organization_id="org-123",
        policy_type="APPROVAL_RULES",
        status="ACTIVE",
        cedar_policies="permit(principal, action, resource);",
    ))
    valid = await application_routes.validate_application_template(created.id, repo=repo)
    assert valid == {"valid": True, "errors": []}


async def test_validate_accepts_supported_system_claim_sources(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    created = await application_routes.create_application_template(
        _create_request(claim_collection_rules=[
            {
                "claim_name": "member_id",
                "source": "SYSTEM",
                "source_config": {"system_field": "applicant.user_id"},
            },
            {
                "claim_name": "role",
                "source": "SYSTEM",
                "source_config": {"system_field": "constant", "value": "member"},
            },
        ]),
        repo=repo,
    )
    monkeypatch.setattr(
        application_routes.httpx,
        "AsyncClient",
        lambda **_kwargs: _CredentialTemplateClient("revocation-profile-1"),
    )

    result = await application_routes.validate_application_template(created.id, repo=repo)

    assert result == {"valid": True, "errors": []}


async def test_claim_transaction_inherits_and_validates_revocation_profile(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    template_response = await application_routes.create_application_template(_create_request(), repo=repo)
    template = await repo.get_application_template(template_response.id)
    assert template is not None
    app = Application(
        organization_id="org-123",
        application_template_id=template.id,
        applicant_identifier="holder-1",
        form_data={"email": "holder@example.test"},
        status=ApplicationStatus.APPROVED,
    )
    await repo.save_application(app)
    validated = []

    async def validate_binding(**kwargs):
        validated.append(kwargs)

    async def apply_issuer_context(_transaction):
        return None

    monkeypatch.setattr(
        application_routes.httpx,
        "AsyncClient",
        lambda **_kwargs: _CredentialTemplateClient("revocation-profile-1"),
    )
    monkeypatch.setattr(application_routes, "_require_active_revocation_profile_binding", validate_binding)
    monkeypatch.setattr(application_routes, "apply_remote_issuer_context", apply_issuer_context)

    transaction = await application_routes._get_or_refresh_transaction(app, repo, template)

    assert transaction.revocation_profile_id == "revocation-profile-1"
    assert validated == [{
        "organization_id": "org-123",
        "revocation_profile_id": "revocation-profile-1",
    }]


async def test_activation_and_deprecation_are_explicit_transitions(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    created = await application_routes.create_application_template(_create_request(), repo=repo)

    async def no_errors(_template, _repo):
        return []

    monkeypatch.setattr(application_routes, "_application_template_validation_errors", no_errors)

    activated = await application_routes.activate_application_template(created.id, repo=repo)
    assert activated.status == "ACTIVE"

    deprecated = await application_routes.deprecate_application_template(created.id, repo=repo)
    assert deprecated.status == "DEPRECATED"

    with pytest.raises(HTTPException) as exc:
        await application_routes.activate_application_template(created.id, repo=repo)
    assert exc.value.status_code == 409


async def test_delete_is_draft_only() -> None:
    repo = InMemoryIssuanceRepository()
    draft = await application_routes.create_application_template(_create_request(), repo=repo)

    response = await application_routes.delete_application_template(draft.id, repo=repo)
    assert response.status_code == 204
    assert await repo.get_application_template(draft.id) is None

    active = await application_routes.create_application_template(
        _create_request(name="Active template"),
        repo=repo,
    )
    template = await repo.get_application_template(active.id)
    assert template is not None
    template.status = "ACTIVE"
    await repo.save_application_template(template)

    with pytest.raises(HTTPException) as exc:
        await application_routes.delete_application_template(active.id, repo=repo)
    assert exc.value.status_code == 409
    assert await repo.get_application_template(active.id) is not None
