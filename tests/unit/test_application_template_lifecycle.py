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


async def test_activation_and_deprecation_are_explicit_transitions(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    created = await application_routes.create_application_template(_create_request(), repo=repo)

    async def no_errors(_template):
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
