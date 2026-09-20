"""Guards for the Rust-owned Application Template management boundary."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SERVICES = _REPO_ROOT / "services"

if str(_SERVICES) not in sys.path:
    sys.path.insert(0, str(_SERVICES))

from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import application_routes


_RETIRED_HANDLERS = {
    "create_application_template",
    "list_application_templates",
    "get_application_template",
    "update_application_template",
    "validate_application_template",
    "activate_application_template",
    "deprecate_application_template",
    "delete_application_template",
}
_RETIRED_MODELS = {
    "ApplicationFieldOption",
    "ApplicationFormField",
    "RequiredApplicationCheck",
    "ApplicationEvidenceRequirement",
    "ClaimCollectionRule",
    "ApplicationTemplateCreate",
    "ApplicationTemplatePatch",
    "ApplicationTemplateResponse",
}


def _top_level_names(path: Path) -> tuple[set[str], set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    functions = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    return functions, classes


def test_python_application_template_management_surface_stays_retired() -> None:
    """Prevent a second Python owner from silently recreating the Rust routes."""

    handlers, _ = _top_level_names(
        _REPO_ROOT
        / "services"
        / "issuance"
        / "infrastructure"
        / "api"
        / "application_routes.py"
    )
    _, models = _top_level_names(
        _REPO_ROOT
        / "services"
        / "issuance"
        / "infrastructure"
        / "api"
        / "routes.py"
    )

    assert handlers.isdisjoint(_RETIRED_HANDLERS)
    assert models.isdisjoint(_RETIRED_MODELS)

    main_source = (
        _REPO_ROOT / "services" / "issuance" / "main.py"
    ).read_text(encoding="utf-8")
    assert "application_template_router" not in main_source


async def test_claim_transaction_inherits_and_validates_revocation_profile(
    monkeypatch,
) -> None:
    """The retained application consumer still binds live credential context."""

    repo = InMemoryIssuanceRepository()
    template = ApplicationTemplate(
        organization_id="org-123",
        name="Membership application",
        credential_template_id="credential-template-1",
        form_fields=[
            {
                "field_id": "email",
                "label": "Email",
                "field_type": "EMAIL",
                "required": True,
                "claim_mapping": "email",
            }
        ],
    )
    await repo.save_application_template(template)
    app = Application(
        organization_id="org-123",
        application_template_id=template.id,
        applicant_identifier="holder-1",
        form_data={"email": "holder@example.test"},
        status=ApplicationStatus.APPROVED,
    )
    await repo.save_application(app)
    validated: list[dict[str, object]] = []

    async def fetch_credential_template(_template_id: str) -> dict[str, object]:
        return {
            "organization_id": "org-123",
            "status": "ACTIVE",
            "credential_type": "MembershipCredential",
            "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
            "issuer_did": "did:web:issuer.example:orgs:org-123",
            "issuer_algorithm": "ES256",
            "claims": [{"name": "email"}],
            "revocation_profile_id": "revocation-profile-1",
        }

    async def validate_binding(**kwargs) -> None:
        validated.append(kwargs)

    async def apply_issuer_context(transaction) -> None:
        transaction.issuer_profile_id = "resolved-profile-1"
        transaction.signing_service_id = "resolved-service-1"

    monkeypatch.setattr(
        application_routes,
        "_fetch_credential_template",
        fetch_credential_template,
    )
    monkeypatch.setattr(
        application_routes,
        "_require_active_revocation_profile_binding",
        validate_binding,
    )
    monkeypatch.setattr(
        application_routes,
        "apply_required_remote_issuer_context",
        apply_issuer_context,
    )

    transaction = await application_routes._get_or_refresh_transaction(
        app,
        repo,
        template,
    )

    assert transaction.revocation_profile_id == "revocation-profile-1"
    assert transaction.issuer_did_override == "did:web:issuer.example:orgs:org-123"
    assert transaction.issuer_algorithm == "ES256"
    assert validated == [
        {
            "organization_id": "org-123",
            "revocation_profile_id": "revocation-profile-1",
        }
    ]
