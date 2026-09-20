import pytest
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    IssuanceStatus,
    IssuanceTransaction,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.api import application_routes
from issuance.infrastructure.api.application_routes import internal_application_router
from issuance.infrastructure.api.routes import (
    ApplicationApproval,
    ApplicationRejection,
)
from pydantic import ValidationError


def test_application_engine_is_internal_only() -> None:
    paths = {route.path for route in internal_application_router.routes}

    assert paths
    assert all(path.startswith("/internal/applications") for path in paths)
    assert all(not path.startswith("/v1/applications") for path in paths)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (ApplicationApproval, {"reviewer_id": "spoofed"}),
        (ApplicationRejection, {"review_notes": "No", "reviewer_id": "spoofed"}),
    ],
)
def test_internal_decisions_reject_caller_supplied_reviewer_identity(model, payload) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.asyncio
async def test_approved_application_offer_read_uses_transaction_issuance_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An approved application remains readable after its transaction is issued."""

    repo = InMemoryIssuanceRepository()
    template = ApplicationTemplate(
        id="template-1",
        organization_id="org-123",
        name="Membership",
        credential_template_id="credential-template-1",
        status="ACTIVE",
    )
    transaction = IssuanceTransaction(
        id="transaction-1",
        organization_id="org-123",
        credential_template_id="credential-template-1",
        application_id="application-1",
        credential_type="MembershipCredential",
        pre_auth_code="contract-pre-authorized-code",
        status=IssuanceStatus.ISSUED,
    )
    application = Application(
        id="application-1",
        organization_id="org-123",
        application_template_id=template.id,
        applicant_identifier="holder-1",
        status=ApplicationStatus.APPROVED,
        issuance_transaction_id=transaction.id,
    )
    await repo.save_application_template(template)
    await repo.save_transaction(transaction)
    await repo.save_application(application)

    async def no_wallets(_template_id: str | None):
        return []

    monkeypatch.setattr(
        application_routes,
        "_fetch_wallets_for_template",
        no_wallets,
    )

    response = await application_routes.get_issuance_offer(
        application_id=application.id,
        trusted_organization_id="org-123",
        repo=repo,
    )

    assert response.transaction_id == transaction.id
    assert response.status == "active"
    assert response.offer_url == response.qr_payload
    assert response.credential_offer_uris == {}
