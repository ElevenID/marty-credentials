from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime, timedelta

import pytest
from issuance.application.application_approval import (
    CredentialContext,
    approve_application_for_issuance,
)
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    ApplicationTemplate,
    CanvasAwardCandidate,
    CanvasAwardCandidateState,
    CredentialStatus,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository


def _application() -> Application:
    return Application(
        id="canvas-application-1",
        organization_id="org-1",
        application_template_id="application-template-1",
        applicant_identifier="learner-1",
        integration_context={
            "canvas": {
                "canvas_platform_id": "canvas-platform-1",
                "canvas_program_binding_id": "canvas-binding-1",
                "canvas_award_candidate_id": "canvas-candidate-1",
            }
        },
    )


def _template() -> ApplicationTemplate:
    return ApplicationTemplate(
        id="application-template-1",
        organization_id="org-1",
        credential_template_id="open-badge-template-1",
    )


def _credential_context() -> CredentialContext:
    return CredentialContext(
        credential_type="OpenBadgeCredential",
        credential_payload_format="w3c_vcdm_v2_sd_jwt",
        revocation_profile_id="status-profile-1",
        issuer_profile_id="issuer-profile-1",
    )


async def _apply_issuer_context(tx: IssuanceTransaction) -> None:
    tx.issuer_did_override = "did:web:issuer.example"
    tx.signing_service_id = "openbao-transit"


@pytest.mark.asyncio
async def test_concurrent_canvas_approvals_reserve_one_claimable_transaction() -> None:
    repo = InMemoryIssuanceRepository()
    application = _application()
    template = _template()
    await repo.save_application(application)
    await repo.save_application_template(template)

    both_prepared = asyncio.Event()
    arrivals = 0

    async def synchronized_issuer_context(tx: IssuanceTransaction) -> None:
        nonlocal arrivals
        await _apply_issuer_context(tx)
        arrivals += 1
        if arrivals == 2:
            both_prepared.set()
        await asyncio.wait_for(both_prepared.wait(), timeout=2)

    snapshots = [copy.deepcopy(application), copy.deepcopy(application)]
    transactions = await asyncio.gather(
        *(
            approve_application_for_issuance(
                repo=repo,
                app=snapshot,
                template=template,
                reviewer_id="canvas-approver",
                review_notes="Concurrent approval",
                credential_context=_credential_context(),
                issuer_context_applier=synchronized_issuer_context,
            )
            for snapshot in snapshots
        )
    )

    assert transactions[0].id == transactions[1].id
    assert transactions[0].pre_auth_code == transactions[1].pre_auth_code
    stored_transactions = await repo.list_transactions("org-1")
    assert [item.id for item in stored_transactions] == [transactions[0].id]
    stored_application = await repo.get_application(application.id)
    assert stored_application is not None
    assert stored_application.status == ApplicationStatus.APPROVED
    assert stored_application.issuance_transaction_id == transactions[0].id


@pytest.mark.asyncio
async def test_expired_authorized_canvas_transaction_cannot_be_replaced() -> None:
    repo = InMemoryIssuanceRepository()
    application = _application()
    application.status = ApplicationStatus.APPROVED
    template = _template()
    authorized = IssuanceTransaction(
        id="authorized-canvas-transaction",
        organization_id="org-1",
        credential_template_id="open-badge-template-1",
        application_id=application.id,
        applicant_id="learner-1",
        status=IssuanceStatus.AUTHORIZED,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    application.issuance_transaction_id = authorized.id
    await repo.save_application(application)
    await repo.save_application_template(template)
    await repo.save_transaction(authorized)

    with pytest.raises(ValueError, match="claim is already in progress"):
        await approve_application_for_issuance(
            repo=repo,
            app=copy.deepcopy(application),
            template=template,
            reviewer_id="canvas-retry",
            review_notes="Do not replace an outstanding bearer grant",
            credential_context=_credential_context(),
            issuer_context_applier=_apply_issuer_context,
        )

    assert len(await repo.list_transactions("org-1")) == 1


@pytest.mark.asyncio
async def test_canvas_claim_projection_commits_with_credential_finalization() -> None:
    repo = InMemoryIssuanceRepository()
    application = _application()
    application.status = ApplicationStatus.APPROVED
    candidate = CanvasAwardCandidate(
        id="canvas-candidate-1",
        organization_id="org-1",
        platform_id="canvas-platform-1",
        binding_id="canvas-binding-1",
        candidate_key="lti-subject:learner-1",
        state=CanvasAwardCandidateState.PENDING_CLAIM,
        application_id=application.id,
    )
    transaction = IssuanceTransaction(
        id="canvas-transaction-1",
        organization_id="org-1",
        credential_template_id="open-badge-template-1",
        application_id=application.id,
        applicant_id="learner-1",
        status=IssuanceStatus.AUTHORIZED,
    )
    application.issuance_transaction_id = transaction.id
    await repo.save_application(application)
    await repo.save_canvas_award_candidate(candidate)
    await repo.save_transaction(transaction)

    claimed = await repo.claim_transaction_for_signing(
        transaction,
        "urn:uuid:canvas-credential-1",
    )
    assert claimed is not None
    credential = IssuedCredential(
        id="urn:uuid:canvas-credential-1",
        transaction_id=transaction.id,
        organization_id="org-1",
        credential_template_id="open-badge-template-1",
        applicant_id="learner-1",
        credential_jwt="signed-open-badge",
        credential_hash="credential-hash",
        status=CredentialStatus.ACTIVE,
        issued_at=datetime.now(UTC),
    )

    await repo.finalize_credential_issuance(claimed, credential)

    stored_application = await repo.get_application(application.id)
    stored_candidate = await repo.get_canvas_award_candidate_for_org("org-1", candidate.id)
    assert stored_application is not None
    assert stored_application.credential_id == credential.id
    assert stored_candidate is not None
    assert stored_candidate.state == CanvasAwardCandidateState.CLAIMED
    assert stored_candidate.claimed_credential_id == credential.id
    assert (await repo.get_credential_by_transaction_id(transaction.id)).id == credential.id

    with pytest.raises(ValueError, match="not reserved for signing"):
        await repo.finalize_credential_issuance(claimed, credential)
    assert len(await repo.list_credentials_by_org("org-1")) == 1


@pytest.mark.asyncio
async def test_canvas_approval_retry_repairs_legacy_issued_projection_without_reissue() -> None:
    repo = InMemoryIssuanceRepository()
    application = _application()
    application.status = ApplicationStatus.APPROVED
    template = _template()
    candidate = CanvasAwardCandidate(
        id="canvas-candidate-1",
        organization_id="org-1",
        platform_id="canvas-platform-1",
        binding_id="canvas-binding-1",
        candidate_key="lti-subject:learner-1",
        state=CanvasAwardCandidateState.PENDING_CLAIM,
        application_id=application.id,
    )
    issued_transaction = IssuanceTransaction(
        id="legacy-issued-canvas-transaction",
        organization_id="org-1",
        credential_template_id="open-badge-template-1",
        application_id=application.id,
        applicant_id="learner-1",
        status=IssuanceStatus.ISSUED,
        issued_at=datetime.now(UTC),
    )
    issued_credential = IssuedCredential(
        id="urn:uuid:legacy-canvas-credential",
        transaction_id=issued_transaction.id,
        organization_id="org-1",
        credential_template_id="open-badge-template-1",
        applicant_id="learner-1",
        credential_jwt="legacy-signed-open-badge",
        credential_hash="legacy-credential-hash",
        status=CredentialStatus.ACTIVE,
        issued_at=issued_transaction.issued_at,
    )
    application.issuance_transaction_id = issued_transaction.id
    await repo.save_application(application)
    await repo.save_application_template(template)
    await repo.save_canvas_award_candidate(candidate)
    await repo.save_transaction(issued_transaction)
    await repo.save_credential(issued_credential)

    with pytest.raises(ValueError, match="already has an issued credential"):
        await approve_application_for_issuance(
            repo=repo,
            app=copy.deepcopy(application),
            template=template,
            reviewer_id="canvas-retry",
            review_notes="Repair after response loss",
            credential_context=_credential_context(),
            issuer_context_applier=_apply_issuer_context,
        )

    stored_application = await repo.get_application(application.id)
    stored_candidate = await repo.get_canvas_award_candidate_for_org("org-1", candidate.id)
    assert stored_application is not None
    assert stored_application.credential_id == issued_credential.id
    assert stored_candidate is not None
    assert stored_candidate.state == CanvasAwardCandidateState.CLAIMED
    assert stored_candidate.claimed_credential_id == issued_credential.id
    assert len(await repo.list_transactions("org-1")) == 1
    assert len(await repo.list_credentials_by_org("org-1")) == 1
