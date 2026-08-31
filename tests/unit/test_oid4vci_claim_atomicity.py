from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.responses import JSONResponse
from issuance.domain.entities import (
    Application,
    ApplicationStatus,
    AuthorizationSession,
    CredentialStatus,
    IssuanceStatus,
    IssuanceTransaction,
    IssuedCredential,
    stable_issuance_credential_id,
)
from issuance.infrastructure.adapters.memory_repository import InMemoryIssuanceRepository
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository
from issuance.infrastructure.api import routes
from issuance.infrastructure.models import issuance_transactions_table, issued_credentials_table
from starlette.requests import Request

migration = import_module(
    "issuance.infrastructure.migrations.versions.20260714_1000_portable_canvas_connections"
)
SIGNING_CONTRACT = json.loads(
    (Path(__file__).resolve().parents[2] / "contracts/issuance-credential-signing.json").read_text(
        encoding="utf-8"
    )
)


class _Result:
    def __init__(self, row=None, *, rowcount: int = 1) -> None:
        self._row = row
        self.rowcount = rowcount

    def first(self):
        return self._row


class _Transaction:
    def __init__(self, session) -> None:
        self.session = session

    async def __aenter__(self):
        self.session.transaction_active = True
        return self

    async def __aexit__(self, exc_type, _exc, _traceback):
        self.session.transaction_active = False
        self.session.committed = exc_type is None
        self.session.rolled_back = exc_type is not None
        return False


class _Session:
    def __init__(self, results: list[_Result]) -> None:
        self.results = list(results)
        self.statements = []
        self.transaction_states: list[bool] = []
        self.transaction_active = False
        self.committed = False
        self.rolled_back = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def begin(self):
        return _Transaction(self)

    async def execute(self, statement):
        self.statements.append(statement)
        self.transaction_states.append(self.transaction_active)
        return self.results.pop(0)

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


class _SessionFactory:
    def __init__(self, session: _Session) -> None:
        self.session = session

    def __call__(self):
        return self.session


def _transaction_row(transaction: IssuanceTransaction) -> SimpleNamespace:
    values = dict(vars(transaction))
    values["status"] = transaction.status.value
    values["c_nonce"] = transaction.nonce
    return SimpleNamespace(**values)


def _application_row(application: Application) -> SimpleNamespace:
    values = dict(vars(application))
    values["status"] = application.status.value
    values["submitted_evidence"] = values.pop("evidence_submissions")
    return SimpleNamespace(**values)


def _transaction(**overrides) -> IssuanceTransaction:
    values = {
        "id": "tx-concurrent-claim",
        "organization_id": "org-1",
        "credential_template_id": "badge-template",
        "revocation_profile_id": "status-profile",
        "application_id": "application-1",
        "applicant_id": "learner-1",
        "status": IssuanceStatus.AUTHORIZED,
        "access_token": "wallet-token",
        "nonce": "wallet-nonce",
        "claims": {"achievement": "Portable Canvas"},
        "credential_type": "OpenBadgeCredential",
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "issuer_did_override": "did:web:issuer.example",
        "issuer_algorithm": "ES256",
    }
    values.update(overrides)
    return IssuanceTransaction(**values)


def _credential(transaction: IssuanceTransaction, credential_id: str) -> IssuedCredential:
    return IssuedCredential(
        id=credential_id,
        transaction_id=transaction.id,
        organization_id=transaction.organization_id,
        credential_template_id=transaction.credential_template_id,
        applicant_id=transaction.applicant_id,
        issuer_did=transaction.issuer_did_override,
        credential_jwt="signed-credential",
        credential_hash="hash",
        status=CredentialStatus.ACTIVE,
        issued_at=datetime.now(UTC),
    )


def _proof_jwt(
    audience: str = "https://beta.elevenidllc.com/org/org-1",
) -> str:
    def encode(value):
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
        )

    return (
        f"{encode({'alg': 'ES256'})}.{encode({'aud': audience, 'nonce': 'wallet-nonce'})}.signature"
    )


async def _accept_test_nonce(_nonce: str) -> bool:
    """Let CAS-focused tests isolate signing concurrency from nonce replay."""
    return True


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/credential",
            "raw_path": b"/credential",
            "query_string": b"",
            "headers": [(b"x-request-id", b"claim-race-test")],
            "client": ("127.0.0.1", 12345),
            "server": ("beta.elevenidllc.com", 443),
        }
    )


@pytest.mark.asyncio
async def test_credential_endpoint_reports_invalid_nonce_separately_from_invalid_proof(
    monkeypatch,
) -> None:
    """A replayed or expired nonce is recoverable with a fresh nonce request."""
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    async def resolve_context(_transaction, **_kwargs):
        return {}

    async def reject_nonce(_nonce: str) -> bool:
        return False

    monkeypatch.setattr(routes, "apply_remote_issuer_context", resolve_context)
    monkeypatch.setattr(
        routes,
        "verify_proof_jwt",
        lambda *_args, **_kwargs: (True, "did:key:wallet", {}, None),
    )
    monkeypatch.setattr(repo, "consume_proof_nonce", reject_nonce)

    response = await routes.issue_credential(
        _request(),
        routes.CredentialRequest(
            credential_configuration_id="OpenBadgeCredential#sd-jwt",
            proofs={"jwt": [_proof_jwt()]},
        ),
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "invalid_nonce",
        "error_description": "Proof nonce is missing, expired, or already used",
    }


@pytest.mark.asyncio
async def test_credential_endpoint_fails_closed_when_nonce_store_is_unavailable(
    monkeypatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    async def resolve_context(_transaction, **_kwargs):
        return {}

    async def unavailable(_nonce: str) -> bool:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(routes, "apply_remote_issuer_context", resolve_context)
    monkeypatch.setattr(
        routes,
        "verify_proof_jwt",
        lambda *_args, **_kwargs: (True, "did:key:wallet", {}, None),
    )
    monkeypatch.setattr(repo, "consume_proof_nonce", unavailable)

    response = await routes.issue_credential(
        _request(),
        routes.CredentialRequest(
            credential_configuration_id="OpenBadgeCredential#sd-jwt",
            proofs={"jwt": [_proof_jwt()]},
        ),
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert json.loads(response.body) == {
        "error": "temporarily_unavailable",
        "error_description": "Proof nonce storage is unavailable",
    }


@pytest.mark.asyncio
async def test_invalid_proof_does_not_consume_wallet_nonce(monkeypatch) -> None:
    """Unauthenticated proof bytes cannot burn a valid wallet nonce."""
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    async def resolve_context(_transaction, **_kwargs):
        return {}

    consumed: list[str] = []

    async def consume_nonce(nonce: str) -> bool:
        consumed.append(nonce)
        return True

    monkeypatch.setattr(routes, "apply_remote_issuer_context", resolve_context)
    monkeypatch.setattr(
        routes,
        "verify_proof_jwt",
        lambda *_args, **_kwargs: (False, "", None, "invalid signature"),
    )
    monkeypatch.setattr(repo, "consume_proof_nonce", consume_nonce)

    response = await routes.issue_credential(
        _request(),
        routes.CredentialRequest(
            credential_configuration_id="OpenBadgeCredential#sd-jwt",
            proofs={"jwt": [_proof_jwt()]},
        ),
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "invalid_proof",
        "error_description": "invalid signature",
    }
    assert consumed == []


@pytest.mark.asyncio
async def test_credential_endpoint_reports_missing_proof_as_invalid_proof(monkeypatch) -> None:
    """OID4VCI uses the standard invalid_proof code for an absent proof."""
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    async def resolve_context(_transaction, **_kwargs):
        return {}

    monkeypatch.setattr(routes, "apply_remote_issuer_context", resolve_context)

    response = await routes.issue_credential(
        _request(),
        routes.CredentialRequest(credential_configuration_id="OpenBadgeCredential#sd-jwt"),
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "invalid_proof",
        "error_description": "Proof of possession is required per OID4VCI §7.2",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "credential_request",
    [
        routes.CredentialRequest(),
        routes.CredentialRequest(
            credential_configuration_id="OpenBadgeCredential#sd-jwt",
            credential_identifier="OpenBadgeCredential-2026",
        ),
    ],
)
async def test_credential_endpoint_requires_exactly_one_final_selector(
    credential_request: routes.CredentialRequest,
) -> None:
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    response = await routes.issue_credential(
        _request(),
        credential_request,
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "invalid_credential_request",
        "error_description": (
            "Provide exactly one of credential_configuration_id or credential_identifier"
        ),
    }


@pytest.mark.asyncio
async def test_credential_endpoint_reports_unknown_configuration_with_standard_error() -> None:
    """OID4VCI defines a specific error for an unknown configuration id."""
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    response = await routes.issue_credential(
        _request(),
        routes.CredentialRequest(
            credential_configuration_id="unknown-configuration",
            proofs={"jwt": [_proof_jwt()]},
        ),
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "unknown_credential_configuration",
        "error_description": "Unknown credential_configuration_id: 'unknown-configuration'",
    }


@pytest.mark.asyncio
async def test_credential_endpoint_rejects_same_tenant_configuration_substitution() -> None:
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    response = await routes.issue_credential(
        _request(),
        routes.CredentialRequest(
            credential_configuration_id="OtherCredential#sd-jwt",
            proofs={"jwt": [_proof_jwt()]},
        ),
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert json.loads(response.body)["error"] == "unknown_credential_configuration"


@pytest.mark.asyncio
async def test_credential_endpoint_reports_unknown_identifier_with_standard_error() -> None:
    """OID4VCI defines a specific error for an unknown credential identifier."""
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    response = await routes.issue_credential(
        _request(),
        routes.CredentialRequest(
            credential_identifier="unknown-identifier",
            proofs={"jwt": [_proof_jwt()]},
        ),
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "unknown_credential_identifier",
        "error_description": "Unknown credential_identifier: 'unknown-identifier'",
    }


def test_schema_enforces_one_credential_per_transaction() -> None:
    assert issuance_transactions_table.c.reserved_credential_id.nullable is True
    indexes = {index.name: index for index in issued_credentials_table.indexes}
    assert indexes["ux_issued_credentials_transaction_id"].unique is True


def test_portable_migration_installs_and_reverses_claim_constraints(monkeypatch) -> None:
    upgrade_sql: list[str] = []

    class EmptyRows:
        def mappings(self):
            return self

        def all(self):
            return []

    class Bind:
        def execute(self, _statement, _parameters=None):
            return EmptyRows()

    monkeypatch.setattr(
        migration.op, "execute", lambda statement: upgrade_sql.append(str(statement))
    )
    monkeypatch.setattr(migration.op, "get_bind", lambda: Bind())
    migration.upgrade()

    applied = "\n".join(upgrade_sql)
    assert "ADD COLUMN IF NOT EXISTS reserved_credential_id" in applied
    assert "CREATE UNIQUE INDEX IF NOT EXISTS ux_issued_credentials_transaction_id" in applied
    assert "DROP INDEX IF EXISTS issuance_service.ix_issued_credentials_transaction_id" in applied

    downgrade_sql: list[str] = []
    monkeypatch.setattr(
        migration.op, "execute", lambda statement: downgrade_sql.append(str(statement))
    )
    migration.downgrade()
    reversed_sql = "\n".join(downgrade_sql)
    assert (
        "DROP INDEX IF EXISTS issuance_service.ux_issued_credentials_transaction_id" in reversed_sql
    )
    assert "CREATE INDEX IF NOT EXISTS ix_issued_credentials_transaction_id" in reversed_sql
    assert "DROP COLUMN IF EXISTS reserved_credential_id" in reversed_sql


@pytest.mark.asyncio
async def test_repository_claim_is_a_single_winner_and_finalization_is_atomic() -> None:
    repo = InMemoryIssuanceRepository()
    original = _transaction()
    await repo.save_transaction(original)

    prepared_a = _transaction(
        issuer_profile_id="profile-a",
        issuer_did_override="did:web:issuer.example:a",
        signing_service_id="kms-a",
    )
    prepared_b = _transaction(
        issuer_profile_id="profile-b",
        issuer_did_override="did:web:issuer.example:b",
        signing_service_id="kms-b",
    )
    credential_id = "urn:uuid:reserved"

    claims = await asyncio.gather(
        repo.claim_transaction_for_signing(prepared_a, credential_id),
        repo.claim_transaction_for_signing(prepared_b, credential_id),
    )
    winners = [claim for claim in claims if claim is not None]
    assert len(winners) == 1
    winner = winners[0]
    assert winner.status == IssuanceStatus.SIGNING
    assert winner.reserved_credential_id == credential_id

    issued = _credential(winner, credential_id)
    results = await asyncio.gather(
        repo.finalize_credential_issuance(winner, issued),
        repo.finalize_credential_issuance(winner, issued),
        return_exceptions=True,
    )
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, ValueError) for result in results) == 1

    stored = await repo.get_transaction(winner.id)
    assert stored is not None
    assert stored.status == IssuanceStatus.ISSUED
    assert stored.nonce is None
    assert (await repo.get_credential_by_transaction_id(winner.id)).id == credential_id


@pytest.mark.asyncio
async def test_push_finalization_is_atomic_idempotent_and_uses_stable_identity() -> None:
    repo = InMemoryIssuanceRepository()
    pending = _transaction(status=IssuanceStatus.PENDING, nonce=None)
    await repo.save_transaction(pending)
    credential_id = stable_issuance_credential_id(pending.id)
    credential = _credential(pending, credential_id)

    results = await asyncio.gather(
        *(repo.finalize_direct_credential_issuance(pending, credential) for _ in range(64))
    )

    assert sum(results) == 1
    stored = await repo.get_transaction(pending.id)
    assert stored is not None
    assert stored.status == IssuanceStatus.ISSUED
    assert stored.issued_at == credential.issued_at
    assert (await repo.get_credential_by_transaction_id(pending.id)).id == credential_id

    wrong = _credential(pending, "urn:uuid:wrong")
    with pytest.raises(ValueError, match="stable transaction identity"):
        await repo.finalize_direct_credential_issuance(pending, wrong)


@pytest.mark.asyncio
async def test_stale_authorized_save_cannot_reopen_a_signing_transaction() -> None:
    repo = InMemoryIssuanceRepository()
    authorized = _transaction()
    await repo.save_transaction(authorized)
    stale_snapshot = await repo.get_transaction(authorized.id)
    prepared = await repo.get_transaction(authorized.id)
    assert stale_snapshot is not None and prepared is not None

    claimed = await repo.claim_transaction_for_signing(prepared, "urn:uuid:reserved")
    assert claimed is not None

    stale_snapshot.nonce = "attacker-replacement-nonce"
    with pytest.raises(ValueError, match="Stale issuance transaction transition"):
        await repo.save_transaction(stale_snapshot)

    stored = await repo.get_transaction(authorized.id)
    assert stored is not None
    assert stored.status == IssuanceStatus.SIGNING
    assert stored.reserved_credential_id == "urn:uuid:reserved"
    assert stored.nonce == "wallet-nonce"


@pytest.mark.asyncio
async def test_generic_save_cannot_bypass_atomic_credential_finalization() -> None:
    repo = InMemoryIssuanceRepository()
    authorized = _transaction()
    await repo.save_transaction(authorized)
    unauthorized_finalization = await repo.get_transaction(authorized.id)
    assert unauthorized_finalization is not None
    unauthorized_finalization.complete()

    with pytest.raises(ValueError, match="Stale issuance transaction transition"):
        await repo.save_transaction(unauthorized_finalization)

    stored = await repo.get_transaction(authorized.id)
    assert stored is not None
    assert stored.status == IssuanceStatus.AUTHORIZED
    assert await repo.get_credential_by_transaction_id(authorized.id) is None


@pytest.mark.asyncio
async def test_postgres_token_claim_uses_pending_compare_and_set() -> None:
    prepared = _transaction(
        status=IssuanceStatus.AUTHORIZED,
        access_token="new-wallet-token",
        nonce=None,
    )
    returned = _transaction(
        status=IssuanceStatus.AUTHORIZED,
        access_token="hashed-at-rest",
        nonce=None,
    )
    winner_session = _Session([_Result(_transaction_row(returned))])
    winner_repo = PostgresIssuanceRepository(_SessionFactory(winner_session))

    claimed = await winner_repo.claim_transaction_for_token(prepared)

    assert claimed is not None
    assert claimed.status == IssuanceStatus.AUTHORIZED
    assert claimed.access_token == "new-wallet-token"
    assert winner_session.committed is True
    statement = winner_session.statements[0]
    sql = str(statement).upper()
    parameters = statement.compile().params
    assert "PRE_AUTH_CODE" in sql
    assert "STATUS =" in sql
    assert "RETURNING" in sql
    assert IssuanceStatus.PENDING.value in parameters.values()
    assert IssuanceStatus.AUTHORIZED.value in parameters.values()

    loser_session = _Session([_Result(None, rowcount=0)])
    loser_repo = PostgresIssuanceRepository(_SessionFactory(loser_session))

    assert await loser_repo.claim_transaction_for_token(prepared) is None
    assert loser_session.rolled_back is True
    assert loser_session.committed is False


@pytest.mark.asyncio
async def test_postgres_claim_and_finalize_use_cas_and_one_database_transaction() -> None:
    prepared = _transaction(
        issuer_profile_id="issuer-profile-1",
        issuer_did_override="did:web:issuer.example",
        signing_service_id="openbao-transit",
    )
    credential_id = "urn:uuid:postgres-reservation"
    returned = _transaction(
        status=IssuanceStatus.SIGNING,
        reserved_credential_id=credential_id,
        issuer_profile_id=prepared.issuer_profile_id,
        issuer_did_override=prepared.issuer_did_override,
        signing_service_id=prepared.signing_service_id,
    )
    claim_session = _Session([_Result(_transaction_row(returned))])
    claim_repo = PostgresIssuanceRepository(_SessionFactory(claim_session))

    claimed = await claim_repo.claim_transaction_for_signing(prepared, credential_id)

    assert claimed is not None and claimed.status == IssuanceStatus.SIGNING
    assert claim_session.committed is True
    claim_statement = claim_session.statements[0]
    claim_sql = str(claim_statement).upper()
    claim_parameters = claim_statement.compile().params
    assert "STATUS =" in claim_sql and "RETURNING" in claim_sql
    assert IssuanceStatus.AUTHORIZED.value in claim_parameters.values()
    assert IssuanceStatus.SIGNING.value in claim_parameters.values()
    assert credential_id in claim_parameters.values()
    assert prepared.signing_service_id in claim_parameters.values()

    issued = _credential(claimed, credential_id)
    finalize_session = _Session(
        [
            _Result(_transaction_row(claimed)),
            _Result(None),
            _Result(None),
            _Result(),
            _Result(rowcount=1),
        ]
    )
    finalize_repo = PostgresIssuanceRepository(_SessionFactory(finalize_session))

    await finalize_repo.finalize_credential_issuance(claimed, issued)

    assert finalize_session.committed is True
    assert finalize_session.rolled_back is False
    assert all(finalize_session.transaction_states)
    finalize_sql = [str(statement).upper() for statement in finalize_session.statements]
    assert "FOR UPDATE" in finalize_sql[0]
    assert "FOR UPDATE" in finalize_sql[2]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUED_CREDENTIALS" in finalize_sql[3]
    assert "UPDATE ISSUANCE_SERVICE.ISSUANCE_TRANSACTIONS" in finalize_sql[4]
    assert "RESERVED_CREDENTIAL_ID" in finalize_sql[4]
    assert issued.issued_at in finalize_session.statements[4].compile().params.values()


@pytest.mark.asyncio
async def test_postgres_push_finalization_is_one_transaction_and_retry_safe() -> None:
    pending = _transaction(status=IssuanceStatus.PENDING, nonce=None)
    credential = _credential(pending, stable_issuance_credential_id(pending.id))
    winner_session = _Session(
        [
            _Result(_transaction_row(pending)),
            _Result(None),
            _Result(None),
            _Result(),
            _Result(rowcount=1),
        ]
    )
    winner_repo = PostgresIssuanceRepository(_SessionFactory(winner_session))

    assert await winner_repo.finalize_direct_credential_issuance(pending, credential) is True
    assert winner_session.committed is True
    assert all(winner_session.transaction_states)
    winner_sql = [str(statement).upper() for statement in winner_session.statements]
    assert "FOR UPDATE" in winner_sql[0]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUED_CREDENTIALS" in winner_sql[3]
    assert "UPDATE ISSUANCE_SERVICE.ISSUANCE_TRANSACTIONS" in winner_sql[4]
    assert "RESERVED_CREDENTIAL_ID" not in winner_sql[4]
    assert credential.issued_at in winner_session.statements[4].compile().params.values()

    retry_session = _Session(
        [
            _Result(_transaction_row(_transaction(status=IssuanceStatus.ISSUED, nonce=None))),
            _Result(SimpleNamespace(id=credential.id)),
        ]
    )
    retry_repo = PostgresIssuanceRepository(_SessionFactory(retry_session))

    assert await retry_repo.finalize_direct_credential_issuance(pending, credential) is False
    assert retry_session.committed is True
    assert len(retry_session.statements) == 2


@pytest.mark.asyncio
async def test_postgres_direct_finalization_binds_the_authoritative_scope() -> None:
    authoritative = _transaction(status=IssuanceStatus.PENDING, nonce=None)
    forged = _transaction(
        status=IssuanceStatus.PENDING,
        nonce=None,
        organization_id="org-forged",
        credential_template_id="template-forged",
    )
    credential = _credential(forged, stable_issuance_credential_id(forged.id))
    session = _Session([_Result(_transaction_row(authoritative))])
    repo = PostgresIssuanceRepository(_SessionFactory(session))

    with pytest.raises(ValueError, match="authoritative issuance transaction"):
        await repo.finalize_direct_credential_issuance(forged, credential)

    assert session.committed is False
    assert session.rolled_back is True
    assert all(session.transaction_states)


@pytest.mark.asyncio
async def test_postgres_canvas_approval_reserves_transaction_under_application_lock() -> None:
    now = datetime.now(UTC)
    application = Application(
        id="canvas-approval-application",
        organization_id="org-1",
        application_template_id="canvas-application-template",
        applicant_identifier="learner-1",
        integration_context={
            "canvas": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
            }
        },
    )
    prepared = _transaction(
        id="canvas-approval-transaction",
        application_id=application.id,
        status=IssuanceStatus.PENDING,
        access_token=None,
        nonce=None,
    )
    approved = Application(**vars(application))
    approved.status = ApplicationStatus.APPROVED
    approved.review_notes = "Concurrent approval"
    approved.reviewer_id = "canvas-approver"
    approved.reviewed_at = now
    approved.updated_at = now
    approved.issuance_transaction_id = prepared.id
    session = _Session(
        [
            _Result(_application_row(application)),
            _Result(_transaction_row(prepared)),
            _Result(_application_row(approved)),
        ]
    )
    repo = PostgresIssuanceRepository(_SessionFactory(session))

    (
        stored_application,
        stored_transaction,
        already_issued,
    ) = await repo.reserve_canvas_application_issuance(
        prepared,
        reviewer_id="canvas-approver",
        review_notes="Concurrent approval",
        reviewed_at=now,
    )

    assert session.committed is True
    assert session.rolled_back is False
    assert all(session.transaction_states)
    assert already_issued is False
    assert stored_application.issuance_transaction_id == prepared.id
    assert stored_transaction.id == prepared.id
    statements = [str(statement).upper() for statement in session.statements]
    assert "FOR UPDATE" in statements[0]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUANCE_TRANSACTIONS" in statements[1]
    assert "UPDATE ISSUANCE_SERVICE.APPLICATIONS" in statements[2]


@pytest.mark.asyncio
async def test_postgres_canvas_approval_refreshes_exact_active_pending_transaction() -> None:
    now = datetime.now(UTC)
    application = Application(
        id="canvas-pending-application",
        organization_id="org-1",
        application_template_id="canvas-application-template",
        applicant_identifier="learner-1",
        integration_context={
            "canvas": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
            }
        },
        issuance_transaction_id="canvas-pending-transaction",
    )
    current = _transaction(
        id=application.issuance_transaction_id,
        application_id=application.id,
        status=IssuanceStatus.PENDING,
        access_token=None,
        nonce="preserved-nonce",
        issuer_profile_id="stale-profile",
        signing_service_id="stale-service",
        delivery_mode="wallet_only",
    )
    prepared = IssuanceTransaction(**vars(current))
    prepared.issuer_profile_id = "active-profile"
    prepared.issuer_did_override = "did:web:active.example"
    prepared.issuer_algorithm = "EdDSA"
    prepared.signing_service_id = "active-service"
    prepared.delivery_mode = "wallet_plus_canvas_mirror"
    prepared.claims = {**prepared.claims, "_vct": "OpenBadgeCredential"}
    approved = Application(**vars(application))
    approved.status = ApplicationStatus.APPROVED
    approved.review_notes = "Refreshed approval"
    approved.reviewer_id = "canvas-approver"
    approved.reviewed_at = now
    approved.updated_at = now
    session = _Session(
        [
            _Result(_application_row(application)),
            _Result(_transaction_row(current)),
            _Result(_transaction_row(prepared)),
            _Result(_application_row(approved)),
        ]
    )
    repo = PostgresIssuanceRepository(_SessionFactory(session))

    _, stored_transaction, already_issued = await repo.reserve_canvas_application_issuance(
        prepared,
        reviewer_id="canvas-approver",
        review_notes="Refreshed approval",
        reviewed_at=now,
    )

    assert already_issued is False
    assert stored_transaction.id == current.id
    assert stored_transaction.nonce == "preserved-nonce"
    assert stored_transaction.issuer_profile_id == "active-profile"
    assert stored_transaction.signing_service_id == "active-service"
    assert session.committed is True
    statements = [str(statement).upper() for statement in session.statements]
    assert "SELECT" in statements[1]
    assert "UPDATE ISSUANCE_SERVICE.ISSUANCE_TRANSACTIONS" in statements[2]
    assert "UPDATE ISSUANCE_SERVICE.APPLICATIONS" in statements[3]
    refresh_params = session.statements[2].compile().params
    assert "preserved-nonce" not in refresh_params.values()
    assert "active-profile" in refresh_params.values()
    assert "active-service" in refresh_params.values()
    assert "wallet_plus_canvas_mirror" in refresh_params.values()
    assert prepared.claims in refresh_params.values()


@pytest.mark.asyncio
async def test_postgres_canvas_pending_refresh_loss_rolls_back_approval() -> None:
    now = datetime.now(UTC)
    application = Application(
        id="canvas-refresh-race-application",
        organization_id="org-1",
        application_template_id="canvas-application-template",
        applicant_identifier="learner-1",
        integration_context={
            "canvas": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
            }
        },
        issuance_transaction_id="canvas-refresh-race-transaction",
    )
    pending = _transaction(
        id=application.issuance_transaction_id,
        application_id=application.id,
        status=IssuanceStatus.PENDING,
        access_token=None,
        nonce=None,
    )
    session = _Session(
        [
            _Result(_application_row(application)),
            _Result(_transaction_row(pending)),
            _Result(None, rowcount=0),
        ]
    )
    repo = PostgresIssuanceRepository(_SessionFactory(session))

    with pytest.raises(
        ValueError,
        match="Canvas pending issuance transaction could not be refreshed",
    ):
        await repo.reserve_canvas_application_issuance(
            pending,
            reviewer_id="canvas-approver",
            review_notes="must-not-commit",
            reviewed_at=now,
        )

    assert session.committed is False
    assert session.rolled_back is True
    assert len(session.statements) == 3


@pytest.mark.asyncio
async def test_postgres_canvas_claim_projection_is_in_finalization_transaction() -> None:
    credential_id = "urn:uuid:canvas-postgres-credential"
    claimed = _transaction(
        id="canvas-postgres-transaction",
        status=IssuanceStatus.SIGNING,
        reserved_credential_id=credential_id,
        application_id="canvas-postgres-application",
    )
    application = Application(
        id=claimed.application_id,
        organization_id=claimed.organization_id,
        application_template_id="canvas-application-template",
        applicant_identifier="learner-1",
        integration_context={
            "canvas": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "canvas_award_candidate_id": "candidate-1",
            }
        },
        status=ApplicationStatus.APPROVED,
        issuance_transaction_id=claimed.id,
    )
    projected = Application(**vars(application))
    projected.credential_id = credential_id
    candidate_row = SimpleNamespace(
        id="candidate-1",
        organization_id="org-1",
        platform_id="platform-1",
        binding_id="binding-1",
        application_id=application.id,
        claimed_credential_id=None,
    )
    session = _Session(
        [
            _Result(_transaction_row(claimed)),
            _Result(None),
            _Result(_application_row(application)),
            _Result(),
            _Result(candidate_row),
            _Result(_application_row(projected)),
            _Result(rowcount=1),
            _Result(rowcount=1),
        ]
    )
    repo = PostgresIssuanceRepository(_SessionFactory(session))

    await repo.finalize_credential_issuance(
        claimed,
        _credential(claimed, credential_id),
    )

    assert session.committed is True
    assert session.rolled_back is False
    assert all(session.transaction_states)
    statements = [str(statement).upper() for statement in session.statements]
    assert "FOR UPDATE" in statements[0]
    assert "FOR UPDATE" in statements[2]
    assert "INSERT INTO ISSUANCE_SERVICE.ISSUED_CREDENTIALS" in statements[3]
    assert "FOR UPDATE" in statements[4]
    assert "UPDATE ISSUANCE_SERVICE.APPLICATIONS" in statements[5]
    assert "UPDATE ISSUANCE_SERVICE.CANVAS_AWARD_CANDIDATES" in statements[6]
    assert "UPDATE ISSUANCE_SERVICE.ISSUANCE_TRANSACTIONS" in statements[7]


@pytest.mark.asyncio
async def test_postgres_generic_save_rejects_a_stale_authorized_snapshot() -> None:
    stale = _transaction(status=IssuanceStatus.AUTHORIZED)
    session = _Session([_Result(rowcount=0)])
    repo = PostgresIssuanceRepository(_SessionFactory(session))

    with pytest.raises(ValueError, match="Stale issuance transaction transition"):
        await repo.save_transaction(stale)

    assert session.rolled_back is True
    statement = session.statements[0]
    sql = str(statement).upper()
    parameters = statement.compile().params
    assert "ON CONFLICT" in sql
    assert "WHERE ISSUANCE_SERVICE.ISSUANCE_TRANSACTIONS.STATUS IN" in sql
    parameter_values = list(parameters.values())
    assert any(
        isinstance(value, list) and set(value) == {"pending", "authorized"}
        for value in parameter_values
    )


@pytest.mark.asyncio
async def test_concurrent_wallet_requests_execute_exactly_one_kms_signing_path(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    await repo.save_transaction(_transaction())

    remote_context = {
        "issuer_profile_id": "issuer-profile-1",
        "issuer_did": "did:web:issuer.example",
        "signing_service_id": "openbao-transit",
        "signing_key_reference": "badge-key",
        "verification_method_id": "did:web:issuer.example#badge-key",
        "service": {"algorithm": "ES256"},
    }

    async def resolve_context(tx, **_kwargs):
        tx.issuer_profile_id = remote_context["issuer_profile_id"]
        tx.issuer_did_override = remote_context["issuer_did"]
        tx.signing_service_id = remote_context["signing_service_id"]
        return remote_context

    # Hold both requests immediately before the repository CAS so this test is
    # a real race rather than two sequential retries.
    guard_arrivals = 0
    both_at_guard = asyncio.Event()

    async def readiness_barrier(**_kwargs):
        nonlocal guard_arrivals
        guard_arrivals += 1
        if guard_arrivals == 2:
            both_at_guard.set()
        await asyncio.wait_for(both_at_guard.wait(), timeout=2)

    counts = {"builder": 0, "kms": 0}

    async def did_sign(**kwargs):
        assert kwargs["issuer_did"] == remote_context["issuer_did"]
        assert kwargs["credential_format"] == "dc+sd-jwt"
        assert kwargs["key_purpose"] == "vc_jwt_issuer"
        assert "issuer_profile_id" not in kwargs
        counts["kms"] += 1
        await asyncio.sleep(0)
        return {"signature": "remote-signature", "algorithm": "ES256"}

    async def build_credential(*, remote_sign, credential_id, **_kwargs):
        counts["builder"] += 1
        await remote_sign(b"signing-input", "ES256")
        return "header.payload.signature~", credential_id

    async def allocate_status(**_kwargs):
        return "status-profile", []

    async def no_op(**_kwargs):
        return None

    async def no_op_positional(*_args, **_kwargs):
        return None

    monkeypatch.setattr(routes, "apply_remote_issuer_context", resolve_context)
    monkeypatch.setattr(repo, "consume_proof_nonce", _accept_test_nonce)
    monkeypatch.setattr(routes, "require_canvas_issuance_ready", readiness_barrier)
    monkeypatch.setattr(
        routes, "verify_proof_jwt", lambda *_args, **_kwargs: (True, "did:key:learner", {}, None)
    )
    monkeypatch.setattr(routes, "sign_payload_with_issuer_did", did_sign)
    monkeypatch.setattr(routes, "create_sd_jwt_vc_with_remote_signing", build_credential)
    monkeypatch.setattr(routes, "_allocate_credential_status_list_entries", allocate_status)
    monkeypatch.setattr(routes, "record_canvas_credential_claim", no_op)
    monkeypatch.setattr(routes, "_finalize_credential_renewal", no_op_positional)
    monkeypatch.setattr(routes, "record_post_issuance_deliveries", no_op_positional)

    credential_request = routes.CredentialRequest(
        credential_configuration_id="OpenBadgeCredential#sd-jwt",
        proofs={"jwt": [_proof_jwt()]},
    )

    results = await asyncio.gather(
        routes.issue_credential(
            _request(), credential_request, authorization="Bearer wallet-token", repo=repo
        ),
        routes.issue_credential(
            _request(), credential_request, authorization="Bearer wallet-token", repo=repo
        ),
    )

    assert counts == {"builder": 1, "kms": 1}
    assert sum(isinstance(result, routes.CredentialResponse) for result in results) == 1
    conflicts = [result for result in results if isinstance(result, JSONResponse)]
    assert len(conflicts) == 1
    concurrent_loser = SIGNING_CONTRACT["state_machine"]["concurrent_loser"]
    assert conflicts[0].status_code == concurrent_loser["status_code"]
    assert json.loads(conflicts[0].body) == concurrent_loser["body"]

    stored = await repo.get_transaction("tx-concurrent-claim")
    assert stored is not None and stored.status == IssuanceStatus.ISSUED
    credentials = await repo.list_credentials_by_org("org-1")
    assert len(credentials) == 1
    assert credentials[0].id == stored.reserved_credential_id


@pytest.mark.parametrize(
    "audience",
    (
        "http://issuer.example/org/org-1",
        "https://other.example/org/org-1",
        "https://issuer.example:444/org/org-1",
        "https://issuer.example@other.example/org/org-1",
        "/org/org-1",
    ),
)
@pytest.mark.asyncio
async def test_grpc_credential_endpoint_rejects_unconfigured_proof_audience(
    monkeypatch,
    audience: str,
) -> None:
    import grpc
    from issuance.infrastructure.adapters import grpc_adapter
    from marty_proto.v1 import issuance_service_pb2 as pb2

    repo = InMemoryIssuanceRepository()
    transaction = _transaction()
    await repo.save_transaction(transaction)

    async def unexpected_resolution(*_args, **_kwargs):
        raise AssertionError("audience rejection must precede issuer resolution")

    monkeypatch.setattr(
        grpc_adapter,
        "_resolve_remote_signing_context_for_tx",
        unexpected_resolution,
    )
    monkeypatch.setattr(grpc_adapter, "ISSUER_BASE_URL", "https://issuer.example")
    service = grpc_adapter.IssuanceServiceGrpc(lambda: repo)
    request = pb2.IssueCredentialRequest(
        access_token=transaction.access_token,
        format="vc+sd-jwt",
        proofs=[pb2.ProofJwt(proof_type="jwt", jwt=_proof_jwt(audience))],
    )

    class Context:
        code = None
        details = None

        def set_code(self, code):
            self.code = code

        def set_details(self, details):
            self.details = details

    context = Context()
    response = await service.IssueCredential(request, context)

    assert response == pb2.IssueCredentialResponse()
    assert context.code is grpc.StatusCode.INVALID_ARGUMENT
    assert context.details == "Proof JWT audience does not match credential issuer"


@pytest.mark.asyncio
async def test_concurrent_grpc_delivery_executes_one_signing_path(monkeypatch) -> None:
    import grpc
    from issuance.application import rust_integration
    from issuance.infrastructure.adapters import delivery_records, grpc_adapter
    from issuance.infrastructure.api import signing_context
    from marty_proto.v1 import issuance_service_pb2 as pb2

    repo = InMemoryIssuanceRepository()
    transaction = _transaction()
    await repo.save_transaction(transaction)
    stable_id = stable_issuance_credential_id(transaction.id)
    remote_context = {
        "issuer_profile_id": "issuer-profile-1",
        "issuer_did": transaction.issuer_did_override,
        "algorithm": "ES256",
        "verification_method_id": "did:web:issuer.example#badge-key",
        "signing_service_id": "openbao-primary",
        "service": {"algorithm": "ES256"},
    }
    drifted_context = {
        **remote_context,
        "verification_method_id": "did:web:issuer.example#rotated-key",
        "signing_service_id": "openbao-rotated",
    }
    counts = {"builder": 0, "kms": 0}
    resolution_calls = 0
    claim_arrivals = 0
    claim_completions = 0
    both_at_claim = asyncio.Event()
    both_claimed = asyncio.Event()
    original_claim = repo.claim_transaction_for_signing

    async def resolve_context(_tx, **_kwargs):
        nonlocal resolution_calls
        resolution_calls += 1
        # Both contenders validate the same admitted context. A forbidden
        # post-claim re-resolution would observe a rotated key and service.
        return remote_context if resolution_calls <= 2 else drifted_context

    async def verify_proof(*_args, **_kwargs):
        assert _kwargs["issuer_url"] == "https://issuer.example/org/org-1"
        return True, "did:key:learner", {"kty": "EC"}, None

    async def claim_for_signing(*args, **kwargs):
        nonlocal claim_arrivals, claim_completions
        claim_arrivals += 1
        if claim_arrivals == 2:
            both_at_claim.set()
        await asyncio.wait_for(both_at_claim.wait(), timeout=2)
        claimed = await original_claim(*args, **kwargs)
        claim_completions += 1
        if claim_completions == 2:
            both_claimed.set()
        return claimed

    async def sign_payload(**kwargs):
        counts["kms"] += 1
        assert kwargs["expected_verification_method_id"] == remote_context["verification_method_id"]
        return {"signature_raw_b64": "cmVtb3RlLXNpZ25hdHVyZQ", "algorithm": "ES256"}

    async def build_credential(*, remote_sign, credential_id, **_kwargs):
        counts["builder"] += 1
        await asyncio.wait_for(both_claimed.wait(), timeout=2)
        await remote_sign(b"signing-input", "ES256")
        return "signed-credential", credential_id

    delivery_calls = 0

    async def record_delivery(*_args, **_kwargs):
        nonlocal delivery_calls
        delivery_calls += 1

    async def no_op_event(*_args, **_kwargs):
        return None

    monkeypatch.setattr(grpc_adapter, "_resolve_remote_signing_context_for_tx", resolve_context)
    monkeypatch.setattr(grpc_adapter, "verify_oid4vci_proof_with_issuer_policy", verify_proof)
    monkeypatch.setattr(grpc_adapter, "ISSUER_BASE_URL", "https://issuer.example")
    monkeypatch.setattr(delivery_records, "record_post_issuance_deliveries", record_delivery)
    monkeypatch.setattr(repo, "claim_transaction_for_signing", claim_for_signing)
    monkeypatch.setattr(rust_integration, "create_sd_jwt_vc_with_remote_signing", build_credential)
    monkeypatch.setattr(signing_context, "sign_payload_with_issuer_did", sign_payload)

    service = grpc_adapter.IssuanceServiceGrpc(lambda: repo)
    monkeypatch.setattr(service, "_emit_credential_event", no_op_event)
    request = pb2.IssueCredentialRequest(
        access_token=transaction.access_token,
        format="vc+sd-jwt",
        proofs=[
            pb2.ProofJwt(
                proof_type="jwt",
                jwt=_proof_jwt("https://issuer.example/org/org-1"),
            )
        ],
    )

    class Context:
        code = None
        details = None

        def set_code(self, code):
            self.code = code

        def set_details(self, details):
            self.details = details

    contexts = [Context(), Context()]
    responses = await asyncio.gather(
        service.IssueCredential(request, contexts[0]),
        service.IssueCredential(request, contexts[1]),
    )

    assert claim_arrivals == 2
    assert resolution_calls == 2
    assert counts == {"builder": 1, "kms": 1}
    assert sum(context.code is None for context in contexts) == 1
    losers = [
        context for context in contexts if context.code is grpc.StatusCode.FAILED_PRECONDITION
    ]
    assert len(losers) == 1
    assert losers[0].details == grpc_adapter._GRPC_SIGNING_CLAIM_CONFLICT
    assert sum(bool(response.credentials) for response in responses) == 1
    assert {
        response.credentials[0].credential for response in responses if response.credentials
    } == {"signed-credential"}
    credentials = await repo.list_credentials_by_org(transaction.organization_id)
    assert len(credentials) == 1
    assert credentials[0].id == stable_id
    stored = await repo.get_transaction(transaction.id)
    assert stored is not None and stored.status == IssuanceStatus.ISSUED
    assert len(await repo.list_events_for_application(transaction.application_id)) == 1
    assert delivery_calls == 1


@pytest.mark.asyncio
async def test_grpc_signing_failure_marks_reserved_transaction_failed(monkeypatch) -> None:
    import grpc
    from issuance.infrastructure.adapters import grpc_adapter
    from marty_proto.v1 import issuance_service_pb2 as pb2

    repo = InMemoryIssuanceRepository()
    transaction = _transaction()
    await repo.save_transaction(transaction)
    stable_id = stable_issuance_credential_id(transaction.id)
    remote_context = {
        "issuer_profile_id": "issuer-profile-1",
        "issuer_did": transaction.issuer_did_override,
        "algorithm": "ES256",
        "verification_method_id": "did:web:issuer.example#badge-key",
        "service": {"algorithm": "ES256"},
    }
    builder_calls = 0

    async def resolve_context(_tx, **_kwargs):
        return remote_context

    async def verify_proof(*_args, **_kwargs):
        return True, "did:key:learner", {"kty": "EC"}, None

    async def fail_signing(_tx, **_kwargs):
        nonlocal builder_calls
        builder_calls += 1
        raise RuntimeError("KMS unavailable")

    monkeypatch.setattr(grpc_adapter, "_resolve_remote_signing_context_for_tx", resolve_context)
    monkeypatch.setattr(grpc_adapter, "verify_oid4vci_proof_with_issuer_policy", verify_proof)
    monkeypatch.setattr(grpc_adapter, "_create_remote_signed_sd_jwt_for_tx", fail_signing)
    monkeypatch.setattr(grpc_adapter, "ISSUER_BASE_URL", "https://issuer.example")

    service = grpc_adapter.IssuanceServiceGrpc(lambda: repo)
    request = pb2.IssueCredentialRequest(
        access_token=transaction.access_token,
        format="vc+sd-jwt",
        proofs=[
            pb2.ProofJwt(
                proof_type="jwt",
                jwt=_proof_jwt("https://issuer.example/org/org-1"),
            )
        ],
    )

    class Context:
        code = None
        details = None

        def set_code(self, code):
            self.code = code

        def set_details(self, details):
            self.details = details

    context = Context()
    response = await service.IssueCredential(request, context)

    assert response == pb2.IssueCredentialResponse()
    assert context.code is grpc.StatusCode.UNAVAILABLE
    assert context.details == "DID-backed remote signing failed: KMS unavailable"
    assert builder_calls == 1
    stored = await repo.get_transaction(transaction.id)
    assert stored is not None
    assert stored.status == IssuanceStatus.FAILED
    assert stored.reserved_credential_id == stable_id
    assert await repo.list_credentials_by_org(transaction.organization_id) == []
    assert await repo.list_events_for_application(transaction.application_id) == []


@pytest.mark.asyncio
async def test_ldp_vc_uses_native_builder_and_did_mediated_profile_signing(monkeypatch) -> None:
    repo = InMemoryIssuanceRepository()
    transaction = _transaction(
        credential_payload_format="w3c_vcdm_v2_di",
        credential_type="EmployeeCredential",
        issuer_did_override="did:web:issuer.example",
        issuer_algorithm="EdDSA",
    )
    credential_document = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:official-document",
        "type": ["VerifiableCredential", "EmployeeCredential"],
        "issuer": "did:web:issuer.example",
        "credentialSubject": {"id": "did:key:learner", "role": "member"},
    }
    transaction.claims["_credential_document"] = credential_document
    await repo.save_transaction(transaction)

    verification_method_id = "did:web:issuer.example#data-integrity"
    public_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
        "kid": verification_method_id,
    }
    remote_context = {
        "issuer_profile_id": "issuer-profile-data-integrity",
        "issuer_did": "did:web:issuer.example",
        "signing_service_id": "managed-custody",
        "verification_method_id": verification_method_id,
        "public_jwk": public_jwk,
        "service": {"algorithm": "EdDSA"},
    }
    captured: dict[str, object] = {}

    async def resolve_context(tx, **kwargs):
        captured["resolution"] = kwargs
        tx.issuer_profile_id = remote_context["issuer_profile_id"]
        tx.issuer_did_override = remote_context["issuer_did"]
        tx.signing_service_id = remote_context["signing_service_id"]
        return remote_context

    async def did_sign(**kwargs):
        captured["sign"] = kwargs
        assert kwargs["organization_id"] == "org-1"
        assert kwargs["issuer_did"] == "did:web:issuer.example"
        assert kwargs["credential_format"] == "ldp_vc"
        assert kwargs["key_purpose"] == "vc_jwt_issuer"
        assert kwargs["algorithm"] == "EdDSA"
        assert "issuer_profile_id" not in kwargs
        assert "signing_service_id" not in kwargs
        assert "key_reference" not in kwargs
        return {
            "ok": True,
            "issuer_did": kwargs["issuer_did"],
            "verification_method_id": verification_method_id,
            "algorithm": "EdDSA",
            "signature_raw_b64": base64.urlsafe_b64encode(bytes(64)).decode().rstrip("="),
        }

    async def build_data_integrity(*, remote_sign, credential_id, **kwargs):
        captured["builder"] = kwargs
        await remote_sign(b"canonical-data-integrity-input", "EdDSA")
        return (
            json.dumps(
                {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": credential_id,
                    "type": ["VerifiableCredential"],
                    "issuer": kwargs["issuer_did"],
                    "credentialSubject": {"id": kwargs["subject_id"]},
                    "proof": {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-rdfc-2022",
                        "verificationMethod": kwargs["verification_method_id"],
                        "proofPurpose": "assertionMethod",
                        "proofValue": "zProof",
                    },
                },
                separators=(",", ":"),
            ),
            credential_id,
        )

    async def allocate_status(**_kwargs):
        return "status-profile", []

    async def no_op(*_args, **_kwargs):
        return None

    monkeypatch.setattr(routes, "apply_remote_issuer_context", resolve_context)
    monkeypatch.setattr(repo, "consume_proof_nonce", _accept_test_nonce)
    monkeypatch.setattr(routes, "require_canvas_issuance_ready", no_op)
    monkeypatch.setattr(
        routes,
        "verify_proof_jwt",
        lambda *_args, **_kwargs: (True, "did:key:learner", {}, None),
    )
    monkeypatch.setattr(routes, "sign_payload_with_issuer_did", did_sign)
    monkeypatch.setattr(
        routes,
        "create_vcdm_data_integrity_with_remote_signing",
        build_data_integrity,
    )
    monkeypatch.setattr(routes, "_allocate_credential_status_list_entries", allocate_status)
    monkeypatch.setattr(routes, "record_canvas_credential_claim", no_op)
    monkeypatch.setattr(routes, "_finalize_credential_renewal", no_op)
    monkeypatch.setattr(routes, "record_post_issuance_deliveries", no_op)

    response = await routes.issue_credential(
        _request(),
        routes.CredentialRequest(
            credential_configuration_id="EmployeeCredential#ldp-vc",
            proofs={"jwt": [_proof_jwt()]},
        ),
        authorization="Bearer wallet-token",
        repo=repo,
    )

    assert isinstance(response, routes.CredentialResponse)
    assert response.credentials[0]["format"] == "ldp_vc"
    assert response.credentials[0]["credential"]["proof"]["cryptosuite"] == "eddsa-rdfc-2022"
    assert captured["resolution"]["credential_format"] == "ldp_vc"
    assert captured["builder"]["public_jwk"] == public_jwk
    assert captured["builder"]["verification_method_id"] == verification_method_id
    assert captured["builder"]["credential_document"] == credential_document
    assert captured["sign"]["payload"] == b"canonical-data-integrity-input"

    credentials = await repo.list_credentials_by_org("org-1")
    assert len(credentials) == 1
    persisted = json.loads(credentials[0].credential_jwt)
    assert persisted["issuer"] == "did:web:issuer.example"
    assert persisted["id"] == credential_document["id"]
    assert persisted["proof"]["verificationMethod"] == verification_method_id


@pytest.mark.asyncio
async def test_auth_code_only_concurrent_claims_share_one_canonical_transaction(
    monkeypatch,
) -> None:
    repo = InMemoryIssuanceRepository()
    auth_code_contract = SIGNING_CONTRACT["authorization_code_only"]
    authorization_session = AuthorizationSession(
        id=auth_code_contract["authorization_session_id"],
        organization_id="org-1",
        credential_configuration_ids=["OpenBadgeCredential#sd-jwt"],
        access_token="wallet-token",
        nonce="wallet-nonce",
        status="exchanged",
    )
    await repo.save_authorization_session(authorization_session)

    async def display_metadata(_organization_id: str):
        return {
            "OpenBadgeCredential": {
                "issuer_did": "did:web:issuer.example",
                "issuer_algorithm": "ES256",
            }
        }

    monkeypatch.setattr(
        repo,
        "get_credential_display_metadata_for_org",
        display_metadata,
    )

    remote_context = {
        "issuer_profile_id": "issuer-profile-1",
        "issuer_did": "did:web:issuer.example",
        "signing_service_id": "openbao-transit",
        "signing_key_reference": "badge-key",
        "verification_method_id": "did:web:issuer.example#badge-key",
        "service": {"algorithm": "ES256"},
    }

    async def resolve_context(tx, **_kwargs):
        tx.issuer_profile_id = remote_context["issuer_profile_id"]
        tx.issuer_did_override = remote_context["issuer_did"]
        tx.signing_service_id = remote_context["signing_service_id"]
        return remote_context

    guard_arrivals = 0
    both_at_guard = asyncio.Event()

    async def readiness_barrier(**_kwargs):
        nonlocal guard_arrivals
        guard_arrivals += 1
        if guard_arrivals == 2:
            both_at_guard.set()
        await asyncio.wait_for(both_at_guard.wait(), timeout=2)

    counts = {"builder": 0, "kms": 0}

    async def did_sign(**kwargs):
        assert kwargs["issuer_did"] == remote_context["issuer_did"]
        assert kwargs["credential_format"] == "dc+sd-jwt"
        assert kwargs["key_purpose"] == "vc_jwt_issuer"
        assert "issuer_profile_id" not in kwargs
        counts["kms"] += 1
        await asyncio.sleep(0)
        return {"signature": "remote-signature", "algorithm": "ES256"}

    async def build_credential(*, remote_sign, credential_id, **_kwargs):
        counts["builder"] += 1
        await remote_sign(b"signing-input", "ES256")
        return "header.payload.signature~", credential_id

    async def allocate_status(**_kwargs):
        return "status-profile", []

    async def no_op(**_kwargs):
        return None

    async def no_op_positional(*_args, **_kwargs):
        return None

    monkeypatch.setattr(routes, "apply_remote_issuer_context", resolve_context)
    monkeypatch.setattr(repo, "consume_proof_nonce", _accept_test_nonce)
    monkeypatch.setattr(routes, "require_canvas_issuance_ready", readiness_barrier)
    monkeypatch.setattr(
        routes,
        "verify_proof_jwt",
        lambda *_args, **_kwargs: (True, "did:key:learner", {}, None),
    )
    monkeypatch.setattr(routes, "sign_payload_with_issuer_did", did_sign)
    monkeypatch.setattr(routes, "create_sd_jwt_vc_with_remote_signing", build_credential)
    monkeypatch.setattr(routes, "_allocate_credential_status_list_entries", allocate_status)
    monkeypatch.setattr(routes, "record_canvas_credential_claim", no_op)
    monkeypatch.setattr(routes, "_finalize_credential_renewal", no_op_positional)
    monkeypatch.setattr(routes, "record_post_issuance_deliveries", no_op_positional)

    credential_request = routes.CredentialRequest(
        credential_configuration_id="OpenBadgeCredential#sd-jwt",
        proofs={"jwt": [_proof_jwt()]},
    )
    results = await asyncio.gather(
        routes.issue_credential(
            _request(), credential_request, authorization="Bearer wallet-token", repo=repo
        ),
        routes.issue_credential(
            _request(), credential_request, authorization="Bearer wallet-token", repo=repo
        ),
    )

    expected_transaction_id = routes._authorization_session_transaction_id(authorization_session.id)
    assert expected_transaction_id == auth_code_contract["transaction_id"]
    transactions = await repo.list_transactions("org-1")
    assert [transaction.id for transaction in transactions] == [expected_transaction_id]
    assert transactions[0].status == IssuanceStatus.ISSUED
    assert counts == {"builder": 1, "kms": 1}
    assert sum(isinstance(result, routes.CredentialResponse) for result in results) == 1
    conflicts = [result for result in results if isinstance(result, JSONResponse)]
    assert len(conflicts) == 1
    concurrent_loser = SIGNING_CONTRACT["state_machine"]["concurrent_loser"]
    assert conflicts[0].status_code == concurrent_loser["status_code"]
    assert json.loads(conflicts[0].body) == concurrent_loser["body"]
    assert len(await repo.list_credentials_by_org("org-1")) == 1
