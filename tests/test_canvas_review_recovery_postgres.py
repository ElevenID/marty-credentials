"""Real migrations, service recovery and repository fences on an owned test DB.

No deployment URL is accepted: the configured test server must be loopback.
The sole database created/dropped here has a fresh, internally generated name.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from issuance.application.canvas_sync_service import (
    _finalize_pending_evidence_recovery,
    resolve_evidence_policy_review,
)
from issuance.domain.entities import (
    EventType,
    EvidencePolicyReview,
    EvidencePolicyReviewStatus,
    IssuanceEvent,
)
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

OLD_HEAD = "merge_issuance_heads"
NEW_HEAD = "canvas_review_recovery_claim"
CONSTRAINT = "ck_evidence_policy_reviews_resolution_claim"


def test_real_postgres_review_recovery_migration_and_fences() -> None:
    configured = os.environ.get("CANVAS_REVIEW_RECOVERY_TEST_DATABASE_URL")
    if not configured:
        pytest.skip("CANVAS_REVIEW_RECOVERY_TEST_DATABASE_URL is not configured")
    base = make_url(configured)
    assert base.drivername == "postgresql+asyncpg"
    assert base.host in {"localhost", "127.0.0.1", "::1"}, "test server must be loopback"
    database = "canvas_review_test_" + uuid4().hex
    admin = create_engine(base.set(drivername="postgresql+psycopg"), isolation_level="AUTOCOMMIT")
    created = False
    try:
        with admin.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database}"')
        created = True
        sync_url = base.set(drivername="postgresql+psycopg", database=database)
        sync_engine = create_engine(sync_url, hide_parameters=True)
        try:
            with sync_engine.begin() as connection:
                connection.exec_driver_sql("CREATE SCHEMA issuance_service")
                connection.exec_driver_sql("CREATE SCHEMA organization_service")
                connection.exec_driver_sql(
                    "CREATE TABLE organization_service.organizations (id VARCHAR PRIMARY KEY, name VARCHAR, slug VARCHAR)"
                )
        finally:
            sync_engine.dispose()
        migrations = (
            Path(__file__).resolve().parents[1] / "services/issuance/infrastructure/migrations"
        )
        config = Config(str(migrations / "alembic.ini"))
        config.set_main_option("script_location", str(migrations))
        config.set_main_option(
            "sqlalchemy.url", sync_url.render_as_string(hide_password=False).replace("%", "%%")
        )
        command.upgrade(config, OLD_HEAD)
        asyncio.run(asyncio.wait_for(_exercise(base.set(database=database), config), timeout=90))
    finally:
        try:
            if created:
                # No FORCE: a leaked session is a test failure, not hidden cleanup.
                with admin.connect() as connection:
                    connection.exec_driver_sql(f'DROP DATABASE "{database}"')
        finally:
            admin.dispose()


async def _exercise(url, config) -> None:
    engine = create_async_engine(url, hide_parameters=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    repo = PostgresIssuanceRepository(factory)
    competitor = PostgresIssuanceRepository(factory)
    try:
        async with engine.begin() as connection:
            for statement in (
                "INSERT INTO organization_service.organizations (id) VALUES ('org-review')",
                "INSERT INTO issuance_service.application_templates (id,organization_id,name,credential_template_id,form_fields,evidence_requirements,claim_collection_rules,approval_strategy,application_validity_days,ui_config,notification_config,status,created_at,updated_at) VALUES ('template-review','org-review','Synthetic','credential-template','[]','[]','[]','MANUAL',30,'{}','{}','ACTIVE',now(),now())",
                "INSERT INTO issuance_service.issuance_transactions (id,organization_id,credential_template_id,status,pre_auth_code,claims,created_at,expires_at) VALUES ('transaction-review','org-review','credential-template','issued','synthetic-unused-code','{}',now(),now()+interval '1 day')",
                "INSERT INTO issuance_service.issued_credentials (id,transaction_id,organization_id,credential_template_id,credential_jwt,credential_hash,status,status_updated_at,revoked,issued_at) VALUES ('credential-review','transaction-review','org-review','credential-template','synthetic-not-signed','synthetic-hash','active',now(),false,now())",
                "INSERT INTO issuance_service.applications (id,organization_id,application_template_id,applicant_identifier,form_data,submitted_evidence,status,derived_claims,integration_context,credential_id,created_at,updated_at) VALUES ('application-review','org-review','template-review','synthetic-subject','{}','[]','approved','{}','{}','credential-review',now(),now())",
            ):
                await connection.exec_driver_sql(statement)
        await repo.save_evidence_policy_review(
            EvidencePolicyReview(
                id="review",
                organization_id="org-review",
                application_id="application-review",
                credential_id="credential-review",
                resolution_recovery_pending=True,
            )
        )

        async def review():
            result = await repo.get_evidence_policy_review_for_org("org-review", "review")
            assert result is not None
            return result

        async def events():
            return await repo.list_events_for_application("application-review")

        async def credential_rows():
            async with engine.connect() as connection:
                return (
                    await connection.execute(
                        text(
                            "SELECT jsonb_build_object('credentials',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) "
                            "FROM issuance_service.issued_credentials c),'transactions',"
                            "(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.issuance_transactions t))"
                        )
                    )
                ).scalar_one()

        preserved_credentials = await credential_rows()

        async def claim(
            owner=repo, token="winner", action="evidence_recovered", organization="org-review"
        ):
            return await owner.claim_evidence_policy_review_resolution(
                organization,
                "review",
                claim_token=token,
                action=action,
            )

        async def failed_handler(*_args):
            active = await review()
            assert active.resolution_claim_action == "suspend"
            assert active.resolution_claim_token is not None
            assert not active.resolution_recovery_pending
            async with engine.begin() as connection:
                updated = await connection.execute(
                    text(
                        "UPDATE issuance_service.evidence_policy_reviews SET resolution_recovery_pending=true "
                        "WHERE id='review' AND organization_id='org-review' AND resolution_claim_token=:token"
                    ),
                    {"token": active.resolution_claim_token},
                )
                assert updated.rowcount == 1
            raise RuntimeError("synthetic lifecycle failure")

        async def fail_manual():
            async with engine.begin() as connection:
                await connection.exec_driver_sql(
                    "UPDATE issuance_service.evidence_policy_reviews SET resolution_recovery_pending=false "
                    "WHERE id='review' AND status='open' AND resolution_claim_token IS NULL"
                )
            with pytest.raises(RuntimeError, match="synthetic lifecycle failure"):
                await resolve_evidence_policy_review(
                    repo=repo,
                    organization_id="org-review",
                    review_id="review",
                    action="suspend",
                    notes=None,
                    resolved_by="synthetic-admin",
                    credential_handler=failed_handler,
                )

        # Historical negative control proves the original published schema defect.
        with pytest.raises(IntegrityError, match=CONSTRAINT):
            await claim()
        await fail_manual()
        before = await review()
        assert before.status == EvidencePolicyReviewStatus.OPEN
        assert before.resolution_recovery_pending and before.resolution_claim_token is None
        assert await events() == []
        command.upgrade(config, NEW_HEAD)
        assert await review() == before, "migration must not rewrite review data"

        # All manual actions remain valid; unknown actions still fail closed.
        for action in ("dismiss", "suspend", "revoke"):
            assert await claim(action=action) is not None
            assert await repo.release_evidence_policy_review_resolution(
                "org-review", "review", claim_token="winner"
            )
        with pytest.raises(IntegrityError, match=CONSTRAINT):
            await claim(action="unknown")
        assert await claim(organization="foreign") is None
        results = await asyncio.gather(claim(token="first"), claim(competitor, token="second"))
        winners = [result for result in results if result is not None]
        assert len(winners) == 1
        winning_token = winners[0].resolution_claim_token
        assert not await repo.release_evidence_policy_review_resolution(
            "org-review", "review", claim_token="stale"
        )

        async def finalize(
            *,
            token=winning_token,
            organization="org-review",
            action="evidence_recovered",
            event_id=None,
            event_app="application-review",
        ):
            event = IssuanceEvent(
                application_id=event_app, event_type=EventType.EVIDENCE_POLICY_REVIEW_RESOLVED
            )
            if event_id is not None:
                event.id = event_id
            return await repo.finalize_evidence_policy_review_resolution(
                organization,
                "review",
                claim_token=token,
                status=EvidencePolicyReviewStatus.RESOLVED,
                resolution_action=action,
                resolution_notes=None,
                resolved_by="synthetic-test",
                resolved_at=datetime.now(UTC),
                audit_event=event,
            )

        assert await finalize(token="stale") is None
        assert await finalize(organization="foreign") is None
        assert await finalize(action="suspend") is None
        with pytest.raises(ValueError, match="does not belong"):
            await finalize(event_app="foreign-application")
        assert (await review()).resolution_claim_token == winning_token
        assert await events() == []
        # Real database audit-insert failure rolls back the earlier review UPDATE.
        async with engine.begin() as connection:
            await connection.exec_driver_sql(
                "ALTER TABLE issuance_service.issuance_events ADD CONSTRAINT synthetic_audit_failure CHECK (id <> 'synthetic-fail')"
            )
        with pytest.raises(IntegrityError, match="synthetic_audit_failure"):
            await finalize(event_id="synthetic-fail")
        assert (await review()).resolution_claim_token == winning_token
        assert (await review()).resolution_recovery_pending
        assert await events() == []
        async with engine.begin() as connection:
            await connection.exec_driver_sql(
                "ALTER TABLE issuance_service.issuance_events DROP CONSTRAINT synthetic_audit_failure"
            )

        # Downgrade must refuse a live recovery claim without losing it or its fence.
        with pytest.raises(IntegrityError, match=CONSTRAINT):
            command.downgrade(config, OLD_HEAD)
        assert (await review()).resolution_claim_token == winning_token
        async with engine.connect() as connection:
            assert (
                await connection.execute(
                    text("SELECT version_num FROM issuance_service.alembic_version")
                )
            ).scalar_one() == NEW_HEAD
        assert await repo.release_evidence_policy_review_resolution(
            "org-review", "review", claim_token=winning_token
        )

        # Same real service path now recovers, while preserving its original handler error.
        await fail_manual()
        recovered = await review()
        assert recovered.status == EvidencePolicyReviewStatus.RESOLVED
        assert recovered.resolution_action == "evidence_recovered"
        assert recovered.resolved_by == "canvas-evidence-sync"
        assert (
            recovered.resolution_claim_token is None and not recovered.resolution_recovery_pending
        )
        audit = await events()
        assert len(audit) == 1
        assert audit[0].metadata["resolution_action"] == "evidence_recovered"
        assert audit[0].metadata["review_id"] == "review"
        await _finalize_pending_evidence_recovery(
            repo=repo, organization_id="org-review", review_id="review"
        )
        assert len(await events()) == 1
        assert await claim() is None
        # Once drained, downgrade and re-upgrade preserve resolved data and audit.
        command.downgrade(config, OLD_HEAD)
        assert await review() == recovered
        command.upgrade(config, NEW_HEAD)
        assert await review() == recovered
        assert len(await events()) == 1
        assert await credential_rows() == preserved_credentials
    finally:
        await engine.dispose()
