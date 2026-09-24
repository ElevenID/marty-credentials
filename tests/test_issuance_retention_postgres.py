"""Owned PostgreSQL oracle for the destructive Hosted Pilot retention path.

The configured server must be loopback. Only a freshly generated database is
created and dropped; this test never accepts a deployment database as a target.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
import yaml
from alembic import command
from alembic.config import Config
from issuance.infrastructure.adapters.postgres_repository import PostgresIssuanceRepository
from issuance.infrastructure.models import (
    application_templates_table,
    applications_table,
    authorization_sessions_table,
    credential_delivery_records_table,
    evidence_facts_table,
    issuance_events_table,
    issuance_transactions_table,
    issued_credentials_table,
)
from sqlalchemy import create_engine, insert, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def test_retention_postgres_oracle_is_mandatory_in_ci() -> None:
    workflow = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = workflow["jobs"]["oid4vci-capability-postgres"]["steps"]
    matching = [step for step in steps if step.get("name") == "Freeze retention purge over owned PostgreSQL"]
    assert len(matching) == 1
    assert matching[0]["run"] == "pytest tests/test_issuance_retention_postgres.py -v"
    assert matching[0]["env"]["RETENTION_TEST_DATABASE_URL"].startswith(
        "postgresql+asyncpg://marty:marty_test@localhost:5432/"
    )
    assert "if" not in matching[0]
    assert not matching[0].get("continue-on-error", False)


def test_retention_purge_is_tenant_scoped_in_owned_postgres() -> None:
    configured = os.environ.get("RETENTION_TEST_DATABASE_URL")
    if not configured:
        pytest.skip("RETENTION_TEST_DATABASE_URL is not configured")
    base = make_url(configured)
    assert base.drivername == "postgresql+asyncpg"
    assert base.host in {"localhost", "127.0.0.1", "::1"}, "test server must be loopback"

    database = "retention_reference_" + uuid4().hex
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

        migrations = Path(__file__).resolve().parents[1] / "services/issuance/infrastructure/migrations"
        config = Config(str(migrations / "alembic.ini"))
        config.set_main_option("script_location", str(migrations))
        config.set_main_option(
            "sqlalchemy.url", sync_url.render_as_string(hide_password=False).replace("%", "%%")
        )
        command.upgrade(config, "head")
        asyncio.run(asyncio.wait_for(_exercise(base.set(database=database)), timeout=90))
    finally:
        try:
            if created:
                with admin.connect() as connection:
                    connection.exec_driver_sql(f'DROP DATABASE "{database}"')
        finally:
            admin.dispose()


async def _exercise(database_url) -> None:
    engine = create_async_engine(database_url, hide_parameters=True)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        repository = PostgresIssuanceRepository(factory)
        now = datetime.now(UTC)
        old, recent = now - timedelta(days=40), now - timedelta(days=5)
        async with factory() as session, session.begin():
                for org in ("a", "b"):
                    await session.execute(
                        insert(application_templates_table).values(
                            id=f"template-{org}", organization_id=f"organization-{org}", name="Synthetic"
                        )
                    )
                    await session.execute(
                        insert(applications_table).values(
                            id=f"app-{org}", organization_id=f"organization-{org}",
                            application_template_id=f"template-{org}", applicant_identifier="synthetic",
                            created_at=old, expires_at=now + timedelta(days=90),
                        )
                    )
                    await session.execute(
                        insert(issuance_transactions_table).values(
                            id=f"tx-{org}", organization_id=f"organization-{org}",
                            credential_template_id="synthetic", pre_auth_code=f"preauth-{org}",
                            created_at=old, expires_at=now + timedelta(days=90),
                        )
                    )
                    await session.execute(
                        insert(issued_credentials_table).values(
                            id=f"credential-{org}", transaction_id=f"tx-{org}",
                            organization_id=f"organization-{org}", credential_template_id="synthetic",
                            credential_jwt="synthetic", credential_hash=f"hash-{org}",
                        )
                    )
                    await session.execute(
                        insert(credential_delivery_records_table).values(
                            id=f"delivery-{org}", credential_id=f"credential-{org}",
                            transaction_id=f"tx-{org}", organization_id=f"organization-{org}",
                            delivery_target="wallet",
                        )
                    )
                    await session.execute(
                        insert(evidence_facts_table).values(
                            id=f"fact-{org}", organization_id=f"organization-{org}",
                            application_id=f"app-{org}", subject_id="synthetic", provider="synthetic",
                            fact_type="synthetic", logical_key=f"key-{org}", source_revision="1",
                            payload_hash=f"payload-{org}",
                        )
                    )
                    await session.execute(
                        insert(authorization_sessions_table).values(
                            id=f"auth-{org}", code=f"code-{org}", client_id="synthetic",
                            organization_id=f"organization-{org}", created_at=old,
                            expires_at=now + timedelta(days=90),
                        )
                    )
                    await session.execute(
                        insert(issuance_events_table).values(
                            id=f"event-{org}", transaction_id=f"tx-{org}",
                            event_type="synthetic", created_at=old,
                        )
                    )
                await session.execute(
                    insert(issuance_transactions_table).values(
                        id="tx-new-a", organization_id="organization-a",
                        credential_template_id="synthetic", pre_auth_code="preauth-new-a",
                        created_at=recent, expires_at=now + timedelta(days=90),
                    )
                )

        before = await repository.get_retention_summary("organization-a", 30)
        assert before["eligible_for_purge"] == {
            "issuance_transactions": 1, "applications": 1, "authorization_sessions": 1,
            "issuance_events": 1, "issued_credentials": 1, "total": 5,
        }
        assert before["oldest_retained_record_at"] == recent.isoformat()
        purged = await repository.purge_retention_records("organization-a", 30)
        assert purged["purged_records"] == before["eligible_for_purge"]
        again = await repository.purge_retention_records("organization-a", 30)
        assert again["purged_records"]["total"] == 0

        async with factory() as session:
            for table, expected in (
                (issuance_transactions_table, {"tx-new-a", "tx-b"}),
                (applications_table, {"app-b"}),
                (authorization_sessions_table, {"auth-b"}),
                (issuance_events_table, {"event-b"}),
                (issued_credentials_table, {"credential-b"}),
                (credential_delivery_records_table, {"delivery-b"}),
                (evidence_facts_table, {"fact-b"}),
            ):
                assert set((await session.execute(select(table.c.id))).scalars()) == expected
    finally:
        await engine.dispose()
