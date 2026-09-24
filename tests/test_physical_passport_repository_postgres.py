"""Owned PostgreSQL reference for retained physical-passport persistence.

The configured server must be loopback. This test creates and drops only its
freshly generated database; it never accepts a deployment database as a target.
Provider transport, webhook signature policy, and tenant authorization remain
separate gates before a Rust port or Python deletion.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
import yaml
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from fastapi import HTTPException
from issuance.infrastructure.adapters import personalization_bureau_client as bureau
from issuance.infrastructure.api import physical_document_routes as routes
from issuance.infrastructure.models import physical_document_jobs_table
from sqlalchemy import create_engine, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def test_passport_repository_oracle_is_mandatory_in_postgres_ci() -> None:
    workflow = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = workflow["jobs"]["oid4vci-capability-postgres"]["steps"]
    matching = [
        step
        for step in steps
        if step.get("name") == "Freeze physical-passport persistence over owned PostgreSQL"
    ]
    assert len(matching) == 1
    assert matching[0]["run"] == "pytest tests/test_physical_passport_repository_postgres.py -v"
    assert matching[0]["env"]["PASSPORT_REPOSITORY_TEST_DATABASE_URL"].startswith(
        "postgresql+asyncpg://marty:marty_test@localhost:5432/"
    )
    assert "if" not in matching[0]
    assert not matching[0].get("continue-on-error", False)


def test_real_postgres_passport_artifact_and_lifecycle_survive_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = os.environ.get("PASSPORT_REPOSITORY_TEST_DATABASE_URL")
    if not configured:
        pytest.skip("PASSPORT_REPOSITORY_TEST_DATABASE_URL is not configured")
    base = make_url(configured)
    assert base.drivername == "postgresql+asyncpg"
    assert base.host in {"localhost", "127.0.0.1", "::1"}, "test server must be loopback"

    database = "passport_reference_" + uuid4().hex
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
        command.upgrade(config, "head")

        key = Fernet.generate_key()
        monkeypatch.setenv("PHYSICAL_DOCUMENT_ARTIFACT_KEY", key.decode("ascii"))
        asyncio.run(
            asyncio.wait_for(_exercise(base.set(database=database), key, monkeypatch), timeout=90)
        )
    finally:
        routes.configure_physical_document_store(None)
        try:
            if created:
                with admin.connect() as connection:
                    connection.exec_driver_sql(f'DROP DATABASE "{database}"')
        finally:
            admin.dispose()


async def _exercise(database_url, key: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_async_engine(database_url, hide_parameters=True)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        routes.configure_physical_document_store(factory)
        payload = routes.PassportApplicationRequest(
            organization_id="org-passport-reference",
            flow_execution_id="flow-reference",
            application_template_id="application-template-reference",
            credential_template_id="credential-template-reference",
            delivery_destination_profile_id="bureau-reference",
            country_code="USA",
            applicant={"name": "Synthetic Applicant"},
            mrz={"line_1": "SYNTHETIC1", "line_2": "SYNTHETIC2"},
            data_groups={"DG1": "ZzE=", "DG2": "ZzI="},
        )
        created = await routes.create_passport_application(payload)
        application_id = created["application_id"]
        assert created["status"] == "DRAFT"
        assert "secure_artifact_ciphertext" not in created
    finally:
        routes.configure_physical_document_store(None)
        await engine.dispose()

    # A fresh engine/session proves this is durable database state, not a mock
    # or a process-local response object.
    engine = create_async_engine(database_url, hide_parameters=True)
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        routes.configure_physical_document_store(factory)
        async with factory() as session:
            row = (
                (
                    await session.execute(
                        select(physical_document_jobs_table).where(
                            physical_document_jobs_table.c.application_id == application_id
                        )
                    )
                )
                .mappings()
                .one()
            )
        assert row["organization_id"] == "org-passport-reference"
        assert row["revocation_profile_id"] is None
        assert row["status"] == "DRAFT"
        assert row["secure_artifact_reference"] == f"physical-artifact://{row['id']}"
        assert "Synthetic Applicant" not in row["secure_artifact_ciphertext"]
        assert routes._decrypt_artifact(dict(row)) == {
            "applicant": payload.applicant,
            "mrz": payload.mrz,
            "data_groups": payload.data_groups,
        }

        grouped = await routes.generate_passport_data_groups(application_id)
        assert grouped["status"] == "DATA_GENERATED"

        async def sign(**values):
            assert values == {
                "country_code": "USA",
                "organization": "org-passport-reference",
                "data_groups": {1: "ZzE=", 2: "ZzI="},
            }
            return {"sod_der_base64": "U09E", "dsc_cert_pem": "synthetic-cert"}

        monkeypatch.setattr(routes, "sign_emrtd", sign)
        signed = await routes.generate_passport_sod(application_id)
        assert signed["status"] == "SOD_SIGNED"
        assert signed["sod_sha256"] == hashlib.sha256(b"SOD").hexdigest()

        await routes._update_job(
            application_id, status="SUBMITTED", bureau_job_id="bureau-reference"
        )
        webhook = {
            "bureau_job_id": "bureau-reference",
            "status": "SHIPPED",
            "tracking_number": "TRACK-42",
        }
        body = json.dumps(webhook, separators=(",", ":")).encode()
        monkeypatch.setattr(bureau, "BUREAU_WEBHOOK_SECRET", "synthetic-webhook-secret")

        class WebhookRequest:
            async def body(self) -> bytes:
                return body

        with pytest.raises(HTTPException) as rejected:
            await routes.personalization_webhook(WebhookRequest(), "invalid-signature")
        assert rejected.value.status_code == 401
        assert (await routes._get_job(application_id))["status"] == "SUBMITTED"
        signature = hmac.new(
            b"synthetic-webhook-secret", body, hashlib.sha256
        ).hexdigest()
        assert await routes.personalization_webhook(WebhookRequest(), signature) == {
            "accepted": True
        }
        after_webhook = await routes._get_job(application_id)
        assert after_webhook["status"] == "READY_FOR_ACTIVATION"
        assert after_webhook["tracking_number"] == "TRACK-42"

        quality = await routes.record_passport_quality_result(
            application_id,
            routes.QualityResultRequest(passed=True),
            x_user_id="synthetic-reviewer",
        )
        assert quality["status"] == "READY_FOR_ACTIVATION"
        activated = await routes.activate_passport(application_id)
        assert activated["status"] == "ACTIVE"
        assert "secure_artifact_ciphertext" not in activated

        async with factory() as session:
            final = (
                (
                    await session.execute(
                        select(physical_document_jobs_table).where(
                            physical_document_jobs_table.c.application_id == application_id
                        )
                    )
                )
                .mappings()
                .one()
            )
        assert final["organization_id"] == "org-passport-reference"
        assert final["status"] == "ACTIVE"
        assert final["tracking_number"] == "TRACK-42"
        assert final["quality_result"]["checked_by"] == "synthetic-reviewer"
        assert final["completed_at"] is not None
        assert final["sod_sha256"] == hashlib.sha256(b"SOD").hexdigest()
        assert Fernet(key).decrypt(final["secure_artifact_ciphertext"].encode("ascii")) == b"{}"
    finally:
        routes.configure_physical_document_store(None)
        await engine.dispose()
