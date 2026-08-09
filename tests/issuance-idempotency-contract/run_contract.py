from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config

DATABASE_URL = os.environ["DATABASE_URL"]
RESULT_PATH = Path(os.environ["CONTRACT_RESULT_PATH"])
SOURCE_REVISION = os.environ.get("CONTRACT_SOURCE_REVISION", "local-worktree")
RAW_KEY = "c" * 64
KEY_HASH = hashlib.sha256(
    f"marty:issuance-idempotency-key:v1:{RAW_KEY}".encode()
).hexdigest()
REQUEST_HASH = "b" * 64


def _upgrade() -> None:
    config = Config("/contract/migrations/alembic.ini")
    config.set_main_option("script_location", "/contract/migrations")
    config.set_main_option(
        "sqlalchemy.url",
        DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1),
    )
    command.upgrade(config, "head")


def _reserve(barrier: threading.Barrier) -> tuple[str, str, bool]:
    transaction_id = str(uuid.uuid4())
    pre_auth_code = f"pre-{uuid.uuid4()}"
    now = datetime.now(UTC)
    barrier.wait(timeout=10)
    with psycopg.connect(DATABASE_URL) as connection:
        created = connection.execute(
            """
            INSERT INTO issuance_service.issuance_transactions (
                id, organization_id, credential_template_id, status,
                pre_auth_code, claims, credential_payload_format,
                wallet_configs, validity_days, renewable, renewal_window_days,
                created_at, expires_at, idempotency_key_hash,
                idempotency_request_hash
            ) VALUES (
                %s, 'org-race', 'template-race', 'pending', %s,
                '{}'::json, 'w3c_vcdm_v2_sd_jwt', '[]'::json,
                365, false, 30, %s, %s, %s, %s
            )
            ON CONFLICT (organization_id, idempotency_key_hash) DO NOTHING
            RETURNING id, pre_auth_code
            """,
            (
                transaction_id,
                pre_auth_code,
                now,
                now + timedelta(days=7),
                KEY_HASH,
                REQUEST_HASH,
            ),
        ).fetchone()
        if created is not None:
            connection.commit()
            return str(created[0]), str(created[1]), True
        existing = connection.execute(
            """
            SELECT id, pre_auth_code, idempotency_request_hash
            FROM issuance_service.issuance_transactions
            WHERE organization_id = 'org-race' AND idempotency_key_hash = %s
            """,
            (KEY_HASH,),
        ).fetchone()
        assert existing is not None and existing[2] == REQUEST_HASH
        connection.commit()
        return str(existing[0]), str(existing[1]), False


def main() -> None:
    _upgrade()
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(_reserve, barrier)
        second = executor.submit(_reserve, barrier)
        results = [first.result(timeout=20), second.result(timeout=20)]

    assert sorted(created for _, _, created in results) == [False, True]
    assert len({transaction_id for transaction_id, _, _ in results}) == 1
    assert len({pre_auth_code for _, pre_auth_code, _ in results}) == 1

    with psycopg.connect(DATABASE_URL) as connection:
        count, stored_key_hash, stored_request_hash = connection.execute(
            """
            SELECT count(*), min(idempotency_key_hash), min(idempotency_request_hash)
            FROM issuance_service.issuance_transactions
            WHERE organization_id = 'org-race'
            """
        ).fetchone()
        assert count == 1
        assert stored_key_hash == KEY_HASH
        assert stored_request_hash == REQUEST_HASH
        raw_key_persisted = connection.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM issuance_service.issuance_transactions
                WHERE idempotency_key_hash = %s
                   OR idempotency_request_hash = %s
            )
            """,
            (RAW_KEY, RAW_KEY),
        ).fetchone()[0]
        assert raw_key_persisted is False
        version = connection.execute(
            "SELECT version_num FROM issuance_service.alembic_version"
        ).fetchone()[0]
        assert version == "issuance_offer_idempotency"

    created_count = sum(created for _, _, created in results)
    recovered_count = len(results) - created_count
    same_transaction = len({transaction_id for transaction_id, _, _ in results}) == 1
    same_pre_authorized_code = len({code for _, code, _ in results}) == 1

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(
        json.dumps(
            {
                "status": "passed",
                "source_revision": SOURCE_REVISION,
                "migration_revision": "issuance_offer_idempotency",
                "created_count": created_count,
                "recovered_count": recovered_count,
                "same_transaction": same_transaction,
                "same_pre_authorized_code": same_pre_authorized_code,
                "raw_key_persisted": raw_key_persisted,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
