"""Replay the frozen oracle inside the isolated published issuance runtime.

The companion Docker runner owns a fresh network-none PostgreSQL namespace.
No configurable database URL, deployed data, replacement cycle, or fake SQL is
used. Only repository entry/outcome observation and exception-log suppression
wrap the real implementation. Never print SQL exceptions or their parameters.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from alembic import command
from alembic.config import Config
from issuance import canvas_worker
from issuance.infrastructure.adapters import postgres_repository
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads(
    (ROOT / "contracts/canvas-worker-consumer-range-oracle.json").read_text(encoding="utf-8")
)
DATABASE = "oracle:synthetic-local-only@127.0.0.1:5432/canvas_range_oracle"


class OracleMismatch(Exception):
    """Only allowlisted harness assertion messages may reach diagnostics."""


def require(condition, message):
    if not condition:
        raise OracleMismatch(message)


def source_hash(module):
    # Git checkouts may have CRLF; the published source is LF. Hash canonical
    # source text, not a platform's checkout newline transformation.
    return hashlib.sha256(Path(module.__file__).read_text(encoding="utf-8").encode()).hexdigest()


def error_identity(error):
    original = getattr(error, "orig", None)
    return {
        "class": type(error).__name__,
        "driver_class": type(original).__name__ if original is not None else None,
        "sqlstate": getattr(original, "sqlstate", None),
    }


class ObservedRepository(postgres_repository.PostgresIssuanceRepository):
    def __init__(self, sessions, stop=None, stop_after=None):
        super().__init__(sessions)
        self.events = []
        self.stop = stop
        self.stop_after = stop_after
        self.cycle_count = 0

    async def observe(self, phase, operation, **arguments):
        self.events.append({"phase": phase, "event": "start"})
        try:
            result = await operation(**arguments)
        except Exception as error:
            self.events.append({"phase": phase, "event": "error", **error_identity(error)})
            raise
        self.events.append({"phase": phase, "event": "complete", "row_count": len(result)})
        return result

    async def upsert_canvas_worker_heartbeat(self, heartbeat):
        phase = heartbeat.metadata["phase"]
        self.events.append({"phase": "heartbeat", "event": phase})
        if phase == "scheduling":
            self.cycle_count += 1
            if self.stop is not None and self.cycle_count == self.stop_after:
                self.stop.set()
        return await super().upsert_canvas_worker_heartbeat(heartbeat)

    async def list_canvas_oauth_revocation_retries(self, **arguments):
        return await self.observe(
            "oauth_queue", super().list_canvas_oauth_revocation_retries, **arguments
        )

    async def enqueue_due_canvas_sync_jobs(self, **arguments):
        return await self.observe("scheduling", super().enqueue_due_canvas_sync_jobs, **arguments)

    async def lease_canvas_sync_jobs(self, **arguments):
        return await self.observe("leasing", super().lease_canvas_sync_jobs, **arguments)


def configuration(case):
    value = FIXTURE["inputs"][case["input"]]
    environment = {
        "CANVAS_SYNC_WORKER_ID": f"oracle-{case['field']}-{case['input']}",
        FIXTURE["fields"][case["field"]]: value,
    }
    with patch.dict(os.environ, environment, clear=True):
        config = canvas_worker.CanvasSyncWorkerConfig.from_env()
    require(getattr(config, case["field"]) == int(value), "Startup changed configured integer")
    return config


def migrate_empty_database():
    engine = create_engine(f"postgresql+psycopg2://{DATABASE}", hide_parameters=True)
    try:
        with engine.begin() as connection:
            # Intentionally fail if the runner did not supply an empty database.
            # Never DROP/TRUNCATE or reuse a previously populated schema.
            connection.execute(text("CREATE SCHEMA issuance_service"))
            connection.execute(text("CREATE SCHEMA organization_service"))
            connection.execute(
                text(
                    "CREATE TABLE organization_service.organizations "
                    "(id VARCHAR PRIMARY KEY, name VARCHAR, slug VARCHAR)"
                )
            )
        config = Config()
        config.set_main_option(
            "script_location",
            str(Path(canvas_worker.__file__).parent / "infrastructure/migrations"),
        )
        config.set_main_option("sqlalchemy.url", f"postgresql+psycopg2://{DATABASE}")
        command.upgrade(config, "heads")
    finally:
        engine.dispose()


async def verify(source):
    worker_hash = source_hash(canvas_worker)
    repository_hash = source_hash(postgres_repository)
    if source == "published":
        require(worker_hash == FIXTURE["observed_source_sha256"], "Published worker hash changed")
        require(
            repository_hash == FIXTURE["observed_repository_sha256"],
            "Published repository hash changed",
        )
    else:
        require(
            Path(canvas_worker.__file__).resolve().is_relative_to(ROOT / "services"),
            "Checkout worker was not imported",
        )
        require(
            Path(postgres_repository.__file__).resolve().is_relative_to(ROOT / "services"),
            "Checkout repository was not imported",
        )
    migrate_empty_database()
    engine = create_async_engine(f"postgresql+asyncpg://{DATABASE}", hide_parameters=True)
    try:
        async with engine.begin() as connection:
            version = (await connection.execute(text("SHOW server_version"))).scalar_one()
            revisions = (
                (
                    await connection.execute(
                        text(
                            "SELECT version_num FROM issuance_service.alembic_version ORDER BY version_num"
                        )
                    )
                )
                .scalars()
                .all()
            )
        require(
            version.split(" ")[0] == FIXTURE["observed_postgres_version"],
            "PostgreSQL version changed",
        )
        require(revisions == FIXTURE["migration_revisions"], "Migration heads changed")
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        for case in FIXTURE["cases"]:
            config = configuration(case)
            repository = ObservedRepository(sessions)
            expected = FIXTURE["outcomes"][case["expected"]]
            cycle, error = "completed", None
            try:
                await canvas_worker.run_canvas_sync_worker_cycle(repo=repository, config=config)
            except Exception as caught:
                cycle, error = "error", error_identity(caught)
            name = f"{case['field']}/{case['input']}"
            require(cycle == expected["cycle"], f"Cycle result mismatch: {name}")
            require(error == expected.get("legacy_error"), f"Error identity mismatch: {name}")
            require(repository.events == expected["events"], f"Phase sequence mismatch: {name}")

        for case in FIXTURE["loop_cases"]:
            stop = asyncio.Event()
            repository = ObservedRepository(sessions, stop, case["cycles"])
            config = replace(configuration(case), poll_seconds=0.1)
            # Preserve the real loop and cycle, only suppress traceback/SQL text.
            with patch.object(logging.getLogger("issuance.canvas_worker"), "exception"):
                await asyncio.wait_for(
                    canvas_worker.run_canvas_sync_worker_loop(
                        repo=repository, config=config, stop_event=stop
                    ),
                    timeout=10,
                )
            expected_events = (
                FIXTURE["outcomes"][case["cycle_events_from"]]["events"] * case["cycles"]
            )
            require(repository.cycle_count == case["cycles"], "Loop cycle count changed")
            require(stop.is_set() == case["stopped_normally"], "Loop did not stop normally")
            require(repository.events == expected_events, f"Loop phase mismatch: {case['field']}")

        return {
            "status": "passed",
            "source": source,
            "worker_source_sha256": worker_hash,
            "repository_source_sha256": repository_hash,
            "fixture_sha256": hashlib.sha256(
                (ROOT / "contracts/canvas-worker-consumer-range-oracle.json").read_bytes()
            ).hexdigest(),
            "cycle_cases": len(FIXTURE["cases"]),
            "loop_cases": len(FIXTURE["loop_cases"]),
            "postgres_version": version,
            "migration_revisions": revisions,
            "scope": "disposable-empty-queues-only",
        }
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("published", "checkout"), required=True)
    arguments = parser.parse_args()
    try:
        result = asyncio.run(verify(arguments.source))
    except Exception as failure:
        # OracleMismatch messages originate only in the allowlisted assertions
        # above. Unexpected driver/provider errors must not expose SQL/data.
        message = str(failure) if isinstance(failure, OracleMismatch) else type(failure).__name__
        print(json.dumps({"status": "failed", "check": message}))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))
