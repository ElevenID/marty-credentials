from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.canvas-migration-contract.yml"
CONTRACT_ROOT = ROOT / "tests" / "canvas-migration-contract"
RUNNER = CONTRACT_ROOT / "run_contract.py"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_canvas_migration_contract_is_an_isolated_compose_one_shot() -> None:
    compose = _text(COMPOSE)

    assert re.search(r"postgres:15\.18-alpine@sha256:[0-9a-f]{64}", compose)
    assert "dockerfile: tests/canvas-migration-contract/Dockerfile" in compose
    assert "condition: service_healthy" in compose
    assert (
        "CONTRACT_SOURCE_REVISION: ${CANVAS_MIGRATION_SOURCE_REVISION:-local-worktree}" in compose
    )
    assert "internal: true" in compose
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "/var/lib/postgresql/data:rw,noexec,nosuid" in compose
    assert 'restart: "no"' in compose
    assert "ports:" not in compose
    assert "network_mode: host" not in compose
    assert "external: true" not in compose
    assert "container_name:" not in compose


def test_contract_image_is_source_bound_and_has_an_exact_dependency_graph() -> None:
    dockerfile = _text(CONTRACT_ROOT / "Dockerfile")
    requirements = _text(CONTRACT_ROOT / "requirements.txt")

    assert re.search(
        r"^FROM python:3\.12-slim-bookworm@sha256:[0-9a-f]{64}$", dockerfile, re.MULTILINE
    )
    assert 'org.opencontainers.image.revision="${CONTRACT_SOURCE_REVISION}"' in dockerfile
    assert 'io.elevenid.canvas-migration.execution-boundary="docker-compose-one-shot"' in dockerfile
    assert "pip install --no-deps --only-binary=:all: --require-hashes" in dockerfile
    assert "COPY services/issuance/infrastructure/migrations/ /contract/migrations/" in dockerfile
    pins = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_.-]*==[0-9][A-Za-z0-9.]*)", requirements)
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", requirements)
    assert len(pins) == 8
    assert len(hashes) >= len(pins)
    assert len(hashes) == len(set(hashes))


def test_contract_executes_real_upgrade_assertions_and_downgrade_restore() -> None:
    runner = _text(RUNNER)
    ast.parse(runner)

    assert 'BASELINE_REVISION = "derive_server_owned_claims"' in runner
    assert 'PORTABLE_REVISION = "portable_canvas_connections"' in runner
    assert "command.upgrade(config, BASELINE_REVISION)" in runner
    assert "command.upgrade(config, PORTABLE_REVISION)" in runner
    assert "command.downgrade(config, BASELINE_REVISION)" in runner
    assert "with connection.cursor() as cursor:" in runner
    assert "cursor.executemany(" in runner
    assert "connection.executemany(" not in runner
    assert "LEGACY_REQUIREMENTS_LIST" in runner
    assert "LEGACY_REQUIREMENTS_OBJECT" in runner
    assert "canvas_program_binding_requirement_backups" in runner
    assert "canvas_platform_state_backups" in runner
    assert "fk_canvas_program_bindings_tenant_platform" in runner
    assert "cross-tenant binding unexpectedly succeeded" in runner
    assert 'write_result("passed"' in runner
    assert '"source_revision": SOURCE_REVISION' in runner
    assert "sqlite" not in runner.lower()


def test_credentials_ci_requires_and_publishes_the_compose_contract() -> None:
    workflow = _text(ROOT / ".github" / "workflows" / "ci.yml")
    job = workflow.split("  canvas-portable-migration:", 1)[1].split("\n  test-python:", 1)[0]

    assert "Canvas PostgreSQL Migration Contract" in job
    assert (
        "docker compose --file docker-compose.canvas-migration-contract.yml config --quiet" in job
    )
    assert "build --pull migration-contract" in job
    assert "up --force-recreate --abort-on-container-exit" in job
    assert "--exit-code-from migration-contract migration-contract" in job
    assert "contract-result.json" in job
    assert "actions/upload-artifact@" in job
    assert "down --volumes --remove-orphans" in job
    assert "if: always()" in job
    assert "continue-on-error" not in job

    uses = [
        line.split("uses:", 1)[1].strip().split(" #", 1)[0]
        for line in job.splitlines()
        if "uses:" in line
    ]
    assert uses
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) for action in uses)
