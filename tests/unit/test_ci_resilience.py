from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
WARM_CACHES = (ROOT / ".github" / "workflows" / "warm-ci-caches.yml").read_text(encoding="utf-8")
STABLE = (ROOT / ".github" / "workflows" / "release-stable.yml").read_text(encoding="utf-8")
OPTIONAL_SCCACHE = (ROOT / ".github" / "actions" / "optional-sccache" / "action.yml").read_text(
    encoding="utf-8"
)
PYTHON_CI = (ROOT / "scripts" / "run-python-ci.sh").read_text(encoding="utf-8")
RETRY = ROOT / "scripts" / "retry-command.sh"


def _bash_path(path: Path) -> str:
    resolved = path.resolve()
    if os.name != "nt":
        return resolved.as_posix()
    drive = resolved.drive.rstrip(":").lower()
    relative = resolved.as_posix().split(":", 1)[1].lstrip("/")
    return f"/mnt/{drive}/{relative}"


@pytest.mark.skipif(os.name == "nt", reason="executable Bash contract runs on CI Linux")
def test_retry_command_retries_then_preserves_success(tmp_path: Path) -> None:
    counter = tmp_path / "attempts"
    command = tmp_path / "transient.sh"
    command.write_bytes(
        b"#!/usr/bin/env bash\n"
        b"count=0\n"
        b'[ ! -f "$1" ] || count=$(cat "$1")\n'
        b"count=$((count + 1))\n"
        b'printf \'%s\' "$count" > "$1"\n'
        b'[ "$count" -ge 3 ]\n'
    )

    env = os.environ.copy()
    env.update(MARTY_CI_RETRY_ATTEMPTS="3", MARTY_CI_RETRY_DELAY_SECONDS="0")
    completed = subprocess.run(
        ["bash", _bash_path(RETRY), "bash", _bash_path(command), _bash_path(counter)],
        cwd=ROOT,
        env=env,
        check=False,
    )

    assert completed.returncode == 0
    assert counter.read_text(encoding="utf-8") == "3"


@pytest.mark.skipif(os.name == "nt", reason="executable Bash contract runs on CI Linux")
def test_retry_command_exhaustion_preserves_failure(tmp_path: Path) -> None:
    counter = tmp_path / "attempts"
    command = tmp_path / "failure.sh"
    command.write_bytes(
        b"#!/usr/bin/env bash\n"
        b"count=0\n"
        b'[ ! -f "$1" ] || count=$(cat "$1")\n'
        b'printf \'%s\' "$((count + 1))" > "$1"\n'
        b"exit 23\n"
    )

    env = os.environ.copy()
    env.update(MARTY_CI_RETRY_ATTEMPTS="3", MARTY_CI_RETRY_DELAY_SECONDS="0")
    completed = subprocess.run(
        ["bash", _bash_path(RETRY), "bash", _bash_path(command), _bash_path(counter)],
        cwd=ROOT,
        env=env,
        check=False,
    )

    assert completed.returncode == 23
    assert counter.read_text(encoding="utf-8") == "3"


def test_compiler_cache_falls_back_without_suppressing_rust_gates() -> None:
    assert "continue-on-error: true" in OPTIONAL_SCCACHE
    assert "if: always()" in OPTIONAL_SCCACHE
    assert 'echo "RUSTC_WRAPPER=" >> "$GITHUB_ENV"' in OPTIONAL_SCCACHE
    assert 'echo "SCCACHE_GHA_ENABLED=false" >> "$GITHUB_ENV"' in OPTIONAL_SCCACHE
    assert "uses: ./marty-credentials/.github/actions/optional-sccache" in CI
    assert "mozilla-actions/sccache-action@" not in CI
    assert "uses: ./marty-credentials/.github/actions/optional-sccache" in WARM_CACHES
    assert "uses: ./.github/actions/optional-sccache" in WARM_CACHES
    assert "continue-on-error:" not in CI
    assert "sccache: 'true'" not in STABLE
    assert "sccache: 'false'" in STABLE
    for command in (
        "cargo fmt --all -- --check",
        "cargo check --locked --no-default-features --features native",
        "cargo nextest run --locked --no-default-features --features native",
        "cargo test --locked --doc --no-default-features --features native",
        "cargo clippy --locked --no-default-features --features native -- -D warnings",
    ):
        assert command in CI


def test_optional_cache_action_contains_main_and_post_failure() -> None:
    install = OPTIONAL_SCCACHE.split("    - name: Install compiler cache", 1)[1].split(
        "\n    - name: Select cached or direct compiler", 1
    )[0]
    fallback = OPTIONAL_SCCACHE.split("    - name: Select cached or direct compiler", 1)[1]

    assert "main phase and its deferred post phase" in install
    assert "continue-on-error: true" in install
    assert "mozilla-actions/sccache-action@" in install
    assert "if: always()" in fallback
    assert 'steps.install.outcome }}" = success' in fallback
    assert "command -v sccache" in fallback
    assert 'echo "RUSTC_WRAPPER=" >> "$GITHUB_ENV"' in fallback


def test_local_optional_cache_action_is_checked_out_before_every_use() -> None:
    ci_jobs = {
        "preflight": CI.split("  preflight:", 1)[1].split("\n  test-rust:", 1)[0],
        "test-rust": CI.split("  test-rust:", 1)[1].split("\n  test-local-python-binding:", 1)[0],
        "test-local-python-binding": CI.split("  test-local-python-binding:", 1)[1].split(
            "\n  security:", 1
        )[0],
        "build-core-python-wheels": CI.split("  build-core-python-wheels:", 1)[1].split(
            "\n  test-python:", 1
        )[0],
    }
    for name, job in ci_jobs.items():
        assert job.index("actions/checkout@") < job.index(
            "uses: ./marty-credentials/.github/actions/optional-sccache"
        ), name

    warm_core = WARM_CACHES.split("  core-python-wheels:", 1)[1].split("\n  rust:", 1)[0]
    warm_rust = WARM_CACHES.split("  rust:", 1)[1].split("\n  python:", 1)[0]
    assert warm_core.index("actions/checkout@") < warm_core.index(
        "uses: ./marty-credentials/.github/actions/optional-sccache"
    )
    assert warm_rust.index("actions/checkout@") < warm_rust.index(
        "uses: ./.github/actions/optional-sccache"
    )


def test_published_python_dependency_resolution_uses_bounded_retry() -> None:
    retry = "scripts/retry-command.sh"
    assert retry in PYTHON_CI
    assert f"{retry} python -m pip install --disable-pip-version-check -e '.[dev]'" in PYTHON_CI
    assert f"{retry} pip-audit . --format json --output pip-audit.json" in CI
    assert f"{retry} python -m pip install --disable-pip-version-check local-wheels/*.whl" in CI
    assert f'{retry} pip install -e .[dev] "psycopg[binary]==3.2.3"' in CI
    assert "python -m pytest tests/ packages/tests/ -v" in PYTHON_CI
    assert "pytest rust/marty-rs/tests/python" in CI
    assert "pytest tests/test_oid4vci_ephemeral_capabilities_postgres.py -v" in CI
