#!/usr/bin/env bash
set -euo pipefail

python -m pip install --disable-pip-version-check --upgrade pip
python -m pip install --disable-pip-version-check pytest pytest-asyncio
python -c "import pathlib, subprocess, sys; wheels = sorted(map(str, pathlib.Path('release-deps').glob('*.whl'))); assert len(wheels) == 2, wheels; subprocess.run([sys.executable, '-m', 'pip', 'install', *wheels], check=True)"
scripts/retry-command.sh python -m pip install --disable-pip-version-check -e '.[dev]'
# The issuance API, worker and Alembic owner are Rust-owned in marty-ui.
# The two legacy adapter modules exercise Credentials' separately built local
# compatibility extension. The production job intentionally installs canonical
# Core marty-rs v0.2 instead; the local-binding job owns these tests.
python -m pytest tests/ packages/tests/ -v \
  --ignore=tests/unit/test_legacy_service_native_boundary.py \
  --ignore=tests/unit/test_verification_adapter_native_boundary.py
