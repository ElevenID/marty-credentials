#!/usr/bin/env bash
set -euo pipefail

python -m pip install --disable-pip-version-check --upgrade pip
python -m pip install --disable-pip-version-check pytest pytest-asyncio
python -c "import pathlib, subprocess, sys; wheels = sorted(map(str, pathlib.Path('release-deps').glob('*.whl'))); assert len(wheels) == 2, wheels; subprocess.run([sys.executable, '-m', 'pip', 'install', *wheels], check=True)"
python -m pip install --disable-pip-version-check -e '.[dev]'
python -c "from issuance.application.rust_integration import validate_marty_rs_capabilities as validate_issuance; from verification.application.rust_verifier import validate_marty_rs_capabilities as validate_verification; validate_issuance(); validate_verification()"
(
  cd services/issuance/infrastructure/migrations
  python -m alembic -c alembic.ini heads
)
(
  cd services/verification/infrastructure/migrations
  python -m alembic -c alembic.ini heads
)
python -m pytest tests/ packages/tests/ -v
