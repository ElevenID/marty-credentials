#!/usr/bin/env bash
set -euo pipefail

python -m pip install --disable-pip-version-check --upgrade pip
python -m pip install --disable-pip-version-check pytest pytest-asyncio
python -c "import pathlib, subprocess, sys; wheels = sorted(map(str, pathlib.Path('release-deps').glob('*.whl'))); assert len(wheels) == 2, wheels; subprocess.run([sys.executable, '-m', 'pip', 'install', *wheels], check=True)"
python -m pip install --disable-pip-version-check -e '.[dev]'
python -c "from issuance.application.rust_integration import validate_marty_rs_capabilities as validate_issuance; validate_issuance()"
(
  cd services/issuance/infrastructure/migrations
  python -m alembic -c alembic.ini heads
)
python -m pytest tests/ packages/tests/ -v
privacy_source_commit="$(python scripts/capture_canvas_privacy_reference.py --source-commit)"
if ! git cat-file -e "${privacy_source_commit}^{commit}" 2>/dev/null; then
  git fetch --no-tags --depth=1 origin "$privacy_source_commit"
fi
python scripts/capture_canvas_privacy_reference.py --verify contracts/canvas-worker-privacy-reference.json
