#!/usr/bin/env bash
set -euo pipefail

python -m pip install --disable-pip-version-check --upgrade pip
python -m pip install --disable-pip-version-check pytest pytest-asyncio
python -c "import pathlib, subprocess, sys; wheels = sorted(map(str, pathlib.Path('release-deps').glob('*.whl'))); assert len(wheels) == 2, wheels; subprocess.run([sys.executable, '-m', 'pip', 'install', *wheels], check=True)"
scripts/retry-command.sh python -m pip install --disable-pip-version-check -e '.[dev]'
# A regression here would silently turn the test harness back into a Python SDK.
test ! -d python/marty_credentials
test ! -e .github/workflows/publish-pypi.yml
test ! -e .github/workflows/release-stable.yml
test ! -e .github/workflows/release-images.yml
# Product issuance and verification are Rust owned. This job checks the
# remaining source, release and protocol contracts; the local-binding job
# exercises the separately built Rust extension.
python -m pytest tests/ packages/tests/ -v
