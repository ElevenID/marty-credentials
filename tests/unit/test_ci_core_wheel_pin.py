"""Keep built Python wheels on the same reviewed Core revision as Rust bindings."""

from __future__ import annotations

import re
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GRAPH_GUARD = ROOT / "scripts" / "ci" / "check_core_kms_graph.py"


def test_python_wheel_builds_use_binding_core_revision() -> None:
    reviewed_revision = runpy.run_path(str(GRAPH_GUARD))["CORE_REVISION"]

    for workflow_name in ("ci.yml", "warm-ci-caches.yml"):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text(
            encoding="utf-8"
        )
        matches = re.findall(r"(?m)^  MARTY_CORE_REVISION: ([0-9a-f]{40})$", workflow)
        assert matches == [reviewed_revision], workflow_name
        assert "ref: ${{ env.MARTY_CORE_REVISION }}" in workflow
