"""Guards for the Rust-owned internal Application HTTP boundary."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISSUANCE = ROOT / "services" / "issuance"
ROUTES = ISSUANCE / "infrastructure" / "api" / "routes.py"
CONTRACT = ROOT / "contracts" / "issuance-internal-applications.json"

RETIRED_MODELS = {
    "ApplicationCreate",
    "ApplicationResponse",
    "EvidenceSubmission",
    "ApplicationApproval",
    "ApplicationRejection",
}
RETIRED_MODULES = (
    ISSUANCE / "infrastructure" / "api" / "application_routes.py",
    ISSUANCE / "application" / "evidence_reconciliation.py",
    ISSUANCE / "application" / "external_evidence_api.py",
)


def _top_level_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        names.update(target.id for target in targets if isinstance(target, ast.Name))
    return names


def test_python_internal_application_http_owner_stays_retired() -> None:
    assert all(not path.exists() for path in RETIRED_MODULES)

    names = _top_level_names(ROUTES)
    assert "internal_application_router" not in names
    assert names.isdisjoint(RETIRED_MODELS)

    main_source = (ISSUANCE / "main.py").read_text(encoding="utf-8")
    assert "internal_application_router" not in main_source
    assert "application_routes" not in main_source


def test_language_neutral_internal_application_contract_remains_frozen() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert contract["schema"] == "marty.issuance-internal-applications/v1"
    assert contract["surface"]["base_path"] == "/internal/applications"
    assert len(contract["surface"]["routes"]) == 14
