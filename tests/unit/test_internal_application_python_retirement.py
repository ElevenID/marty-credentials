"""Guards for the Rust-owned internal Application HTTP boundary."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISSUANCE = ROOT / "services" / "issuance"
ROUTES = ISSUANCE / "infrastructure" / "api" / "routes.py"
CONTRACT = ROOT / "contracts" / "issuance-internal-applications.json"
PAIRED_RUST_CONTRACT_CANONICAL_SHA256 = (
    "11bac34429733ad3658fbe6650809705ef86ce4b83d12d2198be56d4170f0a0d"
)

FROZEN_ROUTE_IDENTITIES = frozenset(
    {
        ("POST", "/internal/applications"),
        ("GET", "/internal/applications"),
        ("GET", "/internal/applications/{application_id}"),
        ("GET", "/internal/applications/{application_id}/evidence-facts"),
        ("GET", "/internal/applications/{application_id}/evidence-summary"),
        (
            "POST",
            "/internal/applications/{application_id}/evidence/api-checks/{check_id}/run",
        ),
        ("POST", "/internal/applications/evidence/reconcile"),
        ("GET", "/internal/applications/evidence/reconciliation-report"),
        ("POST", "/internal/applications/{application_id}/submit-evidence"),
        ("POST", "/internal/applications/{application_id}/approve"),
        ("POST", "/internal/applications/{application_id}/reject"),
        ("POST", "/internal/applications/{application_id}/issuance-offer"),
        ("GET", "/internal/applications/{application_id}/issuance-offer"),
        ("GET", "/internal/applications/{application_id}/issuance-events"),
    }
)

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


def _canonical_contract_digest(contract: object) -> str:
    encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
    assert {
        (route["method"], route["path"])
        for route in contract["surface"]["routes"]
    } == FROZEN_ROUTE_IDENTITIES
    # The paired Rust owner carries the same canonical JSON; normalize first so
    # platform line endings and formatting cannot create a false mismatch.
    assert (
        _canonical_contract_digest(contract)
        == PAIRED_RUST_CONTRACT_CANONICAL_SHA256
    )
