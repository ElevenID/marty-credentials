"""Guards for the Rust-owned Application Template management boundary."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROUTES = ROOT / "services" / "issuance" / "infrastructure" / "api" / "routes.py"

RETIRED_MODELS = {
    "ApplicationFieldOption",
    "ApplicationFormField",
    "RequiredApplicationCheck",
    "ApplicationEvidenceRequirement",
    "ClaimCollectionRule",
    "ApplicationTemplateCreate",
    "ApplicationTemplatePatch",
    "ApplicationTemplateResponse",
}


def _top_level_classes(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {node.name for node in tree.body if isinstance(node, ast.ClassDef)}


def test_python_application_template_management_surface_stays_retired() -> None:
    """Prevent Python from silently recreating the Rust-owned routes."""

    assert not (ROUTES.parent / "application_routes.py").exists()
    assert _top_level_classes(ROUTES).isdisjoint(RETIRED_MODELS)

    main_source = (ROOT / "services" / "issuance" / "main.py").read_text(encoding="utf-8")
    assert "application_template_router" not in main_source
