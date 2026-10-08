"""Guards for the Rust-owned Application Template management boundary."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISSUANCE = ROOT / "services" / "issuance"


def test_python_application_template_management_surface_stays_retired() -> None:
    """Prevent Python from silently recreating the Rust-owned routes."""

    assert not ISSUANCE.exists()
