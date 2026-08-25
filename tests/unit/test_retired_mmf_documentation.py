"""Ensure retained Python MMF reports cannot be mistaken for current guides."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_REPORTS = (
    ROOT / "OPTIONS_2-4_COMPLETE.md",
    ROOT / "services" / "issuance" / "MIGRATION_SUMMARY.md",
)


def test_python_mmf_reports_are_explicitly_historical() -> None:
    for report in HISTORICAL_REPORTS:
        text = report.read_text(encoding="utf-8")
        introduction = "\n".join(text.splitlines()[:14])
        prose = " ".join(line.lstrip("> ") for line in introduction.splitlines())

        assert "Historical record" in prose, report
        assert "not a supported" in prose, report
        assert "Rust service plane" in prose, report
        assert "Do not restore" in prose, report
