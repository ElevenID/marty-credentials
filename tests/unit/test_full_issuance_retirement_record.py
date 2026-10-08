"""The reviewed retirement receipt must cover the exact deletion source."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import check_full_issuance_retirement as gate


def git(repository: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repository, text=True).strip()


def test_receipt_rejects_source_changes_after_qualification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Retirement Test")
    git(tmp_path, "config", "user.email", "retirement@example.test")
    (tmp_path / "source.py").write_text("owner = 'rust'\n", encoding="utf-8")
    git(tmp_path, "add", "source.py")
    git(tmp_path, "commit", "-qm", "delete Python owner")
    source = git(tmp_path, "rev-parse", "HEAD")

    record_path = tmp_path / "contracts/full-issuance-retirement-qualification.json"
    record_path.parent.mkdir()
    record = {
        "status": "qualified_source_only",
        "credentials_source_commit": source,
        "ui_commit": "a" * 40,
        "ui_pr": 1178,
        "ui_pr_head": "b" * 40,
        "current_http_routes": 86,
        "native_http_routes": 122,
        "grpc_methods": 12,
        "passport_http_routes": 9,
        "beta_deployment_authorized": False,
        "service_images": 0,
        "required_checks": sorted(gate.REQUIRED_UI_CHECKS),
        "ui_merge_check_urls": dict.fromkeys(
            gate.REQUIRED_UI_CHECKS, "https://github.com/ElevenID/marty-ui/actions/runs/1"
        ),
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(gate, "RECORD", record_path)
    git(tmp_path, "add", "contracts/full-issuance-retirement-qualification.json")
    git(tmp_path, "commit", "-qm", "record local qualification")
    assert gate.verify_record(tmp_path, git(tmp_path, "rev-parse", "HEAD")) == record

    incomplete = dict(record)
    incomplete["ui_merge_check_urls"] = {}
    record_path.write_text(json.dumps(incomplete), encoding="utf-8")
    with pytest.raises(gate.RetirementError, match="incomplete merge-commit evidence"):
        gate.verify_record(tmp_path, git(tmp_path, "rev-parse", "HEAD"))
    record_path.write_text(json.dumps(record), encoding="utf-8")

    (tmp_path / "source.py").write_text("owner = 'python'\n", encoding="utf-8")
    git(tmp_path, "add", "source.py")
    git(tmp_path, "commit", "-qm", "change source after qualification")
    with pytest.raises(gate.RetirementError, match="source changed after qualification"):
        gate.verify_record(tmp_path, git(tmp_path, "rev-parse", "HEAD"))
