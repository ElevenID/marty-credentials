from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import check_issuance_python_retirement as prior_gate
from scripts import check_issuance_retention_python_retirement as gate


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _rows(keys: set[tuple[str, str]]) -> list[dict[str, object]]:
    return [{"method": method, "path": path} for method, path in sorted(keys)]


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, dict]:
    source = tmp_path / "marty-ui"
    native_rows = _rows(prior_gate.EXPECTED_DELETIONS)
    native_rows.extend(
        {"method": method, "path": path, "retention_behavior_contract": True}
        for method, path in sorted(gate.EXPECTED_DELETIONS)
    )
    _write(
        source / "contracts/issuance-native-coverage.json",
        {"schema": "marty.issuance-native-coverage/v1", "native_http": native_rows},
    )
    _write(
        source / "contracts/issuance-universal-ownership.json",
        {
            "schema": "marty.issuance-universal-ownership/v1",
            "runtime_surface": "contracts/issuance-runtime-surface.json",
            "default_owner": "issuance-native",
            "retained_legacy_owner": "issuance",
            "retained_legacy_http": _rows(gate.EXPECTED_RETAINED),
            "python_deletion_authorized": False,
            "rust_owned_python_retirement": {
                "authorized": True,
                "scope": sorted(prior_gate.EXPECTED_SCOPES),
                "retained_http_route_count": 9,
                "full_python_service_deletion_authorized": False,
            },
        },
    )
    _write(
        source / "contracts/issuance-runtime-surface.json",
        {
            "http": {
                "routes": _rows(
                    prior_gate.EXPECTED_DELETIONS | gate.EXPECTED_DELETIONS | gate.EXPECTED_RETAINED
                )
            }
        },
    )
    _write(
        source / "contracts/issuance-retention-management.json",
        {
            "schema": "marty.issuance-retention-management/v1",
            "routes": _rows(gate.EXPECTED_DELETIONS),
        },
    )
    _write(
        source / "release/stack-lock.json",
        {
            "schema": "marty.stack-lock/v1",
            "components": [
                {
                    "name": "marty-credentials-issuance",
                    "repository": "ElevenID/marty-credentials",
                    "version": "0.1.78",
                    "commit": gate.EXPECTED_CREDENTIALS_SOURCE,
                    "artifacts": [
                        {
                            "type": "oci",
                            "uri": "ghcr.io/elevenid/marty-credentials-issuance",
                            "digest": gate.EXPECTED_CREDENTIALS_DIGEST,
                        }
                    ],
                }
            ],
        },
    )
    contract = json.loads(gate.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
    contract["state"] = "qualified"
    contract["source"]["commit"] = "a" * 40
    for artifact in contract["source"]["artifacts"]:
        artifact["sha256"] = hashlib.sha256((source / artifact["path"]).read_bytes()).hexdigest()
    contract_path = tmp_path / "qualification.json"
    _write(contract_path, contract)

    previous = json.loads(prior_gate.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
    previous["state"] = "qualified"
    previous["source"]["commit"] = "b" * 40
    for artifact in previous["source"]["artifacts"]:
        artifact["sha256"] = hashlib.sha256(f"blob:{artifact['path']}".encode()).hexdigest()
    _write(tmp_path / contract["prior_retirement_qualification"], previous)
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    monkeypatch.setattr(prior_gate, "_git_head", lambda _checkout: "a" * 40)
    monkeypatch.setattr(prior_gate, "_git_is_clean", lambda _checkout: True)
    monkeypatch.setattr(prior_gate, "_git_is_from_protected_main", lambda _checkout, _commit: True)
    monkeypatch.setattr(
        prior_gate,
        "_git_blob",
        lambda checkout, commit, relative: (
            f"blob:{relative}".encode()
            if commit == "b" * 40
            else (checkout / relative).read_bytes()
        ),
    )
    return contract_path, source, contract


def test_checked_in_retention_contract_requires_pinned_ui_checkout(tmp_path: Path) -> None:
    contract = json.loads(gate.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
    assert contract["state"] == "qualified"
    assert contract["source"]["commit"] == "91ea7e52d6a3822981bb42f002da8c68532ebf2e"
    assert all(
        isinstance(digest, str) and len(digest) == 64
        for digest in gate._artifact_map(contract["source"], gate.EXPECTED_ARTIFACTS).values()
    )
    with pytest.raises(prior_gate.QualificationError, match="not a Git worktree"):
        gate.verify(gate.DEFAULT_CONTRACT, tmp_path)


def test_exact_protected_main_retention_checkpoint_qualifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path, source, _ = _fixture(tmp_path, monkeypatch)
    assert gate.verify(contract_path, source) == {
        "status": "qualified",
        "source_commit": "a" * 40,
        "authorized_route_count": 2,
        "retained_python_route_count": 9,
    }


def test_prior_retirement_must_already_be_qualified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path, source, contract = _fixture(tmp_path, monkeypatch)
    previous_path = tmp_path / contract["prior_retirement_qualification"]
    previous = json.loads(previous_path.read_text(encoding="utf-8"))
    previous["state"] = prior_gate.BLOCKED_STATE
    _write(previous_path, previous)
    with pytest.raises(prior_gate.QualificationError, match="Prior retirement is not qualified"):
        gate.verify(contract_path, source)


def test_retention_route_tag_is_required_even_with_matching_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path, source, contract = _fixture(tmp_path, monkeypatch)
    coverage_path = source / "contracts/issuance-native-coverage.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    next(row for row in coverage["native_http"] if row.get("retention_behavior_contract"))[
        "retention_behavior_contract"
    ] = False
    _write(coverage_path, coverage)
    next(
        item
        for item in contract["source"]["artifacts"]
        if item["path"] == "contracts/issuance-native-coverage.json"
    )["sha256"] = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
    _write(contract_path, contract)
    with pytest.raises(prior_gate.QualificationError, match="Retention native route tags changed"):
        gate.verify(contract_path, source)


def test_retained_passport_route_set_cannot_shrink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path, source, contract = _fixture(tmp_path, monkeypatch)
    contract["retained_python_http"].pop()
    _write(contract_path, contract)
    with pytest.raises(
        prior_gate.QualificationError, match="Retained Python route identities changed"
    ):
        gate.verify(contract_path, source)


def test_unprotected_retention_source_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path, source, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(prior_gate, "_git_is_from_protected_main", lambda _checkout, _commit: False)
    with pytest.raises(prior_gate.QualificationError, match="not reachable from protected main"):
        gate.verify(contract_path, source)


def test_rehashed_release_lock_cannot_change_the_qualified_credentials_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path, source, contract = _fixture(tmp_path, monkeypatch)
    relative = "release/stack-lock.json"
    lock_path = source / relative
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["components"][0]["artifacts"][0]["digest"] = "sha256:" + "0" * 64
    _write(lock_path, lock)
    next(item for item in contract["source"]["artifacts"] if item["path"] == relative)["sha256"] = (
        hashlib.sha256(lock_path.read_bytes()).hexdigest()
    )
    _write(contract_path, contract)
    with pytest.raises(prior_gate.QualificationError, match="Released Credentials image changed"):
        gate.verify(contract_path, source)


def test_rehashed_ownership_cannot_select_a_different_default_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_path, source, contract = _fixture(tmp_path, monkeypatch)
    relative = "contracts/issuance-universal-ownership.json"
    ownership_path = source / relative
    ownership = json.loads(ownership_path.read_text(encoding="utf-8"))
    ownership["default_owner"] = "issuance"
    _write(ownership_path, ownership)
    next(item for item in contract["source"]["artifacts"] if item["path"] == relative)["sha256"] = (
        hashlib.sha256(ownership_path.read_bytes()).hexdigest()
    )
    _write(contract_path, contract)
    with pytest.raises(prior_gate.QualificationError, match="Source issuance ownership changed"):
        gate.verify(contract_path, source)
