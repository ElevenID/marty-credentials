from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "release_contract.py"
SPEC = importlib.util.spec_from_file_location("release_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_contract)


def _write_files(directory: Path, names: set[str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_bytes(f"contents:{name}".encode())


def _release_payload(
    *,
    names: set[str],
    draft: bool,
    immutable: bool = False,
) -> dict[str, object]:
    return {
        "id": 1234,
        "tag_name": "v0.1.7",
        "target_commitish": "a" * 40,
        "draft": draft,
        "prerelease": False,
        "immutable": immutable,
        "assets": [{"name": name, "state": "uploaded"} for name in sorted(names)],
    }


@pytest.mark.parametrize("tag", ["0.1.7", "v01.1.7", "v0.1.7-rc.1", "v0.1", "latest"])
def test_version_from_tag_rejects_noncanonical_stable_tags(tag: str) -> None:
    with pytest.raises(release_contract.ReleaseContractError):
        release_contract.version_from_tag(tag)


def test_release_asset_contract_is_complete_and_disjoint() -> None:
    stable = release_contract.stable_asset_names("0.1.7")
    images = release_contract.image_evidence_names()
    assert len(stable) == 8
    assert len(images) == 4
    assert stable.isdisjoint(images)
    assert release_contract.data_asset_names("0.1.7") == stable | images
    assert release_contract.final_asset_names("0.1.7") == stable | images | {
        "SHA256SUMS",
        "SHA256SUMS.sigstore.json",
    }


def test_collect_stable_artifacts_rejects_duplicate_basenames(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "one").mkdir(parents=True)
    (source / "two").mkdir()
    (source / "one" / "same.whl").write_bytes(b"one")
    (source / "two" / "same.whl").write_bytes(b"two")

    with pytest.raises(release_contract.ReleaseContractError, match="duplicate"):
        release_contract.collect_stable_artifacts(source, tmp_path / "destination", "0.1.7")


def test_collect_stable_artifacts_requires_exact_set(tmp_path: Path) -> None:
    source = tmp_path / "source"
    expected = release_contract.stable_asset_names("0.1.7")
    _write_files(source, expected)

    destination = tmp_path / "destination"
    release_contract.collect_stable_artifacts(source, destination, "0.1.7")
    assert {path.name for path in destination.iterdir()} == expected

    (source / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(release_contract.ReleaseContractError, match="unexpected"):
        release_contract.collect_stable_artifacts(source, tmp_path / "other", "0.1.7")


def test_checksum_manifest_covers_only_all_data_assets(tmp_path: Path) -> None:
    expected = release_contract.data_asset_names("0.1.7")
    _write_files(tmp_path, expected)

    manifest = release_contract.write_checksums(tmp_path, "0.1.7")
    release_contract.verify_checksums(tmp_path, "0.1.7")

    lines = manifest.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 12
    assert [line.split("  ", 1)[1] for line in lines] == sorted(expected)
    assert all("SHA256SUMS" not in line for line in lines)


def test_checksum_manifest_rejects_missing_or_tampered_assets(tmp_path: Path) -> None:
    expected = release_contract.data_asset_names("0.1.7")
    _write_files(tmp_path, expected)
    manifest = release_contract.write_checksums(tmp_path, "0.1.7")
    victim = next(iter(expected))
    (tmp_path / victim).write_text("changed", encoding="utf-8")
    with pytest.raises(release_contract.ReleaseContractError, match="checksum mismatch"):
        release_contract.verify_checksums(tmp_path, "0.1.7")

    manifest.write_text("bad manifest\n", encoding="utf-8")
    with pytest.raises(release_contract.ReleaseContractError, match="malformed"):
        release_contract.verify_checksums(tmp_path, "0.1.7")


def test_validate_source_requires_release_commit_on_origin_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "a" * 40
    monkeypatch.setattr(release_contract, "workspace_version", lambda repository: "0.1.7")
    monkeypatch.setattr(release_contract, "locked_marty_rs_version", lambda repository: "0.1.7")
    calls: list[tuple[str, ...]] = []

    def run(
        command: list[str],
        *,
        cwd: Path,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> subprocess.CompletedProcess[str]:
        assert cwd == tmp_path
        assert check and capture_output and text
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, f"{commit}\n", "")

    monkeypatch.setattr(release_contract.subprocess, "run", run)
    release_contract.validate_source(tmp_path, "v0.1.7", commit)

    assert (
        "git",
        "merge-base",
        "--is-ancestor",
        commit,
        "refs/remotes/origin/main",
    ) in calls


def test_validate_source_rejects_release_commit_outside_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "a" * 40
    monkeypatch.setattr(release_contract, "workspace_version", lambda repository: "0.1.7")
    monkeypatch.setattr(release_contract, "locked_marty_rs_version", lambda repository: "0.1.7")

    def run(
        command: list[str],
        *,
        cwd: Path,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> subprocess.CompletedProcess[str]:
        if command[1:3] == ["merge-base", "--is-ancestor"]:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0, f"{commit}\n", "")

    monkeypatch.setattr(release_contract.subprocess, "run", run)
    with pytest.raises(release_contract.ReleaseContractError, match="origin/main"):
        release_contract.validate_source(tmp_path, "v0.1.7", commit)


def test_release_lifecycle_is_bound_to_id_tag_commit_and_asset_phase() -> None:
    stable = release_contract.stable_asset_names("0.1.7")
    payload = _release_payload(names=stable, draft=True)
    payload["target_commitish"] = "main"
    release_contract.validate_release(
        payload,
        release_id=1234,
        tag="v0.1.7",
        commit="a" * 40,
        phase="stable-draft",
    )

    payload["id"] = 999
    with pytest.raises(release_contract.ReleaseContractError, match="release ID"):
        release_contract.validate_release(
            payload,
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="stable-draft",
        )


def test_resumable_draft_accepts_only_partial_final_evidence() -> None:
    stable = release_contract.stable_asset_names("0.1.7")
    optional = {
        "marty-credentials-issuance.digest",
        "marty-credentials-issuance.spdx.json",
        "SHA256SUMS",
    }
    assert (
        release_contract.validate_release(
            _release_payload(names=stable | optional, draft=True),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="resumable",
        )
        == "build"
    )

    assert (
        release_contract.validate_release(
            _release_payload(names=release_contract.final_asset_names("0.1.7"), draft=True),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="resumable",
        )
        == "complete"
    )

    with pytest.raises(release_contract.ReleaseContractError, match="missing_stable"):
        release_contract.validate_release(
            _release_payload(names=(stable - {next(iter(stable))}) | optional, draft=True),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="resumable",
        )

    with pytest.raises(release_contract.ReleaseContractError, match="unexpected"):
        release_contract.validate_release(
            _release_payload(names=stable | {"unapproved.txt"}, draft=True),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="resumable",
        )


def test_resumable_terminal_release_must_be_complete_and_immutable() -> None:
    final = release_contract.final_asset_names("0.1.7")
    assert (
        release_contract.validate_release(
            _release_payload(names=final, draft=False, immutable=True),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="resumable",
        )
        == "terminal"
    )

    with pytest.raises(release_contract.ReleaseContractError, match="not immutable"):
        release_contract.validate_release(
            _release_payload(names=final, draft=False, immutable=False),
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="resumable",
        )


def test_published_release_requires_complete_assets_and_immutability() -> None:
    final = release_contract.final_asset_names("0.1.7")
    mutable = _release_payload(names=final, draft=False, immutable=False)
    with pytest.raises(release_contract.ReleaseContractError, match="not immutable"):
        release_contract.validate_release(
            mutable,
            release_id=1234,
            tag="v0.1.7",
            commit="a" * 40,
            phase="published",
        )

    immutable = _release_payload(names=final, draft=False, immutable=True)
    release_contract.validate_release(
        immutable,
        release_id=1234,
        tag="v0.1.7",
        commit="a" * 40,
        phase="published",
    )


def test_package_tag_guard_handles_paginated_response() -> None:
    payload = [
        [
            {
                "name": f"sha256:{'1' * 64}",
                "metadata": {"container": {"tags": ["v0.1.6"]}},
            }
        ],
        [{"name": f"sha256:{'2' * 64}", "metadata": {"container": {"tags": []}}}],
    ]
    release_contract.validate_package_tag_absent(payload, "v0.1.7")
    with pytest.raises(release_contract.ReleaseContractError, match="already exists"):
        release_contract.validate_package_tag_absent(payload, "v0.1.6")


def test_package_tag_guard_fails_closed_on_malformed_response() -> None:
    with pytest.raises(release_contract.ReleaseContractError, match="invalid"):
        release_contract.validate_package_tag_absent({"message": "rate limited"}, "v0.1.7")


def test_package_tag_validation_supports_idempotent_promotion() -> None:
    digest = f"sha256:{'1' * 64}"
    absent = [[{"name": digest, "metadata": {"container": {"tags": []}}}]]
    assert (
        release_contract.validate_package_tag(absent, "v0.1.7", digest, allow_absent=True)
        == "absent"
    )
    with pytest.raises(release_contract.ReleaseContractError, match="absent"):
        release_contract.validate_package_tag(absent, "v0.1.7", digest, allow_absent=False)

    matched = [[{"name": digest, "metadata": {"container": {"tags": ["v0.1.7"]}}}]]
    assert (
        release_contract.validate_package_tag(matched, "v0.1.7", digest, allow_absent=True)
        == "matched"
    )
    with pytest.raises(release_contract.ReleaseContractError, match="targets"):
        release_contract.validate_package_tag(
            matched, "v0.1.7", f"sha256:{'2' * 64}", allow_absent=True
        )
