#!/usr/bin/env python3
"""Fail-closed helpers for assembling and validating credential releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

TAG_PATTERN = re.compile(r"^v(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SERVICES = ("issuance", "verification")


class ReleaseContractError(RuntimeError):
    """Release inputs or artifacts violate the publication contract."""


def version_from_tag(tag: str) -> str:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ReleaseContractError(f"stable release tag is invalid: {tag!r}")
    return match.group("version")


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ReleaseContractError(f"cannot read TOML file {path}") from error
    if not isinstance(payload, dict):
        raise ReleaseContractError(f"TOML file {path} did not contain an object")
    return payload


def workspace_version(repository: Path) -> str:
    payload = _load_toml(repository / "Cargo.toml")
    try:
        value = payload["workspace"]["package"]["version"]
    except (KeyError, TypeError) as error:
        raise ReleaseContractError("Cargo.toml has no workspace.package.version") from error
    if not isinstance(value, str) or not value:
        raise ReleaseContractError("Cargo.toml workspace version is invalid")
    return value


def locked_marty_rs_version(repository: Path) -> str:
    payload = _load_toml(repository / "Cargo.lock")
    packages = payload.get("package")
    if not isinstance(packages, list):
        raise ReleaseContractError("Cargo.lock has no package list")
    matches = [
        item for item in packages if isinstance(item, dict) and item.get("name") == "marty-rs"
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("version"), str):
        raise ReleaseContractError("Cargo.lock must contain exactly one versioned marty-rs package")
    return str(matches[0]["version"])


def stable_asset_names(version: str) -> set[str]:
    return {
        "checksums-wasm.txt",
        "marty-rs-sbom.json",
        "marty-rs-wasm.tar.gz",
        f"marty_credentials-{version}.tar.gz",
        f"marty_rs-{version}-cp311-abi3-macosx_10_12_x86_64.whl",
        f"marty_rs-{version}-cp311-abi3-macosx_11_0_arm64.whl",
        f"marty_rs-{version}-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        f"marty_rs-{version}-cp311-abi3-win_amd64.whl",
    }


def image_evidence_names() -> set[str]:
    return {
        f"marty-credentials-{service}.{suffix}"
        for service in SERVICES
        for suffix in ("digest", "spdx.json")
    }


def data_asset_names(version: str) -> set[str]:
    return stable_asset_names(version) | image_evidence_names()


def final_asset_names(version: str) -> set[str]:
    return data_asset_names(version) | {"SHA256SUMS", "SHA256SUMS.sigstore.json"}


def _regular_file_names(directory: Path) -> set[str]:
    if not directory.is_dir():
        raise ReleaseContractError(f"artifact directory does not exist: {directory}")
    names: set[str] = set()
    for child in directory.iterdir():
        if child.is_symlink() or not child.is_file():
            raise ReleaseContractError(f"artifact is not a regular file: {child.name}")
        names.add(child.name)
    return names


def require_names(actual: set[str], expected: set[str], context: str) -> None:
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    raise ReleaseContractError(
        f"{context} asset set is invalid; missing={missing!r}, unexpected={unexpected!r}"
    )


def collect_stable_artifacts(source: Path, destination: Path, version: str) -> None:
    if not source.is_dir():
        raise ReleaseContractError(f"artifact source does not exist: {source}")
    if destination.exists() and any(destination.iterdir()):
        raise ReleaseContractError(f"artifact destination must be empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    files = sorted(path for path in source.rglob("*") if path.is_file())
    for item in files:
        if item.is_symlink():
            raise ReleaseContractError(f"artifact source contains a symlink: {item}")
        if item.name in seen:
            raise ReleaseContractError(f"duplicate artifact basename: {item.name}")
        seen.add(item.name)
        shutil.copyfile(item, destination / item.name)
    require_names(seen, stable_asset_names(version), "stable")


def write_checksums(directory: Path, version: str) -> Path:
    expected = data_asset_names(version)
    require_names(_regular_file_names(directory), expected, "checksum input")
    output = directory / "SHA256SUMS"
    lines: list[str] = []
    for name in sorted(expected):
        digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    output.write_text("".join(lines), encoding="utf-8", newline="\n")
    return output


def verify_checksums(directory: Path, version: str) -> None:
    expected = data_asset_names(version)
    manifest = directory / "SHA256SUMS"
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ReleaseContractError("SHA256SUMS is missing") from error
    entries: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        if match is None or match.group(2) in entries:
            raise ReleaseContractError("SHA256SUMS contains a malformed or duplicate entry")
        entries[match.group(2)] = match.group(1)
    require_names(set(entries), expected, "checksum manifest")
    for name, expected_digest in entries.items():
        actual_digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            raise ReleaseContractError(f"checksum mismatch for {name}")


def validate_source(repository: Path, tag: str, expected_commit: str) -> None:
    version = version_from_tag(tag)
    if COMMIT_PATTERN.fullmatch(expected_commit) is None:
        raise ReleaseContractError("expected commit must be a full lowercase SHA")
    if workspace_version(repository) != version:
        raise ReleaseContractError("Cargo.toml version does not match the release tag")
    if locked_marty_rs_version(repository) != version:
        raise ReleaseContractError("Cargo.lock marty-rs version does not match the release tag")
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD^{commit}"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        tag_commit = subprocess.run(
            ["git", "rev-parse", f"{tag}^{{commit}}"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run(
            [
                "git",
                "rev-parse",
                "--verify",
                "refs/remotes/origin/main^{commit}",
            ],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                expected_commit,
                "refs/remotes/origin/main",
            ],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReleaseContractError("cannot validate release source against origin/main") from error
    if head != expected_commit or tag_commit != expected_commit:
        raise ReleaseContractError(
            f"release source mismatch: HEAD={head}, tag={tag_commit}, expected={expected_commit}"
        )


def _release_assets(payload: dict[str, Any]) -> set[str]:
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise ReleaseContractError("release payload has no asset list")
    names: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict) or asset.get("state") != "uploaded":
            raise ReleaseContractError("release contains an incomplete asset")
        name = asset.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ReleaseContractError("release contains an invalid or duplicate asset name")
        names.add(name)
    return names


def validate_release(
    payload: dict[str, Any],
    *,
    release_id: int,
    tag: str,
    commit: str,
    phase: str,
) -> str | None:
    version = version_from_tag(tag)
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ReleaseContractError("release commit must be a full lowercase SHA")
    if payload.get("id") != release_id:
        raise ReleaseContractError("release ID does not match the dispatch contract")
    if payload.get("tag_name") != tag:
        raise ReleaseContractError("release tag does not match the dispatch contract")
    # GitHub documents target_commitish as unused when the tag already exists.
    # The authoritative commit binding is the independently resolved tag ref.
    target_commitish = payload.get("target_commitish")
    if not isinstance(target_commitish, str) or not target_commitish:
        raise ReleaseContractError("release target commitish is invalid")
    if payload.get("prerelease") is not False:
        raise ReleaseContractError("release lifecycle state is invalid")
    assets = _release_assets(payload)
    draft = payload.get("draft")
    if phase == "resumable":
        if draft is True:
            missing_stable = stable_asset_names(version) - assets
            unexpected = assets - final_asset_names(version)
            if missing_stable or unexpected:
                raise ReleaseContractError(
                    "resumable asset set is invalid; "
                    f"missing_stable={sorted(missing_stable)!r}, "
                    f"unexpected={sorted(unexpected)!r}"
                )
            if assets == final_asset_names(version):
                return "complete"
            return "build"
        if draft is False:
            require_names(assets, final_asset_names(version), "published")
            if payload.get("immutable") is not True:
                raise ReleaseContractError("published release is not immutable")
            return "terminal"
        raise ReleaseContractError("release lifecycle state is invalid")

    expected_draft = phase != "published"
    if draft is not expected_draft:
        raise ReleaseContractError("release lifecycle state is invalid")
    if phase == "stable-draft":
        expected_assets = stable_asset_names(version)
    elif phase in {"complete-draft", "published"}:
        expected_assets = final_asset_names(version)
    else:
        raise ReleaseContractError(f"unknown release phase: {phase}")
    require_names(assets, expected_assets, phase)
    if phase == "published" and payload.get("immutable") is not True:
        raise ReleaseContractError("published release is not immutable")
    return None


def validate_package_tag_absent(payload: Any, tag: str) -> None:
    versions = _package_versions(payload)
    for version in versions:
        tags = _package_tags(version)
        if tag in tags:
            raise ReleaseContractError(f"container tag already exists: {tag}")


def _package_versions(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise ReleaseContractError("package version response is invalid")
    pages = payload
    versions: list[dict[str, Any]] = []
    for page in pages:
        if not isinstance(page, list):
            raise ReleaseContractError("package version response is invalid")
        for version in page:
            if not isinstance(version, dict):
                raise ReleaseContractError("package version response is invalid")
            _package_tags(version)
            name = version.get("name")
            if not isinstance(name, str) or not name:
                raise ReleaseContractError("package version digest is invalid")
            versions.append(version)
    return versions


def _package_tags(version: dict[str, Any]) -> list[str]:
    try:
        tags = version["metadata"]["container"]["tags"]
    except (KeyError, TypeError) as error:
        raise ReleaseContractError("package version response is invalid") from error
    if not isinstance(tags, list) or not all(isinstance(item, str) for item in tags):
        raise ReleaseContractError("package tag response is invalid")
    return tags


def validate_package_tag(payload: Any, tag: str, digest: str, *, allow_absent: bool) -> str:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ReleaseContractError("expected package digest is invalid")
    matches = [version for version in _package_versions(payload) if tag in _package_tags(version)]
    if not matches:
        if allow_absent:
            return "absent"
        raise ReleaseContractError(f"container tag is absent: {tag}")
    if len(matches) != 1:
        raise ReleaseContractError(f"container tag is ambiguous: {tag}")
    if matches[0]["name"] != digest:
        raise ReleaseContractError(
            f"container tag {tag} targets {matches[0]['name']}, expected {digest}"
        )
    return "matched"


def _json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseContractError(f"cannot read JSON file {path}") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("validate-source")
    source.add_argument("--repository", type=Path, default=Path.cwd())
    source.add_argument("--tag", required=True)
    source.add_argument("--commit", required=True)

    collect = subparsers.add_parser("collect-stable")
    collect.add_argument("--source", type=Path, required=True)
    collect.add_argument("--destination", type=Path, required=True)
    collect.add_argument("--tag", required=True)

    checksums = subparsers.add_parser("write-checksums")
    checksums.add_argument("--directory", type=Path, required=True)
    checksums.add_argument("--tag", required=True)

    verify = subparsers.add_parser("verify-checksums")
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--tag", required=True)

    list_stable = subparsers.add_parser("list-stable-assets")
    list_stable.add_argument("--tag", required=True)

    release = subparsers.add_parser("validate-release")
    release.add_argument("--json", type=Path, required=True)
    release.add_argument("--release-id", type=int, required=True)
    release.add_argument("--tag", required=True)
    release.add_argument("--commit", required=True)
    release.add_argument(
        "--phase",
        choices=("stable-draft", "resumable", "complete-draft", "published"),
        required=True,
    )

    package = subparsers.add_parser("validate-package-tag-absent")
    package.add_argument("--json", type=Path, required=True)
    package.add_argument("--tag", required=True)

    package_tag = subparsers.add_parser("validate-package-tag")
    package_tag.add_argument("--json", type=Path, required=True)
    package_tag.add_argument("--tag", required=True)
    package_tag.add_argument("--digest", required=True)
    package_tag.add_argument("--allow-absent", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate-source":
            validate_source(args.repository, args.tag, args.commit)
        elif args.command == "collect-stable":
            collect_stable_artifacts(args.source, args.destination, version_from_tag(args.tag))
        elif args.command == "write-checksums":
            write_checksums(args.directory, version_from_tag(args.tag))
        elif args.command == "verify-checksums":
            verify_checksums(args.directory, version_from_tag(args.tag))
        elif args.command == "list-stable-assets":
            for name in sorted(stable_asset_names(version_from_tag(args.tag))):
                print(name)
        elif args.command == "validate-release":
            payload = _json_file(args.json)
            if not isinstance(payload, dict):
                raise ReleaseContractError("release response must be a JSON object")
            state = validate_release(
                payload,
                release_id=args.release_id,
                tag=args.tag,
                commit=args.commit,
                phase=args.phase,
            )
            if state is not None:
                print(state)
        elif args.command == "validate-package-tag-absent":
            validate_package_tag_absent(_json_file(args.json), args.tag)
        elif args.command == "validate-package-tag":
            print(
                validate_package_tag(
                    _json_file(args.json),
                    args.tag,
                    args.digest,
                    allow_absent=args.allow_absent,
                )
            )
    except ReleaseContractError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
