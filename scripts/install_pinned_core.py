#!/usr/bin/env python3
"""Install checksum-pinned canonical marty-core wheels for this platform."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any


class PinnedCoreError(RuntimeError):
    """The pinned Core dependency cannot be selected or authenticated."""


CORE_WHEELS = {
    "marty-rs": "marty_rs-",
    "marty-verification": "marty_verification_py-",
}


def platform_key() -> str:
    machine = platform.machine().lower()
    architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }.get(machine)
    if architecture is None:
        raise PinnedCoreError(f"unsupported runner architecture: {machine}")
    operating_system = {
        "linux": "linux",
        "darwin": "macos",
        "win32": "windows",
    }.get(sys.platform)
    if operating_system is None:
        raise PinnedCoreError(f"unsupported runner platform: {sys.platform}")
    return f"{operating_system}-{architecture}"


def load_core_dependency(
    repository: Path,
    key: str,
    dependency_name: str = "marty-rs",
) -> dict[str, str]:
    try:
        payload: Any = json.loads(
            (repository / "release" / "dependencies.json").read_text(encoding="utf-8")
        )
        core = payload[dependency_name]
        selected = core["platform_assets"][key]
        result = {
            "repository": core["repository"],
            "tag": core["tag"],
            "version": core["version"],
            "asset": selected["asset"],
            "sha256": selected["sha256"],
        }
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise PinnedCoreError(f"invalid pinned Core dependency for {key}") from error

    if result["tag"] != f"v{result['version']}":
        raise PinnedCoreError("pinned Core tag and version do not match")
    expected_prefix = CORE_WHEELS.get(dependency_name)
    if expected_prefix is None:
        raise PinnedCoreError(f"unsupported pinned Core dependency: {dependency_name}")
    if not result["asset"].startswith(f"{expected_prefix}{result['version']}-"):
        raise PinnedCoreError("pinned Core wheel and version do not match")
    if len(result["sha256"]) != 64 or any(
        character not in "0123456789abcdef" for character in result["sha256"]
    ):
        raise PinnedCoreError("pinned Core digest is not lowercase SHA-256")
    return result


def install_pinned_core(repository: Path, destination: Path) -> list[Path]:
    dependencies = [
        load_core_dependency(repository, platform_key(), dependency_name)
        for dependency_name in CORE_WHEELS
    ]
    destination.mkdir(parents=True, exist_ok=True)
    wheels: list[Path] = []
    for dependency in dependencies:
        wheel = destination / dependency["asset"]
        if wheel.exists():
            raise PinnedCoreError(f"download destination already exists: {wheel}")

        subprocess.run(
            [
                "gh",
                "release",
                "download",
                dependency["tag"],
                "--repo",
                dependency["repository"],
                "--pattern",
                dependency["asset"],
                "--dir",
                str(destination),
            ],
            check=True,
        )
        if not wheel.is_file():
            raise PinnedCoreError(f"GitHub release did not provide {dependency['asset']}")
        actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if actual != dependency["sha256"]:
            raise PinnedCoreError(
                f"pinned Core digest mismatch: expected {dependency['sha256']}, got {actual}"
            )
        wheels.append(wheel)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", *(str(wheel) for wheel in wheels)],
        check=True,
    )
    return wheels


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        wheels = install_pinned_core(args.repository.resolve(), args.destination.resolve())
    except (OSError, PinnedCoreError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for wheel in wheels:
        print(wheel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
