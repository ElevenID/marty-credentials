from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "scripts" / "install_pinned_core.py"
SPEC = importlib.util.spec_from_file_location("install_pinned_core", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
install_pinned_core = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(install_pinned_core)


def _repository(tmp_path: Path, *, digest: str = "a" * 64) -> Path:
    release = tmp_path / "release"
    release.mkdir()
    (release / "dependencies.json").write_text(
        json.dumps(
            {
                "marty-rs": {
                    "version": "0.1.38",
                    "repository": "ElevenID/marty-core",
                    "tag": "v0.1.38",
                    "platform_assets": {
                        "linux-x86_64": {
                            "asset": "marty_rs-0.1.38-cp311-abi3-manylinux.whl",
                            "sha256": digest,
                        }
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_load_core_dependency_requires_version_bound_asset(tmp_path: Path) -> None:
    dependency = install_pinned_core.load_core_dependency(_repository(tmp_path), "linux-x86_64")

    assert dependency["repository"] == "ElevenID/marty-core"
    assert dependency["tag"] == "v0.1.38"
    assert dependency["sha256"] == "a" * 64


def test_platform_key_supports_arm64_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(install_pinned_core.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(install_pinned_core.sys, "platform", "darwin")

    assert install_pinned_core.platform_key() == "macos-arm64"


def test_load_core_dependency_rejects_non_sha256_digest(tmp_path: Path) -> None:
    with pytest.raises(install_pinned_core.PinnedCoreError, match="SHA-256"):
        install_pinned_core.load_core_dependency(
            _repository(tmp_path, digest="not-a-digest"), "linux-x86_64"
        )
