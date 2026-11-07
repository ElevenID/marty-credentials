"""Keep reviewed compatibility adapters separate from issuer custody features."""

import copy
import runpy
from pathlib import Path

import pytest

GUARD = runpy.run_path(
    str(Path(__file__).resolve().parents[2] / "scripts/ci/check_core_kms_graph.py")
)


def graph(mode):
    versions = dict.fromkeys(GUARD["CORE_CRATES_BY_MODE"][mode], "0.2.2")
    versions.update(GUARD["CORE_ADAPTERS"])
    packages = [
        {"id": name, "name": name, "version": version, "source": GUARD["CORE_SOURCE"]}
        for name, version in versions.items()
    ]
    packages.append(
        {"id": "isomdl", "name": "isomdl", "version": "0.4.0", "source": GUARD["ISOMDL_SOURCE"]}
    )
    packages.extend([
        {"id": "sd-jwt-rs", "name": "sd-jwt-rs", "version": "0.8.0", "source": GUARD["SD_JWT_SOURCE"]},
        {"id": "ssi-json-ld", "name": "ssi-json-ld", "version": "0.3.3", "source": GUARD["SSI_SOURCE"]},
        {"id": "ecdsa", "name": "ecdsa", "version": "0.17.0", "source": GUARD["SSI_SOURCE"]},
        {"id": "did-web", "name": "did-web", "version": "0.5.1", "source": GUARD["SSI_SOURCE"]},
        {"id": "linked-data", "name": "linked-data", "version": "0.1.2", "source": GUARD["LINKED_DATA_SOURCE"]},
        {"id": "linked-data-derive", "name": "linked-data-derive", "version": "0.1.2", "source": GUARD["LINKED_DATA_SOURCE"]},
    ])
    nodes = [
        {"id": p["id"], "features": ["kms-only"] if p["name"] in GUARD["KMS_ONLY_CRATES"] else []}
        for p in packages
    ]
    return {"packages": packages, "resolve": {"nodes": nodes}}


@pytest.mark.parametrize("mode", ["python", "native", "wasm"])
def test_reviewed_graph(mode):
    GUARD["check"](graph(mode), mode)


@pytest.mark.parametrize(
    "mutation", ["version", "source", "unexpected", "private", "missing_kms", "issuer_signing"]
)
def test_reject_changed_security_boundary(mutation):
    candidate = copy.deepcopy(graph("python"))
    packages = {p["name"]: p for p in candidate["packages"]}
    nodes = {n["id"]: n for n in candidate["resolve"]["nodes"]}
    if mutation == "version":
        packages["elliptic-curve"]["version"] = "0.13.9"
    elif mutation == "source":
        packages["bls12_381_plus"]["source"] += "-unreviewed"
    elif mutation == "unexpected":
        candidate["packages"].append(
            {"id": "extra", "name": "extra", "version": "0.2.2", "source": GUARD["CORE_SOURCE"]}
        )
    elif mutation == "private":
        nodes["marty-crypto"]["features"].append("local-key-operations")
    elif mutation == "missing_kms":
        nodes["marty-crypto"]["features"] = []
    else:
        nodes["isomdl"]["features"].append("issuer-local-signing")
    with pytest.raises(ValueError):
        GUARD["check"](candidate)


@pytest.mark.parametrize("name", ["sd-jwt-rs", "ssi-json-ld", "linked-data"])
def test_reject_mixed_or_unreviewed_fork_revisions(name):
    candidate = graph("python")
    package = next(package for package in candidate["packages"] if package["name"] == name)
    package["source"] += "-unreviewed"
    with pytest.raises(ValueError):
        GUARD["check"](candidate)


def test_reject_duplicate_sd_jwt_implementations():
    candidate = graph("python")
    package = copy.deepcopy(next(package for package in candidate["packages"] if package["name"] == "sd-jwt-rs"))
    package["id"] = "second-sd-jwt-rs"
    candidate["packages"].append(package)
    with pytest.raises(ValueError, match="one reviewed sd-jwt-rs"):
        GUARD["check"](candidate)


@pytest.mark.parametrize("name", ["sd-jwt-rs", "ssi-json-ld", "ecdsa", "did-web", "linked-data", "linked-data-derive"])
@pytest.mark.parametrize("source", [
    "registry+https://github.com/rust-lang/crates.io-index",
    "git+https://github.com/spruceid/ssi?rev=unreviewed#unreviewed",
    None,
])
def test_reject_registry_upstream_or_path_substitution(name, source):
    candidate = graph("python")
    package = next(package for package in candidate["packages"] if package["name"] == name)
    package["source"] = source
    with pytest.raises(ValueError):
        GUARD["check"](candidate)
