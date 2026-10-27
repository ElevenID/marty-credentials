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
        {"id": "isomdl", "name": "isomdl", "version": "0.3.0", "source": GUARD["ISOMDL_SOURCE"]}
    )
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
