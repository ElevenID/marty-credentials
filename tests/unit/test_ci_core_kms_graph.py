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
        {"id": "jsonwebtoken", "name": "jsonwebtoken", "version": GUARD["JWT_VERSION"], "source": GUARD["JWT_SOURCE"]},
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
    for node in nodes:
        if node["id"] == "sd-jwt-rs":
            node["features"] = sorted(GUARD["SD_JWT_FEATURES"])
        elif node["id"] == "jsonwebtoken":
            node["features"] = sorted(GUARD["JWT_FEATURES"])
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


@pytest.mark.parametrize("source", [GUARD["JWT_SOURCE"], None])
def test_reject_second_core_type_graph(source):
    candidate = graph("python")
    package = copy.deepcopy(next(p for p in candidate["packages"] if p["name"] == "marty-oid4vci"))
    package.update(id="second-marty-oid4vci", source=source)
    candidate["packages"].append(package)
    with pytest.raises(ValueError, match="Core packages changed"):
        GUARD["check"](candidate)


@pytest.mark.parametrize("version", ["10.4.0", "11.0.0", "11.1.0"])
def test_reject_duplicate_or_mixed_jsonwebtoken_providers(version):
    candidate = graph("python")
    package = copy.deepcopy(next(p for p in candidate["packages"] if p["name"] == "jsonwebtoken"))
    package.update(id="second-jsonwebtoken", version=version)
    candidate["packages"].append(package)
    with pytest.raises(ValueError, match="one reviewed jsonwebtoken"):
        GUARD["check"](candidate)


@pytest.mark.parametrize("version", ["10.4.0", "11.0.0", "11.2.0"])
def test_reject_unreviewed_jsonwebtoken_version(version):
    candidate = graph("python")
    package = next(p for p in candidate["packages"] if p["name"] == "jsonwebtoken")
    package["version"] = version
    with pytest.raises(ValueError, match="one reviewed jsonwebtoken"):
        GUARD["check"](candidate)


@pytest.mark.parametrize("source", [None, "git+https://example.invalid/jsonwebtoken#unreviewed"])
def test_reject_jsonwebtoken_source_substitution(source):
    candidate = graph("python")
    package = next(p for p in candidate["packages"] if p["name"] == "jsonwebtoken")
    package["source"] = source
    with pytest.raises(ValueError, match="one reviewed jsonwebtoken"):
        GUARD["check"](candidate)


@pytest.mark.parametrize("feature", ["default", "aws_lc_rs", "rust_crypto", "unreviewed-provider"])
def test_reject_builtin_or_unreviewed_jsonwebtoken_provider(feature):
    candidate = graph("python")
    node = next(n for n in candidate["resolve"]["nodes"] if n["id"] == "jsonwebtoken")
    node["features"].append(feature)
    with pytest.raises(ValueError, match="shared verification provider"):
        GUARD["check"](candidate)


@pytest.mark.parametrize("feature", ["default", "holder", "parallel", "issuance_bench", "mock_salts"])
def test_reject_widened_sd_jwt_roles_or_acceleration(feature):
    candidate = graph("python")
    node = next(n for n in candidate["resolve"]["nodes"] if n["id"] == "sd-jwt-rs")
    node["features"].append(feature)
    with pytest.raises(ValueError, match="reviewed issuer and verifier roles"):
        GUARD["check"](candidate)


@pytest.mark.parametrize("feature", sorted(GUARD["SD_JWT_FEATURES"]))
def test_reject_missing_sd_jwt_role_or_provider(feature):
    candidate = graph("python")
    node = next(n for n in candidate["resolve"]["nodes"] if n["id"] == "sd-jwt-rs")
    node["features"].remove(feature)
    with pytest.raises(ValueError, match="reviewed issuer and verifier roles"):
        GUARD["check"](candidate)


@pytest.mark.parametrize("name,feature", [
    (name, feature)
    for name, features in GUARD["FORBIDDEN_PROFILE_FEATURES"].items()
    for feature in sorted(features)
])
def test_reject_implicit_profile_activation(name, feature):
    candidate = graph("python")
    node = next(n for n in candidate["resolve"]["nodes"] if n["id"] == name)
    node["features"].append(feature)
    with pytest.raises(ValueError, match="unselected profile features"):
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
