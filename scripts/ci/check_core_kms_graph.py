"""Reject Credentials binding graphs that restore Core issuer-key custody."""

import argparse
import json
import sys

CORE_REVISION = "44040270000f93b7e7499cbec31b3bb3dd7e3df1"
CORE_REF = "44040270000f93b7e7499cbec31b3bb3dd7e3df1"
CORE_SOURCE = f"git+https://github.com/ElevenID/marty-core?rev={CORE_REF}#{CORE_REVISION}"
CORE_CRATES = {
    "marty-canonical-digest",
    "marty-crypto",
    "marty-oid4vci",
    "marty-python-adapters",
    "marty-status",
    "marty-verification",
    "marty-x509-verification",
}
CORE_CRATES_BY_MODE = {
    "python": CORE_CRATES,
    "native": CORE_CRATES - {"marty-python-adapters", "marty-status"},
    "wasm": CORE_CRATES - {"marty-python-adapters", "marty-status"},
}
CORE_ADAPTERS = {"bls12_381_plus": "0.8.18", "elliptic-curve": "0.13.8"}
KMS_ONLY_CRATES = {"marty-crypto", "marty-oid4vci", "marty-verification"}
FORBIDDEN_FEATURES = {"default", "local-key-operations", "test-fixtures"}
ISOMDL_REVISION = "1e7ab823e26559dfce2f7e0f1fdf2aa61a936b4f"
ISOMDL_SOURCE = (
    f"git+https://github.com/ElevenID/isomdl-elevenid?rev={ISOMDL_REVISION}#{ISOMDL_REVISION}"
)


def check(metadata: dict, mode: str = "python") -> None:
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    core = [
        package
        for package in metadata["packages"]
        if "github.com/ElevenID/marty-core" in (package.get("source") or "")
    ]
    names = [package["name"] for package in core]
    expected = CORE_CRATES_BY_MODE[mode] | CORE_ADAPTERS.keys()
    if len(names) != len(expected) or set(names) != expected:
        raise ValueError(f"Credentials {mode} Core packages changed: {sorted(names)}")

    for package in core:
        name = package["name"]
        expected_version = CORE_ADAPTERS.get(name, "0.2.2")
        if package["version"] != expected_version or package["source"] != CORE_SOURCE:
            raise ValueError(f"{name} is not pinned to reviewed KMS-only Core")
        if name in CORE_ADAPTERS:
            continue
        features = set(nodes[package["id"]]["features"])
        forbidden = features & FORBIDDEN_FEATURES
        if forbidden:
            raise ValueError(f"{name} enables forbidden features: {sorted(forbidden)}")
        if name in KMS_ONLY_CRATES and "kms-only" not in features:
            raise ValueError(f"{name} is missing kms-only")

    isomdl = [package for package in metadata["packages"] if package["name"] == "isomdl"]
    if len(isomdl) != 1 or isomdl[0]["version"] != "0.3.0" or isomdl[0]["source"] != ISOMDL_SOURCE:
        raise ValueError("Expected one reviewed isomdl 0.3.0 package")
    if set(nodes[isomdl[0]["id"]]["features"]) & {"default", "issuer-local-signing"}:
        raise ValueError("isomdl enables local issuer signing")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=CORE_CRATES_BY_MODE, default="python")
    args = parser.parse_args()
    try:
        check(json.load(sys.stdin), args.mode)
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
