"""Reject Credentials binding graphs that restore Core issuer-key custody."""

import argparse
import json
import sys

CORE_REVISION = "08489a2aa5c6215878c38f64f4b257b79e164c14"
CORE_REF = "08489a2"
CORE_SOURCE = (
    "git+https://github.com/ElevenID/marty-core"
    f"?rev={CORE_REF}#{CORE_REVISION}"
)
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
KMS_ONLY_CRATES = {"marty-crypto", "marty-oid4vci", "marty-verification"}
FORBIDDEN_FEATURES = {"default", "local-key-operations", "test-fixtures"}
ISOMDL_REVISION = "784a52943469622873c7ae3200dbc11e89d6bd8e"
ISOMDL_SOURCE = (
    "git+https://github.com/ElevenID/isomdl-elevenid"
    f"?rev={ISOMDL_REVISION}#{ISOMDL_REVISION}"
)


def check(metadata: dict, mode: str = "python") -> None:
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    core = [
        package
        for package in metadata["packages"]
        if "github.com/ElevenID/marty-core" in (package.get("source") or "")
    ]
    names = [package["name"] for package in core]
    expected = CORE_CRATES_BY_MODE[mode]
    if len(names) != len(expected) or set(names) != expected:
        raise ValueError(f"Credentials {mode} Core packages changed: {sorted(names)}")

    for package in core:
        name = package["name"]
        if package["version"] != "0.2.2" or package["source"] != CORE_SOURCE:
            raise ValueError(f"{name} is not pinned to reviewed KMS-only Core")
        features = set(nodes[package["id"]]["features"])
        forbidden = features & FORBIDDEN_FEATURES
        if forbidden:
            raise ValueError(f"{name} enables forbidden features: {sorted(forbidden)}")
        if name in KMS_ONLY_CRATES and "kms-only" not in features:
            raise ValueError(f"{name} is missing kms-only")

    isomdl = [package for package in metadata["packages"] if package["name"] == "isomdl"]
    if (
        len(isomdl) != 1
        or isomdl[0]["version"] != "0.3.0"
        or isomdl[0]["source"] != ISOMDL_SOURCE
    ):
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
