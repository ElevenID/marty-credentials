"""Reject Credentials binding graphs that restore Core issuer-key custody."""

import json
import sys


CORE_REVISION = "7f276a427b28ecc43fb2941b60a3884a731401e0"
CORE_REF = "7f276a4"
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
}
KMS_ONLY_CRATES = {"marty-crypto", "marty-oid4vci", "marty-verification"}
FORBIDDEN_FEATURES = {"default", "local-key-operations", "test-fixtures"}
ISOMDL_REVISION = "784a52943469622873c7ae3200dbc11e89d6bd8e"
ISOMDL_SOURCE = (
    "git+https://github.com/ElevenID/isomdl-elevenid"
    f"?rev={ISOMDL_REVISION}#{ISOMDL_REVISION}"
)


def check(metadata: dict) -> None:
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    core = [
        package
        for package in metadata["packages"]
        if "github.com/ElevenID/marty-core" in (package.get("source") or "")
    ]
    names = [package["name"] for package in core]
    if len(names) != len(CORE_CRATES) or set(names) != CORE_CRATES:
        raise ValueError(f"Credentials Core packages changed: {sorted(names)}")

    for package in core:
        name = package["name"]
        if package["version"] != "0.2.0" or package["source"] != CORE_SOURCE:
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
    try:
        check(json.load(sys.stdin))
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
