"""Reject Credentials binding graphs that restore Core issuer-key custody."""

import argparse
import json
import sys

CORE_REVISION = "11655e38c2dbf69bfa5bc3c873f80c5fad628723"
CORE_REF = "11655e38c2dbf69bfa5bc3c873f80c5fad628723"
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
ISOMDL_REVISION = "fc3aaa2628cd106d4f36f50c957d7f33211f8a5e"
ISOMDL_SOURCE = (
    f"git+https://github.com/ElevenID/isomdl-elevenid?rev={ISOMDL_REVISION}#{ISOMDL_REVISION}"
)
SSI_REVISION = "63a9bcce3daf6f45d1e38e43cf687738bb02cb53"
SSI_SOURCE = f"git+https://github.com/ElevenID/ssi-elevenid?rev={SSI_REVISION}#{SSI_REVISION}"
LINKED_DATA_REVISION = "6f86efc1579033e14ff2ad7d115ca0857e16a67f"
LINKED_DATA_SOURCE = (
    f"git+https://github.com/ElevenID/ssi-elevenid?rev={LINKED_DATA_REVISION}#{LINKED_DATA_REVISION}"
)
SD_JWT_REVISION = "fbe1e1b2c4bf0d62b0fdf0f47f265ffdaaae1ff2"
SD_JWT_SOURCE = f"git+https://github.com/ElevenID/sd-jwt-rust?rev={SD_JWT_REVISION}#{SD_JWT_REVISION}"
SSI_COMPANION_PACKAGES = {
    "ssi", "ecdsa", "linked-data", "linked-data-derive",
    "did-ethr", "did-ion", "did-jwk", "did-method-key", "did-pkh", "did-tz", "did-web",
}


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
    if len(isomdl) != 1 or isomdl[0]["version"] != "0.4.0" or isomdl[0]["source"] != ISOMDL_SOURCE:
        raise ValueError("Expected one reviewed isomdl 0.4.0 package")
    if set(nodes[isomdl[0]["id"]]["features"]) & {"default", "issuer-local-signing"}:
        raise ValueError("isomdl enables local issuer signing")

    sd_jwt = [package for package in metadata["packages"] if package["name"] == "sd-jwt-rs"]
    if len(sd_jwt) != 1 or sd_jwt[0]["version"] != "0.8.0" or sd_jwt[0]["source"] != SD_JWT_SOURCE:
        raise ValueError("Expected one reviewed sd-jwt-rs 0.8.0 package")

    for package in metadata["packages"]:
        name = package["name"]
        governed_name = name.startswith("ssi-") or name in SSI_COMPANION_PACKAGES
        fork_source = "github.com/ElevenID/ssi-elevenid" in (package.get("source") or "")
        if not (governed_name or fork_source):
            continue
        expected_source = (
            LINKED_DATA_SOURCE
            if name in {"linked-data", "linked-data-derive"}
            else SSI_SOURCE
        )
        if package.get("source") != expected_source:
            raise ValueError(f"{name} is not pinned to the reviewed SSI graph")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=CORE_CRATES_BY_MODE, default="python")
    args = parser.parse_args()
    try:
        check(json.load(sys.stdin), args.mode)
    except (KeyError, ValueError) as error:
        raise SystemExit(str(error)) from error
