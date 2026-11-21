"""Require the reviewed shared provider, role features and Core custody boundary."""

import argparse
import json
import sys

CORE_REVISION = "11152cfb83ec47174a21ad76fd4c9e811c93602f"
CORE_REF = "11152cfb83ec47174a21ad76fd4c9e811c93602f"
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
FORBIDDEN_PROFILE_FEATURES = {
    "marty-oid4vci": {"wallet", "lti", "zk_mdoc"},
    "marty-verification": {"mdoc-status-verification"},
}
ISOMDL_REVISION = "fc3aaa2628cd106d4f36f50c957d7f33211f8a5e"
ISOMDL_SOURCE = (
    f"git+https://github.com/ElevenID/isomdl-elevenid?rev={ISOMDL_REVISION}#{ISOMDL_REVISION}"
)
SSI_REVISION = "8b546ef5dbcd6e806ec1c26a0c05296515798429"
SSI_SOURCE = f"git+https://github.com/ElevenID/ssi-elevenid?rev={SSI_REVISION}#{SSI_REVISION}"
LINKED_DATA_REVISION = "6f86efc1579033e14ff2ad7d115ca0857e16a67f"
LINKED_DATA_SOURCE = (
    f"git+https://github.com/ElevenID/ssi-elevenid?rev={LINKED_DATA_REVISION}#{LINKED_DATA_REVISION}"
)
SD_JWT_REVISION = "9fc75ab0befe6b7f80987acd8b740baead40ee76"
SD_JWT_SOURCE = f"git+https://github.com/ElevenID/sd-jwt-rust?rev={SD_JWT_REVISION}#{SD_JWT_REVISION}"
SD_JWT_FEATURES = {"crypto-provider", "issuer-planning", "issuer-completion", "verifier"}
JWT_VERSION = "11.1.0"
JWT_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
JWT_FEATURES = {"use_pem"}
SSI_COMPANION_PACKAGES = {
    "ssi", "ecdsa", "linked-data", "linked-data-derive",
    "did-ethr", "did-ion", "did-jwk", "did-method-key", "did-pkh", "did-tz", "did-web",
}


def check(metadata: dict, mode: str = "python") -> None:
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    core = [
        package
        for package in metadata["packages"]
        if package["name"] in CORE_CRATES
        or "github.com/ElevenID/marty-core" in (package.get("source") or "")
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
        widened_profile = features & FORBIDDEN_PROFILE_FEATURES.get(name, set())
        if widened_profile:
            raise ValueError(f"{name} enables unselected profile features: {sorted(widened_profile)}")

    isomdl = [package for package in metadata["packages"] if package["name"] == "isomdl"]
    if len(isomdl) != 1 or isomdl[0]["version"] != "0.4.0" or isomdl[0]["source"] != ISOMDL_SOURCE:
        raise ValueError("Expected one reviewed isomdl 0.4.0 package")
    if set(nodes[isomdl[0]["id"]]["features"]) & {"default", "issuer-local-signing"}:
        raise ValueError("isomdl enables local issuer signing")

    sd_jwt = [package for package in metadata["packages"] if package["name"] == "sd-jwt-rs"]
    if len(sd_jwt) != 1 or sd_jwt[0]["version"] != "0.8.0" or sd_jwt[0]["source"] != SD_JWT_SOURCE:
        raise ValueError("Expected one reviewed sd-jwt-rs 0.8.0 package")
    if set(nodes[sd_jwt[0]["id"]]["features"]) != SD_JWT_FEATURES:
        raise ValueError("sd-jwt-rs must retain only the reviewed issuer and verifier roles")

    # A second jsonwebtoken major has separate public key types and a separate
    # process-wide provider. Keep defaults off and reject built-in backends that
    # include private-key operations.
    jwt = [package for package in metadata["packages"] if package["name"] == "jsonwebtoken"]
    if len(jwt) != 1 or jwt[0]["version"] != JWT_VERSION or jwt[0]["source"] != JWT_SOURCE:
        raise ValueError(f"Expected one reviewed jsonwebtoken {JWT_VERSION} package")
    if set(nodes[jwt[0]["id"]]["features"]) != JWT_FEATURES:
        raise ValueError("jsonwebtoken must enable only use_pem and the shared verification provider")

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
