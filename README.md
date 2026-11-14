# Marty Credentials

This repository retains Rust credential bindings, remaining historical migration references, and binding/source-boundary tests. The deployed issuance service is Rust owned in [marty-ui](https://github.com/ElevenID/marty-ui); canonical credential and verification libraries are Rust owned in [marty-core](https://github.com/ElevenID/marty-core).

The Python issuance service was retired in [#311](https://github.com/ElevenID/marty-credentials/pull/311). The former `marty_credentials` Python convenience SDK is also retired; its supported Rust owners and SDK-only dispositions are documented in [the retirement guide](docs/rust-migrations/full-issuance-python-retirement.md#retired-sdk-ownership). The root `pyproject.toml` now builds an internal metadata-only test harness named `marty-credentials-test-harness`; it does not install an SDK or provide a signing path. Existing immutable Python images and releases remain historical records and the currently pinned production image until the governed beta transition; no new Python issuance image or SDK distribution is published.

## Repository navigation

| Area | Location |
| --- | --- |
| Documentation and ownership | [Documentation index](docs/README.md) |
| Rust and WASM bindings | [rust/](rust/) |
| Source and binding checks | [tests/](tests/) |
| Developer and CI helpers | [scripts/](scripts/) |
| Build access | [Native build access](docs/private-native-builds.md) |
| Deployment acceptance | [Owner checklist](docs/operations/DEPLOYMENT_CHECKLIST.md) |

## Source layout

- `rust/marty-rs`: local Rust and WASM binding code and tests. Core owns canonical published native wheels.
- `contracts`: historical references not yet reconciled with the Rust owner.
  Canonical executable issuance fixtures live in [UI contracts](https://github.com/ElevenID/marty-ui/tree/main/contracts), not mirrored here.
- `scripts`: CI dependency-graph and resilient test-launch helpers.
- `tests`: source and contract checks.

## Reviewed fork integration

The Rust bindings use the same pinned Core, SSI, SD-JWT and isomdl graph as the
native services. CI checks the selected sources, KMS-only features, and the
absence of local issuer signing and unqualified acceleration features. The
`get_ssi_version` compatibility helper reports the umbrella package version in
that SSI source; individual SSI subcrates have independent package versions.

The Python `SdJwtVerifier` and `verify_sd_jwt` compatibility APIs bind the
configured PEM algorithm to the issuer signature. A valid ES256 credential is
rejected when the caller configures ES384, even though both settings can parse
an EC PEM. The existing holder algorithm policy remains separate and uses the
issuer-authenticated `cnf` key. Callers must still establish the PEM key's
authority for the claimed issuer; successful signature verification does not
establish issuer trust or credential-type authorization.

The shared Core verifier supplies the authenticated MSO to mdoc holder checks
and reports unchecked revocation as unknown. These dependency updates preserve
existing credential profiles and key-custody boundaries. They do not activate
new W3C SD-JWT profiles, holder algorithms, or cryptosuites.

The combined graph passed the native check and Python extension build on Rust
1.97.1, all 19 public Python boundary tests, all three mdoc digest integration
tests, and 32 dependency-guard and wheel-pin tests. Native, Python, and WASM
dependency metadata passed the source and KMS feature checks. This is consumer
integration evidence; the WASM target and complete release matrix remain CI
qualification steps.

## Development checks

### Retained mdoc HSM binding

The internal `_marty_rs.prepare_mdoc_for_hsm` binding now retains Core's opaque
`PreparedMdoc` across signing. `get_tbs_data()` returns the complete COSE Sign1
`Sig_structure`; an external ES256 signer must sign those exact bytes and return
a raw 64-byte `r || s` signature. Completion verifies that signature and consumes
the preparation once. An invalid signature leaves the preparation available for
a corrected retry. The returned bytes are canonical **IssuerSigned CBOR**;
holder presentation and device authentication remain separate operations.

This replaces the historical builder API. Pass `issuer_id`,
`verification_method_id`, public `issuer_public_jwk_json`, `doc_type`,
`namespace`, and `claims_json`, followed by optional `expiration_seconds`,
`credential_id`, and public `holder_jwk_json`. Core validates issuer/key binding,
reserves the credential identifier, and owns validity, salts, digests and COSE.
The previous namespace dictionary, absolute validity timestamps,
`device_key_der`, and digest-selection arguments are no longer accepted. One
Core-supported namespace is prepared per credential. `MdocBuilder` and
`MdocSignedDocument` are removed; their reconstructed MSO and empty holder
presentation output are not compatibility formats. The retained function
`complete_mdoc_with_signature(prepared, signature)` delegates to the same
one-use preparation as `prepared.complete_with_signature(signature)`.

The external-signing regression checks the signature and every salted item
digest independently after completion. Run it with the built internal extension
and `pytest`, `cbor2`, and `cryptography` installed:

```bash
python scripts/test_mdoc_hsm_roundtrip.py
```

The runner starts its own disposable TLS OpenBao using the pinned container
image (or an explicitly supplied local `--bao-binary`), marks it before creating
non-exportable test keys, and destroys it on exit. The regression itself refuses
unmarked or non-loopback signing endpoints. Private signing keys never enter the
Python or Rust process.

Native builds use the existing CI with a scoped reader when the Rust forks
are private. See [Native build access](docs/private-native-builds.md) for
authentication, source-cache controls, and local development.

```bash
cargo test --locked --manifest-path rust/marty-rs/Cargo.toml --no-default-features --features native
python -m pytest tests/unit
```

For browser or Node.js consumers, build the Rust WASM target directly:

```bash
cd rust/marty-rs
wasm-pack build --locked --target web --no-default-features --features wasm
```

Open Badges verification uses `open_badge_ob3_verify`. The former
`open_badge_ob2_verify` export is removed. Existing OB2 assertions must be
reissued by their issuer as OB3 credentials; renaming the function or changing
the assertion's context does not migrate the signed credential.

Product deployment and release instructions live in `marty-ui`. The old Credentials Python source distribution, PyPI publisher, and issuance image release path are retired; do not create a new Python package or image from this repository.

Current deployment acceptance is summarized in the
[owner checklist](docs/operations/DEPLOYMENT_CHECKLIST.md). Official and owned interoperability
workflows live in [marty-integration-tests](https://github.com/ElevenID/marty-integration-tests);
the retired migration receipt and its old local Compose commands are not a
supported test entrypoint.

## License

Dual-licensed under MIT OR Apache-2.0.

The historical Python capture, pre-deletion qualification tools and generated
gRPC stubs are retired. Frozen JSON observations remain available for native
regression checks. Current issuance wire-field and transport checks live with
the Rust owner in [marty-ui](https://github.com/ElevenID/marty-ui), including
`tests/test_proto_descriptor_parity.py` and the issuance gRPC behavior suites.
Retiring these historical tools grants no deployment or cutover authorization.

Historical source inventories, including the old Python gRPC stub paths, are
retained in Git history rather than current executable source. The
[migration roadmap](docs/RUST_ISSUANCE_MIGRATION_ROADMAP.md#frozen-baseline)
links the last snapshot. Current wire/schema validation belongs to the native
service owners linked above.

Canvas migration captures and duplicate fixtures are retired here; see
[regression ownership](docs/canvas-regression-ownership.md) for canonical native
fixtures and the retained behavior requirements.
