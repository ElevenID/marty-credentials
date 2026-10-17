# Marty Credentials

This repository retains Rust credential bindings, frozen migration contracts, and their tests. The deployed issuance service is Rust owned in [marty-ui](https://github.com/ElevenID/marty-ui); canonical credential and verification libraries are Rust owned in [marty-core](https://github.com/ElevenID/marty-core).

The Python issuance service was retired in [#311](https://github.com/ElevenID/marty-credentials/pull/311). The former `marty_credentials` Python convenience SDK is retired by the source change described in `contracts/python-sdk-retirement-v1.json`. The root `pyproject.toml` now builds an internal metadata-only test harness named `marty-credentials-test-harness`; it does not install an SDK or provide a signing path. Existing immutable Python images and releases remain historical records and the currently pinned production image until the governed beta transition; no new Python issuance image or SDK distribution is published.

## Source layout

- `rust/marty-rs`: local Rust and WASM binding code and tests. Core owns canonical published native wheels.
- `contracts`: frozen issuance behavior and retirement evidence.
- `scripts`: CI dependency-graph and resilient test-launch helpers.
- `tests`: source and contract checks.

## Development checks

```bash
cargo test --locked --manifest-path rust/marty-rs/Cargo.toml --no-default-features --features native
python -m pytest tests/unit
```

For browser or Node.js consumers, build the Rust WASM target directly:

```bash
cd rust/marty-rs
wasm-pack build --locked --target web --no-default-features --features wasm
```

Product deployment and release instructions live in `marty-ui`. The old Credentials Python source distribution, PyPI publisher, and issuance image release path are retired; do not create a new Python package or image from this repository.

Current deployment acceptance is summarized in the
[owner checklist](DEPLOYMENT_CHECKLIST.md). Official and owned interoperability
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

Source-file paths retained in frozen contracts, including the old Python gRPC
stub paths in `issuance-runtime-surface.json`, describe historical provenance.
They are not executable paths in the current checkout. Current wire/schema
validation belongs to the native service owners linked above.

Canvas migration captures and duplicate fixtures are retired here; see
[regression ownership](docs/canvas-regression-ownership.md) for canonical native
fixtures and the retained behavior requirements.
