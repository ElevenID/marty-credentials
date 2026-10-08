# Marty Credentials

This repository retains Rust credential bindings, frozen migration contracts, and their tests. The deployed issuance service is Rust owned in [marty-ui](https://github.com/ElevenID/marty-ui); canonical credential and verification libraries are Rust owned in [marty-core](https://github.com/ElevenID/marty-core).

The Python issuance service was retired in [#311](https://github.com/ElevenID/marty-credentials/pull/311). The former `marty_credentials` Python convenience SDK is retired by the source change described in `contracts/python-sdk-retirement-v1.json`. The root `pyproject.toml` now builds an internal metadata-only test harness named `marty-credentials-test-harness`; it does not install an SDK or provide a signing path. Existing immutable Python images and releases remain historical records and the currently pinned production image until the governed beta transition; no new Python issuance image or SDK distribution is published.

## Source layout

- `rust/marty-rs`: local Rust and WASM binding code and tests. Core owns canonical published native wheels.
- `contracts`: frozen issuance behavior and retirement evidence.
- `scripts`: migration evidence and source verification tools.
- `tests`: source and contract checks.

## Development checks

```bash
cargo test --locked --manifest-path rust/marty-rs/Cargo.toml --no-default-features --features native
python -m pytest tests/unit packages/tests
```

For browser or Node.js consumers, build the Rust WASM target directly:

```bash
cd rust/marty-rs
wasm-pack build --locked --target web --no-default-features --features wasm
```

Product deployment and release instructions live in `marty-ui`. The old Credentials Python source distribution, PyPI publisher, and issuance image release path are retired; do not create a new Python package or image from this repository.

## License

Dual-licensed under MIT OR Apache-2.0.
