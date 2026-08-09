# Marty Credentials

Credential domain logic and adapters for the Marty ecosystem. This package provides:

- **Port Interfaces**: Abstract contracts for credential operations (issuance, verification, wallet, key management)
- **Adapters**: Concrete implementations using SpruceID, Multipaz, and other credential libraries
- **Rust FFI**: Python bindings for high-performance cryptographic operations via `marty-rs`

> **Note**: Integration tests have been moved to a separate repository: [marty-integration-tests](https://github.com/ElevenID/marty-integration-tests)

## Architecture

```
marty-credentials/
├── python/
│   └── marty_credentials/
│       ├── ports/           # Abstract port interfaces
│       │   ├── __init__.py
│       │   ├── key_manager.py
│       │   ├── issuer.py
│       │   ├── verifier.py
│       │   └── wallet.py
│       └── adapters/        # Concrete implementations
│           ├── __init__.py
│           ├── spruceid/
│           ├── multipaz/
│           └── persistence/
├── rust/
│   └── marty-rs/           # Rust FFI bindings (PyO3)
├── docs/
└── tests/
```

## Installation

```bash
pip install marty-credentials
```

For Rust FFI support (requires Rust toolchain):

```bash
pip install marty-credentials[ffi]
```

## Usage

### Port Interfaces

```python
from marty_credentials.ports import IKeyManager, ICredentialIssuer

class MyKeyManager(IKeyManager):
    async def generate_key_pair(self, algorithm: str) -> KeyPair:
        ...
```

### Adapters

```python
from marty_credentials.adapters.spruceid import SpruceIDAdapter

adapter = SpruceIDAdapter()
credential = await adapter.issue_credential(claims, key_pair)
```

## Relationship to Marty Core

This package depends on [marty-core](https://github.com/ElevenID/marty-core) for cryptographic primitives:

- `marty-crypto`: Low-level cryptographic operations
- `marty-verification`: Trust chain verification
- `marty-secure-storage`: Encrypted credential storage

## Release Process

Stable releases are tag-driven, fail closed, and use only commits already on
`main`. The version in `Cargo.toml` and the locked `marty-rs` package must match
the tag before any artifact is built.

### Stable Releases

```bash
# After the version change and its checks are merged to main:
git fetch origin main
git tag -a v0.2.0 origin/main -m "marty-credentials v0.2.0"
git push origin refs/tags/v0.2.0
```

The stable workflow runs Rust and Python tests, builds the exact Python, WASM,
and source artifact set, attests it, and creates a draft release. A separate
workflow loaded only from protected `main` builds both service images by
digest, signs and attests them, creates their SBOMs, verifies every draft asset,
and publishes the release exactly once. Published releases are immutable and
`v*` tags cannot be updated or deleted.

If the stable workflow must be started manually before it creates a draft, run
it from the tag itself:

```bash
gh workflow run release-stable.yml --ref v0.2.0 -f tag=v0.2.0
```

If a valid draft already exists, resume only the finalizer from protected
`main`, using the draft's numeric release ID and the tag's fully dereferenced
commit SHA:

```bash
gh workflow run release-images.yml --ref main \
  -f tag=v0.2.0 \
  -f release_id=<release-id> \
  -f commit_sha=<40-character-commit-sha>
```

Never move or recreate a release tag. A conflicting draft asset or image tag is
an integrity failure that must be investigated rather than overwritten.

### Artifacts

Each release produces:
- **Python wheels** for multiple platforms (manylinux, macOS, Windows)
- **WASM packages** for browser and Node.js
- **Source distribution** (.tar.gz)
- **Service images** for issuance and verification, pinned by digest in GHCR
- **SBOMs, SHA256 checksums, Sigstore signatures, and GitHub provenance**

GitHub Releases and GHCR are the canonical artifact sources. PyPI publication
starts only after the immutable GitHub release is published and remains gated
by the `ENABLE_PUBLIC_REGISTRY_PUBLISHING` repository variable and the protected
`pypi` environment.

If that optional PyPI step needs a manual retry, run the reusable publisher from
protected `main` with the same tag, release ID, and commit SHA shown above:

```bash
gh workflow run publish-pypi.yml --ref main \
  -f tag=v0.2.0 \
  -f release_id=<release-id> \
  -f commit_sha=<40-character-commit-sha>
```

### Building from Source

**Python wheels with Rust bindings:**
```bash
python -m pip install maturin==1.14.1
cd rust/marty-rs
maturin build --locked --release --features python
```

**WASM packages:**
```bash
cargo install wasm-pack --version 0.15.0 --locked

cd rust/marty-rs
wasm-pack build --locked --target web --no-default-features --features wasm
```

**Pure Python package:**
```bash
pip install build
python -m build --sdist
```

## License

Dual-licensed under MIT OR Apache-2.0.
