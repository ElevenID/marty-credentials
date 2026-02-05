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

This package depends on [marty-core](https://github.com/adamburdett/marty-core) for cryptographic primitives:

- `marty-crypto`: Low-level cryptographic operations
- `marty-verification`: Trust chain verification
- `marty-secure-storage`: Encrypted credential storage

## Release Process

This repository uses an automated release pipeline synchronized with marty-core:

### Automated Releases

When marty-core releases a new version:
1. This repository is automatically notified
2. Dependencies in `rust/marty-rs/Cargo.toml` are updated
3. Full test suite runs (Rust + Python + WASM)
4. If tests pass: Version bumps and new release created automatically
5. If tests fail: GitHub Issue created for manual intervention

### Manual Releases

```bash
# Create RC tag
git tag v0.2.0-rc.1
git push origin v0.2.0-rc.1

# This triggers build of:
# - Python wheels (Linux/macOS/Windows × x86_64/aarch64)
# - WASM packages (web/nodejs/bundler targets)
# - Python source distribution

# After testing, promote to stable
git tag v0.2.0
git push origin v0.2.0
```

### Artifacts

Each release produces:
- **Python wheels** for multiple platforms (manylinux, macOS, Windows)
- **WASM packages** for browser and Node.js
- **Source distribution** (.tar.gz)
- **SHA256 checksums** for all artifacts

All artifacts are published to **GitHub Releases only** (not PyPI or npm).

### Building from Source

**Python wheels with Rust bindings:**
```bash
pip install maturin
cd rust/marty-rs
maturin build --release --features python
```

**WASM packages:**
```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

cd rust/marty-rs
wasm-pack build --target web --features wasm
```

**Pure Python package:**
```bash
pip install build
python -m build --sdist
```

## License

Dual-licensed under MIT OR Apache-2.0.
