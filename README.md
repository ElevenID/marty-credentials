# Marty Credentials

Credential domain logic and adapters for the Marty ecosystem. This package provides:

- **Port Interfaces**: Abstract contracts for credential operations (issuance, verification, wallet, key management)
- **Adapters**: Concrete implementations using SpruceID, Multipaz, and other credential libraries
- **Rust FFI**: Python bindings for high-performance cryptographic operations via `marty-rs`

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

## License

Dual-licensed under MIT OR Apache-2.0.
