## [unreleased] - 2026-01-08

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-07

### Added
- Initial release of marty-credentials Python package
- Pure Python adapter architecture for credential management
- Optional Rust FFI bindings for performance
- SSI credential verification and issuance
- Digital wallet functionality
- Key management abstractions
- SpruceID and Multipaz adapter support
