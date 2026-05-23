# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased] - 2026-05-23

### Bug Fixes

- **status-list**: Use PyModule::new_bound for PyO3 0.22 compatibility ([432f25a](432f25a048fcc51f2aad076d6e2840f37f5228c9))
- Checkout marty-core in CI for path dependencies ([31c7834](31c78342a38cf368ab45f77f6b800bf3c488733d))
- Correct GitHub Packages URL in beta workflow ([6d2d752](6d2d752349fd7be207c59796d4ea59c6ca2ec840))
- **issuance**: Walt.id OID4VCI compatibility fixes ([0379543](0379543c031ce2753ecdd0746af77ac1572499dc))

### Documentation

- Integration tests moved to marty-integration-tests repo ([6b88418](6b884188ade7855bd162e7fd398c2b294162b44b))

### Features

- **rust**: Add mDoc/mDL issuance and presentation adapters ([d8d8f4d](d8d8f4dd1995eb96ed0b98a72b48400b1497e994))
- **crypto**: Add RSA key algorithm support (RS256/384/512, PS256/384/512) ([25e2100](25e2100576baef2e1db57834b89b75838882960e))
- Add automated release pipeline for Python/WASM packages ([4da17ef](4da17efec7e5c8cc52b65d5f065f6152ea35f9d2))
- Add beta release workflow with multi-platform marty-rs wheels ([52f4553](52f4553c4bfc8964d630a89835bc11b5b3a7a212))
- Comprehensive credential management enhancements ([f3c800f](f3c800ff7e96a8d59629241082af905adf087046))
- Add zero-knowledge proof verification infrastructure ([4c4f3a7](4c4f3a7938c145c55089afbf34fa4746cacd79e5))
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing) ([fe5761f](fe5761f8e1160de925d22d64d21b70c87c8a94c0))
- Add issuance events table, required checks migrations, and update issuance domain ([700ee5d](700ee5daeb32a1d7872d69597a46a1b22dac9e3c))
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint ([932fdba](932fdba70963372558e8e9ec661686275f5409e6))
- **issuance**: Add OID4VCI support and persistence layer improvements ([f347cfb](f347cfb72a30980728b6a7effba0c006a888ec5e))
- **issuance,verification**: Expand OID4VCI routes, refactor verifier, add BDD conformance test suites ([7a70cfe](7a70cfe4ce5bf09b7e306488ebbfa36cf54402c3))
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements ([5166a8a](5166a8acefe8296c253563fcb595a149527fce19))
- **issuance+verification**: Credential management, deferred fix, MIP 26 models ([7ffc688](7ffc688d631b8e2afb8604316331c1ce1f914186))
- Add explicit issuer selection and canvas issuance support ([8b0f53d](8b0f53d57fa1d27c7c3cf03c92b7aea8cd9f92f7))
- Canvas lti integration, evidence flow, delivery records, and migrations ([ba438b1](ba438b1eb88c6682d5ad52fb81cb4d8c196d9080))

### Miscellaneous Tasks

- Remove Multipaz adapter ([0f34796](0f347964422e0bacc9817a6c6299c05823c85457))
- Update CHANGELOG.md ([b038de3](b038de3a9a771376e24c393255d9292159986f58))
- Update CHANGELOG.md ([ace7a48](ace7a4854dec3c26da13915e94f115df7d969273))
- Update CHANGELOG.md ([5914e56](5914e56c3cefcc4f5e1e1b2121ad41184b4d0d85))
- Update CHANGELOG.md ([e2dbb8d](e2dbb8d691dd5585dbf0c99615d1c1715c985776))
- Update CHANGELOG.md ([663dcb2](663dcb2935bdceb73d998738b6790fc622f680f3))
- Update CHANGELOG.md ([ff9c369](ff9c3692f19e5a4bf0cb2e49610d0c2538d79870))
- Update CHANGELOG.md ([2e0753d](2e0753d45e9397fc96fde9488fad513adc8bfb39))
- Update CHANGELOG.md ([3ff878c](3ff878c750633f60e79286d57f3385acd6377d61))
- Update CHANGELOG.md ([6d62f87](6d62f87daf931901e68efbc182aeae5e39360fd2))
- Update CHANGELOG.md ([a7757a9](a7757a995530869bf9c159ce60f16578d88637f2))
- Update CHANGELOG.md ([7b2903a](7b2903a0fd2551de590d6ade3a97b2ceee4aac46))
- Convert marty-core path deps to git deps ([f2915fb](f2915fbc4b86493da8efcea354a798a0119ffa98))
- Update CHANGELOG.md ([0877e76](0877e76a82aeaa6a0b34da78a3640a341237b875))
- Update CHANGELOG.md ([68f2c19](68f2c19fb5d574a59464a2e9f1bb76a4f32eb8f7))
- Update CHANGELOG.md ([51b94ce](51b94cea34718b6b3c1a500705e2f3ac409c2c7a))
- Sync working state for dev environment migration ([a8c3173](a8c31739b2559cb837f164103db50c7b6d8c3421))
- Update CHANGELOG.md ([bf1e721](bf1e721f7c2573817f5e2522fc8787d18157fe7e))
- Workspace sync 2026-04-14 ([7c7ca81](7c7ca81e1b2a42091621191efb1500838ba55af8))
- Update CHANGELOG.md ([0a9dca1](0a9dca1bbcb29c347861044136f7363da4b2047b))
- Update CHANGELOG.md ([e4cc9e8](e4cc9e857ef51636425b6e654f41b6855ea496e3))

### Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing ([2325e14](2325e1483bb252c924d856a957d884dbcbb9df5d))
- Remove integration tests (moved to marty-integration-tests repo) ([e598273](e598273ce36833f611f6b2e5176352cb888f7c62))

### Security

- Add comprehensive security and quality checks ([a12db86](a12db866f9a701ede5e13d3308d48fb904590d51))
- Make security checks non-blocking to prevent repeated failures ([0b437ac](0b437accdb39ee671b1e654dddd4e18aea6c9058))

### Build

- **deps**: Upgrade to SSI 0.12 and update dependencies ([f986467](f986467d188a4df6ec6978a6ef79ce43c2e2c0ed))

### Ci

- Add git auth for private repo Cargo deps ([e7a246a](e7a246ade3402e23ec412046de86c59f9ab35d24))

## [unreleased] - 2026-05-12

### Bug Fixes

- **status-list**: Use PyModule::new_bound for PyO3 0.22 compatibility ([432f25a](432f25a048fcc51f2aad076d6e2840f37f5228c9))
- Checkout marty-core in CI for path dependencies ([31c7834](31c78342a38cf368ab45f77f6b800bf3c488733d))
- Correct GitHub Packages URL in beta workflow ([6d2d752](6d2d752349fd7be207c59796d4ea59c6ca2ec840))
- **issuance**: Walt.id OID4VCI compatibility fixes ([0379543](0379543c031ce2753ecdd0746af77ac1572499dc))

### Documentation

- Integration tests moved to marty-integration-tests repo ([6b88418](6b884188ade7855bd162e7fd398c2b294162b44b))

### Features

- **rust**: Add mDoc/mDL issuance and presentation adapters ([d8d8f4d](d8d8f4dd1995eb96ed0b98a72b48400b1497e994))
- **crypto**: Add RSA key algorithm support (RS256/384/512, PS256/384/512) ([25e2100](25e2100576baef2e1db57834b89b75838882960e))
- Add automated release pipeline for Python/WASM packages ([4da17ef](4da17efec7e5c8cc52b65d5f065f6152ea35f9d2))
- Add beta release workflow with multi-platform marty-rs wheels ([52f4553](52f4553c4bfc8964d630a89835bc11b5b3a7a212))
- Comprehensive credential management enhancements ([f3c800f](f3c800ff7e96a8d59629241082af905adf087046))
- Add zero-knowledge proof verification infrastructure ([4c4f3a7](4c4f3a7938c145c55089afbf34fa4746cacd79e5))
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing) ([fe5761f](fe5761f8e1160de925d22d64d21b70c87c8a94c0))
- Add issuance events table, required checks migrations, and update issuance domain ([700ee5d](700ee5daeb32a1d7872d69597a46a1b22dac9e3c))
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint ([932fdba](932fdba70963372558e8e9ec661686275f5409e6))
- **issuance**: Add OID4VCI support and persistence layer improvements ([f347cfb](f347cfb72a30980728b6a7effba0c006a888ec5e))
- **issuance,verification**: Expand OID4VCI routes, refactor verifier, add BDD conformance test suites ([7a70cfe](7a70cfe4ce5bf09b7e306488ebbfa36cf54402c3))
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements ([5166a8a](5166a8acefe8296c253563fcb595a149527fce19))
- **issuance+verification**: Credential management, deferred fix, MIP 26 models ([7ffc688](7ffc688d631b8e2afb8604316331c1ce1f914186))
- Add explicit issuer selection and canvas issuance support ([8b0f53d](8b0f53d57fa1d27c7c3cf03c92b7aea8cd9f92f7))

### Miscellaneous Tasks

- Remove Multipaz adapter ([0f34796](0f347964422e0bacc9817a6c6299c05823c85457))
- Update CHANGELOG.md ([b038de3](b038de3a9a771376e24c393255d9292159986f58))
- Update CHANGELOG.md ([ace7a48](ace7a4854dec3c26da13915e94f115df7d969273))
- Update CHANGELOG.md ([5914e56](5914e56c3cefcc4f5e1e1b2121ad41184b4d0d85))
- Update CHANGELOG.md ([e2dbb8d](e2dbb8d691dd5585dbf0c99615d1c1715c985776))
- Update CHANGELOG.md ([663dcb2](663dcb2935bdceb73d998738b6790fc622f680f3))
- Update CHANGELOG.md ([ff9c369](ff9c3692f19e5a4bf0cb2e49610d0c2538d79870))
- Update CHANGELOG.md ([2e0753d](2e0753d45e9397fc96fde9488fad513adc8bfb39))
- Update CHANGELOG.md ([3ff878c](3ff878c750633f60e79286d57f3385acd6377d61))
- Update CHANGELOG.md ([6d62f87](6d62f87daf931901e68efbc182aeae5e39360fd2))
- Update CHANGELOG.md ([a7757a9](a7757a995530869bf9c159ce60f16578d88637f2))
- Update CHANGELOG.md ([7b2903a](7b2903a0fd2551de590d6ade3a97b2ceee4aac46))
- Convert marty-core path deps to git deps ([f2915fb](f2915fbc4b86493da8efcea354a798a0119ffa98))
- Update CHANGELOG.md ([0877e76](0877e76a82aeaa6a0b34da78a3640a341237b875))
- Update CHANGELOG.md ([68f2c19](68f2c19fb5d574a59464a2e9f1bb76a4f32eb8f7))
- Update CHANGELOG.md ([51b94ce](51b94cea34718b6b3c1a500705e2f3ac409c2c7a))
- Sync working state for dev environment migration ([a8c3173](a8c31739b2559cb837f164103db50c7b6d8c3421))
- Update CHANGELOG.md ([bf1e721](bf1e721f7c2573817f5e2522fc8787d18157fe7e))
- Workspace sync 2026-04-14 ([7c7ca81](7c7ca81e1b2a42091621191efb1500838ba55af8))
- Update CHANGELOG.md ([0a9dca1](0a9dca1bbcb29c347861044136f7363da4b2047b))

### Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing ([2325e14](2325e1483bb252c924d856a957d884dbcbb9df5d))
- Remove integration tests (moved to marty-integration-tests repo) ([e598273](e598273ce36833f611f6b2e5176352cb888f7c62))

### Security

- Add comprehensive security and quality checks ([a12db86](a12db866f9a701ede5e13d3308d48fb904590d51))
- Make security checks non-blocking to prevent repeated failures ([0b437ac](0b437accdb39ee671b1e654dddd4e18aea6c9058))

### Build

- **deps**: Upgrade to SSI 0.12 and update dependencies ([f986467](f986467d188a4df6ec6978a6ef79ce43c2e2c0ed))

### Ci

- Add git auth for private repo Cargo deps ([e7a246a](e7a246ade3402e23ec412046de86c59f9ab35d24))

## [unreleased] - 2026-04-14

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint
- *(issuance)* Add OID4VCI support and persistence layer improvements
- *(issuance,verification)* Expand OID4VCI routes, refactor verifier, add BDD conformance test suites
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements
- *(issuance+verification)* Credential management, deferred fix, MIP 26 models

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow
- *(issuance)* Walt.id OID4VCI compatibility fixes

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Convert marty-core path deps to git deps
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add git auth for private repo Cargo deps
- Update CHANGELOG.md
- Sync working state for dev environment migration
- Update CHANGELOG.md
- Workspace sync 2026-04-14
## [unreleased] - 2026-04-10

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint
- *(issuance)* Add OID4VCI support and persistence layer improvements
- *(issuance,verification)* Expand OID4VCI routes, refactor verifier, add BDD conformance test suites
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements
- *(issuance+verification)* Credential management, deferred fix, MIP 26 models

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow
- *(issuance)* Walt.id OID4VCI compatibility fixes

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Convert marty-core path deps to git deps
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add git auth for private repo Cargo deps
- Update CHANGELOG.md
- Sync working state for dev environment migration
## [unreleased] - 2026-03-27

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint
- *(issuance)* Add OID4VCI support and persistence layer improvements
- *(issuance,verification)* Expand OID4VCI routes, refactor verifier, add BDD conformance test suites
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements
- *(issuance+verification)* Credential management, deferred fix, MIP 26 models

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow
- *(issuance)* Walt.id OID4VCI compatibility fixes

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Convert marty-core path deps to git deps
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add git auth for private repo Cargo deps
## [unreleased] - 2026-03-27

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint
- *(issuance)* Add OID4VCI support and persistence layer improvements
- *(issuance,verification)* Expand OID4VCI routes, refactor verifier, add BDD conformance test suites
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements
- *(issuance+verification)* Credential management, deferred fix, MIP 26 models

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow
- *(issuance)* Walt.id OID4VCI compatibility fixes

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Convert marty-core path deps to git deps
- Update CHANGELOG.md
## [unreleased] - 2026-03-27

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint
- *(issuance)* Add OID4VCI support and persistence layer improvements
- *(issuance,verification)* Expand OID4VCI routes, refactor verifier, add BDD conformance test suites
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow
- *(issuance)* Walt.id OID4VCI compatibility fixes

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Convert marty-core path deps to git deps
## [unreleased] - 2026-03-18

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint
- *(issuance)* Add OID4VCI support and persistence layer improvements
- *(issuance,verification)* Expand OID4VCI routes, refactor verifier, add BDD conformance test suites
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow
- *(issuance)* Walt.id OID4VCI compatibility fixes

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
## [unreleased] - 2026-03-12

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint
- *(issuance)* Add OID4VCI support and persistence layer improvements
- *(issuance,verification)* Expand OID4VCI routes, refactor verifier, add BDD conformance test suites

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow
- *(issuance)* Walt.id OID4VCI compatibility fixes

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
## [unreleased] - 2026-03-02

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain
- Add SpruceID-compatible /spruce OID4VCI metadata endpoint
- *(issuance)* Add OID4VCI support and persistence layer improvements

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow
- *(issuance)* Walt.id OID4VCI compatibility fixes

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
## [unreleased] - 2026-02-18

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)
- Add issuance events table, required checks migrations, and update issuance domain

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
## [unreleased] - 2026-02-05

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing
- Remove integration tests (moved to marty-integration-tests repo)

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
- Update CHANGELOG.md
## [unreleased] - 2026-02-05

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing

### 📚 Documentation

- Integration tests moved to marty-integration-tests repo

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
- Update CHANGELOG.md
## [unreleased] - 2026-02-05

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure
- Add walt.id integration tests with Rust crypto signing (9/10 tests passing)

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
- Update CHANGELOG.md
## [unreleased] - 2026-02-02

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages
- Add beta release workflow with multi-platform marty-rs wheels
- Comprehensive credential management enhancements
- Add zero-knowledge proof verification infrastructure

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies
- Correct GitHub Packages URL in beta workflow

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### 🚜 Refactor

- Migrate behave tests from Pact HTTP mocking to direct service testing

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
- Update CHANGELOG.md
- Make security checks non-blocking to prevent repeated failures
## [unreleased] - 2026-01-10

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
- Update CHANGELOG.md
- Add comprehensive security and quality checks
## [unreleased] - 2026-01-08

### 🚀 Features

- *(rust)* Add mDoc/mDL issuance and presentation adapters
- *(crypto)* Add RSA key algorithm support (RS256/384/512, PS256/384/512)
- Add automated release pipeline for Python/WASM packages

### 🐛 Bug Fixes

- *(status-list)* Use PyModule::new_bound for PyO3 0.22 compatibility
- Checkout marty-core in CI for path dependencies

### 💼 Other

- *(deps)* Upgrade to SSI 0.12 and update dependencies

### ⚙️ Miscellaneous Tasks

- Remove Multipaz adapter
- Update CHANGELOG.md
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
