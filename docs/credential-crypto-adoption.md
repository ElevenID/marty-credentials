# Shared crypto provider and credential compatibility

Credentials consumes Core and the reviewed SD-JWT fork as one dependency graph.
The JWT 11 migration keeps the complete dependency proposal from
[PR #338](https://github.com/ElevenID/marty-credentials/pull/338): jsonwebtoken
11.1.0 and pyo3, pyo3-build-config, pyo3-ffi, pyo3-macros and
pyo3-macros-backend 0.29.3. It also needs the matching Core migration and the
same SD-JWT revision in both Core and Credentials. Mixing JWT majors would give
the bindings different public-key types and separate provider state.

## Python compatibility boundaries

`SdJwtVerifier.verify` and `verify_sd_jwt` retain SHA-256 admission. The generic
fork can verify SHA-384 and SHA-512 disclosures, but that capability does not
expand this compatibility profile. After the fork successfully authenticates
the presentation, the binding reads `SDJWTVerifier::digest_algorithm()` and
requires `SDJWTDigestAlgorithm::Sha256`. The getter reports the algorithm stored
by the verifier, including the SHA-256 default when the signed selector is
absent. The binding neither reparses the JWT nor infers the selector from the
reconstructed claims, which omit `_sd_alg`. Signature failure keeps precedence
over the profile rejection.

Configured issuer-signature algorithms, the string `iss` boundary, and the
separate issuer-authenticated holder-key policy remain in force. The caller
still owns the decision that the supplied public PEM is authoritative for the
issuer. PEM parsing uses public-key constructors; signing and private-key
encoding are not part of this binding.

`MdocDocumentVerificationEvidence.status_references` projects Core's signed MSO
references into read-only `MdocStatusReference` objects:

| `kind` | `uri` | `index` | `identifier` | `certificate_der` |
| --- | --- | --- | --- | --- |
| `STATUS_LIST` | Signed URI | Unsigned 64-bit list index | `None` | Optional signed DER bytes |
| `IDENTIFIER_LIST` | Signed URI | `None` | Opaque identifier bytes | Optional signed DER bytes |

There is no public constructor or setter. The projection preserves the bytes;
it does not retrieve the URI, make the referenced certificate trusted, or
evaluate a status list. Issuer trust and holder authentication remain separate
results. Offline evidence continues to report `revocation_checked == False`
and `not_revoked is None`. The `mdoc-status-verification` feature remains
unselected in the Credentials graph.

## Dependency update and qualification

The source adapters must land with accepted, matching Core and SD-JWT revisions.
Do not substitute local commits or introduce a second JWT/SD-JWT implementation
to make type checking succeed. Update the five workspace Core dependencies,
both Core compatibility patches, the direct SD-JWT dependency, the reviewed
graph constants, and both workflow Core wheel revisions together. Resolve the
root lockfile with the full PR #338 proposal preserved. The separately checked
out Core wheel workspace keeps its own lockfile. CI uses `--locked` and must not
regenerate either lockfile.

`scripts/ci/check_core_kms_graph.py` checks Python, native and WASM metadata. It
requires exactly one reviewed jsonwebtoken 11.1.0 with only `use_pem`; built-in
`aws_lc_rs` and `rust_crypto` provider features remain disabled. The reviewed
SD-JWT graph selects only `crypto-provider`, `issuer-planning`,
`issuer-completion` and `verifier`. Holder, benchmark, mock-salt, parallel, local
issuer-key, and unselected Core profile capabilities remain rejected. The
fork's verification backend may depend on `aws-lc-rs` directly; that is distinct
from selecting jsonwebtoken's built-in provider.

Use the repository's Rust 1.97.1 toolchain, unchanged MSRV 1.95 and Maturin
1.14.1. Source guard tests are useful before resolution, but they do not prove
the actual dependency graph or compile the Python-only adapters. Required
consumer qualification includes:

```bash
cargo check --locked --manifest-path rust/marty-rs/Cargo.toml --no-default-features --features native
cargo test --locked --manifest-path rust/marty-rs/Cargo.toml --lib --no-default-features --features native
cargo test --locked --manifest-path rust/marty-rs/Cargo.toml --doc --no-default-features --features native
cargo test --locked --manifest-path rust/marty-rs/Cargo.toml --test isomdl_digest_semantics --no-default-features --features isomdl-digest-tests
cargo clippy --locked --manifest-path rust/marty-rs/Cargo.toml --no-default-features --features native -- -D warnings
maturin build --locked --manifest-path rust/marty-rs/Cargo.toml --no-default-features --features python --out local-wheels
```

Install the resulting internal extension into an isolated Python environment,
then run `pytest rust/marty-rs/tests/python -v`, the existing owned OpenBao HSM
roundtrip, and the source/graph guards. The Python boundary test environment
requires `pytest`, `cbor2`, `cryptography` and `defusedxml`; the last dependency
parses the owned pytest result used to reject skipped status cases. Retain all existing WASM web, Node.js,
bundler and Node test jobs; a native build does not qualify those targets.

The `Local Marty Python Binding` CI job also checks out the exact
`MARTY_CORE_REVISION`, fetches its own locked graph, and prebuilds Core's
verification test executable with `kms-only,mdoc-status-verification`. Cargo's
JSON build output must identify exactly one library test artifact from that
checkout's `marty-verification/Cargo.toml` inside the dedicated target directory.
This separate fixture-generator test build does not enable status verification
in the Credentials production graph. Both native artifacts are built before
the disposable KMS is created.

The checked-in `sd_jwt_multi_digest_public.json` fixture is unchanged from
Core commit `64601c9513850e3eb60b00f6aa893cae8d9e4b0d`, at
`marty-oid4vci/tests/fixtures/sd_jwt_multi_digest_public.json`. Its original
signing keys remained non-exportable in a disposable OpenBao instance. Python
tests exercise real SHA-256 acceptance, SHA-384/SHA-512 profile rejection, and
tampered-signature precedence through both compatibility entry points.

The public RSA fixture preserves the compact JWS and only the public `n`/`e`
parameters from [RFC 7515 Appendix A.2](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.2).
Its published payload has `exp: 1300819380`. The Python regression requires the
specific post-signature `ExpiredSignature` rejection for the unchanged RS256
vector, and earlier rejection for altered signatures or mismatched configured
algorithms. This proves the public RSA PEM verification path and expiry
precedence, not successful credential admission. The test changes neither the
signed payload nor the clock or product policy, and contains no signing key.

Nonempty mdoc projection tests use Core's existing
`managed_keys_verify_both_status_mechanisms_and_fail_closed` regression. Its
opt-in public export contains separately signed status-list and identifier-list
presentations, public roots and a session transcript. Set
`MARTY_TEST_MDOC_STATUS_PUBLIC_FIXTURE_DIR` to a fresh owned absolute directory
and `MARTY_TEST_MDOC_STATUS_HTTPS_ORIGIN` to the explicit owned loopback origin
when running that regression through Core's disposable OpenBao harness. The
Credentials harness automates the same lifecycle with its narrow option:

```bash
python scripts/test_mdoc_hsm_roundtrip.py --core-status-test-binary /absolute/path/to/prebuilt/marty_verification-test
```

An explicit `--bao-binary /absolute/path/to/bao` uses the existing local TLS
OpenBao path instead of the pinned container. Before allocating KMS resources,
the runner requires the exact fully qualified Core test in executable test
discovery. It creates a fresh fixture directory, runs only that managed-signing
test, and executes the Python cases within the 600-second MSO validity window.
The CI job requires this option. The runner also checks the JUnit result for all
eight expected status cases and rejects omissions, duplicates, failures and
skips.

For manual execution against an already generated fresh public export, leave
`MARTY_TEST_MDOC_STATUS_PUBLIC_FIXTURE_DIR` set and run
`python -m pytest rust/marty-rs/tests/python/test_shared_mdoc_verifier.py -v`.
With a supplied directory, missing or invalid exports fail; no synthetic
evidence is substituted. The eight external-fixture cases exercise all three mdoc bindings,
both reference kinds, opaque byte preservation, read-only fields, independent
issuer/holder checks and unknown revocation. They skip only when no fixture
directory was supplied, so a normal Python pass without the export does not
constitute nonempty signed-status parity. Do not check in these short-lived
fixtures or claim status-authority/network qualification from these data
projection tests.
