# Issuance retention Python retirement

Status: local preparation only. The two native retention routes are in reviewed
`ElevenID/marty-ui#849`, but are not yet on protected `main`; their Python
owners must remain until its exact-head and merge-group gates pass and its
published-image dependency is verified. The prior OID4VCI/Canvas retirement
landed as `ElevenID/marty-credentials#298` at
`af041c2c3bd2e9fae189b566499146f97156120f`, with a qualified gate. This
separate retention qualification deliberately has no source commit or artifact
hashes yet and fails closed.
When the gate can qualify, pin artifact SHA-256 values from committed Git
blobs, not platform-converted checkout files.

The local deletion is exactly the GET retention summary and POST retention
purge handlers, their response-only models, and their now-unreferenced memory
and PostgreSQL repository methods. Their Python-only HTTP and PostgreSQL tests
are replaced by a retirement guard here and the language-neutral route,
validation, repository, and real-PostgreSQL contracts in `marty-ui#849`.
`contracts/issuance-retention-management.json` remains frozen here. The Rust
PostgreSQL contract covers tenant scope, expired parent/child purge, and
preservation of younger event ownership.

Do not delete shared issuance records, tables, migrations, event-owner storage,
or the PostgreSQL `_result_rowcount` helper: other live repository operations
still use that helper. The nine physical-passport HTTP routes, DIDComm delivery,
and all unrelated issuance features remain Python-owned until separately
qualified. No beta or production deployment is authorized by this local
preparation.

Local exact-head preparation gates: 1,648 unit tests passed, five skipped, with 200
subtests passed in an isolated Starlette 1.7.0 environment; the route/surface
guard and fail-closed qualification tests are included. The broader
`tests/test_issuance_changes.py` module initially reported nine native SD-JWT
binding failures with the machine's stale `marty-rs` 0.1.60. After installing
the repository's checksum-pinned Windows `marty-rs` 0.2.0 wheel into the
isolated test environment, the exact-head module passed: 124 passed, 21
skipped. The pinned binding exposes the expected issuer-public-JWK argument.
A fresh hosted dependency gate remains required before merge.

A separate plain `pytest tests/unit` collection with pinned `marty-rs` 0.2.0
currently stops in two legacy adapter boundary modules: the compatibility
`marty_credentials.adapters.services` package still imports removed raw-key
capabilities (`create_verifiable_credential` and `generate_p256_jwk`). Its
production-consumer status and migration path are tracked in
`ElevenID/marty-credentials#297`; the passing 1,648
unit-test checkpoint above must not be treated as covering that collection.
