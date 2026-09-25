# Issuance retention Python retirement

Status: local preparation only. The two native retention routes are still in
draft `ElevenID/marty-ui#849`; their Python owners must remain until the Rust
source lands on protected `main`, exact-head gates and a published-image
dependency pass, and the prior OID4VCI/Canvas retirement is qualified. The
new qualification contract deliberately has no source commit or artifact
hashes and fails closed.
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
`tests/test_issuance_changes.py` module reported 115 passed, 21 skipped, and
nine native SD-JWT binding failures. Running that same module on the untouched
parent branch produced the identical result and error (`oid4vci_prepare_sd_jwt`
received 13 arguments from Python but the installed binding accepts at most
12). This local binding mismatch is not retention regression evidence, but a
compatible native binding or hosted equivalent is required before merge.
