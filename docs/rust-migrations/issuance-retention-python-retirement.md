# Issuance retention Python retirement

Status: local preparation only. The two native retention routes are still in
draft `ElevenID/marty-ui#849`; their Python owners must remain until the Rust
source lands on protected `main`, exact-head gates and a published-image
dependency pass, and the prior OID4VCI/Canvas retirement is qualified. The
new qualification contract deliberately has no source commit or artifact
hashes and fails closed.

The intended deletion is exactly the GET retention summary and POST retention
purge handlers, their response-only models, and their now-unreferenced memory
and PostgreSQL repository methods. The Python HTTP and repository behavior is
frozen in `contracts/issuance-retention-management.json` and the observed
addendum in `marty-ui`; the Rust PostgreSQL contract also covers tenant scope,
expired parent/child purge, and preservation of younger event ownership.

Do not delete shared issuance records, tables, migrations, event-owner storage,
or the PostgreSQL `_result_rowcount` helper: other live repository operations
still use that helper. The nine physical-passport HTTP routes, DIDComm delivery,
and all unrelated issuance features remain Python-owned until separately
qualified. No beta or production deployment is authorized by this local
preparation.
