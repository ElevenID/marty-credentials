# OID4VCI and Canvas mirror Python retirement

Status: prepared locally; do not publish or deploy before the universal native
ownership checkpoint in `ElevenID/marty-ui#844` and demo qualification in
`ElevenID/marty-ui#845` land. The cross-repository retirement qualification
contract remains blocked with no pinned UI commit or artifact hashes.

This checkpoint removes Python implementations only after their language-neutral
contracts were implemented by the Rust issuance service. The paired contracts
are `contracts/issuance-oid4vci-authorization.json` and
`contracts/issuance-canvas-mirror.json` in `marty-ui`. The retirement covers the
seven frozen OID4VCI public/management routes and the six Canvas Credentials
mirror publication, automation, health, and provenance routes.
The rebased Credentials surface has 97 HTTP routes after those 13 deletions.
It retains the `/ready` delivery-status compatibility route added by the later
Credentials checkpoint, along with the legacy routes listed below.

The deletion deliberately retains:

- the two organization-retention routes and all nine physical-passport routes;
- OID4VCI initiation, token, nonce, credential issuance, discovery metadata,
  registered-client reads, authorization-session persistence, database tables,
  and historical Alembic revisions still used by retained consumers or schema
  ownership;
- credential lifecycle-to-Canvas status synchronization and delivery-record
  creation, entities, repositories, and migrations;
- Canvas provider validation, inbound evidence adapters, LTI/Canvas management,
  and the standalone `CanvasSyncWorker`;
- the local DIDComm delivery path and its tests.

The retired Python repository mutations are the registered-client writer and
the two pushed-authorization-request convenience methods. The shared ephemeral
capability storage remains because proof nonces still use it. Native Rust owns
client registration and PAR mutation after the universal selection lands.

`tests/unit/test_oid4vci_canvas_python_retirement.py` prevents the deleted HTTP,
worker, publication, and repository-writer surfaces from returning while also
asserting that the retained lifecycle, validation, evidence, storage, worker,
and DIDComm boundaries remain available.

The broad issuance regression module remains in place: its DPoP, issuer
metadata, transaction/lifecycle, signing, delivery-record, and tenant-isolation
checks still cover Python behavior that has **not** retired. Only historical
tests calling the 13 Rust-owned HTTP routes are skipped in that module; their
language-neutral OID4VCI and Canvas contracts are exercised in `marty-ui`.
The retirement guard also checks that representative retained test cases are
not accidentally deleted with the old route tests.

## Next linked retirement

DIDComm Python retirement is intentionally separate. The local path remains
until native selection has its own acceptance gate. Key-custody redesign is
still tracked by [DIDCOMM-KMS-001](didcomm-kms-outstanding.md); this checkpoint
does not alter that boundary or claim that the KMS work is complete.
