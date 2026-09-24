# OID4VCI and Canvas mirror Python retirement

Status: prepared locally; do not publish or deploy before the universal native
ownership checkpoint in `ElevenID/marty-ui#844` and demo qualification in
`ElevenID/marty-ui#845` land. The cross-repository retirement qualification
contract remains blocked with no pinned UI commit or artifact hashes.

When it is qualified, fetch `ElevenID/marty-ui` protected `main` in the clean
UI checkout first: the verifier requires the pinned commit to be an ancestor
of `origin/main` as well as matching the checkout and artifact hashes.

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

The broad issuance and Canvas adapter regression modules remain in place.
Their DPoP, issuer metadata, transaction/lifecycle, signing, delivery-record,
tenant-isolation, Canvas evidence, signature, and provider-validation checks
still cover Python behavior that has **not** retired. Only historical tests
calling Rust-owned authorization, revocation, Canvas publication, and mirror
operations are skipped; their language-neutral OID4VCI and Canvas contracts
are exercised in `marty-ui`. The retirement guard checks that representative
retained tests are neither deleted nor skipped with the old route tests.
Status sync also retains its historical timeout fallback to
`CANVAS_CREDENTIALS_PUBLISH_TIMEOUT_SECONDS` when no dedicated status-sync
timeout is configured; removing the publisher must not silently change this
still-owned behavior.

## Next linked retirement

DIDComm Python retirement is intentionally separate. The local path remains
until native selection has its own acceptance gate. Key-custody redesign is
still tracked by [DIDCOMM-KMS-001](didcomm-kms-outstanding.md); this checkpoint
does not alter that boundary or claim that the KMS work is complete.

The eleven retained HTTP routes are a separate future port, not cleanup in this
checkpoint. `tests/unit/test_physical_document_contract.py` already captures
synthetic route-boundary cases for encrypted artifact creation and redaction,
SOD/data-group generation, bureau submission and polling, quality/activation
transitions, and signed-webhook rejection. Its reference explicitly does not
qualify Python deletion: tenant-scoped durable authorization and webhook effects,
live configured signer/bureau integration, and native Rust route, persistence,
provider, and webhook parity still need proof. The two organization-retention
routes likewise need an exact repository-backed summary and purge oracle,
including tenant scope and cross-table effects, before native replacement or
Python deletion is authorized.
