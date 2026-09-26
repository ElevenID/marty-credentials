# OID4VCI and Canvas mirror Python retirement

Status: merged in `ElevenID/marty-credentials#298` at
`af041c2c3bd2e9fae189b566499146f97156120f` after qualification against
protected `marty-ui` main `207c84afc00b2f3b2b3db6b433823a9c7d59ab38`.
Universal native ownership in `ElevenID/marty-ui#844` and demo qualification
in `#845` have landed.
The cross-repository contract pins that commit and four committed Git-blob
digests; its fail-closed verifier passed with exactly 13 authorized deletions
and 11 Python routes retained at that merge. The later retention retirement in
`ElevenID/marty-credentials#299` removed two of those routes. Neither source
merge establishes beta or production deployment acceptance.
Qualification also pins the landed #845 recorder workflow and Rust review
validator: the gate rejects a protected-main source that lacks server-fetched
review-comment permission and record-digest binding. #844 ownership alone is
not sufficient to authorize this deletion.

For future requalification, fetch `ElevenID/marty-ui` protected `main` in the clean
UI checkout first: the verifier requires the pinned commit to be an ancestor
of `origin/main` as well as matching the checkout and artifact hashes.
Populate SHA-256 values from `git show <commit>:<path>` committed bytes, not
working-tree file bytes; platform line-ending conversion can otherwise create
a false mismatch between Windows preparation and Linux CI.

This checkpoint removes Python implementations only after their language-neutral
contracts were implemented by the Rust issuance service. The paired contracts
are `contracts/issuance-oid4vci-authorization.json` and
`contracts/issuance-canvas-mirror.json` in `marty-ui`. The retirement covers the
seven frozen OID4VCI public/management routes and the six Canvas Credentials
mirror publication, automation, health, and provenance routes.
At #298, the Credentials surface had 97 HTTP routes after those 13 deletions;
#299 later reduced it to 95. The surface retained the `/ready` delivery-status
compatibility route added by the later Credentials checkpoint, along with the
legacy routes listed below.

At #298, the deletion deliberately retained:

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
capability storage remains because proof nonces still use it. With universal
native selection, Rust owns client registration and PAR mutation.

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

At #298 qualification, the retained broad `tests/test_issuance_changes.py`
module passed with the repository's checksum-pinned `marty-rs` 0.2.0 Windows
wheel (124 passed, 21 skipped). A separate plain unit collection stopped while
importing the published legacy adapter's removed raw-key Core capabilities;
that compatibility gap is tracked in
`ElevenID/marty-credentials#297` and must not be mistaken for a passing full
suite or resolved by deleting the adapter without a parity review.

## Next linked retirement

DIDComm Python retirement is intentionally separate. The Python path remains
until native selection has its own acceptance gate. Key-custody redesign is
still tracked by [DIDCOMM-KMS-001](didcomm-kms-outstanding.md); this checkpoint
does not alter that boundary or claim that the KMS work is complete.

Of the eleven routes retained by #298, the two organization-retention routes
were subsequently retired in #299. The nine physical-passport routes remain a
separate future port. `tests/unit/test_physical_document_contract.py` captures
synthetic route-boundary cases for encrypted artifact creation and redaction,
SOD/data-group generation, bureau submission and polling, quality/activation
transitions, and signed-webhook rejection. Its reference explicitly does not
qualify Python deletion: tenant-scoped durable authorization and webhook effects,
live configured signer/bureau integration, and native Rust route, persistence,
provider, and webhook parity still need proof. The retention summary and purge
oracle, including tenant scope and cross-table effects, qualified the separate
#299 retirement.
