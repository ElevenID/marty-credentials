# Full Python issuance service retirement

The remaining Credentials LTI, physical-passport provider and Python-route
reference JSON copies are retired. The
[Rust issuance ownership guide](https://github.com/ElevenID/marty-ui/blob/main/docs/issuance-contract-ownership.md)
maps their requirements to maintained native contracts and behavior tests.
The Rust LTI owner preserves all 16 forbidden private-key field names, including
legacy aliases and empty/null members, before signing or publishing JWKS.
Native passport tests retain the nine routes, validation, safe projections,
bureau submit/poll/batch mapping, durable restart, quality/activation, artifact
scrubbing, tenant isolation and signed webhook effects. Legacy local/self-signed
or external signing modes and missing authorization are explicitly rejected.
Live provider/custody, deployment/drain, unreadable-artifact recovery and physical
booklet evidence remain separate qualification work. Existing provenance hashes
refer to immutable history; these retired files are not current runtime inputs.

The Python issuance source and image build path were deleted in [Credentials #311](https://github.com/ElevenID/marty-credentials/pull/311), merged as `12897ba58803e630fc46f12f6d35a9c0677e49d4`. The Rust owner and the baseline migration were merged in [UI #1178](https://github.com/ElevenID/marty-ui/pull/1178) as `927f765cfce54c06f30a4dacba5421960af9a6ff`. [The historical full-issuance qualification receipt](https://github.com/ElevenID/marty-credentials/blob/a9474b319be12341f1a845ee08879143e38f15a5/contracts/full-issuance-retirement-qualification.json) records the exact source and protected UI evidence used for that deletion. Its one-time qualification script and release publisher were retired after the merge; the current CI gate checks that the deleted source and publication paths stay absent.

At full source retirement, the Python surface snapshot recorded 86 HTTP routes and 12 gRPC methods. The Rust coverage inventory includes 85 of those HTTP routes (the remaining `/ready` route is operational), all 12 gRPC methods, and nine historical passport routes deleted earlier from Python. Rust also owns the Canvas worker and the issuance schema baseline. The retained JSON contracts are historical behavior oracles; Rust PostgreSQL and behavior tests execute in the UI owner.

The deletion did not deploy an image. Production remains on its previously pinned immutable image until a separately qualified release changes it. The signed aggregate beta candidate, beta-only acceptance deployment, and soak are distinct release gates.

The separate Python convenience SDK had no live in-repository product consumer
at its retirement audit. The sole cross-repository importer was a mock-only
integration test removed in Integration
[#428](https://github.com/ElevenID/marty-integration-tests/pull/428). External SDK
consumers were unknown; no compatibility guarantee was made. The historical
[SDK consumer audit and ownership receipt](https://github.com/ElevenID/marty-credentials/blob/a9474b319be12341f1a845ee08879143e38f15a5/contracts/python-sdk-retirement-v1.json)
remains available in immutable Git history.

The five completed qualification receipts are retired from current source.
They pinned source/artifact hashes, former route counts and one-time deletion
authority, not current behavioral or deployment acceptance. The canonical Rust behavior oracles, source-absence tests, native coverage
and release gates remain. The CI job
continues to reject Python source and publication paths; it no longer checks a
historical SDK receipt's constant schema string.

## Canonical contract ownership

Twelve byte-identical Credentials mirrors are also retired after comparing
committed bytes with the canonical [UI contracts](https://github.com/ElevenID/marty-ui/tree/main/contracts).
The Rust owner retains application templates, Canvas management/OAuth,
credential admission/lifecycle/signing, internal applications, offer/transaction
reads, proof nonces, static/tenant discovery and token-exchange fixtures, with
its executable [issuance tests](https://github.com/ElevenID/marty-ui/tree/main/rust/services/issuance/tests).
The native libraries, Rust fixture data and all existing executable behavior
tests are unchanged. No vectors were regenerated from implementation output.

The two local mirror-only tests checked a frozen internal-application
schema/routes/digest and static-discovery case count/operation strings. Those
assertions provided no execution coverage of current service behavior. Keep
all fourteen internal-application routes and their tenant, evidence, approval,
concurrency and offer semantics with the native HTTP regression suite. Static
discovery retains its six cases and distinct organization issuer-metadata,
credential-manager and Apple Wallet database-backed operations in the UI
fixture and HTTP tests. The retention mirror's unique repository-failure field is retained by UI's
observed addendum and exercised against a failing Rust repository for both
routes; that mirror and its route-only self-assertion are retired too. The
unused Python source/line snapshot is historical provenance in Git history,
not a current behavioral gate.

The unused local initiation reference is retired too. Its vectors and fields
match the actively consumed [UI initiation contract](https://github.com/ElevenID/marty-ui/blob/main/contracts/issuance-initiation.json)
except for the historical `owner_precheck_order`. Preserve that unresolved
requirement from the [last containing Credentials revision](https://github.com/ElevenID/marty-credentials/blob/c57a715c402c8017035ce50158a0ed875c259bcd/contracts/issuance-initiation.json):

1. Normalize the idempotency key.
2. Normalize the delivery mode.
3. Reject direct-signing headers.
4. Select the delivery owner.

Current Rust `initiation_http.rs::reserve_authorized` rejects direct-signing
headers before `initiation.initiate` normalizes the idempotency key. Requests
with multiple invalid inputs can therefore receive a different winning 422
error. The Rust issuance owner must explicitly resolve that precedence and
qualify competing invalid idempotency keys, delivery modes and direct-signing
headers in its native HTTP regression suite before claiming compatibility.
Deleting the unconsumed JSON does not resolve this behavior difference or
change Rust behavior.

Three nonidentical references remain here pending reconciliation. LTI's
private-key alias prohibition is broader than the UI fixture's list and
requires security-policy qualification. Do not discard that difference as
formatting or alter the other worker's KMS implementation to make a deletion
pass. The two physical-passport references retain unique provider/route
vectors and tenant, durable-job, live-provider and native-parity obligations
referenced by UI's passport contracts. This cleanup makes no parity or
deployment claim for these references or the initiation precedence above.

## Retired SDK ownership

Product ownership and available qualification reside with these Rust owners:

| Capability | Rust owner and executable qualification |
|---|---|
| W3C VC, SD-JWT and mdoc issuance, lookup and revocation | [UI issuance](https://github.com/ElevenID/marty-ui/tree/main/rust/services/issuance/src) `credential_builder.rs` and `credential.rs`, native-coverage and runtime-surface contracts |
| Presentations, OID4VP and wallet issuance | [UI Flow](https://github.com/ElevenID/marty-ui/tree/main/rust/services/flow/src) `presentation_request.rs` and [Core wallet](https://github.com/ElevenID/marty-core/tree/main/marty-oid4vci/src) `wallet.rs` |
| W3C VC, SD-JWT, mdoc, presentation and badge verification | [UI verification tests](https://github.com/ElevenID/marty-ui/tree/main/rust/services/verification/tests) and [Core verification](https://github.com/ElevenID/marty-core/tree/main/marty-verification) Open Badges tests |
| Token validation, distributed rate limiting and issuance events | [UI auth](https://github.com/ElevenID/marty-ui/tree/main/rust/services/auth/src) `oidc.rs`, [Gateway](https://github.com/ElevenID/marty-ui/tree/main/rust/services/gateway/src) `middleware.rs`, issuance `credential_management_events.rs` and admission tests |

The former SDK-only conveniences had no product caller: in-memory/SQLAlchemy
wallet and key stores, and credential/verifier-filtered SQLAlchemy logs. Local
private-JWK OB2/OB3 signing and fail-open Redis limiting are retired; product
paths require managed signer profiles/KMS and the Rust distributed limiter.
Implicit-token redemption and ZK placeholder methods were fail-closed stubs,
not implemented product features. Removing their receipt does not recreate
these APIs or authorize a local signing fallback.

## Schema and test-tool ownership

The unreferenced root `create_application_tables.sql` and `setup_tables.sql`
manual setup copies are retired. Current schema owners are in
[marty-ui](https://github.com/ElevenID/marty-ui):

- `rust/services/issuance/migrations/0000_issuance_service_baseline.sql` owns
  applications, application templates, issuance events and Canvas tables;
- `rust/services/credential-template/migrations/0001_credential_template_schema.sql`
  owns credential templates and the wallet registry;
- `rust/services/trust-profile/migrations/0001_trust_profile_schema.sql` and
  `rust/services/presentation-policy/migrations/0001_presentation_policy.sql`
  own their respective schemas;
- `rust/services/credential-template/src/catalog.rs`, invoked by that service's
  `main.rs`, owns the LISSI, walt.id, Sphereon and DC4EU catalog entries.

Use the Rust service migration and catalog paths rather than recreating a
partial cross-service schema with old columns or hardcoded database-role grants.
Deleting these copies does not qualify a fresh install, upgrade, rollback,
seed reconciliation or interoperability with any listed wallet. Those checks
remain with the deployed service owners and their PostgreSQL regression suites.
The [integration-secret secure-storage requirements](integration-secret-secure-storage-outstanding.md)
remain open; removing the old plaintext `canvas_credentials` DDL does not close them.

The metadata-only Hatch build no longer installs Maturin. Native binding jobs
still install and run the pinned Maturin builder explicitly. Current Python
harness and binding tests are synchronous, so their unused asyncio plugin and
root bootstrap for the retired `services`, `python` and `packages` trees are
removed. Unit database fixtures, native binding tests and all existing test
assertions remain. Removing an uncalled mocked route-import helper does not
turn the historical mdoc format expectations into a live Rust regression.
