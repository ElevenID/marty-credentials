# Full Python issuance service retirement

The Python issuance source and image build path were deleted in [Credentials #311](https://github.com/ElevenID/marty-credentials/pull/311), merged as `12897ba58803e630fc46f12f6d35a9c0677e49d4`. The Rust owner and the baseline migration were merged in [UI #1178](https://github.com/ElevenID/marty-ui/pull/1178) as `927f765cfce54c06f30a4dacba5421960af9a6ff`. [The historical full-issuance qualification receipt](https://github.com/ElevenID/marty-credentials/blob/a9474b319be12341f1a845ee08879143e38f15a5/contracts/full-issuance-retirement-qualification.json) records the exact source and protected UI evidence used for that deletion. Its one-time qualification script and release publisher were retired after the merge; the current CI gate checks that the deleted source and publication paths stay absent.

The frozen Credentials surface has 86 current HTTP routes and 12 gRPC methods. The Rust coverage inventory includes 85 of those HTTP routes (the remaining `/ready` route is operational), all 12 gRPC methods, and nine historical passport routes deleted earlier from Python. Rust also owns the Canvas worker and the issuance schema baseline. The retained JSON contracts are historical behavior oracles; Rust PostgreSQL and behavior tests execute in the UI owner.

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
authority, not current behavioral or deployment acceptance. No behavior oracle,
source-absence test, native coverage or release gate is removed. The CI job
continues to reject Python source and publication paths; it no longer checks a
historical SDK receipt's constant schema string.

## Retired SDK ownership

Product behavior remains with these Rust owners:

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
