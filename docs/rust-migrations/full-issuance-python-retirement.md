# Full Python issuance service retirement

The Python issuance source and image build path were deleted in [Credentials #311](https://github.com/ElevenID/marty-credentials/pull/311), merged as `12897ba58803e630fc46f12f6d35a9c0677e49d4`. The Rust owner and the baseline migration were merged in [UI #1178](https://github.com/ElevenID/marty-ui/pull/1178) as `927f765cfce54c06f30a4dacba5421960af9a6ff`. `contracts/full-issuance-retirement-qualification.json` records the exact source and protected UI evidence used for that deletion. Its one-time qualification script and release publisher were retired after the merge; the current CI gate checks that the deleted source and publication paths stay absent.

The frozen Credentials surface has 86 current HTTP routes and 12 gRPC methods. The Rust coverage inventory includes 85 of those HTTP routes (the remaining `/ready` route is operational), all 12 gRPC methods, and nine historical passport routes deleted earlier from Python. Rust also owns the Canvas worker and the issuance schema baseline. The retained JSON contracts are historical behavior oracles; Rust PostgreSQL and behavior tests execute in the UI owner.

The deletion did not deploy an image. Production remains on its previously pinned immutable image until a separately qualified release changes it. The signed aggregate beta candidate, beta-only acceptance deployment, and soak are distinct release gates.

The separate Python convenience SDK had no live in-repository product consumer. Its retirement mapping and consumer inventory are in `contracts/python-sdk-retirement-v1.json`. The only direct cross-repository importer was a mock-only integration test; its deletion in Integration [#428](https://github.com/ElevenID/marty-integration-tests/pull/428) must merge before the SDK deletion merges.

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
