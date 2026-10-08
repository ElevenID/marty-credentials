# Full Python issuance service retirement

Status: deletion prepared on `chore/retire-python-issuance-after-beta-v1`; protected Rust source and release qualification are pending. This source change does not deploy an image or alter the running production image.

The frozen Credentials runtime surface has 86 current HTTP routes and 12 gRPC methods. The Rust native coverage inventory includes 85 of those HTTP routes (the remaining `/ready` route is operational) and all 12 gRPC methods. Rust also implements the nine historical passport HTTP routes that Credentials PR #305 already removed from Python. The Canvas worker has a Rust binary and executable behavior and PostgreSQL contracts. UI PR #1178 adds the Rust issuance schema baseline, signed beta alias/migrator wiring, and protected aggregate cutover checks.

The deleted `services/issuance` tree contained 102 tracked files, including 48 Alembic revisions. The Rust schema baseline and adoption path in UI #1178 must qualify against the existing database before a new beta owner starts. The retired Python `services/Dockerfile` and the Credentials release matrix must not publish another issuance image. Production stays on its previously pinned immutable image during this source retirement.

## Test evidence retained in Rust

| Retired Python test area | Rust evidence in `marty-ui` |
| --- | --- |
| OID4VCI admission, proof audience, token, nonce, signing and credential lifecycle | `rust/services/issuance/tests/credential_admission_behavior.rs`, `credential_signing_behavior.rs`, `credential_postgres_contract.rs`, plus frozen JSON contracts |
| Issuance reservation and signing races | `credential_postgres_contract.rs` concurrent reserve and signing claim cases; `credential_signing_behavior.rs` concurrent signer case |
| Canvas synchronization, range and privacy behavior | `canvas_sync_worker_behavior.rs`, `canvas_sync_worker_postgres_contract.rs`, `support/canvas_worker_range_oracle.rs`, and published-schema tests |
| DIDComm delivery and durable state | `didcomm_delivery_behavior.rs`, `didcomm_delivery_atomicity.rs`, and PostgreSQL state cases |
| Passport HTTP, KMS signing, bureau batch and callbacks | Rust passport behavior tests and the protected signed beta acceptance gate in UI #1178 |

The old Alembic downgrade restoration fixture is retired with the Python migration owner. The user chose Rust-only forward migration and no Python rollback. The frozen JSON behavior contracts remain in this repository as historical oracles; CI in the Rust owner must continue to execute its PostgreSQL tests.

## Remaining merge gates

1. Merge UI #1178 after protected CI and maintainer review, then pin its protected merge commit and passing run in the full-retirement qualification record.
2. Run the local full-retirement provenance gate against the exact UI #1178 merge commit. It requires that commit on `origin/main`, settled passing PR checks, the new Rust schema baseline and catalog, aggregate beta scripts, and frozen route and gRPC coverage: `python -m scripts.check_full_issuance_retirement --marty-ui <UI checkout> --ui-commit <full UI merge SHA>`. Record its JSON result in the deletion PR review. The Credentials CI token cannot read the private UI repository, so this check is a required premerge review gate rather than a cross-repository CI job.
3. Pass Credentials CI and source-only release contract checks. The service-image matrix must be empty and no new `marty-credentials-issuance` image may be published.
4. Merge this deletion. Then qualify the signed aggregate beta candidate, run one beta-only acceptance deployment and soak, and keep production unchanged.

The separate `python/marty_credentials` compatibility wheel is outside this service-tree deletion. It needs a consumer audit before the repository can be described as entirely Rust-only.
