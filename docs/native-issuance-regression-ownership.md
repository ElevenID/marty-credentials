# Native issuance regression ownership

Three copied Python tests have been retired: local mdoc format constants and
two SQLite queries duplicated Rust behavior without calling the implementation.
Their SQLite fixtures and sole SQLAlchemy harness dependency are also removed.

The current owner is `ElevenID/marty-ui`, in `rust/services/issuance`, with
native regression coverage added in [marty-ui #1376](https://github.com/ElevenID/marty-ui/pull/1376).
That supporting change must land before this test retirement.

- `credential.rs`: `mdoc_aliases_select_the_native_builder_and_wire_format`
  and `other_payload_formats_do_not_select_the_mdoc_builder` exercise the
  actual format policy, native builder selection and wire format mapping.
- `tests/credential_postgres_contract.rs`:
  `tenant_discovery_queries_current_status_and_tenant_boundaries` queries the
  real PostgreSQL repository with active/draft, deprecated, suspended, revoked,
  null-type and cross-tenant data, including deduplication and active metadata.
  CI supplies its disposable PostgreSQL database; it is not a SQLite SQL copy.

Current discovery deliberately advertises active/draft templates and excludes
suspended/revoked ones. The deleted suspended test's comment proposed making
suspended templates visible for wallet metadata. That remains an unresolved
product/protocol policy question, not a delivered feature or a verified
standards requirement. Any change needs owner approval and native regression
coverage; this cleanup preserves current behavior.

`test_status_list_overflow.py` remains: it exercises the actual released native
binding rather than a copied implementation.
