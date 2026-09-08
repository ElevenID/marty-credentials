# DIDComm delivery: feature-preserving KMS transition contract

Baseline: Credentials main `9bd2747f040f203188529758ec38f0a5dce5ac5f`.
The [inventory](../../contracts/issuance-didcomm-delivery-boundary.json) records
existing behavior and its evidence boundary. It reuses the published
[runtime surface](../../contracts/issuance-runtime-surface.json) and
[initiation contract](../../contracts/issuance-initiation.json); it is not a
second implementation, captured full runtime oracle, or cutover authorization.

## Execution order: Rust migration first; KMS correction deferred

User decision, 2026-09-08: migrate the remaining DIDComm consumer behavior to
Rust before correcting its KMS layer. KMS backend design, provisioning and
opaque key-agreement implementation are outside this migration slice. Track
the outstanding work in [DIDCOMM-KMS-001](didcomm-kms-outstanding.md).

Reuse the existing native issuance owner in marty-ui's
`rust/services/issuance/src/initiation_didcomm.rs` and canonical marty-core
protocol implementation; do not build a second Rust delivery implementation.
Freeze and compare remaining Python behavior, repair native gaps, qualify
actual consumers, then delete the superseded Python after its removal gates.
Deferring KMS does not authorize changing production or claiming KMS-only
custody for the existing local-key compatibility path.

Both anoncrypt and true sender-authenticated authcrypt delivery must survive.
Failure must never silently select anoncrypt or plaintext. The current
deployment policy's raw X25519 private-key field is a **transition requirement**,
not a request to preserve private-key export or continue passing private bytes
through the consumer. An opaque KMS operation and its lifecycle still need a
reviewed Core contract. No new crypto API is invented by this inventory.

The Core source at `1ae5b71e53ebfd2bad29b2e7c23c3d048461245c`
does not supply that replacement: `marty-bindings/pyproject.toml` selects
`kms-only` without default features, and `marty-bindings/src/lib.rs` excludes
the production Python authcrypt/decrypt entrypoints. Its optional
`didcomm-encrypted-envelope` capability enables anoncrypt only; the base wheel
does not include that capability. The retained Rust authcrypt function in
`marty-didcomm/src/encrypted_envelope.rs` requires `local-key-operations`, not an
opaque KMS port. The source regressions
`production_module_excludes_private_key_operations` and
`encrypted_envelope_module_exposes_anoncrypt_only` make this intentional
surface explicit. These are source findings, not a newly executed wheel test.
Pinning this Core revision alone is therefore not a feature-preserving consumer
migration; a qualified opaque sender key-agreement capability is still needed.

## Existing evidence

Unmodified baseline command:

```text
python -m pytest tests/unit/test_didcomm_boundary.py tests/unit/test_issuance_initiation_contract.py -q
```

Result: 37 passed in 0.84 seconds (31 parameter-expanded DIDComm boundary cases
and six initiation cases). The inventory lists all 25 boundary test function
names exactly; parameterization expands those 25 functions to 31 cases. Native
encryption,
remote signing, HTTP transport and persistence are controlled or mocked in
these tests; this result is not real wallet/KMS acceptance.

| Behavior | Existing test evidence |
|---|---|
| Public request rejects resolver selection | `test_delivery_contract_rejects_caller_selected_resolver` |
| Deployment-owned resolver and exact document DID | `test_resolver_uses_only_deployment_managed_configuration`; `test_resolver_rejects_a_mismatched_native_document` |
| Authcrypt calls canonical native binding | `test_authcrypt_binding_delegates_all_crypto_to_rust` (mock binding, not cryptographic proof) |
| Both modes remain usable | `test_delivery_defaults_to_anoncrypt_without_a_policy`; `test_configured_authcrypt_resolves_and_binds_the_sender` (mock crypto) |
| Preflight context survives policy changes | `test_prepared_authcrypt_context_is_validated_once_and_frozen_for_delivery` (same serialized documents/private input at both mock native calls) |
| Exhaustive issuer policy, strict JSON, no fallback/reused keys | `test_configured_policy_requires_an_exact_active_issuer_entry`; `test_policy_rejects_ambiguous_or_noncanonical_entries`; `test_authcrypt_failure_never_falls_back_to_anoncrypt`; `test_policy_rejects_cross_issuer_authcrypt_key_reuse` |
| TLS/default trust/operator CA | `test_delivery_uses_normal_web_pki_by_default`; `test_delivery_adds_operator_ca_to_default_trust`; `test_delivery_fails_closed_when_operator_ca_is_unavailable` |
| Sanitized failures | `test_auto_delivery_logs_only_sanitized_stage_and_exception_type`; `test_missing_endpoint_detail_does_not_echo_holder_did`; `test_encryption_logs_do_not_retain_holder_or_exception_details`; `test_delivery_error_omits_remote_body_and_transport_exception_text` |
| Tenant binding before lookup and delivery | `test_delivery_rechecks_gateway_tenant_against_transaction`; `test_delivery_hides_cross_tenant_transaction`; `test_delivery_rejects_claimed_tenant_before_transaction_lookup` |
| Endpoint/preflight failure before allocation/signing | `test_delivery_rejects_private_or_unavailable_encryption`; `test_delivery_validates_holder_endpoint_before_context_or_status_mutation` |
| Stable credential reservation across failure/retry/success | `test_signing_and_delivery_failures_retry_one_stable_status_reservation` (in-memory repository/fake HTTP) |
| Private test endpoint still requires HTTPS | `test_private_test_agent_still_requires_https` |

The six initiation tests remain unchanged. In particular,
`test_http_offer_projection_uses_only_the_committed_snapshot` preserves the
pending DIDComm URI; `test_idempotency_and_delivery_vectors_are_frozen`
preserves shared idempotency vectors. The existing initiation contract records
HTTP 422 / gRPC INVALID_ARGUMENT for DIDComm push with an idempotency key.
That is different from a guarantee of exactly-once remote delivery.

## Ordering and observable limits

The endpoint validates the request tenant, then loads and validates the
transaction tenant/state. Holder resolution and HTTPS/address validation precede
issuer-context mutation. Issuer-context resolution may save the transaction
**before** encryption preflight. Encryption preflight precedes stable status
allocation, signing, packing and final encryption. The prepared context is
reused; policy changes cannot downgrade the active attempt.

The TLS CA is currently loaded **after** allocation/signing/encryption. Do not
claim every deterministic failure occurs before every mutation. The configured
HTTP client uses a 30-second timeout. Current code treats statuses below 400,
including 3xx, as delivered; a real redirect/DNS-rebinding oracle is missing.
Those facts are inventoried, not silently corrected by a migration fixture.

After successful transport, atomic repository finalization creates the issued
credential/state; newly-created finalization owns claim, renewal, audit and
delivery-record hooks. Signing or transport failures leave issuance retryable
and reuse the stable credential ID. The direct public endpoint rejects already-issued transactions
with 409. The generic helper's return DTO intentionally includes holder DID
and service endpoint; failure diagnostic redaction must not delete DTO fields.

## Required migration and deferred KMS evidence

The Rust migration needs real two-mode protocol/delivery parity, state and
consumer qualification. The opaque-KMS-specific portions of items 1 and 3
below belong to DIDCOMM-KMS-001; they do not block porting existing behavior.
They still gate any future claim of KMS-only DIDComm or adoption of an API that
removes the currently required sender-authenticated capability.

1. Real anoncrypt and real opaque-KMS authcrypt through actual native binding,
   wallet decryption/authentication and PostgreSQL finalization. The two modes
   cannot be reduced to mocked dispatch success or an always-unavailable API.
2. Sender DID/key agreement binding, wrong-sender/recipient substitution,
   low-order or invalid-key failure, and no downgrade through that same path.
3. An attempt-scoped opaque context retaining identity/policy under rotation,
   with no consumer-readable private material. Handle ownership, expiry,
   rotation, provider refusal and cancellation remain Core design decisions.
4. Real TLS/custom CA and network boundaries; public management-key/state
   checks and concurrent retry/finalization evidence. Atomic local finalization
   alone is not exactly-once wallet delivery.
5. Complete policy boundaries (size/count/issuer length/UTF-8/types), exact
   prepared-context redaction and whole error/public DTO observations.

The new inventory tests check reference completeness, current public models,
source ordering and four existing synthetic policy rejection vectors. Only the
last group executes the actual policy parser. They do not substitute for the
37 existing behavioral tests or the missing runtime oracles above.

Combined qualification of those two unchanged suites and
`tests/unit/test_didcomm_delivery_contract_inventory.py`: 45 passed in 0.78
seconds (37 existing cases plus eight new checks). This qualification used
isolated Python dependencies; it did not build or exercise a production Core
wheel or provision a wallet/KMS service.

No production consumer, cryptographic implementation, release configuration,
existing oracle or existing test was changed in this slice.
