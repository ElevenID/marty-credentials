# INTEGRATION-SECRET-KMS-001: remote integration-secret custody

Status: active KMS-only hardening (2026-10-07). The cross-repository tracker
is `marty-ui/docs/remote-kms-hardening-plan.md` on the integration worktree.

The Credentials PostgreSQL repository now asks the Rust signing-keys service
to encrypt and decrypt purpose-bound integration-secret envelopes. Its Python
adapter contains no AES master key or local encryption operation, rejects old
AES ciphertext and raw master-key configuration, and does not fall back when
the remote service fails. Python startup performs a remote round-trip proof
before opening its database engine. The same Rust service and OpenBao key serve
native issuance and Canvas workers. The deployment candidate connects Python
directly to signing-keys to avoid a gateway readiness cycle, and removes the
old key from self-host and Kubernetes inputs. Existing beta data may be discarded.

Remaining release evidence: prove Python and Rust consumers against one
clean KMS-backed database, cross-tenant
and purpose rejection, tamper handling, rotation, recovery and exact-image
configuration. Retire stale conformance fixtures and scripts. No legacy
ciphertext readability or migration gate applies.
