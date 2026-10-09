# INTEGRATION-SECRET-KMS-001: remote integration-secret custody

Status: active KMS-only hardening (2026-10-07). The cross-repository tracker
is `marty-ui/docs/remote-kms-hardening-plan.md` on the integration worktree.

The Credentials Python issuance service and SDK have been retired on main.
The native Rust issuance and Canvas worker owners ask Signing Keys to encrypt
and decrypt purpose-bound integration-secret envelopes over authenticated TLS.
Signing Keys delegates the application key to OpenBao; neither client holds an
AES master key or a local encryption fallback. Native startup proves a remote
round trip before accepting stored rows. The supported self-host and Kubernetes
deployments give clients only the server CA and give Signing Keys its separate
TLS server leaf/key. Existing beta data may be discarded.

Remaining release evidence: prove native consumers against one clean KMS-backed
database, cross-tenant and purpose rejection, tamper handling, rotation,
recovery and exact-image configuration. Retire stale Python conformance
fixtures and scripts. No legacy ciphertext readability or migration gate
applies.
