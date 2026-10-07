# DIDCOMM-KMS-001: native remote sender custody

Status: active KMS-only hardening (2026-10-07). The cross-repository tracker
is `marty-ui/docs/remote-kms-hardening-plan.md` on the integration worktree.

Credentials selects the native Rust issuance owner for HTTP initiation and
DIDComm direct delivery and rejects any legacy owner setting. Python local
X25519 sender-key parsing, authcrypt preparation, capability requirements and
private-key test fixtures have been removed. The native owner must preserve
anoncrypt and authenticated authcrypt, tenant/sender/recipient binding, frozen
attempt inputs, retry/finalization semantics and actual wallet decryption.

The native Rust service and the Go OpenBao plugin are the remaining custody
boundary. Standard OpenBao Transit does not provide the needed X25519
operation. The release must prove that the scoped plugin operation keeps
long-lived sender private keys inside OpenBao and fails closed when unavailable.
There is no old-data or legacy behavior compatibility requirement.

The Python gRPC server is disabled by default and an explicit enablement
fails startup before the database engine is created. Its former adapter and
Python-only RPC tests are deleted; the generated service definition remains
as the protocol inventory while native Rust implements all twelve methods.
Qualify exact release images and artifacts together before cutover.
