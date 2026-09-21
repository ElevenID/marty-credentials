# INTEGRATION-SECRET-KMS-001: opaque integration-secret storage

Status: deferred; required before advancing the production
`marty-verification` wheel beyond `v0.1.60`.

Credentials persists Canvas and other organization integration secrets as
`base64(nonce || AES-256-GCM ciphertext || tag)`. The current adapter supplies
the 32-byte deployment master key to the compatibility verification binding.
Core `v0.2.0` intentionally removes generic random-byte and AES-GCM operations
from its production Python surface, so replacing that wheel without another
storage boundary would disable secret creation and retrieval.

Hosted CI reproduces the retained `v0.1.60` wheel from its exact source commit
with `pyo3/extension-module,python,iaca,csca,eudi`. That release predates and
does not define `local-key-operations`; adding that feature to its build command
is a fail-closed CI error, not a hardening measure. Export validation must keep
proving `generate_random_bytes`, `aes_gcm_encrypt`, and `aes_gcm_decrypt`.

Design and qualify a purpose-specific Rust secure-storage API with opaque key
custody. It must preserve existing ciphertext reads, fail-closed authentication
and malformed-input behavior, tenant/purpose separation, rotation and recovery,
and atomic repository semantics. Migration needs language-neutral vectors for
the existing envelope plus restart, rotation, wrong-key and tamper tests. Only
after deployed data is readable through that boundary may the compatibility
wheel and raw master-key adapter be removed.

This item is independent of DIDCOMM-KMS-001. It does not authorize changing
DIDComm authcrypt behavior, reintroducing issuer private-key operations, or
claiming that `marty-verification` `v0.1.60` is KMS-only.
