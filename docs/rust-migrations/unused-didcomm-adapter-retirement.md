# Unused DIDComm adapter retirement

Maintainer-reviewed scope, based on Credentials `28b53d4`: remove only the
`didcomm_decrypt` and `didcomm_unpack_message` functions in the issuance service's
`application/rust_integration.py` and their two startup requirements. This is
internal adapter cleanup, not retirement of decryption or message parsing.

The scoped change was reconciled onto verified main `501977d` (PR #273).
Its KMS deferral note and DIDComm boundary inventory remain unchanged; no
unrelated commits from the older divergent local checkout are included.

The read-only inventory found no callers of these wrappers in issuance HTTP/gRPC
routes, repository tests, documented exports, or the intended workspace service,
UI, CLI, authenticator, verifier, protocol, demo and integration-test repositories.
`application/__init__.py` does not re-export them. The public wheel includes only
`python/marty_credentials`; the source-distribution include list excludes
`services`. No supported package or HTTP/RPC surface was identified for these
image-internal adapters. This scope was accepted by the maintainer; absence of
internal callers alone is not permission to remove a public capability.

Canonical Rust `marty-didcomm` retains `unpack_didcomm_message`, `decrypt_jwe` and
`decrypt_authenticated_jwe`, with their existing feature boundaries and tests.
The UI's actual-wallet composition helper (`didcomm_composed_delivery.rs`,
`decrypt_capture`, inspected at `f60aefc74`) decrypts both encryption modes and
unpacks the captured envelope using these Rust owners. Independent gateway
interoperability tests in `marty-integration-tests` call Core's bindings directly,
not either retired wrapper; those tests and their artifact requirements remain.
This inventory is not a new test run or release-compatibility claim.

No wrapper-specific tests were found to transfer. New startup regressions prove
that both retired capabilities can be absent while all remaining requirements
still reject missing or noncallable implementations. Encryption, authcrypt,
packing, DID resolution, issuer policy and reachable routes remain unchanged.

`DIDCOMM-KMS-001` remains deferred as directed by the user. This change neither
restores local-key APIs to Core's production binding nor implements KMS custody.
It does not resolve the remaining authcrypt/release-profile incompatibility or
authorize further Python deletion, dependency changes or deployment.
