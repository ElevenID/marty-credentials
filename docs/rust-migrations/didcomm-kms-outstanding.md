# DIDCOMM-KMS-001: correct DIDComm key custody after the Rust migration

Status: **outstanding, explicitly deferred by the user on 2026-09-08**.
Owner: the Rust DIDComm consumer and canonical Core maintainers, coordinated
with the crypto worker. No backend implementation or provisioning is authorized
by this note.

## Current decision

Complete the feature-preserving Rust migration first. Preserve anoncrypt,
sender-authenticated authcrypt, issuer/recipient binding, frozen attempt inputs,
fail-closed errors, retry behavior and all intended consumers. Reuse the existing
Rust implementation rather than designing a Python KMS workaround. Keep the
existing key-custody limitation explicit; moving private bytes from Python into
Rust does not itself make them KMS-only. Production remains unchanged.

## Outstanding correction

Credentials currently reads a deployment-owned X25519 sender private key for
authcrypt. Core `1ae5b71e53ebfd2bad29b2e7c23c3d048461245c` removes the old
private-key Python APIs from its production binding and does not provide an
opaque KMS authcrypt/decrypt replacement. Anoncrypt encryption uses recipient
public keys and short-lived envelope keys; its optional Core feature and the
policy governing ephemeral keys still need explicit artifact qualification.

After the Rust port:

1. Design the Rust/Core KMS boundary from the actual native delivery owner.
   Choose and qualify backend key-agreement/envelope support; do not assume
   existing signing or wrap/unwrap endpoints provide non-exportable X25519.
2. Replace raw sender-key configuration with a scoped, versioned key reference.
   Bind tenant, sender DID/key and frozen recipient documents to each attempt;
   specify rotation, expiry, replay, cancellation and failure semantics.
3. Prove that long-lived private keys do not reach consumer memory, logs or
   configuration. Do not reintroduce removed private-key Python bindings or
   silently fall back to anoncrypt/plaintext.
4. Test actual recipient decryption and sender authentication, wrong-key and
   cross-tenant rejection, backend failures, rotation and finalization through
   real wallet/backend/database boundaries. Mocks are not acceptance evidence.
5. Qualify the actual published Core artifacts and consumer startup capabilities
   together before changing release pins. Preserve immutable failed release
   evidence; do not retag an existing version to conceal a compatibility repair.

This follow-up is not complete merely because the Rust port passes. Conversely,
its deferral must not be used to hold up the feature-preserving Rust port.
