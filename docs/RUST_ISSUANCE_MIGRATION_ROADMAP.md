# Native Rust issuance migration roadmap

**Status:** Active; contract freeze in progress

**Started:** 2026-08-28

**Initial deployment boundary:** Beta only. Production remains unchanged unless a
separate promotion is explicitly approved.

## Objective

Replace the deployed Python issuance API and standalone Canvas synchronization
worker with one feature-complete Rust service package. Preserve every public and
internal behavior, move generic behavior into the existing Marty
Microservices Framework Rust crates, consume canonical protocol and
cryptographic behavior from `marty-core`, and delete the superseded Python only
after implementation-independent parity gates pass.

This is a whole-service replacement, not a line-for-line rewrite. A language
change is justified here because it removes the final Marty-owned Python API
and worker from the coordinated beta service plane, removes a Python native
wheel boundary around already-Rust protocol kernels, and consolidates service
lifecycle, resilience, security, telemetry, data, and migration behavior on the
shared Rust platform completed during wave three.

## Frozen baseline

The checked-in
[`issuance-runtime-surface.json`](../contracts/issuance-runtime-surface.json)
is generated from the Python parity oracle and fails closed on unreviewed
surface drift.

| Surface | Frozen baseline |
|---|---:|
| Production Python, excluding tests and migrations | 52 files / 42,138 lines |
| Issuance-owned Alembic history | 44 revisions / 3,922 lines / one head |
| HTTP operations | 131 |
| gRPC operations | 12, including one server stream |
| Literal environment variables | 89 |
| Dynamic environment lookups requiring manual classification | 20 |
| Deployed modes | API and Canvas synchronization worker |

HTTP ownership is frozen across the application, issuance, issued-credential,
resource-owner, application-template, physical-document, Canvas integration,
and Canvas operations routers. The manifest records method, exact path,
operation, router, source, and line. It also proves that the generated gRPC
contract and Python servicer implement the same method set.

## Canonical ownership

| Concern | Canonical Rust owner |
|---|---|
| Credential formats, OID4VCI, signatures, proofs, DIDComm, mDoc, VDS-NC, trust and cryptographic decisions | Existing `marty-core` crates; re-export, never copy |
| Lifecycle, configuration, secrets, SQL, Redis, migrations, messaging, outbox, resilience, telemetry, authorization context, HTTP/gRPC hosting and test support | Existing MMF Rust crates |
| Issuance use cases, route DTO adaptation, repositories and provider ports | New `marty-ui/rust/services/issuance` crates in the AGPL service plane |
| Canvas, personalization bureau, wallet delivery and document-signer integrations | Issuance-local Rust provider adapters |
| Protocol schemas and generated bindings | Existing Marty protocol repositories and generated artifacts |

No issuance crate may copy an MMF implementation or reimplement a canonical
`marty-core` decision. Provider-specific code remains outside MMF.

### License and repository boundary

`marty-credentials` is the permissively licensed MIT/Apache SDK and binding
repository. MMF is AGPL-only, so adding MMF crates to that workspace would
silently change its dependency-license boundary and fail its existing
allowlist. The native deployable therefore belongs in the existing AGPL
`marty-ui` Rust service workspace, beside the other wave-three services. This
repository retains the Python parity oracle, public surface contract and
permissive reusable credential bindings until cutover; it does not gain an
AGPL dependency.

At cutover, the coordinated stack manifest moves issuance image ownership from
the Python `marty-credentials-issuance` artifact to the native `marty-ui`
service artifact. SBOM, provenance, release, integration-test and public image
contracts must all make that ownership transition atomically.

## Ordered implementation

Work proceeds in descending removable production code while keeping every
slice executable and reviewable.

1. **Contract and ownership freeze.** Land the machine-readable HTTP, gRPC,
   runtime, configuration and migration inventory; record cross-repository
   owners and feature-loss gates.
2. **Native host and issuance protocol routes.** In the `marty-ui` Rust service
   workspace, compose MMF lifecycle,
   configuration, secrets, telemetry, HTTP/gRPC hosting and exact errors around
   existing `marty-core` issuance kernels. Preserve health, discovery,
   metadata, offer, nonce, token and credential behavior first.
3. **Persistence and transaction lifecycle.** Port repositories, idempotency,
   transaction state, issued-credential history, outbox/event behavior and
   lifecycle calls using MMF data and messaging crates.
4. **Application and template composition.** Preserve internal template gRPC,
   application issuance, evidence, renewal and server-owned claim behavior
   without recreating services already owned by the Rust platform.
5. **Physical document and delivery providers.** Port production job lifecycle,
   personalization bureau, managed document signing, wallet push and DIDComm
   adapters with bounded I/O and fail-closed provider behavior.
6. **Canvas/LTI and standalone worker.** Port all Canvas routes, OAuth/LTI,
   evidence synchronization, fenced leases, retry semantics, heartbeats and
   readiness. The same native artifact must expose an explicit worker mode.
7. **Rust schema ownership.** Reproduce the full 44-revision upgrade contract,
   fresh-schema result and protected legacy-copy rehearsal. Move bootstrap
   responsibilities to their actual Rust owners instead of creating a new
   aggregate monolith.
8. **Cutover and deletion.** Run the same language-neutral fixtures against
   Python and Rust; build and inspect a Python-free image; deploy once to beta;
   pass public issuance, Canvas, KMS/provider switching, lifecycle, migration,
   observability and soak gates; then delete Python runtime, implementation-only
   tests, Alembic ownership and Python image packaging immediately.

The separately published Credentials verification image follows this service
port. Its public contract must be reconciled with the canonical Rust
verification service and consolidated rather than translated into a second
Rust implementation.

## Required preservation gates

Every slice must cover success, negative, authorization, tenancy, idempotency,
concurrency, dependency failure, timeout, retry, secret redaction, malformed
input and bounded-resource behavior where applicable. Final cutover requires:

- all 131 HTTP and 12 gRPC operations accounted for by a native route manifest;
- exact OID4VCI discovery, authorization, token, nonce, offer, credential,
  deferred and notification behavior;
- credential status, suspension, reinstatement, revocation, renewal and event
  streaming parity;
- all application/template, physical-document, delivery and Canvas/LTI paths;
- PostgreSQL fresh-schema and legacy-copy equivalence with one Rust-owned head;
- worker lease fencing, retries, heartbeats, readiness and restart recovery;
- exact public errors, privacy projections, tenant boundaries and trusted
  downstream identity;
- no Python executable, interpreter, wheel, fallback flag, Alembic runtime or
  superseded implementation in the final issuance image;
- immutable release, SBOM, provenance, signature and dependency evidence;
- one aggregate beta-only deployment and acceptance soak with a recorded,
  unchanged production invariant.

## Delivery discipline

Each slice uses a clean worktree and focused branch, receives a maintainer-style
self-review for missing behavior and inadequate negative tests, passes local
and protected CI, lands through a PR and merge queue, and removes its temporary
branch and worktree after merge. Python remains the parity oracle only until
the corresponding native behavior passes its deletion gate. No permissive
runtime fallback is allowed.
