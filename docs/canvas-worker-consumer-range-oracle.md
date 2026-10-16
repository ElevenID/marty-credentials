# Canvas worker consumer range oracle

`contracts/canvas-worker-consumer-range-oracle.json` freezes 36 real PostgreSQL
cycle observations and three two-cycle loop observations from the published
issuance 0.1.72 image. It supplements, without replacing, the 15 configuration
cases, 18 malformed combinations, 64 lexical vectors, and result oracle.

The fixture pins the published image, worker/repository source hashes, original
observation hash, PostgreSQL 15.17 image and published Alembic migration head.
Large integers are base-10 **strings**, including a 4300-digit value. Four fields
reference nine shared inputs and four shared expected outcomes; each outcome
contains the exact ordered heartbeat/repository events and legacy error identity.
Loop cases repeat the referenced event sequence exactly `cycles` times. New Rust
consumers must preserve the semantic `category` and phase, not Python class names.
The legacy identities remain required when replaying the Python oracle.

| Consumer | Observed behavior on empty queues |
| --- | --- |
| Scheduling/batch limits | Accepted at startup; through i64::MAX succeeds; above i64 fails at scheduling/leasing with SQLSTATE 22000. |
| Lease seconds | Accepted at startup; i32::MAX+1 succeeds; the sampled i64::MAX and larger inputs raise a time-range error at leasing, even with no jobs. |
| OAuth retry limit | All sampled integers, including 4300 digits, succeed; the repository caps to 500 before SQL binding. |
| Worker loop | Scheduling, batch and lease range errors are caught; two actual cycles execute and an owned stop event ends the loop normally. |

This does **not** locate the exact maximum representable lease timestamp. It does
not prove populated-queue concurrency, fencing, renewal, active-job cancellation,
recovery, provider processing, readiness, routing, or beta/device acceptance.

## Current regression ownership

The historical Python consumer replay and Docker controller are retired.
Their implementation remains at Git commit `40158ec`. The frozen JSON corpus
is unchanged and its consumer-boundary assertions remain with the native Rust
Canvas worker in `marty-ui`. No historical image is executed by default CI.

## Rust implementation boundary

Preserve arbitrary configuration integers until their actual consumer boundary.
Do not replace accepted large values with startup rejection or silent global
clamping. Cap OAuth before machine conversion; preserve lease-time validation
on empty queues and loop survival. Use one shared Rust configuration owner and
consume these exact portable contracts rather than copying expectations.

The Python worker was retired after the Rust worker and consumer parity gates
passed. This historical replay changes no runtime, dependency/crypto pin, routing,
release coordinate or deployment.
