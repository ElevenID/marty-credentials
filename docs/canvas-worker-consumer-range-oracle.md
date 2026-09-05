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

## Repeatable verification

With Docker available, run from this repository:

```sh
python scripts/run_canvas_worker_consumer_oracle.py --source both
```

The standard-library runner pulls the exact two image digests and creates a new
PostgreSQL container for **each** source mode: published modules, then this
checkout's actual service modules using the published runtime dependencies.
Neither mode replaces worker cycles, SQL repositories, or the loop. Repository
wrappers record method entry/results; exception logging alone is suppressed to
keep SQL details out of output. Checkout module paths are asserted, so a passing
published import cannot masquerade as current-source evidence.

Each database has network mode `none`, no published ports, tmpfs-only data and
synthetic credentials. The probe joins only that network namespace, is read-only,
drops all capabilities, and mounts the checkout read-only. No configurable
database URL is accepted. Published migrations initialize fresh tables, with a
synthetic organization dependency table. The verifier never drops/truncates or
reuses application schemas. Both exact container IDs are retained for cleanup,
including on failure/timeout, and ownership/topology are checked before removal.
Only those disposable databases and probe containers are removed; no production
or beta containers, data or credentials are accessed. Raw SQL exceptions are not
printed. Successful stdout reports bind source/fixture hashes and case counts.

CI requires this PostgreSQL lane in `CI Gate` on PRs, merge groups and main. It
executes all 36 cycles and all 3 loops twice (published and checkout); there are no
optional database flags or skipped vectors. The pytest-discoverable unit test
also validates fixture structure/provenance and replays all 36 startup inputs.
Those unit tests alone are not evidence of downstream SQL behavior.

## Rust implementation boundary

Preserve arbitrary configuration integers until their actual consumer boundary.
Do not replace accepted large values with startup rejection or silent global
clamping. Cap OAuth before machine conversion; preserve lease-time validation
on empty queues and loop survival. Use one shared Rust configuration owner and
consume these exact portable contracts rather than copying expectations.

The Python worker and every production consumer stay in place until the complete
worker/all-consumer parity and cutover gates pass. This test-only patch changes
no runtime, dependency/crypto pin, routing, release coordinate or deployment.
