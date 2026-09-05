# Canvas worker lease-renewal oracle

The separate [whole-job renewal outcome oracle](CANVAS_WORKER_RENEWAL_JOB_OUTCOMES.md)
now records what the actual job handler persists after its maintainer fails,
including later owner/expiry/attempt fences and cancellation masking. The
maintainer-only observations below do not imply whole-job parity.

`tests/unit/test_canvas_worker_renewal_oracle.py` calls the real legacy renewal
loop with the real in-memory repository and detached worker copies. Existing
worker configuration/target helpers are reused; no production implementation
or dependency is changed. Worker blob
`b516ed3d0855f16e9ec899a452a22df49d2cafe5` and helper blob
`58a0b457bb13d1c94a1fc339adc01f23ef5e2bcd` match the frozen worker source.

Observed language-neutral behavior:

- Renewal interval is bounded to 10–30 seconds (lease duration divided by three).
- Successful durable compare-and-save precedes updating the detached lease,
  generation-fenced target heartbeat and process heartbeat, in that order.
- Local owner/status loss produces no write. Durable missing-job, tenant,
  owner, status, expiry and attempt fences stop renewal without changing the
  detached job or recording either heartbeat.
- Cancellation during the wait makes no write; repository errors propagate
  without claiming renewal or liveness.
- A heartbeat persistence error propagates after the renewed lease has already
  committed. Target-heartbeat failure prevents the process-heartbeat attempt;
  process-heartbeat failure leaves the target heartbeat committed and the local
  process heartbeat mutated. Local mutation alone is not durable evidence.
- Legacy target-generation mismatch rejects that target heartbeat but does not
  stop lease renewal or process liveness. This observation is not approval for
  weakening the Rust candidate's generation fences.

Tests replace only the worker's clock/sleep references, never the shared asyncio
module. Repository methods are wrapped spies except explicit failure injections.
Async calls are bounded; loop cancellation is expected and asserted.

This is an executable legacy floor, not proof of PostgreSQL transaction/race
behavior, complete processor cancellation, target-reconciliation parity or
whole-worker equivalence. Those differentials and all-consumer readiness,
routing and beta acceptance remain mandatory before Python deletion. Do not
activate the unrouted Rust candidate based only on this in-memory evidence.
