# Canvas worker lifecycle oracle

`tests/unit/test_canvas_worker_lifecycle_oracle.py` exercises the actual
legacy scheduling loop, initialized entry point, and cancellation of a real
worker cycle. It reuses the existing worker-test configuration and target
setup instead of copying either implementation or fixture setup.

The worker blob `b516ed3d0855f16e9ec899a452a22df49d2cafe5` and reused test
helper blob `58a0b457bb13d1c94a1fc339adc01f23ef5e2bcd` both match frozen
source `cbda2ac7e3376b858c1e8d5d010a304474c659cf`. No runtime code,
dependency pin, deployment consumer or crypto implementation changes.

The observed language-neutral lifecycle floor is:

- an already-stopped loop starts no work;
- stop or cancellation interrupts a long polling wait without another cycle;
- polling expiry and a cycle exception allow a subsequent cycle while keeping
  the same worker identity and heartbeat;
- external cancellation waits for active-cycle cleanup and propagates;
- after initialization, normal loop exit, failure and cancellation all await
  database-engine disposal;
- cancellation of a real in-memory cycle joins both processor and lease
  renewal tasks, leaves no child task running, and does not falsely complete
  the still-leased job.

The last observation does not prove PostgreSQL reclaim or crash-race behavior;
those require the separate real-database gates. Entry-point tests replace
database factories and do not connect to a database. Their SQLAlchemy calls
are legacy wiring observations, not requirements to reproduce those APIs in
Rust. Initialization failures before loop entry remain a separate boundary.

These tests advance the frozen shutdown/cancellation/disposal scenarios but
do not clear all their requirements: allowlisted exception logging is still
pending, and the existing Python traceback behavior is not approved privacy
parity. Configuration reconciliation, renewal fences, provider differentials,
PostgreSQL races, readiness, all-consumer routing and beta acceptance remain
mandatory before Rust cutover or Python deletion.
