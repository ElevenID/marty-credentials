# Canvas worker outcomes after renewal failure

`contracts/canvas-worker-renewal-job-outcomes.json` freezes observations from
`b027e834d71dee0cc3550aac1150cdb0c40946ae`, worker blob
`b516ed3d0855f16e9ec899a452a22df49d2cafe5`. The reused worker setup helper remains
blob `58a0b457bb13d1c94a1fc339adc01f23ef5e2bcd`.

The 60 cases in `tests/unit/test_canvas_worker_renewal_job_outcomes.py` call the
actual `_process_leased_job` and its actual `_maintain_job_lease` task. They use
the real in-memory repository and a controlled processor. Only the worker's
sleep reference is gated, and one selected renewal write raises a synthetic
exception. Initial heartbeat and subsequent fenced outcome writes still call
the real repository. Global asyncio, job handler, maintainer, task creation and
wall-clock deadline implementation are not replaced.

Each lease, target-heartbeat and process-heartbeat error completes the maintainer
but leaves the processor active and the job handler pending. With a still-valid
lease, the later processor outcome determines durable state **before** the job
handler re-raises the original renewal exception:

| Processor outcome | Durable job state | Completed timestamp | Durable error code |
| --- | --- | --- | --- |
| Success | succeeded | present | none |
| Retryable failure | retry | absent | synthetic_processing_retry |
| Permanent failure | dead_letter | present | synthetic_processing_terminal |
| Deadline | retry | absent | canvas_sync_deadline_exceeded |
| Cancellation | leased | absent | none |

The test then repeats every combination after separately changing the durable
lease owner, expiring the lease, or advancing its attempt count. Every stale
outcome leaves that modified durable job exactly unchanged. Each case verifies
processor cleanup and that no owned task survives the observation. This is
3 renewal failures × 5 processor outcomes × 4 fence states, not 60 unrelated
handwritten implementations.

## Implications for the Rust migration

The native candidate currently stops its owned processor immediately on renewal
error. Its new SQL partial-write tests establish maintainer write boundaries,
but cannot establish these complete job outcomes. Dropping legitimate successful
or retry outcomes is a behavioral difference that must be resolved before
all-consumer worker cutover and Python deletion.

Do not mechanically reproduce every Python consequence. In particular, awaiting
an already-failed maintainer in `finally` masks external cancellation with the
renewal exception, even though the processor is cleaned. The Rust cancellation
acknowledgment and published SIGINT130 contract must stay intact. Likewise, a
renewal exception is not permission to persist through a lost owner, expired
lease, advanced attempt, or stale target generation.

The next native review must distinguish operational renewal/heartbeat errors,
known lease loss, processor termination, and external cancellation. Preserve
legitimate fenced outcomes while retaining owned cleanup and fail-closed
side-effect repositories; test these decisions against actual PostgreSQL and
the authoritative processor. This fixture records the legacy floor, not an
approval to weaken fences, copy cancellation masking, or activate the candidate.

This is not published-schema, provider-effect, full-cycle accounting, readiness,
all-consumer, production or beta acceptance evidence. No runtime or crypto code,
dependency pin, release coordinate or consumer is changed by this oracle.
