# Canvas worker processor-loader oracle

The tests in `tests/unit/test_canvas_worker_loader_oracle.py` observe the
actual legacy loader at frozen production source
`cbda2ac7e3376b858c1e8d5d010a304474c659cf`. No loader implementation is copied
and no service, dependency pin, deployment consumer or crypto code changes.

Covered observations are:

- absent or whitespace-only configuration returns an unconfigured result
  without importing a processor;
- malformed selector syntax fails before attempting an import;
- surrounding whitespace is removed, but the attribute is literal: missing,
  dotted, extra-delimiter and internally whitespace-prefixed attributes fail;
- existing callables retain their identity and are not invoked by selection;
- noncallable attributes fail instead of silently disabling the processor;
- real missing-module failures and injected dependency/initialization failures
  propagate without a fallback processor.

These are legacy wiring observations, not a portable dynamic-import API.
The native Rust worker must use its authoritative processor and remove
`CANVAS_SYNC_PROCESSOR` from every Compose, self-host and Kubernetes consumer
at cutover. A callable accepted by this loader is not necessarily a valid
async processor; runtime result-shape and async behavior remain separate gates.
Do not recreate Python module paths, silently drop processor behavior, or
treat these tests as whole-worker parity, readiness or deletion evidence.

Environment-number reconciliation, loop lifecycle and disposal, database
races, provider behavior, privacy projections, all-consumer routing and the
beta-only acceptance soak remain required by the frozen worker contract.
