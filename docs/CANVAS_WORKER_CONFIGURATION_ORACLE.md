# Canvas worker configuration oracle

`contracts/canvas-worker-configuration-oracle.json` records input/output
observations from the actual Python worker at protected source
`cbda2ac7e3376b858c1e8d5d010a304474c659cf`. The unit test calls the worker's
configuration loader directly, with inherited worker environment values
removed. It does not copy or reimplement the loader.

The fixtures cover defaults, lower and upper bounds, signed and fractional
values, generated and explicit identities, and malformed numeric startup
failures. They also expose previously untested differences from the unrouted
Rust candidate: identity whitespace, non-finite durations, numeric separators,
and integers outside signed 64-bit range. Cases marked
`rust_reconciliation_required` are observations, not approved Rust semantics
or cutover evidence. In particular, Python currently clamps NaN and infinity
to finite duration bounds; Rust rejects these inputs.

The Rust migration must consume these language-neutral cases, retain intended
operator behavior, and explicitly resolve any deliberate hardening differences.
Do not erase an observed behavior or mark the configuration gap closed merely
because the Rust candidate's existing tests pass. Processor configuration,
whole-worker database/provider differentials, readiness, all-consumer routing,
and beta acceptance remain separate mandatory gates.
