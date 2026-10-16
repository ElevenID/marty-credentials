# Canvas regression ownership

The Python issuance service and worker are retired. Their capture tools, tests,
and duplicate fixtures no longer belong in Credentials. The canonical frozen
Canvas corpora and executable regressions live in
[Marty UI contracts](https://github.com/ElevenID/marty-ui/tree/main/contracts)
and [native issuance tests](https://github.com/ElevenID/marty-ui/tree/main/rust/services/issuance/tests).
The removed copies and per-slice capture reports remain in Credentials Git
history at `52c14e5`. Their removal does not qualify a release or deployment.

The configuration, numeric, result, privacy and renewal-outcome copies were
byte-identical to UI's fixtures. The older consumer-range copy differed only
in `schema_preparer_source_sha256`; UI retains the current preparer binding,
original observations and published-image provenance. No expected observations
were regenerated from Rust output.

Current regression requirements remain with the native owners:

- Configuration and result projections preserve arbitrary integers, Unicode
  numeric grammar, JSON integer/float distinctions, defaults, error phases,
  and the 200-code-point result string bound. Non-finite or other intentional
  hardening differences require explicit reconciliation, not skipped cases.
- Consumer ranges are checked at their actual scheduling, SQL and time
  boundaries, including empty queues, OAuth's pre-conversion cap of 500, and
  loop survival. Historical Python exception names are not a new Rust API.
- The authoritative Rust processor replaces dynamic Python loader selection;
  routing must not retain `CANVAS_SYNC_PROCESSOR` as an alternate implementation.
- Shutdown and cancellation join processor/renewal tasks and await disposal.
  The legacy renewal floor is lease/3 bounded to 10?30 seconds; durable renewal
  precedes the detached lease update, target heartbeat and process heartbeat.
  Renewal errors must distinguish operational failure from lease loss, preserve
  legitimate fenced outcomes, and never write through changed owner, expiry,
  attempt or target generation. Do not reproduce Python cancellation masking.
- Privacy regression checks retain bounded signing diagnostics and allowlisted
  worker events without exception text, tracebacks or secrets, including ambient
  correlation injection. A 500-character bound alone is not secret redaction.
- PostgreSQL races, provider behavior, readiness, all-consumer routing and the
  applicable release, beta/device and installed-runtime acceptance gates remain
  independent requirements. Source tests are not deployment acceptance.

The separate [review recovery migration](canvas-review-recovery-migration.md)
retains schema and downgrade constraints; it is not a capture-tool instruction.
