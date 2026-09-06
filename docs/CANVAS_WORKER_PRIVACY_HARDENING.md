# Canvas reference privacy gates

This change addresses the two explicit reference-side prerequisites in the
Marty UI worker migration contract: bounded JSON signing-service diagnostics
and allowlisted worker error logs. It is not a new production Python capability,
a worker cutover, or a replacement for the native Rust implementation.

Base: protected Credentials main `2dfbd6a0a82bb302ecb2c29b9df0ce1c2056ef6f`.
Existing reference worker blob: `b516ed3d0855f16e9ec899a452a22df49d2cafe5`.
Existing signing helper blob: `a72574c4b4e35690e0cdf2df4ee28a092686069c`.
No existing frozen corpus, immutable image pin, crypto implementation,
dependency, consumer command, database schema or lease policy is changed.

## Bounded signing-service diagnostics

The shared `_response_error_detail` now selects the existing diagnostic value
first, then applies one 500-character limit. This covers JSON `detail`,
`error_description` and `error` strings and objects, plain text and reason-phrase
fallback. Short strings, whitespace trimming, field precedence and short Python
dictionary representations remain unchanged. The limit counts Unicode
characters, not encoded bytes. This bounds diagnostics; it does **not** promise
that the first 500 characters of an upstream message are free of sensitive data.

The three remote operations retain their existing status handling and message
prefixes. Tests use synthetic HTTP responses and no real signing service. The
new 51-case detail suite includes exact 499/500/501-character boundaries,
Unicode, dictionary representations, fallback behavior and all three operation
paths for 401 and 503 responses.

## Allowlisted worker error events

One private logging owner permits only a static event/message, exception class,
and explicit job, organization or platform identifiers. It never attaches an
exception object, response, exception message, traceback or stack. The JSON
message preserves useful fields under the deployed `basicConfig` formatter;
the same fields are also available as structured LogRecord attributes. JSON
encoding escapes identifier control characters rather than interpolating them
into additional log lines.

| Event | Identifier fields | Unchanged operational behavior |
| --- | --- | --- |
| `canvas_sync_job_failed` | `job_id` | Unexpected 429 remains rate-limited; other errors remain unexpected-error retries with static persisted summaries. |
| `canvas_oauth_disconnect_marker_failed` | `organization_id`, `platform_id` | Successful remote revoke and connection removal still clean both local secrets even when the marker update fails. |
| `canvas_sync_job_outcome_failed` | `job_id` | Escaped job remains leased for recovery; successful sibling is awaited and completes. |
| `canvas_sync_cycle_failed` | none | The loop continues and the next real cycle can return to idle. |

Six new worker observations exercise these actual error branches using the
existing in-memory repository and controlled failing boundaries. They assert
exact structured fields, rendered safe diagnostics and absent exception/stack
metadata, while checking job/target/connection/secret or heartbeat outcomes.
Each now runs standalone and with ambient correlation injection (12 executions).
An owned handler snapshots producer fields before root handlers mutate records;
the actual downstream rendered logs remain part of the redaction assertions.
They are not PostgreSQL crash/concurrency or deployed-log-collector acceptance.
Existing warning/info messages and cancellation/fencing behavior are retained.

## Evidence and remaining qualification

- Unchanged baseline worker/lifecycle suite: 21 passed.
- Before repair, corrected fixtures demonstrated 21 detail-bound failures
  (30 short/status controls passed) and six missing private-log guarantees.
  One escaped-outcome case previously omitted raw exceptions but lacked the
  required structured fields; the other five attached exception tracebacks.
- After repair, all 716 affected worker/detail tests and 200 subtests passed on
  Python 3.12 in 7.13 seconds, retaining configuration, loader, lifecycle,
  result, consumer-range, renewal and renewal/job-outcome coverage.
- The first hosted Python run (CI34057702111, job101552533945) passed 1661 tests
  and 200 subtests, with two existing skips, but failed six privacy assertions:
  API tests register a root-handler filter adding `request_id` to the same
  mutable LogRecords. This did not occur in the focused local run. The tests
  now snapshot worker-owned records before root-handler enrichment, retaining
  the exact allowlist rather than ignoring arbitrary extra fields. Dedicated
  ambient-correlation cases verify the enrichment actually executes. The
  corrected affected suite passes 722 tests and 200 subtests in 7.11 seconds;
  Ruff passes. This is a test-only correction and requires fresh hosted CI.
- Ruff passes for all four affected source/test files. The existing redundant
  `open(..., "r")` mode was removed without changing file-secret behavior.
- Expanded local issuance run: 857 passed, 200 subtests passed, three failed.
  The same three Core-binding assertions fail on an untouched checkout of the
  exact protected-main baseline (141 passed, three failed). No failing test was
  skipped, relaxed or changed. The temporary baseline worktree was verified
  clean and removed; test output/directories were retained outside it.

The local interpreter loads globally installed `marty-rs==0.1.60`. Credentials'
release manifest pins Core `dce4fb99016dfcb3801fbfb9dcab9e8b0f74bd4f`, while
its CI builds Core `08a0d435390f13186cb6f6278b9a15f9020067a7`. Protected-main
CI34026589471 passed with its configured dependencies. This is a remaining
release/binding qualification finding, not proof that this machine's installed
wheel is equivalent to the CI artifact. Require fresh pinned-build CI and
reconcile the release artifact before aggregate adoption; do not hide the
finding by changing cryptographic assertions or the other worker's branch.

After protected landing, record the exact revised source provenance and capture
the hardened language-neutral privacy observations for Rust comparison. Retain
all older frozen behavior evidence unchanged and identify intentional privacy
hardening explicitly. Neither a source patch nor these local tests alone closes
the aggregate worker deletion/acceptance gates. Production and persistent
self-host deployments remain unchanged.
