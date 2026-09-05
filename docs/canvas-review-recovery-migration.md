# Canvas correction-review recovery claim

The existing recovery service claims the internal `evidence_recovered` action
after a manual credential handler fails while recovered evidence is pending.
The published `merge_issuance_heads` schema rejects that action. The service
preserves the original handler error, but the review remains open and pending
without a resolution audit event. An in-memory test could not detect this.

Forward revision `canvas_review_recovery_claim` permits that existing internal
action in the claim constraint and aligns the persistence model. The three
manual actions, open-state requirement, token/time shape, tenant foreign keys,
application lock and compare-and-set finalization are retained. The public
manual action API still accepts only dismiss, suspend and revoke. No row is
rewritten and no credential lifecycle implementation is added or replaced.

The required PostgreSQL CI job now runs the real migration/service/repository
regression in a fresh owned database. It reproduces the old schema failure,
then verifies recovered-during-handler resolution and exactly one audit event,
one winner from competing repository claims, stale/foreign/action-mismatch
fences, audit-insert rollback, and unchanged credential/transaction rows.
External credential handling is a controlled failing port, not a signing or
external provider qualification. The pinned historical worker oracle remains
unchanged. Published consumer replay still requires its historical migration
head; checkout replay requires the independently frozen current runtime surface
head. All 36 cycle and three loop expectations remain identical. The current
runtime inventory and current-head idempotency gate advance to the new revision.

Downgrade must run only after recovery claims drain. If a recovery claim is
still active, PostgreSQL rejects the old constraint and rolls back the whole
migration; the live claim and new version remain intact. The test exercises
that refusal, then a drained downgrade/re-upgrade preserving resolved rows and
audit history. Do not clear claims or delete pending reviews to force downgrade.

This source change does not deploy or reconcile existing beta/production rows.
The intended Rust operations port must use the corrected schema and qualify
the restored behavior explicitly, not copy the defective historical outcome.
