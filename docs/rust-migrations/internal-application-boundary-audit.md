# Internal Application Rust migration boundary audit

**Status:** behavior-freeze audit in progress; no route is cut over and no
Python implementation is deleted.

The audit found and repaired one retained-owner defect before freezing the
boundary: the wallet-invite GET handler referenced a nonexistent
`ApplicationStatus.ISSUED` member and therefore crashed for every request that
reached its status check. Applications remain `approved`; issuance completion
belongs to `IssuanceTransaction`. A focused regression now exercises an
approved application and its transaction through the actual offer-read handler.
The same audit restored the intended application identifier precedence: a
trimmed given/family name, then email, then a generated opaque identifier. The
old formatted empty-name expression was always `_`, making both fallbacks
unreachable for email-only and anonymous submissions.
The external-evidence audit also removed provider exception text from public
502 responses. Provider failures now retain the application/check identifiers
and exception type in server logs without reflecting a token, URL, or provider
message into the management API response.
The offer replay audit also replaced the non-atomic read-then-create path with
the repository's existing tenant-scoped idempotent reservation primitive. Two
concurrent initial or refresh requests now share one transaction and offer
instead of leaving an unreachable duplicate transaction behind.

**Ordering:** this work follows the eight-route Application Template Rust
landing and its separately gated Python management retirement. The
`ApplicationTemplate` entity, persistence, migrations, and application-facing
lookup behavior remain required inputs to this slice.

## Why this is the next coherent target

After the staged Application Template cutover, the issuance inventory contains
49 Python-owned HTTP operations. The internal Application router is the largest
coherent remaining family: 14 routes and at least 695 lines in the route
handlers alone, excluding shared domain, evidence, offer, repository, and test
code. The larger 18-route `issuance_router` remainder is several independent
protocol and operations families and must not be treated as one deletion unit.

## Frozen route inventory

All routes use the management API-key dependency and the trusted
`X-Organization-ID` tenant boundary.

| Method | Path | Operation |
|---|---|---|
| `POST` | `/internal/applications` | create application |
| `GET` | `/internal/applications` | list applications |
| `GET` | `/internal/applications/{application_id}` | get application |
| `GET` | `/internal/applications/{application_id}/evidence-facts` | list evidence facts |
| `GET` | `/internal/applications/{application_id}/evidence-summary` | get evidence summary |
| `POST` | `/internal/applications/{application_id}/evidence/api-checks/{check_id}/run` | run external evidence API check |
| `POST` | `/internal/applications/evidence/reconcile` | reconcile evidence transitions |
| `GET` | `/internal/applications/evidence/reconciliation-report` | produce a dry-run reconciliation report |
| `POST` | `/internal/applications/{application_id}/submit-evidence` | submit evidence |
| `POST` | `/internal/applications/{application_id}/approve` | approve and prepare issuance |
| `POST` | `/internal/applications/{application_id}/reject` | reject application |
| `GET` | `/internal/applications/{application_id}/issuance-events` | list issuance events |
| `POST` | `/internal/applications/{application_id}/issuance-offer` | generate or refresh wallet invite |
| `GET` | `/internal/applications/{application_id}/issuance-offer` | retrieve wallet invite |

No public `/v1/applications` alias exists. A native selector must match only
the method/path pairs above; sibling and unsupported methods stay with their
current owner until separately frozen.

## Behavior that must survive the port

- Authentication fails closed when the management key is unconfigured,
  missing, or incorrect.
- Missing trusted tenant context is rejected. Claimed organization mismatches
  and foreign application IDs remain indistinguishable from not found.
- Creation requires an existing active Application Template in the trusted
  organization and preserves applicant data and integration context.
- List filtering preserves organization, status, and template semantics. Item
  responses preserve every current field and timestamp representation.
- Evidence facts retain revision head, logical key, source revision, payload
  hash, observation/effective timestamps, and supersession metadata.
- Evidence summaries preserve policy source/set, Canvas context, transaction
  binding, and reviewer-safe available external API check descriptors.
- External API checks retain bounded configuration, response mapping,
  normalized fact persistence, policy evaluation, optional issue-on-permit,
  atomic failure behavior, and public error mapping.
- Reconciliation preserves bounded limits, dry-run behavior, stale-reason
  reporting, policy/audit writes, and approval-to-issuance recovery without
  cross-tenant mutation.
- Evidence submission remains pending-only. Approval and rejection remain
  pending-only and continue using server-owned reviewer identity.
- Approval retains the Canvas issuance guard, live authenticated credential
  template resolution, active revocation-profile binding, issuer/signing
  context resolution, transaction association, and failure atomicity.
- Issuance offers remain application-approved for generation and reads, while
  the associated transaction is authoritative for issuance progress. They
  preserve fresh/reusable transaction rules, pre-authorized
  offer construction, per-wallet deep links, expiry status, event creation,
  authenticated wallet discovery, and Canvas readiness enforcement.
- Existing Application, Application Template, IssuanceTransaction, evidence,
  policy, event, delivery, and Canvas consumers remain usable throughout the
  migration. The port must not narrow those shared storage contracts merely to
  make the HTTP candidate easier to implement.

## Existing evidence and uncovered gates

Existing tests cover internal-only routing, server-owned reviewer identity,
trusted-tenant rejection, foreign-resource hiding, evidence fact projection,
external evidence policy transitions, reconciliation recovery/reporting,
Canvas approval guards, offer idempotency, and offer transaction-read
behavior. Those tests are valuable but are distributed and do not yet prove a
single language-neutral 14-route boundary.

The canonical
[`issuance-internal-applications.json`](../../contracts/issuance-internal-applications.json)
contract and Python oracle now freeze the route surface, authentication,
tenant boundary, request validation, and typed response projections. The
contract deliberately leaves Rust implementation unauthorized until the
remaining behavioral groups below are executable. Before implementation
begins, extend that same contract and oracle suite to cover:

1. every method/path and unsupported sibling routing;
2. authentication and tenant failures on every route class;
3. request-model unknown, missing, null, and malformed inputs;
4. complete response projection for applications, evidence, events, and offers;
5. every lifecycle success and invalid-state transition;
6. dependency not-found, unavailable, wrong-tenant, inactive, and malformed
   responses;
7. exact write sets and no-mutation guarantees for every failure;
8. idempotent/replayed offer behavior and concurrent transition conflicts;
9. external API timeout/transport/mapping failures without secret leakage;
10. Canvas and non-Canvas approval/offer paths with real repository state.

The Rust implementation may start only after that contract replays against the
Python owner. Python deletion remains forbidden until the candidate passes the
same contract, isolated PostgreSQL tests, complete HTTP lifecycle coverage,
packaged-main/gateway routing, all retained-consumer tests, and protected CI.

## Explicit non-goals

- DIDComm KMS redesign remains deferred.
- Application Template entity or storage retirement is not part of this slice.
- Canvas provider orchestration is preserved as a consumer/dependency unless a
  separately frozen capability is deliberately moved.
- No beta or production deployment occurs for this contract/audit work.
