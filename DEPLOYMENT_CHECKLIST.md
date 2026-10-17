# Deployment acceptance and ownership

This repository provides Rust bindings and an internal Python test harness.
It does not provide a deployable Python issuance service. The historical
architecture diagram, local deployment commands and checked production-ready
claims are retired; they did not qualify the current service stack.

Deployment, configuration, service migrations and release qualification belong
to [Marty UI](https://github.com/ElevenID/marty-ui). Canonical cryptographic
libraries belong to [Marty Core](https://github.com/ElevenID/marty-core).
Official and owned interoperability testing belongs to
[marty-integration-tests](https://github.com/ElevenID/marty-integration-tests).
Use their current workflows and immutable release inputs.

## Requirements requiring current evidence

The earlier checklist does not establish any item below complete. Reconcile
each with the current owners and record exact release, configuration, result
and operator approval before a deployment or cutover:

- Validate environment selection, explicit database connections, secret
  provisioning, trusted issuer certificates and trust anchors, TLS and
  certificate verification. Qualify any required network restrictions.
- Prove authenticated and authorized public/internal operations, token
  validation, tenant boundaries, per-issuer/per-verifier rate controls and
  safe failure behavior. Retired Python feature flags, cache choices and
  sample limits are not current security policy.
- Exercise the advertised W3C VC, SD-JWT, mdoc and Open Badges issuance and
  verification journeys, signature/trust-chain decisions, expiry, revocation
  and status checks. Distinguish claimed formats and optional features from
  those actually qualified, including external-wallet interoperability.
- Use approved managed signing-key and secret custody. No production flow may
  acquire a local private signing key from the retired architecture's key
  generation example. Existing [secure-storage obligations](docs/rust-migrations/integration-secret-secure-storage-outstanding.md)
  and [DIDComm custody obligations](docs/rust-migrations/didcomm-kms-outstanding.md)
  remain open.
- Prove durable credential/status data, event delivery and recovery, audit
  records, failure propagation and concurrency. Select actual infrastructure
  from the current deployment profile; the old Redis/Kafka examples do not
  mandate or qualify a backend.
- Verify health/readiness, structured privacy-safe logs, operation/failure
  counters, latency distributions, throughput, active-state gauges, metrics
  scraping, dashboards and actionable alerts. Include success/failure
  event consumption by audit, analytics or other supported subscribers.
- Qualify fresh install, schema and catalog migration, upgrades, backup,
  restore, rollback/forward repair and post-recovery health without losing
  credentials, tenant bindings or audit history.
- Verify signed immutable release/image lineage, current dependency/security
  checks, actual service startup, public API behavior and post-deployment
  integration tests. Keep production pins unchanged until the separately
  governed release/cutover gate authorizes a change.
- Record accountable deployment and operational signoff, monitoring and
  alert ownership and a tested incident/rollback procedure. Historical
  blank signoff rows and placeholder contact details supply no approval.

The removed empty Pact file contained no interactions or assertions. It was
not a gateway behavior contract. Any future consumer/provider contract needs
real interactions and execution against the current gateway owner.
