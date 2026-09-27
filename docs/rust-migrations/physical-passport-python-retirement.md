# Physical-passport Python retirement candidate

This branch removes the nine legacy FastAPI passport routes and their Python
signer and bureau adapters. It is a **draft** until the separate Rust owner is
merged, released, and accepted in beta. The current base and self-host profiles
still default to the legacy passport owner. Merging this branch before those
profiles and their consumers are coordinated would remove a working route.

The frozen Python route and provider references remain in `contracts/`.
Their source hashes and test paths identify the pre-retirement commit; the
deleted Python test module is recoverable from Git history at that checkpoint.
`issuance-runtime-surface.json` describes the remaining live Python service
after this deletion. The `physical_document_jobs` SQLAlchemy model and Alembic
history remain because Rust owns the same durable table and existing records.
The earlier OID4VCI/Canvas and retention qualification records remain historical
evidence and are not rewritten as passport authorization.

Before making this PR ready for review, record the protected `marty-ui` source
commit, live beta receipt, and supported-consumer cutover receipt in
`contracts/physical-passport-python-retirement-qualification.json`. Check
that the four source artifact hashes match committed bytes on protected main,
and that both evidence artifacts match their receipt SHA-256 digests. The
shape test accepts both the current blocked record and a complete qualified
record; it does not itself verify remote Git ancestry or runtime evidence.
The required `Passport Python Retirement Provenance` CI job runs
`scripts.check_physical_passport_python_retirement`. It is intentionally red
while this PR is draft. A future qualified record must pass live protected-main
ancestry, committed source hashes, the signed stack manifest and its official
CD signer, exact successful beta and supported-consumer workflow artifacts, and
their release, image, route, callback and rollback lineage. It still refuses a
`qualified` record until independent physical booklet/provider proof and its
maintainer review have a verifiable source; a successful callback or a report
field marked `verified` does not prove physical personalization.
Confirm all nine Gateway and Flow routes select Rust, the KMS CSCA/DSC chain and SOD
validate, the packaged image and signed bureau callback pass, legacy jobs and
artifacts satisfy the drain gates, and rollback plus production isolation are
verified. The beta bureau is synthetic; it does not prove physical booklet
production or qualify a future external bureau provider.

The beta report must also include `physical_bureau_batch`: a live two-job or
larger physical-provider batch exchange with an accepted HTTP result, queued
batch status, unique source and provider job ID hashes, and an observable
one-to-one response mapping. The verifier runs the exact frozen Rust batch
adapter test from the protected source checkout and requires its shuffled
response oracle to pass; the live provider need not shuffle. The report
records request, response, and provider
receipt digests without publishing raw IDs or document data. Its evidence must
name the protected source commit, signed stack manifest, and exact released
services image. The future protected producer must inspect raw provider IDs
privately and reject `BETA-SIM-` IDs before hashing them. This source-bound
report shape is only one prerequisite; it does not authenticate a physical
provider receipt or prove a manufactured booklet. The final unconditional
retirement block stays until those independent proofs are machine-verifiable
and reviewed.
An accepted beta report must name physical provider mode and exactly the
gateway, Flow, native issuance, signing keys, supported callback signer, and
provider ingress services from the signed services image. The simulator
callback signer and beta bureau services cannot appear in that report.

The beta-only overlay does not qualify the default, self-host, or Kubernetes
consumers. Before deleting the Python route owner, each supported composition
must route and authenticate all nine operations to Rust, select managed signing
and a supported bureau/callback provider, and pass runtime and rollback
acceptance. In the current source, Gateway, Flow, and native issuance default
passport routing off outside beta; self-host Flow also lacks a distinct native
issuance URL, and Kubernetes has no passport selector. Record the protected
consumer cutover commit and its evidence separately from the beta release
commit; they may differ. Keep production deployment unchanged until separately
authorized.

The dedicated Passport Python Retirement Provenance CI job intentionally fails
while this candidate is blocked. It also rejects a syntactically complete
`qualified` record: the current release pipeline has no physical-passport
acceptance report producer or verifier, so receipt names and SHA-shaped strings
cannot authorize deletion. Before promoting this PR, add an executable
acceptance producer and verifier for the beta and all three supported
consumers, bind their reports to the protected source and signed release, and
make that CI job pass on the exact retirement head.
