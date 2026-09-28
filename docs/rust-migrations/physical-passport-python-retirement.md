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
their release, image, route, callback and rollback lineage. A qualified record
proves software route compatibility and Rust ownership. It must explicitly
report `physical_claim=not_claimed`; a simulator callback cannot prove physical
personalization or a booklet.
Confirm all nine Gateway and Flow routes select Rust, the KMS CSCA/DSC chain and SOD
validate, the packaged image and signed bureau callback pass, legacy jobs and
artifacts satisfy the drain gates, and rollback plus production isolation are
verified. The beta bureau is synthetic; it does not prove physical booklet
production or qualify a future external bureau provider.

The beta report must include `physical_bureau_batch` as a **simulator route
compatibility** probe: at least two jobs, an accepted HTTP result, queued batch
status, distinct source and bureau job commitments, and an observable one-to-one
mapping. The protected producer must derive the published job, request, and
response commitments with HMAC-SHA256 using a private acceptance key, then
privately verify the `BETA-SIM-` marker and publish
`physical_claim=not_claimed`. The verifier runs the frozen Rust shuffled-response
batch adapter test from the protected source checkout. The report binds keyed
request and response commitments plus the signed callback receipt digest to the protected source commit,
stack manifest, and released services image without publishing raw IDs or
document data. This evidence preserves the nine-route software behavior; it
does not qualify a future physical provider.
The producer must generate one random 256-bit commitment key per acceptance
run, keep it out of uploaded artifacts, and reuse it across the submitted and
returned job mapping. HMAC inputs are domain-separated as
`passport-retirement/v2:<field>\0` followed by the exact UTF-8 job ID or exact
HTTP request/response body bytes. It must inspect the later simulator tracking
result for `BETA-SIM-`; the batch submission may return UUID bureau job IDs.
`callback_receipt_sha256` hashes the exact protected signed callback receipt,
including its signature, rather than a status value.
An accepted beta report must name simulator mode and exactly the gateway, Flow,
native issuance, signing keys, beta callback signer, and beta bureau services
from the signed services image.

The beta-only overlay does not qualify the default, self-host, or Kubernetes
consumers. Before deleting the Python route owner, each supported composition
must route and authenticate all nine operations to Rust, select managed signing,
exercise a signed simulator callback without a physical claim, and pass runtime and rollback
acceptance. In the current source, Gateway, Flow, and native issuance default
passport routing off outside beta; self-host Flow also lacks a distinct native
issuance URL, and Kubernetes has no passport selector. Record the protected
consumer cutover commit and its evidence separately from the beta release
commit. The current qualification verifier requires both receipts to name the
same protected source commit. If a later consumer cutover uses a different
commit, extend and review its protected ancestry, report, and signed image
lineage checks before qualification. Keep production deployment unchanged until
separately authorized.

The dedicated Passport Python Retirement Provenance CI job intentionally fails
while this candidate is blocked. It also rejects a syntactically complete
`qualified` record: the current release pipeline has no physical-passport
acceptance report producer or verifier, so receipt names and SHA-shaped strings
cannot authorize deletion. Before promoting this PR, add an executable
acceptance producer and verifier for the beta and all three supported
consumers, bind their reports to the protected source and signed release, and
make that CI job pass on the exact retirement head. The executable verifier now
has an achievable qualified path for software route compatibility, but the
qualification contract remains blocked and contains no invented receipt.
