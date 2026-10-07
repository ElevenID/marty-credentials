# Physical-passport Python retirement candidate

This draft deletes the nine legacy FastAPI passport routes and their Python
signer and bureau adapters. It remains blocked until the Rust owner passes one
protected disposable KMS acceptance run on the signed six-service runtime.
No beta deployment or YouTube recording is required before deleting
the superseded Python passport code. Those follow deletion in the single
aggregate beta release and acceptance soak. Production remains unchanged.

The frozen route and provider references remain in `contracts/`. Their source
hashes identify the pre-retirement implementation; the deleted Python tests
remain recoverable from Git history. The `physical_document_jobs` SQLAlchemy
model and Alembic history remain because Rust uses the same durable table and
existing records. This PR does not authorize removal of the whole Python
issuance service, which still serves other routes.

## Pre-deletion qualification

Record the protected `marty-ui` main commit and its seven committed artifact
hashes in `contracts/physical-passport-python-retirement-qualification.json`.
Bind that commit to a signed stack manifest and its official CD signer. Supply
the SHA-256-checked disposable Rust passport acceptance artifact from a
successful protected-main workflow. It must name the same source commit,
signed stack manifest, and released services image. An attested final cutover
report is discovered from a
protected workflow after the exact deletion PR head exists; its run ID cannot
be stored in the qualification JSON without changing that head. The named
pre-deletion acceptance producer from `marty-ui` PR #1011 is on protected
main and still awaits accepted runtime evidence. The final cutover
producer exists, and the qualification record has no invented receipt.

The protected disposable report must prove all nine Gateway and Flow routes
have one Rust owner, including unauthorized and cross-tenant rejection. It
must verify an active, organization-bound ICAO_EMRTD issuer profile, distinct
KMS-backed CSCA and DSC keys and certificates, and the SOD signature against
those exact certificates. Signing Keys must be part of the signed runtime image
set. It must verify packaged runtime images, Marty simulator submission and
two-job batch mapping,
signed callback and Flow execution. The callback must name the batch's exact
job commitments and signed receipt digests, and the native container that
completed them. The batch report uses HMAC-SHA256
commitments for request, response, source jobs, bureau jobs, and signed
callback receipts. Each callback record must pair its source and returned
bureau job commitments with the exact receipt and native completion, bound to the protected commit, signed stack, and services
image. The acceptance key stays private. `physical_claim=not_claimed` and
`booklet_verified=false` prevent a synthetic callback from claiming physical
personalization or a booklet. No external provider is involved.

Install and verify the scoped passport write fence in the real beta deployment
while the shared Python issuance container remains running. The fence must
reject passport job and physical Flow writes, including direct database writes,
while unrelated issuance continues. Query its identified legacy database after
the fence is enabled; bind the zero
nonterminal-job, legacy or unknown artifact, unreadable artifact, and active
passport-Flow counts to that database. Record the beta cluster, writer
deployment, exact running container, writer generation, fence epoch and
verification digest, strictly increasing observation sequence watermarks for
fence and drain, and UTC times. A protected producer must attempt writes to the
job, Flow definition, and Flow
instance surfaces in rollback-only database transactions and attest each
rejection at the drain observation watermark. Each probe uses the running
Python container's `marty` database role, a valid candidate write, and the
fence's exact SQLSTATE and error message. A fresh disposable database cannot
satisfy this gate. The report must also prove
exact disposable resource identity, unchanged production resources, and a beta
inventory change limited to the identified scoped fence. Other beta resources
must remain unchanged.
The protected disposable run must bind all six Rust service selectors, released
images, route and callback probes to one owned resource identity. It must
restart Rust issuance and resume the same KMS-backed durable job. Bind the
before and after native container identities, signed image, owner labels,
organization, issuer profile, and job commitment to inspected runtime records.
A Python owner phase is not part of this gate. The optional base, self-host,
and Kubernetes live fixture is deferred to #944; the frozen Rust batch parity
test and protected disposable run are required here.

The fence installation and drain observation complete before the protected
pre-deletion acceptance run consumes their attested evidence. After that run,
run the
protected final deletion-cutover workflow on the exact `marty-credentials` PR
head. It must re-inspect the same beta database and Python writer deployment,
verify the exact Python container is still running, its generation and fence
epoch have not advanced, recheck the zero counts at a strictly later
observation sequence watermark with a distinct snapshot digest, and verify the
durable write fence still rejects passport writes. The verifier requires
fresh direct database rejection probes at the final watermark, with a new
receipt digest and later probe time, while the fence identity and epoch remain
the same. It checks the attested report's exact deletion head and ordered run
times.
The PR CI job passes `github.event.pull_request.head.sha` explicitly because
Actions checks out a synthetic merge commit. It verifies the event's PR number,
same-repository head and main base, then checks that the live #305 head still
equals that event head. Merge-group checks resolve #305's exact head and its
live merge-queue entry, then require that entry's head commit to be an ancestor
of the running group SHA. Before merge, they recheck the attested final cutover
for that exact head and require successful post-cutover PR provenance and CI
Gate jobs from the same workflow attempt, in the expected GitHub Actions check
suite. Both jobs must have started after the final cutover; the original run
creation time can precede it when CI is rerun. The protected merge queue must
pass these full checks before #305 merges.

After merge, later PR, merge-group, and main CI check #305's immutable merge
ancestry, require the qualification record to match its bytes at that merge,
verify the signed stack release and pinned source, inspect the current Python
route surface for the absence of passport routes, and run the frozen Rust batch
parity test. The permanent gate does not download the pre-deletion or cutover
Actions artifacts after their 30-day retention expires. The protected merge
itself is the durable authorization checkpoint; a synthetic or later commit
never substitutes for #305's exact deletion head before merge.
There is no short wall-clock expiry: CI and review can take hours while the
fence prevents new Python passport writes. Any new deletion commit or lost
fence requires another protected final cutover run before merge.

`scripts.check_physical_passport_python_retirement` verifies protected-main
ancestry, committed bytes, signed release and image lineage, exact workflow
identity, report SHA-256 digests, route and evidence semantics, and the frozen
Rust shuffled-response batch test. Before merge it also verifies the attested
final cutover artifact from the protected main workflow. The required Passport
Python Retirement Provenance CI job intentionally fails while the qualification record is
blocked. After protected evidence exists, qualify the record, resolve maintainer
findings, run the final cutover on the exact deletion head, pass CI, and merge before
the official aggregate beta deployment. The beta passport recording and
YouTube publication are checked by the later beta acceptance work, not by this
pre-deletion verifier.
