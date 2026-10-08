# Physical-passport Python source retirement

The nine passport HTTP operations, managed issuer signing, bureau submission,
polling, batch, and signed callback behavior have Rust implementations. Two
independent maintainer audits found no missing P1–P3 passport implementation at
the reviewed source. This PR removes only the superseded Python passport router,
signer adapter, bureau adapter, and router registration. The shared Python
issuance service, `physical_document_jobs` model, and migration history remain
because unrelated issuance routes and durable records still use them.

## Source deletion decision — October 8, 2026

Source deletion no longer waits for a live beta cutover. The product owner has
stated that no public passport customer deployment requires preserving these
Python modules for compatibility. Merging this PR does not replace the immutable
images currently running in beta or production. It does not authorize a new
Credentials image under the current Python passport routing defaults.

The v4 qualification record identifies the exact protected `marty-ui` source
commit and hashes its frozen behavior contracts, Rust passport/Gateway/Flow
implementation, and disposable composition. Its named full merge-group CI run
must have passed every job, including Rust services, image, release-contract,
security, and CI gates. The Credentials gate also verifies #305's exact head,
absence of the three Python modules and all nine Python HTTP routes, and the
frozen Rust shuffled-response batch parity test. Later CI binds the same
qualification bytes to #305's immutable protected merge and rejects route
reintroduction. No release or protected-runtime receipt is fabricated in this
record; `beta_deployment_authorized` remains false.

The deleted route identities are the frozen set in
`contracts/physical-passport-python-route-reference.json`. The old provider
reference stays as a behavior oracle. Source removal does not claim that the
Marty simulator produced a physical booklet; `physical_claim=not_claimed` and
`booklet_verified=false` remain the software acceptance boundary. No external
provider or CA is needed for the software flow.

## Deployment remains gated

The current beta and production containers still select the legacy Python
passport owner. The current stack lock pins the previously released Credentials
image, so source merge alone changes no running route. A new Credentials image
must not be deployed with those defaults: its passport handlers are gone.

Before the one aggregate beta-only deployment, qualify a signed post-deletion
stack and run protected six-service Rust/KMS passport acceptance. That run must
prove all nine Gateway and Flow routes, tenant isolation, managed CSCA and DSC
profiles and certificates, SOD signing, the two-job Marty simulator batch,
signed callbacks, durable restart/resume, and production isolation. The
separate base, self-host, and Kubernetes reusable fixture remains optional
later work in #944; frozen unit and contract coverage remains required now.

On the real beta database, install and attest the passport-scoped write fence,
identify the still-running shared Python issuance container, and drain or
resolve every passport job, artifact, and active physical Flow. Recheck that
the fence rejects valid direct passport writes by the writer role while
unrelated issuance remains available. The aggregate operator must stage the
signed Rust services, provision the pilot organization's ICAO template,
application template, physical destination, and active Flow through normal
Gateway authorization, and select Rust Gateway, Flow, and native issuance
together before opening beta ingress. The current v1.1.217 beta services cannot
create an ICAO template, so this reference setup belongs inside the guarded
staged-service cutover; an OID4VCI substitute is invalid.

Companion marty-ui PR #1168 changes protected fence and final cutover authority
to require #305's merged commit on protected Credentials main and a signed
replacement image descended from that merge. It must land before #305 merges.
Fresh live fence, drain, and attested acceptance receipts remain required.
The current aggregate operator also validates an active physical Flow before
the Rust-owner transition even though the beta database has none and the
fence blocks creating one. Provision and validate that Flow after transition
while beta ingress remains closed; do not weaken the fence. No old signing
mode, Python owner phase, or rollback is required.
Keep production on its current image and routing. If a beta gate fails, keep
beta ingress closed and preserve jobs and receipts until a reviewed Rust fix
passes. Finish with one aggregate beta deployment, acceptance soak, and D-12
YouTube demo evidence.
