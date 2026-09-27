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
Confirm all nine Gateway and Flow routes select Rust, the KMS CSCA/DSC chain and SOD
validate, the packaged image and signed bureau callback pass, legacy jobs and
artifacts satisfy the drain gates, and rollback plus production isolation are
verified. The beta bureau is synthetic; it does not prove physical booklet
production or qualify a future external bureau provider.

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
