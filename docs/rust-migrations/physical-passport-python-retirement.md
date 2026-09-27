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
commit and live beta receipt in
`contracts/physical-passport-python-retirement-qualification.json`. Confirm
all nine Gateway and Flow routes select Rust, the KMS CSCA/DSC chain and SOD
validate, the packaged image and signed bureau callback pass, legacy jobs and
artifacts satisfy the drain gates, and rollback plus production isolation are
verified. The beta bureau is synthetic; it does not prove physical booklet
production or qualify a future external bureau provider.
