# Marty Credentials documentation

Start with the [repository README](../README.md) for the retained binding scope,
build commands, and retirement boundaries. The deployed issuance service belongs
to [Marty UI](https://github.com/ElevenID/marty-ui), and canonical credential and
verification libraries belong to [Marty Core](https://github.com/ElevenID/marty-core).

## Development and deployment

- [Native build access](private-native-builds.md)
- [Deployment acceptance and ownership](operations/DEPLOYMENT_CHECKLIST.md)
- [Source navigation](../README.md#source-layout)

## Regression ownership

- [Native issuance regression ownership](native-issuance-regression-ownership.md)
- [Canvas regression ownership](canvas-regression-ownership.md)
- [Canvas review and recovery migration](canvas-review-recovery-migration.md)

## Migration references and open obligations

- [Rust issuance migration roadmap](RUST_ISSUANCE_MIGRATION_ROADMAP.md)
- [Python service and convenience SDK retirement](rust-migrations/full-issuance-python-retirement.md)
- [Retained migration references](rust-migrations/)
- [Integration-secret secure-storage obligations](rust-migrations/integration-secret-secure-storage-outstanding.md)
- [DIDComm custody obligations](rust-migrations/didcomm-kms-outstanding.md)

Migration notes retain historical decisions and unresolved requirements; listing
a guide here does not revalidate its feature, test, or deployment-readiness claims.
Use exact release evidence from the responsible repository for deployment decisions.

## File placement

Use this index instead of adding more root-level guides. Operational checklists
belong in `docs/operations/`; existing migration references keep their established
paths. Keep the root README, licenses, changelog, workspace manifests, lockfiles,
and tool-discovered configuration at their supported locations. Commands remain
relative to the repository root unless a guide explicitly changes directory.
