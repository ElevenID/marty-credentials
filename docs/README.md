# Marty Credentials documentation

Start with the [project README](../README.md) for the repository's scope and
current development commands. This repository retains credential bindings and
source-boundary tests; deployment and service operation belong to the native
owners linked there.

## Development and source navigation

| Goal | Guide or source |
| --- | --- |
| Find binding code | [Rust source](../rust/) |
| Run source and binding checks | [Tests](../tests/) and [development commands](../README.md#development-checks) |
| Authenticate native builds | [Native build access](private-native-builds.md) |
| Find build and validation helpers | [Scripts](../scripts/) |

## Operational ownership

- [Deployment acceptance checklist](operations/DEPLOYMENT_CHECKLIST.md)
- [Integration-secret secure-storage obligations](rust-migrations/integration-secret-secure-storage-outstanding.md)
- [DIDComm key-custody obligations](rust-migrations/didcomm-kms-outstanding.md)

These documents describe ownership and evidence requirements. Their placement
here does not mark requirements complete or qualify a release for deployment.

## Migration and regression references

- [Rust issuance migration roadmap](RUST_ISSUANCE_MIGRATION_ROADMAP.md)
- [Python issuance and SDK retirement](rust-migrations/full-issuance-python-retirement.md)
- [Native issuance regression ownership](native-issuance-regression-ownership.md)
- [Canvas regression ownership](canvas-regression-ownership.md)
- [Remaining migration references](rust-migrations/)

## File placement

Put operational guidance in `docs/operations/` and add important guides to this
index rather than creating more root-level Markdown files. Existing migration
references retain their paths. Keep the root README, changelog, licenses,
workspace manifests, lockfiles, and tool-discovered configuration in their
supported locations. No source code, package layout, or release behavior changes
are implied by this organization.
