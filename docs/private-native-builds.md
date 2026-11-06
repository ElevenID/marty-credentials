# Native build access

The whole-fork privacy plan keeps the existing repositories and pinned Git
dependencies: `ElevenID/isomdl-elevenid`, `ElevenID/ssi-elevenid`, and
`ElevenID/sd-jwt-rust`. It does not extract replacement crates or change their
upstream history, license files, or notices.

## Prepared, inactive boundary

`PRIVATE_FORKS_ENABLED` is a repository Actions variable. Leave it unset or
`false` until an authenticated consuming build for this repository works in a
private environment and the native CI/release pause is ready to take effect.
This change does not set the variable or change repository visibility.

When the variable is exactly `true`, the public jobs that resolve these
dependencies fail before checkout, dependency setup, or cache access. The
existing CI Gate still requires the original native checks to pass; the
boundary does not turn an unexecuted test into success.

Metadata-only Python security checks, Python dependency cache warming, the
Python retirement guard, license metadata checks, and public source scans
remain available. The switch pauses Rust preflight/tests/dependency audits,
local Python bindings, Core native wheel production, WASM tests, native cache
warming, and dependency inventory/SBOM resolution. Python contract tests keep
their existing dependency on the Core wheel producer and cannot pass without
that producer. This repository's retired publication workflows remain absent.

## Authorized native work

Use the private
[`ElevenID/marty-commercial-rust` build repository](https://github.com/ElevenID/marty-commercial-rust)
for the native suites and trusted, exact source commits configured in its
manual coordinator. It must support this repository and obtain read-only
access to the three forks in its own private build context before this
repository's switch is activated. Keep that credential, dependency source,
build logs, Cargo Git cache, and Docker intermediate layers out of public
Actions jobs and artifacts. Authorized local builds can use the same Git URLs
with normal private-repository read credentials; no dependency repinning is
needed merely because visibility changes.

The manual coordinator is an initial native validation path. It does **not**
yet report PR/merge-queue checks or produce accepted release artifacts. A
successful private run cannot be substituted for a required public check or
the existing release provenance. Those integrations must be implemented and
validated before native CI and releases can resume under the new model.

Enable the switch only at the coordinated cutover, after private authentication
and the consuming build are working. Removing it later only re-enables the
old anonymous workflows; it does not restore access to private forks or
complete a rollback. Keep ordinary upstream fetch/merge workflows in the
private forks and preserve all required license notices when distributing
compiled Marty artifacts. Previously published artifacts and license notices
are unaffected.
