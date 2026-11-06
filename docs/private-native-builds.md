# Native build access

Native builds use the complete `ElevenID/isomdl-elevenid`,
`ElevenID/ssi-elevenid`, and `ElevenID/sd-jwt-rust` repositories at their existing
pinned commits. Making those forks private does not change their upstream
history, licenses, notices, package APIs, or the public consumer's source license.

## Authenticated existing CI

`PRIVATE_FORKS_ENABLED` is a repository Actions variable. When it is unset or
`false`, the existing anonymous build and cache behavior remains available.
When it is exactly `true`, native jobs fetch their dependency graphs using the
repository's `PRIVATE_FORKS_READ_TOKEN` Actions secret, then run their existing
checks without that token. The reader needs only Contents read access to the
three forks; the credential helper answers only their exact GitHub HTTPS paths.

The reader is restricted to trusted internal work. Same-repository contributors
must already be authorized to read the forks. External fork PRs and Dependabot
PRs receive no reader and cannot pass required native checks through a skipped
job. Maintainers must review and move such changes to an authorized internal
branch before native validation. Merge-queue admission remains subject to the
existing required checks and review rules. Do not use `pull_request_target` to
run untrusted source with this reader.

Native bindings, KMS and scalar dependency-graph checks, Python bindings,
Python contract tests, WASM builds, and the existing CI Gate remain in their
original workflows. The credentials workspace uses its root `Cargo.lock` even
when building the nested `rust/marty-rs` manifest. Core wheel production fetches
the separately checked-out, pinned Core workspace using that workspace's own
lockfile. The two dependency graphs are not repinned or combined.

## Caches, outputs, and local development

Private-mode jobs do not restore or save Cargo Git sources or compiler caches.
The reader is available only to dependency resolution, never to compilation,
tests, package signing, or publication. Existing compiled products and metadata
artifacts remain public; ordinary compiler diagnostics and test logs also remain
public. This boundary prevents full private fork source from being placed in a
public cache or source artifact. It is not a guarantee that public diagnostics
will never show a source excerpt.

Keep the reader out of Git configuration files, command arguments, job-level
environment variables, artifacts, and logs. Enable the variable only after the
secret has read access to the private fork identities and authenticated native
checks pass. Removing the variable does not restore anonymous access to a
private fork.

Authorized local builds use the same pinned Git URLs with normal private-repo
read credentials. Continue merging upstream changes in the private forks, and
preserve required license notices when distributing Marty binaries or other
artifacts. Previously published source and its existing licenses are unaffected.
