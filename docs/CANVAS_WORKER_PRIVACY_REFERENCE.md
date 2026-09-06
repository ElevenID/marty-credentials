# Hardened Canvas privacy reference

`contracts/canvas-worker-privacy-reference.json` freezes actual observations from
the hardened source landed through PR269 at protected commit
`d418ac0df283625f43b0c011fb1c72fd7d3013a9`. It supplements, and does not rewrite,
the older immutable pre-hardening worker oracles.

The existing privacy tests remain the single execution owner. They expose their
observed results as test properties after checking the existing assertions.
`scripts/capture_canvas_privacy_reference.py` collects those properties; it does
not implement a second worker, parser, simulator or expected-result generator.
No Rust outcome supplies an expectation.

| Boundary | Observed cases |
| --- | ---: |
| Shared signing-error detail selection and character bound | 45 |
| Three remote operations with 401/503 responses | 6 |
| Worker error/log branches, standalone and ambient-correlation modes | 12 |

The worker cases execute actual reference cycles or loops with the existing
in-memory repository and controlled processors/provider boundaries. They freeze
retry/error/result/lease-state projections, successful sibling completion,
remote-revoke/local-cleanup results, recovered idle heartbeat, safe log fields,
default-formatter output and absent exception/stack metadata. This is not a
whole deployed process, real PostgreSQL race, remote signing or log-collector
acceptance result. Those requirements remain separate migration gates.

## Stable inputs and explicit normalization

- JSON response bytes are supplied explicitly, independent of HTTPX serializer
  spacing. Requests use a fixed synthetic endpoint/key and mocked transport.
- Generated job IDs become `<matching-job-id>` only after each actual logged
  ID is asserted equal to the actual job outcome ID. No other values are changed.
- Timestamps are represented by completion/lease-state facts, not wall-clock
  values. The tests do not mutate the clock.
- Log producer records are snapshotted before ambient formatter enrichment;
  actual rendered downstream logs still undergo the privacy assertions.
- Stable short case labels replace a generated label containing a long Unicode
  input. Comparing the before/after captures proved all 63 input/observation
  payloads unchanged; only labels and test provenance changed.

## Provenance and mandatory regeneration

The capture rejects runtime-source changes relative to the pinned protected
commit, untracked runtime files, mismatched worker/signing-helper blobs and
modules imported outside the owned checkout. The artifact also records all
runtime-tree IDs and both observation-test blob IDs. Pytest plugin autoload and
injected options are disabled; only the required asyncio plugin is selected.
Missing/duplicate cases, incomplete boundary counts or any failed test session
(including teardown) prevent output. Existing captures cannot be overwritten.

Two final independent processes (captures D/E) produced identical bytes:
SHA256 `2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05`.
The frozen file has the same hash and passes full regeneration. Earlier B/C
captures also matched; their actual observations are unchanged in the final
label-stable corpus. All generated evidence remains retained outside the repo.

The normal Python quality script requires:

```sh
python scripts/capture_canvas_privacy_reference.py --verify contracts/canvas-worker-privacy-reference.json
```

A shallow CI checkout fetches only the required source commit when absent,
using the capture tool's revision query as the single source of that pin.
The gate runs for both supported Python versions and the configured platforms.
Before removing the Python runtime source at completed cutover, preserve this
pinned reference checkout/image as test tooling; do not retain a Python
production service merely to regenerate historical evidence.

Initial local qualification passed 736 affected tests and 200 subtests in 7.30
seconds, then a separate full regeneration passed all 63 observations.
CI34060445313 subsequently passed at `3e500accfecc064c5987cc4cd9118ec0c350f9c6`.
Maintainer review added five capture-tool regressions: matching/mismatched
verification retains the input bytes, new captures serialize actual observations
stably, and imports from either wrong checkout are rejected before document
creation. All 741 affected tests and 200 subtests passed in 7.11 seconds, then
all 63 frozen observations regenerated unchanged in 0.20 seconds. Ruff and diff
checks passed. Fresh exact-head hosted qualification is still required for these
review additions. The underlying privacy repair's protected-main CI34059299079
passed independently after PR269 merged.

Native Rust replay/adoption and full worker/consumer acceptance remain required.
No production runtime, dependency pin, deployment consumer or previous frozen
expectation changed in this reference-capture follow-up. Core release artifact
qualification remains separately tracked in Credentials issue270.
