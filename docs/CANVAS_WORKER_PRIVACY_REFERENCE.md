# Hardened Canvas privacy reference

`contracts/canvas-worker-privacy-reference.json` retains actual observations
from protected Credentials commit `d418ac0df283625f43b0c011fb1c72fd7d3013a9`.
It supplements the earlier immutable pre-hardening worker oracles.
The frozen UTF-8 content, with CRLF normalized to LF, has SHA-256
`2bcffee4bfd78152e1a6eb611442391a228fa034cce1266818ded532f8f35c05`.

| Boundary | Observed cases |
| --- | ---: |
| Shared signing-error detail selection and character bound | 45 |
| Three remote operations with 401/503 responses | 6 |
| Worker error/log branches, standalone and ambient-correlation modes | 12 |

The historical worker cases executed actual cycles or loops against an
in-memory repository and controlled provider responses. They preserve error
content, bounds, logging and correlation behavior without claiming PostgreSQL,
installed runtime, KMS custody or physical-device acceptance. The corpus uses
synthetic inputs, not operator secrets or a deployed provider.

The Python capture/replay tools and their process-control tests are retired.
Their implementation remains recoverable at Git commit `40158ec`.
Keep the frozen observations and current native regression owners in
[marty-ui](https://github.com/ElevenID/marty-ui). No fixture was rewritten from
Rust output, and deleting the historical tools grants no deployment authority.
