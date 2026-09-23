# DIDComm delivery-status read compatibility

The Python management model exposes the language-neutral delivery states
`pending`, `delivered`, and `failed`. During a mixed-version rollout, the Rust
DIDComm writer can persist more detailed transport states in the shared
`credential_delivery_records` table. Python reads project them as follows:

| Persisted status | Management status | Reason |
|---|---|---|
| `pending` | `pending` | Legacy state, unchanged. |
| `delivered` | `delivered` | Legacy terminal success, unchanged. |
| `failed` | `failed` | Legacy terminal failure, unchanged. |
| `transport_ready` | `pending` | Delivery is staged but transport has not started. |
| `transporting` | `pending` | The transport attempt is in flight. |
| `transport_retryable` | `pending` | Delivery remains open after a definitely unattempted transport failure. |
| `transported` | `delivered` | Transport success is durable even if Rust still has projection work to finish. |
| `delivery_unknown` | `pending` | The outcome is unresolved and must not be represented as a definite failure or success. |

Mapping `transported` to `delivered` is the unavoidable lossy choice in the
three-state management model: transport is confirmed, while Rust separately
tracks its remaining projection work. Mapping `delivery_unknown` to `pending`
is conservative and must not be interpreted as permission to resend.

The mapping is closed. A future unrecognized writer status fails the read
without including the raw status or delivery metadata in the exception.
Detailed Rust transport states and metadata remain internal and are not added
to management responses by this compatibility layer.
