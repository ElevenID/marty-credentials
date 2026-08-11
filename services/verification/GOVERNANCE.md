# Verification governance

The verification service fails closed unless `VERIFICATION_GOVERNANCE_JSON`
contains an exact server-owned governance registry. Public requests cannot
select an organization, issuer allowlist, policy, trust profile, public DID
fallback, or raw issuer key.

Each client entry stores only a SHA-256 API-key digest and binds that identity
to one organization plus an exact policy/trust pair for each granted purpose:

- `verification.session.create`
- `verification.direct`
- `verification.vds-nc`

Session and direct policies must require `presentation.structure`,
`presentation.proof`, `credential.proof`, `issuer.trust`,
`credential.status`, `holder.binding`, `transaction.binding`, and
`claim.constraints`. VDS-NC policies must require `credential.proof` and
`issuer.trust`. A policy that omits its purpose's mandatory checks makes the
registry invalid.

The environment value has this shape:

```json
{
  "component": {
    "component_id": "marty-credentials",
    "version": "<deployed version>",
    "artifact_digest": "sha256:<deployed artifact digest>",
    "adapter_id": "verification-service",
    "adapter_version": "1.0.0"
  },
  "policies": [
    {
      "organization_id": "<canonical UUID>",
      "id": "policy:employee",
      "version": "1.0.0",
      "content_digest": "sha256:<canonical content digest>",
      "content": {
        "verifier_id": "did:web:verifier.example",
        "presentation_definition_digest": "sha256:<canonical definition digest>",
        "required_checks": [
          "presentation.structure",
          "presentation.proof",
          "credential.proof",
          "issuer.trust",
          "credential.status",
          "holder.binding",
          "transaction.binding",
          "claim.constraints"
        ]
      }
    }
  ],
  "trust_profiles": [
    {
      "organization_id": "<same canonical UUID>",
      "id": "trust:employee",
      "version": "1.0.0",
      "content_digest": "sha256:<canonical content digest>",
      "content": {
        "trusted_issuers": ["did:web:issuer.example"],
        "allow_public_did_fallback": false
      }
    }
  ],
  "clients": [
    {
      "client_id": "employee-verifier",
      "api_key_sha256": "<lowercase SHA-256 of X-API-Key>",
      "organization_id": "<same canonical UUID>",
      "purposes": {
        "verification.session.create": {
          "policy_id": "policy:employee",
          "trust_profile_id": "trust:employee"
        },
        "verification.direct": {
          "policy_id": "policy:employee",
          "trust_profile_id": "trust:employee"
        }
      }
    }
  ]
}
```

Canonical content digests are SHA-256 over UTF-8 JSON with keys sorted and no
insignificant whitespace. Arrays remain ordered; duplicate object members and
non-finite numbers are rejected. Trust issuer arrays must be sorted and unique.
API keys remain in the secret manager; only their lowercase
SHA-256 digests belong in the registry; use independently generated,
high-entropy keys rather than passwords. The component and adapter identities
are fixed to `marty-credentials` and `verification-service`. Deployment must
populate their version and artifact digest from the verified release manifest,
not from request data or an operator-invented identifier.

Compute `presentation_definition_digest` over the validated API definition
with absent optional fields omitted. In particular, an omitted or null
top-level `format` is not inserted as `"format": null`; the session and direct
routes use the same normalization before enforcing the policy digest.

At session creation, the service freezes the secret-free caller identity,
purpose, policy/trust content and references, and component provenance. On
submission it requires the frozen client, purpose, policy, and trust profile to
still match the server-owned registry, then records the currently executing
component rather than claiming the component that happened to create the
session. Response projection revalidates the evidence records and canonical
result through the pinned Marty Core builder. Legacy, unknown, or malformed
provenance cannot project `PASS`.

## Current fail-closed capability boundary

The JWT session adapter currently authenticates the outer presentation proof
and transaction binding, but it does not independently verify every embedded
issuer credential, its governed trust, and current status. The structured
direct adapter verifies issuer credential proofs, governed issuer trust, and
presentation structure, but it has no authenticated presentation proof,
transaction binding, or current status result. Those paths therefore cannot
produce canonical `PASS` under the mandatory policy checks yet; missing facts
remain `NOT_PERFORMED` and reduce to a non-pass result. Do not advertise them as
positive verification capabilities until each missing layer is implemented and
tested through the same canonical builder.

VDS-NC is narrower: its purpose policy requires only `credential.proof` and
`issuer.trust`. It can pass after the issuer resolves through the caller-bound
allowlist, the internal resolver response binds exactly to the requested
organization, issuer DID, verification method, DID document, and public
asymmetric JWK, and the native VDS-NC signature verifier succeeds. Private,
symmetric, cross-controller, public-fallback, or mismatched resolver responses
fail closed. This scoped result must not be represented as OID4VP presentation,
holder, transaction, or status verification.

Roll out a registry and its API keys before deploying this service version.
Requests that still send `organization_id`, `trusted_issuers`, issuer JWKs, or
public-fallback selectors are rejected. Rotate governance by deploying the new
registry and restarting the service. Retain each in-flight session's client
purpose grant and exact policy/trust entries until that session expires;
otherwise its submission becomes indeterminate instead of silently adopting
new authority. Existing sessions retain frozen policy/trust provenance, while
the decision records the release artifact that actually performed it.

Configure `SIGNING_KEYS_INTERNAL_API_KEY` (or its `_FILE` variant) separately
for the verification workload's authenticated calls to the internal issuer
resolver. The retired public `VERIFICATION_API_KEY` is not a fallback workload
credential and must not be reused for that trust boundary. Startup validates
both this credential and the complete governance registry; an incomplete
deployment does not report healthy and defer failure until its first request.
