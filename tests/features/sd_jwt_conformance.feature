@conformance @sd_jwt
Feature: SD-JWT Selective Disclosure Conformance (IETF draft-ietf-oauth-selective-disclosure-jwt)
  As a credential system
  I want to verify that SD-JWT issuance and presentation comply with the IETF SD-JWT specification
  So that interoperability with other implementors is maintained

  Background:
    Given an SD-JWT test issuer key pair
    And a test subject DID "did:example:subject789"

  # §4.2 — Disclosure format ──────────────────────────────────────────────────

  Scenario: Disclosure bytes are valid Base64URL-encoded JSON arrays
    When I issue an SD-JWT with disclosable claim "given_name" = "Alice"
    Then each disclosure in the SD-JWT must decode to a valid JSON array
    And each disclosure array must have exactly 3 elements: [salt, claim_name, claim_value]

  Scenario: Salt in each disclosure is at least 128 bits of entropy
    When I issue an SD-JWT with disclosable claim "family_name" = "Smith"
    Then each disclosure salt must be at least 16 bytes when base64url-decoded

  Scenario: Disclosure claim name matches the original claim
    When I issue an SD-JWT with disclosable claim "age" = 30
    Then the disclosure for claim "age" must contain the exact claim name "age"

  Scenario: Disclosure claim value matches the original claim value
    When I issue an SD-JWT with disclosable claim "email" = "alice@example.com"
    Then the disclosure for claim "email" must contain value "alice@example.com"

  # §4.1 — JWT payload structure ──────────────────────────────────────────────

  Scenario: SD-JWT payload contains _sd array
    When I issue an SD-JWT with disclosable claim "given_name" = "Alice"
    Then the JWT payload must contain an "_sd" array
    And the "_sd" array must not be empty

  Scenario: _sd_alg defaults to sha-256
    When I issue an SD-JWT with disclosable claim "given_name" = "Alice"
    Then the JWT payload must contain "_sd_alg" equal to "sha-256"

  Scenario: _sd array entries are SHA-256 hashes of disclosure bytes
    When I issue an SD-JWT with disclosable claim "given_name" = "Alice"
    Then for each disclosure, its SHA-256 hash must appear in the "_sd" array
    And the hash must be base64url-encoded without padding

  Scenario: Non-disclosable claims appear in plaintext in the JWT
    When I issue an SD-JWT where "iss" is non-disclosable and "given_name" is disclosable
    Then the JWT payload must contain "iss" in plaintext
    And "given_name" must NOT appear as a top-level plaintext claim in the JWT payload

  # §7 — Compact serialization ────────────────────────────────────────────────

  Scenario: SD-JWT compact serialization uses tilde separator
    When I issue an SD-JWT with disclosable claim "given_name" = "Alice"
    Then the SD-JWT string must contain "~" separators
    And the first token before "~" must be a valid three-part JWT (header.payload.signature)

  Scenario: SD-JWT includes one tilde-separated part per disclosure
    When I issue an SD-JWT with 3 disclosable claims
    Then the SD-JWT compact form must contain at least 3 disclosure parts after the JWT

  # §8 — Holder presentation ──────────────────────────────────────────────────

  Scenario: Holder can create a presentation disclosing a subset of claims
    Given an SD-JWT with disclosable claims "given_name", "family_name", "age"
    When the holder creates a presentation disclosing only "given_name"
    Then the presentation must contain only 1 disclosure
    And the disclosed claim must be "given_name"

  Scenario: Undisclosed claims do not appear in the presentation
    Given an SD-JWT with disclosable claims "given_name", "family_name", "age"
    When the holder creates a presentation disclosing only "given_name"
    Then the presentation must NOT contain a disclosure for "family_name"
    And the presentation must NOT contain a disclosure for "age"

  # §10 — Verification ─────────────────────────────────────────────────────────

  Scenario: Verifier can reconstruct disclosed claims from presentation
    Given an SD-JWT issued with claim "given_name" = "Carol"
    When the holder presents the SD-JWT disclosing "given_name"
    Then verification must succeed
    And the verified claims must include "given_name" = "Carol"

  Scenario: Verifier rejects a tampered disclosure
    Given an SD-JWT issued with claim "given_name" = "Dave"
    When the holder alters a disclosure to change "given_name" to "Eve"
    Then verification must fail with a hash mismatch error
