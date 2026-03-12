@conformance @w3c_vc
Feature: W3C Verifiable Credential Data Model 2.0 Conformance
  As a credential system
  I want to verify that issued credentials conform to the W3C VC Data Model 2.0
  So that credentials are interoperable with W3C VC compliant verifiers

  Background:
    Given a W3C VC test issuer with DID "did:example:issuer-conformance"
    And a W3C VC test subject with DID "did:example:subject-conformance"

  # §4.1 — @context ─────────────────────────────────────────────────────────

  Scenario: Credential includes the W3C VC base context URI
    When I issue a W3C VC with claim "given_name" = "Alice"
    Then the credential "@context" must include "https://www.w3.org/2018/credentials/v1"

  Scenario: Credential @context is the first entry
    When I issue a W3C VC with claim "given_name" = "Alice"
    Then "https://www.w3.org/2018/credentials/v1" must be the first "@context" value

  # §4.2 — type ─────────────────────────────────────────────────────────────

  Scenario: Credential type includes VerifiableCredential
    When I issue a W3C VC with claim "given_name" = "Alice"
    Then the credential "type" must include "VerifiableCredential"

  # §4.3 — id ──────────────────────────────────────────────────────────────

  Scenario: Credential id is a valid URI when present
    When I issue a W3C VC with an explicit credential ID
    Then the credential "id" must be a valid URI

  # §4.4 — issuer ──────────────────────────────────────────────────────────

  Scenario: Credential issuer is a URI or object with id URI
    When I issue a W3C VC with claim "given_name" = "Alice"
    Then the credential "issuer" must be a non-empty URI or an object with a URI "id"

  # §4.5 — issuanceDate / validFrom ─────────────────────────────────────────

  Scenario: Credential includes validFrom (or issuanceDate for v1.1)
    When I issue a W3C VC with claim "given_name" = "Alice"
    Then the credential must contain either "issuanceDate" or "validFrom"
    And the date must be in ISO 8601 format

  # §4.6 — credentialSubject ────────────────────────────────────────────────

  Scenario: Credential has a credentialSubject property
    When I issue a W3C VC with claim "given_name" = "Alice"
    Then the credential must contain "credentialSubject"
    And "credentialSubject" must be an object or array of objects

  Scenario: credentialSubject values match issued claims
    When I issue a W3C VC with the following claims:
      | claim_name  | claim_value |
      | given_name  | Bob         |
      | family_name | Builder     |
    Then the "credentialSubject" must contain "given_name" = "Bob"
    And the "credentialSubject" must contain "family_name" = "Builder"

  # §6.3 — JWT encoding conformance ─────────────────────────────────────────

  Scenario: JWT-encoded VC has three base64url-separated parts
    When I issue a W3C VC as a JWT
    Then the JWT string must have exactly 3 tilde-free dot-separated parts

  Scenario: JWT header declares algorithm in alg field
    When I issue a W3C VC as a JWT
    Then the JWT header must contain an "alg" field
    And the "alg" must not be "none"

  Scenario: JWT payload contains vc claim with credential properties
    When I issue a W3C VC as a JWT
    Then the JWT payload must contain a "vc" claim
    And the "vc" claim must contain "@context" and "type" and "credentialSubject"

  Scenario: JWT iss claim matches the credential issuer
    When I issue a W3C VC as a JWT with issuer "did:example:issuer-conformance"
    Then the JWT payload "iss" claim must equal "did:example:issuer-conformance"

  Scenario: JWT sub claim matches the credential subject id when present
    When I issue a W3C VC as a JWT for subject "did:example:subject-conformance"
    Then the JWT payload "sub" claim must equal "did:example:subject-conformance"

  # §7.1 — Verification ─────────────────────────────────────────────────────

  Scenario: Valid credential signature verifies successfully
    When I issue a W3C VC with claim "given_name" = "Alice"
    Then the credential signature must verify successfully

  Scenario: Tampered credential signature fails verification
    When I issue a W3C VC with claim "given_name" = "Alice"
    And I modify the "given_name" value to "Mallory" in the JWT without re-signing
    Then the credential signature verification must fail
