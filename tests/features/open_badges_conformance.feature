@conformance @open_badges
Feature: Open Badges 3.0 Conformance (IMS Global)
  As a credential system
  I want to verify that issued achievement credentials conform to IMS Global Open Badges 3.0
  So that badges are recognized by Open Badges compliant platforms

  Background:
    Given an Open Badges 3.0 test issuer with DID "did:example:ob3-issuer"
    And a test earner with DID "did:example:ob3-earner"

  # §4.1 — AchievementCredential type ───────────────────────────────────────

  Scenario: Badge credential type includes AchievementCredential
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the credential "type" must include "AchievementCredential"
    And the credential "type" must include "VerifiableCredential"

  Scenario: Badge credential @context includes Open Badges 3.0 context
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the credential "@context" must include "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"

  # §4.2 — Achievement object ════════════════════════════════════════════════

  Scenario: credentialSubject contains an achievement object
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the "credentialSubject" must contain an "achievement" property
    And "achievement" must be an object

  Scenario: Achievement has required id property
    When I issue an Open Badge with achievement id "https://example.com/achievements/rust-101"
    Then the "achievement" object must contain "id" equal to "https://example.com/achievements/rust-101"

  Scenario: Achievement id must be a valid URI
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the "achievement.id" must be a valid URI

  Scenario: Achievement type includes Achievement
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the "achievement.type" must include "Achievement"

  Scenario: Achievement name is present and non-empty
    When I issue an Open Badge for achievement named "Rust Fundamentals Certification"
    Then the "achievement.name" must be "Rust Fundamentals Certification"

  Scenario: Achievement includes criteria
    When I issue an Open Badge with criteria "Complete all 10 Rust training modules"
    Then the "achievement.criteria" must contain "narrative" = "Complete all 10 Rust training modules"

  # §4.3 — Issuer profile ────────────────────────────────────────────────────

  Scenario: Credential issuer matches a Profile with a name
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the credential must have an "issuer" with a "name" property
    And the "issuer.name" must not be empty

  # §4.4 — issuanceDate ─────────────────────────────────────────────────────

  Scenario: Badge includes a valid issuance date
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the credential must contain "issuanceDate" in ISO 8601 format

  # §4.5 — credentialSubject.id ─────────────────────────────────────────────

  Scenario: credentialSubject id identifies the earner
    When I issue an Open Badge to earner "did:example:ob3-earner"
    Then the "credentialSubject.id" must equal "did:example:ob3-earner"

  # §5 — Verification ────────────────────────────────────────────────────────

  Scenario: Open Badge signature verifies correctly
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the badge proof must verify successfully

  Scenario: Open Badge credential is also a valid W3C VC
    When I issue an Open Badge credential for achievement "Completed Rust Training"
    Then the credential must satisfy W3C VC Data Model requirements
    And it must contain "@context", "type", "issuer", "issuanceDate", "credentialSubject"

  # §6 — Alignment ────────────────────────────────────────────────────────────

  Scenario: Achievement alignment targets can be attached
    When I issue an Open Badge with alignment target "https://example.com/framework/rust-skill-1"
    Then the "achievement.alignment" must contain an entry with "targetUrl" = "https://example.com/framework/rust-skill-1"
