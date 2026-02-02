Feature: Digital Identity Credential Issuance and Verification
  As a credential system
  I want to issue and verify different types of digital identity credentials
  So that I can support multiple identity formats

  Background:
    Given a fresh database
    And a test issuer with DID "did:example:issuer123"
    And a test subject with DID "did:example:subject456"

  Scenario: Issue and verify a W3C Verifiable Credential
    When I issue a W3C VC with the following claims:
      | claim_name | claim_value     |
      | given_name | Alice           |
      | family_name| Smith           |
      | email      | alice@example.com |
    Then the credential should be stored in the database
    And the credential type should be "VerifiableCredential"
    When I verify the W3C VC
    Then the verification should succeed
    And the verified claims should contain:
      | claim_name | claim_value     |
      | given_name | Alice           |
      | family_name| Smith           |

  Scenario: Issue and verify an SD-JWT credential
    When I issue an SD-JWT with the following claims:
      | claim_name | claim_value     | disclosable |
      | given_name | Bob             | true        |
      | family_name| Jones           | true        |
      | email      | bob@example.com | false       |
      | age        | 30              | true        |
    Then the credential should be stored in the database
    And the credential type should be "SD-JWT"
    When I create an SD-JWT presentation disclosing:
      | given_name |
      | age        |
    And I verify the SD-JWT presentation
    Then the verification should succeed
    And the verified claims should contain:
      | claim_name | claim_value |
      | given_name | Bob         |
      | age        | 30          |
    And the verified claims should NOT contain "family_name"
    And the verified claims should NOT contain "email"

  Scenario: Issue and verify an mDoc credential
    When I issue an mDoc with doc_type "org.iso.18013.5.1.mDL" and claims:
      | namespace        | element_name    | element_value |
      | org.iso.18013.5.1| family_name     | Williams      |
      | org.iso.18013.5.1| given_name      | Carol         |
      | org.iso.18013.5.1| birth_date      | 1990-05-15    |
      | org.iso.18013.5.1| issue_date      | 2024-01-01    |
      | org.iso.18013.5.1| expiry_date     | 2034-01-01    |
    Then the credential should be stored in the database
    And the credential type should be "mDoc"
    When I verify the mDoc
    Then the verification should succeed
    And the verified mDoc should contain namespace "org.iso.18013.5.1"
    And the verified claims should contain:
      | element_name | element_value |
      | given_name   | Carol         |
      | family_name  | Williams      |

  Scenario: Issue and verify an OpenID4VP presentation
    Given I have issued a W3C VC with claims:
      | claim_name     | claim_value       |
      | credential_type| DriverLicense     |
      | license_number | DL123456          |
      | name           | David Brown       |
    When I create an OpenID4VP presentation request for "DriverLicense"
    And I create an OpenID4VP presentation response
    And I verify the OpenID4VP presentation
    Then the verification should succeed
    And the presentation should contain the VC
    And the verified claims should contain:
      | claim_name     | claim_value   |
      | license_number | DL123456      |

  Scenario: Cross-format credential interoperability
    When I have issued credentials in all formats:
      | format | identifier          |
      | W3C-VC | did:example:vc1     |
      | SD-JWT | did:example:sdjwt1  |
      | mDoc   | did:example:mdoc1   |
    When I query credentials for subject "did:example:subject456"
    Then I should retrieve 3 credentials
    And the credentials should include all format types
    And each credential should be verifiable

  Scenario: Credential lifecycle management
    When I issue a W3C VC with expiry in 1 year
    Then the credential status should be "active"
    When I check the credential after 1 year and 1 day
    Then the credential status should be "expired"
    When I revoke the credential
    Then the credential status should be "revoked"
    And verification should fail with reason "credential revoked"

  Scenario: Error handling for invalid credentials
    When I attempt to verify an invalid W3C VC with malformed signature
    Then the verification should fail
    And the error should indicate "invalid signature"
    When I attempt to verify an SD-JWT with incorrect disclosure
    Then the verification should fail
    And the error should indicate "invalid disclosure"

  @open_badge
  Scenario: Issue and verify Open Badge v2 with Ed25519
    Given an Open Badge issuer with "Ed25519" key
    And a badge class for "Python Programming Certificate"
    When I issue an Open Badge OB2 with recipient "alice@learner.edu"
    Then the credential should be stored in the database
    And the credential type should be "open_badge_v2"
    When I verify the Open Badge OB2
    Then the verification should succeed
    And the verified claims should contain:
      | claim_name     | claim_value       |
      | recipient.identity | alice@learner.edu |

  @open_badge
  Scenario: Issue and verify Open Badge v3 with JsonWebKey2020
    Given an Open Badge issuer with "JsonWebKey2020" key
    And a badge class for "Data Science Achievement"
    When I issue an Open Badge OB3 with recipient "bob@learner.edu"
    Then the credential should be stored in the database
    And the credential type should be "open_badge_v3"
    When I verify the Open Badge OB3
    Then the verification should succeed
    And the verified claims should contain:
      | claim_name | claim_value                |
      | recipient  | bob@learner.edu            |
      | name       | Data Science Achievement   |

  @open_badge
  Scenario: Open Badge v2 with status list integration
    Given an Open Badge issuer with "Ed25519" key
    And a status list endpoint is configured
    When I issue an Open Badge OB2 with status list entry
    Then the credential should have a status list credential URL
    And the status list index should be allocated
    When I verify the Open Badge OB2
    Then the verification should succeed
    And the status should be checked against the status list
    And the credential should not be revoked

  @open_badge
  Scenario: Open Badge v3 with status list and revocation
    Given an Open Badge issuer with "JsonWebKey2020" key
    And a status list endpoint is configured
    When I issue an Open Badge OB3 with status list entry
    And I revoke the Open Badge credential
    When I verify the Open Badge OB3
    Then the verification should fail
    And the error should indicate "credential revoked"

  @open_badge
  Scenario: Open Badge v3 with X509 certificate verification
    Given an Open Badge issuer with "X509VerificationKey2021" certificate
    And the X509 certificate is signed by a trusted CA
    And a CRL is available for revocation checking
    When I issue an Open Badge OB3 with X509 signature
    Then the credential type should be "open_badge_v3"
    When I verify the Open Badge OB3 with X509
    Then the verification should succeed
    And the X509 certificate chain should be validated
    And the CRL should show the certificate is not revoked

  @open_badge
  Scenario: Open Badge endorsement chain validation
    Given an Open Badge issuer with "Ed25519" key
    And an endorsing organization with "Ed25519" key
    And a second-level endorser with "JsonWebKey2020" key
    When I issue an Open Badge OB3 for "Web Development Expert"
    And I add a first-level endorsement from the organization
    And I add a second-level endorsement from the endorser
    When I verify the Open Badge with endorsements
    Then the verification should succeed
    And the endorsement chain should be validated to depth 2
    And all endorsements should be verified
    And endorsement chain depth should not exceed 5

  @open_badge
  Scenario: Open Badge with fail-closed trust policy
    Given an Open Badge issuer with "Ed25519" key
    And the trust policy is set to "fail-closed"
    And the issuer verification method is NOT in the trust store
    When I issue an Open Badge OB3
    And I verify the Open Badge with strict trust
    Then the verification should fail
    And the error should indicate "verification method not trusted"

  @revocation_profile
  @revocation_profile
  Scenario: Create and activate a RevocationProfile
    Given a fresh database
    And a test issuer with DID "did:example:issuer123"
    And a test subject with DID "did:example:subject456"
    Given an organization with ID "org-456"
    When I create a revocation profile named "Standard Revocation"
    Then the revocation profile should be created
    When I activate the revocation profile
    Then the revocation profile should be active

  @revocation_profile
  Scenario: Issue credential with RevocationProfile and revoke it
    Given a fresh database
    And a test issuer with DID "did:example:issuer123"
    And a test subject with DID "did:example:subject456"
    Given an organization with ID "org-456"
    And I create a revocation profile named "Standard Revocation"
    And I activate the revocation profile
    When I allocate a status list index for "sd_jwt_vc"
    Then I should receive a status list index
    When I issue an SD-JWT with the following claims:
      | claim_name | claim_value     | disclosable |
      | given_name | Alice           | true        |
      | age        | 25              | true        |
    And I link the revocation profile to the trust profile
    Then the credential should be stored in the database
    When I revoke the credential via revocation profile
    Then the credential should be marked as revoked

  @revocation_profile
  Scenario: Multi-format revocation with single RevocationProfile
    Given a fresh database
    And a test issuer with DID "did:example:issuer123"
    And a test subject with DID "did:example:subject456"
    Given an organization with ID "org-456"
    And I create a revocation profile named "Multi-Format Revocation"
    And I activate the revocation profile
    When I allocate a status list index for "sd_jwt_vc"
    And I allocate a status list index for "mdoc"
    And I allocate a status list index for "jwt_vc"
    Then I should receive a status list index

  @zk_predicate
  Scenario: Create presentation policy with ZK predicate specifications
    Given an organization with ID "org-789"
    When I create a presentation policy with ZK predicate specs
      | predicate_type | handling_policy   | acceptable_circuits                      | params                          |
      | range_proof    | require_predicate | ligero_age_over_18,ligero_age_over_21   | {"threshold": 21, "comparison": "gte"} |
      | membership     | accept_raw        | bbs_range                                | {"set": ["US", "CA", "MX"]}     |
    Then the presentation policy should include ZK circuit requirements

  @zk_predicate
  Scenario: Verify mDoc with ZK age predicate using Ligero circuit
    Given an organization with ID "org-789"
    And I create a presentation policy with ZK predicate specs
      | predicate_type | handling_policy   | acceptable_circuits     | params                          |
      | range_proof    | require_predicate | ligero_age_over_21      | {"threshold": 21, "comparison": "gte"} |
    When I issue an mDoc with doc_type "org.iso.18013.5.1.mDL" and claims:
      | namespace        | element_name | element_value |
      | org.iso.18013.5.1| given_name   | Bob           |
      | org.iso.18013.5.1| birth_date   | 1995-03-15    |
      | org.iso.18013.5.1| issue_date   | 2024-01-01    |
    And I create a ZK proof for "age_over_21" using circuit "ligero_age_over_21"
    When I verify the ZK proof against the presentation policy
    Then the verification should succeed
    And the disclosed claims should contain:
      | claim_name   | claim_value |
      | age_over_21  | true        |
    And the raw age should not be disclosed

  @zk_predicate
  Scenario: ZK predicate fallback to raw value disclosure
    Given an organization with ID "org-789"
    And I create a presentation policy with ZK predicate specs
      | predicate_type | handling_policy | acceptable_circuits     | params                          |
      | range_proof    | accept_raw      | ligero_age_over_18      | {"threshold": 18, "comparison": "gte"} |
    When I issue an mDoc with doc_type "org.iso.18013.5.1.mDL" and claims:
      | namespace        | element_name | element_value |
      | org.iso.18013.5.1| given_name   | Carol         |
      | org.iso.18013.5.1| birth_date   | 2000-06-20    |
    And the holder wallet does not support ZK circuits
    When I create a standard presentation disclosing "birth_date"
    And I verify the presentation against the policy
    Then the verification should succeed
    And the disclosed claims should contain:
      | claim_name  | claim_value |
      | birth_date  | 2000-06-20  |

  @zk_predicate
  Scenario: Reject presentation when ZK predicate is required but not provided
    Given an organization with ID "org-789"
    And I create a presentation policy with ZK predicate specs
      | predicate_type | handling_policy   | acceptable_circuits     | params                          |
      | range_proof    | require_predicate | ligero_age_over_18      | {"threshold": 18, "comparison": "gte"} |
    When I issue an mDoc with doc_type "org.iso.18013.5.1.mDL" and claims:
      | namespace        | element_name | element_value |
      | org.iso.18013.5.1| birth_date   | 2005-08-10    |
    And the holder wallet does not support ZK circuits
    When I create a standard presentation disclosing "birth_date"
    And I verify the presentation against the policy
    Then the verification should fail
    And the error should indicate "ZK predicate required but not provided"

