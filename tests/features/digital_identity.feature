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
    Given I have issued credentials in all formats:
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
