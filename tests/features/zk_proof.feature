Feature: Zero-Knowledge Proof Verification
  As a verifier
  I want to verify zero-knowledge proofs
  So that I can validate user attributes without receiving sensitive data

  Background:
    Given a ZK verification service is initialized
    And a valid Age Over 18 mDoc credential is available

  @zk_proof
  Scenario: Successfully verify Age Over 18 ZK proof
    Given a fresh ZK challenge session is created for "org.iso.18013.5.1.mDL"
    When I generate a valid Age Over 18 proof for the session nonce
    And I submit the proof and MSO for verification
    Then the ZK verification should succeed
    And the verification result should contain claim "age_over_18" as true

  @zk_proof
  Scenario: Fail verification for invalid ZK proof
    Given a fresh ZK challenge session is created for "org.iso.18013.5.1.mDL"
    When I submit an invalid proof with random bytes
    Then the ZK verification should fail
    And the ZK error should indicate "ZK proof verification failed"

  @zk_proof
  Scenario: Fail verification for replay attack (wrong nonce)
    Given a fresh ZK challenge session is created for "org.iso.18013.5.1.mDL"
    And another separate ZK challenge session exists
    When I generate a valid Age Over 18 proof for the OTHER session nonce
    And I submit the proof to the FIRST session
    Then the ZK verification should fail
