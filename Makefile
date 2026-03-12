# Makefile for marty-credentials
#
# Conformance test targets covering:
#   Phase 3 — SD-JWT (IETF draft-ietf-oauth-selective-disclosure-jwt)
#   Phase 4 — W3C VC Data Model 2.0  +  Open Badges 3.0

.PHONY: test test-bdd conformance conformance-sd-jwt conformance-w3c-vc conformance-open-badges help

BEHAVE := python -m behave
FEATURES := tests/features

# Run the full existing BDD suite
test-bdd:
	$(BEHAVE) $(FEATURES)

# Run all conformance feature tests (Phase 3 + Phase 4)
conformance: conformance-sd-jwt conformance-w3c-vc conformance-open-badges
	@echo "✅ All credential conformance tests passed!"

# Phase 3 — IETF SD-JWT conformance (draft-ietf-oauth-selective-disclosure-jwt)
#   §4.1  JWT payload: _sd array, _sd_alg = sha-256
#   §4.2  Disclosure format: BASE64URL([salt, claim_name, claim_value])
#   §7    Compact serialization: <JWT>~<D1>~...~
#   §8    Holder presentation: selective subset of disclosures
#   §10   Verifier: hash integrity check
conformance-sd-jwt:
	@echo "==> Phase 3: SD-JWT conformance"
	$(BEHAVE) $(FEATURES)/sd_jwt_conformance.feature \
	    --tags=conformance,sd_jwt \
	    --no-capture

# Phase 4a — W3C VC Data Model 2.0 conformance
#   §4.1–4.6  Required properties: @context, type, id, issuer, validFrom, credentialSubject
#   §6.3      JWT encoding: 3-part token, alg != none, vc claim
#   §7.1      Signature verification + tamper detection
conformance-w3c-vc:
	@echo "==> Phase 4a: W3C VC Data Model 2.0 conformance"
	$(BEHAVE) $(FEATURES)/w3c_vc_conformance.feature \
	    --tags=conformance,w3c_vc \
	    --no-capture

# Phase 4b — IMS Global Open Badges 3.0 conformance
#   §4.1  AchievementCredential type
#   §4.2  Achievement object: id (URI), type, name, criteria
#   §4.3  Issuer profile with name
#   §4.5  credentialSubject.id identifies the earner
#   §5    Proof verification
#   §6    Alignment targets
conformance-open-badges:
	@echo "==> Phase 4b: Open Badges 3.0 conformance"
	$(BEHAVE) $(FEATURES)/open_badges_conformance.feature \
	    --tags=conformance,open_badges \
	    --no-capture

help:
	@echo "marty-credentials Makefile"
	@echo ""
	@echo "Test targets:"
	@echo "  make test-bdd              Run full BDD test suite"
	@echo "  make conformance           Run all conformance suites (Phase 3+4)"
	@echo "  make conformance-sd-jwt    SD-JWT IETF spec conformance"
	@echo "  make conformance-w3c-vc    W3C VC Data Model 2.0 conformance"
	@echo "  make conformance-open-badges  Open Badges 3.0 conformance"
