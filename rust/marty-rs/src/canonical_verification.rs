//! Thin Python binding over the canonical result builder from pinned Marty Core.

use pyo3::prelude::*;

fn build(input_json: &str) -> Result<String, String> {
    let input: marty_verification::verification::VerificationDecisionResultInput =
        serde_json::from_str(input_json)
            .map_err(|error| format!("invalid canonical verification input: {error}"))?;
    let result = marty_verification::verification::build_verification_decision_result(input)
        .map_err(|error| error.to_string())?;
    serde_json::to_string(&result)
        .map_err(|error| format!("canonical verification result serialization failed: {error}"))
}

/// Build a canonical decision from caller-supplied facts using pinned Marty Core.
#[pyfunction]
fn verification_build_decision_result(input_json: &str) -> PyResult<String> {
    build(input_json).map_err(pyo3::exceptions::PyValueError::new_err)
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(
        verification_build_decision_result,
        module
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> serde_json::Value {
        serde_json::json!({
            "verification_id": "verification-123",
            "context": {
                "mode": "ONLINE",
                "verifier_id": "verifier:example",
                "organization_id": "123e4567-e89b-42d3-a456-426614174000",
                "transaction_id": "transaction-example-001",
                "audience": "https://verifier.example"
            },
            "processing_status": "COMPLETED",
            "evaluated_at": "2026-08-08T23:30:00Z",
            "input_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "evidence_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "policy": {
                "id": "policy.example",
                "version": "1.0.0",
                "content_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            },
            "trust_profile": {
                "id": "trust.example",
                "version": "1.0.0",
                "content_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            },
            "components": [{
                "component_id": "marty-credentials",
                "version": "0.1.52",
                "artifact_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                "adapter_id": "verification-service",
                "adapter_version": "1.0.0"
            }],
            "checks": [{
                "check_id": "credential.proof",
                "category": "CREDENTIAL_PROOF",
                "required": true,
                "outcome": "PASSED",
                "code": "CREDENTIAL_SIGNATURE_VALID",
                "component_id": "marty-credentials",
                "evaluated_at": "2026-08-08T23:30:00Z",
                "evidence_refs": [
                    "urn:marty:evidence:123e4567-e89b-42d3-a456-426614174000"
                ]
            }]
        })
    }

    #[test]
    fn delegates_derived_result_fields_to_core() {
        let result: serde_json::Value =
            serde_json::from_str(&build(&input().to_string()).expect("canonical result"))
                .expect("result JSON");

        assert_eq!(result["decision"], "PASS");
        assert_eq!(result["valid"], true);
        assert_eq!(
            result["reducer"]["reducer_id"],
            "mip.required-check-reducer"
        );
    }

    #[test]
    fn rejects_caller_supplied_derived_fields() {
        for field in ["decision", "valid", "reducer", "category_summaries"] {
            let mut candidate = input();
            candidate
                .as_object_mut()
                .expect("input object")
                .insert(field.to_owned(), serde_json::json!(true));
            let error = build(&candidate.to_string()).expect_err("derived field must fail");
            assert!(error.contains("unknown field"), "unexpected error: {error}");
        }
    }
}
