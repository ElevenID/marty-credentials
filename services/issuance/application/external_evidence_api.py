"""Declarative external API evidence checks.

Application templates can define simple provider API checks that normalize a
response into a MIP EvidenceFact without requiring a custom adapter.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from issuance.domain.entities import Application, ApplicationTemplate, EvidenceFact


_PLACEHOLDER_RE = re.compile(r"{{\s*([^{}]+?)\s*}}")
_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH"}


class ExternalEvidenceApiError(ValueError):
    """Raised when a declarative external evidence API check is invalid."""


@dataclass(frozen=True)
class ExternalEvidenceApiCheckResult:
    """Result of executing a configured external evidence API check."""

    evidence_fact: EvidenceFact
    requirement: dict[str, Any]
    check_id: str
    http_status_code: int
    expectation_satisfied: bool
    verification_status: str
    response_metadata: dict[str, Any]


def requirement_check_id(requirement: dict[str, Any]) -> str:
    for key in ("evidence_id", "check_id", "id", "name"):
        value = requirement.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def find_external_api_requirement(
    template: ApplicationTemplate,
    check_id: str,
) -> dict[str, Any] | None:
    """Find a template evidence requirement configured as an external API check."""

    for requirement in template.evidence_requirements or []:
        if not isinstance(requirement, dict):
            continue
        evidence_type = str(requirement.get("evidence_type") or "").upper()
        if evidence_type not in {"EXTERNAL_API", "EXTERNAL_FACT"}:
            continue
        if "api" not in requirement and evidence_type != "EXTERNAL_API":
            continue
        if requirement_check_id(requirement) == check_id:
            return requirement
    return None


def _path_value(root: Any, path: str) -> Any:
    normalized = str(path or "").strip()
    if not normalized:
        return None
    if normalized.startswith("$."):
        normalized = normalized[2:]
    elif normalized.startswith("$"):
        normalized = normalized[1:].lstrip(".")
    current = root
    for part in [segment for segment in normalized.split(".") if segment]:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (TypeError, ValueError, IndexError):
                return None
        else:
            return None
    return current


def _template_context(app: Application, inputs: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "organization_id": app.organization_id,
        "application": {
            "id": app.id,
            "organization_id": app.organization_id,
            "application_template_id": app.application_template_id,
            "applicant_identifier": app.applicant_identifier,
            "form_data": app.form_data or {},
            "integration_context": app.integration_context or {},
        },
        "inputs": inputs or {},
    }


def _render_template(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: _render_template(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_render_template(item, context) for item in value]
    if not isinstance(value, str):
        return value

    full_match = _PLACEHOLDER_RE.fullmatch(value)
    if full_match:
        resolved = _path_value(context, full_match.group(1))
        return "" if resolved is None else resolved

    def _replace(match: re.Match[str]) -> str:
        resolved = _path_value(context, match.group(1))
        return "" if resolved is None else str(resolved)

    return _PLACEHOLDER_RE.sub(_replace, value)


def _validate_api_url(url: str, *, allow_private_network: bool = False) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"}:
        raise ExternalEvidenceApiError("External evidence API URL must use https")
    host = parsed.hostname
    if not host:
        raise ExternalEvidenceApiError("External evidence API URL must include a host")

    host_lower = host.lower()
    is_local_http = parsed.scheme == "http" and host_lower in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not is_local_http:
        raise ExternalEvidenceApiError("External evidence API URL must use https outside localhost development")

    if allow_private_network:
        return
    if host_lower == "localhost" or host_lower.endswith(".local"):
        raise ExternalEvidenceApiError("External evidence API URL cannot target local/private hosts")
    try:
        ip = ipaddress.ip_address(host_lower)
    except ValueError:
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ExternalEvidenceApiError("External evidence API URL cannot target local/private addresses")


def _mapping_value(spec: Any, response_json: Any, context: dict[str, Any]) -> Any:
    if isinstance(spec, dict):
        if "path" in spec:
            value = _path_value(response_json, str(spec.get("path") or ""))
            return spec.get("default") if value is None and "default" in spec else value
        if "template" in spec:
            return _render_template(spec.get("template"), context)
        if "value" in spec:
            return spec.get("value")
        return {key: _mapping_value(value, response_json, context) for key, value in spec.items()}
    if isinstance(spec, list):
        return [_mapping_value(item, response_json, context) for item in spec]
    if isinstance(spec, str):
        if spec.startswith("$"):
            return _path_value(response_json, spec)
        if "{{" in spec:
            return _render_template(spec, context)
    return spec


def _mapped_dict(mapping: Any, response_json: Any, context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(mapping, dict):
        return {}
    return {
        key: value
        for key, value in (
            (key, _mapping_value(spec, response_json, context))
            for key, spec in mapping.items()
        )
        if value is not None
    }


def _response_path_value(response_json: Any, status_code: int, path: str) -> Any:
    normalized = str(path or "").strip()
    if normalized == "status_code":
        return status_code
    if normalized.startswith("body.") or normalized.startswith("$.body."):
        return _path_value({"body": response_json}, normalized)
    return _path_value(response_json, normalized)


def _numeric_value(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _response_condition_satisfied(response_json: Any, status_code: int, condition: Any) -> bool:
    if not isinstance(condition, dict):
        return bool(condition)
    if "all" in condition:
        items = condition.get("all")
        return isinstance(items, list) and all(
            _response_condition_satisfied(response_json, status_code, item)
            for item in items
        )
    if "any" in condition:
        items = condition.get("any")
        return isinstance(items, list) and any(
            _response_condition_satisfied(response_json, status_code, item)
            for item in items
        )
    if "not" in condition:
        return not _response_condition_satisfied(response_json, status_code, condition.get("not"))

    path = condition.get("path")
    if not isinstance(path, str) or not path:
        return False
    actual = _response_path_value(response_json, status_code, path)
    operator = str(condition.get("op") or condition.get("operator") or "").lower()
    expected = condition.get("value")
    if not operator:
        operator = "eq" if "value" in condition else "exists"

    if operator in {"exists", "present"}:
        return actual is not None
    if operator in {"truthy", "true"}:
        return bool(actual)
    if operator in {"falsy", "false"}:
        return not bool(actual)
    if operator in {"eq", "equals", "=="}:
        return actual == expected
    if operator in {"neq", "not_equals", "!="}:
        return actual != expected
    if operator in {">=", "gte", "gt_eq", "min"}:
        actual_number = _numeric_value(actual)
        expected_number = _numeric_value(expected)
        return actual_number is not None and expected_number is not None and actual_number >= expected_number
    if operator in {">", "gt"}:
        actual_number = _numeric_value(actual)
        expected_number = _numeric_value(expected)
        return actual_number is not None and expected_number is not None and actual_number > expected_number
    if operator in {"<=", "lte", "lt_eq", "max"}:
        actual_number = _numeric_value(actual)
        expected_number = _numeric_value(expected)
        return actual_number is not None and expected_number is not None and actual_number <= expected_number
    if operator in {"<", "lt"}:
        actual_number = _numeric_value(actual)
        expected_number = _numeric_value(expected)
        return actual_number is not None and expected_number is not None and actual_number < expected_number
    if operator == "in":
        return isinstance(expected, list) and actual in expected
    if operator == "contains":
        if isinstance(actual, list):
            return expected in actual
        if isinstance(actual, str):
            return str(expected) in actual
        return False
    return False


def _expectations_satisfied(
    *,
    response_json: Any,
    status_code: int,
    expectation: dict[str, Any],
) -> bool:
    allowed_statuses = expectation.get("status_codes") or expectation.get("status")
    if allowed_statuses is None:
        status_ok = 200 <= status_code < 300
    elif isinstance(allowed_statuses, list):
        status_ok = status_code in [int(item) for item in allowed_statuses]
    else:
        status_ok = status_code == int(allowed_statuses)
    if not status_ok:
        return False
    condition = (
        expectation.get("json")
        or expectation.get("conditions")
        or expectation.get("body")
    )
    if condition is None:
        return True
    return _response_condition_satisfied(response_json, status_code, condition)


def _response_hash(response_json: Any) -> str:
    body = json.dumps(response_json, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


async def execute_external_evidence_api_check(
    *,
    app: Application,
    requirement: dict[str, Any],
    inputs: dict[str, Any] | None = None,
) -> ExternalEvidenceApiCheckResult:
    """Execute a user-defined API check and normalize its response into an EvidenceFact."""

    api = requirement.get("api")
    if not isinstance(api, dict):
        raise ExternalEvidenceApiError("External evidence requirement is missing api configuration")
    check_id = requirement_check_id(requirement)
    if not check_id:
        raise ExternalEvidenceApiError("External evidence requirement is missing evidence_id")

    context = _template_context(app, inputs)
    method = str(api.get("method") or "POST").upper()
    if method not in _ALLOWED_METHODS:
        raise ExternalEvidenceApiError(f"Unsupported external evidence API method {method!r}")
    url = _render_template(api.get("url"), context)
    if not isinstance(url, str) or not url:
        raise ExternalEvidenceApiError("External evidence API URL is required")
    _validate_api_url(url, allow_private_network=bool(api.get("allow_private_network")))

    timeout_seconds = max(1.0, min(float(api.get("timeout_seconds") or 10.0), 20.0))
    headers = _mapped_dict(api.get("headers") or {}, {}, context)
    secret_headers = api.get("secret_headers") or {}
    if isinstance(secret_headers, dict):
        for header_name, env_name in secret_headers.items():
            if not header_name or not env_name:
                continue
            secret_value = os.environ.get(str(env_name))
            if secret_value:
                headers[str(header_name)] = secret_value
    params = _render_template(api.get("params") or {}, context)
    body = _render_template(api.get("body") if "body" in api else api.get("json"), context)

    request_kwargs: dict[str, Any] = {
        "headers": headers,
        "params": params,
    }
    if method != "GET" and body not in (None, ""):
        if isinstance(body, str):
            request_kwargs["content"] = body
        else:
            request_kwargs["json"] = body

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        response = await client.request(method, url, **request_kwargs)

    try:
        response_json: Any = response.json()
    except ValueError:
        response_json = {"text": response.text}

    expectation = (
        requirement.get("expected_response")
        or requirement.get("response_expectations")
        or requirement.get("expected")
        or {}
    )
    expectation = expectation if isinstance(expectation, dict) else {}
    expectation_satisfied = _expectations_satisfied(
        response_json=response_json,
        status_code=response.status_code,
        expectation=expectation,
    )

    mapping = requirement.get("response_mapping") or {}
    mapping = mapping if isinstance(mapping, dict) else {}
    provider = str(
        _mapping_value(mapping.get("provider"), response_json, context)
        or requirement.get("provider")
        or "external_api"
    )
    fact_type = str(
        _mapping_value(mapping.get("fact_type"), response_json, context)
        or requirement.get("fact_type")
        or f"{provider}.external_check"
    )
    subject_path = mapping.get("subject_id_path")
    subject_id = str(
        _mapping_value(mapping.get("subject_id"), response_json, context)
        or (_path_value(response_json, subject_path) if isinstance(subject_path, str) else None)
        or app.applicant_identifier
    )
    scope = {
        **(requirement.get("scope") if isinstance(requirement.get("scope"), dict) else {}),
        **_mapped_dict(mapping.get("scope") or {}, response_json, context),
    }
    assertion = _mapped_dict(mapping.get("assertion") or mapping.get("assertions") or {}, response_json, context)
    if not assertion:
        assertion = {"response_matched": expectation_satisfied}

    status_path = mapping.get("verification_status_path")
    mapped_status = _path_value(response_json, status_path) if isinstance(status_path, str) else None
    verified_values = mapping.get("verification_verified_values") or ["verified", "valid", "passed", "pass", True]
    if mapped_status is None:
        verification_status = "VERIFIED" if expectation_satisfied else "UNVERIFIED"
    else:
        status_matches = any(
            mapped_status == value
            or str(mapped_status).lower() == str(value).lower()
            for value in verified_values
        )
        verification_status = "VERIFIED" if expectation_satisfied and status_matches else "UNVERIFIED"
    provider_event_path = mapping.get("provider_event_id_path") or mapping.get("source_event_id_path")
    provider_event_id = (
        _mapping_value(mapping.get("provider_event_id"), response_json, context)
        or (_path_value(response_json, provider_event_path) if isinstance(provider_event_path, str) else None)
    )
    parsed_url = urlparse(url)
    now = datetime.now(timezone.utc)
    verification = {
        "method": str(requirement.get("verification_method") or "EXTERNAL_API_RESPONSE"),
        "status": verification_status,
        "verified_at": now.isoformat(),
        "expectation_satisfied": expectation_satisfied,
        "http_status_code": response.status_code,
    }
    source = {
        "type": "USER_DEFINED_API",
        "check_id": check_id,
        "provider_event_id": str(provider_event_id) if provider_event_id is not None else None,
        "endpoint_host": parsed_url.netloc,
        "endpoint_path": parsed_url.path,
        "http_method": method,
        "http_status_code": response.status_code,
        "response_hash": _response_hash(response_json),
    }
    evidence_fact = EvidenceFact(
        organization_id=app.organization_id,
        application_id=app.id,
        subject_id=subject_id,
        provider=provider,
        fact_type=fact_type,
        scope=scope,
        assertion=assertion,
        verification=verification,
        source={key: value for key, value in source.items() if value is not None},
        created_at=now,
    )
    return ExternalEvidenceApiCheckResult(
        evidence_fact=evidence_fact,
        requirement=requirement,
        check_id=check_id,
        http_status_code=response.status_code,
        expectation_satisfied=expectation_satisfied,
        verification_status=verification_status,
        response_metadata={
            "http_status_code": response.status_code,
            "response_hash": source["response_hash"],
            "endpoint_host": parsed_url.netloc,
            "endpoint_path": parsed_url.path,
        },
    )
