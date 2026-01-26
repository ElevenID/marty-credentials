"""Prometheus metrics for credential operations"""
from prometheus_client import Counter, Histogram, Gauge

# Counters - track total occurrences
credentials_issued_total = Counter(
    'credentials_issued_total',
    'Total credentials issued',
    ['credential_type', 'format', 'issuer_id']
)

credentials_verified_total = Counter(
    'credentials_verified_total',
    'Total credentials verified',
    ['credential_type', 'result']
)

credential_verification_failures_total = Counter(
    'credential_verification_failures_total',
    'Total credential verification failures',
    ['credential_type', 'error_type', 'issuer']
)

credentials_revoked_total = Counter(
    'credentials_revoked_total',
    'Total credentials revoked',
    ['credential_type', 'reason']
)

token_validations_total = Counter(
    'token_validations_total',
    'Total token validation attempts',
    ['result']
)

token_cache_hits_total = Counter(
    'token_cache_hits_total',
    'Total token cache hits'
)

token_cache_misses_total = Counter(
    'token_cache_misses_total',
    'Total token cache misses'
)

# Histograms - track duration distributions
credential_issuance_duration_seconds = Histogram(
    'credential_issuance_duration_seconds',
    'Time to issue credential',
    ['credential_type', 'format'],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
)

credential_verification_duration_seconds = Histogram(
    'credential_verification_duration_seconds',
    'Time to verify credential',
    ['credential_type'],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

mdoc_signature_verification_duration_seconds = Histogram(
    'mdoc_signature_verification_duration_seconds',
    'Time to verify mDoc signature',
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)

token_validation_duration_seconds = Histogram(
    'token_validation_duration_seconds',
    'Time to validate OAuth2 token',
    ['cache_hit'],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)
)

# Gauges - track current values
active_credentials = Gauge(
    'active_credentials',
    'Number of active (non-revoked) credentials',
    ['credential_type']
)

rate_limit_remaining = Gauge(
    'rate_limit_remaining',
    'Remaining rate limit quota',
    ['resource_type', 'resource_id']
)
