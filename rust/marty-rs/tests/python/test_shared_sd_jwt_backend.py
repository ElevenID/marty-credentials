"""The shared verification backend returns Python errors for bad public keys."""

import _marty_rs
import pytest


@pytest.mark.parametrize("algorithm", ["ES256", "ES384", "RS256", "EdDSA"])
def test_invalid_public_key_is_a_value_error(algorithm):
    with pytest.raises(ValueError, match="Invalid .* public key PEM"):
        _marty_rs.verify_sd_jwt("invalid~", "invalid PEM", algorithm)


def test_unsupported_algorithm_is_a_value_error():
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        _marty_rs.verify_sd_jwt("invalid~", "invalid PEM", "HS256")
