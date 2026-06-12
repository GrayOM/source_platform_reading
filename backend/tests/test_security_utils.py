"""Unit tests for security utilities."""
import pytest
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
    encrypt_session_data,
    decrypt_session_data,
    validate_target_url,
)


def test_password_hash_verify():
    hashed = hash_password("mysecretpassword")
    assert verify_password("mysecretpassword", hashed)
    assert not verify_password("wrongpassword", hashed)


def test_jwt_round_trip():
    token = create_access_token("user-123", {"role": "admin"})
    payload = decode_token(token)
    assert payload["sub"] == "user-123"
    assert payload["role"] == "admin"
    assert payload["type"] == "access"


def test_session_encryption_round_trip():
    data = b'{"session": "abc123", "token": "xyz"}'
    encrypted = encrypt_session_data(data)
    assert encrypted != data
    decrypted = decrypt_session_data(encrypted)
    assert decrypted == data


def test_ssrf_validation_blocks_localhost():
    with pytest.raises(ValueError, match="SSRF"):
        validate_target_url("http://localhost/admin")


def test_ssrf_validation_blocks_private():
    with pytest.raises(ValueError, match="SSRF"):
        validate_target_url("http://192.168.1.1/")


def test_ssrf_validation_allows_public():
    # Should not raise for public domains (DNS might fail but that's ok)
    try:
        validate_target_url("https://example.com/")
    except ValueError as e:
        if "SSRF" in str(e):
            pytest.fail(f"SSRF check incorrectly blocked example.com: {e}")
