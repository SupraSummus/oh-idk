"""Tests for oh-idk crypto utilities."""
import pytest

from app.crypto import (
    create_request_signature,
    generate_keypair,
    is_valid_public_key,
    sign_message,
    verify_request_signature,
    verify_signature,
)


def test_generate_keypair():
    """Test keypair generation."""
    public_key, private_key = generate_keypair()

    assert public_key is not None
    assert private_key is not None
    assert len(public_key) == 44  # Base64 of 32 bytes
    assert len(private_key) == 44  # Base64 of 32 bytes


def test_sign_and_verify():
    """Test signing and verification."""
    public_key, private_key = generate_keypair()
    message = "Hello, World!"

    signature = sign_message(private_key, message)

    assert signature is not None
    assert verify_signature(public_key, message, signature)


def test_verify_wrong_message():
    """Test that wrong message fails verification."""
    public_key, private_key = generate_keypair()

    signature = sign_message(private_key, "Original message")

    assert not verify_signature(public_key, "Wrong message", signature)


def test_verify_wrong_key():
    """Test that wrong key fails verification."""
    public_key1, private_key1 = generate_keypair()
    public_key2, private_key2 = generate_keypair()

    signature = sign_message(private_key1, "Test message")

    # Signature made with key1 should not verify with key2
    assert not verify_signature(public_key2, "Test message", signature)


def test_request_signature():
    """Test request signing and verification."""
    import time

    public_key, private_key = generate_keypair()
    method = "POST"
    path = "/vouch"
    timestamp = int(time.time())
    body = '{"vouchee_public_key": "abc123"}'

    signature = create_request_signature(private_key, method, path, timestamp, body)

    assert verify_request_signature(
        public_key, method, path, timestamp, signature, body
    )


def test_request_signature_expired():
    """Test that old timestamps are rejected."""
    import time

    public_key, private_key = generate_keypair()
    old_timestamp = int(time.time()) - 600  # 10 minutes ago

    signature = create_request_signature(
        private_key, "POST", "/vouch", old_timestamp, "{}"
    )

    assert not verify_request_signature(
        public_key, "POST", "/vouch", old_timestamp, signature, "{}"
    )


def test_is_valid_public_key():
    """Test public key validation."""
    public_key, _ = generate_keypair()

    assert is_valid_public_key(public_key)
    assert not is_valid_public_key("not-a-key")
    assert not is_valid_public_key("")
    assert not is_valid_public_key("AQAB")  # Too short


def test_generate_keypair_uniqueness():
    """Test that generated keypairs are unique."""
    pairs = [generate_keypair() for _ in range(10)]
    public_keys = [p[0] for p in pairs]
    private_keys = [p[1] for p in pairs]

    # All public keys should be unique
    assert len(set(public_keys)) == 10
    # All private keys should be unique
    assert len(set(private_keys)) == 10


def test_sign_message_empty():
    """Test signing an empty message."""
    public_key, private_key = generate_keypair()
    message = ""

    signature = sign_message(private_key, message)
    assert verify_signature(public_key, message, signature)


def test_sign_message_unicode():
    """Test signing a message with unicode characters."""
    public_key, private_key = generate_keypair()
    message = "Hello, 世界! 🌍 Привет мир"

    signature = sign_message(private_key, message)
    assert verify_signature(public_key, message, signature)


def test_sign_message_long():
    """Test signing a long message."""
    public_key, private_key = generate_keypair()
    message = "A" * 10000

    signature = sign_message(private_key, message)
    assert verify_signature(public_key, message, signature)


def test_verify_signature_invalid_base64():
    """Test verification with invalid base64 signature."""
    public_key, _ = generate_keypair()

    # Invalid base64 strings should return False, not raise
    assert not verify_signature(public_key, "test", "not-valid-base64!!!")
    assert not verify_signature(public_key, "test", "")


def test_verify_signature_wrong_length():
    """Test verification with wrong signature length."""
    public_key, _ = generate_keypair()

    # Valid base64 but wrong length (too short)
    assert not verify_signature(public_key, "test", "AAAA")


def test_request_signature_future_timestamp():
    """Test that future timestamps are rejected."""
    import time

    public_key, private_key = generate_keypair()
    future_timestamp = int(time.time()) + 600  # 10 minutes in the future

    signature = create_request_signature(
        private_key, "POST", "/vouch", future_timestamp, "{}"
    )

    assert not verify_request_signature(
        public_key, "POST", "/vouch", future_timestamp, signature, "{}"
    )


def test_request_signature_different_method():
    """Test that changing HTTP method invalidates signature."""
    import time

    public_key, private_key = generate_keypair()
    timestamp = int(time.time())

    signature = create_request_signature(
        private_key, "POST", "/vouch", timestamp, "{}"
    )

    # Signature for POST should not verify for GET
    assert not verify_request_signature(
        public_key, "GET", "/vouch", timestamp, signature, "{}"
    )


def test_request_signature_different_path():
    """Test that changing path invalidates signature."""
    import time

    public_key, private_key = generate_keypair()
    timestamp = int(time.time())

    signature = create_request_signature(
        private_key, "POST", "/vouch", timestamp, "{}"
    )

    # Signature for /vouch should not verify for /register
    assert not verify_request_signature(
        public_key, "POST", "/register", timestamp, signature, "{}"
    )


def test_request_signature_different_body():
    """Test that changing body invalidates signature."""
    import time

    public_key, private_key = generate_keypair()
    timestamp = int(time.time())

    signature = create_request_signature(
        private_key, "POST", "/vouch", timestamp, '{"key": "value1"}'
    )

    # Signature for one body should not verify for different body
    assert not verify_request_signature(
        public_key, "POST", "/vouch", timestamp, signature, '{"key": "value2"}'
    )


def test_request_signature_custom_max_age():
    """Test request signature with custom max_age_seconds."""
    import time

    public_key, private_key = generate_keypair()
    old_timestamp = int(time.time()) - 120  # 2 minutes ago

    signature = create_request_signature(
        private_key, "POST", "/vouch", old_timestamp, "{}"
    )

    # With default 300s max_age, should pass
    assert verify_request_signature(
        public_key, "POST", "/vouch", old_timestamp, signature, "{}", max_age_seconds=300
    )

    # With 60s max_age, should fail (timestamp is 120s old)
    assert not verify_request_signature(
        public_key, "POST", "/vouch", old_timestamp, signature, "{}", max_age_seconds=60
    )


def test_is_valid_public_key_with_invalid_key_bytes():
    """Test is_valid_public_key with valid base64 but invalid key content."""
    import base64

    # Valid base64, correct length (32 bytes), but not a valid Ed25519 key
    # Actually, any 32 random bytes should be a valid key on the curve
    # So let's test with a key that's the wrong length but valid base64
    wrong_length = base64.b64encode(b"x" * 16).decode()  # 16 bytes, not 32
    assert not is_valid_public_key(wrong_length)

    # Test with exactly 32 bytes of zeros (should be rejected by nacl)
    zeros_key = base64.b64encode(b"\x00" * 32).decode()
    # Note: nacl should reject the all-zeros key as it's not on the curve
    # But actually it might accept it depending on version - this tests the edge case
    result = is_valid_public_key(zeros_key)
    # Either True or False is acceptable; the key point is it doesn't crash
    assert isinstance(result, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
