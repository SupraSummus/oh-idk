"""Tests for oh-idk crypto utilities."""
import pytest
from app.crypto import (
    generate_keypair,
    sign_message,
    verify_signature,
    create_request_signature,
    verify_request_signature,
    is_valid_public_key
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
