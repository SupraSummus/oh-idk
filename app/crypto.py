"""Ed25519 cryptographic utilities."""
import base64
import time
from typing import Tuple

from nacl.exceptions import BadSignature
from nacl.signing import SigningKey, VerifyKey


def generate_keypair() -> Tuple[str, str]:
    """
    Generate a new Ed25519 keypair.
    
    Returns:
        Tuple of (public_key_base64, private_key_base64)
    """
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    private_b64 = base64.b64encode(bytes(signing_key)).decode('utf-8')
    public_b64 = base64.b64encode(bytes(verify_key)).decode('utf-8')
    
    return public_b64, private_b64


def sign_message(private_key_b64: str, message: str) -> str:
    """
    Sign a message with a private key.
    
    Args:
        private_key_b64: Base64-encoded Ed25519 private key
        message: The message to sign
    
    Returns:
        Base64-encoded signature
    """
    private_key_bytes = base64.b64decode(private_key_b64)
    signing_key = SigningKey(private_key_bytes)
    
    signed = signing_key.sign(message.encode('utf-8'))
    signature = signed.signature
    
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(public_key_b64: str, message: str, signature_b64: str) -> bool:
    """
    Verify a signature against a message and public key.
    
    Args:
        public_key_b64: Base64-encoded Ed25519 public key
        message: The original message
        signature_b64: Base64-encoded signature
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key_bytes = base64.b64decode(public_key_b64)
        signature_bytes = base64.b64decode(signature_b64)
        
        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(message.encode('utf-8'), signature_bytes)
        
        return True
    except (BadSignature, ValueError, Exception):
        return False


def create_request_signature(
    private_key_b64: str,
    method: str,
    path: str,
    timestamp: int,
    body: str = ""
) -> str:
    """
    Create a signature for an authenticated request.
    
    The signed message format is: METHOD:PATH:TIMESTAMP:BODY
    
    Args:
        private_key_b64: Base64-encoded Ed25519 private key
        method: HTTP method (GET, POST, etc.)
        path: Request path (e.g., /vouch)
        timestamp: Unix timestamp
        body: Request body (empty string for GET)
    
    Returns:
        Base64-encoded signature
    """
    message = f"{method}:{path}:{timestamp}:{body}"
    return sign_message(private_key_b64, message)


def verify_request_signature(
    public_key_b64: str,
    method: str,
    path: str,
    timestamp: int,
    signature_b64: str,
    body: str = "",
    max_age_seconds: int = 300
) -> bool:
    """
    Verify a request signature.
    
    Also checks that the timestamp is recent (within max_age_seconds).
    
    Args:
        public_key_b64: Base64-encoded Ed25519 public key
        method: HTTP method
        path: Request path
        timestamp: Unix timestamp from request
        signature_b64: Base64-encoded signature
        body: Request body
        max_age_seconds: Maximum age of request in seconds
    
    Returns:
        True if signature is valid and timestamp is recent, False otherwise
    """
    # Check timestamp freshness
    current_time = int(time.time())
    if abs(current_time - timestamp) > max_age_seconds:
        return False
    
    # Verify signature
    message = f"{method}:{path}:{timestamp}:{body}"
    return verify_signature(public_key_b64, message, signature_b64)


def is_valid_public_key(public_key_b64: str) -> bool:
    """
    Check if a string is a valid Ed25519 public key.
    
    Args:
        public_key_b64: Base64-encoded public key
    
    Returns:
        True if valid, False otherwise
    """
    try:
        key_bytes = base64.b64decode(public_key_b64)
        if len(key_bytes) != 32:  # Ed25519 public keys are 32 bytes
            return False
        VerifyKey(key_bytes)
        return True
    except Exception:
        return False
