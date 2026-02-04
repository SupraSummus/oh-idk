"""Authentication middleware for signed requests."""
import time

from fastapi import Header, HTTPException, Request

from app.crypto import verify_request_signature


async def verify_auth_headers(
    request: Request,
    x_public_key: str = Header(..., description="Your Ed25519 public key"),
    x_timestamp: str = Header(..., description="Unix timestamp of request"),
    x_signature: str = Header(..., description="Signature of request")
) -> str:
    """
    Verify authentication headers for a signed request.

    The signature covers: METHOD:PATH:TIMESTAMP:BODY

    Args:
        request: FastAPI request object
        x_public_key: Public key of the requester
        x_timestamp: Unix timestamp
        x_signature: Base64-encoded signature

    Returns:
        The verified public key

    Raises:
        HTTPException: If authentication fails
    """
    try:
        timestamp = int(x_timestamp)
    except ValueError as err:
        raise HTTPException(status_code=400, detail="Invalid timestamp format") from err

    # Get request body for signature verification
    body = await request.body()
    body_str = body.decode('utf-8') if body else ""

    # Verify the signature
    is_valid = verify_request_signature(
        public_key_b64=x_public_key,
        method=request.method,
        path=request.url.path,
        timestamp=timestamp,
        signature_b64=x_signature,
        body=body_str
    )

    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid signature or timestamp expired"
        )

    return x_public_key


def optional_auth_headers(
    x_public_key: str | None = Header(None),
    x_timestamp: str | None = Header(None),
    x_signature: str | None = Header(None)
) -> str | None:
    """
    Optional authentication - returns public key if headers are present and valid.

    Returns:
        Public key if authenticated, None otherwise
    """
    if not all([x_public_key, x_timestamp, x_signature]):
        return None

    try:
        # x_timestamp is guaranteed to be str at this point (checked in if above)
        timestamp = int(x_timestamp)  # type: ignore[arg-type]
        current_time = int(time.time())

        if abs(current_time - timestamp) > 300:
            return None

        # Note: We can't verify the full signature here without the body
        # This is just for optional info - use verify_auth_headers for secured endpoints
        return x_public_key
    except (ValueError, TypeError):
        return None
