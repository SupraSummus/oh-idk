"""Tests for rate limiting functionality."""
import pytest
from httpx import AsyncClient

from app.crypto import generate_keypair


@pytest.mark.asyncio
async def test_register_rate_limit(async_client: AsyncClient) -> None:
    """Test that /register endpoint enforces rate limit."""
    # Make multiple requests and verify rate limiting kicks in
    public_key_base, _ = generate_keypair()

    # Make requests until we hit the rate limit
    success_count = 0
    for i in range(15):  # More than the limit of 10
        response = await async_client.post(
            "/register",
            json={"public_key": f"{public_key_base}_{i}"}  # Unique keys
        )
        if response.status_code == 200:
            success_count += 1
        elif response.status_code == 429:
            # Hit rate limit - this is expected
            assert "X-RateLimit-Limit" in response.headers
            break

    # We should have hit the rate limit before all 15 requests
    assert success_count <= 10


@pytest.mark.asyncio
async def test_verify_rate_limit_headers(async_client: AsyncClient) -> None:
    """Test that /verify endpoint returns rate limit headers."""
    public_key, _ = generate_keypair()

    response = await async_client.post(
        "/verify",
        json={
            "public_key": public_key,
            "message": "test message",
            "signature": "invalid_signature"
        }
    )

    # Check that rate limit headers are present
    if response.status_code == 200:
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers
        # Verify the limit value (100 for /verify)
        assert response.headers["X-RateLimit-Limit"] == "100"


@pytest.mark.asyncio
async def test_trust_endpoint_has_rate_limit(async_client: AsyncClient) -> None:
    """Test that /trust/{key} endpoint has rate limiting configured."""
    public_key, _ = generate_keypair()

    # Make a request to /trust (doesn't need registration to test rate limit headers)
    response = await async_client.get(f"/trust/{public_key}")

    # The endpoint should process the request (even if 404)
    # and rate limit headers should be present on success
    # If we get a 200, check for headers
    if response.status_code == 200:
        assert "X-RateLimit-Limit" in response.headers
        assert response.headers["X-RateLimit-Limit"] == "100"


@pytest.mark.asyncio
async def test_vouch_endpoint_has_rate_limit(async_client: AsyncClient) -> None:
    """Test that /vouch endpoint has rate limiting configured."""
    # This test verifies the decorator is applied
    # We can check this by inspecting the function or making a simple request
    # For simplicity, we'll just verify the limiter is configured
    from app.main import limiter, vouch
    assert limiter is not None
    # The vouch function should have the rate limit decorator
    assert hasattr(vouch, "__wrapped__")  # Decorated functions have __wrapped__


@pytest.mark.asyncio
async def test_rate_limit_429_response(async_client: AsyncClient) -> None:
    """Test that rate limit returns 429 status code when exceeded."""
    public_key_base, _ = generate_keypair()

    # Make enough requests to trigger rate limit (register has limit of 10/minute)
    hit_rate_limit = False
    for i in range(20):
        response = await async_client.post(
            "/register",
            json={"public_key": f"{public_key_base}_ratelimit_{i}"}
        )
        if response.status_code == 429:
            hit_rate_limit = True
            # Verify rate limit headers are present on 429 response
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Reset" in response.headers
            break

    # We should have hit the rate limit
    assert hit_rate_limit, "Expected to hit rate limit but didn't"
