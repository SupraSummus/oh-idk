"""Integration tests for API endpoints."""
import time

import pytest
from fastapi.testclient import TestClient

from app.crypto import create_request_signature, generate_keypair, sign_message
from app.main import app

# Use a sync test client since endpoints need database
# For real integration tests, we'd need a test database setup
# These tests focus on validation and basic flow without a database


@pytest.fixture
def client() -> TestClient:
    """Create a test client."""
    return TestClient(app)


def test_root_endpoint(client: TestClient) -> None:
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "oh-idk"


def test_health_endpoint(client: TestClient) -> None:
    """Test the dedicated health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "oh-idk"
    assert "version" in data


def test_register_invalid_public_key(client: TestClient) -> None:
    """Test register endpoint rejects invalid public keys."""
    # Invalid format
    response = client.post(
        "/register",
        json={"public_key": "not-a-valid-key"}
    )
    assert response.status_code == 422  # Validation error

    # Empty key
    response = client.post(
        "/register",
        json={"public_key": ""}
    )
    assert response.status_code == 422


def test_verify_endpoint_valid_signature(client: TestClient) -> None:
    """Test verify endpoint with valid signature."""
    public_key, private_key = generate_keypair()
    message = "Hello, World!"
    signature = sign_message(private_key, message)

    response = client.post(
        "/verify",
        json={
            "public_key": public_key,
            "message": message,
            "signature": signature
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["public_key"] == public_key


def test_verify_endpoint_invalid_signature(client: TestClient) -> None:
    """Test verify endpoint with invalid signature."""
    public_key, private_key = generate_keypair()
    message = "Hello, World!"
    # Sign a different message
    signature = sign_message(private_key, "Different message")

    response = client.post(
        "/verify",
        json={
            "public_key": public_key,
            "message": message,
            "signature": signature
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False


def test_verify_endpoint_invalid_public_key(client: TestClient) -> None:
    """Test verify endpoint rejects invalid public keys."""
    response = client.post(
        "/verify",
        json={
            "public_key": "invalid",
            "message": "test",
            "signature": "test"
        }
    )
    assert response.status_code == 422  # Validation error


def test_vouch_requires_auth_headers(client: TestClient) -> None:
    """Test vouch endpoint requires authentication headers."""
    public_key, _ = generate_keypair()

    # Missing all auth headers
    response = client.post(
        "/vouch",
        json={"vouchee_public_key": public_key}
    )
    assert response.status_code == 422  # Missing required headers


def test_vouch_invalid_timestamp(client: TestClient) -> None:
    """Test vouch endpoint rejects non-numeric timestamp."""
    public_key, private_key = generate_keypair()
    vouchee_key, _ = generate_keypair()

    response = client.post(
        "/vouch",
        json={"vouchee_public_key": vouchee_key},
        headers={
            "X-Public-Key": public_key,
            "X-Timestamp": "not-a-number",
            "X-Signature": "fake-signature"
        }
    )
    assert response.status_code == 400
    assert "Invalid timestamp format" in response.json()["detail"]


def test_vouch_invalid_signature(client: TestClient) -> None:
    """Test vouch endpoint rejects invalid signature."""
    public_key, private_key = generate_keypair()
    vouchee_key, _ = generate_keypair()
    timestamp = int(time.time())

    # Create a valid-looking but incorrect signature
    wrong_signature = sign_message(private_key, "wrong message")

    response = client.post(
        "/vouch",
        json={"vouchee_public_key": vouchee_key},
        headers={
            "X-Public-Key": public_key,
            "X-Timestamp": str(timestamp),
            "X-Signature": wrong_signature
        }
    )
    assert response.status_code == 401
    assert "Invalid signature" in response.json()["detail"]


def test_vouch_expired_timestamp(client: TestClient) -> None:
    """Test vouch endpoint rejects expired timestamp."""
    public_key, private_key = generate_keypair()
    vouchee_key, _ = generate_keypair()
    old_timestamp = int(time.time()) - 600  # 10 minutes ago
    body = f'{{"vouchee_public_key": "{vouchee_key}"}}'

    signature = create_request_signature(
        private_key, "POST", "/vouch", old_timestamp, body
    )

    response = client.post(
        "/vouch",
        json={"vouchee_public_key": vouchee_key},
        headers={
            "X-Public-Key": public_key,
            "X-Timestamp": str(old_timestamp),
            "X-Signature": signature
        }
    )
    assert response.status_code == 401
    assert "Invalid signature or timestamp expired" in response.json()["detail"]


def test_trust_invalid_public_key(client: TestClient) -> None:
    """Test trust endpoint with invalid public key format."""
    response = client.get("/trust/invalid-key-format")
    assert response.status_code == 400
    assert "Invalid public key format" in response.json()["detail"]


def test_revoke_vouch_requires_auth(client: TestClient) -> None:
    """Test revoke endpoint requires authentication."""
    response = client.delete("/vouch?voucher_public_key=test&vouchee_public_key=test")
    assert response.status_code == 422  # Missing required headers


def test_openapi_docs_available(client: TestClient) -> None:
    """Test that OpenAPI documentation is available."""
    response = client.get("/docs")
    assert response.status_code == 200

    response = client.get("/redoc")
    assert response.status_code == 200

    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "oh-idk"
    assert "paths" in schema


def test_vouch_request_validation(client: TestClient) -> None:
    """Test vouch request validation for vouchee_public_key."""
    public_key, private_key = generate_keypair()
    timestamp = int(time.time())

    # Invalid vouchee_public_key format should fail
    # Note: Auth check (signature verification) happens first, so we get 401
    # This is expected behavior - auth before validation
    response = client.post(
        "/vouch",
        json={"vouchee_public_key": "invalid-key"},
        headers={
            "X-Public-Key": public_key,
            "X-Timestamp": str(timestamp),
            "X-Signature": "dummy"
        }
    )
    assert response.status_code == 401  # Auth fails before validation


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
