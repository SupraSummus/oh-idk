"""Pytest fixtures and test utilities for security-oriented testing.

This module provides fixtures for database integration tests and helper functions
for creating authenticated requests following the security baseline testing pattern.

The baseline testing pattern ensures that security tests:
1. First verify the test setup works (baseline/positive case)
2. Then test the actual security restriction (negative cases)

This prevents false positives where tests pass due to broken setup rather than
actual security controls.
"""
import json
import os
import time
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.crypto import create_request_signature, generate_keypair
from app.main import app
from app.models import Base, Identity, get_db

# Use SQLite for testing to avoid PostgreSQL dependency in CI
# In production/local dev with PostgreSQL, you can override with TEST_DATABASE_URL env var
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "sqlite+aiosqlite:///./test_ohidk.db"
)


# Create a test engine and session maker
test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a test database session with automatic cleanup.

    Creates all tables before the test and drops them after.
    Each test gets a fresh database state.
    """
    # Create tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create session
    async with TestSessionLocal() as session:
        yield session

    # Drop tables after test
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def client(db_session: AsyncSession) -> TestClient:  # type: ignore[misc]
    """
    Create a test client with overridden database dependency.

    This ensures all API calls use the test database session.

    Note: The type: ignore[misc] is necessary because the fixture returns a
    TestClient (not a generator), but it uses yield to allow cleanup code
    to run after the test. Mypy's generator return type checking gets confused
    by this pattern which is standard for pytest fixtures.
    """
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_identity(db_session: AsyncSession) -> tuple[Identity, str, str]:
    """
    Create a test identity in the database.

    Returns:
        Tuple of (Identity object, public_key, private_key)
    """
    public_key, private_key = generate_keypair()

    identity = Identity(
        public_key=public_key,
        metadata_json=json.dumps({"name": "Test User"})
    )

    db_session.add(identity)
    await db_session.commit()
    await db_session.refresh(identity)

    return identity, public_key, private_key


@pytest_asyncio.fixture
async def another_identity(db_session: AsyncSession) -> tuple[Identity, str, str]:
    """
    Create another test identity in the database.

    Useful for testing interactions between different identities.

    Returns:
        Tuple of (Identity object, public_key, private_key)
    """
    public_key, private_key = generate_keypair()

    identity = Identity(
        public_key=public_key,
        metadata_json=json.dumps({"name": "Another User"})
    )

    db_session.add(identity)
    await db_session.commit()
    await db_session.refresh(identity)

    return identity, public_key, private_key


def create_auth_headers(
    private_key: str,
    public_key: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    timestamp: int | None = None
) -> dict[str, str]:
    """
    Create authentication headers for signed requests.

    This is a helper function for creating properly signed requests in tests.

    Args:
        private_key: Base64-encoded Ed25519 private key
        public_key: Base64-encoded Ed25519 public key
        method: HTTP method (GET, POST, DELETE, etc.)
        path: Request path (e.g., "/vouch")
        body: Optional request body (will be JSON-encoded)
        timestamp: Optional timestamp (defaults to current time)

    Returns:
        Dictionary of headers ready to use in requests

    Example:
        headers = create_auth_headers(private_key, public_key, "POST", "/vouch", {"vouchee_public_key": "xyz"})
        response = client.post("/vouch", json=body, headers=headers)
    """
    if timestamp is None:
        timestamp = int(time.time())

    body_str = json.dumps(body) if body else ""

    signature = create_request_signature(
        private_key, method, path, timestamp, body_str
    )

    return {
        "X-Public-Key": public_key,
        "X-Timestamp": str(timestamp),
        "X-Signature": signature
    }


async def create_test_identity(
    db_session: AsyncSession,
    metadata: dict[str, Any] | None = None
) -> tuple[Identity, str, str]:
    """
    Create a test identity in the database.

    This is a helper function (not a fixture) that can be called multiple times
    within a single test to create multiple identities.

    Args:
        db_session: Database session
        metadata: Optional metadata for the identity

    Returns:
        Tuple of (Identity object, public_key, private_key)
    """
    public_key, private_key = generate_keypair()

    identity = Identity(
        public_key=public_key,
        metadata_json=json.dumps(metadata) if metadata else None
    )

    db_session.add(identity)
    await db_session.commit()
    await db_session.refresh(identity)

    return identity, public_key, private_key
