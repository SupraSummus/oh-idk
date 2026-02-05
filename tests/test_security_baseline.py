"""Security-oriented tests using the baseline pattern.

This module demonstrates the baseline testing pattern for security tests.
Each test uses @pytest.mark.parametrize to test both:
1. Baseline case - verifies the test setup works (positive case)
2. Negative case(s) - tests the actual security restriction

This prevents false positives where tests pass due to broken setup rather than
actual security controls working.

Pattern Example:
    @pytest.mark.parametrize("scenario,expected_status", [
        ("baseline", 200),      # Proves setup works
        ("security_check", 403), # Tests the restriction
    ])
    def test_something(scenario, expected_status):
        # Setup
        owner = create_user()
        other = create_user()

        # Act based on scenario
        if scenario == "baseline":
            response = do_action_as(owner)
        else:  # security_check
            response = do_action_as(other)

        # Assert
        assert response.status_code == expected_status

Benefits:
- No false positives - if baseline fails, you know test setup is broken
- Self-documenting - clearly shows what's tested and expected
- Efficient - one test function covers related cases
- Debugging - easier to see which specific case failed
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Vouch
from tests.conftest import create_auth_headers, create_test_identity


@pytest.mark.asyncio
@pytest.mark.parametrize("voucher_scenario,expected_status", [
    ("voucher_self", 200),              # Baseline: registered user can vouch for another
    ("vouchee_self", 404),              # Security: unregistered user cannot vouch
])
async def test_vouch_creation_requires_registered_voucher(
    voucher_scenario: str,
    expected_status: int,
    client: TestClient,
    db_session: AsyncSession
) -> None:
    """
    Test that vouching requires the voucher to be registered.

    Baseline case: A registered user successfully vouches for another registered user
    Security case: An unregistered user cannot create a vouch (gets 404)

    This tests authorization at the identity level.
    """
    # Setup: Create registered identities
    voucher_identity, voucher_public, voucher_private = await create_test_identity(
        db_session, {"name": "Registered Voucher"}
    )
    vouchee_identity, vouchee_public, vouchee_private = await create_test_identity(
        db_session, {"name": "Registered Vouchee"}
    )

    # Create an unregistered identity (keypair only, not in DB)
    from app.crypto import generate_keypair
    unregistered_public, unregistered_private = generate_keypair()

    # Select which identity tries to vouch based on scenario
    if voucher_scenario == "voucher_self":
        # Baseline: registered user vouches
        auth_public, auth_private = voucher_public, voucher_private
    else:  # vouchee_self
        # Security check: unregistered user tries to vouch
        auth_public, auth_private = unregistered_public, unregistered_private

    # Create vouch request
    body = {"vouchee_public_key": vouchee_public}
    headers = create_auth_headers(auth_private, auth_public, "POST", "/vouch", body)

    # Execute
    response = client.post("/vouch", json=body, headers=headers)

    # Assert
    assert response.status_code == expected_status

    if expected_status == 200:
        # Baseline: verify vouch was created
        data = response.json()
        assert data["voucher_public_key"] == auth_public
        assert data["vouchee_public_key"] == vouchee_public
        assert "id" in data


@pytest.mark.asyncio
@pytest.mark.parametrize("vouch_scenario,expected_status", [
    ("self_vouch_attempt", 400),        # Security: cannot vouch for yourself
    ("different_user", 200),            # Baseline: can vouch for different user
])
async def test_vouch_creation_prevents_self_vouching(
    vouch_scenario: str,
    expected_status: int,
    client: TestClient,
    db_session: AsyncSession
) -> None:
    """
    Test that users cannot vouch for themselves.

    Baseline case: A user successfully vouches for a different user
    Security case: A user cannot vouch for themselves (gets 400)

    This tests the self-vouching prevention logic.
    """
    # Setup: Create identities
    identity1, public1, private1 = await create_test_identity(
        db_session, {"name": "User 1"}
    )
    identity2, public2, private2 = await create_test_identity(
        db_session, {"name": "User 2"}
    )

    # Select vouchee based on scenario
    if vouch_scenario == "self_vouch_attempt":
        # Security check: try to vouch for self
        vouchee_public = public1
    else:  # different_user
        # Baseline: vouch for different user
        vouchee_public = public2

    # Create vouch request
    body = {"vouchee_public_key": vouchee_public}
    headers = create_auth_headers(private1, public1, "POST", "/vouch", body)

    # Execute
    response = client.post("/vouch", json=body, headers=headers)

    # Assert
    assert response.status_code == expected_status

    if expected_status == 200:
        # Baseline: verify vouch was created
        data = response.json()
        assert data["voucher_public_key"] == public1
        assert data["vouchee_public_key"] == vouchee_public
    elif expected_status == 400:
        # Security: verify error message
        assert "Cannot vouch for yourself" in response.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("revoker_scenario,expected_status", [
    ("original_voucher", 200),          # Baseline: voucher can revoke own vouch
    ("different_user", 401),            # Security: different user cannot revoke
    ("vouchee", 401),                   # Security: vouchee cannot revoke vouch
])
async def test_vouch_revocation_authorization(
    revoker_scenario: str,
    expected_status: int,
    client: TestClient,
    db_session: AsyncSession
) -> None:
    """
    Test that only the voucher can revoke their own vouch.

    Baseline case: The original voucher successfully revokes their vouch
    Security cases:
        - A different user cannot revoke someone else's vouch (gets 401)
        - The vouchee cannot revoke a vouch given to them (gets 401)

    This tests authorization for the revoke operation.
    """
    # Setup: Create identities
    voucher_identity, voucher_public, voucher_private = await create_test_identity(
        db_session, {"name": "Voucher"}
    )
    vouchee_identity, vouchee_public, vouchee_private = await create_test_identity(
        db_session, {"name": "Vouchee"}
    )
    other_identity, other_public, other_private = await create_test_identity(
        db_session, {"name": "Other User"}
    )

    # Create a vouch
    vouch = Vouch(
        voucher_id=voucher_identity.id,
        vouchee_id=vouchee_identity.id
    )
    db_session.add(vouch)
    await db_session.commit()
    await db_session.refresh(vouch)

    # Select who tries to revoke based on scenario
    if revoker_scenario == "original_voucher":
        # Baseline: original voucher revokes
        auth_public, auth_private = voucher_public, voucher_private
    elif revoker_scenario == "vouchee":
        # Security check: vouchee tries to revoke
        auth_public, auth_private = vouchee_public, vouchee_private
    else:  # different_user
        # Security check: unrelated user tries to revoke
        auth_public, auth_private = other_public, other_private

    # Create revoke request
    path = f"/vouch/{vouch.id}"
    headers = create_auth_headers(auth_private, auth_public, "DELETE", path)

    # Execute
    response = client.delete(path, headers=headers)

    # Assert
    assert response.status_code == expected_status

    if expected_status == 200:
        # Baseline: verify vouch was revoked
        data = response.json()
        assert data["status"] == "revoked"
        assert data["vouch_id"] == vouch.id

        # Verify in database
        await db_session.refresh(vouch)
        assert vouch.revoked is True
        assert vouch.revoked_at is not None
    elif expected_status == 401:
        # Security: verify error message
        assert "Not authorized" in response.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("duplicate_scenario,expected_status", [
    ("first_vouch", 200),               # Baseline: first vouch succeeds
    ("duplicate_vouch", 409),           # Security: duplicate active vouch fails
])
async def test_vouch_creation_prevents_duplicates(
    duplicate_scenario: str,
    expected_status: int,
    client: TestClient,
    db_session: AsyncSession
) -> None:
    """
    Test that duplicate active vouches are prevented.

    Baseline case: First vouch between two users succeeds
    Security case: Attempting to create a duplicate active vouch fails (gets 409)

    This tests duplicate prevention logic.
    """
    # Setup: Create identities
    voucher_identity, voucher_public, voucher_private = await create_test_identity(
        db_session, {"name": "Voucher"}
    )
    vouchee_identity, vouchee_public, vouchee_private = await create_test_identity(
        db_session, {"name": "Vouchee"}
    )

    # If testing duplicate scenario, create the first vouch
    if duplicate_scenario == "duplicate_vouch":
        vouch = Vouch(
            voucher_id=voucher_identity.id,
            vouchee_id=vouchee_identity.id
        )
        db_session.add(vouch)
        await db_session.commit()

    # Attempt to create a vouch
    body = {"vouchee_public_key": vouchee_public}
    headers = create_auth_headers(voucher_private, voucher_public, "POST", "/vouch", body)

    # Execute
    response = client.post("/vouch", json=body, headers=headers)

    # Assert
    assert response.status_code == expected_status

    if expected_status == 200:
        # Baseline: verify vouch was created
        data = response.json()
        assert data["voucher_public_key"] == voucher_public
        assert data["vouchee_public_key"] == vouchee_public
    elif expected_status == 409:
        # Security: verify error message
        assert "Active vouch already exists" in response.json()["detail"]


@pytest.mark.asyncio
async def test_trust_query_is_public_no_auth_required(
    client: TestClient,
    db_session: AsyncSession
) -> None:
    """
    Test that trust information endpoint doesn't require authentication.

    This is a simplified test that validates the endpoint is public (no auth headers needed).
    Note: This test uses a simple public key format to avoid URL path encoding issues
    with base64 strings containing '/'. The URL encoding issue is a known limitation
    of using path parameters with base64-encoded keys.

    In production, the trust endpoint should use query parameters or base64url encoding
    to avoid this issue.
    """
    # For this test, we'll just verify the endpoint accepts requests without auth
    # We use a simple invalid key format to test accessibility without hitting
    # the path encoding issue
    response = client.get("/trust/invalid-key-format")

    # Should return 400 (invalid format) not 401 (unauthorized) or 422 (missing auth)
    # This proves the endpoint is public and doesn't require authentication
    assert response.status_code == 400
    assert "Invalid public key format" in response.json()["detail"]
