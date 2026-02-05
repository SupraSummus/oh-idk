# Security Testing Pattern

This document explains the security-oriented testing pattern used in oh-idk's test suite.

## The Problem with Traditional Security Tests

Traditional security tests often test only what users **CAN'T** do:

```python
def test_user_cant_delete_other_profile():
    user_a = create_user()
    user_b = create_user()
    
    response = client.delete(f"/users/{user_b.id}", auth=user_a)
    assert response.status_code == 403  # Forbidden
```

**Problem:** This test can give false positives:
- If `create_user()` silently fails, you also get 403 → test passes
- If the endpoint doesn't exist, you get 403/404 → test passes
- If authentication is broken, you get 403 → test passes
- **The test doesn't actually verify the permission logic**

## The Solution: Baseline Pattern

Use pytest's `@pytest.mark.parametrize` with **both positive and negative cases**:

```python
@pytest.mark.parametrize("scenario,expected_status", [
    ("own_profile", 200),      # BASELINE - verify setup works
    ("other_profile", 403),    # SECURITY - verify restriction
])
def test_profile_deletion_authorization(scenario, expected_status):
    user_a = create_user()
    user_b = create_user()
    
    target_user = user_a if scenario == "own_profile" else user_b
    
    response = client.delete(f"/users/{target_user.id}", auth=user_a)
    assert response.status_code == expected_status
```

### Why This Works

The baseline case (200) **proves**:
- ✅ User creation worked
- ✅ Authentication works  
- ✅ Endpoint exists and functions
- ✅ The positive case is tested

Only **then** the 403 case is meaningful:
- 🔒 It's specifically because of authorization
- 🔒 Not due to broken test infrastructure

## Pattern Structure

### 1. Use `@pytest.mark.parametrize`

```python
@pytest.mark.parametrize("scenario,expected_status", [
    ("baseline_case", 200),     # Positive case
    ("security_case", 401),     # Negative case(s)
])
```

### 2. Setup Once

```python
def test_something(scenario, expected_status):
    # Create all test data once
    owner = create_user()
    other = create_user()
    resource = create_resource(owner)
```

### 3. Vary the Action

```python
    # Change what's tested based on scenario
    if scenario == "baseline_case":
        actor = owner
    else:  # security_case
        actor = other
    
    response = client.delete(f"/resource/{resource.id}", auth=actor)
```

### 4. Assert

```python
    assert response.status_code == expected_status
    
    # Optional: verify specific behavior for each case
    if expected_status == 200:
        assert response.json()["status"] == "deleted"
    elif expected_status == 401:
        assert "Not authorized" in response.json()["detail"]
```

## Real Examples

### Example 1: Vouch Revocation Authorization

```python
@pytest.mark.parametrize("revoker,expected_status", [
    ("original_voucher", 200),    # Baseline: voucher can revoke
    ("different_user", 401),      # Security: others cannot
    ("vouchee", 401),             # Security: vouchee cannot
])
async def test_vouch_revocation_authorization(revoker, expected_status, client, db):
    # Setup
    voucher = await create_identity(db)
    vouchee = await create_identity(db)
    other = await create_identity(db)
    vouch = await create_vouch(db, voucher, vouchee)
    
    # Select actor
    actors = {
        "original_voucher": voucher,
        "different_user": other,
        "vouchee": vouchee,
    }
    actor = actors[revoker]
    
    # Act
    headers = create_auth_headers(actor.private_key, actor.public_key, "DELETE", f"/vouch/{vouch.id}")
    response = client.delete(f"/vouch/{vouch.id}", headers=headers)
    
    # Assert
    assert response.status_code == expected_status
```

### Example 2: Self-Vouching Prevention

```python
@pytest.mark.parametrize("vouch_target,expected_status", [
    ("different_user", 200),    # Baseline: can vouch for others
    ("self", 400),              # Security: cannot self-vouch
])
async def test_vouch_creation_prevents_self_vouching(vouch_target, expected_status, client, db):
    # Setup
    user = await create_identity(db)
    other = await create_identity(db)
    
    # Select target
    target = user if vouch_target == "self" else other
    
    # Act
    body = {"vouchee_public_key": target.public_key}
    headers = create_auth_headers(user.private_key, user.public_key, "POST", "/vouch", body)
    response = client.post("/vouch", json=body, headers=headers)
    
    # Assert
    assert response.status_code == expected_status
```

## Benefits

### 1. No False Positives
If the baseline case fails, you immediately know the test setup is broken, not the security.

### 2. Self-Documenting
The parameter names clearly show:
- What's being tested
- What should happen in each case
- The expected outcomes

### 3. Efficient
One test function covers multiple related security scenarios without duplication.

### 4. Better Debugging
When a test fails, you can see **which specific scenario** failed:
```
FAILED test_security.py::test_vouch_revocation[different_user-401]
```

This immediately tells you: "The 'different_user' scenario that should return 401 failed"

### 5. Easier to Extend
Adding new security cases is just adding a new parameter:

```python
@pytest.mark.parametrize("scenario,expected", [
    ("baseline", 200),
    ("security_case_1", 401),
    ("security_case_2", 403),  # Just add this line!
])
```

## When to Use This Pattern

✅ **Use for:**
- Authorization checks (who can do what)
- Access control tests (can user A access resource B)
- Permission boundaries (own vs. others)
- Rate limiting tests (below limit vs. exceeded)

❌ **Don't use for:**
- Pure input validation (just test valid/invalid inputs)
- Cryptographic tests (deterministic, no setup needed)
- Simple utility functions

## Pattern Checklist

When writing a security test:

- [ ] Does it test authorization or access control?
- [ ] Could it give a false positive if setup breaks?
- [ ] Are there related positive and negative cases?

If yes to all three → **Use the baseline pattern!**

## Test Organization

### File Structure
```
tests/
├── conftest.py                      # Fixtures and helpers
├── test_security_baseline.py        # Security tests using baseline pattern
├── test_api.py                      # General API tests
└── test_crypto.py                   # Cryptographic unit tests
```

### Naming Convention
- Test files: `test_security_*.py` for security-focused tests
- Test functions: `test_<feature>_<what_is_tested>`
- Scenarios: Use descriptive names like `"original_voucher"`, not `"case_1"`

## Helper Functions (in conftest.py)

### `create_auth_headers()`
Creates properly signed authentication headers:

```python
headers = create_auth_headers(
    private_key=user.private_key,
    public_key=user.public_key,
    method="POST",
    path="/vouch",
    body={"vouchee_public_key": "..."}
)
response = client.post("/vouch", json=body, headers=headers)
```

### `create_test_identity()`
Creates a test identity with keypair:

```python
identity, public_key, private_key = await create_test_identity(
    db_session,
    metadata={"name": "Test User"}
)
```

### Database Fixtures
- `db_session`: Fresh database session for each test
- `client`: TestClient with database override
- `test_identity`, `another_identity`: Pre-created test identities

## Further Reading

- [pytest parametrize documentation](https://docs.pytest.org/en/latest/how-to/parametrize.html)
- [FastAPI testing guide](https://fastapi.tiangolo.com/tutorial/testing/)
- [Security testing best practices](https://owasp.org/www-project-web-security-testing-guide/)

## Questions?

If you're unsure whether to use this pattern, ask yourself:

> "If my test setup is completely broken, would this test still pass?"

If the answer is yes → **Use the baseline pattern!**
