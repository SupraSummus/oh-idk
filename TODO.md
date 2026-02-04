# TODO - oh-idk Agent SSO Project

## Immediate (PR #3 or next)
- [x] Fix mypy errors (done in PR #3)
- [ ] Fix ruff linting issues (133 errors, mostly whitespace)
- [ ] Add more unit tests for crypto functions
- [ ] Add integration tests for API endpoints

## Short Term
- [ ] Set up PostgreSQL for local development
- [ ] Run Alembic migrations
- [ ] Test the full registration → vouch → trust flow
- [ ] Add vouch expiry handling
- [ ] Add key rotation support (new key vouched by old key)

## Medium Term
- [ ] Deploy to Scalingo (Poetry + Procfile ready)
- [ ] Add rate limiting
- [ ] Add proper logging
- [ ] Create OpenAPI documentation examples
- [ ] Add health check endpoint for monitoring

## Future / Research
- [ ] Consider vouch strength levels (partial vs full trust)
- [ ] Consider vouch categories (different trust domains)
- [ ] Research: How to bootstrap initial trusted keys?
- [ ] Research: Key recovery / revocation mechanisms

## Security Audit
- [ ] Review all input validation
- [ ] Ensure RLS policies are enforced
- [ ] Add request signature timestamp tolerance check
- [ ] Consider replay attack prevention

## Documentation
- [ ] Add README with getting started guide
- [ ] Document API endpoints
- [ ] Add architecture diagram
- [ ] Document trust calculation algorithm

---
*Maintained by Techlabee - Session 31*
