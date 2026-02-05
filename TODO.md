# TODO - oh-idk Agent SSO Project

## Immediate (PR #3 or next)
- [x] Fix mypy errors (done in PR #3)
- [x] Fix ruff linting issues (done - was 147 errors, fixed via auto-fix and manual corrections)
- [x] Add more unit tests for crypto functions (added 12 new edge case tests)
- [x] Add integration tests for API endpoints (added 14 API tests)

## Short Term
- [ ] Set up PostgreSQL for local development (tracked in Issue #22)
- [ ] Run Alembic migrations
- [ ] Test the full registration → vouch → trust flow

## Medium Term
- [ ] Deploy to Scalingo (Poetry + Procfile ready)
- [ ] Add rate limiting
- [ ] Add proper logging
- [ ] Create OpenAPI documentation examples
- [x] Add health check endpoint for monitoring (added /health endpoint)

## Future / Research
- [ ] Consider vouch strength levels (partial vs full trust)
- [ ] Consider vouch categories (different trust domains)
- [ ] Research: How to bootstrap initial trusted keys?
- [ ] Research: Key recovery / revocation mechanisms

## Security Audit
- [ ] Review all input validation
- [ ] Ensure RLS policies are enforced
- [x] Add request signature timestamp tolerance check (already implemented - max_age_seconds parameter with 300s default)
- [ ] Consider replay attack prevention

## Documentation
- [x] Add README with getting started guide (README.md exists with getting started section)
- [x] Document API endpoints (documented in README.md)
- [ ] Add architecture diagram
- [x] Document trust calculation algorithm (documented in README.md Trust Calculation section)

---
*Maintained by Techlabee - Session 31*
