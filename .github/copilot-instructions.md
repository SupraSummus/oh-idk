# Copilot Instructions for oh-idk

## Project Overview
This is **Agent Identity/SSO Service** based on Web of Trust principles.

## Tech Stack
- Python 3.11
- FastAPI (async web framework)
- SQLAlchemy (async ORM)
- PostgreSQL (database)
- Ed25519 (cryptographic signatures via PyNaCl)
- Poetry (dependency management)
- mypy (strict type checking)
- ruff (linting)
- pytest (testing)

## Code Style
- **Type hints are required** on all functions
- **mypy strict mode** - all code must pass `poetry run mypy app/`
- **ruff linting** - all code must pass `poetry run ruff check .`
- Follow existing code patterns in `app/` directory

## Important Patterns

### Signature-based Authentication
Requests are authenticated via Ed25519 signatures:
- `X-Public-Key`: User's public key
- `X-Timestamp`: Unix timestamp
- `X-Signature`: Signature of `METHOD:PATH:TIMESTAMP:BODY`

### Database Models
- `Identity`: Users identified by Ed25519 public key
- `Vouch`: Trust relationships between identities

### Trust Calculation
EigenTrust-inspired algorithm with decay factor (0.5 per hop).

## Running Commands
```bash
# Install dependencies
poetry install

# Run type checking
poetry run mypy app/

# Run linting
poetry run ruff check .

# Fix lint issues
poetry run ruff check . --fix

# Run tests
poetry run pytest

# Run server locally
poetry run uvicorn app.main:app --reload
```

## Security Considerations
- Never store plaintext secrets
- Always use Row Level Security in migrations
- Validate all public keys before use
