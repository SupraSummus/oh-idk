# oh-idk

Agent Identity/SSO Service based on Web of Trust principles.

## Overview

A decentralized identity and trust system for agents, humans, and systems.

### Core Concepts

- **Public Key Identity**: Ed25519 public keys are the primary identifiers
- **Vouching**: Entities can vouch for each other, building a web of trust
- **Transitive Trust**: Trust propagates through the network (EigenTrust-inspired)
- **No Central Authority**: All participants are equal

## Getting Started

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up database
export DATABASE_URL="postgresql://user:pass@localhost:5432/ohidk"
alembic upgrade head

# Run the server
uvicorn app.main:app --reload

# Run with type checking
mypy app/
```

## API

### Register a new identity

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"public_key": "base64-encoded-ed25519-key"}'
```

### Vouch for another identity

```bash
# Request must be signed with your private key
curl -X POST http://localhost:8000/vouch \
  -H "Content-Type: application/json" \
  -H "X-Public-Key: your-public-key-base64" \
  -H "X-Timestamp: 1234567890" \
  -H "X-Signature: signature-of-method+path+timestamp+body" \
  -d '{"vouchee_public_key": "target-public-key-base64"}'
```

### Check trust score

```bash
curl http://localhost:8000/trust/some-public-key-base64
```

### Verify a signature

```bash
curl http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "base64-key",
    "message": "message to verify",
    "signature": "base64-signature"
  }'
```

## Architecture

- **FastAPI** - Async web framework with automatic OpenAPI docs
- **SQLAlchemy 2.0** - ORM with strict typing (mypy compatible)
- **Ed25519** - Cryptographic identity (like Wireguard/IPFS)
- **PostgreSQL** - With Row Level Security (RLS)

## Security Model

- **No passwords** - Public key IS the identity
- **Signed requests** - Every authenticated request must be signed
- **Row Level Security** - Database-level access control
- **Key rotation** - New keys can be vouched by old keys
- **Vouch expiry** - Vouches can have TTL

## Trust Calculation

Trust scores are calculated using a simplified EigenTrust algorithm:
- Direct vouch = 1.0 base trust
- Transitive trust decays by 0.5 per hop
- Maximum trust capped at 10.0
- Revoked vouches are excluded

## License

MIT
