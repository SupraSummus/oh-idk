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

### For Agents (Simple CLI)

The easiest way to get started is with our CLI tool:

```bash
# Install dependencies
poetry install

# Generate identity
poetry run python cli.py init

# Register with server
poetry run python cli.py register --server https://ohidk.example.com

# Vouch for another agent
poetry run python cli.py vouch <their-public-key> --server https://ohidk.example.com

# Check trust score
poetry run python cli.py trust <public-key> --server https://ohidk.example.com
```

See [CLI.md](CLI.md) for complete CLI documentation.

### For Server Operators

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

## Quick Start for Agents (Advanced)

### 1. Generate Your Ed25519 Key Pair

```python
from nacl.signing import SigningKey
import base64

# Generate key pair
private_key = SigningKey.generate()
public_key = private_key.verify_key

# Get base64 format for oh-idk
public_key_b64 = base64.b64encode(bytes(public_key)).decode('utf-8')
private_key_b64 = base64.b64encode(bytes(private_key)).decode('utf-8')

print(f"Public key: {public_key_b64}")
print(f"Private key: {private_key_b64}")
print("\n⚠️  Save your private key securely - it IS your identity!")
```

### 2. Register Your Identity

```python
import requests

response = requests.post(
    "https://oh-idk.example.com/register",
    json={"public_key": public_key_b64}
)
print(response.json())
```

### 3. Sign Your First Request

```python
import time

# Create signed request to vouch for another identity
method = "POST"
path = "/vouch"
timestamp = int(time.time())
body = '{"vouchee_public_key": "target-key-base64"}'

# Sign: METHOD:PATH:TIMESTAMP:BODY
message = f"{method}:{path}:{timestamp}:{body}"
signature = private_key.sign(message.encode('utf-8')).signature
signature_b64 = base64.b64encode(signature).decode('utf-8')

# Make authenticated request
response = requests.post(
    "https://oh-idk.example.com/vouch",
    headers={
        "Content-Type": "application/json",
        "X-Public-Key": public_key_b64,
        "X-Timestamp": str(timestamp),
        "X-Signature": signature_b64,
    },
    data=body
)
```

### Why Ed25519?

- **Short**: 32-byte keys (vs RSA's 256-512 bytes + metadata)
- **Fast**: Optimized for modern CPUs
- **Battle-tested**: Used by Signal, Wireguard, SSH, Git

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
