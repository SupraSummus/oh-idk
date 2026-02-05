# oh-idk CLI Tool

Simple command-line interface for agent onboarding and identity management.

## Features

- **Single file**: No complex installation, just `cli.py`
- **Minimal dependencies**: Uses existing project dependencies (`pynacl`, `httpx`)
- **Secure key storage**: Keys stored locally with 600 permissions
- **Human-readable output**: Clear success/error messages

## Installation

The CLI requires Python 3.11+ and the project dependencies:

```bash
# Install dependencies
poetry install

# Run the CLI
poetry run python cli.py --help
```

## Usage

### 1. Generate Identity (init)

Create a new Ed25519 keypair and save it locally:

```bash
poetry run python cli.py init
```

Output:
```
✓ Identity created!
  Public key: ggb1wrR5bM6BxCCOXYp6SE0EkClq7ULkKLt+Lf3ZYOk=
  Key saved to: /home/user/.ohidk/key

Next steps:
  1. Register with a server: cli.py register --server https://example.com
  2. Get vouches from other agents to build trust
```

**Options:**
- `--key-file PATH`: Specify custom key file location (default: `~/.ohidk/key`)
- `--force`: Overwrite existing key file

**Examples:**
```bash
# Custom key location
poetry run python cli.py --key-file /tmp/my-agent-key init

# Overwrite existing key
poetry run python cli.py init --force
```

### 2. Register with Server (register)

Register your public key with an oh-idk server:

```bash
poetry run python cli.py register --server https://ohidk.example.com
```

Output:
```
✓ Registered successfully!
  Server: https://ohidk.example.com
  Public key: ggb1wrR5bM6BxCCOXYp6SE0EkClq7ULkKLt+Lf3ZYOk=
  Identity ID: 550e8400-e29b-41d4-a716-446655440000
  Created: 2026-02-05T08:30:00Z
```

**Options:**
- `--server URL`: Server URL (required)
- `--metadata KEY=VALUE`: Optional metadata (can be used multiple times)

**Examples:**
```bash
# Register with metadata
poetry run python cli.py register \
  --server https://ohidk.example.com \
  --metadata name=MyAgent \
  --metadata version=1.0.0
```

### 3. Vouch for Another Agent (vouch)

Create a trust vouch for another agent:

```bash
poetry run python cli.py vouch <their-public-key> --server https://ohidk.example.com
```

Output:
```
✓ Vouch created!
  Voucher (you): ggb1wrR5bM6BxC...
  Vouchee: abc123xyz456...
  Vouch ID: 660e8400-e29b-41d4-a716-446655440111
  Expires: Never
```

**Options:**
- `--server URL`: Server URL (required)
- `--expires-in-days N`: Number of days until vouch expires (optional)

**Examples:**
```bash
# Vouch with expiry
poetry run python cli.py vouch abc123xyz456PublicKey \
  --server https://ohidk.example.com \
  --expires-in-days 365
```

### 4. Check Trust Score (trust)

Query trust information for any agent:

```bash
poetry run python cli.py trust <public-key> --server https://ohidk.example.com
```

Output:
```
Trust information for: abc123xyz456...
  Exists: Yes
  Trust score: 3.50
  Direct vouches: 2

  Vouches (2):
    - ggb1wrR5bM6BxC... (active)
    - def789ghi012... (active)
```

**Options:**
- `--server URL`: Server URL (required)

## Key Management

### Key File Format

Keys are stored as JSON:

```json
{
  "public_key": "ggb1wrR5bM6BxCCOXYp6SE0EkClq7ULkKLt+Lf3ZYOk=",
  "private_key": "4Sqakojr20zFMz9MZcc/KIJOAuKJYj2SOhu6dEZF8ow="
}
```

### Key Security

- Files are created with **600 permissions** (owner read/write only)
- Never share your private key
- The private key **IS** your identity - if lost, you cannot recover it
- If compromised, generate a new key and have trusted agents vouch for it

### Custom Key Location

All commands support `--key-file`:

```bash
# Use custom key file
poetry run python cli.py --key-file /secure/location/key register --server https://...
```

## Complete Workflow Example

```bash
# 1. Generate identity
poetry run python cli.py init

# 2. Register with server
poetry run python cli.py register --server https://ohidk.example.com

# 3. Vouch for another agent
poetry run python cli.py vouch abc123PublicKey --server https://ohidk.example.com

# 4. Check someone's trust score
poetry run python cli.py trust abc123PublicKey --server https://ohidk.example.com
```

## Error Handling

The CLI provides clear error messages:

- **Missing key file**: Suggests running `init`
- **Invalid key format**: Validation error with details
- **Network errors**: Connection error with details
- **API errors**: HTTP status and error message from server

Example error:
```
✗ Request failed: Connection timeout
  Could not connect to https://ohidk.example.com
```

## Integration with Scripts

The CLI returns standard exit codes:
- **0**: Success
- **1**: Error

Example bash script:
```bash
#!/bin/bash
if poetry run python cli.py trust "$PUBLIC_KEY" --server "$SERVER" > /dev/null 2>&1; then
    echo "Agent is registered"
else
    echo "Agent not found"
fi
```

## Authentication

Authenticated commands (vouch) automatically:
1. Load your private key from the key file
2. Generate a timestamp
3. Create a signature of `METHOD:PATH:TIMESTAMP:BODY`
4. Send request with headers:
   - `X-Public-Key`: Your public key
   - `X-Timestamp`: Current Unix timestamp
   - `X-Signature`: Ed25519 signature

## Troubleshooting

### "Key file not found"
Run `init` first: `poetry run python cli.py init`

### "Registration failed: HTTP 409"
Your key is already registered (this is usually fine)

### "Invalid Ed25519 public key"
Check that the public key is valid base64-encoded Ed25519 key (44 characters)

### "Request failed: Connection error"
- Check server URL is correct
- Ensure server is running and accessible
- Check network connectivity

## Development

The CLI is a single file (`cli.py`) with:
- Type hints (mypy strict mode)
- Linting (ruff)
- Tests (`tests/test_cli.py`)

Run tests:
```bash
poetry run pytest tests/test_cli.py -v
```

Run type checking:
```bash
poetry run mypy cli.py
```

Run linting:
```bash
poetry run ruff check cli.py
```

## Comparison to Direct API Usage

### Before (Direct API):
```python
import time
import base64
import requests
from nacl.signing import SigningKey

# Generate key
private_key = SigningKey.generate()
public_key = private_key.verify_key
public_key_b64 = base64.b64encode(bytes(public_key)).decode('utf-8')

# Register
response = requests.post(
    "https://ohidk.example.com/register",
    json={"public_key": public_key_b64}
)

# Vouch (requires manual signing)
method = "POST"
path = "/vouch"
timestamp = int(time.time())
body = '{"vouchee_public_key": "target-key"}'
message = f"{method}:{path}:{timestamp}:{body}"
signature = private_key.sign(message.encode('utf-8')).signature
signature_b64 = base64.b64encode(signature).decode('utf-8')

response = requests.post(
    "https://ohidk.example.com/vouch",
    headers={
        "X-Public-Key": public_key_b64,
        "X-Timestamp": str(timestamp),
        "X-Signature": signature_b64,
    },
    data=body
)
```

### After (CLI):
```bash
poetry run python cli.py init
poetry run python cli.py register --server https://ohidk.example.com
poetry run python cli.py vouch target-key --server https://ohidk.example.com
```

## License

MIT (same as oh-idk project)
