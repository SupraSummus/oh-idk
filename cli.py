#!/usr/bin/env python3
"""
Simple CLI tool for oh-idk agent onboarding.

Single-file implementation with minimal dependencies.
Handles Ed25519 key generation, storage, and authenticated requests.
"""
import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx
from nacl.signing import SigningKey

# Configuration
DEFAULT_CONFIG_DIR = Path.home() / ".ohidk"
DEFAULT_KEY_FILE = DEFAULT_CONFIG_DIR / "key"


def generate_keypair() -> tuple[str, str]:
    """
    Generate a new Ed25519 keypair.

    Returns:
        Tuple of (public_key_base64, private_key_base64)
    """
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    private_b64 = base64.b64encode(bytes(signing_key)).decode('utf-8')
    public_b64 = base64.b64encode(bytes(verify_key)).decode('utf-8')

    return public_b64, private_b64


def create_request_signature(
    private_key_b64: str,
    method: str,
    path: str,
    timestamp: int,
    body: str = ""
) -> str:
    """
    Create a signature for an authenticated request.

    The signed message format is: METHOD:PATH:TIMESTAMP:BODY

    Args:
        private_key_b64: Base64-encoded Ed25519 private key
        method: HTTP method (GET, POST, etc.)
        path: Request path (e.g., /vouch)
        timestamp: Unix timestamp
        body: Request body (empty string for GET)

    Returns:
        Base64-encoded signature
    """
    private_key_bytes = base64.b64decode(private_key_b64)
    signing_key = SigningKey(private_key_bytes)

    message = f"{method}:{path}:{timestamp}:{body}"
    signed = signing_key.sign(message.encode('utf-8'))
    signature = signed.signature

    return base64.b64encode(signature).decode('utf-8')


def save_keypair(public_key: str, private_key: str, key_file: Path) -> None:
    """Save keypair to file."""
    key_file.parent.mkdir(parents=True, exist_ok=True)

    # Save both keys to a JSON file
    key_data = {
        "public_key": public_key,
        "private_key": private_key
    }

    # Write with restrictive permissions (owner read/write only)
    key_file.write_text(json.dumps(key_data, indent=2))
    os.chmod(key_file, 0o600)


def load_keypair(key_file: Path) -> tuple[str, str]:
    """
    Load keypair from file.

    Returns:
        Tuple of (public_key, private_key)
    """
    if not key_file.exists():
        print(f"Error: Key file not found at {key_file}", file=sys.stderr)
        print("Run 'cli.py init' to generate a new identity.", file=sys.stderr)
        sys.exit(1)

    try:
        key_data = json.loads(key_file.read_text())
        return key_data["public_key"], key_data["private_key"]
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error: Invalid key file format: {e}", file=sys.stderr)
        sys.exit(1)


def make_authenticated_request(
    method: str,
    url: str,
    public_key: str,
    private_key: str,
    json_data: dict[str, Any] | None = None
) -> httpx.Response:
    """Make an authenticated HTTP request with signature headers."""
    timestamp = int(time.time())

    # Parse URL to get path
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path

    # Prepare body
    body = ""
    if json_data:
        body = json.dumps(json_data, separators=(',', ':'))

    # Create signature
    signature = create_request_signature(
        private_key,
        method.upper(),
        path,
        timestamp,
        body
    )

    # Make request with auth headers
    headers = {
        "X-Public-Key": public_key,
        "X-Timestamp": str(timestamp),
        "X-Signature": signature,
        "Content-Type": "application/json"
    }

    with httpx.Client() as client:
        if method.upper() == "GET":
            response = client.get(url, headers=headers)
        elif method.upper() == "POST":
            response = client.post(url, headers=headers, content=body)
        elif method.upper() == "DELETE":
            response = client.delete(url, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    return response


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize a new identity by generating keypair."""
    key_file = Path(args.key_file)

    if key_file.exists() and not args.force:
        print(f"Error: Key file already exists at {key_file}", file=sys.stderr)
        print("Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    # Generate keypair
    public_key, private_key = generate_keypair()

    # Save to file
    save_keypair(public_key, private_key, key_file)

    print("✓ Identity created!")
    print(f"  Public key: {public_key}")
    print(f"  Key saved to: {key_file}")
    print()
    print("Next steps:")
    print("  1. Register with a server: cli.py register --server https://example.com")
    print("  2. Get vouches from other agents to build trust")


def cmd_register(args: argparse.Namespace) -> None:
    """Register identity with oh-idk server."""
    key_file = Path(args.key_file)
    public_key, _ = load_keypair(key_file)

    # Prepare registration request
    url = f"{args.server.rstrip('/')}/register"
    data: dict[str, Any] = {"public_key": public_key}

    if args.metadata:
        # Parse metadata as key=value pairs
        metadata = {}
        for item in args.metadata:
            if '=' not in item:
                print(f"Error: Invalid metadata format '{item}'. Use key=value", file=sys.stderr)
                sys.exit(1)
            key, value = item.split('=', 1)
            metadata[key] = value
        data["metadata"] = metadata

    try:
        with httpx.Client() as client:
            response = client.post(url, json=data)

        if response.status_code == 200:
            result = response.json()
            print("✓ Registered successfully!")
            print(f"  Server: {args.server}")
            print(f"  Public key: {result['public_key']}")
            print(f"  Identity ID: {result['id']}")
            print(f"  Created: {result['created_at']}")
        elif response.status_code == 409:
            print("✓ Already registered!")
            print(f"  Public key: {public_key}")
            print(f"  Server: {args.server}")
        else:
            print(f"✗ Registration failed: HTTP {response.status_code}", file=sys.stderr)
            try:
                error = response.json()
                print(f"  Error: {error.get('detail', error)}", file=sys.stderr)
            except json.JSONDecodeError:
                print(f"  Response: {response.text}", file=sys.stderr)
            sys.exit(1)

    except httpx.RequestError as e:
        print(f"✗ Request failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_vouch(args: argparse.Namespace) -> None:
    """Vouch for another identity."""
    key_file = Path(args.key_file)
    public_key, private_key = load_keypair(key_file)

    vouchee_key = args.public_key

    # Prepare vouch request
    url = f"{args.server.rstrip('/')}/vouch"
    data: dict[str, Any] = {"vouchee_public_key": vouchee_key}

    if args.expires_in_days:
        data["expires_in_days"] = args.expires_in_days

    try:
        response = make_authenticated_request(
            "POST",
            url,
            public_key,
            private_key,
            json_data=data
        )

        if response.status_code == 200:
            result = response.json()
            print("✓ Vouch created!")
            print(f"  Voucher (you): {result['voucher_public_key'][:16]}...")
            print(f"  Vouchee: {result['vouchee_public_key'][:16]}...")
            print(f"  Vouch ID: {result['id']}")
            if result.get('expires_at'):
                print(f"  Expires: {result['expires_at']}")
            else:
                print("  Expires: Never")
        else:
            print(f"✗ Vouch failed: HTTP {response.status_code}", file=sys.stderr)
            try:
                error = response.json()
                print(f"  Error: {error.get('detail', error)}", file=sys.stderr)
            except json.JSONDecodeError:
                print(f"  Response: {response.text}", file=sys.stderr)
            sys.exit(1)

    except httpx.RequestError as e:
        print(f"✗ Request failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_trust(args: argparse.Namespace) -> None:
    """Check trust information for an identity."""
    target_key = args.public_key

    # Get trust information (no auth required)
    url = f"{args.server.rstrip('/')}/trust/{target_key}"

    try:
        with httpx.Client() as client:
            response = client.get(url)

        if response.status_code == 200:
            result = response.json()

            print(f"Trust information for: {result['public_key'][:16]}...")
            print(f"  Exists: {'Yes' if result['exists'] else 'No'}")
            print(f"  Trust score: {result['trust_score']:.2f}")
            print(f"  Direct vouches: {result['direct_vouches']}")

            if result['vouches']:
                print(f"\n  Vouches ({len(result['vouches'])}):")
                for vouch in result['vouches']:
                    status = "revoked" if vouch['revoked'] else "active"
                    voucher = vouch['voucher_public_key'][:16]
                    print(f"    - {voucher}... ({status})")
            else:
                print("\n  No vouches yet.")
        else:
            print(f"✗ Query failed: HTTP {response.status_code}", file=sys.stderr)
            try:
                error = response.json()
                print(f"  Error: {error.get('detail', error)}", file=sys.stderr)
            except json.JSONDecodeError:
                print(f"  Response: {response.text}", file=sys.stderr)
            sys.exit(1)

    except httpx.RequestError as e:
        print(f"✗ Request failed: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="oh-idk CLI - Simple tool for agent identity and trust",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a new identity
  cli.py init

  # Register with a server
  cli.py register --server https://ohidk.example.com

  # Vouch for another agent
  cli.py vouch <their-public-key> --server https://ohidk.example.com

  # Check trust score
  cli.py trust <public-key> --server https://ohidk.example.com
        """
    )

    parser.add_argument(
        '--key-file',
        default=str(DEFAULT_KEY_FILE),
        help=f'Path to key file (default: {DEFAULT_KEY_FILE})'
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Init command
    init_parser = subparsers.add_parser('init', help='Generate new identity')
    init_parser.add_argument(
        '--force',
        action='store_true',
        help='Overwrite existing key file'
    )

    # Register command
    register_parser = subparsers.add_parser('register', help='Register with oh-idk server')
    register_parser.add_argument(
        '--server',
        required=True,
        help='Server URL (e.g., https://ohidk.example.com)'
    )
    register_parser.add_argument(
        '--metadata',
        nargs='+',
        help='Metadata as key=value pairs (e.g., name=MyAgent version=1.0)'
    )

    # Vouch command
    vouch_parser = subparsers.add_parser('vouch', help='Vouch for another identity')
    vouch_parser.add_argument(
        'public_key',
        help='Public key of the identity to vouch for'
    )
    vouch_parser.add_argument(
        '--server',
        required=True,
        help='Server URL'
    )
    vouch_parser.add_argument(
        '--expires-in-days',
        type=int,
        help='Number of days until vouch expires (optional)'
    )

    # Trust command
    trust_parser = subparsers.add_parser('trust', help='Check trust information')
    trust_parser.add_argument(
        'public_key',
        help='Public key to check trust for'
    )
    trust_parser.add_argument(
        '--server',
        required=True,
        help='Server URL'
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    if args.command == 'init':
        cmd_init(args)
    elif args.command == 'register':
        cmd_register(args)
    elif args.command == 'vouch':
        cmd_vouch(args)
    elif args.command == 'trust':
        cmd_trust(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
