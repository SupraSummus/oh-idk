#!/bin/bash
# Example script demonstrating oh-idk CLI usage
#
# This script shows a complete workflow:
# 1. Generate two agent identities
# 2. Register both with the server
# 3. Agent 1 vouches for Agent 2
# 4. Check Agent 2's trust score

set -e  # Exit on error

# Configuration
SERVER_URL="${OHIDK_SERVER:-http://localhost:8000}"
TEMP_DIR=$(mktemp -d)
AGENT1_KEY="$TEMP_DIR/agent1_key"
AGENT2_KEY="$TEMP_DIR/agent2_key"

echo "=== oh-idk CLI Example Workflow ==="
echo "Server: $SERVER_URL"
echo "Temp dir: $TEMP_DIR"
echo ""

# Clean up on exit
trap "rm -rf $TEMP_DIR" EXIT

# Step 1: Generate identities
echo "Step 1: Generating identities..."
poetry run python cli.py --key-file "$AGENT1_KEY" init
echo ""
poetry run python cli.py --key-file "$AGENT2_KEY" init
echo ""

# Extract public keys for later use
AGENT1_PUBKEY=$(jq -r '.public_key' "$AGENT1_KEY")
AGENT2_PUBKEY=$(jq -r '.public_key' "$AGENT2_KEY")

echo "Agent 1 public key: $AGENT1_PUBKEY"
echo "Agent 2 public key: $AGENT2_PUBKEY"
echo ""

# Step 2: Register both agents
echo "Step 2: Registering agents with server..."
poetry run python cli.py --key-file "$AGENT1_KEY" register \
  --server "$SERVER_URL" \
  --metadata name=Agent1 \
  --metadata role=example
echo ""

poetry run python cli.py --key-file "$AGENT2_KEY" register \
  --server "$SERVER_URL" \
  --metadata name=Agent2 \
  --metadata role=example
echo ""

# Step 3: Check initial trust (should be 0)
echo "Step 3: Checking Agent 2's initial trust score..."
poetry run python cli.py trust "$AGENT2_PUBKEY" --server "$SERVER_URL"
echo ""

# Step 4: Agent 1 vouches for Agent 2
echo "Step 4: Agent 1 vouches for Agent 2..."
poetry run python cli.py --key-file "$AGENT1_KEY" vouch "$AGENT2_PUBKEY" \
  --server "$SERVER_URL"
echo ""

# Step 5: Check trust again (should be 1.0 from direct vouch)
echo "Step 5: Checking Agent 2's trust score after vouch..."
poetry run python cli.py trust "$AGENT2_PUBKEY" --server "$SERVER_URL"
echo ""

echo "=== Workflow Complete ==="
echo "Key files saved to: $TEMP_DIR"
echo "To clean up manually: rm -rf $TEMP_DIR"
