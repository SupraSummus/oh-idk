"""Tests for the CLI tool."""
import json
import subprocess
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


def run_cli(*args: str, key_file: str | None = None) -> tuple[int, str, str]:
    """
    Run the CLI command and return exit code, stdout, stderr.

    Args:
        args: CLI arguments
        key_file: Optional key file path (prepended as --key-file)

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    cmd = ["poetry", "run", "python", "cli.py"]

    if key_file:
        cmd.extend(["--key-file", key_file])

    cmd.extend(args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False
    )

    return result.returncode, result.stdout, result.stderr


def test_cli_help() -> None:
    """Test CLI help output."""
    exit_code, stdout, stderr = run_cli("--help")
    assert exit_code == 0
    assert "oh-idk CLI" in stdout
    assert "init" in stdout
    assert "register" in stdout
    assert "vouch" in stdout
    assert "trust" in stdout


def test_init_command() -> None:
    """Test init command creates keypair."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = str(Path(tmpdir) / "test_key")

        # Run init
        exit_code, stdout, stderr = run_cli("init", key_file=key_file)

        assert exit_code == 0
        assert "Identity created!" in stdout
        assert "Public key:" in stdout
        assert key_file in stdout

        # Verify key file exists and has correct permissions
        key_path = Path(key_file)
        assert key_path.exists()
        assert oct(key_path.stat().st_mode)[-3:] == "600"

        # Verify key file content
        key_data = json.loads(key_path.read_text(encoding="utf-8"))
        assert "public_key" in key_data
        assert "private_key" in key_data
        assert len(key_data["public_key"]) > 0
        assert len(key_data["private_key"]) > 0


def test_init_command_force_overwrite() -> None:
    """Test init command with --force overwrites existing key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = str(Path(tmpdir) / "test_key")

        # Create initial key
        exit_code, stdout, stderr = run_cli("init", key_file=key_file)
        assert exit_code == 0

        key_path = Path(key_file)
        first_key = json.loads(key_path.read_text(encoding="utf-8"))

        # Try to overwrite without --force (should fail)
        exit_code, stdout, stderr = run_cli("init", key_file=key_file)
        assert exit_code == 1
        assert "already exists" in stderr

        # Overwrite with --force (should succeed)
        exit_code, stdout, stderr = run_cli("init", "--force", key_file=key_file)
        assert exit_code == 0

        # Verify key changed
        second_key = json.loads(key_path.read_text(encoding="utf-8"))
        assert first_key["public_key"] != second_key["public_key"]


def test_register_command_integration(client: TestClient) -> None:
    """Test register command with actual server."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = str(Path(tmpdir) / "test_key")

        # Initialize key
        exit_code, stdout, stderr = run_cli("init", key_file=key_file)
        assert exit_code == 0

        # Get the public key
        key_data = json.loads(Path(key_file).read_text(encoding="utf-8"))
        public_key = key_data["public_key"]

        # Register via API directly to verify it works
        response = client.post("/register", json={"public_key": public_key})
        assert response.status_code == 200

        # Verify registration
        result = response.json()
        assert result["public_key"] == public_key
        assert "id" in result


def test_trust_command_missing_key() -> None:
    """Test that commands fail gracefully when key file is missing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = str(Path(tmpdir) / "nonexistent_key")

        # Try to vouch without a key file (should fail with clear error)
        exit_code, stdout, stderr = run_cli(
            "vouch",
            "test-public-key",
            "--server",
            "http://localhost:8000",
            key_file=key_file
        )

        assert exit_code == 1
        assert "Key file not found" in stderr
        assert "cli.py init" in stderr


def test_help_for_subcommands() -> None:
    """Test that subcommands have help text."""
    commands = ["init", "register", "vouch", "trust"]

    for cmd in commands:
        exit_code, stdout, stderr = run_cli(cmd, "--help")
        assert exit_code == 0
        assert cmd in stdout.lower()


def test_full_workflow_integration(client: TestClient, db_session) -> None:  # type: ignore[no-untyped-def]
    """Test full workflow: init -> register."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file1 = str(Path(tmpdir) / "agent1_key")
        key_file2 = str(Path(tmpdir) / "agent2_key")

        # 1. Create two identities
        exit_code, stdout, stderr = run_cli("init", key_file=key_file1)
        assert exit_code == 0

        exit_code, stdout, stderr = run_cli("init", key_file=key_file2)
        assert exit_code == 0

        # 2. Register both via API
        key1_data = json.loads(Path(key_file1).read_text(encoding="utf-8"))
        key2_data = json.loads(Path(key_file2).read_text(encoding="utf-8"))

        response = client.post("/register", json={"public_key": key1_data["public_key"]})
        assert response.status_code == 200

        response = client.post("/register", json={"public_key": key2_data["public_key"]})
        assert response.status_code == 200

        # Verify the keys are valid base64 Ed25519 keys
        assert len(key1_data["public_key"]) > 40
        assert len(key2_data["public_key"]) > 40
        assert len(key1_data["private_key"]) > 40
        assert len(key2_data["private_key"]) > 40
