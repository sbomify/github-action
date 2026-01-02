"""Shared utilities for SBOM generation."""

import subprocess
from typing import Optional

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger

# Lock file constants by ecosystem
PYTHON_LOCK_FILES = [
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
]

RUST_LOCK_FILES = ["Cargo.lock"]

JAVASCRIPT_LOCK_FILES = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
]

RUBY_LOCK_FILES = ["Gemfile.lock"]
GO_LOCK_FILES = ["go.mod"]
DART_LOCK_FILES = ["pubspec.lock"]
CPP_LOCK_FILES = ["conan.lock"]
JAVA_LOCK_FILES = ["pom.xml"]

# All supported lock files
ALL_LOCK_FILES = (
    PYTHON_LOCK_FILES
    + RUST_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + RUBY_LOCK_FILES
    + GO_LOCK_FILES
    + DART_LOCK_FILES
    + CPP_LOCK_FILES
    + JAVA_LOCK_FILES
)

# Default command timeout in seconds
DEFAULT_TIMEOUT = 600  # 10 minutes


def log_command_error(command_name: str, stderr: str) -> None:
    """
    Log command errors with a standardized format.

    Args:
        command_name: The name of the command that failed
        stderr: The stderr output from the command
    """
    if stderr:
        logger.error(f"[{command_name}] error: {stderr.strip()}")


def run_command(
    cmd: list[str],
    command_name: str,
    timeout: int = DEFAULT_TIMEOUT,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run a command and handle common error cases.

    Args:
        cmd: Command to run as a list
        command_name: Name of the command for error reporting
        timeout: Command timeout in seconds
        capture_output: Whether to capture stdout/stderr

    Returns:
        CompletedProcess result

    Raises:
        SBOMGenerationError: If command fails or times out
    """
    logger.info(f"Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            check=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"{command_name} command failed with error: {e}")
        log_command_error(command_name, e.stderr if e.stderr else "")
        raise SBOMGenerationError(f"{command_name} command failed with return code {e.returncode}")
    except subprocess.TimeoutExpired:
        logger.error(f"{command_name} command timed out after {timeout}s")
        raise SBOMGenerationError(f"{command_name} command timed out")
    except FileNotFoundError:
        logger.error(f"{command_name} command not found")
        raise SBOMGenerationError(f"{command_name} command not found - is it installed?")


def get_lock_file_ecosystem(lock_file_name: str) -> Optional[str]:
    """
    Get the ecosystem for a lock file.

    Args:
        lock_file_name: Name of the lock file

    Returns:
        Ecosystem name or None if not recognized
    """
    if lock_file_name in PYTHON_LOCK_FILES:
        return "python"
    elif lock_file_name in RUST_LOCK_FILES:
        return "rust"
    elif lock_file_name in JAVASCRIPT_LOCK_FILES:
        return "javascript"
    elif lock_file_name in RUBY_LOCK_FILES:
        return "ruby"
    elif lock_file_name in GO_LOCK_FILES:
        return "go"
    elif lock_file_name in DART_LOCK_FILES:
        return "dart"
    elif lock_file_name in CPP_LOCK_FILES:
        return "cpp"
    elif lock_file_name in JAVA_LOCK_FILES:
        return "java"
    return None


def is_supported_lock_file(lock_file_name: str) -> bool:
    """Check if a lock file is supported."""
    return lock_file_name in ALL_LOCK_FILES
