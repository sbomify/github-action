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

GO_LOCK_FILES = [
    "go.mod",
    "go.sum",
]

DART_LOCK_FILES = ["pubspec.lock"]
CPP_LOCK_FILES = ["conan.lock"]

JAVA_LOCK_FILES = [
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
]

PHP_LOCK_FILES = [
    "composer.json",
    "composer.lock",
]

DOTNET_LOCK_FILES = [
    "packages.lock.json",
]

SWIFT_LOCK_FILES = [
    "Package.swift",
    "Package.resolved",
]

ELIXIR_LOCK_FILES = ["mix.lock"]

SCALA_LOCK_FILES = ["build.sbt"]

TERRAFORM_LOCK_FILES = [".terraform.lock.hcl"]

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
    + PHP_LOCK_FILES
    + DOTNET_LOCK_FILES
    + SWIFT_LOCK_FILES
    + ELIXIR_LOCK_FILES
    + SCALA_LOCK_FILES
    + TERRAFORM_LOCK_FILES
)

# =============================================================================
# Tool-specific lock file support
# Each tool supports different ecosystems - this drives generator selection
# =============================================================================

# cyclonedx-py: Native Python generator - Python only
CYCLONEDX_PY_LOCK_FILES = PYTHON_LOCK_FILES

# cdxgen: Comprehensive multi-ecosystem support
# Excellent for Java (pom.xml, gradle), JavaScript, Python, Go, Rust, etc.
CDXGEN_LOCK_FILES = (
    PYTHON_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + JAVA_LOCK_FILES  # Best tool for Java/Gradle lock files
    + GO_LOCK_FILES
    + RUST_LOCK_FILES
    + RUBY_LOCK_FILES
    + DART_LOCK_FILES
    + CPP_LOCK_FILES
    + PHP_LOCK_FILES
    + DOTNET_LOCK_FILES
    + SWIFT_LOCK_FILES
    + ELIXIR_LOCK_FILES
    + SCALA_LOCK_FILES
)

# Trivy: Good multi-ecosystem support
# Supports most common ecosystems but may have varying quality
TRIVY_LOCK_FILES = (
    PYTHON_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + GO_LOCK_FILES
    + RUST_LOCK_FILES
    + RUBY_LOCK_FILES
    + JAVA_LOCK_FILES
    + CPP_LOCK_FILES
    + PHP_LOCK_FILES
    + DOTNET_LOCK_FILES
)

# Syft: Good multi-ecosystem support
# Note: Java support is for compiled artifacts (jar/war/ear), not pom.xml/gradle
SYFT_LOCK_FILES = (
    PYTHON_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + GO_LOCK_FILES
    + RUST_LOCK_FILES
    + RUBY_LOCK_FILES
    + DART_LOCK_FILES
    + CPP_LOCK_FILES
    + PHP_LOCK_FILES
    + DOTNET_LOCK_FILES
    + SWIFT_LOCK_FILES
    + ELIXIR_LOCK_FILES
    + TERRAFORM_LOCK_FILES
    # Note: Syft does NOT support pom.xml/gradle - only compiled Java artifacts
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
    elif lock_file_name in PHP_LOCK_FILES:
        return "php"
    elif lock_file_name in DOTNET_LOCK_FILES:
        return "dotnet"
    elif lock_file_name in SWIFT_LOCK_FILES:
        return "swift"
    elif lock_file_name in ELIXIR_LOCK_FILES:
        return "elixir"
    elif lock_file_name in SCALA_LOCK_FILES:
        return "scala"
    elif lock_file_name in TERRAFORM_LOCK_FILES:
        return "terraform"
    return None


def is_supported_lock_file(lock_file_name: str) -> bool:
    """Check if a lock file is supported."""
    return lock_file_name in ALL_LOCK_FILES
