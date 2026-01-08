"""Shared utilities for SBOM generation."""

import shutil
import subprocess
import threading
from typing import Optional

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger

# Track whether Java/Maven has been installed on-demand
_java_maven_installed = False
_java_maven_lock = threading.Lock()

# Track whether Go has been installed on-demand
_go_installed = False
_go_lock = threading.Lock()

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
)

# Default command timeout in seconds
DEFAULT_TIMEOUT = 1800  # 30 minutes (large Maven projects can take a while)

# Progress indicator interval in seconds
PROGRESS_INTERVAL = 60  # Log progress every minute


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
    cwd: str | None = None,
) -> subprocess.CompletedProcess:
    """
    Run a command and handle common error cases.

    For long-running commands, logs progress every PROGRESS_INTERVAL seconds.

    Args:
        cmd: Command to run as a list
        command_name: Name of the command for error reporting
        timeout: Command timeout in seconds
        capture_output: Whether to capture stdout/stderr
        cwd: Working directory for the command (optional)

    Returns:
        CompletedProcess result

    Raises:
        SBOMGenerationError: If command fails or times out
    """
    import threading
    import time

    cwd_info = f" (cwd: {cwd})" if cwd else ""
    logger.info(f"Running command: {' '.join(cmd)}{cwd_info}")

    # Use Popen for progress tracking on long-running commands
    start_time = time.time()
    stop_progress = threading.Event()

    def log_progress():
        """Log progress periodically while command is running."""
        timeout_minutes = timeout // 60
        while not stop_progress.wait(PROGRESS_INTERVAL):
            elapsed = int(time.time() - start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            logger.info(f"{command_name} still running... ({minutes}m {seconds}s elapsed, timeout: {timeout_minutes}m)")

    # Start progress thread
    progress_thread = threading.Thread(target=log_progress, daemon=True)
    progress_thread.start()

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            check=True,
            text=True,
            shell=False,
            timeout=timeout,
            cwd=cwd,
        )
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"{command_name} command failed with error: {e}")
        log_command_error(command_name, e.stderr if e.stderr else "")
        raise SBOMGenerationError(f"{command_name} command failed with return code {e.returncode}")
    except subprocess.TimeoutExpired:
        elapsed = int(time.time() - start_time)
        logger.error(f"{command_name} command timed out after {elapsed}s (limit: {timeout}s)")
        raise SBOMGenerationError(f"{command_name} command timed out")
    except FileNotFoundError:
        logger.error(f"{command_name} command not found")
        raise SBOMGenerationError(f"{command_name} command not found - is it installed?")
    finally:
        # Stop the progress thread
        stop_progress.set()
        progress_thread.join(timeout=1)


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


def ensure_java_maven_installed() -> None:
    """
    Install Maven + JDK on-demand if not already present.

    This function is called lazily when processing Java/Scala projects
    to avoid bloating the Docker image with Java dependencies that are
    only needed for a subset of ecosystems.

    The installation state is cached to avoid repeated checks.
    Thread-safe: uses a lock to prevent concurrent installation attempts.

    Raises:
        SBOMGenerationError: If installation fails
    """
    global _java_maven_installed

    # Fast path: skip if already confirmed installed (no lock needed)
    if _java_maven_installed:
        return

    # Use lock to prevent race conditions if multiple threads try to install
    with _java_maven_lock:
        # Double-check after acquiring lock (another thread may have installed)
        if _java_maven_installed:
            return

        # Check if Maven is already available
        if shutil.which("mvn"):
            logger.debug("Maven already installed, skipping on-demand installation")
            _java_maven_installed = True
            return

        logger.info("Java/Maven not found - installing for Java dependency resolution...")

        try:
            # Update package lists
            subprocess.run(
                ["apt-get", "update"],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Install Maven and JDK
            subprocess.run(
                [
                    "apt-get",
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "maven",
                    "default-jdk-headless",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes for package installation
            )

            _java_maven_installed = True
            logger.info("Java/Maven installed successfully")

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            logger.error(f"Failed to install Java/Maven: {error_msg}")
            raise SBOMGenerationError(f"Failed to install Java/Maven for dependency resolution: {error_msg}")
        except subprocess.TimeoutExpired:
            logger.error("Java/Maven installation timed out")
            raise SBOMGenerationError("Java/Maven installation timed out")


def ensure_go_installed() -> None:
    """
    Install Go on-demand if not already present.

    This function is called lazily when processing Go projects
    to avoid bloating the Docker image with Go dependencies that are
    only needed for a subset of ecosystems.

    The installation state is cached to avoid repeated checks.
    Thread-safe: uses a lock to prevent concurrent installation attempts.

    Raises:
        SBOMGenerationError: If installation fails
    """
    global _go_installed

    # Fast path: skip if already confirmed installed (no lock needed)
    if _go_installed:
        return

    # Use lock to prevent race conditions if multiple threads try to install
    with _go_lock:
        # Double-check after acquiring lock (another thread may have installed)
        if _go_installed:
            return

        # Check if Go is already available
        if shutil.which("go"):
            logger.debug("Go already installed, skipping on-demand installation")
            _go_installed = True
            return

        logger.info("Go not found - installing for Go dependency resolution...")

        try:
            # Update package lists
            subprocess.run(
                ["apt-get", "update"],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Install Go
            subprocess.run(
                [
                    "apt-get",
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "golang",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes for package installation
            )

            _go_installed = True
            logger.info("Go installed successfully")

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            logger.error(f"Failed to install Go: {error_msg}")
            raise SBOMGenerationError(f"Failed to install Go for dependency resolution: {error_msg}")
        except subprocess.TimeoutExpired:
            logger.error("Go installation timed out")
            raise SBOMGenerationError("Go installation timed out")
