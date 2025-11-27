"""
SBOM Generation Module

This module contains all SBOM generation logic, including:
- Lock file processing for various ecosystems
- Python-specific SBOM generation
- Trivy-based SBOM generation for filesystems and Docker images
- Command execution utilities for SBOM generation tools
"""

import json
import subprocess
from pathlib import Path

from .exceptions import FileProcessingError, SBOMGenerationError
from .logging_config import logger

# Lock file constants for better maintainability
COMMON_PYTHON_LOCK_FILES = [
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
]

COMMON_RUST_LOCK_FILES = ["Cargo.lock"]

COMMON_JAVASCRIPT_LOCK_FILES = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
]

COMMON_RUBY_LOCK_FILES = ["Gemfile.lock"]
COMMON_GO_LOCK_FILES = ["go.mod"]
COMMON_DART_LOCK_FILES = ["pubspec.lock"]
COMMON_CPP_LOCK_FILES = ["conan.lock"]


def log_command_error(command_name: str, stderr: str) -> None:
    """
    Logs command errors with a standardized format.

    Args:
        command_name: The name of the command that failed (e.g., 'cyclonedx-py',
            'trivy')
        stderr: The stderr output from the command
    """
    if stderr:
        logger.error(f"[{command_name}] error: {stderr.strip()}")


def process_lock_file(file_path: str) -> None:
    """
    Process a lock file and generate step_1.json SBOM.

    Args:
        file_path: Path to the lock file

    Raises:
        FileProcessingError: If lock file type is not supported
        SBOMGenerationError: If SBOM generation fails
    """
    lock_file_name = Path(file_path).name

    if lock_file_name in COMMON_PYTHON_LOCK_FILES:
        logger.info("Detected Python lockfile")
        _process_python_lock_file(file_path, lock_file_name)
    elif lock_file_name in COMMON_RUST_LOCK_FILES:
        logger.info("Detected Rust lockfile")
        run_trivy_fs(lock_file=file_path, output_file="step_1.json")
    elif lock_file_name in COMMON_JAVASCRIPT_LOCK_FILES:
        logger.info("Detected JavaScript lockfile")
        run_trivy_fs(lock_file=file_path, output_file="step_1.json")
    elif lock_file_name in COMMON_RUBY_LOCK_FILES:
        logger.info("Detected Ruby lockfile")
        run_trivy_fs(lock_file=file_path, output_file="step_1.json")
    elif lock_file_name in COMMON_GO_LOCK_FILES:
        logger.info("Detected Go lockfile")
        run_trivy_fs(lock_file=file_path, output_file="step_1.json")
    elif lock_file_name in COMMON_DART_LOCK_FILES:
        logger.info("Detected Dart lockfile")
        run_trivy_fs(lock_file=file_path, output_file="step_1.json")
    elif lock_file_name in COMMON_CPP_LOCK_FILES:
        logger.info("Detected C++ lockfile")
        run_trivy_fs(lock_file=file_path, output_file="step_1.json")
    else:
        raise FileProcessingError(f"{file_path} is not a recognized lock file type")


def _process_python_lock_file(file_path: str, lock_file_name: str) -> None:
    """
    Process Python-specific lock files.

    Args:
        file_path: Path to the lock file
        lock_file_name: Name of the lock file

    Raises:
        SBOMGenerationError: If SBOM generation fails
        FileProcessingError: If lock file type is not recognized
    """
    if lock_file_name == "requirements.txt":
        return_code = generate_sbom_from_python_lock_file(
            lock_file=file_path,
            lock_file_type="requirements",
            output_file="step_1.json",
        )
    elif lock_file_name in ["poetry.lock", "pyproject.toml"]:
        project_dir = str(Path(file_path).parent)
        logger.info(f"Using Poetry project directory: {project_dir}")
        return_code = generate_sbom_from_python_lock_file(
            lock_file=project_dir,
            lock_file_type="poetry",
            output_file="step_1.json",
        )
    elif lock_file_name == "Pipfile.lock":
        return_code = generate_sbom_from_python_lock_file(
            lock_file=file_path,
            lock_file_type="pipenv",
            output_file="step_1.json",
        )
    elif lock_file_name == "uv.lock":
        logger.info("Processing uv.lock file with Trivy")
        run_trivy_fs(lock_file=file_path, output_file="step_1.json")
        return  # Trivy doesn't return a code we need to check
    else:
        raise FileProcessingError(f"{lock_file_name} is not a recognized Python lock file")

    if return_code != 0:
        raise SBOMGenerationError(f"SBOM generation failed with return code {return_code}")


def generate_sbom_from_python_lock_file(
    lock_file: str, lock_file_type: str, output_file: str, schema_version: str = "1.6"
) -> int:
    """
    Takes a Python lockfile and generates a CycloneDX SBOM.

    Args:
        lock_file: Path to the lock file
        lock_file_type: Type of lock file (requirements, poetry, pipenv)
        output_file: Path to save the generated SBOM
        schema_version: CycloneDX schema version to use

    Returns:
        Process return code

    Raises:
        SBOMGenerationError: If SBOM generation fails
    """
    cmd = [
        "cyclonedx-py",
        lock_file_type,
        lock_file,
        "--spec-version",  # Use modern parameter instead of deprecated --schema-version
        schema_version,
        "--output-file",  # Use modern parameter instead of deprecated --outfile
        output_file,
        "--mc-type",  # Set main component type
        "application",  # Default to application type
        "--validate",  # Enable validation during generation
        "--output-reproducible",  # Ensure reproducible output
        "--output-format",
        "JSON",  # Explicitly set JSON format
    ]

    if lock_file_type == "poetry":
        cmd += ["--no-dev"]

    logger.info(f"Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            check=True,
            text=True,
            shell=False,  # Security: explicit shell=False
            timeout=300,  # Security: 5 minute timeout for SBOM generation
        )
        logger.info(f"Command completed successfully with return code {result.returncode}")
        if result.stdout:
            logger.debug(f"Command stdout: {result.stdout}")
        return result.returncode
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with return code {e.returncode}")
        logger.error(f"Command output: {e.stdout}")
        log_command_error("cyclonedx-py", e.stderr)
        raise SBOMGenerationError(f"cyclonedx-py failed with return code {e.returncode}")
    except subprocess.TimeoutExpired:
        logger.error("SBOM generation timed out")
        raise SBOMGenerationError("SBOM generation timed out after 5 minutes")


def run_command_with_json_output(cmd: list, command_name: str, output_file: str) -> int:
    """
    Generic function to run a command that outputs JSON and save it to a file.

    Args:
        cmd: Command to run as a list
        command_name: Name of the command for error reporting
        output_file: Path to save the JSON output

    Returns:
        Process return code

    Raises:
        SBOMGenerationError: If command fails or output is invalid JSON
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            check=True,
            text=True,
            shell=False,  # Security: explicit shell=False
            timeout=600,  # Security: 10 minute timeout
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"{command_name} command failed with error: {e}")
        log_command_error(command_name, e.stderr)
        raise SBOMGenerationError(f"{command_name} command failed with return code {e.returncode}")
    except subprocess.TimeoutExpired:
        logger.error(f"{command_name} command timed out")
        raise SBOMGenerationError(f"{command_name} command timed out")

    if result.returncode == 0:
        try:
            json_data = json.loads(result.stdout)
            with Path(output_file).open("w") as f:
                json.dump(json_data, f, indent=4)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON output from {command_name}: {e}")
            raise SBOMGenerationError(f"Invalid JSON output from {command_name}")
    else:
        log_command_error(command_name, result.stderr)

    return result.returncode


def run_trivy_fs(lock_file: str, output_file: str) -> int:
    """
    Takes a supported lockfile and generates a CycloneDX SBOM using Trivy.

    Args:
        lock_file: Path to the lock file
        output_file: Path to save the generated SBOM

    Returns:
        Process return code
    """
    cmd = [
        "trivy",
        "fs",
        lock_file,
        "--parallel",
        "0",
        "--format",
        "cyclonedx",
    ]

    return run_command_with_json_output(cmd, "trivy", output_file)


def run_trivy_docker_image(docker_image: str, output_file: str) -> int:
    """
    Takes a Docker image and generates a CycloneDX SBOM using Trivy.

    Args:
        docker_image: Docker image name/tag
        output_file: Path to save the generated SBOM

    Returns:
        Process return code
    """
    cmd = [
        "trivy",
        "image",
        "--parallel",
        "0",
        "--format",
        "cyclonedx",
        "--pkg-types",
        "os",
        docker_image,
    ]

    return run_command_with_json_output(cmd, "trivy", output_file)
