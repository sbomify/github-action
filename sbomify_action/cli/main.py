import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import sentry_sdk

# Add cyclonedx imports for proper SBOM handling
from cyclonedx.model.bom import Bom

from ..augmentation import augment_sbom_from_file
from ..exceptions import (
    APIError,
    CommandExecutionError,
    ConfigurationError,
    FileProcessingError,
    SBOMGenerationError,
    SBOMValidationError,
)
from ..logging_config import logger
from ..serialization import serialize_cyclonedx_bom


# Import version for tool metadata with multiple fallback mechanisms
def _get_package_version() -> str:
    """Get the package version using multiple fallback methods."""
    # Method 1: Try importlib.metadata (preferred for installed packages)
    try:
        from importlib.metadata import version

        return version("sbomify-github-action")
    except ImportError:
        pass
    except Exception:
        pass

    # Method 2: Try reading from pyproject.toml directly
    try:
        import tomllib

        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                pyproject_data = tomllib.load(f)
            return pyproject_data.get("tool", {}).get("poetry", {}).get("version", "unknown")
    except ImportError:
        # Python < 3.11 doesn't have tomllib
        pass
    except Exception:
        pass

    # Method 3: Try toml library as fallback for older Python
    try:
        import toml

        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "r") as f:
                pyproject_data = toml.load(f)
            return pyproject_data.get("tool", {}).get("poetry", {}).get("version", "unknown")
    except ImportError:
        pass
    except Exception:
        pass

    # Method 4: Try package __version__ attribute
    try:
        from sbomify_action import __version__

        return __version__
    except (ImportError, AttributeError):
        pass

    # Final fallback
    return "unknown"


SBOMIFY_VERSION = _get_package_version()

# Constants for magic strings/numbers
SPDX_LOGICAL_OPERATORS = [" OR ", " AND ", " WITH "]
SBOMIFY_PRODUCTION_API = "https://app.sbomify.com"
SBOMIFY_TOOL_NAME = "sbomify-github-action"
SBOMIFY_VENDOR_NAME = "sbomify"
LOCALHOST_PATTERNS = ["127.0.0.1", "localhost", "0.0.0.0"]


def _get_current_utc_timestamp() -> str:
    """
    Generate current UTC timestamp in ISO-8601 format.

    Returns:
        Current UTC timestamp as ISO-8601 string (e.g., "2024-12-19T14:30:00Z")
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


"""

There are three steps in our SBOM generation.

# Step 1: Generation / Validation
In this step we either generate an SBOM from a lockfile
or we validate a provided SBOM.

The output of this phase is `step_1.json`.

# Step 2: Augmentation
This step augments the provided SBOM with data about
you as the software provider from sbomify's backend.
This includes merging in information about licensing,
supplier and vendor. This data is required for NTIA
Minimum Elements compliance.

The output of this `step_2.json`.


# Step 3: Enrichment
SBOMs will vary a lot in quality of the components.
As we aspire to reach NTIA Minimum Elements compliants
we will enrich components using the ecosyste.ms API to ensure that
as many of our components in the SBOM as possible have
the required data.

The output of this step is `step_3.json`.

Since both step 2 and 3 are optional, we will only
write `OUTPUT_FILE` at the end of the run.

# Configuration
The tool can be configured via environment variables:
- API_BASE_URL: Override the sbomify API base URL (default: https://app.sbomify.com)
  Useful for testing against development instances (e.g., http://127.0.0.1:8000)

"""

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


# Configuration dataclass for better organization
@dataclass
class Config:
    """Configuration settings for the SBOM action."""

    token: str
    component_id: str
    sbom_file: Optional[str] = None
    docker_image: Optional[str] = None
    lock_file: Optional[str] = None
    output_file: str = "sbom_output.json"
    upload: bool = True
    augment: bool = False
    enrich: bool = False
    override_sbom_metadata: bool = False
    override_name: bool = False
    component_version: Optional[str] = None
    component_name: Optional[str] = None
    product_releases: Optional[str | list[str]] = None
    api_base_url: str = SBOMIFY_PRODUCTION_API

    def validate(self) -> None:
        """
        Validate configuration settings.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        if not self.token:
            raise ConfigurationError("sbomify API token is not defined")
        if not self.component_id:
            raise ConfigurationError("Component ID is not defined")

        inputs = [self.sbom_file, self.lock_file, self.docker_image]
        if sum(bool(x) for x in inputs) > 1:
            raise ConfigurationError("Please provide only one of: SBOM_FILE, LOCK_FILE, or DOCKER_IMAGE")
        if not any(inputs):
            raise ConfigurationError("Please provide one of: SBOM_FILE, LOCK_FILE, or DOCKER_IMAGE")

        # Validate product releases format
        if self.product_releases:
            try:
                # Parse JSON list format like ["product_id:v1.2.3"]
                product_releases_list = json.loads(self.product_releases)
                if not isinstance(product_releases_list, list):
                    raise ConfigurationError('PRODUCT_RELEASE must be a JSON list like ["product_id:v1.2.3"]')

                for release in product_releases_list:
                    if not isinstance(release, str) or ":" not in release:
                        raise ConfigurationError(
                            f"Invalid PRODUCT_RELEASE format: '{release}'. Expected format: 'product_id:version'"
                        )

                    product_id, version = release.split(":", 1)
                    # Validate that product_id looks like a proper ID (not empty)
                    if not product_id.strip():
                        raise ConfigurationError(
                            f"Invalid product_id in PRODUCT_RELEASE: '{release}'. Product ID cannot be empty."
                        )
                    if not version.strip():
                        raise ConfigurationError(
                            f"Invalid version in PRODUCT_RELEASE: '{release}'. Version cannot be empty."
                        )

                # Store the parsed list back for later use
                self.product_releases = product_releases_list
                logger.info(f"Validated product releases: {self.product_releases}")

            except json.JSONDecodeError as e:
                raise ConfigurationError(f"Invalid JSON format for PRODUCT_RELEASE: {e}")
            except Exception as e:
                if "ConfigurationError" in str(type(e)):
                    raise  # Re-raise ConfigurationError as-is
                raise ConfigurationError(f"Error parsing PRODUCT_RELEASE: {e}")

        # Validate API base URL format with proper parsing
        self._validate_api_url()

    def _validate_api_url(self) -> None:
        """
        Validate and normalize the API base URL.

        Raises:
            ConfigurationError: If URL format is invalid
        """
        from urllib.parse import urlparse

        try:
            parsed = urlparse(self.api_base_url)
        except Exception as e:
            raise ConfigurationError(f"Invalid API base URL format: {e}")

        # Validate scheme
        if not parsed.scheme or parsed.scheme not in ("http", "https"):
            raise ConfigurationError("API base URL must start with http:// or https://")

        # Validate hostname
        if not parsed.netloc:
            raise ConfigurationError("API base URL must include a valid hostname")

        # Security warning for HTTP on non-localhost
        if parsed.scheme == "http" and not any(localhost in parsed.netloc for localhost in LOCALHOST_PATTERNS):
            logger.warning("Using HTTP (not HTTPS) for API communication - consider using HTTPS in production")

        # Remove trailing slash if present for consistency
        if self.api_base_url.endswith("/"):
            self.api_base_url = self.api_base_url.rstrip("/")


def load_config() -> Config:
    """
    Load and validate configuration from environment variables.

    Returns:
        Validated configuration object

    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Handle component version with deprecation support
    component_version = os.getenv("COMPONENT_VERSION")
    sbom_version = os.getenv("SBOM_VERSION")  # Deprecated

    # Determine which version to use and show appropriate warnings
    final_component_version = None
    if component_version and sbom_version:
        logger.warning(
            "Both COMPONENT_VERSION and SBOM_VERSION are set. Using COMPONENT_VERSION and ignoring SBOM_VERSION."
        )
        logger.warning("SBOM_VERSION is deprecated. Please use COMPONENT_VERSION instead.")
        final_component_version = component_version
    elif sbom_version:
        logger.warning("SBOM_VERSION is deprecated. Please use COMPONENT_VERSION instead.")
        final_component_version = sbom_version
    elif component_version:
        final_component_version = component_version

    # Log the determined component version for user visibility
    if final_component_version:
        logger.info(f"Using component version: {final_component_version}")
    else:
        logger.info("No component version specified (COMPONENT_VERSION not set)")

    # Handle component name with deprecation support
    component_name = os.getenv("COMPONENT_NAME")
    override_name = evaluate_boolean(os.getenv("OVERRIDE_NAME", "False"))  # Deprecated

    # Determine which name approach to use and show appropriate warnings
    final_component_name = None
    final_override_name = False
    if component_name and override_name:
        logger.warning(
            "Both COMPONENT_NAME and OVERRIDE_NAME are set. Using COMPONENT_NAME and ignoring OVERRIDE_NAME."
        )
        logger.warning("OVERRIDE_NAME is deprecated. Please use COMPONENT_NAME instead.")
        final_component_name = component_name
        final_override_name = False
    elif override_name:
        logger.warning("OVERRIDE_NAME is deprecated. Please use COMPONENT_NAME instead.")
        final_component_name = None
        final_override_name = True
    elif component_name:
        final_component_name = component_name
        final_override_name = False

    # Log the determined component name for user visibility
    if final_component_name:
        logger.info(f"Using component name: {final_component_name}")
    elif final_override_name:
        logger.info("Using OVERRIDE_NAME mode (deprecated) - will use name from backend metadata")
    else:
        logger.info("No component name specified")

    # Handle product releases
    product_releases = None
    product_release_env = os.getenv("PRODUCT_RELEASE")
    if product_release_env:
        logger.info(f"Raw product release input: {product_release_env}")
        # Store the raw value for validation later in Config.validate()
        product_releases = product_release_env

    config = Config(
        token=os.getenv("TOKEN", ""),
        component_id=os.getenv("COMPONENT_ID", ""),
        sbom_file=path_expansion(os.getenv("SBOM_FILE")) if os.getenv("SBOM_FILE") else None,
        docker_image=os.getenv("DOCKER_IMAGE"),
        lock_file=path_expansion(os.getenv("LOCK_FILE")) if os.getenv("LOCK_FILE") else None,
        output_file=os.getenv("OUTPUT_FILE", "sbom_output.json"),
        upload=evaluate_boolean(os.getenv("UPLOAD", "True")),
        augment=evaluate_boolean(os.getenv("AUGMENT", "False")),
        enrich=evaluate_boolean(os.getenv("ENRICH", "False")),
        override_sbom_metadata=evaluate_boolean(os.getenv("OVERRIDE_SBOM_METADATA", "False")),
        override_name=final_override_name,
        component_version=final_component_version,
        component_name=final_component_name,
        product_releases=product_releases,
        api_base_url=os.getenv("API_BASE_URL", SBOMIFY_PRODUCTION_API),
    )

    try:
        config.validate()
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    return config


def setup_dependencies() -> None:
    """
    Check and install required dependencies.

    Raises:
        SBOMGenerationError: If dependency setup fails
    """
    try:
        result = subprocess.run(
            ["cyclonedx-py", "--version"],
            capture_output=True,
            check=True,
            text=True,
            shell=False,  # Security: explicit shell=False
            timeout=30,  # Security: add timeout
        )
        logger.info(f"cyclonedx-py version: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"cyclonedx-py command failed: {e}")
        logger.error(f"Command output: {e.stdout if hasattr(e, 'stdout') else 'No output'}")
        log_command_error("cyclonedx-py", e.stderr if hasattr(e, "stderr") else "No error")
    except FileNotFoundError:
        logger.error("cyclonedx-py command not found. Make sure it's installed.")
        try:
            logger.info("Attempting to install cyclonedx-py...")
            result = subprocess.run(
                ["pip", "install", "cyclonedx-bom"],
                check=True,
                capture_output=True,
                shell=False,  # Security: explicit shell=False
                timeout=120,  # Security: add timeout for installation
            )
            logger.info("cyclonedx-py installed successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install cyclonedx-py: {e}")
            log_command_error("pip", e.stderr if hasattr(e, "stderr") else "No error")
            raise SBOMGenerationError("Failed to install required cyclonedx-py dependency")
    except subprocess.TimeoutExpired:
        logger.error("cyclonedx-py version check timed out")
        raise SBOMGenerationError("Dependency check timed out")


def initialize_sentry() -> None:
    """Initialize Sentry for error tracking."""
    # TODO: Make DSN configurable via environment variable
    sentry_dsn = os.getenv("SENTRY_DSN", "https://84e8d6d0a7d0872a4bba8add571a554c@sentry.vikpire.com/4")

    def before_send(event, hint):
        """
        Filter events before sending to Sentry.
        Don't send user input validation errors - these are expected user errors.
        """
        if "exc_info" in hint:
            exc_type, exc_value, tb = hint["exc_info"]
            # Don't send validation or configuration errors - these are user errors
            # SBOMGenerationError and APIError should still be sent (tool/system bugs)
            if isinstance(exc_value, (SBOMValidationError, ConfigurationError)):
                return None
        return event

    sentry_sdk.init(
        dsn=sentry_dsn,
        send_default_pii=True,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        before_send=before_send,
    )


def path_expansion(path: str) -> str:
    """
    Takes a path/file and returns an absolute path.
    This function is needed to handle GitHub Action's
    somewhat custom path management inside Docker.

    Args:
        path: Input path to expand

    Returns:
        Absolute path string

    Raises:
        FileProcessingError: If file is not found
    """
    current_dir = Path.cwd()
    relative_path = current_dir / path
    workspace_relative_path = Path("/github/workspace") / path

    if Path(path).is_file():
        logger.info(f"Using input file '{path}'.")
        return str(current_dir / path)
    elif relative_path.is_file():
        logger.info(f"Using input file '{relative_path}'.")
        return str(relative_path)
    elif workspace_relative_path.is_file():
        logger.info(f"Using input file '{workspace_relative_path}'.")
        return str(workspace_relative_path)
    else:
        raise FileProcessingError("Specified input file not found")


def get_last_sbom_from_last_step() -> Optional[str]:
    """
    Helper function to get the SBOM from the previous step.

    Returns:
        Path to the most recent SBOM file, or None if not found
    """
    steps = ["step_3.json", "step_2.json", "step_1.json"]
    for file in steps:
        if Path(file).is_file():
            return file
    return None


def evaluate_boolean(value: str) -> bool:
    """
    Evaluate string values as boolean.

    Args:
        value: String value to evaluate

    Returns:
        Boolean result
    """
    return value.lower() in ["true", "yes", "yeah", "1"]


def validate_sbom(file_path: str) -> str:
    """
    Validate and detect the format of an SBOM file.

    Args:
        file_path: Path to the SBOM JSON file

    Returns:
        Format string: 'cyclonedx' or 'spdx'

    Raises:
        SBOMValidationError: If SBOM is invalid or unsupported format
    """
    try:
        with Path(file_path).open("r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        raise SBOMValidationError("Invalid JSON format")
    except FileNotFoundError:
        raise SBOMValidationError(f"SBOM file not found: {file_path}")

    # Detect artifact type (only log once during initial validation)
    if data.get("bomFormat") == "CycloneDX":
        logger.info("Detected CycloneDX SBOM.")
        return "cyclonedx"
    elif data.get("spdxVersion") is not None:
        logger.info("Detected SPDX SBOM.")
        return "spdx"
    else:
        raise SBOMValidationError("Neither CycloneDX nor SPDX format found in JSON file")


def _detect_sbom_format_silent(file_path: str) -> str:
    """
    Silently detect the format of an SBOM file without logging.
    Used for internal format checks after initial detection.

    Args:
        file_path: Path to the SBOM JSON file

    Returns:
        Format string: 'cyclonedx' or 'spdx'

    Raises:
        SBOMValidationError: If SBOM is invalid or unsupported format
    """
    try:
        with Path(file_path).open("r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        raise SBOMValidationError("Invalid JSON format")
    except FileNotFoundError:
        raise SBOMValidationError(f"SBOM file not found: {file_path}")

    # Detect artifact type without logging
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    elif data.get("spdxVersion") is not None:
        return "spdx"
    else:
        raise SBOMValidationError("Neither CycloneDX nor SPDX format found in JSON file")


def load_sbom_from_file(file_path: str) -> tuple[str, dict, object]:
    """
    Load SBOM from JSON file using appropriate library based on format.

    Args:
        file_path: Path to the SBOM JSON file

    Returns:
        Tuple of (format, original_json, parsed_object)
        - format: 'cyclonedx' or 'spdx'
        - original_json: Original JSON dict
        - parsed_object: Parsed object (Bom for CycloneDX, future SPDX object)

    Raises:
        SBOMValidationError: If SBOM cannot be parsed
    """
    try:
        with Path(file_path).open("r") as f:
            sbom_json = json.load(f)

        # Detect format silently (format should already be known at this point)
        if sbom_json.get("bomFormat") == "CycloneDX":
            sbom_format = "cyclonedx"
            # Use cyclonedx deserializer
            parsed_object = Bom.from_json(sbom_json)
            logger.debug(f"Successfully loaded CycloneDX SBOM from {file_path}")
        elif sbom_json.get("spdxVersion") is not None:
            sbom_format = "spdx"
            # For now, just return the JSON - we'll add SPDX library later
            parsed_object = sbom_json  # Placeholder for future SPDX object
            logger.debug(f"Successfully loaded SPDX SBOM from {file_path}")
        else:
            raise SBOMValidationError("Neither CycloneDX nor SPDX format found in JSON file")

        return sbom_format, sbom_json, parsed_object

    except Exception as e:
        raise SBOMValidationError(f"Failed to load SBOM from {file_path}: {e}")


def log_command_error(command_name, stderr):
    """
    Logs command errors with a standardized format.

    Args:
        command_name: The name of the command that failed (e.g., 'cyclonedx-py',
            'trivy')
        stderr: The stderr output from the command
    """
    if stderr:
        logger.error(f"[{command_name}] error: {stderr.strip()}")


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


def enrich_sbom_with_ecosystems(input_file: str, output_file: str) -> None:
    """
    Takes a path to an SBOM as input and returns an enriched SBOM as the output
    using ecosyste.ms API.

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save enriched SBOM

    Raises:
        SBOMGenerationError: If enrichment fails
    """
    from ..enrichment import enrich_sbom_with_ecosystems as _enrich_impl

    try:
        _enrich_impl(input_file, output_file)
    except FileNotFoundError as e:
        raise SBOMGenerationError(f"Input file not found: {e}")
    except ValueError as e:
        raise SBOMValidationError(f"Invalid SBOM format: {e}")
    except Exception as e:
        raise SBOMGenerationError(f"Enrichment failed: {e}")


def print_banner() -> None:
    """Print the sbomify banner."""
    ascii_art = """

      _                     _  __
     | |                   (_)/ _|
  ___| |__   ___  _ __ ___  _| |_ _   _
 / __| '_ \\ / _ \\| '_ ' _ \\| |  _| | | |
 \\__ \\ |_) | (_) | | | | | | | | | |_| |
 |___/_.__/ \\___/|_| |_| |_|_|_|  \\__, |
                                   __/ |
 The SBOM hub for secure          |___/
 sharing and distribution.
"""
    logger.info(ascii_art)


def _log_step_header(step_num: int, title: str, emoji: str = "") -> None:
    """
    Log a nicely formatted step header optimized for GitHub Actions.

    Args:
        step_num: Step number (1-5)
        title: Step title
        emoji: Optional emoji to include (deprecated, will be ignored)
    """
    import os

    # Check if we're running in GitHub Actions
    is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"

    # Create a shorter border optimized for GitHub Actions (max 60 chars)
    title_with_step = f"STEP {step_num}: {title}"
    border_length = min(60, max(50, len(title_with_step) + 4))
    border = "=" * border_length

    # Use GitHub Actions grouping if available
    if is_github_actions:
        # GitHub Actions group syntax
        print(f"::group::{title_with_step}")
        logger.info(f"{title_with_step}")
        logger.info(border)
    else:
        # Local/standard logging with full ASCII art
        logger.info("")
        logger.info(border)
        logger.info(f"{title_with_step.center(border_length - 2)}")
        logger.info(border)


def _log_step_end(step_num: int, success: bool = True) -> None:
    """
    Log step completion and close GitHub Actions group if applicable.

    Args:
        step_num: Step number (1-5)
        success: Whether the step completed successfully
    """
    import os

    is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"

    if success:
        logger.info(f"Step {step_num} completed successfully")
    else:
        logger.error(f"Step {step_num} failed")

    # Close GitHub Actions group
    if is_github_actions:
        print("::endgroup::")
    else:
        logger.info("")  # Add spacing for local runs


def _check_release_exists(config: "Config", product_id: str, version: str) -> bool:
    """
    Check if a release exists for a product.

    Args:
        config: Configuration object with API details
        product_id: The product ID
        version: The release version

    Returns:
        True if release exists, False otherwise

    Raises:
        APIError: If API call fails
    """
    url = config.api_base_url + "/api/v1/releases"
    headers = {
        "Authorization": f"Bearer {config.token}",
    }

    params = {"product_id": product_id, "version": version}

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=60,
        )
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if response.status_code == 404:
        return False
    elif response.ok:
        # Check if any releases match our criteria
        try:
            releases = response.json().get("items", [])
            for release in releases:
                if release.get("version") == version:
                    return True
            return False
        except (ValueError, KeyError):
            return False
    else:
        err_msg = f"Failed to check release existence. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)


def _create_release(config: "Config", product_id: str, version: str) -> str:
    """
    Create a release for a product.

    Args:
        config: Configuration object with API details
        product_id: The product ID
        version: The release version

    Returns:
        The created release ID

    Raises:
        APIError: If API call fails
    """
    url = config.api_base_url + "/api/v1/releases"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.token}",
    }

    payload = {
        "product_id": product_id,
        "version": version,
        "name": f"Release {version}",
        "description": f"Release {version} created by sbomify-github-action",
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=60,
        )
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        err_msg = f"Failed to create release. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
                else:
                    # Log full error response for debugging when detail is missing
                    err_msg += f" - {error_data}"
            except (ValueError, KeyError):
                pass
        else:
            # Log response text for non-JSON responses
            try:
                response_text = response.text[:500]  # Limit to first 500 chars
                if response_text:
                    err_msg += f" - Response: {response_text}"
            except Exception:
                pass
        raise APIError(err_msg)

    try:
        return response.json().get("id")
    except (ValueError, KeyError):
        raise APIError("Invalid response format when creating release")


def _tag_sbom_with_release(config: "Config", sbom_id: str, release_id: str) -> None:
    """
    Associate/tag an SBOM with a release.

    Args:
        config: Configuration object with API details
        sbom_id: The SBOM ID from upload response
        release_id: The release ID to associate with

    Raises:
        APIError: If API call fails
    """
    url = config.api_base_url + f"/api/v1/releases/{release_id}/artifacts"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.token}",
    }

    payload = {"sbom_id": sbom_id}

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=60,
        )
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        err_msg = f"Failed to tag SBOM with release. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)


def _get_release_id(config: "Config", product_id: str, version: str) -> Optional[str]:
    """
    Get the release ID for a product and version.

    Args:
        config: Configuration object with API details
        product_id: The product ID
        version: The release version

    Returns:
        The release ID if found, None otherwise

    Raises:
        APIError: If API call fails
    """
    url = config.api_base_url + "/api/v1/releases"
    headers = {
        "Authorization": f"Bearer {config.token}",
    }

    params = {"product_id": product_id, "version": version}

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=60,
        )
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if response.ok:
        try:
            releases = response.json().get("items", [])
            for release in releases:
                if release.get("version") == version:
                    return release.get("id")
            return None
        except (ValueError, KeyError):
            return None
    else:
        err_msg = f"Failed to get release ID. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)


def _process_product_releases(config: "Config", sbom_id: str) -> None:
    """
    Process product releases by checking if they exist, creating them if needed,
    and tagging the SBOM with the releases.

    Args:
        config: Configuration object with product releases to process
        sbom_id: The SBOM ID to tag with releases
    """
    if not config.product_releases:
        return

    # Ensure we have a list (should be converted during validation)
    if isinstance(config.product_releases, str):
        logger.error("Product releases not properly validated - still in string format")
        return

    for release in config.product_releases:
        product_id, version = release.split(":", 1)

        logger.info(f"Processing release {version} for product {product_id}")

        # Track details and ID so we can tag without redundant lookups
        release_exists = _check_release_exists(config, product_id, version)
        release_details = None
        release_id = None

        if release_exists:
            # Get release details for user-friendly logging
            try:
                release_details = _get_release_details(config, product_id, version)
                friendly_name = _get_release_friendly_name(release_details, product_id, version)
                logger.info(f"{friendly_name} already exists for product {product_id}")
                release_id = release_details.get("id")
            except APIError as e:
                logger.warning(f"Could not get release details for logging: {e}")
                logger.info(f"Release {version} already exists for product {product_id}")
        else:
            logger.info(f"Creating release {version} for product {product_id}")
            created_release_id = _create_release(config, product_id, version)
            if created_release_id:
                release_id = created_release_id
            # Get details after creation for consistent logging
            try:
                release_details = _get_release_details(config, product_id, version)
                if not release_id and release_details:
                    release_id = release_details.get("id")
            except APIError as e:
                logger.warning(f"Could not get release details after creation: {e}")

        # Fall back to explicit lookup if we still don't know the release ID
        if not release_id:
            release_id = _get_release_id(config, product_id, version)

        if release_id:
            # Use friendly name if we have release details
            if release_details:
                friendly_name = _get_release_friendly_name(release_details, product_id, version)
                logger.info(f"Tagging SBOM {sbom_id} with {friendly_name} (ID: {release_id})")
            else:
                logger.info(f"Tagging SBOM {sbom_id} with release {version} (ID: {release_id})")
            _tag_sbom_with_release(config, sbom_id, release_id)
        else:
            logger.error(f"Could not get release ID for {product_id}:{version}")


def main() -> None:
    """Main entry point for the sbomify action."""
    print_banner()

    # Setup dependencies
    try:
        setup_dependencies()
    except SBOMGenerationError as e:
        logger.error(f"Dependency setup failed: {e}")
        sys.exit(1)

    # Initialize Sentry
    initialize_sentry()

    config = load_config()

    # Log the API base URL being used for transparency
    if config.api_base_url != SBOMIFY_PRODUCTION_API:
        logger.info(f"Using custom API base URL: {config.api_base_url}")
    else:
        logger.info(f"Using production API: {config.api_base_url}")

    # Step 1: SBOM Generation/Validation
    _log_step_header(1, "SBOM Generation/Input Processing")

    # Check if either SBOM_FILE or LOCK_FILE exists
    if config.sbom_file:
        FILE = config.sbom_file
        FILE_TYPE = "SBOM"
    elif config.lock_file:
        FILE = config.lock_file
        FILE_TYPE = "LOCK_FILE"
    elif config.docker_image:
        FILE_TYPE = None
        pass
    else:
        logger.error("Neither SBOM file, Docker image nor lockfile found.")
        sys.exit(1)

    # Process input based on type
    try:
        if FILE_TYPE == "SBOM":
            logger.info(f"Processing existing SBOM file: {FILE}")
            FORMAT = validate_sbom(FILE)
            shutil.copy(FILE, "step_1.json")
        elif config.docker_image:
            logger.info(f"Generating SBOM from Docker image: {config.docker_image}")
            run_trivy_docker_image(docker_image=config.docker_image, output_file="step_1.json")
        elif FILE_TYPE == "LOCK_FILE":
            logger.info(f"Generating SBOM from lock file: {FILE}")
            process_lock_file(FILE)
        else:
            logger.error("Unrecognized FILE_TYPE.")
            sys.exit(1)
    except SBOMValidationError as e:
        # User-provided SBOM validation errors - don't send to Sentry
        logger.error(f"Step 1 failed: {e}")
        if FILE_TYPE == "SBOM":
            file_name = Path(FILE).name
            logger.error(f"The provided SBOM file '{FILE}' appears to be invalid.")
            logger.error("Please ensure the file is a valid CycloneDX or SPDX JSON document.")

            # Check if user accidentally provided a lock file instead of an SBOM
            all_lock_files = (
                COMMON_PYTHON_LOCK_FILES
                + COMMON_RUST_LOCK_FILES
                + COMMON_JAVASCRIPT_LOCK_FILES
                + COMMON_RUBY_LOCK_FILES
                + COMMON_GO_LOCK_FILES
                + COMMON_DART_LOCK_FILES
                + COMMON_CPP_LOCK_FILES
            )
            if file_name in all_lock_files:
                logger.error(f"'{file_name}' is a lock file, not an SBOM.")
                logger.error(f"Please use LOCK_FILE instead of SBOM_FILE for '{file_name}'.")
        _log_step_end(1, success=False)
        sys.exit(1)
    except (FileProcessingError, SBOMGenerationError) as e:
        logger.error(f"Step 1 failed: {e}")
        _log_step_end(1, success=False)
        sys.exit(1)

    # Set the SBOM format based on the output (silent detection for generated SBOMs)
    try:
        if FILE_TYPE != "SBOM":  # Only detect format if we generated the SBOM
            FORMAT = _detect_sbom_format_silent("step_1.json")
            logger.info(f"Generated SBOM format: {FORMAT.upper()}")
    except SBOMValidationError as e:
        logger.error(f"Generated SBOM validation failed: {e}")
        logger.error("The SBOM generation tool produced an invalid output file.")

        # Re-raise with better context for Sentry (but don't include file contents for privacy)
        if config.docker_image:
            raise SBOMGenerationError(
                f"Trivy generated invalid SBOM for Docker image '{config.docker_image}': {e}"
            ) from e
        elif FILE_TYPE == "LOCK_FILE":
            lock_file_name = Path(FILE).name
            raise SBOMGenerationError(
                f"SBOM generation tool produced invalid output for lock file '{lock_file_name}': {e}"
            ) from e
        else:
            raise SBOMGenerationError(f"Generated SBOM validation failed: {e}") from e

    _log_step_end(1)

    # Apply component version override if specified (regardless of augmentation settings)
    if config.component_version:
        logger.info(f"Applying component version override: {config.component_version}")
        _apply_sbom_version_override("step_1.json", config)

    # Apply component name override if specified (regardless of augmentation settings)
    if config.component_name:
        logger.info(f"Applying component name override: {config.component_name}")
        _apply_sbom_name_override("step_1.json", config)

    # Step 2: Augmentation
    if config.augment:
        _log_step_header(2, "SBOM Augmentation with Backend Metadata")
        try:
            sbom_input_file = get_last_sbom_from_last_step()
            if not sbom_input_file:
                raise FileProcessingError("No SBOM file found from previous step")

            logger.info("Augmenting SBOM with backend metadata")

            # Use augmentation module's file-based function
            sbom_format = augment_sbom_from_file(
                input_file=sbom_input_file,
                output_file="step_2.json",
                api_base_url=config.api_base_url,
                token=config.token,
                component_id=config.component_id,
                override_sbom_metadata=config.override_sbom_metadata,
                component_name=config.component_name,
                component_version=config.component_version,
            )

            logger.info(f"{sbom_format.upper()} SBOM augmentation completed")
            _log_step_end(2)

        except (FileProcessingError, APIError, SBOMValidationError) as e:
            logger.error(f"Step 2 (augmentation) failed: {e}")
            _log_step_end(2, success=False)
            sys.exit(1)
    else:
        _log_step_header(2, "SBOM Augmentation - SKIPPED")
        logger.info("SBOM augmentation disabled (AUGMENT=false)")
        _log_step_end(2)

    # Step 3: Enrichment
    if config.enrich:
        _log_step_header(3, "SBOM Enrichment with Ecosystem Data")
        try:
            sbom_input_file = get_last_sbom_from_last_step()
            if not sbom_input_file:
                raise FileProcessingError("No SBOM file found from previous step")

            logger.info("Enriching SBOM components with ecosystem metadata from Ecosyste.ms")
            enrich_sbom_with_ecosystems(sbom_input_file, "step_3.json")
            _detect_sbom_format_silent("step_3.json")  # Silent validation
            _log_step_end(3)
        except (FileProcessingError, SBOMGenerationError, SBOMValidationError) as e:
            logger.error(f"Step 3 (enrichment) failed: {e}")
            _log_step_end(3, success=False)
            sys.exit(1)
    else:
        _log_step_header(3, "SBOM Enrichment - SKIPPED")
        logger.info("SBOM enrichment disabled (ENRICH=false)")
        _log_step_end(3)

    # Step 4: Finalize output
    _log_step_header(4, "Finalizing SBOM Output")
    try:
        final_sbom_file = get_last_sbom_from_last_step()
        if not final_sbom_file:
            raise FileProcessingError("No SBOM file found to finalize")

        # Get the parent directory of the file path
        parent_dir = Path(config.output_file).parent

        # Check if the parent directory exists; if not, create it recursively
        if parent_dir != Path(".") and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)

        # Clean up and write final SBOM
        shutil.copy(final_sbom_file, config.output_file)

        # Clean up temporary files
        while get_last_sbom_from_last_step():
            temp_file = get_last_sbom_from_last_step()
            Path(temp_file).unlink()

        logger.info(f"Final SBOM saved to: {config.output_file}")
        _log_step_end(4)

    except (FileProcessingError, OSError) as e:
        logger.error(f"Failed to finalize output: {e}")
        _log_step_end(4, success=False)
        sys.exit(1)

    # Step 5: Upload SBOM via API
    sbom_id = None  # Store SBOM ID for potential release tagging
    if config.upload:
        _log_step_header(5, "Uploading SBOM to sbomify")
        try:
            # Validate SBOM before uploading (for CycloneDX)
            if FORMAT == "cyclonedx":
                try:
                    validation_passed = _validate_cyclonedx_sbom(config.output_file)
                    if not validation_passed:
                        logger.warning("SBOM validation failed, but proceeding with upload")
                except CommandExecutionError as e:
                    logger.warning(f"SBOM validation error: {e}, proceeding with upload")

            # Execute the POST request to upload the SBOM file
            url = config.api_base_url + f"/api/v1/sboms/artifact/{FORMAT}/{config.component_id}"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {config.token}",
            }

            with Path(config.output_file).open() as f:
                sbom_data = f.read()

            logger.info(f"Uploading {FORMAT.upper()} SBOM to component: {config.component_id}")

            try:
                response = requests.post(
                    url,
                    headers=headers,
                    data=sbom_data,
                    timeout=120,  # Security: add timeout for upload
                )
            except requests.exceptions.ConnectionError:
                raise APIError("Failed to connect to sbomify API for upload")
            except requests.exceptions.Timeout:
                raise APIError("SBOM upload timed out")

            if not response.ok:
                err_msg = f"Failed to upload SBOM file. [{response.status_code}]"
                try:
                    if response.json() and "detail" in response.json():
                        err_msg += f" - {response.json()['detail']}"
                except (ValueError, json.JSONDecodeError):
                    pass

                raise APIError(err_msg)
            else:
                logger.info("SBOM uploaded successfully to sbomify")

                # Extract SBOM ID from response for potential release tagging
                try:
                    response_data = response.json()
                    sbom_id = response_data.get("sbom_id") or response_data.get("id")
                    if sbom_id:
                        logger.info(f"SBOM ID: {sbom_id}")
                except (ValueError, json.JSONDecodeError):
                    logger.warning("Could not extract SBOM ID from upload response")

            _log_step_end(5)

        except (APIError, FileProcessingError) as e:
            logger.error(f"Step 5 (upload) failed: {e}")
            _log_step_end(5, success=False)
            sys.exit(1)
    else:
        _log_step_header(5, "SBOM Upload - SKIPPED")
        logger.info("SBOM upload disabled (UPLOAD=false)")
        _log_step_end(5)

    # Step 6: Process Product Releases
    if config.product_releases and sbom_id:
        _log_step_header(6, "Processing Product Releases")
        try:
            _process_product_releases(config, sbom_id)
            _log_step_end(6)
        except (APIError, Exception) as e:
            logger.error(f"Step 6 (product releases) failed: {e}")
            _log_step_end(6, success=False)
            # Don't exit here - releases are optional, continue with success message
    elif config.product_releases and not sbom_id:
        _log_step_header(6, "Processing Product Releases - SKIPPED")
        logger.warning("Product releases specified but no SBOM ID available (upload may have been disabled or failed)")
        _log_step_end(6, success=False)
    elif config.product_releases:
        _log_step_header(6, "Processing Product Releases - SKIPPED")
        logger.info("No product releases specified")
        _log_step_end(6)

    # Final success message optimized for both local and GitHub Actions
    import os

    if os.getenv("GITHUB_ACTIONS") == "true":
        # Simple success message for GitHub Actions
        logger.info("")
        logger.info("SUCCESS! All steps completed successfully!")
        logger.info("")
    else:
        # ASCII art for local runs (without emojis)
        logger.info("")
        logger.info("=" * 60)
        logger.info(" SUCCESS! All steps completed successfully! ".center(60))
        logger.info("=" * 60)
        logger.info("")


def _validate_cyclonedx_sbom(sbom_file_path: str) -> bool | None:
    """
    Validate CycloneDX SBOM using cyclonedx-py tool.

    Args:
        sbom_file_path: Path to the SBOM JSON file to validate

    Returns:
        True if valid, False if invalid, None if validation tool not available
    """
    import json

    try:
        # Basic JSON validation - ensure it's valid JSON and has required CycloneDX fields
        with Path(sbom_file_path).open("r") as f:
            sbom_data = json.load(f)

        # Check for basic CycloneDX structure
        if sbom_data.get("bomFormat") == "CycloneDX" and sbom_data.get("specVersion"):
            logger.debug("SBOM basic validation successful")
            return True
        else:
            logger.warning("SBOM basic validation failed: missing bomFormat or specVersion")
            return False

    except json.JSONDecodeError as e:
        logger.warning(f"SBOM validation failed: Invalid JSON - {e}")
        return False
    except FileNotFoundError:
        logger.warning(f"SBOM validation failed: File not found - {sbom_file_path}")
        return False
    except Exception as e:
        logger.warning(f"SBOM validation error: {e}")
        return False


def _apply_sbom_version_override(sbom_file: str, config: "Config") -> None:
    """
    Apply component version override based on configuration.
    This function ensures that COMPONENT_VERSION (or deprecated SBOM_VERSION) is applied regardless of augmentation settings.

    Args:
        sbom_file: Path to the SBOM file to modify
        config: Configuration with version override settings

    Raises:
        SBOMValidationError: If SBOM cannot be processed
        FileProcessingError: If file operations fail
    """
    if not config.component_version:
        return  # No version override specified

    try:
        # Load SBOM from file
        sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_file)

        if sbom_format == "cyclonedx":
            from cyclonedx.model.bom import Bom
            from cyclonedx.model.component import Component, ComponentType

            if isinstance(parsed_object, Bom):
                # Apply version override to CycloneDX BOM object
                if hasattr(parsed_object.metadata, "component") and parsed_object.metadata.component:
                    parsed_object.metadata.component.version = config.component_version
                else:
                    # Create component if it doesn't exist
                    component_name = original_json.get("metadata", {}).get("component", {}).get("name", "unknown")
                    parsed_object.metadata.component = Component(
                        name=component_name, type=ComponentType.APPLICATION, version=config.component_version
                    )

                logger.info(f"Set component version from configuration: {config.component_version}")

                # Serialize the BOM back to JSON using version-aware serializer
                spec_version = original_json.get("specVersion", "1.6")
                serialized = serialize_cyclonedx_bom(parsed_object, spec_version)
                with Path(sbom_file).open("w") as f:
                    f.write(serialized)

        elif sbom_format == "spdx":
            # For SPDX, apply version override directly to JSON
            if "metadata" not in original_json:
                original_json["metadata"] = {}
            if "component" not in original_json["metadata"]:
                original_json["metadata"]["component"] = {}

            original_json["metadata"]["component"]["version"] = config.component_version
            logger.info(f"Set SPDX component version from configuration: {config.component_version}")

            with Path(sbom_file).open("w") as f:
                json.dump(original_json, f, indent=2)

    except Exception as e:
        logger.warning(f"Failed to apply component version override: {e}")
        # Don't fail the entire process for version override issues


def _apply_sbom_name_override(sbom_file: str, config: "Config") -> None:
    """
    Apply component name override based on configuration.
    This function ensures that COMPONENT_NAME is applied regardless of augmentation settings.

    Args:
        sbom_file: Path to the SBOM file to modify
        config: Configuration with name override settings

    Raises:
        SBOMValidationError: If SBOM cannot be processed
        FileProcessingError: If file operations fail
    """
    if not config.component_name:
        return  # No name override specified

    try:
        # Load SBOM from file
        sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_file)

        if sbom_format == "cyclonedx":
            from cyclonedx.model.bom import Bom
            from cyclonedx.model.component import Component, ComponentType

            if isinstance(parsed_object, Bom):
                # Apply name override to CycloneDX BOM object
                if hasattr(parsed_object.metadata, "component") and parsed_object.metadata.component:
                    existing_name = parsed_object.metadata.component.name or "unknown"
                    parsed_object.metadata.component.name = config.component_name
                else:
                    # Create component if it doesn't exist
                    existing_name = "none (creating new component)"
                    component_version = original_json.get("metadata", {}).get("component", {}).get("version", "unknown")
                    parsed_object.metadata.component = Component(
                        name=config.component_name, type=ComponentType.APPLICATION, version=component_version
                    )

                logger.info(f"Overriding component name: '{existing_name}' -> '{config.component_name}'")

                # Serialize the BOM back to JSON using version-aware serializer
                spec_version = original_json.get("specVersion", "1.6")
                serialized = serialize_cyclonedx_bom(parsed_object, spec_version)
                with Path(sbom_file).open("w") as f:
                    f.write(serialized)

        elif sbom_format == "spdx":
            # For SPDX, apply name override to the top-level "name" field
            existing_name = original_json.get("name", "unknown")
            original_json["name"] = config.component_name
            logger.info(f"Overriding SPDX component name: '{existing_name}' -> '{config.component_name}'")

            with Path(sbom_file).open("w") as f:
                json.dump(original_json, f, indent=2)

    except Exception as e:
        logger.warning(f"Failed to apply component name override: {e}")
        # Don't fail the entire process for name override issues


def _get_release_details(config: "Config", product_id: str, version: str) -> Optional[dict]:
    """
    Get full release details for a product and version.

    Args:
        config: Configuration object with API details
        product_id: The product ID
        version: The release version

    Returns:
        Full release details dict if found, None otherwise

    Raises:
        APIError: If API call fails
    """
    url = config.api_base_url + "/api/v1/releases"
    headers = {
        "Authorization": f"Bearer {config.token}",
    }

    params = {"product_id": product_id, "version": version}

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=60,
        )
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if response.ok:
        try:
            releases = response.json().get("items", [])
            for release in releases:
                if release.get("version") == version:
                    return release
            return None
        except (ValueError, KeyError):
            return None
    else:
        err_msg = f"Failed to get release details. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)


def _get_release_friendly_name(release_details: dict, product_id: str, version: str) -> str:
    """
    Get a user-friendly name for a release.

    Args:
        release_details: Full release details from the API
        product_id: The product ID (fallback)
        version: The release version (fallback)

    Returns:
        User-friendly release name
    """
    if not release_details:
        return f"Release {version}"

    # Try to get the release name from the API response
    release_name = release_details.get("name")
    if release_name and release_name != f"Release {version}":
        # Custom release name
        return f"'{release_name}' ({version})"
    else:
        # Default release name format
        return f"Release {version}"


if __name__ == "__main__":
    main()
