import json
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import sentry_sdk

# Add cyclonedx imports for proper SBOM handling
from cyclonedx.model.bom import Bom

from .._upload import VALID_DESTINATIONS
from ..additional_packages import inject_additional_packages
from ..augmentation import augment_sbom_from_file
from ..console import (
    print_banner as console_print_banner,
)
from ..console import (
    print_final_success,
    print_step_end,
    print_step_header,
    print_transformation_summary,
    reset_transformation_tracker,
)
from ..exceptions import (
    APIError,
    ConfigurationError,
    FileProcessingError,
    SBOMGenerationError,
    SBOMValidationError,
)
from ..generation import (
    ALL_LOCK_FILES,
    SBOMFormat,
    generate_sbom,
    process_lock_file,
)
from ..logging_config import logger
from ..serialization import serialize_cyclonedx_bom
from ..upload import upload_sbom


# Import version for tool metadata with multiple fallback mechanisms
def _get_package_version() -> str:
    """Get the package version using multiple fallback methods.

    Priority:
    1. SBOMIFY_GITHUB_ACTION_VERSION environment variable (set at Docker build time for release tracking)
    2. importlib.metadata (for installed packages)
    3. pyproject.toml (for development)
    4. Package __version__ attribute
    5. Fallback to "unknown"
    """
    # Method 1: Check for environment variable (set at Docker build time)
    # This takes precedence as it contains the release version (tag or branch-sha)
    env_version = os.getenv("SBOMIFY_GITHUB_ACTION_VERSION")
    if env_version and env_version not in ("dev", "unknown", ""):
        return env_version

    # Method 2: Try importlib.metadata (preferred for installed packages)
    try:
        from importlib.metadata import version

        return version("sbomify-action")
    except ImportError:
        pass
    except Exception:
        pass

    # Method 3: Try reading from pyproject.toml using tomllib when available (Python 3.11+; older versions fall back to other methods)
    try:
        import tomllib

        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                pyproject_data = tomllib.load(f)
            return pyproject_data.get("project", {}).get("version", "unknown")
    except ImportError:
        # Python < 3.11 doesn't have tomllib
        pass
    except Exception:
        pass

    # Method 4: Try toml library as fallback for older Python
    try:
        import toml

        pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "r") as f:
                pyproject_data = toml.load(f)
            return pyproject_data.get("project", {}).get("version", "unknown")
    except ImportError:
        pass
    except Exception:
        pass

    # Method 5: Try package __version__ attribute
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
SBOMIFY_TOOL_NAME = "sbomify-action"
SBOMIFY_VENDOR_NAME = "sbomify"
LOCALHOST_PATTERNS = ["127.0.0.1", "localhost", "0.0.0.0"]

# Intermediate SBOM files for pipeline steps
STEP_1_FILE = "step_1.json"  # Output of generation/validation
STEP_2_FILE = "step_2.json"  # Output of augmentation
STEP_3_FILE = "step_3.json"  # Output of enrichment


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
    upload_destinations: list[str] | None = None
    augment: bool = False
    enrich: bool = False
    override_sbom_metadata: bool = False
    override_name: bool = False
    component_version: Optional[str] = None
    component_name: Optional[str] = None
    component_purl: Optional[str] = None
    product_releases: Optional[str | list[str]] = None
    api_base_url: str = SBOMIFY_PRODUCTION_API
    sbom_format: SBOMFormat = "cyclonedx"

    def __post_init__(self) -> None:
        """Set default values that depend on other fields."""
        if self.upload_destinations is None:
            self.upload_destinations = ["sbomify"]  # Default to sbomify only

    def validate(self) -> None:
        """
        Validate configuration settings.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Check if sbomify API access is required:
        # - Uploading to sbomify destination
        # - Augmenting (uses sbomify API)
        # - Managing releases (uses sbomify API)
        uploads_to_sbomify = self.upload and "sbomify" in self.upload_destinations
        requires_sbomify_api = uploads_to_sbomify or self.augment or self.product_releases

        if requires_sbomify_api:
            if not self.token:
                operations = []
                if uploads_to_sbomify:
                    operations.append("uploading to sbomify")
                if self.augment:
                    operations.append("AUGMENT=true")
                if self.product_releases:
                    operations.append("PRODUCT_RELEASE is set")
                reason = " or ".join(operations)
                raise ConfigurationError(f"sbomify API token is not defined (required when {reason})")
            if not self.component_id:
                operations = []
                if uploads_to_sbomify:
                    operations.append("uploading to sbomify")
                if self.augment:
                    operations.append("AUGMENT=true")
                if self.product_releases:
                    operations.append("PRODUCT_RELEASE is set")
                reason = " or ".join(operations)
                raise ConfigurationError(f"Component ID is not defined (required when {reason})")

        inputs = [self.sbom_file, self.lock_file, self.docker_image]
        if sum(bool(x) for x in inputs) > 1:
            raise ConfigurationError("Please provide only one of: SBOM_FILE, LOCK_FILE, or DOCKER_IMAGE")
        if not any(inputs):
            raise ConfigurationError("Please provide one of: SBOM_FILE, LOCK_FILE, or DOCKER_IMAGE")

        # Validate SBOM format
        valid_formats = ("cyclonedx", "spdx")
        if self.sbom_format not in valid_formats:
            raise ConfigurationError(
                f"Invalid SBOM_FORMAT: '{self.sbom_format}'. Must be one of: {', '.join(valid_formats)}"
            )

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

    # Handle component PURL override
    component_purl = os.getenv("COMPONENT_PURL")
    if component_purl:
        logger.info(f"Using component PURL: {component_purl}")

    # Handle product releases
    product_releases = None
    product_release_env = os.getenv("PRODUCT_RELEASE")
    if product_release_env:
        logger.info(f"Raw product release input: {product_release_env}")
        # Store the raw value for validation later in Config.validate()
        product_releases = product_release_env

    # Handle upload destinations
    upload_destinations = None
    upload_destinations_env = os.getenv("UPLOAD_DESTINATIONS")
    if upload_destinations_env:
        # Parse comma-separated list of destinations
        upload_destinations = [d.strip() for d in upload_destinations_env.split(",") if d.strip()]
        # Validate destination names using centralized registry constant
        invalid_destinations = [d for d in upload_destinations if d not in VALID_DESTINATIONS]
        if invalid_destinations:
            logger.error(f"Invalid upload destination(s): {invalid_destinations}")
            logger.error(f"Valid destinations are: {sorted(VALID_DESTINATIONS)}")
            sys.exit(1)
        logger.info(f"Upload destinations: {upload_destinations}")

    # Handle SBOM format (cyclonedx or spdx)
    sbom_format = os.getenv("SBOM_FORMAT", "cyclonedx").lower()
    logger.info(f"SBOM format: {sbom_format.upper()}")

    config = Config(
        token=os.getenv("TOKEN", ""),
        component_id=os.getenv("COMPONENT_ID", ""),
        sbom_file=path_expansion(os.getenv("SBOM_FILE")) if os.getenv("SBOM_FILE") else None,
        docker_image=os.getenv("DOCKER_IMAGE"),
        lock_file=path_expansion(os.getenv("LOCK_FILE")) if os.getenv("LOCK_FILE") else None,
        output_file=os.getenv("OUTPUT_FILE", "sbom_output.json"),
        upload=evaluate_boolean(os.getenv("UPLOAD", "True")),
        upload_destinations=upload_destinations,
        augment=evaluate_boolean(os.getenv("AUGMENT", "False")),
        enrich=evaluate_boolean(os.getenv("ENRICH", "False")),
        override_sbom_metadata=evaluate_boolean(os.getenv("OVERRIDE_SBOM_METADATA", "False")),
        override_name=final_override_name,
        component_version=final_component_version,
        component_name=final_component_name,
        component_purl=component_purl,
        product_releases=product_releases,
        api_base_url=os.getenv("API_BASE_URL", SBOMIFY_PRODUCTION_API),
        sbom_format=sbom_format,
    )

    try:
        config.validate()
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    return config


def setup_dependencies() -> None:
    """
    Check available SBOM generation tools and log their status.

    This function no longer auto-installs tools. Instead, it logs
    which tools are available and provides guidance when tools are missing.
    """
    from ..tool_checks import get_available_tools, get_missing_tools

    # Check all tools and log status
    available = get_available_tools()
    missing = get_missing_tools()

    if available:
        logger.info(f"Available SBOM generators: {', '.join(available)}")
    else:
        logger.warning("No external SBOM generators found.")
        logger.warning("SBOM generation may fail. Install trivy, syft, or cdxgen for full functionality.")
        logger.warning("The Docker image (sbomifyhub/sbomify-action) includes all tools pre-installed.")

    if missing and available:
        # Some tools available, some missing - just log for information
        logger.debug(f"Additional tools not installed: {', '.join(missing)}")


def initialize_sentry() -> None:
    """Initialize Sentry for error tracking.

    Can be disabled by setting TELEMETRY to 'false', '0', or 'no'.
    """
    # Allow users to opt-out of telemetry
    telemetry_enabled = os.getenv("TELEMETRY", "true").lower()
    if telemetry_enabled in ("false", "0", "no", "off", "disabled"):
        logger.debug("Sentry telemetry disabled via TELEMETRY environment variable")
        return

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
        release=f"sbomify-action@{SBOMIFY_VERSION}",
    )

    # Set the action version as a tag (always safe to send)
    sentry_sdk.set_tag("action.version", SBOMIFY_VERSION)

    # Detect CI/CD platform
    is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"
    is_gitlab_ci = os.getenv("GITLAB_CI") == "true"
    is_bitbucket = os.getenv("BITBUCKET_PIPELINE_UUID") is not None

    # Determine if we should send context based on repository visibility
    # GitHub Actions
    if is_github_actions:
        github_visibility = os.getenv("GITHUB_REPOSITORY_VISIBILITY", "").lower()
        is_public_repo = github_visibility == "public"
        sentry_sdk.set_tag("ci.platform", "github-actions")
        sentry_sdk.set_tag("repo.public", str(is_public_repo))

        if is_public_repo:
            # Add GitHub context tags for public repos only
            ci_context = {}
            if repo := os.getenv("GITHUB_REPOSITORY"):
                sentry_sdk.set_tag("ci.repository", repo)
                ci_context["repository"] = repo
            if workflow := os.getenv("GITHUB_WORKFLOW"):
                sentry_sdk.set_tag("ci.workflow", workflow)
                ci_context["workflow"] = workflow
            if ref := os.getenv("GITHUB_REF"):
                sentry_sdk.set_tag("ci.ref", ref)
                ci_context["ref"] = ref
            if sha := os.getenv("GITHUB_SHA"):
                sentry_sdk.set_tag("ci.sha", sha[:7])
                ci_context["sha"] = sha
            if action := os.getenv("GITHUB_ACTION"):
                ci_context["action"] = action
            if run_id := os.getenv("GITHUB_RUN_ID"):
                ci_context["run_id"] = run_id
            if run_number := os.getenv("GITHUB_RUN_NUMBER"):
                ci_context["run_number"] = run_number

            if ci_context:
                sentry_sdk.set_context("ci", ci_context)
        else:
            logger.debug("Skipping CI context for Sentry (private repository or visibility not set)")

    # GitLab CI
    elif is_gitlab_ci:
        gitlab_visibility = os.getenv("CI_PROJECT_VISIBILITY", "").lower()
        is_public_repo = gitlab_visibility == "public"
        sentry_sdk.set_tag("ci.platform", "gitlab-ci")
        sentry_sdk.set_tag("repo.public", str(is_public_repo))

        if is_public_repo:
            # Add GitLab context tags for public projects only
            ci_context = {}
            if project := os.getenv("CI_PROJECT_PATH"):
                sentry_sdk.set_tag("ci.repository", project)
                ci_context["project"] = project
            if pipeline_source := os.getenv("CI_PIPELINE_SOURCE"):
                sentry_sdk.set_tag("ci.pipeline_source", pipeline_source)
                ci_context["pipeline_source"] = pipeline_source
            if ref := os.getenv("CI_COMMIT_REF_NAME"):
                sentry_sdk.set_tag("ci.ref", ref)
                ci_context["ref"] = ref
            if sha := os.getenv("CI_COMMIT_SHORT_SHA"):
                sentry_sdk.set_tag("ci.sha", sha)
                ci_context["sha"] = sha
            if pipeline_id := os.getenv("CI_PIPELINE_ID"):
                ci_context["pipeline_id"] = pipeline_id
            if job_name := os.getenv("CI_JOB_NAME"):
                ci_context["job_name"] = job_name

            if ci_context:
                sentry_sdk.set_context("ci", ci_context)
        else:
            logger.debug("Skipping CI context for Sentry (private repository or visibility not set)")

    # Bitbucket Pipelines
    elif is_bitbucket:
        # Bitbucket doesn't expose repository visibility, so we treat all repos as private by default
        # This is the safest approach for privacy
        sentry_sdk.set_tag("ci.platform", "bitbucket-pipelines")
        sentry_sdk.set_tag("repo.public", "False")
        logger.debug("Skipping CI context for Sentry (Bitbucket repository visibility unknown, treating as private)")

    # Unknown/Local environment
    else:
        sentry_sdk.set_tag("ci.platform", "unknown")
        logger.debug("Skipping CI context for Sentry (not running in a recognized CI/CD platform)")


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
    steps = [STEP_3_FILE, STEP_2_FILE, STEP_1_FILE]
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


def _format_display_name(fmt: str) -> str:
    """Return properly capitalized display name for SBOM format.

    Args:
        fmt: Format string ('cyclonedx' or 'spdx')

    Returns:
        Display name: 'CycloneDX' or 'SPDX'
    """
    return "CycloneDX" if fmt == "cyclonedx" else "SPDX"


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


def enrich_sbom(input_file: str, output_file: str) -> None:
    """
    Takes a path to an SBOM as input and returns an enriched SBOM as the output
    using the plugin-based enrichment system.

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save enriched SBOM

    Raises:
        SBOMGenerationError: If enrichment fails
    """
    from ..enrichment import enrich_sbom as _enrich_impl

    try:
        _enrich_impl(input_file, output_file)
    except FileNotFoundError as e:
        raise SBOMGenerationError(f"Input file not found: {e}")
    except ValueError as e:
        raise SBOMValidationError(f"Invalid SBOM format: {e}")
    except Exception as e:
        raise SBOMGenerationError(f"Enrichment failed: {e}")


def print_banner() -> None:
    """Print the sbomify banner with gradient colors."""
    console_print_banner(SBOMIFY_VERSION)


def _log_step_header(step_num: int, title: str, emoji: str = "") -> None:
    """
    Log a nicely formatted step header optimized for GitHub Actions.

    Args:
        step_num: Step number (1-6)
        title: Step title
        emoji: Optional emoji to include (deprecated, will be ignored)
    """
    print_step_header(step_num, title)


def _log_step_end(step_num: int, success: bool = True) -> None:
    """
    Log step completion and close GitHub Actions group if applicable.

    Args:
        step_num: Step number (1-6)
        success: Whether the step completed successfully
    """
    print_step_end(step_num, success)


def main() -> None:
    """Main entry point for the sbomify action."""
    # Reset transformation tracker for this run (tracks all SBOM modifications for attestation)
    reset_transformation_tracker()

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
            shutil.copy(FILE, STEP_1_FILE)
        elif config.docker_image:
            logger.info(f"Generating SBOM from Docker image: {config.docker_image}")
            result = generate_sbom(
                docker_image=config.docker_image,
                output_file=STEP_1_FILE,
                output_format=config.sbom_format,
            )
            if not result.success:
                raise SBOMGenerationError(result.error_message or "SBOM generation failed")
        elif FILE_TYPE == "LOCK_FILE":
            logger.info(f"Generating SBOM from lock file: {FILE}")
            result = process_lock_file(
                FILE,
                output_file=STEP_1_FILE,
                output_format=config.sbom_format,
            )
            if not result.success:
                raise SBOMGenerationError(result.error_message or "SBOM generation failed")
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
            if file_name in ALL_LOCK_FILES:
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
            FORMAT = _detect_sbom_format_silent(STEP_1_FILE)
            logger.info(f"Generated SBOM format: {_format_display_name(FORMAT)}")
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
        _apply_sbom_version_override(STEP_1_FILE, config)

    # Apply component name override if specified (regardless of augmentation settings)
    if config.component_name:
        logger.info(f"Applying component name override: {config.component_name}")
        _apply_sbom_name_override(STEP_1_FILE, config)

    # Apply component PURL override if specified (regardless of augmentation settings)
    if config.component_purl:
        logger.info(f"Applying component PURL override: {config.component_purl}")
        _apply_sbom_purl_override(STEP_1_FILE, config)

    # Inject additional packages if specified (file or environment variables)
    try:
        injected_count = inject_additional_packages(STEP_1_FILE)
        if injected_count > 0:
            logger.info(f"Successfully injected {injected_count} additional package(s) into SBOM")
    except Exception as e:
        logger.warning(
            f"Failed to inject additional packages into SBOM: {e}. "
            f"Verify that the SBOM file '{STEP_1_FILE}' exists and is readable, and that any "
            "additional package configuration (ADDITIONAL_PACKAGES env var or "
            "additional_packages.txt file) is present and correctly formatted."
        )
        # Don't fail the entire process for additional packages injection issues

    # Step 2: Augmentation
    if config.augment:
        _log_step_header(2, "SBOM Augmentation with Backend Metadata")
        try:
            sbom_input_file = get_last_sbom_from_last_step()
            if not sbom_input_file:
                raise FileProcessingError("No SBOM file found from previous step")

            logger.info("Augmenting SBOM with backend metadata")

            # Use augmentation module's file-based function
            # Note: PURL override is applied separately via _apply_sbom_purl_override()
            sbom_format = augment_sbom_from_file(
                input_file=sbom_input_file,
                output_file=STEP_2_FILE,
                api_base_url=config.api_base_url,
                token=config.token,
                component_id=config.component_id,
                override_sbom_metadata=config.override_sbom_metadata,
                component_name=config.component_name,
                component_version=config.component_version,
            )

            logger.info(f"{_format_display_name(sbom_format)} SBOM augmentation completed")
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

            logger.info("Enriching SBOM components with metadata from multiple data sources")
            enrich_sbom(sbom_input_file, STEP_3_FILE)
            _detect_sbom_format_silent(STEP_3_FILE)  # Silent validation
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

    # Step 5: Upload SBOM to configured destinations
    sbom_id = None  # Store SBOM ID for potential release tagging (from sbomify)
    if config.upload:
        _log_step_header(5, "Uploading SBOM")
        try:
            # Upload to each configured destination
            logger.info(f"Upload destinations: {config.upload_destinations}")

            failed_destinations: list[str] = []
            for destination in config.upload_destinations:
                logger.info(f"Uploading to: {destination}")

                result = upload_sbom(
                    sbom_file=config.output_file,
                    sbom_format=FORMAT,
                    token=config.token,
                    component_id=config.component_id,
                    api_base_url=config.api_base_url,
                    component_name=config.component_name,
                    component_version=config.component_version,
                    destination=destination,
                    validate_before_upload=(FORMAT == "cyclonedx"),
                )

                if not result.success:
                    logger.error(f"Upload to {destination} failed: {result.error_message}")
                    failed_destinations.append(destination)
                else:
                    logger.info(f"Upload to {destination} succeeded")
                    # Store sbom_id from sbomify for release tagging
                    if destination == "sbomify" and result.sbom_id:
                        sbom_id = result.sbom_id

            # Fail if any upload failed
            if failed_destinations:
                raise APIError(f"Upload failed for destination(s): {', '.join(failed_destinations)}")

            _log_step_end(5)

        except (APIError, FileProcessingError) as e:
            logger.error(f"Step 5 (upload) failed: {e}")
            _log_step_end(5, success=False)
            sys.exit(1)
    else:
        _log_step_header(5, "SBOM Upload - SKIPPED")
        logger.info("SBOM upload disabled (UPLOAD=false)")
        _log_step_end(5)

    # Step 6: Post-upload Processing (releases, signing, etc.)
    if sbom_id:
        _log_step_header(6, "Post-upload Processing")
        try:
            from sbomify_action._processors import ProcessorInput, ProcessorOrchestrator

            orchestrator = ProcessorOrchestrator(
                api_base_url=config.api_base_url,
                token=config.token,
            )
            processor_input = ProcessorInput(
                sbom_id=sbom_id,
                sbom_file=config.output_file,
                product_releases=config.product_releases,
                api_base_url=config.api_base_url,
                token=config.token,
            )

            # Check if any processors are enabled
            enabled_processors = orchestrator.get_enabled_processors(processor_input)
            if enabled_processors:
                logger.info(f"Running {len(enabled_processors)} processor(s): {enabled_processors}")
                results = orchestrator.process_all(processor_input)

                # Log results
                for result in results.enabled_processors:
                    if result.success:
                        logger.info(
                            f"Processor '{result.processor_name}' completed: {result.processed_items} item(s) processed"
                        )
                    else:
                        logger.error(f"Processor '{result.processor_name}' failed: {result.error_message}")

                if results.any_failures:
                    _log_step_end(6, success=False)
                else:
                    _log_step_end(6)
            else:
                logger.info("No processors enabled for this run")
                _log_step_end(6)
        except Exception as e:
            logger.error(f"Step 6 (post-upload processing) failed: {e}")
            _log_step_end(6, success=False)
            # Don't exit here - post-upload processing is optional
    elif config.product_releases and not sbom_id:
        _log_step_header(6, "Post-upload Processing - SKIPPED")
        logger.warning("Product releases specified but no SBOM ID available (upload may have been disabled or failed)")
        _log_step_end(6, success=False)

    # Print transformation summary for attestation (shows all SBOM modifications)
    print_transformation_summary()

    # Final success message
    print_final_success()


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


def _update_spdx_json_purl_version(package_json: dict, new_version: str) -> bool:
    """
    Update the version in an SPDX package's PURL external reference in JSON format.

    This function operates on the raw JSON dict, not the SPDX model objects,
    because it's used in the version override path which manipulates JSON directly.

    Args:
        package_json: The SPDX package dict with optional externalRefs
        new_version: The new version to set in the PURL

    Returns:
        True if PURL was updated, False if package has no PURL ref or update failed
    """
    from packageurl import PackageURL

    external_refs = package_json.get("externalRefs", [])
    for ref in external_refs:
        if ref.get("referenceType") == "purl":
            try:
                old_purl = PackageURL.from_string(ref.get("referenceLocator", ""))
                new_purl = PackageURL(
                    type=old_purl.type,
                    namespace=old_purl.namespace,
                    name=old_purl.name,
                    version=new_version,
                    qualifiers=old_purl.qualifiers,
                    subpath=old_purl.subpath,
                )
                ref["referenceLocator"] = str(new_purl)
                logger.debug(f"Updated SPDX package PURL version in JSON: {old_purl} -> {ref['referenceLocator']}")
                return True
            except Exception as e:
                logger.warning(f"Failed to update SPDX package PURL version in JSON: {e}")
                return False
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

            from ..augmentation import _update_component_purl_version

            if isinstance(parsed_object, Bom):
                # Apply version override to CycloneDX BOM object
                if hasattr(parsed_object.metadata, "component") and parsed_object.metadata.component:
                    parsed_object.metadata.component.version = config.component_version
                    # Also update the PURL version to maintain consistency
                    _update_component_purl_version(parsed_object.metadata.component, config.component_version)
                else:
                    # Create component if it doesn't exist
                    component_name = original_json.get("metadata", {}).get("component", {}).get("name", "unknown")
                    parsed_object.metadata.component = Component(
                        name=component_name, type=ComponentType.APPLICATION, version=config.component_version
                    )

                logger.info(f"Set component version from configuration: {config.component_version}")

                # Serialize the BOM back to JSON using version-aware serializer
                spec_version = original_json.get("specVersion")
                if spec_version is None:
                    raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")
                serialized = serialize_cyclonedx_bom(parsed_object, spec_version)
                with Path(sbom_file).open("w") as f:
                    f.write(serialized)

        elif sbom_format == "spdx":
            # For SPDX, apply version override to packages[0].versionInfo in JSON
            # Note: SPDX stores the root package in packages array, not metadata.component
            if "packages" in original_json and original_json["packages"]:
                main_package = original_json["packages"][0]
                main_package["versionInfo"] = config.component_version
                # Also update PURL in externalRefs if present
                _update_spdx_json_purl_version(main_package, config.component_version)
                logger.info(f"Set SPDX package version from configuration: {config.component_version}")
            else:
                logger.warning("SPDX SBOM has no packages - cannot set version override")

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
                needs_update = False
                if hasattr(parsed_object.metadata, "component") and parsed_object.metadata.component:
                    existing_name = parsed_object.metadata.component.name or "unknown"
                    if existing_name != config.component_name:
                        parsed_object.metadata.component.name = config.component_name
                        logger.info(f"Overriding component name: '{existing_name}' -> '{config.component_name}'")
                        needs_update = True
                else:
                    # Create component if it doesn't exist
                    component_version = original_json.get("metadata", {}).get("component", {}).get("version", "unknown")
                    parsed_object.metadata.component = Component(
                        name=config.component_name, type=ComponentType.APPLICATION, version=component_version
                    )
                    logger.info(
                        f"Overriding component name: 'none (creating new component)' -> '{config.component_name}'"
                    )
                    needs_update = True

                if needs_update:
                    # Serialize the BOM back to JSON using version-aware serializer
                    spec_version = original_json.get("specVersion")
                    if spec_version is None:
                        raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")
                    serialized = serialize_cyclonedx_bom(parsed_object, spec_version)
                    with Path(sbom_file).open("w") as f:
                        f.write(serialized)

        elif sbom_format == "spdx":
            # For SPDX, apply name override to the top-level "name" field
            existing_name = original_json.get("name", "unknown")
            if existing_name != config.component_name:
                original_json["name"] = config.component_name
                logger.info(f"Overriding SPDX component name: '{existing_name}' -> '{config.component_name}'")

                with Path(sbom_file).open("w") as f:
                    json.dump(original_json, f, indent=2)

    except Exception as e:
        logger.warning(f"Failed to apply component name override: {e}")
        # Don't fail the entire process for name override issues


def _apply_sbom_purl_override(sbom_file: str, config: "Config") -> None:
    """
    Apply component PURL override based on configuration.
    This function ensures that COMPONENT_PURL is applied regardless of augmentation settings.

    Args:
        sbom_file: Path to the SBOM file to modify
        config: Configuration with PURL override settings

    Raises:
        SBOMValidationError: If SBOM cannot be processed
        FileProcessingError: If file operations fail
    """
    if not config.component_purl:
        return  # No PURL override specified

    # Validate PURL format before applying
    try:
        from packageurl import PackageURL

        purl_obj = PackageURL.from_string(config.component_purl)
    except ValueError as e:
        logger.warning(
            f"Invalid COMPONENT_PURL '{config.component_purl}': {e}. Expected format: pkg:type/namespace/name@version"
        )
        return  # Skip invalid PURLs

    try:
        # Load SBOM from file
        sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_file)

        if sbom_format == "cyclonedx":
            from cyclonedx.model.bom import Bom
            from cyclonedx.model.component import Component, ComponentType

            if isinstance(parsed_object, Bom):
                # Apply PURL override to CycloneDX BOM object
                needs_update = False
                if hasattr(parsed_object.metadata, "component") and parsed_object.metadata.component:
                    existing_purl = (
                        str(parsed_object.metadata.component.purl) if parsed_object.metadata.component.purl else None
                    )
                    if existing_purl != config.component_purl:
                        parsed_object.metadata.component.purl = purl_obj
                        logger.info(
                            f"Overriding component PURL: '{existing_purl or 'none'}' -> '{config.component_purl}'"
                        )
                        needs_update = True
                else:
                    # Create component if it doesn't exist
                    component = original_json.get("metadata", {}).get("component", {})
                    component_name = component.get("name", "unknown")
                    component_version = component.get("version", "unknown")
                    parsed_object.metadata.component = Component(
                        name=component_name, type=ComponentType.APPLICATION, version=component_version, purl=purl_obj
                    )
                    logger.info(
                        f"Overriding component PURL: 'none (creating new component)' -> '{config.component_purl}'"
                    )
                    needs_update = True

                if needs_update:
                    # Serialize the BOM back to JSON using version-aware serializer
                    spec_version = original_json.get("specVersion")
                    if spec_version is None:
                        raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")
                    serialized = serialize_cyclonedx_bom(parsed_object, spec_version)
                    with Path(sbom_file).open("w") as f:
                        f.write(serialized)

        elif sbom_format == "spdx":
            # For SPDX, apply PURL override to external references of the main package
            packages = original_json.get("packages", [])
            if packages:
                main_package = packages[0]
                external_refs = main_package.get("externalRefs", [])

                # Find existing PURL reference
                existing_purl_ref = None
                existing_purl_idx = None
                for idx, ref in enumerate(external_refs):
                    if ref.get("referenceType") == "purl":
                        existing_purl_ref = ref
                        existing_purl_idx = idx
                        break

                if existing_purl_ref:
                    existing_purl = existing_purl_ref.get("referenceLocator", "unknown")
                    if existing_purl != config.component_purl:
                        external_refs[existing_purl_idx]["referenceLocator"] = config.component_purl
                        logger.info(f"Overriding SPDX component PURL: '{existing_purl}' -> '{config.component_purl}'")
                else:
                    # Add new PURL reference
                    # Determine category based on PURL type - containers aren't package-manager packages
                    purl_category = "PACKAGE-MANAGER"
                    if config.component_purl.startswith("pkg:docker/") or config.component_purl.startswith("pkg:oci/"):
                        purl_category = "OTHER"
                    new_purl_ref = {
                        "referenceCategory": purl_category,
                        "referenceType": "purl",
                        "referenceLocator": config.component_purl,
                    }
                    external_refs.append(new_purl_ref)
                    main_package["externalRefs"] = external_refs
                    logger.info(f"Adding SPDX component PURL: '{config.component_purl}'")

                with Path(sbom_file).open("w") as f:
                    json.dump(original_json, f, indent=2)
            else:
                logger.warning("SPDX SBOM has no packages - cannot set PURL override")

    except Exception as e:
        logger.warning(f"Failed to apply component PURL override: {e}")
        # Don't fail the entire process for PURL override issues


if __name__ == "__main__":
    main()
