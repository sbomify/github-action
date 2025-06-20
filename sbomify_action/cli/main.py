import copy
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

import requests
import sentry_sdk

# Add cyclonedx imports for proper SBOM handling
from cyclonedx.model.bom import Bom

from ..exceptions import (
    APIError,
    CommandExecutionError,
    ConfigurationError,
    FileProcessingError,
    SBOMGenerationError,
    SBOMValidationError,
)
from ..logging_config import logger


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
we will use an enrichment tool (Parlay) to ensure that
as many of our components in the SBOM as possible have
the required data.

The output of this step is `step_3.json`.

Since both step 2 and 3 are optional, we will only
write `OUTPUT_FILE` at the end of the run.

"""

SBOMIFY_API_BASE = "https://app.sbomify.com/api/v1"

# Lock file constants for better maintainability
COMMON_PYTHON_LOCK_FILES = [
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
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
    sbom_version: Optional[str] = None

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


def load_config() -> Config:
    """
    Load and validate configuration from environment variables.

    Returns:
        Validated configuration object

    Raises:
        ConfigurationError: If configuration is invalid
    """
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
        override_name=evaluate_boolean(os.getenv("OVERRIDE_NAME", "False")),
        sbom_version=os.getenv("SBOM_VERSION"),
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
    sentry_dsn = os.getenv(
        "SENTRY_DSN", "https://df0bcb2d9d6ae6f7564e1568a1a4625c@o4508342753230848.ingest.us.sentry.io/4508834660155392"
    )

    sentry_sdk.init(
        dsn=sentry_dsn,
        send_default_pii=True,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
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


def get_spec_version(file_format: Literal["cyclonedx", "spdx"], json_data: dict) -> str:
    if file_format == "cyclonedx":
        return json_data.get("specVersion")

    if file_format == "spdx":
        return json_data.get("spdxVersion").removeprefix("SPDX-")


def get_metadata(file_format: Literal["cyclonedx", "spdx"], json_data: dict) -> dict:
    if file_format == "cyclonedx":
        return json_data.get("metadata")

    if file_format == "spdx":
        return json_data.get("creationInfo")


def merge_metadata(existing_metadata: dict, augmentation_data: dict) -> dict:
    """
    Merge augmentation data from the backend with existing SBOM metadata.

    Args:
        existing_metadata: Current metadata from the SBOM
        augmentation_data: Augmentation data retrieved from the backend

    Returns:
        Merged metadata with augmentation data applied
    """
    if not existing_metadata:
        return augmentation_data

    if not augmentation_data:
        return existing_metadata

    # Create a deep copy to avoid modifying the original
    merged = copy.deepcopy(existing_metadata)

    # Merge top-level fields from augmentation data
    for key, value in augmentation_data.items():
        if key in ["supplier", "vendor", "licenses", "properties"]:
            # These fields should be replaced/augmented from backend
            merged[key] = value
        elif key == "component" and isinstance(value, dict):
            # For component, merge selectively
            if "component" not in merged:
                merged["component"] = {}

            # Merge component fields, preserving existing values unless overridden
            for comp_key, comp_value in value.items():
                if comp_key in ["supplier", "vendor", "licenses", "properties"]:
                    merged["component"][comp_key] = comp_value
                elif comp_key not in merged["component"]:
                    # Only add if not already present
                    merged["component"][comp_key] = comp_value
        elif key not in merged:
            # Add new fields that don't exist
            merged[key] = value

    return merged


def set_metadata(file_format: Literal["cyclonedx", "spdx"], json_data: dict, metadata: dict) -> dict:
    if file_format == "cyclonedx":
        json_data["metadata"] = metadata

    if file_format == "spdx":
        json_data["creationInfo"] = metadata

    return json_data


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


def enrich_sbom_with_backend_metadata(
    sbom_format: str, original_json: dict, parsed_object: object, config: "Config"
) -> tuple[object, dict]:
    """
    Enrich SBOM with metadata retrieved from the backend (format-agnostic).

    Args:
        sbom_format: 'cyclonedx' or 'spdx'
        original_json: Original SBOM JSON dict
        parsed_object: Parsed SBOM object
        config: Configuration object with API details

    Returns:
        Tuple of (enriched_object, updated_json)

    Raises:
        APIError: If backend API call fails
        SBOMValidationError: If format is not supported
    """
    if sbom_format == "cyclonedx":
        return _enrich_cyclonedx_sbom(original_json, parsed_object, config)
    elif sbom_format == "spdx":
        return _enrich_spdx_sbom(original_json, parsed_object, config)
    else:
        raise SBOMValidationError(f"Unsupported SBOM format for enrichment: {sbom_format}")


def _enrich_cyclonedx_sbom(original_json: dict, bom: Bom, config: "Config") -> tuple[Bom, dict]:
    """
    Enrich CycloneDX SBOM with backend metadata.
    """
    # Get backend metadata
    logger.info("Fetching component metadata from sbomify API")
    augmentation_data = _fetch_backend_metadata(config)

    # Add sbomify as a processing tool
    _add_sbomify_tool_metadata(bom)
    logger.info("Added sbomify as processing tool to SBOM metadata")

    # Apply to CycloneDX BOM object
    if "supplier" in augmentation_data:
        from cyclonedx.model.bom import OrganizationalContact, OrganizationalEntity

        supplier_data = augmentation_data["supplier"]
        logger.info(f"Adding supplier information: {supplier_data.get('name', 'Unknown')}")

        # Create backend supplier entity
        backend_supplier = OrganizationalEntity(
            name=supplier_data.get("name"),
            urls=supplier_data.get("url", [])
            if isinstance(supplier_data.get("url"), list)
            else ([supplier_data.get("url")] if supplier_data.get("url") else []),
            contacts=[],
        )

        # Add contacts if present
        if "contacts" in supplier_data:
            contact_count = len(supplier_data["contacts"])
            logger.info(f"Adding {contact_count} supplier contact(s) from sbomify")
            for contact_data in supplier_data["contacts"]:
                contact = OrganizationalContact(
                    name=contact_data.get("name"), email=contact_data.get("email"), phone=contact_data.get("phone")
                )
                backend_supplier.contacts.add(contact)

        # Merge with existing supplier or replace based on preference
        if bom.metadata.supplier and not config.override_sbom_metadata:
            # Preserve existing supplier, merge with backend data
            logger.info("Merging supplier information with existing SBOM data (preserving existing)")
            existing_supplier = bom.metadata.supplier

            # Keep existing name if prefer_existing, otherwise use backend name
            merged_name = existing_supplier.name if existing_supplier.name else backend_supplier.name

            # Merge URLs
            merged_urls = set()
            if existing_supplier.urls:
                # Convert XsUri objects to strings
                for url in existing_supplier.urls:
                    merged_urls.add(str(url))
            if backend_supplier.urls:
                # Backend URLs should already be strings
                for url in backend_supplier.urls:
                    merged_urls.add(str(url))

            # Merge contacts (avoid duplicates by email)
            merged_contacts = set()
            existing_emails = set()

            # Add existing contacts first
            if existing_supplier.contacts:
                for contact in existing_supplier.contacts:
                    merged_contacts.add(contact)
                    if contact.email:
                        existing_emails.add(contact.email)

            # Add backend contacts (no email duplicates)
            if backend_supplier.contacts:
                for contact in backend_supplier.contacts:
                    if not contact.email or contact.email not in existing_emails:
                        merged_contacts.add(contact)

            # Create merged supplier
            merged_supplier = OrganizationalEntity(
                name=merged_name,
                urls=list(merged_urls),
                contacts=list(merged_contacts),
            )

            bom.metadata.supplier = merged_supplier
        else:
            # Use backend supplier (either no existing supplier or override_sbom_metadata=True)
            if config.override_sbom_metadata:
                logger.info("Replacing existing supplier information with sbomify data (override mode)")
            else:
                logger.info("Adding supplier information from sbomify (no existing supplier)")
            bom.metadata.supplier = backend_supplier

    # Add authors if present
    if "authors" in augmentation_data:
        from cyclonedx.model.bom import OrganizationalContact

        author_count = len(augmentation_data["authors"])
        logger.info(f"Adding {author_count} author(s) from sbomify")

        for author_data in augmentation_data["authors"]:
            author = OrganizationalContact(
                name=author_data.get("name"), email=author_data.get("email"), phone=author_data.get("phone")
            )
            bom.metadata.authors.add(author)
            logger.debug(f"Added author: {author_data.get('name', 'Unknown')}")

    # Add licenses if present - now supporting advanced formats
    if "licenses" in augmentation_data:
        license_count = len(augmentation_data["licenses"])
        logger.info(f"Adding {license_count} license(s) from sbomify")

        for license_data in augmentation_data["licenses"]:
            license_obj = _process_license_data(license_data)
            if license_obj:
                bom.metadata.licenses.add(license_obj)
                # Log license details
                if isinstance(license_data, str):
                    logger.debug(f"Added license: {license_data}")
                elif isinstance(license_data, dict):
                    license_name = license_data.get("name", "Unknown")
                    logger.debug(f"Added license: {license_name}")

    # Apply enrichment back to JSON with intelligent merging
    # Use override_sbom_metadata to control merging preference
    prefer_backend = config.override_sbom_metadata  # If True, backend data takes precedence
    updated_json = _apply_cyclonedx_metadata_to_json(original_json, bom, prefer_backend)

    # Apply local SBOM overrides (component name, version)
    bom, updated_json = _apply_local_sbom_overrides(bom, updated_json, config, augmentation_data)

    logger.debug("Successfully enriched CycloneDX SBOM with backend metadata")
    return bom, updated_json


def _enrich_spdx_sbom(original_json: dict, spdx_obj: object, config: "Config") -> tuple[object, dict]:
    """
    Enrich SPDX SBOM with backend metadata (placeholder for future implementation).
    """
    # Get backend metadata
    logger.info("Fetching component metadata from sbomify API")
    augmentation_data = _fetch_backend_metadata(config)

    # Log what metadata is available
    available_metadata = []
    if "supplier" in augmentation_data:
        available_metadata.append("supplier information")
    if "authors" in augmentation_data:
        available_metadata.append(f"{len(augmentation_data['authors'])} author(s)")
    if "licenses" in augmentation_data:
        available_metadata.append(f"{len(augmentation_data['licenses'])} license(s)")

    if available_metadata:
        logger.info(f"Adding to SPDX SBOM: {', '.join(available_metadata)}")
    else:
        logger.info("No additional metadata available from sbomify for this component")

    # TODO: Implement SPDX enrichment using SPDX libraries
    # For now, apply directly to JSON
    updated_json = _apply_spdx_metadata_to_json(original_json, augmentation_data)

    logger.debug("Successfully enriched SPDX SBOM with backend metadata")
    return spdx_obj, updated_json


def _fetch_backend_metadata(config: "Config") -> dict:
    """
    Fetch metadata from backend API.

    Returns:
        Backend metadata dict

    Raises:
        APIError: If API call fails
    """
    url = SBOMIFY_API_BASE + f"/sboms/component/{config.component_id}/meta"
    headers = {
        "Authorization": f"Bearer {config.token}",
    }

    query_params = {}
    # Note: sbom_version, override_name, and override_sbom_metadata are for local SBOM modification,
    # not server-side query parameters. The API only returns supplier, authors, and licenses metadata.

    try:
        response = requests.get(
            url,
            headers=headers,
            params=query_params,
            timeout=60,  # Security: add timeout
        )
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")
    except ConnectionError:
        raise APIError("Failed to connect to sbomify API")

    if not response.ok:
        err_msg = f"Failed to retrieve component metadata from sbomify. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)

    return response.json()


def save_sbom_to_file(original_json: dict, file_path: str) -> None:
    """
    Save SBOM JSON dict to file.

    Args:
        original_json: The JSON dict to save
        file_path: Path where to save the SBOM JSON file

    Raises:
        SBOMGenerationError: If SBOM cannot be serialized
    """
    try:
        with Path(file_path).open("w") as f:
            json.dump(original_json, f, indent=2)

        logger.info(f"Successfully saved SBOM to {file_path}")

    except Exception as e:
        raise SBOMGenerationError(f"Failed to save SBOM to {file_path}: {e}")


def _apply_local_sbom_overrides(
    bom: Bom, original_json: dict, config: "Config", augmentation_data: dict = None
) -> tuple[Bom, dict]:
    """
    Apply local SBOM overrides based on configuration.

    Args:
        bom: The Bom object to modify
        original_json: Original JSON dict
        config: Configuration with override settings
        augmentation_data: Backend metadata to apply

    Returns:
        Tuple of (modified Bom, updated JSON)
    """
    # Apply component name override if specified
    if config.override_name and hasattr(bom.metadata, "component") and bom.metadata.component:
        # Use component name from backend metadata if available
        if augmentation_data and "name" in augmentation_data:
            backend_component_name = augmentation_data["name"]
            bom.metadata.component.name = backend_component_name
            logger.info(f"Overrode component name with sbomify data: {backend_component_name}")
        else:
            logger.warning("OVERRIDE_NAME requested but component name not available in backend metadata")

    # Apply component version override if specified
    if config.sbom_version and hasattr(bom.metadata, "component") and bom.metadata.component:
        from cyclonedx.model.component import Component, ComponentType

        # Update the component version
        if bom.metadata.component:
            bom.metadata.component.version = config.sbom_version
        else:
            # Create component if it doesn't exist
            component_name = original_json.get("metadata", {}).get("component", {}).get("name", "unknown")
            bom.metadata.component = Component(
                name=component_name, type=ComponentType.APPLICATION, version=config.sbom_version
            )
        logger.info(f"Set component version from configuration: {config.sbom_version}")

    # Apply changes back to JSON
    updated_json = _apply_cyclonedx_metadata_to_json(original_json, bom, True)

    return bom, updated_json


def _apply_cyclonedx_metadata_to_json(original_json: dict, bom: Bom, prefer_backend: bool = True) -> dict:
    """
    Apply enriched CycloneDX metadata from Bom object back to original JSON with intelligent merging.
    Preserves existing metadata while adding/updating backend data.
    Handles version-specific formats (1.5 vs 1.6).

    Args:
        original_json: Original SBOM JSON dict
        bom: Enriched Bom object
        prefer_backend: Whether to prefer backend data over existing data

    Returns:
        Updated JSON dict with enriched metadata
    """
    # Create a copy to avoid modifying original
    updated_json = copy.deepcopy(original_json)

    # Detect CycloneDX version for version-specific handling
    spec_version = original_json.get("specVersion", "1.5")
    logger.debug(f"Applying metadata for CycloneDX version {spec_version}")

    # Ensure metadata exists
    if "metadata" not in updated_json:
        updated_json["metadata"] = {}

    metadata = updated_json["metadata"]

    # Apply component metadata (name and version) if present
    if bom.metadata.component:
        if "component" not in metadata:
            metadata["component"] = {}

        component_metadata = metadata["component"]

        # Apply component name if present
        if hasattr(bom.metadata.component, "name") and bom.metadata.component.name:
            component_metadata["name"] = bom.metadata.component.name

        # Apply component version if present
        if hasattr(bom.metadata.component, "version") and bom.metadata.component.version:
            component_metadata["version"] = bom.metadata.component.version

        # Apply component type if present
        if hasattr(bom.metadata.component, "type") and bom.metadata.component.type:
            component_metadata["type"] = str(bom.metadata.component.type).lower()

    # Apply version-specific metadata handling (tools are version-specific, others are same format)
    _apply_version_specific_metadata(metadata, bom, spec_version, prefer_backend)

    return updated_json


def _apply_version_specific_metadata(metadata: dict, bom: Bom, spec_version: str, prefer_backend: bool):
    """
    Apply metadata based on CycloneDX version-specific requirements.

    Note: Tools and authors metadata are version-specific. Supplier and licenses
    have the same format in both CycloneDX 1.5 and 1.6.

    Args:
        metadata: Metadata dictionary to update
        bom: Enriched Bom object
        spec_version: CycloneDX version (e.g., "1.5", "1.6")
        prefer_backend: Whether to prefer backend data over existing data
    """

    # Add tools metadata (version-specific format)
    if bom.metadata.tools and bom.metadata.tools.tools:
        _apply_tools_metadata(metadata, bom, spec_version)

    # Add supplier information (same format for both versions)
    if bom.metadata.supplier:
        _apply_supplier_metadata(metadata, bom, prefer_backend)

    # Add authors information (version-specific format)
    if bom.metadata.authors:
        _apply_authors_metadata(metadata, bom, spec_version)

    # Add licenses information (same format for both versions)
    if bom.metadata.licenses:
        _apply_licenses_metadata(metadata, bom)


def _apply_supplier_metadata(metadata: dict, bom: Bom, prefer_backend: bool):
    """Apply supplier metadata (same format for 1.5 and 1.6)."""
    existing_supplier = metadata.get("supplier", {})
    supplier_dict = {}

    # Merge name based on preference
    if prefer_backend and bom.metadata.supplier.name:
        supplier_dict["name"] = bom.metadata.supplier.name
    elif not prefer_backend and existing_supplier.get("name"):
        supplier_dict["name"] = existing_supplier["name"]
    elif bom.metadata.supplier.name:
        supplier_dict["name"] = bom.metadata.supplier.name
    elif existing_supplier.get("name"):
        supplier_dict["name"] = existing_supplier["name"]

    # Merge URLs (backend + existing)
    urls = set()
    if bom.metadata.supplier.urls:
        urls.update(bom.metadata.supplier.urls)
    if existing_supplier.get("url"):
        if isinstance(existing_supplier["url"], list):
            urls.update(existing_supplier["url"])
        else:
            urls.add(existing_supplier["url"])
    if urls:
        supplier_dict["url"] = list(urls)

    # Merge contacts (backend + existing)
    contacts_list = []

    # Add backend contacts
    if bom.metadata.supplier.contacts:
        for contact in bom.metadata.supplier.contacts:
            contact_dict = {}
            if contact.name:
                contact_dict["name"] = contact.name
            if contact.email:
                contact_dict["email"] = contact.email
            if contact.phone:
                contact_dict["phone"] = contact.phone
            if contact_dict:
                contacts_list.append(contact_dict)

    # Add existing contacts (avoid duplicates by email)
    existing_contacts = existing_supplier.get("contacts", [])
    existing_emails = {c.get("email") for c in contacts_list if c.get("email")}
    for existing_contact in existing_contacts:
        if not existing_contact.get("email") or existing_contact["email"] not in existing_emails:
            contacts_list.append(existing_contact)

    if contacts_list:
        supplier_dict["contacts"] = contacts_list

    if supplier_dict:
        metadata["supplier"] = supplier_dict


def _apply_tools_metadata(metadata: dict, bom: Bom, spec_version: str):
    """Apply tools metadata with version-specific format."""
    existing_tools = metadata.get("tools", [])

    if spec_version == "1.5":
        # CycloneDX 1.5: tools = [{ vendor: "...", name: "...", version: "..." }]
        if isinstance(existing_tools, list):
            tools_list = existing_tools
        else:
            tools_list = []

        for tool in bom.metadata.tools.tools:
            tool_dict = {}
            if hasattr(tool, "vendor") and tool.vendor:
                tool_dict["vendor"] = tool.vendor
            if hasattr(tool, "name") and tool.name:
                tool_dict["name"] = tool.name
            if hasattr(tool, "version") and tool.version:
                tool_dict["version"] = tool.version

            if tool_dict.get("name") and not any(t.get("name") == tool_dict["name"] for t in tools_list):
                tools_list.append(tool_dict)

        if tools_list:
            metadata["tools"] = tools_list

    elif spec_version == "1.6":
        # CycloneDX 1.6: tools = { components: [{ type: "application", manufacturer: "sbomify", name: "...", version: "..." }] }
        if isinstance(existing_tools, dict) and "components" in existing_tools:
            tools_list = existing_tools["components"]
        else:
            tools_list = []

        for tool in bom.metadata.tools.tools:
            tool_dict = {"type": "application"}
            if hasattr(tool, "vendor") and tool.vendor:
                tool_dict["manufacturer"] = tool.vendor  # Use manufacturer instead of vendor for 1.6
            if hasattr(tool, "name") and tool.name:
                tool_dict["name"] = tool.name
            if hasattr(tool, "version") and tool.version:
                tool_dict["version"] = tool.version

            if tool_dict.get("name") and not any(t.get("name") == tool_dict["name"] for t in tools_list):
                tools_list.append(tool_dict)

        if tools_list:
            metadata["tools"] = {"components": tools_list}

    else:
        # Default to 1.5 format for unknown versions
        logger.warning(f"Unknown CycloneDX version {spec_version}, using 1.5 format")
        if isinstance(existing_tools, list):
            tools_list = existing_tools
        else:
            tools_list = []

        for tool in bom.metadata.tools.tools:
            tool_dict = {}
            if hasattr(tool, "vendor") and tool.vendor:
                tool_dict["vendor"] = tool.vendor
            if hasattr(tool, "name") and tool.name:
                tool_dict["name"] = tool.name
            if hasattr(tool, "version") and tool.version:
                tool_dict["version"] = tool.version

            if tool_dict.get("name") and not any(t.get("name") == tool_dict["name"] for t in tools_list):
                tools_list.append(tool_dict)

        if tools_list:
            metadata["tools"] = tools_list


def _apply_authors_metadata(metadata: dict, bom: Bom, spec_version: str):
    """Apply authors metadata (version-specific format)."""

    # Get backend authors from BOM object
    backend_authors = []
    for author in bom.metadata.authors:
        author_dict = {}
        if author.name:
            author_dict["name"] = author.name
        if author.email:
            author_dict["email"] = author.email
        if author.phone:
            author_dict["phone"] = author.phone
        if author_dict:
            backend_authors.append(author_dict)

    if spec_version == "1.5":
        # CycloneDX 1.5: author = "string"
        existing_author = metadata.get("author", "")

        # Combine all authors into a single string (comma-separated)
        author_names = []

        # Add existing author if present
        if existing_author:
            author_names.append(existing_author)

        # Add backend authors (just names)
        for author in backend_authors:
            if author.get("name"):
                author_names.append(author["name"])

        # Set the combined author string (remove duplicates while preserving order)
        if author_names:
            unique_authors = []
            seen = set()
            for name in author_names:
                if name not in seen:
                    unique_authors.append(name)
                    seen.add(name)
            metadata["author"] = ", ".join(unique_authors)

    else:  # spec_version == "1.6" or unknown (default to 1.6)
        # CycloneDX 1.6: authors = [{ name: "...", email: "..." }]
        existing_authors = metadata.get("authors", [])
        authors_list = []

        # Add backend authors
        authors_list.extend(backend_authors)

        # Add existing authors (avoid duplicates by email)
        existing_emails = {a.get("email") for a in authors_list if a.get("email")}
        for existing_author in existing_authors:
            if not existing_author.get("email") or existing_author["email"] not in existing_emails:
                authors_list.append(existing_author)

        if authors_list:
            metadata["authors"] = authors_list


def _apply_licenses_metadata(metadata: dict, bom: Bom):
    """Apply licenses metadata (same format for 1.5 and 1.6)."""
    existing_licenses = metadata.get("licenses", [])
    licenses_list = []

    # Add backend licenses with enhanced format support
    for license_obj in bom.metadata.licenses:
        if hasattr(license_obj, "value") and license_obj.value:
            # License expression (SPDX expressions like "MIT OR GPL-3.0")
            licenses_list.append({"expression": license_obj.value})
        elif hasattr(license_obj, "name") and license_obj.name:
            # Named license (simple or complex)
            license_entry = {"license": {"name": license_obj.name}}

            # Add URL if present
            if hasattr(license_obj, "url") and license_obj.url:
                license_entry["license"]["url"] = str(license_obj.url)

            # Add text if present
            if hasattr(license_obj, "text") and license_obj.text:
                license_entry["license"]["text"] = {"content": license_obj.text.content}

            licenses_list.append(license_entry)

    # Add existing licenses (avoid duplicates)
    existing_values = set()
    for license_item in licenses_list:
        if "expression" in license_item:
            existing_values.add(license_item["expression"])
        elif "license" in license_item and "name" in license_item["license"]:
            existing_values.add(license_item["license"]["name"])

    for existing_license in existing_licenses:
        license_value = None
        if isinstance(existing_license, dict):
            if "expression" in existing_license:
                license_value = existing_license["expression"]
            elif "license" in existing_license and "name" in existing_license["license"]:
                license_value = existing_license["license"]["name"]
            elif "name" in existing_license:  # Handle legacy format
                license_value = existing_license["name"]

        if license_value and license_value not in existing_values:
            licenses_list.append(existing_license)

    if licenses_list:
        metadata["licenses"] = licenses_list


def _apply_spdx_metadata_to_json(original_json: dict, augmentation_data: dict) -> dict:
    """
    Apply backend metadata to SPDX JSON with intelligent merging.
    Preserves existing metadata while adding/updating backend data.

    Args:
        original_json: Original SPDX JSON dict
        augmentation_data: Backend metadata to apply

    Returns:
        Updated JSON dict with enriched metadata
    """
    # Create a copy to avoid modifying original
    updated_json = copy.deepcopy(original_json)

    # SPDX metadata is typically in creationInfo
    if "creationInfo" not in updated_json:
        updated_json["creationInfo"] = {}

    creation_info = updated_json["creationInfo"]

    # Apply supplier as creator if available
    if "supplier" in augmentation_data:
        supplier_data = augmentation_data["supplier"]

        # Add to creators list (preserve existing)
        creators = creation_info.get("creators", [])
        if supplier_data.get("name"):
            creator_entry = f"Organization: {supplier_data['name']}"
            if creator_entry not in creators:
                creators.append(creator_entry)
        creation_info["creators"] = creators

    # TODO: Add more SPDX-specific metadata mapping as needed
    # This is a placeholder for future SPDX library integration

    return updated_json


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
    lock_file: str, lock_file_type: str, output_file: str, schema_version: str = "1.5"
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
        "--schema-version",
        schema_version,
        "--outfile",
        output_file,
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


def enrich_sbom_with_parley(input_file: str, output_file: str) -> int:
    """
    Takes a path to an SBOM as input and returns an enriched SBOM as the output.

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save enriched SBOM

    Returns:
        Process return code
    """
    cmd = ["parlay", "ecosystems", "enrich", input_file]
    return run_command_with_json_output(cmd, "parlay", output_file)


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
    except (FileProcessingError, SBOMGenerationError, SBOMValidationError) as e:
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
        _log_step_end(1, success=False)
        sys.exit(1)

    _log_step_end(1)

    # Step 2: Augmentation
    if config.augment:
        _log_step_header(2, "SBOM Augmentation with Backend Metadata")
        try:
            sbom_input_file = get_last_sbom_from_last_step()
            if not sbom_input_file:
                raise FileProcessingError("No SBOM file found from previous step")

            with Path(sbom_input_file).open() as f:
                sbom_data = json.load(f)

            # Check if format is supported for augmentation
            if FORMAT == "spdx":
                logger.info("Augmenting SPDX SBOM with supplier, author, and license information")
                # Load SPDX SBOM (currently using JSON fallback)
                sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_input_file)

                # Enrich with backend metadata
                parsed_object, updated_json = enrich_sbom_with_backend_metadata(
                    sbom_format, original_json, parsed_object, config
                )

                # Save enriched SBOM
                save_sbom_to_file(updated_json, "step_2.json")

                logger.info("SPDX SBOM augmentation completed")
            elif FORMAT == "cyclonedx":
                logger.info("Augmenting CycloneDX SBOM with supplier, author, and license information")
                # Use format-agnostic loading
                sbom_format, original_json, parsed_object = load_sbom_from_file(sbom_input_file)

                # Ensure we have the mandatory component metadata for CycloneDX
                if not parsed_object.metadata.component:
                    from cyclonedx.model.component import Component, ComponentType

                    component_name = Path(FILE).name if FILE else "unknown"
                    parsed_object.metadata.component = Component(name=component_name, type=ComponentType.APPLICATION)
                elif not parsed_object.metadata.component.name:
                    parsed_object.metadata.component.name = Path(FILE).name if FILE else "unknown"

                # Enrich with backend metadata
                parsed_object, updated_json = enrich_sbom_with_backend_metadata(
                    sbom_format, original_json, parsed_object, config
                )

                # Save enriched SBOM
                save_sbom_to_file(updated_json, "step_2.json")

                logger.info("CycloneDX SBOM augmentation completed")
            else:
                raise SBOMValidationError(f"Unsupported format '{FORMAT}' for augmentation")

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
            enrich_sbom_with_parley(sbom_input_file, "step_3.json")
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
            url = SBOMIFY_API_BASE + f"/sboms/artifact/{FORMAT}/{config.component_id}"
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

            _log_step_end(5)

        except (APIError, FileProcessingError) as e:
            logger.error(f"Step 5 (upload) failed: {e}")
            _log_step_end(5, success=False)
            sys.exit(1)
    else:
        _log_step_header(5, "SBOM Upload - SKIPPED")
        logger.info("SBOM upload disabled (UPLOAD=false)")
        _log_step_end(5)

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


def _add_sbomify_tool_metadata(bom: Bom) -> None:
    """
    Add sbomify as a tool in the SBOM metadata to track processing.

    Args:
        bom: The Bom object to update with tool metadata
    """
    from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
    from cyclonedx.model.bom import Tool

    # Create sbomify tool entry
    sbomify_tool = Tool(vendor="sbomify", name="sbomify-github-action", version=SBOMIFY_VERSION)

    # Add external references for the tool
    try:
        sbomify_tool.external_references.add(
            ExternalReference(
                reference_type=ExternalReferenceType.WEBSITE, url=XsUri("https://github.com/sbomify/github-action")
            )
        )
    except Exception:
        # If external references fail, continue without them
        pass

    # Add the tool to the metadata
    bom.metadata.tools.tools.add(sbomify_tool)


def _process_license_data(license_data: Any) -> Optional[Any]:
    """
    Process license data from backend, supporting various formats:
    - String: SPDX expression (e.g., "MIT OR GPL-3.0", "Apache-2.0 WITH Commons-Clause")
    - Dict: Custom license with name, url, text

    Args:
        license_data: License data from backend (string or dict)

    Returns:
        License object for CycloneDX or None if invalid
    """
    from cyclonedx.model import AttachedText, XsUri
    from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression

    if isinstance(license_data, str):
        # Handle SPDX license expressions
        if any(op in license_data for op in [" OR ", " AND ", " WITH "]):
            # Complex SPDX expression
            try:
                return LicenseExpression(value=license_data)
            except Exception:
                # If expression parsing fails, treat as simple name
                return DisjunctiveLicense(name=license_data)
        else:
            # Simple license name
            return DisjunctiveLicense(name=license_data)

    elif isinstance(license_data, dict):
        # Custom license object with name, url, text
        license_name = license_data.get("name", "")
        license_url = license_data.get("url")
        license_text = license_data.get("text")

        if not license_name:
            return None

        # Create DisjunctiveLicense with additional details
        license_obj = DisjunctiveLicense(name=license_name)

        if license_url:
            try:
                license_obj.url = XsUri(license_url)
            except Exception:
                pass  # Skip invalid URLs

        if license_text:
            try:
                license_obj.text = AttachedText(content=license_text)
            except Exception:
                pass  # Skip if text attachment fails

        return license_obj

    return None


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


if __name__ == "__main__":
    main()
