import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

import requests
import sentry_sdk

from ..exceptions import (
    APIError,
    ConfigurationError,
    FileProcessingError,
    SBOMGenerationError,
    SBOMValidationError,
)
from ..logging_config import logger

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
    Validate SBOM file and detect format.

    Args:
        file_path: Path to SBOM file

    Returns:
        SBOM format ('cyclonedx' or 'spdx')

    Raises:
        SBOMValidationError: If SBOM is invalid or format is unsupported
    """
    try:
        with Path(file_path).open() as f:
            data = json.load(f)
    except json.JSONDecodeError:
        raise SBOMValidationError("Invalid JSON format")
    except FileNotFoundError:
        raise SBOMValidationError(f"SBOM file not found: {file_path}")

    # Detect artifact type
    if data.get("bomFormat") == "CycloneDX":
        logger.info("Detected CycloneDX SBOM.")
        return "cyclonedx"
    elif data.get("spdxVersion") is not None:
        logger.info("Detected SPDX SBOM.")
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


def set_metadata(file_format: Literal["cyclonedx", "spdx"], json_data: dict, metadata: dict) -> dict:
    if file_format == "cyclonedx":
        json_data["metadata"] = metadata

    if file_format == "spdx":
        json_data["creationInfo"] = metadata

    return json_data


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
    logger.info("Starting SBOM processing workflow")

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
            FORMAT = validate_sbom(FILE)
            shutil.copy(FILE, "step_1.json")
        elif config.docker_image:
            logger.info("Detected Docker Image as input")
            run_trivy_docker_image(docker_image=config.docker_image, output_file="step_1.json")
        elif FILE_TYPE == "LOCK_FILE":
            process_lock_file(FILE)
        else:
            logger.error("Unrecognized FILE_TYPE.")
            sys.exit(1)
    except (FileProcessingError, SBOMGenerationError, SBOMValidationError) as e:
        logger.error(f"Step 1 failed: {e}")
        sys.exit(1)

    # Set the SBOM format based on the output
    try:
        FORMAT = validate_sbom("step_1.json")
    except SBOMValidationError as e:
        logger.error(f"Generated SBOM validation failed: {e}")
        sys.exit(1)

    # Step 2: Augmentation
    if config.augment:
        logger.info("Starting SBOM augmentation")
        try:
            sbom_input_file = get_last_sbom_from_last_step()
            if not sbom_input_file:
                raise FileProcessingError("No SBOM file found from previous step")

            with Path(sbom_input_file).open() as f:
                sbom_data = json.load(f)

            # Check if format is supported for augmentation
            if FORMAT == "spdx":
                logger.warning("SBOM augmentation is not supported for SPDX format. Skipping augmentation.")
                logger.info("Only CycloneDX format is supported for metadata augmentation.")
            elif FORMAT == "cyclonedx":
                # Make sure we have the mandatory fields
                # Ensure 'metadata' and 'component' keys exist in sbom_data
                metadata = sbom_data.get("metadata", {})
                component = metadata.get("component", {})

                # Check if 'name' and 'type' are missing, and add them if necessary
                if "name" not in component:
                    component["name"] = Path(FILE).name if FILE else "unknown"

                # Default this to "application" if nothing is set
                if "type" not in component:
                    component["type"] = "application"

                # Update the main sbom_data dictionary
                sbom_data["metadata"]["component"] = component

                # Get format version from sbom_file
                SPEC_VERSION = get_spec_version(FORMAT, sbom_data)
                sbom_metadata = get_metadata(FORMAT, sbom_data)

                # Updated URL structure for v0.12+
                url = SBOMIFY_API_BASE + f"/sboms/artifact/cyclonedx/{SPEC_VERSION}/{config.component_id}/metadata"
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {config.token}",
                }

                query_params = {}

                if config.sbom_version:
                    query_params["sbom_version"] = config.sbom_version

                if config.override_name:
                    query_params["override_name"] = True

                if config.override_sbom_metadata:
                    query_params["override_metadata"] = True

                try:
                    response = requests.post(
                        url,
                        headers=headers,
                        json=sbom_metadata,
                        params=query_params,
                        timeout=60,  # Security: add timeout
                    )
                except requests.exceptions.ConnectionError:
                    raise APIError("Failed to connect to sbomify API")
                except requests.exceptions.Timeout:
                    raise APIError("API request timed out")

                if not response.ok:
                    err_msg = f"Failed to augment SBOM file via sbomify. [{response.status_code}]"
                    if response.headers.get("content-type") == "application/json":
                        try:
                            error_data = response.json()
                            if "detail" in error_data:
                                err_msg += f" - {error_data['detail']}"
                        except (ValueError, KeyError):
                            pass

                    raise APIError(err_msg)

                set_metadata(FORMAT, sbom_data, response.json())
                with Path("step_2.json").open("w") as f:
                    json.dump(sbom_data, f)

                logger.info("SBOM file augmented successfully.")
            else:
                raise SBOMValidationError(f"Unsupported format '{FORMAT}' for augmentation")

        except (FileProcessingError, APIError, SBOMValidationError) as e:
            logger.error(f"Step 2 (augmentation) failed: {e}")
            sys.exit(1)

    # Step 3: Enrichment
    if config.enrich:
        logger.info("Starting SBOM enrichment")
        try:
            sbom_input_file = get_last_sbom_from_last_step()
            if not sbom_input_file:
                raise FileProcessingError("No SBOM file found from previous step")

            enrich_sbom_with_parley(sbom_input_file, "step_3.json")
            validate_sbom("step_3.json")
        except (FileProcessingError, SBOMGenerationError, SBOMValidationError) as e:
            logger.error(f"Step 3 (enrichment) failed: {e}")
            sys.exit(1)

    # Finalize output
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

        logger.info(f"SBOM processing completed. Output saved to: {config.output_file}")

    except (FileProcessingError, OSError) as e:
        logger.error(f"Failed to finalize output: {e}")
        sys.exit(1)

    # Upload if requested
    if config.upload:
        logger.info("Starting SBOM upload")
        try:
            # Execute the POST request to upload the SBOM file
            url = SBOMIFY_API_BASE + f"/sboms/artifact/{FORMAT}/{config.component_id}"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {config.token}",
            }

            with Path(config.output_file).open() as f:
                sbom_data = f.read()

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
                logger.info("SBOM file uploaded successfully.")

        except (APIError, FileProcessingError) as e:
            logger.error(f"Upload failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
