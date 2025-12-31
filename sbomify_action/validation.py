"""SBOM validation using JSON schemas.

This module provides validation for generated and processed SBOMs against their
respective JSON schemas (CycloneDX and SPDX).

Usage:
    from sbomify_action.validation import validate_sbom_file, validate_sbom_file_auto

    # Validate with known format and version
    result = validate_sbom_file("sbom.json", "cyclonedx", "1.6")
    if result.valid is None:
        print(f"Validation skipped: {result.error_message}")
    elif not result.valid:
        print(f"Validation failed: {result.error_message}")

    # Auto-detect format and version
    result = validate_sbom_file_auto("sbom.json")
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional, Tuple

import jsonschema

from sbomify_action.logging_config import logger

# SBOM format type - matches _generation.protocol.SBOMFormat
SBOMFormat = Literal["cyclonedx", "spdx"]

# Path to schemas within the package directory
PACKAGE_DIR = Path(__file__).parent
CDX_SCHEMA_DIR = PACKAGE_DIR / "schemas" / "cyclonedx"
SPDX_SCHEMA_DIR = PACKAGE_DIR / "schemas" / "spdx"

# Schema file mappings
CDX_SCHEMAS = {
    "1.3": CDX_SCHEMA_DIR / "cdx-1.3.schema.json",
    "1.4": CDX_SCHEMA_DIR / "cdx-1.4.schema.json",
    "1.5": CDX_SCHEMA_DIR / "cdx-1.5.schema.json",
    "1.6": CDX_SCHEMA_DIR / "cdx-1.6.schema.json",
    "1.7": CDX_SCHEMA_DIR / "cdx-1.7.schema.json",
}

SPDX_SCHEMAS = {
    "2.2": SPDX_SCHEMA_DIR / "spdx-2.2.schema.json",
    "2.3": SPDX_SCHEMA_DIR / "spdx-2.3.schema.json",
}

# Cache for loaded schemas
_schema_cache: dict[str, dict] = {}


@dataclass
class ValidationResult:
    """Result of SBOM validation.

    The `valid` field has three states:
    - True: Validation passed
    - False: Validation failed
    - None: Validation was skipped (e.g., no schema available)
    """

    valid: Optional[bool]
    sbom_format: SBOMFormat
    spec_version: str
    error_message: Optional[str] = None
    error_path: Optional[str] = None

    @classmethod
    def success(cls, sbom_format: SBOMFormat, spec_version: str) -> "ValidationResult":
        """Create a successful validation result."""
        return cls(valid=True, sbom_format=sbom_format, spec_version=spec_version)

    @classmethod
    def failure(
        cls,
        sbom_format: SBOMFormat,
        spec_version: str,
        error_message: str,
        error_path: Optional[str] = None,
    ) -> "ValidationResult":
        """Create a failed validation result."""
        return cls(
            valid=False,
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=error_message,
            error_path=error_path,
        )

    @classmethod
    def skipped(cls, sbom_format: SBOMFormat, spec_version: str, reason: str) -> "ValidationResult":
        """Create a result indicating validation was skipped (schema not available)."""
        return cls(
            valid=None,
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=reason,
        )


def _load_schema(schema_path: Path) -> Optional[dict]:
    """Load a JSON schema from disk with caching."""
    cache_key = str(schema_path)
    if cache_key in _schema_cache:
        return _schema_cache[cache_key]

    if not schema_path.exists():
        logger.warning(f"Schema file not found: {schema_path}")
        return None

    with open(schema_path) as f:
        schema = json.load(f)
        _schema_cache[cache_key] = schema
        return schema


def get_schema_for_format(sbom_format: SBOMFormat, spec_version: str) -> Optional[dict]:
    """
    Get the JSON schema for a specific format and version.

    Args:
        sbom_format: The SBOM format ("cyclonedx" or "spdx")
        spec_version: The spec version (e.g., "1.6" or "2.3")

    Returns:
        The JSON schema dict, or None if not found
    """
    if sbom_format == "cyclonedx":
        schema_path = CDX_SCHEMAS.get(spec_version)
    elif sbom_format == "spdx":
        schema_path = SPDX_SCHEMAS.get(spec_version)
    else:
        return None

    if schema_path is None:
        return None

    return _load_schema(schema_path)


def validate_sbom_data(
    sbom_data: dict,
    sbom_format: SBOMFormat,
    spec_version: str,
) -> ValidationResult:
    """
    Validate SBOM data against its JSON schema.

    Args:
        sbom_data: The parsed SBOM JSON data
        sbom_format: The SBOM format ("cyclonedx" or "spdx")
        spec_version: The spec version (e.g., "1.6" or "2.3")

    Returns:
        ValidationResult with validation status and any errors
    """
    schema = get_schema_for_format(sbom_format, spec_version)

    if schema is None:
        # No schema available - skip validation but log warning
        reason = f"No schema available for {sbom_format} {spec_version}"
        logger.warning(f"{reason}, unable to validate SBOM")
        return ValidationResult.skipped(sbom_format, spec_version, reason)

    try:
        jsonschema.validate(instance=sbom_data, schema=schema)
        logger.info(f"SBOM validated successfully against {sbom_format} {spec_version} schema")
        return ValidationResult.success(sbom_format, spec_version)
    except jsonschema.ValidationError as e:
        error_path = ".".join(str(p) for p in e.absolute_path) if e.absolute_path else None
        logger.error(f"SBOM validation failed: {e.message}")
        if error_path:
            logger.error(f"Error at path: {error_path}")
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=e.message,
            error_path=error_path,
        )
    except jsonschema.SchemaError as e:
        logger.error(f"Invalid schema: {e.message}")
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=f"Invalid schema: {e.message}",
        )


def validate_sbom_file(
    file_path: str,
    sbom_format: SBOMFormat,
    spec_version: str,
) -> ValidationResult:
    """
    Validate an SBOM file against its JSON schema.

    Args:
        file_path: Path to the SBOM JSON file
        sbom_format: The SBOM format ("cyclonedx" or "spdx")
        spec_version: The spec version (e.g., "1.6" or "2.3")

    Returns:
        ValidationResult with validation status and any errors
    """
    path = Path(file_path)
    if not path.exists():
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=f"File not found: {file_path}",
        )

    try:
        with open(path) as f:
            sbom_data = json.load(f)
    except json.JSONDecodeError as e:
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version=spec_version,
            error_message=f"Invalid JSON: {e}",
        )

    return validate_sbom_data(sbom_data, sbom_format, spec_version)


def detect_sbom_format_and_version(sbom_data: dict) -> Tuple[Optional[SBOMFormat], Optional[str]]:
    """
    Detect the format and version of an SBOM from its data.

    Args:
        sbom_data: The parsed SBOM JSON data

    Returns:
        Tuple of (format, version) or (None, None) if unrecognized
    """
    # CycloneDX detection
    if "bomFormat" in sbom_data and sbom_data.get("bomFormat") == "CycloneDX":
        spec_version = sbom_data.get("specVersion")
        if spec_version:
            return "cyclonedx", spec_version
        return "cyclonedx", None

    # SPDX detection
    if "spdxVersion" in sbom_data:
        spdx_version = sbom_data.get("spdxVersion", "")
        # Extract version from "SPDX-2.3" format
        if spdx_version.startswith("SPDX-"):
            version = spdx_version[5:]  # Remove "SPDX-" prefix
            return "spdx", version
        return "spdx", None

    return None, None


def validate_sbom_file_auto(file_path: str) -> ValidationResult:
    """
    Validate an SBOM file, auto-detecting its format and version.

    Args:
        file_path: Path to the SBOM JSON file

    Returns:
        ValidationResult with validation status and any errors
    """
    path = Path(file_path)
    if not path.exists():
        return ValidationResult.failure(
            sbom_format="cyclonedx",  # Default for error reporting
            spec_version="unknown",
            error_message=f"File not found: {file_path}",
        )

    try:
        with open(path) as f:
            sbom_data = json.load(f)
    except json.JSONDecodeError as e:
        return ValidationResult.failure(
            sbom_format="cyclonedx",
            spec_version="unknown",
            error_message=f"Invalid JSON: {e}",
        )

    sbom_format, spec_version = detect_sbom_format_and_version(sbom_data)

    if sbom_format is None:
        return ValidationResult.failure(
            sbom_format="cyclonedx",
            spec_version="unknown",
            error_message="Could not detect SBOM format (not CycloneDX or SPDX)",
        )

    if spec_version is None:
        return ValidationResult.failure(
            sbom_format=sbom_format,
            spec_version="unknown",
            error_message=f"Could not detect {sbom_format} spec version",
        )

    return validate_sbom_data(sbom_data, sbom_format, spec_version)
