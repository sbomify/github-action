"""
SBOM serialization utilities for version-aware output.

This module provides centralized serialization functions for both CycloneDX and SPDX
formats, supporting multiple versions and making it easy to add new versions in the future.
"""

from typing import Dict, Optional, Type

from cyclonedx.model.bom import Bom
from spdx_tools.spdx.model import Document

from .logging_config import logger

# ============================================================================
# CycloneDX Version Management
# ============================================================================

# Lazy imports to avoid loading all versions upfront
_CYCLONEDX_OUTPUTTERS: Dict[str, Optional[Type]] = {
    "1.4": None,  # JsonV1Dot4
    "1.5": None,  # JsonV1Dot5
    "1.6": None,  # JsonV1Dot6
    # Add new versions here as they become available:
    # "1.7": None,  # JsonV1Dot7
    # "2.0": None,  # JsonV2Dot0
}

# Default version to use when version cannot be detected
DEFAULT_CYCLONEDX_VERSION = "1.6"


def _get_cyclonedx_outputter(spec_version: str) -> Type:
    """
    Get the appropriate CycloneDX outputter class for a given spec version.

    Uses lazy loading to only import the outputter classes that are actually needed.

    Args:
        spec_version: CycloneDX spec version (e.g., "1.5", "1.6", "1.7", "2.0")

    Returns:
        Outputter class for the specified version

    Raises:
        ValueError: If version is not supported
    """
    # Normalize version to major.minor format
    if spec_version:
        major_minor = ".".join(spec_version.split(".")[:2])
    else:
        major_minor = DEFAULT_CYCLONEDX_VERSION

    # Lazy load the outputter class if not already loaded
    if major_minor in _CYCLONEDX_OUTPUTTERS and _CYCLONEDX_OUTPUTTERS[major_minor] is None:
        try:
            if major_minor == "1.4":
                from cyclonedx.output.json import JsonV1Dot4

                _CYCLONEDX_OUTPUTTERS["1.4"] = JsonV1Dot4
            elif major_minor == "1.5":
                from cyclonedx.output.json import JsonV1Dot5

                _CYCLONEDX_OUTPUTTERS["1.5"] = JsonV1Dot5
            elif major_minor == "1.6":
                from cyclonedx.output.json import JsonV1Dot6

                _CYCLONEDX_OUTPUTTERS["1.6"] = JsonV1Dot6
            # Add future versions here:
            # elif major_minor == "1.7":
            #     from cyclonedx.output.json import JsonV1Dot7
            #     _CYCLONEDX_OUTPUTTERS["1.7"] = JsonV1Dot7
            # elif major_minor == "2.0":
            #     from cyclonedx.output.json import JsonV2Dot0
            #     _CYCLONEDX_OUTPUTTERS["2.0"] = JsonV2Dot0
        except ImportError as e:
            logger.warning(f"CycloneDX version {major_minor} not available in installed library: {e}")
            _CYCLONEDX_OUTPUTTERS[major_minor] = None

    outputter_class = _CYCLONEDX_OUTPUTTERS.get(major_minor)

    if outputter_class is None:
        # Build list of supported versions (either loaded or known to be available)
        supported_versions = [v for v, cls in _CYCLONEDX_OUTPUTTERS.items() if cls is not None or v in ["1.5", "1.6"]]
        raise ValueError(
            f"Unsupported CycloneDX version: {spec_version}. "
            f"Supported versions: {', '.join(sorted(supported_versions))}"
        )

    return outputter_class


def serialize_cyclonedx_bom(bom: Bom, spec_version: Optional[str] = None) -> str:
    """
    Serialize a CycloneDX BOM to JSON string using the appropriate version outputter.

    This function automatically selects the correct serializer based on the spec version,
    supporting multiple CycloneDX versions (1.4, 1.5, 1.6, and future versions like 1.7, 2.0).

    Args:
        bom: The CycloneDX BOM object to serialize
        spec_version: The CycloneDX spec version (e.g., "1.5", "1.6", "1.7", "2.0").
                     If None, will try to detect from BOM object. Raises ValueError if not found.

    Returns:
        JSON string representation of the BOM

    Raises:
        ValueError: If spec_version is unsupported or cannot be determined

    Examples:
        >>> bom = Bom.from_json(data)
        >>> # Serialize as CycloneDX 1.6
        >>> json_str = serialize_cyclonedx_bom(bom, "1.6")
        >>>
        >>> # Auto-detect version from BOM
        >>> json_str = serialize_cyclonedx_bom(bom)
    """
    # Detect version if not provided
    if spec_version is None:
        # Try to get from BOM metadata if available
        if hasattr(bom, "spec_version") and bom.spec_version:
            spec_version = str(bom.spec_version)
        else:
            # Fail fast - do not default to a version
            raise ValueError(
                "spec_version is required for serialization. CycloneDX SBOM must have a valid specVersion field."
            )

    # Get the appropriate outputter class
    outputter_class = _get_cyclonedx_outputter(spec_version)

    logger.debug(f"Serializing CycloneDX BOM using version {spec_version}")
    outputter = outputter_class(bom)
    return outputter.output_as_string()


# ============================================================================
# SPDX Version Management
# ============================================================================

# SPDX versions supported by the spdx-tools library
SUPPORTED_SPDX_VERSIONS = ["2.2", "2.3"]  # Add "3.0" when available

# Default SPDX version
DEFAULT_SPDX_VERSION = "2.3"


def detect_spdx_version(document: Document) -> str:
    """
    Detect SPDX version from a document.

    Args:
        document: SPDX document object

    Returns:
        Version string (e.g., "2.3", "3.0")

    Examples:
        >>> document = spdx_parse_file("sbom.spdx.json")
        >>> version = detect_spdx_version(document)
        >>> print(version)  # "2.3"
    """
    if hasattr(document, "creation_info") and hasattr(document.creation_info, "spdx_version"):
        version_str = document.creation_info.spdx_version
        # Extract version number from "SPDX-2.3" format
        if version_str and version_str.startswith("SPDX-"):
            return version_str.replace("SPDX-", "")

    logger.debug(f"Could not detect SPDX version, defaulting to {DEFAULT_SPDX_VERSION}")
    return DEFAULT_SPDX_VERSION


def validate_spdx_version(version: str) -> bool:
    """
    Check if SPDX version is supported.

    Args:
        version: SPDX version string (e.g., "2.3", "3.0")

    Returns:
        True if supported, False otherwise

    Examples:
        >>> validate_spdx_version("2.3")
        True
        >>> validate_spdx_version("3.0")
        False  # Until SPDX 3.0 support is added
    """
    return version in SUPPORTED_SPDX_VERSIONS


def get_supported_cyclonedx_versions() -> list[str]:
    """
    Get list of supported CycloneDX versions.

    Returns:
        List of version strings (e.g., ["1.4", "1.5", "1.6"])
    """
    return sorted(_CYCLONEDX_OUTPUTTERS.keys())


def get_supported_spdx_versions() -> list[str]:
    """
    Get list of supported SPDX versions.

    Returns:
        List of version strings (e.g., ["2.2", "2.3"])
    """
    return SUPPORTED_SPDX_VERSIONS.copy()
