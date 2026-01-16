"""
SBOM serialization utilities for version-aware output.

This module provides centralized serialization functions for both CycloneDX and SPDX
formats, supporting multiple versions and making it easy to add new versions in the future.
"""

import json
import re
import warnings
from typing import TYPE_CHECKING, Dict, Optional, Type

from cyclonedx.model.bom import Bom

if TYPE_CHECKING:
    from cyclonedx.model.component import Component
from packageurl import PackageURL
from spdx_tools.spdx.model import Document

from .console import get_transformation_tracker
from .logging_config import logger

# ============================================================================
# CycloneDX Version Management
# ============================================================================

# Lazy imports to avoid loading all versions upfront
_CYCLONEDX_OUTPUTTERS: Dict[str, Optional[Type]] = {
    "1.3": None,  # JsonV1Dot3
    "1.4": None,  # JsonV1Dot4
    "1.5": None,  # JsonV1Dot5
    "1.6": None,  # JsonV1Dot6
    "1.7": None,  # JsonV1Dot7
    # Add new versions here as they become available:
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
            if major_minor == "1.3":
                from cyclonedx.output.json import JsonV1Dot3

                _CYCLONEDX_OUTPUTTERS["1.3"] = JsonV1Dot3
            elif major_minor == "1.4":
                from cyclonedx.output.json import JsonV1Dot4

                _CYCLONEDX_OUTPUTTERS["1.4"] = JsonV1Dot4
            elif major_minor == "1.5":
                from cyclonedx.output.json import JsonV1Dot5

                _CYCLONEDX_OUTPUTTERS["1.5"] = JsonV1Dot5
            elif major_minor == "1.6":
                from cyclonedx.output.json import JsonV1Dot6

                _CYCLONEDX_OUTPUTTERS["1.6"] = JsonV1Dot6
            elif major_minor == "1.7":
                from cyclonedx.output.json import JsonV1Dot7

                _CYCLONEDX_OUTPUTTERS["1.7"] = JsonV1Dot7
            # Add future versions here:
            # elif major_minor == "2.0":
            #     from cyclonedx.output.json import JsonV2Dot0
            #     _CYCLONEDX_OUTPUTTERS["2.0"] = JsonV2Dot0
        except ImportError as e:
            logger.warning(f"CycloneDX version {major_minor} not available in installed library: {e}")
            _CYCLONEDX_OUTPUTTERS[major_minor] = None

    outputter_class = _CYCLONEDX_OUTPUTTERS.get(major_minor)

    if outputter_class is None:
        # Build list of supported versions (either loaded or known to be available)
        supported_versions = [
            v for v, cls in _CYCLONEDX_OUTPUTTERS.items() if cls is not None or v in ["1.5", "1.6", "1.7"]
        ]
        raise ValueError(
            f"Unsupported CycloneDX version: {spec_version}. "
            f"Supported versions: {', '.join(sorted(supported_versions))}"
        )

    return outputter_class


# Display value for missing namespace in log messages
_NO_NAMESPACE_DISPLAY = "<none>"

# Default version for stub components when version cannot be determined
_UNKNOWN_VERSION = "unknown"


def _extract_component_info_from_purl(
    purl_string: str,
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[PackageURL]]:
    """
    Extract component information from a PURL string for stub creation.

    Uses the packageurl library for robust parsing.

    Args:
        purl_string: PURL string (e.g., "pkg:npm/vue-chartjs@3.5.1" or "pkg:npm/%40scope/name@1.0.0")

    Returns:
        Tuple of (name, version, namespace, PackageURL) or (None, None, None, None) if parsing fails
    """
    try:
        purl_obj = PackageURL.from_string(purl_string)
        return purl_obj.name, purl_obj.version, purl_obj.namespace, purl_obj
    except ValueError:
        # ValueError: the provided PURL string is malformed
        return None, None, None, None


# Package types that require a version in the PURL
# These ecosystems always have versioned packages in standard usage
PURL_TYPES_REQUIRING_VERSION = frozenset(
    {
        "npm",  # JavaScript/Node.js
        "maven",  # Java
        "pypi",  # Python
        "cargo",  # Rust
        "gem",  # Ruby
        "golang",  # Go
        "nuget",  # .NET
    }
)


def normalize_purl(purl_str: str | None) -> tuple[str | None, bool]:
    """
    Normalize a PURL string, fixing common encoding issues.

    Fixes:
    - Double @@ symbols (encoding bugs)
    - Double-encoded @ symbols (%40%40 → %40)

    Args:
        purl_str: The PURL string to normalize

    Returns:
        Tuple of (normalized_purl, was_modified) where was_modified indicates
        if any changes were made
    """
    from urllib.parse import unquote

    if not purl_str:
        return purl_str, False

    original = purl_str
    normalized = purl_str

    # Collapse any sequence of consecutive %40 into a single %40
    normalized = re.sub(r"(%40)+", "%40", normalized)

    # Decode to check for @@ issues
    decoded = unquote(normalized)

    # Fix double @@ in decoded form, but be careful:
    # - Valid: @scope (namespace) + @ (version separator) = exactly 2 @ for scoped packages
    # - Invalid: @@ appearing together
    if "@@" in decoded:
        # Replace @@ with single @
        decoded = decoded.replace("@@", "@")

        # Re-encode the namespace @ symbol (first @ after pkg:type/)
        # Split on first / to get type, then handle namespace
        try:
            # Try to parse the fixed decoded PURL
            # The namespace @ needs to be encoded as %40
            purl = PackageURL.from_string(decoded)
            normalized = str(purl)
        except ValueError:
            # If we can't parse, just do simple fix
            normalized = decoded

    was_modified = normalized != original

    if was_modified:
        logger.debug(f"Normalized PURL: {original} → {normalized}")

    return normalized, was_modified


def _is_invalid_purl(purl_str: str | None) -> tuple[bool, str]:
    """
    Check if a PURL is invalid and cannot be fixed.

    Invalid PURLs include:
    - Empty or None PURLs
    - PURLs with file: references in qualifiers (local workspace packages)
    - PURLs with path-based versions (e.g., @../../packages/foo)
    - PURLs with link: references (npm link)
    - PURLs missing version (except for certain ecosystems where this is acceptable)

    Note: Double @@ encoding issues are fixed by normalize_purl() rather than rejected.

    Args:
        purl_str: The PURL string to check (may be None or empty)

    Returns:
        Tuple of (is_invalid, reason) where reason explains why it's invalid
    """
    if not purl_str:
        return True, "empty or None PURL"

    # Check for file: references anywhere in the PURL
    if "file:" in purl_str:
        return True, "contains file: reference (local workspace package)"

    # Check for link: references (npm link)
    if "link:" in purl_str:
        return True, "contains link: reference (npm link)"

    # Check for path-based versions (e.g., @../../ or @../ or @./)
    if "@../../" in purl_str or "@../" in purl_str or "@./" in purl_str:
        return True, "contains path-based version"

    # Try to parse the PURL
    try:
        purl = PackageURL.from_string(purl_str)

        # Check for invalid root namespace (common SBOM generator bug)
        # Must check parsed namespace, not string matching, to avoid false positives
        if purl.namespace in {"root", "@root"}:
            return True, "contains invalid root namespace"

        # Check for file: in qualifiers
        if purl.qualifiers:
            for key, value in purl.qualifiers.items():
                if isinstance(value, str) and ("file:" in value or "link:" in value):
                    return True, f"qualifier '{key}' contains file:/link: reference"

        # Check for missing version in ecosystems that require it
        if purl.type in PURL_TYPES_REQUIRING_VERSION:
            if not purl.version:
                return True, f"missing version for {purl.type} package"

    except ValueError as e:
        return True, f"malformed PURL: {e}"

    return False, ""


def _sanitize_component_purl(comp: "Component", comp_type: str) -> tuple[int, int]:
    """
    Sanitize a single component's PURL.

    Args:
        comp: CycloneDX Component object with optional purl attribute
        comp_type: Description of component type for logging (e.g., "component", "metadata component")

    Returns:
        Tuple of (purls_normalized, purls_cleared) counts for this component
    """
    if not comp.purl:
        return 0, 0

    purls_normalized = 0
    purls_cleared = 0
    purl_str = str(comp.purl)

    tracker = get_transformation_tracker()
    original_purl = purl_str

    # First, try to normalize
    normalized_str, was_normalized = normalize_purl(purl_str)
    if was_normalized:
        try:
            comp.purl = PackageURL.from_string(normalized_str)
            purl_str = normalized_str
            purls_normalized = 1
            # Record for attestation
            tracker.record_purl_normalization(comp.name, original_purl, normalized_str)
        except ValueError:
            # Normalization produced invalid PURL, will be caught below
            pass

    # Then check if it's still invalid
    is_invalid, reason = _is_invalid_purl(purl_str)
    if is_invalid:
        # Record for attestation
        tracker.record_purl_cleared(comp.name, purl_str, reason)
        comp.purl = None
        purls_cleared = 1

    return purls_normalized, purls_cleared


def sanitize_purls(bom: Bom) -> tuple[int, int]:
    """
    Normalize and sanitize PURLs in the BOM.

    This function:
    1. Normalizes PURLs (fixes encoding issues like double @@)
    2. Clears invalid PURLs that cannot be fixed (file: references, path-based versions, etc.)

    Components are NOT removed (to preserve dependency graph integrity),
    but their invalid PURLs are set to None.

    Args:
        bom: The CycloneDX BOM object to sanitize (modified in place)

    Returns:
        Tuple of (purls_normalized, purls_cleared)
    """
    purls_normalized = 0
    purls_cleared = 0

    # Process regular components
    for comp in bom.components:
        normalized, cleared = _sanitize_component_purl(comp, "component")
        purls_normalized += normalized
        purls_cleared += cleared

    # Process metadata component
    if bom.metadata and bom.metadata.component:
        normalized, cleared = _sanitize_component_purl(bom.metadata.component, "metadata component")
        purls_normalized += normalized
        purls_cleared += cleared

    # Process tools.components (CycloneDX 1.5+ modern format)
    if bom.metadata and bom.metadata.tools and bom.metadata.tools.components:
        for comp in bom.metadata.tools.components:
            normalized, cleared = _sanitize_component_purl(comp, "tools.component")
            purls_normalized += normalized
            purls_cleared += cleared

    if purls_normalized:
        logger.info(f"PURL sanitization: normalized {purls_normalized} PURL(s)")
    if purls_cleared:
        logger.info(f"PURL sanitization: cleared {purls_cleared} invalid PURL(s)")

    return purls_normalized, purls_cleared


def sanitize_spdx_purls(document: "Document") -> int:
    """
    Normalize PURLs in SPDX external references.

    This function normalizes PURL locators in package external references to ensure
    consistent encoding. For example, it fixes double-encoded @ symbols (%40%40 -> %40).

    Args:
        document: The SPDX Document object to sanitize (modified in place)

    Returns:
        Number of PURLs normalized
    """
    normalized_count = 0

    for package in document.packages:
        for ref in package.external_references:
            if ref.reference_type == "purl":
                normalized, was_normalized = normalize_purl(ref.locator)
                if was_normalized and normalized:
                    logger.info(f"Normalized SPDX PURL: {ref.locator} -> {normalized}")
                    ref.locator = normalized
                    normalized_count += 1

    if normalized_count:
        logger.info(f"SPDX PURL sanitization: normalized {normalized_count} PURL(s)")

    return normalized_count


# Map of invalid SPDX enum values to valid ones (workaround for spdx_tools enum-serialization bug;
# see the upstream spdx/tools-python issue tracker for the bug where enums are serialized using Python
# names with underscores instead of SPDX spec values with hyphens).
SPDX_PACKAGE_PURPOSE_FIXES = {
    "OPERATING_SYSTEM": "OPERATING-SYSTEM",
}


def sanitize_spdx_json_file(file_path: str) -> int:
    """
    Fix invalid enum values in SPDX JSON files.

    The spdx_tools library has a bug where it outputs Python enum names
    (e.g., OPERATING_SYSTEM) instead of SPDX spec values (e.g., OPERATING-SYSTEM).
    This function post-processes the JSON file to fix these values.

    Args:
        file_path: Path to the SPDX JSON file to sanitize (modified in place)

    Returns:
        Number of values fixed
    """
    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Failed to read SPDX file for sanitization: {e}")
        return 0

    fixed_count = 0

    # Fix primaryPackagePurpose values in packages
    for package in data.get("packages", []):
        purpose = package.get("primaryPackagePurpose")
        if purpose is None:
            continue
        fixed_value = SPDX_PACKAGE_PURPOSE_FIXES.get(purpose, purpose)
        if fixed_value != purpose:
            package["primaryPackagePurpose"] = fixed_value
            logger.debug(f"Fixed SPDX primaryPackagePurpose: {purpose} -> {fixed_value}")
            fixed_count += 1

    if fixed_count > 0:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            logger.info(f"SPDX JSON sanitization: fixed {fixed_count} invalid enum value(s)")
        except OSError as e:
            logger.warning(f"Failed to write sanitized SPDX file: {e}")
            return 0

    return fixed_count


def sanitize_dependency_graph(bom: Bom) -> int:
    """
    Fix orphaned dependency references by adding stub components for missing refs.

    Some SBOM generators (like CycloneDX webpack plugin) may produce SBOMs with
    dependency graph entries that reference components not included in the BOM.
    The cyclonedx-python library's validate() rejects such SBOMs. This function
    creates minimal stub components for missing references to make the tool
    resilient to malformed inputs while preserving the dependency graph structure.

    Args:
        bom: The CycloneDX BOM object to sanitize (modified in place)

    Returns:
        Number of stub components added
    """
    from cyclonedx.model import BomRef
    from cyclonedx.model.component import Component, ComponentType

    # Collect all known BomRef values
    known_refs: set[str] = set()

    # Add component BomRefs
    for comp in bom.components:
        if comp.bom_ref and comp.bom_ref.value:
            known_refs.add(comp.bom_ref.value)

    # Add service BomRefs
    for service in bom.services:
        if service.bom_ref and service.bom_ref.value:
            known_refs.add(service.bom_ref.value)

    # Add metadata component BomRef
    if bom.metadata and bom.metadata.component:
        if bom.metadata.component.bom_ref and bom.metadata.component.bom_ref.value:
            known_refs.add(bom.metadata.component.bom_ref.value)

    # Collect all refs used in dependency graph
    dependency_refs: set[str] = set()
    for dep in bom.dependencies:
        if dep.ref and dep.ref.value:
            dependency_refs.add(dep.ref.value)
        for nested_dep in dep.dependencies:
            if nested_dep.ref and nested_dep.ref.value:
                dependency_refs.add(nested_dep.ref.value)

    # Find orphaned refs (in dependencies but not in components)
    orphaned_refs = dependency_refs - known_refs

    if not orphaned_refs:
        return 0

    tracker = get_transformation_tracker()
    stubs_added = 0

    for ref_value in orphaned_refs:
        # Try to parse as PURL to get component info
        name, version, namespace, purl_obj = _extract_component_info_from_purl(ref_value)

        if name:
            # Create stub component from PURL info
            stub = Component(
                type=ComponentType.LIBRARY,
                name=name,
                version=version or _UNKNOWN_VERSION,
                bom_ref=BomRef(ref_value),
            )
            if namespace:
                stub.group = namespace
            if purl_obj:
                stub.purl = purl_obj

            # Record for attestation
            tracker.record_stub_added(ref_value, name, version or _UNKNOWN_VERSION)
        else:
            # Can't parse as PURL - create minimal stub with ref as name
            stub = Component(
                type=ComponentType.LIBRARY,
                name=ref_value,
                version=_UNKNOWN_VERSION,
                bom_ref=BomRef(ref_value),
            )
            # Record for attestation
            tracker.record_stub_added(ref_value, ref_value, _UNKNOWN_VERSION)

        bom.components.add(stub)
        stubs_added += 1

    logger.info(
        f"Dependency graph sanitization: added {stubs_added} stub component(s) for orphaned references. "
        "These stubs may be enriched in the enrichment step."
    )

    return stubs_added


def link_root_dependencies(bom: Bom) -> int:
    """
    Link top-level components as dependencies of the root component.

    When the root component has no dependencies defined, this function links all
    top-level components (those not already nested dependencies of other components)
    as direct dependencies of the root. This fixes CycloneDX library warnings about
    incomplete dependency graphs while preserving existing hierarchical relationships.

    Args:
        bom: The CycloneDX BOM object to modify (modified in place)

    Returns:
        Number of dependencies linked to root (0 if root already has dependencies
        or no root component exists)
    """
    from cyclonedx.model import BomRef
    from cyclonedx.model.dependency import Dependency

    # Check if root component exists
    if not bom.metadata or not bom.metadata.component:
        logger.debug("No root component found, skipping dependency linking")
        return 0

    root_component = bom.metadata.component
    if not root_component.bom_ref or not root_component.bom_ref.value:
        logger.debug("Root component has no bom-ref, skipping dependency linking")
        return 0

    root_ref_value = root_component.bom_ref.value

    # Find or create the root's dependency entry
    root_dep: Dependency | None = None
    for dep in bom.dependencies:
        if dep.ref and dep.ref.value == root_ref_value:
            root_dep = dep
            break

    # If root dependency entry doesn't exist, create it
    if root_dep is None:
        root_dep = Dependency(ref=BomRef(root_ref_value))
        bom.dependencies.add(root_dep)

    # Check if root already has dependencies defined
    if root_dep.dependencies and len(root_dep.dependencies) > 0:
        logger.debug(
            f"Root component '{root_component.name}' already has {len(root_dep.dependencies)} dependencies, skipping"
        )
        return 0

    # Collect all refs that are nested dependencies of other components
    # These are "transitive" dependencies - not top-level
    nested_refs: set[str] = set()
    for dep in bom.dependencies:
        for nested_dep in dep.dependencies:
            if nested_dep.ref and nested_dep.ref.value:
                nested_refs.add(nested_dep.ref.value)

    # Collect all component bom-refs
    all_component_refs: set[str] = set()
    for comp in bom.components:
        if comp.bom_ref and comp.bom_ref.value:
            all_component_refs.add(comp.bom_ref.value)

    # Top-level = all component refs - nested refs - root ref
    top_level_refs = all_component_refs - nested_refs - {root_ref_value}

    if not top_level_refs:
        logger.debug("No top-level components to link to root")
        return 0

    # Link top-level components as direct dependencies of root
    for ref_value in top_level_refs:
        root_dep.dependencies.add(Dependency(ref=BomRef(ref_value)))

    # Record for attestation
    tracker = get_transformation_tracker()
    tracker.record_root_dependencies_linked(root_component.name, len(top_level_refs))

    logger.info(f"Linked {len(top_level_refs)} top-level component(s) as dependencies of root '{root_component.name}'")

    return len(top_level_refs)


def serialize_cyclonedx_bom(bom: Bom, spec_version: Optional[str] = None) -> str:
    """
    Serialize a CycloneDX BOM to JSON string using the appropriate version outputter.

    This function automatically selects the correct serializer based on the spec version,
    supporting multiple CycloneDX versions (1.4, 1.5, 1.6, 1.7, and future versions like 2.0).

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

    # Capture CycloneDX library warnings and re-emit with cleaner formatting
    # The library emits UserWarnings for incomplete dependency graphs which can be confusing
    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always", UserWarning)
        outputter = outputter_class(bom)
        result = outputter.output_as_string()

    # Process captured warnings and re-emit with user-friendly messages
    for w in caught_warnings:
        warning_msg = str(w.message)
        if "has no defined dependencies" in warning_msg:
            # Re-emit the CycloneDX dependency graph warning with cleaner message
            root_name = bom.metadata.component.name if bom.metadata.component else "unknown"
            logger.warning(
                f"SBOM dependency graph is incomplete: root component '{root_name}' has no dependencies defined. "
                f"This is common when the SBOM generator doesn't track dependency relationships."
            )
        else:
            # Re-emit other warnings as-is using our logger
            logger.warning(f"CycloneDX serialization warning: {warning_msg}")

    return result


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
