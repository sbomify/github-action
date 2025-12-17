"""SBOM enrichment using plugin-based data sources with native library support.

This module provides SBOM enrichment through a plugin architecture that queries
multiple data sources in priority order to populate NTIA-required fields.

Plugin architecture is in sbomify_action/_enrichment/:
- metadata.py: NormalizedMetadata dataclass
- protocol.py: DataSource protocol
- registry.py: SourceRegistry class
- enricher.py: Enricher orchestration class
- sources/: Individual data source implementations
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cyclonedx.model import ExternalReference, ExternalReferenceType, Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.license import LicenseExpression
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    SpdxNoAssertion,
    SpdxNone,
)
from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

# Import from plugin architecture
from ._enrichment.enricher import Enricher, clear_all_caches
from ._enrichment.metadata import NormalizedMetadata
from ._enrichment.sources.purl import NAMESPACE_TO_SUPPLIER
from .exceptions import SBOMValidationError
from .generation import (
    COMMON_CPP_LOCK_FILES,
    COMMON_DART_LOCK_FILES,
    COMMON_GO_LOCK_FILES,
    COMMON_JAVASCRIPT_LOCK_FILES,
    COMMON_PYTHON_LOCK_FILES,
    COMMON_RUBY_LOCK_FILES,
    COMMON_RUST_LOCK_FILES,
)
from .logging_config import logger
from .serialization import serialize_cyclonedx_bom

# Combine all lockfile names into a single set for efficient lookup
ALL_LOCKFILE_NAMES = set(
    COMMON_PYTHON_LOCK_FILES
    + COMMON_RUST_LOCK_FILES
    + COMMON_JAVASCRIPT_LOCK_FILES
    + COMMON_RUBY_LOCK_FILES
    + COMMON_GO_LOCK_FILES
    + COMMON_DART_LOCK_FILES
    + COMMON_CPP_LOCK_FILES
)

# Human-readable descriptions for lockfile types (for NTIA compliance)
# Note: This includes lockfiles we generate from AND those that might appear
# in container/filesystem scans via Trivy
LOCKFILE_DESCRIPTIONS = {
    # Python
    "requirements.txt": "Python pip requirements manifest",
    "pyproject.toml": "Python project configuration",
    "Pipfile": "Python Pipenv manifest",
    "Pipfile.lock": "Python Pipenv lockfile",
    "poetry.lock": "Python Poetry lockfile",
    "uv.lock": "Python uv lockfile",
    "pdm.lock": "Python PDM lockfile",
    "conda-lock.yml": "Conda environment lockfile",
    # Rust
    "Cargo.lock": "Rust Cargo lockfile",
    # JavaScript
    "package.json": "JavaScript package manifest",
    "package-lock.json": "JavaScript npm lockfile",
    "yarn.lock": "JavaScript Yarn lockfile",
    "pnpm-lock.yaml": "JavaScript pnpm lockfile",
    "bun.lock": "JavaScript Bun lockfile",
    "npm-shrinkwrap.json": "JavaScript npm shrinkwrap lockfile",
    # Ruby
    "Gemfile.lock": "Ruby Bundler lockfile",
    # Go
    "go.sum": "Go module checksums",
    "go.mod": "Go module definition",
    # Dart
    "pubspec.lock": "Dart pub lockfile",
    # C++
    "conan.lock": "C++ Conan lockfile",
    "vcpkg.json": "C++ vcpkg manifest",
}

# CycloneDX component type for operating system
COMPONENT_TYPE_OPERATING_SYSTEM = "operating_system"

# Delimiter used for SPDX package comment entries
COMMENT_DELIMITER = " | "


def clear_cache() -> None:
    """Clear all cached metadata from all data sources."""
    clear_all_caches()
    logger.debug("All metadata caches cleared")


def _is_lockfile_component(component: Component) -> bool:
    """Check if a CycloneDX component represents a lockfile artifact."""
    if component.type.name.lower() != "application":
        return False
    if component.purl:
        return False
    if component.name and component.name in ALL_LOCKFILE_NAMES:
        return True
    return False


def _enrich_lockfile_components(bom: Bom) -> int:
    """
    Enrich lockfile components in a CycloneDX BOM with NTIA-compliant metadata.

    Instead of removing lockfiles, we enrich them with:
    - Description: Human-readable description based on lockfile type
    - Supplier: Same as the root component (metadata.component or metadata.supplier)

    This preserves the dependency graph integrity.
    """
    lockfile_components = [c for c in bom.components if _is_lockfile_component(c)]

    if not lockfile_components:
        return 0

    # Get supplier from root component or BOM metadata
    root_supplier = None
    if bom.metadata.component and bom.metadata.component.supplier:
        root_supplier = bom.metadata.component.supplier
    elif bom.metadata.supplier:
        root_supplier = bom.metadata.supplier

    for component in lockfile_components:
        # Add description if not present
        if not component.description and component.name:
            description = LOCKFILE_DESCRIPTIONS.get(component.name)
            if description:
                component.description = description
                logger.debug(f"Added description to lockfile: {component.name}")

        # Add supplier from root component if not present
        if not component.supplier and root_supplier:
            component.supplier = root_supplier
            logger.debug(f"Added supplier to lockfile: {component.name}")

        logger.info(f"Enriched lockfile component: {component.name}")

    return len(lockfile_components)


def _is_lockfile_package(package: Package) -> bool:
    """Check if an SPDX package represents a lockfile artifact."""
    if package.name and package.name in ALL_LOCKFILE_NAMES:
        has_purl = any(ref.reference_type == "purl" for ref in package.external_references)
        if not has_purl:
            return True
    return False


def _enrich_lockfile_packages(document: Document) -> int:
    """
    Enrich lockfile packages in an SPDX document with NTIA-compliant metadata.

    Instead of removing lockfiles, we enrich them with:
    - Description: Human-readable description based on lockfile type
    - Supplier: Same as the main package (first package in document)

    This preserves the relationship graph integrity.
    """
    lockfile_packages = [p for p in document.packages if _is_lockfile_package(p)]

    if not lockfile_packages:
        return 0

    # Get supplier from the main package (usually first package represents the described component)
    root_supplier = None
    if document.packages:
        for pkg in document.packages:
            if pkg.supplier and not isinstance(pkg.supplier, (SpdxNoAssertion, SpdxNone)):
                root_supplier = pkg.supplier
                break

    for pkg in lockfile_packages:
        # Add description if not present
        if (not pkg.description or pkg.description == "NOASSERTION") and pkg.name:
            description = LOCKFILE_DESCRIPTIONS.get(pkg.name)
            if description:
                pkg.description = description
                logger.debug(f"Added description to lockfile: {pkg.name}")

        # Add supplier from root package if not present
        if root_supplier and (not pkg.supplier or isinstance(pkg.supplier, (SpdxNoAssertion, SpdxNone))):
            pkg.supplier = root_supplier
            logger.debug(f"Added supplier to lockfile: {pkg.name}")

        logger.info(f"Enriched lockfile package: {pkg.name}")

    return len(lockfile_packages)


def _add_enrichment_source_property(component: Component, source: str) -> None:
    """Add enrichment source property to a CycloneDX component."""
    property_name = "sbomify:enrichment:source"
    for prop in component.properties:
        if prop.name == property_name:
            return
    component.properties.add(Property(name=property_name, value=source))


def _add_enrichment_source_comment(package: Package, source: str) -> None:
    """Add enrichment source comment to an SPDX package."""
    enrichment_note = f"Enriched by sbomify from {source}"
    if package.comment:
        comment_entries = [entry.strip() for entry in package.comment.split(COMMENT_DELIMITER)]
        if enrichment_note not in comment_entries:
            comment_entries.append(enrichment_note)
        package.comment = COMMENT_DELIMITER.join(comment_entries)
    else:
        package.comment = enrichment_note


def _extract_components_from_cyclonedx(bom: Bom) -> List[Tuple[Component, str]]:
    """Extract components from CycloneDX BOM."""
    components = []
    for component in bom.components:
        if component.purl:
            components.append((component, str(component.purl)))
    return components


def _extract_packages_from_spdx(document: Document) -> List[Tuple[Package, str]]:
    """Extract packages from SPDX document."""
    packages = []
    for package in document.packages:
        purl = None
        for ref in package.external_references:
            if ref.reference_type == "purl":
                purl = ref.locator
                break
        if purl:
            packages.append((package, purl))
    return packages


def _apply_metadata_to_cyclonedx_component(component: Component, metadata: NormalizedMetadata) -> List[str]:
    """
    Apply NormalizedMetadata to a CycloneDX component.

    Args:
        component: Component to enrich
        metadata: Normalized metadata to apply

    Returns:
        List of added field names for logging
    """
    added_fields = []

    # Description
    if not component.description and metadata.description:
        component.description = metadata.description
        added_fields.append("description")

    # Licenses
    has_licenses = component.licenses is not None and len(component.licenses) > 0
    if not has_licenses and metadata.licenses:
        if len(metadata.licenses) == 1:
            license_expression = metadata.licenses[0]
        else:
            license_expression = " OR ".join(metadata.licenses)
        license_expr = LicenseExpression(value=license_expression)
        component.licenses.add(license_expr)
        added_fields.append(f"licenses ({license_expression})")

    # Publisher
    if not component.publisher and metadata.supplier:
        component.publisher = metadata.supplier
        added_fields.append(f"publisher ({metadata.supplier})")

    # External references helper
    def _add_external_ref(ref_type: ExternalReferenceType, url: str) -> bool:
        if url:
            for existing in component.external_references:
                if existing.type == ref_type and str(existing.url) == url:
                    return False
            component.external_references.add(ExternalReference(type=ref_type, url=XsUri(url)))
            return True
        return False

    # Homepage
    if metadata.homepage:
        if _add_external_ref(ExternalReferenceType.WEBSITE, metadata.homepage):
            added_fields.append("homepage URL")

    # Repository
    if metadata.repository_url:
        if _add_external_ref(ExternalReferenceType.VCS, metadata.repository_url):
            added_fields.append("repository URL")

    # Registry/Distribution
    if metadata.registry_url:
        if _add_external_ref(ExternalReferenceType.DISTRIBUTION, metadata.registry_url):
            added_fields.append("distribution URL")

    # Issue tracker
    if metadata.issue_tracker_url:
        if _add_external_ref(ExternalReferenceType.ISSUE_TRACKER, metadata.issue_tracker_url):
            added_fields.append("issue-tracker URL")

    return added_fields


def _is_spdx_license_empty(license_value) -> bool:
    """Check if an SPDX license field is empty or NOASSERTION."""
    if license_value is None:
        return True
    if isinstance(license_value, (SpdxNoAssertion, SpdxNone)):
        return True
    return False


def _apply_metadata_to_spdx_package(package: Package, metadata: NormalizedMetadata) -> List[str]:
    """
    Apply NormalizedMetadata to an SPDX package.

    Args:
        package: Package to enrich
        metadata: Normalized metadata to apply

    Returns:
        List of added field names for logging
    """
    added_fields = []

    # Description
    if not package.description and metadata.description:
        package.description = metadata.description
        added_fields.append("description")

    # Homepage
    if not package.homepage and metadata.homepage:
        package.homepage = metadata.homepage
        added_fields.append("homepage")

    # Download location
    if not package.download_location or package.download_location == "NOASSERTION":
        download_url = metadata.registry_url or metadata.download_url or metadata.repository_url
        if download_url:
            package.download_location = download_url
            added_fields.append("downloadLocation")

    # Licenses - use helper to avoid boolean evaluation of LicenseExpression
    if _is_spdx_license_empty(package.license_declared) and metadata.licenses:
        if len(metadata.licenses) == 1:
            license_expression = metadata.licenses[0]
        else:
            license_expression = " OR ".join(metadata.licenses)

        license_parser = LicenseExpressionParser()
        try:
            parsed_expression = license_parser.parse_license_expression(license_expression)
            package.license_declared = parsed_expression
            added_fields.append(f"license_declared ({license_expression})")
        except Exception as e:
            logger.warning(f"Failed to parse license expression '{license_expression}': {e}")
            source = metadata.source or "enrichment"
            if package.license_comment:
                package.license_comment += f" | Licenses from {source}: {license_expression}"
            else:
                package.license_comment = f"Licenses from {source}: {license_expression}"
            added_fields.append(f"license_comment ({license_expression})")

    # Source info
    if not package.source_info and metadata.repository_url:
        package.source_info = f"acquired from {metadata.repository_url}"
        added_fields.append("sourceInfo")

    # Originator
    if not package.originator and metadata.maintainer_name:
        originator_str = metadata.maintainer_name
        if metadata.maintainer_email:
            originator_str += f" ({metadata.maintainer_email})"
        package.originator = Actor(ActorType.PERSON, originator_str)
        added_fields.append(f"originator ({metadata.maintainer_name})")

    # Supplier
    if not package.supplier and metadata.supplier:
        package.supplier = Actor(ActorType.ORGANIZATION, metadata.supplier)
        added_fields.append(f"supplier ({metadata.supplier})")

    # External references helper
    def _add_external_ref(category: ExternalPackageRefCategory, ref_type: str, locator: str) -> bool:
        if locator:
            for existing in package.external_references:
                if existing.locator == locator:
                    return False
            package.external_references.append(
                ExternalPackageRef(category=category, reference_type=ref_type, locator=locator)
            )
            return True
        return False

    # Registry URL
    if metadata.registry_url:
        if _add_external_ref(ExternalPackageRefCategory.PACKAGE_MANAGER, "url", metadata.registry_url):
            added_fields.append("externalRef (registry)")

    # Documentation URL
    if metadata.documentation_url:
        if _add_external_ref(ExternalPackageRefCategory.OTHER, "url", metadata.documentation_url):
            added_fields.append("externalRef (documentation)")

    return added_fields


def _enrich_os_component(component: Component) -> List[str]:
    """Enrich an operating-system type component with supplier info."""
    if component.type.name.lower() != COMPONENT_TYPE_OPERATING_SYSTEM:
        return []

    added_fields = []
    os_name = component.name.lower() if component.name else ""

    if not component.publisher:
        supplier = NAMESPACE_TO_SUPPLIER.get(os_name)
        if supplier:
            component.publisher = supplier
            added_fields.append(f"publisher ({supplier})")

    return added_fields


def _enrich_cyclonedx_bom_with_plugin_architecture(bom: Bom, enricher: Enricher) -> Dict[str, int]:
    """
    Enrich CycloneDX BOM using the plugin architecture.

    Args:
        bom: Bom object to enrich (modified in place)
        enricher: Enricher instance with configured sources

    Returns:
        Enrichment statistics
    """
    stats = {
        "components_enriched": 0,
        "descriptions_added": 0,
        "licenses_added": 0,
        "publishers_added": 0,
        "homepages_added": 0,
        "repositories_added": 0,
        "distributions_added": 0,
        "issue_trackers_added": 0,
        "os_components_enriched": 0,
        "sources": {},
    }

    for component in bom.components:
        added_fields = []
        enrichment_source = None
        purl_str = str(component.purl) if component.purl else None

        # Handle OS type components
        if component.type.name.lower() == COMPONENT_TYPE_OPERATING_SYSTEM:
            added_fields = _enrich_os_component(component)
            if added_fields:
                enrichment_source = "purl"
                stats["os_components_enriched"] += 1
                stats["components_enriched"] += 1
                for field in added_fields:
                    if "publisher" in field:
                        stats["publishers_added"] += 1
                _add_enrichment_source_property(component, enrichment_source)
            continue

        # Use plugin architecture for components with PURLs
        if purl_str:
            metadata = enricher.fetch_metadata(purl_str, merge_results=True)
            if metadata and metadata.has_data():
                added_fields = _apply_metadata_to_cyclonedx_component(component, metadata)
                if added_fields:
                    enrichment_source = metadata.source
                    # Track by primary source
                    primary_source = metadata.source.split(", ")[0] if metadata.source else "unknown"
                    stats["sources"][primary_source] = stats["sources"].get(primary_source, 0) + 1

        if added_fields:
            stats["components_enriched"] += 1
            if enrichment_source:
                _add_enrichment_source_property(component, enrichment_source.split(", ")[0])
            for field in added_fields:
                if "description" in field:
                    stats["descriptions_added"] += 1
                elif "licenses" in field:
                    stats["licenses_added"] += 1
                elif "publisher" in field:
                    stats["publishers_added"] += 1
                elif "homepage" in field or "tracker" in field:
                    stats["homepages_added"] += 1
                elif "repository" in field:
                    stats["repositories_added"] += 1
                elif "distribution" in field:
                    stats["distributions_added"] += 1
                elif "issue-tracker" in field:
                    stats["issue_trackers_added"] += 1

    return stats


def _enrich_spdx_document_with_plugin_architecture(document: Document, enricher: Enricher) -> Dict[str, int]:
    """
    Enrich SPDX document using the plugin architecture.

    Args:
        document: Document object to enrich (modified in place)
        enricher: Enricher instance with configured sources

    Returns:
        Enrichment statistics
    """
    stats = {
        "components_enriched": 0,
        "descriptions_added": 0,
        "licenses_added": 0,
        "homepages_added": 0,
        "originators_added": 0,
        "suppliers_added": 0,
        "source_info_added": 0,
        "external_refs_added": 0,
        "sources": {},
    }

    for package in document.packages:
        added_fields = []
        enrichment_source = None

        # Find PURL in external references
        purl_str = None
        for ref in package.external_references:
            if ref.reference_type == "purl":
                purl_str = ref.locator
                break

        if purl_str:
            metadata = enricher.fetch_metadata(purl_str, merge_results=True)
            if metadata and metadata.has_data():
                added_fields = _apply_metadata_to_spdx_package(package, metadata)
                if added_fields:
                    enrichment_source = metadata.source
                    primary_source = metadata.source.split(", ")[0] if metadata.source else "unknown"
                    stats["sources"][primary_source] = stats["sources"].get(primary_source, 0) + 1

        if added_fields:
            stats["components_enriched"] += 1
            if enrichment_source:
                _add_enrichment_source_comment(package, enrichment_source.split(", ")[0])
            for field in added_fields:
                if "description" in field:
                    stats["descriptions_added"] += 1
                elif "license_declared" in field or "license_comment" in field:
                    stats["licenses_added"] += 1
                elif "homepage" in field:
                    stats["homepages_added"] += 1
                elif "originator" in field:
                    stats["originators_added"] += 1
                elif "supplier" in field:
                    stats["suppliers_added"] += 1
                elif "sourceInfo" in field:
                    stats["source_info_added"] += 1
                elif "externalRef" in field:
                    stats["external_refs_added"] += 1

    return stats


def enrich_sbom_with_ecosystems(input_file: str, output_file: str) -> None:
    """
    Enrich SBOM with metadata from multiple data sources using plugin architecture.

    This function uses the new plugin-based enrichment system which queries
    data sources in priority order:
    1. Native sources (PyPI for pypi packages)
    2. Generic sources (ecosyste.ms)
    3. PURL-based extraction (for OS packages)
    4. Fallback sources (Repology - last resort)

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save enriched SBOM

    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If SBOM format is invalid
        Exception: For other errors during enrichment
    """
    logger.info(f"Starting SBOM enrichment for: {input_file}")

    input_path = Path(input_file)
    output_path = Path(output_file)

    # Parse input file
    try:
        with open(input_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input SBOM file not found: {input_file}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in SBOM file: {e}")

    # Create enricher with default sources
    with Enricher() as enricher:
        # Log registered sources
        sources = enricher.registry.list_sources()
        logger.debug(f"Registered data sources: {[s['name'] for s in sources]}")

        if data.get("bomFormat") == "CycloneDX":
            _enrich_cyclonedx_sbom(data, input_path, output_path, enricher)
        elif data.get("spdxVersion"):
            _enrich_spdx_sbom(input_path, output_path, enricher)
        else:
            raise ValueError("Neither CycloneDX nor SPDX format found in JSON file")


def _enrich_cyclonedx_sbom(data: Dict[str, Any], input_path: Path, output_path: Path, enricher: Enricher) -> None:
    """Enrich a CycloneDX SBOM."""
    logger.info("Processing CycloneDX SBOM")

    spec_version = data.get("specVersion")
    if spec_version is None:
        raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")

    # Handle tools format conversion for 1.5+
    if "metadata" in data and "tools" in data["metadata"]:
        tools_data = data["metadata"]["tools"]
        if isinstance(tools_data, list):
            spec_parts = spec_version.split(".")
            major = int(spec_parts[0]) if len(spec_parts) > 0 else 1
            minor = int(spec_parts[1]) if len(spec_parts) > 1 else 0
            is_v15_or_later = (major > 1) or (major == 1 and minor >= 5)

            if is_v15_or_later:
                logger.debug("Converting tools from legacy array to components format")
                components = []
                for tool_data in tools_data:
                    component_data = tool_data.copy()
                    if "vendor" in component_data:
                        component_data["group"] = component_data.pop("vendor")
                    if "type" not in component_data:
                        component_data["type"] = "application"
                    components.append(component_data)
                data["metadata"]["tools"] = {"components": components, "services": []}

    # Parse BOM
    try:
        bom = Bom.from_json(data)
    except Exception as e:
        raise SBOMValidationError(f"Failed to parse CycloneDX SBOM: {e}")

    # Enrich lockfile components (instead of removing them)
    lockfiles_enriched = _enrich_lockfile_components(bom)
    if lockfiles_enriched > 0:
        logger.info(f"Enriched {lockfiles_enriched} lockfile component(s)")

    # Extract components
    components = _extract_components_from_cyclonedx(bom)
    if not components:
        logger.warning("No components with PURLs found in SBOM, skipping enrichment")
        serialized = serialize_cyclonedx_bom(bom, spec_version)
        with open(output_path, "w") as f:
            f.write(serialized)
        return

    logger.info(f"Found {len(components)} components to enrich")

    # Enrich using plugin architecture
    stats = _enrich_cyclonedx_bom_with_plugin_architecture(bom, enricher)

    # Print summary
    _log_cyclonedx_enrichment_summary(stats, len(components))

    # Write output
    try:
        serialized = serialize_cyclonedx_bom(bom, spec_version)
        with open(output_path, "w") as f:
            f.write(serialized)
        logger.info(f"Enriched SBOM written to: {output_path}")
    except Exception as e:
        raise Exception(f"Failed to write enriched SBOM: {e}")


def _enrich_spdx_sbom(input_path: Path, output_path: Path, enricher: Enricher) -> None:
    """Enrich an SPDX SBOM."""
    logger.info("Processing SPDX SBOM")

    try:
        document = spdx_parse_file(str(input_path))
    except Exception as e:
        raise SBOMValidationError(f"Failed to parse SPDX SBOM: {e}")

    # Enrich lockfile packages (instead of removing them)
    lockfiles_enriched = _enrich_lockfile_packages(document)
    if lockfiles_enriched > 0:
        logger.info(f"Enriched {lockfiles_enriched} lockfile package(s)")

    # Extract packages
    packages = _extract_packages_from_spdx(document)
    if not packages:
        logger.warning("No packages with PURLs found in SBOM, skipping enrichment")
        spdx_write_file(document, str(output_path), validate=False)
        return

    logger.info(f"Found {len(packages)} packages to enrich")

    # Enrich using plugin architecture
    stats = _enrich_spdx_document_with_plugin_architecture(document, enricher)

    # Print summary
    _log_spdx_enrichment_summary(stats, len(packages))

    # Write output
    try:
        spdx_write_file(document, str(output_path), validate=False)
        logger.info(f"Enriched SBOM written to: {output_path}")
    except Exception as e:
        raise Exception(f"Failed to write enriched SBOM: {e}")


def _log_cyclonedx_enrichment_summary(stats: Dict[str, int], total_components: int) -> None:
    """Log enrichment summary for CycloneDX."""
    logger.info("Enrichment Summary:")
    logger.info(f"  Components enriched: {stats['components_enriched']}/{total_components}")

    # Log by source
    for source, count in sorted(stats.get("sources", {}).items()):
        logger.info(f"  Enriched from {source}: {count}")

    if stats.get("os_components_enriched", 0) > 0:
        logger.info(f"  OS components enriched: {stats['os_components_enriched']}")
    if stats["descriptions_added"] > 0:
        logger.info(f"  Descriptions added: {stats['descriptions_added']}")
    if stats["licenses_added"] > 0:
        logger.info(f"  Licenses added: {stats['licenses_added']}")
    if stats["publishers_added"] > 0:
        logger.info(f"  Publishers added: {stats['publishers_added']}")
    if stats["homepages_added"] > 0:
        logger.info(f"  Homepage URLs added: {stats['homepages_added']}")
    if stats["repositories_added"] > 0:
        logger.info(f"  Repository URLs added: {stats['repositories_added']}")
    if stats["distributions_added"] > 0:
        logger.info(f"  Distribution URLs added: {stats['distributions_added']}")
    if stats["issue_trackers_added"] > 0:
        logger.info(f"  Issue tracker URLs added: {stats['issue_trackers_added']}")


def _log_spdx_enrichment_summary(stats: Dict[str, int], total_packages: int) -> None:
    """Log enrichment summary for SPDX."""
    logger.info("Enrichment Summary:")
    logger.info(f"  Packages enriched: {stats['components_enriched']}/{total_packages}")

    # Log by source
    for source, count in sorted(stats.get("sources", {}).items()):
        logger.info(f"  Enriched from {source}: {count}")

    if stats["descriptions_added"] > 0:
        logger.info(f"  Descriptions added: {stats['descriptions_added']}")
    if stats["licenses_added"] > 0:
        logger.info(f"  Licenses added: {stats['licenses_added']}")
    if stats["homepages_added"] > 0:
        logger.info(f"  Homepage URLs added: {stats['homepages_added']}")
    if stats["originators_added"] > 0:
        logger.info(f"  Originators added: {stats['originators_added']}")
    if stats["suppliers_added"] > 0:
        logger.info(f"  Suppliers added: {stats['suppliers_added']}")
    if stats["source_info_added"] > 0:
        logger.info(f"  Source info added: {stats['source_info_added']}")
    if stats["external_refs_added"] > 0:
        logger.info(f"  External references added: {stats['external_refs_added']}")
