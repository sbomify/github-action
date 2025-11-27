"""SBOM enrichment using ecosyste.ms API with native library support."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
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
)
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

from .logging_config import logger
from .serialization import serialize_cyclonedx_bom


def _get_package_version() -> str:
    """Get the package version for User-Agent header."""
    try:
        from importlib.metadata import version

        return version("sbomify-github-action")
    except Exception:
        try:
            from pathlib import Path

            import tomllib

            pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                return pyproject_data.get("project", {}).get("version", "unknown")
        except Exception:
            return "unknown"


USER_AGENT = f"sbomify-github-action/{_get_package_version()} (hello@sbomify.com)"
ECOSYSTEMS_API_BASE = "https://packages.ecosyste.ms/api/v1"


# Simple in-memory cache for package metadata
_metadata_cache: Dict[str, Optional[Dict[str, Any]]] = {}


def clear_cache() -> None:
    """Clear all cached metadata."""
    global _metadata_cache
    _metadata_cache.clear()
    logger.debug("Metadata cache cleared")


def get_cache_stats() -> Dict[str, int]:
    """Get cache statistics."""
    return {"entries": len(_metadata_cache)}


def _extract_components_from_cyclonedx(bom: Bom) -> List[Tuple[Component, str]]:
    """
    Extract components from CycloneDX BOM.

    Args:
        bom: Parsed CycloneDX Bom object

    Returns:
        List of tuples (component, purl)
    """
    components = []
    for component in bom.components:
        if component.purl:
            components.append((component, str(component.purl)))
    return components


def _extract_packages_from_spdx(document: Document) -> List[Tuple[Package, str]]:
    """
    Extract packages from SPDX document.

    Args:
        document: Parsed SPDX Document object

    Returns:
        List of tuples (package, purl)
    """
    packages = []
    for package in document.packages:
        # Try to extract PURL from external references
        purl = None
        for ref in package.external_references:
            if ref.reference_type == "purl":
                purl = ref.locator
                break

        if purl:
            packages.append((package, purl))
    return packages


def _fetch_package_metadata(purl: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    """
    Fetch package metadata from ecosyste.ms API with caching.

    Args:
        purl: Package URL
        session: requests.Session with configured headers

    Returns:
        Package metadata dict or None if fetch fails
    """
    # Check cache first
    if purl in _metadata_cache:
        logger.debug(f"Cache hit: {purl}")
        return _metadata_cache[purl]

    try:
        # The API endpoint expects PURL as a query parameter
        url = f"{ECOSYSTEMS_API_BASE}/packages/lookup"
        params = {"purl": purl}

        logger.debug(f"Fetching metadata for: {purl}")
        response = session.get(url, params=params, timeout=30)

        metadata = None
        if response.status_code == 200:
            data = response.json()
            # The API returns an array, take the first result if available
            if isinstance(data, list) and len(data) > 0:
                metadata = data[0]
            elif isinstance(data, dict):
                metadata = data
            else:
                logger.debug(f"No package data found for: {purl}")
        elif response.status_code == 404:
            logger.debug(f"Package not found in ecosyste.ms: {purl}")
        elif response.status_code == 429:
            logger.warning(
                f"Rate limit exceeded for {purl}. "
                "Consider using an API key for higher rate limits. "
                "API keys will be available soon from ecosyste.ms."
            )
        else:
            logger.warning(f"Failed to fetch metadata for {purl}: HTTP {response.status_code}")

        # Cache the result (including None for negative caching)
        _metadata_cache[purl] = metadata
        return metadata

    except requests.exceptions.Timeout:
        logger.warning(f"Timeout fetching metadata for {purl}")
        # Cache negative result for timeouts to avoid repeated timeouts
        _metadata_cache[purl] = None
        return None
    except requests.exceptions.RequestException as e:
        logger.warning(f"Error fetching metadata for {purl}: {e}")
        # Cache negative result for request errors
        _metadata_cache[purl] = None
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching metadata for {purl}: {e}")
        # Don't cache unexpected errors as they might be transient
        return None


def _fetch_all_metadata_sequential(purls: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
    """
    Fetch metadata for all PURLs sequentially.

    Args:
        purls: List of package URLs

    Returns:
        Dictionary mapping PURL to metadata
    """
    metadata_map = {}

    # Use a single session for sequential requests
    with requests.Session() as session:
        session.headers.update({"User-Agent": USER_AGENT})

        # Fetch metadata sequentially
        for purl in purls:
            try:
                metadata = _fetch_package_metadata(purl, session)
                metadata_map[purl] = metadata
            except Exception as e:
                logger.error(f"Unexpected error fetching metadata for {purl}: {e}")
                metadata_map[purl] = None

    return metadata_map


def _enrich_cyclonedx_component(component: Component, metadata: Optional[Dict[str, Any]]) -> List[str]:
    """
    Enrich a CycloneDX component with ecosyste.ms metadata using native library.

    Native fields used:
    - description: Component description
    - licenses: Array of license objects
    - publisher: Publishing entity/primary maintainer
    - externalReferences: URLs for website, vcs, distribution, issue-tracker, etc.

    Args:
        component: Component object to enrich (modified in place)
        metadata: Metadata from ecosyste.ms API

    Returns:
        List of added fields for logging
    """
    if not metadata:
        return []

    added_fields = []

    # Add description (native CycloneDX field)
    if not component.description and metadata.get("description"):
        component.description = metadata["description"]
        added_fields.append("description")

    # Add licenses (native CycloneDX field)
    # Prefer normalized_licenses (array of SPDX identifiers) over licenses (string)
    if metadata.get("normalized_licenses"):
        if not component.licenses or len(component.licenses) == 0:
            # normalized_licenses is an array of SPDX identifiers
            for license_id in metadata["normalized_licenses"]:
                if license_id:
                    license_expr = LicenseExpression(value=license_id)
                    component.licenses.add(license_expr)
            license_display = ", ".join(metadata["normalized_licenses"])
            added_fields.append(f"licenses ({license_display})")
    elif metadata.get("licenses"):
        if not component.licenses or len(component.licenses) == 0:
            # licenses is a string (could be comma-separated) - fallback
            licenses_str = str(metadata["licenses"])
            for license_name in licenses_str.split(","):
                license_name = license_name.strip()
                if license_name:
                    license_expr = LicenseExpression(value=license_name)
                    component.licenses.add(license_expr)
            license_display = licenses_str
            added_fields.append(f"licenses ({license_display})")

    # Add publisher (native CycloneDX field) - use first maintainer if available
    if not component.publisher and metadata.get("maintainers") and isinstance(metadata["maintainers"], list):
        if metadata["maintainers"]:
            maintainer = metadata["maintainers"][0]
            publisher_name = maintainer.get("name") or maintainer.get("login")
            if publisher_name:
                component.publisher = publisher_name
                added_fields.append(f"publisher ({publisher_name})")

    # Add external references (native CycloneDX field)
    def _add_external_ref(ref_type: ExternalReferenceType, url: str) -> bool:
        """Helper to add external reference if URL exists and not already present. Returns True if added."""
        if url:
            # Check if this type/URL combo already exists
            for existing_ref in component.external_references:
                if existing_ref.type == ref_type and str(existing_ref.url) == url:
                    return False
            # Add the reference
            component.external_references.add(ExternalReference(type=ref_type, url=XsUri(url)))
            return True
        return False

    # Website/homepage
    if metadata.get("homepage"):
        if _add_external_ref(ExternalReferenceType.WEBSITE, metadata["homepage"]):
            added_fields.append("homepage URL")

    # VCS repository
    if metadata.get("repository_url"):
        if _add_external_ref(ExternalReferenceType.VCS, metadata["repository_url"]):
            added_fields.append("repository URL")

    # Distribution (use registry URL which points to the package manager like https://pypi.org)
    if metadata.get("registry_url"):
        if _add_external_ref(ExternalReferenceType.DISTRIBUTION, metadata["registry_url"]):
            added_fields.append("distribution URL")

    # Issue tracker (use repo_metadata.html_url + /issues for GitHub repos)
    if metadata.get("repo_metadata") and metadata["repo_metadata"].get("html_url"):
        html_url = metadata["repo_metadata"]["html_url"]
        repo_metadata = metadata["repo_metadata"]

        # For GitHub repos, verify issues are enabled before adding
        if "github.com" in html_url:
            issues_enabled = False

            # First check if repo_metadata has has_issues field (from GitHub API)
            if "has_issues" in repo_metadata:
                issues_enabled = repo_metadata.get("has_issues", False)
            else:
                # Fall back to checking if issues URL is accessible
                issues_url = f"{html_url}/issues"
                try:
                    # Use HEAD request to check if issues page exists (more efficient than GET)
                    response = requests.head(issues_url, timeout=5, allow_redirects=True)
                    # Consider 200 OK as issues enabled
                    issues_enabled = response.status_code == 200
                except (requests.exceptions.RequestException, Exception):
                    # If we can't verify, don't add the issue tracker
                    issues_enabled = False

            if issues_enabled:
                issues_url = f"{html_url}/issues"
                if _add_external_ref(ExternalReferenceType.ISSUE_TRACKER, issues_url):
                    added_fields.append("issue-tracker URL")

    return added_fields


def _enrich_spdx_package(package: Package, metadata: Optional[Dict[str, Any]]) -> List[str]:
    """
    Enrich an SPDX package with ecosyste.ms metadata using native library.

    Native fields used:
    - description: Package description
    - homepage: Package homepage URL
    - download_location: Where to download the package
    - license_declared: Declared license
    - source_info: Information about source code
    - originator: Original creator/maintainer
    - supplier: Current supplier/maintainer
    - external_references: External references (package manager, etc.)

    Args:
        package: Package object to enrich (modified in place)
        metadata: Metadata from ecosyste.ms API

    Returns:
        List of added fields for logging
    """
    if not metadata:
        return []

    added_fields = []

    # Add description (native SPDX field)
    if not package.description and metadata.get("description"):
        package.description = metadata["description"]
        added_fields.append("description")

    # Add homepage (native SPDX field)
    if not package.homepage and metadata.get("homepage"):
        package.homepage = metadata["homepage"]
        added_fields.append("homepage")

    # Add download location (native SPDX field)
    if not package.download_location or package.download_location == "NOASSERTION":
        # Priority order for download location:
        # 1. registry_url (package manager page)
        # 2. repo_metadata.download_url (direct download from repo)
        # 3. repository_url (source repository)
        download_url = None

        if metadata.get("registry_url"):
            download_url = metadata["registry_url"]
        elif metadata.get("repo_metadata") and metadata["repo_metadata"].get("download_url"):
            download_url = metadata["repo_metadata"]["download_url"]
        elif metadata.get("repository_url"):
            download_url = metadata["repository_url"]

        if download_url:
            package.download_location = download_url
            added_fields.append("downloadLocation")

    # Add licenses (native SPDX field)
    # Note: SPDX license expressions are complex and require proper parsing
    # For now, we'll add license information via comments/descriptions
    # TODO: Implement proper SPDX license expression handling
    if metadata.get("normalized_licenses") or metadata.get("licenses"):
        # Add license information to the package comment field instead
        if metadata.get("normalized_licenses"):
            license_info = ", ".join(metadata["normalized_licenses"])
        else:
            license_info = str(metadata.get("licenses", ""))

        if license_info:
            # Append to license_comment if it exists, otherwise create it
            if package.license_comment:
                package.license_comment += f" | Licenses from ecosyste.ms: {license_info}"
            else:
                package.license_comment = f"Licenses from ecosyste.ms: {license_info}"
            added_fields.append(f"license comment ({license_info})")

    # Add source info (native SPDX field) - include repository URL
    if not package.source_info and metadata.get("repository_url"):
        package.source_info = f"acquired from {metadata['repository_url']}"
        added_fields.append("sourceInfo")

    # Add originator (native SPDX field) - first maintainer
    if not package.originator and metadata.get("maintainers") and isinstance(metadata["maintainers"], list):
        if metadata["maintainers"]:
            maintainer = metadata["maintainers"][0]
            name = maintainer.get("name") or maintainer.get("login", "")
            email = maintainer.get("email", "")
            if name:
                originator_str = name
                if email:
                    originator_str += f" ({email})"
                package.originator = Actor(ActorType.PERSON, originator_str)
                added_fields.append(f"originator ({name})")

    # Add supplier (native SPDX field) - can be organization or primary maintainer
    if not package.supplier:
        # Priority order for supplier:
        # 1. ecosystem (ecosystem/registry name)
        # 2. repo_metadata.owner (repository owner/organization)
        # 3. maintainers (first maintainer as person)
        if metadata.get("ecosystem"):
            ecosystem_name = metadata["ecosystem"]
            package.supplier = Actor(ActorType.ORGANIZATION, ecosystem_name)
            added_fields.append(f"supplier ({ecosystem_name})")
        elif metadata.get("repo_metadata") and metadata["repo_metadata"].get("owner"):
            owner_info = metadata["repo_metadata"]["owner"]
            # owner can be a dict with login/name or just a string
            if isinstance(owner_info, dict):
                owner_name = owner_info.get("name") or owner_info.get("login", "")
                owner_type_str = owner_info.get("type", "Organization")  # GitHub API provides type
                owner_type = ActorType.ORGANIZATION if owner_type_str == "Organization" else ActorType.PERSON
                if owner_name:
                    package.supplier = Actor(owner_type, owner_name)
                    added_fields.append(f"supplier ({owner_name})")
            elif isinstance(owner_info, str):
                package.supplier = Actor(ActorType.ORGANIZATION, owner_info)
                added_fields.append(f"supplier ({owner_info})")
        elif metadata.get("maintainers") and isinstance(metadata["maintainers"], list):
            # Otherwise use first maintainer
            if metadata["maintainers"]:
                maintainer = metadata["maintainers"][0]
                name = maintainer.get("name") or maintainer.get("login", "")
                if name:
                    package.supplier = Actor(ActorType.PERSON, name)
                    added_fields.append(f"supplier ({name})")

    # Add external references (native SPDX field)
    def _add_external_ref(category: ExternalPackageRefCategory, ref_type: str, locator: str) -> bool:
        """Helper to add external reference if not already exists. Returns True if added."""
        if locator:
            # Check if this locator already exists
            for existing_ref in package.external_references:
                if existing_ref.locator == locator:
                    return False
            # Add the reference
            package.external_references.append(
                ExternalPackageRef(
                    category=category,
                    reference_type=ref_type,
                    locator=locator,
                )
            )
            return True
        return False

    # Add registry URL (PACKAGE-MANAGER category)
    if metadata.get("registry_url"):
        if _add_external_ref(ExternalPackageRefCategory.PACKAGE_MANAGER, "url", metadata["registry_url"]):
            added_fields.append("externalRef (registry)")

    # Add documentation URL (OTHER category)
    if metadata.get("documentation_url"):
        if _add_external_ref(ExternalPackageRefCategory.OTHER, "url", metadata["documentation_url"]):
            added_fields.append("externalRef (documentation)")

    return added_fields


def _enrich_cyclonedx_bom_with_metadata(bom: Bom, metadata_map: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, int]:
    """
    Enrich CycloneDX BOM with fetched metadata.

    Args:
        bom: Bom object to enrich (modified in place)
        metadata_map: Map of PURL to metadata

    Returns:
        Enrichment statistics
    """
    # Track enrichment statistics
    stats = {
        "components_enriched": 0,
        "descriptions_added": 0,
        "licenses_added": 0,
        "publishers_added": 0,
        "homepages_added": 0,
        "repositories_added": 0,
        "distributions_added": 0,
        "issue_trackers_added": 0,
    }

    for component in bom.components:
        purl = str(component.purl) if component.purl else None
        if purl and purl in metadata_map:
            added_fields = _enrich_cyclonedx_component(component, metadata_map[purl])

            if added_fields:
                stats["components_enriched"] += 1
                for field in added_fields:
                    if "description" in field:
                        stats["descriptions_added"] += 1
                    elif "licenses" in field:
                        stats["licenses_added"] += 1
                    elif "publisher" in field:
                        stats["publishers_added"] += 1
                    elif "homepage" in field:
                        stats["homepages_added"] += 1
                    elif "repository" in field:
                        stats["repositories_added"] += 1
                    elif "distribution" in field:
                        stats["distributions_added"] += 1
                    elif "issue-tracker" in field:
                        stats["issue_trackers_added"] += 1

    return stats


def _enrich_spdx_document_with_metadata(
    document: Document, metadata_map: Dict[str, Optional[Dict[str, Any]]]
) -> Dict[str, int]:
    """
    Enrich SPDX document with fetched metadata.

    Args:
        document: Document object to enrich (modified in place)
        metadata_map: Map of PURL to metadata

    Returns:
        Enrichment statistics
    """
    # Track enrichment statistics
    stats = {
        "components_enriched": 0,
        "descriptions_added": 0,
        "licenses_added": 0,
        "homepages_added": 0,
        "originators_added": 0,
        "suppliers_added": 0,
        "source_info_added": 0,
        "external_refs_added": 0,
    }

    for package in document.packages:
        # Find PURL in external references
        purl = None
        for ref in package.external_references:
            if ref.reference_type == "purl":
                purl = ref.locator
                break

        if purl and purl in metadata_map:
            added_fields = _enrich_spdx_package(package, metadata_map[purl])

            if added_fields:
                stats["components_enriched"] += 1
                for field in added_fields:
                    if "description" in field:
                        stats["descriptions_added"] += 1
                    elif "license" in field:
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
    Enrich SBOM with metadata from ecosyste.ms API using native libraries.

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save enriched SBOM

    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If SBOM format is invalid
        Exception: For other errors during enrichment
    """
    logger.info(f"Starting SBOM enrichment with ecosyste.ms for: {input_file}")

    input_path = Path(input_file)
    output_path = Path(output_file)

    # Try to detect format
    try:
        with open(input_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input SBOM file not found: {input_file}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in SBOM file: {e}")

    # Detect and process based on format
    if data.get("bomFormat") == "CycloneDX":
        logger.info("Processing CycloneDX SBOM")
        # Detect spec version for proper output serialization
        spec_version = data.get("specVersion", "1.6")

        # Parse as CycloneDX
        bom = Bom.from_json(data)

        # Extract components
        components = _extract_components_from_cyclonedx(bom)
        if not components:
            logger.warning("No components with PURLs found in SBOM, skipping enrichment")
            # Write as-is using proper serialization with correct version
            serialized = serialize_cyclonedx_bom(bom, spec_version)
            with open(output_path, "w") as f:
                f.write(serialized)
            return

        logger.info(f"Found {len(components)} components to enrich")

        # Extract PURLs
        purls = [purl for _, purl in components]

        # Fetch metadata sequentially
        metadata_map = _fetch_all_metadata_sequential(purls)

        # Count successful fetches
        successful_fetches = sum(1 for v in metadata_map.values() if v is not None)
        logger.info(f"Successfully fetched metadata for {successful_fetches}/{len(purls)} components")

        # Log cache statistics
        cache_stats = get_cache_stats()
        logger.info(f"Cache statistics: {cache_stats['entries']} entries cached")

        # Enrich BOM
        stats = _enrich_cyclonedx_bom_with_metadata(bom, metadata_map)

        # Print enrichment summary
        logger.info("Enrichment Summary:")
        logger.info(f"  Components enriched: {stats['components_enriched']}/{len(components)}")

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

        # Write enriched SBOM using proper serialization with correct version
        try:
            serialized = serialize_cyclonedx_bom(bom, spec_version)
            with open(output_path, "w") as f:
                f.write(serialized)
            logger.info(f"Enriched SBOM written to: {output_file}")
        except Exception as e:
            raise Exception(f"Failed to write enriched SBOM: {e}")

    elif data.get("spdxVersion"):
        logger.info("Processing SPDX SBOM")
        # Parse as SPDX
        document = spdx_parse_file(str(input_path))

        # Extract packages
        packages = _extract_packages_from_spdx(document)
        if not packages:
            logger.warning("No packages with PURLs found in SBOM, skipping enrichment")
            # Write as-is
            spdx_write_file(document, str(output_path), validate=False)
            return

        logger.info(f"Found {len(packages)} packages to enrich")

        # Extract PURLs
        purls = [purl for _, purl in packages]

        # Fetch metadata sequentially
        metadata_map = _fetch_all_metadata_sequential(purls)

        # Count successful fetches
        successful_fetches = sum(1 for v in metadata_map.values() if v is not None)
        logger.info(f"Successfully fetched metadata for {successful_fetches}/{len(purls)} packages")

        # Log cache statistics
        cache_stats = get_cache_stats()
        logger.info(f"Cache statistics: {cache_stats['entries']} entries cached")

        # Enrich document
        stats = _enrich_spdx_document_with_metadata(document, metadata_map)

        # Print enrichment summary
        logger.info("Enrichment Summary:")
        logger.info(f"  Packages enriched: {stats['components_enriched']}/{len(packages)}")

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

        # Write enriched SBOM
        try:
            spdx_write_file(document, str(output_path), validate=False)
            logger.info(f"Enriched SBOM written to: {output_file}")
        except Exception as e:
            raise Exception(f"Failed to write enriched SBOM: {e}")

    else:
        raise ValueError("Neither CycloneDX nor SPDX format found in JSON file")
