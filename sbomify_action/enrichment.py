"""SBOM enrichment using ecosyste.ms API with native library support."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.license import LicenseExpression
from packageurl import PackageURL
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

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
from .http_client import USER_AGENT
from .logging_config import logger
from .serialization import serialize_cyclonedx_bom

ECOSYSTEMS_API_BASE = "https://packages.ecosyste.ms/api/v1"
PYPI_API_BASE = "https://pypi.org/pypi"

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

# OS package types that ecosyste.ms doesn't support but we can enrich via PURL parsing
OS_PACKAGE_TYPES = {"deb", "rpm", "apk", "alpm", "ebuild"}

# Mapping of PURL namespace to supplier organization name
NAMESPACE_TO_SUPPLIER: Dict[str, str] = {
    # Debian-based
    "debian": "Debian Project",
    "ubuntu": "Canonical Ltd",
    # Red Hat-based (rpm)
    "redhat": "Red Hat, Inc.",
    "rhel": "Red Hat, Inc.",
    "centos": "CentOS Project",
    "fedora": "Fedora Project",
    "amazon": "Amazon Web Services",
    "oracle": "Oracle Corporation",
    "rocky": "Rocky Enterprise Software Foundation",
    "almalinux": "AlmaLinux OS Foundation",
    # Alpine (apk)
    "alpine": "Alpine Linux",
    # Other distros
    "arch": "Arch Linux",
    "gentoo": "Gentoo Foundation",
    "opensuse": "openSUSE Project",
    "suse": "SUSE LLC",
    "wolfi": "Chainguard, Inc.",
    "chainguard": "Chainguard, Inc.",
}

# Mapping of PURL type/namespace to package tracker URL templates
# Note: Some URLs are version/arch agnostic (e.g., use search or generic landing pages)
# to avoid hardcoding specific versions or architectures
PACKAGE_TRACKER_URLS: Dict[str, Dict[str, str]] = {
    "deb": {
        "debian": "https://tracker.debian.org/pkg/{name}",
        "ubuntu": "https://launchpad.net/ubuntu/+source/{name}",
    },
    "rpm": {
        "fedora": "https://packages.fedoraproject.org/pkgs/{name}",
        "centos": "https://git.centos.org/rpms/{name}",
        "redhat": "https://access.redhat.com/downloads/content/package-browser",
        "rhel": "https://access.redhat.com/downloads/content/package-browser",
        "amazon": "https://docs.aws.amazon.com/linux/",
        # Rocky uses pkgs.org search which works across versions/architectures
        "rocky": "https://pkgs.org/search/?q={name}",
        # AlmaLinux uses pkgs.org search which works across versions/architectures
        "almalinux": "https://pkgs.org/search/?q={name}",
    },
    "apk": {
        # Alpine URL defaults to edge/main/x86_64 but the package page shows all variants
        "alpine": "https://pkgs.alpinelinux.org/package/edge/main/x86_64/{name}",
        "wolfi": "https://github.com/wolfi-dev/os/tree/main/{name}",
        # Chainguard images catalog with package name in search
        "chainguard": "https://images.chainguard.dev/directory/image/{name}/overview",
    },
}


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


def _parse_purl_safe(purl_str: str) -> Optional[PackageURL]:
    """
    Safely parse a PURL string.

    Args:
        purl_str: Package URL string

    Returns:
        PackageURL object or None if parsing fails
    """
    try:
        return PackageURL.from_string(purl_str)
    except ValueError as e:
        logger.debug(f"Failed to parse PURL '{purl_str}': {e}")
        return None


def _get_supplier_from_purl(purl: PackageURL) -> Optional[str]:
    """
    Get supplier organization name from PURL namespace.

    Args:
        purl: Parsed PackageURL object

    Returns:
        Supplier name or None if not found
    """
    if purl.namespace:
        # Check our mapping first
        supplier = NAMESPACE_TO_SUPPLIER.get(purl.namespace.lower())
        if supplier:
            return supplier
        # Fall back to capitalizing the namespace
        return f"{purl.namespace.title()} Project"
    return None


def _get_package_tracker_url(purl: PackageURL) -> Optional[str]:
    """
    Get package tracker URL for OS packages.

    Args:
        purl: Parsed PackageURL object

    Returns:
        Package tracker URL or None if not available
    """
    if purl.type in PACKAGE_TRACKER_URLS:
        type_urls = PACKAGE_TRACKER_URLS[purl.type]
        if purl.namespace and purl.namespace.lower() in type_urls:
            url_template = type_urls[purl.namespace.lower()]
            return url_template.format(name=purl.name)
    return None


def _is_os_package_type(purl_str: str) -> bool:
    """
    Check if a PURL represents an OS package type.

    Args:
        purl_str: Package URL string

    Returns:
        True if this is an OS package type (deb, rpm, apk, etc.)
    """
    purl = _parse_purl_safe(purl_str)
    if purl:
        return purl.type in OS_PACKAGE_TYPES
    return False


def _is_lockfile_component(component: Component) -> bool:
    """
    Check if a CycloneDX component represents a lockfile artifact.

    These are "application" type components created by scanners like Trivy
    to represent the scanned lockfile itself (e.g., uv.lock, requirements.txt).
    They are not real packages and should be filtered out.

    Args:
        component: CycloneDX Component object

    Returns:
        True if this is a lockfile component that should be filtered out
    """
    # Must be application type
    if component.type.name.lower() != "application":
        return False

    # Must have no PURL (lockfiles aren't real packages)
    if component.purl:
        return False

    # Check if name matches known lockfile patterns
    if component.name and component.name in ALL_LOCKFILE_NAMES:
        return True

    return False


def _filter_lockfile_components(bom: Bom) -> int:
    """
    Remove lockfile components from a CycloneDX BOM.

    Args:
        bom: CycloneDX Bom object (modified in place)

    Returns:
        Number of lockfile components removed
    """
    # Find lockfile components to remove
    lockfile_components = [c for c in bom.components if _is_lockfile_component(c)]

    # Remove them
    for component in lockfile_components:
        bom.components.discard(component)
        logger.info(f"Filtered out lockfile component: {component.name}")

    return len(lockfile_components)


def _enrich_cyclonedx_component_from_purl(component: Component, purl_str: str) -> List[str]:
    """
    Enrich a CycloneDX component using PURL parsing for OS packages.

    This is used as a fallback when ecosyste.ms doesn't have data for the package.
    Works for pkg:deb, pkg:rpm, pkg:apk and similar OS package types.

    Args:
        component: Component object to enrich (modified in place)
        purl_str: Package URL string

    Returns:
        List of added fields for logging
    """
    purl = _parse_purl_safe(purl_str)
    if not purl or purl.type not in OS_PACKAGE_TYPES:
        return []

    added_fields = []

    # Add publisher from PURL namespace
    if not component.publisher:
        supplier = _get_supplier_from_purl(purl)
        if supplier:
            component.publisher = supplier
            added_fields.append(f"publisher ({supplier})")

    # Add package tracker URL as website external reference
    tracker_url = _get_package_tracker_url(purl)
    if tracker_url:
        # Check if this URL already exists
        url_exists = any(str(ref.url) == tracker_url for ref in component.external_references)
        if not url_exists:
            component.external_references.add(
                ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri(tracker_url))
            )
            added_fields.append("package tracker URL")

    return added_fields


def _enrich_spdx_package_from_purl(package: Package, purl_str: str) -> List[str]:
    """
    Enrich an SPDX package using PURL parsing for OS packages.

    This is used as a fallback when ecosyste.ms doesn't have data for the package.
    Works for pkg:deb, pkg:rpm, pkg:apk and similar OS package types.

    Args:
        package: Package object to enrich (modified in place)
        purl_str: Package URL string

    Returns:
        List of added fields for logging
    """
    purl = _parse_purl_safe(purl_str)
    if not purl or purl.type not in OS_PACKAGE_TYPES:
        return []

    added_fields = []

    # Add supplier from PURL namespace
    if not package.supplier:
        supplier = _get_supplier_from_purl(purl)
        if supplier:
            package.supplier = Actor(ActorType.ORGANIZATION, supplier)
            added_fields.append(f"supplier ({supplier})")

    # Add homepage from package tracker URL
    tracker_url = _get_package_tracker_url(purl)
    if tracker_url and not package.homepage:
        package.homepage = tracker_url
        added_fields.append("homepage")

    return added_fields


def _enrich_os_component(component: Component) -> List[str]:
    """
    Enrich an operating-system type component with supplier info.

    For components like the base OS (e.g., debian, ubuntu), add supplier
    information based on the component name.

    Args:
        component: Component object to enrich (modified in place)

    Returns:
        List of added fields for logging
    """
    # CycloneDX ComponentType enum uses OPERATING_SYSTEM (with underscore)
    if component.type.name.lower() != "operating_system":
        return []

    added_fields = []
    os_name = component.name.lower() if component.name else ""

    # Add publisher if not present
    if not component.publisher:
        supplier = NAMESPACE_TO_SUPPLIER.get(os_name)
        if supplier:
            component.publisher = supplier
            added_fields.append(f"publisher ({supplier})")

    return added_fields


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


def _fetch_pypi_metadata(package_name: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    """
    Fetch package metadata from PyPI JSON API.

    This is used as a fallback when ecosyste.ms doesn't have data for a PyPI package.

    Args:
        package_name: Name of the PyPI package
        session: requests.Session with configured headers

    Returns:
        Package metadata dict (normalized to ecosyste.ms format) or None if fetch fails
    """
    cache_key = f"pypi:{package_name}"

    # Check cache first
    if cache_key in _metadata_cache:
        logger.debug(f"Cache hit (PyPI): {package_name}")
        return _metadata_cache[cache_key]

    try:
        url = f"{PYPI_API_BASE}/{package_name}/json"
        logger.debug(f"Fetching PyPI metadata for: {package_name}")
        response = session.get(url, timeout=30)

        metadata = None
        if response.status_code == 200:
            data = response.json()
            info = data.get("info", {})

            # Normalize PyPI response to ecosyste.ms format
            metadata = {
                "description": info.get("summary"),
                "homepage": info.get("home_page"),
                "licenses": info.get("license"),
                "registry_url": f"https://pypi.org/project/{package_name}/",
            }

            # Extract maintainers from author/maintainer fields
            maintainers = []
            if info.get("author"):
                maintainer = {"name": info["author"]}
                if info.get("author_email"):
                    maintainer["email"] = info["author_email"]
                maintainers.append(maintainer)
            elif info.get("maintainer"):
                maintainer = {"name": info["maintainer"]}
                if info.get("maintainer_email"):
                    maintainer["email"] = info["maintainer_email"]
                maintainers.append(maintainer)
            if maintainers:
                metadata["maintainers"] = maintainers

            # Extract URLs from project_urls
            project_urls = info.get("project_urls") or {}
            for key, url_value in project_urls.items():
                key_lower = key.lower()
                if "source" in key_lower or "repository" in key_lower or "github" in key_lower:
                    metadata["repository_url"] = url_value
                elif "issue" in key_lower or "bug" in key_lower or "tracker" in key_lower:
                    # Store for issue tracker
                    if "repo_metadata" not in metadata:
                        metadata["repo_metadata"] = {}
                    # Only strip "/issues" suffix if the URL actually ends with it
                    if url_value.endswith("/issues"):
                        metadata["repo_metadata"]["html_url"] = url_value[:-7]
                    else:
                        metadata["repo_metadata"]["html_url"] = url_value
                    metadata["repo_metadata"]["has_issues"] = True
                elif "documentation" in key_lower or "docs" in key_lower:
                    metadata["documentation_url"] = url_value
                elif "homepage" in key_lower and not metadata.get("homepage"):
                    metadata["homepage"] = url_value

            logger.debug(f"Successfully fetched PyPI metadata for: {package_name}")
        elif response.status_code == 404:
            logger.debug(f"Package not found on PyPI: {package_name}")
        else:
            logger.warning(f"Failed to fetch PyPI metadata for {package_name}: HTTP {response.status_code}")

        # Cache the result
        _metadata_cache[cache_key] = metadata
        return metadata

    except requests.exceptions.Timeout:
        logger.warning(f"Timeout fetching PyPI metadata for {package_name}")
        _metadata_cache[cache_key] = None
        return None
    except requests.exceptions.RequestException as e:
        logger.warning(f"Error fetching PyPI metadata for {package_name}: {e}")
        _metadata_cache[cache_key] = None
        return None
    except json.JSONDecodeError as e:
        logger.warning(f"JSON decode error fetching PyPI metadata for {package_name}: {e}")
        _metadata_cache[cache_key] = None
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


def _add_enrichment_source_property(component: Component, source: str) -> None:
    """
    Add enrichment source property to a CycloneDX component.

    Args:
        component: Component object to add property to
        source: Enrichment source (e.g., "ecosyste.ms", "pypi.org", "purl")
    """
    from cyclonedx.model import Property

    property_name = "sbomify:enrichment:source"

    # Check if property already exists
    for prop in component.properties:
        if prop.name == property_name:
            return  # Already has enrichment source

    component.properties.add(Property(name=property_name, value=source))


def _add_enrichment_source_comment(package: Package, source: str) -> None:
    """
    Add enrichment source comment to an SPDX package.

    Args:
        package: Package object to add comment to
        source: Enrichment source (e.g., "ecosyste.ms", "pypi.org", "purl")
    """
    enrichment_note = f"Enriched by sbomify from {source}"

    if package.comment:
        # Append to existing comment if not already present
        if enrichment_note not in package.comment:
            package.comment = f"{package.comment} | {enrichment_note}"
    else:
        package.comment = enrichment_note


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
    # Only add licenses if the component has NO existing licenses
    # CycloneDX spec requires multiple licenses to be combined into a single LicenseExpression
    # using operators like OR/AND, not as separate LicenseExpression objects
    # Prefer normalized_licenses (array of SPDX identifiers) over licenses (string)
    has_licenses = component.licenses is not None and len(component.licenses) > 0

    if not has_licenses:
        if metadata.get("normalized_licenses"):
            # normalized_licenses is an array of SPDX identifiers
            licenses = [lic for lic in metadata["normalized_licenses"] if lic]
            if licenses:
                # Combine multiple licenses with OR operator into a single expression
                if len(licenses) == 1:
                    license_expression = licenses[0]
                else:
                    license_expression = " OR ".join(licenses)

                license_expr = LicenseExpression(value=license_expression)
                component.licenses.add(license_expr)
                added_fields.append(f"licenses ({license_expression})")
        elif metadata.get("licenses"):
            # licenses is a string (could be comma-separated) - fallback
            licenses_str = str(metadata["licenses"]).strip()
            if licenses_str:
                license_expr = LicenseExpression(value=licenses_str)
                component.licenses.add(license_expr)
                added_fields.append(f"licenses ({licenses_str})")

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
    # Use proper SPDX license expression handling with the spdx-tools library
    if not package.license_declared:
        if metadata.get("normalized_licenses") or metadata.get("licenses"):
            # Prefer normalized_licenses (array of SPDX identifiers)
            if metadata.get("normalized_licenses"):
                licenses = metadata["normalized_licenses"]
                # Build SPDX license expression from array
                # If multiple licenses, join with OR operator
                if len(licenses) == 1:
                    license_expression = licenses[0]
                else:
                    license_expression = " OR ".join(licenses)
            else:
                # Fallback to licenses string field
                license_expression = str(metadata.get("licenses", ""))

            if license_expression:
                # Parse and set the license expression using spdx-tools parser
                license_parser = LicenseExpressionParser()
                try:
                    parsed_expression = license_parser.parse_license_expression(license_expression)
                    package.license_declared = parsed_expression
                    added_fields.append(f"license_declared ({license_expression})")
                except Exception as e:
                    # If parsing fails, add to license_comment instead
                    logger.warning(f"Failed to parse license expression '{license_expression}': {e}")
                    if package.license_comment:
                        package.license_comment += f" | Licenses from ecosyste.ms: {license_expression}"
                    else:
                        package.license_comment = f"Licenses from ecosyste.ms: {license_expression}"
                    added_fields.append(f"license_comment ({license_expression})")

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


def _enrich_cyclonedx_bom_with_metadata(
    bom: Bom, metadata_map: Dict[str, Optional[Dict[str, Any]]], session: requests.Session
) -> Dict[str, int]:
    """
    Enrich CycloneDX BOM with fetched metadata.

    Uses ecosyste.ms metadata when available, falls back to PyPI API for
    pypi packages, and PURL-based enrichment for OS packages (deb, rpm, apk).
    Also handles operating-system type components separately.

    Args:
        bom: Bom object to enrich (modified in place)
        metadata_map: Map of PURL to metadata
        session: requests.Session for PyPI fallback calls

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
        "os_components_enriched": 0,
        "purl_fallback_enriched": 0,
        "pypi_fallback_enriched": 0,
        "ecosystems_enriched": 0,
    }

    for component in bom.components:
        added_fields = []
        enrichment_source = None
        purl = str(component.purl) if component.purl else None

        # First, handle operating-system type components (no PURL typically)
        # CycloneDX ComponentType enum uses OPERATING_SYSTEM (with underscore)
        if component.type.name.lower() == "operating_system":
            added_fields = _enrich_os_component(component)
            if added_fields:
                enrichment_source = "purl"
                stats["os_components_enriched"] += 1
                stats["components_enriched"] += 1
                for field in added_fields:
                    if "publisher" in field:
                        stats["publishers_added"] += 1
                # Add enrichment source property
                _add_enrichment_source_property(component, enrichment_source)
            continue

        # For components with PURLs, try ecosyste.ms first
        if purl and purl in metadata_map:
            metadata = metadata_map[purl]
            if metadata:
                # ecosyste.ms has data for this package
                added_fields = _enrich_cyclonedx_component(component, metadata)
                if added_fields:
                    enrichment_source = "ecosyste.ms"
                    stats["ecosystems_enriched"] += 1
            else:
                # ecosyste.ms returned no data, try fallbacks
                parsed_purl = _parse_purl_safe(purl)
                if parsed_purl:
                    if parsed_purl.type == "pypi":
                        # Try PyPI API fallback
                        pypi_metadata = _fetch_pypi_metadata(parsed_purl.name, session)
                        if pypi_metadata:
                            added_fields = _enrich_cyclonedx_component(component, pypi_metadata)
                            if added_fields:
                                enrichment_source = "pypi.org"
                                stats["pypi_fallback_enriched"] += 1
                    elif parsed_purl.type in OS_PACKAGE_TYPES:
                        # Try PURL-based fallback for OS packages
                        added_fields = _enrich_cyclonedx_component_from_purl(component, purl)
                        if added_fields:
                            enrichment_source = "purl"
                            stats["purl_fallback_enriched"] += 1

            if added_fields:
                stats["components_enriched"] += 1
                # Add enrichment source property
                if enrichment_source:
                    _add_enrichment_source_property(component, enrichment_source)
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


def _enrich_spdx_document_with_metadata(
    document: Document, metadata_map: Dict[str, Optional[Dict[str, Any]]], session: requests.Session
) -> Dict[str, int]:
    """
    Enrich SPDX document with fetched metadata.

    Uses ecosyste.ms metadata when available, falls back to PyPI API for
    pypi packages, and PURL-based enrichment for OS packages (deb, rpm, apk).

    Args:
        document: Document object to enrich (modified in place)
        metadata_map: Map of PURL to metadata
        session: requests.Session for PyPI fallback calls

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
        "purl_fallback_enriched": 0,
        "pypi_fallback_enriched": 0,
        "ecosystems_enriched": 0,
    }

    for package in document.packages:
        added_fields = []
        enrichment_source = None

        # Find PURL in external references
        purl = None
        for ref in package.external_references:
            if ref.reference_type == "purl":
                purl = ref.locator
                break

        if purl and purl in metadata_map:
            metadata = metadata_map[purl]
            if metadata:
                # ecosyste.ms has data for this package
                added_fields = _enrich_spdx_package(package, metadata)
                if added_fields:
                    enrichment_source = "ecosyste.ms"
                    stats["ecosystems_enriched"] += 1
            else:
                # ecosyste.ms returned no data, try fallbacks
                parsed_purl = _parse_purl_safe(purl)
                if parsed_purl:
                    if parsed_purl.type == "pypi":
                        # Try PyPI API fallback
                        pypi_metadata = _fetch_pypi_metadata(parsed_purl.name, session)
                        if pypi_metadata:
                            added_fields = _enrich_spdx_package(package, pypi_metadata)
                            if added_fields:
                                enrichment_source = "pypi.org"
                                stats["pypi_fallback_enriched"] += 1
                    elif parsed_purl.type in OS_PACKAGE_TYPES:
                        # Try PURL-based fallback for OS packages
                        added_fields = _enrich_spdx_package_from_purl(package, purl)
                        if added_fields:
                            enrichment_source = "purl"
                            stats["purl_fallback_enriched"] += 1

            if added_fields:
                stats["components_enriched"] += 1
                # Add enrichment source comment
                if enrichment_source:
                    _add_enrichment_source_comment(package, enrichment_source)
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
        # Validate required fields before processing
        spec_version = data.get("specVersion")
        if spec_version is None:
            raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")

        # Workaround for CycloneDX library deserialization bug with tools
        # When tools are serialized as legacy array format, vendor dicts aren't deserialized properly
        # This causes "unhashable type: 'dict'" errors during parsing
        # Convert legacy array format to modern components format for 1.5+
        if "metadata" in data and "tools" in data["metadata"]:
            tools_data = data["metadata"]["tools"]

            # If tools is a list (legacy format) and we're using spec 1.5+, convert to modern format
            if isinstance(tools_data, list):
                # For CycloneDX 1.5+, convert to object format with components
                # For 1.4 and earlier, the array format is standard and should work
                spec_version_parts = spec_version.split(".")
                major = int(spec_version_parts[0]) if len(spec_version_parts) > 0 else 1
                minor = int(spec_version_parts[1]) if len(spec_version_parts) > 1 else 0
                is_v15_or_later = (major > 1) or (major == 1 and minor >= 5)

                if is_v15_or_later:
                    logger.debug(
                        f"Converting {len(tools_data)} tools from legacy array to components format for spec {spec_version}"
                    )
                    # In modern format (1.5+), tools go in the components array
                    # Components use 'group' field (not 'manufacturer') to represent the tool vendor
                    # Tool.from_component() maps component.group -> tool.vendor
                    components = []
                    for tool_data in tools_data:
                        component_data = tool_data.copy()
                        # Rename vendor -> group for components (this is the correct mapping)
                        if "vendor" in component_data:
                            component_data["group"] = component_data.pop("vendor")
                        # Ensure type is set (required for components)
                        if "type" not in component_data:
                            component_data["type"] = "application"
                        components.append(component_data)

                    data["metadata"]["tools"] = {"components": components, "services": []}
                else:
                    # For 1.4 and earlier, keep the array format but ensure vendor dicts are properly structured
                    logger.debug(f"Keeping legacy array format for spec {spec_version}")

        # Parse as CycloneDX
        try:
            bom = Bom.from_json(data)
        except Exception as e:
            raise SBOMValidationError(f"Failed to parse CycloneDX SBOM: {e}")

        # Filter out lockfile components (e.g., uv.lock, requirements.txt)
        lockfiles_removed = _filter_lockfile_components(bom)
        if lockfiles_removed > 0:
            logger.info(f"Removed {lockfiles_removed} lockfile component(s) from SBOM")

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

        # Use a session for all API calls
        with requests.Session() as session:
            session.headers.update({"User-Agent": USER_AGENT})

            # Fetch metadata sequentially
            metadata_map = _fetch_all_metadata_sequential(purls)

            # Count successful fetches
            successful_fetches = sum(1 for v in metadata_map.values() if v is not None)
            logger.info(f"Successfully fetched metadata for {successful_fetches}/{len(purls)} components")

            # Log cache statistics
            cache_stats = get_cache_stats()
            logger.info(f"Cache statistics: {cache_stats['entries']} entries cached")

            # Enrich BOM (pass session for PyPI fallback)
            stats = _enrich_cyclonedx_bom_with_metadata(bom, metadata_map, session)

        # Print enrichment summary
        logger.info("Enrichment Summary:")
        logger.info(f"  Components enriched: {stats['components_enriched']}/{len(components)}")

        # Log enrichment sources
        if stats.get("ecosystems_enriched", 0) > 0:
            logger.info(f"  Enriched from ecosyste.ms: {stats['ecosystems_enriched']}")
        if stats.get("pypi_fallback_enriched", 0) > 0:
            logger.info(f"  Enriched from pypi.org: {stats['pypi_fallback_enriched']}")
        if stats.get("os_components_enriched", 0) > 0:
            logger.info(f"  OS components enriched: {stats['os_components_enriched']}")
        if stats.get("purl_fallback_enriched", 0) > 0:
            logger.info(f"  OS packages enriched via PURL: {stats['purl_fallback_enriched']}")
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
        try:
            document = spdx_parse_file(str(input_path))
        except Exception as e:
            raise SBOMValidationError(f"Failed to parse SPDX SBOM: {e}")

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

        # Use a session for all API calls
        with requests.Session() as session:
            session.headers.update({"User-Agent": USER_AGENT})

            # Fetch metadata sequentially
            metadata_map = _fetch_all_metadata_sequential(purls)

            # Count successful fetches
            successful_fetches = sum(1 for v in metadata_map.values() if v is not None)
            logger.info(f"Successfully fetched metadata for {successful_fetches}/{len(purls)} packages")

            # Log cache statistics
            cache_stats = get_cache_stats()
            logger.info(f"Cache statistics: {cache_stats['entries']} entries cached")

            # Enrich document (pass session for PyPI fallback)
            stats = _enrich_spdx_document_with_metadata(document, metadata_map, session)

        # Print enrichment summary
        logger.info("Enrichment Summary:")
        logger.info(f"  Packages enriched: {stats['components_enriched']}/{len(packages)}")

        # Log enrichment sources
        if stats.get("ecosystems_enriched", 0) > 0:
            logger.info(f"  Enriched from ecosyste.ms: {stats['ecosystems_enriched']}")
        if stats.get("pypi_fallback_enriched", 0) > 0:
            logger.info(f"  Enriched from pypi.org: {stats['pypi_fallback_enriched']}")
        if stats.get("purl_fallback_enriched", 0) > 0:
            logger.info(f"  OS packages enriched via PURL: {stats['purl_fallback_enriched']}")
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
