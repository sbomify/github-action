"""SBOM enrichment using ecosyste.ms API."""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from .logging_config import logger


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


def _extract_components_from_sbom(sbom_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract components from SBOM (supports both CycloneDX and SPDX formats).

    Args:
        sbom_data: Parsed SBOM JSON data

    Returns:
        List of component dictionaries with metadata
    """
    components = []

    # CycloneDX format
    if "components" in sbom_data:
        for component in sbom_data.get("components", []):
            if "purl" in component:
                components.append(
                    {
                        "purl": component["purl"],
                        "name": component.get("name"),
                        "version": component.get("version"),
                        "original": component,
                    }
                )

    # SPDX format
    elif "packages" in sbom_data:
        for package in sbom_data.get("packages", []):
            # Try to extract PURL from externalRefs
            purl = None
            for ref in package.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    break

            if purl:
                components.append(
                    {
                        "purl": purl,
                        "name": package.get("name"),
                        "version": package.get("versionInfo"),
                        "original": package,
                    }
                )

    return components


def _fetch_package_metadata(purl: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    """
    Fetch package metadata from ecosyste.ms API.

    Args:
        purl: Package URL
        session: requests.Session with configured headers

    Returns:
        Package metadata dict or None if fetch fails
    """
    try:
        # The API endpoint expects PURL as a query parameter
        url = f"{ECOSYSTEMS_API_BASE}/packages/lookup"
        params = {"purl": purl}

        logger.debug(f"Fetching metadata for: {purl}")
        response = session.get(url, params=params, timeout=30)

        if response.status_code == 200:
            data = response.json()
            # The API returns an array, take the first result if available
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            elif isinstance(data, dict):
                return data
            else:
                logger.debug(f"No package data found for: {purl}")
                return None
        elif response.status_code == 404:
            logger.debug(f"Package not found in ecosyste.ms: {purl}")
            return None
        else:
            logger.warning(f"Failed to fetch metadata for {purl}: HTTP {response.status_code}")
            return None

    except requests.exceptions.Timeout:
        logger.warning(f"Timeout fetching metadata for {purl}")
        return None
    except requests.exceptions.RequestException as e:
        logger.warning(f"Error fetching metadata for {purl}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching metadata for {purl}: {e}")
        return None


def _fetch_all_metadata_concurrent(purls: List[str], max_workers: int = 10) -> Dict[str, Optional[Dict[str, Any]]]:
    """
    Fetch metadata for all PURLs concurrently using ThreadPoolExecutor.

    Args:
        purls: List of package URLs
        max_workers: Maximum number of concurrent threads (default: 10)

    Returns:
        Dictionary mapping PURL to metadata
    """
    metadata_map = {}

    # Use a single session with context manager for proper cleanup
    with requests.Session() as session:
        session.headers.update({"User-Agent": USER_AGENT})

        # Use ThreadPoolExecutor for concurrent fetching
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all fetch tasks
            future_to_purl = {executor.submit(_fetch_package_metadata, purl, session): purl for purl in purls}

            # Collect results as they complete
            for future in as_completed(future_to_purl):
                purl = future_to_purl[future]
                try:
                    metadata = future.result()
                    metadata_map[purl] = metadata
                except Exception as e:
                    logger.error(f"Unexpected error fetching metadata for {purl}: {e}")
                    metadata_map[purl] = None

    return metadata_map


def _enrich_cyclonedx_component(
    component: Dict[str, Any], metadata: Optional[Dict[str, Any]]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Enrich a CycloneDX component with ecosyste.ms metadata using ONLY native CycloneDX fields.

    Native fields used:
    - description: Component description
    - licenses: Array of license objects
    - publisher: Publishing entity/primary maintainer
    - externalReferences: URLs for website, vcs, distribution, issue-tracker, etc.

    Args:
        component: Original component dict
        metadata: Metadata from ecosyste.ms API

    Returns:
        Tuple of (enriched component dict, list of added fields)
    """
    if not metadata:
        return component, []

    enriched = component.copy()
    added_fields = []

    # Add description (native CycloneDX field)
    if "description" not in enriched or not enriched["description"]:
        if metadata.get("description"):
            enriched["description"] = metadata["description"]
            added_fields.append("description")

    # Add licenses (native CycloneDX field)
    if metadata.get("licenses"):
        if "licenses" not in enriched or not enriched.get("licenses"):
            licenses = []
            licenses_str = metadata["licenses"]

            # Parse license string (could be comma-separated)
            for license_name in licenses_str.split(","):
                license_name = license_name.strip()
                if license_name:
                    licenses.append({"license": {"id": license_name}})

            if licenses:
                enriched["licenses"] = licenses
                added_fields.append(f"licenses ({licenses_str})")

    # Add publisher (native CycloneDX field) - use first maintainer if available
    if "publisher" not in enriched or not enriched.get("publisher"):
        if metadata.get("maintainers") and isinstance(metadata["maintainers"], list):
            if metadata["maintainers"]:
                maintainer = metadata["maintainers"][0]
                publisher_name = maintainer.get("name") or maintainer.get("login")
                if publisher_name:
                    enriched["publisher"] = publisher_name
                    added_fields.append(f"publisher ({publisher_name})")

    # Add external references (native CycloneDX field)
    external_refs = enriched.get("externalReferences", [])
    original_refs_count = len(external_refs)

    def _add_external_ref(ref_type: str, url: str) -> bool:
        """Helper to add external reference if URL exists and not already present. Returns True if added."""
        if url and not any(ref.get("type") == ref_type and ref.get("url") == url for ref in external_refs):
            external_refs.append({"type": ref_type, "url": url})
            return True
        return False

    # Website/homepage
    if metadata.get("homepage"):
        if _add_external_ref("website", metadata["homepage"]):
            added_fields.append("homepage URL")

    # VCS repository
    if metadata.get("repository_url"):
        if _add_external_ref("vcs", metadata["repository_url"]):
            added_fields.append("repository URL")

    # Distribution (use registry URL which points to the package manager like https://pypi.org)
    if metadata.get("registry") and metadata["registry"].get("url"):
        if _add_external_ref("distribution", metadata["registry"]["url"]):
            added_fields.append("distribution URL")

    # Issue tracker (use repo_metadata.html_url + /issues for GitHub repos)
    if metadata.get("repo_metadata") and metadata["repo_metadata"].get("html_url"):
        html_url = metadata["repo_metadata"]["html_url"]
        # For GitHub repos, construct issues URL
        if "github.com" in html_url:
            issues_url = f"{html_url}/issues"
            if _add_external_ref("issue-tracker", issues_url):
                added_fields.append("issue-tracker URL")

    if external_refs:
        enriched["externalReferences"] = external_refs

    return enriched, added_fields


def _enrich_spdx_package(
    package: Dict[str, Any], metadata: Optional[Dict[str, Any]]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Enrich an SPDX package with ecosyste.ms metadata using ONLY native SPDX fields.

    Native fields used:
    - description: Package description
    - homepage: Package homepage URL
    - downloadLocation: Where to download the package
    - licenseDeclared: Declared license
    - sourceInfo: Information about source code
    - originator: Original creator/maintainer
    - supplier: Current supplier/maintainer
    - externalRefs: External references (package manager, etc.)

    Args:
        package: Original package dict
        metadata: Metadata from ecosyste.ms API

    Returns:
        Tuple of (enriched package dict, list of added fields)
    """
    if not metadata:
        return package, []

    enriched = package.copy()
    added_fields = []

    # Add description (native SPDX field)
    if not enriched.get("description") or enriched["description"] == "NOASSERTION":
        if metadata.get("description"):
            enriched["description"] = metadata["description"]
            added_fields.append("description")

    # Add homepage (native SPDX field)
    if not enriched.get("homepage") or enriched["homepage"] == "NOASSERTION":
        if metadata.get("homepage"):
            enriched["homepage"] = metadata["homepage"]
            added_fields.append("homepage")

    # Add download location (native SPDX field)
    if not enriched.get("downloadLocation") or enriched["downloadLocation"] == "NOASSERTION":
        # Use registry URL or repository URL
        download_url = None
        if metadata.get("registry") and metadata["registry"].get("url"):
            download_url = metadata["registry"]["url"]
        elif metadata.get("repository_url"):
            download_url = metadata["repository_url"]

        if download_url:
            enriched["downloadLocation"] = download_url
            added_fields.append("downloadLocation")

    # Add licenses (native SPDX field)
    if metadata.get("licenses"):
        if not enriched.get("licenseDeclared") or enriched["licenseDeclared"] == "NOASSERTION":
            enriched["licenseDeclared"] = metadata["licenses"]
            added_fields.append(f"licenseDeclared ({metadata['licenses']})")

    # Add source info (native SPDX field) - include repository URL
    if not enriched.get("sourceInfo") or enriched["sourceInfo"] == "NOASSERTION":
        if metadata.get("repository_url"):
            enriched["sourceInfo"] = f"acquired from {metadata['repository_url']}"
            added_fields.append("sourceInfo")

    # Add originator (native SPDX field) - first maintainer
    if not enriched.get("originator") or enriched["originator"] == "NOASSERTION":
        if metadata.get("maintainers") and isinstance(metadata["maintainers"], list):
            if metadata["maintainers"]:
                maintainer = metadata["maintainers"][0]
                name = maintainer.get("name") or maintainer.get("login", "")
                email = maintainer.get("email", "")
                if name:
                    if email:
                        enriched["originator"] = f"Person: {name} ({email})"
                    else:
                        enriched["originator"] = f"Person: {name}"
                    added_fields.append(f"originator ({name})")

    # Add supplier (native SPDX field) - can be organization or primary maintainer
    if not enriched.get("supplier") or enriched["supplier"] == "NOASSERTION":
        # If we have a registry/ecosystem, use that as supplier
        if metadata.get("registry", {}).get("name"):
            registry_name = metadata["registry"]["name"]
            enriched["supplier"] = f"Organization: {registry_name}"
            added_fields.append(f"supplier ({registry_name})")
        elif metadata.get("maintainers") and isinstance(metadata["maintainers"], list):
            # Otherwise use first maintainer
            if metadata["maintainers"]:
                maintainer = metadata["maintainers"][0]
                name = maintainer.get("name") or maintainer.get("login", "")
                if name:
                    enriched["supplier"] = f"Person: {name}"
                    added_fields.append(f"supplier ({name})")

    # Add external references (native SPDX field)
    external_refs = enriched.get("externalRefs", [])

    def _add_external_ref(category: str, ref_type: str, locator: str) -> bool:
        """Helper to add external reference if not already exists. Returns True if added."""
        if locator and not any(ref.get("referenceLocator") == locator for ref in external_refs):
            external_refs.append(
                {
                    "referenceCategory": category,
                    "referenceType": ref_type,
                    "referenceLocator": locator,
                }
            )
            return True
        return False

    # Add registry URL (PACKAGE-MANAGER category)
    if metadata.get("registry") and metadata["registry"].get("url"):
        if _add_external_ref("PACKAGE-MANAGER", "url", metadata["registry"]["url"]):
            added_fields.append("externalRef (registry)")

    # Add documentation URL (OTHER category)
    if metadata.get("documentation_url"):
        if _add_external_ref("OTHER", "url", metadata["documentation_url"]):
            added_fields.append("externalRef (documentation)")

    if external_refs:
        enriched["externalRefs"] = external_refs

    return enriched, added_fields


def _enrich_sbom_with_metadata(
    sbom_data: Dict[str, Any], metadata_map: Dict[str, Optional[Dict[str, Any]]]
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """
    Enrich SBOM with fetched metadata.

    Args:
        sbom_data: Original SBOM data
        metadata_map: Map of PURL to metadata

    Returns:
        Tuple of (enriched SBOM data, enrichment statistics)
    """
    enriched_sbom = sbom_data.copy()

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
        "originators_added": 0,
        "suppliers_added": 0,
        "source_info_added": 0,
        "external_refs_added": 0,
    }

    # CycloneDX format
    if "components" in sbom_data:
        enriched_components = []
        for component in sbom_data.get("components", []):
            purl = component.get("purl")
            if purl and purl in metadata_map:
                enriched_component, added_fields = _enrich_cyclonedx_component(component, metadata_map[purl])
                enriched_components.append(enriched_component)

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
            else:
                enriched_components.append(component)
        enriched_sbom["components"] = enriched_components

    # SPDX format
    elif "packages" in sbom_data:
        enriched_packages = []
        for package in sbom_data.get("packages", []):
            # Find PURL in externalRefs
            purl = None
            for ref in package.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    break

            if purl and purl in metadata_map:
                enriched_package, added_fields = _enrich_spdx_package(package, metadata_map[purl])
                enriched_packages.append(enriched_package)

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
            else:
                enriched_packages.append(package)
        enriched_sbom["packages"] = enriched_packages

    return enriched_sbom, stats


def enrich_sbom_with_ecosystems(input_file: str, output_file: str) -> None:
    """
    Enrich SBOM with metadata from ecosyste.ms API.

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save enriched SBOM

    Raises:
        FileNotFoundError: If input file doesn't exist
        ValueError: If SBOM format is invalid
        Exception: For other errors during enrichment
    """
    logger.info(f"Starting SBOM enrichment with ecosyste.ms for: {input_file}")

    # Load SBOM
    try:
        with open(input_file, "r") as f:
            sbom_data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Input SBOM file not found: {input_file}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in SBOM file: {e}")

    # Extract components
    components = _extract_components_from_sbom(sbom_data)
    if not components:
        logger.warning("No components with PURLs found in SBOM, skipping enrichment")
        # Just copy the file as-is
        with open(output_file, "w") as f:
            json.dump(sbom_data, f, indent=2)
        return

    logger.info(f"Found {len(components)} components to enrich")

    # Extract PURLs
    purls = [comp["purl"] for comp in components]

    # Fetch metadata concurrently using ThreadPoolExecutor
    try:
        metadata_map = _fetch_all_metadata_concurrent(purls)
    except Exception as e:
        logger.error(f"Error fetching metadata: {e}")
        # Continue with empty metadata map
        metadata_map = {}

    # Count successful fetches
    successful_fetches = sum(1 for v in metadata_map.values() if v is not None)
    logger.info(f"Successfully fetched metadata for {successful_fetches}/{len(purls)} components")

    # Enrich SBOM
    enriched_sbom, stats = _enrich_sbom_with_metadata(sbom_data, metadata_map)

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
        with open(output_file, "w") as f:
            json.dump(enriched_sbom, f, indent=2)
        logger.info(f"Enriched SBOM written to: {output_file}")
    except Exception as e:
        raise Exception(f"Failed to write enriched SBOM: {e}")
