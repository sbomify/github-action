"""ClearlyDefined data source for package metadata (license and attribution)."""

import json
from typing import Any, Dict, List, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url

CLEARLYDEFINED_API_BASE = "https://api.clearlydefined.io"
DEFAULT_TIMEOUT = 10  # seconds - short timeout, API can be slow/unreliable

# Mapping from PURL type to ClearlyDefined type
# NOTE: Only include types that ClearlyDefined reliably supports.
# Tested 2024-12: deb, apk, rpm are NOT reliably supported (timeouts, 404s).
# See: https://docs.clearlydefined.io/docs/curation/coordinates
PURL_TYPE_TO_CD_TYPE: Dict[str, str] = {
    "pypi": "pypi/pypi",
    "npm": "npm/npmjs",
    "cargo": "crate/cratesio",
    "maven": "maven/mavencentral",
    "gem": "gem/rubygems",
    "nuget": "nuget/nuget",
    "golang": "go/golang",
    # NOT SUPPORTED (unreliable):
    # "deb": Timeouts, not properly indexed
    # "apk": Not supported at all
    # "rpm": Timeouts, not properly indexed
}

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the ClearlyDefined metadata cache."""
    _cache.clear()


class ClearlyDefinedSource:
    """
    Data source for ClearlyDefined API.

    ClearlyDefined provides curated license and attribution data for
    open source packages across many ecosystems.

    Priority: 75 (medium-low - good for license data, slower API)
    Supports: pypi, npm, cargo, maven, gem, nuget, golang packages

    NOTE: OS packages (deb, apk, rpm) are NOT supported - ClearlyDefined
    does not reliably index these package types.
    """

    @property
    def name(self) -> str:
        return "clearlydefined.io"

    @property
    def priority(self) -> int:
        # Tier 3: Fallback sources (70-99) - Last resort, basic or rate-limited
        return 75

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        return purl.type in PURL_TYPE_TO_CD_TYPE

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from ClearlyDefined API.

        Args:
            purl: Parsed PackageURL
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        cd_type = PURL_TYPE_TO_CD_TYPE.get(purl.type)
        if not cd_type:
            return None

        # Build the coordinate for ClearlyDefined API
        # Format: type/provider/namespace/name/revision
        # e.g., maven/mavencentral/org.apache.commons/commons-lang3/3.12.0
        version = purl.version or "-"
        namespace = purl.namespace or "-"
        cache_key = f"clearlydefined:{purl.type}:{namespace}:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (ClearlyDefined): {purl.name}")
            return _cache[cache_key]

        try:
            # Build coordinate: type/provider/namespace/name/version
            coordinate = f"{cd_type}/{namespace}/{purl.name}/{version}"
            url = f"{CLEARLYDEFINED_API_BASE}/definitions/{coordinate}"

            logger.debug(f"Fetching ClearlyDefined metadata for: {purl}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                data = response.json()
                metadata = self._normalize_response(purl.name, data)
            elif response.status_code == 404:
                logger.debug(f"Package not found in ClearlyDefined: {purl}")
            else:
                logger.warning(f"Failed to fetch ClearlyDefined metadata for {purl}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching ClearlyDefined metadata for {purl}")
            _cache[cache_key] = None
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching ClearlyDefined metadata for {purl}: {e}")
            _cache[cache_key] = None
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for ClearlyDefined {purl}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(self, package_name: str, data: Dict[str, Any]) -> Optional[NormalizedMetadata]:
        """
        Normalize ClearlyDefined API response to NormalizedMetadata.

        Args:
            package_name: Name of the package
            data: Raw ClearlyDefined API response

        Returns:
            NormalizedMetadata with extracted fields, or None if no data
        """
        if not data:
            return None

        # Extract licensed info
        licensed = data.get("licensed", {})
        declared_license = licensed.get("declared")

        licenses: List[str] = []
        if declared_license and declared_license != "NOASSERTION":
            licenses = [declared_license]

        # Extract description from described section
        described = data.get("described", {})
        description = None

        # Try to get description from source info
        source_info = described.get("sourceLocation", {})

        # Extract URLs
        homepage = described.get("projectWebsite")
        repository_url = None

        if source_info:
            repo_url = source_info.get("url")
            if repo_url:
                repository_url = normalize_vcs_url(repo_url)

        # Extract supplier from attribution
        supplier = None
        attribution_parties = licensed.get("attribution", {}).get("parties", [])
        if attribution_parties:
            supplier = attribution_parties[0]

        # Build field_sources for attribution
        field_sources = {}
        if licenses:
            field_sources["licenses"] = self.name
        if supplier:
            field_sources["supplier"] = self.name
        if homepage:
            field_sources["homepage"] = self.name
        if repository_url:
            field_sources["repository_url"] = self.name

        metadata = NormalizedMetadata(
            description=description,
            licenses=licenses,
            supplier=supplier,
            homepage=homepage,
            repository_url=repository_url,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug(f"Successfully normalized ClearlyDefined metadata for {package_name}")
            return metadata
        return None
