"""ecosyste.ms data source for multi-ecosystem package metadata."""

import json
from typing import Any, Dict, List, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata
from ..sanitization import normalize_vcs_url

ECOSYSTEMS_API_BASE = "https://packages.ecosyste.ms/api/v1"
DEFAULT_TIMEOUT = 15  # seconds - ecosyste.ms can be slower

# Package types that ecosyste.ms doesn't support well
# OS packages (deb, rpm, apk) should use PURL/Repology instead
UNSUPPORTED_TYPES = {"deb", "rpm", "apk", "alpm", "ebuild"}

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the ecosyste.ms metadata cache."""
    _cache.clear()


class EcosystemsSource:
    """
    Data source for ecosyste.ms package metadata API.

    ecosyste.ms provides metadata for packages across many ecosystems
    (npm, pypi, maven, cargo, etc.) but has limited support for
    OS-level packages (deb, rpm, apk).

    Priority: 45 (medium - generic source)
    Supports: Most package types except OS packages
    """

    @property
    def name(self) -> str:
        return "ecosyste.ms"

    @property
    def priority(self) -> int:
        # Tier 2: Primary aggregators (40-49) - High-quality aggregated data
        return 45

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        # Don't support OS package types - they should use PURL/Repology
        return purl.type not in UNSUPPORTED_TYPES

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from ecosyste.ms API.

        Args:
            purl: Parsed PackageURL
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        purl_str = str(purl)
        cache_key = f"ecosystems:{purl_str}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (ecosyste.ms): {purl.name}")
            return _cache[cache_key]

        try:
            url = f"{ECOSYSTEMS_API_BASE}/packages/lookup"
            params = {"purl": purl_str}

            logger.debug(f"Fetching ecosyste.ms metadata for: {purl_str}")
            response = session.get(url, params=params, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                data = response.json()
                # API returns an array, take first result
                if isinstance(data, list) and len(data) > 0:
                    metadata = self._normalize_response(data[0])
                elif isinstance(data, dict):
                    metadata = self._normalize_response(data)
                else:
                    logger.debug(f"No package data found in ecosyste.ms for: {purl_str}")
            elif response.status_code == 404:
                logger.debug(f"Package not found in ecosyste.ms: {purl_str}")
            elif response.status_code == 429:
                logger.warning(
                    f"Rate limit exceeded for ecosyste.ms: {purl_str}. "
                    "Consider using an API key for higher rate limits."
                )
            else:
                logger.warning(f"Failed to fetch ecosyste.ms metadata for {purl_str}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching ecosyste.ms metadata for {purl_str}")
            _cache[cache_key] = None
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching ecosyste.ms metadata for {purl_str}: {e}")
            _cache[cache_key] = None
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for ecosyste.ms {purl_str}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(self, data: Dict[str, Any]) -> Optional[NormalizedMetadata]:
        """
        Normalize ecosyste.ms API response to NormalizedMetadata.

        Args:
            data: Raw ecosyste.ms API response

        Returns:
            NormalizedMetadata with extracted fields, or None if no data
        """
        if not data:
            return None

        # Extract licenses
        licenses: List[str] = []
        if data.get("normalized_licenses"):
            licenses = [lic for lic in data["normalized_licenses"] if lic]
        elif data.get("licenses"):
            # licenses might be a string
            lic_str = str(data["licenses"]).strip()
            if lic_str:
                licenses = [lic_str]

        # Extract maintainer info
        maintainer_name = None
        maintainer_email = None
        maintainers = data.get("maintainers")
        if maintainers and isinstance(maintainers, list) and len(maintainers) > 0:
            first_maintainer = maintainers[0]
            maintainer_name = first_maintainer.get("name") or first_maintainer.get("login")
            maintainer_email = first_maintainer.get("email")

        # Extract supplier from maintainer or repo owner
        # NEVER use ecosystem name as supplier - "pypi", "npm", etc. are platforms, not suppliers
        supplier = None
        # Priority 1: Maintainer name or login (already extracted above)
        if maintainer_name:
            supplier = maintainer_name
        # Priority 2: Repo owner name or login
        elif data.get("repo_metadata") and data["repo_metadata"].get("owner"):
            owner = data["repo_metadata"]["owner"]
            if isinstance(owner, dict):
                supplier = owner.get("name") or owner.get("login")
            elif isinstance(owner, str):
                supplier = owner
        # Do NOT fall back to data["ecosystem"] - it's just the platform name

        # Extract issue tracker URL from repo metadata
        issue_tracker_url = None
        repo_metadata = data.get("repo_metadata") or {}
        if repo_metadata.get("html_url") and repo_metadata.get("has_issues"):
            issue_tracker_url = f"{repo_metadata['html_url']}/issues"

        # Build field_sources for attribution
        field_sources = {}
        if data.get("description"):
            field_sources["description"] = self.name
        if licenses:
            field_sources["licenses"] = self.name
        if supplier:
            field_sources["supplier"] = self.name
        if data.get("homepage"):
            field_sources["homepage"] = self.name
        if data.get("repository_url"):
            field_sources["repository_url"] = self.name
        if data.get("documentation_url"):
            field_sources["documentation_url"] = self.name
        if issue_tracker_url:
            field_sources["issue_tracker_url"] = self.name

        # Normalize repository URL to consistent SPDX VCS format
        repository_url = data.get("repository_url")
        if repository_url:
            repository_url = normalize_vcs_url(repository_url)

        metadata = NormalizedMetadata(
            description=data.get("description"),
            licenses=licenses,
            supplier=supplier,
            homepage=data.get("homepage"),
            repository_url=repository_url,
            documentation_url=data.get("documentation_url"),
            registry_url=data.get("registry_url"),
            issue_tracker_url=issue_tracker_url,
            download_url=repo_metadata.get("download_url") if repo_metadata else None,
            maintainer_name=maintainer_name,
            maintainer_email=maintainer_email,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug("Successfully normalized ecosyste.ms metadata")
            return metadata
        return None
