"""Debian Sources data source for Debian package metadata."""

import json
from typing import Any, Dict, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata

DEBIAN_SOURCES_API_BASE = "https://sources.debian.org/api"
DEFAULT_TIMEOUT = 10  # seconds

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}


def clear_cache() -> None:
    """Clear the Debian Sources metadata cache."""
    _cache.clear()


class DebianSource:
    """
    Data source for Debian packages using the official Debian Sources API.

    This is the authoritative source for Debian packages and should be tried
    before generic sources like ecosyste.ms for pkg:deb/debian/* packages.

    API Documentation: https://sources.debian.org/doc/api/

    Priority: 15 (high - native source for Debian packages)
    Supports: pkg:deb/debian/* packages only
    """

    @property
    def name(self) -> str:
        return "sources.debian.org"

    @property
    def priority(self) -> int:
        return 15  # High priority - native source for Debian packages

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL."""
        # Only support Debian packages (not Ubuntu or other deb-based distros)
        if purl.type != "deb":
            return False
        if not purl.namespace:
            return False
        return purl.namespace.lower() == "debian"

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from Debian Sources API.

        Uses a fuzzy-match strategy:
        1. Try exact version first
        2. Fallback to "latest" if exact version not found

        Args:
            purl: Parsed PackageURL for a Debian package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        version = purl.version or "latest"
        cache_key = f"debian:{purl.name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (Debian Sources): {purl.name}@{version}")
            return _cache[cache_key]

        # Try exact version first
        metadata = self._fetch_package_info(purl.name, version, session)

        # Fallback to latest if exact version not found
        if metadata is None and version != "latest":
            logger.debug(f"Exact version not found, trying latest for {purl.name}")
            metadata = self._fetch_package_info(purl.name, "latest", session)

        # Cache result
        _cache[cache_key] = metadata
        return metadata

    def _fetch_package_info(
        self, package_name: str, version: str, session: requests.Session
    ) -> Optional[NormalizedMetadata]:
        """
        Fetch package info from Debian Sources API.

        Args:
            package_name: Name of the Debian package
            version: Version string or "latest"
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        try:
            url = f"{DEBIAN_SOURCES_API_BASE}/info/package/{package_name}/{version}"
            logger.debug(f"Fetching Debian Sources metadata for: {package_name}@{version}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                return self._normalize_response(package_name, version, data)
            elif response.status_code == 404:
                logger.debug(f"Package not found on Debian Sources: {package_name}@{version}")
                return None
            else:
                logger.warning(
                    f"Failed to fetch Debian Sources metadata for {package_name}: HTTP {response.status_code}"
                )
                return None

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching Debian Sources metadata for {package_name}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching Debian Sources metadata for {package_name}: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for Debian Sources {package_name}: {e}")
            return None

    def _normalize_response(self, package_name: str, version: str, data: Dict[str, Any]) -> NormalizedMetadata:
        """
        Normalize Debian Sources API response to NormalizedMetadata.

        Args:
            package_name: Name of the package
            version: Version that was queried
            data: Raw Debian Sources API response

        Returns:
            NormalizedMetadata with extracted fields
        """
        # Extract package info from response
        pkg_info = data.get("pkg_infos", {})

        # Build field_sources for attribution
        field_sources = {}

        # Supplier is always Debian Project for Debian packages
        supplier = "Debian Project"
        field_sources["supplier"] = self.name

        # Homepage is the Debian Package Tracker
        homepage = f"https://tracker.debian.org/pkg/{package_name}"
        field_sources["homepage"] = self.name

        # Registry URL points to the source browser
        # Use the actual version from the response if available
        actual_version = version
        if version == "latest" and data.get("version"):
            actual_version = data["version"]
        registry_url = f"https://sources.debian.org/src/{package_name}/{actual_version}/"
        field_sources["registry_url"] = self.name

        # Extract VCS info if available
        repository_url = None
        vcs_info = pkg_info.get("vcs")
        if vcs_info:
            # VCS can be in format "Git https://..." or just the URL
            if isinstance(vcs_info, str):
                parts = vcs_info.split()
                if len(parts) >= 2:
                    repository_url = parts[1]
                elif vcs_info.startswith(("http://", "https://", "git://")):
                    repository_url = vcs_info
            elif isinstance(vcs_info, dict):
                repository_url = vcs_info.get("url") or vcs_info.get("browser")

        if repository_url:
            field_sources["repository_url"] = self.name

        # Extract description if available (from package long_description or summary)
        description = None
        if pkg_info.get("long_description"):
            description = pkg_info["long_description"]
        elif pkg_info.get("description"):
            description = pkg_info["description"]

        if description:
            field_sources["description"] = self.name

        logger.debug(f"Successfully fetched Debian Sources metadata for: {package_name}")

        return NormalizedMetadata(
            description=description,
            supplier=supplier,
            homepage=homepage,
            repository_url=repository_url,
            registry_url=registry_url,
            source=self.name,
            field_sources=field_sources,
        )
