"""Debian Sources data source for Debian package metadata."""

import json
import re
from typing import Any, Dict, Optional

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata

DEBIAN_SOURCES_BASE = "https://sources.debian.org"
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

    Uses the debian/control file from source packages to extract:
    - Description
    - Maintainer
    - Homepage

    Priority: 10 (Tier 1 - native source for Debian packages)
    Supports: pkg:deb/debian/* packages only
    """

    @property
    def name(self) -> str:
        return "sources.debian.org"

    @property
    def priority(self) -> int:
        # Tier 1: Native sources (10-19) - Direct from official package registries
        return 10

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

        Uses the debian/control file to get package description and metadata.

        Args:
            purl: Parsed PackageURL for a Debian package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        cache_key = f"debian:{purl.name}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (Debian Sources): {purl.name}")
            return _cache[cache_key]

        metadata = self._fetch_control_file(purl.name, session)

        # Cache result
        _cache[cache_key] = metadata
        return metadata

    def _fetch_control_file(self, package_name: str, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch and parse the debian/control file for package metadata.

        Args:
            package_name: Name of the Debian package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        try:
            # First get the control file metadata to find the raw_url
            api_url = f"{DEBIAN_SOURCES_BASE}/api/src/{package_name}/latest/debian/control/"
            logger.debug(f"Fetching Debian control file metadata for: {package_name}")
            response = session.get(api_url, timeout=DEFAULT_TIMEOUT)

            if response.status_code == 404:
                logger.debug(f"Package not found on Debian Sources: {package_name}")
                return None
            elif response.status_code != 200:
                logger.warning(
                    f"Failed to fetch Debian Sources metadata for {package_name}: HTTP {response.status_code}"
                )
                return None

            api_data = response.json()

            # Check for API error response
            if "error" in api_data:
                logger.debug(f"Debian Sources API error for {package_name}: {api_data.get('error')}")
                return None

            # Get the raw control file content
            raw_url = api_data.get("raw_url")
            if not raw_url:
                logger.debug(f"No raw_url in Debian Sources response for {package_name}")
                return None

            raw_response = session.get(f"{DEBIAN_SOURCES_BASE}{raw_url}", timeout=DEFAULT_TIMEOUT)
            if raw_response.status_code != 200:
                logger.warning(f"Failed to fetch raw control file for {package_name}: HTTP {raw_response.status_code}")
                return None

            # Parse the control file and extract metadata
            return self._parse_control_file(package_name, raw_response.text, api_data)

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching Debian Sources metadata for {package_name}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching Debian Sources metadata for {package_name}: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for Debian Sources {package_name}: {e}")
            return None

    def _parse_control_file(
        self, package_name: str, control_content: str, api_data: Dict[str, Any]
    ) -> Optional[NormalizedMetadata]:
        """
        Parse a Debian control file and extract metadata.

        Args:
            package_name: Name of the package
            control_content: Raw content of debian/control file
            api_data: API response data containing pkg_infos

        Returns:
            NormalizedMetadata with extracted fields
        """
        # Parse control file fields
        fields = self._parse_control_fields(control_content, package_name)

        # Build field_sources for attribution
        field_sources = {}

        # Supplier is always Debian Project for Debian packages
        supplier = "Debian Project"
        field_sources["supplier"] = self.name

        # Extract maintainer
        maintainer_name = None
        maintainer_email = None
        maintainer = fields.get("Maintainer", "")
        if maintainer:
            # Parse "Name <email>" format
            match = re.match(r"^(.+?)\s*<(.+?)>", maintainer)
            if match:
                maintainer_name = match.group(1).strip()
                maintainer_email = match.group(2).strip()
            else:
                maintainer_name = maintainer

        # Extract description (from binary package stanza matching source name)
        description = fields.get("Description")
        if description:
            field_sources["description"] = self.name

        # Extract homepage
        homepage = fields.get("Homepage")
        if not homepage:
            # Fallback to Package Tracker
            homepage = f"https://tracker.debian.org/pkg/{package_name}"
        field_sources["homepage"] = self.name

        # Registry URL points to the source browser
        version = api_data.get("version", "latest")
        registry_url = f"https://sources.debian.org/src/{package_name}/{version}/"
        field_sources["registry_url"] = self.name

        # Extract VCS info from pkg_infos if available
        repository_url = None
        pkg_infos = api_data.get("pkg_infos", {})
        pts_link = pkg_infos.get("pts_link")
        if pts_link:
            field_sources["homepage"] = self.name

        logger.debug(f"Successfully parsed Debian control file for: {package_name}")

        metadata = NormalizedMetadata(
            description=description,
            supplier=supplier,
            homepage=homepage,
            repository_url=repository_url,
            registry_url=registry_url,
            maintainer_name=maintainer_name,
            maintainer_email=maintainer_email,
            source=self.name,
            field_sources=field_sources,
        )

        return metadata if metadata.has_data() else None

    def _parse_control_fields(self, content: str, target_package: str) -> Dict[str, str]:
        """
        Parse Debian control file format and extract fields.

        Control files have multiple stanzas (paragraphs) separated by blank lines.
        We want fields from the Source stanza and the binary Package stanza
        matching the target package name.

        Args:
            content: Raw control file content
            target_package: Package name to find description for

        Returns:
            Dictionary of field name -> value
        """
        result = {}
        current_field = None
        current_value = []
        in_target_package = False

        for line in content.split("\n"):
            # Empty line marks end of stanza
            if not line.strip():
                # Save any pending field
                if current_field and current_value:
                    result[current_field] = "\n".join(current_value).strip()
                current_field = None
                current_value = []
                in_target_package = False
                continue

            # Continuation line (starts with space or tab)
            if line.startswith((" ", "\t")):
                if current_field:
                    # Handle description continuation (strip leading space, keep . as paragraph separator)
                    stripped = line.strip()
                    if stripped == ".":
                        current_value.append("")
                    else:
                        current_value.append(stripped)
                continue

            # Field line
            if ":" in line:
                # Save previous field
                if current_field and current_value:
                    result[current_field] = "\n".join(current_value).strip()

                field_name, _, field_value = line.partition(":")
                field_name = field_name.strip()
                field_value = field_value.strip()

                # Track if we're in the target package stanza
                if field_name == "Package" and field_value == target_package:
                    in_target_package = True

                # Only capture Description from target package stanza
                if field_name == "Description" and not in_target_package:
                    current_field = None
                    current_value = []
                    continue

                current_field = field_name
                current_value = [field_value] if field_value else []

        # Save final field
        if current_field and current_value:
            result[current_field] = "\n".join(current_value).strip()

        return result
