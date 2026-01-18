"""Lifecycle data source for CLE (Common Lifecycle Enumeration) enrichment.

This source provides lifecycle dates (release_date, end_of_support, end_of_life)
for:
1. Linux distributions (Alpine, Ubuntu, Rocky, etc.) - based on distro version in PURL
2. Language runtimes and frameworks (Python, PHP, Go, Rust, Django, Rails, etc.) - based on name patterns

Priority: 5 (high priority - local data, no API calls)
Supports: Distro packages (apk, deb, rpm) and packages matching PACKAGE_LIFECYCLE patterns
"""

import fnmatch
import re
from typing import Dict, Optional, Tuple

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..lifecycle_data import (
    DISTRO_LIFECYCLE,
    PACKAGE_LIFECYCLE,
    PackageLifecycleEntry,
    extract_version_cycle,
)
from ..metadata import NormalizedMetadata

# Simple in-memory cache for lifecycle lookups
_cache: Dict[str, Optional[NormalizedMetadata]] = {}

# Mapping of PURL types/namespaces to distro names in DISTRO_LIFECYCLE
DISTRO_MAPPINGS = {
    # APK packages
    ("apk", "alpine"): "alpine",
    ("apk", "wolfi"): "wolfi",
    ("apk", "chainguard"): "wolfi",  # Chainguard uses Wolfi base
    # DEB packages
    ("deb", "ubuntu"): "ubuntu",
    ("deb", "debian"): None,  # Debian not tracked yet
    # RPM packages
    ("rpm", "rocky"): "rocky",
    ("rpm", "almalinux"): "almalinux",
    ("rpm", "amazonlinux"): "amazonlinux",
    ("rpm", "amzn"): "amazonlinux",  # Common PURL namespace for Amazon Linux
    ("rpm", "centos"): "centos",
    ("rpm", "fedora"): "fedora",
}


def clear_cache() -> None:
    """Clear the lifecycle metadata cache."""
    _cache.clear()


class LifecycleSource:
    """
    Data source for lifecycle (CLE) information.

    This source provides CLE dates for:

    1. **Linux Distributions** - All packages from supported distros get the distro's
       lifecycle dates. Detected via PURL type/namespace:
       - pkg:apk/alpine/curl@8.0 -> Alpine lifecycle
       - pkg:deb/ubuntu/curl@8.0 -> Ubuntu lifecycle
       - pkg:rpm/fedora/curl@8.0 -> Fedora lifecycle

    2. **Language Runtimes & Frameworks** - Matched by name patterns:
       - "python" matches pkg:pypi/python, pkg:deb/ubuntu/python3, etc.
       - "django" matches pkg:pypi/django
       - "rails" matches pkg:gem/rails

    Priority: 5 (high - local data, no network calls)
    Supports: Distro packages and packages matching PACKAGE_LIFECYCLE patterns
    """

    @property
    def name(self) -> str:
        return "lifecycle"

    @property
    def priority(self) -> int:
        # Priority 5: Very high - local data with no API calls
        return 5

    def supports(self, purl: PackageURL) -> bool:
        """
        Check if this source supports the given PURL.

        Returns True if:
        - The package name matches any pattern in PACKAGE_LIFECYCLE, OR
        - The package is from a supported distro (Alpine, Ubuntu, etc.)
        """
        # Check package lifecycle first (more specific)
        entry = self._find_package_entry(purl)
        if entry is not None:
            return True

        # Check if it's a distro package (fallback)
        distro, version = self._parse_distro_from_purl(purl)
        return distro is not None and version is not None

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch lifecycle metadata for the given PURL.

        Priority:
        1. Package-specific lifecycle (Python, PHP, etc.) - more specific
        2. Distro lifecycle (Alpine, Ubuntu, etc.) - fallback for other packages

        Args:
            purl: Parsed PackageURL object
            session: requests.Session (not used - local data only)

        Returns:
            NormalizedMetadata with CLE fields if found, None otherwise
        """
        # Build cache key including namespace for distro detection
        namespace = purl.namespace or ""
        cache_key = f"lifecycle:{purl.type}:{namespace}:{purl.name}:{purl.version or 'latest'}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (lifecycle): {purl.name}")
            return _cache[cache_key]

        # Try package lifecycle first (more specific - Python, PHP, Go, Rust, etc.)
        metadata = self._fetch_package_lifecycle(purl)
        if metadata:
            _cache[cache_key] = metadata
            return metadata

        # Fall back to distro lifecycle (Alpine, Ubuntu, etc.)
        metadata = self._fetch_distro_lifecycle(purl)
        _cache[cache_key] = metadata
        return metadata

    def _fetch_distro_lifecycle(self, purl: PackageURL) -> Optional[NormalizedMetadata]:
        """Fetch lifecycle data for a distro package."""
        distro, version = self._parse_distro_from_purl(purl)
        if not distro or not version:
            return None

        # Look up distro lifecycle
        distro_data = DISTRO_LIFECYCLE.get(distro)
        if not distro_data:
            logger.debug(f"No lifecycle data for distro: {distro}")
            return None

        lifecycle_dates = distro_data.get(version)
        if not lifecycle_dates:
            logger.debug(f"No lifecycle data for {distro} version {version}")
            return None

        return self._build_metadata(lifecycle_dates, f"{distro} {version}")

    def _fetch_package_lifecycle(self, purl: PackageURL) -> Optional[NormalizedMetadata]:
        """Fetch lifecycle data for a language runtime or framework."""
        entry = self._find_package_entry(purl)
        if not entry:
            logger.debug(f"No lifecycle data found for: {purl.name}")
            return None

        # Extract version cycle
        version = purl.version or ""
        version_extract = entry.get("version_extract", "major.minor")
        cycle = extract_version_cycle(version, version_extract)

        if not cycle:
            logger.debug(f"Could not extract version cycle from {purl.name}@{version}")
            return None

        # Look up lifecycle dates for this cycle
        cycles = entry.get("cycles", {})
        lifecycle_dates = cycles.get(cycle)

        if not lifecycle_dates:
            logger.debug(f"No lifecycle data for {purl.name} cycle {cycle}")
            return None

        return self._build_metadata(lifecycle_dates, f"{purl.name} {cycle}")

    def _build_metadata(self, lifecycle_dates: Dict, context: str) -> Optional[NormalizedMetadata]:
        """Build NormalizedMetadata from lifecycle dates."""
        cle_eos = lifecycle_dates.get("end_of_support")
        cle_eol = lifecycle_dates.get("end_of_life")
        cle_release_date = lifecycle_dates.get("release_date")

        # Only return metadata if we have at least one CLE field
        if not any([cle_eos, cle_eol, cle_release_date]):
            logger.debug(f"No CLE dates available for {context}")
            return None

        # Build field sources
        field_sources: Dict[str, str] = {}
        if cle_eos:
            field_sources["cle_eos"] = self.name
        if cle_eol:
            field_sources["cle_eol"] = self.name
        if cle_release_date:
            field_sources["cle_release_date"] = self.name

        logger.debug(f"Found lifecycle data for {context}: EOS={cle_eos}, EOL={cle_eol}")

        return NormalizedMetadata(
            cle_eos=cle_eos,
            cle_eol=cle_eol,
            cle_release_date=cle_release_date,
            source=self.name,
            field_sources=field_sources,
        )

    def _parse_distro_from_purl(self, purl: PackageURL) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract distro and version from PURL.

        Args:
            purl: PackageURL to parse

        Returns:
            Tuple of (distro_name, version) or (None, None)
        """
        purl_type = purl.type.lower()
        namespace = (purl.namespace or "").lower()
        qualifiers = purl.qualifiers or {}

        # Look up distro from type/namespace mapping
        distro = DISTRO_MAPPINGS.get((purl_type, namespace))
        if not distro:
            return None, None

        # Try to get version from qualifiers first
        distro_qualifier = qualifiers.get("distro", "")
        version = None

        if distro_qualifier:
            # Parse distro qualifier (e.g., "ubuntu-24.04.1", "alpine-3.20")
            match = re.match(r"([a-z]+)-(.+)", distro_qualifier.lower())
            if match:
                version = match.group(2)
            # For APK packages, distro qualifier may be just version (e.g., "3.19.9")
            elif namespace in ("alpine", "wolfi") and re.match(r"^\d+\.\d+", distro_qualifier):
                version = distro_qualifier

        # Normalize version to match DISTRO_LIFECYCLE keys
        if version:
            normalized = self._normalize_distro_version(distro, version)
            if normalized:
                return distro, normalized

        # Fall back to latest version if no qualifier
        distro_data = DISTRO_LIFECYCLE.get(distro, {})
        if distro_data:
            # Get the latest version (last key)
            versions = list(distro_data.keys())
            if versions:
                return distro, versions[-1]

        return None, None

    def _normalize_distro_version(self, distro: str, version: str) -> Optional[str]:
        """
        Normalize a version string to match DISTRO_LIFECYCLE keys.

        Handles point releases like:
        - Ubuntu: 24.04.1 -> 24.04
        - Alpine: 3.19.9 -> 3.19
        - Rocky/Alma: 9.4 -> 9
        """
        distro_data = DISTRO_LIFECYCLE.get(distro, {})
        if not distro_data:
            return None

        # Direct match first
        if version in distro_data:
            return version

        # Try progressively shorter version prefixes
        parts = version.split(".")
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in distro_data:
                return prefix

        return None

    def _find_package_entry(self, purl: PackageURL) -> Optional[PackageLifecycleEntry]:
        """
        Find the PACKAGE_LIFECYCLE entry matching the given PURL.

        Checks name patterns, namespace (for composer packages), and PURL type filters.

        For composer packages (like Laravel), the namespace is significant:
        - pkg:composer/laravel/framework matches patterns against both "laravel" and "framework"

        Args:
            purl: Parsed PackageURL object

        Returns:
            PackageLifecycleEntry if found, None otherwise
        """
        name_lower = purl.name.lower()
        namespace_lower = (purl.namespace or "").lower()
        purl_type = purl.type.lower()

        # Build list of names to check (name + namespace for namespaced packages)
        names_to_check = [name_lower]
        if namespace_lower:
            names_to_check.append(namespace_lower)
            # Also check combined namespace/name format
            names_to_check.append(f"{namespace_lower}/{name_lower}")

        for entry_key, entry in PACKAGE_LIFECYCLE.items():
            # Check name patterns against all possible name variations
            patterns = entry.get("name_patterns", [])
            name_matches = False

            for pattern in patterns:
                pattern_lower = pattern.lower()
                for name in names_to_check:
                    if fnmatch.fnmatch(name, pattern_lower):
                        name_matches = True
                        break
                if name_matches:
                    break

            if not name_matches:
                continue

            # Check PURL type filter
            allowed_types = entry.get("purl_types")
            if allowed_types is not None:
                if purl_type not in [t.lower() for t in allowed_types]:
                    continue

            return entry

        return None
