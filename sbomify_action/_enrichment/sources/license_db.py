"""License Database data source for Linux distro package licenses.

Downloads and uses pre-computed license databases from GitHub Releases
to provide license information for Ubuntu and RPM-based distro packages.

The databases are keyed by PURL for fast lookups and contain SPDX-validated
license expressions extracted from package copyright files (Ubuntu) or
RPM metadata (Rocky, Alma, Fedora).
"""

import gzip
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata

# GitHub repository hosting the license databases
GITHUB_REPO = "sbomify/github-action"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases"

# Default timeout for downloads
DEFAULT_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 120

# Cache directory (XDG compliant)
DEFAULT_CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "sbomify" / "license-db"

# Supported distros and their database file patterns
SUPPORTED_DISTROS = {
    "ubuntu": {
        "type": "deb",
        "versions": ["20.04", "22.04", "24.04"],
        "codenames": {"20.04": "focal", "22.04": "jammy", "24.04": "noble"},
    },
    "rocky": {
        "type": "rpm",
        "versions": ["8", "9"],
    },
    "almalinux": {
        "type": "rpm",
        "versions": ["8", "9"],
    },
    "fedora": {
        "type": "rpm",
        "versions": ["39", "40", "41"],
    },
}

# In-memory cache of loaded databases
# Key: (distro, version) -> Dict of PURL -> license data
_db_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

# Cache for checking release availability
_release_cache: Optional[List[Dict[str, Any]]] = None


def clear_cache() -> None:
    """Clear the license database cache."""
    _db_cache.clear()
    global _release_cache
    _release_cache = None


def get_cache_dir() -> Path:
    """Get the cache directory, creating it if needed."""
    cache_dir = DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


class LicenseDBSource:
    """
    Data source using pre-computed license databases.

    Downloads license databases from GitHub Releases on first use and
    caches them locally. Provides fast PURL-based lookups for license
    information.

    This source only provides license data - other metadata fields
    come from the existing Ubuntu/RPM sources.

    Priority: 8 (before API calls, provides license-only data)
    Supports: pkg:deb/ubuntu/*, pkg:rpm/rocky/*, pkg:rpm/almalinux/*, pkg:rpm/fedora/*
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize the license database source.

        Args:
            cache_dir: Optional custom cache directory
        """
        self._cache_dir = cache_dir or get_cache_dir()

    @property
    def name(self) -> str:
        return "license-db"

    @property
    def priority(self) -> int:
        # Higher priority than API sources (10+) since this is local/fast
        # but lower than native sources that provide full metadata
        return 8

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL."""
        # Check package type
        if purl.type == "deb":
            namespace = (purl.namespace or "").lower()
            return namespace == "ubuntu"
        elif purl.type == "rpm":
            namespace = (purl.namespace or "").lower()
            return namespace in ("rocky", "almalinux", "fedora")
        return False

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch license metadata from the pre-computed database.

        Args:
            purl: Parsed PackageURL
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata with license info, or None if not found
        """
        # Determine distro and version from PURL
        distro, version = self._parse_distro_from_purl(purl)
        if not distro or not version:
            return None

        # Load the database
        db = self._load_database(distro, version, session)
        if not db:
            return None

        # Look up by PURL (try exact match first)
        purl_str = str(purl)
        pkg_data = db.get("packages", {}).get(purl_str)

        # If no exact match, try lookup by name only
        if not pkg_data:
            pkg_data = self._lookup_by_name(db, purl.name)

        if not pkg_data:
            logger.debug(f"Package {purl.name} not found in license database")
            return None

        # Extract license info - required
        spdx = pkg_data.get("spdx")
        if not spdx:
            return None

        # Build metadata with all available fields
        field_sources: dict = {}

        # License (required)
        licenses = [spdx]
        field_sources["licenses"] = self.name

        # Description
        description = pkg_data.get("description")
        if description:
            field_sources["description"] = self.name

        # Supplier
        supplier = pkg_data.get("supplier")
        if supplier:
            field_sources["supplier"] = self.name

        # Homepage
        homepage = pkg_data.get("homepage")
        if homepage:
            field_sources["homepage"] = self.name

        # Download URL
        download_url = pkg_data.get("download_url")
        if download_url:
            field_sources["download_url"] = self.name

        # Maintainer info
        maintainer_name = pkg_data.get("maintainer_name")
        maintainer_email = pkg_data.get("maintainer_email")
        if maintainer_name:
            field_sources["maintainer_name"] = self.name
        if maintainer_email:
            field_sources["maintainer_email"] = self.name

        return NormalizedMetadata(
            licenses=licenses,
            description=description,
            supplier=supplier,
            homepage=homepage,
            download_url=download_url,
            maintainer_name=maintainer_name,
            maintainer_email=maintainer_email,
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
        namespace = (purl.namespace or "").lower()
        qualifiers = purl.qualifiers or {}
        distro_qualifier = qualifiers.get("distro", "")

        # Parse distro qualifier (e.g., "ubuntu-24.04", "rocky-9")
        if distro_qualifier:
            match = re.match(r"([a-z]+)-(.+)", distro_qualifier.lower())
            if match:
                return match.group(1), match.group(2)

        # Fall back to namespace and try to infer version
        if namespace in SUPPORTED_DISTROS:
            # Use latest supported version as default
            versions = SUPPORTED_DISTROS[namespace]["versions"]
            return namespace, versions[-1]  # Latest version

        return None, None

    def _load_database(self, distro: str, version: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """
        Load the license database for a distro/version.

        Downloads from GitHub Releases if not cached locally.

        Args:
            distro: Distribution name (ubuntu, rocky, etc.)
            version: Distribution version
            session: requests.Session

        Returns:
            Loaded database dict or None
        """
        cache_key = (distro, version)

        # Check in-memory cache
        if cache_key in _db_cache:
            return _db_cache[cache_key]

        # Check local file cache
        cache_file = self._cache_dir / f"{distro}-{version}.json.gz"
        if cache_file.exists():
            try:
                db = self._load_from_file(cache_file)
                _db_cache[cache_key] = db
                logger.debug(f"Loaded license database from cache: {cache_file}")
                return db
            except Exception as e:
                logger.warning(f"Failed to load cached database {cache_file}: {e}")
                cache_file.unlink(missing_ok=True)

        # Download from GitHub Releases
        db = self._download_database(distro, version, session)
        if db:
            _db_cache[cache_key] = db
            # Save to local cache
            try:
                self._save_to_file(cache_file, db)
            except Exception as e:
                logger.warning(f"Failed to save database to cache: {e}")

        return db

    def _load_from_file(self, path: Path) -> Dict[str, Any]:
        """Load a gzipped JSON database from file."""
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)

    def _save_to_file(self, path: Path, db: Dict[str, Any]) -> None:
        """Save a database to gzipped JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wt", encoding="utf-8") as f:
            json.dump(db, f)

    def _download_database(self, distro: str, version: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """
        Download database from GitHub Releases.

        Args:
            distro: Distribution name
            version: Distribution version
            session: requests.Session

        Returns:
            Loaded database dict or None
        """
        filename = f"{distro}-{version}.json.gz"

        # Get releases
        releases = self._get_releases(session)
        if not releases:
            logger.debug("No license database releases found")
            return None

        # Look for the file in releases (check latest first)
        for release in releases:
            for asset in release.get("assets", []):
                if asset.get("name") == filename:
                    download_url = asset.get("browser_download_url")
                    if download_url:
                        return self._download_asset(download_url, session)

        logger.debug(f"License database not found: {filename}")
        return None

    def _get_releases(self, session: requests.Session) -> List[Dict[str, Any]]:
        """Get GitHub releases with caching."""
        global _release_cache
        if _release_cache is not None:
            return _release_cache

        try:
            # Look for releases with "license-db" tag prefix
            response = session.get(
                GITHUB_RELEASES_API,
                timeout=DEFAULT_TIMEOUT,
                params={"per_page": 10},
            )
            response.raise_for_status()

            releases = response.json()
            # Filter to license-db releases
            _release_cache = [r for r in releases if r.get("tag_name", "").startswith("license-db-")]
            return _release_cache

        except Exception as e:
            logger.warning(f"Failed to fetch GitHub releases: {e}")
            _release_cache = []
            return []

    def _download_asset(self, url: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """Download and parse a release asset."""
        try:
            logger.info(f"Downloading license database: {url}")
            response = session.get(url, timeout=DOWNLOAD_TIMEOUT)
            response.raise_for_status()

            # Decompress and parse using BytesIO for reliability
            import io

            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
                return json.load(gz)

        except Exception as e:
            logger.warning(f"Failed to download license database: {e}")
            return None

    def _lookup_by_name(self, db: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
        """
        Look up package by name when exact PURL match fails.

        Searches through all packages to find a name match.

        Args:
            db: Loaded database
            name: Package name to find

        Returns:
            Package data dict or None
        """
        packages = db.get("packages", {})

        # First pass: look for exact name match in the data
        for purl_str, pkg_data in packages.items():
            if pkg_data.get("name") == name:
                return pkg_data

        # Second pass: try to extract name from PURL keys
        for purl_str, pkg_data in packages.items():
            try:
                purl = PackageURL.from_string(purl_str)
                if purl.name == name:
                    return pkg_data
            except Exception:
                continue

        return None
