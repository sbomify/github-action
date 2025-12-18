"""Ubuntu APT Repository data source for Ubuntu package metadata.

Fetches package metadata from public Ubuntu APT repository Packages.gz files.
Supports Ubuntu LTS releases (20.04, 22.04, 24.04) and their updates/security pockets.
"""

import gzip
import io
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata

DEFAULT_TIMEOUT = 30  # seconds for Release files
PACKAGES_TIMEOUT = 120  # seconds for large Packages.gz files

# Ubuntu archive base URL
UBUNTU_ARCHIVE_BASE = "https://archive.ubuntu.com/ubuntu/"

# Map Ubuntu versions to codenames
UBUNTU_CODENAMES: Dict[str, str] = {
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
    "24.10": "oracular",
}

# Search order for pockets (most recent updates first)
POCKET_SEARCH_ORDER = ["-security", "-updates", ""]

# Search order for components (most common first, lazy-load larger repos)
# main: ~20k packages, Canonical-supported
# universe: ~60k packages, community-maintained (includes nodejs, redis, etc.)
# restricted: ~500 packages, proprietary drivers
# multiverse: ~1k packages, non-free software
COMPONENT_SEARCH_ORDER = ["main", "universe", "restricted", "multiverse"]

# In-memory cache: (codename, component, pocket, arch) -> {package_name -> PackageInfo}
_repo_cache: Dict[Tuple[str, str, str, str], Dict[str, "PackageInfo"]] = {}


def clear_cache() -> None:
    """Clear the Ubuntu repo metadata cache."""
    _repo_cache.clear()


class PackageInfo:
    """Package metadata from Packages.gz."""

    __slots__ = (
        "name",
        "version",
        "arch",
        "maintainer",
        "homepage",
        "description",
        "filename",
        "sha256",
    )

    def __init__(
        self,
        name: str,
        version: str,
        arch: str,
        maintainer: Optional[str] = None,
        homepage: Optional[str] = None,
        description: Optional[str] = None,
        filename: Optional[str] = None,
        sha256: Optional[str] = None,
    ):
        self.name = name
        self.version = version
        self.arch = arch
        self.maintainer = maintainer
        self.homepage = homepage
        self.description = description
        self.filename = filename
        self.sha256 = sha256


def _parse_deb822(text: str) -> List[Dict[str, str]]:
    """
    Parse Debian control-style stanzas (deb822 format).

    Field: value format with continuation lines starting with space/tab.
    Stanzas are separated by blank lines.

    Returns list of stanzas, each a dict[str, str].
    """
    stanzas: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    last_key: Optional[str] = None

    def flush() -> None:
        nonlocal cur, last_key
        if cur:
            stanzas.append(cur)
        cur = {}
        last_key = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip():
            flush()
            continue

        # Continuation line
        if line.startswith((" ", "\t")) and last_key:
            cur[last_key] = cur[last_key] + "\n" + line.lstrip()
            continue

        # Field: value line
        if ":" not in line:
            # Malformed line; skip
            continue

        k, v = line.split(":", 1)
        k = k.strip()
        v = v.lstrip()
        cur[k] = v
        last_key = k

    flush()
    return stanzas


def _normalize_base_url(url: str) -> str:
    """Ensure URL has trailing slash."""
    return url.rstrip("/") + "/"


class UbuntuSource:
    """
    Data source for Ubuntu packages using public APT repository metadata.

    Fetches package metadata from Packages.gz files in Ubuntu's archive.
    Supports Ubuntu LTS releases with security/updates pockets.

    This is a Tier 1 native source for Ubuntu packages, providing metadata
    including description, supplier (maintainer), homepage, and download URL.

    Note: License information is NOT available in APT Packages.gz metadata.
    Licenses must come from fallback sources or SBOM generation tools.

    Priority: 12 (Tier 1 - native source for Ubuntu packages)
    Supports: pkg:deb/ubuntu/* packages
    """

    @property
    def name(self) -> str:
        return "ubuntu-apt"

    @property
    def priority(self) -> int:
        # Tier 1: Native sources (10-19) - Direct from official package repos
        # Slightly higher than Debian (10) since Ubuntu packages should use Ubuntu repos
        return 12

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        if purl.type != "deb":
            return False

        # Only support Ubuntu packages (not Debian or other deb-based distros)
        namespace = (purl.namespace or "").lower()
        if namespace != "ubuntu":
            return False

        # Need distro qualifier to determine version/codename
        qualifiers = purl.qualifiers or {}
        distro = qualifiers.get("distro", "")

        if distro:
            # Parse distro to get codename
            codename = self._get_codename_from_distro(distro)
            return codename is not None

        # Without distro qualifier, we can still try default versions
        return True

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from Ubuntu APT repository Packages.gz.

        Searches components in order: main -> universe -> restricted -> multiverse.
        For each component, searches pockets: security -> updates -> base.
        Lazy-loads indices only when needed to minimize network requests.

        Args:
            purl: Parsed PackageURL for an Ubuntu package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        qualifiers = purl.qualifiers or {}
        distro = qualifiers.get("distro", "")
        arch = qualifiers.get("arch", "amd64")

        # Determine codename from distro qualifier
        if distro:
            codename = self._get_codename_from_distro(distro)
        else:
            # Default to latest LTS
            codename = "jammy"

        if not codename:
            logger.debug(f"Could not determine Ubuntu codename for distro: {distro}")
            return None

        # Search through components in order (main first, then universe, etc.)
        # This ensures we don't load large indices like universe unless needed
        for component in COMPONENT_SEARCH_ORDER:
            # Search through pockets in order: security -> updates -> base
            for pocket in POCKET_SEARCH_ORDER:
                suite = f"{codename}{pocket}"
                try:
                    pkg_info = self._find_package(
                        purl.name,
                        suite,
                        component,
                        arch,
                        session,
                    )
                    if pkg_info:
                        logger.debug(f"Found {purl.name} in ubuntu/{suite}/{component}")
                        return self._to_normalized_metadata(pkg_info, suite)

                except Exception as e:
                    logger.warning(f"Error searching Ubuntu repo {suite}/{component}: {e}")
                    continue

        logger.debug(f"Package {purl.name} not found in Ubuntu {codename} repos")
        return None

    def _get_codename_from_distro(self, distro: str) -> Optional[str]:
        """
        Extract Ubuntu codename from distro qualifier.

        Handles formats:
        - "ubuntu-22.04" -> "jammy"
        - "ubuntu-jammy" -> "jammy"
        - "22.04" -> "jammy"

        Args:
            distro: Distro qualifier string

        Returns:
            Ubuntu codename or None if not recognized
        """
        distro = distro.lower()

        # Remove "ubuntu-" prefix if present
        if distro.startswith("ubuntu-"):
            distro = distro[7:]

        # Check if it's a version number
        if distro in UBUNTU_CODENAMES:
            return UBUNTU_CODENAMES[distro]

        # Check if it's already a codename
        if distro in UBUNTU_CODENAMES.values():
            return distro

        return None

    def _find_package(
        self,
        package_name: str,
        suite: str,
        component: str,
        arch: str,
        session: requests.Session,
    ) -> Optional[PackageInfo]:
        """
        Find a package in the specified repo.

        Args:
            package_name: Name of the package to find
            suite: Ubuntu suite (e.g., "jammy", "jammy-updates")
            component: Repository component (e.g., "main")
            arch: Architecture (e.g., "amd64")
            session: requests.Session

        Returns:
            PackageInfo if found, None otherwise
        """
        # Parse suite to get codename and pocket
        if "-" in suite:
            codename, pocket = suite.rsplit("-", 1)
            pocket = f"-{pocket}"
        else:
            codename = suite
            pocket = ""

        cache_key = (codename, component, pocket, arch)

        # Check cache
        if cache_key not in _repo_cache:
            # Load the packages index
            self._load_packages_index(suite, component, arch, session)

        # Look up in cache
        package_index = _repo_cache.get(cache_key, {})
        return package_index.get(package_name)

    def _load_packages_index(
        self,
        suite: str,
        component: str,
        arch: str,
        session: requests.Session,
    ) -> None:
        """
        Load and cache the Packages.gz index.

        Args:
            suite: Ubuntu suite (e.g., "jammy-updates")
            component: Repository component (e.g., "main")
            arch: Architecture (e.g., "amd64")
            session: requests.Session
        """
        # Parse suite to get codename and pocket
        if "-" in suite:
            codename, pocket = suite.rsplit("-", 1)
            pocket = f"-{pocket}"
        else:
            codename = suite
            pocket = ""

        cache_key = (codename, component, pocket, arch)

        # Build URL
        packages_url = urljoin(
            UBUNTU_ARCHIVE_BASE,
            f"dists/{suite}/{component}/binary-{arch}/Packages.gz",
        )

        logger.info(f"Loading Ubuntu packages index from {suite}/{component}/{arch}")

        try:
            response = session.get(packages_url, timeout=PACKAGES_TIMEOUT)
            response.raise_for_status()

            # Decompress and parse
            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
                text = gz.read().decode("utf-8", errors="replace")

            # Parse and index by package name
            package_index: Dict[str, PackageInfo] = {}
            for stanza in _parse_deb822(text):
                pkg_info = self._stanza_to_package_info(stanza, arch)
                if pkg_info:
                    package_index[pkg_info.name] = pkg_info

            _repo_cache[cache_key] = package_index
            logger.info(f"Loaded {len(package_index)} packages from {suite}/{component}/{arch}")

        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch Ubuntu packages index {packages_url}: {e}")
            # Cache empty dict to avoid repeated failures
            _repo_cache[cache_key] = {}

    def _stanza_to_package_info(
        self,
        stanza: Dict[str, str],
        arch: str,
    ) -> Optional[PackageInfo]:
        """
        Convert a parsed deb822 stanza to PackageInfo.

        Args:
            stanza: Parsed stanza dict
            arch: Architecture

        Returns:
            PackageInfo or None if required fields missing
        """
        name = stanza.get("Package")
        version = stanza.get("Version")

        if not name or not version:
            return None

        return PackageInfo(
            name=name,
            version=version,
            arch=stanza.get("Architecture", arch),
            maintainer=stanza.get("Maintainer"),
            homepage=stanza.get("Homepage"),
            description=stanza.get("Description"),
            filename=stanza.get("Filename"),
            sha256=stanza.get("SHA256"),
        )

    def _to_normalized_metadata(
        self,
        pkg: PackageInfo,
        suite: str,
    ) -> Optional[NormalizedMetadata]:
        """
        Convert PackageInfo to NormalizedMetadata.

        Args:
            pkg: Package information
            suite: Ubuntu suite where package was found

        Returns:
            NormalizedMetadata or None if no useful data
        """
        field_sources: Dict[str, str] = {}

        # Supplier from maintainer
        supplier = pkg.maintainer
        if supplier:
            field_sources["supplier"] = self.name

        # Description (first line only for summary)
        description = pkg.description
        if description:
            # Take first line as summary
            first_line = description.split("\n")[0].strip()
            description = first_line if first_line else description
            field_sources["description"] = self.name

        # Homepage
        homepage = pkg.homepage
        if homepage:
            field_sources["homepage"] = self.name

        # Download URL from filename
        download_url = None
        if pkg.filename:
            download_url = urljoin(UBUNTU_ARCHIVE_BASE, pkg.filename)
            field_sources["download_url"] = self.name

        # Registry URL (packages.ubuntu.com)
        registry_url = f"https://packages.ubuntu.com/{suite}/{pkg.name}"
        field_sources["registry_url"] = self.name

        metadata = NormalizedMetadata(
            description=description,
            supplier=supplier,
            homepage=homepage,
            download_url=download_url,
            registry_url=registry_url,
            source=self.name,
            field_sources=field_sources,
        )

        return metadata if metadata.has_data() else None
