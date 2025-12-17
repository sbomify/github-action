"""RPM Repository data source for RPM-based distro package metadata.

Fetches package metadata from public RPM repository primary.xml.gz files.
Supports Rocky Linux, Alma Linux, CentOS Stream, Fedora, and Amazon Linux.
"""

import dataclasses
import gzip
import io
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata

DEFAULT_TIMEOUT = 30  # seconds for repomd.xml
PRIMARY_TIMEOUT = 120  # seconds for large primary.xml.gz files

# Supported distro patterns and their repo URL templates
# {ver} = version, {repo} = BaseOS/AppStream, {arch} = x86_64/aarch64
DISTRO_REPO_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "rocky": {
        "versions": ["8", "9"],
        "template": "https://download.rockylinux.org/pub/rocky/{ver}/{repo}/{arch}/os/",
        "repos": ["BaseOS", "AppStream"],
    },
    "almalinux": {
        "versions": ["8", "9"],
        "template": "https://repo.almalinux.org/almalinux/{ver}/{repo}/{arch}/os/",
        "repos": ["BaseOS", "AppStream"],
    },
    "alma": {  # Alias for almalinux
        "versions": ["8", "9"],
        "template": "https://repo.almalinux.org/almalinux/{ver}/{repo}/{arch}/os/",
        "repos": ["BaseOS", "AppStream"],
    },
    "centos": {
        "versions": ["8", "9"],
        "template_8": "https://vault.centos.org/centos/8-stream/{repo}/{arch}/os/",
        "template_9": "https://mirror.stream.centos.org/9-stream/{repo}/{arch}/os/",
        "repos": ["BaseOS", "AppStream"],
    },
    "fedora": {
        "versions": ["39", "40", "41", "42"],
        "template": "https://dl.fedoraproject.org/pub/fedora/linux/releases/{ver}/Everything/{arch}/os/",
        "repos": ["Everything"],  # Fedora uses single repo
    },
    "amzn": {
        "versions": ["2", "2023"],
        "mirror_list_2": "https://cdn.amazonlinux.com/2/core/latest/{arch}/mirror.list",
        "mirror_list_2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/{arch}/mirror.list",
        "repos": ["core"],
    },
    "amazonlinux": {  # Alias for amzn
        "versions": ["2", "2023"],
        "mirror_list_2": "https://cdn.amazonlinux.com/2/core/latest/{arch}/mirror.list",
        "mirror_list_2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/{arch}/mirror.list",
        "repos": ["core"],
    },
}

# In-memory cache: repo_url -> {package_name -> PackageInfo}
_repo_cache: Dict[str, Dict[str, "PackageInfo"]] = {}

# Cache for resolved mirror URLs
_mirror_cache: Dict[str, str] = {}


def clear_cache() -> None:
    """Clear the RPM repo metadata cache."""
    _repo_cache.clear()
    _mirror_cache.clear()


@dataclasses.dataclass
class PackageInfo:
    """Package metadata from primary.xml."""

    name: str
    arch: str
    epoch: Optional[str]
    version: str
    release: str
    evr: str  # epoch:version-release
    license: Optional[str]
    vendor: Optional[str]
    packager: Optional[str]
    url: Optional[str]
    summary: Optional[str]
    description: Optional[str]
    download_url: Optional[str]
    checksum: Optional[Tuple[str, str]]  # (algorithm, value)


def _safe_text(elem: Optional[ET.Element]) -> Optional[str]:
    """Extract text from element, returning None if empty."""
    if elem is None or elem.text is None:
        return None
    t = elem.text.strip()
    return t if t else None


def _build_evr(epoch: Optional[str], version: str, release: str) -> str:
    """Build epoch:version-release string."""
    if epoch and epoch != "0":
        return f"{epoch}:{version}-{release}"
    return f"{version}-{release}"


def _normalize_repo_base(url: str) -> str:
    """Ensure URL has trailing slash."""
    return url.rstrip("/") + "/"


class RpmRepoSource:
    """
    Data source for RPM-based distributions using public repository metadata.

    Fetches package metadata from primary.xml.gz files in public RPM repos.
    Supports Rocky Linux, Alma Linux, CentOS Stream, Fedora, and Amazon Linux.

    This is a Tier 1 native source for RPM packages, providing authoritative
    metadata including license, vendor/packager, description, and homepage.

    Priority: 15 (Tier 1 - native source for RPM packages)
    Supports: pkg:rpm/* packages with supported distro qualifiers
    """

    @property
    def name(self) -> str:
        return "rpm-repo"

    @property
    def priority(self) -> int:
        # Tier 1: Native sources (10-19) - Direct from official package repos
        return 15

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        if purl.type != "rpm":
            return False

        # Need distro qualifier to know which repo to query
        qualifiers = purl.qualifiers or {}
        distro = qualifiers.get("distro", "")
        if not distro:
            # Try to infer from namespace
            namespace = (purl.namespace or "").lower()
            if namespace in DISTRO_REPO_TEMPLATES:
                return True
            return False

        # Parse distro-version format (e.g., "rocky-9", "fedora-40")
        distro_name, _ = self._parse_distro_qualifier(distro)
        return distro_name in DISTRO_REPO_TEMPLATES

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from RPM repository primary.xml.

        Args:
            purl: Parsed PackageURL for an RPM package
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        qualifiers = purl.qualifiers or {}
        distro_qualifier = qualifiers.get("distro", "")
        arch = qualifiers.get("arch", "x86_64")

        # Parse distro and version
        if distro_qualifier:
            distro_name, distro_version = self._parse_distro_qualifier(distro_qualifier)
        else:
            # Try namespace as distro name
            distro_name = (purl.namespace or "").lower()
            distro_version = None

        if distro_name not in DISTRO_REPO_TEMPLATES:
            logger.debug(f"Unsupported distro for RPM repo lookup: {distro_name}")
            return None

        config = DISTRO_REPO_TEMPLATES[distro_name]

        # If no version, try each supported version
        versions_to_try = [distro_version] if distro_version else config["versions"]

        for version in versions_to_try:
            if version not in config["versions"]:
                continue

            # Get repo URLs for this distro/version/arch
            repo_urls = self._get_repo_urls(distro_name, version, arch, config, session)

            for repo_url in repo_urls:
                try:
                    # Ensure repo is loaded into cache
                    self._ensure_repo_loaded(repo_url, session)

                    # Look up package in cache
                    repo_index = _repo_cache.get(repo_url, {})
                    pkg_info = repo_index.get(purl.name)

                    if pkg_info:
                        logger.debug(f"Found {purl.name} in {repo_url}")
                        return self._to_normalized_metadata(pkg_info)

                except Exception as e:
                    logger.warning(f"Error loading repo {repo_url}: {e}")
                    continue

        logger.debug(f"Package {purl.name} not found in any RPM repo for {distro_name}")
        return None

    def _parse_distro_qualifier(self, distro: str) -> Tuple[str, Optional[str]]:
        """
        Parse distro qualifier like 'rocky-9' into (name, version).

        Handles formats:
        - "rocky-9" -> ("rocky", "9")
        - "fedora-40" -> ("fedora", "40")
        - "centos-stream-9" -> ("centos", "9")
        - "amzn-2023" -> ("amzn", "2023")
        """
        distro = distro.lower()

        # Handle centos-stream-X format
        if distro.startswith("centos-stream-"):
            return "centos", distro.replace("centos-stream-", "")

        # Handle el8/el9 suffix style (e.g., from some SBOMs)
        if "-el" in distro:
            # "rocky-el9" -> ("rocky", "9")
            parts = distro.split("-el")
            if len(parts) == 2:
                return parts[0], parts[1]

        # Standard name-version format
        parts = distro.rsplit("-", 1)
        if len(parts) == 2:
            return parts[0], parts[1]

        return distro, None

    def _get_repo_urls(
        self,
        distro_name: str,
        version: str,
        arch: str,
        config: Dict[str, Any],
        session: requests.Session,
    ) -> List[str]:
        """Get repo URLs for a distro/version/arch combination."""
        urls = []

        # Handle Amazon Linux mirror lists
        if distro_name in ("amzn", "amazonlinux"):
            mirror_key = f"mirror_list_{version}"
            if mirror_key in config:
                mirror_list_url = config[mirror_key].format(arch=arch)
                try:
                    repo_base = self._resolve_mirror_list(mirror_list_url, session)
                    if repo_base:
                        urls.append(repo_base)
                except Exception as e:
                    logger.warning(f"Failed to resolve Amazon Linux mirror list: {e}")
            return urls

        # Handle CentOS with version-specific templates
        if distro_name == "centos":
            template_key = f"template_{version}"
            if template_key in config:
                template = config[template_key]
                for repo in config["repos"]:
                    url = template.format(ver=version, repo=repo, arch=arch)
                    urls.append(_normalize_repo_base(url))
                return urls

        # Standard template-based repos
        if "template" in config:
            template = config["template"]
            for repo in config["repos"]:
                url = template.format(ver=version, repo=repo, arch=arch)
                urls.append(_normalize_repo_base(url))

        return urls

    def _resolve_mirror_list(self, mirror_list_url: str, session: requests.Session) -> Optional[str]:
        """Resolve Amazon Linux mirror list to actual repo URL."""
        if mirror_list_url in _mirror_cache:
            return _mirror_cache[mirror_list_url]

        try:
            logger.debug(f"Fetching mirror list: {mirror_list_url}")
            response = session.get(mirror_list_url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()

            # Mirror list contains URLs, one per line
            lines = response.text.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line and line.startswith("http"):
                    repo_url = _normalize_repo_base(line)
                    _mirror_cache[mirror_list_url] = repo_url
                    return repo_url

        except Exception as e:
            logger.warning(f"Failed to resolve mirror list {mirror_list_url}: {e}")

        return None

    def _ensure_repo_loaded(self, repo_url: str, session: requests.Session) -> None:
        """Ensure repo metadata is loaded into cache."""
        if repo_url in _repo_cache:
            return

        logger.info(f"Loading RPM repo metadata from {repo_url}")

        # Fetch repomd.xml to find primary.xml.gz location
        repomd_url = urljoin(repo_url, "repodata/repomd.xml")
        primary_href = self._parse_repomd(repomd_url, session)

        if not primary_href:
            raise RuntimeError(f"Could not find primary metadata in {repomd_url}")

        # Fetch and parse primary.xml.gz
        primary_url = urljoin(repo_url, primary_href)
        logger.debug(f"Fetching primary.xml.gz from {primary_url}")

        response = session.get(primary_url, timeout=PRIMARY_TIMEOUT)
        response.raise_for_status()

        # Build package index
        package_index: Dict[str, PackageInfo] = {}
        for pkg in self._iter_primary_packages(response.content, repo_url):
            # Index by name (may overwrite if multiple versions, keeps latest)
            package_index[pkg.name] = pkg

        _repo_cache[repo_url] = package_index
        logger.info(f"Loaded {len(package_index)} packages from {repo_url}")

    def _parse_repomd(self, repomd_url: str, session: requests.Session) -> Optional[str]:
        """Parse repomd.xml to find primary.xml.gz location."""
        try:
            response = session.get(repomd_url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()

            root = ET.fromstring(response.content)

            # Handle namespace
            ns_match = re.match(r"\{([^}]+)\}", root.tag)
            ns = ns_match.group(1) if ns_match else ""

            def q(tag: str) -> str:
                return f"{{{ns}}}{tag}" if ns else tag

            for data in root.findall(q("data")):
                if data.get("type") == "primary":
                    location = data.find(q("location"))
                    if location is not None:
                        return location.get("href")

        except Exception as e:
            logger.warning(f"Error parsing repomd.xml from {repomd_url}: {e}")

        return None

    def _iter_primary_packages(self, primary_xml_gz: bytes, repo_url: str) -> Iterable[PackageInfo]:
        """Stream-parse primary.xml.gz and yield PackageInfo records."""
        repo_url = _normalize_repo_base(repo_url)

        # Decompress
        with gzip.GzipFile(fileobj=io.BytesIO(primary_xml_gz)) as gz:
            data = gz.read()

        # Parse to find namespace
        root = ET.fromstring(data)
        ns_match = re.match(r"\{([^}]+)\}", root.tag)
        ns_primary = ns_match.group(1) if ns_match else ""

        def q(tag: str) -> str:
            return f"{{{ns_primary}}}{tag}" if ns_primary else tag

        # Iterate packages
        for elem in root.findall(q("package")):
            # Only include RPM packages
            if elem.get("type") and elem.get("type") != "rpm":
                continue

            name = _safe_text(elem.find(q("name"))) or ""
            arch = _safe_text(elem.find(q("arch"))) or ""

            version_el = elem.find(q("version"))
            if version_el is None:
                continue

            epoch = version_el.get("epoch")
            version = version_el.get("ver") or ""
            release = version_el.get("rel") or ""
            evr = _build_evr(epoch, version, release)

            # Checksum
            checksum_el = elem.find(q("checksum"))
            checksum = None
            if checksum_el is not None and _safe_text(checksum_el):
                alg = checksum_el.get("type") or "unknown"
                checksum = (alg, _safe_text(checksum_el) or "")

            # Location
            location_el = elem.find(q("location"))
            location_href = location_el.get("href") if location_el is not None else None
            download_url = urljoin(repo_url, location_href) if location_href else None

            # Top-level elements (not inside <format>)
            summary = _safe_text(elem.find(q("summary")))
            description = _safe_text(elem.find(q("description")))
            packager = _safe_text(elem.find(q("packager")))
            url_s = _safe_text(elem.find(q("url")))

            # Format block contains rpm-namespaced elements like license, vendor
            fmt = elem.find(q("format"))
            license_s = None
            vendor = None

            if fmt is not None:
                # rpm:license, rpm:vendor are in a different namespace
                # They appear as {http://linux.duke.edu/metadata/rpm}license
                for child in list(fmt):
                    tag = child.tag
                    if tag.endswith("}license") or tag == "license":
                        license_s = _safe_text(child)
                    elif tag.endswith("}vendor") or tag == "vendor":
                        vendor = _safe_text(child)

            yield PackageInfo(
                name=name,
                arch=arch,
                epoch=epoch,
                version=version,
                release=release,
                evr=evr,
                license=license_s,
                vendor=vendor,
                packager=packager,
                url=url_s,
                summary=summary,
                description=description,
                download_url=download_url,
                checksum=checksum,
            )

    def _to_normalized_metadata(self, pkg: PackageInfo) -> Optional[NormalizedMetadata]:
        """Convert PackageInfo to NormalizedMetadata."""
        field_sources: Dict[str, str] = {}

        # Supplier: prefer vendor, fallback to packager
        supplier = pkg.vendor or pkg.packager
        if supplier:
            field_sources["supplier"] = self.name

        # Description: prefer summary (shorter), include full description if different
        description = pkg.summary
        if description:
            field_sources["description"] = self.name

        # Licenses
        licenses: List[str] = []
        if pkg.license:
            licenses = [pkg.license]
            field_sources["licenses"] = self.name

        # Homepage
        homepage = pkg.url
        if homepage:
            field_sources["homepage"] = self.name

        # Download URL
        download_url = pkg.download_url
        if download_url:
            field_sources["download_url"] = self.name

        metadata = NormalizedMetadata(
            description=description,
            licenses=licenses,
            supplier=supplier,
            homepage=homepage,
            download_url=download_url,
            source=self.name,
            field_sources=field_sources,
        )

        return metadata if metadata.has_data() else None
