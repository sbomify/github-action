"""Generate license database for Linux distro packages.

This module extracts license information from Linux distro packages,
validates them against SPDX, and outputs a JSON database keyed by PURL
for easy lookups during SBOM enrichment.

Supported distros:
- Alpine Linux (3.13-3.21)
- Wolfi (Chainguard) - rolling release
- Amazon Linux (2, 2023)
- CentOS Stream (8, 9)
- Ubuntu (20.04, 22.04, 24.04)
- Rocky Linux (8, 9)
- AlmaLinux (8, 9)
- Fedora (39, 40, 41, 42)

Usage:
    sbomify-license-db --distro alpine --version 3.20 --output alpine-3.20.json.gz
    sbomify-license-db --distro wolfi --version rolling --output wolfi-rolling.json.gz
    sbomify-license-db --distro ubuntu --version 24.04 --output ubuntu-24.04.json.gz
    sbomify-license-db --distro rocky --version 9 --output rocky-9.json.gz
"""

import argparse
import gzip
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional
from urllib.parse import urljoin

import requests
from packageurl import PackageURL

from ..http_client import USER_AGENT
from ..logging_config import setup_logging
from .license_normalizer import (
    extract_dep5_license,
    normalize_rpm_license,
    validate_spdx_expression,
)

# Initialize logger
logger = setup_logging(level="INFO", use_rich=True)

# HTTP session with sbomify user agent
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": f"{USER_AGENT} (license-db-generator)"})

# Timeouts
DEFAULT_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 120


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class PackageMetadata:
    """Full metadata for a single package."""

    purl: str
    name: str
    version: str
    # License info
    spdx: Optional[str]
    license_raw: str
    # Description
    description: Optional[str]
    # Supplier/Maintainer
    supplier: Optional[str]
    maintainer_name: Optional[str]
    maintainer_email: Optional[str]
    # URLs
    homepage: Optional[str]
    download_url: Optional[str]
    # Metadata
    confidence: str
    source: str


@dataclass
class DatabaseMetadata:
    """Metadata about the generated database."""

    distro: str
    version: str
    codename: Optional[str]
    generated_at: str
    package_count: int
    schema_version: int = 1
    # CLE (Common Lifecycle Enumeration) fields
    release_date: Optional[str] = None  # ISO 8601 date when distro version was released
    end_of_support: Optional[str] = None  # ISO 8601 date when security fixes stop
    end_of_life: Optional[str] = None  # ISO 8601 date when all support ends


# CLE (Common Lifecycle Enumeration) data for supported distros
#
# Schema:
#   release_date: ISO-8601 date (YYYY-MM-DD) or YYYY-MM when only month is known
#   end_of_support: When standard/active updates end (or same as EOL when upstream publishes only one date)
#   end_of_life: When all updates end (security support end)
#
# Sources and calculation methodology documented per-distro below.
# For rolling releases, all dates are None.

DISTRO_LIFECYCLE = {
    # -------------------------------------------------------------------------
    # Wolfi (Chainguard) - Rolling Release
    # Source: https://docs.chainguard.dev/open-source/wolfi/
    # Note: Wolfi is a rolling-release distribution; lifecycle is not expressed
    # as fixed version EOL dates. All fields are None.
    # -------------------------------------------------------------------------
    "wolfi": {
        "rolling": {
            "release_date": None,
            "end_of_support": None,
            "end_of_life": None,
        },
    },
    # -------------------------------------------------------------------------
    # Alpine Linux
    # Source: https://alpinelinux.org/releases/
    # Note: Alpine publishes a single per-branch end date. Alpine does not
    # separately publish EOS vs EOL for the branch, so the published end date
    # is used as both end_of_support and end_of_life.
    # -------------------------------------------------------------------------
    "alpine": {
        "3.13": {
            "release_date": "2021-01-14",
            "end_of_support": "2022-11-01",
            "end_of_life": "2022-11-01",
        },
        "3.14": {
            "release_date": "2021-06-15",
            "end_of_support": "2023-05-01",
            "end_of_life": "2023-05-01",
        },
        "3.15": {
            "release_date": "2021-11-24",
            "end_of_support": "2023-11-01",
            "end_of_life": "2023-11-01",
        },
        "3.16": {
            "release_date": "2022-05-23",
            "end_of_support": "2024-05-23",
            "end_of_life": "2024-05-23",
        },
        "3.17": {
            "release_date": "2022-11-22",
            "end_of_support": "2024-11-22",
            "end_of_life": "2024-11-22",
        },
        "3.18": {
            "release_date": "2023-05-09",
            "end_of_support": "2025-05-09",
            "end_of_life": "2025-05-09",
        },
        "3.19": {
            "release_date": "2023-12-07",
            "end_of_support": "2025-11-01",
            "end_of_life": "2025-11-01",
        },
        "3.20": {
            "release_date": "2024-05-22",
            "end_of_support": "2026-04-01",
            "end_of_life": "2026-04-01",
        },
        "3.21": {
            "release_date": "2024-12-05",
            "end_of_support": "2026-11-01",
            "end_of_life": "2026-11-01",
        },
    },
    # -------------------------------------------------------------------------
    # Rocky Linux
    # Source: https://docs.rockylinux.org/
    # Note: Rocky publishes both 'general support until' (EOS) and 'security
    # support through' (EOL) dates.
    # -------------------------------------------------------------------------
    "rocky": {
        "8": {
            "release_date": "2021-06-21",
            "end_of_support": "2024-05-01",  # General support end
            "end_of_life": "2029-05-01",  # Security support end
        },
        "9": {
            "release_date": "2022-07-14",
            "end_of_support": "2027-05-31",  # General support end
            "end_of_life": "2032-05-31",  # Security support end
        },
    },
    # -------------------------------------------------------------------------
    # AlmaLinux
    # Source: https://wiki.almalinux.org/release-notes/
    # Note: AlmaLinux publishes 'active support until' (EOS) and 'security
    # support until' (EOL) dates.
    # -------------------------------------------------------------------------
    "almalinux": {
        "8": {
            "release_date": "2021-03-30",
            "end_of_support": "2024-05-31",  # Active support end
            "end_of_life": "2029-05-31",  # Security support end
        },
        "9": {
            "release_date": "2022-05-26",
            "end_of_support": "2027-05-31",  # Active support end
            "end_of_life": "2032-05-31",  # Security support end
        },
    },
    # -------------------------------------------------------------------------
    # Amazon Linux
    # Source: https://aws.amazon.com/amazon-linux-2/faqs/
    # Note: AWS publishes an explicit end-of-support date but does not publish
    # separate EOS vs EOL semantics, so the published date is used for both.
    # AL2023 only specifies month ("until June 2029").
    # -------------------------------------------------------------------------
    "amazonlinux": {
        "2": {
            "release_date": "2017-12-19",  # AWS announcement date
            "end_of_support": "2026-06-30",
            "end_of_life": "2026-06-30",
        },
        "2023": {
            "release_date": None,  # Not explicitly published
            "end_of_support": "2029-06",  # Month precision only
            "end_of_life": "2029-06",
        },
    },
    # -------------------------------------------------------------------------
    # CentOS Stream
    # Source: https://www.centos.org/cl-vs-cs/
    # Note: CentOS publishes an 'expected end of life (EOL)' date. No separate
    # EOS date is published, so EOL is used for both.
    # -------------------------------------------------------------------------
    "centos": {
        "stream8": {
            "release_date": None,  # Not explicitly published
            "end_of_support": "2024-05-31",
            "end_of_life": "2024-05-31",
        },
        "stream9": {
            "release_date": None,  # Not explicitly published
            "end_of_support": "2027-05-31",
            "end_of_life": "2027-05-31",
        },
    },
    # -------------------------------------------------------------------------
    # Fedora
    # Source: https://fedorapeople.org/groups/schedule/
    # Note: Fedora schedules publish explicit EOL dates. Fedora publishes only
    # one end date per release, so it's used for both EOS and EOL.
    # Release dates are from 'Current Final Target date' in the schedule.
    # -------------------------------------------------------------------------
    "fedora": {
        "39": {
            "release_date": None,  # Not captured
            "end_of_support": "2024-11-26",
            "end_of_life": "2024-11-26",
        },
        "40": {
            "release_date": None,  # Not captured
            "end_of_support": "2025-05-13",
            "end_of_life": "2025-05-13",
        },
        "41": {
            "release_date": "2024-10-29",
            "end_of_support": "2025-12-15",
            "end_of_life": "2025-12-15",
        },
        "42": {
            "release_date": "2025-04-15",
            # EOL date not yet captured from Fedora sources
            # See: https://fedorapeople.org/groups/schedule/f-42/f-42-key-tasks.html
            "end_of_support": None,
            "end_of_life": None,
        },
    },
    # -------------------------------------------------------------------------
    # Ubuntu
    # Source: https://ubuntu.com/about/release-cycle
    # Note: Ubuntu publishes 'Standard security maintenance' (EOS) and
    # 'Expanded security maintenance' (EOL) dates at month precision.
    # -------------------------------------------------------------------------
    "ubuntu": {
        "20.04": {
            "release_date": "2020-04",  # Month precision
            "end_of_support": "2025-05",  # Standard security maintenance end
            "end_of_life": "2030-04",  # Expanded security maintenance end
        },
        "22.04": {
            "release_date": "2022-04",
            "end_of_support": "2027-06",
            "end_of_life": "2032-04",
        },
        "24.04": {
            "release_date": "2024-04",
            "end_of_support": "2029-05",
            "end_of_life": "2034-04",
        },
    },
}


# =============================================================================
# PURL Construction
# =============================================================================


def make_deb_purl(
    name: str,
    version: str,
    distro: str,
    distro_version: str,
    arch: str = "amd64",
) -> str:
    """Construct a PURL for a Debian/Ubuntu package."""
    purl = PackageURL(
        type="deb",
        namespace=distro,
        name=name,
        version=version,
        qualifiers={"arch": arch, "distro": f"{distro}-{distro_version}"},
    )
    return str(purl)


def make_rpm_purl(
    name: str,
    version: str,
    release: str,
    distro: str,
    distro_version: str,
    arch: str = "x86_64",
    epoch: Optional[str] = None,
) -> str:
    """Construct a PURL for an RPM package."""
    full_version = f"{version}-{release}"
    if epoch and epoch != "0":
        full_version = f"{epoch}:{full_version}"

    purl = PackageURL(
        type="rpm",
        namespace=distro,
        name=name,
        version=full_version,
        qualifiers={"arch": arch, "distro": f"{distro}-{distro_version}"},
    )
    return str(purl)


def make_apk_purl(
    name: str,
    version: str,
    distro_version: str,
    arch: str = "x86_64",
) -> str:
    """Construct a PURL for an Alpine APK package."""
    purl = PackageURL(
        type="apk",
        namespace="alpine",
        name=name,
        version=version,
        qualifiers={"arch": arch, "distro": f"alpine-{distro_version}"},
    )
    return str(purl)


# =============================================================================
# Alpine Package Processing
# =============================================================================

ALPINE_CDN_BASE = "https://dl-cdn.alpinelinux.org/alpine/"
ALPINE_REPOS = ["main", "community"]

# Wolfi (Chainguard) repository - rolling release
WOLFI_REPO_BASE = "https://packages.wolfi.dev/os/"


@dataclass
class ApkPackageInfo:
    """Package info from Alpine APKINDEX."""

    name: str  # P:
    version: str  # V:
    arch: str  # A:
    description: Optional[str]  # T:
    url: Optional[str]  # U:
    license: Optional[str]  # L:
    maintainer: Optional[str]  # m:
    origin: Optional[str]  # o:


def parse_apkindex(content: str) -> Iterator[Dict[str, str]]:
    """Parse APKINDEX file format (single-letter fields, blank line separators)."""
    current: Dict[str, str] = {}

    for line in content.splitlines():
        line = line.rstrip()

        if not line:
            if current:
                yield current
                current = {}
            continue

        if ":" in line:
            key, _, value = line.partition(":")
            current[key] = value

    if current:
        yield current


def fetch_alpine_packages(
    version: str,
    repo: str = "main",
    arch: str = "x86_64",
) -> Iterator[ApkPackageInfo]:
    """Fetch and parse Alpine APKINDEX."""
    url = f"{ALPINE_CDN_BASE}v{version}/{repo}/{arch}/APKINDEX.tar.gz"

    logger.info(f"Fetching {url}")

    try:
        response = SESSION.get(url, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()

        # APKINDEX.tar.gz contains APKINDEX file
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name == "APKINDEX":
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        for pkg_data in parse_apkindex(content):
                            name = pkg_data.get("P")
                            version_str = pkg_data.get("V")
                            if not name or not version_str:
                                continue

                            yield ApkPackageInfo(
                                name=name,
                                version=version_str,
                                arch=pkg_data.get("A", arch),
                                description=pkg_data.get("T"),
                                url=pkg_data.get("U"),
                                license=pkg_data.get("L"),
                                maintainer=pkg_data.get("m"),
                                origin=pkg_data.get("o"),
                            )
                        break

    except Exception as e:
        logger.warning(f"Failed to fetch APKINDEX from {url}: {e}")


def normalize_alpine_license(license_str: str) -> Optional[str]:
    """Normalize Alpine license string to SPDX.

    Alpine packages should already use SPDX identifiers per their policy,
    but we still validate them.
    """
    if not license_str:
        return None

    # Alpine often uses SPDX-compatible identifiers directly
    # First try the raw string
    if validate_spdx_expression(license_str):
        return license_str

    # Some Alpine packages use slightly different formats
    # Try common transformations
    normalized = license_str.strip()

    # Handle "AND" / "OR" operators (Alpine uses spaces sometimes)
    if " " in normalized and " AND " not in normalized and " OR " not in normalized:
        # Check if it's multiple licenses separated by space
        parts = normalized.split()
        if all(validate_spdx_expression(p) for p in parts):
            # Multiple licenses - treat as AND
            return " AND ".join(parts)

    # Try direct validation again with cleaned string
    if validate_spdx_expression(normalized):
        return normalized

    return None


def process_alpine_package(
    pkg_info: ApkPackageInfo,
    distro_version: str,
) -> Optional[PackageMetadata]:
    """Process a single Alpine package and extract all metadata."""
    if not pkg_info.license:
        return None

    spdx = normalize_alpine_license(pkg_info.license)
    if not spdx:
        return None

    purl = make_apk_purl(
        name=pkg_info.name,
        version=pkg_info.version,
        distro_version=distro_version,
        arch=pkg_info.arch,
    )

    description = pkg_info.description
    if description:
        description = description.strip()[:500]

    maintainer_name, maintainer_email = parse_maintainer(pkg_info.maintainer)

    return PackageMetadata(
        purl=purl,
        name=pkg_info.name,
        version=pkg_info.version,
        spdx=spdx,
        license_raw=pkg_info.license,
        description=description,
        supplier=None,  # Alpine doesn't have vendor field
        maintainer_name=maintainer_name,
        maintainer_email=maintainer_email,
        homepage=pkg_info.url,
        download_url=None,  # Would need to construct from origin
        confidence="high",
        source="apk_metadata",
    )


# =============================================================================
# Wolfi (Chainguard) Package Processing
# =============================================================================


def make_wolfi_purl(
    name: str,
    version: str,
    arch: str = "x86_64",
) -> str:
    """Construct a PURL for a Wolfi package."""
    purl = PackageURL(
        type="apk",
        namespace="wolfi",
        name=name,
        version=version,
        qualifiers={"arch": arch},
    )
    return str(purl)


def fetch_wolfi_packages(arch: str = "x86_64") -> Iterator[ApkPackageInfo]:
    """Fetch and parse Wolfi APKINDEX."""
    url = f"{WOLFI_REPO_BASE}{arch}/APKINDEX.tar.gz"

    logger.info(f"Fetching {url}")

    try:
        response = SESSION.get(url, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()

        # APKINDEX.tar.gz contains APKINDEX file
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name == "APKINDEX":
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        for pkg_data in parse_apkindex(content):
                            name = pkg_data.get("P")
                            version_str = pkg_data.get("V")
                            if not name or not version_str:
                                continue

                            yield ApkPackageInfo(
                                name=name,
                                version=version_str,
                                arch=pkg_data.get("A", arch),
                                description=pkg_data.get("T"),
                                url=pkg_data.get("U"),
                                license=pkg_data.get("L"),
                                maintainer=pkg_data.get("m"),
                                origin=pkg_data.get("o"),
                            )
                        break

    except Exception as e:
        logger.warning(f"Failed to fetch APKINDEX from {url}: {e}")


def process_wolfi_package(pkg_info: ApkPackageInfo) -> Optional[PackageMetadata]:
    """Process a single Wolfi package and extract all metadata."""
    if not pkg_info.license:
        return None

    # Wolfi uses SPDX identifiers like Alpine
    spdx = normalize_alpine_license(pkg_info.license)
    if not spdx:
        return None

    purl = make_wolfi_purl(
        name=pkg_info.name,
        version=pkg_info.version,
        arch=pkg_info.arch,
    )

    description = pkg_info.description
    if description:
        description = description.strip()[:500]

    maintainer_name, maintainer_email = parse_maintainer(pkg_info.maintainer)

    return PackageMetadata(
        purl=purl,
        name=pkg_info.name,
        version=pkg_info.version,
        spdx=spdx,
        license_raw=pkg_info.license,
        description=description,
        supplier="Chainguard",  # Wolfi is maintained by Chainguard
        maintainer_name=maintainer_name,
        maintainer_email=maintainer_email,
        homepage=pkg_info.url,
        download_url=None,
        confidence="high",
        source="apk_metadata",
    )


# =============================================================================
# Ubuntu/Debian Package Processing
# =============================================================================

UBUNTU_ARCHIVE_BASE = "https://archive.ubuntu.com/ubuntu/"
UBUNTU_CODENAMES = {
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
}
UBUNTU_COMPONENTS = ["main", "universe", "restricted", "multiverse"]
UBUNTU_POCKETS = ["-security", "-updates", ""]


def parse_deb822(text: str) -> Iterator[Dict[str, str]]:
    """Parse Debian control-style stanzas."""
    cur: Dict[str, str] = {}
    last_key: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip():
            if cur:
                yield cur
                cur = {}
                last_key = None
            continue

        if line.startswith((" ", "\t")) and last_key:
            cur[last_key] = cur[last_key] + "\n" + line.lstrip()
            continue

        if ":" not in line:
            continue

        k, v = line.split(":", 1)
        cur[k.strip()] = v.lstrip()
        last_key = k.strip()

    if cur:
        yield cur


def fetch_ubuntu_packages(
    codename: str,
    component: str = "main",
    pocket: str = "",
    arch: str = "amd64",
) -> Iterator[Dict[str, str]]:
    """Fetch and parse Ubuntu Packages.gz index."""
    suite = f"{codename}{pocket}"
    url = urljoin(
        UBUNTU_ARCHIVE_BASE,
        f"dists/{suite}/{component}/binary-{arch}/Packages.gz",
    )

    logger.info(f"Fetching {url}")

    try:
        response = SESSION.get(url, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()

        with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
            text = gz.read().decode("utf-8", errors="replace")

        yield from parse_deb822(text)
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")


def download_and_extract_deb(filename: str, package_name: str) -> Optional[str]:
    """Download a .deb file and extract the copyright file."""
    url = urljoin(UBUNTU_ARCHIVE_BASE, filename)

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            deb_path = Path(tmpdir) / "package.deb"

            response = SESSION.get(url, timeout=DOWNLOAD_TIMEOUT, stream=True)
            response.raise_for_status()

            with open(deb_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            extract_dir = Path(tmpdir) / "extracted"
            extract_dir.mkdir()

            # Use dpkg-deb if available, otherwise ar + tar
            try:
                subprocess.run(
                    ["dpkg-deb", "-x", str(deb_path), str(extract_dir)],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except (subprocess.CalledProcessError, FileNotFoundError):
                subprocess.run(
                    ["ar", "x", str(deb_path)],
                    cwd=tmpdir,
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
                for data_tar in Path(tmpdir).glob("data.tar.*"):
                    subprocess.run(
                        ["tar", "xf", str(data_tar), "-C", str(extract_dir)],
                        check=True,
                        capture_output=True,
                        timeout=60,
                    )
                    break

            # Look for copyright file
            copyright_paths = [
                extract_dir / "usr" / "share" / "doc" / package_name / "copyright",
                extract_dir / "usr" / "share" / "doc" / package_name.split(":")[0] / "copyright",
            ]

            for cp_path in copyright_paths:
                if cp_path.exists():
                    return cp_path.read_text(errors="replace")

            for cp_path in extract_dir.rglob("copyright"):
                return cp_path.read_text(errors="replace")

    except Exception as e:
        logger.debug(f"Failed to extract copyright from {package_name}: {e}")

    return None


def parse_maintainer(maintainer: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Parse maintainer field into name and email."""
    if not maintainer:
        return None, None

    # Format: "Name <email>" or just "Name"
    match = re.match(r"^(.+?)\s*<([^>]+)>", maintainer)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return maintainer.strip(), None


def process_ubuntu_package(
    pkg_info: Dict[str, str],
    distro_version: str,
    codename: str,
) -> Optional[PackageMetadata]:
    """Process a single Ubuntu package and extract all metadata."""
    name = pkg_info.get("Package")
    version = pkg_info.get("Version")
    filename = pkg_info.get("Filename")

    if not name or not version:
        return None

    # Extract license from copyright file
    spdx = None
    if filename:
        copyright_text = download_and_extract_deb(filename, name)
        if copyright_text:
            spdx = extract_dep5_license(copyright_text)

    # We still require a valid license for inclusion
    if not spdx:
        return None

    # Extract other metadata from Packages.gz
    description = pkg_info.get("Description")
    if description:
        # Take first line only (rest is long description)
        description = description.split("\n")[0].strip()

    maintainer = pkg_info.get("Maintainer")
    maintainer_name, maintainer_email = parse_maintainer(maintainer)

    homepage = pkg_info.get("Homepage")

    # Construct download URL
    download_url = None
    if filename:
        download_url = urljoin(UBUNTU_ARCHIVE_BASE, filename)

    purl = make_deb_purl(
        name=name,
        version=version,
        distro="ubuntu",
        distro_version=distro_version,
    )

    return PackageMetadata(
        purl=purl,
        name=name,
        version=version,
        spdx=spdx,
        license_raw=spdx,
        description=description,
        supplier=maintainer,
        maintainer_name=maintainer_name,
        maintainer_email=maintainer_email,
        homepage=homepage,
        download_url=download_url,
        confidence="high",
        source="deb_metadata",
    )


# =============================================================================
# RPM Package Processing
# =============================================================================

RPM_DISTRO_REPOS = {
    "rocky": {
        "8": [
            "https://download.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/",
            "https://download.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/",
        ],
        "9": [
            "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/",
            "https://download.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/",
        ],
    },
    "almalinux": {
        "8": [
            "https://repo.almalinux.org/almalinux/8/BaseOS/x86_64/os/",
            "https://repo.almalinux.org/almalinux/8/AppStream/x86_64/os/",
        ],
        "9": [
            "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/",
            "https://repo.almalinux.org/almalinux/9/AppStream/x86_64/os/",
        ],
    },
    "amazonlinux": {
        # Amazon Linux uses mirror.list files that return the actual repo URL with GUID
        "2": [
            "mirror:https://cdn.amazonlinux.com/2/core/2.0/x86_64/mirror.list",
        ],
        "2023": [
            "mirror:https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
        ],
    },
    "centos": {
        # Stream 8 is EOL, use vault archive
        "stream8": [
            "https://vault.centos.org/centos/8-stream/BaseOS/x86_64/os/",
            "https://vault.centos.org/centos/8-stream/AppStream/x86_64/os/",
        ],
        "stream9": [
            "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/",
            "https://mirror.stream.centos.org/9-stream/AppStream/x86_64/os/",
        ],
    },
    "fedora": {
        # Fedora keeps only currently supported releases on the main download server;
        # older releases are moved to the archives. Releases listed with
        # archives.fedoraproject.org URLs are end-of-life, while those with
        # dl.fedoraproject.org URLs are still supported. When a release reaches
        # end-of-life, move its entry to the archives pattern and add the new
        # current release with a dl.fedoraproject.org URL.
        "39": ["https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/39/Everything/x86_64/os/"],
        "40": ["https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/40/Everything/x86_64/os/"],
        "41": ["https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/41/Everything/x86_64/os/"],
        "42": ["https://dl.fedoraproject.org/pub/fedora/linux/releases/42/Everything/x86_64/os/"],
    },
}


@dataclass
class RpmPackageInfo:
    """Package info from RPM primary.xml."""

    name: str
    version: str
    release: str
    epoch: Optional[str]
    arch: str
    license: Optional[str]
    location_href: Optional[str]
    # Additional metadata
    summary: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    vendor: Optional[str] = None
    packager: Optional[str] = None


def fetch_rpm_repomd(repo_url: str) -> Optional[str]:
    """Fetch repomd.xml and return the primary.xml.gz href."""
    repomd_url = urljoin(repo_url, "repodata/repomd.xml")

    try:
        response = SESSION.get(repomd_url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        root = ET.fromstring(response.content)
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
        logger.warning(f"Failed to fetch repomd.xml from {repo_url}: {e}")

    return None


def fetch_rpm_packages(repo_url: str) -> Iterator[RpmPackageInfo]:
    """Fetch and parse RPM repository primary.xml (gzip or zstd compressed)."""
    primary_href = fetch_rpm_repomd(repo_url)
    if not primary_href:
        return

    primary_url = urljoin(repo_url, primary_href)
    logger.info(f"Fetching {primary_url}")

    try:
        response = SESSION.get(primary_url, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()

        # Handle both gzip and zstd compression
        if primary_href.endswith(".zst"):
            try:
                import zstandard as zstd

                dctx = zstd.ZstdDecompressor()
                # Use streaming decompression for files without content size in header
                reader = dctx.stream_reader(io.BytesIO(response.content))
                data = reader.read()
                reader.close()
            except ImportError:
                logger.warning("zstandard not installed, cannot decompress .zst files")
                logger.warning("Install with: pip install zstandard")
                return
        else:
            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
                data = gz.read()

        root = ET.fromstring(data)
        ns_match = re.match(r"\{([^}]+)\}", root.tag)
        ns_primary = ns_match.group(1) if ns_match else ""

        def q(tag: str) -> str:
            return f"{{{ns_primary}}}{tag}" if ns_primary else tag

        for pkg_elem in root.findall(q("package")):
            if pkg_elem.get("type") and pkg_elem.get("type") != "rpm":
                continue

            name_elem = pkg_elem.find(q("name"))
            arch_elem = pkg_elem.find(q("arch"))
            version_elem = pkg_elem.find(q("version"))
            location_elem = pkg_elem.find(q("location"))

            if name_elem is None or version_elem is None:
                continue

            name = name_elem.text or ""
            arch = arch_elem.text if arch_elem is not None else ""
            epoch = version_elem.get("epoch")
            version = version_elem.get("ver") or ""
            release = version_elem.get("rel") or ""
            location_href = location_elem.get("href") if location_elem is not None else None

            # Extract top-level elements
            summary_elem = pkg_elem.find(q("summary"))
            desc_elem = pkg_elem.find(q("description"))
            url_elem = pkg_elem.find(q("url"))
            packager_elem = pkg_elem.find(q("packager"))

            summary = summary_elem.text if summary_elem is not None else None
            description = desc_elem.text if desc_elem is not None else None
            url = url_elem.text if url_elem is not None else None
            packager = packager_elem.text if packager_elem is not None else None

            # License and vendor are in <format> block
            license_str = None
            vendor = None
            fmt = pkg_elem.find(q("format"))
            if fmt is not None:
                for child in list(fmt):
                    tag = child.tag
                    if tag.endswith("}license") or tag == "license":
                        license_str = child.text
                    elif tag.endswith("}vendor") or tag == "vendor":
                        vendor = child.text

            yield RpmPackageInfo(
                name=name,
                version=version,
                release=release,
                epoch=epoch,
                arch=arch,
                license=license_str,
                location_href=location_href,
                summary=summary,
                description=description,
                url=url,
                vendor=vendor,
                packager=packager,
            )

    except Exception as e:
        logger.warning(f"Failed to fetch primary.xml from {repo_url}: {e}")


def process_rpm_package(
    pkg_info: RpmPackageInfo,
    distro: str,
    distro_version: str,
    repo_url: str,
) -> Optional[PackageMetadata]:
    """Process a single RPM package and extract all metadata."""
    if not pkg_info.license:
        return None

    # Use shared library for normalization
    result = normalize_rpm_license(pkg_info.license)

    if not result.spdx:
        return None

    purl = make_rpm_purl(
        name=pkg_info.name,
        version=pkg_info.version,
        release=pkg_info.release,
        distro=distro,
        distro_version=distro_version,
        arch=pkg_info.arch,
        epoch=pkg_info.epoch,
    )

    # Use summary as description (shorter), fallback to full description
    description = pkg_info.summary or pkg_info.description
    if description:
        description = description.strip()[:500]  # Truncate long descriptions

    # Supplier: prefer vendor, fallback to packager
    supplier = pkg_info.vendor or pkg_info.packager
    maintainer_name, maintainer_email = parse_maintainer(pkg_info.packager)

    # Construct download URL
    download_url = None
    if pkg_info.location_href:
        download_url = urljoin(repo_url, pkg_info.location_href)

    return PackageMetadata(
        purl=purl,
        name=pkg_info.name,
        version=f"{pkg_info.version}-{pkg_info.release}",
        spdx=result.spdx,
        license_raw=result.raw[:500],
        description=description,
        supplier=supplier,
        maintainer_name=maintainer_name,
        maintainer_email=maintainer_email,
        homepage=pkg_info.url,
        download_url=download_url,
        confidence=result.confidence,
        source="rpm_metadata",
    )


# =============================================================================
# Database Generation
# =============================================================================


def generate_alpine_db(
    distro_version: str,
    output_path: Path,
    max_packages: Optional[int] = None,
) -> None:
    """Generate license database for Alpine Linux."""
    logger.info(f"Generating license database for Alpine {distro_version}")

    packages: Dict[str, Dict[str, Any]] = {}
    seen_names: set = set()
    count = 0
    skipped = 0

    for repo in ALPINE_REPOS:
        for pkg_info in fetch_alpine_packages(distro_version, repo):
            if pkg_info.name in seen_names:
                continue

            seen_names.add(pkg_info.name)

            if max_packages and count >= max_packages:
                break

            result = process_alpine_package(pkg_info, distro_version)
            if result:
                packages[result.purl] = {
                    "name": result.name,
                    "version": result.version,
                    "spdx": result.spdx,
                    "license_raw": result.license_raw,
                    "description": result.description,
                    "supplier": result.supplier,
                    "maintainer_name": result.maintainer_name,
                    "maintainer_email": result.maintainer_email,
                    "homepage": result.homepage,
                    "download_url": result.download_url,
                    "confidence": result.confidence,
                    "source": result.source,
                }
                count += 1
                if count % 500 == 0:
                    logger.info(f"Processed {count} packages with valid licenses...")
            else:
                skipped += 1

        if max_packages and count >= max_packages:
            break

    # Get CLE lifecycle data
    lifecycle = DISTRO_LIFECYCLE.get("alpine", {}).get(distro_version, {})

    db = {
        "metadata": asdict(
            DatabaseMetadata(
                distro="alpine",
                version=distro_version,
                codename=None,
                generated_at=datetime.now(timezone.utc).isoformat(),
                package_count=len(packages),
                release_date=lifecycle.get("release_date"),
                end_of_support=lifecycle.get("end_of_support"),
                end_of_life=lifecycle.get("end_of_life"),
            )
        ),
        "packages": packages,
    }

    with gzip.open(output_path, "wt", encoding="utf-8") as f:
        json.dump(db, f, separators=(",", ":"))

    logger.info(f"Wrote {len(packages)} packages to {output_path}")
    logger.info(f"Skipped: {skipped} (license not validated)")
    logger.info(f"Total: {len(seen_names)}, Success rate: {len(packages) / max(len(seen_names), 1) * 100:.1f}%")


def generate_wolfi_db(
    output_path: Path,
    max_packages: Optional[int] = None,
) -> None:
    """Generate license database for Wolfi (Chainguard)."""
    logger.info("Generating license database for Wolfi (rolling release)")

    packages: Dict[str, Dict[str, Any]] = {}
    seen_names: set = set()
    count = 0
    skipped = 0

    for pkg_info in fetch_wolfi_packages():
        if pkg_info.name in seen_names:
            continue

        seen_names.add(pkg_info.name)

        if max_packages and count >= max_packages:
            break

        result = process_wolfi_package(pkg_info)
        if result:
            packages[result.purl] = {
                "name": result.name,
                "version": result.version,
                "spdx": result.spdx,
                "license_raw": result.license_raw,
                "description": result.description,
                "supplier": result.supplier,
                "maintainer_name": result.maintainer_name,
                "maintainer_email": result.maintainer_email,
                "homepage": result.homepage,
                "download_url": result.download_url,
                "confidence": result.confidence,
                "source": result.source,
            }
            count += 1
            if count % 500 == 0:
                logger.info(f"Processed {count} packages with valid licenses...")
        else:
            skipped += 1

    # Get CLE lifecycle data (rolling release - dates may be null)
    lifecycle = DISTRO_LIFECYCLE.get("wolfi", {}).get("rolling", {})

    db = {
        "metadata": asdict(
            DatabaseMetadata(
                distro="wolfi",
                version="rolling",
                codename=None,
                generated_at=datetime.now(timezone.utc).isoformat(),
                package_count=len(packages),
                release_date=lifecycle.get("release_date"),
                end_of_support=lifecycle.get("end_of_support"),
                end_of_life=lifecycle.get("end_of_life"),
            )
        ),
        "packages": packages,
    }

    with gzip.open(output_path, "wt", encoding="utf-8") as f:
        json.dump(db, f, separators=(",", ":"))

    logger.info(f"Wrote {len(packages)} packages to {output_path}")
    logger.info(f"Skipped: {skipped} (license not validated)")
    logger.info(f"Total: {len(seen_names)}, Success rate: {len(packages) / max(len(seen_names), 1) * 100:.1f}%")


def generate_ubuntu_db(
    distro_version: str,
    output_path: Path,
    max_packages: Optional[int] = None,
) -> None:
    """Generate license database for Ubuntu."""
    codename = UBUNTU_CODENAMES.get(distro_version)
    if not codename:
        logger.error(f"Unknown Ubuntu version: {distro_version}")
        sys.exit(1)

    logger.info(f"Generating license database for Ubuntu {distro_version} ({codename})")

    packages: Dict[str, Dict[str, Any]] = {}
    seen_names: set = set()
    count = 0
    skipped = 0

    for component in UBUNTU_COMPONENTS:
        for pocket in UBUNTU_POCKETS:
            for pkg_info in fetch_ubuntu_packages(codename, component, pocket):
                name = pkg_info.get("Package")
                if not name or name in seen_names:
                    continue

                seen_names.add(name)

                if max_packages and count >= max_packages:
                    break

                result = process_ubuntu_package(pkg_info, distro_version, codename)
                if result:
                    packages[result.purl] = {
                        "name": result.name,
                        "version": result.version,
                        "spdx": result.spdx,
                        "license_raw": result.license_raw,
                        "description": result.description,
                        "supplier": result.supplier,
                        "maintainer_name": result.maintainer_name,
                        "maintainer_email": result.maintainer_email,
                        "homepage": result.homepage,
                        "download_url": result.download_url,
                        "confidence": result.confidence,
                        "source": result.source,
                    }
                    count += 1
                    if count % 100 == 0:
                        logger.info(f"Processed {count} packages with valid licenses...")
                else:
                    skipped += 1

            if max_packages and count >= max_packages:
                break
        if max_packages and count >= max_packages:
            break

    # Get CLE lifecycle data
    lifecycle = DISTRO_LIFECYCLE.get("ubuntu", {}).get(distro_version, {})

    db = {
        "metadata": asdict(
            DatabaseMetadata(
                distro="ubuntu",
                version=distro_version,
                codename=codename,
                generated_at=datetime.now(timezone.utc).isoformat(),
                package_count=len(packages),
                release_date=lifecycle.get("release_date"),
                end_of_support=lifecycle.get("end_of_support"),
                end_of_life=lifecycle.get("end_of_life"),
            )
        ),
        "packages": packages,
    }

    with gzip.open(output_path, "wt", encoding="utf-8") as f:
        json.dump(db, f, separators=(",", ":"))

    logger.info(f"Wrote {len(packages)} packages to {output_path}")
    logger.info(f"Skipped: {skipped} (license not validated)")
    logger.info(f"Total: {len(seen_names)}, Success rate: {len(packages) / max(len(seen_names), 1) * 100:.1f}%")


def resolve_mirror_url(mirror_list_url: str) -> Optional[str]:
    """Resolve a mirror.list URL to the actual repository URL.

    Amazon Linux uses mirror.list files that return the actual repo URL with GUID.
    """
    try:
        response = SESSION.get(mirror_list_url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        # mirror.list contains one URL per line, use the first one
        lines = response.text.strip().splitlines()
        if lines:
            repo_url = lines[0].strip()
            # Ensure it ends with /
            if not repo_url.endswith("/"):
                repo_url += "/"
            return repo_url
    except Exception as e:
        logger.warning(f"Failed to resolve mirror list {mirror_list_url}: {e}")
    return None


def generate_rpm_db(
    distro: str,
    distro_version: str,
    output_path: Path,
    max_packages: Optional[int] = None,
) -> None:
    """Generate license database for RPM-based distro."""
    repos = RPM_DISTRO_REPOS.get(distro, {}).get(distro_version)
    if not repos:
        logger.error(f"Unknown distro/version: {distro} {distro_version}")
        sys.exit(1)

    # Resolve any mirror.list URLs
    resolved_repos = []
    for repo_url in repos:
        if repo_url.startswith("mirror:"):
            mirror_list_url = repo_url[7:]  # Remove "mirror:" prefix
            resolved = resolve_mirror_url(mirror_list_url)
            if resolved:
                resolved_repos.append(resolved)
        else:
            resolved_repos.append(repo_url)

    if not resolved_repos:
        logger.error(f"No repositories resolved for {distro} {distro_version}")
        sys.exit(1)

    repos = resolved_repos

    logger.info(f"Generating license database for {distro} {distro_version}")

    packages: Dict[str, Dict[str, Any]] = {}
    seen_names: set = set()
    count = 0
    skipped = 0

    for repo_url in repos:
        for pkg_info in fetch_rpm_packages(repo_url):
            if pkg_info.name in seen_names:
                continue

            seen_names.add(pkg_info.name)

            if max_packages and count >= max_packages:
                break

            result = process_rpm_package(pkg_info, distro, distro_version, repo_url)
            if result:
                packages[result.purl] = {
                    "name": result.name,
                    "version": result.version,
                    "spdx": result.spdx,
                    "license_raw": result.license_raw,
                    "description": result.description,
                    "supplier": result.supplier,
                    "maintainer_name": result.maintainer_name,
                    "maintainer_email": result.maintainer_email,
                    "homepage": result.homepage,
                    "download_url": result.download_url,
                    "confidence": result.confidence,
                    "source": result.source,
                }
                count += 1
                if count % 500 == 0:
                    logger.info(f"Processed {count} packages with valid licenses...")
            else:
                skipped += 1

        if max_packages and count >= max_packages:
            break

    # Get CLE lifecycle data
    lifecycle = DISTRO_LIFECYCLE.get(distro, {}).get(distro_version, {})

    db = {
        "metadata": asdict(
            DatabaseMetadata(
                distro=distro,
                version=distro_version,
                codename=None,
                generated_at=datetime.now(timezone.utc).isoformat(),
                package_count=len(packages),
                release_date=lifecycle.get("release_date"),
                end_of_support=lifecycle.get("end_of_support"),
                end_of_life=lifecycle.get("end_of_life"),
            )
        ),
        "packages": packages,
    }

    with gzip.open(output_path, "wt", encoding="utf-8") as f:
        json.dump(db, f, separators=(",", ":"))

    logger.info(f"Wrote {len(packages)} packages to {output_path}")
    logger.info(f"Skipped: {skipped} (license not validated)")
    logger.info(f"Total: {len(seen_names)}, Success rate: {len(packages) / max(len(seen_names), 1) * 100:.1f}%")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main() -> None:
    """CLI entry point for license database generation."""
    parser = argparse.ArgumentParser(
        prog="sbomify-license-db",
        description="Generate license database for Linux distro packages",
    )
    parser.add_argument(
        "--distro",
        required=True,
        choices=["alpine", "amazonlinux", "centos", "ubuntu", "rocky", "almalinux", "fedora", "wolfi"],
        help="Distribution name",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Distribution version (e.g., 24.04, 9, 41)",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output file path (will be gzipped JSON)",
    )
    parser.add_argument(
        "--max-packages",
        type=int,
        default=None,
        help="Maximum number of packages to process (for testing)",
    )

    args = parser.parse_args()

    output_path = args.output
    if not str(output_path).endswith(".gz"):
        output_path = Path(str(output_path) + ".gz")

    if args.distro == "alpine":
        generate_alpine_db(args.version, output_path, args.max_packages)
    elif args.distro == "wolfi":
        # Wolfi is rolling release, version is ignored
        generate_wolfi_db(output_path, args.max_packages)
    elif args.distro == "ubuntu":
        generate_ubuntu_db(args.version, output_path, args.max_packages)
    else:
        generate_rpm_db(args.distro, args.version, output_path, args.max_packages)


if __name__ == "__main__":
    main()
