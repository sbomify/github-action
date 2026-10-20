"""Hashes for PlatformIO libraries, from the PlatformIO registry."""

from pathlib import Path

import requests

from sbomify_action._platformio import InstalledLibrary, installed_libraries
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

from ..models import HashAlgorithm, PackageHash

REGISTRY_API = "https://api.registry.platformio.org/v3/packages"
DEFAULT_TIMEOUT = 10  # seconds


def _registry_versions(version: str) -> list[str]:
    """The installed version, then the forms the registry may hold it under.

    PlatformIO normalises versions to full semver when it installs, so a
    release published as `2.8` is recorded in `.piopm` as `2.8.0` -- and the
    registry answers only to `2.8`.
    """
    candidates = [version]
    trimmed = version
    while trimmed.endswith(".0") and trimmed.count(".") > 1:
        trimmed = trimmed[: -len(".0")]
        candidates.append(trimmed)
    return candidates


def _fetch_sha256(library: InstalledLibrary) -> str | None:
    for version in _registry_versions(library.version):
        url = f"{REGISTRY_API}/{library.owner}/library/{library.name}"
        try:
            response = requests.get(
                url, params={"version": version}, headers=get_default_headers(), timeout=DEFAULT_TIMEOUT
            )
        except requests.RequestException as e:
            logger.debug(f"PlatformIO registry: {library.owner}/{library.name}: {e}")
            return None
        if response.status_code != 200:
            continue
        try:
            release = response.json().get("version") or {}
        except ValueError:
            return None
        if release.get("name") != version:
            continue
        for artifact in release.get("files") or []:
            sha256 = (artifact.get("checksum") or {}).get("sha256")
            if sha256:
                return str(sha256)
    return None


class PlatformIOParser:
    """SHA-256 of each registry library's published archive.

    PlatformIO records no hash at install time, but the registry publishes
    one for every release: the checksum of the archive `pio pkg install`
    downloads. That is the same thing Cargo.lock or package-lock.json records.

    Libraries installed from git get no hash here. Their commit, which pins
    the source exactly, is already in the component's purl.
    """

    name = "platformio"
    supported_files = ("platformio.ini",)
    ecosystem = "platformio"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        hashes: list[PackageHash] = []
        for library in installed_libraries(lock_file_path):
            if not library.from_registry:
                continue
            sha256 = _fetch_sha256(library)
            if sha256:
                hashes.append(
                    PackageHash(
                        name=library.name,
                        version=library.version,
                        algorithm=HashAlgorithm.SHA256,
                        value=sha256,
                        artifact_type="tarball",
                    )
                )
        return hashes
