"""deps.dev data source for package metadata (Google Open Source Insights)."""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from packageurl import PackageURL

from sbomify_action.logging_config import logger

from ..metadata import NormalizedMetadata
from ..utils import get_qualified_name

DEPSDEV_API_BASE = "https://api.deps.dev/v3"
DEFAULT_TIMEOUT = 10  # seconds - deps.dev is generally fast

# Mapping from PURL type to deps.dev system name
PURL_TYPE_TO_SYSTEM: Dict[str, str] = {
    "pypi": "PYPI",
    "npm": "NPM",
    "cargo": "CARGO",
    "maven": "MAVEN",
    "golang": "GO",
    "gem": "RUBYGEMS",
    "nuget": "NUGET",
}

# Simple in-memory cache
_cache: Dict[str, Optional[NormalizedMetadata]] = {}

# Pattern for SSH-style git URLs: git@host:path
_SSH_GIT_PATTERN = re.compile(r"^git@([^:]+):(.+)$")

# Pattern for Maven SCM URLs: scm:git:...
_SCM_GIT_PATTERN = re.compile(r"^scm:git:(.+)$", re.IGNORECASE)


def _normalize_vcs_url(url: str) -> str:
    """
    Normalize VCS URLs to SPDX-standard format.

    Converts Maven SCM URLs and SSH shorthand to SPDX VCS URL schemes:
    - scm:git:git@host:path -> git+ssh://git@host/path
    - scm:git:git://host/path -> git://host/path
    - scm:git:https://host/path -> git+https://host/path
    - git@host:path -> git+ssh://git@host/path
    - git://host/path -> unchanged (already valid)

    Args:
        url: The URL to normalize

    Returns:
        Normalized URL in SPDX VCS format, or original if no normalization needed
    """
    if not url:
        return url

    original_url = url

    # Step 1: Strip Maven SCM prefix if present
    scm_match = _SCM_GIT_PATTERN.match(url)
    if scm_match:
        url = scm_match.group(1)

    # Step 2: Handle SSH shorthand (git@host:path)
    ssh_match = _SSH_GIT_PATTERN.match(url)
    if ssh_match:
        host = ssh_match.group(1)
        path = ssh_match.group(2)
        normalized = f"git+ssh://git@{host}/{path}"
        logger.info(f"Normalized VCS URL: {original_url} -> {normalized}")
        return normalized

    # Step 3: Handle git:// protocol (already valid, but if it came from scm:git:, log it)
    if url.startswith("git://"):
        if original_url != url:
            logger.info(f"Normalized VCS URL: {original_url} -> {url}")
        return url

    # Step 4: Handle https:// or http:// from SCM prefix -> convert to git+https:// or git+http://
    if scm_match:
        if url.startswith("https://"):
            normalized = f"git+{url}"
            logger.info(f"Normalized VCS URL: {original_url} -> {normalized}")
            return normalized
        elif url.startswith("http://"):
            normalized = f"git+{url}"
            logger.info(f"Normalized VCS URL: {original_url} -> {normalized}")
            return normalized

    # No normalization needed
    return url


def clear_cache() -> None:
    """Clear the deps.dev metadata cache."""
    _cache.clear()


class DepsDevSource:
    """
    Data source for deps.dev (Google Open Source Insights) API.

    deps.dev provides package metadata including licenses, links, and
    security advisories for many package ecosystems.

    Priority: 40 (medium-high - reliable Google-backed source)
    Supports: pypi, npm, cargo, maven, golang, gem, nuget packages
    """

    @property
    def name(self) -> str:
        return "deps.dev"

    @property
    def priority(self) -> int:
        # Tier 2: Primary aggregators (40-49) - High-quality aggregated data
        return 40

    def supports(self, purl: PackageURL) -> bool:
        """Check if this source supports the given PURL type."""
        return purl.type in PURL_TYPE_TO_SYSTEM

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        """
        Fetch metadata from deps.dev API.

        Args:
            purl: Parsed PackageURL
            session: requests.Session with configured headers

        Returns:
            NormalizedMetadata if successful, None otherwise
        """
        system = PURL_TYPE_TO_SYSTEM.get(purl.type)
        if not system:
            return None

        # Build cache key and package name using shared utility
        # Different package types use different separators:
        # - Maven uses ":" (group:artifact)
        # - npm uses "/" (@scope/name)
        # - Go uses "/" (namespace/name)
        version = purl.version or ""
        separator = ":" if purl.type == "maven" else "/"
        package_name = get_qualified_name(purl, separator=separator)
        cache_key = f"depsdev:{purl.type}:{package_name}:{version}"

        # Check cache
        if cache_key in _cache:
            logger.debug(f"Cache hit (deps.dev): {package_name}")
            return _cache[cache_key]

        try:
            # URL encode the package name
            encoded_name = quote(package_name, safe="")

            if version:
                # Get specific version info
                encoded_version = quote(version, safe="")
                url = f"{DEPSDEV_API_BASE}/systems/{system}/packages/{encoded_name}/versions/{encoded_version}"
            else:
                # Get package info (default version)
                url = f"{DEPSDEV_API_BASE}/systems/{system}/packages/{encoded_name}"

            logger.debug(f"Fetching deps.dev metadata for: {purl}")
            response = session.get(url, timeout=DEFAULT_TIMEOUT)

            metadata = None
            if response.status_code == 200:
                data = response.json()
                metadata = self._normalize_response(purl.name, data)
            elif response.status_code == 404:
                logger.debug(f"Package not found in deps.dev: {purl}")
            else:
                logger.warning(f"Failed to fetch deps.dev metadata for {purl}: HTTP {response.status_code}")

            # Cache result
            _cache[cache_key] = metadata
            return metadata

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching deps.dev metadata for {purl}")
            _cache[cache_key] = None
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error fetching deps.dev metadata for {purl}: {e}")
            _cache[cache_key] = None
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error for deps.dev {purl}: {e}")
            _cache[cache_key] = None
            return None

    def _normalize_response(self, package_name: str, data: Dict[str, Any]) -> Optional[NormalizedMetadata]:
        """
        Normalize deps.dev API response to NormalizedMetadata.

        Args:
            package_name: Name of the package
            data: Raw deps.dev API response

        Returns:
            NormalizedMetadata with extracted fields, or None if no data
        """
        if not data:
            return None

        # Extract licenses
        licenses: List[str] = data.get("licenses", [])

        # Extract links
        homepage = None
        repository_url = None
        links = data.get("links", [])
        for link in links:
            label = link.get("label", "").lower()
            url = link.get("url", "")
            if "homepage" in label or "home" in label:
                homepage = url
            elif "source" in label or "repository" in label or "repo" in label:
                repository_url = url

        # Extract related projects for repository URL
        if not repository_url:
            related_projects = data.get("relatedProjects", [])
            for project in related_projects:
                project_key = project.get("projectKey", {})
                project_id = project_key.get("id", "")
                if project_id:
                    # Convert project ID to URL
                    if project_id.startswith("github.com/"):
                        repository_url = f"https://{project_id}"
                        break
                    elif project_id.startswith("gitlab.com/"):
                        repository_url = f"https://{project_id}"
                        break

        # Normalize repository URL to SPDX VCS standard format
        if repository_url:
            repository_url = _normalize_vcs_url(repository_url)

        # Build field_sources for attribution
        field_sources = {}
        if licenses:
            field_sources["licenses"] = self.name
        if homepage:
            field_sources["homepage"] = self.name
        if repository_url:
            field_sources["repository_url"] = self.name

        metadata = NormalizedMetadata(
            licenses=licenses,
            homepage=homepage,
            repository_url=repository_url,
            source=self.name,
            field_sources=field_sources,
        )

        if metadata.has_data():
            logger.debug(f"Successfully normalized deps.dev metadata for {package_name}")
            return metadata
        return None
