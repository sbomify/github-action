"""Utility functions for augmentation providers."""

import os
from typing import Optional


def is_vcs_augmentation_disabled() -> bool:
    """
    Check if VCS augmentation is disabled via environment variable.

    Set DISABLE_VCS_AUGMENTATION=true to disable all VCS enrichment
    from CI providers and sbomify.json config.

    Returns:
        True if VCS augmentation should be disabled, False otherwise
    """
    return os.getenv("DISABLE_VCS_AUGMENTATION", "").lower() in ("true", "1", "yes")


def build_vcs_url_with_commit(vcs_url: str, commit_sha: Optional[str]) -> str:
    """
    Build a VCS URL with commit pinning in git+ format.

    This creates URLs compatible with both CycloneDX and SPDX specs:
    - git+https://github.com/owner/repo@abc123def456

    Args:
        vcs_url: Base repository URL (e.g., https://github.com/owner/repo)
        commit_sha: Full commit SHA to pin, or None for unpinned URL

    Returns:
        VCS URL with commit pinning if SHA provided, otherwise the
        URL normalized to git+ format
    """
    if not commit_sha:
        # Just normalize to git+ format if no commit
        if vcs_url.startswith("https://"):
            return f"git+{vcs_url}"
        return vcs_url

    # Build URL with commit pinning
    if vcs_url.startswith("https://"):
        return f"git+{vcs_url}@{commit_sha}"
    elif vcs_url.startswith("git+"):
        return f"{vcs_url}@{commit_sha}"
    else:
        return f"{vcs_url}@{commit_sha}"
