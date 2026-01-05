"""Input sanitization utilities for enrichment data.

This module provides sanitization functions to protect against injection attacks
when using data from external package registries.

Security considerations:
- URLs: Allow http/https and SPDX VCS schemes (git, git+ssh, git+https, git+http), validate format
- Strings: Remove control characters, enforce length limits
- Emails: Basic format validation
"""

import re
from typing import Optional
from urllib.parse import urlparse

from sbomify_action.logging_config import logger

# Maximum lengths for various fields
MAX_DESCRIPTION_LENGTH = 4096
MAX_SUPPLIER_LENGTH = 256
MAX_URL_LENGTH = 2048
MAX_LICENSE_LENGTH = 512
MAX_EMAIL_LENGTH = 254

# Allowed URL schemes
# Includes SPDX VCS URL schemes: git, git+ssh, git+https, git+http
# See: https://spdx.github.io/spdx-spec/v2.3/package-information/
ALLOWED_URL_SCHEMES = {"http", "https", "git", "git+ssh", "git+https", "git+http"}

# Control characters to remove (except newline/tab in descriptions)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Pattern for basic email validation
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# Pattern to detect HTML-like content in URLs (potential XSS vectors)
HTML_PATTERN = re.compile(r"<[a-zA-Z][^>]*>", re.IGNORECASE)

# Pattern for SSH-style git URLs: git@host:path
_SSH_GIT_PATTERN = re.compile(r"^git@([^:]+):(.+)$")

# Pattern for Maven SCM URLs: scm:git:...
_SCM_GIT_PATTERN = re.compile(r"^scm:git:(.+)$", re.IGNORECASE)

# Known git hosting providers - we can safely assume URLs from these are git repos
_KNOWN_GIT_HOSTS = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "sr.ht",
        "git.sr.ht",
        "gitea.com",
        "gitee.com",
        "salsa.debian.org",  # Debian's GitLab
        "gitlab.gnome.org",
        "gitlab.freedesktop.org",
        "git.kernel.org",
        "git.savannah.gnu.org",
        "git.savannah.nongnu.org",
    }
)


def sanitize_string(
    value: Optional[str],
    max_length: int = MAX_DESCRIPTION_LENGTH,
    allow_newlines: bool = True,
    field_name: str = "field",
) -> Optional[str]:
    """
    Sanitize a string value from external sources.

    Removes control characters, enforces length limits, and normalizes whitespace.

    Args:
        value: The string to sanitize
        max_length: Maximum allowed length
        allow_newlines: Whether to preserve newlines (for descriptions)
        field_name: Name of field for logging

    Returns:
        Sanitized string or None if input was None/empty
    """
    if value is None:
        return None

    if not isinstance(value, str):
        logger.warning(f"Non-string value for {field_name}: {type(value)}")
        value = str(value)

    # Remove control characters
    sanitized = CONTROL_CHAR_PATTERN.sub("", value)

    # Optionally remove newlines
    if not allow_newlines:
        sanitized = sanitized.replace("\n", " ").replace("\r", " ")

    # Normalize whitespace (collapse multiple spaces)
    sanitized = " ".join(sanitized.split()) if not allow_newlines else sanitized

    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()

    # Enforce length limit
    if len(sanitized) > max_length:
        logger.debug(f"Truncating {field_name} from {len(sanitized)} to {max_length} chars")
        # Reserve space for ellipsis so the final length does not exceed max_length
        if max_length > 3:
            truncation_limit = max_length - 3
            base = sanitized[:truncation_limit]

            # Try not to cut a word in half if there is a space to break on
            last_space = base.rfind(" ")
            if last_space > 0:
                base = base[:last_space]

            sanitized = base.rstrip() + "..."
        else:
            # For very small max_length, just hard-truncate without ellipsis
            sanitized = sanitized[:max_length]

    return sanitized if sanitized else None


def sanitize_url(value: Optional[str], field_name: str = "url") -> Optional[str]:
    """
    Sanitize and validate a URL from external sources.

    Allows http/https URLs and SPDX VCS URL schemes (git, git+ssh, git+https, git+http).
    Validates format and enforces length limits.

    Args:
        value: The URL to sanitize
        field_name: Name of field for logging

    Returns:
        Sanitized URL or None if invalid/empty
    """
    if value is None:
        return None

    if not isinstance(value, str):
        logger.warning(f"Non-string URL for {field_name}: {type(value)}")
        return None

    # Strip whitespace
    url = value.strip()

    if not url:
        return None

    # Enforce length limit
    if len(url) > MAX_URL_LENGTH:
        logger.warning(f"URL too long for {field_name}: {len(url)} chars")
        return None

    # Parse and validate URL
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
            logger.warning(f"Disallowed URL scheme for {field_name}: '{parsed.scheme}' in URL: {url[:200]}")
            return None

        # Must have a netloc (host)
        if not parsed.netloc:
            logger.warning(f"Invalid URL (no host) for {field_name}: {url[:100]}")
            return None

        # Reject URLs with HTML-like content (potential XSS vectors)
        if HTML_PATTERN.search(url):
            logger.warning(f"URL contains HTML-like content for {field_name}")
            return None

        # Reconstruct URL to normalize it
        # This also helps prevent some injection attempts
        return url

    except Exception as e:
        logger.warning(f"Failed to parse URL for {field_name}: {e}")
        return None


def sanitize_email(value: Optional[str], field_name: str = "email") -> Optional[str]:
    """
    Sanitize and validate an email address.

    Args:
        value: The email to sanitize
        field_name: Name of field for logging

    Returns:
        Sanitized email or None if invalid/empty
    """
    if value is None:
        return None

    if not isinstance(value, str):
        return None

    email = value.strip()

    if not email:
        return None

    # Enforce length limit
    if len(email) > MAX_EMAIL_LENGTH:
        logger.warning(f"Email too long for {field_name}: {len(email)} chars")
        return None

    # Basic format validation
    if not EMAIL_PATTERN.match(email):
        # Don't log the actual email for privacy
        logger.debug(f"Invalid email format for {field_name}")
        return None

    return email


def sanitize_description(value: Optional[str]) -> Optional[str]:
    """Sanitize a description field (allows newlines)."""
    return sanitize_string(value, MAX_DESCRIPTION_LENGTH, allow_newlines=True, field_name="description")


def sanitize_supplier(value: Optional[str]) -> Optional[str]:
    """Sanitize a supplier/vendor field."""
    return sanitize_string(value, MAX_SUPPLIER_LENGTH, allow_newlines=False, field_name="supplier")


def sanitize_license(value: Optional[str]) -> Optional[str]:
    """Sanitize a license string."""
    return sanitize_string(value, MAX_LICENSE_LENGTH, allow_newlines=False, field_name="license")


def _is_known_git_host(url: str) -> bool:
    """Check if URL is from a known git hosting provider."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        # Handle www. prefix
        if host.startswith("www."):
            host = host[4:]
        return host in _KNOWN_GIT_HOSTS
    except Exception:
        return False


def normalize_vcs_url(url: str) -> str:
    """
    Normalize VCS URLs to SPDX-standard format.

    Normalizes URLs that are explicitly git-related or from known git hosts:
    - scm:git:... -> strips prefix, normalizes inner URL
    - git@host:path -> git+https://host/path
    - git://host/path -> git+https://host/path
    - https://github.com/... (known git hosts) -> git+https://...

    Plain https:// URLs from unknown domains are NOT modified since we can't
    assume they are git repositories (could be Mercurial, SVN, or just a website).

    Args:
        url: The URL to normalize

    Returns:
        Normalized URL in SPDX VCS format, or original if no normalization needed
    """
    if not url:
        return url

    original_url = url
    had_scm_prefix = False

    # Step 1: Strip Maven SCM prefix if present
    scm_match = _SCM_GIT_PATTERN.match(url)
    if scm_match:
        url = scm_match.group(1)
        had_scm_prefix = True

    # Step 2: Handle SSH shorthand (git@host:path) -> git+https://host/path
    ssh_match = _SSH_GIT_PATTERN.match(url)
    if ssh_match:
        host = ssh_match.group(1)
        path = ssh_match.group(2)
        normalized = f"git+https://{host}/{path}"
        logger.info(f"Normalized VCS URL: {original_url} -> {normalized}")
        return normalized

    # Step 3: git:// is already a valid SPDX VCS URL scheme - leave it as-is
    # (git:// is the git protocol on port 9418, NOT https)
    if url.startswith("git://"):
        # Only log if we stripped an scm: prefix
        if original_url != url:
            logger.info(f"Normalized VCS URL: {original_url} -> {url}")
        return url

    # Step 4: Add git+ prefix if we KNOW it's git:
    # - Had scm:git: prefix, OR
    # - URL is from a known git hosting provider
    is_known_git = had_scm_prefix or _is_known_git_host(url)

    if is_known_git:
        if url.startswith("https://"):
            normalized = f"git+{url}"
            if original_url != normalized:
                logger.info(f"Normalized VCS URL: {original_url} -> {normalized}")
            return normalized
        elif url.startswith("http://"):
            normalized = f"git+{url}"
            if original_url != normalized:
                logger.info(f"Normalized VCS URL: {original_url} -> {normalized}")
            return normalized

    # No normalization needed - return URL as-is
    return url
