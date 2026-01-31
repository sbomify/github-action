"""Input validation functions for the sbomify.json wizard."""

import re
from datetime import datetime
from urllib.parse import urlparse

from license_expression import ExpressionError, get_spdx_licensing

# SPDX licensing instance for validation
_spdx_licensing = get_spdx_licensing()

# Valid CISA 2025 lifecycle phases
LIFECYCLE_PHASES = [
    "design",
    "pre-build",
    "build",
    "post-build",
    "operations",
    "discovery",
    "decommission",
]


def validate_email(email: str) -> bool:
    """Validate email format.

    Args:
        email: Email address to validate

    Returns:
        True if valid email format, False otherwise
    """
    if not email:
        return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def validate_url(url: str) -> bool:
    """Validate URL format.

    Args:
        url: URL to validate

    Returns:
        True if valid HTTP/HTTPS URL, False otherwise
    """
    if not url:
        return False
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def validate_security_contact(value: str) -> bool:
    """Validate security contact format.

    Accepts:
    - mailto: URI (e.g., mailto:security@example.com)
    - tel: URI (e.g., tel:+1-555-123-4567)
    - HTTP/HTTPS URL (e.g., https://example.com/.well-known/security.txt)

    Args:
        value: Security contact value to validate

    Returns:
        True if valid format, False otherwise
    """
    if not value:
        return False

    if value.startswith("mailto:"):
        return validate_email(value[7:])
    if value.startswith("tel:"):
        return len(value) > 4  # At least "tel:" + something
    return validate_url(value)


def validate_iso_date(date_str: str) -> bool:
    """Validate ISO-8601 YYYY-MM-DD date format.

    Args:
        date_str: Date string to validate

    Returns:
        True if valid ISO date, False otherwise
    """
    if not date_str:
        return False
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def validate_license(license_str: str) -> bool:
    """Validate SPDX license expression.

    Args:
        license_str: SPDX license ID or expression to validate

    Returns:
        True if valid SPDX license, False otherwise
    """
    if not license_str:
        return False
    try:
        _spdx_licensing.parse(license_str, validate=True)
        return True
    except ExpressionError:
        return False


def validate_lifecycle_phase(phase: str) -> bool:
    """Validate CISA 2025 lifecycle phase.

    Args:
        phase: Lifecycle phase to validate

    Returns:
        True if valid phase, False otherwise
    """
    if not phase:
        return False
    return phase.lower() in LIFECYCLE_PHASES
