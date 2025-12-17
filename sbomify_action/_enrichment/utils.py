"""Shared utilities for enrichment sources."""

from typing import Optional, Tuple

from packageurl import PackageURL


def get_qualified_name(purl: PackageURL, separator: str = ":") -> str:
    """
    Get the fully qualified package name for APIs that need namespace.

    For packages with namespaces (like Maven's group:artifact), this combines
    the namespace and name with the specified separator.

    Args:
        purl: Parsed PackageURL
        separator: Character to join namespace and name (default ":")
                   - Use ":" for deps.dev (Maven)
                   - Use "/" for ClearlyDefined

    Returns:
        Qualified name string, e.g. "org.apache.commons:commons-lang3"
    """
    if purl.namespace:
        return f"{purl.namespace}{separator}{purl.name}"
    return purl.name


def parse_author_string(author_str: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse an author string which may be in format "Name <email>".

    This is a common format used by pub.dev (Dart), npm, and other package managers.

    Args:
        author_str: Author string like "John Doe <john@example.com>" or just "John Doe"

    Returns:
        Tuple of (name, email) where either may be None
    """
    if not author_str:
        return None, None

    author_str = author_str.strip()

    # Check for "Name <email>" format
    if "<" in author_str and ">" in author_str:
        try:
            lt_idx = author_str.index("<")
            gt_idx = author_str.index(">")
            if lt_idx < gt_idx:
                name_part = author_str[:lt_idx].strip()
                email_part = author_str[lt_idx + 1 : gt_idx].strip()
                return name_part or None, email_part or None
        except (ValueError, IndexError):
            pass

    # Just a name (no email)
    return author_str, None
