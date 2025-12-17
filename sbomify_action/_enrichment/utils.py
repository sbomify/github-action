"""Shared utilities for enrichment sources."""

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
