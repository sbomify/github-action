"""Data models for dependency expansion."""

from dataclasses import dataclass


@dataclass
class DiscoveredDependency:
    """Represents a discovered transitive dependency.

    Attributes:
        name: Package name as reported by pipdeptree
        version: Installed version
        purl: Package URL (e.g., pkg:pypi/requests@2.31.0)
        parent: Name of the package that required this dependency
        depth: How many levels from a direct dependency (1 = direct transitive)
        ecosystem: Package ecosystem identifier (default: pypi)
    """

    name: str
    version: str
    purl: str
    parent: str | None = None
    depth: int = 1
    ecosystem: str = "pypi"


@dataclass
class ExpansionResult:
    """Result of dependency expansion.

    Attributes:
        original_count: Number of components in SBOM before expansion
        discovered_count: Total transitive dependencies discovered
        added_count: Number actually added (excluding duplicates)
        dependencies: List of discovered dependencies
        source: Tool that discovered the dependencies (e.g., "pipdeptree")
    """

    original_count: int
    discovered_count: int
    added_count: int
    dependencies: list[DiscoveredDependency]
    source: str


def normalize_python_package_name(name: str) -> str:
    """Normalize Python package name per PEP 503.

    PEP 503: Package names are case-insensitive and treat
    hyphens, underscores, and dots as equivalent.

    Args:
        name: Package name to normalize

    Returns:
        Normalized lowercase name with underscores
    """
    return name.lower().replace("-", "_").replace(".", "_")
