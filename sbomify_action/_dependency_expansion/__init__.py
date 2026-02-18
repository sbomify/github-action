"""Transitive dependency expansion for SBOMs.

This module provides functionality to discover transitive dependencies
that are missing from lockfiles (particularly requirements.txt) and
add them to SBOMs. It uses ecosystem-specific tools like pipdeptree
to inspect installed packages.

Supported lockfiles:
- Python: requirements.txt (using pipdeptree)

Example usage:
    from sbomify_action._dependency_expansion import expand_sbom_dependencies

    result = expand_sbom_dependencies(
        sbom_file="sbom.json",
        lock_file="requirements.txt",
    )
    print(f"Added {result.added_count} transitive dependencies")

Note:
    For pipdeptree to work, packages from requirements.txt must be
    installed in the current Python environment. If packages are not
    installed, expansion is skipped gracefully.
"""

from .enricher import (
    DependencyEnricher,
    create_default_registry,
    expand_sbom_dependencies,
    supports_dependency_expansion,
)
from .models import DiscoveredDependency, ExpansionResult, normalize_python_package_name
from .protocol import DependencyExpander
from .registry import ExpanderRegistry

__all__ = [
    # Main API
    "expand_sbom_dependencies",
    "supports_dependency_expansion",
    # Classes for advanced usage
    "DependencyEnricher",
    "ExpanderRegistry",
    "DependencyExpander",
    # Models
    "DiscoveredDependency",
    "ExpansionResult",
    "normalize_python_package_name",
    # Factory
    "create_default_registry",
]
