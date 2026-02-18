"""Protocol definition for dependency expanders."""

from pathlib import Path
from typing import Protocol

from .models import DiscoveredDependency


class DependencyExpander(Protocol):
    """Protocol for dependency expansion plugins.

    Each expander implements this protocol to discover transitive
    dependencies using ecosystem-specific tools. Expanders are
    registered with ExpanderRegistry and selected based on the
    lockfile type.

    Example:
        class PipdeptreeExpander:
            name = "pipdeptree"
            priority = 10
            ecosystems = ["pypi"]

            def supports(self, lock_file: Path) -> bool:
                return lock_file.name == "requirements.txt"

            def can_expand(self) -> bool:
                # Check if packages are installed
                ...

            def expand(self, lock_file: Path) -> list[DiscoveredDependency]:
                # Discover transitive dependencies
                ...
    """

    @property
    def name(self) -> str:
        """Human-readable name of this expander.

        Used for logging and audit trail source identification.
        Examples: "pipdeptree"
        """
        ...

    @property
    def priority(self) -> int:
        """Priority for expander selection (lower = higher priority).

        When multiple expanders support a lockfile, the one with
        lowest priority value is chosen.
        """
        ...

    @property
    def ecosystems(self) -> list[str]:
        """Package ecosystems this expander supports.

        Examples: ["pypi"], ["npm"]
        """
        ...

    def supports(self, lock_file: Path) -> bool:
        """Check if this expander supports the given lockfile.

        Args:
            lock_file: Path to the lockfile

        Returns:
            True if this expander can process the lockfile.
        """
        ...

    def can_expand(self) -> bool:
        """Check if expansion is possible in the current environment.

        This checks prerequisites like:
        - Required tool is installed
        - Packages from lockfile are installed in environment

        Returns:
            True if expand() can be called successfully.
        """
        ...

    def expand(self, lock_file: Path) -> list[DiscoveredDependency]:
        """Discover transitive dependencies.

        Implementations should:
        1. Parse the lockfile to identify direct dependencies
        2. Use ecosystem tooling to discover transitive dependencies
        3. Return dependencies NOT in the original lockfile

        Args:
            lock_file: Path to the lockfile

        Returns:
            List of discovered transitive dependencies.
            Empty list if none found or expansion not possible.
        """
        ...
