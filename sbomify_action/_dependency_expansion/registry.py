"""Registry for dependency expanders."""

from pathlib import Path

from ..logging_config import logger
from .models import DiscoveredDependency
from .protocol import DependencyExpander


class ExpanderRegistry:
    """Registry for dependency expanders.

    Manages expander instances and selects the appropriate expander
    based on lockfile type and priority.

    Example:
        registry = ExpanderRegistry()
        registry.register(PipdeptreeExpander())

        expander = registry.get_expander_for(Path("requirements.txt"))
        if expander and expander.can_expand():
            deps = expander.expand(Path("requirements.txt"))
    """

    def __init__(self) -> None:
        self._expanders: list[DependencyExpander] = []

    def register(self, expander: DependencyExpander) -> None:
        """Register an expander.

        Args:
            expander: Expander instance implementing DependencyExpander protocol.
        """
        self._expanders.append(expander)
        logger.debug(f"Registered dependency expander: {expander.name} (priority {expander.priority})")

    def get_expander_for(self, lock_file: Path) -> DependencyExpander | None:
        """Get the best expander for this lockfile.

        Selects the expander with lowest priority that supports
        the lockfile.

        Args:
            lock_file: Path to the lockfile

        Returns:
            Expander instance if found, None otherwise.
        """
        candidates = [e for e in self._expanders if e.supports(lock_file)]

        if not candidates:
            return None

        # Sort by priority (lowest first)
        candidates.sort(key=lambda e: e.priority)
        return candidates[0]

    def expand_lockfile(self, lock_file: Path) -> list[DiscoveredDependency]:
        """Expand a lockfile using the appropriate expander.

        Args:
            lock_file: Path to the lockfile

        Returns:
            List of discovered dependencies. Empty list if no expander
            found or expansion not possible.
        """
        expander = self.get_expander_for(lock_file)

        if expander is None:
            logger.debug(f"No dependency expander found for: {lock_file.name}")
            return []

        if not expander.can_expand():
            logger.debug(f"Expander {expander.name} cannot expand (prerequisites not met)")
            return []

        logger.debug(f"Using {expander.name} to expand {lock_file.name}")
        try:
            dependencies = expander.expand(lock_file)
            logger.debug(f"Discovered {len(dependencies)} transitive dependencies")
            return dependencies
        except Exception as e:
            logger.warning(f"Failed to expand {lock_file.name}: {e}", exc_info=True)
            return []

    @property
    def registered_expanders(self) -> list[str]:
        """Get names of all registered expanders."""
        return [e.name for e in self._expanders]
