"""Source registry for managing augmentation source plugins."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from sbomify_action.logging_config import logger

from .data import AugmentationData
from .protocol import AugmentationSource


class AugmentationSourceRegistry:
    """
    Registry for managing and querying augmentation source plugins.

    The registry maintains a list of sources and provides methods
    to find applicable sources, sorted by priority (lower = higher priority).

    Example:
        registry = AugmentationSourceRegistry()
        registry.register(SbomifyAPISource())
        registry.register(LocalJSONSource())
        registry.register(PyProjectSource())

        # Get sources that can provide data
        sources = registry.get_sources_for(working_dir, config)

        # Fetch and merge metadata from all sources
        data = registry.fetch_metadata(working_dir, config)
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._sources: List[AugmentationSource] = []

    def register(self, source: AugmentationSource) -> None:
        """
        Register an augmentation source.

        Sources are stored and later sorted by priority when queried.

        Args:
            source: AugmentationSource implementation to register
        """
        self._sources.append(source)
        logger.debug(f"Registered augmentation source: {source.name} (priority={source.priority})")

    def get_sources_for(self, working_dir: Path, config: dict) -> List[AugmentationSource]:
        """
        Get all applicable sources for the given context, sorted by priority.

        Args:
            working_dir: Working directory (project root)
            config: Configuration dict

        Returns:
            List of AugmentationSource instances that support this context,
            sorted by priority (lowest/highest priority first)
        """
        applicable = [s for s in self._sources if s.supports(working_dir, config)]
        return sorted(applicable, key=lambda s: s.priority)

    def fetch_metadata(
        self,
        working_dir: Path,
        config: dict,
        merge_results: bool = True,
    ) -> Optional[AugmentationData]:
        """
        Fetch metadata using the priority chain of sources.

        Tries sources in priority order. When merge_results is True,
        data from multiple sources is merged (lower priority wins on conflicts).
        When False, stops at the first source that returns data.

        Args:
            working_dir: Working directory (project root)
            config: Configuration dict
            merge_results: If True, merge results from multiple sources

        Returns:
            AugmentationData if any source returned data, None otherwise
        """
        sources = self.get_sources_for(working_dir, config)
        if not sources:
            logger.debug("No augmentation sources available for this context")
            return None

        result: Optional[AugmentationData] = None

        for source in sources:
            try:
                data = source.fetch(working_dir, config)
                if data and data.has_data():
                    logger.debug(f"Fetched augmentation data from {source.name}")
                    if result is None:
                        result = data
                    elif merge_results:
                        # Merge new data into existing result
                        # Note: result (lower priority) takes precedence
                        result = result.merge(data)
                    else:
                        # First result wins
                        break

            except Exception as e:
                logger.warning(f"Error fetching from {source.name}: {e}")
                continue

        return result

    def list_sources(self) -> List[Dict[str, Any]]:
        """
        List all registered sources with their priorities.

        Returns:
            List of dicts with 'name' and 'priority' keys
        """
        return [{"name": s.name, "priority": s.priority} for s in sorted(self._sources, key=lambda s: s.priority)]

    def clear(self) -> None:
        """Remove all registered sources."""
        self._sources.clear()
