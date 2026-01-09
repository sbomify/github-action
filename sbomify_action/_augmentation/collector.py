"""Augmentation collector for orchestrating data sources."""

from pathlib import Path
from typing import Optional

from sbomify_action.logging_config import logger

from .data import AugmentationData
from .registry import AugmentationSourceRegistry


class AugmentationCollector:
    """
    Orchestrates fetching and merging augmentation data from multiple sources.

    The collector uses a registry of sources and fetches data in priority order,
    merging results to produce a complete AugmentationData object.
    """

    def __init__(self, registry: AugmentationSourceRegistry) -> None:
        """
        Initialize the collector with a source registry.

        Args:
            registry: Pre-configured AugmentationSourceRegistry
        """
        self._registry = registry

    def collect(self, working_dir: Path, config: dict) -> Optional[AugmentationData]:
        """
        Collect augmentation data from all applicable sources.

        Fetches from sources in priority order and merges results.

        Args:
            working_dir: Working directory (project root)
            config: Configuration dict with settings like token, component_id, etc.

        Returns:
            Merged AugmentationData if any source returned data, None otherwise
        """
        logger.debug(f"Collecting augmentation data from {working_dir}")

        # Log available sources
        sources = self._registry.list_sources()
        if sources:
            logger.debug(f"Available augmentation sources: {[s['name'] for s in sources]}")

        # Fetch and merge from all applicable sources
        result = self._registry.fetch_metadata(working_dir, config, merge_results=True)

        if result and result.has_data():
            # Log what we found
            fields = []
            if result.supplier and result.supplier.has_data():
                fields.append("supplier")
            if result.manufacturer and result.manufacturer.has_data():
                fields.append("manufacturer")
            if result.authors:
                fields.append(f"authors ({len(result.authors)})")
            if result.licenses:
                fields.append(f"licenses ({len(result.licenses)})")

            logger.info(f"Collected augmentation data: {', '.join(fields)}")
            if result.field_sources:
                for field_name, source_name in result.field_sources.items():
                    logger.debug(f"  {field_name} from {source_name}")

        return result


def create_default_registry(enabled_sources: list[str] | None = None) -> AugmentationSourceRegistry:
    """
    Create a registry with augmentation sources.

    Sources are registered in priority order:
    - sbomify API (priority 10) - authoritative when configured
    - local JSON (priority 50) - explicit project config
    - package manifests (priority 70) - auto-discovered fallbacks

    Args:
        enabled_sources: List of source types to enable.
                        Valid values: "sbomify", "local_json", "manifest"
                        If None, all sources are enabled.

    Returns:
        Configured AugmentationSourceRegistry
    """
    from .sources.cargo import CargoSource
    from .sources.local_json import LocalJSONSource
    from .sources.package_json import PackageJSONSource
    from .sources.pyproject import PyProjectSource
    from .sources.sbomify_api import SbomifyAPISource

    registry = AugmentationSourceRegistry()

    # Default: all sources enabled
    if enabled_sources is None:
        enabled_sources = ["sbomify", "local_json", "manifest"]

    enabled_set = set(enabled_sources)
    logger.debug(f"Enabled augmentation sources: {enabled_sources}")

    # Register sources in priority order (lower = higher priority)
    # Native/authoritative sources (priority 1-20)
    if "sbomify" in enabled_set:
        registry.register(SbomifyAPISource())

    # Explicit configuration (priority 21-50)
    if "local_json" in enabled_set:
        registry.register(LocalJSONSource())

    # Auto-discovered sources (priority 51-80) - all under "manifest" category
    if "manifest" in enabled_set:
        registry.register(PyProjectSource())
        registry.register(PackageJSONSource())
        registry.register(CargoSource())

    return registry
