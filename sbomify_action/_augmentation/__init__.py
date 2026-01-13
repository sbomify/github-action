"""Augmentation plugin architecture for SBOM metadata providers.

This module provides a plugin-based approach to fetching organizational
metadata for SBOM augmentation. Multiple providers can supply metadata
(supplier, authors, licenses, lifecycle_phase), which is merged by priority.

Providers:
- json-config: Reads from sbomify.json config file (priority 10)
- sbomify-api: Fetches from sbomify backend API (priority 50)

Usage:
    from sbomify_action._augmentation import create_default_registry

    registry = create_default_registry()
    metadata = registry.fetch_metadata(
        component_id="xxx",
        api_base_url="https://app.sbomify.com",
        token="your-token",
    )
"""

from .metadata import AugmentationMetadata
from .protocol import AugmentationProvider
from .registry import ProviderRegistry

__all__ = [
    "AugmentationMetadata",
    "AugmentationProvider",
    "ProviderRegistry",
    "create_default_registry",
]


def create_default_registry() -> ProviderRegistry:
    """
    Create a registry with default augmentation providers.

    Returns:
        ProviderRegistry configured with standard providers
    """
    from .providers import JsonConfigProvider, SbomifyApiProvider

    registry = ProviderRegistry()
    registry.register(JsonConfigProvider())
    registry.register(SbomifyApiProvider())

    return registry
