"""Plugin-based SBOM enrichment architecture."""

from .enricher import Enricher, create_default_registry
from .metadata import NormalizedMetadata
from .protocol import DataSource
from .registry import SourceRegistry

__all__ = [
    "Enricher",
    "create_default_registry",
    "NormalizedMetadata",
    "DataSource",
    "SourceRegistry",
]
