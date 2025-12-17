"""Plugin-based SBOM enrichment architecture."""

from .enricher import Enricher, create_default_registry
from .metadata import NormalizedMetadata
from .protocol import DataSource
from .registry import SourceRegistry
from .utils import get_qualified_name

__all__ = [
    "Enricher",
    "create_default_registry",
    "get_qualified_name",
    "NormalizedMetadata",
    "DataSource",
    "SourceRegistry",
]
