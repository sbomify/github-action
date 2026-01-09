"""Plugin-based SBOM augmentation architecture for metadata from multiple sources."""

from .collector import AugmentationCollector, create_default_registry
from .data import AugmentationData, OrganizationalContact, OrganizationalEntity
from .protocol import AugmentationSource
from .registry import AugmentationSourceRegistry

# Valid augmentation source names that users can specify in AUGMENTATION_SOURCES
# - sbomify: Fetch metadata from sbomify API (requires token and component_id)
# - local_json: Read metadata from local JSON file (e.g., .sbomify.json)
# - manifest: Extract metadata from package manifests (pyproject.toml, package.json, Cargo.toml)
VALID_AUGMENTATION_SOURCES = frozenset({"sbomify", "local_json", "manifest"})

__all__ = [
    "AugmentationCollector",
    "AugmentationData",
    "AugmentationSource",
    "AugmentationSourceRegistry",
    "OrganizationalContact",
    "OrganizationalEntity",
    "VALID_AUGMENTATION_SOURCES",
    "create_default_registry",
]
