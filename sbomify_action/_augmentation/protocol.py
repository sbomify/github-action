"""AugmentationSource protocol for SBOM augmentation plugins."""

from pathlib import Path
from typing import Optional, Protocol

from .data import AugmentationData


class AugmentationSource(Protocol):
    """
    Protocol defining the interface for augmentation source plugins.

    Each source implements this protocol to provide organizational metadata
    (supplier, authors, licenses) from different sources. Sources have
    priorities - lower numbers indicate higher priority (tried first).

    Unlike enrichment sources that work per-PURL, augmentation sources
    provide metadata at the project/SBOM level.

    Example:
        class PyProjectSource:
            name = "pyproject.toml"
            priority = 70  # Fallback priority

            def supports(self, working_dir: Path, config: dict) -> bool:
                return (working_dir / "pyproject.toml").exists()

            def fetch(self, working_dir: Path, config: dict) -> Optional[AugmentationData]:
                # Parse pyproject.toml and return normalized data
                ...
    """

    @property
    def name(self) -> str:
        """
        Human-readable name of this augmentation source.

        Used for logging and tracking which source provided metadata.
        Examples: "sbomify-api", "local-json", "pyproject.toml"
        """
        ...

    @property
    def priority(self) -> int:
        """
        Priority of this source (lower = higher priority, tried first).

        When multiple sources provide data, they are merged in priority
        order. Lower priority values win on field conflicts.

        Recommended priority ranges (per ADR-0001):
        - 1-20: Native/authoritative sources (sbomify API)
        - 21-50: Explicit configuration (local JSON files)
        - 51-80: Auto-discovered sources (package manifests)
        - 81-100: Fallback sources
        """
        ...

    def supports(self, working_dir: Path, config: dict) -> bool:
        """
        Check if this source can provide data for the given context.

        Args:
            working_dir: Working directory (project root)
            config: Configuration dict with keys like 'token', 'component_id',
                   'api_base_url', 'augmentation_file', etc.

        Returns:
            True if this source can provide augmentation data
        """
        ...

    def fetch(self, working_dir: Path, config: dict) -> Optional[AugmentationData]:
        """
        Fetch augmentation data from this source.

        Implementations should:
        1. Read/fetch data from their source (file, API, etc.)
        2. Normalize the response into AugmentationData
        3. Handle errors gracefully (return None on failure)
        4. Set the 'source' field on the returned data

        Args:
            working_dir: Working directory (project root)
            config: Configuration dict with relevant settings

        Returns:
            AugmentationData if successful, None if fetch fails or no data
        """
        ...
