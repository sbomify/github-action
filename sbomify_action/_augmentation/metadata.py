"""AugmentationMetadata dataclass for normalized augmentation data."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AugmentationMetadata:
    """
    Normalized metadata for SBOM augmentation.

    This dataclass represents the canonical format for augmentation data
    from any provider. It includes fields for NTIA Minimum Elements and
    CISA 2025 requirements.

    Attributes:
        supplier: Supplier information (name, urls, contacts)
        authors: List of author information
        licenses: List of license data (strings or dicts)
        lifecycle_phase: CISA 2025 Generation Context (build, post-build, operations, etc.)
        source: Name of the provider that supplied this metadata
    """

    supplier: Optional[Dict[str, Any]] = None
    authors: Optional[List[Dict[str, Any]]] = None
    licenses: Optional[List[Any]] = None
    lifecycle_phase: Optional[str] = None
    source: Optional[str] = None

    # Additional fields that may be added in the future
    _extra: Dict[str, Any] = field(default_factory=dict)

    def has_data(self) -> bool:
        """Check if this metadata contains any meaningful data."""
        return any(
            [
                self.supplier,
                self.authors,
                self.licenses,
                self.lifecycle_phase,
            ]
        )

    def merge(self, other: "AugmentationMetadata") -> "AugmentationMetadata":
        """
        Merge another metadata instance into this one.

        The current instance's values take precedence (are not overwritten).
        Only missing fields are filled from the other instance.

        Args:
            other: Another AugmentationMetadata to merge from

        Returns:
            New AugmentationMetadata with merged values
        """
        # Merge sources for attribution
        sources = []
        if self.source:
            sources.append(self.source)
        if other.source and other.source not in sources:
            sources.append(other.source)
        merged_source = ", ".join(sources) if sources else None

        return AugmentationMetadata(
            supplier=self.supplier if self.supplier else other.supplier,
            authors=self.authors if self.authors else other.authors,
            licenses=self.licenses if self.licenses else other.licenses,
            lifecycle_phase=self.lifecycle_phase if self.lifecycle_phase else other.lifecycle_phase,
            source=merged_source,
            _extra={**other._extra, **self._extra},  # self takes precedence
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format compatible with existing augmentation functions.

        Returns:
            Dictionary with augmentation data
        """
        result: Dict[str, Any] = {}

        if self.supplier:
            result["supplier"] = self.supplier
        if self.authors:
            result["authors"] = self.authors
        if self.licenses:
            result["licenses"] = self.licenses
        if self.lifecycle_phase:
            result["lifecycle_phase"] = self.lifecycle_phase

        # Include any extra fields
        result.update(self._extra)

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source: Optional[str] = None) -> "AugmentationMetadata":
        """
        Create AugmentationMetadata from a dictionary.

        Args:
            data: Dictionary with augmentation data
            source: Name of the source that provided this data

        Returns:
            New AugmentationMetadata instance
        """
        known_keys = {"supplier", "authors", "licenses", "lifecycle_phase"}
        extra = {k: v for k, v in data.items() if k not in known_keys}

        return cls(
            supplier=data.get("supplier"),
            authors=data.get("authors"),
            licenses=data.get("licenses"),
            lifecycle_phase=data.get("lifecycle_phase"),
            source=source,
            _extra=extra,
        )
