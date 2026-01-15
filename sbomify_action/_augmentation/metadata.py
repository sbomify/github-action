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
        manufacturer: Manufacturer information (name, urls, contacts, address)
        authors: List of author information
        licenses: List of license data (strings or dicts)
        lifecycle_phase: CISA 2025 Generation Context (build, post-build, operations, etc.)
        source: Name of the provider that supplied this metadata

        VCS fields (added by CI providers or sbomify.json config):
        vcs_url: Repository URL (e.g., https://github.com/owner/repo)
        vcs_commit_sha: Full commit SHA
        vcs_ref: Branch or tag name (e.g., main, refs/heads/main, v1.0.0)
        vcs_commit_url: URL to the specific commit
    """

    supplier: Optional[Dict[str, Any]] = None
    manufacturer: Optional[Dict[str, Any]] = None
    authors: Optional[List[Dict[str, Any]]] = None
    licenses: Optional[List[Any]] = None
    lifecycle_phase: Optional[str] = None
    source: Optional[str] = None

    # VCS fields for CI environment enrichment
    vcs_url: Optional[str] = None
    vcs_commit_sha: Optional[str] = None
    vcs_ref: Optional[str] = None
    vcs_commit_url: Optional[str] = None

    # Additional fields that may be added in the future
    _extra: Dict[str, Any] = field(default_factory=dict)

    def has_data(self) -> bool:
        """Check if this metadata contains any meaningful data."""
        return any(
            [
                self.supplier,
                self.manufacturer,
                self.authors,
                self.licenses,
                self.lifecycle_phase,
                self.vcs_url,
                self.vcs_commit_sha,
                self.vcs_ref,
                self.vcs_commit_url,
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
            manufacturer=self.manufacturer if self.manufacturer else other.manufacturer,
            authors=self.authors if self.authors else other.authors,
            licenses=self.licenses if self.licenses else other.licenses,
            lifecycle_phase=self.lifecycle_phase if self.lifecycle_phase else other.lifecycle_phase,
            source=merged_source,
            # VCS fields
            vcs_url=self.vcs_url if self.vcs_url else other.vcs_url,
            vcs_commit_sha=self.vcs_commit_sha if self.vcs_commit_sha else other.vcs_commit_sha,
            vcs_ref=self.vcs_ref if self.vcs_ref else other.vcs_ref,
            vcs_commit_url=self.vcs_commit_url if self.vcs_commit_url else other.vcs_commit_url,
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
        if self.manufacturer:
            result["manufacturer"] = self.manufacturer
        if self.authors:
            result["authors"] = self.authors
        if self.licenses:
            result["licenses"] = self.licenses
        if self.lifecycle_phase:
            result["lifecycle_phase"] = self.lifecycle_phase

        # VCS fields
        if self.vcs_url:
            result["vcs_url"] = self.vcs_url
        if self.vcs_commit_sha:
            result["vcs_commit_sha"] = self.vcs_commit_sha
        if self.vcs_ref:
            result["vcs_ref"] = self.vcs_ref
        if self.vcs_commit_url:
            result["vcs_commit_url"] = self.vcs_commit_url

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
        known_keys = {
            "supplier",
            "manufacturer",
            "authors",
            "licenses",
            "lifecycle_phase",
            "vcs_url",
            "vcs_commit_sha",
            "vcs_ref",
            "vcs_commit_url",
        }
        extra = {k: v for k, v in data.items() if k not in known_keys}

        return cls(
            supplier=data.get("supplier"),
            manufacturer=data.get("manufacturer"),
            authors=data.get("authors"),
            licenses=data.get("licenses"),
            lifecycle_phase=data.get("lifecycle_phase"),
            source=source,
            vcs_url=data.get("vcs_url"),
            vcs_commit_sha=data.get("vcs_commit_sha"),
            vcs_ref=data.get("vcs_ref"),
            vcs_commit_url=data.get("vcs_commit_url"),
            _extra=extra,
        )
