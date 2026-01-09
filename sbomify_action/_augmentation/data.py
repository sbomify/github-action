"""Augmentation data dataclasses for SBOM metadata."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union


@dataclass
class OrganizationalContact:
    """
    Contact information for an individual.

    Maps to CycloneDX organizationalContact and SPDX Actor (Person).
    """

    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {}
        if self.name:
            result["name"] = self.name
        if self.email:
            result["email"] = self.email
        if self.phone:
            result["phone"] = self.phone
        return result

    def has_data(self) -> bool:
        """Check if this contact has any meaningful data."""
        return bool(self.name or self.email)


@dataclass
class OrganizationalEntity:
    """
    Organization information.

    Maps to CycloneDX organizationalEntity (supplier, manufacturer).
    """

    name: Optional[str] = None
    urls: List[str] = field(default_factory=list)
    contacts: List[OrganizationalContact] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format expected by augmentation.py."""
        result: Dict[str, Any] = {}
        if self.name:
            result["name"] = self.name
        if self.urls:
            result["url"] = self.urls
        if self.contacts:
            result["contact"] = [c.to_dict() for c in self.contacts if c.has_data()]
        return result

    def has_data(self) -> bool:
        """Check if this entity has any meaningful data."""
        return bool(self.name or self.urls or any(c.has_data() for c in self.contacts))

    def merge(self, other: "OrganizationalEntity") -> "OrganizationalEntity":
        """
        Merge another entity, filling in missing fields.

        Current object's values take precedence.

        Args:
            other: Another OrganizationalEntity to merge from

        Returns:
            A new OrganizationalEntity with merged values
        """
        # Merge URLs (combine and dedupe)
        merged_urls = list(self.urls)
        for url in other.urls:
            if url not in merged_urls:
                merged_urls.append(url)

        # Merge contacts (dedupe by email)
        merged_contacts = list(self.contacts)
        existing_emails = {c.email for c in self.contacts if c.email}
        for contact in other.contacts:
            if not contact.email or contact.email not in existing_emails:
                merged_contacts.append(contact)
                if contact.email:
                    existing_emails.add(contact.email)

        return OrganizationalEntity(
            name=self.name or other.name,
            urls=merged_urls,
            contacts=merged_contacts,
        )


@dataclass
class AugmentationData:
    """
    Normalized augmentation data from any source.

    This dataclass provides a consistent structure for organizational
    metadata regardless of the source (sbomify API, local JSON, package manifests).
    All fields are optional - sources populate what they can provide.

    The data model matches CycloneDX 1.6+ metadata fields:
    - supplier: Organization that distributes the software
    - manufacturer: Organization that created the software (CDX 1.6+)
    - authors: Individual people who created/maintain the software
    - licenses: SPDX identifiers or custom license objects
    """

    # CycloneDX metadata-level fields
    supplier: Optional[OrganizationalEntity] = None
    manufacturer: Optional[OrganizationalEntity] = None
    authors: List[OrganizationalContact] = field(default_factory=list)
    licenses: List[Union[str, Dict[str, Any]]] = field(default_factory=list)

    # Source tracking (per ADR-0001)
    source: str = ""
    field_sources: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary format compatible with existing augmentation.py.

        Returns dict with keys: supplier, authors, licenses (matching backend API format)
        """
        result: Dict[str, Any] = {}

        if self.supplier and self.supplier.has_data():
            result["supplier"] = self.supplier.to_dict()

        if self.manufacturer and self.manufacturer.has_data():
            result["manufacturer"] = self.manufacturer.to_dict()

        if self.authors:
            authors_list = [a.to_dict() for a in self.authors if a.has_data()]
            if authors_list:
                result["authors"] = authors_list

        if self.licenses:
            result["licenses"] = self.licenses

        return result

    def has_data(self) -> bool:
        """Check if this data has any meaningful content."""
        return bool(
            (self.supplier and self.supplier.has_data())
            or (self.manufacturer and self.manufacturer.has_data())
            or any(a.has_data() for a in self.authors)
            or self.licenses
        )

    def merge(self, other: "AugmentationData") -> "AugmentationData":
        """
        Merge another data object, filling in missing fields.

        The current object's values take precedence - only missing fields
        are filled from the other object. Per-field attribution is tracked.

        Args:
            other: Another AugmentationData to merge from

        Returns:
            A new AugmentationData with merged values
        """
        # Start with existing field_sources
        merged_sources = dict(self.field_sources)

        # Helper to track source attribution
        def track_source(field_name: str, has_self: bool, has_other: bool) -> None:
            if not has_self and has_other and other.source:
                merged_sources[field_name] = other.source

        # Merge supplier
        merged_supplier = None
        if self.supplier and self.supplier.has_data():
            if other.supplier and other.supplier.has_data():
                merged_supplier = self.supplier.merge(other.supplier)
            else:
                merged_supplier = self.supplier
        elif other.supplier and other.supplier.has_data():
            merged_supplier = other.supplier
            track_source("supplier", False, True)

        # Merge manufacturer
        merged_manufacturer = None
        if self.manufacturer and self.manufacturer.has_data():
            if other.manufacturer and other.manufacturer.has_data():
                merged_manufacturer = self.manufacturer.merge(other.manufacturer)
            else:
                merged_manufacturer = self.manufacturer
        elif other.manufacturer and other.manufacturer.has_data():
            merged_manufacturer = other.manufacturer
            track_source("manufacturer", False, True)

        # Merge authors (dedupe by email)
        merged_authors = list(self.authors)
        existing_emails = {a.email for a in self.authors if a.email}
        authors_added_from_other = False
        for author in other.authors:
            if not author.email or author.email not in existing_emails:
                merged_authors.append(author)
                if author.email:
                    existing_emails.add(author.email)
                authors_added_from_other = True
        if not self.authors and authors_added_from_other:
            track_source("authors", False, True)

        # Merge licenses (dedupe)
        merged_licenses: List[Union[str, Dict[str, Any]]] = list(self.licenses)
        for lic in other.licenses:
            if lic not in merged_licenses:
                merged_licenses.append(lic)
        if not self.licenses and other.licenses:
            track_source("licenses", False, True)

        return AugmentationData(
            supplier=merged_supplier,
            manufacturer=merged_manufacturer,
            authors=merged_authors,
            licenses=merged_licenses,
            source=self.source or other.source,
            field_sources=merged_sources,
        )
