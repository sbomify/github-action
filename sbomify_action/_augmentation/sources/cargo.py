"""Cargo.toml augmentation source (Rust format)."""

import re
from pathlib import Path
from typing import Optional

import tomllib

from sbomify_action.logging_config import logger

from ..data import AugmentationData, OrganizationalContact, OrganizationalEntity


class CargoSource:
    """
    Augmentation source that reads metadata from Cargo.toml.

    Parses Rust package format to extract:
    - authors -> authors (format: "Name <email>")
    - license -> licenses
    - homepage -> supplier.urls
    - repository -> supplier.urls

    Priority: 70 (fallback source)
    """

    name = "Cargo.toml"
    priority = 70

    def supports(self, working_dir: Path, config: dict) -> bool:
        """Check if Cargo.toml exists in working directory."""
        cargo_path = working_dir / "Cargo.toml"
        return cargo_path.exists()

    def _parse_author_string(self, author_str: str) -> Optional[OrganizationalContact]:
        """
        Parse Cargo author string format: "Name <email>"

        Examples:
        - "John Doe"
        - "John Doe <john@example.com>"

        Args:
            author_str: Author string in Cargo format

        Returns:
            OrganizationalContact or None if parsing fails
        """
        if not author_str or not isinstance(author_str, str):
            return None

        # Pattern: Name <email>
        pattern = r"^([^<]+?)(?:\s*<([^>]+)>)?$"
        match = re.match(pattern, author_str.strip())

        if match:
            name = match.group(1).strip() if match.group(1) else None
            email = match.group(2).strip() if match.group(2) else None

            if name or email:
                return OrganizationalContact(name=name, email=email)

        return None

    def fetch(self, working_dir: Path, config: dict) -> Optional[AugmentationData]:
        """
        Parse Cargo.toml and extract augmentation metadata.

        Args:
            working_dir: Working directory containing Cargo.toml
            config: Configuration dict (unused for this source)

        Returns:
            AugmentationData with extracted metadata, or None on failure
        """
        cargo_path = working_dir / "Cargo.toml"

        try:
            with open(cargo_path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            logger.warning(f"Failed to parse Cargo.toml: {e}")
            return None

        # Get the package section
        package = data.get("package", {})
        if not package:
            logger.debug("No [package] section found in Cargo.toml")
            return None

        authors = []
        supplier_urls = []
        licenses = []

        # Parse authors
        # Cargo format: authors = ["Name <email>", ...]
        for author_str in package.get("authors", []):
            contact = self._parse_author_string(author_str)
            if contact and contact.has_data():
                authors.append(contact)

        # Parse license
        # Cargo supports: license = "MIT" or license-file = "LICENSE"
        license_data = package.get("license")
        if isinstance(license_data, str):
            # Cargo uses "/" for multiple licenses: "MIT/Apache-2.0"
            # Convert to SPDX format with " OR "
            if "/" in license_data:
                # This is a dual license, convert to SPDX expression
                license_parts = [lic.strip() for lic in license_data.split("/")]
                licenses.append(" OR ".join(license_parts))
            else:
                licenses.append(license_data)

        # Parse homepage
        homepage = package.get("homepage")
        if homepage and isinstance(homepage, str):
            supplier_urls.append(homepage)

        # Parse repository
        repository = package.get("repository")
        if repository and isinstance(repository, str):
            if repository not in supplier_urls:
                supplier_urls.append(repository)

        # Parse documentation URL as fallback
        documentation = package.get("documentation")
        if documentation and isinstance(documentation, str):
            if documentation not in supplier_urls:
                supplier_urls.append(documentation)

        # Build supplier if we have any supplier data
        supplier = None
        if supplier_urls:
            # Try to derive supplier name from first author
            supplier_name = None
            if authors and authors[0].name:
                supplier_name = authors[0].name

            supplier = OrganizationalEntity(
                name=supplier_name,
                urls=supplier_urls,
                contacts=[],
            )

        # Only return data if we found something useful
        if not (authors or (supplier and supplier.has_data()) or licenses):
            logger.debug("No augmentation data found in Cargo.toml")
            return None

        logger.debug(
            f"Extracted from Cargo.toml: {len(authors)} authors, "
            f"{len(licenses)} licenses, supplier={'yes' if supplier else 'no'}"
        )

        return AugmentationData(
            supplier=supplier,
            authors=authors,
            licenses=licenses,
            source=self.name,
        )
