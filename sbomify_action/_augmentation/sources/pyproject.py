"""PyProject.toml augmentation source (PEP 621 format)."""

from pathlib import Path
from typing import Optional

import tomllib

from sbomify_action.logging_config import logger

from ..data import AugmentationData, OrganizationalContact, OrganizationalEntity


class PyProjectSource:
    """
    Augmentation source that reads metadata from pyproject.toml.

    Parses PEP 621 format to extract:
    - authors -> authors
    - maintainers -> supplier.contacts (fallback)
    - license -> licenses
    - urls.homepage -> supplier.urls

    Priority: 70 (fallback source)
    """

    name = "pyproject.toml"
    priority = 70

    def supports(self, working_dir: Path, config: dict) -> bool:
        """Check if pyproject.toml exists in working directory."""
        pyproject_path = working_dir / "pyproject.toml"
        return pyproject_path.exists()

    def fetch(self, working_dir: Path, config: dict) -> Optional[AugmentationData]:
        """
        Parse pyproject.toml and extract augmentation metadata.

        Args:
            working_dir: Working directory containing pyproject.toml
            config: Configuration dict (unused for this source)

        Returns:
            AugmentationData with extracted metadata, or None on failure
        """
        pyproject_path = working_dir / "pyproject.toml"

        try:
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            logger.warning(f"Failed to parse pyproject.toml: {e}")
            return None

        # Get the project section (PEP 621)
        project = data.get("project", {})
        if not project:
            logger.debug("No [project] section found in pyproject.toml")
            return None

        authors = []
        supplier_contacts = []
        supplier_urls = []
        licenses = []

        # Parse authors
        # PEP 621 format: authors = [{name = "...", email = "..."}]
        for author in project.get("authors", []):
            if isinstance(author, dict):
                contact = OrganizationalContact(
                    name=author.get("name"),
                    email=author.get("email"),
                )
                if contact.has_data():
                    authors.append(contact)

        # Parse maintainers -> supplier contacts
        # Maintainers often represent the organization maintaining the software
        for maintainer in project.get("maintainers", []):
            if isinstance(maintainer, dict):
                contact = OrganizationalContact(
                    name=maintainer.get("name"),
                    email=maintainer.get("email"),
                )
                if contact.has_data():
                    supplier_contacts.append(contact)

        # Parse license
        # PEP 621 supports: license = "MIT" or license = {text = "..."} or license = {file = "..."}
        license_data = project.get("license")
        if isinstance(license_data, str):
            licenses.append(license_data)
        elif isinstance(license_data, dict):
            # Could be {text: "..."} or {file: "LICENSE"}
            if "text" in license_data:
                # Custom license text - add as dict for custom license handling
                licenses.append({"name": "Custom License", "text": license_data["text"]})
            # Note: We don't read license files here, just the identifier if present

        # Also check classifiers for license info
        classifiers = project.get("classifiers", [])
        for classifier in classifiers:
            if classifier.startswith("License :: OSI Approved :: "):
                # Extract license name from classifier
                license_name = classifier.replace("License :: OSI Approved :: ", "")
                # Try to map common license names to SPDX
                spdx_mapping = {
                    "MIT License": "MIT",
                    "Apache Software License": "Apache-2.0",
                    "BSD License": "BSD-3-Clause",
                    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
                    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
                    "ISC License (ISCL)": "ISC",
                    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
                }
                spdx_id = spdx_mapping.get(license_name, license_name)
                if spdx_id not in licenses:
                    licenses.append(spdx_id)

        # Parse URLs -> supplier.urls
        urls = project.get("urls", {})
        if isinstance(urls, dict):
            # Prioritize homepage, then repository
            for url_key in ["Homepage", "homepage", "Home", "Repository", "repository"]:
                if url_key in urls and urls[url_key]:
                    supplier_urls.append(urls[url_key])

        # Build supplier if we have any supplier data
        supplier = None
        if supplier_contacts or supplier_urls:
            # Try to derive supplier name from first maintainer or first author
            supplier_name = None
            if supplier_contacts and supplier_contacts[0].name:
                supplier_name = supplier_contacts[0].name
            elif authors and authors[0].name:
                supplier_name = authors[0].name

            supplier = OrganizationalEntity(
                name=supplier_name,
                urls=supplier_urls,
                contacts=supplier_contacts,
            )

        # Only return data if we found something useful
        if not (authors or (supplier and supplier.has_data()) or licenses):
            logger.debug("No augmentation data found in pyproject.toml")
            return None

        logger.debug(
            f"Extracted from pyproject.toml: {len(authors)} authors, "
            f"{len(licenses)} licenses, supplier={'yes' if supplier else 'no'}"
        )

        return AugmentationData(
            supplier=supplier,
            authors=authors,
            licenses=licenses,
            source=self.name,
        )
