"""Package.json augmentation source (npm/Node.js format)."""

import json
import re
from pathlib import Path
from typing import Optional

from sbomify_action.logging_config import logger

from ..data import AugmentationData, OrganizationalContact, OrganizationalEntity


class PackageJSONSource:
    """
    Augmentation source that reads metadata from package.json.

    Parses npm/Node.js format to extract:
    - author -> authors (can be string or object)
    - contributors -> authors
    - license -> licenses
    - homepage -> supplier.urls
    - repository -> supplier.urls

    Priority: 70 (fallback source)
    """

    name = "package.json"
    priority = 70

    def supports(self, working_dir: Path, config: dict) -> bool:
        """Check if package.json exists in working directory."""
        package_json_path = working_dir / "package.json"
        return package_json_path.exists()

    def _parse_author_string(self, author_str: str) -> Optional[OrganizationalContact]:
        """
        Parse npm author string format: "Name <email> (url)"

        Examples:
        - "John Doe"
        - "John Doe <john@example.com>"
        - "John Doe <john@example.com> (https://example.com)"

        Args:
            author_str: Author string in npm format

        Returns:
            OrganizationalContact or None if parsing fails
        """
        if not author_str or not isinstance(author_str, str):
            return None

        # Pattern: Name <email> (url)
        # All parts except name are optional
        pattern = r"^([^<(]+?)(?:\s*<([^>]+)>)?(?:\s*\(([^)]+)\))?$"
        match = re.match(pattern, author_str.strip())

        if match:
            name = match.group(1).strip() if match.group(1) else None
            email = match.group(2).strip() if match.group(2) else None
            # url is group(3) but we don't use it for contact

            if name or email:
                return OrganizationalContact(name=name, email=email)

        return None

    def _parse_author(self, author_data) -> Optional[OrganizationalContact]:
        """
        Parse author data which can be a string or object.

        Args:
            author_data: Author data (string or dict)

        Returns:
            OrganizationalContact or None
        """
        if isinstance(author_data, str):
            return self._parse_author_string(author_data)
        elif isinstance(author_data, dict):
            return OrganizationalContact(
                name=author_data.get("name"),
                email=author_data.get("email"),
            )
        return None

    def fetch(self, working_dir: Path, config: dict) -> Optional[AugmentationData]:
        """
        Parse package.json and extract augmentation metadata.

        Args:
            working_dir: Working directory containing package.json
            config: Configuration dict (unused for this source)

        Returns:
            AugmentationData with extracted metadata, or None on failure
        """
        package_json_path = working_dir / "package.json"

        try:
            with open(package_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to parse package.json: {e}")
            return None

        authors = []
        supplier_urls = []
        licenses = []

        # Parse author (can be string or object)
        author_data = data.get("author")
        if author_data:
            contact = self._parse_author(author_data)
            if contact and contact.has_data():
                authors.append(contact)

        # Parse contributors
        contributors = data.get("contributors", [])
        if isinstance(contributors, list):
            for contrib in contributors:
                contact = self._parse_author(contrib)
                if contact and contact.has_data():
                    authors.append(contact)

        # Parse license
        license_data = data.get("license")
        if isinstance(license_data, str):
            licenses.append(license_data)
        elif isinstance(license_data, dict):
            # Older format: {type: "MIT", url: "..."}
            if "type" in license_data:
                licenses.append(license_data["type"])

        # Also check "licenses" array (older npm format)
        licenses_array = data.get("licenses", [])
        if isinstance(licenses_array, list):
            for lic in licenses_array:
                if isinstance(lic, str):
                    if lic not in licenses:
                        licenses.append(lic)
                elif isinstance(lic, dict) and "type" in lic:
                    if lic["type"] not in licenses:
                        licenses.append(lic["type"])

        # Parse homepage
        homepage = data.get("homepage")
        if homepage and isinstance(homepage, str):
            supplier_urls.append(homepage)

        # Parse repository
        repository = data.get("repository")
        if isinstance(repository, str):
            # Simple string format
            if repository not in supplier_urls:
                supplier_urls.append(repository)
        elif isinstance(repository, dict):
            # Object format: {type: "git", url: "..."}
            repo_url = repository.get("url", "")
            if repo_url:
                # Clean up git URLs
                repo_url = repo_url.replace("git+", "").replace("git://", "https://")
                if repo_url.endswith(".git"):
                    repo_url = repo_url[:-4]
                if repo_url and repo_url not in supplier_urls:
                    supplier_urls.append(repo_url)

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
            logger.debug("No augmentation data found in package.json")
            return None

        logger.debug(
            f"Extracted from package.json: {len(authors)} authors, "
            f"{len(licenses)} licenses, supplier={'yes' if supplier else 'no'}"
        )

        return AugmentationData(
            supplier=supplier,
            authors=authors,
            licenses=licenses,
            source=self.name,
        )
