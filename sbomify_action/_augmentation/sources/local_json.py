"""Local JSON file augmentation source (.sbomify.json)."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from sbomify_action.logging_config import logger

from ..data import AugmentationData, OrganizationalContact, OrganizationalEntity

# Default filename for local augmentation config
DEFAULT_AUGMENTATION_FILE = ".sbomify.json"


class LocalJSONSource:
    """
    Augmentation source that reads metadata from a local JSON file.

    The JSON file supports the full augmentation schema:
    - supplier: {name, url[], contact[]}
    - manufacturer: {name, url[], contact[]}
    - authors: [{name, email, phone}]
    - licenses: [string or {name, url, text}]

    Default file: .sbomify.json
    Can be customized via config["augmentation_file"]

    Priority: 50 (explicit configuration)
    """

    name = "local-json"
    priority = 50

    def supports(self, working_dir: Path, config: dict) -> bool:
        """Check if augmentation JSON file exists."""
        augmentation_file = config.get("augmentation_file", DEFAULT_AUGMENTATION_FILE)
        json_path = working_dir / augmentation_file
        return json_path.exists()

    def _parse_contact(self, contact_data: Dict[str, Any]) -> Optional[OrganizationalContact]:
        """Parse a contact dict into OrganizationalContact."""
        if not isinstance(contact_data, dict):
            return None

        contact = OrganizationalContact(
            name=contact_data.get("name"),
            email=contact_data.get("email"),
            phone=contact_data.get("phone"),
        )

        return contact if contact.has_data() else None

    def _parse_entity(self, entity_data: Dict[str, Any]) -> Optional[OrganizationalEntity]:
        """Parse an entity dict into OrganizationalEntity."""
        if not isinstance(entity_data, dict):
            return None

        # Parse URLs (can be string or list)
        urls: List[str] = []
        url_data = entity_data.get("url", [])
        if isinstance(url_data, str):
            urls = [url_data]
        elif isinstance(url_data, list):
            urls = [u for u in url_data if isinstance(u, str)]

        # Parse contacts
        contacts: List[OrganizationalContact] = []
        contact_data = entity_data.get("contact", [])
        if isinstance(contact_data, list):
            for c in contact_data:
                contact = self._parse_contact(c)
                if contact:
                    contacts.append(contact)

        entity = OrganizationalEntity(
            name=entity_data.get("name"),
            urls=urls,
            contacts=contacts,
        )

        return entity if entity.has_data() else None

    def fetch(self, working_dir: Path, config: dict) -> Optional[AugmentationData]:
        """
        Parse local JSON file and extract augmentation metadata.

        Args:
            working_dir: Working directory containing the JSON file
            config: Configuration dict with optional 'augmentation_file' key

        Returns:
            AugmentationData with extracted metadata, or None on failure
        """
        augmentation_file = config.get("augmentation_file", DEFAULT_AUGMENTATION_FILE)
        json_path = working_dir / augmentation_file

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {augmentation_file}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Failed to read {augmentation_file}: {e}")
            return None

        if not isinstance(data, dict):
            logger.warning(f"Invalid format in {augmentation_file}: expected object at root")
            return None

        # Parse supplier
        supplier = None
        supplier_data = data.get("supplier")
        if supplier_data:
            supplier = self._parse_entity(supplier_data)

        # Parse manufacturer
        manufacturer = None
        manufacturer_data = data.get("manufacturer")
        if manufacturer_data:
            manufacturer = self._parse_entity(manufacturer_data)

        # Parse authors
        authors: List[OrganizationalContact] = []
        authors_data = data.get("authors", [])
        if isinstance(authors_data, list):
            for author_data in authors_data:
                contact = self._parse_contact(author_data)
                if contact:
                    authors.append(contact)

        # Parse licenses
        # Can be: ["MIT", "Apache-2.0"] or [{name, url, text}]
        licenses: List[Any] = []
        licenses_data = data.get("licenses", [])
        if isinstance(licenses_data, list):
            for lic in licenses_data:
                if isinstance(lic, str):
                    licenses.append(lic)
                elif isinstance(lic, dict):
                    # Custom license object - pass through as-is
                    licenses.append(lic)

        # Only return data if we found something useful
        if not (
            (supplier and supplier.has_data()) or (manufacturer and manufacturer.has_data()) or authors or licenses
        ):
            logger.debug(f"No augmentation data found in {augmentation_file}")
            return None

        logger.info(f"Loaded augmentation data from {augmentation_file}")
        logger.debug(
            f"Extracted from {augmentation_file}: {len(authors)} authors, "
            f"{len(licenses)} licenses, supplier={'yes' if supplier else 'no'}, "
            f"manufacturer={'yes' if manufacturer else 'no'}"
        )

        return AugmentationData(
            supplier=supplier,
            manufacturer=manufacturer,
            authors=authors,
            licenses=licenses,
            source=self.name,
        )
