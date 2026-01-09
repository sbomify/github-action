"""sbomify API augmentation source."""

from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

from ..data import AugmentationData, OrganizationalContact, OrganizationalEntity


class SbomifyAPISource:
    """
    Augmentation source that fetches metadata from sbomify backend API.

    Requires configuration:
    - token: API authentication token
    - component_id: Component ID to fetch metadata for
    - api_base_url: Base URL for the API (default: https://app.sbomify.com)

    Priority: 10 (native/authoritative source)
    """

    name = "sbomify-api"
    priority = 10

    def supports(self, working_dir: Path, config: dict) -> bool:
        """
        Check if sbomify API credentials are configured.

        Returns True only if both token and component_id are provided.
        """
        token = config.get("token")
        component_id = config.get("component_id")

        return bool(token and component_id)

    def _parse_contact(self, contact_data: Dict[str, Any]) -> Optional[OrganizationalContact]:
        """Parse a contact dict from API response."""
        if not isinstance(contact_data, dict):
            return None

        contact = OrganizationalContact(
            name=contact_data.get("name"),
            email=contact_data.get("email"),
            phone=contact_data.get("phone"),
        )

        return contact if contact.has_data() else None

    def _parse_entity(self, entity_data: Dict[str, Any]) -> Optional[OrganizationalEntity]:
        """Parse an entity dict from API response."""
        if not isinstance(entity_data, dict):
            return None

        # Parse URLs (API returns 'url' which can be string or list)
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
        Fetch augmentation metadata from sbomify API.

        Args:
            working_dir: Working directory (unused for API source)
            config: Configuration dict with token, component_id, api_base_url

        Returns:
            AugmentationData with API metadata, or None on failure
        """
        token = config.get("token")
        component_id = config.get("component_id")
        api_base_url = config.get("api_base_url", "https://app.sbomify.com")

        if not token or not component_id:
            logger.debug("sbomify API credentials not configured")
            return None

        url = f"{api_base_url}/api/v1/sboms/component/{component_id}/meta"
        headers = get_default_headers(token)

        try:
            response = requests.get(url, headers=headers, timeout=60)
        except requests.exceptions.ConnectionError:
            logger.warning("Failed to connect to sbomify API")
            return None
        except requests.exceptions.Timeout:
            logger.warning("sbomify API request timed out")
            return None

        if not response.ok:
            err_msg = f"Failed to retrieve component metadata from sbomify. [{response.status_code}]"
            if response.headers.get("content-type") == "application/json":
                try:
                    error_data = response.json()
                    if "detail" in error_data:
                        err_msg += f" - {error_data['detail']}"
                except (ValueError, KeyError):
                    pass
            logger.warning(err_msg)
            return None

        try:
            data = response.json()
        except ValueError:
            logger.warning("Invalid JSON response from sbomify API")
            return None

        # Parse supplier
        supplier = None
        supplier_data = data.get("supplier")
        if supplier_data:
            supplier = self._parse_entity(supplier_data)

        # Parse authors
        authors: List[OrganizationalContact] = []
        authors_data = data.get("authors", [])
        if isinstance(authors_data, list):
            for author_data in authors_data:
                contact = self._parse_contact(author_data)
                if contact:
                    authors.append(contact)

        # Parse licenses (API returns list of strings or dicts)
        licenses: List[Any] = data.get("licenses", [])

        # Only return data if we found something useful
        if not ((supplier and supplier.has_data()) or authors or licenses):
            logger.debug("No augmentation data returned from sbomify API")
            return None

        logger.info("Fetched augmentation data from sbomify API")
        logger.debug(
            f"API returned: {len(authors)} authors, {len(licenses)} licenses, supplier={'yes' if supplier else 'no'}"
        )

        return AugmentationData(
            supplier=supplier,
            authors=authors,
            licenses=licenses,
            source=self.name,
        )
