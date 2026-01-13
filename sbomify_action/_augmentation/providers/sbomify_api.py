"""sbomify API provider for augmentation metadata.

This provider fetches organizational metadata from the sbomify backend API,
including supplier, authors, licenses, and lifecycle phase.
"""

from typing import Any, Dict, Optional

import requests

from sbomify_action.exceptions import APIError
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata


class SbomifyApiProvider:
    """
    Provider that fetches augmentation metadata from the sbomify API.

    This provider has lower priority (50) so local config can override
    API data when needed.
    """

    name: str = "sbomify-api"
    priority: int = 50

    def fetch(
        self,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        config_path: Optional[str] = None,
        **kwargs,
    ) -> Optional[AugmentationMetadata]:
        """
        Fetch augmentation metadata from the sbomify API.

        Args:
            component_id: Component ID to fetch metadata for (required)
            api_base_url: Base URL for the API (required)
            token: Authentication token (required)
            config_path: Ignored (not needed for API provider)
            **kwargs: Additional arguments (ignored)

        Returns:
            AugmentationMetadata if API call succeeds, None otherwise
        """
        # Validate required parameters
        if not component_id:
            logger.debug("sbomify API provider: component_id not provided, skipping")
            return None
        if not api_base_url:
            logger.debug("sbomify API provider: api_base_url not provided, skipping")
            return None
        if not token:
            logger.debug("sbomify API provider: token not provided, skipping")
            return None

        # Fetch from API
        try:
            data = self._fetch_backend_metadata(api_base_url, token, component_id)
            if not data:
                return None

            # Create metadata from API response
            metadata = AugmentationMetadata.from_dict(data, source=self.name)

            if metadata.has_data():
                logger.info(f"Fetched augmentation metadata from sbomify API for component {component_id}")
                return metadata
            else:
                logger.debug("No augmentation metadata returned from sbomify API")
                return None

        except APIError as e:
            logger.warning(f"sbomify API error: {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error fetching from sbomify API: {e}")
            return None

    def _fetch_backend_metadata(
        self,
        api_base_url: str,
        token: str,
        component_id: str,
    ) -> Dict[str, Any]:
        """
        Fetch metadata from backend API.

        Args:
            api_base_url: Base URL for the API
            token: Authentication token
            component_id: Component ID to fetch metadata for

        Returns:
            Backend metadata dict

        Raises:
            APIError: If API call fails
        """
        url = f"{api_base_url}/api/v1/sboms/component/{component_id}/meta"
        headers = get_default_headers(token)

        try:
            response = requests.get(url, headers=headers, timeout=60)
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to sbomify API")
        except requests.exceptions.Timeout:
            raise APIError("API request timed out")

        if not response.ok:
            err_msg = f"Failed to retrieve component metadata from sbomify. [{response.status_code}]"
            if response.headers.get("content-type") == "application/json":
                try:
                    error_data = response.json()
                    if "detail" in error_data:
                        err_msg += f" - {error_data['detail']}"
                except (ValueError, KeyError):
                    pass
            raise APIError(err_msg)

        return response.json()
