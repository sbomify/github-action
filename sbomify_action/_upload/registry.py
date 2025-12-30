"""Destination registry for managing SBOM upload plugins."""

from typing import Any, Dict, FrozenSet, List, Optional

from sbomify_action.logging_config import logger

from .protocol import Destination, UploadInput
from .result import UploadResult

# Valid destination names - single source of truth for destination validation
VALID_DESTINATIONS: FrozenSet[str] = frozenset({"sbomify", "dependency-track"})


class DestinationRegistry:
    """
    Registry for managing SBOM upload destination plugins.

    The registry maintains a collection of available destinations and provides
    methods to upload to one or multiple configured destinations.

    Example:
        registry = DestinationRegistry()
        registry.register(SbomifyDestination(token="...", component_id="..."))
        registry.register(DependencyTrackDestination())

        # Upload to all configured destinations
        results = registry.upload_all(input)

        # Upload to specific destination
        result = registry.upload(input, destination_name="sbomify")
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._destinations: Dict[str, Destination] = {}

    def register(self, destination: Destination) -> None:
        """
        Register a destination.

        Args:
            destination: Destination implementation to register
        """
        self._destinations[destination.name] = destination
        logger.debug(f"Registered destination: {destination.name}")

    def get(self, name: str) -> Optional[Destination]:
        """
        Get a destination by name.

        Args:
            name: Name of the destination

        Returns:
            Destination if found, None otherwise
        """
        return self._destinations.get(name)

    def get_configured_destinations(self) -> List[Destination]:
        """
        Get all destinations that are configured and ready for upload.

        Returns:
            List of configured Destination instances
        """
        return [d for d in self._destinations.values() if d.is_configured()]

    def upload(self, input: UploadInput, destination_name: str) -> UploadResult:
        """
        Upload an SBOM to a specific destination.

        Args:
            input: UploadInput with SBOM file and format
            destination_name: Name of destination to upload to

        Returns:
            UploadResult from the destination

        Raises:
            ValueError: If destination not found
        """
        destination = self._destinations.get(destination_name)
        if not destination:
            available = list(self._destinations.keys())
            raise ValueError(f"Destination '{destination_name}' not found. Available destinations: {available}")

        if not destination.is_configured():
            return UploadResult.failure_result(
                destination_name=destination_name,
                error_message=f"Destination '{destination_name}' is not configured",
            )

        return self._execute_upload(destination, input)

    def upload_all(self, input: UploadInput) -> List[UploadResult]:
        """
        Upload an SBOM to all configured destinations.

        Args:
            input: UploadInput with SBOM file and format

        Returns:
            List of UploadResult from each configured destination
        """
        configured = self.get_configured_destinations()

        if not configured:
            logger.warning("No destinations configured for upload")
            return []

        results = []
        for destination in configured:
            result = self._execute_upload(destination, input)
            results.append(result)

        return results

    def _execute_upload(self, destination: Destination, input: UploadInput) -> UploadResult:
        """Execute upload with a specific destination."""
        logger.info(f"Uploading to destination: {destination.name}")
        try:
            result = destination.upload(input)
            if result.success:
                logger.info(f"Successfully uploaded SBOM to {destination.name}")
            else:
                logger.warning(f"Upload to {destination.name} failed: {result.error_message}")
            return result
        except Exception as e:
            logger.error(f"Destination {destination.name} raised exception: {e}")
            return UploadResult.failure_result(
                destination_name=destination.name,
                error_message=str(e),
            )

    def list_destinations(self) -> List[Dict[str, Any]]:
        """
        List all registered destinations with their configuration status.

        Returns:
            List of dicts with destination info
        """
        return [
            {
                "name": name,
                "configured": dest.is_configured(),
            }
            for name, dest in sorted(self._destinations.items())
        ]

    def clear(self) -> None:
        """Remove all registered destinations."""
        self._destinations.clear()
