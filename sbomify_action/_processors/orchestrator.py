"""Processor orchestrator and factory functions."""

from typing import TYPE_CHECKING, List, Optional

from sbomify_action.logging_config import logger

from .processors import SbomifyReleasesProcessor
from .protocol import ProcessorInput
from .registry import ProcessorRegistry
from .result import AggregateResult

if TYPE_CHECKING:
    from .result import ProcessorResult


def create_default_registry(
    api_base_url: Optional[str] = None,
    token: Optional[str] = None,
) -> ProcessorRegistry:
    """
    Create a ProcessorRegistry with default processors.

    Args:
        api_base_url: sbomify API base URL
        token: sbomify API token

    Returns:
        Configured ProcessorRegistry
    """
    registry = ProcessorRegistry()

    # Register the sbomify releases processor
    registry.register(
        SbomifyReleasesProcessor(
            api_base_url=api_base_url,
            token=token,
        )
    )

    # Future processors can be added here:
    # registry.register(SigningProcessor())
    # registry.register(AttestationProcessor())

    return registry


class ProcessorOrchestrator:
    """
    Main class for orchestrating post-upload SBOM processing.

    The ProcessorOrchestrator manages multiple processors and executes
    all enabled processors for a given input.

    Example:
        # Create orchestrator with sbomify config
        orchestrator = ProcessorOrchestrator(
            api_base_url="https://app.sbomify.com/api/v1",
            token="...",
        )

        # Process with all enabled processors
        results = orchestrator.process_all(ProcessorInput(
            sbom_id="sbom-123",
            product_releases=["product-id:v1.0.0"],
        ))

        # Process with a specific processor
        result = orchestrator.process(input, processor_name="releases")
    """

    def __init__(
        self,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        registry: Optional[ProcessorRegistry] = None,
    ) -> None:
        """
        Initialize the ProcessorOrchestrator.

        Args:
            api_base_url: sbomify API base URL
            token: sbomify API token
            registry: Optional custom registry (overrides other params)
        """
        if registry:
            self._registry = registry
        else:
            self._registry = create_default_registry(
                api_base_url=api_base_url,
                token=token,
            )

    @property
    def registry(self) -> ProcessorRegistry:
        """Get the processor registry."""
        return self._registry

    def process(
        self,
        input: ProcessorInput,
        processor_name: str,
    ) -> "ProcessorResult":
        """
        Execute a specific processor.

        Args:
            input: ProcessorInput with SBOM and configuration details
            processor_name: Name of processor to execute

        Returns:
            ProcessorResult from the processor
        """
        logger.info(f"Processing SBOM {input.sbom_id} with processor: {processor_name}")
        return self._registry.process(input, processor_name)

    def process_all(self, input: ProcessorInput) -> AggregateResult:
        """
        Execute all enabled processors.

        Args:
            input: ProcessorInput with SBOM and configuration details

        Returns:
            AggregateResult with results from all processors
        """
        enabled = self._registry.get_enabled_processors(input)
        logger.info(
            f"Processing SBOM {input.sbom_id} with {len(enabled)} enabled processor(s): {[p.name for p in enabled]}"
        )

        return self._registry.process_all(input)

    def get_enabled_processors(self, input: ProcessorInput) -> List[str]:
        """
        Get names of all processors enabled for the given input.

        Args:
            input: ProcessorInput to check against

        Returns:
            List of processor names that are enabled
        """
        return [p.name for p in self._registry.get_enabled_processors(input)]

    def list_all_processors(self) -> List[str]:
        """
        List all registered processors.

        Returns:
            List of processor names
        """
        return [p["name"] for p in self._registry.list_processors()]
