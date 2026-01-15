"""Processor registry for managing SBOM processor plugins."""

from typing import Any, Dict, List, Optional

from sbomify_action.logging_config import logger

from .protocol import ProcessorInput, SBOMProcessor
from .result import AggregateResult, ProcessorResult


class ProcessorRegistry:
    """
    Registry for managing SBOM processor plugins.

    The registry maintains a collection of available processors and provides
    methods to execute enabled processors on a given input.

    Example:
        registry = ProcessorRegistry()
        registry.register(ReleasesProcessor(api_base_url="...", token="..."))
        registry.register(SigningProcessor())

        # Process with all enabled processors
        results = registry.process_all(input)

        # Process with a specific processor
        result = registry.process(input, processor_name="releases")
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._processors: Dict[str, SBOMProcessor] = {}

    def register(self, processor: SBOMProcessor) -> None:
        """
        Register a processor.

        Args:
            processor: SBOMProcessor implementation to register
        """
        self._processors[processor.name] = processor
        logger.debug(f"Registered processor: {processor.name}")

    def get(self, name: str) -> Optional[SBOMProcessor]:
        """
        Get a processor by name.

        Args:
            name: Name of the processor

        Returns:
            Processor if found, None otherwise
        """
        return self._processors.get(name)

    def get_enabled_processors(self, input: ProcessorInput) -> List[SBOMProcessor]:
        """
        Get all processors that are enabled for the given input.

        Args:
            input: ProcessorInput to check against

        Returns:
            List of enabled SBOMProcessor instances
        """
        return [p for p in self._processors.values() if p.is_enabled(input)]

    def process(self, input: ProcessorInput, processor_name: str) -> ProcessorResult:
        """
        Execute a specific processor.

        Args:
            input: ProcessorInput with SBOM and configuration details
            processor_name: Name of processor to execute

        Returns:
            ProcessorResult from the processor

        Raises:
            ValueError: If processor not found
        """
        processor = self._processors.get(processor_name)
        if not processor:
            available = list(self._processors.keys())
            raise ValueError(f"Processor '{processor_name}' not found. Available processors: {available}")

        if not processor.is_enabled(input):
            return ProcessorResult.skipped_result(
                processor_name=processor_name,
                reason=f"Processor '{processor_name}' is not enabled for this input",
            )

        return self._execute_processor(processor, input)

    def process_all(self, input: ProcessorInput) -> AggregateResult:
        """
        Execute all enabled processors.

        Args:
            input: ProcessorInput with SBOM and configuration details

        Returns:
            AggregateResult with results from all processors
        """
        aggregate = AggregateResult()

        for processor in self._processors.values():
            if processor.is_enabled(input):
                result = self._execute_processor(processor, input)
            else:
                result = ProcessorResult.skipped_result(
                    processor_name=processor.name,
                    reason="Not enabled for this input",
                )
            aggregate.add(result)

        return aggregate

    def _execute_processor(self, processor: SBOMProcessor, input: ProcessorInput) -> ProcessorResult:
        """Execute a processor with error handling."""
        logger.info(f"Executing processor: {processor.name}")
        try:
            result = processor.process(input)
            if result.success:
                logger.info(f"Processor {processor.name} completed successfully")
            else:
                logger.warning(f"Processor {processor.name} failed: {result.error_message}")
            return result
        except Exception as e:
            logger.error(f"Processor {processor.name} raised exception: {e}")
            return ProcessorResult.failure_result(
                processor_name=processor.name,
                error_message=str(e),
            )

    def list_processors(self) -> List[Dict[str, Any]]:
        """
        List all registered processors.

        Returns:
            List of dicts with processor info
        """
        return [
            {
                "name": name,
            }
            for name in sorted(self._processors.keys())
        ]

    def clear(self) -> None:
        """Remove all registered processors."""
        self._processors.clear()
