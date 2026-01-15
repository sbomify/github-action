"""SBOM Processor plugin system for post-upload operations.

This module provides an extensible plugin architecture for operations
that occur after an SBOM has been uploaded, such as:
- Tagging releases with SBOMs
- Signing SBOMs
- Creating attestations

Example:
    from sbomify_action._processors import ProcessorOrchestrator, ProcessorInput

    orchestrator = ProcessorOrchestrator(
        api_base_url="https://app.sbomify.com/api/v1",
        token="your-token",
    )

    input = ProcessorInput(
        sbom_id="sbom-123",
        product_releases=["product-id:v1.0.0"],
    )

    results = orchestrator.process_all(input)
"""

from .orchestrator import ProcessorOrchestrator, create_default_registry
from .processors import SbomifyReleasesProcessor
from .protocol import ProcessorInput, SBOMProcessor
from .registry import ProcessorRegistry
from .result import AggregateResult, ProcessorResult

__all__ = [
    # Main entry points
    "ProcessorOrchestrator",
    "ProcessorInput",
    "ProcessorResult",
    "AggregateResult",
    # Registry and protocol
    "ProcessorRegistry",
    "SBOMProcessor",
    # Factory
    "create_default_registry",
    # Processors
    "SbomifyReleasesProcessor",
]
