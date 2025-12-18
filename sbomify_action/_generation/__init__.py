"""SBOM Generation Plugin Architecture.

This module provides a plugin-based system for SBOM generation supporting:
- Multiple generator implementations (cyclonedx-py, Trivy, Syft)
- Multiple output formats (CycloneDX, SPDX)
- Spec version selection
- Priority-based generator selection
- Schema validation after generation

Usage:
    from sbomify_action._generation import (
        GeneratorOrchestrator,
        GenerationInput,
        GenerationResult,
        create_default_registry,
    )

    orchestrator = GeneratorOrchestrator()
    result = orchestrator.generate(GenerationInput(
        lock_file="requirements.txt",
        output_file="sbom.json",
        output_format="cyclonedx",
        spec_version="1.6",
    ))
"""

# Re-export validation from parent module for convenience
from sbomify_action.validation import (
    ValidationResult,
    validate_sbom_data,
    validate_sbom_file,
    validate_sbom_file_auto,
)

from .generator import GeneratorOrchestrator, create_default_registry
from .protocol import (
    # Version constants
    CYCLONEDX_VERSIONS,
    SPDX_VERSIONS,
    # Types
    FormatVersion,
    GenerationInput,
    Generator,
    SBOMFormat,
)
from .registry import GeneratorRegistry
from .result import GenerationResult

__all__ = [
    # Core types
    "SBOMFormat",
    "FormatVersion",
    "GenerationInput",
    "GenerationResult",
    "Generator",
    # Version constants
    "CYCLONEDX_VERSIONS",
    "SPDX_VERSIONS",
    # Registry and orchestration
    "GeneratorRegistry",
    "GeneratorOrchestrator",
    "create_default_registry",
    # Validation (re-exported from sbomify_action.validation)
    "ValidationResult",
    "validate_sbom_data",
    "validate_sbom_file",
    "validate_sbom_file_auto",
]
