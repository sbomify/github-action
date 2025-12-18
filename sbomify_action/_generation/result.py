"""GenerationResult dataclass for SBOM generation output."""

from dataclasses import dataclass
from typing import Optional

from .protocol import SBOMFormat


@dataclass
class GenerationResult:
    """
    Result of an SBOM generation operation.

    Attributes:
        success: Whether generation completed successfully
        output_file: Path to the generated SBOM file (if successful)
        sbom_format: The format of the generated SBOM
        spec_version: The spec version of the generated SBOM
        generator_name: Name of the generator that produced the SBOM
        error_message: Error message if generation failed
        validated: Whether the SBOM was validated against its schema
        validation_error: Validation error message if validation failed
    """

    success: bool
    output_file: Optional[str]
    sbom_format: SBOMFormat
    spec_version: str
    generator_name: str
    error_message: Optional[str] = None
    validated: bool = False
    validation_error: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate result state."""
        if self.success and not self.output_file:
            raise ValueError("Successful result must have output_file")
        if not self.success and not self.error_message:
            raise ValueError("Failed result must have error_message")

    @property
    def is_valid(self) -> bool:
        """Check if generation was successful and SBOM is valid."""
        return self.success and self.validated and self.validation_error is None

    @classmethod
    def success_result(
        cls,
        output_file: str,
        sbom_format: SBOMFormat,
        spec_version: str,
        generator_name: str,
        validated: bool = False,
        validation_error: Optional[str] = None,
    ) -> "GenerationResult":
        """Create a successful generation result."""
        return cls(
            success=True,
            output_file=output_file,
            sbom_format=sbom_format,
            spec_version=spec_version,
            generator_name=generator_name,
            error_message=None,
            validated=validated,
            validation_error=validation_error,
        )

    @classmethod
    def failure_result(
        cls,
        error_message: str,
        sbom_format: SBOMFormat,
        spec_version: str,
        generator_name: str,
    ) -> "GenerationResult":
        """Create a failed generation result."""
        return cls(
            success=False,
            output_file=None,
            sbom_format=sbom_format,
            spec_version=spec_version,
            generator_name=generator_name,
            error_message=error_message,
            validated=False,
            validation_error=None,
        )
