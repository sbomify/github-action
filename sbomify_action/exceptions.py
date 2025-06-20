"""Custom exceptions for sbomify-action."""


class SbomifyError(Exception):
    """Base exception for all sbomify operations."""


class ConfigurationError(SbomifyError):
    """Raised when configuration validation fails."""


class SBOMGenerationError(SbomifyError):
    """Raised when SBOM generation fails."""


class SBOMValidationError(SbomifyError):
    """Raised when SBOM validation fails."""


class APIError(SbomifyError):
    """Raised when API operations fail."""


class FileProcessingError(SbomifyError):
    """Raised when file operations fail."""
