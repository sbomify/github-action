"""Custom exceptions for sbomify-action."""


class SbomifyError(Exception):
    """Base exception for all sbomify operations."""


class ConfigurationError(SbomifyError):
    """Raised when configuration validation fails."""


class SBOMGenerationError(SbomifyError):
    """Raised when SBOM generation fails."""


class DockerImageNotFoundError(SBOMGenerationError):
    """Raised when a Docker image cannot be found in any registry.

    This error is raised when SBOM generation tools (trivy, syft, cdxgen) fail
    because the specified Docker image doesn't exist or the tag is invalid.

    Attributes:
        image: The Docker image that was not found
        message: Detailed error message
    """

    def __init__(self, image: str, message: str | None = None):
        self.image = image
        if message:
            super().__init__(message)
        else:
            super().__init__(
                f"Docker image '{image}' not found. Verify the image exists in the registry and the tag is correct."
            )


class SBOMValidationError(SbomifyError):
    """Raised when SBOM validation fails."""


class APIError(SbomifyError):
    """Raised when API operations fail."""


class FileProcessingError(SbomifyError):
    """Raised when file operations fail."""


class CommandExecutionError(SbomifyError):
    """Raised when external command execution fails."""
