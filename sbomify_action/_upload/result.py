"""UploadResult dataclass for SBOM upload output."""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class UploadResult:
    """
    Result of an SBOM upload operation.

    Attributes:
        success: Whether upload completed successfully
        destination_name: Name of the destination that handled the upload
        sbom_id: ID of the uploaded SBOM (if destination returns one)
        error_message: Error message if upload failed
        validated: Whether the SBOM was validated before upload
        validation_error: Validation error message if validation failed
        metadata: Additional destination-specific metadata from the response
    """

    success: bool
    destination_name: str
    sbom_id: Optional[str] = None
    error_message: Optional[str] = None
    validated: bool = False
    validation_error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate result state."""
        if self.success and self.error_message:
            raise ValueError("Successful result should not have error_message")
        if not self.success and not self.error_message:
            raise ValueError("Failed result must have error_message")

    @property
    def has_sbom_id(self) -> bool:
        """Check if an SBOM ID was returned from the destination."""
        return self.sbom_id is not None

    @classmethod
    def success_result(
        cls,
        destination_name: str,
        sbom_id: Optional[str] = None,
        validated: bool = False,
        validation_error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "UploadResult":
        """Create a successful upload result."""
        return cls(
            success=True,
            destination_name=destination_name,
            sbom_id=sbom_id,
            error_message=None,
            validated=validated,
            validation_error=validation_error,
            metadata=metadata or {},
        )

    @classmethod
    def failure_result(
        cls,
        destination_name: str,
        error_message: str,
        validated: bool = False,
        validation_error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "UploadResult":
        """Create a failed upload result."""
        return cls(
            success=False,
            destination_name=destination_name,
            sbom_id=None,
            error_message=error_message,
            validated=validated,
            validation_error=validation_error,
            metadata=metadata or {},
        )
