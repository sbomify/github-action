"""ProcessorResult dataclass for SBOM processor output."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ProcessorResult:
    """
    Result of an SBOM processor operation.

    Attributes:
        success: Whether the operation completed successfully
        processor_name: Name of the processor that handled the operation
        error_message: Error message if operation failed
        processed_items: Number of items successfully processed (e.g., releases tagged)
        failed_items: Number of items that failed to process
        metadata: Additional processor-specific metadata from the operation
    """

    success: bool
    processor_name: str
    error_message: Optional[str] = None
    processed_items: int = 0
    failed_items: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate result state."""
        if self.success and self.error_message:
            raise ValueError("Successful result should not have error_message")
        if not self.success and not self.error_message:
            raise ValueError("Failed result must have error_message")

    @property
    def has_failures(self) -> bool:
        """Check if any items failed to process."""
        return self.failed_items > 0

    @property
    def total_items(self) -> int:
        """Get total number of items attempted."""
        return self.processed_items + self.failed_items

    @classmethod
    def success_result(
        cls,
        processor_name: str,
        processed_items: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ProcessorResult":
        """Create a successful processor result."""
        return cls(
            success=True,
            processor_name=processor_name,
            error_message=None,
            processed_items=processed_items,
            metadata=metadata or {},
        )

    @classmethod
    def failure_result(
        cls,
        processor_name: str,
        error_message: str,
        processed_items: int = 0,
        failed_items: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ProcessorResult":
        """Create a failed processor result."""
        return cls(
            success=False,
            processor_name=processor_name,
            error_message=error_message,
            processed_items=processed_items,
            failed_items=failed_items,
            metadata=metadata or {},
        )

    @classmethod
    def skipped_result(
        cls,
        processor_name: str,
        reason: str = "Not enabled",
    ) -> "ProcessorResult":
        """Create a result indicating the processor was skipped."""
        return cls(
            success=True,
            processor_name=processor_name,
            error_message=None,
            processed_items=0,
            metadata={"skipped": True, "skip_reason": reason},
        )


@dataclass
class AggregateResult:
    """
    Aggregated results from multiple processors.

    Attributes:
        results: List of individual ProcessorResult objects
        total_processed: Total items processed across all processors
        total_failed: Total items that failed across all processors
    """

    results: List[ProcessorResult] = field(default_factory=list)

    @property
    def total_processed(self) -> int:
        """Get total items processed across all processors."""
        return sum(r.processed_items for r in self.results)

    @property
    def total_failed(self) -> int:
        """Get total items that failed across all processors."""
        return sum(r.failed_items for r in self.results)

    @property
    def all_successful(self) -> bool:
        """Check if all processors completed successfully."""
        return all(r.success for r in self.results)

    @property
    def any_failures(self) -> bool:
        """Check if any processor had failures."""
        return any(not r.success or r.has_failures for r in self.results)

    @property
    def enabled_processors(self) -> List[ProcessorResult]:
        """Get results from processors that actually ran (not skipped)."""
        return [r for r in self.results if not r.metadata.get("skipped", False)]

    @property
    def skipped_processors(self) -> List[ProcessorResult]:
        """Get results from processors that were skipped."""
        return [r for r in self.results if r.metadata.get("skipped", False)]

    def add(self, result: ProcessorResult) -> None:
        """Add a processor result to the aggregate."""
        self.results.append(result)
