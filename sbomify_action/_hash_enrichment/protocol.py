"""Protocol definition for lockfile hash parsers."""

from pathlib import Path
from typing import Protocol

from .models import PackageHash


class LockfileHashParser(Protocol):
    """Protocol for lockfile hash extraction plugins.

    Each parser implements this protocol to extract hashes from a
    specific lockfile format. Parsers are registered with ParserRegistry
    and selected based on the lockfile name.

    Example:
        class UvLockParser:
            name = "uv-lock"
            supported_files = ("uv.lock",)

            def supports(self, lock_file_name: str) -> bool:
                return lock_file_name in self.supported_files

            def parse(self, lock_file_path: Path) -> list[PackageHash]:
                # Parse uv.lock and return hashes
                ...
    """

    @property
    def name(self) -> str:
        """Human-readable name of this parser.

        Used for logging and diagnostics.
        Examples: "uv-lock", "cargo-lock", "npm-package-lock"
        """
        ...

    @property
    def supported_files(self) -> tuple[str, ...]:
        """Lock file names this parser handles.

        Each entry is a filename (not a path), e.g., "uv.lock", "Cargo.lock".
        A parser may support multiple filenames.
        """
        ...

    @property
    def ecosystem(self) -> str:
        """Ecosystem identifier for package name normalization.

        Used by normalize_package_name() for matching.
        Examples: "pypi", "npm", "cargo", "pub"
        """
        ...

    def supports(self, lock_file_name: str) -> bool:
        """Check if this parser can handle the given lockfile.

        Args:
            lock_file_name: Filename (not full path) to check

        Returns:
            True if this parser can parse the file.
        """
        ...

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse lockfile and extract all package hashes.

        Implementations should:
        1. Read the lockfile
        2. Extract package name, version, and hash(es) for each package
        3. Return PackageHash objects for all found hashes

        Args:
            lock_file_path: Full path to the lockfile

        Returns:
            List of PackageHash objects. Empty list if no hashes found.

        Raises:
            FileProcessingError: If lockfile cannot be read or parsed.
        """
        ...
