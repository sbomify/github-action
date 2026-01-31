"""Registry for lockfile hash parsers."""

from pathlib import Path

from ..logging_config import logger
from .models import PackageHash
from .protocol import LockfileHashParser


class ParserRegistry:
    """Registry for lockfile hash parsers.

    Manages parser instances and dispatches parsing to the appropriate
    parser based on lockfile name.

    Example:
        registry = ParserRegistry()
        registry.register(UvLockParser())
        registry.register(CargoLockParser())

        hashes = registry.parse_lockfile(Path("uv.lock"))
    """

    def __init__(self) -> None:
        self._parsers: list[LockfileHashParser] = []

    def register(self, parser: LockfileHashParser) -> None:
        """Register a parser.

        Args:
            parser: Parser instance implementing LockfileHashParser protocol.
        """
        self._parsers.append(parser)
        logger.debug(f"Registered hash parser: {parser.name} for {parser.supported_files}")

    def get_parser_for(self, lock_file_name: str) -> LockfileHashParser | None:
        """Get the parser that supports this lockfile.

        Args:
            lock_file_name: Filename (not full path) to find parser for

        Returns:
            Parser instance if found, None otherwise.
        """
        for parser in self._parsers:
            if parser.supports(lock_file_name):
                return parser
        return None

    def parse_lockfile(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse a lockfile using the appropriate parser.

        Args:
            lock_file_path: Full path to the lockfile

        Returns:
            List of PackageHash objects extracted from the lockfile.
            Empty list if no parser found or no hashes extracted.
        """
        lock_file_name = lock_file_path.name
        parser = self.get_parser_for(lock_file_name)

        if parser is None:
            logger.debug(f"No hash parser found for lockfile: {lock_file_name}")
            return []

        logger.debug(f"Using {parser.name} to parse {lock_file_name}")
        try:
            hashes = parser.parse(lock_file_path)
            logger.debug(f"Extracted {len(hashes)} hash(es) from {lock_file_name}")
            return hashes
        except Exception as e:
            logger.warning(f"Failed to parse {lock_file_name} for hashes: {e}")
            return []

    @property
    def registered_parsers(self) -> list[str]:
        """Get names of all registered parsers."""
        return [p.name for p in self._parsers]

    @property
    def supported_files(self) -> set[str]:
        """Get all supported lockfile names."""
        result: set[str] = set()
        for parser in self._parsers:
            result.update(parser.supported_files)
        return result
