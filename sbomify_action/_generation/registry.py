"""Generator registry for managing SBOM generator plugins."""

from typing import Any, Dict, List, Optional

from sbomify_action.logging_config import logger
from sbomify_action.tool_checks import check_tool_for_input, format_no_tools_error
from sbomify_action.validation import validate_sbom_file

from .protocol import FormatVersion, GenerationInput, Generator
from .result import GenerationResult


class GeneratorRegistry:
    """
    Registry for managing and querying SBOM generator plugins.

    The registry maintains a list of generators and provides methods
    to find applicable generators for a given input, sorted by priority.

    Example:
        registry = GeneratorRegistry()
        registry.register(CycloneDXPyGenerator())
        registry.register(TrivyFsGenerator())
        registry.register(SyftFsGenerator())

        # Get generators for a Python requirements file
        input = GenerationInput(lock_file="requirements.txt", output_format="cyclonedx")
        generators = registry.get_generators_for(input)

        # Generate SBOM using first matching generator
        result = registry.generate(input)
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._generators: List[Generator] = []

    def register(self, generator: Generator) -> None:
        """
        Register a generator.

        Generators are stored and later sorted by priority when queried.

        Args:
            generator: Generator implementation to register
        """
        self._generators.append(generator)
        logger.debug(f"Registered generator: {generator.name} (priority={generator.priority})")

    def get_generators_for(self, input: GenerationInput) -> List[Generator]:
        """
        Get all applicable generators for an input, sorted by priority.

        Filters generators by:
        1. Input type support (lock file type, Docker image)
        2. Output format support
        3. Spec version support (if specified)

        Args:
            input: GenerationInput with file/image and format requirements

        Returns:
            List of Generator instances that support this input,
            sorted by priority (lowest/highest priority first)
        """
        applicable = []

        for generator in self._generators:
            # Check if generator supports this input type
            if not generator.supports(input):
                continue

            # Check if generator supports requested format
            format_match = self._supports_format(generator, input.output_format)
            if not format_match:
                continue

            # Check version support if specified
            if input.spec_version:
                if not self._supports_version(generator, input.output_format, input.spec_version):
                    logger.debug(
                        f"Generator {generator.name} doesn't support {input.output_format} version {input.spec_version}"
                    )
                    continue

            applicable.append(generator)

        # Sort by priority (lower = higher priority)
        return sorted(applicable, key=lambda g: g.priority)

    def generate(self, input: GenerationInput, validate: bool = True) -> GenerationResult:
        """
        Generate an SBOM using the first matching generator.

        Tries generators in priority order until one succeeds.
        Optionally validates the generated SBOM against its schema.

        Args:
            input: GenerationInput with all generation parameters
            validate: Whether to validate the generated SBOM (default: True)

        Returns:
            GenerationResult from the first successful generator

        Raises:
            ValueError: If no generator supports the input
        """
        generators = self.get_generators_for(input)

        if not generators:
            # Determine input type for error messages
            if input.is_docker_image:
                input_type = "docker_image"
            elif input.is_lock_file:
                input_type = "lock_file"
            else:
                # SBOM file input or other - these don't need generation tools
                raise ValueError(
                    f"No generator found for input. "
                    f"Requested: format={input.output_format}, version={input.spec_version}."
                )

            # Check if this is due to missing tools
            lock_file = input.lock_file if input.is_lock_file else None
            available_tools, missing_tools = check_tool_for_input(input_type, lock_file)

            if missing_tools and not available_tools:
                # No tools available - provide installation instructions
                error_msg = format_no_tools_error(input_type, lock_file)
                raise ValueError(error_msg)
            else:
                # Tools available but don't support this format/version
                available_formats = self._get_available_formats()
                raise ValueError(
                    f"No generator found for input. "
                    f"Requested: format={input.output_format}, version={input.spec_version}. "
                    f"Available formats: {available_formats}"
                )

        # Try generators in priority order
        last_error: Optional[str] = None
        for generator in generators:
            logger.info(f"Trying generator: {generator.name}")
            try:
                result = generator.generate(input)
                if result.success:
                    logger.info(f"Successfully generated SBOM with {generator.name}")

                    # Validate the generated SBOM
                    if validate and result.output_file:
                        result = self._validate_result(result)

                    return result
                else:
                    last_error = result.error_message
                    logger.warning(f"Generator {generator.name} failed: {result.error_message}")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Generator {generator.name} raised exception: {e}")

        # All generators failed - check if it's a tool availability issue
        spec_version = input.spec_version or "default"
        input_type = "docker_image" if input.is_docker_image else "lock_file"
        lock_file = input.lock_file if input.is_lock_file else None
        available_tools, missing_tools = check_tool_for_input(input_type, lock_file)

        if missing_tools:
            # Some tools are missing - suggest installation
            missing_names = ", ".join(missing_tools)
            error_message = (
                f"All available generators failed. Last error: {last_error}\n"
                f"Additional tools that could help: {missing_names}\n"
                f"Install them for more generation options."
            )
        else:
            error_message = f"All generators failed. Last error: {last_error}"

        return GenerationResult.failure_result(
            error_message=error_message,
            sbom_format=input.output_format,
            spec_version=spec_version,
            generator_name="none",
        )

    def _validate_result(self, result: GenerationResult) -> GenerationResult:
        """Validate a generation result and update with validation info."""
        if not result.output_file:
            return result

        validation_result = validate_sbom_file(
            result.output_file,
            result.sbom_format,
            result.spec_version,
        )

        if validation_result.valid:
            logger.info(f"SBOM validated successfully: {result.sbom_format} {result.spec_version}")
            return GenerationResult.success_result(
                output_file=result.output_file,
                sbom_format=result.sbom_format,
                spec_version=result.spec_version,
                generator_name=result.generator_name,
                validated=True,
                validation_error=None,
            )
        else:
            logger.warning(f"SBOM validation failed: {validation_result.error_message}")
            return GenerationResult.success_result(
                output_file=result.output_file,
                sbom_format=result.sbom_format,
                spec_version=result.spec_version,
                generator_name=result.generator_name,
                validated=True,
                validation_error=validation_result.error_message,
            )

    def _supports_format(self, generator: Generator, format: str) -> bool:
        """Check if generator supports a format."""
        for fv in generator.supported_formats:
            if fv.format == format:
                return True
        return False

    def _supports_version(self, generator: Generator, format: str, version: str) -> bool:
        """Check if generator supports a specific version of a format."""
        for fv in generator.supported_formats:
            if fv.format == format and fv.supports_version(version):
                return True
        return False

    def _get_format_version(self, generator: Generator, format: str) -> Optional[FormatVersion]:
        """Get the FormatVersion for a specific format from a generator."""
        for fv in generator.supported_formats:
            if fv.format == format:
                return fv
        return None

    def _get_available_formats(self) -> Dict[str, List[str]]:
        """Get all available formats and versions from registered generators."""
        formats: Dict[str, set] = {}
        for generator in self._generators:
            for fv in generator.supported_formats:
                if fv.format not in formats:
                    formats[fv.format] = set()
                formats[fv.format].update(fv.versions)
        return {f: sorted(v) for f, v in formats.items()}

    def list_generators(self) -> List[Dict[str, Any]]:
        """
        List all registered generators with their capabilities.

        Returns:
            List of dicts with generator info
        """
        result = []
        for g in sorted(self._generators, key=lambda x: x.priority):
            formats = []
            for fv in g.supported_formats:
                formats.append(
                    {
                        "format": fv.format,
                        "versions": list(fv.versions),
                        "default": fv.default_version,
                    }
                )
            result.append(
                {
                    "name": g.name,
                    "priority": g.priority,
                    "formats": formats,
                }
            )
        return result

    def clear(self) -> None:
        """Remove all registered generators."""
        self._generators.clear()
