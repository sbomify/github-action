"""cdxgen generator plugins for filesystem and Docker image scanning.

Priority: 20 (comprehensive multi-ecosystem)

cdxgen is a comprehensive SBOM generator that supports many ecosystems
and programming languages with excellent coverage.

Verified capabilities (cdxgen 12.0.0):
- CycloneDX versions: 1.4, 1.5, 1.6, 1.7 (default: 1.6)
- SPDX: Not supported (cdxgen only outputs CycloneDX format)
- Version selection: --spec-version
"""

from pathlib import Path

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger

from ..protocol import (
    CDXGEN_CYCLONEDX_DEFAULT,
    CDXGEN_CYCLONEDX_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import CDXGEN_LOCK_FILES, run_command


class CdxgenFsGenerator:
    """
    cdxgen filesystem scanner for lock files.

    Uses cdxgen to scan lock files and generate SBOMs. Supports
    all ecosystems that cdxgen supports with version selection.

    Verified capabilities (cdxgen 12.0.0):
    - CycloneDX versions: 1.4, 1.5, 1.6, 1.7 (default: 1.6)
    - SPDX: Not supported
    - Version selection: --spec-version
    """

    @property
    def name(self) -> str:
        return "cdxgen-fs"

    @property
    def priority(self) -> int:
        # Comprehensive multi-ecosystem, higher priority than Trivy/Syft
        return 20

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=CDXGEN_CYCLONEDX_VERSIONS,
                default_version=CDXGEN_CYCLONEDX_DEFAULT,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports all lock files for CycloneDX format only.
        Does not support SPDX or Docker images (use CdxgenImageGenerator).
        """
        # Only supports lock files
        if not input.is_lock_file:
            return False

        # Check if it's a supported lock file for cdxgen
        if input.lock_file_name not in CDXGEN_LOCK_FILES:
            return False

        # Only supports CycloneDX format (cdxgen doesn't output SPDX)
        if input.output_format != "cyclonedx":
            return False

        # Check version if specified
        if input.spec_version:
            if input.spec_version not in CDXGEN_CYCLONEDX_VERSIONS:
                return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate an SBOM using cdxgen command."""
        version = input.spec_version or CDXGEN_CYCLONEDX_DEFAULT

        # Get the directory containing the lock file
        lock_file_path = Path(input.lock_file)
        scan_path = str(lock_file_path.parent) if lock_file_path.parent != Path(".") else "."

        cmd = [
            "cdxgen",
            "-o",
            input.output_file,
            "--spec-version",
            version,
            scan_path,
        ]

        logger.info(f"Running cdxgen for {input.lock_file_name} (cyclonedx {version})")

        try:
            result = run_command(cmd, "cdxgen", timeout=600)

            if result.returncode == 0:
                # Verify output file was created
                if not Path(input.output_file).exists():
                    return GenerationResult.failure_result(
                        error_message="cdxgen completed but output file not created",
                        sbom_format="cyclonedx",
                        spec_version=version,
                        generator_name=self.name,
                    )

                return GenerationResult.success_result(
                    output_file=input.output_file,
                    sbom_format="cyclonedx",
                    spec_version=version,
                    generator_name=self.name,
                )
            else:
                return GenerationResult.failure_result(
                    error_message=f"cdxgen failed with return code {result.returncode}",
                    sbom_format="cyclonedx",
                    spec_version=version,
                    generator_name=self.name,
                )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format="cyclonedx",
                spec_version=input.spec_version or CDXGEN_CYCLONEDX_DEFAULT,
                generator_name=self.name,
            )


class CdxgenImageGenerator:
    """
    cdxgen Docker image scanner.

    Uses cdxgen to scan Docker images and generate SBOMs.

    Verified capabilities (cdxgen 12.0.0):
    - CycloneDX versions: 1.4, 1.5, 1.6, 1.7 (default: 1.6)
    - SPDX: Not supported
    - Version selection: --spec-version
    - Image scanning: -t oci
    """

    @property
    def name(self) -> str:
        return "cdxgen-image"

    @property
    def priority(self) -> int:
        # Comprehensive multi-ecosystem, higher priority than Trivy/Syft
        return 20

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=CDXGEN_CYCLONEDX_VERSIONS,
                default_version=CDXGEN_CYCLONEDX_DEFAULT,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        """
        Check if this generator supports the given input.

        Supports Docker images for CycloneDX format only.
        Does not support SPDX or lock files (use CdxgenFsGenerator).
        """
        # Only supports Docker images
        if not input.is_docker_image:
            return False

        # Only supports CycloneDX format (cdxgen doesn't output SPDX)
        if input.output_format != "cyclonedx":
            return False

        # Check version if specified
        if input.spec_version:
            if input.spec_version not in CDXGEN_CYCLONEDX_VERSIONS:
                return False

        return True

    def generate(self, input: GenerationInput) -> GenerationResult:
        """Generate an SBOM using cdxgen command for Docker images."""
        version = input.spec_version or CDXGEN_CYCLONEDX_DEFAULT

        cmd = [
            "cdxgen",
            "-t",
            "oci",
            "-o",
            input.output_file,
            "--spec-version",
            version,
            input.docker_image,
        ]

        logger.info(f"Running cdxgen for {input.docker_image} (cyclonedx {version})")

        try:
            result = run_command(cmd, "cdxgen", timeout=600)

            if result.returncode == 0:
                # Verify output file was created
                if not Path(input.output_file).exists():
                    return GenerationResult.failure_result(
                        error_message="cdxgen completed but output file not created",
                        sbom_format="cyclonedx",
                        spec_version=version,
                        generator_name=self.name,
                    )

                return GenerationResult.success_result(
                    output_file=input.output_file,
                    sbom_format="cyclonedx",
                    spec_version=version,
                    generator_name=self.name,
                )
            else:
                return GenerationResult.failure_result(
                    error_message=f"cdxgen failed with return code {result.returncode}",
                    sbom_format="cyclonedx",
                    spec_version=version,
                    generator_name=self.name,
                )
        except SBOMGenerationError as e:
            return GenerationResult.failure_result(
                error_message=str(e),
                sbom_format="cyclonedx",
                spec_version=input.spec_version or CDXGEN_CYCLONEDX_DEFAULT,
                generator_name=self.name,
            )
