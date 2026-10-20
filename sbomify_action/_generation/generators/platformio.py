"""Read the libraries PlatformIO installed for a project.

Priority: 10 (native, authoritative)

No other generator understands PlatformIO: cdxgen, syft and trivy have no
cataloger for it, so an Arduino or ESP32 project had no way to produce an SBOM
short of hand-munging each library's `library.json` into CycloneDX.

The input is `platformio.ini`, and what is read is the `.piopm` metadata
PlatformIO's package manager wrote for each library under `.pio/libdeps/` --
see `sbomify_action._platformio`. That directory exists only after
`pio pkg install` (or a build), so in CI this runs after the build step.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sbomify_action._platformio import PLATFORMIO_INI, InstalledLibrary, declared_lib_deps, installed_libraries
from sbomify_action.logging_config import logger

from ..protocol import (
    CYCLONEDX_VERSIONS,
    SPDX_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import convert_to_spdx

CYCLONEDX_DEFAULT_VERSION = "1.6"
SPDX_DEFAULT_VERSION = "2.3"


def _component(library: InstalledLibrary) -> dict[str, Any]:
    purl = library.purl
    component: dict[str, Any] = {
        "type": "library",
        "name": library.name,
        "version": library.version,
        "purl": purl,
        "bom-ref": purl,
    }
    if library.owner:
        component["group"] = library.owner
    if library.uri:
        component["externalReferences"] = [{"type": "vcs", "url": library.uri}]
    return component


class PlatformIOGenerator:
    """Native reader for a PlatformIO project's installed libraries."""

    @property
    def name(self) -> str:
        return "platformio"

    @property
    def command(self) -> str:
        return ""  # nothing to run: PlatformIO already recorded the answer

    @property
    def priority(self) -> int:
        return 10

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(format="cyclonedx", versions=CYCLONEDX_VERSIONS, default_version=CYCLONEDX_DEFAULT_VERSION),
            FormatVersion(format="spdx", versions=SPDX_VERSIONS, default_version=SPDX_DEFAULT_VERSION),
        ]

    def supports(self, input: GenerationInput) -> bool:
        if not input.is_lock_file or input.lock_file_name != PLATFORMIO_INI:
            return False
        if input.output_format not in ("cyclonedx", "spdx"):
            return False
        allowed = SPDX_VERSIONS if input.output_format == "spdx" else CYCLONEDX_VERSIONS
        return not (input.spec_version and input.spec_version not in allowed)

    def generate(self, input: GenerationInput) -> GenerationResult:
        assert input.lock_file is not None  # guaranteed by supports()
        source = Path(input.lock_file)
        libraries = installed_libraries(source)
        if not libraries:
            if declared_lib_deps(source):
                message = (
                    f"{source.name} declares lib_deps but none are installed. "
                    "Run `pio pkg install` (or build) before generating the SBOM."
                )
            else:
                message = f"{source.name} declares no lib_deps"
            return GenerationResult.failure_result(
                error_message=message,
                sbom_format=input.output_format,
                spec_version=input.spec_version or "",
                generator_name=self.name,
            )

        version = input.spec_version or (
            SPDX_DEFAULT_VERSION if input.output_format == "spdx" else CYCLONEDX_DEFAULT_VERSION
        )
        cyclonedx_version = CYCLONEDX_DEFAULT_VERSION if input.output_format == "spdx" else version
        project = source.resolve().parent.name or "platformio-project"
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": cyclonedx_version,
            "version": 1,
            "metadata": {
                "component": {
                    "type": "firmware",
                    "name": project,
                    "bom-ref": f"root-{project}",
                }
            },
            "components": [_component(library) for library in libraries],
        }

        output = Path(input.output_file)
        output.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Read {len(libraries)} installed PlatformIO libraries for {source.name}")

        if input.output_format == "spdx":
            # Written beside the output rather than in the project, which may
            # be read-only and is not ours to litter.
            staging = output.parent / f".{output.name}.cdx.json"
            staging.write_text(json.dumps(document, indent=2))
            try:
                convert_to_spdx(staging, output, source.parent)
            finally:
                staging.unlink(missing_ok=True)
        else:
            output.write_text(json.dumps(document, indent=2))

        return GenerationResult.success_result(
            output_file=str(output),
            sbom_format=input.output_format,
            spec_version=version,
            generator_name=self.name,
        )
