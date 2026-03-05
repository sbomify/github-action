"""Custom hatch build hook to ensure SBOM placeholder exists for local builds.

In CI, the real SBOM is generated before building. Locally, we create a
minimal valid CycloneDX placeholder so hatchling's sbom-files doesn't fail.
"""

from __future__ import annotations

import json
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

SBOM_FILE = "sbomify-action.cdx.json"

PLACEHOLDER = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "sbomify-action",
            "description": "Placeholder SBOM — replaced during CI build",
        }
    },
    "components": [],
}


class SBOMBuildHook(BuildHookInterface):
    PLUGIN_NAME = "sbom-placeholder"

    def initialize(self, version: str, build_data: dict) -> None:  # noqa: ARG002
        sbom_path = Path(self.root) / SBOM_FILE
        if not sbom_path.exists():
            sbom_path.write_text(json.dumps(PLACEHOLDER, indent=2) + "\n")
