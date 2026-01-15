"""Tool availability checks for external SBOM generators.

This module provides functions to check if external tools required for
SBOM generation are available on the system. When tools are missing,
it provides helpful installation instructions.

For pip-installed users, external tools are optional but recommended
for full functionality. The Docker image includes all tools pre-installed.
"""

import shutil
from dataclasses import dataclass, field
from typing import Optional

from .logging_config import logger


@dataclass
class ToolInfo:
    """Information about an external tool."""

    name: str
    command: str
    description: str
    install_instructions: str
    homepage: str
    required_for: list[str] = field(default_factory=list)


# Tool definitions with installation instructions
EXTERNAL_TOOLS: dict[str, ToolInfo] = {
    "trivy": ToolInfo(
        name="Trivy",
        command="trivy",
        description="Comprehensive vulnerability scanner and SBOM generator",
        install_instructions=(
            "Install via package manager:\n"
            "  - macOS: brew install trivy\n"
            "  - Linux: See https://aquasecurity.github.io/trivy/latest/getting-started/installation/\n"
            "  - Docker: docker pull aquasec/trivy"
        ),
        homepage="https://trivy.dev",
        required_for=["Docker images", "Many lockfile types"],
    ),
    "syft": ToolInfo(
        name="Syft",
        command="syft",
        description="SBOM generator with broad ecosystem support",
        install_instructions=(
            "Install via package manager:\n"
            "  - macOS: brew install syft\n"
            "  - Linux: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin\n"
            "  - Docker: docker pull anchore/syft"
        ),
        homepage="https://github.com/anchore/syft",
        required_for=["Docker images", "Many lockfile types", "Terraform"],
    ),
    "cdxgen": ToolInfo(
        name="cdxgen",
        command="cdxgen",
        description="CycloneDX SBOM generator with extensive language support",
        install_instructions=(
            "Install via npm/bun:\n"
            "  - npm: npm install -g @cyclonedx/cdxgen\n"
            "  - bun: bun install -g @cyclonedx/cdxgen\n"
            "  - Docker: docker pull ghcr.io/cyclonedx/cdxgen"
        ),
        homepage="https://github.com/CycloneDX/cdxgen",
        required_for=["Java/Gradle projects", "Docker images", "Many lockfile types"],
    ),
    "cyclonedx-py": ToolInfo(
        name="cyclonedx-py",
        command="cyclonedx-py",
        description="Native CycloneDX generator for Python projects",
        install_instructions=("Install via pip:\n  - pip install cyclonedx-bom\n  - uv pip install cyclonedx-bom"),
        homepage="https://github.com/CycloneDX/cyclonedx-python",
        required_for=["Python lockfiles (requirements.txt, poetry.lock, Pipfile.lock)"],
    ),
}


@dataclass
class ToolStatus:
    """Status of an external tool."""

    name: str
    available: bool
    path: Optional[str] = None
    info: Optional[ToolInfo] = None


def check_tool_available(command: str) -> tuple[bool, Optional[str]]:
    """
    Check if a command-line tool is available on the system.

    Args:
        command: The command to check (e.g., "trivy", "syft")

    Returns:
        Tuple of (is_available, path_if_found)
    """
    path = shutil.which(command)
    return (path is not None, path)


def check_all_tools() -> dict[str, ToolStatus]:
    """
    Check availability of all external tools.

    Returns:
        Dictionary mapping tool names to their status
    """
    results = {}
    for tool_id, info in EXTERNAL_TOOLS.items():
        available, path = check_tool_available(info.command)
        results[tool_id] = ToolStatus(
            name=info.name,
            available=available,
            path=path,
            info=info,
        )
    return results


def get_available_tools() -> list[str]:
    """
    Get list of available tool IDs.

    Returns:
        List of tool IDs that are installed
    """
    statuses = check_all_tools()
    return [tool_id for tool_id, status in statuses.items() if status.available]


def get_missing_tools() -> list[str]:
    """
    Get list of missing tool IDs.

    Returns:
        List of tool IDs that are not installed
    """
    statuses = check_all_tools()
    return [tool_id for tool_id, status in statuses.items() if not status.available]


def log_tool_status(verbose: bool = False) -> None:
    """
    Log the status of all external tools.

    Args:
        verbose: If True, show installation instructions for missing tools
    """
    statuses = check_all_tools()
    available = [s for s in statuses.values() if s.available]
    missing = [s for s in statuses.values() if not s.available]

    if available:
        logger.info(f"Available SBOM generators: {', '.join(s.name for s in available)}")

    if missing:
        logger.warning(f"Missing SBOM generators: {', '.join(s.name for s in missing)}")
        if verbose:
            logger.info("Some SBOM generation features may be limited.")
            logger.info("Install missing tools for full functionality:")
            for status in missing:
                if status.info:
                    logger.info(f"\n{status.info.name}:")
                    logger.info(f"  {status.info.install_instructions}")


def get_tool_install_message(tool_ids: list[str]) -> str:
    """
    Get a formatted message with installation instructions for specific tools.

    Args:
        tool_ids: List of tool IDs to include

    Returns:
        Formatted installation instructions string
    """
    lines = ["To enable this feature, install the required tool(s):", ""]
    for tool_id in tool_ids:
        if tool_id in EXTERNAL_TOOLS:
            info = EXTERNAL_TOOLS[tool_id]
            lines.append(f"{info.name} ({info.homepage})")
            lines.append(info.install_instructions)
            lines.append("")
    return "\n".join(lines)


def check_tool_for_input(input_type: str, lock_file: Optional[str] = None) -> tuple[list[str], list[str]]:
    """
    Check which tools can handle a specific input type.

    Args:
        input_type: Type of input ("docker_image", "lock_file", "sbom_file")
        lock_file: If input_type is "lock_file", the filename

    Returns:
        Tuple of (available_tool_ids, missing_tool_ids) that can handle this input
    """
    statuses = check_all_tools()

    # Map input types to tools that can handle them
    if input_type == "docker_image":
        relevant_tools = ["trivy", "syft", "cdxgen"]
    elif input_type == "lock_file" and lock_file:
        # Determine which tools can handle this lock file
        filename = lock_file.split("/")[-1] if "/" in lock_file else lock_file
        if filename in ("requirements.txt", "poetry.lock", "pyproject.toml", "Pipfile.lock", "uv.lock"):
            # Python files - cyclonedx-py is native, others can also handle
            relevant_tools = ["cyclonedx-py", "cdxgen", "trivy", "syft"]
        elif filename in ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"):
            # Java - cdxgen is best
            relevant_tools = ["cdxgen", "trivy", "syft"]
        elif filename == "pubspec.lock":
            # Dart - cdxgen and syft support it, trivy doesn't
            relevant_tools = ["cdxgen", "syft"]
        elif filename == ".terraform.lock.hcl":
            # Terraform - only syft
            relevant_tools = ["syft"]
        else:
            # General lockfiles
            relevant_tools = ["cdxgen", "trivy", "syft"]
    elif input_type == "sbom_file":
        # No external tools needed for existing SBOMs
        return ([], [])
    else:
        relevant_tools = ["trivy", "syft", "cdxgen"]

    available = [t for t in relevant_tools if statuses.get(t, ToolStatus(t, False)).available]
    missing = [t for t in relevant_tools if not statuses.get(t, ToolStatus(t, False)).available]

    return (available, missing)


def format_no_tools_error(input_type: str, lock_file: Optional[str] = None) -> str:
    """
    Format an error message when no tools are available for a given input.

    Args:
        input_type: Type of input ("docker_image", "lock_file")
        lock_file: If input_type is "lock_file", the filename

    Returns:
        Formatted error message with installation instructions
    """
    available, missing = check_tool_for_input(input_type, lock_file)

    if available:
        # This shouldn't happen if called correctly, but handle it gracefully
        return f"Tools available but generation failed: {', '.join(available)}"

    if input_type == "docker_image":
        input_desc = "Docker images"
    elif input_type == "lock_file" and lock_file:
        input_desc = f"'{lock_file}'"
    else:
        input_desc = "this input"

    lines = [
        f"No SBOM generators available for {input_desc}.",
        "",
        "sbomify-action requires external tools for SBOM generation.",
        "The Docker image (sbomifyhub/sbomify-action) includes all tools pre-installed.",
        "",
        "For pip installations, install one or more of these tools:",
        "",
    ]

    for tool_id in missing:
        if tool_id in EXTERNAL_TOOLS:
            info = EXTERNAL_TOOLS[tool_id]
            lines.append(f"  {info.name}:")
            for install_line in info.install_instructions.split("\n"):
                lines.append(f"    {install_line}")
            lines.append("")

    return "\n".join(lines)
