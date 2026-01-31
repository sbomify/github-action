"""Main wizard runner that orchestrates the sbomify.json generation."""

import json
import shutil
from pathlib import Path
from typing import Any

from questionary import Choice
from rich.json import JSON
from rich.panel import Panel

from sbomify_action.cli.wizard.prompts import (
    GoBack,
    ask_confirm,
    ask_select,
    print_info,
    print_success,
    print_warning,
)
from sbomify_action.cli.wizard.sections import (
    SECTION_AUTHORS,
    SECTION_LICENSES,
    SECTION_LIFECYCLE,
    SECTION_ORGANIZATION,
    SECTION_SECURITY,
    SECTION_VCS,
    collect_authors,
    collect_licenses,
    collect_lifecycle_and_dates,
    collect_organization,
    collect_security_contact,
    collect_vcs_override,
)
from sbomify_action.console import console, print_banner


def _load_existing_config(path: Path) -> dict[str, Any] | None:
    """Load existing sbomify.json if it exists.

    Args:
        path: Path to sbomify.json

    Returns:
        Existing configuration or None
    """
    if not path.exists():
        return None

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (json.JSONDecodeError, OSError) as e:
        print_warning(f"Could not load existing config: {e}")

    return None


def _merge_config(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """Merge updates into base config.

    Args:
        base: Base configuration
        updates: Updates to merge

    Returns:
        Merged configuration
    """
    result = base.copy()
    for key, value in updates.items():
        if value is not None:
            result[key] = value
    return result


def _preview_config(config: dict[str, Any]) -> None:
    """Display config preview with syntax highlighting.

    Args:
        config: Configuration to preview
    """
    console.print()
    console.print(
        Panel(
            JSON(json.dumps(config, indent=2)),
            title="[bold]Generated sbomify.json[/bold]",
            border_style="green",
        )
    )
    console.print()


def _write_config(config: dict[str, Any], path: Path, backup: bool = True) -> bool:
    """Write configuration to file.

    Args:
        config: Configuration to write
        path: Output path
        backup: Whether to create backup of existing file

    Returns:
        True if successful
    """
    try:
        # Create backup if file exists
        if backup and path.exists():
            backup_path = path.with_suffix(".json.bak")
            shutil.copy2(path, backup_path)
            print_info(f"Backup created: {backup_path}")

        # Write config
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")  # Trailing newline

        return True
    except OSError as e:
        print_warning(f"Failed to write config: {e}")
        return False


def run_wizard(output_path: str = "sbomify.json") -> int:
    """Run the interactive sbomify.json configuration wizard.

    Args:
        output_path: Path to write the configuration file

    Returns:
        Exit code (0 for success, 1 for error/cancel)
    """
    path = Path(output_path)

    # Print banner
    print_banner()
    console.print()
    console.print("[bold]sbomify.json Configuration Wizard[/bold]")
    console.print("Create or update your SBOM configuration file.")
    console.print("[dim]Press Ctrl+C at any time to exit.[/dim]")
    console.print()

    # Load existing config
    existing = _load_existing_config(path)
    config: dict[str, Any] = {}
    completed: set[str] = set()

    if existing:
        print_info(f"Found existing configuration: {path}")
        try:
            load_existing = ask_confirm("Load existing configuration?", default=True)
        except GoBack:
            print_info("Cancelled.")
            return 1
        if load_existing:
            config = existing.copy()
            # Mark sections that have data as completed
            if config.get("supplier") or config.get("manufacturer"):
                completed.add(SECTION_ORGANIZATION)
            if config.get("authors"):
                completed.add(SECTION_AUTHORS)
            if config.get("licenses"):
                completed.add(SECTION_LICENSES)
            if config.get("security_contact"):
                completed.add(SECTION_SECURITY)
            if (
                config.get("lifecycle_phase")
                or config.get("release_date")
                or config.get("support_period_end")
                or config.get("end_of_life")
            ):
                completed.add(SECTION_LIFECYCLE)
            if config.get("vcs_url"):
                completed.add(SECTION_VCS)
        console.print()

    # Menu-driven section selection

    try:
        while True:
            # Build menu choices
            choices = []
            for section_id, label in [
                (SECTION_ORGANIZATION, "Organization (supplier/manufacturer)"),
                (SECTION_AUTHORS, "Authors"),
                (SECTION_LICENSES, "Licenses"),
                (SECTION_SECURITY, "Security Contact"),
                (SECTION_LIFECYCLE, "Lifecycle & Dates"),
                (SECTION_VCS, "VCS Override"),
            ]:
                mark = "[x]" if section_id in completed else "[ ]"
                choices.append(Choice(f"{mark} {label}", value=section_id))

            choices.append(Choice("─" * 40, value="separator", disabled=""))
            if completed:
                choices.append(Choice(">>> Continue (save and exit)", value="continue"))
            choices.append(Choice(">>> Exit (cancel)", value="exit"))

            # Add padding so user isn't at bottom of terminal
            console.print("\n" * 3)

            selection = ask_select(
                "Configure sections (enter to select):",
                choices=choices,
            )

            if selection == "exit" or selection is None:
                print_info("Cancelled.")
                return 1

            if selection == "continue":
                break

            if selection == "separator":
                continue

            # Run the selected section (GoBack returns to menu)
            try:
                if selection == SECTION_ORGANIZATION:
                    org_data = collect_organization(config)
                    config = _merge_config(config, org_data)
                elif selection == SECTION_AUTHORS:
                    authors = collect_authors(config.get("authors"))
                    if authors is not None:
                        config["authors"] = authors
                elif selection == SECTION_LICENSES:
                    licenses = collect_licenses(config.get("licenses"))
                    if licenses is not None:
                        config["licenses"] = licenses
                elif selection == SECTION_SECURITY:
                    security = collect_security_contact(config.get("security_contact"))
                    if security is not None:
                        config["security_contact"] = security
                elif selection == SECTION_LIFECYCLE:
                    lifecycle_data = collect_lifecycle_and_dates(config)
                    config = _merge_config(config, lifecycle_data)
                elif selection == SECTION_VCS:
                    vcs_data = collect_vcs_override(config)
                    config = _merge_config(config, vcs_data)

                completed.add(selection)
            except GoBack:
                # User pressed Escape - return to menu
                console.print()
                print_info("Returned to menu.")
                continue

    except KeyboardInterrupt:
        console.print()
        print_info("Cancelled.")
        return 1

    # Remove None values and empty dicts/lists
    config = {k: v for k, v in config.items() if v is not None and v != {} and v != []}

    # Preview and save
    if config:
        console.print()
        _preview_config(config)

        if not ask_confirm(f"Save to {path}?", default=True):
            print_info("Cancelled.")
            return 1

        if _write_config(config, path, backup=existing is not None):
            print_success(f"Configuration saved to {path}")
            console.print()
            print_info("Next steps:")
            print_info("  1. Review the generated file")
            print_info("  2. Run with --augment flag: sbomify-action --augment --lock-file ...")
            return 0
        else:
            return 1
    else:
        print_info("No data entered. Nothing to save.")
        return 0
