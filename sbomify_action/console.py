"""Rich console utilities for sbomify-action.

This module provides a shared Rich Console instance and helper functions
for beautiful CLI output, optimized for GitHub Actions and CI environments.
"""

import contextvars
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Detect CI environments
IS_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"
IS_GITLAB_CI = os.getenv("GITLAB_CI") == "true"
IS_CI = os.getenv("CI") == "true" or IS_GITHUB_ACTIONS or IS_GITLAB_CI

# sbomify brand colors (from logo gradient)
# These hex colors look great in local terminals
BRAND_COLORS_HEX = {
    "blue": "#4059D0",
    "purple_light": "#7C5BC8",
    "purple": "#A85AC0",
    "pink": "#CC58BB",
    "peach": "#E0879D",
    "orange": "#F4B57F",
}

# Theme-adaptive colors for GitHub Actions (works in both light and dark mode)
# Standard ANSI color names automatically adapt to the terminal's theme
BRAND_COLORS_ADAPTIVE = {
    "blue": "blue",
    "purple_light": "bright_blue",
    "purple": "magenta",
    "pink": "bright_magenta",
    "peach": "bright_red",
    "orange": "yellow",
}

# Choose colors based on environment
# In CI, use adaptive colors that work in both light and dark themes
# Locally, use the exact brand hex colors for best appearance
BRAND_COLORS = BRAND_COLORS_ADAPTIVE if IS_CI else BRAND_COLORS_HEX

# Custom theme for sbomify branding
# Uses adaptive colors that work in both light and dark terminal themes
custom_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "step": "bold blue",
        "highlight": "magenta",
        "brand.blue": BRAND_COLORS["blue"],
        "brand.purple": BRAND_COLORS["purple"],
        "brand.pink": BRAND_COLORS["pink"],
        "brand.orange": BRAND_COLORS["orange"],
    }
)

# Shared console instance
# Force colors ON in GitHub Actions (it supports ANSI colors but Rich may incorrectly disable them)
console = Console(
    theme=custom_theme,
    force_terminal=IS_GITHUB_ACTIONS or None,
    color_system="auto",
)


def print_banner(version: str = "unknown") -> None:
    """Print the sbomify banner with gradient colors."""
    banner = Text()
    banner.append("      _                     _  __\n", style=BRAND_COLORS["blue"])
    banner.append("     | |                   (_)/ _|\n", style=BRAND_COLORS["blue"])
    banner.append("  ___| |__   ___  _ __ ___  _| |_ _   _\n", style=BRAND_COLORS["purple_light"])
    banner.append(" / __| '_ \\ / _ \\| '_ ` _ \\| |  _| | | |\n", style=BRAND_COLORS["purple"])
    banner.append(" \\__ \\ |_) | (_) | | | | | | | | | |_| |\n", style=BRAND_COLORS["pink"])
    banner.append(" |___/_.__/ \\___/|_| |_| |_|_|_|  \\__, |\n", style=BRAND_COLORS["peach"])
    banner.append("                                   __/ |\n", style=BRAND_COLORS["orange"])
    banner.append(" From zero to SBOM hero.           |___/\n", style=BRAND_COLORS["orange"])
    # Only prefix with 'v' if version looks like semver (starts with digit)
    version_display = f"v{version}" if version and version[0:1].isdigit() else version
    banner.append(f" {version_display}\n", style=BRAND_COLORS["orange"])

    console.print(banner)


def print_step_header(step_num: int, title: str) -> None:
    """
    Print a styled step header.

    In GitHub Actions, uses ::group:: for collapsible sections.
    In other environments, uses Rich styling.

    Args:
        step_num: Step number (1-6)
        title: Step title
    """
    step_title = f"STEP {step_num}: {title}"

    if IS_GITHUB_ACTIONS:
        # GitHub Actions collapsible group
        print(f"::group::{step_title}")
        console.print(f"[bold blue]{step_title}[/bold blue]")
    else:
        # Rich panel-style header for local terminal
        console.print()
        console.rule(f"[bold blue]{step_title}[/bold blue]", style="blue")


def print_step_end(step_num: int, success: bool = True) -> None:
    """
    Print step completion status and close GitHub Actions group.

    Args:
        step_num: Step number (1-6)
        success: Whether the step completed successfully
    """
    if success:
        console.print(f"[success]✓ Step {step_num} completed successfully[/success]")
    else:
        console.print(f"[error]✗ Step {step_num} failed[/error]")

    if IS_GITHUB_ACTIONS:
        print("::endgroup::")
    else:
        console.print()


@contextmanager
def gha_group(title: str) -> Generator[None, None, None]:
    """
    Context manager for GitHub Actions collapsible groups.

    Args:
        title: Group title

    Usage:
        with gha_group("Details"):
            print("This is collapsible in GHA")
    """
    if IS_GITHUB_ACTIONS:
        print(f"::group::{title}")
    try:
        yield
    finally:
        if IS_GITHUB_ACTIONS:
            print("::endgroup::")


def gha_warning(message: str, title: Optional[str] = None) -> None:
    """
    Emit a warning that appears in GitHub Actions job summary.

    Args:
        message: Warning message
        title: Optional title for the warning
    """
    if IS_GITHUB_ACTIONS:
        if title:
            print(f"::warning title={title}::{message}")
        else:
            print(f"::warning::{message}")
    else:
        if title:
            console.print(f"[warning]Warning ({title}):[/warning] {message}")
        else:
            console.print(f"[warning]Warning:[/warning] {message}")


def gha_error(message: str, title: Optional[str] = None) -> None:
    """
    Emit an error that appears in GitHub Actions job summary.

    Args:
        message: Error message
        title: Optional title for the error
    """
    if IS_GITHUB_ACTIONS:
        if title:
            print(f"::error title={title}::{message}")
        else:
            print(f"::error::{message}")
    else:
        if title:
            console.print(f"[error]Error ({title}):[/error] {message}")
        else:
            console.print(f"[error]Error:[/error] {message}")


def gha_notice(message: str, title: Optional[str] = None) -> None:
    """
    Emit a notice annotation in GitHub Actions.

    Args:
        message: Notice message
        title: Optional title for the notice
    """
    if IS_GITHUB_ACTIONS:
        if title:
            print(f"::notice title={title}::{message}")
        else:
            print(f"::notice::{message}")
    else:
        if title:
            console.print(f"[info]Notice ({title}):[/info] {message}")
        else:
            console.print(f"[info]Notice:[/info] {message}")


def print_summary_table(
    title: str,
    data: List[Tuple[str, Any]],
    show_if_empty: bool = False,
) -> None:
    """
    Print a summary table.

    Args:
        title: Table title
        data: List of (label, value) tuples
        show_if_empty: Whether to show the table if all values are 0/empty
    """
    # Filter out zero/empty values unless show_if_empty is True
    if not show_if_empty:
        data = [(label, value) for label, value in data if value]

    if not data:
        return

    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    for label, value in data:
        table.add_row(label, str(value))

    console.print(table)


def print_enrichment_summary(stats: Dict[str, Any], total_components: int) -> None:
    """
    Print enrichment summary as a Rich table.

    Args:
        stats: Enrichment statistics dictionary (from CycloneDX or SPDX enrichment)
        total_components: Total number of components processed
    """
    data = [
        ("Components enriched", f"{stats.get('components_enriched', 0)}/{total_components}"),
        ("Descriptions added", stats.get("descriptions_added", 0)),
        ("Licenses added", stats.get("licenses_added", 0)),
        ("Publishers added", stats.get("publishers_added", 0)),
        ("Suppliers added", stats.get("suppliers_added", 0)),
        ("Homepage URLs added", stats.get("homepages_added", 0)),
        ("Repository URLs added", stats.get("repositories_added", 0)),
        # CycloneDX-specific fields
        ("Distribution URLs added", stats.get("distributions_added", 0)),
        ("Issue tracker URLs added", stats.get("issue_trackers_added", 0)),
        ("OS components enriched", stats.get("os_components_enriched", 0)),
        # SPDX-specific fields
        ("Originators added", stats.get("originators_added", 0)),
        ("Source info added", stats.get("source_info_added", 0)),
        ("External refs added", stats.get("external_refs_added", 0)),
    ]

    print_summary_table("Enrichment Summary", data)

    # Show sources breakdown if available
    sources = stats.get("sources", {})
    if sources:
        source_data = [(source, count) for source, count in sorted(sources.items())]
        print_summary_table("Enrichment by Source", source_data)


def print_sanitization_summary(
    vcs_normalized: int = 0,
    purls_normalized: int = 0,
    purls_cleared: int = 0,
    urls_rejected: int = 0,
    stubs_added: int = 0,
    details: Optional[List[str]] = None,
) -> None:
    """
    Print sanitization summary as a Rich table.

    Args:
        vcs_normalized: Number of VCS URLs normalized
        purls_normalized: Number of PURLs normalized
        purls_cleared: Number of invalid PURLs cleared
        urls_rejected: Number of URLs rejected
        stubs_added: Number of stub components added
        details: Optional list of detail strings for attestation
    """
    data = [
        ("VCS URLs normalized", vcs_normalized),
        ("PURLs normalized", purls_normalized),
        ("PURLs cleared (invalid)", purls_cleared),
        ("URLs rejected", urls_rejected),
        ("Stub components added", stubs_added),
    ]

    print_summary_table("Sanitization Summary", data)

    # Show details in collapsible group for attestation
    if details and any(d for d in details):
        with gha_group("Sanitization Details (for attestation)"):
            for detail in details:
                console.print(f"  {detail}")


def print_upload_summary(
    destination: str,
    success: bool,
    sbom_format: str,
    sbom_id: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    """
    Print upload result summary.

    Args:
        destination: Upload destination name
        success: Whether upload succeeded
        sbom_format: SBOM format (cyclonedx/spdx)
        sbom_id: Optional SBOM ID from response
        error_message: Optional error message if failed
    """
    if success:
        console.print(f"[success]✓ Uploaded to {destination}[/success]")
        if sbom_id:
            console.print(f"  SBOM ID: {sbom_id}")
    else:
        console.print(f"[error]✗ Upload to {destination} failed[/error]")
        if error_message:
            console.print(f"  Error: {error_message}")


def print_final_success() -> None:
    """Print final success message."""
    console.print()
    if IS_GITHUB_ACTIONS:
        console.print("[bold green]✓ SUCCESS![/bold green] All steps completed successfully.")
    else:
        console.rule("[bold green]SUCCESS[/bold green]", style="green")
        console.print("[bold green]All steps completed successfully![/bold green]", justify="center")
    console.print()


def print_final_failure(message: str) -> None:
    """Print final failure message."""
    console.print()
    gha_error(message, title="SBOM Processing Failed")
    if not IS_GITHUB_ACTIONS:
        console.rule("[bold red]FAILED[/bold red]", style="red")
        console.print(f"[bold red]{message}[/bold red]", justify="center")
    console.print()


@dataclass
class TransformationTracker:
    """
    Tracks all SBOM transformations for attestation purposes.

    This class collects all modifications made to an SBOM during processing,
    then outputs them in an organized way:
    - Summary table visible by default
    - Details in collapsible groups (GitHub Actions) or verbose output

    All transformations are logged for the audit trail, ensuring attestation
    requirements are met.
    """

    # VCS URL normalizations: (original, normalized)
    vcs_normalizations: List[Tuple[str, str]] = field(default_factory=list)

    # PURL normalizations: (component_name, original_purl, normalized_purl)
    purl_normalizations: List[Tuple[str, str, str]] = field(default_factory=list)

    # PURLs cleared: (component_name, purl, reason)
    purls_cleared: List[Tuple[str, str, str]] = field(default_factory=list)

    # URLs rejected: (field_name, url, reason)
    urls_rejected: List[Tuple[str, str, str]] = field(default_factory=list)

    # Stub components added: (ref_value, component_name, version)
    stubs_added: List[Tuple[str, str, str]] = field(default_factory=list)

    # Root dependencies linked: (root_name, count)
    root_dependencies_linked: List[Tuple[str, int]] = field(default_factory=list)

    def record_vcs_normalization(self, original: str, normalized: str) -> None:
        """Record a VCS URL normalization."""
        self.vcs_normalizations.append((original, normalized))

    def record_purl_normalization(self, component_name: str, original: str, normalized: str) -> None:
        """Record a PURL normalization."""
        self.purl_normalizations.append((component_name, original, normalized))

    def record_purl_cleared(self, component_name: str, purl: str, reason: str) -> None:
        """Record a PURL that was cleared due to being invalid."""
        self.purls_cleared.append((component_name, purl, reason))

    def record_url_rejected(self, field_name: str, url: str, reason: str) -> None:
        """Record a URL that was rejected during sanitization."""
        self.urls_rejected.append((field_name, url, reason))

    def record_stub_added(self, ref_value: str, component_name: str, version: str) -> None:
        """Record a stub component added for orphaned dependency reference."""
        self.stubs_added.append((ref_value, component_name, version))

    def record_root_dependencies_linked(self, root_name: str, count: int) -> None:
        """Record root dependencies linking (components linked to root component)."""
        self.root_dependencies_linked.append((root_name, count))

    def has_transformations(self) -> bool:
        """Check if any transformations were recorded."""
        return bool(
            self.vcs_normalizations
            or self.purl_normalizations
            or self.purls_cleared
            or self.urls_rejected
            or self.stubs_added
            or self.root_dependencies_linked
        )

    def print_summary(self, title: str = "SBOM Transformations") -> None:
        """
        Print transformation summary and details.

        Outputs:
        1. Summary table with counts (always visible)
        2. Details in collapsible group (GitHub Actions) or under verbose flag

        All information is logged for attestation purposes.
        """
        if not self.has_transformations():
            return

        # Print summary table
        data = [
            ("VCS URLs normalized", len(self.vcs_normalizations)),
            ("PURLs normalized", len(self.purl_normalizations)),
            ("PURLs cleared (invalid)", len(self.purls_cleared)),
            ("URLs rejected", len(self.urls_rejected)),
            ("Stub components added", len(self.stubs_added)),
            ("Components linked to root", sum(count for _, count in self.root_dependencies_linked)),
        ]
        print_summary_table(title, data)

        # Print details in collapsible group for attestation
        details = self._format_details()
        if details:
            with gha_group(f"{title} - Details (for attestation)"):
                for detail in details:
                    console.print(f"  {detail}")

    def _format_details(self) -> List[str]:
        """Format all transformations as detail strings."""
        details = []

        for original, normalized in self.vcs_normalizations:
            details.append(f"VCS: {original} → {normalized}")

        for comp_name, original, normalized in self.purl_normalizations:
            details.append(f"PURL normalized ({comp_name}): {original} → {normalized}")

        for comp_name, purl, reason in self.purls_cleared:
            details.append(f"PURL cleared ({comp_name}): {purl} ({reason})")

        for field_name, url, reason in self.urls_rejected:
            # Truncate long URLs for readability
            url_display = url[:100] + "..." if len(url) > 100 else url
            details.append(f"URL rejected ({field_name}): {url_display} ({reason})")

        for ref_value, comp_name, version in self.stubs_added:
            details.append(f"Stub added: {comp_name}@{version} (ref: {ref_value})")

        for root_name, count in self.root_dependencies_linked:
            details.append(f"Linked {count} components to root '{root_name}'")

        return details


# Thread-safe transformation tracker using contextvars
# This ensures each thread/async context has its own tracker instance
_current_tracker: contextvars.ContextVar[Optional[TransformationTracker]] = contextvars.ContextVar(
    "transformation_tracker", default=None
)


def get_transformation_tracker() -> TransformationTracker:
    """
    Get the current transformation tracker, creating one if needed.

    Thread-safe: Each thread/async context gets its own tracker.

    Returns:
        The current TransformationTracker instance
    """
    tracker = _current_tracker.get()
    if tracker is None:
        tracker = TransformationTracker()
        _current_tracker.set(tracker)
    return tracker


def reset_transformation_tracker() -> TransformationTracker:
    """
    Reset the transformation tracker for a new SBOM processing run.

    Thread-safe: Only affects the current thread/async context.

    Returns:
        A fresh TransformationTracker instance
    """
    tracker = TransformationTracker()
    _current_tracker.set(tracker)
    return tracker


def print_transformation_summary() -> None:
    """Print the current transformation tracker's summary."""
    tracker = get_transformation_tracker()
    tracker.print_summary()
