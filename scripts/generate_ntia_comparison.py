#!/usr/bin/env python3
"""
Generate SBOM enrichment documentation.

This script generates documentation about sbomify's enrichment capabilities,
including data sources, field coverage, and example transformations.

Run: uv run scripts/generate_ntia_comparison.py
"""

import json
from datetime import datetime
from pathlib import Path

# Data sources by ecosystem with expected coverage
ECOSYSTEM_DATA = {
    "Python (pip)": {
        "primary": "PyPI API",
        "fallbacks": ["deps.dev", "ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "high",
            "homepage": "high",
            "repository": "medium-high",
        },
        "notes": "PyPI requires license metadata for new packages since 2023.",
    },
    "JavaScript (npm)": {
        "primary": "deps.dev",
        "fallbacks": ["ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "high",
            "homepage": "high",
            "repository": "high",
        },
        "notes": "npm registry has excellent metadata coverage.",
    },
    "Rust (cargo)": {
        "primary": "deps.dev",
        "fallbacks": ["ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "high",
            "homepage": "medium",
            "repository": "high",
        },
        "notes": "crates.io requires license field.",
    },
    "Go (mod)": {
        "primary": "deps.dev",
        "fallbacks": ["ecosyste.ms"],
        "coverage": {
            "supplier": "medium",
            "license": "high",
            "description": "medium",
            "homepage": "low",
            "repository": "high",
        },
        "notes": "Go modules are often just GitHub repos with minimal metadata.",
    },
    "Ruby (gem)": {
        "primary": "deps.dev",
        "fallbacks": ["ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "high",
            "homepage": "high",
            "repository": "medium",
        },
    },
    "Java/Maven": {
        "primary": "deps.dev",
        "fallbacks": ["ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "medium",
            "homepage": "medium",
            "repository": "medium",
        },
        "notes": "Maven Central has good metadata but older artifacts may lack some fields.",
    },
    "Dart (pub)": {
        "primary": "pub.dev API",
        "fallbacks": ["ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "high",
            "homepage": "high",
            "repository": "high",
        },
        "notes": "pub.dev has excellent metadata.",
    },
    "Debian/Ubuntu (deb)": {
        "primary": "Debian Sources",
        "fallbacks": ["Repology", "ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "high",
            "homepage": "medium",
            "repository": "low",
        },
        "notes": "Debian packages have maintainer info but may lack upstream URLs.",
    },
    "Alpine (apk)": {
        "primary": "Repology",
        "fallbacks": ["ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "medium",
            "homepage": "medium",
            "repository": "low",
        },
    },
    "Red Hat/Fedora (rpm)": {
        "primary": "Repology",
        "fallbacks": ["ecosyste.ms"],
        "coverage": {
            "supplier": "high",
            "license": "high",
            "description": "medium",
            "homepage": "medium",
            "repository": "low",
        },
    },
}

# Example before/after for documentation
EXAMPLE_BEFORE = {
    "type": "library",
    "name": "django",
    "version": "5.1",
    "purl": "pkg:pypi/django@5.1",
}

EXAMPLE_AFTER = {
    "type": "library",
    "name": "django",
    "version": "5.1",
    "purl": "pkg:pypi/django@5.1",
    "publisher": "Django Software Foundation",
    "description": "A high-level Python web framework that encourages rapid development and clean, pragmatic design.",
    "licenses": [{"expression": "BSD-3-Clause"}],
    "externalReferences": [
        {"type": "website", "url": "https://www.djangoproject.com/"},
        {"type": "vcs", "url": "https://github.com/django/django"},
        {"type": "distribution", "url": "https://pypi.org/project/Django/"},
    ],
}


def coverage_emoji(level: str) -> str:
    """Convert coverage level to emoji."""
    return {"high": "🟢", "medium-high": "🟢", "medium": "🟡", "low": "🟠"}.get(level, "⚪")


def generate_data_sources_table() -> str:
    """Generate table of data sources by ecosystem."""
    lines = [
        "## Data Sources by Ecosystem",
        "",
        "sbomify queries multiple sources in priority order, using fallbacks when primary sources lack data.",
        "",
        "| Ecosystem | Primary Source | Fallbacks |",
        "|-----------|----------------|-----------|",
    ]

    for ecosystem, data in ECOSYSTEM_DATA.items():
        fallbacks = " → ".join(data["fallbacks"])
        lines.append(f"| {ecosystem} | {data['primary']} | {fallbacks} |")

    lines.append("")
    return "\n".join(lines)


def generate_coverage_table() -> str:
    """Generate table showing expected field coverage by ecosystem."""
    lines = [
        "## Expected Field Coverage",
        "",
        "Coverage varies by ecosystem and data source availability.",
        "",
        "Legend: 🟢 High | 🟡 Medium | 🟠 Low",
        "",
        "| Ecosystem | Supplier | License | Description | Homepage | Repository |",
        "|-----------|----------|---------|-------------|----------|------------|",
    ]

    for ecosystem, data in ECOSYSTEM_DATA.items():
        cov = data["coverage"]
        lines.append(
            f"| {ecosystem} | "
            f"{coverage_emoji(cov['supplier'])} | "
            f"{coverage_emoji(cov['license'])} | "
            f"{coverage_emoji(cov['description'])} | "
            f"{coverage_emoji(cov['homepage'])} | "
            f"{coverage_emoji(cov['repository'])} |"
        )

    lines.append("")
    return "\n".join(lines)


def generate_ecosystem_notes() -> str:
    """Generate notes about each ecosystem."""
    lines = [
        "## Ecosystem Notes",
        "",
    ]

    for ecosystem, data in ECOSYSTEM_DATA.items():
        if data.get("notes"):
            lines.append(f"- **{ecosystem}**: {data['notes']}")

    lines.append("")
    return "\n".join(lines)


def generate_example() -> str:
    """Generate before/after example."""
    lines = [
        "## Example: Before and After Enrichment",
        "",
        "### Scanner Output (Trivy)",
        "",
        "```json",
        json.dumps(EXAMPLE_BEFORE, indent=2),
        "```",
        "",
        "### After sbomify Enrichment",
        "",
        "```json",
        json.dumps(EXAMPLE_AFTER, indent=2),
        "```",
        "",
    ]
    return "\n".join(lines)


def generate_limitations() -> str:
    """Generate limitations section."""
    return """## Limitations

- **Network required**: Enrichment calls external APIs during CI. Not suitable for air-gapped environments.
- **Rate limits**: Large SBOMs (1000+ packages) may experience slower enrichment due to API rate limits.
- **Best effort**: Private packages, vendored code, and obscure packages may not have registry data.
- **Data freshness**: Metadata is fetched at enrichment time. Registry data may lag behind actual releases.
- **Coverage varies**: Different ecosystems and registries have different metadata requirements and quality.

"""


def generate_full_report() -> str:
    """Generate the full documentation."""
    sections = [
        "# SBOM Enrichment Coverage",
        "",
        "This document details sbomify's enrichment capabilities, data sources, and expected coverage.",
        "",
        generate_data_sources_table(),
        generate_coverage_table(),
        generate_ecosystem_notes(),
        generate_example(),
        generate_limitations(),
        f"*Generated: {datetime.now().strftime('%Y-%m-%d')}*",
    ]
    return "\n".join(sections)


def main():
    """Generate and write the documentation."""
    report = generate_full_report()
    print(report)

    # Write to docs folder
    output_path = Path(__file__).parent.parent / "docs" / "enrichment_coverage.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report)
    print(f"\n✅ Documentation written to: {output_path}")


if __name__ == "__main__":
    main()
