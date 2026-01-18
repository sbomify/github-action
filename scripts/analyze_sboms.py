#!/usr/bin/env python3
"""
Comprehensive SBOM analysis script.

Analyzes all SBOMs in test-data to:
1. Find all invalid license IDs (CycloneDX and SPDX)
2. Test sanitization functions
3. Verify sanitized output is valid
4. Check license normalization mappings
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from license_expression import ExpressionError, get_spdx_licensing

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sbomify_action.serialization import (
    sanitize_cyclonedx_licenses,
    sanitize_spdx_licenses,
)

TEST_DATA = Path(__file__).parent.parent / "tests" / "test-data"
spdx_licensing = get_spdx_licensing()


def check_license_valid(license_str: str) -> tuple[bool, list[str]]:
    """Check if a license string is valid SPDX."""
    if not license_str or license_str in ("NOASSERTION", "NONE"):
        return True, []
    if license_str.startswith("LicenseRef-"):
        return True, []
    try:
        parsed = spdx_licensing.parse(license_str, validate=False)
        unknown = spdx_licensing.unknown_license_keys(parsed)
        invalid = [str(k) for k in unknown if not str(k).startswith("LicenseRef-")]
        return len(invalid) == 0, invalid
    except ExpressionError:
        return False, [license_str]


def analyze_cyclonedx(file_path: Path) -> dict[str, Any]:
    """Analyze a CycloneDX SBOM file."""
    with open(file_path) as f:
        data = json.load(f)

    results = {
        "file": file_path.name,
        "format": "cyclonedx",
        "spec_version": data.get("specVersion", "unknown"),
        "components": len(data.get("components", [])),
        "total_licenses": 0,
        "invalid_licenses": [],
        "license_in_id": 0,  # license.id field
        "license_in_name": 0,  # license.name field
        "license_in_expression": 0,  # expression field
    }

    for comp in data.get("components", []):
        for lic in comp.get("licenses", []):
            license_obj = lic.get("license", {})
            lid = license_obj.get("id")
            lname = license_obj.get("name")
            expr = lic.get("expression")

            if lid:
                results["total_licenses"] += 1
                results["license_in_id"] += 1
                valid, invalid_ids = check_license_valid(lid)
                if not valid:
                    for inv in invalid_ids:
                        results["invalid_licenses"].append(
                            {
                                "license": inv,
                                "component": comp.get("name"),
                                "field": "license.id",
                                "original": lid,
                            }
                        )
            elif lname:
                results["total_licenses"] += 1
                results["license_in_name"] += 1
                # Names don't need to be valid SPDX
            elif expr:
                results["total_licenses"] += 1
                results["license_in_expression"] += 1
                valid, invalid_ids = check_license_valid(expr)
                if not valid:
                    for inv in invalid_ids:
                        results["invalid_licenses"].append(
                            {
                                "license": inv,
                                "component": comp.get("name"),
                                "field": "expression",
                                "original": expr,
                            }
                        )

    return results


def analyze_spdx(file_path: Path) -> dict[str, Any]:
    """Analyze an SPDX SBOM file."""
    with open(file_path) as f:
        data = json.load(f)

    results = {
        "file": file_path.name,
        "format": "spdx",
        "spec_version": data.get("spdxVersion", "unknown"),
        "packages": len(data.get("packages", [])),
        "total_licenses": 0,
        "noassertion_count": 0,
        "invalid_licenses": [],
        "has_extracted_licensing_info": len(data.get("hasExtractedLicensingInfos", [])),
    }

    for pkg in data.get("packages", []):
        for field in ["licenseConcluded", "licenseDeclared"]:
            val = pkg.get(field, "")
            if val in ("NOASSERTION", "NONE"):
                results["noassertion_count"] += 1
            elif val:
                results["total_licenses"] += 1
                valid, invalid_ids = check_license_valid(val)
                if not valid:
                    for inv in invalid_ids:
                        results["invalid_licenses"].append(
                            {
                                "license": inv,
                                "package": pkg.get("name"),
                                "field": field,
                                "original": val[:100] if len(val) > 100 else val,
                            }
                        )

    return results


def test_sanitization_cyclonedx(file_path: Path) -> dict[str, Any]:
    """Test CycloneDX sanitization on a file."""
    import copy

    with open(file_path) as f:
        data = json.load(f)

    data_copy = copy.deepcopy(data)
    sanitized_count = sanitize_cyclonedx_licenses(data_copy)

    # Check if sanitized output is valid
    remaining_invalid = []
    for comp in data_copy.get("components", []):
        for lic in comp.get("licenses", []):
            license_obj = lic.get("license", {})
            lid = license_obj.get("id")
            expr = lic.get("expression")

            if lid:
                valid, invalid_ids = check_license_valid(lid)
                if not valid:
                    remaining_invalid.extend(invalid_ids)
            elif expr:
                valid, invalid_ids = check_license_valid(expr)
                if not valid:
                    remaining_invalid.extend(invalid_ids)

    return {
        "file": file_path.name,
        "sanitized_count": sanitized_count,
        "remaining_invalid": remaining_invalid,
        "sanitization_complete": len(remaining_invalid) == 0,
    }


def test_sanitization_spdx(file_path: Path) -> dict[str, Any]:
    """Test SPDX sanitization on a file."""
    import copy

    with open(file_path) as f:
        data = json.load(f)

    data_copy = copy.deepcopy(data)
    sanitized_count = sanitize_spdx_licenses(data_copy)

    # Check if sanitized output is valid
    remaining_invalid = []
    for pkg in data_copy.get("packages", []):
        for field in ["licenseConcluded", "licenseDeclared"]:
            val = pkg.get(field, "")
            if val and val not in ("NOASSERTION", "NONE"):
                valid, invalid_ids = check_license_valid(val)
                if not valid:
                    remaining_invalid.extend(invalid_ids)

    return {
        "file": file_path.name,
        "sanitized_count": sanitized_count,
        "remaining_invalid": remaining_invalid,
        "sanitization_complete": len(remaining_invalid) == 0,
    }


def main():
    print("=" * 70)
    print("COMPREHENSIVE SBOM ANALYSIS")
    print("=" * 70)

    cdx_files = list(TEST_DATA.glob("*.cdx.json"))
    spdx_files = list(TEST_DATA.glob("*.spdx.json"))

    print(f"\nFound {len(cdx_files)} CycloneDX files")
    print(f"Found {len(spdx_files)} SPDX files")

    # Analyze all files
    cdx_results = []
    spdx_results = []
    all_invalid_licenses = defaultdict(lambda: {"cdx": [], "spdx": []})

    print("\n" + "-" * 70)
    print("ANALYZING CYCLONEDX FILES")
    print("-" * 70)

    for f in sorted(cdx_files):
        try:
            result = analyze_cyclonedx(f)
            cdx_results.append(result)
            for inv in result["invalid_licenses"]:
                all_invalid_licenses[inv["license"]]["cdx"].append(
                    {"file": f.name, "component": inv["component"], "field": inv["field"]}
                )
        except Exception as e:
            print(f"Error processing {f.name}: {e}")

    print("\n" + "-" * 70)
    print("ANALYZING SPDX FILES")
    print("-" * 70)

    for f in sorted(spdx_files):
        try:
            result = analyze_spdx(f)
            spdx_results.append(result)
            for inv in result["invalid_licenses"]:
                all_invalid_licenses[inv["license"]]["spdx"].append(
                    {"file": f.name, "package": inv["package"], "field": inv["field"]}
                )
        except Exception as e:
            print(f"Error processing {f.name}: {e}")

    # Summary statistics
    print("\n" + "=" * 70)
    print("CYCLONEDX SUMMARY")
    print("=" * 70)
    total_components = sum(r["components"] for r in cdx_results)
    total_licenses = sum(r["total_licenses"] for r in cdx_results)
    total_in_id = sum(r["license_in_id"] for r in cdx_results)
    total_in_name = sum(r["license_in_name"] for r in cdx_results)
    total_in_expr = sum(r["license_in_expression"] for r in cdx_results)
    total_invalid = sum(len(r["invalid_licenses"]) for r in cdx_results)

    print(f"Total components: {total_components}")
    print(f"Total licenses: {total_licenses}")
    print(f"  - In license.id: {total_in_id}")
    print(f"  - In license.name: {total_in_name}")
    print(f"  - In expression: {total_in_expr}")
    print(f"Total invalid license occurrences: {total_invalid}")

    print("\n" + "=" * 70)
    print("SPDX SUMMARY")
    print("=" * 70)
    total_packages = sum(r["packages"] for r in spdx_results)
    total_licenses_spdx = sum(r["total_licenses"] for r in spdx_results)
    total_noassertion = sum(r["noassertion_count"] for r in spdx_results)
    total_extracted = sum(r["has_extracted_licensing_info"] for r in spdx_results)
    total_invalid_spdx = sum(len(r["invalid_licenses"]) for r in spdx_results)

    print(f"Total packages: {total_packages}")
    print(f"Total licenses (non-NOASSERTION): {total_licenses_spdx}")
    print(f"NOASSERTION count: {total_noassertion}")
    print(f"ExtractedLicensingInfo entries: {total_extracted}")
    print(f"Total invalid license occurrences: {total_invalid_spdx}")

    print("\n" + "=" * 70)
    print("ALL INVALID LICENSES FOUND")
    print("=" * 70)

    if all_invalid_licenses:
        for lic, occurrences in sorted(
            all_invalid_licenses.items(), key=lambda x: -(len(x[1]["cdx"]) + len(x[1]["spdx"]))
        ):
            cdx_count = len(occurrences["cdx"])
            spdx_count = len(occurrences["spdx"])
            cdx_files_set = set(o["file"] for o in occurrences["cdx"])
            spdx_files_set = set(o["file"] for o in occurrences["spdx"])

            print(f"\n{lic}:")
            print(f"  CycloneDX: {cdx_count} occurrences in {len(cdx_files_set)} files")
            print(f"  SPDX: {spdx_count} occurrences in {len(spdx_files_set)} files")

            # Show sample occurrences
            for o in occurrences["cdx"][:3]:
                print(f"    - CDX: {o['file']}: {o['component']} ({o['field']})")
            for o in occurrences["spdx"][:3]:
                print(f"    - SPDX: {o['file']}: {o['package']} ({o['field']})")
    else:
        print("No invalid licenses found!")

    # Test sanitization
    print("\n" + "=" * 70)
    print("TESTING SANITIZATION")
    print("=" * 70)

    # Test on files with invalid licenses
    files_with_invalid_cdx = [r["file"] for r in cdx_results if r["invalid_licenses"]]
    files_with_invalid_spdx = [r["file"] for r in spdx_results if r["invalid_licenses"]]

    print(f"\nCycloneDX files with invalid licenses: {len(files_with_invalid_cdx)}")
    sanitization_failures_cdx = []
    for fname in files_with_invalid_cdx:
        fpath = TEST_DATA / fname
        result = test_sanitization_cyclonedx(fpath)
        if not result["sanitization_complete"]:
            sanitization_failures_cdx.append(result)
        print(f"  {fname}: sanitized {result['sanitized_count']}, remaining: {result['remaining_invalid']}")

    print(f"\nSPDX files with invalid licenses: {len(files_with_invalid_spdx)}")
    sanitization_failures_spdx = []
    for fname in files_with_invalid_spdx:
        fpath = TEST_DATA / fname
        result = test_sanitization_spdx(fpath)
        if not result["sanitization_complete"]:
            sanitization_failures_spdx.append(result)
        print(f"  {fname}: sanitized {result['sanitized_count']}, remaining: {result['remaining_invalid']}")

    # Final verdict
    print("\n" + "=" * 70)
    print("FINAL VERDICT")
    print("=" * 70)

    if sanitization_failures_cdx or sanitization_failures_spdx:
        print("\n❌ SANITIZATION INCOMPLETE - some invalid licenses remain!")
        if sanitization_failures_cdx:
            print("\nCycloneDX failures:")
            for f in sanitization_failures_cdx:
                print(f"  {f['file']}: {f['remaining_invalid']}")
        if sanitization_failures_spdx:
            print("\nSPDX failures:")
            for f in sanitization_failures_spdx:
                print(f"  {f['file']}: {f['remaining_invalid']}")
    else:
        print("\n✅ All invalid licenses are properly sanitized!")

    # List unique invalid licenses for reference
    print("\n" + "=" * 70)
    print("UNIQUE INVALID LICENSES (for license_normalizer.py)")
    print("=" * 70)
    for lic in sorted(all_invalid_licenses.keys()):
        print(f'    "{lic.lower()}": "???",  # TODO: map to valid SPDX')


if __name__ == "__main__":
    main()
