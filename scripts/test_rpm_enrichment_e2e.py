#!/usr/bin/env python3
"""
End-to-end acceptance test for RPM repository enrichment.

Tests the full flow:
1. Generate SBOM from Docker image using Syft
2. Run enrichment through the sbomify pipeline
3. Verify RPM packages have enriched metadata (license, supplier, description)
4. Report coverage statistics

Usage:
    uv run python scripts/test_rpm_enrichment_e2e.py [--image IMAGE] [--all]

Examples:
    # Test single image
    uv run python scripts/test_rpm_enrichment_e2e.py --image rockylinux:9

    # Test all acceptance criteria images
    uv run python scripts/test_rpm_enrichment_e2e.py --all
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Acceptance criteria images from the plan
ACCEPTANCE_IMAGES = [
    # Rocky Linux
    ("rockylinux:8", "rocky-8"),
    ("rockylinux:9", "rocky-9"),
    # Alma Linux
    ("almalinux:8", "almalinux-8"),
    ("almalinux:9", "almalinux-9"),
    # CentOS Stream
    ("quay.io/centos/centos:stream8", "centos-stream-8"),
    ("quay.io/centos/centos:stream9", "centos-stream-9"),
    # Fedora
    ("fedora:39", "fedora-39"),
    ("fedora:40", "fedora-40"),
    ("fedora:41", "fedora-41"),
    # Amazon Linux
    ("amazonlinux:2", "amzn-2"),
    ("amazonlinux:2023", "amzn-2023"),
]


def generate_sbom(image: str, output_path: Path) -> bool:
    """Generate CycloneDX SBOM for a Docker image using Syft."""
    print(f"  Generating SBOM for {image}...")
    try:
        result = subprocess.run(
            ["syft", image, "-o", f"cyclonedx-json={output_path}"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            print(f"    ERROR: Syft failed: {result.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"    ERROR: Syft timed out for {image}")
        return False
    except FileNotFoundError:
        print("    ERROR: Syft not found. Install with: brew install syft")
        return False


def run_enrichment(sbom_path: Path, output_path: Path) -> bool:
    """Run sbomify enrichment on the SBOM."""
    print("  Running enrichment...")
    try:
        # Import and run enrichment directly
        from sbomify_action.enrichment import enrich_sbom

        # enrich_sbom takes file paths, not dicts
        enrich_sbom(str(sbom_path), str(output_path))

        return True
    except Exception as e:
        print(f"    ERROR: Enrichment failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def analyze_enrichment(enriched_path: Path) -> Dict[str, Any]:
    """Analyze enrichment results and return statistics."""
    with open(enriched_path) as f:
        enriched = json.load(f)

    # Count RPM components
    rpm_components = []
    for comp in enriched.get("components", []):
        purl = comp.get("purl", "")
        if purl.startswith("pkg:rpm/"):
            rpm_components.append(comp)

    total_rpm = len(rpm_components)
    if total_rpm == 0:
        return {
            "total_rpm": 0,
            "enriched": 0,
            "with_license": 0,
            "with_supplier": 0,
            "with_description": 0,
            "coverage_pct": 0,
        }

    # Count enriched fields
    with_license = 0
    with_supplier = 0
    with_description = 0
    enriched_count = 0

    for comp in rpm_components:
        has_enrichment = False

        # Check licenses
        licenses = comp.get("licenses", [])
        if licenses:
            with_license += 1
            has_enrichment = True

        # Check supplier/publisher (CycloneDX uses publisher for supplier info)
        supplier = comp.get("supplier", {})
        publisher = comp.get("publisher")
        if (supplier and supplier.get("name")) or publisher:
            with_supplier += 1
            has_enrichment = True

        # Check description
        if comp.get("description"):
            with_description += 1
            has_enrichment = True

        if has_enrichment:
            enriched_count += 1

    return {
        "total_rpm": total_rpm,
        "enriched": enriched_count,
        "with_license": with_license,
        "with_supplier": with_supplier,
        "with_description": with_description,
        "coverage_pct": round(enriched_count / total_rpm * 100, 1) if total_rpm > 0 else 0,
    }


def test_image(image: str, distro: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Test a single Docker image end-to-end."""
    print(f"\n{'=' * 60}")
    print(f"Testing: {image} (distro: {distro})")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        sbom_path = tmppath / "sbom.json"
        enriched_path = tmppath / "enriched.json"

        # Step 1: Generate SBOM
        if not generate_sbom(image, sbom_path):
            return False, None

        # Step 2: Run enrichment
        if not run_enrichment(sbom_path, enriched_path):
            return False, None

        # Step 3: Analyze results
        stats = analyze_enrichment(enriched_path)

        print(f"\n  Results for {image}:")
        print(f"    Total RPM packages: {stats['total_rpm']}")
        print(f"    Enriched packages:  {stats['enriched']} ({stats['coverage_pct']}%)")
        print(f"    With license:       {stats['with_license']}")
        print(f"    With supplier:      {stats['with_supplier']}")
        print(f"    With description:   {stats['with_description']}")

        # Consider success if we have >50% coverage
        success = stats["coverage_pct"] >= 50 or stats["total_rpm"] == 0
        if not success:
            print("    WARNING: Coverage below 50%")

        return success, stats


def main():
    parser = argparse.ArgumentParser(description="End-to-end RPM enrichment acceptance test")
    parser.add_argument("--image", help="Test a specific Docker image")
    parser.add_argument("--all", action="store_true", help="Test all acceptance criteria images")
    parser.add_argument("--quick", action="store_true", help="Test one image per distro family")
    args = parser.parse_args()

    if not args.image and not args.all and not args.quick:
        parser.print_help()
        sys.exit(1)

    images_to_test = []
    if args.image:
        # Find matching distro or use generic
        distro = "unknown"
        for img, dist in ACCEPTANCE_IMAGES:
            if img == args.image:
                distro = dist
                break
        images_to_test = [(args.image, distro)]
    elif args.quick:
        # One image per distro family
        images_to_test = [
            ("rockylinux:9", "rocky-9"),
            ("almalinux:9", "almalinux-9"),
            ("quay.io/centos/centos:stream9", "centos-stream-9"),
            ("fedora:41", "fedora-41"),
            ("amazonlinux:2023", "amzn-2023"),
        ]
    else:
        images_to_test = ACCEPTANCE_IMAGES

    results = []
    for image, distro in images_to_test:
        success, stats = test_image(image, distro)
        results.append(
            {
                "image": image,
                "distro": distro,
                "success": success,
                "stats": stats,
            }
        )

    # Print summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    passed = sum(1 for r in results if r["success"])
    failed = len(results) - passed

    print(f"\nTotal images tested: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    print("\nDetailed results:")
    print("-" * 60)
    for r in results:
        status = "PASS" if r["success"] else "FAIL"
        stats = r["stats"]
        if stats:
            coverage = f"{stats['coverage_pct']}% ({stats['enriched']}/{stats['total_rpm']})"
        else:
            coverage = "N/A"
        print(f"  [{status}] {r['image']}: {coverage}")

    # Exit with error if any failed
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
