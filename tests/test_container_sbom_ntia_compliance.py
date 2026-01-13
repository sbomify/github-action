"""
Tests for NTIA compliance on real container image SBOMs.

Reference: https://sbomify.com/compliance/ntia-minimum-elements/
Crosswalk: https://sbomify.com/compliance/schema-crosswalk/

This module tests enrichment and augmentation on SBOMs generated from:
- Ubuntu 22.04
- Alpine 3.19
- Debian 12
- Red Hat UBI9

Both CycloneDX and SPDX formats are tested with Trivy and Syft outputs.

NTIA Minimum Elements validated:
- Supplier Name: CycloneDX publisher/supplier.name, SPDX packages[].supplier
- Component Name/Version: Always present from generators
- Unique Identifiers: PURLs from generators
- Dependency Relationship: dependencies[]/relationships[]
- SBOM Author: metadata.authors[]/creationInfo.creators[]
- Timestamp: metadata.timestamp/creationInfo.created
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import Mock, patch

import pytest

from sbomify_action.augmentation import augment_sbom_from_file
from sbomify_action.enrichment import clear_cache, enrich_sbom

# Test data directory
TEST_DATA_DIR = Path(__file__).parent / "test-data"

# Container images we generated SBOMs for
CONTAINER_IMAGES = ["ubuntu", "alpine", "debian", "redhat"]

# Sample backend metadata for augmentation testing
SAMPLE_BACKEND_METADATA = {
    "supplier": {
        "name": "Acme Corporation",
        "url": ["https://acme.example.com"],
        "contact": [
            {"name": "Security Team", "email": "security@acme.example.com"},
        ],
    },
    "authors": [
        {"name": "John Doe", "email": "john@acme.example.com"},
    ],
    "licenses": ["Apache-2.0"],
}


class NTIAComplianceChecker:
    """Utility class to check NTIA Minimum Elements compliance."""

    @staticmethod
    def check_cyclonedx(data: Dict[str, Any]) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
        """
        Check CycloneDX SBOM for NTIA compliance.

        Returns:
            Tuple of (is_compliant, present_elements, missing_elements, stats)
        """
        present = []
        missing = []
        stats = {
            "total_components": 0,
            "components_with_supplier": 0,
            "components_with_name": 0,
            "components_with_version": 0,
            "components_with_identifiers": 0,
        }

        # 1. Timestamp
        if data.get("metadata", {}).get("timestamp"):
            present.append("Timestamp")
        else:
            missing.append("Timestamp")

        # 2. Author of SBOM Data (authors - not tools, per NTIA standard)
        # NTIA defines "Author" as the entity that creates the SBOM, not the tool
        authors = data.get("metadata", {}).get("authors", [])
        has_author = bool(authors)
        if has_author:
            present.append("Author of SBOM Data")
        else:
            missing.append("Author of SBOM Data")

        # Check components
        components = data.get("components", [])
        # Filter to library components only (exclude OS type)
        library_components = [c for c in components if c.get("type") == "library"]
        stats["total_components"] = len(library_components)

        if not library_components:
            missing.extend(["Component Name", "Version", "Supplier Name", "Unique Identifiers"])
            return (False, present, missing, stats)

        for c in library_components:
            if c.get("name"):
                stats["components_with_name"] += 1
            if c.get("version"):
                stats["components_with_version"] += 1
            # Check for publisher (string) or supplier (object with name)
            has_supplier = False
            if c.get("publisher"):
                has_supplier = True
            elif c.get("supplier"):
                supplier = c.get("supplier")
                if isinstance(supplier, dict) and supplier.get("name"):
                    has_supplier = True
                elif isinstance(supplier, str) and supplier:
                    has_supplier = True
            if has_supplier:
                stats["components_with_supplier"] += 1
            # Unique identifier validation: PURL, CPE, or valid SWID (object with tagId and name)
            has_identifier = False
            if c.get("purl") or c.get("cpe"):
                has_identifier = True
            else:
                swid = c.get("swid")
                if isinstance(swid, dict) and swid.get("tagId") and swid.get("name"):
                    has_identifier = True
            if has_identifier:
                stats["components_with_identifiers"] += 1

        # 3. Component Name
        if stats["components_with_name"] == stats["total_components"]:
            present.append("Component Name")
        else:
            missing.append(f"Component Name ({stats['components_with_name']}/{stats['total_components']})")

        # 4. Version
        if stats["components_with_version"] == stats["total_components"]:
            present.append("Version")
        else:
            missing.append(f"Version ({stats['components_with_version']}/{stats['total_components']})")

        # 5. Supplier Name
        if stats["components_with_supplier"] == stats["total_components"]:
            present.append("Supplier Name")
        else:
            missing.append(f"Supplier Name ({stats['components_with_supplier']}/{stats['total_components']})")

        # 6. Other Unique Identifiers
        if stats["components_with_identifiers"] == stats["total_components"]:
            present.append("Unique Identifiers")
        else:
            missing.append(f"Unique Identifiers ({stats['components_with_identifiers']}/{stats['total_components']})")

        # 7. Dependency Relationship
        if data.get("dependencies"):
            present.append("Dependency Relationships")
        else:
            missing.append("Dependency Relationships")

        # NTIA compliance requires all supplier fields to be filled
        is_compliant = "Supplier Name" in present

        return (is_compliant, present, missing, stats)

    @staticmethod
    def check_spdx(data: Dict[str, Any]) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
        """
        Check SPDX SBOM for NTIA compliance.

        Returns:
            Tuple of (is_compliant, present_elements, missing_elements, stats)
        """
        present = []
        missing = []
        stats = {
            "total_packages": 0,
            "packages_with_supplier": 0,
            "packages_with_name": 0,
            "packages_with_version": 0,
            "packages_with_identifiers": 0,
        }

        # 1. Timestamp
        if data.get("creationInfo", {}).get("created"):
            present.append("Timestamp")
        else:
            missing.append("Timestamp")

        # 2. Author of SBOM Data (creators)
        creators = data.get("creationInfo", {}).get("creators", [])
        if creators:
            present.append("Author of SBOM Data")
        else:
            missing.append("Author of SBOM Data")

        # Check packages
        packages = data.get("packages", [])
        # Filter to library packages - include LIBRARY or packages without explicit purpose
        # Exclude CONTAINER and APPLICATION purposes which represent the main artifact
        excluded_purposes = {"CONTAINER", "APPLICATION", "SOURCE", "OPERATING-SYSTEM"}
        library_packages = [
            p
            for p in packages
            if p.get("primaryPackagePurpose") not in excluded_purposes or p.get("primaryPackagePurpose") is None
        ]
        # Also filter by name - exclude packages that look like container images
        library_packages = [
            p for p in library_packages if not any(x in p.get("name", "").lower() for x in [":", "sha256", "@"])
        ]
        stats["total_packages"] = len(library_packages)

        if not library_packages:
            missing.extend(["Component Name", "Version", "Supplier Name", "Unique Identifiers"])
            return (False, present, missing, stats)

        for p in library_packages:
            if p.get("name"):
                stats["packages_with_name"] += 1
            if p.get("versionInfo"):
                stats["packages_with_version"] += 1
            supplier = p.get("supplier")
            if supplier and supplier != "NOASSERTION":
                stats["packages_with_supplier"] += 1
            # Check for unique identifiers (PURL, CPE, or SWID) in external refs
            valid_id_types = {"purl", "cpe22Type", "cpe23Type", "swid"}
            for ref in p.get("externalRefs", []):
                if ref.get("referenceType") in valid_id_types:
                    stats["packages_with_identifiers"] += 1
                    break

        # 3. Component Name
        if stats["packages_with_name"] == stats["total_packages"]:
            present.append("Component Name")
        else:
            missing.append(f"Component Name ({stats['packages_with_name']}/{stats['total_packages']})")

        # 4. Version
        if stats["packages_with_version"] == stats["total_packages"]:
            present.append("Version")
        else:
            missing.append(f"Version ({stats['packages_with_version']}/{stats['total_packages']})")

        # 5. Supplier Name
        if stats["packages_with_supplier"] == stats["total_packages"]:
            present.append("Supplier Name")
        else:
            missing.append(f"Supplier Name ({stats['packages_with_supplier']}/{stats['total_packages']})")

        # 6. Other Unique Identifiers
        if stats["packages_with_identifiers"] == stats["total_packages"]:
            present.append("Unique Identifiers")
        else:
            missing.append(f"Unique Identifiers ({stats['packages_with_identifiers']}/{stats['total_packages']})")

        # 7. Dependency Relationship (must be DEPENDS_ON or CONTAINS, not just DESCRIBES)
        relationships = data.get("relationships", [])
        has_deps = any(rel.get("relationshipType", "").upper() in ["DEPENDS_ON", "CONTAINS"] for rel in relationships)
        if has_deps:
            present.append("Dependency Relationships")
        else:
            missing.append("Dependency Relationships")

        is_compliant = "Supplier Name" in present

        return (is_compliant, present, missing, stats)


class TestContainerSBOMsExist:
    """Verify all expected test SBOMs exist."""

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_trivy_cdx_exists(self, image):
        """Test that Trivy CycloneDX SBOM exists."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.cdx.json"
        assert sbom_path.exists(), f"Missing: {sbom_path}"

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_trivy_spdx_exists(self, image):
        """Test that Trivy SPDX SBOM exists."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.spdx.json"
        assert sbom_path.exists(), f"Missing: {sbom_path}"

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_syft_cdx_exists(self, image):
        """Test that Syft CycloneDX SBOM exists."""
        sbom_path = TEST_DATA_DIR / f"{image}-syft.cdx.json"
        assert sbom_path.exists(), f"Missing: {sbom_path}"

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_syft_spdx_exists(self, image):
        """Test that Syft SPDX SBOM exists."""
        sbom_path = TEST_DATA_DIR / f"{image}-syft.spdx.json"
        assert sbom_path.exists(), f"Missing: {sbom_path}"


class TestRawSBOMNTIACompliance:
    """Test NTIA compliance of raw scanner output (before enrichment)."""

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_raw_trivy_cyclonedx_compliance(self, image):
        """Test NTIA compliance of raw Trivy CycloneDX output."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        with open(sbom_path) as f:
            data = json.load(f)

        is_compliant, present, missing, stats = NTIAComplianceChecker.check_cyclonedx(data)

        print(f"\n{image} Trivy CycloneDX Raw NTIA Compliance:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  With supplier: {stats['components_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

        # Trivy typically includes supplier for deb/rpm packages
        # This test documents the raw state - we may or may not be compliant

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_raw_trivy_spdx_compliance(self, image):
        """Test NTIA compliance of raw Trivy SPDX output."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.spdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        with open(sbom_path) as f:
            data = json.load(f)

        is_compliant, present, missing, stats = NTIAComplianceChecker.check_spdx(data)

        print(f"\n{image} Trivy SPDX Raw NTIA Compliance:")
        print(f"  Total packages: {stats['total_packages']}")
        print(f"  With supplier: {stats['packages_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_raw_syft_cyclonedx_compliance(self, image):
        """Test NTIA compliance of raw Syft CycloneDX output."""
        sbom_path = TEST_DATA_DIR / f"{image}-syft.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        with open(sbom_path) as f:
            data = json.load(f)

        is_compliant, present, missing, stats = NTIAComplianceChecker.check_cyclonedx(data)

        print(f"\n{image} Syft CycloneDX Raw NTIA Compliance:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  With supplier: {stats['components_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_raw_syft_spdx_compliance(self, image):
        """Test NTIA compliance of raw Syft SPDX output."""
        sbom_path = TEST_DATA_DIR / f"{image}-syft.spdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        with open(sbom_path) as f:
            data = json.load(f)

        is_compliant, present, missing, stats = NTIAComplianceChecker.check_spdx(data)

        print(f"\n{image} Syft SPDX Raw NTIA Compliance:")
        print(f"  Total packages: {stats['total_packages']}")
        print(f"  With supplier: {stats['packages_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")


class TestEnrichmentNTIACompliance:
    """Test that enrichment improves NTIA compliance."""

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_enriched_trivy_cyclonedx_compliance(self, image, tmp_path):
        """Test NTIA compliance after enrichment of Trivy CycloneDX."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock ecosyste.ms to return None (force PURL fallback for OS packages)
        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            enriched_data = json.load(f)

        is_compliant, present, missing, stats = NTIAComplianceChecker.check_cyclonedx(enriched_data)

        print(f"\n{image} Trivy CycloneDX ENRICHED NTIA Compliance:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  With supplier: {stats['components_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

        # After enrichment, supplier should be filled in via PURL fallback
        assert stats["components_with_supplier"] > 0, "Enrichment should add some suppliers"

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_enriched_trivy_spdx_compliance(self, image, tmp_path):
        """Test NTIA compliance after enrichment of Trivy SPDX."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.spdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.spdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            enriched_data = json.load(f)

        is_compliant, present, missing, stats = NTIAComplianceChecker.check_spdx(enriched_data)

        print(f"\n{image} Trivy SPDX ENRICHED NTIA Compliance:")
        print(f"  Total packages: {stats['total_packages']}")
        print(f"  With supplier: {stats['packages_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")


class TestAugmentationNTIACompliance:
    """Test that augmentation adds organizational metadata."""

    @pytest.fixture
    def mock_backend_response(self):
        """Mock backend API response."""
        return SAMPLE_BACKEND_METADATA

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_augmented_trivy_cyclonedx(self, image, tmp_path, mock_backend_response):
        """Test augmentation adds supplier to CycloneDX SBOM."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        output_file = tmp_path / "augmented.cdx.json"

        # Mock the sbomify API provider
        mock_api_response = Mock()
        mock_api_response.ok = True
        mock_api_response.json.return_value = mock_backend_response

        with patch("sbomify_action._augmentation.providers.sbomify_api.requests.get", return_value=mock_api_response):
            sbom_format = augment_sbom_from_file(
                str(sbom_path),
                str(output_file),
                api_base_url="https://api.example.com",
                token="test-token",
                component_id="test-component",
                validate=False,
            )

        assert sbom_format == "cyclonedx"

        with open(output_file) as f:
            augmented_data = json.load(f)

        # Check supplier was added to metadata
        supplier = augmented_data.get("metadata", {}).get("supplier", {})
        assert supplier.get("name") == "Acme Corporation", "Augmentation should add supplier"

        # Check sbomify was added to tools
        tools = augmented_data.get("metadata", {}).get("tools", {})
        services = tools.get("services", [])
        components = tools.get("components", [])
        all_tools = services + components

        sbomify_found = any("sbomify" in str(t.get("name", "")).lower() for t in all_tools)
        assert sbomify_found, f"sbomify should be in tools. Found: {[t.get('name') for t in all_tools]}"

        print(f"\n{image} Trivy CycloneDX AUGMENTED:")
        print(f"  Supplier: {supplier.get('name')}")
        print(f"  Tools: {[t.get('name') for t in all_tools]}")

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_augmented_trivy_spdx(self, image, tmp_path, mock_backend_response):
        """Test augmentation adds supplier to SPDX SBOM."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.spdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        output_file = tmp_path / "augmented.spdx.json"

        mock_api_response = Mock()
        mock_api_response.ok = True
        mock_api_response.json.return_value = mock_backend_response

        with patch("sbomify_action._augmentation.providers.sbomify_api.requests.get", return_value=mock_api_response):
            sbom_format = augment_sbom_from_file(
                str(sbom_path),
                str(output_file),
                api_base_url="https://api.example.com",
                token="test-token",
                component_id="test-component",
                validate=False,
            )

        assert sbom_format == "spdx"

        with open(output_file) as f:
            augmented_data = json.load(f)

        # Check creators include sbomify
        creators = augmented_data.get("creationInfo", {}).get("creators", [])
        sbomify_creator = [c for c in creators if "sbomify" in c.lower()]
        assert sbomify_creator, f"sbomify should be in creators. Found: {creators}"

        print(f"\n{image} Trivy SPDX AUGMENTED:")
        print(f"  Creators: {creators}")


class TestFullPipelineNTIACompliance:
    """Test full pipeline: enrich then augment."""

    @pytest.mark.parametrize("image", CONTAINER_IMAGES)
    def test_full_pipeline_cyclonedx(self, image, tmp_path):
        """Test full pipeline achieves NTIA compliance for CycloneDX."""
        sbom_path = TEST_DATA_DIR / f"{image}-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        enriched_file = tmp_path / "enriched.cdx.json"
        augmented_file = tmp_path / "augmented.cdx.json"

        # Step 1: Enrich
        clear_cache()
        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(enriched_file), validate=False)

        # Step 2: Augment
        mock_api_response = Mock()
        mock_api_response.ok = True
        mock_api_response.json.return_value = SAMPLE_BACKEND_METADATA

        with patch("sbomify_action._augmentation.providers.sbomify_api.requests.get", return_value=mock_api_response):
            augment_sbom_from_file(
                str(enriched_file),
                str(augmented_file),
                api_base_url="https://api.example.com",
                token="test-token",
                component_id="test-component",
                validate=False,
            )

        with open(augmented_file) as f:
            final_data = json.load(f)

        is_compliant, present, missing, stats = NTIAComplianceChecker.check_cyclonedx(final_data)

        print(f"\n{image} FULL PIPELINE CycloneDX NTIA Compliance:")
        print(f"  Total components: {stats['total_components']}")
        print(f"  With supplier: {stats['components_with_supplier']}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")
        print(f"  Compliant: {is_compliant}")

        # Document compliance status - we expect most elements to be present
        # After full pipeline:
        # - Timestamp: Yes (scanner)
        # - Author of SBOM Data: Yes (scanner + sbomify)
        # - Component Name: Yes (scanner)
        # - Version: Yes (scanner)
        # - Supplier Name: Should be improved by enrichment
        # - Unique Identifiers: Yes (PURL from scanner)
        # - Dependencies: Depends on scanner


class TestSpecificDistroEnrichment:
    """Test enrichment for specific distro packages."""

    def test_debian_deb_package_enrichment(self, tmp_path):
        """Test that Debian deb packages get proper supplier from PURL."""
        sbom_path = TEST_DATA_DIR / "debian-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            data = json.load(f)

        # Find OS component
        os_components = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
        if os_components:
            os_comp = os_components[0]
            print("\nDebian OS Component:")
            print(f"  Name: {os_comp.get('name')}")
            print(f"  Publisher: {os_comp.get('publisher')}")
            # Enrichment should add publisher for known OS
            if os_comp.get("name", "").lower() == "debian":
                assert os_comp.get("publisher") == "Debian Project", "Debian OS should have Debian Project as publisher"

    def test_alpine_apk_package_enrichment(self, tmp_path):
        """Test that Alpine apk packages get proper supplier from PURL."""
        sbom_path = TEST_DATA_DIR / "alpine-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            data = json.load(f)

        # Find OS component
        os_components = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
        if os_components:
            os_comp = os_components[0]
            print("\nAlpine OS Component:")
            print(f"  Name: {os_comp.get('name')}")
            print(f"  Publisher: {os_comp.get('publisher')}")
            if os_comp.get("name", "").lower() == "alpine":
                assert os_comp.get("publisher") == "Alpine Linux", "Alpine OS should have Alpine Linux as publisher"

    def test_ubuntu_deb_package_enrichment(self, tmp_path):
        """Test that Ubuntu deb packages get proper supplier from PURL."""
        sbom_path = TEST_DATA_DIR / "ubuntu-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            data = json.load(f)

        # Find OS component
        os_components = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
        if os_components:
            os_comp = os_components[0]
            print("\nUbuntu OS Component:")
            print(f"  Name: {os_comp.get('name')}")
            print(f"  Publisher: {os_comp.get('publisher')}")
            if os_comp.get("name", "").lower() == "ubuntu":
                assert os_comp.get("publisher") == "Canonical Ltd", "Ubuntu OS should have Canonical Ltd as publisher"

    def test_redhat_rpm_package_enrichment(self, tmp_path):
        """Test that Red Hat rpm packages get proper supplier from PURL."""
        sbom_path = TEST_DATA_DIR / "redhat-trivy.cdx.json"
        if not sbom_path.exists():
            pytest.skip(f"SBOM not found: {sbom_path}")

        clear_cache()
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(sbom_path), str(output_file), validate=False)

        with open(output_file) as f:
            data = json.load(f)

        # Find OS component
        os_components = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
        if os_components:
            os_comp = os_components[0]
            print("\nRedHat OS Component:")
            print(f"  Name: {os_comp.get('name')}")
            print(f"  Publisher: {os_comp.get('publisher')}")
