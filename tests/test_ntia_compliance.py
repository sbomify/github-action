"""
Tests for NTIA Minimum Elements compliance validation.

NTIA Minimum Elements for SBOM (July 2021):
1. Supplier Name - Entity that created/distributed the component
2. Component Name - Designation assigned by original supplier
3. Version - Change state identifier
4. Other Unique Identifiers - PURLs, CPE, etc.
5. Dependency Relationship - How components relate
6. Author of SBOM Data - Entity that created the SBOM
7. Timestamp - Date/time SBOM was assembled
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import Mock, patch

import pytest
from cyclonedx.model.bom import Bom

from sbomify_action.enrichment import clear_cache, enrich_sbom


class NTIAComplianceChecker:
    """Utility class to check NTIA Minimum Elements compliance."""

    # Known lockfile names that should be excluded from NTIA compliance checks
    LOCKFILE_NAMES = {
        "requirements.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
        "conda-lock.yml",
        "Cargo.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
        "Gemfile.lock",
        "go.sum",
        "go.mod",
        "pubspec.lock",
        "conan.lock",
        "vcpkg.json",
    }

    @staticmethod
    def _is_lockfile_component(component: Dict[str, Any]) -> bool:
        """Check if a component is a lockfile artifact (not a real package)."""
        # Must be application type
        if component.get("type") != "application":
            return False
        # Must have no PURL
        if component.get("purl"):
            return False
        # Must match known lockfile name
        return component.get("name") in NTIAComplianceChecker.LOCKFILE_NAMES

    @staticmethod
    def check_cyclonedx(data: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        """
        Check CycloneDX SBOM for NTIA compliance.

        Note: Lockfile components (e.g., requirements.txt, uv.lock) are excluded
        from compliance checks as they are metadata artifacts, not software packages.

        Returns:
            Tuple of (is_compliant, present_elements, missing_elements)
        """
        present = []
        missing = []

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

        # Check components (excluding lockfile artifacts)
        all_components = data.get("components", [])
        components = [c for c in all_components if not NTIAComplianceChecker._is_lockfile_component(c)]
        if not components:
            missing.extend(["Component Name", "Version", "Supplier Name", "Unique Identifiers"])
            return (False, present, missing)

        # Check each component for required fields
        all_have_name = all(c.get("name") for c in components)
        all_have_version = all(c.get("version") for c in components)

        # Supplier validation: publisher (string) or supplier.name (dict) or supplier (string)
        def has_valid_supplier(c):
            if c.get("publisher"):
                return True
            supplier = c.get("supplier")
            if isinstance(supplier, dict) and supplier.get("name"):
                return True
            if isinstance(supplier, str) and supplier:
                return True
            return False

        all_have_supplier = all(has_valid_supplier(c) for c in components)

        # Unique identifier validation: PURL, CPE, or valid SWID (object with tagId and name)
        def has_valid_identifier(c):
            if c.get("purl") or c.get("cpe"):
                return True
            swid = c.get("swid")
            if isinstance(swid, dict) and swid.get("tagId") and swid.get("name"):
                return True
            return False

        all_have_identifiers = all(has_valid_identifier(c) for c in components)

        # 3. Component Name
        if all_have_name:
            present.append("Component Name")
        else:
            missing.append("Component Name")

        # 4. Version
        if all_have_version:
            present.append("Version")
        else:
            missing.append("Version")

        # 5. Supplier Name
        if all_have_supplier:
            present.append("Supplier Name")
        else:
            missing.append("Supplier Name")

        # 6. Other Unique Identifiers
        if all_have_identifiers:
            present.append("Unique Identifiers")
        else:
            missing.append("Unique Identifiers")

        # 7. Dependency Relationship
        if data.get("dependencies"):
            present.append("Dependency Relationships")
        else:
            missing.append("Dependency Relationships")

        is_compliant = len(missing) == 0
        return (is_compliant, present, missing)

    @staticmethod
    def check_spdx(data: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        """
        Check SPDX SBOM for NTIA compliance.

        Returns:
            Tuple of (is_compliant, present_elements, missing_elements)
        """
        present = []
        missing = []

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
        if not packages:
            missing.extend(["Component Name", "Version", "Supplier Name", "Unique Identifiers"])
            return (False, present, missing)

        # Check each package for required fields
        all_have_name = all(p.get("name") for p in packages)
        all_have_version = all(p.get("versionInfo") for p in packages)

        # Supplier should not be NOASSERTION
        def has_valid_supplier(p):
            supplier = p.get("supplier")
            return supplier and supplier != "NOASSERTION"

        all_have_supplier = all(has_valid_supplier(p) for p in packages)

        # Check for unique identifiers (PURL, CPE, or SWID) in external references
        def has_unique_id(p):
            valid_types = {"purl", "cpe22Type", "cpe23Type", "swid"}
            for ref in p.get("externalRefs", []):
                if ref.get("referenceType") in valid_types:
                    return True
            return False

        all_have_identifiers = all(has_unique_id(p) for p in packages)

        # 3. Component Name
        if all_have_name:
            present.append("Component Name")
        else:
            missing.append("Component Name")

        # 4. Version
        if all_have_version:
            present.append("Version")
        else:
            missing.append("Version")

        # 5. Supplier Name
        if all_have_supplier:
            present.append("Supplier Name")
        else:
            missing.append("Supplier Name")

        # 6. Other Unique Identifiers
        if all_have_identifiers:
            present.append("Unique Identifiers")
        else:
            missing.append("Unique Identifiers")

        # 7. Dependency Relationship (must be DEPENDS_ON or CONTAINS, not just DESCRIBES)
        relationships = data.get("relationships", [])
        has_deps = any(rel.get("relationshipType", "").upper() in ["DEPENDS_ON", "CONTAINS"] for rel in relationships)
        if has_deps:
            present.append("Dependency Relationships")
        else:
            missing.append("Dependency Relationships")

        is_compliant = len(missing) == 0
        return (is_compliant, present, missing)


class TestNTIAComplianceCycloneDX:
    """Test NTIA compliance for CycloneDX SBOMs."""

    @pytest.fixture
    def trivy_cdx_path(self):
        """Path to Trivy CycloneDX test data."""
        return Path(__file__).parent / "test-data" / "trivy.cdx.json"

    @pytest.fixture
    def ecosystems_metadata(self):
        """Sample ecosyste.ms metadata for enrichment."""
        return {
            "pkg:pypi/django@5.1": {
                "description": "A high-level Python web framework",
                "homepage": "https://www.djangoproject.com/",
                "repository_url": "https://github.com/django/django",
                "registry_url": "https://pypi.org/project/django/",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Django Software Foundation", "login": "django"}],
            },
            "pkg:pypi/asgiref@3.8.1": {
                "description": "ASGI specs, helper code, and adapters",
                "homepage": "https://github.com/django/asgiref",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Django Software Foundation"}],
            },
            "pkg:pypi/sqlparse@0.5.1": {
                "description": "A non-validating SQL parser",
                "homepage": "https://github.com/andialbrecht/sqlparse",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Andi Albrecht"}],
            },
        }

    def test_raw_trivy_sbom_missing_supplier(self, trivy_cdx_path):
        """Test that raw Trivy SBOM is missing supplier (NTIA requirement)."""
        with open(trivy_cdx_path) as f:
            data = json.load(f)

        # Filter out lockfile components (requirements.txt) for compliance check
        library_components = [c for c in data.get("components", []) if c.get("type") == "library"]

        # Raw scanner output should be missing supplier
        for component in library_components:
            assert component.get("publisher") is None, (
                f"Component {component['name']} should not have publisher in raw output"
            )
            assert component.get("supplier") is None, (
                f"Component {component['name']} should not have supplier in raw output"
            )

        # But should have other NTIA elements
        for component in library_components:
            assert component.get("name"), "Component should have name"
            assert component.get("version"), "Component should have version"
            assert component.get("purl"), "Component should have PURL"

        # Check timestamp and tools are present
        assert data.get("metadata", {}).get("timestamp"), "Should have timestamp"
        assert data.get("metadata", {}).get("tools"), "Should have tools"

    def test_enriched_sbom_has_supplier(self, trivy_cdx_path, ecosystems_metadata, tmp_path):
        """Test that enriched SBOM has supplier field populated (NTIA compliant).

        Uses PyPI API as native source for Python packages (new plugin architecture).
        """
        clear_cache()

        # Mock PyPI HTTP responses at the source level
        def mock_get(url, *args, **kwargs):
            mock_response = Mock()
            # Parse package name from URL
            if "pypi.org/pypi/" in url:
                pkg_name = url.split("/pypi/")[1].split("/")[0]
                purl_key = f"pkg:pypi/{pkg_name}@"
                # Find matching metadata
                for key, meta in ecosystems_metadata.items():
                    if purl_key in key or f"pkg:pypi/{pkg_name}@" in key:
                        mock_response.status_code = 200
                        mock_response.json.return_value = {
                            "info": {
                                "summary": meta.get("description"),
                                "home_page": meta.get("homepage"),
                                "license": meta.get("normalized_licenses", [""])[0]
                                if meta.get("normalized_licenses")
                                else "",
                                "author": meta.get("maintainers", [{}])[0].get("name")
                                if meta.get("maintainers")
                                else None,
                                "project_urls": {"Source": meta.get("repository_url")}
                                if meta.get("repository_url")
                                else None,
                            }
                        }
                        return mock_response
            mock_response.status_code = 404
            return mock_response

        with patch("requests.Session.get", side_effect=mock_get):
            output_file = tmp_path / "enriched.cdx.json"
            enrich_sbom(str(trivy_cdx_path), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Filter library components
        library_components = [c for c in enriched_data.get("components", []) if c.get("type") == "library"]

        # All library components should now have publisher
        for component in library_components:
            assert component.get("publisher"), f"Component {component['name']} should have publisher after enrichment"

        # Run NTIA compliance check
        is_compliant, present, missing = NTIAComplianceChecker.check_cyclonedx(enriched_data)

        print("\nNTIA Compliance Check Results:")
        print(f"  Present elements: {present}")
        print(f"  Missing elements: {missing}")

        # Supplier should now be present
        assert "Supplier Name" in present, "Supplier Name should be present after enrichment"

    def test_full_ntia_compliance_after_enrichment(self, trivy_cdx_path, ecosystems_metadata, tmp_path):
        """Test full NTIA compliance after enrichment.

        Uses PyPI API as native source for Python packages (new plugin architecture).
        """
        clear_cache()

        # Mock PyPI HTTP responses at the source level
        def mock_get(url, *args, **kwargs):
            mock_response = Mock()
            if "pypi.org/pypi/" in url:
                pkg_name = url.split("/pypi/")[1].split("/")[0]
                purl_key = f"pkg:pypi/{pkg_name}@"
                for key, meta in ecosystems_metadata.items():
                    if purl_key in key or f"pkg:pypi/{pkg_name}@" in key:
                        mock_response.status_code = 200
                        mock_response.json.return_value = {
                            "info": {
                                "summary": meta.get("description"),
                                "home_page": meta.get("homepage"),
                                "license": meta.get("normalized_licenses", [""])[0]
                                if meta.get("normalized_licenses")
                                else "",
                                "author": meta.get("maintainers", [{}])[0].get("name")
                                if meta.get("maintainers")
                                else None,
                                "project_urls": {"Source": meta.get("repository_url")}
                                if meta.get("repository_url")
                                else None,
                            }
                        }
                        return mock_response
            mock_response.status_code = 404
            return mock_response

        with patch("requests.Session.get", side_effect=mock_get):
            output_file = tmp_path / "enriched.cdx.json"
            enrich_sbom(str(trivy_cdx_path), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        is_compliant, present, missing = NTIAComplianceChecker.check_cyclonedx(enriched_data)

        print("\nNTIA Compliance Check After Enrichment:")
        print(f"  Compliant: {is_compliant}")
        print(f"  Present: {present}")
        print(f"  Missing: {missing}")

        # Enrichment adds supplier, licenses, description, etc. but NOT authors
        # Full NTIA compliance requires augmentation to add authors
        assert "Timestamp" in present
        assert "Component Name" in present
        assert "Version" in present
        assert "Supplier Name" in present
        assert "Unique Identifiers" in present
        assert "Dependency Relationships" in present
        # Note: "Author of SBOM Data" requires metadata.authors which comes from augmentation, not enrichment


class TestNTIAComplianceSPDX:
    """Test NTIA compliance for SPDX SBOMs."""

    @pytest.fixture
    def trivy_spdx_path(self):
        """Path to Trivy SPDX test data."""
        return Path(__file__).parent / "test-data" / "trivy.spdx.json"

    @pytest.fixture
    def ecosystems_metadata(self):
        """Sample ecosyste.ms metadata for enrichment."""
        return {
            "pkg:pypi/django@5.1": {
                "description": "A high-level Python web framework",
                "homepage": "https://www.djangoproject.com/",
                "repository_url": "https://github.com/django/django",
                "registry_url": "https://pypi.org/project/django/",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Django Software Foundation", "login": "django"}],
                "ecosystem": "PyPI",
            },
            "pkg:pypi/asgiref@3.8.1": {
                "description": "ASGI specs, helper code, and adapters",
                "homepage": "https://github.com/django/asgiref",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Django Software Foundation"}],
                "ecosystem": "PyPI",
            },
            "pkg:pypi/sqlparse@0.5.1": {
                "description": "A non-validating SQL parser",
                "homepage": "https://github.com/andialbrecht/sqlparse",
                "normalized_licenses": ["BSD-3-Clause"],
                "maintainers": [{"name": "Andi Albrecht"}],
                "ecosystem": "PyPI",
            },
        }

    def test_raw_trivy_spdx_has_noassertion_supplier(self, trivy_spdx_path):
        """Test that raw Trivy SPDX SBOM has NOASSERTION for supplier."""
        with open(trivy_spdx_path) as f:
            data = json.load(f)

        # Filter out non-library packages
        library_packages = [p for p in data.get("packages", []) if p.get("primaryPackagePurpose") == "LIBRARY"]

        # Raw scanner output has NOASSERTION for supplier
        for package in library_packages:
            assert package.get("supplier") == "NOASSERTION", (
                f"Package {package['name']} should have NOASSERTION supplier in raw output"
            )

        # But should have other elements
        for package in library_packages:
            assert package.get("name"), "Package should have name"
            assert package.get("versionInfo"), "Package should have version"

    def test_enriched_spdx_has_originator_and_metadata(self, trivy_spdx_path, ecosystems_metadata, tmp_path):
        """Test that enriched SPDX SBOM has originator and other metadata populated.

        Note: SPDX supplier handling is complex - the spdx-tools library may preserve
        NOASSERTION if already set. We verify originator is populated (maps to NTIA
        Author requirement at the package level) and other fields are enriched.
        """
        clear_cache()

        # Mock PyPI response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Test description",
                "home_page": "https://example.com",
                "license": "MIT",
                "author": "Test Author",
            }
        }

        output_file = tmp_path / "enriched.spdx.json"
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(trivy_spdx_path), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Filter library packages
        library_packages = [p for p in enriched_data.get("packages", []) if p.get("primaryPackagePurpose") == "LIBRARY"]

        # All library packages should now have originator (relates to supplier/author)
        for package in library_packages:
            originator = package.get("originator")
            assert originator and originator != "NOASSERTION", (
                f"Package {package['name']} should have valid originator after enrichment"
            )
            # Also check description was enriched
            assert package.get("description"), f"Package {package['name']} should have description after enrichment"
            # Also check homepage was enriched
            assert package.get("homepage"), f"Package {package['name']} should have homepage after enrichment"

        print("\nSPDX Enrichment Results:")
        for package in library_packages:
            print(f"  {package['name']}:")
            print(f"    originator = {package.get('originator')}")
            print(f"    description = {package.get('description')[:50] if package.get('description') else None}...")


class TestNTIAPURLFallback:
    """Test PURL-based enrichment for OS packages when ecosyste.ms has no data."""

    def test_debian_package_purl_fallback(self, tmp_path):
        """Test that Debian packages get supplier from PURL namespace."""
        clear_cache()

        # Create a Debian-based SBOM
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "operating-system",
                    "name": "debian",
                    "version": "12",
                    "bom-ref": "os-debian",
                },
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2.15-2",
                    "purl": "pkg:deb/debian/bash@5.2.15-2?distro=debian-12",
                    "bom-ref": "pkg-bash",
                },
                {
                    "type": "library",
                    "name": "coreutils",
                    "version": "9.1-1",
                    "purl": "pkg:deb/debian/coreutils@9.1-1?distro=debian-12",
                    "bom-ref": "pkg-coreutils",
                },
            ],
            "dependencies": [
                {"ref": "os-debian", "dependsOn": ["pkg-bash", "pkg-coreutils"]},
                {"ref": "pkg-bash", "dependsOn": []},
                {"ref": "pkg-coreutils", "dependsOn": []},
            ],
        }

        input_file = tmp_path / "debian.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (simulating no data - force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Find OS component
        os_component = next(
            (c for c in enriched_data["components"] if c.get("type") == "operating-system"),
            None,
        )
        assert os_component is not None
        assert os_component.get("publisher") == "Debian Project", "OS component should have Debian Project as publisher"

        # Find library components
        library_components = [c for c in enriched_data["components"] if c.get("type") == "library"]

        for component in library_components:
            assert component.get("publisher") == "Debian Project", (
                f"Component {component['name']} should have Debian Project as publisher from PURL"
            )

        print("\nPURL Fallback Results (Debian):")
        for component in enriched_data["components"]:
            print(f"  {component['name']}: publisher = {component.get('publisher')}")

    def test_alpine_package_purl_fallback(self, tmp_path):
        """Test that Alpine packages get supplier from PURL namespace."""
        clear_cache()

        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "busybox",
                    "version": "1.36.1-r15",
                    "purl": "pkg:apk/alpine/busybox@1.36.1-r15?distro=alpine-3.19",
                    "bom-ref": "pkg-busybox",
                },
            ],
            "dependencies": [{"ref": "pkg-busybox", "dependsOn": []}],
        }

        input_file = tmp_path / "alpine.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (simulating no data - force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        component = enriched_data["components"][0]
        assert component.get("publisher") == "Alpine Linux", "Component should have Alpine Linux as publisher from PURL"

    def test_rpm_package_purl_fallback(self, tmp_path):
        """Test that RPM packages get supplier from PURL namespace."""
        clear_cache()

        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2.15-5.fc39",
                    "purl": "pkg:rpm/fedora/bash@5.2.15-5.fc39?distro=fedora-39",
                    "bom-ref": "pkg-bash",
                },
            ],
            "dependencies": [{"ref": "pkg-bash", "dependsOn": []}],
        }

        input_file = tmp_path / "fedora.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock API responses to 404 (simulating no data - force PURL fallback)
        mock_response = Mock()
        mock_response.status_code = 404
        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        component = enriched_data["components"][0]
        assert component.get("publisher") == "Fedora Project", (
            "Component should have Fedora Project as publisher from PURL"
        )


class TestNTIAAugmentation:
    """Test that augmentation adds supplier and tool metadata."""

    @pytest.fixture
    def sample_backend_metadata(self):
        """Sample backend metadata for augmentation."""
        return {
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
            "licenses": ["MIT"],
        }

    def test_augmentation_adds_supplier_cyclonedx(self, sample_backend_metadata, tmp_path):
        """Test that augmentation adds supplier to CycloneDX SBOM."""
        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Create a minimal CycloneDX BOM with valid UUID
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "my-lib",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/my-lib@1.0.0",
                },
            ],
        }
        bom = Bom.from_json(bom_json)

        # Augment with backend metadata
        augmented_bom = augment_cyclonedx_sbom(bom, sample_backend_metadata, spec_version="1.6")

        # Check supplier was added
        assert augmented_bom.metadata.supplier is not None
        assert augmented_bom.metadata.supplier.name == "Acme Corporation"

        # Check sbomify was added as a tool/service (for 1.6, uses services)
        services = list(augmented_bom.metadata.tools.services) if augmented_bom.metadata.tools.services else []
        components = list(augmented_bom.metadata.tools.components) if augmented_bom.metadata.tools.components else []

        # sbomify should be added as service for 1.5+
        sbomify_found = any("sbomify" in s.name.lower() for s in services)
        if not sbomify_found:
            # Might be in components or tools for different versions
            sbomify_found = any("sbomify" in c.name.lower() for c in components)

        assert sbomify_found, (
            f"sbomify should be added to tools. Services: {[s.name for s in services]}, Components: {[c.name for c in components]}"
        )

        print("\nAugmentation Results (CycloneDX):")
        print(f"  Supplier: {augmented_bom.metadata.supplier.name}")
        print(f"  Tools/Services: {[s.name for s in services]}")

    def test_augmentation_adds_supplier_spdx(self, sample_backend_metadata, tmp_path):
        """Test that augmentation adds supplier to SPDX SBOM."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            ActorType,
            CreationInfo,
            Document,
            Package,
        )

        from sbomify_action.augmentation import augment_spdx_sbom

        # Create a minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-sbom",
            document_namespace="https://example.com/test",
            creators=[],
            created=datetime.now(),
        )
        document = Document(
            creation_info=creation_info,
            packages=[
                Package(
                    spdx_id="SPDXRef-main",
                    name="my-app",
                    download_location="https://example.com/download",
                    version="1.0.0",
                ),
            ],
            relationships=[],
        )

        # Augment with backend metadata
        augmented_doc = augment_spdx_sbom(document, sample_backend_metadata)

        # Check supplier was added to main package
        main_package = augmented_doc.packages[0]
        assert main_package.supplier is not None
        assert main_package.supplier.actor_type == ActorType.ORGANIZATION
        assert "Acme Corporation" in main_package.supplier.name

        # Check sbomify was added to creators
        creator_names = [str(c) for c in augmented_doc.creation_info.creators]
        sbomify_creator = next((c for c in creator_names if "sbomify" in c.lower()), None)
        assert sbomify_creator is not None, "sbomify should be added to creators"

        print("\nAugmentation Results (SPDX):")
        print(f"  Supplier: {main_package.supplier.name}")
        print(f"  Creators: {creator_names}")


class TestNTIAValidationFunction:
    """Test the NTIA compliance validation function."""

    def test_compliance_checker_cyclonedx_compliant(self):
        """Test compliance checker with a fully compliant CycloneDX SBOM."""
        compliant_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool"}]},
                "authors": [{"name": "Test Author", "email": "test@example.com"}],
            },
            "components": [
                {
                    "type": "library",
                    "name": "test-lib",
                    "version": "1.0.0",
                    "publisher": "Test Publisher",
                    "purl": "pkg:pypi/test-lib@1.0.0",
                },
            ],
            "dependencies": [{"ref": "test-lib", "dependsOn": []}],
        }

        is_compliant, present, missing = NTIAComplianceChecker.check_cyclonedx(compliant_sbom)

        assert is_compliant, f"SBOM should be compliant. Missing: {missing}"
        assert len(missing) == 0
        assert "Supplier Name" in present
        assert "Timestamp" in present
        assert "Author of SBOM Data" in present

    def test_compliance_checker_cyclonedx_missing_supplier(self):
        """Test compliance checker detects missing supplier."""
        non_compliant_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "test-lib",
                    "version": "1.0.0",
                    # No publisher!
                    "purl": "pkg:pypi/test-lib@1.0.0",
                },
            ],
            "dependencies": [{"ref": "test-lib", "dependsOn": []}],
        }

        is_compliant, present, missing = NTIAComplianceChecker.check_cyclonedx(non_compliant_sbom)

        assert not is_compliant, "SBOM should NOT be compliant without supplier"
        assert "Supplier Name" in missing

    def test_compliance_checker_spdx_compliant(self):
        """Test compliance checker with a fully compliant SPDX SBOM."""
        compliant_sbom = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test-tool-1.0"],
            },
            "packages": [
                {
                    "name": "test-pkg",
                    "versionInfo": "1.0.0",
                    "supplier": "Organization: Test Supplier",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/test-pkg@1.0.0"},
                    ],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Package",
                },
                {
                    "spdxElementId": "SPDXRef-Package",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": "SPDXRef-Dep",
                },
            ],
        }

        is_compliant, present, missing = NTIAComplianceChecker.check_spdx(compliant_sbom)

        assert is_compliant, f"SBOM should be compliant. Missing: {missing}"
        assert "Supplier Name" in present
        assert "Dependency Relationships" in present

    def test_compliance_checker_spdx_noassertion_supplier(self):
        """Test compliance checker detects NOASSERTION as invalid supplier."""
        non_compliant_sbom = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test-tool-1.0"],
            },
            "packages": [
                {
                    "name": "test-pkg",
                    "versionInfo": "1.0.0",
                    "supplier": "NOASSERTION",  # Invalid!
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/test-pkg@1.0.0"},
                    ],
                },
            ],
            "relationships": [],
        }

        is_compliant, present, missing = NTIAComplianceChecker.check_spdx(non_compliant_sbom)

        assert not is_compliant, "SBOM should NOT be compliant with NOASSERTION supplier"
        assert "Supplier Name" in missing


class TestNTIAEdgeCases:
    """Test edge cases that were previously not covered by NTIA tests."""

    def test_pypi_author_email_without_author(self, tmp_path):
        """Test that packages with empty author but valid author_email get supplier.

        This tests the uri-template scenario: author="" but author_email="Peter Linss <email>"
        """
        from sbomify_action.enrichment import clear_cache, enrich_sbom

        clear_cache()

        # Create SBOM with a package that will be looked up
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
            },
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/test-package@1.0.0",
                    "bom-ref": "pkg:pypi/test-package@1.0.0",
                },
            ],
            "dependencies": [{"ref": "pkg:pypi/test-package@1.0.0", "dependsOn": []}],
        }

        input_file = tmp_path / "test.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock PyPI response with empty author but valid author_email (like uri-template)
        def mock_get(url, *args, **kwargs):
            mock_response = Mock()
            if "pypi.org/pypi/" in url:
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "info": {
                        "summary": "Test package description",
                        "author": "",  # Empty author!
                        "author_email": "Test Author <test@example.com>",  # But valid author_email
                        "maintainer": "",
                        "maintainer_email": "",
                        "license": "MIT",
                        "home_page": "https://example.com",
                    }
                }
            else:
                mock_response.status_code = 404
            return mock_response

        with patch("requests.Session.get", side_effect=mock_get):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Verify the component got supplier from author_email
        component = enriched_data["components"][0]
        assert component.get("publisher") == "Test Author", (
            f"Expected publisher 'Test Author' from author_email, got: {component.get('publisher')}"
        )

    def test_lockfile_components_have_version(self, tmp_path):
        """Test that lockfile components get version after enrichment.

        Previously, lockfiles were excluded from NTIA checks but they should
        still have compliant metadata including version.
        """
        from sbomify_action.enrichment import clear_cache, enrich_sbom

        clear_cache()

        # Create SBOM with lockfile component (no version, no purl)
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
                "component": {
                    "type": "application",
                    "name": "my-project",
                    "version": "1.2.3",
                },
            },
            "components": [
                {
                    "type": "application",
                    "name": "uv.lock",
                    "bom-ref": "lockfile-uv",
                    # No version, no purl - this is how Trivy generates lockfile components
                },
            ],
            "dependencies": [{"ref": "lockfile-uv", "dependsOn": []}],
        }

        input_file = tmp_path / "test.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock all external calls to 404
        mock_response = Mock()
        mock_response.status_code = 404

        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Find the lockfile component
        lockfile_component = next(
            (c for c in enriched_data["components"] if c.get("name") == "uv.lock"),
            None,
        )

        assert lockfile_component is not None, "Lockfile component should still exist"
        assert lockfile_component.get("version"), "Lockfile should have version after enrichment"
        assert lockfile_component.get("description"), "Lockfile should have description after enrichment"

    def test_root_component_gets_supplier_from_augmentation(self, tmp_path):
        """Test that root component (metadata.component) gets supplier from backend metadata.

        Previously, augmentation set metadata.supplier but not metadata.component.supplier.
        """
        from cyclonedx.model.bom import Bom

        from sbomify_action.augmentation import augment_cyclonedx_sbom

        # Create a minimal CycloneDX BOM with a root component but no supplier
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
                "component": {
                    "type": "application",
                    "name": "my-project",
                    "version": "1.0.0",
                    # No supplier!
                },
            },
            "components": [],
        }
        bom = Bom.from_json(bom_json)

        # Augmentation data from backend
        augmentation_data = {
            "supplier": {
                "name": "My Company Inc",
                "url": ["https://mycompany.com"],
            },
        }

        # Augment the BOM
        augmented_bom = augment_cyclonedx_sbom(bom, augmentation_data, spec_version="1.6")

        # Verify both metadata.supplier AND metadata.component.supplier are set
        assert augmented_bom.metadata.supplier is not None, "metadata.supplier should be set"
        assert augmented_bom.metadata.supplier.name == "My Company Inc"

        assert augmented_bom.metadata.component is not None, "metadata.component should exist"
        assert augmented_bom.metadata.component.supplier is not None, (
            "metadata.component.supplier should be propagated from backend"
        )
        assert augmented_bom.metadata.component.supplier.name == "My Company Inc"

    def test_self_referencing_component_gets_supplier(self, tmp_path):
        """Test that self-referencing components (project's own package in dependencies) get supplier.

        When a project scans itself, it may include its own package as a dependency.
        This package won't be found in external registries, so it should inherit
        supplier from the root component.
        """
        from sbomify_action.enrichment import clear_cache, enrich_sbom

        clear_cache()

        # Create SBOM where the project includes itself as a dependency
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:44444444-4444-4444-4444-444444444444",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "tools": {"components": [{"type": "application", "name": "test-tool", "version": "1.0"}]},
                "component": {
                    "type": "application",
                    "name": "my-project",
                    "version": "1.0.0",
                },
                "supplier": {
                    "name": "My Company Inc",
                    "url": ["https://mycompany.com"],
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": "my-project",  # Same as root component name!
                    "version": "1.0.0",
                    "purl": "pkg:pypi/my-project@1.0.0",
                    "bom-ref": "pkg:pypi/my-project@1.0.0",
                    # No publisher - this is the project itself, won't be found in PyPI
                },
            ],
            "dependencies": [{"ref": "pkg:pypi/my-project@1.0.0", "dependsOn": []}],
        }

        input_file = tmp_path / "test.cdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.cdx.json"

        # Mock all external calls to 404 (package not found - it's a private project)
        mock_response = Mock()
        mock_response.status_code = 404

        with patch("requests.Session.get", return_value=mock_response):
            enrich_sbom(str(input_file), str(output_file))

        with open(output_file) as f:
            enriched_data = json.load(f)

        # Find the self-referencing component
        self_component = next(
            (c for c in enriched_data["components"] if c.get("name") == "my-project"),
            None,
        )

        assert self_component is not None, "Self-referencing component should exist"
        assert self_component.get("publisher") == "My Company Inc", (
            f"Self-referencing component should inherit publisher from root. Got: {self_component.get('publisher')}"
        )

    def test_ecosystems_does_not_use_platform_as_supplier(self, tmp_path):
        """Test that ecosyste.ms doesn't use platform name (pypi, npm) as supplier.

        Registry/platform names are not valid suppliers - they're distribution channels.
        """
        import requests
        from packageurl import PackageURL

        from sbomify_action._enrichment.sources.ecosystems import EcosystemsSource

        # Create mock response with ecosystem but no maintainer name
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "ecosystem": "pypi",  # Should NOT be used as supplier
                "description": "Test package",
                "normalized_licenses": ["MIT"],
                "maintainers": [
                    {"login": "testuser", "name": None}  # No name, only login
                ],
            }
        ]

        source = EcosystemsSource()
        session = requests.Session()

        with patch.object(session, "get", return_value=mock_response):
            purl = PackageURL.from_string("pkg:pypi/test-package@1.0.0")
            metadata = source.fetch(purl, session)

        # Supplier should be the maintainer login, NOT "pypi"
        assert metadata is not None
        assert metadata.supplier != "pypi", "Should not use ecosystem name as supplier"
        assert metadata.supplier == "testuser", f"Should use maintainer login as supplier. Got: {metadata.supplier}"
