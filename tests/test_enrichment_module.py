"""
Tests for the refactored enrichment module with library-based approach.
Tests key differences between schema versions.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL
from spdx_tools.spdx.model import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file

from sbomify_action.enrichment import (
    _enrich_cyclonedx_component,
    _enrich_spdx_package,
    _extract_components_from_cyclonedx,
    _fetch_package_metadata,
    clear_cache,
    enrich_sbom_with_ecosystems,
    get_cache_stats,
)
from sbomify_action.http_client import USER_AGENT


class TestLibraryBasedEnrichment:
    """Test enrichment using native libraries instead of JSON manipulation."""

    @pytest.fixture
    def sample_metadata(self):
        """Sample ecosyste.ms metadata."""
        return {
            "description": "A high-level Python web framework",
            "homepage": "https://www.djangoproject.com/",
            "repository_url": "https://github.com/django/django",
            "registry_url": "https://pypi.org/project/django/",
            "normalized_licenses": ["BSD-3-Clause"],
            "maintainers": [{"name": "Django Software Foundation", "login": "django"}],
        }

    def test_cyclonedx_component_enrichment(self, sample_metadata):
        """Test enriching a CycloneDX component with library objects."""
        # Create a component using the library
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:pypi/django@5.1")

        # Enrich it
        added_fields = _enrich_cyclonedx_component(component, sample_metadata)

        # Verify enrichment
        assert component.description == "A high-level Python web framework"
        assert component.publisher == "Django Software Foundation"
        assert len(component.external_references) > 0
        assert len(component.licenses) > 0

        # Verify added fields tracking
        assert "description" in added_fields
        assert "publisher" in " ".join(added_fields)
        assert "homepage URL" in added_fields

    def test_spdx_package_enrichment(self, sample_metadata):
        """Test enriching an SPDX package with library objects."""

        # Create a package using the library
        package = Package(
            spdx_id="SPDXRef-django",
            name="django",
            download_location="NOASSERTION",
            version="5.1",
        )
        package.external_references = [
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:pypi/django@5.1",
            )
        ]

        # Enrich it
        added_fields = _enrich_spdx_package(package, sample_metadata)

        # Verify enrichment
        assert package.description == "A high-level Python web framework"
        assert package.homepage == "https://www.djangoproject.com/"
        assert package.download_location == "https://pypi.org/project/django/"
        assert len(package.external_references) > 1  # Original purl + new refs

        # Verify added fields tracking
        assert "description" in added_fields
        assert "homepage" in added_fields

    def test_spdx_license_declared_with_single_license(self, sample_metadata):
        """Test that license_declared is properly set using SPDX license expression parser for single license."""
        # Create a package with no license declared (None by default)
        package = Package(
            spdx_id="SPDXRef-django",
            name="django",
            download_location="NOASSERTION",
            version="5.1",
        )
        # By default, license_declared is None which triggers enrichment

        # Enrich it with single license
        added_fields = _enrich_spdx_package(package, sample_metadata)

        # Verify license_declared was set properly using the parser
        assert package.license_declared is not None
        assert "BSD-3-Clause" in str(package.license_declared)
        assert "license_declared" in " ".join(added_fields)

    def test_spdx_license_declared_with_multiple_licenses(self):
        """Test that license_declared handles multiple licenses with OR operator."""
        # Create metadata with multiple licenses
        metadata = {
            "normalized_licenses": ["MIT", "Apache-2.0"],
        }

        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
            version="1.0",
        )

        # Enrich it
        added_fields = _enrich_spdx_package(package, metadata)

        # Verify license expression with OR
        assert package.license_declared is not None
        license_str = str(package.license_declared)
        assert "MIT" in license_str
        assert "Apache-2.0" in license_str
        assert "OR" in license_str
        assert "license_declared" in " ".join(added_fields)

    def test_spdx_license_declared_fallback_to_comment(self):
        """Test that invalid license expressions fall back to license_comment."""
        # Create metadata with invalid license expression
        metadata = {
            "licenses": "This is not a valid SPDX expression!@#$",
        }

        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
            version="1.0",
        )

        # Enrich it
        added_fields = _enrich_spdx_package(package, metadata)

        # Verify it fell back to license_comment
        assert package.license_comment is not None
        assert "ecosyste.ms" in package.license_comment
        assert "license_comment" in " ".join(added_fields)

    def test_spdx_license_declared_not_override_existing(self):
        """Test that existing license_declared is not overridden."""
        from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser

        metadata = {
            "normalized_licenses": ["MIT"],
        }

        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
            version="1.0",
        )

        # Set existing license
        license_parser = LicenseExpressionParser()
        existing_license = license_parser.parse_license_expression("GPL-3.0-or-later")
        package.license_declared = existing_license

        # Enrich it
        added_fields = _enrich_spdx_package(package, metadata)

        # Verify existing license was preserved
        assert "GPL-3.0" in str(package.license_declared)
        assert "MIT" not in str(package.license_declared)
        # License should not be in added fields since we didn't add it
        assert not any("license" in field for field in added_fields)


class TestSchemaVersionDifferences:
    """Test key differences between different schema versions."""

    @pytest.fixture
    def cyclonedx_15_bom_json(self):
        """CycloneDX 1.5 SBOM JSON."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {"type": "application", "name": "test-app-15", "version": "1.5.0"},
            },
            "components": [{"type": "library", "name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}],
        }

    @pytest.fixture
    def cyclonedx_16_bom_json(self):
        """CycloneDX 1.6 SBOM JSON."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {"type": "application", "name": "test-app-16", "version": "1.6.0"},
            },
            "components": [
                {"type": "library", "name": "requests", "version": "2.32.0", "purl": "pkg:pypi/requests@2.32.0"}
            ],
        }

    @pytest.fixture
    def spdx_22_doc_json(self):
        """SPDX 2.2 document JSON."""
        return {
            "spdxVersion": "SPDX-2.2",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-doc-22",
            "documentNamespace": "https://test.com/spdx22",
            "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test-tool"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-django",
                    "name": "django",
                    "versionInfo": "5.1",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/django@5.1",
                        }
                    ],
                }
            ],
        }

    @pytest.fixture
    def spdx_23_doc_json(self):
        """SPDX 2.3 document JSON."""
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-doc-23",
            "documentNamespace": "https://test.com/spdx23",
            "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test-tool"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-requests",
                    "name": "requests",
                    "versionInfo": "2.32.0",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.32.0",
                        }
                    ],
                }
            ],
        }

    @patch("sbomify_action.enrichment.requests.Session.get")
    def test_cyclonedx_15_enrichment_end_to_end(self, mock_get, cyclonedx_15_bom_json):
        """Test end-to-end enrichment for CycloneDX 1.5."""
        # Clear cache before test
        clear_cache()

        # Mock ecosyste.ms API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "description": "Python HTTP library",
            "homepage": "https://requests.readthedocs.io",
            "normalized_licenses": ["Apache-2.0"],
        }
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input_15.json"
            output_file = Path(tmpdir) / "output_15.json"

            # Write input
            with open(input_file, "w") as f:
                json.dump(cyclonedx_15_bom_json, f)

            # Enrich
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

            # Verify output exists and is valid
            assert output_file.exists()

            with open(output_file, "r") as f:
                output_data = json.load(f)

            # Verify it's still CycloneDX 1.5
            assert output_data["bomFormat"] == "CycloneDX"
            assert output_data["specVersion"] == "1.5"

            # Verify components were enriched
            assert len(output_data["components"]) > 0
            enriched_comp = output_data["components"][0]
            assert enriched_comp["description"] == "Python HTTP library"

    @patch("sbomify_action.enrichment.requests.Session.get")
    def test_cyclonedx_16_enrichment_end_to_end(self, mock_get, cyclonedx_16_bom_json):
        """Test end-to-end enrichment for CycloneDX 1.6."""
        # Clear cache before test
        clear_cache()

        # Mock ecosyste.ms API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "description": "Python HTTP library",
            "homepage": "https://requests.readthedocs.io",
            "normalized_licenses": ["Apache-2.0"],
        }
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input_16.json"
            output_file = Path(tmpdir) / "output_16.json"

            # Write input
            with open(input_file, "w") as f:
                json.dump(cyclonedx_16_bom_json, f)

            # Enrich
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

            # Verify output exists and is valid
            assert output_file.exists()

            with open(output_file, "r") as f:
                output_data = json.load(f)

            # Verify it's still CycloneDX 1.6
            assert output_data["bomFormat"] == "CycloneDX"
            assert output_data["specVersion"] == "1.6"

            # Verify components were enriched
            assert len(output_data["components"]) > 0
            enriched_comp = output_data["components"][0]
            assert enriched_comp["description"] == "Python HTTP library"

    @patch("sbomify_action.enrichment.requests.Session.get")
    def test_spdx_22_enrichment_end_to_end(self, mock_get, spdx_22_doc_json):
        """Test end-to-end enrichment for SPDX 2.2."""
        # Clear cache before test
        clear_cache()

        # Mock ecosyste.ms API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "description": "A high-level Python web framework",
            "homepage": "https://www.djangoproject.com/",
            "normalized_licenses": ["BSD-3-Clause"],
        }
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input_spdx22.json"
            output_file = Path(tmpdir) / "output_spdx22.json"

            # Write input
            with open(input_file, "w") as f:
                json.dump(spdx_22_doc_json, f)

            # Enrich
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

            # Verify output exists
            assert output_file.exists()

            # Parse and verify
            document = spdx_parse_file(str(output_file))
            assert document.creation_info.spdx_version == "SPDX-2.2"

            # Verify packages were enriched
            assert len(document.packages) > 0
            enriched_pkg = document.packages[0]
            assert enriched_pkg.description == "A high-level Python web framework"
            assert enriched_pkg.homepage == "https://www.djangoproject.com/"

    @patch("sbomify_action.enrichment.requests.Session.get")
    def test_spdx_23_enrichment_end_to_end(self, mock_get, spdx_23_doc_json):
        """Test end-to-end enrichment for SPDX 2.3."""
        # Clear cache before test
        clear_cache()

        # Mock ecosyste.ms API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "description": "Python HTTP library",
            "homepage": "https://requests.readthedocs.io",
            "repository_url": "https://github.com/psf/requests",
            "normalized_licenses": ["Apache-2.0"],
        }
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input_spdx23.json"
            output_file = Path(tmpdir) / "output_spdx23.json"

            # Write input
            with open(input_file, "w") as f:
                json.dump(spdx_23_doc_json, f)

            # Enrich
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

            # Verify output exists
            assert output_file.exists()

            # Parse and verify
            document = spdx_parse_file(str(output_file))
            assert document.creation_info.spdx_version == "SPDX-2.3"

            # Verify packages were enriched
            assert len(document.packages) > 0
            enriched_pkg = document.packages[0]
            assert enriched_pkg.description == "Python HTTP library"
            assert enriched_pkg.homepage == "https://requests.readthedocs.io"


class TestCycloneDXVersionSpecificBehavior:
    """Test CycloneDX version-specific behavior differences."""

    def test_license_format_cyclonedx_15_vs_16(self):
        """Test that license format is properly handled in both versions."""
        # Both versions use the same license format in the library
        # The library handles the version-specific serialization

        # Create 1.5 BOM
        bom_15_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {},
            "components": [],
        }
        bom_15 = Bom.from_json(bom_15_json)

        # Create 1.6 BOM
        bom_16_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {},
            "components": [],
        }
        bom_16 = Bom.from_json(bom_16_json)

        # Add components to both
        for bom in [bom_15, bom_16]:
            comp = Component(name="test", version="1.0", type=ComponentType.LIBRARY)
            comp.purl = PackageURL.from_string("pkg:pypi/test@1.0")
            bom.components.add(comp)

        # Extract components
        comps_15 = _extract_components_from_cyclonedx(bom_15)
        comps_16 = _extract_components_from_cyclonedx(bom_16)

        # Both should extract the same way (library handles version differences)
        assert len(comps_15) == 1
        assert len(comps_16) == 1
        assert comps_15[0][1] == "pkg:pypi/test@1.0"
        assert comps_16[0][1] == "pkg:pypi/test@1.0"

    def test_external_references_cyclonedx(self):
        """Test that external references work correctly."""
        from cyclonedx.model import ExternalReferenceType

        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:pypi/test@1.0")

        metadata = {
            "homepage": "https://test.com",
            "repository_url": "https://github.com/test/test",
            "registry_url": "https://pypi.org/project/test/",
        }

        _enrich_cyclonedx_component(component, metadata)

        # Verify external references were added
        assert len(component.external_references) == 3

        # Verify types
        ref_types = {ref.type for ref in component.external_references}
        assert ExternalReferenceType.WEBSITE in ref_types
        assert ExternalReferenceType.VCS in ref_types
        assert ExternalReferenceType.DISTRIBUTION in ref_types


class TestSPDXVersionSpecificBehavior:
    """Test SPDX version-specific behavior differences."""

    def test_spdx_22_package_fields(self):
        """Test SPDX 2.2 package field handling."""
        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION", version="1.0")

        metadata = {
            "description": "Test package",
            "homepage": "https://test.com",
            "repository_url": "https://github.com/test/test",
        }

        added_fields = _enrich_spdx_package(package, metadata)

        # Verify fields
        assert package.description == "Test package"
        assert package.homepage == "https://test.com"
        assert "description" in added_fields
        assert "homepage" in added_fields

    def test_spdx_23_package_fields(self):
        """Test SPDX 2.3 package field handling (same as 2.2 in our case)."""
        package = Package(spdx_id="SPDXRef-test23", name="test23", download_location="NOASSERTION", version="1.0")

        metadata = {
            "description": "Test package 2.3",
            "homepage": "https://test23.com",
            "repository_url": "https://github.com/test/test23",
        }

        _enrich_spdx_package(package, metadata)

        # Verify fields (should work the same as 2.2)
        assert package.description == "Test package 2.3"
        assert package.homepage == "https://test23.com"

    def test_spdx_external_references(self):
        """Test SPDX external reference handling."""
        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION", version="1.0")

        metadata = {
            "registry_url": "https://pypi.org/project/test/",
            "documentation_url": "https://test.readthedocs.io",
        }

        _enrich_spdx_package(package, metadata)

        # Verify external references were added
        assert len(package.external_references) == 2

        # Verify categories
        categories = {ref.category for ref in package.external_references}
        assert ExternalPackageRefCategory.PACKAGE_MANAGER in categories
        assert ExternalPackageRefCategory.OTHER in categories


class TestCacheAndAPIBehavior:
    """Test caching and API interaction."""

    def test_cache_functionality(self):
        """Test that caching works correctly."""
        clear_cache()
        stats = get_cache_stats()
        assert stats["entries"] == 0

        # Mock an API call to populate cache
        with patch("sbomify_action.enrichment.requests.Session") as mock_session_class:
            mock_session = Mock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"description": "Test"}
            mock_session.get.return_value = mock_response
            mock_session_class.return_value.__enter__.return_value = mock_session

            # First call should hit API
            metadata1 = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
            assert metadata1 is not None

            # Check cache was populated
            stats = get_cache_stats()
            assert stats["entries"] == 1

            # Second call should use cache
            metadata2 = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
            assert metadata2 == metadata1

            # Should only have called API once (second was cached)
            assert mock_session.get.call_count == 1

    def test_api_404_response(self):
        """Test handling of 404 response from API."""
        clear_cache()
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = _fetch_package_metadata("pkg:pypi/nonexistent@1.0", mock_session)
        assert metadata is None

        # Should cache the negative result
        stats = get_cache_stats()
        assert stats["entries"] == 1

    def test_api_429_rate_limit(self):
        """Test handling of 429 rate limit response."""
        clear_cache()
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 429
        mock_session.get.return_value = mock_response

        metadata = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
        assert metadata is None

        # Should cache the negative result
        stats = get_cache_stats()
        assert stats["entries"] == 1

    def test_api_timeout(self):
        """Test handling of API timeout."""
        clear_cache()
        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.Timeout("Connection timeout")

        metadata = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
        assert metadata is None

        # Should cache the negative result
        stats = get_cache_stats()
        assert stats["entries"] == 1

    def test_api_connection_error(self):
        """Test handling of connection errors."""
        clear_cache()
        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        metadata = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
        assert metadata is None

        # Should cache the negative result
        stats = get_cache_stats()
        assert stats["entries"] == 1

    def test_api_generic_exception(self):
        """Test handling of generic exceptions."""
        clear_cache()
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Unexpected error")

        metadata = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
        assert metadata is None

        # Should NOT cache unexpected errors
        stats = get_cache_stats()
        assert stats["entries"] == 0

    def test_user_agent_header(self):
        """Test that User-Agent header is properly formatted."""
        assert "sbomify-github-action/" in USER_AGENT
        assert "(hello@sbomify.com)" in USER_AGENT

        # Version should not be empty or unknown in tests
        parts = USER_AGENT.split("/")
        assert len(parts) == 2
        version_part = parts[1].split(" ")[0]
        assert version_part != ""


class TestEnrichmentEdgeCases:
    """Test edge cases and error conditions in enrichment."""

    def test_enrich_component_with_none_metadata(self):
        """Test enriching component with None metadata."""
        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:pypi/test@1.0")

        added_fields = _enrich_cyclonedx_component(component, None)
        assert added_fields == []

    def test_enrich_spdx_package_with_none_metadata(self):
        """Test enriching SPDX package with None metadata."""
        from spdx_tools.spdx.model import Package

        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        added_fields = _enrich_spdx_package(package, None)
        assert added_fields == []

    def test_enrich_component_single_license(self):
        """Test enriching component with single license."""
        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:pypi/test@1.0")

        metadata = {
            "normalized_licenses": ["MIT"],
        }

        added_fields = _enrich_cyclonedx_component(component, metadata)
        assert len(component.licenses) == 1
        assert "licenses" in " ".join(added_fields)

    def test_enrich_component_duplicate_external_ref(self):
        """Test that duplicate external references are not added."""
        from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri

        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:pypi/test@1.0")

        # Add an existing reference
        component.external_references.add(
            ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri("https://example.com"))
        )

        metadata = {
            "homepage": "https://example.com",  # Same URL
        }

        added_fields = _enrich_cyclonedx_component(component, metadata)
        # Should not add duplicate
        assert len(component.external_references) == 1
        assert "homepage URL" not in added_fields

    def test_enrich_spdx_download_location_from_repo_metadata(self):
        """Test SPDX package enrichment with download_url from repo_metadata."""
        from spdx_tools.spdx.model import Package

        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        metadata = {"repo_metadata": {"download_url": "https://github.com/test/test/archive/v1.0.tar.gz"}}

        added_fields = _enrich_spdx_package(package, metadata)
        assert package.download_location == "https://github.com/test/test/archive/v1.0.tar.gz"
        assert "downloadLocation" in added_fields

    def test_enrich_spdx_license_parse_failure(self):
        """Test SPDX license enrichment with parse failure falls back to comment."""
        from spdx_tools.spdx.model import Package

        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        metadata = {"normalized_licenses": ["INVALID!@#$LICENSE"]}

        _enrich_spdx_package(package, metadata)
        # Should fall back to license_comment
        assert package.license_comment is not None
        assert "INVALID!@#$LICENSE" in package.license_comment

    def test_enrich_spdx_supplier_from_ecosystem(self):
        """Test SPDX package supplier from ecosystem field."""
        from spdx_tools.spdx.model import Package

        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        metadata = {"ecosystem": "PyPI"}

        added_fields = _enrich_spdx_package(package, metadata)
        assert package.supplier is not None
        assert "PyPI" in package.supplier.name
        assert "supplier" in " ".join(added_fields)

    def test_enrich_spdx_supplier_from_repo_owner_dict(self):
        """Test SPDX package supplier from repo owner (dict format)."""
        from spdx_tools.spdx.model import Package

        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        metadata = {
            "repo_metadata": {"owner": {"login": "testorg", "name": "Test Organization", "type": "Organization"}}
        }

        _enrich_spdx_package(package, metadata)
        assert package.supplier is not None
        assert "Test Organization" in package.supplier.name

    def test_enrich_spdx_supplier_from_repo_owner_string(self):
        """Test SPDX package supplier from repo owner (string format)."""
        from spdx_tools.spdx.model import Package

        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        metadata = {"repo_metadata": {"owner": "testorg"}}

        _enrich_spdx_package(package, metadata)
        assert package.supplier is not None
        assert "testorg" in package.supplier.name

    def test_enrich_spdx_originator_with_email(self):
        """Test SPDX package originator with email."""
        from spdx_tools.spdx.model import Package

        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        metadata = {"maintainers": [{"name": "John Doe", "email": "john@example.com"}]}

        _enrich_spdx_package(package, metadata)
        assert package.originator is not None
        assert "John Doe" in package.originator.name
        assert "john@example.com" in package.originator.name

    def test_enrich_spdx_duplicate_external_ref(self):
        """Test that duplicate external references are not added to SPDX."""
        from spdx_tools.spdx.model import ExternalPackageRef, ExternalPackageRefCategory, Package

        package = Package(spdx_id="SPDXRef-test", name="test", download_location="NOASSERTION")

        # Add existing reference
        package.external_references = [
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="url",
                locator="https://pypi.org/project/test/",
            )
        ]

        metadata = {
            "registry_url": "https://pypi.org/project/test/"  # Same URL
        }

        added_fields = _enrich_spdx_package(package, metadata)
        # Should not add duplicate
        assert len(package.external_references) == 1
        assert "externalRef" not in " ".join(added_fields)


class TestFileErrorHandling:
    """Test error handling for file operations."""

    def test_enrich_sbom_file_not_found(self, tmp_path):
        """Test enrichment with non-existent file."""
        input_file = tmp_path / "nonexistent.json"
        output_file = tmp_path / "output.json"

        with pytest.raises(FileNotFoundError):
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

    def test_enrich_sbom_invalid_json(self, tmp_path):
        """Test enrichment with invalid JSON."""
        input_file = tmp_path / "invalid.json"
        input_file.write_text("{invalid json")
        output_file = tmp_path / "output.json"

        with pytest.raises(ValueError, match="Invalid JSON"):
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

    def test_enrich_sbom_missing_spec_version(self, tmp_path):
        """Test enrichment with CycloneDX SBOM missing specVersion."""
        from sbomify_action.exceptions import SBOMValidationError

        sbom_data = {
            "bomFormat": "CycloneDX",
            # Missing specVersion
            "version": 1,
            "components": [],
        }

        input_file = tmp_path / "missing_spec.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "output.json"

        with pytest.raises(SBOMValidationError, match="missing required 'specVersion' field"):
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

    def test_enrich_sbom_no_components_with_purls(self, tmp_path, mocker):
        """Test enrichment with SBOM that has no components with PURLs."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {"name": "test", "version": "1.0", "type": "library"}
                # No purl
            ],
        }

        input_file = tmp_path / "no_purls.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "output.json"

        enrich_sbom_with_ecosystems(str(input_file), str(output_file))

        # Should write output file even with no enrichment
        assert output_file.exists()

    def test_enrich_sbom_unsupported_format(self, tmp_path):
        """Test enrichment with unsupported SBOM format."""
        sbom_data = {"some": "unknown format"}

        input_file = tmp_path / "unknown.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "output.json"

        with pytest.raises(ValueError, match="Neither CycloneDX nor SPDX"):
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

    # Note: Legacy tools format tests are skipped because cyclonedx-python-lib v11.5.0
    # still has deserialization bugs with vendor dicts. The workaround code in enrichment.py
    # handles this, but we can't easily test it in isolation.

    def test_api_response_dict_format(self):
        """Test handling of API response that returns dict instead of list."""
        clear_cache()
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"description": "Test package"}  # Dict, not list
        mock_session.get.return_value = mock_response

        metadata = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
        assert metadata is not None
        assert metadata["description"] == "Test package"

    def test_enrich_component_with_license_string_fallback(self):
        """Test enriching component with licenses as string instead of normalized_licenses."""
        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:pypi/test@1.0")

        metadata = {
            "licenses": "MIT OR Apache-2.0",  # String instead of array
        }

        added_fields = _enrich_cyclonedx_component(component, metadata)
        assert len(component.licenses) == 1
        assert "licenses" in " ".join(added_fields)

    def test_enrich_spdx_no_packages_with_purls(self, tmp_path):
        """Test enrichment with SPDX SBOM that has no packages with PURLs."""
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: test"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package",
                    "name": "test",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    # No purl in external references
                }
            ],
        }

        input_file = tmp_path / "no_purls_spdx.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "output_spdx.json"

        enrich_sbom_with_ecosystems(str(input_file), str(output_file))

        # Should write output file even with no enrichment
        assert output_file.exists()
