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
    ALL_LOCKFILE_NAMES,
    NAMESPACE_TO_SUPPLIER,
    OS_PACKAGE_TYPES,
    PACKAGE_TRACKER_URLS,
    _add_enrichment_source_comment,
    _add_enrichment_source_property,
    _enrich_cyclonedx_component,
    _enrich_cyclonedx_component_from_purl,
    _enrich_os_component,
    _enrich_spdx_package,
    _enrich_spdx_package_from_purl,
    _extract_components_from_cyclonedx,
    _fetch_package_metadata,
    _fetch_pypi_metadata,
    _filter_lockfile_components,
    _get_package_tracker_url,
    _get_supplier_from_purl,
    _is_lockfile_component,
    _is_os_package_type,
    _parse_purl_safe,
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

        # Verify the API was actually called
        mock_session.get.assert_called_once()

        # Should cache the negative result
        stats = get_cache_stats()
        assert stats["entries"] == 1

    def test_api_429_rate_limit(self, caplog):
        """Test handling of 429 rate limit response."""
        clear_cache()
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 429
        mock_session.get.return_value = mock_response

        metadata = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
        assert metadata is None

        # Verify rate limit warning is logged
        assert any("Rate limit exceeded" in record.message for record in caplog.records)

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

    def test_api_generic_exception(self, caplog):
        """Test handling of generic exceptions."""
        clear_cache()
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Unexpected error")

        metadata = _fetch_package_metadata("pkg:pypi/test@1.0", mock_session)
        assert metadata is None

        # Verify unexpected error is logged at ERROR level
        assert any(record.levelname == "ERROR" and "Unexpected error" in record.message for record in caplog.records)

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
        assert version_part != "unknown"


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

        # Verify the license expression was properly created with the OR operator
        license_list = list(component.licenses)
        assert len(license_list) == 1
        license_expr = license_list[0]
        assert hasattr(license_expr, "value")
        assert license_expr.value == "MIT OR Apache-2.0"

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


class TestPURLBasedEnrichment:
    """Test PURL-based enrichment for OS packages (deb, rpm, apk)."""

    def test_parse_purl_safe_valid(self):
        """Test parsing a valid PURL."""
        purl = _parse_purl_safe("pkg:deb/debian/bash@5.2.15-2")
        assert purl is not None
        assert purl.type == "deb"
        assert purl.namespace == "debian"
        assert purl.name == "bash"
        assert purl.version == "5.2.15-2"

    def test_parse_purl_safe_invalid(self):
        """Test parsing an invalid PURL returns None."""
        purl = _parse_purl_safe("not-a-valid-purl")
        assert purl is None

    def test_parse_purl_safe_empty(self):
        """Test parsing an empty PURL returns None."""
        purl = _parse_purl_safe("")
        assert purl is None

    def test_get_supplier_from_purl_known_namespace(self):
        """Test getting supplier from known namespaces."""
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        supplier = _get_supplier_from_purl(purl)
        assert supplier == "Debian Project"

        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.2")
        supplier = _get_supplier_from_purl(purl)
        assert supplier == "Canonical Ltd"

        purl = PackageURL.from_string("pkg:rpm/fedora/bash@5.2")
        supplier = _get_supplier_from_purl(purl)
        assert supplier == "Fedora Project"

        purl = PackageURL.from_string("pkg:rpm/redhat/bash@5.2")
        supplier = _get_supplier_from_purl(purl)
        assert supplier == "Red Hat, Inc."

        purl = PackageURL.from_string("pkg:rpm/amazon/bash@5.2")
        supplier = _get_supplier_from_purl(purl)
        assert supplier == "Amazon Web Services"

        purl = PackageURL.from_string("pkg:apk/alpine/bash@5.2")
        supplier = _get_supplier_from_purl(purl)
        assert supplier == "Alpine Linux"

    def test_get_supplier_from_purl_unknown_namespace(self):
        """Test getting supplier from unknown namespace falls back to title case."""
        purl = PackageURL.from_string("pkg:deb/custom-distro/bash@5.2")
        supplier = _get_supplier_from_purl(purl)
        assert supplier == "Custom-Distro Project"

    def test_get_supplier_from_purl_no_namespace(self):
        """Test getting supplier when no namespace is present."""
        purl = PackageURL(type="generic", name="bash", version="5.2")
        supplier = _get_supplier_from_purl(purl)
        assert supplier is None

    def test_get_package_tracker_url_debian(self):
        """Test getting package tracker URL for Debian packages."""
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        url = _get_package_tracker_url(purl)
        assert url == "https://tracker.debian.org/pkg/bash"

    def test_get_package_tracker_url_ubuntu(self):
        """Test getting package tracker URL for Ubuntu packages."""
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.2")
        url = _get_package_tracker_url(purl)
        assert url == "https://launchpad.net/ubuntu/+source/bash"

    def test_get_package_tracker_url_alpine(self):
        """Test getting package tracker URL for Alpine packages."""
        purl = PackageURL.from_string("pkg:apk/alpine/bash@5.2")
        url = _get_package_tracker_url(purl)
        assert url == "https://pkgs.alpinelinux.org/package/edge/main/x86_64/bash"

    def test_get_package_tracker_url_unknown(self):
        """Test getting package tracker URL for unknown distro returns None."""
        purl = PackageURL.from_string("pkg:deb/custom-distro/bash@5.2")
        url = _get_package_tracker_url(purl)
        assert url is None

    def test_is_os_package_type_deb(self):
        """Test identifying deb packages as OS packages."""
        assert _is_os_package_type("pkg:deb/debian/bash@5.2") is True

    def test_is_os_package_type_rpm(self):
        """Test identifying rpm packages as OS packages."""
        assert _is_os_package_type("pkg:rpm/fedora/bash@5.2") is True

    def test_is_os_package_type_apk(self):
        """Test identifying apk packages as OS packages."""
        assert _is_os_package_type("pkg:apk/alpine/bash@5.2") is True

    def test_is_os_package_type_pypi(self):
        """Test that pypi packages are not OS packages."""
        assert _is_os_package_type("pkg:pypi/django@5.1") is False

    def test_is_os_package_type_invalid(self):
        """Test that invalid PURLs return False."""
        assert _is_os_package_type("not-a-purl") is False

    def test_enrich_cyclonedx_component_from_purl_debian(self):
        """Test enriching a CycloneDX component from a Debian PURL."""
        component = Component(name="bash", version="5.2", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")

        added_fields = _enrich_cyclonedx_component_from_purl(component, "pkg:deb/debian/bash@5.2")

        assert component.publisher == "Debian Project"
        assert len(component.external_references) == 1
        ext_ref = list(component.external_references)[0]
        assert str(ext_ref.url) == "https://tracker.debian.org/pkg/bash"
        assert "publisher" in " ".join(added_fields)
        assert "package tracker URL" in added_fields

    def test_enrich_cyclonedx_component_from_purl_non_os_package(self):
        """Test that non-OS packages are not enriched by PURL fallback."""
        component = Component(name="django", version="5.1", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:pypi/django@5.1")

        added_fields = _enrich_cyclonedx_component_from_purl(component, "pkg:pypi/django@5.1")

        # Should not add anything for pypi packages
        assert added_fields == []
        assert component.publisher is None

    def test_enrich_cyclonedx_component_from_purl_existing_publisher(self):
        """Test that existing publisher is not overwritten."""
        component = Component(name="bash", version="5.2", type=ComponentType.LIBRARY)
        component.purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        component.publisher = "Existing Publisher"

        added_fields = _enrich_cyclonedx_component_from_purl(component, "pkg:deb/debian/bash@5.2")

        # Publisher should not be changed
        assert component.publisher == "Existing Publisher"
        # But URL should still be added
        assert "package tracker URL" in added_fields

    def test_enrich_os_component_debian(self):
        """Test enriching a Debian operating-system component."""
        component = Component(name="debian", version="12.12", type=ComponentType.OPERATING_SYSTEM)

        added_fields = _enrich_os_component(component)

        assert component.publisher == "Debian Project"
        assert "publisher" in " ".join(added_fields)

    def test_enrich_os_component_ubuntu(self):
        """Test enriching an Ubuntu operating-system component."""
        component = Component(name="ubuntu", version="22.04", type=ComponentType.OPERATING_SYSTEM)

        added_fields = _enrich_os_component(component)

        assert component.publisher == "Canonical Ltd"
        assert "publisher" in " ".join(added_fields)

    def test_enrich_os_component_redhat(self):
        """Test enriching a Red Hat operating-system component."""
        component = Component(name="redhat", version="9.7", type=ComponentType.OPERATING_SYSTEM)

        added_fields = _enrich_os_component(component)

        assert component.publisher == "Red Hat, Inc."
        assert "publisher" in " ".join(added_fields)

    def test_enrich_os_component_alpine(self):
        """Test enriching an Alpine operating-system component."""
        component = Component(name="alpine", version="3.19", type=ComponentType.OPERATING_SYSTEM)

        added_fields = _enrich_os_component(component)

        assert component.publisher == "Alpine Linux"
        assert "publisher" in " ".join(added_fields)

    def test_enrich_os_component_unknown(self):
        """Test enriching an unknown operating-system component."""
        component = Component(name="unknownos", version="1.0", type=ComponentType.OPERATING_SYSTEM)

        added_fields = _enrich_os_component(component)

        # Unknown OS should not get a publisher
        assert component.publisher is None
        assert added_fields == []

    def test_enrich_os_component_existing_publisher(self):
        """Test that existing publisher is not overwritten for OS component."""
        component = Component(name="debian", version="12.12", type=ComponentType.OPERATING_SYSTEM)
        component.publisher = "Existing Publisher"

        added_fields = _enrich_os_component(component)

        assert component.publisher == "Existing Publisher"
        assert added_fields == []

    def test_enrich_os_component_non_os_type(self):
        """Test that non-OS components are not enriched by this function."""
        component = Component(name="debian", version="12.12", type=ComponentType.LIBRARY)

        added_fields = _enrich_os_component(component)

        assert added_fields == []
        assert component.publisher is None

    def test_enrich_spdx_package_from_purl_debian(self):
        """Test enriching an SPDX package from a Debian PURL."""

        package = Package(
            spdx_id="SPDXRef-bash",
            name="bash",
            download_location="NOASSERTION",
            version="5.2",
        )
        package.external_references = [
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:deb/debian/bash@5.2",
            )
        ]

        added_fields = _enrich_spdx_package_from_purl(package, "pkg:deb/debian/bash@5.2")

        assert package.supplier is not None
        assert package.supplier.name == "Debian Project"
        assert package.homepage == "https://tracker.debian.org/pkg/bash"
        assert "supplier" in " ".join(added_fields)
        assert "homepage" in added_fields

    def test_constants_defined(self):
        """Test that the PURL enrichment constants are properly defined."""
        assert "deb" in OS_PACKAGE_TYPES
        assert "rpm" in OS_PACKAGE_TYPES
        assert "apk" in OS_PACKAGE_TYPES

        assert "debian" in NAMESPACE_TO_SUPPLIER
        assert "ubuntu" in NAMESPACE_TO_SUPPLIER
        assert "alpine" in NAMESPACE_TO_SUPPLIER

        assert "deb" in PACKAGE_TRACKER_URLS
        assert "debian" in PACKAGE_TRACKER_URLS["deb"]


class TestPURLEnrichmentIntegration:
    """Integration tests for PURL-based enrichment with full SBOM processing."""

    def test_enrich_debian_sbom_end_to_end(self, tmp_path):
        """Test end-to-end enrichment of a Debian-based SBOM."""
        # Create a minimal Debian SBOM
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "version": 1,
            "components": [
                {
                    "type": "operating-system",
                    "name": "debian",
                    "version": "12.12",
                    "bom-ref": "os-debian",
                },
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2.15-2",
                    "purl": "pkg:deb/debian/bash@5.2.15-2?distro=debian-12.12",
                    "bom-ref": "pkg-bash",
                },
                {
                    "type": "library",
                    "name": "coreutils",
                    "version": "9.1",
                    "purl": "pkg:deb/debian/coreutils@9.1?distro=debian-12.12",
                    "bom-ref": "pkg-coreutils",
                },
            ],
        }

        input_file = tmp_path / "debian_sbom.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched_sbom.json"

        clear_cache()

        # Mock the API to return empty results (simulating ecosyste.ms not having deb packages)
        with patch("sbomify_action.enrichment._fetch_package_metadata") as mock_fetch:
            mock_fetch.return_value = None  # ecosyste.ms returns no data

            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

        # Verify output
        assert output_file.exists()
        with open(output_file) as f:
            result = json.load(f)

        # Find the OS component
        os_component = next(
            (c for c in result["components"] if c.get("type") == "operating-system"),
            None,
        )
        assert os_component is not None
        assert os_component.get("publisher") == "Debian Project"

        # Find bash package
        bash_pkg = next((c for c in result["components"] if c.get("name") == "bash"), None)
        assert bash_pkg is not None
        assert bash_pkg.get("publisher") == "Debian Project"
        # Check for external reference
        ext_refs = bash_pkg.get("externalReferences", [])
        tracker_url = next(
            (r["url"] for r in ext_refs if "tracker.debian.org" in r.get("url", "")),
            None,
        )
        assert tracker_url == "https://tracker.debian.org/pkg/bash"

    def test_enrich_mixed_sbom_with_pypi_and_debian(self, tmp_path):
        """Test enrichment of SBOM with both PyPI and Debian packages."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:b2c3d4e5-f6a7-8901-bcde-f12345678901",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "django",
                    "version": "5.1",
                    "purl": "pkg:pypi/django@5.1",
                    "bom-ref": "pkg-django",
                },
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2",
                    "purl": "pkg:deb/debian/bash@5.2",
                    "bom-ref": "pkg-bash",
                },
            ],
        }

        input_file = tmp_path / "mixed_sbom.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched_sbom.json"

        clear_cache()

        # Mock API: return data for django, None for bash
        def mock_fetch(purl, session):
            if "pypi" in purl:
                return {
                    "description": "Django web framework",
                    "normalized_licenses": ["BSD-3-Clause"],
                }
            return None  # Debian packages not in ecosyste.ms

        with patch("sbomify_action.enrichment._fetch_package_metadata", side_effect=mock_fetch):
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

        with open(output_file) as f:
            result = json.load(f)

        # Django should be enriched from ecosyste.ms
        django_pkg = next((c for c in result["components"] if c.get("name") == "django"), None)
        assert django_pkg is not None
        assert django_pkg.get("description") == "Django web framework"

        # Bash should be enriched from PURL
        bash_pkg = next((c for c in result["components"] if c.get("name") == "bash"), None)
        assert bash_pkg is not None
        assert bash_pkg.get("publisher") == "Debian Project"


class TestLockfileFiltering:
    """Tests for lockfile component filtering."""

    def test_all_lockfile_names_contains_expected_files(self):
        """Test that ALL_LOCKFILE_NAMES contains all expected lockfiles."""
        expected = [
            "uv.lock",
            "requirements.txt",
            "Pipfile.lock",
            "poetry.lock",
            "Cargo.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Gemfile.lock",
            "go.mod",
            "pubspec.lock",
            "conan.lock",
        ]
        for lockfile in expected:
            assert lockfile in ALL_LOCKFILE_NAMES, f"{lockfile} should be in ALL_LOCKFILE_NAMES"

    def test_is_lockfile_component_true_for_uv_lock(self):
        """Test that uv.lock is identified as a lockfile component."""
        component = Component(name="uv.lock", type=ComponentType.APPLICATION)
        assert _is_lockfile_component(component) is True

    def test_is_lockfile_component_true_for_requirements_txt(self):
        """Test that requirements.txt is identified as a lockfile component."""
        component = Component(name="requirements.txt", type=ComponentType.APPLICATION)
        assert _is_lockfile_component(component) is True

    def test_is_lockfile_component_false_for_library(self):
        """Test that library components are not identified as lockfiles."""
        component = Component(name="uv.lock", type=ComponentType.LIBRARY)
        assert _is_lockfile_component(component) is False

    def test_is_lockfile_component_false_with_purl(self):
        """Test that components with PURLs are not identified as lockfiles."""
        component = Component(name="uv.lock", type=ComponentType.APPLICATION)
        component.purl = PackageURL.from_string("pkg:pypi/something@1.0")
        assert _is_lockfile_component(component) is False

    def test_is_lockfile_component_false_for_regular_app(self):
        """Test that regular application components are not identified as lockfiles."""
        component = Component(name="my-app", type=ComponentType.APPLICATION)
        assert _is_lockfile_component(component) is False

    def test_filter_lockfile_components_removes_lockfiles(self):
        """Test that filter_lockfile_components removes lockfile components."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {"type": "application", "name": "uv.lock"},
                {"type": "library", "name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"},
                {"type": "application", "name": "requirements.txt"},
            ],
        }
        bom = Bom.from_json(bom_json)
        assert len(bom.components) == 3

        removed = _filter_lockfile_components(bom)

        assert removed == 2
        assert len(bom.components) == 1
        remaining = list(bom.components)[0]
        assert remaining.name == "django"

    def test_filter_lockfile_end_to_end(self, tmp_path):
        """Test end-to-end that lockfiles are filtered from SBOM."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "version": 1,
            "components": [
                {"type": "application", "name": "uv.lock", "bom-ref": "lockfile-uv"},
                {
                    "type": "library",
                    "name": "django",
                    "version": "5.1",
                    "purl": "pkg:pypi/django@5.1",
                    "bom-ref": "pkg-django",
                },
            ],
        }

        input_file = tmp_path / "sbom.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.json"

        clear_cache()

        with patch("sbomify_action.enrichment._fetch_package_metadata") as mock_fetch:
            mock_fetch.return_value = {"description": "Django framework"}
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

        with open(output_file) as f:
            result = json.load(f)

        # uv.lock should be removed
        component_names = [c["name"] for c in result["components"]]
        assert "uv.lock" not in component_names
        assert "django" in component_names


class TestPyPIFallback:
    """Tests for PyPI API fallback enrichment."""

    def test_fetch_pypi_metadata_success(self):
        """Test successful PyPI metadata fetch."""
        clear_cache()
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Boolean algebra library",
                "author": "John Doe",
                "author_email": "john@example.com",
                "license": "BSD-2-Clause",
                "home_page": "https://example.com",
                "project_urls": {
                    "Source": "https://github.com/example/boolean-py",
                    "Issue Tracker": "https://github.com/example/boolean-py/issues",
                },
            }
        }
        mock_session.get.return_value = mock_response

        metadata = _fetch_pypi_metadata("boolean-py", mock_session)

        assert metadata is not None
        assert metadata["description"] == "Boolean algebra library"
        assert metadata["homepage"] == "https://example.com"
        assert metadata["licenses"] == "BSD-2-Clause"
        assert metadata["repository_url"] == "https://github.com/example/boolean-py"
        assert len(metadata["maintainers"]) == 1
        assert metadata["maintainers"][0]["name"] == "John Doe"

    def test_fetch_pypi_metadata_not_found(self):
        """Test PyPI metadata fetch for non-existent package."""
        clear_cache()
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = _fetch_pypi_metadata("nonexistent-package", mock_session)

        assert metadata is None

    def test_fetch_pypi_metadata_cached(self):
        """Test that PyPI metadata is cached."""
        clear_cache()
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"summary": "Test"}}
        mock_session.get.return_value = mock_response

        # First call
        _fetch_pypi_metadata("test-pkg", mock_session)
        # Second call should use cache
        _fetch_pypi_metadata("test-pkg", mock_session)

        # Should only call API once
        assert mock_session.get.call_count == 1

    def test_pypi_fallback_end_to_end(self, tmp_path):
        """Test end-to-end PyPI fallback when ecosyste.ms has no data."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "boolean-py",
                    "version": "5.0",
                    "purl": "pkg:pypi/boolean-py@5.0",
                    "bom-ref": "pkg-boolean",
                },
            ],
        }

        input_file = tmp_path / "sbom.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.json"

        clear_cache()

        # Mock ecosyste.ms to return None, but PyPI to return data
        def mock_ecosystems_fetch(purl, session):
            return None

        pypi_response = {
            "info": {
                "summary": "Boolean algebra library",
                "author": "Test Author",
                "license": "BSD-2-Clause",
            }
        }

        with patch("sbomify_action.enrichment._fetch_package_metadata", side_effect=mock_ecosystems_fetch):
            with patch("sbomify_action.enrichment.requests.Session") as mock_session_class:
                mock_session = Mock()
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = pypi_response
                mock_session.get.return_value = mock_response
                mock_session.headers = {}
                mock_session.__enter__ = Mock(return_value=mock_session)
                mock_session.__exit__ = Mock(return_value=False)
                mock_session_class.return_value = mock_session

                enrich_sbom_with_ecosystems(str(input_file), str(output_file))

        with open(output_file) as f:
            result = json.load(f)

        # Check that component was enriched from PyPI
        component = result["components"][0]
        assert component["description"] == "Boolean algebra library"


class TestEnrichmentSourceTracking:
    """Tests for enrichment source tracking (sbomify:enrichment:source property)."""

    def test_add_enrichment_source_property(self):
        """Test adding enrichment source property to CycloneDX component."""
        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)

        _add_enrichment_source_property(component, "ecosyste.ms")

        # Find the property
        props = list(component.properties)
        source_prop = next((p for p in props if p.name == "sbomify:enrichment:source"), None)

        assert source_prop is not None
        assert source_prop.value == "ecosyste.ms"

    def test_add_enrichment_source_property_not_duplicate(self):
        """Test that enrichment source property is not added twice."""
        component = Component(name="test", version="1.0", type=ComponentType.LIBRARY)

        _add_enrichment_source_property(component, "ecosyste.ms")
        _add_enrichment_source_property(component, "pypi.org")  # Should not add

        # Count properties with our name
        props = [p for p in component.properties if p.name == "sbomify:enrichment:source"]
        assert len(props) == 1
        assert props[0].value == "ecosyste.ms"

    def test_add_enrichment_source_comment_spdx(self):
        """Test adding enrichment source comment to SPDX package."""
        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
        )

        _add_enrichment_source_comment(package, "ecosyste.ms")

        assert package.comment == "Enriched by sbomify from ecosyste.ms"

    def test_add_enrichment_source_comment_appends(self):
        """Test that enrichment source comment appends to existing comment."""
        package = Package(
            spdx_id="SPDXRef-test",
            name="test",
            download_location="NOASSERTION",
        )
        package.comment = "Existing comment"

        _add_enrichment_source_comment(package, "pypi.org")

        assert "Existing comment" in package.comment
        assert "Enriched by sbomify from pypi.org" in package.comment

    def test_enrichment_source_in_output_cyclonedx(self, tmp_path):
        """Test that enrichment source property appears in CycloneDX output."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "django",
                    "version": "5.1",
                    "purl": "pkg:pypi/django@5.1",
                    "bom-ref": "pkg-django",
                },
            ],
        }

        input_file = tmp_path / "sbom.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.json"

        clear_cache()

        with patch("sbomify_action.enrichment._fetch_package_metadata") as mock_fetch:
            mock_fetch.return_value = {"description": "Django framework"}
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

        with open(output_file) as f:
            result = json.load(f)

        # Check for enrichment source property
        component = result["components"][0]
        properties = component.get("properties", [])
        source_prop = next((p for p in properties if p["name"] == "sbomify:enrichment:source"), None)

        assert source_prop is not None
        assert source_prop["value"] == "ecosyste.ms"

    def test_enrichment_source_purl_for_os_packages(self, tmp_path):
        """Test that OS packages get 'purl' as enrichment source."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "bash",
                    "version": "5.2",
                    "purl": "pkg:deb/debian/bash@5.2",
                    "bom-ref": "pkg-bash",
                },
            ],
        }

        input_file = tmp_path / "sbom.json"
        input_file.write_text(json.dumps(sbom_data))
        output_file = tmp_path / "enriched.json"

        clear_cache()

        with patch("sbomify_action.enrichment._fetch_package_metadata") as mock_fetch:
            mock_fetch.return_value = None  # ecosyste.ms has no data
            enrich_sbom_with_ecosystems(str(input_file), str(output_file))

        with open(output_file) as f:
            result = json.load(f)

        # Check for enrichment source property
        component = result["components"][0]
        properties = component.get("properties", [])
        source_prop = next((p for p in properties if p["name"] == "sbomify:enrichment:source"), None)

        assert source_prop is not None
        assert source_prop["value"] == "purl"
