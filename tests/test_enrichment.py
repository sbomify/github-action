"""
Tests for SBOM enrichment functionality with backend metadata.
"""

import copy
import json
from unittest.mock import Mock, patch

import pytest

from sbomify_action.cli.main import (
    Config,
    _apply_cyclonedx_metadata_to_json,
    _validate_cyclonedx_sbom,
    enrich_sbom_with_backend_metadata,
    load_sbom_from_file,
)
from sbomify_action.exceptions import APIError


class TestSBOMEnrichment:
    """Test SBOM enrichment with backend metadata."""

    @pytest.fixture
    def sample_backend_payload_basic(self):
        """Sample backend metadata payload with basic license formats."""
        return {
            "supplier": {
                "name": "Test Supplier",
                "url": ["http://supply.org"],
                "address": "1234, Test Street, Test City, Test Country",
                "contacts": [{"name": "C1", "email": "c1@contacts.org", "phone": "236623636"}],
            },
            "authors": [
                {"name": "A1", "email": "a1@example.org", "phone": "2356235"},
                {"name": "A2", "email": "a2@example.com", "phone": ""},
            ],
            "licenses": [{"name": "GPL-1.0", "url": "http://custom.com/license", "text": "Custom license text"}],
            "lifecycle_phase": "post-build",
        }

    @pytest.fixture
    def sample_backend_payload_advanced(self):
        """Sample backend metadata payload with advanced license formats."""
        return {
            "supplier": {
                "name": "Advanced Software Corp",
                "url": ["https://advanced-software.com", "https://support.advanced-software.com"],
                "address": "123 Innovation Drive, Tech City, TC 12345",
                "contacts": [
                    {"name": "Legal Department", "email": "legal@advanced-software.com", "phone": "+1-555-0123"}
                ],
            },
            "authors": [{"name": "Jane Developer", "email": "jane@advanced-software.com", "phone": "+1-555-0124"}],
            "licenses": [
                "Apache-2.0 WITH Commons-Clause",
                "MIT OR GPL-3.0",
                "BSD-3-Clause AND MIT",
                {
                    "name": "Advanced Software Proprietary License",
                    "url": "https://advanced-software.com/licenses/proprietary-v2",
                    "text": "Copyright (c) 2024 Advanced Software Corp. All rights reserved.\n\nThis software is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.\n\nPermission is granted to use this software solely for evaluation purposes under the terms of a separate evaluation agreement.",
                },
                {
                    "name": "Internal Research License",
                    "url": "https://advanced-software.com/licenses/research",
                    "text": "This component contains research code developed internally.\nUse is restricted to authorized research personnel only.",
                },
                "LGPL-2.1-only",
            ],
            "lifecycle_phase": "operations",
        }

    @pytest.fixture
    def sample_cyclonedx_sbom_v15(self):
        """Sample CycloneDX 1.5 SBOM with some existing metadata."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2023-01-01T00:00:00Z",
                "component": {"type": "application", "name": "test-app", "version": "1.0.0"},
                # Use authors array for loading (library compatibility), but test will verify correct output format
                "authors": [{"name": "Original Author", "email": "original@example.com"}],
            },
            "components": [],
        }

    @pytest.fixture
    def sample_cyclonedx_sbom(self):
        """Sample CycloneDX SBOM with some existing metadata."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2023-01-01T00:00:00Z",
                "component": {"type": "application", "name": "test-app", "version": "1.0.0"},
                "authors": [{"name": "Original Author", "email": "original@example.com"}],
            },
            "components": [],
        }

    @pytest.fixture
    def sample_spdx_sbom(self):
        """Sample SPDX SBOM with some existing metadata."""
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-document",
            "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test-tool"]},
            "packages": [],
        }

    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing."""
        return Config(token="test-token", component_id="test-component-123", upload=False, augment=True)

    @pytest.fixture
    def sample_backend_payload_with_manufacturer(self):
        """Sample backend payload for comprehensive version testing."""
        return {
            "name": "Test Component",
            "supplier": {
                "name": "Test Supplier",
                "url": ["http://supply.org"],
                "contacts": [{"name": "C1", "email": "c1@contacts.org", "phone": "555-0101"}],
            },
            "authors": [
                {"name": "A1", "email": "a1@example.org"},
                {"name": "A2", "email": "a2@example.com", "phone": "555-0103"},
            ],
            "licenses": [{"name": "GPL-1.0", "url": "https://www.gnu.org/licenses/gpl-1.0.html"}],
            "lifecycle_phase": "operations",
        }

    def test_load_cyclonedx_sbom(self, tmp_path, sample_cyclonedx_sbom):
        """Test loading CycloneDX SBOM with format detection."""
        # Create temporary SBOM file
        sbom_file = tmp_path / "test_sbom.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_cyclonedx_sbom, f)

        # Load the SBOM
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))

        assert sbom_format == "cyclonedx"
        assert original_json["bomFormat"] == "CycloneDX"
        assert original_json["specVersion"] == "1.6"
        assert parsed_object is not None
        # Check that it's properly parsed as a Bom object
        assert hasattr(parsed_object, "metadata")
        assert hasattr(parsed_object, "components")

    def test_load_spdx_sbom(self, tmp_path, sample_spdx_sbom):
        """Test loading SPDX SBOM with format detection."""
        # Create temporary SBOM file
        sbom_file = tmp_path / "test_spdx.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_spdx_sbom, f)

        # Load the SBOM
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))

        assert sbom_format == "spdx"
        assert original_json["spdxVersion"] == "SPDX-2.3"
        assert parsed_object == sample_spdx_sbom  # Currently just returns JSON for SPDX

    @patch("sbomify_action.cli.main.requests.get")
    def test_cyclonedx_enrichment_end_to_end(
        self, mock_get, tmp_path, sample_cyclonedx_sbom, sample_backend_payload_advanced, mock_config
    ):
        """Test complete CycloneDX enrichment process end-to-end."""
        # Setup mock API response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_payload_advanced
        mock_get.return_value = mock_response

        # Create temporary SBOM file
        sbom_file = tmp_path / "test_sbom.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_cyclonedx_sbom, f)

        # Load and enrich SBOM
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))
        enriched_object, updated_json = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, mock_config
        )

        # Verify API was called correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        # The URL is the first positional argument
        assert "test-component-123" in call_args[0][0]
        assert call_args[1]["headers"]["Authorization"] == "Bearer test-token"

        # Verify enrichment results
        metadata = updated_json["metadata"]

        # Check supplier information
        assert "supplier" in metadata
        supplier = metadata["supplier"]
        assert supplier["name"] == "Advanced Software Corp"
        assert "https://advanced-software.com" in supplier["url"]
        assert "https://support.advanced-software.com" in supplier["url"]
        assert len(supplier["contacts"]) == 1
        assert supplier["contacts"][0]["name"] == "Legal Department"
        assert supplier["contacts"][0]["email"] == "legal@advanced-software.com"

        # Check authors (should include both backend and existing)
        assert "authors" in metadata
        authors = metadata["authors"]
        assert len(authors) >= 2  # 1 from backend + 1 existing

        # Find backend authors
        backend_author_emails = {"jane@advanced-software.com"}
        found_backend_authors = {a["email"] for a in authors if a.get("email") in backend_author_emails}
        assert found_backend_authors == backend_author_emails

        # Verify existing author is preserved
        existing_author = next((a for a in authors if a.get("email") == "original@example.com"), None)
        assert existing_author is not None
        assert existing_author["name"] == "Original Author"

        # Check licenses (advanced format with expressions and custom licenses)
        assert "licenses" in metadata
        licenses = metadata["licenses"]
        assert len(licenses) >= 5

        # Extract license names and expressions
        license_names = set()
        license_expressions = set()
        for license_item in licenses:
            if isinstance(license_item, dict):
                if "license" in license_item and "name" in license_item["license"]:
                    license_names.add(license_item["license"]["name"])
                elif "expression" in license_item:
                    license_expressions.add(license_item["expression"])

        # Check for SPDX expressions
        assert "Apache-2.0 WITH Commons-Clause" in license_expressions
        assert "MIT OR GPL-3.0" in license_expressions
        assert "BSD-3-Clause AND MIT" in license_expressions

        # Check for named licenses
        assert "Advanced Software Proprietary License" in license_names
        assert "Internal Research License" in license_names
        assert "LGPL-2.1-only" in license_names

    def test_intelligent_metadata_merging(self, sample_cyclonedx_sbom, sample_backend_payload_basic):
        """Test that existing metadata is preserved and intelligently merged."""
        # Add more existing metadata to test merging
        sample_cyclonedx_sbom["metadata"]["supplier"] = {
            "name": "Existing Supplier",
            "url": "http://existing.com",
            "contacts": [{"name": "Existing Contact", "email": "existing@example.com"}],
        }
        sample_cyclonedx_sbom["metadata"]["licenses"] = [{"license": {"name": "MIT"}}]

        # Load as CycloneDX
        from cyclonedx.model.bom import Bom

        bom = Bom.from_json(sample_cyclonedx_sbom)

        # Apply backend metadata to BOM object (simulate enrichment)
        if "supplier" in sample_backend_payload_basic:
            from cyclonedx.model.bom import OrganizationalContact, OrganizationalEntity

            supplier_data = sample_backend_payload_basic["supplier"]
            supplier = OrganizationalEntity(
                name=supplier_data.get("name"), urls=supplier_data.get("url", []), contacts=[]
            )
            for contact_data in supplier_data.get("contacts", []):
                contact = OrganizationalContact(
                    name=contact_data.get("name"), email=contact_data.get("email"), phone=contact_data.get("phone")
                )
                supplier.contacts.add(contact)
            bom.metadata.supplier = supplier

        # Apply back to JSON with intelligent merging
        updated_json = _apply_cyclonedx_metadata_to_json(sample_cyclonedx_sbom, bom)

        # Verify intelligent merging
        metadata = updated_json["metadata"]

        # Supplier should be updated to backend data (backend takes precedence for name)
        assert metadata["supplier"]["name"] == "Test Supplier"

        # URLs should be merged
        urls = metadata["supplier"]["url"]
        assert "http://supply.org" in urls
        assert "http://existing.com" in urls

        # Contacts should be merged (no duplicates by email)
        contacts = metadata["supplier"]["contacts"]
        contact_emails = {c["email"] for c in contacts}
        assert "c1@contacts.org" in contact_emails
        assert "existing@example.com" in contact_emails

    @patch("sbomify_action.cli.main.requests.get")
    def test_spdx_enrichment_placeholder(
        self, mock_get, tmp_path, sample_spdx_sbom, sample_backend_payload_basic, mock_config
    ):
        """Test SPDX enrichment (placeholder implementation)."""
        # Setup mock API response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_payload_basic
        mock_get.return_value = mock_response

        # Create temporary SBOM file
        sbom_file = tmp_path / "test_spdx.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_spdx_sbom, f)

        # Load and enrich SBOM
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))
        enriched_object, updated_json = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, mock_config
        )

        # Verify API was called
        mock_get.assert_called_once()

        # Verify SPDX enrichment (basic placeholder)
        creation_info = updated_json["creationInfo"]
        creators = creation_info["creators"]

        # Should include supplier as organization creator
        org_creators = [c for c in creators if c.startswith("Organization:")]
        assert any("Test Supplier" in c for c in org_creators)

        # Should preserve existing creators
        assert "Tool: test-tool" in creators

    def test_api_error_handling(self, tmp_path, sample_cyclonedx_sbom, mock_config):
        """Test proper error handling for API failures."""
        # Create temporary SBOM file
        sbom_file = tmp_path / "test_sbom.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_cyclonedx_sbom, f)

        # Test connection error
        with patch("sbomify_action.cli.main.requests.get") as mock_get:
            mock_get.side_effect = ConnectionError("Connection failed")

            sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))

            with pytest.raises(APIError) as exc_info:
                enrich_sbom_with_backend_metadata(sbom_format, original_json, parsed_object, mock_config)

            assert "Failed to connect to sbomify API" in str(exc_info.value)

        # Test HTTP error response
        with patch("sbomify_action.cli.main.requests.get") as mock_get:
            mock_response = Mock()
            mock_response.ok = False
            mock_response.status_code = 404
            mock_response.headers = {"content-type": "application/json"}
            mock_response.json.return_value = {"detail": "Component not found"}
            mock_get.return_value = mock_response

            with pytest.raises(APIError) as exc_info:
                enrich_sbom_with_backend_metadata(sbom_format, original_json, parsed_object, mock_config)

            assert "404" in str(exc_info.value)
            assert "Component not found" in str(exc_info.value)

    @patch("sbomify_action.cli.main.requests.get")
    def test_cyclonedx_enrichment_basic_licenses(
        self, mock_get, tmp_path, sample_cyclonedx_sbom, sample_backend_payload_basic, mock_config
    ):
        """Test CycloneDX enrichment with basic license formats."""
        # Setup mock API response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_payload_basic
        mock_get.return_value = mock_response

        # Create temporary SBOM file
        sbom_file = tmp_path / "test_sbom.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_cyclonedx_sbom, f)

        # Load and enrich SBOM
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))
        enriched_object, updated_json = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, mock_config
        )

        # Verify enrichment results for basic scenario
        metadata = updated_json["metadata"]

        # Check supplier information
        assert "supplier" in metadata
        supplier = metadata["supplier"]
        assert supplier["name"] == "Test Supplier"
        assert "http://supply.org" in supplier["url"]
        assert len(supplier["contacts"]) == 1
        assert supplier["contacts"][0]["name"] == "C1"
        assert supplier["contacts"][0]["email"] == "c1@contacts.org"

        # Check authors (should include both backend and existing)
        assert "authors" in metadata
        authors = metadata["authors"]
        assert len(authors) >= 3  # 2 from backend + 1 existing

        # Find backend authors
        backend_author_emails = {"a1@example.org", "a2@example.com"}
        found_backend_authors = {a["email"] for a in authors if a.get("email") in backend_author_emails}
        assert found_backend_authors == backend_author_emails

        # Verify existing author is preserved
        existing_author = next((a for a in authors if a.get("email") == "original@example.com"), None)
        assert existing_author is not None
        assert existing_author["name"] == "Original Author"

        # Check licenses (basic format)
        assert "licenses" in metadata
        licenses = metadata["licenses"]
        assert len(licenses) >= 1

        # Extract license names from the proper CycloneDX format
        license_names = set()
        for license_item in licenses:
            if isinstance(license_item, dict) and "license" in license_item and "name" in license_item["license"]:
                license_names.add(license_item["license"]["name"])

        assert "GPL-1.0" in license_names

    def test_sbomify_tool_metadata_added(
        self, tmp_path, sample_cyclonedx_sbom, sample_backend_payload_basic, mock_config
    ):
        """Test that sbomify tool metadata is added to the SBOM."""
        with patch("sbomify_action.cli.main.requests.get") as mock_get:
            # Setup mock API response
            mock_response = Mock()
            mock_response.ok = True
            mock_response.json.return_value = sample_backend_payload_basic
            mock_get.return_value = mock_response

            # Create temporary SBOM file
            sbom_file = tmp_path / "test_sbom.json"
            with open(sbom_file, "w") as f:
                json.dump(sample_cyclonedx_sbom, f)

            # Load and enrich SBOM
            sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))
            enriched_object, updated_json = enrich_sbom_with_backend_metadata(
                sbom_format, original_json, parsed_object, mock_config
            )

            # Verify sbomify tool was added to metadata
            metadata = updated_json["metadata"]
            assert "tools" in metadata

            tools = metadata["tools"]
            # Handle the newer CycloneDX format where tools is {"components": [...]}
            if isinstance(tools, dict) and "components" in tools:
                tools_list = tools["components"]
            else:
                tools_list = tools if isinstance(tools, list) else []

            sbomify_tool = None
            for tool in tools_list:
                if isinstance(tool, dict) and tool.get("name") == "sbomify-github-action":
                    sbomify_tool = tool
                    break

            assert sbomify_tool is not None
            assert sbomify_tool["type"] == "application"
            # Check manufacturer - could be string or OrganizationalEntity object
            manufacturer = sbomify_tool["manufacturer"]
            if hasattr(manufacturer, "name"):
                # OrganizationalEntity object
                assert manufacturer.name == "sbomify"
            else:
                # String value
                assert manufacturer == "sbomify"
            assert sbomify_tool["name"] == "sbomify-github-action"
            # Version should be present and match the package version
            assert "version" in sbomify_tool
            # In CycloneDX 1.6, vendor field should not be present (uses manufacturer instead)
            assert "vendor" not in sbomify_tool

    def test_version_consistency(self):
        """Test that version detection methods are consistent."""
        import sbomify_action
        from sbomify_action.cli.main import SBOMIFY_VERSION

        # Both should return the same version
        assert sbomify_action.__version__ == SBOMIFY_VERSION
        # Should not be unknown in test environment
        assert sbomify_action.__version__ != "unknown"
        assert SBOMIFY_VERSION != "unknown"

    def test_cyclonedx_validation(self, tmp_path):
        """Test CycloneDX validation functionality."""
        # Create a test SBOM dictionary with required CycloneDX fields
        test_sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "test"}}}

        with patch("subprocess.run") as mock_run:
            # Mock successful validation
            mock_run.return_value.returncode = 0
            mock_run.return_value.stderr = ""

            # Create temporary SBOM file
            sbom_file = tmp_path / "test_sbom.json"
            with open(sbom_file, "w") as f:
                json.dump(test_sbom, f)

            # Test successful validation
            result = _validate_cyclonedx_sbom(str(sbom_file))
            assert result is True

            # Test validation failure with invalid SBOM
            invalid_sbom = {"metadata": {"component": {"name": "test"}}}  # Missing bomFormat and specVersion
            sbom_file_invalid = tmp_path / "test_sbom_invalid.json"
            with open(sbom_file_invalid, "w") as f:
                json.dump(invalid_sbom, f)

            result = _validate_cyclonedx_sbom(str(sbom_file_invalid))
            assert result is False

            # Test with non-existent file
            result = _validate_cyclonedx_sbom("non_existent_file.json")
            assert result is False

    @patch("sbomify_action.cli.main.requests.get")
    def test_local_sbom_version_override(self, mock_get, tmp_path, sample_cyclonedx_sbom, sample_backend_payload_basic):
        """Test that sbom_version overrides the component version locally."""
        # Setup config with sbom_version
        config = Config(
            token="test-token", component_id="test-component-123", upload=False, augment=True, sbom_version="v2.5.0"
        )

        # Setup mock API response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_payload_basic
        mock_get.return_value = mock_response

        # Ensure original SBOM has a different version
        sample_cyclonedx_sbom["metadata"]["component"]["version"] = "v1.0.0"

        # Create temporary SBOM file
        sbom_file = tmp_path / "test_sbom.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_cyclonedx_sbom, f)

        # Load and enrich SBOM
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))
        enriched_object, updated_json = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, config
        )

        # Verify that component version was overridden
        component = updated_json["metadata"]["component"]
        assert component["version"] == "v2.5.0"  # Should be the overridden version

    @patch("sbomify_action.cli.main.requests.get")
    def test_override_sbom_metadata_precedence(
        self, mock_get, tmp_path, sample_cyclonedx_sbom, sample_backend_payload_basic
    ):
        """Test that override_sbom_metadata controls metadata merging precedence."""

        # Test with override_sbom_metadata=True (backend takes precedence)
        config_override = Config(
            token="test-token",
            component_id="test-component-123",
            upload=False,
            augment=True,
            override_sbom_metadata=True,
        )

        # Setup mock API response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_payload_basic
        mock_get.return_value = mock_response

        # Create a copy and add existing supplier
        sbom_with_existing_supplier = copy.deepcopy(sample_cyclonedx_sbom)
        sbom_with_existing_supplier["metadata"]["supplier"] = {
            "name": "Original Supplier",
            "url": ["http://original.com"],  # Use list format for CycloneDX compatibility
        }

        # Create temporary SBOM file for override=True test
        sbom_file1 = tmp_path / "test_sbom_override.json"
        with open(sbom_file1, "w") as f:
            json.dump(sbom_with_existing_supplier, f)

        # Load and enrich SBOM with override=True
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file1))
        enriched_object, updated_json = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, config_override
        )

        # Verify backend data takes precedence
        supplier = updated_json["metadata"]["supplier"]
        assert supplier["name"] == "Test Supplier"  # Backend name should win

        # Test with override_sbom_metadata=False (existing takes precedence)
        config_no_override = Config(
            token="test-token",
            component_id="test-component-123",
            upload=False,
            augment=True,
            override_sbom_metadata=False,
        )

        # Reset mock and create a new copy
        mock_get.reset_mock()
        mock_get.return_value = mock_response

        # Create another copy for the second test
        sbom_with_existing_supplier2 = copy.deepcopy(sample_cyclonedx_sbom)
        sbom_with_existing_supplier2["metadata"]["supplier"] = {
            "name": "Original Supplier",
            "url": ["http://original.com"],  # Use list format for CycloneDX compatibility
        }

        # Create temporary SBOM file for override=False test
        sbom_file2 = tmp_path / "test_sbom_no_override.json"
        with open(sbom_file2, "w") as f:
            json.dump(sbom_with_existing_supplier2, f)

        # Load and enrich SBOM with override=False
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file2))
        enriched_object, updated_json = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, config_no_override
        )

        # Verify existing data takes precedence
        supplier = updated_json["metadata"]["supplier"]
        assert supplier["name"] == "Original Supplier"  # Original name should win

    @patch("sbomify_action.cli.main.requests.get")
    def test_override_name_working(self, mock_get, tmp_path, sample_cyclonedx_sbom, sample_backend_payload_basic):
        """Test that override_name actually overrides the component name with backend data."""
        # Add component name to the backend payload
        backend_payload_with_name = copy.deepcopy(sample_backend_payload_basic)
        backend_payload_with_name["name"] = "Backend Component Name"

        # Setup config with override_name
        config = Config(
            token="test-token", component_id="test-component-123", upload=False, augment=True, override_name=True
        )

        # Setup mock API response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = backend_payload_with_name
        mock_get.return_value = mock_response

        # Create temporary SBOM file
        sbom_file = tmp_path / "test_sbom.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_cyclonedx_sbom, f)

        # Load and enrich SBOM
        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file))
        enriched_object, updated_json = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, config
        )

        # Verify component name was overridden
        component = updated_json["metadata"]["component"]
        assert component["name"] == "Backend Component Name"  # Should be the backend name, not original

    @patch("sbomify_action.cli.main.requests.get")
    def test_comprehensive_version_aware_enrichment(
        self,
        mock_get,
        tmp_path,
        sample_cyclonedx_sbom_v15,
        sample_cyclonedx_sbom,
        sample_backend_payload_with_manufacturer,
        mock_config,
    ):
        """Test comprehensive version-aware enrichment between CycloneDX 1.5 and 1.6.

        Tools and authors metadata are version-specific:
        - CycloneDX 1.5: tools as array, author as string
        - CycloneDX 1.6: tools as object with components, authors as array
        Supplier and licenses have the same format in both versions.
        """
        # Setup mock API response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_payload_with_manufacturer
        mock_get.return_value = mock_response

        # Test CycloneDX 1.5 enrichment
        sbom_file_v15 = tmp_path / "test_sbom_v15.json"
        with open(sbom_file_v15, "w") as f:
            json.dump(sample_cyclonedx_sbom_v15, f)

        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file_v15))

        # Simulate 1.5 format in the original JSON (convert authors array to author string)
        # This simulates what a real 1.5 SBOM would look like
        if "authors" in original_json["metadata"]:
            original_authors = original_json["metadata"]["authors"]
            original_json["metadata"]["author"] = original_authors[0]["name"] if original_authors else ""
            del original_json["metadata"]["authors"]

        enriched_object, updated_json_v15 = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, mock_config
        )

        # ===== CycloneDX 1.5 VERIFICATION =====
        metadata_v15 = updated_json_v15["metadata"]

        # 1. Tools format verification (version-specific)
        assert "tools" in metadata_v15
        tools_v15 = metadata_v15["tools"]
        assert isinstance(tools_v15, list), "CycloneDX 1.5 tools should be an array"

        sbomify_tool_v15 = None
        for tool in tools_v15:
            if tool.get("name") == "sbomify-github-action":
                sbomify_tool_v15 = tool
                break

        assert sbomify_tool_v15 is not None
        # Check vendor - could be string or OrganizationalEntity object
        vendor = sbomify_tool_v15["vendor"]
        if hasattr(vendor, "name"):
            # OrganizationalEntity object
            assert vendor.name == "sbomify"
        else:
            # String value
            assert vendor == "sbomify"
        assert sbomify_tool_v15["name"] == "sbomify-github-action"
        assert "version" in sbomify_tool_v15
        assert "type" not in sbomify_tool_v15  # No type field in 1.5
        assert "manufacturer" not in sbomify_tool_v15  # No manufacturer field in 1.5

        # 2. Common metadata fields (same format in both versions)
        # Supplier
        assert "supplier" in metadata_v15
        supplier_v15 = metadata_v15["supplier"]
        assert supplier_v15["name"] == "Test Supplier"

        # Authors (CycloneDX 1.5 format: author as string)
        assert "author" in metadata_v15
        author_v15 = metadata_v15["author"]
        assert isinstance(author_v15, str), "CycloneDX 1.5 author should be a string"
        # Should combine backend authors with existing author
        assert "A1" in author_v15 and "A2" in author_v15 and "Original Author" in author_v15

        # Licenses
        assert "licenses" in metadata_v15
        licenses_v15 = metadata_v15["licenses"]
        license_names = set()
        for license_item in licenses_v15:
            if isinstance(license_item, dict) and "license" in license_item:
                license_names.add(license_item["license"]["name"])
        assert "GPL-1.0" in license_names

        # Reset mock for second test
        mock_get.reset_mock()
        mock_get.return_value = mock_response

        # Test CycloneDX 1.6 enrichment
        sbom_file_v16 = tmp_path / "test_sbom_v16.json"
        with open(sbom_file_v16, "w") as f:
            json.dump(sample_cyclonedx_sbom, f)

        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file_v16))
        enriched_object, updated_json_v16 = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, mock_config
        )

        # ===== CycloneDX 1.6 VERIFICATION =====
        metadata_v16 = updated_json_v16["metadata"]

        # 1. Tools format verification (version-specific)
        assert "tools" in metadata_v16
        tools_v16 = metadata_v16["tools"]
        assert isinstance(tools_v16, dict), "CycloneDX 1.6 tools should be an object"
        assert "components" in tools_v16, "CycloneDX 1.6 tools should have components array"

        components = tools_v16["components"]
        assert isinstance(components, list)

        sbomify_tool_v16 = None
        for tool in components:
            if tool.get("name") == "sbomify-github-action":
                sbomify_tool_v16 = tool
                break

        assert sbomify_tool_v16 is not None
        assert sbomify_tool_v16["type"] == "application"  # Required in 1.6
        # Check manufacturer - could be string or OrganizationalEntity object
        manufacturer = sbomify_tool_v16["manufacturer"]
        if hasattr(manufacturer, "name"):
            # OrganizationalEntity object
            assert manufacturer.name == "sbomify"
        else:
            # String value
            assert manufacturer == "sbomify"
        assert sbomify_tool_v16["name"] == "sbomify-github-action"
        assert "version" in sbomify_tool_v16
        assert "vendor" not in sbomify_tool_v16  # No vendor field in 1.6

        # 2. Common metadata fields verification (should be identical to 1.5)
        # Supplier
        assert "supplier" in metadata_v16
        supplier_v16 = metadata_v16["supplier"]
        assert supplier_v16["name"] == "Test Supplier"

        # Authors (CycloneDX 1.6 format: authors as array)
        assert "authors" in metadata_v16
        authors_v16 = metadata_v16["authors"]
        assert isinstance(authors_v16, list), "CycloneDX 1.6 authors should be an array"
        author_emails_v16 = {a["email"] for a in authors_v16}
        assert "a1@example.org" in author_emails_v16
        assert "a2@example.com" in author_emails_v16
        # Should preserve existing author from 1.6 format
        existing_author_v16 = next((a for a in authors_v16 if a.get("email") == "original@example.com"), None)
        assert existing_author_v16 is not None
        assert existing_author_v16["name"] == "Original Author"

        # Licenses
        assert "licenses" in metadata_v16
        licenses_v16 = metadata_v16["licenses"]
        license_names_v16 = set()
        for license_item in licenses_v16:
            if isinstance(license_item, dict) and "license" in license_item:
                license_names_v16.add(license_item["license"]["name"])
        assert "GPL-1.0" in license_names_v16

        # ===== CROSS-VERSION CONSISTENCY VERIFICATION =====
        # Verify that common metadata fields produce identical results
        assert supplier_v15 == supplier_v16, "Supplier metadata should be identical between versions"

        # Authors have different formats but should contain same information:
        # 1.5: author string contains all author names
        # 1.6: authors array contains author objects with emails
        assert "A1" in author_v15 and "A2" in author_v15, "1.5 author string should contain backend authors"
        assert author_emails_v16 == {"a1@example.org", "a2@example.com", "original@example.com"}, (
            "1.6 should have all author emails"
        )

        assert license_names == license_names_v16, "License names should be identical between versions"

    @patch("sbomify_action.cli.main.requests.get")
    def test_version_edge_cases_and_fallbacks(
        self, mock_get, tmp_path, sample_backend_payload_with_manufacturer, mock_config
    ):
        """Test version detection edge cases and fallback behavior."""
        # Setup mock API response
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_payload_with_manufacturer
        mock_get.return_value = mock_response

        # Test 1: Unknown version should fallback to 1.5 format
        sbom_unknown_version = {
            "bomFormat": "CycloneDX",
            "specVersion": "2.0",  # Future version
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2023-01-01T00:00:00Z",
                "component": {"type": "application", "name": "test-app", "version": "1.0.0"},
            },
            "components": [],
        }

        sbom_file_unknown = tmp_path / "test_sbom_unknown.json"
        with open(sbom_file_unknown, "w") as f:
            json.dump(sbom_unknown_version, f)

        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file_unknown))
        enriched_object, updated_json_unknown = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, mock_config
        )

        # Should fallback to 1.5 format (array tools, vendor field, manufacture field)
        metadata_unknown = updated_json_unknown["metadata"]
        tools_unknown = metadata_unknown["tools"]
        assert isinstance(tools_unknown, list), "Unknown version should fallback to 1.5 format (array tools)"

        # Find sbomify tool
        sbomify_tool = next((t for t in tools_unknown if t.get("name") == "sbomify-github-action"), None)
        assert sbomify_tool is not None
        assert "vendor" in sbomify_tool, "Unknown version should fallback to 1.5 format (vendor field)"
        assert "manufacturer" not in sbomify_tool, "Unknown version should not have 1.6 manufacturer field"

        # Test 2: Missing specVersion should fallback to 1.5
        mock_get.reset_mock()
        mock_get.return_value = mock_response

        sbom_no_version = {
            "bomFormat": "CycloneDX",
            # No specVersion field
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2023-01-01T00:00:00Z",
                "component": {"type": "application", "name": "test-app", "version": "1.0.0"},
            },
            "components": [],
        }

        sbom_file_no_version = tmp_path / "test_sbom_no_version.json"
        with open(sbom_file_no_version, "w") as f:
            json.dump(sbom_no_version, f)

        sbom_format, original_json, parsed_object = load_sbom_from_file(str(sbom_file_no_version))
        enriched_object, updated_json_no_version = enrich_sbom_with_backend_metadata(
            sbom_format, original_json, parsed_object, mock_config
        )

        # Should fallback to 1.5 format
        metadata_no_version = updated_json_no_version["metadata"]
        tools_no_version = metadata_no_version["tools"]
        assert isinstance(tools_no_version, list), "Missing specVersion should fallback to 1.5 format"
