"""
Tests for SBOM enrichment functionality with backend metadata.
"""

import json
import subprocess
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
            sbomify_tool = None
            for tool in tools:
                if isinstance(tool, dict) and tool.get("name") == "sbomify-github-action":
                    sbomify_tool = tool
                    break

            assert sbomify_tool is not None
            assert sbomify_tool["vendor"] == "sbomify"
            assert sbomify_tool["name"] == "sbomify-github-action"
            # Version should be present and match the package version
            assert "version" in sbomify_tool

            # Verify it's the correct version from poetry (should be 0.2.0)
            import sbomify_action

            expected_version = sbomify_action.__version__
            assert sbomify_tool["version"] == expected_version
            # Sanity check that we're not getting "unknown"
            assert sbomify_tool["version"] != "unknown"

    def test_version_consistency(self):
        """Test that version detection methods are consistent."""
        import sbomify_action
        from sbomify_action.cli.main import SBOMIFY_VERSION

        # Both should return the same version
        assert sbomify_action.__version__ == SBOMIFY_VERSION
        # Should not be unknown in test environment
        assert sbomify_action.__version__ != "unknown"
        assert SBOMIFY_VERSION != "unknown"

    def test_cyclonedx_validation(self, tmp_path, sample_cyclonedx_sbom):
        """Test CycloneDX SBOM validation functionality."""

        # Create temporary SBOM file
        sbom_file = tmp_path / "test_sbom.json"
        with open(sbom_file, "w") as f:
            json.dump(sample_cyclonedx_sbom, f)

        # Test successful validation
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stderr = ""

            result = _validate_cyclonedx_sbom(str(sbom_file))
            assert result is True

            # Verify cyclonedx-py was called correctly
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "cyclonedx-py" in call_args
            assert "validate" in call_args
            assert str(sbom_file) in call_args

        # Test validation failure
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "Validation failed"

            result = _validate_cyclonedx_sbom(str(sbom_file))
            assert result is False

        # Test when cyclonedx-py tool is not found
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("cyclonedx-py not found")

            result = _validate_cyclonedx_sbom(str(sbom_file))
            assert result is True  # Should not fail if tool is not available

        # Test timeout
        with patch("subprocess.run") as mock_run:
            from sbomify_action.exceptions import CommandExecutionError

            mock_run.side_effect = subprocess.TimeoutExpired("cyclonedx-py", 30)

            with pytest.raises(CommandExecutionError) as exc_info:
                _validate_cyclonedx_sbom(str(sbom_file))

            assert "timed out" in str(exc_info.value)
