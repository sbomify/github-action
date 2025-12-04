"""
Tests for the new augmentation module with proper library usage.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cyclonedx.model.bom import Bom
from spdx_tools.spdx.model import Actor, ActorType

from sbomify_action.augmentation import (
    augment_cyclonedx_sbom,
    augment_sbom_from_file,
    augment_spdx_sbom,
    fetch_backend_metadata,
)


class TestLicenseHandling:
    """Test handling of three license types from backend API."""

    @pytest.fixture
    def sample_backend_metadata_with_mixed_licenses(self):
        """Backend metadata with all three license types."""
        return {
            "supplier": {
                "name": "Test Corp",
                "url": ["https://test.com"],
                "contact": [{"name": "Test Contact", "email": "contact@test.com"}],
            },
            "authors": [{"name": "Test Author", "email": "author@test.com"}],
            "licenses": [
                "MIT",  # Type 1: Simple SPDX license string
                "Apache-2.0 OR GPL-3.0",  # Type 2: License expression string
                {  # Type 3: Custom license object
                    "name": "Custom Proprietary License",
                    "url": "https://test.com/license",
                    "text": "Custom license text here",
                },
            ],
        }

    @pytest.fixture
    def sample_cyclonedx_bom(self):
        """Sample CycloneDX BOM for testing."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    def test_cyclonedx_augmentation_with_mixed_licenses(
        self, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses
    ):
        """Test that CycloneDX augmentation handles all three license types."""
        # Augment the BOM
        enriched_bom = augment_cyclonedx_sbom(
            bom=sample_cyclonedx_bom,
            augmentation_data=sample_backend_metadata_with_mixed_licenses,
            override_sbom_metadata=False,
        )

        # Verify licenses were combined into ONE expression (per CycloneDX spec)
        # When multiple licenses are present, they must be combined into a single LicenseExpression
        assert len(enriched_bom.metadata.licenses) == 1

        # Convert to JSON to verify structure using proper serialization
        from cyclonedx.model.license import LicenseExpression
        from cyclonedx.output.json import JsonV1Dot6

        outputter = JsonV1Dot6(enriched_bom)
        bom_json_str = outputter.output_as_string()
        bom_json = json.loads(bom_json_str)
        licenses = bom_json["metadata"]["licenses"]

        # Verify we have one license expression
        assert len(licenses) == 1
        assert "expression" in licenses[0]

        # The expression should combine all three licenses with OR (treating as alternatives)
        # This is correct for dual/multi-licensing: user can choose any of the offered licenses
        expression = licenses[0]["expression"]
        assert "MIT" in expression
        assert "Apache-2.0 OR GPL-3.0" in expression
        assert "Custom Proprietary License" in expression
        assert " OR " in expression

        # Verify the licenses are alternatives, not all required
        # Should be: "MIT OR Apache-2.0 OR GPL-3.0 OR Custom Proprietary License"
        # NOT: "MIT AND (Apache-2.0 OR GPL-3.0) AND Custom Proprietary License"

        # Verify it's a valid LicenseExpression object
        license_obj = list(enriched_bom.metadata.licenses)[0]
        assert isinstance(license_obj, LicenseExpression)

    def test_cyclonedx_supplier_augmentation(self, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses):
        """Test that supplier information is properly augmented."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=sample_cyclonedx_bom,
            augmentation_data=sample_backend_metadata_with_mixed_licenses,
            override_sbom_metadata=False,
        )

        # Verify supplier
        assert enriched_bom.metadata.supplier is not None
        assert enriched_bom.metadata.supplier.name == "Test Corp"
        assert len(enriched_bom.metadata.supplier.urls) > 0
        assert len(enriched_bom.metadata.supplier.contacts) == 1

    def test_cyclonedx_authors_augmentation(self, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses):
        """Test that authors are properly augmented."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=sample_cyclonedx_bom,
            augmentation_data=sample_backend_metadata_with_mixed_licenses,
            override_sbom_metadata=False,
        )

        # Verify authors
        assert len(enriched_bom.metadata.authors) == 1
        author = list(enriched_bom.metadata.authors)[0]
        assert author.name == "Test Author"
        assert author.email == "author@test.com"

    def test_component_overrides(self, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses):
        """Test that component name and version overrides work."""
        enriched_bom = augment_cyclonedx_sbom(
            bom=sample_cyclonedx_bom,
            augmentation_data=sample_backend_metadata_with_mixed_licenses,
            override_sbom_metadata=False,
            component_name="overridden-name",
            component_version="2.0.0",
        )

        # Verify overrides
        assert enriched_bom.metadata.component.name == "overridden-name"
        assert enriched_bom.metadata.component.version == "2.0.0"

    @patch("sbomify_action.augmentation.requests.get")
    def test_fetch_backend_metadata(self, mock_get, sample_backend_metadata_with_mixed_licenses):
        """Test fetching metadata from backend API."""
        # Setup mock
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_metadata_with_mixed_licenses
        mock_get.return_value = mock_response

        # Fetch metadata
        result = fetch_backend_metadata(
            api_base_url="https://api.test.com",
            token="test-token",
            component_id="test-component-123",
        )

        # Verify API call
        mock_get.assert_called_once()
        assert result == sample_backend_metadata_with_mixed_licenses

    @patch("sbomify_action.augmentation.requests.get")
    def test_augment_sbom_from_file_cyclonedx(
        self, mock_get, sample_cyclonedx_bom, sample_backend_metadata_with_mixed_licenses
    ):
        """Test augmenting SBOM from file (CycloneDX)."""
        # Setup mock
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = sample_backend_metadata_with_mixed_licenses
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create input file
            input_file = Path(tmpdir) / "input.json"
            output_file = Path(tmpdir) / "output.json"

            from cyclonedx.output.json import JsonV1Dot6

            outputter = JsonV1Dot6(sample_cyclonedx_bom)
            with open(input_file, "w") as f:
                f.write(outputter.output_as_string())

            # Augment
            format_result = augment_sbom_from_file(
                input_file=str(input_file),
                output_file=str(output_file),
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component-123",
            )

            # Verify
            assert format_result == "cyclonedx"
            assert output_file.exists()

            # Load and verify output
            with open(output_file, "r") as f:
                output_data = json.load(f)

            assert output_data["bomFormat"] == "CycloneDX"
            assert "supplier" in output_data["metadata"]
            assert output_data["metadata"]["supplier"]["name"] == "Test Corp"


class TestVersionCompatibility:
    """Test compatibility with different SBOM versions."""

    @pytest.fixture
    def cyclonedx_15_bom(self):
        """CycloneDX 1.5 BOM."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app-15",
                    "version": "1.5.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    @pytest.fixture
    def cyclonedx_16_bom(self):
        """CycloneDX 1.6 BOM."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app-16",
                    "version": "1.6.0",
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    def test_cyclonedx_15_augmentation(self, cyclonedx_15_bom):
        """Test augmentation works with CycloneDX 1.5."""
        backend_data = {
            "supplier": {"name": "Test Supplier 1.5"},
            "authors": [{"name": "Author 1.5"}],
            "licenses": ["MIT"],
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_15_bom,
            augmentation_data=backend_data,
        )

        # Verify augmentation worked
        assert enriched_bom.metadata.supplier.name == "Test Supplier 1.5"

    def test_cyclonedx_16_augmentation(self, cyclonedx_16_bom):
        """Test augmentation works with CycloneDX 1.6."""
        backend_data = {
            "supplier": {"name": "Test Supplier 1.6"},
            "authors": [{"name": "Author 1.6"}],
            "licenses": ["Apache-2.0"],
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_16_bom,
            augmentation_data=backend_data,
        )

        # Verify augmentation worked
        assert enriched_bom.metadata.supplier.name == "Test Supplier 1.6"


class TestSPDXAugmentation:
    """Test SPDX augmentation functionality."""

    @pytest.fixture
    def spdx_document(self):
        """Create a sample SPDX document."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            ActorType,
            CreationInfo,
            Document,
            Package,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://test.com/test-doc",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime(2024, 1, 1),
        )

        package = Package(
            spdx_id="SPDXRef-main", name="test-app", download_location="https://example.com", version="1.0.0"
        )

        return Document(creation_info=creation_info, packages=[package])

    def test_spdx_supplier_augmentation(self, spdx_document):
        """Test SPDX supplier augmentation."""
        backend_data = {
            "supplier": {
                "name": "SPDX Test Corp",
                "url": ["https://spdxtest.com"],
            },
            "authors": [],
            "licenses": [],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Verify supplier was added to creators
        org_creators = [c for c in enriched_doc.creation_info.creators if c.actor_type == ActorType.ORGANIZATION]
        assert len(org_creators) > 0
        assert any("SPDX Test Corp" in c.name for c in org_creators)

        # Verify packages have supplier
        assert enriched_doc.packages[0].supplier is not None
        assert "SPDX Test Corp" in enriched_doc.packages[0].supplier.name

    def test_spdx_authors_augmentation(self, spdx_document):
        """Test SPDX authors augmentation."""
        backend_data = {
            "supplier": {},
            "authors": [{"name": "SPDX Author", "email": "author@spdx.com"}],
            "licenses": [],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Verify author was added to creators
        person_creators = [c for c in enriched_doc.creation_info.creators if c.actor_type == ActorType.PERSON]
        assert len(person_creators) > 0
        assert any("SPDX Author" in c.name for c in person_creators)

        # Verify packages have originator
        assert enriched_doc.packages[0].originator is not None
        assert "SPDX Author" in enriched_doc.packages[0].originator.name

    def test_spdx_component_overrides(self, spdx_document):
        """Test SPDX component name and version overrides."""
        backend_data = {
            "supplier": {},
            "authors": [],
            # No licenses key to avoid the empty list issue
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            component_name="overridden-spdx-name",
            component_version="2.0.0-spdx",
        )

        # Verify document name was overridden (SPDX stores name in creation_info)
        assert enriched_doc.creation_info.name == "overridden-spdx-name"

        # Verify package name and version were overridden
        assert enriched_doc.packages[0].name == "overridden-spdx-name"
        assert enriched_doc.packages[0].version == "2.0.0-spdx"

    @patch("sbomify_action.augmentation.requests.get")
    def test_augment_sbom_from_file_spdx(self, mock_get, spdx_document):
        """Test augmenting SPDX SBOM from file."""
        backend_data = {
            "supplier": {"name": "SPDX Supplier"},
            "authors": [{"name": "SPDX Author"}],
            "licenses": ["MIT"],
        }

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = backend_data
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

            input_file = Path(tmpdir) / "input_spdx.json"
            output_file = Path(tmpdir) / "output_spdx.json"

            # Write input
            spdx_write_file(spdx_document, str(input_file), validate=False)

            # Augment
            format_result = augment_sbom_from_file(
                input_file=str(input_file),
                output_file=str(output_file),
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component-spdx",
            )

            # Verify
            assert format_result == "spdx"
            assert output_file.exists()

            # Load and verify output
            from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file

            output_doc = spdx_parse_file(str(output_file))

            # Verify supplier was added
            org_creators = [c for c in output_doc.creation_info.creators if c.actor_type == ActorType.ORGANIZATION]
            assert any("SPDX Supplier" in c.name for c in org_creators)

    def test_spdx_homepage_preservation(self, spdx_document):
        """Test that existing homepage is preserved."""
        # Set existing homepage
        spdx_document.packages[0].homepage = "https://existing.com"

        backend_data = {
            "supplier": {
                "name": "Test Supplier",
                "url": ["https://supplier.com"],
            },
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            override_sbom_metadata=False,
        )

        # Homepage should be preserved (not overridden)
        assert enriched_doc.packages[0].homepage == "https://existing.com"

    def test_spdx_homepage_added_when_missing(self, spdx_document):
        """Test that homepage is added from supplier URL when missing."""
        backend_data = {
            "supplier": {
                "name": "Test Supplier",
                "url": ["https://supplier.com"],
            },
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Homepage should be added from supplier URL
        assert enriched_doc.packages[0].homepage == "https://supplier.com"

    def test_spdx_originator_preservation(self, spdx_document):
        """Test that existing originator is preserved."""
        from spdx_tools.spdx.model import ActorType

        # Set existing originator
        spdx_document.packages[0].originator = Actor(ActorType.PERSON, "Existing Originator")

        backend_data = {
            "authors": [{"name": "Backend Author"}],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            override_sbom_metadata=False,
        )

        # Originator should be preserved
        assert "Existing Originator" in enriched_doc.packages[0].originator.name

    def test_spdx_duplicate_external_refs_avoided(self, spdx_document):
        """Test that duplicate external references are not added."""
        from spdx_tools.spdx.model import ExternalPackageRef, ExternalPackageRefCategory

        # Add an existing external ref
        existing_ref = ExternalPackageRef(
            category=ExternalPackageRefCategory.OTHER,
            reference_type="website",
            locator="https://supplier.com",
            comment="Existing",
        )
        spdx_document.packages[0].external_references.append(existing_ref)

        backend_data = {
            "supplier": {
                "name": "Test Supplier",
                "url": ["https://supplier.com"],  # Same URL
            },
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Should not have duplicate - still only 1 ref
        refs_with_url = [
            ref for ref in enriched_doc.packages[0].external_references if ref.locator == "https://supplier.com"
        ]
        assert len(refs_with_url) == 1

    def test_spdx_preserves_existing_creators(self, spdx_document):
        """Test that existing creators are preserved."""
        from spdx_tools.spdx.model import ActorType

        # Add an existing creator
        existing_creator = Actor(ActorType.PERSON, "Original Creator")
        spdx_document.creation_info.creators.append(existing_creator)

        backend_data = {
            "supplier": {"name": "New Supplier"},
            "authors": [{"name": "New Author"}],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Original creator should still be present
        creator_names = [c.name for c in enriched_doc.creation_info.creators]
        assert "Original Creator" in " ".join(creator_names)

    def test_spdx_license_handling(self, spdx_document):
        """Test SPDX license handling with mixed types."""
        backend_data = {
            "licenses": [
                "MIT",
                "Apache-2.0 OR GPL-3.0",
                {"name": "Custom SPDX License", "url": "https://custom.com/license", "text": "Custom license text"},
            ],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Verify license_declared was set with the full expression
        package = enriched_doc.packages[0]
        assert package.license_declared is not None
        license_declared_str = str(package.license_declared)
        assert "MIT" in license_declared_str
        # Custom licenses are converted to LicenseRef format
        assert "LicenseRef" in license_declared_str

        # Verify ExtractedLicensingInfo objects were added to document
        assert len(enriched_doc.extracted_licensing_info) > 0
        custom_license = enriched_doc.extracted_licensing_info[0]
        assert custom_license.license_id.startswith("LicenseRef-")
        assert custom_license.extracted_text == "Custom license text"
        assert custom_license.license_name == "Custom SPDX License"
        assert "https://custom.com/license" in custom_license.cross_references

    def test_spdx_supplier_with_multiple_urls(self, spdx_document):
        """Test SPDX handling of supplier with multiple URLs."""
        backend_data = {
            "supplier": {
                "name": "Multi URL Supplier",
                "url": ["https://main.com", "https://support.com"],
            },
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Verify external references were added
        package = enriched_doc.packages[0]
        ref_locators = [ref.locator for ref in package.external_references]
        assert "https://main.com" in ref_locators
        assert "https://support.com" in ref_locators

    def test_spdx_extracted_licensing_info_multiple_custom_licenses(self, spdx_document):
        """Test that multiple custom licenses create unique ExtractedLicensingInfo objects."""
        backend_data = {
            "licenses": [
                {"name": "Custom License 1", "url": "https://custom1.com", "text": "License 1 text"},
                {"name": "Custom License 2", "url": "https://custom2.com", "text": "License 2 text"},
                "MIT",  # Standard license
            ],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Should have 2 ExtractedLicensingInfo objects (for the 2 custom licenses)
        assert len(enriched_doc.extracted_licensing_info) == 2

        # Verify each custom license has proper fields
        license_ids = [lic.license_id for lic in enriched_doc.extracted_licensing_info]
        assert "LicenseRef-Custom-License-1" in license_ids
        assert "LicenseRef-Custom-License-2" in license_ids

        # Verify license_declared includes all licenses
        package = enriched_doc.packages[0]
        license_declared_str = str(package.license_declared)
        assert "MIT" in license_declared_str
        assert "LicenseRef-Custom-License-1" in license_declared_str
        assert "LicenseRef-Custom-License-2" in license_declared_str
        assert " OR " in license_declared_str

    def test_spdx_extracted_licensing_info_without_text(self, spdx_document):
        """Test that custom licenses without text field still work."""
        backend_data = {
            "licenses": [
                {"name": "Custom License No Text", "url": "https://custom.com"},
            ],
        }

        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
        )

        # Should have 1 ExtractedLicensingInfo object
        assert len(enriched_doc.extracted_licensing_info) == 1
        custom_license = enriched_doc.extracted_licensing_info[0]

        # Should have default text when not provided
        assert custom_license.extracted_text == "License text not provided"
        assert custom_license.license_name == "Custom License No Text"

    def test_spdx_license_declared_override_behavior(self, spdx_document):
        """Test that license_declared respects override_sbom_metadata flag."""
        # Set existing license_declared (need to use the parser to create an Expression object)
        from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser

        license_parser = LicenseExpressionParser()
        existing_license = license_parser.parse_license_expression("GPL-3.0")
        spdx_document.packages[0].license_declared = existing_license

        backend_data = {
            "licenses": ["MIT"],
        }

        # Without override - should add to comment
        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            override_sbom_metadata=False,
        )

        # Original license should be preserved (parser normalizes GPL-3.0 to GPL-3.0-only)
        assert "GPL-3.0" in str(enriched_doc.packages[0].license_declared)
        # Backend license should be in comment
        assert "MIT" in enriched_doc.packages[0].license_comment

        # With override - should replace
        spdx_document.packages[0].license_declared = existing_license
        enriched_doc = augment_spdx_sbom(
            document=spdx_document,
            augmentation_data=backend_data,
            override_sbom_metadata=True,
        )

        # Should be replaced with backend license
        assert "MIT" in str(enriched_doc.packages[0].license_declared)


class TestErrorHandling:
    """Test error handling in augmentation."""

    @patch("requests.get")
    def test_file_not_found_error(self, mock_get):
        """Test handling of missing input file."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {}}
        mock_get.return_value = mock_response

        with pytest.raises(FileNotFoundError) as exc_info:
            augment_sbom_from_file(
                input_file="/nonexistent/file.json",
                output_file="/tmp/output.json",
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component",
            )

        assert "Input SBOM file not found" in str(exc_info.value)
        assert "/nonexistent/file.json" in str(exc_info.value)

    @patch("requests.get")
    def test_invalid_json_error(self, mock_get):
        """Test handling of invalid JSON in input file."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "invalid.json"
            output_file = Path(tmpdir) / "output.json"

            # Write invalid JSON
            with open(input_file, "w") as f:
                f.write("{invalid json content")

            with pytest.raises(ValueError) as exc_info:
                augment_sbom_from_file(
                    input_file=str(input_file),
                    output_file=str(output_file),
                    api_base_url="https://api.test.com",
                    token="test-token",
                    component_id="test-component",
                )

            assert "Invalid JSON in SBOM file" in str(exc_info.value)

    @patch("requests.get")
    def test_api_connection_error(self, mock_get):
        """Test handling of API connection errors."""
        import requests

        from sbomify_action.exceptions import APIError

        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        with pytest.raises(APIError) as exc_info:
            fetch_backend_metadata(
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component",
            )

        assert "Failed to connect" in str(exc_info.value)

    @patch("requests.get")
    def test_api_timeout_error(self, mock_get):
        """Test handling of API timeout errors."""
        import requests

        from sbomify_action.exceptions import APIError

        mock_get.side_effect = requests.exceptions.Timeout("Timeout")

        with pytest.raises(APIError) as exc_info:
            fetch_backend_metadata(
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="test-component",
            )

        assert "timed out" in str(exc_info.value)

    @patch("requests.get")
    def test_api_404_error(self, mock_get):
        """Test handling of API 404 errors."""
        from sbomify_action.exceptions import APIError

        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Component not found"}
        mock_get.return_value = mock_response

        with pytest.raises(APIError) as exc_info:
            fetch_backend_metadata(
                api_base_url="https://api.test.com",
                token="test-token",
                component_id="nonexistent",
            )

        assert "404" in str(exc_info.value)
        assert "Component not found" in str(exc_info.value)

    @patch("requests.get")
    def test_missing_spec_version_error(self, mock_get):
        """Test handling of missing specVersion in CycloneDX SBOM."""
        from sbomify_action.exceptions import SBOMValidationError

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"supplier": {}}
        mock_get.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "sbom.json"
            output_file = Path(tmpdir) / "output.json"

            # Write CycloneDX SBOM without specVersion
            sbom_data = {
                "bomFormat": "CycloneDX",
                # specVersion is intentionally missing
                "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
                "version": 1,
                "metadata": {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "component": {
                        "type": "application",
                        "name": "test-app",
                        "version": "1.0.0",
                    },
                },
                "components": [],
            }

            with open(input_file, "w") as f:
                json.dump(sbom_data, f)

            with pytest.raises(SBOMValidationError) as exc_info:
                augment_sbom_from_file(
                    input_file=str(input_file),
                    output_file=str(output_file),
                    api_base_url="https://api.test.com",
                    token="test-token",
                    component_id="test-component",
                )

            assert "specVersion" in str(exc_info.value)
            assert "missing" in str(exc_info.value).lower()


class TestSupplierMerging:
    """Test supplier merging behavior."""

    @pytest.fixture
    def cyclonedx_bom_with_existing_supplier(self):
        """BOM that already has supplier info."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
                "supplier": {
                    "name": "Existing Supplier",
                    "url": ["https://existing.com"],
                    "contact": [{"name": "Existing Contact", "email": "existing@example.com"}],
                },
            },
            "components": [],
        }
        return Bom.from_json(bom_json)

    def test_supplier_merge_preserves_existing(self, cyclonedx_bom_with_existing_supplier):
        """Test that existing supplier is preserved when override=False."""
        backend_data = {
            "supplier": {
                "name": "Backend Supplier",
                "url": ["https://backend.com"],
                "contact": [{"name": "Backend Contact", "email": "backend@example.com"}],
            },
            # No authors or licenses to avoid empty list issues
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_bom_with_existing_supplier,
            augmentation_data=backend_data,
            override_sbom_metadata=False,
        )

        # Name should be preserved from existing
        assert enriched_bom.metadata.supplier.name == "Existing Supplier"

        # URLs should be merged
        urls = {str(url) for url in enriched_bom.metadata.supplier.urls}
        assert "https://existing.com" in urls
        assert "https://backend.com" in urls

        # Contacts should be merged
        assert len(enriched_bom.metadata.supplier.contacts) == 2

    def test_supplier_override_replaces_existing(self, cyclonedx_bom_with_existing_supplier):
        """Test that existing supplier is replaced when override=True."""
        backend_data = {
            "supplier": {
                "name": "Backend Supplier",
                "url": ["https://backend.com"],
                "contact": [{"name": "Backend Contact", "email": "backend@example.com"}],
            },
            # No authors or licenses
        }

        enriched_bom = augment_cyclonedx_sbom(
            bom=cyclonedx_bom_with_existing_supplier,
            augmentation_data=backend_data,
            override_sbom_metadata=True,
        )

        # Name should be replaced with backend
        assert enriched_bom.metadata.supplier.name == "Backend Supplier"


class TestToolMetadataVersions:
    """Test tool metadata handling across different CycloneDX versions."""

    def test_tool_metadata_cyclonedx_14(self):
        """Test tool metadata is correctly added for CycloneDX 1.4 (legacy format)."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        bom = Bom.from_json(bom_json)
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.4")

        # For 1.4, sbomify should be added as a Tool in tools.tools (legacy format)
        tool_names = [tool.name for tool in enriched_bom.metadata.tools.tools]
        assert "sbomify GitHub Action" in tool_names, "sbomify should be in tools.tools for CDX 1.4"

        # Verify vendor is set (Tool.vendor should be string per spec)
        sbomify_tool = next(t for t in enriched_bom.metadata.tools.tools if t.name == "sbomify GitHub Action")
        assert sbomify_tool.vendor is not None
        assert sbomify_tool.vendor == "sbomify"
        assert isinstance(sbomify_tool.vendor, str), "Tool.vendor must be string, not OrganizationalEntity"

    def test_tool_metadata_cyclonedx_15(self):
        """Test tool metadata is correctly added for CycloneDX 1.5."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        bom = Bom.from_json(bom_json)
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.5")

        # For 1.5+, sbomify should be added as a Service in tools.services (modern format)
        service_names = [service.name for service in enriched_bom.metadata.tools.services]
        assert "sbomify GitHub Action" in service_names, "sbomify should be in tools.services for CDX 1.5+"

        # Verify group is set (equivalent to vendor in legacy format)
        sbomify_service = next(s for s in enriched_bom.metadata.tools.services if s.name == "sbomify GitHub Action")
        assert sbomify_service.group is not None
        assert sbomify_service.group == "sbomify"

    def test_tool_metadata_cyclonedx_16(self):
        """Test tool metadata is correctly added for CycloneDX 1.6."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        bom = Bom.from_json(bom_json)
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.6")

        # For 1.6+, sbomify should be added as a Service in tools.services (modern format)
        service_names = [service.name for service in enriched_bom.metadata.tools.services]
        assert "sbomify GitHub Action" in service_names, "sbomify should be in tools.services for CDX 1.6+"

        # Verify external references
        sbomify_service = next(s for s in enriched_bom.metadata.tools.services if s.name == "sbomify GitHub Action")
        assert len(sbomify_service.external_references) > 0

    def test_tool_metadata_avoids_duplicates(self):
        """Test that tool metadata doesn't create duplicates."""
        bom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:33333333-3333-3333-3333-333333333333",
            "version": 1,
            "metadata": {},
            "components": [],
        }

        bom = Bom.from_json(bom_json)

        # Augment twice
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.6")
        enriched_bom = augment_cyclonedx_sbom(enriched_bom, augmentation_data={}, spec_version="1.6")

        # For 1.6+, sbomify is in services (modern format)
        service_names = [service.name for service in enriched_bom.metadata.tools.services]
        sbomify_count = service_names.count("sbomify GitHub Action")
        assert sbomify_count == 1, "Should not have duplicate sbomify services"

    def test_tool_metadata_normalizes_services_with_string_providers(self):
        """Test that tools are correctly handled in modern format (1.5+) without converting to legacy."""
        # This test verifies that for 1.5+, we keep the modern format (components/services)
        # and add sbomify as a service, not converting everything to legacy Tool format

        # Create a BOM programmatically with components that have group fields
        # (This is what SBOM generators like Trivy produce)
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType
        from cyclonedx.model.service import Service

        bom = Bom()
        bom.spec_version = "1.6"  # Set spec version to 1.6

        # Add a component with group (standard way to specify tool vendor)
        component = Component(name="tool-component", version="1.0.0", type=ComponentType.APPLICATION)
        component.group = "example-org"
        bom.metadata.tools.components.add(component)

        # Add a component like Trivy produces (with group field)
        component2 = Component(name="trivy", version="0.67.2", type=ComponentType.APPLICATION)
        component2.group = "aquasecurity"
        bom.metadata.tools.components.add(component2)

        # Add a service
        service = Service(name="test-service", version="1.0.0")
        bom.metadata.tools.services.add(service)

        # This should not raise TypeError during augmentation or serialization
        enriched_bom = augment_cyclonedx_sbom(bom, augmentation_data={}, spec_version="1.6")

        # For 1.6+, components and services should NOT be converted to legacy tools
        # They should remain in modern format
        assert len(enriched_bom.metadata.tools.components) == 2, (
            "Components should remain in modern format for CDX 1.6+"
        )
        assert len(enriched_bom.metadata.tools.services) >= 2, (
            "Services should remain in modern format (original + sbomify) for CDX 1.6+"
        )

        # Verify sbomify was added as a service
        service_names = [s.name for s in enriched_bom.metadata.tools.services]
        assert "sbomify GitHub Action" in service_names

        # Verify all components have string groups (equivalent to vendor)
        for comp in enriched_bom.metadata.tools.components:
            if comp.group is not None:
                assert isinstance(comp.group, str), (
                    f"Component '{comp.name}' group should be string, got {type(comp.group)}"
                )

        # Most importantly: verify we can serialize without errors
        from sbomify_action.serialization import serialize_cyclonedx_bom

        serialized = serialize_cyclonedx_bom(enriched_bom, "1.6")
        assert serialized is not None
        assert len(serialized) > 0


class TestLicenseRefSanitization:
    """Test SPDX LicenseRef sanitization."""

    def test_sanitize_basic_name(self):
        """Test sanitizing a simple license name."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("Custom License") == "Custom-License"
        assert _sanitize_license_ref_id("MIT") == "MIT"
        assert _sanitize_license_ref_id("Apache-2.0") == "Apache-2.0"

    def test_sanitize_special_characters(self):
        """Test sanitization removes invalid characters."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        # Remove parentheses, brackets, etc.
        assert _sanitize_license_ref_id("License (v1.0)") == "License-v1.0"
        assert _sanitize_license_ref_id("License [Beta]") == "License-Beta"
        assert _sanitize_license_ref_id("License/Version") == "License-Version"
        assert _sanitize_license_ref_id("License\\Path") == "License-Path"

        # Remove other invalid chars
        assert _sanitize_license_ref_id("License@Company") == "LicenseCompany"
        assert _sanitize_license_ref_id("License#1") == "License1"
        assert _sanitize_license_ref_id("License$Money") == "LicenseMoney"

    def test_sanitize_multiple_spaces(self):
        """Test multiple spaces collapse to single hyphen."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("Custom   License") == "Custom-License"
        assert _sanitize_license_ref_id("My  Custom  License") == "My-Custom-License"

    def test_sanitize_underscores_and_slashes(self):
        """Test underscores and slashes become hyphens."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("Custom_License") == "Custom-License"
        assert _sanitize_license_ref_id("BSD/MIT") == "BSD-MIT"
        assert _sanitize_license_ref_id("Custom_License/v2") == "Custom-License-v2"

    def test_sanitize_consecutive_hyphens(self):
        """Test multiple consecutive hyphens collapse to one."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("Custom---License") == "Custom-License"
        assert _sanitize_license_ref_id("A-.-.B") == "A-B"

    def test_sanitize_leading_trailing(self):
        """Test leading/trailing hyphens and periods are removed."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        assert _sanitize_license_ref_id("  Custom License  ") == "Custom-License"
        assert _sanitize_license_ref_id("-License-") == "License"
        assert _sanitize_license_ref_id(".License.") == "License"

    def test_sanitize_empty_name_raises(self):
        """Test empty or whitespace-only names raise ValueError."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        with pytest.raises(ValueError, match="cannot be empty"):
            _sanitize_license_ref_id("")

        with pytest.raises(ValueError, match="cannot be empty"):
            _sanitize_license_ref_id("   ")

    def test_sanitize_all_special_chars_raises(self):
        """Test name with only special characters raises ValueError."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        with pytest.raises(ValueError, match="cannot be sanitized"):
            _sanitize_license_ref_id("@#$%^&*()")

        with pytest.raises(ValueError, match="cannot be sanitized"):
            _sanitize_license_ref_id("---...")

    def test_sanitize_long_name_truncates(self):
        """Test very long names are truncated with hash."""
        from sbomify_action.augmentation import _sanitize_license_ref_id

        long_name = "A" * 100 + " Very Long License Name"
        result = _sanitize_license_ref_id(long_name)

        # Should be truncated to reasonable length
        assert len(result) <= 64
        # Should contain a hash for uniqueness
        assert "-" in result

    def test_convert_expression_with_collision_handling(self):
        """Test that duplicate custom licenses get unique refs."""
        from sbomify_action.augmentation import _convert_backend_licenses_to_spdx_expression

        # Two licenses that would sanitize to same thing
        licenses = [
            {"name": "Custom License"},
            {"name": "Custom-License"},  # Would sanitize to same as above
        ]

        expression, extracted_infos = _convert_backend_licenses_to_spdx_expression(licenses)

        # Should have two distinct LicenseRefs
        assert "LicenseRef-Custom-License" in expression
        assert "LicenseRef-Custom-License-2" in expression
        # Should have 2 ExtractedLicensingInfo objects
        assert len(extracted_infos) == 2

    def test_convert_expression_skips_invalid(self):
        """Test that invalid license names are skipped with warning."""
        from sbomify_action.augmentation import _convert_backend_licenses_to_spdx_expression

        licenses = [
            "MIT",
            {"name": "@@@"},  # Invalid - all special chars
            "Apache-2.0",
        ]

        expression, extracted_infos = _convert_backend_licenses_to_spdx_expression(licenses)

        # Should only have the valid licenses
        assert expression == "MIT OR Apache-2.0"
        # No extracted infos since invalid license was skipped
        assert len(extracted_infos) == 0

    def test_convert_expression_mixed_types(self):
        """Test conversion with mixed string and dict licenses."""
        from sbomify_action.augmentation import _convert_backend_licenses_to_spdx_expression

        licenses = [
            "MIT",
            {"name": "Proprietary License (Company X)"},
            "Apache-2.0",
        ]

        expression, extracted_infos = _convert_backend_licenses_to_spdx_expression(licenses)

        assert "MIT" in expression
        assert "LicenseRef-Proprietary-License-Company-X" in expression
        assert "Apache-2.0" in expression
        assert " OR " in expression
        # Should have 1 ExtractedLicensingInfo for the custom license
        assert len(extracted_infos) == 1
        assert extracted_infos[0].license_id == "LicenseRef-Proprietary-License-Company-X"
