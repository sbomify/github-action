import unittest
from unittest.mock import MagicMock, patch

from sbomify_action.cli.main import (
    SBOMIFY_TOOL_NAME,
    SBOMIFY_VENDOR_NAME,
    SPDX_LOGICAL_OPERATORS,
    _apply_cyclonedx_augmentation_to_json,
    _apply_spdx_augmentation_to_json,
)


class TestJSONAugmentation(unittest.TestCase):
    """Test cases for JSON-only augmentation functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = MagicMock()
        self.config.override_sbom_metadata = False

    def test_apply_cyclonedx_augmentation_adds_sbomify_tool(self):
        """Test that CycloneDX augmentation adds sbomify tool."""
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}}
        augmentation_data = {}

        with patch("sbomify_action.cli.main._add_sbomify_tool_to_json") as mock_add_tool:
            _apply_cyclonedx_augmentation_to_json(sbom_json, augmentation_data, self.config)
            mock_add_tool.assert_called_once()

    def test_apply_cyclonedx_augmentation_fixes_manufacturer_field(self):
        """Test that manufacturer field is fixed from string to object."""
        sbom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"tools": {"components": [{"name": "test-tool", "manufacturer": "test-vendor"}]}},
        }
        augmentation_data = {}

        _apply_cyclonedx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        tool = sbom_json["metadata"]["tools"]["components"][0]
        self.assertIsInstance(tool["manufacturer"], dict)
        self.assertEqual(tool["manufacturer"]["name"], "test-vendor")

    def test_apply_cyclonedx_augmentation_adds_supplier(self):
        """Test that supplier information is added correctly."""
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}}
        augmentation_data = {
            "supplier": {
                "name": "Test Supplier",
                "url": "https://example.com",
                "contacts": [{"name": "John Doe", "email": "john@example.com"}],
            }
        }

        _apply_cyclonedx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        supplier = sbom_json["metadata"]["supplier"]
        self.assertEqual(supplier["name"], "Test Supplier")
        self.assertEqual(supplier["url"], ["https://example.com"])
        self.assertEqual(len(supplier["contacts"]), 1)
        self.assertEqual(supplier["contacts"][0]["name"], "John Doe")

    def test_apply_cyclonedx_augmentation_adds_authors_v16(self):
        """Test that authors are added correctly for CycloneDX 1.6."""
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}}
        augmentation_data = {"authors": [{"name": "Jane Smith", "email": "jane@example.com"}, {"name": "Bob Johnson"}]}

        _apply_cyclonedx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        authors = sbom_json["metadata"]["authors"]
        self.assertEqual(len(authors), 2)
        self.assertEqual(authors[0]["name"], "Jane Smith")
        self.assertEqual(authors[0]["email"], "jane@example.com")
        self.assertEqual(authors[1]["name"], "Bob Johnson")

    def test_apply_cyclonedx_augmentation_adds_authors_v15(self):
        """Test that authors are added correctly for CycloneDX 1.5."""
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {}}
        augmentation_data = {"authors": [{"name": "Jane Smith"}, {"name": "Bob Johnson"}]}

        _apply_cyclonedx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        # CycloneDX 1.5 uses single author string
        self.assertEqual(sbom_json["metadata"]["author"], "Jane Smith, Bob Johnson")

    def test_apply_cyclonedx_augmentation_adds_simple_licenses(self):
        """Test that simple license names are added correctly."""
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}}
        augmentation_data = {"licenses": ["MIT", "Apache-2.0"]}

        _apply_cyclonedx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        licenses = sbom_json["metadata"]["licenses"]
        self.assertEqual(len(licenses), 2)
        self.assertEqual(licenses[0]["license"]["name"], "MIT")
        self.assertEqual(licenses[1]["license"]["name"], "Apache-2.0")

    def test_apply_cyclonedx_augmentation_adds_spdx_expression_licenses(self):
        """Test that SPDX expression licenses are handled correctly."""
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}}
        augmentation_data = {"licenses": ["MIT OR Apache-2.0", "GPL-3.0 WITH Classpath-exception-2.0"]}

        _apply_cyclonedx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        licenses = sbom_json["metadata"]["licenses"]
        self.assertEqual(len(licenses), 2)
        self.assertEqual(licenses[0]["expression"], "MIT OR Apache-2.0")
        self.assertEqual(licenses[1]["expression"], "GPL-3.0 WITH Classpath-exception-2.0")

    def test_apply_cyclonedx_augmentation_adds_complex_licenses(self):
        """Test that complex license objects are handled correctly."""
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}}
        augmentation_data = {
            "licenses": [
                {"name": "Custom License", "url": "https://example.com/license", "text": "Custom license text"}
            ]
        }

        _apply_cyclonedx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        licenses = sbom_json["metadata"]["licenses"]
        self.assertEqual(len(licenses), 1)
        license_entry = licenses[0]["license"]
        self.assertEqual(license_entry["name"], "Custom License")
        self.assertEqual(license_entry["url"], "https://example.com/license")
        self.assertEqual(license_entry["text"]["content"], "Custom license text")

    def test_apply_spdx_augmentation_adds_supplier_as_creator(self):
        """Test that SPDX augmentation adds supplier as creator."""
        sbom_json = {"spdxVersion": "SPDX-2.3"}
        augmentation_data = {"supplier": {"name": "Test Organization"}}

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        self.assertIn("creationInfo", sbom_json)
        creators = sbom_json["creationInfo"]["creators"]
        self.assertIn("Organization: Test Organization", creators)

    def test_apply_spdx_augmentation_preserves_existing_creators(self):
        """Test that existing SPDX creators are preserved."""
        sbom_json = {"spdxVersion": "SPDX-2.3", "creationInfo": {"creators": ["Tool: existing-tool"]}}
        augmentation_data = {"supplier": {"name": "Test Organization"}}

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        creators = sbom_json["creationInfo"]["creators"]
        self.assertEqual(len(creators), 2)
        self.assertIn("Tool: existing-tool", creators)
        self.assertIn("Organization: Test Organization", creators)

    def test_spdx_logical_operators_constant(self):
        """Test that SPDX logical operators constant is properly defined."""
        self.assertIn(" OR ", SPDX_LOGICAL_OPERATORS)
        self.assertIn(" AND ", SPDX_LOGICAL_OPERATORS)
        self.assertIn(" WITH ", SPDX_LOGICAL_OPERATORS)

    def test_constants_are_used(self):
        """Test that constants are properly defined."""
        self.assertEqual(SBOMIFY_TOOL_NAME, "sbomify-github-action")
        self.assertEqual(SBOMIFY_VENDOR_NAME, "sbomify")


if __name__ == "__main__":
    unittest.main()
