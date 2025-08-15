import unittest
from unittest.mock import MagicMock, patch

from sbomify_action.cli.main import (
    SBOMIFY_TOOL_NAME,
    SBOMIFY_VENDOR_NAME,
    SPDX_LOGICAL_OPERATORS,
    _apply_cyclonedx_augmentation_to_json,
    _apply_spdx_augmentation_to_json,
    _convert_backend_licenses_to_spdx_expression,
    _extract_custom_licenses_for_spdx,
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
        self.assertEqual(len(creators), 3)  # existing + sbomify + supplier
        self.assertIn("Tool: existing-tool", creators)
        self.assertIn("Organization: Test Organization", creators)
        self.assertIn("Tool: sbomify-github-action", creators)

    def test_apply_spdx_augmentation_adds_sbomify_tool(self):
        """Test that SPDX augmentation adds sbomify tool to creators."""
        sbom_json = {"spdxVersion": "SPDX-2.3"}
        augmentation_data = {}

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        creators = sbom_json["creationInfo"]["creators"]
        self.assertIn("Tool: sbomify-github-action", creators)

    def test_apply_spdx_augmentation_adds_authors_as_creators(self):
        """Test that SPDX augmentation adds authors as person creators."""
        sbom_json = {"spdxVersion": "SPDX-2.3"}
        augmentation_data = {
            "authors": [
                {"name": "John Doe", "email": "john@example.com"},
                {"name": "Jane Smith", "email": "jane@example.com"},
                {"name": "Bob Wilson"},  # No email
            ]
        }

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        creators = sbom_json["creationInfo"]["creators"]
        self.assertIn("Person: John Doe (john@example.com)", creators)
        self.assertIn("Person: Jane Smith (jane@example.com)", creators)
        self.assertIn("Person: Bob Wilson", creators)

    def test_apply_spdx_augmentation_adds_package_supplier(self):
        """Test that SPDX augmentation adds supplier to packages."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "test-package", "SPDXID": "SPDXRef-Package-test"},
                {"name": "other-package", "SPDXID": "SPDXRef-Package-other"},
            ],
        }
        augmentation_data = {"supplier": {"name": "Test Supplier"}}

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        for package in sbom_json["packages"]:
            self.assertEqual(package["supplier"], "Organization: Test Supplier")

    def test_apply_spdx_augmentation_adds_package_homepage(self):
        """Test that SPDX augmentation adds homepage to packages from supplier URLs."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "test-package", "SPDXID": "SPDXRef-Package-test"}],
        }
        augmentation_data = {
            "supplier": {"name": "Test Supplier", "url": ["https://example.com", "https://support.example.com"]}
        }

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        package = sbom_json["packages"][0]
        self.assertEqual(package["homePage"], "https://example.com")

    def test_apply_spdx_augmentation_adds_external_references(self):
        """Test that SPDX augmentation adds external references to packages."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "test-package", "SPDXID": "SPDXRef-Package-test"}],
        }
        augmentation_data = {
            "supplier": {"name": "Test Supplier", "url": ["https://example.com", "https://support.example.com"]}
        }

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        package = sbom_json["packages"][0]
        self.assertIn("externalRefs", package)
        external_refs = package["externalRefs"]
        self.assertEqual(len(external_refs), 2)

        # Check first reference
        ref1 = external_refs[0]
        self.assertEqual(ref1["referenceCategory"], "OTHER")
        self.assertEqual(ref1["referenceType"], "website")
        self.assertEqual(ref1["referenceLocator"], "https://example.com")
        self.assertEqual(ref1["comment"], "Supplier website")

    def test_apply_spdx_augmentation_adds_package_originator(self):
        """Test that SPDX augmentation adds first author as package originator."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "test-package", "SPDXID": "SPDXRef-Package-test"},
                {"name": "other-package", "SPDXID": "SPDXRef-Package-other"},
            ],
        }
        augmentation_data = {
            "authors": [
                {"name": "John Doe", "email": "john@example.com"},
                {"name": "Jane Smith", "email": "jane@example.com"},
            ]
        }

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        for package in sbom_json["packages"]:
            self.assertEqual(package["originator"], "Person: John Doe (john@example.com)")

    def test_apply_spdx_augmentation_adds_licenses_to_packages(self):
        """Test that SPDX augmentation adds licenses to packages."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "test-package",
                    "SPDXID": "SPDXRef-Package-test",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                }
            ],
        }
        augmentation_data = {"licenses": ["MIT", "Apache-2.0"]}

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        package = sbom_json["packages"][0]
        expected_expression = "MIT AND Apache-2.0"
        self.assertEqual(package["licenseConcluded"], expected_expression)
        self.assertEqual(package["licenseDeclared"], expected_expression)

    def test_apply_spdx_augmentation_handles_custom_licenses(self):
        """Test that SPDX augmentation handles custom licenses with extracted licensing info."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "test-package",
                    "SPDXID": "SPDXRef-Package-test",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                }
            ],
        }
        augmentation_data = {
            "licenses": [
                {
                    "name": "Custom License",
                    "url": "https://example.com/license",
                    "text": "This is a custom license text.",
                },
                "MIT",
            ]
        }

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        # Check extracted licensing info
        self.assertIn("hasExtractedLicensingInfo", sbom_json)
        extracted = sbom_json["hasExtractedLicensingInfo"]
        self.assertEqual(len(extracted), 1)

        custom_license = extracted[0]
        self.assertEqual(custom_license["licenseId"], "LicenseRef-Custom-License")
        self.assertEqual(custom_license["name"], "Custom License")
        self.assertEqual(custom_license["extractedText"], "This is a custom license text.")
        self.assertEqual(custom_license["seeAlsos"], ["https://example.com/license"])

        # Check package licenses
        package = sbom_json["packages"][0]
        expected_expression = "LicenseRef-Custom-License AND MIT"
        self.assertEqual(package["licenseConcluded"], expected_expression)
        self.assertEqual(package["licenseDeclared"], expected_expression)

    def test_apply_spdx_augmentation_preserves_existing_homepage(self):
        """Test that SPDX augmentation preserves existing package homepage."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "test-package", "SPDXID": "SPDXRef-Package-test", "homePage": "https://existing.com"}
            ],
        }
        augmentation_data = {"supplier": {"name": "Test Supplier", "url": ["https://example.com"]}}

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        package = sbom_json["packages"][0]
        self.assertEqual(package["homePage"], "https://existing.com")

    def test_apply_spdx_augmentation_preserves_existing_originator(self):
        """Test that SPDX augmentation preserves existing package originator."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "test-package", "SPDXID": "SPDXRef-Package-test", "originator": "Person: Existing Author"}
            ],
        }
        augmentation_data = {"authors": [{"name": "New Author", "email": "new@example.com"}]}

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        package = sbom_json["packages"][0]
        self.assertEqual(package["originator"], "Person: Existing Author")

    def test_apply_spdx_augmentation_avoids_duplicate_external_refs(self):
        """Test that SPDX augmentation avoids duplicate external references."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "test-package",
                    "SPDXID": "SPDXRef-Package-test",
                    "externalRefs": [
                        {
                            "referenceCategory": "OTHER",
                            "referenceType": "website",
                            "referenceLocator": "https://example.com",
                        }
                    ],
                }
            ],
        }
        augmentation_data = {
            "supplier": {"name": "Test Supplier", "url": ["https://example.com", "https://support.example.com"]}
        }

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        package = sbom_json["packages"][0]
        external_refs = package["externalRefs"]

        # Should have 2 refs total: 1 existing + 1 new (duplicate URL skipped)
        self.assertEqual(len(external_refs), 2)

        # Check that URLs are unique
        urls = [ref["referenceLocator"] for ref in external_refs]
        self.assertEqual(len(set(urls)), 2)
        self.assertIn("https://example.com", urls)
        self.assertIn("https://support.example.com", urls)

    def test_apply_spdx_augmentation_avoids_duplicate_extracted_licenses(self):
        """Test that SPDX augmentation avoids duplicate extracted licensing info."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "hasExtractedLicensingInfo": [
                {
                    "licenseId": "LicenseRef-Existing-License",
                    "name": "Existing License",
                    "extractedText": "Existing license text",
                }
            ],
            "packages": [{"name": "test-package", "SPDXID": "SPDXRef-Package-test", "licenseConcluded": "NOASSERTION"}],
        }
        augmentation_data = {
            "licenses": [
                {
                    "name": "Existing License",  # Same as existing
                    "text": "Duplicate license text",
                },
                {"name": "New License", "text": "New license text"},
            ]
        }

        _apply_spdx_augmentation_to_json(sbom_json, augmentation_data, self.config)

        extracted = sbom_json["hasExtractedLicensingInfo"]
        # Should have 2 licenses: 1 existing + 1 new (duplicate avoided)
        self.assertEqual(len(extracted), 2)

        license_ids = [lic["licenseId"] for lic in extracted]
        self.assertIn("LicenseRef-Existing-License", license_ids)
        self.assertIn("LicenseRef-New-License", license_ids)

    def test_convert_backend_licenses_to_spdx_expression_simple_licenses(self):
        """Test converting simple license strings to SPDX expression."""
        licenses = ["MIT", "Apache-2.0", "GPL-3.0"]
        result = _convert_backend_licenses_to_spdx_expression(licenses)
        self.assertEqual(result, "MIT AND Apache-2.0 AND GPL-3.0")

    def test_convert_backend_licenses_to_spdx_expression_single_license(self):
        """Test converting single license to SPDX expression."""
        licenses = ["MIT"]
        result = _convert_backend_licenses_to_spdx_expression(licenses)
        self.assertEqual(result, "MIT")

    def test_convert_backend_licenses_to_spdx_expression_custom_licenses(self):
        """Test converting custom license objects to SPDX expression."""
        licenses = [
            {"name": "Custom License", "url": "https://example.com", "text": "Custom text"},
            "MIT",
            {"name": "Another Custom License", "text": "Another text"},
        ]
        result = _convert_backend_licenses_to_spdx_expression(licenses)
        self.assertEqual(result, "LicenseRef-Custom-License AND MIT AND LicenseRef-Another-Custom-License")

    def test_convert_backend_licenses_to_spdx_expression_empty_list(self):
        """Test converting empty license list returns NOASSERTION."""
        licenses = []
        result = _convert_backend_licenses_to_spdx_expression(licenses)
        self.assertEqual(result, "NOASSERTION")

    def test_convert_backend_licenses_to_spdx_expression_handles_special_chars(self):
        """Test that special characters in license names are handled properly."""
        licenses = [{"name": "Custom License (v1.0)", "text": "Custom text"}]
        result = _convert_backend_licenses_to_spdx_expression(licenses)
        self.assertEqual(result, "LicenseRef-Custom-License-v1.0")

    def test_extract_custom_licenses_for_spdx_complete_license(self):
        """Test extracting custom licenses with all fields."""
        licenses = [
            {"name": "Custom License", "url": "https://example.com/license", "text": "This is the custom license text."}
        ]
        result = _extract_custom_licenses_for_spdx(licenses)

        self.assertEqual(len(result), 1)
        extracted = result[0]
        self.assertEqual(extracted["licenseId"], "LicenseRef-Custom-License")
        self.assertEqual(extracted["name"], "Custom License")
        self.assertEqual(extracted["extractedText"], "This is the custom license text.")
        self.assertEqual(extracted["seeAlsos"], ["https://example.com/license"])

    def test_extract_custom_licenses_for_spdx_minimal_license(self):
        """Test extracting custom licenses with minimal fields."""
        licenses = [{"name": "Minimal License"}]
        result = _extract_custom_licenses_for_spdx(licenses)

        self.assertEqual(len(result), 1)
        extracted = result[0]
        self.assertEqual(extracted["licenseId"], "LicenseRef-Minimal-License")
        self.assertEqual(extracted["name"], "Minimal License")
        self.assertEqual(extracted["extractedText"], "Custom license text not provided")
        self.assertNotIn("seeAlsos", extracted)

    def test_extract_custom_licenses_for_spdx_ignores_strings(self):
        """Test that string licenses are ignored in extraction."""
        licenses = ["MIT", {"name": "Custom License", "text": "Custom text"}, "Apache-2.0"]
        result = _extract_custom_licenses_for_spdx(licenses)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["licenseId"], "LicenseRef-Custom-License")

    def test_extract_custom_licenses_for_spdx_ignores_incomplete(self):
        """Test that licenses without names are ignored in extraction."""
        licenses = [
            {"url": "https://example.com", "text": "Text without name"},
            {"name": "Valid License", "text": "Valid text"},
            {"text": "Another incomplete license"},
        ]
        result = _extract_custom_licenses_for_spdx(licenses)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["licenseId"], "LicenseRef-Valid-License")

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
