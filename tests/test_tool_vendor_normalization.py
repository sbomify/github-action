"""Test tool vendor normalization to fix comparison errors during serialization."""

import json
from pathlib import Path

import pytest
from cyclonedx.model.bom import Bom, Tool
from cyclonedx.model.component import Component, ComponentType

from sbomify_action.augmentation import _add_sbomify_tool_to_cyclonedx, augment_sbom_from_file
from sbomify_action.serialization import serialize_cyclonedx_bom


class TestToolVendorNormalization:
    """Test that tool vendor types are properly normalized to prevent comparison errors."""

    def test_serialization_with_component_in_metadata_tools(self):
        """
        Test that serialization works when metadata.tools.components has items with string suppliers.

        During serialization, CycloneDX converts components to Tools and adds them
        to a SortedSet. If those components have string suppliers while our sbomify
        tool has OrganizationalEntity vendor, we get a TypeError during comparison.

        This reproduces the CI error:
        TypeError: '<' not supported between instances of 'OrganizationalEntity' and 'str'
        """
        # Create a BOM
        bom = Bom()

        # Add a component to metadata.tools.components with a string supplier
        # When cyclonedx serializes, it will convert this to a Tool with string vendor (from supplier)
        tool_component = Component(
            name="cyclonedx-bom",
            version="4.1.0",
            type=ComponentType.APPLICATION,
        )
        # Force set supplier as string using object.__setattr__ to bypass validation
        # This simulates what happens when parsing older SBOM formats
        object.__setattr__(tool_component, "supplier", "CycloneDX")

        bom.metadata.tools.components.add(tool_component)

        # Add sbomify tool (which uses OrganizationalEntity vendor)
        _add_sbomify_tool_to_cyclonedx(bom)

        # This should not raise a TypeError during serialization
        try:
            serialized = serialize_cyclonedx_bom(bom, "1.6")
            assert serialized is not None
            assert "sbomify" in serialized
        except TypeError as e:
            if "'<' not supported between instances" in str(e):
                pytest.fail(f"Tool vendor comparison error during serialization: {e}")
            raise

    def test_serialization_with_tool_with_string_vendor(self):
        """
        Test that serialization works when existing tools have string vendors.

        This reproduces the actual CI error where cyclonedx-py generates tools with
        string vendors (e.g., vendor="CycloneDX") and then we add our tool with
        OrganizationalEntity vendor, causing a comparison error during serialization.

        Based on Sentry error showing:
        - existing tool: vendor="CycloneDX" (string)
        - sbomify tool: vendor=OrganizationalEntity(name="sbomify")
        """
        # Create a BOM
        bom = Bom()

        # Create a tool with a string vendor like cyclonedx-py does
        # We'll manually set the vendor as a string to simulate what cyclonedx-py generates
        cyclonedx_tool = Tool(name="cyclonedx-bom", version="4.1.0")

        # Force set vendor as string using object.__setattr__ to bypass any validation
        # This simulates what happens when cyclonedx-py generates an SBOM
        object.__setattr__(cyclonedx_tool, "vendor", "CycloneDX")

        bom.metadata.tools.tools.add(cyclonedx_tool)

        # Add sbomify tool (which uses OrganizationalEntity vendor)
        _add_sbomify_tool_to_cyclonedx(bom)

        # This should not raise a TypeError during serialization
        try:
            serialized = serialize_cyclonedx_bom(bom, "1.6")
            assert serialized is not None
            assert "sbomify" in serialized
            # Should have normalized the cyclonedx-bom tool vendor
            assert "cyclonedx-bom" in serialized or "CycloneDX" in serialized
        except TypeError as e:
            if "'<' not supported between instances" in str(e):
                pytest.fail(f"Tool vendor comparison error during serialization: {e}")
            raise

    def test_serialization_with_multiple_components_in_tools(self):
        """
        Test serialization with multiple components in metadata.tools.

        This is closer to what happens in real scenarios where SBOMs might have
        multiple tool components from various generators.
        """
        bom = Bom()

        # Add multiple components to metadata.tools
        for i in range(3):
            tool_component = Component(
                name=f"tool-{i}",
                version=f"{i}.0.0",
                type=ComponentType.APPLICATION,
            )
            bom.metadata.tools.components.add(tool_component)

        # Add sbomify tool
        _add_sbomify_tool_to_cyclonedx(bom)

        # Serialize - should not raise TypeError
        try:
            serialized = serialize_cyclonedx_bom(bom, "1.6")
            assert serialized is not None
            assert "sbomify" in serialized
        except TypeError as e:
            if "'<' not supported between instances" in str(e):
                pytest.fail(f"Tool vendor comparison error during serialization: {e}")
            raise

    def test_augmentation_from_parsed_json_with_string_vendor(self, mocker, tmp_path):
        """
        Test augmentation when parsing SBOM JSON that contains tools with string vendors.

        This reproduces the exact CI scenario:
        1. cyclonedx-py generates SBOM JSON with tools having string vendors
        2. We parse the JSON file using Bom.from_json()
        3. We augment it (which should normalize vendors)
        4. We serialize it (which triggers the comparison error if not normalized)
        """
        # Create a test SBOM JSON with a tool that has a string vendor
        # This simulates what cyclonedx-py generates
        sbom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:12345678-1234-5678-1234-567812345678",
            "version": 1,
            "metadata": {
                "timestamp": "2025-11-27T00:00:00Z",
                "tools": [
                    {
                        "vendor": "CycloneDX",  # String vendor - this causes the problem!
                        "name": "cyclonedx-bom",
                        "version": "4.1.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0",
                },
            },
            "components": [],
        }

        # Write the JSON to a file
        sbom_file = tmp_path / "test_sbom.json"
        with open(sbom_file, "w") as f:
            json.dump(sbom_json, f)

        # Mock the backend API
        component_id = "test-component-id"
        api_base_url = "https://test.sbomify.com"
        token = "test-token"

        mock_response = mocker.Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "supplier": {"name": "sbomify", "url": "https://sbomify.com"},
            "authors": [{"name": "Test Author"}],
            "licenses": [{"key": "Apache-2.0", "name": "Apache License 2.0"}],
        }
        mocker.patch("requests.get", return_value=mock_response)

        # Augment the SBOM - this should not raise a TypeError
        output_file = tmp_path / "augmented_sbom.json"
        try:
            augment_sbom_from_file(
                input_file=str(sbom_file),
                output_file=str(output_file),
                api_base_url=api_base_url,
                token=token,
                component_id=component_id,
                override_sbom_metadata=False,
                component_name="test-component",
                component_version="1.0.0",
            )
        except TypeError as e:
            if "'<' not supported between instances" in str(e):
                pytest.fail(f"Tool vendor comparison error during augmentation: {e}")
            raise

        # Verify the augmented SBOM is valid JSON
        with open(output_file) as f:
            augmented_data = json.load(f)
            assert "metadata" in augmented_data
            assert "tools" in augmented_data["metadata"]

    def test_augmentation_from_generated_sbom(self, mocker, tmp_path):
        """
        Test augmentation of an SBOM generated by cyclonedx-py.

        This reproduces the actual CI workflow: generate SBOM, augment it, serialize it.
        """
        # Use the test uv.lock file
        test_lock_file = Path(__file__).parent / "test-data" / "uv.lock"

        # Mock the backend API
        component_id = "test-component-id"
        api_base_url = "https://test.sbomify.com"
        token = "test-token"

        mock_response = mocker.Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "supplier": {"name": "sbomify", "url": "https://sbomify.com"},
            "authors": [{"name": "Test Author"}],
            "licenses": [{"key": "Apache-2.0", "name": "Apache License 2.0"}],
        }
        mocker.patch("requests.get", return_value=mock_response)

        # Generate SBOM from lock file
        from sbomify_action.generation import generate_sbom_from_python_lock_file

        output_file = tmp_path / "test_sbom.json"
        try:
            generate_sbom_from_python_lock_file(
                lock_file=str(test_lock_file),
                lock_file_type="requirements",
                output_file=str(output_file),
                schema_version="1.6",
            )
        except Exception as e:
            pytest.skip(f"SBOM generation failed (cyclonedx-py might not be available): {e}")

        # Augment the generated SBOM
        try:
            augment_sbom_from_file(
                input_file=str(output_file),
                api_base_url=api_base_url,
                token=token,
                component_id=component_id,
                override_sbom_metadata=False,
                component_name="test-component",
                component_version="1.0.0",
            )
        except TypeError as e:
            if "'<' not supported between instances" in str(e):
                pytest.fail(f"Tool vendor comparison error during augmentation: {e}")
            raise

        # Verify the augmented SBOM is valid JSON
        with open(output_file) as f:
            augmented_data = json.load(f)
            assert "metadata" in augmented_data
            assert "tools" in augmented_data["metadata"]
