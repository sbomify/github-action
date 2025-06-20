import os
import unittest
from unittest.mock import patch

from sbomify_action.cli.main import (
    SBOMIFY_PRODUCTION_API,
    SBOMIFY_TOOL_NAME,
    Config,
    _add_sbomify_tool_to_json,
    _ensure_tools_structure,
    load_config,
)
from sbomify_action.exceptions import ConfigurationError


class TestConfig(unittest.TestCase):
    """Test cases for the Config dataclass and related functionality."""

    def test_config_validation_missing_token(self):
        """Test that Config raises ConfigurationError when token is missing."""
        config = Config(token="", component_id="test-component")

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("sbomify API token is not defined", str(cm.exception))

    def test_config_validation_missing_component_id(self):
        """Test that Config raises ConfigurationError when component_id is missing."""
        config = Config(token="test-token", component_id="")

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("Component ID is not defined", str(cm.exception))

    def test_config_validation_multiple_inputs(self):
        """Test that Config raises ConfigurationError when multiple input types are provided."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            lock_file="/path/to/requirements.txt",
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("Please provide only one of", str(cm.exception))

    def test_config_validation_no_inputs(self):
        """Test that Config raises ConfigurationError when no inputs are provided."""
        config = Config(token="test-token", component_id="test-component")

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("Please provide one of", str(cm.exception))

    def test_config_validation_valid_config(self):
        """Test that Config validation passes with valid configuration."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
        )

        # Should not raise any exception
        config.validate()

    def test_config_url_validation_invalid_scheme(self):
        """Test that Config raises ConfigurationError for invalid URL schemes."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            api_base_url="ftp://invalid.com",
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("API base URL must start with http:// or https://", str(cm.exception))

    def test_config_url_validation_missing_hostname(self):
        """Test that Config raises ConfigurationError for URLs without hostname."""
        config = Config(
            token="test-token", component_id="test-component", sbom_file="/path/to/sbom.json", api_base_url="https://"
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("API base URL must include a valid hostname", str(cm.exception))

    @patch("sbomify_action.cli.main.logger")
    def test_config_url_validation_http_warning(self, mock_logger):
        """Test that Config issues warning for HTTP on non-localhost."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            api_base_url="http://example.com/api",
        )

        config.validate()
        mock_logger.warning.assert_called_with(
            "⚠️  Using HTTP (not HTTPS) for API communication - consider using HTTPS in production"
        )

    @patch("sbomify_action.cli.main.logger")
    def test_config_url_validation_http_localhost_no_warning(self, mock_logger):
        """Test that Config does not warn for HTTP on localhost."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            api_base_url="http://127.0.0.1:8000/api",
        )

        config.validate()
        mock_logger.warning.assert_not_called()

    def test_config_url_trailing_slash_removal(self):
        """Test that trailing slashes are removed from URLs."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            api_base_url="https://api.example.com/",
        )

        config.validate()
        self.assertEqual(config.api_base_url, "https://api.example.com")

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "UPLOAD": "false",
            "AUGMENT": "true",
        },
    )
    def test_load_config_from_environment(self):
        """Test loading configuration from environment variables."""
        config = load_config()

        self.assertEqual(config.token, "test-token")
        self.assertEqual(config.component_id, "test-component")
        self.assertFalse(config.upload)
        self.assertTrue(config.augment)

    @patch.dict(os.environ, {"TOKEN": "", "COMPONENT_ID": "test"})
    @patch("sys.exit")
    def test_load_config_exits_on_invalid_config(self, mock_exit):
        """Test that load_config exits when configuration is invalid."""
        load_config()
        mock_exit.assert_called_once_with(1)

    def test_load_config_uses_production_api_default(self):
        """Test that load_config uses production API as default."""
        with patch.dict(
            os.environ,
            {"TOKEN": "test-token", "COMPONENT_ID": "test-component", "SBOM_FILE": "tests/test-data/valid_json.json"},
            clear=True,
        ):
            config = load_config()
            self.assertEqual(config.api_base_url, SBOMIFY_PRODUCTION_API)


class TestHelperFunctions(unittest.TestCase):
    """Test cases for helper functions."""

    def test_ensure_tools_structure_cyclonedx_15_pure(self):
        """Test tools structure initialization for pure CycloneDX 1.5 format."""
        metadata = {}
        _ensure_tools_structure(metadata, "1.5")

        self.assertIn("tools", metadata)
        self.assertIsInstance(metadata["tools"], list)

    def test_ensure_tools_structure_cyclonedx_16(self):
        """Test tools structure initialization for CycloneDX 1.6 format."""
        metadata = {}
        _ensure_tools_structure(metadata, "1.6")

        self.assertIn("tools", metadata)
        self.assertIsInstance(metadata["tools"], dict)
        self.assertIn("components", metadata["tools"])
        self.assertIsInstance(metadata["tools"]["components"], list)

    def test_ensure_tools_structure_hybrid_15(self):
        """Test tools structure with hybrid 1.5 format (using 1.6 structure)."""
        metadata = {"tools": {"components": []}}
        _ensure_tools_structure(metadata, "1.5")

        # Should preserve existing 1.6-style structure even for 1.5
        self.assertIsInstance(metadata["tools"], dict)
        self.assertIn("components", metadata["tools"])

    def test_ensure_tools_structure_converts_list_to_components(self):
        """Test conversion from list format to components format."""
        metadata = {"tools": [{"vendor": "test", "name": "test-tool"}]}
        _ensure_tools_structure(metadata, "1.6")

        self.assertIsInstance(metadata["tools"], dict)
        self.assertIn("components", metadata["tools"])
        self.assertEqual(len(metadata["tools"]["components"]), 1)

    @patch("sbomify_action.cli.main.logger")
    def test_add_sbomify_tool_to_json_cyclonedx_15(self, mock_logger):
        """Test adding sbomify tool for CycloneDX 1.5 format."""
        metadata = {}
        _add_sbomify_tool_to_json(metadata, "1.5")

        self.assertIn("tools", metadata)
        self.assertIsInstance(metadata["tools"], list)
        self.assertEqual(len(metadata["tools"]), 1)

        tool = metadata["tools"][0]
        self.assertEqual(tool["name"], SBOMIFY_TOOL_NAME)
        self.assertIn("vendor", tool)
        self.assertIn("version", tool)

    @patch("sbomify_action.cli.main.logger")
    def test_add_sbomify_tool_to_json_cyclonedx_16(self, mock_logger):
        """Test adding sbomify tool for CycloneDX 1.6 format."""
        metadata = {}
        _add_sbomify_tool_to_json(metadata, "1.6")

        self.assertIn("tools", metadata)
        self.assertIsInstance(metadata["tools"], dict)
        self.assertIn("components", metadata["tools"])
        self.assertEqual(len(metadata["tools"]["components"]), 1)

        tool = metadata["tools"]["components"][0]
        self.assertEqual(tool["name"], SBOMIFY_TOOL_NAME)
        self.assertEqual(tool["type"], "application")
        self.assertIn("manufacturer", tool)
        self.assertIn("externalReferences", tool)

        # Check external references
        refs = tool["externalReferences"]
        self.assertEqual(len(refs), 2)
        website_ref = next((ref for ref in refs if ref["type"] == "website"), None)
        vcs_ref = next((ref for ref in refs if ref["type"] == "vcs"), None)

        self.assertIsNotNone(website_ref)
        self.assertIsNotNone(vcs_ref)
        self.assertEqual(website_ref["url"], "https://sbomify.com")
        self.assertIn("github.com", vcs_ref["url"])

    @patch("sbomify_action.cli.main.logger")
    def test_add_sbomify_tool_avoids_duplicates(self, mock_logger):
        """Test that adding sbomify tool avoids duplicates."""
        metadata = {"tools": {"components": [{"name": SBOMIFY_TOOL_NAME, "type": "application"}]}}
        _add_sbomify_tool_to_json(metadata, "1.6")

        # Should still have only one tool
        self.assertEqual(len(metadata["tools"]["components"]), 1)


if __name__ == "__main__":
    unittest.main()
