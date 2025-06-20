import os
import unittest
from unittest.mock import patch

from sbomify_action.cli.main import Config, load_config
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


if __name__ == "__main__":
    unittest.main()
