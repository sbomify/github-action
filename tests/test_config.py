import os
import unittest
from unittest.mock import patch

from sbomify_action.cli.main import (
    SBOMIFY_PRODUCTION_API,
    Config,
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
            "Using HTTP (not HTTPS) for API communication - consider using HTTPS in production"
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
            "UPLOAD": "False",
            "AUGMENT": "True",
            "PRODUCT_RELEASE": '["Gu9wem8mkX:v1.0.0", "GFcFpn8q4h:v2.1.0"]',
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

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '["Gu9wem8mkX:v1.0.0", "GFcFpn8q4h:v2.1.0"]',
        },
    )
    def test_load_config_with_product_releases(self):
        """Test loading configuration with valid product releases."""
        config = load_config()

        # After validation, should be converted to a list
        self.assertEqual(config.product_releases, ["Gu9wem8mkX:v1.0.0", "GFcFpn8q4h:v2.1.0"])

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '["Gu9wem8mkX:v1.0.0"]',
        },
    )
    def test_load_config_with_single_product_release(self):
        """Test loading configuration with single product release."""
        config = load_config()

        # After validation, should be converted to a list
        self.assertEqual(config.product_releases, ["Gu9wem8mkX:v1.0.0"])

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": "not-json",
        },
    )
    @patch("sys.exit")
    def test_load_config_invalid_product_release_json(self, mock_exit):
        """Test that invalid JSON for PRODUCT_RELEASE causes exit."""
        load_config()
        mock_exit.assert_called_once_with(1)

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '"not-a-list"',
        },
    )
    @patch("sys.exit")
    def test_load_config_product_release_not_list(self, mock_exit):
        """Test that non-list PRODUCT_RELEASE causes exit."""
        load_config()
        mock_exit.assert_called_once_with(1)

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '["invalid-format"]',
        },
    )
    @patch("sys.exit")
    def test_load_config_invalid_product_release_format(self, mock_exit):
        """Test that invalid format in PRODUCT_RELEASE causes exit."""
        load_config()
        mock_exit.assert_called_once_with(1)

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '["ab:v1.0.0"]',
        },
    )
    def test_load_config_short_product_id_allowed(self):
        """Test that short product IDs are now allowed."""
        config = load_config()
        # Should pass validation and be converted to list
        self.assertEqual(config.product_releases, ["ab:v1.0.0"])

    def test_component_name_no_warning(self):
        """Test that using COMPONENT_NAME alone produces no deprecation warnings."""
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        # Create a dummy lock file for validation
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "test.lock"
            lock_file.write_text("dummy content")

            # Mock environment variables with only COMPONENT_NAME
            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "COMPONENT_NAME": "my-custom-component",
                "LOCK_FILE": str(lock_file),
            }
            with patch.dict(os.environ, env_vars, clear=False):
                # Clear any existing env var
                for key in ["OVERRIDE_NAME"]:
                    if key in os.environ:
                        del os.environ[key]

                # Load config
                config = load_config()

                # Should use COMPONENT_NAME value
                self.assertEqual(config.component_name, "my-custom-component")
                self.assertFalse(config.override_name)

    def test_override_name_deprecated_warning(self):
        """Test that OVERRIDE_NAME shows deprecation warning."""
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with self.assertLogs("sbomify_action", level="WARNING") as log:
            # Create a dummy lock file for validation
            with tempfile.TemporaryDirectory() as tmp_dir:
                lock_file = Path(tmp_dir) / "test.lock"
                lock_file.write_text("dummy content")

                # Mock environment variables with only deprecated OVERRIDE_NAME
                env_vars = {
                    "TOKEN": "test-token",
                    "COMPONENT_ID": "test-component",
                    "OVERRIDE_NAME": "true",
                    "LOCK_FILE": str(lock_file),
                }
                with patch.dict(os.environ, env_vars, clear=False):
                    # Clear any existing env var
                    for key in ["COMPONENT_NAME"]:
                        if key in os.environ:
                            del os.environ[key]

                    # Load config
                    config = load_config()

                    # Should have deprecation warning
                    self.assertTrue(config.override_name)
                    self.assertIsNone(config.component_name)

                    # Should have logged deprecation warning
                    log_output = "\n".join(log.output)
                    self.assertIn("OVERRIDE_NAME is deprecated", log_output)
                    self.assertIn("Please use COMPONENT_NAME instead", log_output)

    def test_component_name_takes_precedence_over_deprecated(self):
        """Test that COMPONENT_NAME takes precedence over deprecated OVERRIDE_NAME."""
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with self.assertLogs("sbomify_action", level="WARNING") as log:
            # Create a dummy lock file for validation
            with tempfile.TemporaryDirectory() as tmp_dir:
                lock_file = Path(tmp_dir) / "test.lock"
                lock_file.write_text("dummy content")

                # Mock environment variables with both set
                env_vars = {
                    "TOKEN": "test-token",
                    "COMPONENT_ID": "test-component",
                    "COMPONENT_NAME": "my-custom-component",
                    "OVERRIDE_NAME": "true",
                    "LOCK_FILE": str(lock_file),
                }
                with patch.dict(os.environ, env_vars, clear=False):
                    # Load config which should prefer COMPONENT_NAME
                    config = load_config()

                    # Should use COMPONENT_NAME value and ignore OVERRIDE_NAME
                    self.assertEqual(config.component_name, "my-custom-component")
                    self.assertFalse(config.override_name)

                    # Should have logged warnings
                    log_output = "\n".join(log.output)
                    self.assertIn("Both COMPONENT_NAME and OVERRIDE_NAME are set", log_output)
                    self.assertIn("Using COMPONENT_NAME and ignoring OVERRIDE_NAME", log_output)
                    self.assertIn("OVERRIDE_NAME is deprecated", log_output)


if __name__ == "__main__":
    unittest.main()
