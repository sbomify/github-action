"""Test Sentry error filtering for user vs system errors."""

import unittest

import sentry_sdk

from sbomify_action.cli.main import initialize_sentry
from sbomify_action.exceptions import (
    ConfigurationError,
    SBOMGenerationError,
    SBOMValidationError,
)


class TestSentryFiltering(unittest.TestCase):
    def test_sentry_filters_validation_errors(self):
        """
        Test that SBOMValidationError is filtered from Sentry.
        This represents user input errors that shouldn't be tracked.
        """
        initialize_sentry()

        # Get the before_send function that was registered (Sentry 2.x API)
        client = sentry_sdk.get_client()

        if client and client.options.get("before_send"):
            before_send = client.options["before_send"]

            # Create a mock event and hint with SBOMValidationError
            event = {"exception": {"values": [{"type": "SBOMValidationError"}]}}
            hint = {
                "exc_info": (
                    SBOMValidationError,
                    SBOMValidationError("Test validation error"),
                    None,
                )
            }

            # Should return None (filtered out)
            result = before_send(event, hint)
            self.assertIsNone(result, "SBOMValidationError should be filtered from Sentry")

    def test_sentry_filters_configuration_errors(self):
        """
        Test that ConfigurationError is filtered from Sentry.
        This represents user configuration errors.
        """
        initialize_sentry()

        client = sentry_sdk.get_client()

        if client and client.options.get("before_send"):
            before_send = client.options["before_send"]

            event = {"exception": {"values": [{"type": "ConfigurationError"}]}}
            hint = {
                "exc_info": (
                    ConfigurationError,
                    ConfigurationError("Test config error"),
                    None,
                )
            }

            result = before_send(event, hint)
            self.assertIsNone(result, "ConfigurationError should be filtered from Sentry")

    def test_sentry_allows_generation_errors(self):
        """
        Test that SBOMGenerationError is NOT filtered from Sentry.
        This represents tool/system bugs that should be tracked.
        """
        initialize_sentry()

        client = sentry_sdk.get_client()

        if client and client.options.get("before_send"):
            before_send = client.options["before_send"]

            event = {"exception": {"values": [{"type": "SBOMGenerationError"}]}}
            hint = {
                "exc_info": (
                    SBOMGenerationError,
                    SBOMGenerationError("Test generation error"),
                    None,
                )
            }

            result = before_send(event, hint)
            self.assertIsNotNone(result, "SBOMGenerationError should be sent to Sentry")
            self.assertEqual(result, event)


if __name__ == "__main__":
    unittest.main()
