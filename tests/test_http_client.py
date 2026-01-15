"""Tests for http_client module."""

import re
import unittest

from sbomify_action.http_client import USER_AGENT, get_default_headers


class TestUserAgent(unittest.TestCase):
    """Tests for USER_AGENT constant."""

    def test_user_agent_format(self):
        """Test USER_AGENT has expected format."""
        self.assertIn("sbomify-action/", USER_AGENT)
        self.assertIn("(hello@sbomify.com)", USER_AGENT)

    def test_user_agent_has_version(self):
        """Test USER_AGENT includes a version."""
        # Format: sbomify-action/X.Y (hello@sbomify.com)
        parts = USER_AGENT.split("/")
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0], "sbomify-action")
        # Version part should exist and be a valid version string
        version_part = parts[1].split(" ")[0]
        self.assertTrue(len(version_part) > 0)
        # Verify it's either a valid semver-like version or "unknown"
        # Valid versions match patterns like "1.0", "1.0.0", "1.0.0-beta", etc.
        version_pattern = r"^\d+\.\d+(\.\d+)?(-[\w.]+)?$"
        is_valid_version = re.match(version_pattern, version_part) is not None
        is_unknown = version_part == "unknown"
        self.assertTrue(
            is_valid_version or is_unknown,
            f"Version '{version_part}' is neither a valid version pattern nor 'unknown'",
        )


class TestGetDefaultHeaders(unittest.TestCase):
    """Tests for get_default_headers function."""

    def test_default_headers_minimal(self):
        """Test get_default_headers with no arguments."""
        headers = get_default_headers()
        self.assertIn("User-Agent", headers)
        self.assertEqual(headers["User-Agent"], USER_AGENT)
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Content-Type", headers)

    def test_default_headers_with_token(self):
        """Test get_default_headers with token."""
        headers = get_default_headers(token="test-token-123")
        self.assertIn("User-Agent", headers)
        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer test-token-123")

    def test_default_headers_with_content_type(self):
        """Test get_default_headers with content_type."""
        headers = get_default_headers(content_type="application/json")
        self.assertIn("User-Agent", headers)
        self.assertIn("Content-Type", headers)
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_default_headers_with_all_options(self):
        """Test get_default_headers with all options."""
        headers = get_default_headers(token="my-secret-token", content_type="application/xml")
        self.assertEqual(headers["User-Agent"], USER_AGENT)
        self.assertEqual(headers["Authorization"], "Bearer my-secret-token")
        self.assertEqual(headers["Content-Type"], "application/xml")

    def test_default_headers_empty_token_not_included(self):
        """Test get_default_headers with empty string token."""
        headers = get_default_headers(token="")
        self.assertNotIn("Authorization", headers)

    def test_default_headers_none_values_not_included(self):
        """Test get_default_headers with explicit None values."""
        headers = get_default_headers(token=None, content_type=None)
        self.assertIn("User-Agent", headers)
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Content-Type", headers)


if __name__ == "__main__":
    unittest.main()
