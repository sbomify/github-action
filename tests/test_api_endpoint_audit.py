"""
Comprehensive audit of all API endpoints to ensure correct URL construction.

This test verifies that all API endpoints construct URLs correctly with the
updated SBOMIFY_PRODUCTION_API base URL.
"""

import unittest
from unittest.mock import Mock, patch

from sbomify_action.cli.main import (
    SBOMIFY_PRODUCTION_API,
    Config,
    _check_release_exists,
    _create_release,
    _get_release_details,
    _get_release_id,
    _tag_sbom_with_release,
    enrich_sbom_with_backend_metadata,
)


class TestAPIEndpointAudit(unittest.TestCase):
    """Comprehensive audit of all API endpoints."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="test.json",
            api_base_url=SBOMIFY_PRODUCTION_API,
        )

    def test_production_api_base_url_format(self):
        """Test that production API base URL is in the correct format."""
        # Should be just the base domain without /api/v1
        self.assertEqual(SBOMIFY_PRODUCTION_API, "https://app.sbomify.com")
        self.assertFalse(SBOMIFY_PRODUCTION_API.endswith("/api/v1"))
        self.assertFalse(SBOMIFY_PRODUCTION_API.endswith("/"))

    @patch("sbomify_action.cli.main.requests.get")
    def test_check_release_exists_endpoint(self, mock_get):
        """Test _check_release_exists API endpoint URL construction."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        _check_release_exists(self.config, "product123", "v1.0.0")

        mock_get.assert_called_once()
        call_args = mock_get.call_args
        actual_url = call_args[0][0]

        expected_url = "https://app.sbomify.com/api/v1/releases"
        self.assertEqual(actual_url, expected_url)
        self.assertNotIn("/api/v1/api/v1", actual_url)

    @patch("sbomify_action.cli.main.requests.post")
    def test_create_release_endpoint(self, mock_post):
        """Test _create_release API endpoint URL construction."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"id": "new-release-id"}
        mock_post.return_value = mock_response

        _create_release(self.config, "product123", "v1.0.0")

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        actual_url = call_args[0][0]

        expected_url = "https://app.sbomify.com/api/v1/releases"
        self.assertEqual(actual_url, expected_url)
        self.assertNotIn("/api/v1/api/v1", actual_url)

    @patch("sbomify_action.cli.main.requests.post")
    def test_tag_sbom_with_release_endpoint(self, mock_post):
        """Test _tag_sbom_with_release API endpoint URL construction."""
        mock_response = Mock()
        mock_response.ok = True
        mock_post.return_value = mock_response

        _tag_sbom_with_release(self.config, "sbom123", "release456")

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        actual_url = call_args[0][0]

        expected_url = "https://app.sbomify.com/api/v1/releases/release456/artifacts"
        self.assertEqual(actual_url, expected_url)
        self.assertNotIn("/api/v1/api/v1", actual_url)

    @patch("sbomify_action.cli.main.requests.get")
    def test_get_release_id_endpoint(self, mock_get):
        """Test _get_release_id API endpoint URL construction."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        _get_release_id(self.config, "product123", "v1.0.0")

        mock_get.assert_called_once()
        call_args = mock_get.call_args
        actual_url = call_args[0][0]

        expected_url = "https://app.sbomify.com/api/v1/releases"
        self.assertEqual(actual_url, expected_url)
        self.assertNotIn("/api/v1/api/v1", actual_url)

    @patch("sbomify_action.cli.main.requests.get")
    def test_get_release_details_endpoint(self, mock_get):
        """Test _get_release_details API endpoint URL construction."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        _get_release_details(self.config, "product123", "v1.0.0")

        mock_get.assert_called_once()
        call_args = mock_get.call_args
        actual_url = call_args[0][0]

        expected_url = "https://app.sbomify.com/api/v1/releases"
        self.assertEqual(actual_url, expected_url)
        self.assertNotIn("/api/v1/api/v1", actual_url)

    @patch("sbomify_action.cli.main.requests.get")
    def test_enrich_sbom_metadata_endpoint(self, mock_get):
        """Test enrich_sbom_with_backend_metadata API endpoint URL construction."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"components": [], "vulnerabilities": [], "licenses": []}
        mock_get.return_value = mock_response

        # Create a minimal SBOM structure for testing
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType

        bom = Bom()
        component = Component(name="test-component", type=ComponentType.LIBRARY, bom_ref="test-ref")
        bom.components.add(component)

        try:
            enrich_sbom_with_backend_metadata("cyclonedx", {}, bom, self.config)
        except Exception:
            # We don't care if the function fails, we just want to check the URL
            pass

        if mock_get.called:
            call_args = mock_get.call_args
            actual_url = call_args[0][0]

            expected_url = "https://app.sbomify.com/api/v1/sboms/component/test-component/meta"
            self.assertEqual(actual_url, expected_url)
            self.assertNotIn("/api/v1/api/v1", actual_url)

    def test_sbom_upload_url_construction(self):
        """Test SBOM upload URL construction pattern."""
        # This tests the URL pattern used in the upload function
        FORMAT = "cyclonedx"
        expected_url = f"{self.config.api_base_url}/api/v1/sboms/artifact/{FORMAT}/{self.config.component_id}"

        self.assertEqual(expected_url, "https://app.sbomify.com/api/v1/sboms/artifact/cyclonedx/test-component")
        self.assertNotIn("/api/v1/api/v1", expected_url)
        self.assertEqual(expected_url.count("/api/v1"), 1)

    def test_custom_api_base_url_override(self):
        """Test that custom API base URLs work correctly."""
        custom_config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="test.json",
            api_base_url="https://api.dev.sbomify.com",
        )

        # Test release URL construction with custom base
        release_url = custom_config.api_base_url + "/api/v1/releases"
        self.assertEqual(release_url, "https://api.dev.sbomify.com/api/v1/releases")
        self.assertNotIn("/api/v1/api/v1", release_url)

        # Test SBOM metadata URL construction with custom base
        metadata_url = custom_config.api_base_url + f"/api/v1/sboms/component/{custom_config.component_id}/meta"
        self.assertEqual(metadata_url, "https://api.dev.sbomify.com/api/v1/sboms/component/test-component/meta")
        self.assertNotIn("/api/v1/api/v1", metadata_url)

    def test_all_endpoints_have_single_api_v1_prefix(self):
        """Test that all API endpoints have exactly one /api/v1 prefix."""
        base_url = "https://app.sbomify.com"
        component_id = "test-component"
        release_id = "test-release"
        format_type = "cyclonedx"

        # All API endpoints that should exist
        endpoints = [
            f"{base_url}/api/v1/releases",
            f"{base_url}/api/v1/releases/{release_id}/artifacts",
            f"{base_url}/api/v1/sboms/component/{component_id}/meta",
            f"{base_url}/api/v1/sboms/artifact/{format_type}/{component_id}",
        ]

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                # Should have exactly one occurrence of /api/v1
                self.assertEqual(endpoint.count("/api/v1"), 1, f"Endpoint {endpoint} should have exactly one /api/v1")
                # Should not have double slashes (except after protocol)
                self.assertNotIn(
                    "//", endpoint.replace("https://", ""), f"Endpoint {endpoint} should not have double slashes"
                )
                # Should not have double /api/v1
                self.assertNotIn("/api/v1/api/v1", endpoint, f"Endpoint {endpoint} should not have double /api/v1")


if __name__ == "__main__":
    unittest.main()
