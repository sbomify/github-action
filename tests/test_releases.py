"""
Tests for product release functionality.

These tests verify the shared releases API module which is used by
the SbomifyReleasesProcessor.
"""

import unittest
from unittest.mock import Mock, patch

from sbomify_action._processors.releases_api import (
    check_release_exists,
    create_release,
    get_release_details,
    get_release_friendly_name,
    get_release_id,
    tag_sbom_with_release,
)
from sbomify_action.exceptions import APIError


class TestReleasesApi(unittest.TestCase):
    """Test releases API functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.api_base_url = "https://api.test.com/v1"
        self.token = "test-token"

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_check_release_exists_true(self, mock_get):
        """Test checking for existing release returns True."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "items": [{"id": "rel1", "version": "v1.0.0"}, {"id": "rel2", "version": "v2.0.0"}]
        }
        mock_get.return_value = mock_response

        result = check_release_exists(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertTrue(result)
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        self.assertIn("product_id", call_args[1]["params"])
        self.assertEqual(call_args[1]["params"]["product_id"], "Gu9wem8mkX")
        self.assertEqual(call_args[1]["params"]["version"], "v1.0.0")

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_check_release_exists_false(self, mock_get):
        """Test checking for non-existing release returns False."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": [{"id": "rel1", "version": "v2.0.0"}]}
        mock_get.return_value = mock_response

        result = check_release_exists(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertFalse(result)

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_check_release_exists_404(self, mock_get):
        """Test that 404 response returns False."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.ok = False
        mock_get.return_value = mock_response

        result = check_release_exists(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertFalse(result)

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_check_release_exists_api_error(self, mock_get):
        """Test that API errors are properly raised."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.ok = False
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Server error"}
        mock_get.return_value = mock_response

        with self.assertRaises(APIError) as cm:
            check_release_exists(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertIn("500", str(cm.exception))
        self.assertIn("Server error", str(cm.exception))

    @patch("sbomify_action._processors.releases_api.requests.post")
    def test_create_release_success(self, mock_post):
        """Test successful release creation."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"id": "new-release-id"}
        mock_post.return_value = mock_response

        result = create_release(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertEqual(result, "new-release-id")
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]["json"]["product_id"], "Gu9wem8mkX")
        self.assertEqual(call_args[1]["json"]["version"], "v1.0.0")

    @patch("sbomify_action._processors.releases_api.requests.post")
    def test_create_release_api_error(self, mock_post):
        """Test create release API error handling."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Bad request"}
        mock_post.return_value = mock_response

        with self.assertRaises(APIError) as cm:
            create_release(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertIn("400", str(cm.exception))
        self.assertIn("Bad request", str(cm.exception))

    @patch("sbomify_action._processors.releases_api.get_release_id")
    @patch("sbomify_action._processors.releases_api.requests.post")
    def test_create_release_duplicate_name_returns_existing_id(self, mock_post, mock_get_release_id):
        """Test create release handles DUPLICATE_NAME by returning existing release ID."""
        # First call returns DUPLICATE_NAME error
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "detail": "A release with this name already exists for this product",
            "error_code": "DUPLICATE_NAME",
        }
        mock_post.return_value = mock_response

        # get_release_id returns the existing release ID
        mock_get_release_id.return_value = "existing-release-id"

        result = create_release(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertEqual(result, "existing-release-id")
        mock_get_release_id.assert_called_once_with(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

    @patch("sbomify_action._processors.releases_api.get_release_id")
    @patch("sbomify_action._processors.releases_api.requests.post")
    def test_create_release_duplicate_name_fallback_to_error(self, mock_post, mock_get_release_id):
        """Test create release raises error if DUPLICATE_NAME but can't find existing release."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "detail": "A release with this name already exists for this product",
            "error_code": "DUPLICATE_NAME",
        }
        mock_post.return_value = mock_response

        # get_release_id returns None (can't find the release)
        mock_get_release_id.return_value = None

        with self.assertRaises(APIError) as cm:
            create_release(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertIn("400", str(cm.exception))
        # Error message includes the detail field, not the error_code
        self.assertIn("already exists", str(cm.exception))

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_get_release_id_success(self, mock_get):
        """Test successful release ID retrieval."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "items": [{"id": "rel1", "version": "v1.0.0"}, {"id": "rel2", "version": "v2.0.0"}]
        }
        mock_get.return_value = mock_response

        result = get_release_id(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertEqual(result, "rel1")

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_get_release_id_not_found(self, mock_get):
        """Test release ID retrieval when release not found."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        result = get_release_id(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertIsNone(result)

    @patch("sbomify_action._processors.releases_api.requests.post")
    def test_tag_sbom_with_release_success(self, mock_post):
        """Test successful SBOM tagging."""
        mock_response = Mock()
        mock_response.ok = True
        mock_post.return_value = mock_response

        tag_sbom_with_release(self.api_base_url, self.token, "sbom123", "rel456")

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]["json"]["sbom_id"], "sbom123")

    @patch("sbomify_action._processors.releases_api.requests.post")
    def test_tag_sbom_with_release_api_error(self, mock_post):
        """Test SBOM tagging API error handling."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 403
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Forbidden"}
        mock_post.return_value = mock_response

        with self.assertRaises(APIError) as cm:
            tag_sbom_with_release(self.api_base_url, self.token, "sbom123", "rel456")

        self.assertIn("403", str(cm.exception))
        self.assertIn("Forbidden", str(cm.exception))

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_get_release_details_success(self, mock_get):
        """Test successful release details retrieval."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "items": [
                {
                    "id": "rel1",
                    "version": "v1.0.0",
                    "name": "First Major Release",
                    "description": "Our first major release with all core features",
                },
                {"id": "rel2", "version": "v2.0.0"},
            ]
        }
        mock_get.return_value = mock_response

        result = get_release_details(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertIsNotNone(result)
        self.assertEqual(result["id"], "rel1")
        self.assertEqual(result["name"], "First Major Release")
        self.assertEqual(result["description"], "Our first major release with all core features")

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_get_release_details_not_found(self, mock_get):
        """Test release details retrieval when release not found."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        result = get_release_details(self.api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        self.assertIsNone(result)

    def test_get_release_friendly_name_with_custom_name(self):
        """Test friendly name generation with custom release name."""
        release_details = {
            "id": "rel1",
            "version": "v1.0.0",
            "name": "Major Feature Release",
            "description": "Custom release description",
        }

        result = get_release_friendly_name(release_details, "v1.0.0")

        self.assertEqual(result, "'Major Feature Release' (v1.0.0)")

    def test_get_release_friendly_name_with_default_name(self):
        """Test friendly name generation with default release name."""
        release_details = {
            "id": "rel1",
            "version": "v1.0.0",
            "name": "Release v1.0.0",  # Default format
            "description": "Auto-generated release",
        }

        result = get_release_friendly_name(release_details, "v1.0.0")

        self.assertEqual(result, "Release v1.0.0")

    def test_get_release_friendly_name_no_details(self):
        """Test friendly name generation when no release details available."""
        result = get_release_friendly_name(None, "v1.0.0")

        self.assertEqual(result, "Release v1.0.0")

    def test_get_release_friendly_name_with_empty_string_name(self):
        """Test friendly name generation when name is empty string."""
        release_details = {
            "id": "rel1",
            "version": "v1.0.0",
            "name": "",  # Empty string
        }

        result = get_release_friendly_name(release_details, "v1.0.0")

        self.assertEqual(result, "Release v1.0.0")

    def test_get_release_friendly_name_with_none_name(self):
        """Test friendly name generation when name is None."""
        release_details = {
            "id": "rel1",
            "version": "v1.0.0",
            "name": None,  # Explicitly None
        }

        result = get_release_friendly_name(release_details, "v1.0.0")

        self.assertEqual(result, "Release v1.0.0")

    def test_get_release_friendly_name_with_whitespace_only_name(self):
        """Test friendly name generation when name is whitespace only."""
        release_details = {
            "id": "rel1",
            "version": "v1.0.0",
            "name": "   ",  # Whitespace only
        }

        result = get_release_friendly_name(release_details, "v1.0.0")

        self.assertEqual(result, "Release v1.0.0")

    def test_get_release_friendly_name_trims_whitespace(self):
        """Test friendly name generation trims leading/trailing whitespace."""
        release_details = {
            "id": "rel1",
            "version": "v1.0.0",
            "name": "  Custom Release Name  ",  # Has leading/trailing whitespace
        }

        result = get_release_friendly_name(release_details, "v1.0.0")

        self.assertEqual(result, "'Custom Release Name' (v1.0.0)")

    @patch("sbomify_action._processors.releases_api.requests.post")
    def test_create_release_url_construction_no_double_api_prefix(self, mock_post):
        """Test that create_release doesn't create URLs with double /api/v1 prefix."""
        # Use production API URL which contains /api/v1
        prod_api_base_url = "https://app.sbomify.com"

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"id": "new-release-id"}
        mock_post.return_value = mock_response

        create_release(prod_api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        # Verify the URL was constructed correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        actual_url = call_args[0][0]

        # Should be exactly this URL (no double /api/v1)
        expected_url = "https://app.sbomify.com/api/v1/releases"
        self.assertEqual(actual_url, expected_url, f"URL construction error: got {actual_url}, expected {expected_url}")

        # Should not contain double /api/v1
        self.assertNotIn("/api/v1/api/v1", actual_url, f"URL contains double /api/v1 prefix: {actual_url}")

    @patch("sbomify_action._processors.releases_api.requests.get")
    def test_check_release_exists_url_construction_no_double_api_prefix(self, mock_get):
        """Test that check_release_exists doesn't create URLs with double /api/v1 prefix."""
        # Use production API URL which contains /api/v1
        prod_api_base_url = "https://app.sbomify.com"

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        check_release_exists(prod_api_base_url, self.token, "Gu9wem8mkX", "v1.0.0")

        # Verify the URL was constructed correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        actual_url = call_args[0][0]

        # Should be exactly this URL (no double /api/v1)
        expected_url = "https://app.sbomify.com/api/v1/releases"
        self.assertEqual(actual_url, expected_url, f"URL construction error: got {actual_url}, expected {expected_url}")

        # Should not contain double /api/v1
        self.assertNotIn("/api/v1/api/v1", actual_url, f"URL contains double /api/v1 prefix: {actual_url}")

    @patch("sbomify_action._processors.releases_api.requests.post")
    def test_tag_sbom_with_release_url_construction_no_double_api_prefix(self, mock_post):
        """Test that tag_sbom_with_release doesn't create URLs with double /api/v1 prefix."""
        # Use production API URL which contains /api/v1
        prod_api_base_url = "https://app.sbomify.com"

        mock_response = Mock()
        mock_response.ok = True
        mock_post.return_value = mock_response

        tag_sbom_with_release(prod_api_base_url, self.token, "sbom123", "rel456")

        # Verify the URL was constructed correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        actual_url = call_args[0][0]

        # Should be exactly this URL (no double /api/v1)
        expected_url = "https://app.sbomify.com/api/v1/releases/rel456/artifacts"
        self.assertEqual(actual_url, expected_url, f"URL construction error: got {actual_url}, expected {expected_url}")

        # Should not contain double /api/v1
        self.assertNotIn("/api/v1/api/v1", actual_url, f"URL contains double /api/v1 prefix: {actual_url}")


if __name__ == "__main__":
    unittest.main()
