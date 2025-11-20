"""
Tests for product release functionality.
"""

import unittest
from unittest.mock import Mock, patch

from sbomify_action.cli.main import (
    Config,
    _check_release_exists,
    _create_release,
    _get_release_details,
    _get_release_friendly_name,
    _get_release_id,
    _process_product_releases,
    _tag_sbom_with_release,
)
from sbomify_action.exceptions import APIError


class TestProductReleases(unittest.TestCase):
    """Test product release management functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = Config(
            token="test-token",
            component_id="test-component",
            api_base_url="https://api.test.com/v1",
            product_releases=["Gu9wem8mkX:v1.0.0", "GFcFpn8q4h:v2.1.0"],  # Already validated format
        )

    @patch("sbomify_action.cli.main.requests.get")
    def test_check_release_exists_true(self, mock_get):
        """Test checking for existing release returns True."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "items": [{"id": "rel1", "version": "v1.0.0"}, {"id": "rel2", "version": "v2.0.0"}]
        }
        mock_get.return_value = mock_response

        result = _check_release_exists(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertTrue(result)
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        self.assertIn("product_id", call_args[1]["params"])
        self.assertEqual(call_args[1]["params"]["product_id"], "Gu9wem8mkX")
        self.assertEqual(call_args[1]["params"]["version"], "v1.0.0")

    @patch("sbomify_action.cli.main.requests.get")
    def test_check_release_exists_false(self, mock_get):
        """Test checking for non-existing release returns False."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": [{"id": "rel1", "version": "v2.0.0"}]}
        mock_get.return_value = mock_response

        result = _check_release_exists(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertFalse(result)

    @patch("sbomify_action.cli.main.requests.get")
    def test_check_release_exists_404(self, mock_get):
        """Test that 404 response returns False."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.ok = False
        mock_get.return_value = mock_response

        result = _check_release_exists(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertFalse(result)

    @patch("sbomify_action.cli.main.requests.get")
    def test_check_release_exists_api_error(self, mock_get):
        """Test that API errors are properly raised."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.ok = False
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Server error"}
        mock_get.return_value = mock_response

        with self.assertRaises(APIError) as cm:
            _check_release_exists(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertIn("500", str(cm.exception))
        self.assertIn("Server error", str(cm.exception))

    @patch("sbomify_action.cli.main.requests.post")
    def test_create_release_success(self, mock_post):
        """Test successful release creation."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"id": "new-release-id"}
        mock_post.return_value = mock_response

        result = _create_release(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertEqual(result, "new-release-id")
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]["json"]["product_id"], "Gu9wem8mkX")
        self.assertEqual(call_args[1]["json"]["version"], "v1.0.0")

    @patch("sbomify_action.cli.main.requests.post")
    def test_create_release_api_error(self, mock_post):
        """Test create release API error handling."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 400
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Bad request"}
        mock_post.return_value = mock_response

        with self.assertRaises(APIError) as cm:
            _create_release(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertIn("400", str(cm.exception))
        self.assertIn("Bad request", str(cm.exception))

    @patch("sbomify_action.cli.main.requests.get")
    def test_get_release_id_success(self, mock_get):
        """Test successful release ID retrieval."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "items": [{"id": "rel1", "version": "v1.0.0"}, {"id": "rel2", "version": "v2.0.0"}]
        }
        mock_get.return_value = mock_response

        result = _get_release_id(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertEqual(result, "rel1")

    @patch("sbomify_action.cli.main.requests.get")
    def test_get_release_id_not_found(self, mock_get):
        """Test release ID retrieval when release not found."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        result = _get_release_id(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertIsNone(result)

    @patch("sbomify_action.cli.main.requests.post")
    def test_tag_sbom_with_release_success(self, mock_post):
        """Test successful SBOM tagging."""
        mock_response = Mock()
        mock_response.ok = True
        mock_post.return_value = mock_response

        _tag_sbom_with_release(self.config, "sbom123", "rel456")

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[1]["json"]["sbom_id"], "sbom123")

    @patch("sbomify_action.cli.main.requests.post")
    def test_tag_sbom_with_release_api_error(self, mock_post):
        """Test SBOM tagging API error handling."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 403
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Forbidden"}
        mock_post.return_value = mock_response

        with self.assertRaises(APIError) as cm:
            _tag_sbom_with_release(self.config, "sbom123", "rel456")

        self.assertIn("403", str(cm.exception))
        self.assertIn("Forbidden", str(cm.exception))

    @patch("sbomify_action.cli.main._tag_sbom_with_release")
    @patch("sbomify_action.cli.main._get_release_id")
    @patch("sbomify_action.cli.main._get_release_friendly_name")
    @patch("sbomify_action.cli.main._get_release_details")
    @patch("sbomify_action.cli.main._create_release")
    @patch("sbomify_action.cli.main._check_release_exists")
    def test_process_product_releases_existing_release(
        self, mock_check, mock_create, mock_get_details, mock_get_friendly, mock_get_id, mock_tag
    ):
        """Test processing when release already exists."""
        self.config.product_releases = ["Gu9wem8mkX:v1.0.0"]
        mock_check.return_value = True
        mock_get_details.return_value = {"id": "existing-release-id", "name": "Test Release", "version": "v1.0.0"}
        mock_get_friendly.return_value = "Test Release (v1.0.0)"

        _process_product_releases(self.config, "sbom123")

        mock_check.assert_called_once()
        mock_create.assert_not_called()
        mock_get_id.assert_not_called()
        mock_tag.assert_called_once_with(self.config, "sbom123", "existing-release-id")

    @patch("sbomify_action.cli.main._tag_sbom_with_release")
    @patch("sbomify_action.cli.main._get_release_id")
    @patch("sbomify_action.cli.main._get_release_friendly_name")
    @patch("sbomify_action.cli.main._get_release_details")
    @patch("sbomify_action.cli.main._create_release")
    @patch("sbomify_action.cli.main._check_release_exists")
    def test_process_product_releases_new_release(
        self, mock_check, mock_create, mock_get_details, mock_get_friendly, mock_get_id, mock_tag
    ):
        """Test processing when creating new release."""
        mock_check.return_value = False
        mock_create.side_effect = ["rel-a", "rel-b"]
        mock_get_details.side_effect = [
            {"id": "rel-a", "name": "New Release A", "version": "v1.0.0"},
            {"id": "rel-b", "name": "New Release B", "version": "v2.1.0"},
        ]
        mock_get_friendly.side_effect = ["New Release A (v1.0.0)", "New Release B (v2.1.0)"]

        _process_product_releases(self.config, "sbom123")

        # Should check if releases exist
        self.assertEqual(mock_check.call_count, 2)
        # Should create the releases that don't exist
        self.assertEqual(mock_create.call_count, 2)
        # Should not need to look up IDs again once create returns them
        mock_get_id.assert_not_called()
        # Should tag SBOM with both releases using the IDs from creation
        self.assertEqual(mock_tag.call_count, 2)

    @patch("sbomify_action.cli.main._tag_sbom_with_release")
    @patch("sbomify_action.cli.main._get_release_id")
    @patch("sbomify_action.cli.main._get_release_friendly_name")
    @patch("sbomify_action.cli.main._get_release_details")
    @patch("sbomify_action.cli.main._create_release")
    @patch("sbomify_action.cli.main._check_release_exists")
    def test_process_product_releases_fallback_to_lookup_when_id_unknown(
        self, mock_check, mock_create, mock_get_details, mock_get_friendly, mock_get_id, mock_tag
    ):
        """Test fallback to release ID lookup when creation response lacks ID."""
        self.config.product_releases = ["Gu9wem8mkX:v1.0.0"]
        mock_check.return_value = False
        mock_create.return_value = None
        mock_get_details.return_value = None
        mock_get_id.return_value = "resolved-release-id"
        mock_get_friendly.return_value = "Release v1.0.0"

        _process_product_releases(self.config, "sbom123")

        mock_create.assert_called_once()
        mock_get_id.assert_called_once()
        mock_tag.assert_called_once_with(self.config, "sbom123", "resolved-release-id")

    @patch("sbomify_action.cli.main._tag_sbom_with_release")
    @patch("sbomify_action.cli.main._get_release_id")
    @patch("sbomify_action.cli.main._get_release_friendly_name")
    @patch("sbomify_action.cli.main._get_release_details")
    @patch("sbomify_action.cli.main._create_release")
    @patch("sbomify_action.cli.main._check_release_exists")
    def test_process_product_releases_existing_release_without_details(
        self, mock_check, mock_create, mock_get_details, mock_get_friendly, mock_get_id, mock_tag
    ):
        """Test fallback when release exists but details API fails."""
        self.config.product_releases = ["Gu9wem8mkX:v1.0.0"]
        mock_check.return_value = True
        mock_get_details.side_effect = APIError("details failed")
        mock_get_id.return_value = "existing-release-id"
        mock_get_friendly.return_value = "Release v1.0.0"

        _process_product_releases(self.config, "sbom123")

        mock_create.assert_not_called()
        mock_get_id.assert_called_once()
        mock_tag.assert_called_once_with(self.config, "sbom123", "existing-release-id")

    @patch("sbomify_action.cli.main.requests.get")
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

        result = _get_release_details(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertIsNotNone(result)
        self.assertEqual(result["id"], "rel1")
        self.assertEqual(result["name"], "First Major Release")
        self.assertEqual(result["description"], "Our first major release with all core features")

    @patch("sbomify_action.cli.main.requests.get")
    def test_get_release_details_not_found(self, mock_get):
        """Test release details retrieval when release not found."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        result = _get_release_details(self.config, "Gu9wem8mkX", "v1.0.0")

        self.assertIsNone(result)

    def test_get_release_friendly_name_with_custom_name(self):
        """Test friendly name generation with custom release name."""
        release_details = {
            "id": "rel1",
            "version": "v1.0.0",
            "name": "Major Feature Release",
            "description": "Custom release description",
        }

        result = _get_release_friendly_name(release_details, "Gu9wem8mkX", "v1.0.0")

        self.assertEqual(result, "'Major Feature Release' (v1.0.0)")

    def test_get_release_friendly_name_with_default_name(self):
        """Test friendly name generation with default release name."""
        release_details = {
            "id": "rel1",
            "version": "v1.0.0",
            "name": "Release v1.0.0",  # Default format
            "description": "Auto-generated release",
        }

        result = _get_release_friendly_name(release_details, "Gu9wem8mkX", "v1.0.0")

        self.assertEqual(result, "Release v1.0.0")

    def test_get_release_friendly_name_no_details(self):
        """Test friendly name generation when no release details available."""
        result = _get_release_friendly_name(None, "Gu9wem8mkX", "v1.0.0")

        self.assertEqual(result, "Release v1.0.0")

    @patch("sbomify_action.cli.main.requests.post")
    def test_create_release_url_construction_no_double_api_prefix(self, mock_post):
        """Test that create_release doesn't create URLs with double /api/v1 prefix."""
        # Use production API URL which contains /api/v1
        from sbomify_action.cli.main import SBOMIFY_PRODUCTION_API

        prod_config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="test.json",
            api_base_url=SBOMIFY_PRODUCTION_API,
        )

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"id": "new-release-id"}
        mock_post.return_value = mock_response

        _create_release(prod_config, "Gu9wem8mkX", "v1.0.0")

        # Verify the URL was constructed correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        actual_url = call_args[0][0]

        # Should be exactly this URL (no double /api/v1)
        expected_url = "https://app.sbomify.com/api/v1/releases"
        self.assertEqual(actual_url, expected_url, f"URL construction error: got {actual_url}, expected {expected_url}")

        # Should not contain double /api/v1
        self.assertNotIn("/api/v1/api/v1", actual_url, f"URL contains double /api/v1 prefix: {actual_url}")

    @patch("sbomify_action.cli.main.requests.get")
    def test_check_release_exists_url_construction_no_double_api_prefix(self, mock_get):
        """Test that check_release_exists doesn't create URLs with double /api/v1 prefix."""
        # Use production API URL which contains /api/v1
        from sbomify_action.cli.main import SBOMIFY_PRODUCTION_API

        prod_config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="test.json",
            api_base_url=SBOMIFY_PRODUCTION_API,
        )

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"items": []}
        mock_get.return_value = mock_response

        _check_release_exists(prod_config, "Gu9wem8mkX", "v1.0.0")

        # Verify the URL was constructed correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        actual_url = call_args[0][0]

        # Should be exactly this URL (no double /api/v1)
        expected_url = "https://app.sbomify.com/api/v1/releases"
        self.assertEqual(actual_url, expected_url, f"URL construction error: got {actual_url}, expected {expected_url}")

        # Should not contain double /api/v1
        self.assertNotIn("/api/v1/api/v1", actual_url, f"URL contains double /api/v1 prefix: {actual_url}")

    @patch("sbomify_action.cli.main.requests.post")
    def test_tag_sbom_with_release_url_construction_no_double_api_prefix(self, mock_post):
        """Test that tag_sbom_with_release doesn't create URLs with double /api/v1 prefix."""
        # Use production API URL which contains /api/v1
        from sbomify_action.cli.main import SBOMIFY_PRODUCTION_API

        prod_config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="test.json",
            api_base_url=SBOMIFY_PRODUCTION_API,
        )

        mock_response = Mock()
        mock_response.ok = True
        mock_post.return_value = mock_response

        _tag_sbom_with_release(prod_config, "sbom123", "rel456")

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
