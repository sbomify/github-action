"""
Tests for timestamp functionality in SBOM generation and augmentation.
"""

import unittest
from unittest.mock import MagicMock

from cyclonedx.model.bom import Bom

from sbomify_action.cli.main import (
    _apply_cyclonedx_augmentation_to_json,
    _apply_cyclonedx_metadata_to_json,
    _apply_spdx_augmentation_to_json,
    _apply_spdx_metadata_to_json,
    _get_current_utc_timestamp,
)


class TestTimestampFunctionality(unittest.TestCase):
    """Test timestamp handling for both CycloneDX and SPDX formats."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = MagicMock()

    def test_get_current_utc_timestamp_format(self):
        """Test that UTC timestamp format is correct ISO-8601."""
        timestamp = _get_current_utc_timestamp()

        # Check that it ends with 'Z' (UTC indicator)
        self.assertTrue(timestamp.endswith("Z"), "Timestamp should end with 'Z' for UTC")

        # Check that it's in ISO format (YYYY-MM-DDTHH:MM:SSZ)
        self.assertEqual(len(timestamp), 20, "Timestamp should be 20 characters long")
        self.assertIn("T", timestamp, "Timestamp should contain 'T' separator")

        # Check that it contains valid date/time components
        parts = timestamp.replace("Z", "").split("T")
        self.assertEqual(len(parts), 2, "Should have date and time parts")

        date_part, time_part = parts
        self.assertEqual(len(date_part), 10, "Date part should be YYYY-MM-DD format")
        self.assertEqual(len(time_part), 8, "Time part should be HH:MM:SS format")

    def test_cyclonedx_timestamp_added_when_missing(self):
        """Test that CycloneDX SBOM gets timestamp added when missing."""
        sbom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"component": {"type": "application", "name": "test-app"}},
        }

        # Apply augmentation - should add timestamp
        _apply_cyclonedx_augmentation_to_json(sbom_json, {}, self.config)

        self.assertIn("timestamp", sbom_json["metadata"], "Timestamp should be added when missing")
        timestamp = sbom_json["metadata"]["timestamp"]
        self.assertTrue(timestamp.endswith("Z"), "Added timestamp should be in UTC format")

    def test_cyclonedx_timestamp_preserved_when_existing(self):
        """Test that existing CycloneDX timestamp is preserved."""
        existing_timestamp = "2023-01-01T00:00:00Z"
        sbom_json = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"timestamp": existing_timestamp, "component": {"type": "application", "name": "test-app"}},
        }

        # Apply augmentation - should preserve existing timestamp
        _apply_cyclonedx_augmentation_to_json(sbom_json, {}, self.config)

        self.assertEqual(
            sbom_json["metadata"]["timestamp"], existing_timestamp, "Existing timestamp should be preserved"
        )

    def test_cyclonedx_metadata_function_adds_timestamp(self):
        """Test that CycloneDX metadata function adds timestamp when missing."""
        bom = Bom()
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}}

        result = _apply_cyclonedx_metadata_to_json(sbom_json, bom)

        self.assertIn("timestamp", result["metadata"], "Metadata function should add timestamp")
        timestamp = result["metadata"]["timestamp"]
        self.assertTrue(timestamp.endswith("Z"), "Added timestamp should be in UTC format")

    def test_cyclonedx_metadata_function_preserves_timestamp(self):
        """Test that CycloneDX metadata function preserves existing timestamp."""
        existing_timestamp = "2023-01-01T00:00:00Z"
        bom = Bom()
        sbom_json = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"timestamp": existing_timestamp}}

        result = _apply_cyclonedx_metadata_to_json(sbom_json, bom)

        self.assertEqual(
            result["metadata"]["timestamp"], existing_timestamp, "Metadata function should preserve existing timestamp"
        )

    def test_spdx_timestamp_added_when_missing(self):
        """Test that SPDX SBOM gets creation timestamp added when missing."""
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-document",
            "creationInfo": {"creators": ["Tool: test-tool"]},
        }

        # Apply augmentation - should add creation timestamp
        _apply_spdx_augmentation_to_json(sbom_json, {}, self.config)

        self.assertIn("created", sbom_json["creationInfo"], "Creation timestamp should be added when missing")
        timestamp = sbom_json["creationInfo"]["created"]
        self.assertTrue(timestamp.endswith("Z"), "Added timestamp should be in UTC format")

    def test_spdx_timestamp_preserved_when_existing(self):
        """Test that existing SPDX creation timestamp is preserved."""
        existing_timestamp = "2023-01-01T00:00:00Z"
        sbom_json = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-document",
            "creationInfo": {"created": existing_timestamp, "creators": ["Tool: test-tool"]},
        }

        # Apply augmentation - should preserve existing timestamp
        _apply_spdx_augmentation_to_json(sbom_json, {}, self.config)

        self.assertEqual(
            sbom_json["creationInfo"]["created"], existing_timestamp, "Existing SPDX timestamp should be preserved"
        )

    def test_spdx_metadata_function_adds_timestamp(self):
        """Test that SPDX metadata function adds creation timestamp when missing."""
        sbom_json = {"spdxVersion": "SPDX-2.3", "creationInfo": {}}

        result = _apply_spdx_metadata_to_json(sbom_json, {})

        self.assertIn("created", result["creationInfo"], "Metadata function should add creation timestamp")
        timestamp = result["creationInfo"]["created"]
        self.assertTrue(timestamp.endswith("Z"), "Added timestamp should be in UTC format")

    def test_spdx_metadata_function_preserves_timestamp(self):
        """Test that SPDX metadata function preserves existing creation timestamp."""
        existing_timestamp = "2023-01-01T00:00:00Z"
        sbom_json = {"spdxVersion": "SPDX-2.3", "creationInfo": {"created": existing_timestamp}}

        result = _apply_spdx_metadata_to_json(sbom_json, {})

        self.assertEqual(
            result["creationInfo"]["created"],
            existing_timestamp,
            "Metadata function should preserve existing SPDX timestamp",
        )

    def test_timestamp_is_current_time(self):
        """Test that timestamp is approximately current time."""
        import datetime

        timestamp_str = _get_current_utc_timestamp()

        # Parse the generated timestamp
        timestamp = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

        # Should be UTC timezone
        self.assertEqual(timestamp.tzinfo, datetime.timezone.utc, "Timestamp should be in UTC")

        # Should be within the last minute (very generous check)
        now = datetime.datetime.now(datetime.timezone.utc)
        time_diff = abs((timestamp - now).total_seconds())
        self.assertLess(time_diff, 60.0, "Timestamp should be within 1 minute of current time")


if __name__ == "__main__":
    unittest.main()
