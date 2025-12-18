"""Tests for SBOM validation module."""

import json
import tempfile
import unittest
from pathlib import Path

from sbomify_action.validation import (
    ValidationResult,
    detect_sbom_format_and_version,
    validate_sbom_data,
    validate_sbom_file,
    validate_sbom_file_auto,
)


class TestValidationResult(unittest.TestCase):
    """Tests for ValidationResult dataclass."""

    def test_success_result(self):
        """Test creating a success result."""
        result = ValidationResult.success("cyclonedx", "1.6")
        self.assertTrue(result.valid)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertEqual(result.spec_version, "1.6")
        self.assertIsNone(result.error_message)

    def test_failure_result(self):
        """Test creating a failure result."""
        result = ValidationResult.failure("cyclonedx", "1.6", "Test error", error_path="components.0.name")
        self.assertFalse(result.valid)
        self.assertEqual(result.error_message, "Test error")
        self.assertEqual(result.error_path, "components.0.name")


class TestDetectSBOMFormatAndVersion(unittest.TestCase):
    """Tests for detect_sbom_format_and_version function."""

    def test_detect_cyclonedx(self):
        """Test detecting CycloneDX format."""
        data = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
        format, version = detect_sbom_format_and_version(data)
        self.assertEqual(format, "cyclonedx")
        self.assertEqual(version, "1.6")

    def test_detect_spdx(self):
        """Test detecting SPDX format."""
        data = {"spdxVersion": "SPDX-2.3"}
        format, version = detect_sbom_format_and_version(data)
        self.assertEqual(format, "spdx")
        self.assertEqual(version, "2.3")

    def test_detect_unknown_format(self):
        """Test detecting unknown format."""
        data = {"unknown": "format"}
        format, version = detect_sbom_format_and_version(data)
        self.assertIsNone(format)
        self.assertIsNone(version)

    def test_detect_cyclonedx_no_version(self):
        """Test CycloneDX without version."""
        data = {"bomFormat": "CycloneDX"}
        format, version = detect_sbom_format_and_version(data)
        self.assertEqual(format, "cyclonedx")
        self.assertIsNone(version)


class TestValidateSBOMData(unittest.TestCase):
    """Tests for validate_sbom_data function."""

    def test_valid_cyclonedx_minimal(self):
        """Test validating minimal valid CycloneDX."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
        }
        result = validate_sbom_data(data, "cyclonedx", "1.6")
        self.assertTrue(result.valid)

    def test_invalid_cyclonedx_wrong_type(self):
        """Test validating CycloneDX with wrong field type."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": "not_an_integer",  # Should be integer
        }
        result = validate_sbom_data(data, "cyclonedx", "1.6")
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.error_message)

    def test_valid_spdx_minimal(self):
        """Test validating minimal valid SPDX."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "created": "2023-01-01T00:00:00Z",
                "creators": ["Tool: test"],
            },
        }
        result = validate_sbom_data(data, "spdx", "2.3")
        self.assertTrue(result.valid)


class TestValidateSBOMFile(unittest.TestCase):
    """Tests for validate_sbom_file function."""

    def test_file_not_found(self):
        """Test validating non-existent file."""
        result = validate_sbom_file("/nonexistent/file.json", "cyclonedx", "1.6")
        self.assertFalse(result.valid)
        self.assertIn("not found", result.error_message.lower())

    def test_invalid_json(self):
        """Test validating file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {")
            temp_path = f.name

        try:
            result = validate_sbom_file(temp_path, "cyclonedx", "1.6")
            self.assertFalse(result.valid)
            self.assertIn("invalid json", result.error_message.lower())
        finally:
            Path(temp_path).unlink()

    def test_valid_file(self):
        """Test validating valid SBOM file."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            result = validate_sbom_file(temp_path, "cyclonedx", "1.6")
            self.assertTrue(result.valid)
        finally:
            Path(temp_path).unlink()


class TestValidateSBOMFileAuto(unittest.TestCase):
    """Tests for validate_sbom_file_auto function."""

    def test_auto_detect_cyclonedx(self):
        """Test auto-detecting and validating CycloneDX."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            result = validate_sbom_file_auto(temp_path)
            self.assertTrue(result.valid)
            self.assertEqual(result.sbom_format, "cyclonedx")
            self.assertEqual(result.spec_version, "1.6")
        finally:
            Path(temp_path).unlink()

    def test_auto_detect_spdx(self):
        """Test auto-detecting and validating SPDX."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "created": "2023-01-01T00:00:00Z",
                "creators": ["Tool: test"],
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            result = validate_sbom_file_auto(temp_path)
            self.assertTrue(result.valid)
            self.assertEqual(result.sbom_format, "spdx")
            self.assertEqual(result.spec_version, "2.3")
        finally:
            Path(temp_path).unlink()

    def test_file_not_found(self):
        """Test auto-validating non-existent file."""
        result = validate_sbom_file_auto("/nonexistent/file.json")
        self.assertFalse(result.valid)
        self.assertIn("not found", result.error_message.lower())

    def test_unknown_format(self):
        """Test auto-validating file with unknown format."""
        data = {"unknown": "format"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            result = validate_sbom_file_auto(temp_path)
            self.assertFalse(result.valid)
            self.assertIn("could not detect", result.error_message.lower())
        finally:
            Path(temp_path).unlink()


class TestValidationWithRealSchemas(unittest.TestCase):
    """Tests using real schema files from the project."""

    def test_validate_real_cyclonedx_file(self):
        """Test validating a real CycloneDX test file."""
        test_file = Path(__file__).parent / "test-data" / "trivy.cdx.json"
        if test_file.exists():
            result = validate_sbom_file_auto(str(test_file))
            # The test file should be valid
            self.assertTrue(result.valid, f"Validation failed: {result.error_message}")
            self.assertEqual(result.sbom_format, "cyclonedx")

    def test_validate_real_spdx_file(self):
        """Test validating a real SPDX test file."""
        test_file = Path(__file__).parent / "test-data" / "trivy.spdx.json"
        if test_file.exists():
            result = validate_sbom_file_auto(str(test_file))
            # The test file should be valid
            self.assertTrue(result.valid, f"Validation failed: {result.error_message}")
            self.assertEqual(result.sbom_format, "spdx")


if __name__ == "__main__":
    unittest.main()
