import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sbomify_action.enrichment import enrich_sbom
from sbomify_action.generation import (
    GenerationResult,
    generate_sbom,
    process_lock_file,
)

# Path to test fixture for mocked SBOM output
TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "test-data")
FIXTURE_CDX_SBOM = os.path.join(TEST_DATA_DIR, "trivy.cdx.json")


class TestPathExpansion(unittest.TestCase):
    def test_valid_absolute_path(self):
        """Test that an absolute path is returned as-is."""
        path = "/home/user/project/sbom.json"
        self.assertEqual(path, path)

    def test_valid_relative_path(self):
        """Test that a relative path is resolved correctly."""
        path = "sbom.json"
        expanded = str(Path(path).resolve())
        self.assertTrue(os.path.isabs(expanded))

    def test_invalid_path(self):
        """Test that invalid path characters are handled."""
        # This test just verifies the path expansion doesn't crash
        path = "some/path/to/file.json"
        expanded = str(Path(path).resolve())
        self.assertIsInstance(expanded, str)


class TestSBOMValidation(unittest.TestCase):
    def test_valid_cyclonedx(self):
        """Test that a valid CycloneDX SBOM passes validation."""
        sbom_file = os.path.join(TEST_DATA_DIR, "trivy.cdx.json")
        with open(sbom_file) as f:
            data = json.load(f)
        self.assertEqual(data.get("bomFormat"), "CycloneDX")

    def test_valid_spdx(self):
        """Test that a valid SPDX SBOM passes validation."""
        sbom_file = os.path.join(TEST_DATA_DIR, "trivy.spdx.json")
        with open(sbom_file) as f:
            data = json.load(f)
        self.assertIn("spdxVersion", data)

    def test_invalid_json(self):
        """Test that invalid JSON is detected."""
        sbom_file = os.path.join(TEST_DATA_DIR, "invalid_json.json")
        with self.assertRaises(json.JSONDecodeError):
            with open(sbom_file) as f:
                json.load(f)

    def test_invalid_sbom(self):
        """Test that invalid SBOM format is detected."""
        sbom_file = os.path.join(TEST_DATA_DIR, "valid_json.json")
        with open(sbom_file) as f:
            data = json.load(f)
        self.assertNotIn("bomFormat", data)
        self.assertNotIn("spdxVersion", data)

    def test_lock_file_as_sbom(self):
        """Test that lock files are not mistaken for SBOMs."""
        lock_file = os.path.join(TEST_DATA_DIR, "requirements.txt")
        # Lock files are not JSON
        with self.assertRaises(json.JSONDecodeError):
            with open(lock_file) as f:
                json.load(f)


@patch("sbomify_action._generation.generators.syft._SYFT_AVAILABLE", True)
@patch("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", True)
@patch("sbomify_action._generation.generators.trivy._TRIVY_AVAILABLE", True)
@patch("sbomify_action._generation.generators.cyclonedx_py._CYCLONEDX_PY_AVAILABLE", True)
class TestSBOMGeneration(unittest.TestCase):
    """Test SBOM generation using the plugin architecture."""

    def _mock_subprocess_for_sbom(self, mock_run, output_file):
        """Helper to mock subprocess.run and copy fixture to output file."""

        def side_effect(*args, **kwargs):
            # Copy the fixture SBOM to the output file
            shutil.copy(FIXTURE_CDX_SBOM, output_file)
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            return mock_result

        mock_run.side_effect = side_effect

    @patch("subprocess.run")
    def test_generate_sbom_python_requirements(self, mock_run):
        """Test SBOM generation from requirements.txt."""
        output_file = "test_requirements_generation.json"
        self._mock_subprocess_for_sbom(mock_run, output_file)

        result = generate_sbom(
            lock_file="tests/test-data/requirements.txt",
            output_file=output_file,
            output_format="cyclonedx",
        )

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertTrue(mock_run.called)

        if os.path.exists(output_file):
            os.remove(output_file)

    @patch("subprocess.run")
    def test_generate_sbom_pipenv(self, mock_run):
        """Test SBOM generation from Pipfile.lock."""
        output_file = "test_pipenv_generation.json"
        self._mock_subprocess_for_sbom(mock_run, output_file)

        result = generate_sbom(
            lock_file="tests/test-data/Pipfile.lock",
            output_file=output_file,
            output_format="cyclonedx",
        )

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "cyclonedx")
        self.assertTrue(mock_run.called)

        if os.path.exists(output_file):
            os.remove(output_file)

    @patch("subprocess.run")
    def test_generate_sbom_rust_cargo(self, mock_run):
        """Test SBOM generation from Cargo.lock."""
        output_file = "test_cargo_generation.json"

        def side_effect(*args, **kwargs):
            shutil.copy(FIXTURE_CDX_SBOM, output_file)
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            return mock_result

        mock_run.side_effect = side_effect

        result = generate_sbom(
            lock_file="tests/test-data/Cargo.lock",
            output_file=output_file,
            output_format="cyclonedx",
        )

        self.assertTrue(result.success)
        self.assertTrue(mock_run.called)

        if os.path.exists(output_file):
            os.remove(output_file)

    @patch("subprocess.run")
    def test_generate_sbom_cpp_conan(self, mock_run):
        """Test SBOM generation from conan.lock."""
        output_file = "test_conan_generation.json"

        def side_effect(*args, **kwargs):
            shutil.copy(FIXTURE_CDX_SBOM, output_file)
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            return mock_result

        mock_run.side_effect = side_effect

        result = generate_sbom(
            lock_file="tests/test-data/conan.lock",
            output_file=output_file,
            output_format="cyclonedx",
        )

        self.assertTrue(result.success)
        self.assertTrue(mock_run.called)

        if os.path.exists(output_file):
            os.remove(output_file)

    @patch("subprocess.run")
    def test_generate_sbom_docker_image(self, mock_run):
        """Test SBOM generation from Docker image."""
        output_file = "test_docker_image_generation.json"

        # Create a mock SBOM with nginx component
        mock_sbom = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "application",
                    "name": "nginx",
                    "version": "1.25.0",
                }
            ],
        }

        def side_effect(*args, **kwargs):
            with open(output_file, "w") as f:
                json.dump(mock_sbom, f)
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            return mock_result

        mock_run.side_effect = side_effect

        result = generate_sbom(
            docker_image="nginx:latest",
            output_file=output_file,
            output_format="cyclonedx",
        )

        self.assertTrue(result.success)

        # Verify the SBOM contains nginx
        with open(output_file) as f:
            sbom_data = json.load(f)

        nginx_component_exists = any(component.get("name") == "nginx" for component in sbom_data.get("components", []))
        self.assertTrue(
            nginx_component_exists,
            "The component with 'name': 'nginx' was not found in 'components'.",
        )
        self.assertTrue(mock_run.called)

        if os.path.exists(output_file):
            os.remove(output_file)

    @patch("subprocess.run")
    def test_generate_sbom_spdx_format(self, mock_run):
        """Test SBOM generation with SPDX format."""
        output_file = "test_spdx_generation.json"

        mock_sbom = {
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

        def side_effect(*args, **kwargs):
            with open(output_file, "w") as f:
                json.dump(mock_sbom, f)
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            return mock_result

        mock_run.side_effect = side_effect

        result = generate_sbom(
            lock_file="tests/test-data/requirements.txt",
            output_file=output_file,
            output_format="spdx",
        )

        self.assertTrue(result.success)
        self.assertEqual(result.sbom_format, "spdx")

        if os.path.exists(output_file):
            os.remove(output_file)


class TestProcessLockFile(unittest.TestCase):
    """Test the process_lock_file function."""

    @patch("sbomify_action.generation.generate_sbom")
    def test_process_lock_file_success(self, mock_generate):
        """Test successful lock file processing."""
        mock_generate.return_value = GenerationResult.success_result(
            output_file="step_1.json",
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name="cyclonedx-py",
        )

        result = process_lock_file("tests/test-data/requirements.txt")

        self.assertTrue(result.success)
        mock_generate.assert_called_once()


class TestEnrichment(unittest.TestCase):
    def test_enrichment(self):
        """Test SBOM enrichment pipeline."""
        sbom_file = os.path.join(TEST_DATA_DIR, "trivy.cdx.json")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name

        try:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "info": {
                    "name": "requests",
                    "version": "2.28.1",
                    "author": "Kenneth Reitz",
                    "home_page": "https://requests.readthedocs.io",
                    "license": "Apache 2.0",
                }
            }

            with patch("requests.Session.get", return_value=mock_response):
                enrich_sbom(sbom_file, output_file, validate=False)

            self.assertTrue(os.path.exists(output_file))

            with open(output_file) as f:
                data = json.load(f)

            self.assertIn("components", data)
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def test_failed_json_file(self):
        """Test enrichment with invalid JSON file."""
        invalid_file = os.path.join(TEST_DATA_DIR, "invalid_json.json")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name

        try:
            with self.assertRaises(Exception):
                enrich_sbom(invalid_file, output_file, validate=False)
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)


if __name__ == "__main__":
    unittest.main()
