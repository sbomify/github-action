import json
import os
import unittest
from unittest.mock import Mock, patch

from sbomify_action.cli.main import (
    enrich_sbom_with_ecosystems,
    path_expansion,
    validate_sbom,
)
from sbomify_action.exceptions import (
    FileProcessingError,
    SBOMValidationError,
)
from sbomify_action.generation import (
    generate_sbom_from_python_lock_file,
    run_trivy_docker_image,
    run_trivy_fs,
)


class TestPathExpansion(unittest.TestCase):
    def test_valid_absolute_path(self):
        """
        Test that a valid absolute path returns the correct path.
        """

        valid_file_path = os.path.join(os.getcwd(), "tests/test-data/valid_json.json")

        # Call the function with a valid absolute path
        result = path_expansion(valid_file_path)

        # Assert that the returned path is the absolute path
        self.assertTrue(os.path.isabs(result))

    def test_valid_relative_path(self):
        """
        Test that a valid relative path returns the correct joined path.
        """
        # Call the function with a valid relative path
        result = path_expansion("tests/test-data/valid_json.json")

        expected_result = os.path.join(os.getcwd(), "tests/test-data/valid_json.json")

        # Assert that the returned path is the joined relative path
        self.assertEqual(result, expected_result)

    def test_invalid_path(self):
        """
        Test that an invalid path results in FileProcessingError.
        """

        # Expect FileProcessingError when calling the function
        with self.assertRaises(FileProcessingError):
            path_expansion("invalid/path.txt")


class TestSBOMValidation(unittest.TestCase):
    def test_invalid_json(self):
        """
        Test that an invalid JSON results in SBOMValidationError.
        """

        # Expect SBOMValidationError when calling the function
        with self.assertRaises(SBOMValidationError):
            validate_sbom("tests/test-data/invalid_json.json")

    def test_invalid_sbom(self):
        """
        Test that a valid JSON, but not an SBOM, results in SBOMValidationError.
        """

        # Expect SBOMValidationError when calling the function
        with self.assertRaises(SBOMValidationError):
            validate_sbom("tests/test-data/valid_json.json")

    def test_valid_cyclonedx(self):
        """
        Test that a valid CycloneDX SBOM.
        """
        result = validate_sbom("tests/test-data/syft.cdx.json")
        self.assertEqual(result, "cyclonedx")

    def test_valid_spdx(self):
        """
        Test that a valid SPDX SBOM.
        """
        result = validate_sbom("tests/test-data/syft.spdx.json")
        self.assertEqual(result, "spdx")

    def test_lock_file_as_sbom(self):
        """
        Test that providing a lock file (e.g., Pipfile.lock) as an SBOM results in SBOMValidationError.
        This simulates the common user mistake of setting SBOM_FILE to a lock file.
        """
        # Expect SBOMValidationError when calling the function with a lock file
        with self.assertRaises(SBOMValidationError):
            validate_sbom("tests/test-data/Pipfile.lock")


class TestPythonSBOMGeneration(unittest.TestCase):
    def test_generation_requirements_txt(self):
        """
        Test CycloneDX generation of SBOM
        from a `requirements.txt` file.
        """

        output_file = "test_requirements_generation.json"
        generation_return_code = generate_sbom_from_python_lock_file(
            lock_file="tests/test-data/requirements.txt",
            lock_file_type="requirements",
            output_file=output_file,
        )

        sbom_type = validate_sbom(output_file)

        self.assertEqual(generation_return_code, 0)
        self.assertEqual(sbom_type, "cyclonedx")

        os.remove(output_file)

    def test_generation_requirements(self):
        """
        Test CycloneDX generation of SBOM
        from a `requirements.txt` file.
        """

        output_file = "test_requirements_generation.json"
        generation_return_code = generate_sbom_from_python_lock_file(
            lock_file="tests/test-data/requirements.txt",
            lock_file_type="requirements",
            output_file=output_file,
        )

        sbom_type = validate_sbom(output_file)

        self.assertEqual(generation_return_code, 0)
        self.assertEqual(sbom_type, "cyclonedx")

        os.remove(output_file)

    def test_generation_pipenv(self):
        """
        Test CycloneDX generation of SBOM
        from a `poetry.lock` file.
        """

        output_file = "test_pipenv_generation.json"
        generation_return_code = generate_sbom_from_python_lock_file(
            lock_file=os.path.dirname("tests/test-data/Pipfile.lock"),
            lock_file_type="pipenv",
            output_file=output_file,
        )

        sbom_type = validate_sbom(output_file)

        self.assertEqual(generation_return_code, 0)
        self.assertEqual(sbom_type, "cyclonedx")

        os.remove(output_file)


class TestRustSBOMGeneration(unittest.TestCase):
    def test_generation_cargo_lock(self):
        """
        Test CycloneDX generation of SBOM
        from a `Cargo.lock` file.
        """

        output_file = "test_cargo_generation.json"

        run_trivy_fs(
            lock_file="tests/test-data/Cargo.lock",
            output_file=output_file,
        )


class TestCppSBOMGeneration(unittest.TestCase):
    def test_generation_conan_lock(self):
        """
        Test CycloneDX generation of SBOM
        from a `conan.lock` file.
        """

        output_file = "test_conan_generation.json"

        run_trivy_fs(
            lock_file="tests/test-data/conan.lock",
            output_file=output_file,
        )


class TestDockerImageSBOMGeneration(unittest.TestCase):
    def test_generation_docker_image(self):
        """
        Test CycloneDX generation of SBOM
        from a Docker Image.
        """

        output_file = "test_docker_image_generation.json"

        run_trivy_docker_image(
            docker_image="nginx:latest",
            output_file=output_file,
        )

        with open(output_file) as f:
            json_data = json.load(f)

        nginx_component_exists = any(component.get("name") == "nginx" for component in json_data.get("components", []))
        self.assertTrue(
            nginx_component_exists,
            "The component with 'name': 'nginx' was not found in 'components'.",
        )


class TestEnrichment(unittest.TestCase):
    @patch("requests.Session.get")
    def test_enrichment(self, mock_get):
        """
        Test the enrichment with ecosyste.ms API
        """
        # Mock API response for PyPI packages
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Test package description",
                "license": "MIT",
                "home_page": "https://example.com",
                "author": "Test Author",
            }
        }
        mock_get.return_value = mock_response

        input_file = "tests/test-data/syft.cdx.json"
        output_file = "enriched_sbom.cdx.json"

        enrich_sbom_with_ecosystems(input_file, output_file)
        validate_sbom(output_file)

        # Verify that the API was called
        self.assertTrue(mock_get.called)

    def test_failed_json_file(self):
        """
        Test the enrichment with invalid JSON input
        """

        input_file = "tests/test-data/invalid_json.json"
        output_file = "enriched_sbom.cdx.json"

        # Should raise SBOMValidationError for invalid JSON
        with self.assertRaises(SBOMValidationError):
            enrich_sbom_with_ecosystems(input_file, output_file)


if __name__ == "__main__":
    unittest.main()
