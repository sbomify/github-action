import os
import sys
import unittest

from entrypoint import (
    enrich_sbom_with_parley,
    generate_sbom_from_python_lock_file,
    run_trivy_fs,
    path_expansion,
    validate_sbom,
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
        Test that an invalid path results in sys.exit(1).
        """

        # Expect SystemExit with code 1 when calling the function
        with self.assertRaises(SystemExit) as cm:
            path_expansion("invalid/path.txt")

        # Assert that the exit code is 1
        self.assertEqual(cm.exception.code, 1)


class TestSBOMValidation(unittest.TestCase):
    def test_invalid_json(self):
        """
        Test that an invalid JSON results in sys.exit(1).
        """

        # Expect SystemExit with code 1 when calling the function
        with self.assertRaises(SystemExit) as cm:
            validate_sbom("tests/test-data/invalid_json.json")

        # Assert that the exit code is 1
        self.assertEqual(cm.exception.code, 1)

    def test_invalid_sbom(self):
        """
        Test that an valid JSON, but not an SBOM, results in sys.exit(1).
        """

        # Expect SystemExit with code 1 when calling the function
        with self.assertRaises(SystemExit) as cm:
            validate_sbom("tests/test-data/valid_json.json")

        # Assert that the exit code is 1
        self.assertEqual(cm.exception.code, 1)

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

    def test_generation_poetry(self):
        """
        Test CycloneDX generation of SBOM
        from a `poetry.lock` file.
        """

        output_file = "test_poetry_generation.json"
        generation_return_code = generate_sbom_from_python_lock_file(
            lock_file=os.path.dirname("poetry.lock"),
            lock_file_type="poetry",
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

        generation_return_code = run_trivy_fs(
            lock_file="tests/test-data/Cargo.lock",
            output_file=output_file,
        )


class TestEnrichment(unittest.TestCase):
    def test_enrichment(self):
        """
        Test the enrichment in Parlay
        """

        input_file = "tests/test-data/syft.cdx.json"
        output_file = "enriched_sbom.cdx.json"

        enrich = enrich_sbom_with_parley(input_file, output_file)
        sbom_type = validate_sbom(output_file)

    def test_failed_json_file(self):
        """
        Test the enrichment in Parlay
        """

        input_file = "tests/test-data/invalid_json.json"
        output_file = "enriched_sbom.cdx.json"

        with self.assertRaises(SystemExit) as cm:
            enrich = enrich_sbom_with_parley(input_file, output_file)

        # Assert that the exit code is 1
        self.assertEqual(cm.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
