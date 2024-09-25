import unittest
import os
import sys

from entrypoint import path_expansion
from entrypoint import validate_sbom

class TestPathExpansion(unittest.TestCase):
    def test_valid_absolute_path(self):
        """
        Test that a valid absolute path returns the correct path.
        """

        valid_file_path = os.path.join(os.getcwd(), 'tests/test-data/valid_json.json' )

        # Call the function with a valid absolute path
        result = path_expansion(valid_file_path)

        # Assert that the returned path is the absolute path
        self.assertTrue(os.path.isabs(result))

    def test_valid_relative_path(self):
        """
        Test that a valid relative path returns the correct joined path.
        """
        # Call the function with a valid relative path
        result = path_expansion('tests/test-data/valid_json.json')

        expected_result = os.path.join(os.getcwd(), 'tests/test-data/valid_json.json')

        # Assert that the returned path is the joined relative path
        self.assertEqual(result, expected_result)

    def test_invalid_path(self):
        """
        Test that an invalid path results in sys.exit(1).
        """

        # Expect SystemExit with code 1 when calling the function
        with self.assertRaises(SystemExit) as cm:
            path_expansion('invalid/path.txt')

        # Assert that the exit code is 1
        self.assertEqual(cm.exception.code, 1)

class TestSBOMValidation(unittest.TestCase):
    def test_invalid_json(self):
        """
        Test that an invalid JSON results in sys.exit(1).
        """

        # Expect SystemExit with code 1 when calling the function
        with self.assertRaises(SystemExit) as cm:
            validate_sbom('tests/test-data/invalid_json.json')

        # Assert that the exit code is 1
        self.assertEqual(cm.exception.code, 1)

    def test_invalid_sbom(self):
        """
        Test that an valid JSON, but not an SBOM, results in sys.exit(1).
        """

        # Expect SystemExit with code 1 when calling the function
        with self.assertRaises(SystemExit) as cm:
            validate_sbom('tests/test-data/valid_json.json')

        # Assert that the exit code is 1
        self.assertEqual(cm.exception.code, 1)

    def test_valid_cyclonedx(self):
        """
        Test that a valid CycloneDX SBOM.
        """
        result = validate_sbom('tests/test-data/syft.cdx.json')
        self.assertEqual(result, 'cyclonedx')

    def test_valid_spdx(self):
        """
        Test that a valid SPDX SBOM.
        """
        result = validate_sbom('tests/test-data/syft.spdx.json')
        self.assertEqual(result, 'spdx')

if __name__ == '__main__':
    unittest.main()