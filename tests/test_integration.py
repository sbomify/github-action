import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from sbomify_action.cli.main import cli


class TestIntegration(unittest.TestCase):
    """Integration tests for the main workflow."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        self.runner = CliRunner()

    def tearDown(self):
        """Clean up test fixtures."""
        os.chdir(self.original_cwd)
        # Clean up temporary files
        for file in ["step_1.json", "step_2.json", "step_3.json", "output.json", "sbom_output.json", "test_sbom.json"]:
            if os.path.exists(file):
                os.remove(file)

    @patch("sbomify_action.cli.main.setup_dependencies")
    @patch("sbomify_action.cli.main.initialize_sentry")
    def test_main_sbom_file_workflow(self, mock_sentry, mock_setup):
        """Test main workflow with SBOM file input."""
        # Create a temporary SBOM file
        test_sbom = {"bomFormat": "CycloneDX", "specVersion": "1.4"}
        with open("test_sbom.json", "w") as f:
            json.dump(test_sbom, f)

        # Use Click's CliRunner to invoke the CLI with arguments
        with patch("sbomify_action.cli.main.print_banner"):
            result = self.runner.invoke(
                cli,
                [
                    "--sbom-file",
                    "test_sbom.json",
                    "--token",
                    "test-token",
                    "--component-id",
                    "test-component",
                    "--no-upload",
                    "--no-augment",
                    "--no-enrich",
                ],
            )

        # Check the command succeeded
        if result.exit_code != 0:
            print(f"CLI output: {result.output}")
            print(f"CLI exception: {result.exception}")

        self.assertEqual(result.exit_code, 0, f"CLI failed with: {result.output}")

        # Verify setup functions were called
        mock_setup.assert_called_once()
        mock_sentry.assert_called_once()

        # Verify output file was created
        self.assertTrue(os.path.exists("sbom_output.json"))


if __name__ == "__main__":
    unittest.main()
