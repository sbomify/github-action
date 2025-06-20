import json
import os
import tempfile
import unittest
from unittest.mock import patch

from sbomify_action.cli.main import main


class TestIntegration(unittest.TestCase):
    """Integration tests for the main workflow."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        os.chdir(self.original_cwd)
        # Clean up temporary files
        for file in ["step_1.json", "step_2.json", "step_3.json", "output.json"]:
            if os.path.exists(file):
                os.remove(file)

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/syft.cdx.json",
            "UPLOAD": "false",
            "AUGMENT": "false",
            "ENRICH": "false",
        },
    )
    @patch("sbomify_action.cli.main.setup_dependencies")
    @patch("sbomify_action.cli.main.initialize_sentry")
    def test_main_sbom_file_workflow(self, mock_sentry, mock_setup):
        """Test main workflow with SBOM file input."""
        # Create a temporary SBOM file
        test_sbom = {"bomFormat": "CycloneDX", "specVersion": "1.4"}
        with open("test_sbom.json", "w") as f:
            json.dump(test_sbom, f)

        # Override environment for this test
        with patch.dict(os.environ, {"SBOM_FILE": "test_sbom.json"}):
            with patch("sbomify_action.cli.main.print_banner"):
                main()

        # Verify setup functions were called
        mock_setup.assert_called_once()
        mock_sentry.assert_called_once()

        # Verify output file was created
        self.assertTrue(os.path.exists("sbom_output.json"))


if __name__ == "__main__":
    unittest.main()
