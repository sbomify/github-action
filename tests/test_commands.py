import subprocess
import unittest
from unittest.mock import MagicMock, mock_open, patch

from sbomify_action.cli.main import (
    _process_python_lock_file,
    process_lock_file,
    run_command_with_json_output,
)
from sbomify_action.exceptions import (
    FileProcessingError,
    SBOMGenerationError,
)


class TestCommandExecution(unittest.TestCase):
    """Test cases for command execution functions with proper mocking."""

    @patch("subprocess.run")
    @patch("pathlib.Path.open", new_callable=mock_open)
    def test_run_command_with_json_output_success(self, mock_file, mock_run):
        """Test successful command execution with valid JSON output."""
        # Setup mock
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"test": "data"}'
        mock_run.return_value = mock_result

        result = run_command_with_json_output(["echo", "test"], "test-command", "output.json")

        # Assertions
        self.assertEqual(result, 0)
        mock_run.assert_called_once_with(
            ["echo", "test"], capture_output=True, check=True, text=True, shell=False, timeout=600
        )
        mock_file.assert_called_once_with("w")

    @patch("subprocess.run")
    def test_run_command_with_json_output_command_failure(self, mock_run):
        """Test command execution when subprocess fails."""
        # Setup mock to raise CalledProcessError
        mock_run.side_effect = subprocess.CalledProcessError(1, ["echo", "test"], stderr="error")

        with self.assertRaises(SBOMGenerationError):
            run_command_with_json_output(["echo", "test"], "test-command", "output.json")

    @patch("subprocess.run")
    def test_run_command_with_json_output_invalid_json(self, mock_run):
        """Test command execution with invalid JSON output."""
        # Setup mock with invalid JSON
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json"
        mock_run.return_value = mock_result

        with self.assertRaises(SBOMGenerationError):
            run_command_with_json_output(["echo", "test"], "test-command", "output.json")

    @patch("subprocess.run")
    def test_run_command_with_json_output_timeout(self, mock_run):
        """Test command execution timeout."""
        # Setup mock to raise TimeoutExpired
        mock_run.side_effect = subprocess.TimeoutExpired(["echo", "test"], 10)

        with self.assertRaises(SBOMGenerationError):
            run_command_with_json_output(["echo", "test"], "test-command", "output.json")


class TestLockFileProcessing(unittest.TestCase):
    """Test cases for lock file processing with mocking."""

    @patch("sbomify_action.cli.main._process_python_lock_file")
    def test_process_lock_file_python_requirements(self, mock_process_python):
        """Test processing Python requirements.txt file."""
        test_file = "/path/to/requirements.txt"

        process_lock_file(test_file)

        mock_process_python.assert_called_once_with(test_file, "requirements.txt")

    @patch("sbomify_action.cli.main.run_trivy_fs")
    def test_process_lock_file_rust_cargo(self, mock_trivy):
        """Test processing Rust Cargo.lock file."""
        test_file = "/path/to/Cargo.lock"

        process_lock_file(test_file)

        mock_trivy.assert_called_once_with(lock_file=test_file, output_file="step_1.json")

    def test_process_lock_file_unsupported_type(self):
        """Test processing unsupported lock file type."""
        test_file = "/path/to/unsupported.lock"

        with self.assertRaises(FileProcessingError) as cm:
            process_lock_file(test_file)

        self.assertIn("not a recognized lock file type", str(cm.exception))

    @patch("sbomify_action.cli.main.generate_sbom_from_python_lock_file")
    def test_process_python_lock_file_requirements(self, mock_generate):
        """Test processing Python requirements.txt with mocking."""
        mock_generate.return_value = 0

        _process_python_lock_file("/path/to/requirements.txt", "requirements.txt")

        mock_generate.assert_called_once_with(
            lock_file="/path/to/requirements.txt",
            lock_file_type="requirements",
            output_file="step_1.json",
        )

    @patch("sbomify_action.cli.main.generate_sbom_from_python_lock_file")
    def test_process_python_lock_file_poetry(self, mock_generate):
        """Test processing Python poetry.lock with mocking."""
        mock_generate.return_value = 0

        _process_python_lock_file("/path/to/poetry.lock", "poetry.lock")

        mock_generate.assert_called_once_with(
            lock_file="/path/to",  # Directory path for poetry
            lock_file_type="poetry",
            output_file="step_1.json",
        )

    @patch("sbomify_action.cli.main.generate_sbom_from_python_lock_file")
    def test_process_python_lock_file_failure(self, mock_generate):
        """Test handling of SBOM generation failure."""
        mock_generate.return_value = 1  # Non-zero return code indicates failure

        with self.assertRaises(SBOMGenerationError):
            _process_python_lock_file("/path/to/requirements.txt", "requirements.txt")


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions."""

    def test_evaluate_boolean_true_values(self):
        """Test boolean evaluation for various true values."""
        from sbomify_action.cli.main import evaluate_boolean

        true_values = ["true", "True", "TRUE", "yes", "YES", "yeah", "1"]
        for value in true_values:
            with self.subTest(value=value):
                self.assertTrue(evaluate_boolean(value))

    def test_evaluate_boolean_false_values(self):
        """Test boolean evaluation for various false values."""
        from sbomify_action.cli.main import evaluate_boolean

        false_values = ["false", "False", "FALSE", "no", "NO", "0", "anything"]
        for value in false_values:
            with self.subTest(value=value):
                self.assertFalse(evaluate_boolean(value))


if __name__ == "__main__":
    unittest.main()
