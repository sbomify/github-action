"""Integration tests for the sbomify.json wizard."""

import json

from click.testing import CliRunner

from sbomify_action.cli.main import cli


class TestInitCommand:
    """Tests for the init CLI command."""

    def test_init_help(self):
        """Test that init --help works."""
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])
        assert result.exit_code == 0
        assert "Interactive wizard" in result.output
        assert "--output" in result.output

    def test_init_output_option(self):
        """Test that init accepts --output option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])
        assert "-o, --output TEXT" in result.output


class TestWizardRunner:
    """Tests for the wizard runner module."""

    def test_load_existing_config_not_found(self, tmp_path):
        """Test loading when config doesn't exist."""
        from sbomify_action.cli.wizard.runner import _load_existing_config

        result = _load_existing_config(tmp_path / "sbomify.json")
        assert result is None

    def test_load_existing_config_valid(self, tmp_path):
        """Test loading valid existing config."""
        from sbomify_action.cli.wizard.runner import _load_existing_config

        config = {"lifecycle_phase": "build", "licenses": ["MIT"]}
        config_path = tmp_path / "sbomify.json"
        config_path.write_text(json.dumps(config))

        result = _load_existing_config(config_path)
        assert result == config

    def test_load_existing_config_invalid_json(self, tmp_path):
        """Test loading invalid JSON file."""
        from sbomify_action.cli.wizard.runner import _load_existing_config

        config_path = tmp_path / "sbomify.json"
        config_path.write_text("not valid json")

        result = _load_existing_config(config_path)
        assert result is None

    def test_merge_config(self):
        """Test config merging."""
        from sbomify_action.cli.wizard.runner import _merge_config

        base = {"a": 1, "b": 2}
        updates = {"b": 3, "c": 4}

        result = _merge_config(base, updates)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_merge_config_ignores_none(self):
        """Test that merge ignores None values."""
        from sbomify_action.cli.wizard.runner import _merge_config

        base = {"a": 1, "b": 2}
        updates = {"b": None, "c": 4}

        result = _merge_config(base, updates)
        assert result == {"a": 1, "b": 2, "c": 4}

    def test_write_config(self, tmp_path):
        """Test writing config to file."""
        from sbomify_action.cli.wizard.runner import _write_config

        config = {"lifecycle_phase": "build"}
        config_path = tmp_path / "sbomify.json"

        result = _write_config(config, config_path, backup=False)
        assert result is True
        assert config_path.exists()

        written = json.loads(config_path.read_text())
        assert written == config

    def test_write_config_creates_backup(self, tmp_path):
        """Test that writing creates backup of existing file."""
        from sbomify_action.cli.wizard.runner import _write_config

        config_path = tmp_path / "sbomify.json"
        original = {"original": True}
        config_path.write_text(json.dumps(original))

        new_config = {"new": True}
        result = _write_config(new_config, config_path, backup=True)

        assert result is True
        backup_path = tmp_path / "sbomify.json.bak"
        assert backup_path.exists()
        assert json.loads(backup_path.read_text()) == original
        assert json.loads(config_path.read_text()) == new_config


class TestWizardSections:
    """Tests for wizard section constants."""

    def test_section_constants_exist(self):
        """Test that section constants are defined."""
        from sbomify_action.cli.wizard.sections import (
            SECTION_AUTHORS,
            SECTION_LICENSES,
            SECTION_LIFECYCLE,
            SECTION_ORGANIZATION,
            SECTION_SECURITY,
            SECTION_VCS,
        )

        assert SECTION_ORGANIZATION == "organization"
        assert SECTION_AUTHORS == "authors"
        assert SECTION_LICENSES == "licenses"
        assert SECTION_SECURITY == "security"
        assert SECTION_LIFECYCLE == "lifecycle"
        assert SECTION_VCS == "vcs"
