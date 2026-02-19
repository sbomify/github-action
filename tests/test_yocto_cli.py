"""Tests for the Yocto CLI command."""

import tarfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from sbomify_action._yocto.models import YoctoPipelineResult
from sbomify_action.cli.main import cli

YOCTO_TEST_DATA = Path(__file__).parent / "test-data" / "yocto"


def _make_tar_gz(tmp_path: Path) -> str:
    """Create a tar.gz from test fixtures."""
    archive_path = str(tmp_path / "test.spdx.tar.gz")
    with tarfile.open(archive_path, "w:gz") as tar:
        for f in YOCTO_TEST_DATA.glob("*.spdx.json"):
            tar.add(str(f), arcname=f.name)
    return archive_path


class TestYoctoCli:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["yocto", "--help"])
        assert result.exit_code == 0
        assert "Yocto/OpenEmbedded" in result.output
        assert "--release" in result.output
        assert "--dry-run" in result.output

    def test_missing_release(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive])
        assert result.exit_code != 0
        assert "Missing option '--release'" in result.output or "required" in result.output.lower()

    def test_missing_token(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["yocto", archive, "--release", "prod:1.0"])
        assert result.exit_code != 0

    def test_invalid_release_format(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", "no-colon"])
        assert result.exit_code != 0
        assert "product_id:version" in result.output

    def test_empty_product_id(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", ":1.0"])
        assert result.exit_code != 0
        assert "non-empty" in result.output

    def test_empty_version(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", "prod:"])
        assert result.exit_code != 0
        assert "non-empty" in result.output

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_dry_run(self, mock_pipeline, tmp_path):
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult(packages_found=3, sboms_skipped=3)

        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", "prod:1.0", "--dry-run"])
        assert result.exit_code == 0
        mock_pipeline.assert_called_once()

        config = mock_pipeline.call_args[0][0]
        assert config.dry_run is True
        assert config.product_id == "prod"
        assert config.release_version == "1.0"

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_exit_code_1_on_errors(self, mock_pipeline, tmp_path):
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult(errors=1)

        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", "prod:1.0"])
        assert result.exit_code == 1

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_augment_enrich_flags(self, mock_pipeline, tmp_path):
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--token", "t", "yocto", archive, "--release", "prod:1.0", "--augment", "--enrich"],
        )
        assert result.exit_code == 0

        config = mock_pipeline.call_args[0][0]
        assert config.augment is True
        assert config.enrich is True

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_api_base_url(self, mock_pipeline, tmp_path):
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "--token",
                "t",
                "--api-base-url",
                "https://custom.example.com/",
                "yocto",
                archive,
                "--release",
                "prod:1.0",
            ],
        )
        assert result.exit_code == 0
        config = mock_pipeline.call_args[0][0]
        assert config.api_base_url == "https://custom.example.com"  # trailing slash stripped

    def test_nonexistent_archive(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["yocto", "/nonexistent/path.tar.zst", "--token", "t", "--release", "prod:1.0"])
        assert result.exit_code != 0
