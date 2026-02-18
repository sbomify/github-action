"""Tests for Yocto pipeline orchestrator."""

import shutil
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from sbomify_action._upload.result import UploadResult
from sbomify_action._yocto.models import YoctoConfig, YoctoPipelineResult
from sbomify_action._yocto.pipeline import _process_single_package, run_yocto_pipeline
from sbomify_action.exceptions import APIError

YOCTO_TEST_DATA = Path(__file__).parent / "test-data" / "yocto"
API_BASE = "https://app.sbomify.com"
TOKEN = "test-token"


def _make_tar_gz(tmp_path: Path) -> str:
    """Create a tar.gz from test fixtures."""
    archive_path = str(tmp_path / "test.spdx.tar.gz")
    with tarfile.open(archive_path, "w:gz") as tar:
        for f in YOCTO_TEST_DATA.glob("*.spdx.json"):
            tar.add(str(f), arcname=f.name)
    return archive_path


def _make_config(archive_path: str, **kwargs) -> YoctoConfig:
    defaults = {
        "archive_path": archive_path,
        "token": TOKEN,
        "product_id": "test-product",
        "release_version": "1.0.0",
        "api_base_url": API_BASE,
    }
    defaults.update(kwargs)
    return YoctoConfig(**defaults)


class TestProcessSinglePackage:
    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_upload_success(self, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-123")
        config = _make_config(str(tmp_path / "dummy.tar.gz"))

        result = _process_single_package("busybox", spdx_file, "comp-1", config)
        assert result == "sbom-123"

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_duplicate_artifact_returns_none(self, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")
        mock_upload.return_value = UploadResult.failure_result(
            destination_name="sbomify",
            error_message="Duplicate",
            error_code="DUPLICATE_ARTIFACT",
        )
        config = _make_config(str(tmp_path / "dummy.tar.gz"))

        result = _process_single_package("busybox", spdx_file, "comp-1", config)
        assert result is None

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_upload_failure_raises(self, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")
        mock_upload.return_value = UploadResult.failure_result(
            destination_name="sbomify",
            error_message="Server error",
        )
        config = _make_config(str(tmp_path / "dummy.tar.gz"))

        with pytest.raises(APIError, match="Upload failed"):
            _process_single_package("busybox", spdx_file, "comp-1", config)

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.augment_sbom_from_file")
    def test_augment_called(self, mock_augment, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")

        # Make augment write the file so upload can read it
        def fake_augment(input_file, output_file, **kwargs):
            shutil.copy(input_file, output_file)
            return "spdx"

        mock_augment.side_effect = fake_augment
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-456")
        config = _make_config(str(tmp_path / "dummy.tar.gz"), augment=True)

        result = _process_single_package("busybox", spdx_file, "comp-1", config)
        assert result == "sbom-456"
        mock_augment.assert_called_once()

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.enrich_sbom")
    def test_enrich_called(self, mock_enrich, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")

        def fake_enrich(input_file, output_file, **kwargs):
            shutil.copy(input_file, output_file)

        mock_enrich.side_effect = fake_enrich
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-789")
        config = _make_config(str(tmp_path / "dummy.tar.gz"), enrich=True)

        result = _process_single_package("busybox", spdx_file, "comp-1", config)
        assert result == "sbom-789"
        mock_enrich.assert_called_once()


class TestRunYoctoPipeline:
    @patch("sbomify_action._yocto.pipeline.tag_sbom_with_release")
    @patch("sbomify_action._yocto.pipeline.create_release")
    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_full_pipeline(self, mock_list, mock_upload, mock_create_release, mock_tag, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive)

        mock_list.return_value = {}  # no existing components
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-001")
        mock_create_release.return_value = "release-001"

        with patch("sbomify_action._yocto.pipeline.get_or_create_component") as mock_goc:
            mock_goc.return_value = ("comp-new", True)
            result = run_yocto_pipeline(config)

        assert result.packages_found == 3  # busybox, base-files, zlib
        assert result.sboms_uploaded == 3
        assert result.components_created == 3
        assert result.errors == 0
        assert result.release_id == "release-001"
        assert mock_tag.call_count == 3

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_dry_run(self, mock_list, mock_upload, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive, dry_run=True)

        result = run_yocto_pipeline(config)

        assert result.packages_found == 3
        assert result.sboms_uploaded == 0
        assert result.sboms_skipped == 3
        mock_list.assert_not_called()
        mock_upload.assert_not_called()

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_continue_on_error(self, mock_list, mock_upload, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive)

        mock_list.return_value = {}
        # First package fails, rest succeed
        call_count = {"n": 0}

        def upload_side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise APIError("Connection failed")
            return UploadResult.success_result(destination_name="sbomify", sbom_id=f"sbom-{call_count['n']}")

        mock_upload.side_effect = upload_side_effect

        with patch("sbomify_action._yocto.pipeline.get_or_create_component") as mock_goc:
            mock_goc.return_value = ("comp-1", True)
            with patch("sbomify_action._yocto.pipeline.create_release") as mock_rel:
                mock_rel.return_value = "rel-1"
                with patch("sbomify_action._yocto.pipeline.tag_sbom_with_release"):
                    result = run_yocto_pipeline(config)

        assert result.packages_found == 3
        assert result.errors >= 1
        assert result.sboms_uploaded >= 1  # at least some succeeded
        assert result.has_errors is True

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_duplicate_artifacts_counted_as_skipped(self, mock_list, mock_upload, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive)

        mock_list.return_value = {"busybox": "c1", "base-files": "c2", "zlib": "c3"}
        mock_upload.return_value = UploadResult.failure_result(
            destination_name="sbomify",
            error_message="Duplicate",
            error_code="DUPLICATE_ARTIFACT",
        )

        with patch("sbomify_action._yocto.pipeline.get_or_create_component") as mock_goc:
            mock_goc.side_effect = lambda url, tok, name, cache: (cache.get(name, "x"), False)
            result = run_yocto_pipeline(config)

        assert result.sboms_skipped == 3
        assert result.sboms_uploaded == 0
        assert result.errors == 0


class TestYoctoPipelineResult:
    def test_has_errors(self):
        r = YoctoPipelineResult(errors=1)
        assert r.has_errors is True

    def test_no_errors(self):
        r = YoctoPipelineResult()
        assert r.has_errors is False
