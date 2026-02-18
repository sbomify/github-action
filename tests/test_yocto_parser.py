"""Tests for Yocto SPDX parser and package discovery."""

import json
import shutil
from pathlib import Path

import pytest

from sbomify_action._yocto.models import YoctoPackage
from sbomify_action._yocto.parser import (
    _categorize_document,
    _compute_sha256,
    _is_rootfs_manifest,
    _is_spdx_22,
    discover_packages,
)
from sbomify_action.exceptions import FileProcessingError

YOCTO_TEST_DATA = Path(__file__).parent / "test-data" / "yocto"


class TestIsSpdx22:
    def test_spdx_22(self):
        assert _is_spdx_22({"spdxVersion": "SPDX-2.2"}) is True

    def test_spdx_23(self):
        assert _is_spdx_22({"spdxVersion": "SPDX-2.3"}) is False

    def test_missing_version(self):
        assert _is_spdx_22({}) is False


class TestIsRootfsManifest:
    def test_rootfs_name(self):
        data = {"name": "core-image-base-qemux86-64.rootfs-20260214054917"}
        assert _is_rootfs_manifest(Path("rootfs.spdx.json"), data) is True

    def test_rootfs_filename(self):
        data = {"name": "some-image"}
        assert _is_rootfs_manifest(Path("image.rootfs.spdx.json"), data) is True

    def test_package_with_ext_refs(self):
        """Package SBOMs have externalDocumentRefs but are NOT rootfs."""
        data = {"name": "busybox", "externalDocumentRefs": [{"id": "recipe-ref"}]}
        assert _is_rootfs_manifest(Path("busybox.spdx.json"), data) is False

    def test_no_rootfs_marker(self):
        assert _is_rootfs_manifest(Path("zlib.spdx.json"), {}) is False


class TestCategorizeDocument:
    def test_rootfs(self):
        data = {"name": "core-image-base.rootfs-20260214", "externalDocumentRefs": [{"id": "x"}]}
        assert _categorize_document(Path("rootfs.spdx.json"), data) == "rootfs"

    def test_recipe(self):
        data = {"name": "recipe-busybox"}
        assert _categorize_document(Path("recipe-busybox.spdx.json"), data) == "recipe"

    def test_runtime(self):
        data = {"name": "runtime-busybox"}
        assert _categorize_document(Path("runtime-busybox.spdx.json"), data) == "runtime"

    def test_package(self):
        data = {"name": "busybox", "externalDocumentRefs": [{"id": "recipe-ref"}]}
        assert _categorize_document(Path("busybox.spdx.json"), data) == "package"

    def test_package_without_ext_refs(self):
        data = {"name": "busybox"}
        assert _categorize_document(Path("busybox.spdx.json"), data) == "package"


class TestComputeSha256:
    def test_deterministic(self, tmp_path):
        """Same content should produce same hash regardless of key order."""
        f1 = tmp_path / "a.json"
        f2 = tmp_path / "b.json"
        f1.write_text(json.dumps({"b": 2, "a": 1}))
        f2.write_text(json.dumps({"a": 1, "b": 2}))
        assert _compute_sha256(str(f1)) == _compute_sha256(str(f2))

    def test_different_content(self, tmp_path):
        f1 = tmp_path / "a.json"
        f2 = tmp_path / "b.json"
        f1.write_text(json.dumps({"x": 1}))
        f2.write_text(json.dumps({"x": 2}))
        assert _compute_sha256(str(f1)) != _compute_sha256(str(f2))


class TestDiscoverPackages:
    def test_discover_from_test_data(self, tmp_path):
        """Test discovery from the test fixture directory."""
        # Copy test data to tmp_path to avoid side effects
        dest = tmp_path / "spdx"
        shutil.copytree(YOCTO_TEST_DATA, dest)

        packages = discover_packages(str(dest))

        # Should find busybox, base-files, zlib (not recipe-*, runtime-*, rootfs)
        names = {p.name for p in packages}
        assert "busybox" in names
        assert "base-files" in names
        assert "zlib" in names
        assert "recipe-busybox" not in names
        assert "runtime-busybox" not in names
        assert "core-image-base-qemux86-64.rootfs-20260214054917" not in names

    def test_package_has_correct_fields(self, tmp_path):
        dest = tmp_path / "spdx"
        shutil.copytree(YOCTO_TEST_DATA, dest)

        packages = discover_packages(str(dest))
        busybox = next(p for p in packages if p.name == "busybox")

        assert isinstance(busybox, YoctoPackage)
        assert busybox.version == "1.36.1"
        assert busybox.document_namespace == "http://spdx.org/spdxdocs/busybox-1.36.1-abcd"
        assert busybox.sha256  # non-empty
        assert busybox.spdx_file.endswith("busybox.spdx.json")

    def test_empty_directory(self, tmp_path):
        with pytest.raises(FileProcessingError, match="No .spdx.json files found"):
            discover_packages(str(tmp_path))

    def test_only_recipes_and_runtime(self, tmp_path):
        """If all files are recipe/runtime, should raise."""
        recipe = {
            "spdxVersion": "SPDX-2.2",
            "name": "recipe-foo",
            "packages": [{"versionInfo": "1.0"}],
        }
        (tmp_path / "recipe-foo.spdx.json").write_text(json.dumps(recipe))

        with pytest.raises(FileProcessingError, match="No package SBOMs found"):
            discover_packages(str(tmp_path))

    def test_skips_non_spdx22(self, tmp_path):
        """Non-SPDX-2.2 files should be skipped."""
        pkg = {
            "spdxVersion": "SPDX-2.3",
            "name": "some-pkg",
            "packages": [{"versionInfo": "1.0"}],
        }
        (tmp_path / "some-pkg.spdx.json").write_text(json.dumps(pkg))

        valid = {
            "spdxVersion": "SPDX-2.2",
            "name": "valid-pkg",
            "packages": [{"versionInfo": "2.0"}],
        }
        (tmp_path / "valid-pkg.spdx.json").write_text(json.dumps(valid))

        packages = discover_packages(str(tmp_path))
        assert len(packages) == 1
        assert packages[0].name == "valid-pkg"

    def test_skips_invalid_json(self, tmp_path):
        """Invalid JSON files should be skipped with warning."""
        (tmp_path / "bad.spdx.json").write_text("not json{{{")
        valid = {
            "spdxVersion": "SPDX-2.2",
            "name": "good-pkg",
            "packages": [{"versionInfo": "1.0"}],
        }
        (tmp_path / "good-pkg.spdx.json").write_text(json.dumps(valid))

        packages = discover_packages(str(tmp_path))
        assert len(packages) == 1
        assert packages[0].name == "good-pkg"
