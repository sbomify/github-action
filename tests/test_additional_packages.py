"""Tests for additional packages injection functionality."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from packageurl import PackageURL

from sbomify_action.additional_packages import (
    DEFAULT_PACKAGES_FILE,
    ENV_PACKAGES_FILE,
    ENV_PACKAGES_INLINE,
    SBOMIFY_SOURCE_PROPERTY,
    SBOMIFY_SOURCE_VALUE,
    get_additional_packages,
    inject_additional_packages,
    inject_packages_into_cyclonedx,
    inject_packages_into_spdx,
    parse_additional_packages_file,
    parse_purl,
    validate_purl,
)


class TestValidatePurl(unittest.TestCase):
    """Tests for PURL validation."""

    def test_valid_pypi_purl(self):
        """Test valid PyPI PURL."""
        self.assertTrue(validate_purl("pkg:pypi/requests@2.31.0"))

    def test_valid_npm_purl(self):
        """Test valid npm PURL."""
        self.assertTrue(validate_purl("pkg:npm/lodash@4.17.21"))

    def test_valid_deb_purl(self):
        """Test valid Debian PURL."""
        self.assertTrue(validate_purl("pkg:deb/debian/openssl@3.0.11"))

    def test_valid_purl_without_version(self):
        """Test valid PURL without version."""
        self.assertTrue(validate_purl("pkg:pypi/requests"))

    def test_valid_purl_with_namespace(self):
        """Test valid PURL with namespace."""
        self.assertTrue(validate_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0"))

    def test_invalid_purl_empty(self):
        """Test invalid empty PURL."""
        self.assertFalse(validate_purl(""))

    def test_invalid_purl_no_prefix(self):
        """Test invalid PURL without pkg: prefix."""
        self.assertFalse(validate_purl("pypi/requests@2.31.0"))

    def test_invalid_purl_malformed(self):
        """Test invalid malformed PURL."""
        self.assertFalse(validate_purl("pkg:"))
        self.assertFalse(validate_purl("pkg:pypi"))

    def test_invalid_purl_random_string(self):
        """Test invalid random string."""
        self.assertFalse(validate_purl("not a purl at all"))


class TestParsePurl(unittest.TestCase):
    """Tests for PURL parsing."""

    def test_parse_valid_purl(self):
        """Test parsing valid PURL."""
        purl = parse_purl("pkg:pypi/requests@2.31.0")
        self.assertIsNotNone(purl)
        self.assertEqual(purl.type, "pypi")
        self.assertEqual(purl.name, "requests")
        self.assertEqual(purl.version, "2.31.0")

    def test_parse_purl_with_namespace(self):
        """Test parsing PURL with namespace."""
        purl = parse_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
        self.assertIsNotNone(purl)
        self.assertEqual(purl.type, "maven")
        self.assertEqual(purl.namespace, "org.apache.commons")
        self.assertEqual(purl.name, "commons-lang3")
        self.assertEqual(purl.version, "3.12.0")

    def test_parse_purl_without_version(self):
        """Test parsing PURL without version."""
        purl = parse_purl("pkg:npm/lodash")
        self.assertIsNotNone(purl)
        self.assertEqual(purl.name, "lodash")
        self.assertIsNone(purl.version)

    def test_parse_invalid_purl(self):
        """Test parsing invalid PURL returns None."""
        self.assertIsNone(parse_purl("not a purl"))
        self.assertIsNone(parse_purl(""))


class TestParseAdditionalPackagesFile(unittest.TestCase):
    """Tests for file parsing."""

    def test_parse_simple_file(self):
        """Test parsing simple file with PURLs."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("pkg:pypi/requests@2.31.0\n")
            f.write("pkg:npm/lodash@4.17.21\n")
            f.flush()

            try:
                purls = parse_additional_packages_file(f.name)
                self.assertEqual(len(purls), 2)
                self.assertIn("pkg:pypi/requests@2.31.0", purls)
                self.assertIn("pkg:npm/lodash@4.17.21", purls)
            finally:
                os.unlink(f.name)

    def test_parse_file_with_comments(self):
        """Test parsing file with comments."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# This is a comment\n")
            f.write("pkg:pypi/requests@2.31.0\n")
            f.write("# Another comment\n")
            f.write("pkg:npm/lodash@4.17.21\n")
            f.flush()

            try:
                purls = parse_additional_packages_file(f.name)
                self.assertEqual(len(purls), 2)
                # Comments should be ignored
                self.assertNotIn("# This is a comment", purls)
            finally:
                os.unlink(f.name)

    def test_parse_file_with_empty_lines(self):
        """Test parsing file with empty lines."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("pkg:pypi/requests@2.31.0\n")
            f.write("\n")
            f.write("   \n")
            f.write("pkg:npm/lodash@4.17.21\n")
            f.flush()

            try:
                purls = parse_additional_packages_file(f.name)
                self.assertEqual(len(purls), 2)
            finally:
                os.unlink(f.name)

    def test_parse_file_with_whitespace(self):
        """Test parsing file with whitespace around PURLs."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("  pkg:pypi/requests@2.31.0  \n")
            f.write("\tpkg:npm/lodash@4.17.21\t\n")
            f.flush()

            try:
                purls = parse_additional_packages_file(f.name)
                self.assertEqual(len(purls), 2)
                self.assertIn("pkg:pypi/requests@2.31.0", purls)
                self.assertIn("pkg:npm/lodash@4.17.21", purls)
            finally:
                os.unlink(f.name)

    def test_parse_file_with_invalid_purls(self):
        """Test parsing file with invalid PURLs (warns but continues)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("pkg:pypi/requests@2.31.0\n")
            f.write("not a valid purl\n")
            f.write("pkg:npm/lodash@4.17.21\n")
            f.flush()

            try:
                purls = parse_additional_packages_file(f.name)
                # Only valid PURLs should be returned
                self.assertEqual(len(purls), 2)
            finally:
                os.unlink(f.name)

    def test_parse_nonexistent_file(self):
        """Test parsing nonexistent file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            parse_additional_packages_file("/nonexistent/path/to/file.txt")

    def test_parse_empty_file(self):
        """Test parsing empty file returns empty list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.flush()

            try:
                purls = parse_additional_packages_file(f.name)
                self.assertEqual(len(purls), 0)
            finally:
                os.unlink(f.name)


class TestGetAdditionalPackages(unittest.TestCase):
    """Tests for collecting packages from all sources."""

    def setUp(self):
        """Clear environment variables before each test."""
        for var in [ENV_PACKAGES_FILE, ENV_PACKAGES_INLINE]:
            if var in os.environ:
                del os.environ[var]

    def tearDown(self):
        """Clear environment variables after each test."""
        for var in [ENV_PACKAGES_FILE, ENV_PACKAGES_INLINE]:
            if var in os.environ:
                del os.environ[var]

    def test_no_sources_returns_empty(self):
        """Test with no sources returns empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("os.getcwd", return_value=tmpdir):
                purls = get_additional_packages()
                self.assertEqual(len(purls), 0)

    def test_default_file_in_cwd(self):
        """Test loading from default file in current working directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create default file
            default_file = Path(tmpdir) / DEFAULT_PACKAGES_FILE
            default_file.write_text("pkg:pypi/requests@2.31.0\n")

            with patch("os.getcwd", return_value=tmpdir):
                with patch.object(Path, "cwd", return_value=Path(tmpdir)):
                    # Need to patch Path.cwd() properly
                    original_cwd = Path.cwd

                    def mock_cwd():
                        return Path(tmpdir)

                    Path.cwd = staticmethod(mock_cwd)
                    try:
                        purls = get_additional_packages()
                        self.assertEqual(len(purls), 1)
                        self.assertIn("pkg:pypi/requests@2.31.0", purls)
                    finally:
                        Path.cwd = original_cwd

    def test_custom_file_via_env(self):
        """Test loading from custom file via environment variable."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("pkg:npm/lodash@4.17.21\n")
            f.flush()

            try:
                os.environ[ENV_PACKAGES_FILE] = f.name
                purls = get_additional_packages()
                self.assertEqual(len(purls), 1)
                self.assertIn("pkg:npm/lodash@4.17.21", purls)
            finally:
                os.unlink(f.name)

    def test_inline_packages_single(self):
        """Test loading single inline package."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0"
        purls = get_additional_packages()
        self.assertEqual(len(purls), 1)
        self.assertIn("pkg:pypi/requests@2.31.0", purls)

    def test_inline_packages_comma_separated(self):
        """Test loading comma-separated inline packages."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0,pkg:npm/lodash@4.17.21"
        purls = get_additional_packages()
        self.assertEqual(len(purls), 2)
        self.assertIn("pkg:pypi/requests@2.31.0", purls)
        self.assertIn("pkg:npm/lodash@4.17.21", purls)

    def test_inline_packages_newline_separated(self):
        """Test loading newline-separated inline packages."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0\npkg:npm/lodash@4.17.21"
        purls = get_additional_packages()
        self.assertEqual(len(purls), 2)

    def test_merge_and_deduplicate(self):
        """Test that packages from multiple sources are merged and deduplicated."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("pkg:pypi/requests@2.31.0\n")
            f.write("pkg:npm/lodash@4.17.21\n")
            f.flush()

            try:
                os.environ[ENV_PACKAGES_FILE] = f.name
                # Duplicate from inline
                os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0,pkg:cargo/serde@1.0.0"

                purls = get_additional_packages()
                # Should have 3 unique PURLs (duplicate removed)
                self.assertEqual(len(purls), 3)
                self.assertIn("pkg:pypi/requests@2.31.0", purls)
                self.assertIn("pkg:npm/lodash@4.17.21", purls)
                self.assertIn("pkg:cargo/serde@1.0.0", purls)
            finally:
                os.unlink(f.name)

    def test_invalid_inline_purls_skipped(self):
        """Test that invalid inline PURLs are skipped with warning."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0,invalid purl,pkg:npm/lodash@4.17.21"
        purls = get_additional_packages()
        self.assertEqual(len(purls), 2)


class TestInjectPackagesIntoCycloneDX(unittest.TestCase):
    """Tests for CycloneDX injection."""

    def test_inject_single_package(self):
        """Test injecting a single package."""
        bom = Bom()
        purls = ["pkg:pypi/requests@2.31.0"]

        count = inject_packages_into_cyclonedx(bom, purls)

        self.assertEqual(count, 1)
        self.assertEqual(len(bom.components), 1)

        component = list(bom.components)[0]
        self.assertEqual(component.name, "requests")
        self.assertEqual(component.version, "2.31.0")
        self.assertEqual(component.type, ComponentType.LIBRARY)
        self.assertEqual(str(component.purl), "pkg:pypi/requests@2.31.0")

    def test_inject_multiple_packages(self):
        """Test injecting multiple packages."""
        bom = Bom()
        purls = [
            "pkg:pypi/requests@2.31.0",
            "pkg:npm/lodash@4.17.21",
            "pkg:cargo/serde@1.0.0",
        ]

        count = inject_packages_into_cyclonedx(bom, purls)

        self.assertEqual(count, 3)
        self.assertEqual(len(bom.components), 3)

    def test_inject_package_without_version(self):
        """Test injecting package without version uses 'unknown'."""
        bom = Bom()
        purls = ["pkg:pypi/requests"]

        count = inject_packages_into_cyclonedx(bom, purls)

        self.assertEqual(count, 1)
        component = list(bom.components)[0]
        self.assertEqual(component.version, "unknown")

    def test_inject_adds_source_property(self):
        """Test that injected packages have source property."""
        bom = Bom()
        purls = ["pkg:pypi/requests@2.31.0"]

        inject_packages_into_cyclonedx(bom, purls)

        component = list(bom.components)[0]
        source_props = [p for p in component.properties if p.name == SBOMIFY_SOURCE_PROPERTY]
        self.assertEqual(len(source_props), 1)
        self.assertEqual(source_props[0].value, SBOMIFY_SOURCE_VALUE)

    def test_inject_skips_duplicates(self):
        """Test that duplicate PURLs are skipped."""
        bom = Bom()

        # Add existing component with same PURL
        existing = Component(
            name="requests",
            version="2.31.0",
            type=ComponentType.LIBRARY,
            purl=PackageURL.from_string("pkg:pypi/requests@2.31.0"),
        )
        bom.components.add(existing)

        purls = ["pkg:pypi/requests@2.31.0"]
        count = inject_packages_into_cyclonedx(bom, purls)

        self.assertEqual(count, 0)
        self.assertEqual(len(bom.components), 1)

    def test_inject_skips_invalid_purls(self):
        """Test that invalid PURLs are skipped."""
        bom = Bom()
        purls = ["not a valid purl", "pkg:pypi/requests@2.31.0"]

        count = inject_packages_into_cyclonedx(bom, purls)

        self.assertEqual(count, 1)
        self.assertEqual(len(bom.components), 1)


class TestInjectPackagesIntoSPDX(unittest.TestCase):
    """Tests for SPDX injection."""

    def _create_empty_spdx_document(self):
        """Create an empty SPDX document for testing."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="Test SBOM",
            document_namespace="https://example.com/test-sbom",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime.now(),
        )

        return Document(creation_info=creation_info)

    def test_inject_single_package(self):
        """Test injecting a single package."""
        document = self._create_empty_spdx_document()
        purls = ["pkg:pypi/requests@2.31.0"]

        count = inject_packages_into_spdx(document, purls)

        self.assertEqual(count, 1)
        self.assertEqual(len(document.packages), 1)

        package = document.packages[0]
        self.assertEqual(package.name, "requests")
        self.assertEqual(package.version, "2.31.0")
        self.assertIn(SBOMIFY_SOURCE_VALUE, package.comment)

    def test_inject_package_has_purl_external_ref(self):
        """Test that injected package has PURL external reference."""
        document = self._create_empty_spdx_document()
        purls = ["pkg:pypi/requests@2.31.0"]

        inject_packages_into_spdx(document, purls)

        package = document.packages[0]
        purl_refs = [r for r in package.external_references if r.reference_type == "purl"]
        self.assertEqual(len(purl_refs), 1)
        self.assertEqual(purl_refs[0].locator, "pkg:pypi/requests@2.31.0")

    def test_inject_package_without_version(self):
        """Test injecting package without version uses 'unknown'."""
        document = self._create_empty_spdx_document()
        purls = ["pkg:npm/lodash"]

        inject_packages_into_spdx(document, purls)

        package = document.packages[0]
        self.assertEqual(package.version, "unknown")

    def test_inject_generates_unique_spdx_ids(self):
        """Test that unique SPDX IDs are generated."""
        document = self._create_empty_spdx_document()
        purls = [
            "pkg:pypi/requests@2.31.0",
            "pkg:npm/lodash@4.17.21",
        ]

        inject_packages_into_spdx(document, purls)

        spdx_ids = [p.spdx_id for p in document.packages]
        self.assertEqual(len(spdx_ids), len(set(spdx_ids)))  # All unique

    def test_inject_skips_duplicate_purls(self):
        """Test that duplicate PURLs are skipped."""
        document = self._create_empty_spdx_document()

        # First injection
        inject_packages_into_spdx(document, ["pkg:pypi/requests@2.31.0"])

        # Try to inject same PURL again
        count = inject_packages_into_spdx(document, ["pkg:pypi/requests@2.31.0"])

        self.assertEqual(count, 0)
        self.assertEqual(len(document.packages), 1)


class TestInjectAdditionalPackages(unittest.TestCase):
    """Tests for main injection entry point."""

    def setUp(self):
        """Clear environment variables before each test."""
        for var in [ENV_PACKAGES_FILE, ENV_PACKAGES_INLINE]:
            if var in os.environ:
                del os.environ[var]

    def tearDown(self):
        """Clear environment variables after each test."""
        for var in [ENV_PACKAGES_FILE, ENV_PACKAGES_INLINE]:
            if var in os.environ:
                del os.environ[var]

    def test_no_packages_returns_zero(self):
        """Test with no packages returns 0."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, f)
            f.flush()

            try:
                count = inject_additional_packages(f.name)
                self.assertEqual(count, 0)
            finally:
                os.unlink(f.name)

    def test_inject_into_cyclonedx(self):
        """Test injecting into CycloneDX SBOM."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "version": 1,
                    "components": [],
                },
                f,
            )
            f.flush()

            try:
                count = inject_additional_packages(f.name)
                self.assertEqual(count, 1)

                # Verify file was updated
                with open(f.name, "r") as rf:
                    data = json.load(rf)
                    self.assertEqual(len(data.get("components", [])), 1)
                    self.assertEqual(data["components"][0]["name"], "requests")
            finally:
                os.unlink(f.name)

    def test_inject_into_spdx(self):
        """Test injecting into SPDX SBOM."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:npm/lodash@4.17.21"

        # Create minimal valid SPDX document
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Test SBOM",
            "dataLicense": "CC0-1.0",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: test"],
            },
            "packages": [],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(spdx_data, f)
            f.flush()

            try:
                count = inject_additional_packages(f.name)
                self.assertEqual(count, 1)

                # Verify file was updated
                with open(f.name, "r") as rf:
                    data = json.load(rf)
                    self.assertGreater(len(data.get("packages", [])), 0)
            finally:
                os.unlink(f.name)

    def test_nonexistent_file_returns_zero(self):
        """Test with nonexistent file returns 0."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0"
        count = inject_additional_packages("/nonexistent/file.json")
        self.assertEqual(count, 0)

    def test_invalid_json_returns_zero(self):
        """Test with invalid JSON returns 0."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json")
            f.flush()

            try:
                count = inject_additional_packages(f.name)
                self.assertEqual(count, 0)
            finally:
                os.unlink(f.name)

    def test_unknown_format_returns_zero(self):
        """Test with unknown SBOM format returns 0."""
        os.environ[ENV_PACKAGES_INLINE] = "pkg:pypi/requests@2.31.0"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"unknownFormat": True}, f)
            f.flush()

            try:
                count = inject_additional_packages(f.name)
                self.assertEqual(count, 0)
            finally:
                os.unlink(f.name)


class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def test_purl_with_qualifiers(self):
        """Test PURL with qualifiers is parsed correctly."""
        purl = parse_purl("pkg:deb/debian/openssl@3.0.11?arch=amd64")
        self.assertIsNotNone(purl)
        self.assertEqual(purl.name, "openssl")
        self.assertEqual(purl.qualifiers.get("arch"), "amd64")

    def test_purl_with_subpath(self):
        """Test PURL with subpath is parsed correctly."""
        purl = parse_purl("pkg:github/owner/repo@1.0.0#path/to/file")
        self.assertIsNotNone(purl)
        self.assertEqual(purl.subpath, "path/to/file")

    def test_file_with_only_comments(self):
        """Test file with only comments returns empty list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Comment 1\n")
            f.write("# Comment 2\n")
            f.write("# Comment 3\n")
            f.flush()

            try:
                purls = parse_additional_packages_file(f.name)
                self.assertEqual(len(purls), 0)
            finally:
                os.unlink(f.name)

    def test_inline_with_extra_whitespace(self):
        """Test inline packages with extra whitespace."""
        os.environ[ENV_PACKAGES_INLINE] = "  pkg:pypi/requests@2.31.0  ,  pkg:npm/lodash@4.17.21  "

        try:
            purls = get_additional_packages()
            self.assertEqual(len(purls), 2)
            self.assertIn("pkg:pypi/requests@2.31.0", purls)
            self.assertIn("pkg:npm/lodash@4.17.21", purls)
        finally:
            del os.environ[ENV_PACKAGES_INLINE]


if __name__ == "__main__":
    unittest.main()
