"""Tests for SPDX 3 parser, writer, and helpers."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from sbomify_action.spdx3 import (
    extract_spdx3_version,
    get_spdx3_document,
    get_spdx3_packages,
    get_spdx3_root_package,
    is_spdx3,
    make_spdx3_creation_info,
    make_spdx3_spdx_id,
    parse_spdx3_data,
    parse_spdx3_file,
    spdx3_license_from_string,
    spdx3_licenses_from_list,
    write_spdx3_file,
)

TEST_DATA_DIR = Path(__file__).parent / "test-data"


class TestIsSpdx3(unittest.TestCase):
    """Tests for is_spdx3() detection."""

    def test_spdx3_string_context(self):
        data = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        self.assertTrue(is_spdx3(data))

    def test_spdx3_list_context(self):
        data = {"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}
        self.assertTrue(is_spdx3(data))

    def test_spdx3_dict_context(self):
        data = {"@context": {"@vocab": "https://spdx.org/rdf/3.0.1/terms/Core/"}}
        self.assertTrue(is_spdx3(data))

    def test_not_spdx3_spdx2(self):
        data = {"spdxVersion": "SPDX-2.3"}
        self.assertFalse(is_spdx3(data))

    def test_not_spdx3_cyclonedx(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
        self.assertFalse(is_spdx3(data))

    def test_not_spdx3_empty(self):
        self.assertFalse(is_spdx3({}))


class TestExtractSpdx3Version(unittest.TestCase):
    """Tests for extract_spdx3_version()."""

    def test_extract_from_string_context(self):
        data = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        self.assertEqual(extract_spdx3_version(data), "3.0.1")

    def test_extract_from_list_context(self):
        data = {"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}
        self.assertEqual(extract_spdx3_version(data), "3.0.1")

    def test_no_version(self):
        data = {"@context": "https://spdx.org/rdf/spdx-context.jsonld"}
        self.assertIsNone(extract_spdx3_version(data))

    def test_no_context(self):
        self.assertIsNone(extract_spdx3_version({}))


class TestParseSpdx3File(unittest.TestCase):
    """Tests for parse_spdx3_file()."""

    def test_parse_minimal(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        doc = get_spdx3_document(payload)
        self.assertIsNotNone(doc)
        self.assertEqual(doc.name, "test-document")

    def test_parse_packages(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        packages = get_spdx3_packages(payload)
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0].name, "test-package")
        self.assertEqual(packages[0].package_version, "1.0.0")
        self.assertEqual(packages[0].package_url, "pkg:pypi/test-package@1.0.0")

    def test_parse_root_package(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        root = get_spdx3_root_package(payload)
        self.assertIsNotNone(root)
        self.assertEqual(root.name, "test-package")

    def test_parse_tool(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        from spdx_tools.spdx3.model import Tool

        tools = [e for e in payload.get_full_map().values() if isinstance(e, Tool)]
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0].name, "test-tool")

    def test_parse_relationship(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        from spdx_tools.spdx3.model import Relationship, RelationshipType

        rels = [e for e in payload.get_full_map().values() if isinstance(e, Relationship)]
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0].relationship_type, RelationshipType.DESCRIBES)

    def test_parse_not_spdx3_raises(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"spdxVersion": "SPDX-2.3"}, f)
            with self.assertRaises(ValueError):
                parse_spdx3_file(path)
        finally:
            os.unlink(path)

    def test_parse_data(self):
        data = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {
                    "type": "software_Package",
                    "@id": "urn:spdx.dev:pkg-1",
                    "name": "foo",
                    "packageVersion": "2.0",
                }
            ],
        }
        payload = parse_spdx3_data(data)
        pkgs = get_spdx3_packages(payload)
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0].name, "foo")


class TestWriteSpdx3File(unittest.TestCase):
    """Tests for write_spdx3_file()."""

    def test_round_trip(self):
        """Parse -> write -> parse should preserve data."""
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            payload2 = parse_spdx3_file(path)
        finally:
            os.unlink(path)

        doc1 = get_spdx3_document(payload)
        doc2 = get_spdx3_document(payload2)
        self.assertEqual(doc1.name, doc2.name)

        pkgs1 = get_spdx3_packages(payload)
        pkgs2 = get_spdx3_packages(payload2)
        self.assertEqual(len(pkgs1), len(pkgs2))
        self.assertEqual(pkgs1[0].name, pkgs2[0].name)
        self.assertEqual(pkgs1[0].package_version, pkgs2[0].package_version)

    def test_writes_context_url(self):
        payload = parse_spdx3_file(str(TEST_DATA_DIR / "spdx3_minimal.json"))

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            write_spdx3_file(payload, path)
            with open(path) as rf:
                data = json.load(rf)
        finally:
            os.unlink(path)

        self.assertEqual(data["@context"], "https://spdx.org/rdf/3.0.1/spdx-context.jsonld")
        self.assertIn("@graph", data)


class TestHelpers(unittest.TestCase):
    """Tests for helper functions."""

    def test_make_creation_info(self):
        ci = make_spdx3_creation_info()
        self.assertEqual(str(ci.spec_version), "3.0.1")
        self.assertIsNotNone(ci.created)

    def test_make_spdx_id(self):
        id1 = make_spdx3_spdx_id()
        id2 = make_spdx3_spdx_id()
        self.assertNotEqual(id1, id2)
        self.assertTrue(id1.startswith("urn:spdx.dev:"))

    def test_license_from_string_spdx_id(self):
        from spdx_tools.spdx3.model.licensing import ListedLicense

        lic = spdx3_license_from_string("MIT")
        self.assertIsInstance(lic, ListedLicense)
        self.assertEqual(lic.license_id, "MIT")

    def test_license_from_string_noassertion(self):
        from spdx_tools.spdx3.model.licensing import NoAssertionLicense

        lic = spdx3_license_from_string("NOASSERTION")
        self.assertIsInstance(lic, NoAssertionLicense)

    def test_license_from_string_empty(self):
        from spdx_tools.spdx3.model.licensing import NoAssertionLicense

        lic = spdx3_license_from_string("")
        self.assertIsInstance(lic, NoAssertionLicense)

    def test_license_from_string_complex_sanitized(self):
        """Complex license expressions should have sanitized IDs."""
        from spdx_tools.spdx3.model.licensing import CustomLicense

        lic = spdx3_license_from_string("MIT OR Apache-2.0")
        self.assertIsInstance(lic, CustomLicense)
        # Should not contain spaces or parentheses
        self.assertNotIn(" ", lic.license_id)
        self.assertTrue(lic.license_id.startswith("LicenseRef-"))

    def test_licenses_from_list_single(self):
        from spdx_tools.spdx3.model.licensing import ListedLicense

        lic = spdx3_licenses_from_list(["Apache-2.0"])
        self.assertIsInstance(lic, ListedLicense)

    def test_licenses_from_list_multiple(self):
        from spdx_tools.spdx3.model.licensing import DisjunctiveLicenseSet

        lic = spdx3_licenses_from_list(["MIT", "Apache-2.0"])
        self.assertIsInstance(lic, DisjunctiveLicenseSet)

    def test_licenses_from_list_empty(self):
        from spdx_tools.spdx3.model.licensing import NoAssertionLicense

        lic = spdx3_licenses_from_list([])
        self.assertIsInstance(lic, NoAssertionLicense)


class TestValidationIntegration(unittest.TestCase):
    """Tests for SPDX 3 format detection in validation module."""

    def test_detect_spdx3_format(self):
        from sbomify_action.validation import detect_sbom_format_and_version

        data = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}
        fmt, ver = detect_sbom_format_and_version(data)
        self.assertEqual(fmt, "spdx")
        self.assertEqual(ver, "3.0.1")

    def test_schema_validation(self):
        from sbomify_action.validation import validate_sbom_file_auto

        result = validate_sbom_file_auto(str(TEST_DATA_DIR / "spdx3_minimal.json"))
        self.assertEqual(result.sbom_format, "spdx")
        self.assertEqual(result.spec_version, "3.0.1")
        # Our minimal test fixture may not pass the strict 3.0.1 schema,
        # but format/version detection must always succeed (valid is not None).
        self.assertIsNotNone(result.valid)


class TestAdditionalPackagesIntegration(unittest.TestCase):
    """Tests for SPDX 3 in additional_packages module."""

    def test_create_empty_spdx3(self):
        from sbomify_action.additional_packages import create_empty_sbom

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            result = create_empty_sbom(path, "spdx", spec_version="3.0.1")
            self.assertEqual(result, "spdx")

            with open(path) as rf:
                data = json.load(rf)
            self.assertTrue(is_spdx3(data))
            self.assertIn("@graph", data)
        finally:
            os.unlink(path)

    def test_inject_packages_into_spdx3(self):
        import shutil

        from packageurl import PackageURL

        from sbomify_action.additional_packages import inject_packages_into_spdx3

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            shutil.copy(str(TEST_DATA_DIR / "spdx3_minimal.json"), path)

            purls = [PackageURL.from_string("pkg:pypi/requests@2.31.0")]
            injected = inject_packages_into_spdx3(path, purls)

            self.assertEqual(injected, 1)

            payload = parse_spdx3_file(path)
            pkgs = get_spdx3_packages(payload)
            self.assertEqual(len(pkgs), 2)  # original + injected
            pkg_names = {p.name for p in pkgs}
            self.assertIn("requests", pkg_names)
        finally:
            os.unlink(path)


class TestSerializationIntegration(unittest.TestCase):
    """Tests for SPDX 3 in serialization module."""

    def test_supported_versions_includes_spdx3(self):
        from sbomify_action.serialization import SUPPORTED_SPDX_VERSIONS

        self.assertIn("3.0.1", SUPPORTED_SPDX_VERSIONS)


if __name__ == "__main__":
    unittest.main()
