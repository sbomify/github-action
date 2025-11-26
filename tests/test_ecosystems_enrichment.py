"""
Tests for ecosyste.ms API enrichment functionality.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from sbomify_action.enrichment import (
    USER_AGENT,
    _enrich_cyclonedx_component,
    _enrich_sbom_with_metadata,
    _enrich_spdx_package,
    _extract_components_from_sbom,
    _fetch_package_metadata,
    enrich_sbom_with_ecosystems,
)


class TestUserAgent(unittest.TestCase):
    """Test User-Agent header configuration."""

    def test_user_agent_format(self):
        """Test that User-Agent header has the correct format."""
        # Should be in format: sbomify-github-action/VERSION (hello@sbomify.com)
        self.assertIn("sbomify-github-action/", USER_AGENT)
        self.assertIn("(hello@sbomify.com)", USER_AGENT)
        # Version should not be empty
        parts = USER_AGENT.split("/")
        self.assertEqual(len(parts), 2)
        version_part = parts[1].split(" ")[0]
        self.assertNotEqual(version_part, "")


class TestComponentExtraction(unittest.TestCase):
    """Test extraction of components from SBOMs."""

    def test_extract_cyclonedx_components(self):
        """Test extracting components from CycloneDX SBOM."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"},
                {"name": "requests", "version": "2.32.0", "purl": "pkg:pypi/requests@2.32.0"},
                {"name": "no-purl", "version": "1.0.0"},  # Should be skipped
            ],
        }

        components = _extract_components_from_sbom(sbom)

        self.assertEqual(len(components), 2)
        self.assertEqual(components[0]["purl"], "pkg:pypi/django@5.1")
        self.assertEqual(components[0]["name"], "django")
        self.assertEqual(components[1]["purl"], "pkg:pypi/requests@2.32.0")

    def test_extract_spdx_components(self):
        """Test extracting components from SPDX SBOM."""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "django",
                    "versionInfo": "5.1",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/django@5.1"}],
                },
                {
                    "name": "requests",
                    "versionInfo": "2.32.0",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.32.0"}],
                },
                {
                    "name": "no-purl",
                    "versionInfo": "1.0.0",
                    "externalRefs": [],  # Should be skipped
                },
            ],
        }

        components = _extract_components_from_sbom(sbom)

        self.assertEqual(len(components), 2)
        self.assertEqual(components[0]["purl"], "pkg:pypi/django@5.1")
        self.assertEqual(components[0]["name"], "django")

    def test_extract_empty_sbom(self):
        """Test extracting from empty SBOM."""
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}

        components = _extract_components_from_sbom(sbom)

        self.assertEqual(len(components), 0)


class TestFetchMetadata(unittest.TestCase):
    """Test fetching metadata from ecosyste.ms API."""

    @patch("sbomify_action.enrichment.requests.Session")
    def test_fetch_successful(self, mock_session_class):
        """Test successful metadata fetch (API returns array)."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        # ecosyste.ms API returns an array of results
        mock_response.json.return_value = [
            {
                "name": "django",
                "description": "A high-level Python web framework",
                "licenses": "BSD-3-Clause",
                "homepage": "https://www.djangoproject.com/",
                "repository_url": "https://github.com/django/django",
                "language": "Python",
                "keywords_array": ["web", "framework", "django"],
            }
        ]
        mock_session.get.return_value = mock_response

        metadata = _fetch_package_metadata("pkg:pypi/django@5.1", mock_session)

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata["name"], "django")
        self.assertEqual(metadata["licenses"], "BSD-3-Clause")
        mock_session.get.assert_called_once()

    @patch("sbomify_action.enrichment.requests.Session")
    def test_fetch_not_found(self, mock_session_class):
        """Test handling 404 response."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response

        metadata = _fetch_package_metadata("pkg:pypi/nonexistent@1.0.0", mock_session)

        self.assertIsNone(metadata)

    @patch("sbomify_action.enrichment.requests.Session")
    def test_fetch_timeout(self, mock_session_class):
        """Test handling timeout."""
        import requests

        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.Timeout("Timeout")

        metadata = _fetch_package_metadata("pkg:pypi/django@5.1", mock_session)

        self.assertIsNone(metadata)

    @patch("sbomify_action.enrichment.requests.Session")
    def test_fetch_request_exception(self, mock_session_class):
        """Test handling request exceptions."""
        import requests

        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.RequestException("Connection error")

        metadata = _fetch_package_metadata("pkg:pypi/django@5.1", mock_session)

        self.assertIsNone(metadata)


class TestCycloneDXEnrichment(unittest.TestCase):
    """Test enrichment of CycloneDX components."""

    def test_enrich_with_description(self):
        """Test adding description to component."""
        component = {"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}

        metadata = {"description": "A high-level Python web framework"}

        enriched, added_fields = _enrich_cyclonedx_component(component, metadata)

        self.assertEqual(enriched["description"], "A high-level Python web framework")
        self.assertIn("description", added_fields)

    def test_enrich_preserves_existing_description(self):
        """Test that existing description is preserved."""
        component = {
            "name": "django",
            "version": "5.1",
            "purl": "pkg:pypi/django@5.1",
            "description": "Existing description",
        }

        metadata = {"description": "New description"}

        enriched, added_fields = _enrich_cyclonedx_component(component, metadata)

        self.assertEqual(enriched["description"], "Existing description")
        self.assertNotIn("description", added_fields)

    def test_enrich_with_licenses(self):
        """Test adding licenses to component."""
        component = {"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}

        metadata = {"licenses": "BSD-3-Clause"}

        enriched, added_fields = _enrich_cyclonedx_component(component, metadata)

        self.assertIn("licenses", enriched)
        self.assertEqual(len(enriched["licenses"]), 1)
        self.assertEqual(enriched["licenses"][0]["license"]["id"], "BSD-3-Clause")

    def test_enrich_with_multiple_licenses(self):
        """Test adding multiple licenses (comma-separated)."""
        component = {"name": "test", "version": "1.0", "purl": "pkg:pypi/test@1.0"}

        metadata = {"licenses": "MIT, Apache-2.0"}

        enriched, added_fields = _enrich_cyclonedx_component(component, metadata)

        self.assertEqual(len(enriched["licenses"]), 2)
        self.assertEqual(enriched["licenses"][0]["license"]["id"], "MIT")
        self.assertEqual(enriched["licenses"][1]["license"]["id"], "Apache-2.0")

    def test_enrich_preserves_existing_licenses(self):
        """Test that existing licenses are preserved."""
        component = {
            "name": "django",
            "version": "5.1",
            "purl": "pkg:pypi/django@5.1",
            "licenses": [{"license": {"id": "MIT"}}],
        }

        metadata = {"licenses": "BSD-3-Clause"}

        enriched, added_fields = _enrich_cyclonedx_component(component, metadata)

        # Should keep existing license
        self.assertEqual(enriched["licenses"][0]["license"]["id"], "MIT")

    def test_enrich_with_homepage(self):
        """Test adding homepage as external reference."""
        component = {"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}

        metadata = {"homepage": "https://www.djangoproject.com/"}

        enriched, added_fields = _enrich_cyclonedx_component(component, metadata)

        self.assertIn("externalReferences", enriched)
        website_refs = [ref for ref in enriched["externalReferences"] if ref["type"] == "website"]
        self.assertEqual(len(website_refs), 1)
        self.assertEqual(website_refs[0]["url"], "https://www.djangoproject.com/")

    def test_enrich_with_repository(self):
        """Test adding repository as external reference."""
        component = {"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}

        metadata = {"repository_url": "https://github.com/django/django"}

        enriched, added_fields = _enrich_cyclonedx_component(component, metadata)

        self.assertIn("externalReferences", enriched)
        vcs_refs = [ref for ref in enriched["externalReferences"] if ref["type"] == "vcs"]
        self.assertEqual(len(vcs_refs), 1)
        self.assertEqual(vcs_refs[0]["url"], "https://github.com/django/django")

    def test_enrich_with_properties(self):
        """Test that properties (language, keywords) are NOT added (not in native CycloneDX spec)."""
        component = {"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}

        metadata = {"language": "Python", "keywords_array": ["web", "framework", "django"]}

        enriched, added_fields = _enrich_cyclonedx_component(component, metadata)

        # We no longer add custom properties like language/keywords as they're not native CycloneDX fields
        self.assertNotIn("properties", enriched)

    def test_enrich_with_no_metadata(self):
        """Test that component is unchanged when metadata is None."""
        component = {"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}

        enriched, added_fields = _enrich_cyclonedx_component(component, None)

        self.assertEqual(enriched, component)
        self.assertEqual(added_fields, [])


class TestSPDXEnrichment(unittest.TestCase):
    """Test enrichment of SPDX packages."""

    def test_enrich_with_description(self):
        """Test adding description to SPDX package."""
        package = {"name": "django", "versionInfo": "5.1", "description": "NOASSERTION"}

        metadata = {"description": "A high-level Python web framework"}

        enriched, added_fields = _enrich_spdx_package(package, metadata)

        self.assertEqual(enriched["description"], "A high-level Python web framework")

    def test_enrich_preserves_existing_description(self):
        """Test that existing description is preserved."""
        package = {"name": "django", "versionInfo": "5.1", "description": "Existing description"}

        metadata = {"description": "New description"}

        enriched, added_fields = _enrich_spdx_package(package, metadata)

        self.assertEqual(enriched["description"], "Existing description")

    def test_enrich_with_homepage(self):
        """Test adding homepage to SPDX package."""
        package = {"name": "django", "versionInfo": "5.1", "homepage": "NOASSERTION"}

        metadata = {"homepage": "https://www.djangoproject.com/"}

        enriched, added_fields = _enrich_spdx_package(package, metadata)

        self.assertEqual(enriched["homepage"], "https://www.djangoproject.com/")

    def test_enrich_with_download_location(self):
        """Test adding download location from repository."""
        package = {"name": "django", "versionInfo": "5.1", "downloadLocation": "NOASSERTION"}

        metadata = {"repository_url": "https://github.com/django/django"}

        enriched, added_fields = _enrich_spdx_package(package, metadata)

        self.assertEqual(enriched["downloadLocation"], "https://github.com/django/django")

    def test_enrich_with_licenses(self):
        """Test adding licenses to SPDX package."""
        package = {"name": "django", "versionInfo": "5.1", "licenseDeclared": "NOASSERTION"}

        metadata = {"licenses": "BSD-3-Clause"}

        enriched, added_fields = _enrich_spdx_package(package, metadata)

        self.assertEqual(enriched["licenseDeclared"], "BSD-3-Clause")

    def test_enrich_with_no_metadata(self):
        """Test that package is unchanged when metadata is None."""
        package = {"name": "django", "versionInfo": "5.1"}

        enriched, added_fields = _enrich_spdx_package(package, None)

        self.assertEqual(enriched, package)
        self.assertEqual(added_fields, [])


class TestSBOMEnrichment(unittest.TestCase):
    """Test full SBOM enrichment."""

    def test_enrich_cyclonedx_sbom(self):
        """Test enriching a CycloneDX SBOM."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"},
                {"name": "requests", "version": "2.32.0", "purl": "pkg:pypi/requests@2.32.0"},
            ],
        }

        metadata_map = {
            "pkg:pypi/django@5.1": {"description": "Django framework", "licenses": "BSD-3-Clause"},
            "pkg:pypi/requests@2.32.0": {"description": "HTTP library", "licenses": "Apache-2.0"},
        }

        enriched, stats = _enrich_sbom_with_metadata(sbom, metadata_map)

        self.assertEqual(enriched["components"][0]["description"], "Django framework")
        self.assertEqual(enriched["components"][1]["description"], "HTTP library")

    def test_enrich_spdx_sbom(self):
        """Test enriching an SPDX SBOM."""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "django",
                    "versionInfo": "5.1",
                    "description": "NOASSERTION",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/django@5.1"}],
                }
            ],
        }

        metadata_map = {"pkg:pypi/django@5.1": {"description": "Django framework"}}

        enriched, stats = _enrich_sbom_with_metadata(sbom, metadata_map)

        self.assertEqual(enriched["packages"][0]["description"], "Django framework")


class TestEndToEndEnrichment(unittest.TestCase):
    """Test end-to-end enrichment workflow."""

    @patch("sbomify_action.enrichment.requests.Session")
    def test_enrich_sbom_file(self, mock_session_class):
        """Test enriching an SBOM file end-to-end."""
        # Create a temporary SBOM file
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "django", "version": "5.1", "purl": "pkg:pypi/django@5.1"}],
        }

        # Mock API response (API returns array)
        mock_session = Mock()
        # Make the mock session support context manager protocol
        mock_session.__enter__ = Mock(return_value=mock_session)
        mock_session.__exit__ = Mock(return_value=False)
        mock_session_class.return_value = mock_session
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "description": "Django framework",
                "licenses": "BSD-3-Clause",
                "homepage": "https://djangoproject.com",
            }
        ]
        mock_session.get.return_value = mock_response

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as input_f:
            json.dump(sbom_data, input_f)
            input_file = input_f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as output_f:
            output_file = output_f.name

        try:
            # Run enrichment
            enrich_sbom_with_ecosystems(input_file, output_file)

            # Verify output
            with open(output_file, "r") as f:
                enriched_data = json.load(f)

            self.assertEqual(enriched_data["components"][0]["description"], "Django framework")
            self.assertIn("licenses", enriched_data["components"][0])

            # Verify API was called with correct User-Agent
            mock_session.headers.update.assert_called_once()
            call_args = mock_session.headers.update.call_args[0][0]
            self.assertIn("User-Agent", call_args)
            self.assertIn("sbomify-github-action", call_args["User-Agent"])

        finally:
            os.unlink(input_file)
            os.unlink(output_file)

    def test_enrich_missing_file(self):
        """Test handling of missing input file."""
        with self.assertRaises(FileNotFoundError):
            enrich_sbom_with_ecosystems("nonexistent.json", "output.json")

    def test_enrich_invalid_json(self):
        """Test handling of invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json{]")
            input_file = f.name

        try:
            with self.assertRaises(ValueError):
                enrich_sbom_with_ecosystems(input_file, "output.json")
        finally:
            os.unlink(input_file)

    @patch("sbomify_action.enrichment.requests.Session")
    def test_enrich_sbom_without_purls(self, mock_session_class):
        """Test enriching SBOM with no components having PURLs."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "django", "version": "5.1"}],  # No PURL
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as input_f:
            json.dump(sbom_data, input_f)
            input_file = input_f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as output_f:
            output_file = output_f.name

        try:
            # Should complete without errors but not call API
            enrich_sbom_with_ecosystems(input_file, output_file)

            # Verify output file exists and is valid
            with open(output_file, "r") as f:
                output_data = json.load(f)

            self.assertEqual(output_data, sbom_data)

            # Verify API was not called
            self.assertFalse(mock_session_class.called)

        finally:
            os.unlink(input_file)
            os.unlink(output_file)


if __name__ == "__main__":
    unittest.main()
