"""Tests for the ConanSource enrichment data source."""

from unittest.mock import Mock, patch

import pytest
import requests
from packageurl import PackageURL

from sbomify_action._enrichment.sources.conan import ConanSource, clear_cache


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Clear the cache before each test to ensure isolation."""
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def mock_session():
    """Create a mock requests session (not used by ConanSource but required by protocol)."""
    return Mock(spec=requests.Session)


class TestConanSourceBasics:
    """Test basic properties of ConanSource."""

    def test_source_name(self):
        """Test that the source name is correct."""
        source = ConanSource()
        assert source.name == "conan.io"

    def test_source_priority(self):
        """Test that the source has Tier 1 priority."""
        source = ConanSource()
        assert source.priority == 10  # Tier 1: Native sources

    def test_supports_conan_packages(self):
        """Test that ConanSource supports conan packages."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")
        assert source.supports(purl) is True

    def test_supports_conan_without_version(self):
        """Test that ConanSource supports conan packages without version."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/boost")
        assert source.supports(purl) is True

    def test_does_not_support_pypi(self):
        """Test that ConanSource does not support PyPI packages."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")
        assert source.supports(purl) is False

    def test_does_not_support_npm(self):
        """Test that ConanSource does not support npm packages."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:npm/lodash@4.17.21")
        assert source.supports(purl) is False

    def test_does_not_support_cargo(self):
        """Test that ConanSource does not support cargo packages."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:cargo/serde@1.0.0")
        assert source.supports(purl) is False

    def test_does_not_support_deb(self):
        """Test that ConanSource does not support deb packages."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is False


class TestConanSourceFetchMocked:
    """Test fetch functionality of ConanSource with mocked Conan API."""

    def test_fetch_conan_not_available(self, mock_session):
        """Test graceful handling when Conan library is not available."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")

        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=None):
            metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_profiles_not_available(self, mock_session):
        """Test graceful handling when profiles are not available."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")

        mock_api = Mock()
        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=mock_api):
            with patch("sbomify_action._enrichment.sources.conan._get_profiles", return_value=None):
                metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_success_with_mocked_graph(self, mock_session):
        """Test successful metadata fetch with mocked graph response."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")

        # Create mock conanfile
        mock_conanfile = Mock()
        mock_conanfile.name = "zlib"
        mock_conanfile.license = "Zlib"
        mock_conanfile.description = "A Massively Spiffy Yet Delicately Unobtrusive Compression Library"
        mock_conanfile.homepage = "https://zlib.net"
        mock_conanfile.url = "https://github.com/conan-io/conan-center-index"
        mock_conanfile.topics = ("zlib", "compression")
        mock_conanfile.author = None

        # Create mock node
        mock_node = Mock()
        mock_node.conanfile = mock_conanfile

        # Create mock graph
        mock_graph = Mock()
        mock_graph.nodes = [mock_node]

        # Create mock API
        mock_api = Mock()
        mock_api.remotes.list.return_value = []
        mock_api.graph.load_graph_requires.return_value = mock_graph

        mock_profiles = (Mock(), Mock())

        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=mock_api):
            with patch("sbomify_action._enrichment.sources.conan._get_profiles", return_value=mock_profiles):
                metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.licenses == ["Zlib"]
        assert metadata.description == "A Massively Spiffy Yet Delicately Unobtrusive Compression Library"
        assert metadata.homepage == "https://zlib.net"
        assert "github.com/conan-io/conan-center-index" in metadata.repository_url
        assert metadata.registry_url == "https://conan.io/center/recipes/zlib"
        assert metadata.source == "conan.io"

    def test_fetch_success_with_tuple_license(self, mock_session):
        """Test handling of tuple license (multiple licenses)."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/mbedtls@3.6.4")

        mock_conanfile = Mock()
        mock_conanfile.name = "mbedtls"
        mock_conanfile.license = ("Apache-2.0", "GPL-2.0-or-later")
        mock_conanfile.description = "mbed TLS"
        mock_conanfile.homepage = "https://tls.mbed.org"
        mock_conanfile.url = None
        mock_conanfile.topics = None
        mock_conanfile.author = None

        mock_node = Mock()
        mock_node.conanfile = mock_conanfile

        mock_graph = Mock()
        mock_graph.nodes = [mock_node]

        mock_api = Mock()
        mock_api.remotes.list.return_value = []
        mock_api.graph.load_graph_requires.return_value = mock_graph

        mock_profiles = (Mock(), Mock())

        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=mock_api):
            with patch("sbomify_action._enrichment.sources.conan._get_profiles", return_value=mock_profiles):
                metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.licenses == ["Apache-2.0", "GPL-2.0-or-later"]

    def test_fetch_package_not_found(self, mock_session):
        """Test handling when package is not found in Conan Center."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/nonexistent-package@1.0.0")

        mock_api = Mock()
        mock_api.remotes.list.return_value = []
        mock_api.graph.load_graph_requires.side_effect = Exception("Package not found")

        mock_profiles = (Mock(), Mock())

        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=mock_api):
            with patch("sbomify_action._enrichment.sources.conan._get_profiles", return_value=mock_profiles):
                metadata = source.fetch(purl, mock_session)

        assert metadata is None

    def test_fetch_with_author(self, mock_session):
        """Test that author is preserved as maintainer_name."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/testpkg@1.0.0")

        mock_conanfile = Mock()
        mock_conanfile.name = "testpkg"
        mock_conanfile.license = "MIT"
        mock_conanfile.description = "Test package"
        mock_conanfile.homepage = "https://example.com"
        mock_conanfile.url = None
        mock_conanfile.topics = None
        mock_conanfile.author = "Test Author"

        mock_node = Mock()
        mock_node.conanfile = mock_conanfile

        mock_graph = Mock()
        mock_graph.nodes = [mock_node]

        mock_api = Mock()
        mock_api.remotes.list.return_value = []
        mock_api.graph.load_graph_requires.return_value = mock_graph

        mock_profiles = (Mock(), Mock())

        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=mock_api):
            with patch("sbomify_action._enrichment.sources.conan._get_profiles", return_value=mock_profiles):
                metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        # Supplier is always the distribution platform
        assert metadata.supplier == "Conan Center"
        # Author is preserved as maintainer_name
        assert metadata.maintainer_name == "Test Author"


class TestConanSourceCaching:
    """Test caching behavior of ConanSource."""

    def test_cache_hit(self, mock_session):
        """Test that repeated requests use cache."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")

        mock_conanfile = Mock()
        mock_conanfile.name = "zlib"
        mock_conanfile.license = "Zlib"
        mock_conanfile.description = "Compression library"
        mock_conanfile.homepage = "https://zlib.net"
        mock_conanfile.url = None
        mock_conanfile.topics = None
        mock_conanfile.author = None

        mock_node = Mock()
        mock_node.conanfile = mock_conanfile

        mock_graph = Mock()
        mock_graph.nodes = [mock_node]

        mock_api = Mock()
        mock_api.remotes.list.return_value = []
        mock_api.graph.load_graph_requires.return_value = mock_graph

        mock_profiles = (Mock(), Mock())

        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=mock_api):
            with patch("sbomify_action._enrichment.sources.conan._get_profiles", return_value=mock_profiles):
                # First fetch
                metadata1 = source.fetch(purl, mock_session)
                # Second fetch (should use cache)
                metadata2 = source.fetch(purl, mock_session)

        assert metadata1 is not None
        assert metadata2 is not None
        assert metadata1.description == metadata2.description
        # API should only be called once
        assert mock_api.graph.load_graph_requires.call_count == 1

    def test_cache_cleared(self, mock_session):
        """Test that clear_cache() works."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")

        mock_conanfile = Mock()
        mock_conanfile.name = "zlib"
        mock_conanfile.license = "Zlib"
        mock_conanfile.description = "Compression library"
        mock_conanfile.homepage = "https://zlib.net"
        mock_conanfile.url = None
        mock_conanfile.topics = None
        mock_conanfile.author = None

        mock_node = Mock()
        mock_node.conanfile = mock_conanfile

        mock_graph = Mock()
        mock_graph.nodes = [mock_node]

        mock_api = Mock()
        mock_api.remotes.list.return_value = []
        mock_api.graph.load_graph_requires.return_value = mock_graph

        mock_profiles = (Mock(), Mock())

        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=mock_api):
            with patch("sbomify_action._enrichment.sources.conan._get_profiles", return_value=mock_profiles):
                # First fetch
                source.fetch(purl, mock_session)
                # Clear cache
                clear_cache()
                # Second fetch (should not use cache)
                source.fetch(purl, mock_session)

        # API should be called twice (cache was cleared)
        assert mock_api.graph.load_graph_requires.call_count == 2


class TestConanSourceFieldSources:
    """Test field_sources attribution in ConanSource."""

    def test_field_sources_populated(self, mock_session):
        """Test that field_sources is populated correctly."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")

        mock_conanfile = Mock()
        mock_conanfile.name = "zlib"
        mock_conanfile.license = "Zlib"
        mock_conanfile.description = "Compression library"
        mock_conanfile.homepage = "https://zlib.net"
        mock_conanfile.url = "https://github.com/conan-io/conan-center-index"
        mock_conanfile.topics = ("zlib", "compression")
        mock_conanfile.author = None

        mock_node = Mock()
        mock_node.conanfile = mock_conanfile

        mock_graph = Mock()
        mock_graph.nodes = [mock_node]

        mock_api = Mock()
        mock_api.remotes.list.return_value = []
        mock_api.graph.load_graph_requires.return_value = mock_graph

        mock_profiles = (Mock(), Mock())

        with patch("sbomify_action._enrichment.sources.conan._get_conan_api", return_value=mock_api):
            with patch("sbomify_action._enrichment.sources.conan._get_profiles", return_value=mock_profiles):
                metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        assert metadata.field_sources.get("description") == "conan.io"
        assert metadata.field_sources.get("licenses") == "conan.io"
        assert metadata.field_sources.get("homepage") == "conan.io"
        assert metadata.field_sources.get("repository_url") == "conan.io"


class TestConanSourceRegistration:
    """Test ConanSource registration in the enrichment registry."""

    def test_registered_in_default_registry(self):
        """Test that ConanSource is in the default registry."""
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")

        sources = registry.get_sources_for(purl)

        # ConanSource should be in the list
        source_names = [s.name for s in sources]
        assert "conan.io" in source_names

        # ConanSource should have Tier 1 priority
        conan_source = next(s for s in sources if s.name == "conan.io")
        assert conan_source.priority == 10

    def test_priority_over_depsdev(self):
        """Test that ConanSource has priority over DepsDevSource for conan."""
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")

        sources = registry.get_sources_for(purl)

        # Find both sources
        source_dict = {s.name: s for s in sources}
        assert "conan.io" in source_dict

        # conan.io should have lower priority number (= higher priority) than aggregators
        # Note: deps.dev doesn't support conan, so just verify conan.io priority
        assert source_dict["conan.io"].priority == 10


# Integration tests - these make real network calls to Conan Center
# Mark with @pytest.mark.slow so they can be skipped in quick test runs
class TestConanSourceIntegration:
    """Integration tests for ConanSource with real Conan Center lookups.

    These tests use the packages from tests/test-data/conan.lock:
    - mbedtls/3.6.4 (Apache-2.0)
    - cjson/1.7.18 (MIT)
    """

    @pytest.mark.slow
    def test_integration_zlib(self):
        """Integration test with real zlib package."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/zlib@1.3.1")
        metadata = source.fetch(purl, requests.Session())

        assert metadata is not None
        assert metadata.licenses == ["Zlib"]
        assert metadata.description is not None
        assert "compression" in metadata.description.lower() or "zlib" in metadata.description.lower()
        assert metadata.homepage == "https://zlib.net"
        assert metadata.source == "conan.io"

    @pytest.mark.slow
    def test_integration_mbedtls_from_conan_lock(self):
        """Integration test with real mbedtls package from conan.lock test data."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/mbedtls@3.6.4")
        metadata = source.fetch(purl, requests.Session())

        assert metadata is not None
        assert metadata.licenses  # Should have license
        assert "Apache-2.0" in metadata.licenses[0] or "Apache" in str(metadata.licenses)
        assert metadata.description is not None
        assert metadata.homepage is not None

    @pytest.mark.slow
    def test_integration_cjson_from_conan_lock(self):
        """Integration test with real cjson package from conan.lock test data."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/cjson@1.7.18")
        metadata = source.fetch(purl, requests.Session())

        assert metadata is not None
        assert "MIT" in metadata.licenses
        assert metadata.description is not None
        assert metadata.homepage is not None

    @pytest.mark.slow
    def test_integration_nonexistent_package(self):
        """Integration test with nonexistent package."""
        source = ConanSource()
        purl = PackageURL.from_string("pkg:conan/this-package-definitely-does-not-exist@99.99.99")
        metadata = source.fetch(purl, requests.Session())

        assert metadata is None
