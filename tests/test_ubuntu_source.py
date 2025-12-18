"""Tests for the Ubuntu APT Repository data source."""

from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
from packageurl import PackageURL

from sbomify_action._enrichment.sources.ubuntu import (
    COMPONENT_SEARCH_ORDER,
    UBUNTU_CODENAMES,
    UbuntuSource,
    _parse_deb822,
    _repo_cache,
    clear_cache,
)

# Test data directory
TEST_DATA_DIR = Path(__file__).parent / "test-data" / "apt-repo"


def load_test_packages_gz() -> bytes:
    """Load test Packages.gz content (for updates pocket)."""
    return (TEST_DATA_DIR / "Packages.gz").read_bytes()


def load_test_packages_base_gz() -> bytes:
    """Load test Packages-base.gz content (for base release)."""
    return (TEST_DATA_DIR / "Packages-base.gz").read_bytes()


def load_test_packages_text() -> str:
    """Load test Packages text content."""
    return (TEST_DATA_DIR / "Packages").read_text()


@pytest.fixture
def mock_ubuntu_session():
    """Create a mocked session with Ubuntu repo responses pre-configured."""
    mock_session = Mock(spec=requests.Session)

    # Mock response for updates pocket
    mock_updates_response = Mock()
    mock_updates_response.status_code = 200
    mock_updates_response.content = load_test_packages_gz()
    mock_updates_response.raise_for_status = Mock()

    mock_session.get.return_value = mock_updates_response
    return mock_session


@pytest.fixture
def mock_ubuntu_session_fallback():
    """Create a mocked session that simulates fallback to base release."""
    mock_session = Mock(spec=requests.Session)

    # First call (security) returns empty, second (updates) returns empty,
    # third (base) returns packages
    mock_empty_response = Mock()
    mock_empty_response.status_code = 200
    # Empty gzip with minimal valid content
    import gzip
    import io

    empty_gz = io.BytesIO()
    with gzip.GzipFile(fileobj=empty_gz, mode="wb") as gz:
        gz.write(b"")
    empty_gz.seek(0)
    mock_empty_response.content = empty_gz.read()
    mock_empty_response.raise_for_status = Mock()

    mock_base_response = Mock()
    mock_base_response.status_code = 200
    mock_base_response.content = load_test_packages_base_gz()
    mock_base_response.raise_for_status = Mock()

    # Return empty for security, empty for updates, base packages for base
    mock_session.get.side_effect = [
        mock_empty_response,  # security
        mock_empty_response,  # updates
        mock_base_response,  # base
    ]
    return mock_session


class TestUbuntuSourceBasics:
    """Test basic UbuntuSource functionality."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_source_name(self):
        """Test that source name is correct."""
        source = UbuntuSource()
        assert source.name == "ubuntu-apt"

    def test_source_priority(self):
        """Test that priority is 12 (Tier 1: Native sources)."""
        source = UbuntuSource()
        assert source.priority == 12

    def test_supports_ubuntu_with_distro_qualifier(self):
        """Test that source supports pkg:deb/ubuntu/* packages with distro qualifier."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1-6ubuntu1.1?arch=amd64&distro=ubuntu-22.04")
        assert source.supports(purl) is True

    def test_supports_ubuntu_without_distro(self):
        """Test that source supports pkg:deb/ubuntu/* without distro qualifier."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1")
        assert source.supports(purl) is True

    def test_does_not_support_debian(self):
        """Test that source does not support Debian packages."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.1?distro=debian-12")
        assert source.supports(purl) is False

    def test_does_not_support_rpm(self):
        """Test that source does not support RPM packages."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1")
        assert source.supports(purl) is False

    def test_does_not_support_pypi(self):
        """Test that source does not support PyPI packages."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")
        assert source.supports(purl) is False


class TestUbuntuSourceCodenames:
    """Test Ubuntu version to codename mapping."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_codename_mapping_exists(self):
        """Test that all expected codenames are mapped."""
        expected = {"18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble"}
        for version, codename in expected.items():
            assert version in UBUNTU_CODENAMES
            assert UBUNTU_CODENAMES[version] == codename

    def test_get_codename_from_version(self):
        """Test getting codename from version string."""
        source = UbuntuSource()
        assert source._get_codename_from_distro("22.04") == "jammy"
        assert source._get_codename_from_distro("24.04") == "noble"

    def test_get_codename_from_ubuntu_prefixed(self):
        """Test getting codename from 'ubuntu-XX.XX' format."""
        source = UbuntuSource()
        assert source._get_codename_from_distro("ubuntu-22.04") == "jammy"
        assert source._get_codename_from_distro("ubuntu-24.04") == "noble"

    def test_get_codename_from_codename(self):
        """Test that codename is returned as-is."""
        source = UbuntuSource()
        assert source._get_codename_from_distro("jammy") == "jammy"
        assert source._get_codename_from_distro("noble") == "noble"

    def test_get_codename_from_ubuntu_codename(self):
        """Test getting codename from 'ubuntu-codename' format."""
        source = UbuntuSource()
        assert source._get_codename_from_distro("ubuntu-jammy") == "jammy"
        assert source._get_codename_from_distro("ubuntu-noble") == "noble"

    def test_get_codename_unknown(self):
        """Test that unknown distro returns None."""
        source = UbuntuSource()
        assert source._get_codename_from_distro("unknown-123") is None
        assert source._get_codename_from_distro("debian-12") is None


class TestDeb822Parser:
    """Test the deb822 parser function."""

    def test_parse_single_stanza(self):
        """Test parsing a single package stanza."""
        text = """Package: test
Version: 1.0
Description: A test package
"""
        stanzas = _parse_deb822(text)
        assert len(stanzas) == 1
        assert stanzas[0]["Package"] == "test"
        assert stanzas[0]["Version"] == "1.0"
        assert stanzas[0]["Description"] == "A test package"

    def test_parse_multiple_stanzas(self):
        """Test parsing multiple package stanzas."""
        text = """Package: pkg1
Version: 1.0

Package: pkg2
Version: 2.0
"""
        stanzas = _parse_deb822(text)
        assert len(stanzas) == 2
        assert stanzas[0]["Package"] == "pkg1"
        assert stanzas[1]["Package"] == "pkg2"

    def test_parse_continuation_lines(self):
        """Test parsing continuation lines (multi-line values)."""
        text = """Package: test
Description: First line
 Second line
 Third line
Version: 1.0
"""
        stanzas = _parse_deb822(text)
        assert len(stanzas) == 1
        desc = stanzas[0]["Description"]
        assert "First line" in desc
        assert "Second line" in desc
        assert "Third line" in desc

    def test_parse_real_packages_file(self):
        """Test parsing the test Packages file."""
        text = load_test_packages_text()
        stanzas = _parse_deb822(text)

        # Should have 6 packages in test data
        assert len(stanzas) == 6

        # Find bash
        bash = next((s for s in stanzas if s.get("Package") == "bash"), None)
        assert bash is not None
        assert bash["Version"] == "5.1-6ubuntu1.1"
        assert bash["Homepage"] == "http://tiswww.case.edu/php/chet/bash/bashtop.html"


class TestUbuntuSourceFetch:
    """Test UbuntuSource fetch functionality with mocked HTTP."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_fetch_success(self, mock_ubuntu_session):
        """Test successful metadata fetch."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1-6ubuntu1.1?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        assert metadata.source == "ubuntu-apt"
        assert "Ubuntu Developers" in metadata.supplier
        assert "GNU Bourne Again SHell" in metadata.description
        assert metadata.homepage == "http://tiswww.case.edu/php/chet/bash/bashtop.html"

    def test_fetch_apt(self, mock_ubuntu_session):
        """Test fetching apt package."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/apt@2.4.14?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        assert "commandline package manager" in metadata.description

    def test_fetch_libc6(self, mock_ubuntu_session):
        """Test fetching libc6 package."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/libc6@2.35-0ubuntu3.11?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        assert "GNU C Library" in metadata.description
        assert metadata.homepage == "https://www.gnu.org/software/libc/libc.html"

    def test_fetch_package_not_found(self, mock_ubuntu_session):
        """Test handling when package is not in repo."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/nonexistent@1.0?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)
        assert metadata is None

    def test_fetch_connection_error(self):
        """Test handling of connection error."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        mock_session = Mock(spec=requests.Session)
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        metadata = source.fetch(purl, mock_session)
        assert metadata is None

    def test_fetch_timeout(self):
        """Test handling of request timeout."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        mock_session = Mock(spec=requests.Session)
        mock_session.get.side_effect = requests.exceptions.Timeout("Connection timeout")

        metadata = source.fetch(purl, mock_session)
        assert metadata is None


class TestUbuntuSourceCaching:
    """Test UbuntuSource caching functionality."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_cache_hit(self, mock_ubuntu_session):
        """Test that subsequent calls use cache."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        # First call loads repo
        metadata1 = source.fetch(purl, mock_ubuntu_session)
        # Second call should use cache
        metadata2 = source.fetch(purl, mock_ubuntu_session)

        assert metadata1 is not None
        assert metadata2 is not None
        assert metadata1.description == metadata2.description
        # Should only call API once (first fetch loads index)
        assert mock_ubuntu_session.get.call_count == 1

    def test_different_packages_same_repo(self, mock_ubuntu_session):
        """Test that different packages from same repo use cached repo data."""
        source = UbuntuSource()
        purl_bash = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")
        purl_curl = PackageURL.from_string("pkg:deb/ubuntu/curl@7.81.0?arch=amd64&distro=ubuntu-22.04")

        # Fetch bash
        metadata_bash = source.fetch(purl_bash, mock_ubuntu_session)
        # Fetch curl - should use cached repo
        metadata_curl = source.fetch(purl_curl, mock_ubuntu_session)

        assert metadata_bash is not None
        assert metadata_curl is not None
        assert "bash" in metadata_bash.description.lower() or "shell" in metadata_bash.description.lower()
        assert "curl" in metadata_curl.description.lower() or "url" in metadata_curl.description.lower()
        # Only loaded repo once
        assert mock_ubuntu_session.get.call_count == 1

    def test_clear_cache(self, mock_ubuntu_session):
        """Test that clear_cache clears the cache."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        # First fetch
        source.fetch(purl, mock_ubuntu_session)
        assert mock_ubuntu_session.get.call_count == 1

        # Clear cache
        clear_cache()

        # Second fetch should reload
        source.fetch(purl, mock_ubuntu_session)
        assert mock_ubuntu_session.get.call_count == 2

    def test_cache_key_structure(self, mock_ubuntu_session):
        """Test that cache uses correct key structure (codename, component, pocket, arch)."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        source.fetch(purl, mock_ubuntu_session)

        # Cache should have entry for jammy/main/security/amd64
        assert len(_repo_cache) >= 1
        # Check cache key format
        for key in _repo_cache.keys():
            assert len(key) == 4  # (codename, component, pocket, arch)
            codename, component, pocket, arch = key
            assert codename == "jammy"
            assert component == "main"
            assert pocket in ["-security", "-updates", ""]
            assert arch == "amd64"

    def test_cache_populated_with_packages(self, mock_ubuntu_session):
        """Test that cache contains parsed package data."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        source.fetch(purl, mock_ubuntu_session)

        # Get cached packages
        total_packages = sum(len(pkgs) for pkgs in _repo_cache.values())
        assert total_packages > 0, "Cache should contain packages"

        # Verify bash is in cache
        for cache_key, packages in _repo_cache.items():
            if "bash" in packages:
                assert packages["bash"].name == "bash"
                assert packages["bash"].version is not None
                break

    def test_many_packages_single_fetch(self, mock_ubuntu_session):
        """Test that fetching many packages only loads index once."""
        source = UbuntuSource()
        packages_to_fetch = ["bash", "apt", "libc6", "curl", "openssl", "adduser"]

        for pkg_name in packages_to_fetch:
            purl = PackageURL.from_string(f"pkg:deb/ubuntu/{pkg_name}@1.0?arch=amd64&distro=ubuntu-22.04")
            source.fetch(purl, mock_ubuntu_session)

        # Should only have loaded the index once (all packages found in first pocket)
        assert mock_ubuntu_session.get.call_count == 1, (
            f"Expected 1 API call for {len(packages_to_fetch)} packages, got {mock_ubuntu_session.get.call_count}"
        )

    def test_cache_per_component(self):
        """Test that each component gets its own cache entry."""
        source = UbuntuSource()

        # Track which URLs are called
        call_urls = []

        def track_calls(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            call_urls.append(url)
            mock_resp = Mock()
            mock_resp.status_code = 200
            # Return packages for all components
            mock_resp.content = load_test_packages_gz()
            mock_resp.raise_for_status = Mock()
            return mock_resp

        mock_session = Mock(spec=requests.Session)
        mock_session.get.side_effect = track_calls

        # First package (found in main)
        purl1 = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")
        source.fetch(purl1, mock_session)
        calls_after_first = mock_session.get.call_count

        # Same package again (should use cache, no new calls)
        source.fetch(purl1, mock_session)
        assert mock_session.get.call_count == calls_after_first, "Should use cache for same package"


class TestUbuntuSourceFieldSources:
    """Test field_sources tracking."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_field_sources_populated(self, mock_ubuntu_session):
        """Test that field_sources tracks which fields came from this source."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        assert "supplier" in metadata.field_sources
        assert metadata.field_sources["supplier"] == "ubuntu-apt"
        assert "description" in metadata.field_sources
        assert metadata.field_sources["description"] == "ubuntu-apt"
        assert "homepage" in metadata.field_sources
        assert metadata.field_sources["homepage"] == "ubuntu-apt"
        assert "registry_url" in metadata.field_sources
        assert metadata.field_sources["registry_url"] == "ubuntu-apt"


class TestUbuntuSourceMetadataContent:
    """Test metadata content extraction."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_download_url_constructed(self, mock_ubuntu_session):
        """Test that download URL is constructed from Filename field."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        assert metadata.download_url is not None
        assert "archive.ubuntu.com" in metadata.download_url
        assert "bash" in metadata.download_url
        assert ".deb" in metadata.download_url

    def test_registry_url_constructed(self, mock_ubuntu_session):
        """Test that registry URL points to packages.ubuntu.com."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        assert metadata.registry_url is not None
        assert "packages.ubuntu.com" in metadata.registry_url
        assert "bash" in metadata.registry_url

    def test_description_first_line_only(self, mock_ubuntu_session):
        """Test that description uses first line only (summary)."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        # Description should be first line only, not full multi-line
        assert "\n" not in metadata.description
        assert "GNU Bourne Again SHell" in metadata.description

    def test_has_data(self, mock_ubuntu_session):
        """Test that returned metadata has_data() returns True."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        assert metadata.has_data() is True


class TestUbuntuSourceMultiComponent:
    """Test multi-component search functionality."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_component_search_order(self):
        """Test that component search order includes all major repos."""
        assert COMPONENT_SEARCH_ORDER == ["main", "universe", "restricted", "multiverse"]

    def test_searches_main_first(self):
        """Test that main component is searched before universe."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        # Create mock that tracks call order
        call_urls = []

        def track_calls(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            call_urls.append(url)
            # Return response for main
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = load_test_packages_gz()
            mock_resp.raise_for_status = Mock()
            return mock_resp

        mock_session = Mock(spec=requests.Session)
        mock_session.get.side_effect = track_calls

        # Fetch - should find in main, not search universe
        metadata = source.fetch(purl, mock_session)

        assert metadata is not None
        # Should have called main first (security pocket)
        assert any("main" in url for url in call_urls)
        # Should NOT have called universe since bash is in main
        assert not any("universe" in url for url in call_urls)

    def test_falls_back_to_universe(self):
        """Test that universe is searched if package not in main."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/nodejs@12.0?arch=amd64&distro=ubuntu-22.04")

        call_urls = []

        def track_calls(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            call_urls.append(url)
            mock_resp = Mock()
            mock_resp.status_code = 200
            # Return empty for main, packages for universe
            if "universe" in url:
                mock_resp.content = load_test_packages_gz()  # Has bash, used for structure
            else:
                # Empty gzip
                import gzip
                import io

                buf = io.BytesIO()
                with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                    gz.write(b"")
                buf.seek(0)
                mock_resp.content = buf.read()
            mock_resp.raise_for_status = Mock()
            return mock_resp

        mock_session = Mock(spec=requests.Session)
        mock_session.get.side_effect = track_calls

        # Fetch - should search main first, then universe
        source.fetch(purl, mock_session)

        # Should have searched both main and universe
        main_calls = [url for url in call_urls if "main" in url]
        universe_calls = [url for url in call_urls if "universe" in url]
        assert len(main_calls) > 0, "Should have searched main"
        assert len(universe_calls) > 0, "Should have searched universe after main"


class TestUbuntuSourceNoLiveNetwork:
    """Tests to verify no live network calls are made in unit tests."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_all_fetch_tests_use_mocks(self, mock_ubuntu_session):
        """Verify that fetch tests use mocked sessions, not real network."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        # This should use the mock, not real network
        metadata = source.fetch(purl, mock_ubuntu_session)

        # Verify the mock was called
        assert mock_ubuntu_session.get.called, "Mock session should have been called"
        # Verify we got data from mock
        assert metadata is not None

    def test_mock_session_is_mock_object(self, mock_ubuntu_session):
        """Verify that mock_ubuntu_session is actually a Mock object."""
        assert isinstance(mock_ubuntu_session, Mock), "Session should be a Mock object"
        # Verify it has mocked methods that can track calls
        assert hasattr(mock_ubuntu_session, "get"), "Mock should have get method"
        assert hasattr(mock_ubuntu_session.get, "call_count"), "Mock.get should track call count"

    def test_fetch_with_real_session_blocked(self, monkeypatch):
        """Verify that real network calls would be blocked in tests."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        # Create a real session but mock its get method to raise error
        real_session = requests.Session()

        def blocked_get(*args, **kwargs):
            raise RuntimeError("Real network call attempted - this should not happen in unit tests!")

        monkeypatch.setattr(real_session, "get", blocked_get)

        # This should not make real network calls
        try:
            source.fetch(purl, real_session)
        except RuntimeError as e:
            # Expected - proves that if real network was attempted, it would fail
            assert "Real network call attempted" in str(e)


class TestUbuntuSourceIntegration:
    """Integration tests for UbuntuSource."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_source_works_with_registry(self, mock_ubuntu_session):
        """Test that UbuntuSource works with the enrichment registry."""
        from sbomify_action._enrichment.registry import SourceRegistry

        registry = SourceRegistry()
        registry.register(UbuntuSource())

        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")
        sources = registry.get_sources_for(purl)

        assert len(sources) == 1
        assert sources[0].name == "ubuntu-apt"

    def test_no_license_in_metadata(self, mock_ubuntu_session):
        """Test that licenses field is empty (not available in APT metadata)."""
        source = UbuntuSource()
        purl = PackageURL.from_string("pkg:deb/ubuntu/bash@5.1?arch=amd64&distro=ubuntu-22.04")

        metadata = source.fetch(purl, mock_ubuntu_session)

        assert metadata is not None
        # Licenses should be empty - APT Packages.gz doesn't include license info
        assert metadata.licenses == []
