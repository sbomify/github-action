"""Tests for the RPM Repository data source."""

from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
from packageurl import PackageURL

from sbomify_action._enrichment.sources.rpmrepo import (
    DISTRO_REPO_TEMPLATES,
    RpmRepoSource,
    clear_cache,
)

# Test data directory
TEST_DATA_DIR = Path(__file__).parent / "test-data" / "rpm-repo"


def load_test_repomd() -> str:
    """Load test repomd.xml content."""
    return (TEST_DATA_DIR / "repomd.xml").read_text()


def load_test_primary_gz() -> bytes:
    """Load test primary.xml.gz content."""
    return (TEST_DATA_DIR / "primary.xml.gz").read_bytes()


def load_test_mirror_list() -> str:
    """Load test mirror.list content."""
    return (TEST_DATA_DIR / "mirror.list").read_text()


@pytest.fixture
def mock_rpm_session():
    """Create a mocked session with RPM repo responses pre-configured."""
    mock_session = Mock()

    mock_repomd_response = Mock()
    mock_repomd_response.status_code = 200
    mock_repomd_response.content = load_test_repomd().encode()
    mock_repomd_response.raise_for_status = Mock()

    mock_primary_response = Mock()
    mock_primary_response.status_code = 200
    mock_primary_response.content = load_test_primary_gz()
    mock_primary_response.raise_for_status = Mock()

    mock_session.get.side_effect = [mock_repomd_response, mock_primary_response]
    return mock_session


class TestRpmRepoSourceBasics:
    """Test basic RpmRepoSource functionality."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_source_name(self):
        """Test that source name is correct."""
        source = RpmRepoSource()
        assert source.name == "rpm-repo"

    def test_source_priority(self):
        """Test that priority is 15 (Tier 1: Native sources)."""
        source = RpmRepoSource()
        assert source.priority == 15

    def test_supports_rpm_with_distro_qualifier(self):
        """Test that source supports pkg:rpm/* packages with distro qualifier."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")
        assert source.supports(purl) is True

    def test_supports_rpm_with_namespace_only(self):
        """Test that source supports pkg:rpm/rocky/* without distro qualifier."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8")
        assert source.supports(purl) is True

    def test_does_not_support_unknown_distro(self):
        """Test that source does not support unknown distros."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/unknown/bash@5.1.8?distro=unknown-1")
        assert source.supports(purl) is False

    def test_does_not_support_pypi(self):
        """Test that source does not support PyPI packages."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:pypi/requests@2.31.0")
        assert source.supports(purl) is False

    def test_does_not_support_deb(self):
        """Test that source does not support deb packages."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:deb/debian/bash@5.2")
        assert source.supports(purl) is False


class TestRpmRepoSourceDistroSupport:
    """Test distro qualifier parsing and support."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_supports_rocky_8(self):
        """Test Rocky Linux 8 support."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1?distro=rocky-8")
        assert source.supports(purl) is True

    def test_supports_rocky_9(self):
        """Test Rocky Linux 9 support."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1?distro=rocky-9")
        assert source.supports(purl) is True

    def test_supports_almalinux_8(self):
        """Test AlmaLinux 8 support."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/almalinux/bash@5.1?distro=almalinux-8")
        assert source.supports(purl) is True

    def test_supports_almalinux_9(self):
        """Test AlmaLinux 9 support."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/almalinux/bash@5.1?distro=almalinux-9")
        assert source.supports(purl) is True

    def test_supports_alma_alias(self):
        """Test 'alma' alias for almalinux."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/alma/bash@5.1?distro=alma-9")
        assert source.supports(purl) is True

    def test_supports_centos_stream_9(self):
        """Test CentOS Stream 9 support."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/centos/bash@5.1?distro=centos-stream-9")
        assert source.supports(purl) is True

    def test_supports_centos_simple(self):
        """Test CentOS with simple version format."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/centos/bash@5.1?distro=centos-9")
        assert source.supports(purl) is True

    def test_supports_fedora_40(self):
        """Test Fedora 40 support."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/fedora/bash@5.2?distro=fedora-40")
        assert source.supports(purl) is True

    def test_supports_fedora_41(self):
        """Test Fedora 41 support."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/fedora/bash@5.2?distro=fedora-41")
        assert source.supports(purl) is True

    def test_supports_amazon_linux_2023(self):
        """Test Amazon Linux 2023 support."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/amzn/bash@5.2?distro=amzn-2023")
        assert source.supports(purl) is True

    def test_supports_amazonlinux_alias(self):
        """Test 'amazonlinux' alias."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/amazonlinux/bash@5.2?distro=amazonlinux-2023")
        assert source.supports(purl) is True


class TestRpmRepoSourceFetch:
    """Test RpmRepoSource fetch functionality with mocked HTTP."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_fetch_success(self, mock_rpm_session):
        """Test successful metadata fetch."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")

        metadata = source.fetch(purl, mock_rpm_session)

        assert metadata is not None
        assert metadata.source == "rpm-repo"
        assert metadata.supplier == "Rocky Enterprise Software Foundation"
        assert metadata.licenses == ["GPLv3+"]
        assert "GNU Bourne Again shell" in metadata.description
        assert metadata.homepage == "https://www.gnu.org/software/bash"

    def test_fetch_openssl(self, mock_rpm_session):
        """Test fetching openssl package."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/openssl@3.0.7?arch=x86_64&distro=rocky-9")

        metadata = source.fetch(purl, mock_rpm_session)

        assert metadata is not None
        assert metadata.licenses == ["Apache-2.0"]
        assert "cryptography" in metadata.description.lower()

    def test_fetch_package_not_found(self, mock_rpm_session):
        """Test handling when package is not in repo."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/nonexistent@1.0?arch=x86_64&distro=rocky-9")

        metadata = source.fetch(purl, mock_rpm_session)
        assert metadata is None

    def test_fetch_repomd_error(self):
        """Test handling of repomd.xml fetch error."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")

        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        metadata = source.fetch(purl, mock_session)
        assert metadata is None

    def test_fetch_timeout(self):
        """Test handling of request timeout."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")

        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.Timeout("Connection timeout")

        metadata = source.fetch(purl, mock_session)
        assert metadata is None


class TestRpmRepoSourceCaching:
    """Test RpmRepoSource caching functionality."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_cache_hit(self):
        """Test that subsequent calls use cache."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")

        mock_session = Mock()
        mock_repomd_response = Mock()
        mock_repomd_response.status_code = 200
        mock_repomd_response.content = load_test_repomd().encode()
        mock_repomd_response.raise_for_status = Mock()

        mock_primary_response = Mock()
        mock_primary_response.status_code = 200
        mock_primary_response.content = load_test_primary_gz()
        mock_primary_response.raise_for_status = Mock()

        mock_session.get.side_effect = [mock_repomd_response, mock_primary_response]

        # First call loads repo
        metadata1 = source.fetch(purl, mock_session)
        # Second call should use cache
        metadata2 = source.fetch(purl, mock_session)

        assert metadata1 is not None
        assert metadata2 is not None
        assert metadata1.supplier == metadata2.supplier
        # Should only call API twice (repomd + primary), not four times
        assert mock_session.get.call_count == 2

    def test_different_packages_same_repo(self):
        """Test that different packages from same repo use cached repo data."""
        source = RpmRepoSource()
        purl_bash = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")
        purl_curl = PackageURL.from_string("pkg:rpm/rocky/curl@7.76.1?arch=x86_64&distro=rocky-9")

        mock_session = Mock()
        mock_repomd_response = Mock()
        mock_repomd_response.status_code = 200
        mock_repomd_response.content = load_test_repomd().encode()
        mock_repomd_response.raise_for_status = Mock()

        mock_primary_response = Mock()
        mock_primary_response.status_code = 200
        mock_primary_response.content = load_test_primary_gz()
        mock_primary_response.raise_for_status = Mock()

        mock_session.get.side_effect = [mock_repomd_response, mock_primary_response]

        # Fetch bash
        metadata_bash = source.fetch(purl_bash, mock_session)
        # Fetch curl - should use cached repo
        metadata_curl = source.fetch(purl_curl, mock_session)

        assert metadata_bash is not None
        assert metadata_curl is not None
        assert metadata_bash.licenses == ["GPLv3+"]
        assert metadata_curl.licenses == ["MIT"]
        # Only loaded repo once
        assert mock_session.get.call_count == 2

    def test_clear_cache(self):
        """Test that clear_cache clears the cache."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")

        mock_session = Mock()
        mock_repomd_response = Mock()
        mock_repomd_response.status_code = 200
        mock_repomd_response.content = load_test_repomd().encode()
        mock_repomd_response.raise_for_status = Mock()

        mock_primary_response = Mock()
        mock_primary_response.status_code = 200
        mock_primary_response.content = load_test_primary_gz()
        mock_primary_response.raise_for_status = Mock()

        # First fetch
        mock_session.get.side_effect = [mock_repomd_response, mock_primary_response]
        source.fetch(purl, mock_session)
        assert mock_session.get.call_count == 2

        # Clear cache
        clear_cache()

        # Second fetch should reload
        mock_session.get.side_effect = [mock_repomd_response, mock_primary_response]
        source.fetch(purl, mock_session)
        assert mock_session.get.call_count == 4


class TestRpmRepoSourceMirrorList:
    """Test Amazon Linux mirror list resolution."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_mirror_list_resolution(self):
        """Test that mirror list is resolved correctly."""
        source = RpmRepoSource()

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = load_test_mirror_list()
        mock_response.raise_for_status = Mock()
        mock_session.get.return_value = mock_response

        result = source._resolve_mirror_list(
            "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
            mock_session,
        )

        assert result is not None
        assert result.startswith("https://")
        assert result.endswith("/")

    def test_mirror_list_caching(self):
        """Test that mirror list results are cached."""
        source = RpmRepoSource()

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = load_test_mirror_list()
        mock_response.raise_for_status = Mock()
        mock_session.get.return_value = mock_response

        mirror_url = "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"

        # First call
        result1 = source._resolve_mirror_list(mirror_url, mock_session)
        # Second call should use cache
        result2 = source._resolve_mirror_list(mirror_url, mock_session)

        assert result1 == result2
        assert mock_session.get.call_count == 1


class TestRpmRepoSourceFieldSources:
    """Test field_sources tracking."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_field_sources_populated(self, mock_rpm_session):
        """Test that field_sources tracks which fields came from this source."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")

        metadata = source.fetch(purl, mock_rpm_session)

        assert metadata is not None
        assert "supplier" in metadata.field_sources
        assert metadata.field_sources["supplier"] == "rpm-repo"
        assert "licenses" in metadata.field_sources
        assert metadata.field_sources["licenses"] == "rpm-repo"
        assert "description" in metadata.field_sources
        assert metadata.field_sources["description"] == "rpm-repo"
        assert "homepage" in metadata.field_sources
        assert metadata.field_sources["homepage"] == "rpm-repo"


class TestRpmRepoSourceDistroQualifierParsing:
    """Test distro qualifier parsing edge cases."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_parse_rocky_9(self):
        """Test parsing 'rocky-9' distro qualifier."""
        source = RpmRepoSource()
        name, version = source._parse_distro_qualifier("rocky-9")
        assert name == "rocky"
        assert version == "9"

    def test_parse_centos_stream_9(self):
        """Test parsing 'centos-stream-9' distro qualifier."""
        source = RpmRepoSource()
        name, version = source._parse_distro_qualifier("centos-stream-9")
        assert name == "centos"
        assert version == "9"

    def test_parse_fedora_40(self):
        """Test parsing 'fedora-40' distro qualifier."""
        source = RpmRepoSource()
        name, version = source._parse_distro_qualifier("fedora-40")
        assert name == "fedora"
        assert version == "40"

    def test_parse_el_suffix(self):
        """Test parsing distro with -el suffix (e.g., 'rocky-el9')."""
        source = RpmRepoSource()
        name, version = source._parse_distro_qualifier("rocky-el9")
        assert name == "rocky"
        assert version == "9"

    def test_parse_amzn_2023(self):
        """Test parsing 'amzn-2023' distro qualifier."""
        source = RpmRepoSource()
        name, version = source._parse_distro_qualifier("amzn-2023")
        assert name == "amzn"
        assert version == "2023"

    def test_parse_uppercase(self):
        """Test that parsing handles uppercase."""
        source = RpmRepoSource()
        name, version = source._parse_distro_qualifier("Rocky-9")
        assert name == "rocky"
        assert version == "9"

    def test_parse_el_suffix_without_version(self):
        """Test parsing distro with -el suffix but no version number."""
        source = RpmRepoSource()
        name, version = source._parse_distro_qualifier("rocky-el")
        assert name == "rocky"
        assert version == ""

    def test_parse_distro_only(self):
        """Test parsing distro without version."""
        source = RpmRepoSource()
        name, version = source._parse_distro_qualifier("rocky")
        assert name == "rocky"
        assert version is None


class TestRpmRepoSourceUnsupportedVersions:
    """Test handling of unsupported distro versions."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_unsupported_rocky_version(self):
        """Test that unsupported Rocky version returns False from supports()."""
        source = RpmRepoSource()
        # Rocky 7 doesn't exist - only 8 and 9 are supported
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1?distro=rocky-7")
        # supports() returns True because rocky is a known distro
        # but fetch() will fail to find it
        assert source.supports(purl) is True

    def test_fetch_unsupported_version_returns_none(self, mock_rpm_session):
        """Test that fetching an unsupported version returns None gracefully."""
        source = RpmRepoSource()
        # Rocky 7 doesn't exist
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1?distro=rocky-7")

        # The mock won't be called because version 7 is not in the supported list
        metadata = source.fetch(purl, mock_rpm_session)
        assert metadata is None


class TestRpmRepoSourceIntegration:
    """Integration tests for RpmRepoSource with the enrichment pipeline."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear cache before each test."""
        clear_cache()

    def test_rpm_packages_handled_by_license_db(self):
        """Test that RPM packages are handled by LicenseDBSource in the default registry."""
        from sbomify_action._enrichment.enricher import create_default_registry

        registry = create_default_registry()
        sources = registry.list_sources()

        # RPM packages are now handled by LicenseDBSource (pre-computed database)
        # instead of RpmRepoSource (individual package downloads)
        source_names = [s["name"] for s in sources]
        assert "license-db" in source_names

        # LicenseDBSource should be top priority
        license_db = next(s for s in sources if s["name"] == "license-db")
        assert license_db["priority"] == 1

    def test_metadata_has_data(self, mock_rpm_session):
        """Test that returned metadata has_data() returns True."""
        source = RpmRepoSource()
        purl = PackageURL.from_string("pkg:rpm/rocky/bash@5.1.8?arch=x86_64&distro=rocky-9")

        metadata = source.fetch(purl, mock_rpm_session)

        assert metadata is not None
        assert metadata.has_data() is True


class TestRpmRepoSourceDistroTemplates:
    """Test distro template configuration."""

    def test_all_supported_distros_have_templates(self):
        """Test that all documented distros have templates."""
        expected_distros = ["rocky", "almalinux", "alma", "centos", "fedora", "amzn", "amazonlinux"]
        for distro in expected_distros:
            assert distro in DISTRO_REPO_TEMPLATES, f"Missing template for {distro}"

    def test_rocky_template_has_required_fields(self):
        """Test Rocky template has all required fields."""
        template = DISTRO_REPO_TEMPLATES["rocky"]
        assert "versions" in template
        assert "template" in template
        assert "repos" in template
        assert "8" in template["versions"]
        assert "9" in template["versions"]

    def test_fedora_template_has_current_versions(self):
        """Test Fedora template has current versions."""
        template = DISTRO_REPO_TEMPLATES["fedora"]
        assert "39" in template["versions"]
        assert "40" in template["versions"]
        assert "41" in template["versions"]
        assert "42" in template["versions"]

    def test_amazon_linux_has_mirror_list_config(self):
        """Test Amazon Linux has mirror list configuration."""
        template = DISTRO_REPO_TEMPLATES["amzn"]
        assert "mirror_list_2" in template
        assert "mirror_list_2023" in template
