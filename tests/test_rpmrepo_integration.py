"""Integration tests for RPM Repository enrichment source.

These tests hit real RPM repositories and validate enrichment works
for each supported distro. They are marked as slow and can be skipped
with: pytest -m "not slow"

Acceptance Criteria:
- Rocky Linux 8, 9
- Alma Linux 8, 9
- CentOS Stream 8, 9
- Fedora 39, 40, 41, 42 (EOL versions use archive fallback)
- Amazon Linux 2, 2023
"""

import pytest
import requests
from packageurl import PackageURL

from sbomify_action._enrichment.sources.rpmrepo import RpmRepoSource, clear_cache


@pytest.fixture(autouse=True)
def clear_cache_before_test():
    """Clear cache before each test to ensure fresh data."""
    clear_cache()


@pytest.fixture
def session():
    """Create a requests session with appropriate headers."""
    s = requests.Session()
    s.headers.update({"User-Agent": "sbomify-integration-test/1.0"})
    yield s
    s.close()


@pytest.fixture
def source():
    """Create an RpmRepoSource instance."""
    return RpmRepoSource()


class TestRockyLinuxIntegration:
    """Integration tests for Rocky Linux."""

    @pytest.mark.slow
    def test_rocky_9_bash_enrichment(self, source, session):
        """Test Rocky Linux 9 bash package enrichment."""
        purl = PackageURL.from_string("pkg:rpm/rocky/bash?arch=x86_64&distro=rocky-9")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in Rocky 9"
        assert metadata.supplier is not None, "Should have supplier"
        assert "Rocky" in metadata.supplier, f"Supplier should contain 'Rocky': {metadata.supplier}"
        assert metadata.licenses, "Should have licenses"
        assert metadata.description, "Should have description"

    @pytest.mark.slow
    def test_rocky_8_bash_enrichment(self, source, session):
        """Test Rocky Linux 8 bash package enrichment."""
        purl = PackageURL.from_string("pkg:rpm/rocky/bash?arch=x86_64&distro=rocky-8")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in Rocky 8"
        assert metadata.supplier is not None
        assert metadata.licenses


class TestAlmaLinuxIntegration:
    """Integration tests for Alma Linux."""

    @pytest.mark.slow
    def test_alma_9_bash_enrichment(self, source, session):
        """Test Alma Linux 9 bash package enrichment."""
        purl = PackageURL.from_string("pkg:rpm/almalinux/bash?arch=x86_64&distro=almalinux-9")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in Alma 9"
        assert metadata.supplier is not None
        assert "Alma" in metadata.supplier, f"Supplier should contain 'Alma': {metadata.supplier}"
        assert metadata.licenses

    @pytest.mark.slow
    def test_alma_8_bash_enrichment(self, source, session):
        """Test Alma Linux 8 bash package enrichment."""
        purl = PackageURL.from_string("pkg:rpm/almalinux/bash?arch=x86_64&distro=almalinux-8")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in Alma 8"
        assert metadata.supplier is not None
        assert metadata.licenses


class TestCentOSStreamIntegration:
    """Integration tests for CentOS Stream."""

    @pytest.mark.slow
    def test_centos_stream_9_bash_enrichment(self, source, session):
        """Test CentOS Stream 9 bash package enrichment."""
        purl = PackageURL.from_string("pkg:rpm/centos/bash?arch=x86_64&distro=centos-stream-9")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in CentOS Stream 9"
        assert metadata.supplier is not None
        assert "CentOS" in metadata.supplier, f"Supplier should contain 'CentOS': {metadata.supplier}"
        assert metadata.licenses

    @pytest.mark.slow
    def test_centos_stream_8_bash_enrichment(self, source, session):
        """Test CentOS Stream 8 bash package enrichment.

        Note: CentOS Stream 8 is EOL, repo may be unavailable.
        """
        purl = PackageURL.from_string("pkg:rpm/centos/bash?arch=x86_64&distro=centos-stream-8")
        metadata = source.fetch(purl, session)

        # CentOS Stream 8 is EOL, repo may not be available
        if metadata:
            assert metadata.supplier is not None
            assert metadata.licenses


class TestFedoraIntegration:
    """Integration tests for Fedora."""

    @pytest.mark.slow
    def test_fedora_41_bash_enrichment(self, source, session):
        """Test Fedora 41 bash package enrichment."""
        purl = PackageURL.from_string("pkg:rpm/fedora/bash?arch=x86_64&distro=fedora-41")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in Fedora 41"
        assert metadata.supplier is not None
        assert "Fedora" in metadata.supplier, f"Supplier should contain 'Fedora': {metadata.supplier}"
        assert metadata.licenses

    @pytest.mark.slow
    def test_fedora_40_bash_enrichment(self, source, session):
        """Test Fedora 40 bash package enrichment.

        Note: Fedora 40 is EOL, uses archive fallback.
        """
        purl = PackageURL.from_string("pkg:rpm/fedora/bash?arch=x86_64&distro=fedora-40")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in Fedora 40 (via archive)"
        assert metadata.supplier is not None
        assert metadata.licenses

    @pytest.mark.slow
    def test_fedora_39_bash_enrichment(self, source, session):
        """Test Fedora 39 bash package enrichment.

        Note: Fedora 39 is EOL but repos may still be available.
        """
        purl = PackageURL.from_string("pkg:rpm/fedora/bash?arch=x86_64&distro=fedora-39")
        metadata = source.fetch(purl, session)

        # Fedora 39 is EOL, repo may not be available
        if metadata:
            assert metadata.supplier is not None
            assert metadata.licenses


class TestAmazonLinuxIntegration:
    """Integration tests for Amazon Linux."""

    @pytest.mark.slow
    def test_amazon_linux_2023_bash_enrichment(self, source, session):
        """Test Amazon Linux 2023 bash package enrichment."""
        purl = PackageURL.from_string("pkg:rpm/amzn/bash?arch=x86_64&distro=amzn-2023")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in Amazon Linux 2023"
        assert metadata.supplier is not None
        assert "Amazon" in metadata.supplier, f"Supplier should contain 'Amazon': {metadata.supplier}"
        assert metadata.licenses

    @pytest.mark.slow
    def test_amazon_linux_2_bash_enrichment(self, source, session):
        """Test Amazon Linux 2 bash package enrichment."""
        purl = PackageURL.from_string("pkg:rpm/amzn/bash?arch=x86_64&distro=amzn-2")
        metadata = source.fetch(purl, session)

        assert metadata is not None, "Should find bash in Amazon Linux 2"
        assert metadata.supplier is not None
        assert metadata.licenses


class TestEnrichmentCoverage:
    """Test that enrichment provides comprehensive metadata."""

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "purl_str,expected_supplier_contains",
        [
            ("pkg:rpm/rocky/openssl?arch=x86_64&distro=rocky-9", "Rocky"),
            ("pkg:rpm/almalinux/curl?arch=x86_64&distro=almalinux-9", "Alma"),
            ("pkg:rpm/fedora/python3?arch=x86_64&distro=fedora-41", "Fedora"),
            ("pkg:rpm/amzn/wget?arch=x86_64&distro=amzn-2023", "Amazon"),
        ],
    )
    def test_various_packages_have_complete_metadata(self, source, session, purl_str, expected_supplier_contains):
        """Test that various packages have complete NTIA metadata."""
        purl = PackageURL.from_string(purl_str)
        metadata = source.fetch(purl, session)

        assert metadata is not None, f"Should find {purl.name}"
        assert metadata.supplier is not None, "Should have supplier"
        assert expected_supplier_contains in metadata.supplier
        assert metadata.licenses, "Should have licenses"
        assert metadata.description, "Should have description"
        assert metadata.field_sources, "Should track field sources"

    @pytest.mark.slow
    def test_enrichment_provides_download_url(self, source, session):
        """Test that enrichment provides download URL."""
        purl = PackageURL.from_string("pkg:rpm/rocky/bash?arch=x86_64&distro=rocky-9")
        metadata = source.fetch(purl, session)

        assert metadata is not None
        assert metadata.download_url is not None
        assert metadata.download_url.endswith(".rpm")

    @pytest.mark.slow
    def test_enrichment_provides_homepage(self, source, session):
        """Test that enrichment provides homepage."""
        purl = PackageURL.from_string("pkg:rpm/rocky/bash?arch=x86_64&distro=rocky-9")
        metadata = source.fetch(purl, session)

        assert metadata is not None
        assert metadata.homepage is not None
        assert metadata.homepage.startswith("http")


class TestCachingPerformance:
    """Test caching behavior with real repos."""

    @pytest.mark.slow
    def test_multiple_packages_from_same_repo_use_cache(self, source, session):
        """Test that multiple packages from same repo use cached data."""
        import time

        # First package - should load repo
        purl1 = PackageURL.from_string("pkg:rpm/rocky/bash?arch=x86_64&distro=rocky-9")
        start1 = time.time()
        metadata1 = source.fetch(purl1, session)
        time1 = time.time() - start1

        # Second package - should use cache
        purl2 = PackageURL.from_string("pkg:rpm/rocky/coreutils?arch=x86_64&distro=rocky-9")
        start2 = time.time()
        metadata2 = source.fetch(purl2, session)
        time2 = time.time() - start2

        assert metadata1 is not None
        assert metadata2 is not None
        # Second lookup should be faster (cached) - use generous threshold to avoid flakiness
        # Cache lookup should take < 100ms and be faster than the initial load time
        assert time2 < 0.1 and time2 < time1 * 0.8, (
            f"Cache lookup ({time2:.2f}s) should be faster than initial load ({time1:.2f}s)"
        )
