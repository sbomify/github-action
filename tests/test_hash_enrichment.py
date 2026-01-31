"""Tests for the hash enrichment subsystem."""

import json
from pathlib import Path

import pytest

from sbomify_action._hash_enrichment import (
    HashAlgorithm,
    PackageHash,
    create_default_registry,
    enrich_sbom_with_hashes,
    normalize_package_name,
)
from sbomify_action._hash_enrichment.parsers import (
    CargoLockParser,
    PipfileLockParser,
    PubspecLockParser,
    UvLockParser,
)


class TestHashAlgorithm:
    """Tests for HashAlgorithm enum."""

    def test_from_prefix_sha256(self):
        """Test parsing sha256 prefix."""
        assert HashAlgorithm.from_prefix("sha256") == HashAlgorithm.SHA256
        assert HashAlgorithm.from_prefix("SHA256") == HashAlgorithm.SHA256
        assert HashAlgorithm.from_prefix("sha-256") == HashAlgorithm.SHA256

    def test_from_prefix_sha512(self):
        """Test parsing sha512 prefix."""
        assert HashAlgorithm.from_prefix("sha512") == HashAlgorithm.SHA512
        assert HashAlgorithm.from_prefix("SHA512") == HashAlgorithm.SHA512

    def test_from_prefix_unknown(self):
        """Test unknown prefix returns None."""
        assert HashAlgorithm.from_prefix("unknown") is None
        assert HashAlgorithm.from_prefix("") is None

    def test_cyclonedx_alg(self):
        """Test CycloneDX algorithm name conversion."""
        assert HashAlgorithm.SHA256.cyclonedx_alg == "SHA-256"
        assert HashAlgorithm.SHA512.cyclonedx_alg == "SHA-512"
        assert HashAlgorithm.SHA1.cyclonedx_alg == "SHA-1"

    def test_spdx_alg(self):
        """Test SPDX algorithm name conversion."""
        assert HashAlgorithm.SHA256.spdx_alg == "SHA256"
        assert HashAlgorithm.SHA512.spdx_alg == "SHA512"
        assert HashAlgorithm.SHA1.spdx_alg == "SHA1"


class TestPackageHash:
    """Tests for PackageHash dataclass."""

    def test_from_prefixed_sha256(self):
        """Test parsing sha256:... format."""
        pkg_hash = PackageHash.from_prefixed("django", "5.1.1", "sha256:abc123def456")
        assert pkg_hash is not None
        assert pkg_hash.name == "django"
        assert pkg_hash.version == "5.1.1"
        assert pkg_hash.algorithm == HashAlgorithm.SHA256
        assert pkg_hash.value == "abc123def456"

    def test_from_prefixed_sha512(self):
        """Test parsing sha512:... format."""
        pkg_hash = PackageHash.from_prefixed("requests", "2.31.0", "sha512:fedcba987654")
        assert pkg_hash is not None
        assert pkg_hash.algorithm == HashAlgorithm.SHA512
        assert pkg_hash.value == "fedcba987654"

    def test_from_prefixed_no_colon(self):
        """Test that missing colon returns None."""
        assert PackageHash.from_prefixed("pkg", "1.0", "nocolon") is None

    def test_from_prefixed_unknown_algorithm(self):
        """Test that unknown algorithm returns None."""
        assert PackageHash.from_prefixed("pkg", "1.0", "unknown:hash") is None

    def test_from_sri_sha512(self):
        """Test parsing SRI format (sha512-base64)."""
        # Valid SHA512 SRI hash
        pkg_hash = PackageHash.from_sri(
            "lodash",
            "4.17.21",
            "sha512-Dh4h7PEF7IU9JNcohnrXBhPCFmOkaTB0sqNhnBvTnWa1iMM3I7tGbHJCToDjymPCSQeKs0e6uUKFAOfuQwWdDQ==",
        )
        assert pkg_hash is not None
        assert pkg_hash.name == "lodash"
        assert pkg_hash.version == "4.17.21"
        assert pkg_hash.algorithm == HashAlgorithm.SHA512
        # Value should be hex-encoded
        assert len(pkg_hash.value) == 128  # SHA512 = 64 bytes = 128 hex chars

    def test_from_sri_invalid(self):
        """Test that invalid SRI returns None."""
        assert PackageHash.from_sri("pkg", "1.0", "nohyphen") is None
        assert PackageHash.from_sri("pkg", "1.0", "unknown-base64") is None


class TestNormalizePackageName:
    """Tests for package name normalization."""

    def test_pypi_normalization(self):
        """Test PyPI name normalization."""
        assert normalize_package_name("Django", "pypi") == "django"
        assert normalize_package_name("django-rest-framework", "pypi") == "django_rest_framework"
        assert normalize_package_name("Pillow", "pypi") == "pillow"
        assert normalize_package_name("zope.interface", "pypi") == "zope_interface"

    def test_npm_normalization(self):
        """Test npm name normalization."""
        assert normalize_package_name("Lodash", "npm") == "lodash"
        # Scoped packages are also case-insensitive
        assert normalize_package_name("@types/Node", "npm") == "@types/node"
        assert normalize_package_name("@Scope/Package", "npm") == "@scope/package"

    def test_cargo_normalization(self):
        """Test Cargo name normalization."""
        assert normalize_package_name("serde-json", "cargo") == "serde_json"
        assert normalize_package_name("Tokio", "cargo") == "tokio"


class TestUvLockParser:
    """Tests for uv.lock parser."""

    @pytest.fixture
    def uv_lock_content(self):
        return """
version = 1

[[package]]
name = "django"
version = "5.1.1"
sdist = { url = "...", hash = "sha256:abc123def", size = 100 }
wheels = [
    { url = "...", hash = "sha256:wheel1hash", size = 50 },
    { url = "...", hash = "sha256:wheel2hash", size = 50 },
]

[[package]]
name = "requests"
version = "2.31.0"
sdist = { url = "...", hash = "sha256:reqhash", size = 100 }
"""

    def test_parse_uv_lock(self, uv_lock_content, tmp_path):
        """Test parsing uv.lock file."""
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(uv_lock_content)

        parser = UvLockParser()
        assert parser.supports("uv.lock")
        assert not parser.supports("Cargo.lock")

        hashes = parser.parse(lock_file)

        # Should have 2 hashes: 1 per package (wheel preferred over sdist)
        assert len(hashes) == 2

        django_hash = next(h for h in hashes if h.name == "django")
        # Should prefer wheel over sdist
        assert django_hash.artifact_type == "wheel"
        assert django_hash.value == "wheel1hash"
        assert django_hash.algorithm == HashAlgorithm.SHA256

        # requests only has sdist
        requests_hash = next(h for h in hashes if h.name == "requests")
        assert requests_hash.artifact_type == "sdist"
        assert requests_hash.value == "reqhash"

    def test_parse_real_uv_lock(self):
        """Test parsing actual uv.lock from test data."""
        lock_file = Path("tests/test-data/uv.lock")
        if not lock_file.exists():
            pytest.skip("Test data file not found")

        parser = UvLockParser()
        hashes = parser.parse(lock_file)

        assert len(hashes) > 0
        # All hashes should be SHA256 (uv uses sha256)
        assert all(h.algorithm == HashAlgorithm.SHA256 for h in hashes)


class TestPipfileLockParser:
    """Tests for Pipfile.lock parser."""

    def test_parse_real_pipfile_lock(self):
        """Test parsing actual Pipfile.lock from test data."""
        lock_file = Path("tests/test-data/Pipfile.lock")
        if not lock_file.exists():
            pytest.skip("Test data file not found")

        parser = PipfileLockParser()
        assert parser.supports("Pipfile.lock")

        hashes = parser.parse(lock_file)

        assert len(hashes) > 0
        # Should find django
        django_hashes = [h for h in hashes if h.name == "django"]
        assert len(django_hashes) > 0
        assert django_hashes[0].version == "5.1.1"


class TestCargoLockParser:
    """Tests for Cargo.lock parser."""

    def test_parse_real_cargo_lock(self):
        """Test parsing actual Cargo.lock from test data."""
        lock_file = Path("tests/test-data/Cargo.lock")
        if not lock_file.exists():
            pytest.skip("Test data file not found")

        parser = CargoLockParser()
        assert parser.supports("Cargo.lock")

        hashes = parser.parse(lock_file)

        assert len(hashes) > 0
        # All Cargo hashes are SHA256
        assert all(h.algorithm == HashAlgorithm.SHA256 for h in hashes)
        # All should be crate type
        assert all(h.artifact_type == "crate" for h in hashes)


class TestPubspecLockParser:
    """Tests for pubspec.lock parser."""

    def test_parse_real_pubspec_lock(self):
        """Test parsing actual pubspec.lock from test data."""
        lock_file = Path("tests/test-data/pubspec.lock")
        if not lock_file.exists():
            pytest.skip("Test data file not found")

        parser = PubspecLockParser()
        assert parser.supports("pubspec.lock")

        hashes = parser.parse(lock_file)

        assert len(hashes) > 0
        # All pubspec hashes are SHA256
        assert all(h.algorithm == HashAlgorithm.SHA256 for h in hashes)


class TestHashEnricher:
    """Tests for HashEnricher class."""

    @pytest.fixture
    def sample_cyclonedx_sbom(self):
        """Create a sample CycloneDX SBOM."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "django",
                    "version": "5.1.1",
                    "purl": "pkg:pypi/django@5.1.1",
                },
                {
                    "type": "library",
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                },
            ],
        }

    @pytest.fixture
    def sample_spdx_sbom(self):
        """Create a sample SPDX SBOM."""
        return {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-sbom",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-django",
                    "name": "django",
                    "versionInfo": "5.1.1",
                },
                {
                    "SPDXID": "SPDXRef-Package-requests",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                },
            ],
        }

    @pytest.fixture
    def sample_uv_lock(self, tmp_path):
        """Create a sample uv.lock file."""
        content = """
version = 1

[[package]]
name = "django"
version = "5.1.1"
sdist = { hash = "sha256:abc123" }

[[package]]
name = "requests"
version = "2.31.0"
sdist = { hash = "sha256:def456" }
"""
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(content)
        return lock_file

    def test_enrich_cyclonedx_adds_hashes(self, sample_cyclonedx_sbom, sample_uv_lock, tmp_path):
        """Test that CycloneDX components get hashes added."""
        # Write SBOM to file
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sample_cyclonedx_sbom))

        # Enrich
        stats = enrich_sbom_with_hashes(
            sbom_file=str(sbom_file),
            lock_file=str(sample_uv_lock),
        )

        assert stats["hashes_added"] == 2
        assert stats["components_matched"] == 2

        # Verify hashes in output
        enriched = json.loads(sbom_file.read_text())
        django_comp = next(c for c in enriched["components"] if c["name"] == "django")
        assert "hashes" in django_comp
        assert len(django_comp["hashes"]) == 1
        assert django_comp["hashes"][0]["alg"] == "SHA-256"
        assert django_comp["hashes"][0]["content"] == "abc123"

    def test_enrich_spdx_adds_checksums(self, sample_spdx_sbom, sample_uv_lock, tmp_path):
        """Test that SPDX packages get checksums added."""
        # Write SBOM to file
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sample_spdx_sbom))

        # Enrich
        stats = enrich_sbom_with_hashes(
            sbom_file=str(sbom_file),
            lock_file=str(sample_uv_lock),
        )

        assert stats["hashes_added"] == 2
        assert stats["components_matched"] == 2

        # Verify checksums in output
        enriched = json.loads(sbom_file.read_text())
        django_pkg = next(p for p in enriched["packages"] if p["name"] == "django")
        assert "checksums" in django_pkg
        assert len(django_pkg["checksums"]) == 1
        assert django_pkg["checksums"][0]["algorithm"] == "SHA256"
        assert django_pkg["checksums"][0]["checksumValue"] == "abc123"

    def test_enrich_skips_existing_hashes(self, tmp_path):
        """Test that existing hashes are not overwritten by default."""
        # SBOM with existing hash
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "django",
                    "version": "5.1.1",
                    "hashes": [{"alg": "SHA-256", "content": "existing"}],
                },
            ],
        }
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom))

        # Lock file with different hash
        lock_content = """
version = 1

[[package]]
name = "django"
version = "5.1.1"
sdist = { hash = "sha256:newvalue" }
"""
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(lock_content)

        # Enrich without overwrite
        stats = enrich_sbom_with_hashes(
            sbom_file=str(sbom_file),
            lock_file=str(lock_file),
            overwrite_existing=False,
        )

        assert stats["hashes_added"] == 0
        assert stats["hashes_skipped"] == 1

        # Verify original hash preserved
        enriched = json.loads(sbom_file.read_text())
        django_comp = enriched["components"][0]
        assert django_comp["hashes"][0]["content"] == "existing"

    def test_enrich_with_overwrite(self, tmp_path):
        """Test that overwrite_existing=True replaces hashes."""
        # SBOM with existing hash
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "django",
                    "version": "5.1.1",
                    "hashes": [{"alg": "SHA-256", "content": "existing"}],
                },
            ],
        }
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(json.dumps(sbom))

        # Lock file with different hash
        lock_content = """
version = 1

[[package]]
name = "django"
version = "5.1.1"
sdist = { hash = "sha256:newvalue" }
"""
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(lock_content)

        # Enrich with overwrite
        stats = enrich_sbom_with_hashes(
            sbom_file=str(sbom_file),
            lock_file=str(lock_file),
            overwrite_existing=True,
        )

        assert stats["hashes_added"] == 1

        # Verify new hash replaced old
        enriched = json.loads(sbom_file.read_text())
        django_comp = enriched["components"][0]
        assert len(django_comp["hashes"]) == 1
        assert django_comp["hashes"][0]["content"] == "newvalue"


class TestParserRegistry:
    """Tests for ParserRegistry."""

    def test_default_registry_has_parsers(self):
        """Test that default registry has all expected parsers."""
        registry = create_default_registry()

        # Check some expected parsers
        assert registry.get_parser_for("uv.lock") is not None
        assert registry.get_parser_for("Pipfile.lock") is not None
        assert registry.get_parser_for("poetry.lock") is not None
        assert registry.get_parser_for("Cargo.lock") is not None
        assert registry.get_parser_for("pubspec.lock") is not None
        assert registry.get_parser_for("package-lock.json") is not None
        assert registry.get_parser_for("yarn.lock") is not None
        assert registry.get_parser_for("pnpm-lock.yaml") is not None

    def test_registry_returns_none_for_unknown(self):
        """Test that registry returns None for unknown lockfiles."""
        registry = create_default_registry()
        assert registry.get_parser_for("unknown.lock") is None
        assert registry.get_parser_for("requirements.txt") is None
