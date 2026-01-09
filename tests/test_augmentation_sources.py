"""
Tests for the SBOM augmentation sources with plugin-based architecture.

Tests the augmentation data sources: pyproject.toml, package.json, Cargo.toml,
local JSON, and sbomify API.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

from sbomify_action._augmentation.collector import AugmentationCollector, create_default_registry
from sbomify_action._augmentation.data import AugmentationData, OrganizationalContact, OrganizationalEntity
from sbomify_action._augmentation.registry import AugmentationSourceRegistry
from sbomify_action._augmentation.sources.cargo import CargoSource
from sbomify_action._augmentation.sources.local_json import LocalJSONSource
from sbomify_action._augmentation.sources.package_json import PackageJSONSource
from sbomify_action._augmentation.sources.pyproject import PyProjectSource
from sbomify_action._augmentation.sources.sbomify_api import SbomifyAPISource

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_pyproject_toml():
    """Sample pyproject.toml content (PEP 621 format)."""
    return """
[project]
name = "my-package"
version = "1.0.0"
description = "A sample package"
authors = [
    {name = "John Doe", email = "john@example.com"},
    {name = "Jane Smith", email = "jane@example.com"}
]
maintainers = [
    {name = "Maintenance Team", email = "maint@example.com"}
]
license = "MIT"

[project.urls]
Homepage = "https://example.com"
Repository = "https://github.com/example/package"

[project.optional-dependencies]
dev = ["pytest"]
"""


@pytest.fixture
def sample_package_json():
    """Sample package.json content."""
    return json.dumps(
        {
            "name": "my-package",
            "version": "1.0.0",
            "description": "A sample Node.js package",
            "author": "John Doe <john@example.com>",
            "contributors": [{"name": "Jane Smith", "email": "jane@example.com"}],
            "license": "Apache-2.0",
            "homepage": "https://example.com",
            "repository": {"type": "git", "url": "git+https://github.com/example/package.git"},
        }
    )


@pytest.fixture
def sample_cargo_toml():
    """Sample Cargo.toml content."""
    return """
[package]
name = "my-crate"
version = "0.1.0"
edition = "2021"
authors = ["Alice <alice@example.com>", "Bob <bob@example.com>"]
license = "MIT/Apache-2.0"
homepage = "https://example.com"
repository = "https://github.com/example/crate"
documentation = "https://docs.rs/my-crate"
"""


@pytest.fixture
def sample_sbomify_json():
    """Sample .sbomify.json content."""
    return json.dumps(
        {
            "supplier": {
                "name": "Acme Corp",
                "url": ["https://acme.com", "https://www.acme.com"],
                "contact": [{"name": "Security Team", "email": "security@acme.com", "phone": "+1-555-1234"}],
            },
            "manufacturer": {"name": "Acme Engineering", "url": ["https://eng.acme.com"]},
            "authors": [{"name": "Lead Developer", "email": "dev@acme.com"}],
            "licenses": ["Apache-2.0", "MIT"],
        }
    )


# =============================================================================
# Test OrganizationalContact
# =============================================================================


class TestOrganizationalContact:
    """Test the OrganizationalContact dataclass."""

    def test_has_data_with_name(self):
        """Test has_data returns True when name is present."""
        contact = OrganizationalContact(name="John Doe")
        assert contact.has_data() is True

    def test_has_data_with_email(self):
        """Test has_data returns True when email is present."""
        contact = OrganizationalContact(email="john@example.com")
        assert contact.has_data() is True

    def test_has_data_with_phone_only(self):
        """Test has_data returns False when only phone is present."""
        contact = OrganizationalContact(phone="+1-555-1234")
        assert contact.has_data() is False

    def test_has_data_empty(self):
        """Test has_data returns False when empty."""
        contact = OrganizationalContact()
        assert contact.has_data() is False

    def test_to_dict(self):
        """Test to_dict method."""
        contact = OrganizationalContact(name="John", email="john@example.com", phone="+1-555")
        result = contact.to_dict()
        assert result == {"name": "John", "email": "john@example.com", "phone": "+1-555"}

    def test_to_dict_excludes_none(self):
        """Test to_dict excludes None values."""
        contact = OrganizationalContact(name="John")
        result = contact.to_dict()
        assert result == {"name": "John"}


# =============================================================================
# Test OrganizationalEntity
# =============================================================================


class TestOrganizationalEntity:
    """Test the OrganizationalEntity dataclass."""

    def test_has_data_with_name(self):
        """Test has_data returns True when name is present."""
        entity = OrganizationalEntity(name="Acme Corp")
        assert entity.has_data() is True

    def test_has_data_with_urls(self):
        """Test has_data returns True when URLs are present."""
        entity = OrganizationalEntity(urls=["https://acme.com"])
        assert entity.has_data() is True

    def test_has_data_with_contacts(self):
        """Test has_data returns True when contacts are present."""
        contact = OrganizationalContact(name="John")
        entity = OrganizationalEntity(contacts=[contact])
        assert entity.has_data() is True

    def test_has_data_empty(self):
        """Test has_data returns False when empty."""
        entity = OrganizationalEntity()
        assert entity.has_data() is False

    def test_to_dict(self):
        """Test to_dict method."""
        contact = OrganizationalContact(name="John", email="john@example.com")
        entity = OrganizationalEntity(name="Acme Corp", urls=["https://acme.com"], contacts=[contact])
        result = entity.to_dict()
        assert result == {
            "name": "Acme Corp",
            "url": ["https://acme.com"],
            "contact": [{"name": "John", "email": "john@example.com"}],
        }

    def test_merge_entities(self):
        """Test merging two entities."""
        contact1 = OrganizationalContact(name="John", email="john@example.com")
        entity1 = OrganizationalEntity(name="Acme Corp", urls=["https://acme.com"], contacts=[contact1])

        contact2 = OrganizationalContact(name="Jane", email="jane@example.com")
        entity2 = OrganizationalEntity(name="Other Corp", urls=["https://other.com"], contacts=[contact2])

        merged = entity1.merge(entity2)

        # entity1 values take precedence
        assert merged.name == "Acme Corp"
        assert "https://acme.com" in merged.urls
        assert "https://other.com" in merged.urls
        assert len(merged.contacts) == 2


# =============================================================================
# Test AugmentationData
# =============================================================================


class TestAugmentationData:
    """Test the AugmentationData dataclass."""

    def test_has_data_with_supplier(self):
        """Test has_data returns True when supplier is present."""
        supplier = OrganizationalEntity(name="Acme Corp")
        data = AugmentationData(supplier=supplier)
        assert data.has_data() is True

    def test_has_data_with_authors(self):
        """Test has_data returns True when authors are present."""
        author = OrganizationalContact(name="John")
        data = AugmentationData(authors=[author])
        assert data.has_data() is True

    def test_has_data_with_licenses(self):
        """Test has_data returns True when licenses are present."""
        data = AugmentationData(licenses=["MIT"])
        assert data.has_data() is True

    def test_has_data_empty(self):
        """Test has_data returns False when empty."""
        data = AugmentationData()
        assert data.has_data() is False

    def test_to_dict(self):
        """Test to_dict method."""
        supplier = OrganizationalEntity(name="Acme Corp", urls=["https://acme.com"])
        author = OrganizationalContact(name="John", email="john@example.com")
        data = AugmentationData(supplier=supplier, authors=[author], licenses=["MIT", "Apache-2.0"])
        result = data.to_dict()

        assert "supplier" in result
        assert result["supplier"]["name"] == "Acme Corp"
        assert "authors" in result
        assert len(result["authors"]) == 1
        assert "licenses" in result
        assert result["licenses"] == ["MIT", "Apache-2.0"]

    def test_merge_data(self):
        """Test merging two AugmentationData objects."""
        supplier1 = OrganizationalEntity(name="Acme Corp")
        data1 = AugmentationData(supplier=supplier1, licenses=["MIT"], source="source1")

        author2 = OrganizationalContact(name="Jane")
        data2 = AugmentationData(authors=[author2], licenses=["Apache-2.0"], source="source2")

        merged = data1.merge(data2)

        # data1 values take precedence
        assert merged.supplier.name == "Acme Corp"
        assert len(merged.authors) == 1
        assert "MIT" in merged.licenses
        assert "Apache-2.0" in merged.licenses
        assert merged.source == "source1"


# =============================================================================
# Test PyProjectSource
# =============================================================================


class TestPyProjectSource:
    """Test the PyProject.toml augmentation source."""

    def test_name_and_priority(self):
        """Test source name and priority."""
        source = PyProjectSource()
        assert source.name == "pyproject.toml"
        assert source.priority == 70

    def test_supports_with_file(self, temp_dir, sample_pyproject_toml):
        """Test supports returns True when pyproject.toml exists."""
        (temp_dir / "pyproject.toml").write_text(sample_pyproject_toml)
        source = PyProjectSource()
        assert source.supports(temp_dir, {}) is True

    def test_supports_without_file(self, temp_dir):
        """Test supports returns False when pyproject.toml doesn't exist."""
        source = PyProjectSource()
        assert source.supports(temp_dir, {}) is False

    def test_fetch_authors(self, temp_dir, sample_pyproject_toml):
        """Test fetching authors from pyproject.toml."""
        (temp_dir / "pyproject.toml").write_text(sample_pyproject_toml)
        source = PyProjectSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert len(data.authors) == 2
        assert data.authors[0].name == "John Doe"
        assert data.authors[0].email == "john@example.com"

    def test_fetch_license(self, temp_dir, sample_pyproject_toml):
        """Test fetching license from pyproject.toml."""
        (temp_dir / "pyproject.toml").write_text(sample_pyproject_toml)
        source = PyProjectSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert "MIT" in data.licenses

    def test_fetch_supplier_urls(self, temp_dir, sample_pyproject_toml):
        """Test fetching supplier URLs from pyproject.toml."""
        (temp_dir / "pyproject.toml").write_text(sample_pyproject_toml)
        source = PyProjectSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert data.supplier is not None
        assert "https://example.com" in data.supplier.urls

    def test_fetch_invalid_toml(self, temp_dir):
        """Test handling of invalid TOML."""
        (temp_dir / "pyproject.toml").write_text("invalid { toml }")
        source = PyProjectSource()
        data = source.fetch(temp_dir, {})

        assert data is None


# =============================================================================
# Test PackageJSONSource
# =============================================================================


class TestPackageJSONSource:
    """Test the package.json augmentation source."""

    def test_name_and_priority(self):
        """Test source name and priority."""
        source = PackageJSONSource()
        assert source.name == "package.json"
        assert source.priority == 70

    def test_supports_with_file(self, temp_dir, sample_package_json):
        """Test supports returns True when package.json exists."""
        (temp_dir / "package.json").write_text(sample_package_json)
        source = PackageJSONSource()
        assert source.supports(temp_dir, {}) is True

    def test_supports_without_file(self, temp_dir):
        """Test supports returns False when package.json doesn't exist."""
        source = PackageJSONSource()
        assert source.supports(temp_dir, {}) is False

    def test_fetch_author_string(self, temp_dir):
        """Test parsing author as string."""
        content = json.dumps({"author": "John Doe <john@example.com>"})
        (temp_dir / "package.json").write_text(content)
        source = PackageJSONSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert len(data.authors) == 1
        assert data.authors[0].name == "John Doe"
        assert data.authors[0].email == "john@example.com"

    def test_fetch_author_object(self, temp_dir):
        """Test parsing author as object."""
        content = json.dumps({"author": {"name": "Jane Smith", "email": "jane@example.com"}})
        (temp_dir / "package.json").write_text(content)
        source = PackageJSONSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert len(data.authors) == 1
        assert data.authors[0].name == "Jane Smith"

    def test_fetch_license(self, temp_dir, sample_package_json):
        """Test fetching license from package.json."""
        (temp_dir / "package.json").write_text(sample_package_json)
        source = PackageJSONSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert "Apache-2.0" in data.licenses

    def test_fetch_repository_url(self, temp_dir, sample_package_json):
        """Test fetching repository URL from package.json."""
        (temp_dir / "package.json").write_text(sample_package_json)
        source = PackageJSONSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert data.supplier is not None
        # Git URL should be cleaned up
        assert any("github.com/example/package" in url for url in data.supplier.urls)

    def test_fetch_invalid_json(self, temp_dir):
        """Test handling of invalid JSON."""
        (temp_dir / "package.json").write_text("invalid json {")
        source = PackageJSONSource()
        data = source.fetch(temp_dir, {})

        assert data is None


# =============================================================================
# Test CargoSource
# =============================================================================


class TestCargoSource:
    """Test the Cargo.toml augmentation source."""

    def test_name_and_priority(self):
        """Test source name and priority."""
        source = CargoSource()
        assert source.name == "Cargo.toml"
        assert source.priority == 70

    def test_supports_with_file(self, temp_dir, sample_cargo_toml):
        """Test supports returns True when Cargo.toml exists."""
        (temp_dir / "Cargo.toml").write_text(sample_cargo_toml)
        source = CargoSource()
        assert source.supports(temp_dir, {}) is True

    def test_supports_without_file(self, temp_dir):
        """Test supports returns False when Cargo.toml doesn't exist."""
        source = CargoSource()
        assert source.supports(temp_dir, {}) is False

    def test_fetch_authors(self, temp_dir, sample_cargo_toml):
        """Test fetching authors from Cargo.toml."""
        (temp_dir / "Cargo.toml").write_text(sample_cargo_toml)
        source = CargoSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert len(data.authors) == 2
        assert data.authors[0].name == "Alice"
        assert data.authors[0].email == "alice@example.com"

    def test_fetch_dual_license(self, temp_dir, sample_cargo_toml):
        """Test fetching dual license from Cargo.toml."""
        (temp_dir / "Cargo.toml").write_text(sample_cargo_toml)
        source = CargoSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        # MIT/Apache-2.0 should be converted to "MIT OR Apache-2.0"
        assert len(data.licenses) == 1
        assert "OR" in data.licenses[0]

    def test_fetch_urls(self, temp_dir, sample_cargo_toml):
        """Test fetching URLs from Cargo.toml."""
        (temp_dir / "Cargo.toml").write_text(sample_cargo_toml)
        source = CargoSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert data.supplier is not None
        assert "https://example.com" in data.supplier.urls
        assert "https://github.com/example/crate" in data.supplier.urls


# =============================================================================
# Test LocalJSONSource
# =============================================================================


class TestLocalJSONSource:
    """Test the local JSON augmentation source."""

    def test_name_and_priority(self):
        """Test source name and priority."""
        source = LocalJSONSource()
        assert source.name == "local-json"
        assert source.priority == 50

    def test_supports_with_default_file(self, temp_dir, sample_sbomify_json):
        """Test supports returns True when .sbomify.json exists."""
        (temp_dir / ".sbomify.json").write_text(sample_sbomify_json)
        source = LocalJSONSource()
        assert source.supports(temp_dir, {}) is True

    def test_supports_with_custom_file(self, temp_dir, sample_sbomify_json):
        """Test supports with custom augmentation file."""
        (temp_dir / "custom-meta.json").write_text(sample_sbomify_json)
        source = LocalJSONSource()
        config = {"augmentation_file": "custom-meta.json"}
        assert source.supports(temp_dir, config) is True

    def test_supports_without_file(self, temp_dir):
        """Test supports returns False when file doesn't exist."""
        source = LocalJSONSource()
        assert source.supports(temp_dir, {}) is False

    def test_fetch_full_schema(self, temp_dir, sample_sbomify_json):
        """Test fetching full schema from .sbomify.json."""
        (temp_dir / ".sbomify.json").write_text(sample_sbomify_json)
        source = LocalJSONSource()
        data = source.fetch(temp_dir, {})

        assert data is not None

        # Check supplier
        assert data.supplier is not None
        assert data.supplier.name == "Acme Corp"
        assert len(data.supplier.urls) == 2
        assert len(data.supplier.contacts) == 1
        assert data.supplier.contacts[0].phone == "+1-555-1234"

        # Check manufacturer
        assert data.manufacturer is not None
        assert data.manufacturer.name == "Acme Engineering"

        # Check authors
        assert len(data.authors) == 1
        assert data.authors[0].name == "Lead Developer"

        # Check licenses
        assert "Apache-2.0" in data.licenses
        assert "MIT" in data.licenses

    def test_fetch_custom_license(self, temp_dir):
        """Test fetching custom license object."""
        content = json.dumps(
            {"licenses": [{"name": "Custom License", "url": "https://example.com/license", "text": "License text..."}]}
        )
        (temp_dir / ".sbomify.json").write_text(content)
        source = LocalJSONSource()
        data = source.fetch(temp_dir, {})

        assert data is not None
        assert len(data.licenses) == 1
        assert isinstance(data.licenses[0], dict)
        assert data.licenses[0]["name"] == "Custom License"

    def test_fetch_invalid_json(self, temp_dir):
        """Test handling of invalid JSON."""
        (temp_dir / ".sbomify.json").write_text("invalid json {")
        source = LocalJSONSource()
        data = source.fetch(temp_dir, {})

        assert data is None


# =============================================================================
# Test SbomifyAPISource
# =============================================================================


class TestSbomifyAPISource:
    """Test the sbomify API augmentation source."""

    def test_name_and_priority(self):
        """Test source name and priority."""
        source = SbomifyAPISource()
        assert source.name == "sbomify-api"
        assert source.priority == 10

    def test_supports_with_credentials(self, temp_dir):
        """Test supports returns True when credentials are provided."""
        source = SbomifyAPISource()
        config = {"token": "test-token", "component_id": "test-component-id"}
        assert source.supports(temp_dir, config) is True

    def test_supports_without_token(self, temp_dir):
        """Test supports returns False when token is missing."""
        source = SbomifyAPISource()
        config = {"component_id": "test-component-id"}
        assert source.supports(temp_dir, config) is False

    def test_supports_without_component_id(self, temp_dir):
        """Test supports returns False when component_id is missing."""
        source = SbomifyAPISource()
        config = {"token": "test-token"}
        assert source.supports(temp_dir, config) is False

    @patch("sbomify_action._augmentation.sources.sbomify_api.requests.get")
    def test_fetch_success(self, mock_get, temp_dir):
        """Test successful API fetch."""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "supplier": {"name": "API Supplier", "url": ["https://api.example.com"]},
            "authors": [{"name": "API Author", "email": "api@example.com"}],
            "licenses": ["BSD-3-Clause"],
        }
        mock_get.return_value = mock_response

        source = SbomifyAPISource()
        config = {"token": "test-token", "component_id": "test-component-id", "api_base_url": "https://api.sbomify.com"}
        data = source.fetch(temp_dir, config)

        assert data is not None
        assert data.supplier.name == "API Supplier"
        assert len(data.authors) == 1
        assert "BSD-3-Clause" in data.licenses

    @patch("sbomify_action._augmentation.sources.sbomify_api.requests.get")
    def test_fetch_api_error(self, mock_get, temp_dir):
        """Test handling of API error."""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"detail": "Component not found"}
        mock_get.return_value = mock_response

        source = SbomifyAPISource()
        config = {"token": "test-token", "component_id": "invalid-id"}
        data = source.fetch(temp_dir, config)

        assert data is None

    @patch("sbomify_action._augmentation.sources.sbomify_api.requests.get")
    def test_fetch_connection_error(self, mock_get, temp_dir):
        """Test handling of connection error."""
        mock_get.side_effect = requests.exceptions.ConnectionError()

        source = SbomifyAPISource()
        config = {"token": "test-token", "component_id": "test-id"}
        data = source.fetch(temp_dir, config)

        assert data is None


# =============================================================================
# Test AugmentationSourceRegistry
# =============================================================================


class TestAugmentationSourceRegistry:
    """Test the augmentation source registry."""

    def test_register_source(self):
        """Test registering a source."""
        registry = AugmentationSourceRegistry()
        source = PyProjectSource()
        registry.register(source)

        sources = registry.list_sources()
        assert len(sources) == 1
        assert sources[0]["name"] == "pyproject.toml"

    def test_get_sources_sorted_by_priority(self, temp_dir, sample_pyproject_toml, sample_sbomify_json):
        """Test sources are returned sorted by priority."""
        (temp_dir / "pyproject.toml").write_text(sample_pyproject_toml)
        (temp_dir / ".sbomify.json").write_text(sample_sbomify_json)

        registry = AugmentationSourceRegistry()
        registry.register(PyProjectSource())  # priority 70
        registry.register(LocalJSONSource())  # priority 50

        sources = registry.get_sources_for(temp_dir, {})
        assert len(sources) == 2
        assert sources[0].name == "local-json"  # Lower priority = first
        assert sources[1].name == "pyproject.toml"

    def test_fetch_metadata_merge(self, temp_dir, sample_pyproject_toml, sample_sbomify_json):
        """Test fetching and merging metadata from multiple sources."""
        (temp_dir / "pyproject.toml").write_text(sample_pyproject_toml)
        (temp_dir / ".sbomify.json").write_text(sample_sbomify_json)

        registry = AugmentationSourceRegistry()
        registry.register(LocalJSONSource())  # priority 50
        registry.register(PyProjectSource())  # priority 70

        data = registry.fetch_metadata(temp_dir, {}, merge_results=True)

        assert data is not None
        # LocalJSON (higher priority) supplier should take precedence
        assert data.supplier.name == "Acme Corp"
        # But authors from both sources should be merged
        assert len(data.authors) >= 1

    def test_clear_registry(self):
        """Test clearing the registry."""
        registry = AugmentationSourceRegistry()
        registry.register(PyProjectSource())
        registry.clear()

        assert registry.list_sources() == []


# =============================================================================
# Test AugmentationCollector
# =============================================================================


class TestAugmentationCollector:
    """Test the augmentation collector."""

    def test_collect_from_multiple_sources(self, temp_dir, sample_pyproject_toml, sample_sbomify_json):
        """Test collecting data from multiple sources."""
        (temp_dir / "pyproject.toml").write_text(sample_pyproject_toml)
        (temp_dir / ".sbomify.json").write_text(sample_sbomify_json)

        registry = AugmentationSourceRegistry()
        registry.register(LocalJSONSource())
        registry.register(PyProjectSource())

        collector = AugmentationCollector(registry)
        data = collector.collect(temp_dir, {})

        assert data is not None
        assert data.has_data()

    def test_collect_empty_sources(self, temp_dir):
        """Test collecting with no available sources."""
        registry = AugmentationSourceRegistry()
        collector = AugmentationCollector(registry)
        data = collector.collect(temp_dir, {})

        assert data is None


# =============================================================================
# Test create_default_registry
# =============================================================================


class TestCreateDefaultRegistry:
    """Test the default registry factory."""

    def test_creates_registry_with_all_sources(self):
        """Test that default registry includes all sources."""
        registry = create_default_registry()
        sources = registry.list_sources()

        source_names = [s["name"] for s in sources]
        assert "sbomify-api" in source_names
        assert "local-json" in source_names
        assert "pyproject.toml" in source_names
        assert "package.json" in source_names
        assert "Cargo.toml" in source_names

    def test_priority_order(self):
        """Test that sources are in correct priority order."""
        registry = create_default_registry()
        sources = registry.list_sources()

        # Should be sorted by priority
        priorities = [s["priority"] for s in sources]
        assert priorities == sorted(priorities)

        # sbomify-api should be first (priority 10)
        assert sources[0]["name"] == "sbomify-api"


# =============================================================================
# Test Integration
# =============================================================================


class TestIntegration:
    """Integration tests for the augmentation system."""

    def test_full_augmentation_flow(self, temp_dir, sample_pyproject_toml):
        """Test complete augmentation flow with real files."""
        # Create test files
        (temp_dir / "pyproject.toml").write_text(sample_pyproject_toml)
        sbomify_content = json.dumps({"supplier": {"name": "Test Supplier"}, "licenses": ["Apache-2.0"]})
        (temp_dir / ".sbomify.json").write_text(sbomify_content)

        # Use default registry
        registry = create_default_registry()
        collector = AugmentationCollector(registry)

        # Collect data (no API credentials, so sbomify-api won't contribute)
        config = {}
        data = collector.collect(temp_dir, config)

        assert data is not None
        assert data.has_data()

        # Convert to dict for augmentation
        result = data.to_dict()
        assert "supplier" in result
        assert "licenses" in result

    def test_augmentation_priority(self, temp_dir):
        """Test that higher priority sources take precedence."""
        # Create conflicting data
        pyproject = """
[project]
name = "test"
license = "GPL-3.0"
authors = [{name = "PyProject Author"}]
"""
        sbomify = json.dumps({"licenses": ["MIT"], "authors": [{"name": "JSON Author"}]})

        (temp_dir / "pyproject.toml").write_text(pyproject)
        (temp_dir / ".sbomify.json").write_text(sbomify)

        registry = create_default_registry()
        collector = AugmentationCollector(registry)
        data = collector.collect(temp_dir, {})

        assert data is not None
        # Local JSON (priority 50) should take precedence over pyproject.toml (priority 70)
        assert "MIT" in data.licenses
        # Both authors should be merged
        author_names = [a.name for a in data.authors]
        assert "JSON Author" in author_names
