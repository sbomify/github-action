"""Tests for the serialization module, including dependency graph sanitization."""

import pytest
from cyclonedx.model import BomRef
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency

from sbomify_action.serialization import (
    _UNKNOWN_VERSION,
    _extract_component_info_from_purl,
    sanitize_dependency_graph,
    serialize_cyclonedx_bom,
)


class TestExtractComponentInfoFromPurl:
    """Tests for PURL parsing helper function."""

    def test_simple_npm_purl(self):
        """Test parsing a simple npm PURL."""
        name, version, namespace, purl_obj = _extract_component_info_from_purl("pkg:npm/lodash@4.17.21")
        assert name == "lodash"
        assert version == "4.17.21"
        assert namespace is None
        assert purl_obj is not None
        assert purl_obj.type == "npm"
        assert purl_obj.name == "lodash"

    def test_scoped_npm_purl(self):
        """Test parsing a scoped npm PURL with URL-encoded @ symbol."""
        name, version, namespace, purl_obj = _extract_component_info_from_purl("pkg:npm/%40scope/package@1.0.0")
        assert name == "package"
        assert version == "1.0.0"
        assert namespace == "@scope"
        assert purl_obj is not None

    def test_pypi_purl(self):
        """Test parsing a PyPI PURL."""
        name, version, namespace, purl_obj = _extract_component_info_from_purl("pkg:pypi/requests@2.31.0")
        assert name == "requests"
        assert version == "2.31.0"
        assert namespace is None

    def test_maven_purl_with_group(self):
        """Test parsing a Maven PURL with namespace."""
        name, version, namespace, purl_obj = _extract_component_info_from_purl(
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
        )
        assert name == "commons-lang3"
        assert version == "3.12.0"
        assert namespace == "org.apache.commons"

    def test_purl_without_version(self):
        """Test parsing a PURL without version."""
        name, version, namespace, purl_obj = _extract_component_info_from_purl("pkg:npm/lodash")
        assert name == "lodash"
        assert version is None
        assert namespace is None
        assert purl_obj is not None  # PURL object should still be valid

    def test_purl_with_qualifiers(self):
        """Test parsing a PURL with qualifiers after version."""
        name, version, namespace, purl_obj = _extract_component_info_from_purl("pkg:npm/lodash@4.17.21?arch=x86")
        assert name == "lodash"
        assert version == "4.17.21"
        assert namespace is None
        # Qualifiers are preserved in the PackageURL object
        assert purl_obj.qualifiers == {"arch": "x86"}

    def test_invalid_purl_no_pkg_prefix(self):
        """Test that non-PURL strings return None."""
        name, version, namespace, purl_obj = _extract_component_info_from_purl("not-a-purl")
        assert name is None
        assert version is None
        assert namespace is None
        assert purl_obj is None

    def test_invalid_purl_no_slash(self):
        """Test that malformed PURL without slash returns None."""
        name, version, namespace, purl_obj = _extract_component_info_from_purl("pkg:npm")
        assert name is None
        assert version is None
        assert namespace is None
        assert purl_obj is None


class TestSanitizeDependencyGraph:
    """Tests for dependency graph sanitization."""

    def test_no_orphaned_refs_returns_zero(self):
        """Test that a valid BOM with no orphans returns 0."""
        bom = Bom()
        comp1 = Component(
            name="comp1",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/comp1@1.0.0"),
        )
        comp2 = Component(
            name="comp2",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/comp2@1.0.0"),
        )
        bom.components.add(comp1)
        bom.components.add(comp2)

        # Add valid dependency
        dep = Dependency(ref=comp1.bom_ref)
        dep2 = Dependency(ref=comp2.bom_ref)
        dep.dependencies.add(dep2)
        bom.dependencies.add(dep)

        stubs_added = sanitize_dependency_graph(bom)
        assert stubs_added == 0
        assert len(bom.components) == 2

    def test_adds_stub_for_orphaned_nested_dependency(self):
        """Test that a stub is added for orphaned nested dependency reference."""
        bom = Bom()
        comp1 = Component(
            name="comp1",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/comp1@1.0.0"),
        )
        bom.components.add(comp1)

        # Add dependency that references unknown component
        unknown_ref = BomRef("pkg:npm/unknown@2.0.0")
        dep = Dependency(ref=comp1.bom_ref)
        dep.dependencies.add(Dependency(ref=unknown_ref))
        bom.dependencies.add(dep)

        stubs_added = sanitize_dependency_graph(bom)
        assert stubs_added == 1
        assert len(bom.components) == 2

        # Find the stub component
        stub = None
        for comp in bom.components:
            if comp.bom_ref and comp.bom_ref.value == "pkg:npm/unknown@2.0.0":
                stub = comp
                break

        assert stub is not None
        assert stub.name == "unknown"
        assert stub.version == "2.0.0"
        assert stub.type == ComponentType.LIBRARY

    def test_adds_stub_for_orphaned_top_level_dependency(self):
        """Test that a stub is added for orphaned top-level dependency entry."""
        bom = Bom()
        comp1 = Component(
            name="comp1",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/comp1@1.0.0"),
        )
        bom.components.add(comp1)

        # Add dependency entry for component that doesn't exist
        orphan_dep = Dependency(ref=BomRef("pkg:npm/orphan@1.0.0"))
        bom.dependencies.add(orphan_dep)

        stubs_added = sanitize_dependency_graph(bom)
        assert stubs_added == 1
        assert len(bom.components) == 2

    def test_handles_scoped_npm_packages(self):
        """Test that scoped npm packages are parsed correctly."""
        bom = Bom()
        comp1 = Component(
            name="comp1",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/comp1@1.0.0"),
        )
        bom.components.add(comp1)

        # Add dependency referencing scoped package
        scoped_ref = BomRef("pkg:npm/%40vue/chartjs@3.5.1")
        dep = Dependency(ref=comp1.bom_ref)
        dep.dependencies.add(Dependency(ref=scoped_ref))
        bom.dependencies.add(dep)

        stubs_added = sanitize_dependency_graph(bom)
        assert stubs_added == 1

        # Find the stub
        stub = None
        for comp in bom.components:
            if comp.bom_ref and comp.bom_ref.value == "pkg:npm/%40vue/chartjs@3.5.1":
                stub = comp
                break

        assert stub is not None
        assert stub.name == "chartjs"
        # CycloneDX Component uses 'group' field for PURL namespace (e.g., npm scopes)
        assert stub.group == "@vue"
        assert stub.version == "3.5.1"

    def test_handles_non_purl_refs(self):
        """Test that non-PURL refs get a stub with ref as name."""
        bom = Bom()
        comp1 = Component(
            name="comp1",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("comp1-ref"),
        )
        bom.components.add(comp1)

        # Add dependency with non-PURL ref
        weird_ref = BomRef("some-weird-ref-format")
        dep = Dependency(ref=comp1.bom_ref)
        dep.dependencies.add(Dependency(ref=weird_ref))
        bom.dependencies.add(dep)

        stubs_added = sanitize_dependency_graph(bom)
        assert stubs_added == 1

        # Find the stub
        stub = None
        for comp in bom.components:
            if comp.bom_ref and comp.bom_ref.value == "some-weird-ref-format":
                stub = comp
                break

        assert stub is not None
        assert stub.name == "some-weird-ref-format"
        assert stub.version == _UNKNOWN_VERSION

    def test_multiple_orphaned_refs(self):
        """Test that multiple orphaned refs are all handled."""
        bom = Bom()
        comp1 = Component(
            name="comp1",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/comp1@1.0.0"),
        )
        bom.components.add(comp1)

        # Add multiple orphaned dependencies
        dep = Dependency(ref=comp1.bom_ref)
        dep.dependencies.add(Dependency(ref=BomRef("pkg:npm/orphan1@1.0.0")))
        dep.dependencies.add(Dependency(ref=BomRef("pkg:npm/orphan2@2.0.0")))
        dep.dependencies.add(Dependency(ref=BomRef("pkg:npm/orphan3@3.0.0")))
        bom.dependencies.add(dep)

        stubs_added = sanitize_dependency_graph(bom)
        assert stubs_added == 3
        assert len(bom.components) == 4  # Original + 3 stubs

    def test_metadata_component_not_treated_as_orphan(self):
        """Test that metadata component refs are recognized as valid."""
        bom = Bom()

        # Add metadata component
        main_component = Component(
            name="main-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/main-app@1.0.0"),
        )
        bom.metadata.component = main_component

        # Add dependency entry for metadata component
        main_dep = Dependency(ref=main_component.bom_ref)
        bom.dependencies.add(main_dep)

        stubs_added = sanitize_dependency_graph(bom)
        assert stubs_added == 0
        assert len(bom.components) == 0  # No stubs added

    def test_bom_validates_after_sanitization(self):
        """Test that the BOM passes validation after sanitization."""
        bom = Bom()
        comp1 = Component(
            name="comp1",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/comp1@1.0.0"),
        )
        bom.components.add(comp1)

        # Add orphaned dependency that would fail validation
        orphan_ref = BomRef("pkg:npm/vue-chartjs@3.5.1")
        dep = Dependency(ref=comp1.bom_ref)
        dep.dependencies.add(Dependency(ref=orphan_ref))
        bom.dependencies.add(dep)

        # Before sanitization, validation would fail
        # (we don't call validate() directly as it throws)

        # Sanitize
        stubs_added = sanitize_dependency_graph(bom)
        assert stubs_added == 1

        # After sanitization, validation should pass
        bom.validate()  # Should not raise


class TestSerializeCycloneDxBom:
    """Tests for CycloneDX BOM serialization."""

    def test_serialize_with_explicit_version(self):
        """Test serialization with explicit version."""
        bom = Bom()
        comp = Component(
            name="test",
            type=ComponentType.LIBRARY,
            version="1.0.0",
        )
        bom.components.add(comp)

        result = serialize_cyclonedx_bom(bom, "1.6")
        assert '"bomFormat": "CycloneDX"' in result
        assert '"specVersion": "1.6"' in result

    def test_serialize_requires_version(self):
        """Test that serialization fails without version."""
        bom = Bom()
        with pytest.raises(ValueError, match="spec_version is required"):
            serialize_cyclonedx_bom(bom, None)
