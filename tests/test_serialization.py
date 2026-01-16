"""Tests for the serialization module, including dependency graph sanitization."""

import pytest
from cyclonedx.model import BomRef
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.dependency import Dependency

from sbomify_action.serialization import (
    _UNKNOWN_VERSION,
    SPDX_PACKAGE_PURPOSE_FIXES,
    _extract_component_info_from_purl,
    _is_invalid_purl,
    link_root_dependencies,
    normalize_purl,
    sanitize_dependency_graph,
    sanitize_purls,
    sanitize_spdx_json_file,
    sanitize_spdx_purls,
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

    def test_serialize_captures_dependency_warning(self, caplog):
        """Test that incomplete dependency graph warning is captured and re-emitted cleanly."""
        import logging

        # Create a BOM with root component and other components but no dependencies
        # This triggers the CycloneDX library warning about incomplete dependency graph
        bom = Bom()

        # Add a root component (metadata.component)
        root = Component(
            name="my-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("my-app-ref"),
        )
        bom.metadata.component = root

        # Add other components
        dep1 = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
        )
        bom.components.add(dep1)

        # No dependencies defined - this should trigger the warning
        with caplog.at_level(logging.WARNING):
            result = serialize_cyclonedx_bom(bom, "1.6")

        # Verify we got a result
        assert '"bomFormat": "CycloneDX"' in result

        # Verify our cleaned-up warning was logged (not the raw library warning)
        assert any("SBOM dependency graph is incomplete" in record.message for record in caplog.records)
        assert any("my-app" in record.message for record in caplog.records)
        assert any("SBOM generator doesn't track" in record.message for record in caplog.records)

    def test_serialize_no_warning_when_dependencies_defined(self, caplog):
        """Test that no warning is emitted when dependencies are properly defined."""
        import logging

        bom = Bom()

        # Add a root component
        root = Component(
            name="my-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("my-app-ref"),
        )
        bom.metadata.component = root

        # Add a dependency component
        dep1 = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
        )
        bom.components.add(dep1)

        # Define dependencies properly - root depends on lodash
        root_dep = Dependency(ref=root.bom_ref)
        lodash_dep = Dependency(ref=dep1.bom_ref)
        root_dep.dependencies.add(lodash_dep)
        bom.dependencies.add(root_dep)

        with caplog.at_level(logging.WARNING):
            result = serialize_cyclonedx_bom(bom, "1.6")

        # Verify we got a result
        assert '"bomFormat": "CycloneDX"' in result

        # No dependency warning should be logged
        assert not any("SBOM dependency graph is incomplete" in record.message for record in caplog.records)

    def test_serialize_no_warning_when_no_components(self, caplog):
        """Test that no warning is emitted when there are no components (just root)."""
        import logging

        bom = Bom()

        # Add only a root component, no other components
        root = Component(
            name="my-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("my-app-ref"),
        )
        bom.metadata.component = root

        with caplog.at_level(logging.WARNING):
            result = serialize_cyclonedx_bom(bom, "1.6")

        # Verify we got a result
        assert '"bomFormat": "CycloneDX"' in result

        # No dependency warning should be logged (no components to depend on)
        assert not any("SBOM dependency graph is incomplete" in record.message for record in caplog.records)


class TestLinkRootDependencies:
    """Tests for linking top-level components to root component."""

    def test_flat_graph_links_all_components(self):
        """Test that flat graph (no existing dependencies) links all components to root."""
        bom = Bom()

        # Add root component
        root = Component(
            name="my-container",
            type=ComponentType.CONTAINER,
            version="1.0.0",
            bom_ref=BomRef("pkg:oci/my-container@sha256:abc123"),
        )
        bom.metadata.component = root

        # Add components (flat - no dependencies between them)
        comp1 = Component(
            name="apt",
            type=ComponentType.LIBRARY,
            version="2.0.0",
            bom_ref=BomRef("pkg:generic/apt"),
        )
        comp2 = Component(
            name="bash",
            type=ComponentType.LIBRARY,
            version="5.0.0",
            bom_ref=BomRef("pkg:generic/bash"),
        )
        comp3 = Component(
            name="curl",
            type=ComponentType.LIBRARY,
            version="7.0.0",
            bom_ref=BomRef("pkg:generic/curl"),
        )
        bom.components.add(comp1)
        bom.components.add(comp2)
        bom.components.add(comp3)

        # Add empty dependency entries (like container SBOMs have)
        bom.dependencies.add(Dependency(ref=root.bom_ref))
        bom.dependencies.add(Dependency(ref=comp1.bom_ref))
        bom.dependencies.add(Dependency(ref=comp2.bom_ref))
        bom.dependencies.add(Dependency(ref=comp3.bom_ref))

        # Link root dependencies
        linked = link_root_dependencies(bom)

        # All 3 components should be linked to root
        assert linked == 3

        # Find root dependency entry and verify it has all components
        root_dep = None
        for dep in bom.dependencies:
            if dep.ref.value == root.bom_ref.value:
                root_dep = dep
                break

        assert root_dep is not None
        dep_refs = {d.ref.value for d in root_dep.dependencies}
        assert dep_refs == {"pkg:generic/apt", "pkg:generic/bash", "pkg:generic/curl"}

    def test_hierarchical_graph_preserves_tree(self):
        """Test that hierarchical graph only links top-level components, preserving tree."""
        bom = Bom()

        # Add root component
        root = Component(
            name="my-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("my-app-ref"),
        )
        bom.metadata.component = root

        # Add components with hierarchy: express -> body-parser -> bytes, lodash standalone
        express = Component(
            name="express",
            type=ComponentType.LIBRARY,
            version="4.18.0",
            bom_ref=BomRef("pkg:npm/express@4.18.0"),
        )
        body_parser = Component(
            name="body-parser",
            type=ComponentType.LIBRARY,
            version="1.20.0",
            bom_ref=BomRef("pkg:npm/body-parser@1.20.0"),
        )
        bytes_pkg = Component(
            name="bytes",
            type=ComponentType.LIBRARY,
            version="3.1.0",
            bom_ref=BomRef("pkg:npm/bytes@3.1.0"),
        )
        lodash = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
        )
        bom.components.add(express)
        bom.components.add(body_parser)
        bom.components.add(bytes_pkg)
        bom.components.add(lodash)

        # Set up dependency hierarchy
        root_dep = Dependency(ref=root.bom_ref)
        bom.dependencies.add(root_dep)

        express_dep = Dependency(ref=express.bom_ref)
        body_parser_dep_for_express = Dependency(ref=body_parser.bom_ref)
        express_dep.dependencies.add(body_parser_dep_for_express)
        bom.dependencies.add(express_dep)

        body_parser_dep = Dependency(ref=body_parser.bom_ref)
        bytes_dep_for_body_parser = Dependency(ref=bytes_pkg.bom_ref)
        body_parser_dep.dependencies.add(bytes_dep_for_body_parser)
        bom.dependencies.add(body_parser_dep)

        bom.dependencies.add(Dependency(ref=bytes_pkg.bom_ref))
        bom.dependencies.add(Dependency(ref=lodash.bom_ref))

        # Link root dependencies
        linked = link_root_dependencies(bom)

        # Only express and lodash should be linked (not body-parser or bytes)
        assert linked == 2

        # Find root dependency entry and verify
        for dep in bom.dependencies:
            if dep.ref.value == root.bom_ref.value:
                dep_refs = {d.ref.value for d in dep.dependencies}
                assert dep_refs == {"pkg:npm/express@4.18.0", "pkg:npm/lodash@4.17.21"}
                break

    def test_root_with_existing_deps_not_modified(self):
        """Test that root with existing dependencies is not modified."""
        bom = Bom()

        # Add root component
        root = Component(
            name="my-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("my-app-ref"),
        )
        bom.metadata.component = root

        # Add components
        comp1 = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
        )
        comp2 = Component(
            name="express",
            type=ComponentType.LIBRARY,
            version="4.18.0",
            bom_ref=BomRef("pkg:npm/express@4.18.0"),
        )
        bom.components.add(comp1)
        bom.components.add(comp2)

        # Root already has dependencies defined
        root_dep = Dependency(ref=root.bom_ref)
        root_dep.dependencies.add(Dependency(ref=comp1.bom_ref))
        bom.dependencies.add(root_dep)

        # Try to link - should do nothing
        linked = link_root_dependencies(bom)

        assert linked == 0

        # Verify root still has only lodash (express not added)
        for dep in bom.dependencies:
            if dep.ref.value == root.bom_ref.value:
                dep_refs = {d.ref.value for d in dep.dependencies}
                assert dep_refs == {"pkg:npm/lodash@4.17.21"}
                break

    def test_no_root_component_does_nothing(self):
        """Test that BOM without root component is not modified."""
        bom = Bom()

        # Add components but no root
        comp1 = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
        )
        bom.components.add(comp1)

        linked = link_root_dependencies(bom)

        assert linked == 0

    def test_root_without_bomref_does_nothing(self):
        """Test that root component without bom-ref is not modified."""
        bom = Bom()

        # Add root component without bom-ref
        root = Component(
            name="my-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
        )
        bom.metadata.component = root

        # Add components
        comp1 = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
        )
        bom.components.add(comp1)

        linked = link_root_dependencies(bom)

        assert linked == 0

    def test_creates_root_dep_entry_if_missing(self):
        """Test that root dependency entry is created if it doesn't exist."""
        bom = Bom()

        # Add root component
        root = Component(
            name="my-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("my-app-ref"),
        )
        bom.metadata.component = root

        # Add component
        comp1 = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
        )
        bom.components.add(comp1)

        # Don't add root to dependencies - it should be created
        bom.dependencies.add(Dependency(ref=comp1.bom_ref))

        linked = link_root_dependencies(bom)

        assert linked == 1

        # Verify root dependency entry was created with lodash
        root_dep_found = False
        for dep in bom.dependencies:
            if dep.ref.value == root.bom_ref.value:
                root_dep_found = True
                dep_refs = {d.ref.value for d in dep.dependencies}
                assert dep_refs == {"pkg:npm/lodash@4.17.21"}
                break

        assert root_dep_found

    def test_no_components_does_nothing(self):
        """Test that BOM with root but no components does nothing."""
        bom = Bom()

        # Add root component only
        root = Component(
            name="my-app",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("my-app-ref"),
        )
        bom.metadata.component = root

        linked = link_root_dependencies(bom)

        assert linked == 0


class TestIsInvalidPurl:
    """Tests for PURL validation helper function."""

    def test_valid_npm_purl(self):
        """Test that a valid npm PURL is accepted."""
        is_invalid, reason = _is_invalid_purl("pkg:npm/lodash@4.17.21")
        assert not is_invalid
        assert reason == ""

    def test_valid_maven_purl(self):
        """Test that a valid Maven PURL is accepted."""
        is_invalid, reason = _is_invalid_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
        assert not is_invalid
        assert reason == ""

    def test_file_reference_in_purl_string(self):
        """Test that PURLs with file: references in string are rejected early."""
        is_invalid, reason = _is_invalid_purl("pkg:npm/%40keycloak/admin-ui@1.0.0?vcs_url=file:apps/admin-ui")
        assert is_invalid
        assert "file:" in reason

    def test_file_reference_in_parsed_qualifiers(self):
        """Test that file: references are detected in parsed qualifiers."""
        # This tests the second validation path after PURL parsing
        is_invalid, reason = _is_invalid_purl("pkg:npm/%40keycloak/admin-ui@1.0.0?repository_url=file:../local")
        assert is_invalid
        assert "file:" in reason

    def test_link_reference_in_purl(self):
        """Test that PURLs with link: references are rejected."""
        is_invalid, reason = _is_invalid_purl("pkg:npm/some-pkg@link:../packages/foo")
        assert is_invalid
        assert "link:" in reason

    def test_path_based_version(self):
        """Test that path-based versions are rejected."""
        is_invalid, reason = _is_invalid_purl("pkg:npm/some-pkg@../../packages/foo")
        assert is_invalid
        assert "path-based" in reason

    def test_root_namespace(self):
        """Test that root namespace is rejected."""
        # Test with @root namespace (proper npm scoped package format)
        is_invalid, reason = _is_invalid_purl("pkg:npm/%40root/some-pkg@1.0.0")
        assert is_invalid
        assert "root" in reason

        # Also test unscoped root namespace
        is_invalid, reason = _is_invalid_purl("pkg:npm/root/some-pkg@1.0.0")
        assert is_invalid
        assert "root" in reason

    def test_missing_version_npm(self):
        """Test that npm packages without version are rejected."""
        is_invalid, reason = _is_invalid_purl("pkg:npm/lodash")
        assert is_invalid
        assert "missing version" in reason

    def test_missing_version_maven(self):
        """Test that maven packages without version are rejected."""
        is_invalid, reason = _is_invalid_purl("pkg:maven/org.apache/commons")
        assert is_invalid
        assert "missing version" in reason

    def test_empty_purl_rejected(self):
        """Test that empty PURL is rejected."""
        is_invalid, reason = _is_invalid_purl("")
        assert is_invalid
        assert "empty" in reason

    def test_malformed_purl(self):
        """Test that malformed PURL is rejected."""
        is_invalid, reason = _is_invalid_purl("not-a-purl")
        assert is_invalid
        assert "malformed" in reason

    def test_deb_without_version_allowed(self):
        """Test that deb packages without version are allowed (version may come from distro)."""
        # deb is not in the list of types that require version
        is_invalid, reason = _is_invalid_purl("pkg:deb/debian/openssl")
        assert not is_invalid


class TestNormalizePurl:
    """Tests for PURL normalization function."""

    def test_no_change_for_valid_purl(self):
        """Test that valid PURLs are not modified."""
        purl = "pkg:npm/%40scope/package@1.0.0"
        normalized, was_modified = normalize_purl(purl)
        assert not was_modified
        assert normalized == purl

    def test_fixes_double_at_in_version(self):
        """Test that double @@ before version is fixed."""
        purl = "pkg:npm/%40scope/pkg@@1.0.0"
        normalized, was_modified = normalize_purl(purl)
        assert was_modified
        assert "@@" not in normalized
        # Should have single @ before version and not be encoded
        assert "@1.0.0" in normalized
        assert "%401.0.0" not in normalized

    def test_fixes_double_encoded_at(self):
        """Test that double-encoded @ (%40%40) is fixed."""
        purl = "pkg:npm/%40%40scope/pkg@1.0.0"
        normalized, was_modified = normalize_purl(purl)
        assert was_modified
        assert "%40%40" not in normalized

    def test_empty_purl(self):
        """Test that empty PURL returns unchanged."""
        normalized, was_modified = normalize_purl("")
        assert not was_modified
        assert normalized == ""

    def test_none_purl(self):
        """Test that None PURL returns unchanged."""
        normalized, was_modified = normalize_purl(None)
        assert not was_modified
        assert normalized is None


class TestSanitizePurls:
    """Tests for PURL sanitization function."""

    def test_clears_purl_with_file_reference(self):
        """Test that PURLs with file: references are cleared but component kept."""
        from packageurl import PackageURL

        bom = Bom()
        # Valid component
        valid_comp = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
            purl=PackageURL.from_string("pkg:npm/lodash@4.17.21"),
        )
        # Component with invalid file: reference in PURL
        invalid_comp = Component(
            name="admin-ui",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/%40keycloak/admin-ui@1.0.0"),
            purl=PackageURL(
                type="npm",
                namespace="@keycloak",
                name="admin-ui",
                version="1.0.0",
                qualifiers={"vcs_url": "file:apps/admin-ui"},
            ),
        )
        bom.components.add(valid_comp)
        bom.components.add(invalid_comp)

        normalized, cleared = sanitize_purls(bom)
        assert cleared == 1
        # Both components are kept (preserves dependency graph)
        assert len(bom.components) == 2

        # Find the sanitized component
        admin_ui = None
        for comp in bom.components:
            if comp.name == "admin-ui":
                admin_ui = comp
                break

        assert admin_ui is not None
        assert admin_ui.purl is None  # PURL cleared
        assert admin_ui.version == "1.0.0"  # Other fields preserved

    def test_clears_purl_without_version(self):
        """Test that PURLs without version are cleared but component kept."""
        from packageurl import PackageURL

        bom = Bom()
        # Valid component
        valid_comp = Component(
            name="lodash",
            type=ComponentType.LIBRARY,
            version="4.17.21",
            bom_ref=BomRef("pkg:npm/lodash@4.17.21"),
            purl=PackageURL.from_string("pkg:npm/lodash@4.17.21"),
        )
        # Component with PURL missing version
        invalid_comp = Component(
            name="no-version",
            type=ComponentType.LIBRARY,
            version="1.0.0",  # Component has version, but PURL doesn't
            bom_ref=BomRef("pkg:npm/no-version"),
            purl=PackageURL.from_string("pkg:npm/no-version"),
        )
        bom.components.add(valid_comp)
        bom.components.add(invalid_comp)

        normalized, cleared = sanitize_purls(bom)
        assert cleared == 1
        # Both components kept
        assert len(bom.components) == 2

        # Find the sanitized component
        no_version = None
        for comp in bom.components:
            if comp.name == "no-version":
                no_version = comp
                break

        assert no_version is not None
        assert no_version.purl is None  # PURL cleared
        assert no_version.version == "1.0.0"  # Component version preserved

    def test_clears_invalid_metadata_component_purl(self):
        """Test that invalid PURLs are cleared from metadata component."""
        from packageurl import PackageURL

        bom = Bom()
        # Metadata component with invalid PURL
        meta_comp = Component(
            name="admin-ui",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("main"),
            purl=PackageURL(
                type="npm",
                namespace="@keycloak",
                name="admin-ui",
                qualifiers={"vcs_url": "file:apps/admin-ui"},
            ),
        )
        bom.metadata.component = meta_comp

        normalized, cleared = sanitize_purls(bom)
        assert cleared == 1
        assert bom.metadata.component is not None
        assert bom.metadata.component.purl is None
        assert bom.metadata.component.name == "admin-ui"  # Other fields preserved

    def test_keeps_valid_components_and_purls(self):
        """Test that valid components keep their PURLs."""
        from packageurl import PackageURL

        bom = Bom()
        for i in range(5):
            comp = Component(
                name=f"pkg{i}",
                type=ComponentType.LIBRARY,
                version="1.0.0",
                bom_ref=BomRef(f"pkg:npm/pkg{i}@1.0.0"),
                purl=PackageURL.from_string(f"pkg:npm/pkg{i}@1.0.0"),
            )
            bom.components.add(comp)

        normalized, cleared = sanitize_purls(bom)
        assert normalized == 0
        assert cleared == 0
        assert len(bom.components) == 5
        # All PURLs preserved
        for comp in bom.components:
            assert comp.purl is not None

    def test_returns_zero_for_empty_bom(self):
        """Test that empty BOM returns zeros."""
        bom = Bom()
        normalized, cleared = sanitize_purls(bom)
        assert normalized == 0
        assert cleared == 0

    def test_preserves_dependency_graph(self):
        """Test that dependency graph is preserved when PURLs are cleared."""
        from packageurl import PackageURL

        bom = Bom()
        # Parent component (valid)
        parent = Component(
            name="parent",
            type=ComponentType.APPLICATION,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/parent@1.0.0"),
            purl=PackageURL.from_string("pkg:npm/parent@1.0.0"),
        )
        # Child component (invalid PURL - missing version)
        child = Component(
            name="child",
            type=ComponentType.LIBRARY,
            version="2.0.0",
            bom_ref=BomRef("pkg:npm/child"),
            purl=PackageURL.from_string("pkg:npm/child"),
        )
        bom.components.add(parent)
        bom.components.add(child)

        # Add dependency: parent depends on child
        parent_dep = Dependency(ref=parent.bom_ref)
        child_dep = Dependency(ref=child.bom_ref)
        parent_dep.dependencies.add(child_dep)
        bom.dependencies.add(parent_dep)

        normalized, cleared = sanitize_purls(bom)
        assert cleared == 1

        # Both components still exist
        assert len(bom.components) == 2

        # Dependency graph intact
        assert len(bom.dependencies) == 1
        dep = list(bom.dependencies)[0]
        assert dep.ref.value == "pkg:npm/parent@1.0.0"
        assert len(dep.dependencies) == 1

    def test_valid_scoped_purl_not_modified(self):
        """Test that valid scoped PURLs are not modified by sanitization."""
        from packageurl import PackageURL

        bom = Bom()
        # Valid scoped npm package - should not be touched
        comp = Component(
            name="pkg",
            type=ComponentType.LIBRARY,
            version="1.0.0",
            bom_ref=BomRef("pkg:npm/%40scope/pkg@1.0.0"),
            purl=PackageURL.from_string("pkg:npm/%40scope/pkg@1.0.0"),
        )
        bom.components.add(comp)

        # Valid PURL should not be modified or cleared
        normalized, cleared = sanitize_purls(bom)
        assert normalized == 0
        assert cleared == 0
        assert comp.purl is not None

    def test_clears_invalid_tools_component_purl(self):
        """Test that invalid PURLs are cleared from tools.components (CycloneDX 1.5+)."""
        from packageurl import PackageURL

        bom = Bom()
        # Add a valid tool component
        valid_tool = Component(
            name="trivy",
            type=ComponentType.APPLICATION,
            version="0.67.2",
            purl=PackageURL.from_string("pkg:golang/github.com/aquasecurity/trivy@0.67.2"),
        )
        valid_tool.group = "aquasecurity"
        bom.metadata.tools.components.add(valid_tool)

        # Add a tool component with invalid PURL (missing version)
        invalid_tool = Component(
            name="cdxgen",
            type=ComponentType.APPLICATION,
            version="11.0.0",  # Component has version, but PURL doesn't
            purl=PackageURL.from_string("pkg:npm/cdxgen"),
        )
        bom.metadata.tools.components.add(invalid_tool)

        normalized, cleared = sanitize_purls(bom)
        assert cleared == 1

        # Both tool components are kept
        assert len(bom.metadata.tools.components) == 2

        # Find the sanitized tool component
        cdxgen_tool = None
        for comp in bom.metadata.tools.components:
            if comp.name == "cdxgen":
                cdxgen_tool = comp
                break

        assert cdxgen_tool is not None
        assert cdxgen_tool.purl is None  # PURL cleared
        assert cdxgen_tool.version == "11.0.0"  # Other fields preserved

        # Valid tool component should still have its PURL
        trivy_tool = None
        for comp in bom.metadata.tools.components:
            if comp.name == "trivy":
                trivy_tool = comp
                break
        assert trivy_tool is not None
        assert trivy_tool.purl is not None

    def test_normalizes_tools_component_purl_encoding(self):
        """Test that double %40 encoding is normalized in tools.components."""
        from packageurl import PackageURL

        bom = Bom()
        # Tool component with double-encoded @ (%40%40 issue)
        tool = Component(
            name="scoped-tool",
            type=ComponentType.APPLICATION,
            version="1.0.0",
        )
        # Manually create a PURL with double %40 encoding issue
        tool.purl = PackageURL.from_string("pkg:npm/%40scope/tool@1.0.0")
        bom.metadata.tools.components.add(tool)

        # Valid scoped PURL should not be modified
        normalized, cleared = sanitize_purls(bom)
        assert cleared == 0
        # The PURL should still be valid
        assert tool.purl is not None


class TestSpdxPurlSanitization:
    """Tests for SPDX PURL sanitization in external references."""

    def test_normalizes_spdx_purl_with_double_at(self):
        """Test that SPDX PURL with double @@ is normalized."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            ExternalPackageRef,
            ExternalPackageRefCategory,
            Package,
            SpdxNoAssertion,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://test.com/test-doc",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime(2024, 1, 1),
        )
        document = Document(creation_info=creation_info)

        package = Package(
            spdx_id="SPDXRef-Package-parser",
            name="parser",
            version="7.28.0",
            download_location=SpdxNoAssertion(),
        )
        # Add PURL with double @@ issue
        package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:npm/%40babel/parser@@7.28.0",
            )
        )
        document.packages.append(package)

        normalized_count = sanitize_spdx_purls(document)

        assert normalized_count == 1
        # Check the locator was normalized
        purl_ref = package.external_references[0]
        assert "@@" not in purl_ref.locator
        assert "@7.28.0" in purl_ref.locator

    def test_normalizes_spdx_purl_with_double_encoded_at(self):
        """Test that SPDX PURL with double %40 encoding is normalized."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            ExternalPackageRef,
            ExternalPackageRefCategory,
            Package,
            SpdxNoAssertion,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://test.com/test-doc",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime(2024, 1, 1),
        )
        document = Document(creation_info=creation_info)

        package = Package(
            spdx_id="SPDXRef-Package-parser",
            name="parser",
            version="7.28.0",
            download_location=SpdxNoAssertion(),
        )
        # Add PURL with double %40 encoding issue
        package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator="pkg:npm/%40%40babel/parser@7.28.0",
            )
        )
        document.packages.append(package)

        normalized_count = sanitize_spdx_purls(document)

        assert normalized_count == 1
        # Check the locator was normalized
        purl_ref = package.external_references[0]
        assert "%40%40" not in purl_ref.locator

    def test_valid_spdx_purl_unchanged(self):
        """Test that valid SPDX PURLs are not modified."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            ExternalPackageRef,
            ExternalPackageRefCategory,
            Package,
            SpdxNoAssertion,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://test.com/test-doc",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime(2024, 1, 1),
        )
        document = Document(creation_info=creation_info)

        package = Package(
            spdx_id="SPDXRef-Package-parser",
            name="parser",
            version="7.28.0",
            download_location=SpdxNoAssertion(),
        )
        # Add valid PURL (single %40 is correct)
        original_locator = "pkg:npm/%40babel/parser@7.28.0"
        package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=original_locator,
            )
        )
        document.packages.append(package)

        normalized_count = sanitize_spdx_purls(document)

        assert normalized_count == 0
        # Check the locator was not modified
        purl_ref = package.external_references[0]
        assert purl_ref.locator == original_locator

    def test_non_purl_refs_unchanged(self):
        """Test that non-PURL external references are not modified."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            ExternalPackageRef,
            ExternalPackageRefCategory,
            Package,
            SpdxNoAssertion,
        )

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://test.com/test-doc",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime(2024, 1, 1),
        )
        document = Document(creation_info=creation_info)

        package = Package(
            spdx_id="SPDXRef-Package-mylib",
            name="mylib",
            version="1.0.0",
            download_location=SpdxNoAssertion(),
        )
        # Add non-PURL reference (e.g., CPE)
        original_locator = "cpe:2.3:a:vendor:mylib:1.0.0:*:*:*:*:*:*:*"
        package.external_references.append(
            ExternalPackageRef(
                category=ExternalPackageRefCategory.SECURITY,
                reference_type="cpe23Type",
                locator=original_locator,
            )
        )
        document.packages.append(package)

        normalized_count = sanitize_spdx_purls(document)

        assert normalized_count == 0
        # Check the locator was not modified
        ref = package.external_references[0]
        assert ref.locator == original_locator


class TestSanitizeSpdxJsonFile:
    """Tests for SPDX JSON file sanitization (fixing spdx_tools enum bugs)."""

    def test_fixes_operating_system_enum(self, tmp_path):
        """Test that OPERATING_SYSTEM is fixed to OPERATING-SYSTEM."""
        import json

        spdx_file = tmp_path / "test.spdx.json"
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-debian",
                    "name": "debian",
                    "primaryPackagePurpose": "OPERATING_SYSTEM",
                }
            ],
        }
        spdx_file.write_text(json.dumps(spdx_data))

        fixed_count = sanitize_spdx_json_file(str(spdx_file))

        assert fixed_count == 1

        # Verify the file was fixed
        with open(spdx_file) as f:
            result = json.load(f)
        assert result["packages"][0]["primaryPackagePurpose"] == "OPERATING-SYSTEM"

    def test_no_changes_when_already_correct(self, tmp_path):
        """Test that already correct values are not modified."""
        import json

        spdx_file = tmp_path / "test.spdx.json"
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-debian",
                    "name": "debian",
                    "primaryPackagePurpose": "OPERATING-SYSTEM",
                },
                {
                    "SPDXID": "SPDXRef-Package-mylib",
                    "name": "mylib",
                    "primaryPackagePurpose": "LIBRARY",
                },
            ],
        }
        original_content = json.dumps(spdx_data)
        spdx_file.write_text(original_content)

        fixed_count = sanitize_spdx_json_file(str(spdx_file))

        assert fixed_count == 0

        # File should not have been rewritten
        assert spdx_file.read_text() == original_content

    def test_fixes_multiple_packages(self, tmp_path):
        """Test that multiple packages with OPERATING_SYSTEM are fixed."""
        import json

        spdx_file = tmp_path / "test.spdx.json"
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-debian",
                    "name": "debian",
                    "primaryPackagePurpose": "OPERATING_SYSTEM",
                },
                {
                    "SPDXID": "SPDXRef-Package-alpine",
                    "name": "alpine",
                    "primaryPackagePurpose": "OPERATING_SYSTEM",
                },
                {
                    "SPDXID": "SPDXRef-Package-mylib",
                    "name": "mylib",
                    "primaryPackagePurpose": "LIBRARY",
                },
            ],
        }
        spdx_file.write_text(json.dumps(spdx_data))

        fixed_count = sanitize_spdx_json_file(str(spdx_file))

        assert fixed_count == 2

        # Verify both were fixed
        with open(spdx_file) as f:
            result = json.load(f)
        assert result["packages"][0]["primaryPackagePurpose"] == "OPERATING-SYSTEM"
        assert result["packages"][1]["primaryPackagePurpose"] == "OPERATING-SYSTEM"
        assert result["packages"][2]["primaryPackagePurpose"] == "LIBRARY"

    def test_nonexistent_file_returns_zero(self, tmp_path, caplog):
        """Test that nonexistent file returns 0 with warning."""
        import logging

        nonexistent = tmp_path / "nonexistent.spdx.json"

        with caplog.at_level(logging.WARNING):
            fixed_count = sanitize_spdx_json_file(str(nonexistent))

        assert fixed_count == 0
        assert any("Failed to read SPDX file" in record.message for record in caplog.records)

    def test_invalid_json_returns_zero(self, tmp_path, caplog):
        """Test that invalid JSON file returns 0 with warning."""
        import logging

        invalid_file = tmp_path / "invalid.spdx.json"
        invalid_file.write_text("{ this is not valid json }")

        with caplog.at_level(logging.WARNING):
            fixed_count = sanitize_spdx_json_file(str(invalid_file))

        assert fixed_count == 0
        assert any("Failed to read SPDX file" in record.message for record in caplog.records)

    def test_preserves_unicode_characters(self, tmp_path):
        """Test that Unicode characters in package names are preserved."""
        import json

        spdx_file = tmp_path / "test.spdx.json"
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-unicode",
                    "name": "日本語パッケージ",
                    "description": "Пакет с описанием на русском языке",
                    "primaryPackagePurpose": "OPERATING_SYSTEM",
                }
            ],
        }
        spdx_file.write_text(json.dumps(spdx_data, ensure_ascii=False))

        fixed_count = sanitize_spdx_json_file(str(spdx_file))

        assert fixed_count == 1

        # Verify Unicode is preserved
        with open(spdx_file, encoding="utf-8") as f:
            result = json.load(f)
        assert result["packages"][0]["name"] == "日本語パッケージ"
        assert result["packages"][0]["description"] == "Пакет с описанием на русском языке"
        assert result["packages"][0]["primaryPackagePurpose"] == "OPERATING-SYSTEM"

    def test_empty_packages_array(self, tmp_path):
        """Test that empty packages array is handled correctly."""
        import json

        spdx_file = tmp_path / "test.spdx.json"
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [],
        }
        original_content = json.dumps(spdx_data)
        spdx_file.write_text(original_content)

        fixed_count = sanitize_spdx_json_file(str(spdx_file))

        assert fixed_count == 0
        # File should not have been rewritten
        assert spdx_file.read_text() == original_content

    def test_missing_packages_field(self, tmp_path):
        """Test that missing packages field is handled correctly."""
        import json

        spdx_file = tmp_path / "test.spdx.json"
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
        }
        original_content = json.dumps(spdx_data)
        spdx_file.write_text(original_content)

        fixed_count = sanitize_spdx_json_file(str(spdx_file))

        assert fixed_count == 0
        # File should not have been rewritten
        assert spdx_file.read_text() == original_content

    def test_package_without_purpose_field(self, tmp_path):
        """Test that packages without primaryPackagePurpose are handled correctly."""
        import json

        spdx_file = tmp_path / "test.spdx.json"
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-mylib",
                    "name": "mylib",
                    # No primaryPackagePurpose field
                }
            ],
        }
        original_content = json.dumps(spdx_data)
        spdx_file.write_text(original_content)

        fixed_count = sanitize_spdx_json_file(str(spdx_file))

        assert fixed_count == 0
        # File should not have been rewritten
        assert spdx_file.read_text() == original_content

    def test_spdx_package_purpose_fixes_map(self):
        """Test that the SPDX_PACKAGE_PURPOSE_FIXES map contains expected entries."""
        # This tests that the fix map is properly defined
        assert "OPERATING_SYSTEM" in SPDX_PACKAGE_PURPOSE_FIXES
        assert SPDX_PACKAGE_PURPOSE_FIXES["OPERATING_SYSTEM"] == "OPERATING-SYSTEM"
        # Ensure no other enum values are incorrectly included
        # (only OPERATING_SYSTEM has underscore that maps to hyphen in SPDX spec)
        assert len(SPDX_PACKAGE_PURPOSE_FIXES) == 1
