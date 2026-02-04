"""Tests for the dependency expansion subsystem."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from sbomify_action._dependency_expansion import (
    DiscoveredDependency,
    ExpansionResult,
    create_default_registry,
    expand_sbom_dependencies,
    normalize_python_package_name,
)
from sbomify_action._dependency_expansion.expanders.pipdeptree import PipdeptreeExpander
from sbomify_action._dependency_expansion.registry import ExpanderRegistry


class TestNormalizePythonPackageName:
    """Tests for normalize_python_package_name function."""

    def test_lowercase(self):
        """Test that names are lowercased."""
        assert normalize_python_package_name("Django") == "django"
        assert normalize_python_package_name("REQUESTS") == "requests"

    def test_hyphen_to_underscore(self):
        """Test that hyphens become underscores."""
        assert normalize_python_package_name("my-package") == "my_package"
        assert normalize_python_package_name("some-long-name") == "some_long_name"

    def test_dot_to_underscore(self):
        """Test that dots become underscores."""
        assert normalize_python_package_name("zope.interface") == "zope_interface"

    def test_mixed_normalization(self):
        """Test mixed case with various separators."""
        assert normalize_python_package_name("My-Package.Name") == "my_package_name"


class TestDiscoveredDependency:
    """Tests for DiscoveredDependency dataclass."""

    def test_basic_creation(self):
        """Test basic dataclass creation."""
        dep = DiscoveredDependency(
            name="urllib3",
            version="2.0.4",
            purl="pkg:pypi/urllib3@2.0.4",
            parent="requests",
            depth=1,
        )
        assert dep.name == "urllib3"
        assert dep.version == "2.0.4"
        assert dep.purl == "pkg:pypi/urllib3@2.0.4"
        assert dep.parent == "requests"
        assert dep.depth == 1
        assert dep.ecosystem == "pypi"  # Default

    def test_defaults(self):
        """Test default values."""
        dep = DiscoveredDependency(
            name="certifi",
            version="2023.7.22",
            purl="pkg:pypi/certifi@2023.7.22",
        )
        assert dep.parent is None
        assert dep.depth == 1
        assert dep.ecosystem == "pypi"


class TestExpansionResult:
    """Tests for ExpansionResult dataclass."""

    def test_basic_creation(self):
        """Test basic dataclass creation."""
        result = ExpansionResult(
            original_count=5,
            discovered_count=10,
            added_count=8,
            dependencies=[],
            source="pipdeptree",
        )
        assert result.original_count == 5
        assert result.discovered_count == 10
        assert result.added_count == 8
        assert result.source == "pipdeptree"

    def test_source_required(self):
        """Test that source is a required field."""
        # source must be provided explicitly - no default value
        result = ExpansionResult(
            original_count=0,
            discovered_count=0,
            added_count=0,
            dependencies=[],
            source="test-expander",
        )
        assert result.source == "test-expander"


class TestPipdeptreeExpander:
    """Tests for PipdeptreeExpander class."""

    def test_name(self):
        """Test expander name."""
        expander = PipdeptreeExpander()
        assert expander.name == "pipdeptree"

    def test_priority(self):
        """Test expander priority."""
        expander = PipdeptreeExpander()
        assert expander.priority == 10

    def test_ecosystems(self):
        """Test supported ecosystems."""
        expander = PipdeptreeExpander()
        assert "pypi" in expander.ecosystems

    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree._PIPDEPTREE_AVAILABLE", True)
    def test_supports_requirements_txt(self):
        """Test that requirements.txt is supported."""
        expander = PipdeptreeExpander()
        assert expander.supports(Path("requirements.txt"))

    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree._PIPDEPTREE_AVAILABLE", True)
    def test_not_supports_other_lockfiles(self):
        """Test that other lockfiles are not supported."""
        expander = PipdeptreeExpander()
        assert not expander.supports(Path("poetry.lock"))
        assert not expander.supports(Path("Pipfile.lock"))
        assert not expander.supports(Path("uv.lock"))

    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree._PIPDEPTREE_AVAILABLE", False)
    def test_not_supports_when_tool_unavailable(self):
        """Test that nothing is supported when pipdeptree is unavailable."""
        expander = PipdeptreeExpander()
        assert not expander.supports(Path("requirements.txt"))

    def test_parse_requirements_basic(self, tmp_path):
        """Test parsing basic requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            """
requests==2.31.0
django>=4.0
flask
"""
        )

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert "requests" in deps
        assert deps["requests"] == "2.31.0"
        assert "django" in deps
        assert deps["django"] is None  # No exact version
        assert "flask" in deps
        assert deps["flask"] is None

    def test_parse_requirements_with_comments(self, tmp_path):
        """Test parsing requirements.txt with comments."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            """
# This is a comment
requests==2.31.0

# Another comment
django>=4.0  # inline comment
"""
        )

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert "requests" in deps
        assert "django" in deps
        assert len(deps) == 2

    def test_parse_requirements_with_extras(self, tmp_path):
        """Test parsing requirements with extras."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests[security]==2.31.0\n")

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert "requests" in deps
        assert deps["requests"] == "2.31.0"

    def test_parse_requirements_with_options(self, tmp_path):
        """Test that option lines are skipped."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            """
-r base.txt
--index-url https://pypi.org/simple
-e git+https://github.com/user/repo.git
requests==2.31.0
"""
        )

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        # Only requests should be parsed
        assert len(deps) == 1
        assert "requests" in deps

    def test_parse_requirements_with_markers(self, tmp_path):
        """Test parsing requirements with environment markers."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text('requests==2.31.0; python_version >= "3.6"\n')

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert "requests" in deps
        assert deps["requests"] == "2.31.0"

    def test_collect_transitives(self):
        """Test transitive dependency collection."""
        expander = PipdeptreeExpander()

        # Simulated pipdeptree JSON tree
        tree = [
            {
                "package_name": "requests",
                "installed_version": "2.31.0",
                "dependencies": [
                    {
                        "package_name": "urllib3",
                        "installed_version": "2.0.4",
                        "dependencies": [],
                    },
                    {
                        "package_name": "certifi",
                        "installed_version": "2023.7.22",
                        "dependencies": [],
                    },
                ],
            }
        ]

        direct_names = {"requests"}
        discovered: list[DiscoveredDependency] = []
        seen_package_versions: set[str] = set()

        for pkg in tree:
            expander._collect_transitives(pkg, direct_names, discovered, seen_package_versions, depth=0)

        # Should discover urllib3 and certifi as transitives
        assert len(discovered) == 2
        purl_names = {d.purl for d in discovered}
        assert "pkg:pypi/urllib3@2.0.4" in purl_names
        assert "pkg:pypi/certifi@2023.7.22" in purl_names

        # Both should have requests as parent
        for dep in discovered:
            assert dep.parent == "requests"
            assert dep.depth == 1


class TestExpanderRegistry:
    """Tests for ExpanderRegistry class."""

    def test_register_and_get(self):
        """Test registering and retrieving expanders."""
        registry = ExpanderRegistry()
        expander = PipdeptreeExpander()

        registry.register(expander)

        # Mock pipdeptree as available for this test
        with patch.object(expander, "supports", return_value=True):
            result = registry.get_expander_for(Path("requirements.txt"))
            assert result is not None
            assert result.name == "pipdeptree"

    def test_no_expander_found(self):
        """Test when no expander supports the lockfile."""
        registry = ExpanderRegistry()
        result = registry.get_expander_for(Path("unknown.lock"))
        assert result is None

    def test_priority_ordering(self):
        """Test that expanders are selected by priority."""
        registry = ExpanderRegistry()

        # Create mock expanders with different priorities
        low_priority = MagicMock()
        low_priority.name = "low"
        low_priority.priority = 100
        low_priority.supports.return_value = True

        high_priority = MagicMock()
        high_priority.name = "high"
        high_priority.priority = 10
        high_priority.supports.return_value = True

        registry.register(low_priority)
        registry.register(high_priority)

        result = registry.get_expander_for(Path("test.txt"))
        assert result.name == "high"


class TestDefaultRegistry:
    """Tests for default registry creation."""

    def test_create_default_registry(self):
        """Test that default registry is created with pipdeptree."""
        registry = create_default_registry()
        assert "pipdeptree" in registry.registered_expanders


class TestExpandSbomDependencies:
    """Integration tests for expand_sbom_dependencies function."""

    def test_returns_empty_result_for_unsupported_lockfile(self, tmp_path):
        """Test that unsupported lockfiles return empty result."""
        # Create a minimal SBOM
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [],
                }
            )
        )

        # Create an unsupported lockfile
        lock_file = tmp_path / "unknown.lock"
        lock_file.write_text("some content")

        result = expand_sbom_dependencies(str(sbom_file), str(lock_file))

        assert result.added_count == 0
        assert result.discovered_count == 0
        assert result.source == "none"

    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree._PIPDEPTREE_AVAILABLE", True)
    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree.PipdeptreeExpander.can_expand")
    def test_skips_when_cannot_expand(self, mock_can_expand, tmp_path):
        """Test that expansion is skipped when prerequisites not met."""
        mock_can_expand.return_value = False

        # Create a minimal SBOM
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [],
                }
            )
        )

        # Create requirements.txt
        lock_file = tmp_path / "requirements.txt"
        lock_file.write_text("requests==2.31.0")

        result = expand_sbom_dependencies(str(sbom_file), str(lock_file))

        assert result.added_count == 0
        assert result.discovered_count == 0
        assert result.source == "pipdeptree"
