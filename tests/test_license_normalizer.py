"""Tests for the license normalizer shared library."""

from sbomify_action._enrichment.license_normalizer import (
    DEP5_LICENSE_ALIASES,
    RPM_LICENSE_ALIASES,
    extract_dep5_license,
    normalize_dep5_license,
    normalize_license,
    normalize_rpm_license,
    parse_deb822_stanzas,
    parse_dep5_copyright,
    validate_spdx_expression,
)


class TestValidateSpdxExpression:
    """Tests for SPDX expression validation."""

    def test_valid_simple_license(self):
        assert validate_spdx_expression("MIT") is True
        assert validate_spdx_expression("Apache-2.0") is True
        assert validate_spdx_expression("GPL-3.0-only") is True

    def test_valid_compound_expression(self):
        assert validate_spdx_expression("MIT AND Apache-2.0") is True
        assert validate_spdx_expression("GPL-2.0-only OR MIT") is True
        assert validate_spdx_expression("(MIT AND Apache-2.0) OR GPL-3.0-only") is True

    def test_valid_special_values(self):
        assert validate_spdx_expression("NOASSERTION") is True
        assert validate_spdx_expression("NONE") is True

    def test_valid_license_ref(self):
        assert validate_spdx_expression("LicenseRef-Custom") is True
        assert validate_spdx_expression("LicenseRef-my-license-1.0") is True

    def test_invalid_license(self):
        assert validate_spdx_expression("") is False
        assert validate_spdx_expression("NotALicense") is False
        assert validate_spdx_expression("GPLv2") is False  # Not valid SPDX
        assert validate_spdx_expression("LicenseRef-") is False  # Invalid format

    def test_invalid_expression(self):
        assert validate_spdx_expression("MIT AND") is False
        assert validate_spdx_expression("AND MIT") is False


class TestNormalizeRpmLicense:
    """Tests for RPM license normalization."""

    def test_already_valid_spdx(self):
        result = normalize_rpm_license("MIT")
        assert result.spdx == "MIT"
        assert result.confidence == "high"

    def test_rpm_alias_mapping(self):
        result = normalize_rpm_license("GPLv2+")
        assert result.spdx == "GPL-2.0-or-later"
        assert result.confidence == "high"

        result = normalize_rpm_license("ASL 2.0")
        assert result.spdx == "Apache-2.0"
        assert result.confidence == "high"

    def test_compound_expression(self):
        result = normalize_rpm_license("GPLv2+ and BSD")
        assert result.spdx == "GPL-2.0-or-later AND BSD-3-Clause"
        assert result.confidence == "high"

    def test_parenthesized_expression(self):
        result = normalize_rpm_license("(GPLv2+ or MIT) and BSD")
        assert result.spdx == "(GPL-2.0-or-later OR MIT) AND BSD-3-Clause"
        assert result.confidence == "high"

    def test_unknown_license_fails(self):
        result = normalize_rpm_license("UnknownLicense")
        assert result.spdx is None
        assert result.confidence == "low"

    def test_partial_unknown_fails(self):
        # If any part is unknown, the whole thing should fail
        result = normalize_rpm_license("MIT and UnknownLicense")
        assert result.spdx is None
        assert result.confidence == "low"

    def test_empty_input(self):
        result = normalize_rpm_license("")
        assert result.spdx is None


class TestNormalizeDep5License:
    """Tests for DEP-5 license normalization."""

    def test_already_valid_spdx(self):
        result = normalize_dep5_license("MIT")
        assert result.spdx == "MIT"
        assert result.confidence == "high"

    def test_dep5_alias_mapping(self):
        result = normalize_dep5_license("GPL-2+")
        assert result.spdx == "GPL-2.0-or-later"
        assert result.confidence == "high"

        result = normalize_dep5_license("Expat")
        assert result.spdx == "MIT"
        assert result.confidence == "high"

    def test_unknown_license_fails(self):
        result = normalize_dep5_license("some-custom-license")
        assert result.spdx is None
        assert result.confidence == "low"


class TestParseDeb822Stanzas:
    """Tests for deb822 format parsing."""

    def test_single_stanza(self):
        text = """Package: foo
Version: 1.0
Description: A test package"""
        stanzas = list(parse_deb822_stanzas(text))
        assert len(stanzas) == 1
        assert stanzas[0]["Package"] == "foo"
        assert stanzas[0]["Version"] == "1.0"

    def test_uk_spelling_licence_normalized(self):
        """Test that UK spelling 'Licence' is normalized to 'License'."""
        text = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2020 Test
Licence: MIT"""
        stanzas = list(parse_deb822_stanzas(text))
        assert len(stanzas) == 2
        # The UK spelling should be normalized to US spelling
        assert "License" in stanzas[1]
        assert stanzas[1]["License"] == "MIT"

    def test_multiple_stanzas(self):
        text = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: test

Files: *
Copyright: 2020 Test Author
License: MIT"""
        stanzas = list(parse_deb822_stanzas(text))
        assert len(stanzas) == 2
        assert stanzas[0]["Format"].startswith("https://")
        assert stanzas[1]["License"] == "MIT"

    def test_continuation_lines(self):
        text = """Package: foo
Description: First line
 Second line
 Third line"""
        stanzas = list(parse_deb822_stanzas(text))
        assert len(stanzas) == 1
        assert "Second line" in stanzas[0]["Description"]


class TestParseDep5Copyright:
    """Tests for DEP-5 copyright file parsing."""

    def test_valid_dep5_format(self):
        text = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: test

Files: *
Copyright: 2020 Test
License: MIT

License: MIT
 Permission is hereby granted..."""
        result = parse_dep5_copyright(text)
        assert result.is_dep5 is True
        assert "MIT" in result.licenses

    def test_non_dep5_format(self):
        text = """This is a freeform copyright file.
Copyright 2020 Test Author
Licensed under the MIT license."""
        result = parse_dep5_copyright(text)
        assert result.is_dep5 is False
        assert len(result.licenses) == 0


class TestExtractDep5License:
    """Tests for DEP-5 license extraction."""

    def test_single_license(self):
        text = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2020 Test
License: MIT"""
        result = extract_dep5_license(text)
        assert result == "MIT"

    def test_multiple_licenses(self):
        text = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: src/*
Copyright: 2020 Test
License: MIT

Files: lib/*
Copyright: 2020 Test
License: Apache-2.0"""
        result = extract_dep5_license(text)
        # Multiple licenses should be ANDed
        assert result is not None
        assert "MIT" in result
        assert "Apache-2.0" in result

    def test_dep5_alias_normalization(self):
        text = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2020 Test
License: GPL-2+"""
        result = extract_dep5_license(text)
        assert result == "GPL-2.0-or-later"

    def test_unknown_license_returns_none(self):
        text = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2020 Test
License: some-unknown-license"""
        result = extract_dep5_license(text)
        assert result is None

    def test_non_dep5_returns_none(self):
        text = """This is a freeform copyright file."""
        result = extract_dep5_license(text)
        assert result is None

    def test_uk_spelling_licence_works(self):
        """Test that UK spelling 'Licence' is handled correctly."""
        text = """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 2020 Test
Licence: Apache-2.0"""
        result = extract_dep5_license(text)
        assert result == "Apache-2.0"


class TestNormalizeLicense:
    """Tests for the general normalize_license function."""

    def test_uses_all_aliases(self):
        # RPM alias
        result = normalize_license("GPLv2+")
        assert result.spdx == "GPL-2.0-or-later"

        # DEP-5 alias
        result = normalize_license("GPL-2+")
        assert result.spdx == "GPL-2.0-or-later"


class TestAliasCompleteness:
    """Tests to ensure alias dictionaries are properly defined."""

    def test_rpm_aliases_have_valid_targets(self):
        """All RPM alias targets should be valid SPDX."""
        for alias, spdx in RPM_LICENSE_ALIASES.items():
            assert validate_spdx_expression(spdx), f"RPM alias '{alias}' maps to invalid SPDX '{spdx}'"

    def test_dep5_aliases_have_valid_targets(self):
        """All DEP-5 alias targets should be valid SPDX."""
        for alias, spdx in DEP5_LICENSE_ALIASES.items():
            assert validate_spdx_expression(spdx), f"DEP-5 alias '{alias}' maps to invalid SPDX '{spdx}'"
