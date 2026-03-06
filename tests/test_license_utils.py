"""Tests for license_utils split and normalize functions."""

from sbomify_action._enrichment.license_utils import (
    _split_license_string,
    normalize_license_list,
)


class TestSplitLicenseString:
    """Tests for _split_license_string."""

    def test_single_license(self):
        assert _split_license_string("MIT") == ["MIT"]

    def test_comma_separated(self):
        assert _split_license_string("Apache-2.0, MIT") == ["Apache-2.0", "MIT"]

    def test_and_separated(self):
        result = _split_license_string("GPL-2 and LGPL-2.1")
        assert result == ["GPL-2", "LGPL-2.1"]

    def test_comma_and_mixed(self):
        result = _split_license_string("MPL-1.1, GPL-2 and LGPL-2.1")
        assert result == ["MPL-1.1", "GPL-2", "LGPL-2.1"]

    def test_uppercase_and_not_split(self):
        """Uppercase AND is a valid SPDX operator and should not be split."""
        result = _split_license_string("GPL-2.0-only AND MIT")
        assert result == ["GPL-2.0-only AND MIT"]

    def test_empty_string(self):
        assert _split_license_string("") == []

    def test_whitespace_stripped(self):
        result = _split_license_string("  MIT ,  Apache-2.0  ")
        assert result == ["MIT", "Apache-2.0"]

    def test_or_separated(self):
        result = _split_license_string("GPLv2+ or LGPLv3+")
        assert result == ["GPLv2+", "LGPLv3+"]

    def test_uppercase_or_not_split(self):
        """Uppercase OR is a valid SPDX operator and should not be split."""
        result = _split_license_string("MIT OR Apache-2.0")
        assert result == ["MIT OR Apache-2.0"]

    def test_no_false_split_on_standard(self):
        """'and' inside words like 'Standard' should not cause splits."""
        result = _split_license_string("StandardLicense")
        assert result == ["StandardLicense"]


class TestNormalizeLicenseListSplitting:
    """Tests for normalize_license_list with comma/and-separated inputs."""

    def test_splits_and_normalizes(self):
        """Comma/and-separated string should be split and each part normalized."""
        licenses, _texts = normalize_license_list(["MPL-1.1, GPL-2 and LGPL-2.1"])
        assert "MPL-1.1" in licenses
        assert "GPL-2.0-only" in licenses
        # LGPL-2.1 is a valid (deprecated) SPDX ID, recognized by the parser as-is
        assert any(lic.startswith("LGPL-2.1") for lic in licenses)
        assert len(licenses) == 3

    def test_single_license_unchanged(self):
        licenses, _texts = normalize_license_list(["MIT"])
        assert licenses == ["MIT"]

    def test_alias_normalization(self):
        """Common non-SPDX shorthand IDs should be normalized."""
        licenses, _texts = normalize_license_list(["GPL-2"])
        assert licenses == ["GPL-2.0-only"]

        licenses, _texts = normalize_license_list(["GPL-3"])
        assert licenses == ["GPL-3.0-only"]

    def test_empty_list(self):
        licenses, texts = normalize_license_list([])
        assert licenses == []
        assert texts == {}
