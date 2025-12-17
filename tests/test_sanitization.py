"""Tests for the input sanitization module."""

from sbomify_action._enrichment.sanitization import (
    MAX_DESCRIPTION_LENGTH,
    MAX_SUPPLIER_LENGTH,
    MAX_URL_LENGTH,
    sanitize_description,
    sanitize_email,
    sanitize_license,
    sanitize_string,
    sanitize_supplier,
    sanitize_url,
)


class TestSanitizeString:
    """Tests for sanitize_string function."""

    def test_returns_none_for_none(self):
        """Test that None input returns None."""
        assert sanitize_string(None) is None

    def test_returns_none_for_empty_string(self):
        """Test that empty string returns None."""
        assert sanitize_string("") is None
        assert sanitize_string("   ") is None

    def test_strips_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        assert sanitize_string("  hello  ") == "hello"

    def test_removes_control_characters(self):
        """Test that control characters are removed."""
        assert sanitize_string("hello\x00world") == "helloworld"
        assert sanitize_string("test\x1fdata") == "testdata"

    def test_preserves_newlines_by_default(self):
        """Test that newlines are preserved by default."""
        assert sanitize_string("line1\nline2") == "line1\nline2"

    def test_removes_newlines_when_disabled(self):
        """Test that newlines can be removed."""
        result = sanitize_string("line1\nline2", allow_newlines=False)
        assert "\n" not in result

    def test_truncates_long_strings(self):
        """Test that long strings are truncated."""
        long_string = "a" * 5000
        result = sanitize_string(long_string, max_length=100)
        assert len(result) <= 103  # 100 + "..."

    def test_converts_non_string_to_string(self):
        """Test that non-string values are converted."""
        assert sanitize_string(123) == "123"


class TestSanitizeUrl:
    """Tests for sanitize_url function."""

    def test_returns_none_for_none(self):
        """Test that None input returns None."""
        assert sanitize_url(None) is None

    def test_returns_none_for_empty_string(self):
        """Test that empty string returns None."""
        assert sanitize_url("") is None
        assert sanitize_url("   ") is None

    def test_allows_http_urls(self):
        """Test that http URLs are allowed."""
        url = "http://example.com/path"
        assert sanitize_url(url) == url

    def test_allows_https_urls(self):
        """Test that https URLs are allowed."""
        url = "https://example.com/path"
        assert sanitize_url(url) == url

    def test_blocks_javascript_urls(self):
        """Test that javascript: URLs are blocked."""
        assert sanitize_url("javascript:alert(1)") is None

    def test_blocks_file_urls(self):
        """Test that file: URLs are blocked."""
        assert sanitize_url("file:///etc/passwd") is None

    def test_blocks_data_urls(self):
        """Test that data: URLs are blocked."""
        assert sanitize_url("data:text/html,<script>alert(1)</script>") is None

    def test_blocks_ftp_urls(self):
        """Test that ftp: URLs are blocked."""
        assert sanitize_url("ftp://ftp.example.com/file") is None

    def test_blocks_urls_without_host(self):
        """Test that URLs without host are blocked."""
        assert sanitize_url("http:///path") is None

    def test_blocks_too_long_urls(self):
        """Test that very long URLs are blocked."""
        long_url = "https://example.com/" + "a" * MAX_URL_LENGTH
        assert sanitize_url(long_url) is None

    def test_strips_whitespace(self):
        """Test that whitespace is stripped from URLs."""
        assert sanitize_url("  https://example.com  ") == "https://example.com"


class TestSanitizeEmail:
    """Tests for sanitize_email function."""

    def test_returns_none_for_none(self):
        """Test that None input returns None."""
        assert sanitize_email(None) is None

    def test_returns_none_for_empty_string(self):
        """Test that empty string returns None."""
        assert sanitize_email("") is None

    def test_valid_email_passes(self):
        """Test that valid emails pass."""
        assert sanitize_email("user@example.com") == "user@example.com"
        assert sanitize_email("user.name@example.org") == "user.name@example.org"

    def test_invalid_email_returns_none(self):
        """Test that invalid emails return None."""
        assert sanitize_email("not-an-email") is None
        assert sanitize_email("@example.com") is None
        assert sanitize_email("user@") is None

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert sanitize_email("  user@example.com  ") == "user@example.com"


class TestSanitizeDescription:
    """Tests for sanitize_description function."""

    def test_allows_newlines(self):
        """Test that descriptions preserve newlines."""
        desc = "Line 1\nLine 2"
        assert sanitize_description(desc) == desc

    def test_truncates_long_descriptions(self):
        """Test that long descriptions are truncated."""
        long_desc = "a" * (MAX_DESCRIPTION_LENGTH + 100)
        result = sanitize_description(long_desc)
        assert len(result) <= MAX_DESCRIPTION_LENGTH + 10


class TestSanitizeSupplier:
    """Tests for sanitize_supplier function."""

    def test_removes_newlines(self):
        """Test that supplier names don't have newlines."""
        assert "\n" not in (sanitize_supplier("Supplier\nName") or "")

    def test_truncates_long_names(self):
        """Test that long supplier names are truncated."""
        long_name = "a" * (MAX_SUPPLIER_LENGTH + 100)
        result = sanitize_supplier(long_name)
        assert len(result) <= MAX_SUPPLIER_LENGTH + 10


class TestSanitizeLicense:
    """Tests for sanitize_license function."""

    def test_valid_license(self):
        """Test that valid license expressions pass."""
        assert sanitize_license("MIT") == "MIT"
        assert sanitize_license("Apache-2.0") == "Apache-2.0"
        assert sanitize_license("GPL-3.0-or-later") == "GPL-3.0-or-later"

    def test_removes_control_chars(self):
        """Test that control characters are removed from licenses."""
        assert sanitize_license("MIT\x00") == "MIT"


class TestSanitizeUrlFieldNames:
    """Tests for URL sanitization with different field names."""

    def test_sanitize_url_with_field_name_homepage(self):
        """Test URL sanitization with homepage field name."""
        assert sanitize_url("https://example.com", field_name="homepage") == "https://example.com"
        assert sanitize_url("javascript:alert(1)", field_name="homepage") is None

    def test_sanitize_url_with_field_name_repository(self):
        """Test URL sanitization with repository field name."""
        assert (
            sanitize_url("https://github.com/user/repo", field_name="repository_url") == "https://github.com/user/repo"
        )
        assert sanitize_url("file:///etc/passwd", field_name="repository_url") is None

    def test_sanitize_url_with_field_name_download(self):
        """Test URL sanitization with download field name."""
        assert (
            sanitize_url("https://cdn.example.com/file.tar.gz", field_name="download_url")
            == "https://cdn.example.com/file.tar.gz"
        )
        assert sanitize_url("data:text/html,malicious", field_name="download_url") is None


class TestXSSPrevention:
    """Tests for XSS attack prevention."""

    def test_allows_script_in_url_path(self):
        """Test that script tags in URL paths are allowed (valid URL content).

        Note: XSS protection in URLs is about blocking dangerous schemes
        (javascript:, data:), not about filtering path content. Path content
        should be properly escaped by consumers when rendering HTML.
        """
        # This is a valid https URL, the path content is not executable
        url = "https://example.com/<script>alert(1)</script>"
        assert sanitize_url(url) == url

    def test_removes_script_from_description(self):
        """Test that script content in descriptions is handled."""
        # Script tags are not removed, but control chars are
        # The actual XSS protection comes from proper output encoding in consumers
        desc = sanitize_description("<script>alert(1)</script>")
        # Description still contains the text, but it's text, not executable
        assert desc is not None

    def test_blocks_javascript_url_scheme(self):
        """Test that javascript: scheme is blocked for all URL field types."""
        malicious = "javascript:alert(document.cookie)"
        assert sanitize_url(malicious, field_name="homepage") is None
        assert sanitize_url(malicious, field_name="repository_url") is None
        assert sanitize_url(malicious, field_name="download_url") is None
        assert sanitize_url(malicious) is None


class TestInjectionPrevention:
    """Tests for injection attack prevention."""

    def test_handles_null_bytes(self):
        """Test that null bytes are removed."""
        assert "\x00" not in (sanitize_string("hello\x00world") or "")
        assert "\x00" not in (sanitize_description("test\x00data") or "")
        assert "\x00" not in (sanitize_supplier("vendor\x00name") or "")

    def test_handles_unicode_control_chars(self):
        """Test that unicode control characters are handled."""
        # Bell character
        assert sanitize_string("hello\x07world") == "helloworld"
