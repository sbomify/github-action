"""Tests for the sbomify.json wizard validators."""

from sbomify_action.cli.wizard.validators import (
    LIFECYCLE_PHASES,
    validate_email,
    validate_iso_date,
    validate_license,
    validate_lifecycle_phase,
    validate_security_contact,
    validate_url,
)


class TestValidateEmail:
    """Tests for email validation."""

    def test_valid_email(self):
        assert validate_email("test@example.com") is True
        assert validate_email("user.name@domain.org") is True
        assert validate_email("user+tag@sub.domain.com") is True

    def test_invalid_email(self):
        assert validate_email("not-an-email") is False
        assert validate_email("@example.com") is False
        assert validate_email("test@") is False
        assert validate_email("test") is False

    def test_empty_email(self):
        assert validate_email("") is False

    def test_none_like_inputs(self):
        assert validate_email(None) is False  # type: ignore


class TestValidateUrl:
    """Tests for URL validation."""

    def test_valid_http_url(self):
        assert validate_url("http://example.com") is True
        assert validate_url("https://example.com") is True
        assert validate_url("https://example.com/path/to/resource") is True
        assert validate_url("https://example.com:8080/path") is True

    def test_invalid_url(self):
        assert validate_url("not-a-url") is False
        assert validate_url("ftp://example.com") is False  # Only http/https
        assert validate_url("//example.com") is False  # Missing scheme

    def test_empty_url(self):
        assert validate_url("") is False

    def test_none_like_inputs(self):
        assert validate_url(None) is False  # type: ignore


class TestValidateSecurityContact:
    """Tests for security contact validation."""

    def test_valid_mailto(self):
        assert validate_security_contact("mailto:security@example.com") is True

    def test_invalid_mailto(self):
        assert validate_security_contact("mailto:not-an-email") is False

    def test_valid_tel(self):
        assert validate_security_contact("tel:+1-555-123-4567") is True

    def test_valid_url(self):
        assert validate_security_contact("https://example.com/.well-known/security.txt") is True
        assert validate_security_contact("https://example.com/security") is True

    def test_invalid_value(self):
        assert validate_security_contact("invalid") is False

    def test_empty_value(self):
        assert validate_security_contact("") is False


class TestValidateIsoDate:
    """Tests for ISO-8601 date validation."""

    def test_valid_date(self):
        assert validate_iso_date("2024-01-15") is True
        assert validate_iso_date("2025-12-31") is True

    def test_invalid_format(self):
        assert validate_iso_date("2024/01/15") is False
        assert validate_iso_date("01-15-2024") is False
        assert validate_iso_date("2024-01-15T00:00:00Z") is False  # With time
        assert validate_iso_date("not-a-date") is False

    def test_invalid_date(self):
        assert validate_iso_date("2024-13-01") is False  # Invalid month
        assert validate_iso_date("2024-02-30") is False  # Invalid day

    def test_empty_date(self):
        assert validate_iso_date("") is False


class TestValidateLicense:
    """Tests for SPDX license validation."""

    def test_valid_spdx_license(self):
        assert validate_license("MIT") is True
        assert validate_license("Apache-2.0") is True
        assert validate_license("GPL-3.0-only") is True
        assert validate_license("BSD-3-Clause") is True

    def test_valid_license_expression(self):
        assert validate_license("MIT OR Apache-2.0") is True
        assert validate_license("GPL-2.0-only AND MIT") is True

    def test_invalid_license(self):
        assert validate_license("InvalidLicense") is False
        assert validate_license("NotARealLicense-1.0") is False

    def test_empty_license(self):
        assert validate_license("") is False


class TestValidateLifecyclePhase:
    """Tests for lifecycle phase validation."""

    def test_valid_phases(self):
        for phase in LIFECYCLE_PHASES:
            assert validate_lifecycle_phase(phase) is True

    def test_case_insensitive(self):
        assert validate_lifecycle_phase("BUILD") is True
        assert validate_lifecycle_phase("Build") is True
        assert validate_lifecycle_phase("Pre-Build") is True

    def test_invalid_phase(self):
        assert validate_lifecycle_phase("invalid") is False
        assert validate_lifecycle_phase("testing") is False

    def test_empty_phase(self):
        assert validate_lifecycle_phase("") is False
