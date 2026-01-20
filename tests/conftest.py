"""Pytest configuration and shared fixtures for all tests."""

import pytest


@pytest.fixture(autouse=True)
def disable_sentry_for_tests(monkeypatch):
    """Disable Sentry telemetry for all tests.

    This fixture runs automatically for every test to prevent Sentry events
    from being sent during test runs. Tests that specifically need to test
    Sentry functionality (like test_sentry_filtering.py) should override
    this by setting TELEMETRY=true in their own fixtures or patches.
    """
    monkeypatch.setenv("TELEMETRY", "false")
