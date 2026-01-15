"""Shared API client for release-related operations.

This module provides reusable functions for interacting with the sbomify
releases API. Used by both cli/main.py and the ReleasesProcessor.
"""

from typing import Any, Dict, Optional

import requests

from sbomify_action.exceptions import APIError
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger


def check_release_exists(api_base_url: str, token: str, product_id: str, version: str) -> bool:
    """
    Check if a release exists for a product.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        version: The release version

    Returns:
        True if release exists, False otherwise

    Raises:
        APIError: If API call fails
    """
    url = api_base_url + "/api/v1/releases"
    headers = get_default_headers(token)
    params = {"product_id": product_id, "version": version}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if response.status_code == 404:
        return False
    elif response.ok:
        try:
            releases = response.json().get("items", [])
            for release in releases:
                if release.get("version") == version:
                    return True
            return False
        except (ValueError, KeyError):
            return False
    else:
        err_msg = f"Failed to check release existence. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)


def get_release_id(api_base_url: str, token: str, product_id: str, version: str) -> Optional[str]:
    """
    Get the release ID for a product and version.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        version: The release version

    Returns:
        The release ID if found, None otherwise

    Raises:
        APIError: If API call fails
    """
    url = api_base_url + "/api/v1/releases"
    headers = get_default_headers(token)
    params = {"product_id": product_id, "version": version}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if response.ok:
        try:
            releases = response.json().get("items", [])
            for release in releases:
                if release.get("version") == version:
                    return release.get("id")
            return None
        except (ValueError, KeyError):
            return None
    else:
        err_msg = f"Failed to get release ID. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)


def get_release_details(api_base_url: str, token: str, product_id: str, version: str) -> Optional[Dict[str, Any]]:
    """
    Get full release details for a product and version.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        version: The release version

    Returns:
        Full release details dict if found, None otherwise

    Raises:
        APIError: If API call fails
    """
    url = api_base_url + "/api/v1/releases"
    headers = get_default_headers(token)
    params = {"product_id": product_id, "version": version}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if response.ok:
        try:
            releases = response.json().get("items", [])
            for release in releases:
                if release.get("version") == version:
                    return release
            return None
        except (ValueError, KeyError):
            return None
    else:
        err_msg = f"Failed to get release details. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)


def create_release(api_base_url: str, token: str, product_id: str, version: str) -> Optional[str]:
    """
    Create a release for a product, with get-or-create pattern.

    If the release already exists (DUPLICATE_NAME error), retrieves
    and returns the existing release ID instead of failing.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        product_id: The product ID
        version: The release version

    Returns:
        The created or existing release ID

    Raises:
        APIError: If API call fails and release cannot be retrieved
    """
    url = api_base_url + "/api/v1/releases"
    headers = get_default_headers(token, content_type="application/json")

    payload = {
        "product_id": product_id,
        "version": version,
        "name": f"Release {version}",
        "description": f"Release {version} created by sbomify-github-action",
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        # Handle duplicate release - get existing instead of failing (get-or-create pattern)
        if response.status_code == 400:
            try:
                error_data = response.json()
                if error_data.get("error_code") == "DUPLICATE_NAME":
                    logger.info(
                        f"Release {version} for product {product_id} already exists, retrieving existing release ID"
                    )
                    existing_id = get_release_id(api_base_url, token, product_id, version)
                    if existing_id:
                        return existing_id
                    # If we couldn't find it, fall through to error handling
            except (ValueError, KeyError):
                pass

        err_msg = f"Failed to create release. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
                else:
                    err_msg += f" - {error_data}"
            except (ValueError, KeyError):
                pass
        else:
            try:
                response_text = response.text[:500]
                if response_text:
                    err_msg += f" - Response: {response_text}"
            except Exception:
                pass
        raise APIError(err_msg)

    try:
        return response.json().get("id")
    except (ValueError, KeyError):
        raise APIError("Invalid response format when creating release")


def tag_sbom_with_release(api_base_url: str, token: str, sbom_id: str, release_id: str) -> None:
    """
    Associate/tag an SBOM with a release.

    Args:
        api_base_url: Base URL for the sbomify API
        token: API authentication token
        sbom_id: The SBOM ID from upload response
        release_id: The release ID to associate with

    Raises:
        APIError: If API call fails
    """
    url = api_base_url + f"/api/v1/releases/{release_id}/artifacts"
    headers = get_default_headers(token, content_type="application/json")
    payload = {"sbom_id": sbom_id}

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        err_msg = f"Failed to tag SBOM with release. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)


def get_release_friendly_name(release_details: Optional[Dict[str, Any]], version: str) -> str:
    """
    Get a user-friendly name for a release.

    Args:
        release_details: Full release details from the API
        version: The release version (fallback)

    Returns:
        User-friendly release name
    """
    if not release_details:
        return f"Release {version}"

    release_name = release_details.get("name")
    if release_name and release_name != f"Release {version}":
        return f"'{release_name}' ({version})"
    else:
        return f"Release {version}"
