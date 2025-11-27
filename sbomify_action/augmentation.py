"""SBOM augmentation with backend metadata using native libraries."""

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

import requests
from cyclonedx.model import AttachedText, ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom, OrganizationalContact, OrganizationalEntity, Tool
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    ExtractedLicensingInfo,
)
from spdx_tools.spdx.parser.jsonlikedict.license_expression_parser import LicenseExpressionParser
from spdx_tools.spdx.parser.parse_anything import parse_file as spdx_parse_file
from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

from .logging_config import logger
from .serialization import serialize_cyclonedx_bom

# Constants for SPDX license parsing
SPDX_LOGICAL_OPERATORS = [" OR ", " AND ", " WITH "]


def _get_package_version() -> str:
    """Get the package version for tool metadata."""
    try:
        from importlib.metadata import version

        return version("sbomify-github-action")
    except Exception:
        try:
            from pathlib import Path

            import tomllib

            pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                return pyproject_data.get("project", {}).get("version", "unknown")
        except Exception:
            return "unknown"


SBOMIFY_VERSION = _get_package_version()
SBOMIFY_TOOL_NAME = "sbomify-github-action"
SBOMIFY_VENDOR_NAME = "sbomify"


def fetch_backend_metadata(api_base_url: str, token: str, component_id: str) -> Dict[str, Any]:
    """
    Fetch metadata from backend API.

    Args:
        api_base_url: Base URL for the API
        token: Authentication token
        component_id: Component ID to fetch metadata for

    Returns:
        Backend metadata dict

    Raises:
        APIError: If API call fails
    """
    from .exceptions import APIError

    url = f"{api_base_url}/api/v1/sboms/component/{component_id}/meta"
    headers = {
        "Authorization": f"Bearer {token}",
    }

    try:
        response = requests.get(url, headers=headers, timeout=60)
    except requests.exceptions.ConnectionError:
        raise APIError("Failed to connect to sbomify API")
    except requests.exceptions.Timeout:
        raise APIError("API request timed out")

    if not response.ok:
        err_msg = f"Failed to retrieve component metadata from sbomify. [{response.status_code}]"
        if response.headers.get("content-type") == "application/json":
            try:
                error_data = response.json()
                if "detail" in error_data:
                    err_msg += f" - {error_data['detail']}"
            except (ValueError, KeyError):
                pass
        raise APIError(err_msg)

    return response.json()


def _process_license_data(license_data: Any) -> Optional[Any]:
    """
    Process license data from backend into CycloneDX license objects.

    Supports:
    - String: SPDX expression (e.g., "MIT OR GPL-3.0", "Apache-2.0 WITH Commons-Clause")
    - Dict: Custom license with name, url, text

    Args:
        license_data: License data from backend (string or dict)

    Returns:
        License object for CycloneDX or None if invalid
    """
    if isinstance(license_data, str):
        # Handle SPDX license expressions
        if any(op in license_data for op in SPDX_LOGICAL_OPERATORS):
            # Complex SPDX expression
            try:
                return LicenseExpression(value=license_data)
            except Exception:
                # If expression parsing fails, treat as simple name
                return DisjunctiveLicense(name=license_data)
        else:
            # Simple license name
            return DisjunctiveLicense(name=license_data)

    elif isinstance(license_data, dict):
        # Custom license object with name, url, text
        license_name = license_data.get("name", "")
        license_url = license_data.get("url")
        license_text = license_data.get("text")

        if not license_name:
            return None

        # Create DisjunctiveLicense with additional details
        license_obj = DisjunctiveLicense(name=license_name)

        if license_url:
            try:
                license_obj.url = XsUri(license_url)
            except Exception:
                pass  # Skip invalid URLs

        if license_text:
            try:
                license_obj.text = AttachedText(content=license_text)
            except Exception:
                pass  # Skip if text attachment fails

        return license_obj

    return None


def _add_sbomify_tool_to_cyclonedx(bom: Bom) -> None:
    """
    Add sbomify as a tool in the CycloneDX SBOM metadata.

    Args:
        bom: The Bom object to update with tool metadata
    """
    # Create sbomify tool entry
    sbomify_vendor = OrganizationalEntity(name=SBOMIFY_VENDOR_NAME)
    sbomify_tool = Tool(vendor=sbomify_vendor, name=SBOMIFY_TOOL_NAME, version=SBOMIFY_VERSION)

    # Add external references for the tool
    try:
        sbomify_tool.external_references.add(
            ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri("https://github.com/sbomify/github-action"))
        )
    except Exception as e:
        logger.debug(f"Failed to add external references to sbomify tool: {e}")

    # Add the tool to the metadata
    bom.metadata.tools.tools.add(sbomify_tool)
    logger.info("Added sbomify as processing tool to SBOM metadata")


def augment_cyclonedx_sbom(
    bom: Bom,
    augmentation_data: Dict[str, Any],
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
) -> Bom:
    """
    Augment CycloneDX SBOM with backend metadata using native library.

    Args:
        bom: The Bom object to augment
        augmentation_data: Metadata from backend
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override

    Returns:
        Augmented Bom object
    """
    # Add sbomify as a processing tool
    _add_sbomify_tool_to_cyclonedx(bom)

    # Add supplier information
    if "supplier" in augmentation_data:
        supplier_data = augmentation_data["supplier"]
        logger.info(f"Adding supplier information: {supplier_data.get('name', 'Unknown')}")

        # Create backend supplier entity
        backend_supplier = OrganizationalEntity(
            name=supplier_data.get("name"),
            urls=supplier_data.get("url", [])
            if isinstance(supplier_data.get("url"), list)
            else ([supplier_data.get("url")] if supplier_data.get("url") else []),
            contacts=[],
        )

        # Add contacts if present
        if "contact" in supplier_data:
            contact_count = len(supplier_data["contact"])
            logger.info(f"Adding {contact_count} supplier contact(s) from sbomify")
            for contact_data in supplier_data["contact"]:
                contact = OrganizationalContact(
                    name=contact_data.get("name"), email=contact_data.get("email"), phone=contact_data.get("phone")
                )
                backend_supplier.contacts.add(contact)

        # Merge with existing supplier or replace
        if bom.metadata.supplier and not override_sbom_metadata:
            # Preserve existing supplier, merge with backend data
            logger.info("Merging supplier information with existing SBOM data")
            existing_supplier = bom.metadata.supplier

            # Keep existing name if present, otherwise use backend
            merged_name = existing_supplier.name if existing_supplier.name else backend_supplier.name

            # Merge URLs
            merged_urls = set()
            if existing_supplier.urls:
                for url in existing_supplier.urls:
                    merged_urls.add(str(url))
            if backend_supplier.urls:
                for url in backend_supplier.urls:
                    merged_urls.add(str(url))

            # Merge contacts (avoid duplicates by email)
            merged_contacts = set()
            existing_emails = set()

            if existing_supplier.contacts:
                for contact in existing_supplier.contacts:
                    merged_contacts.add(contact)
                    if contact.email:
                        existing_emails.add(contact.email)

            if backend_supplier.contacts:
                for contact in backend_supplier.contacts:
                    if not contact.email or contact.email not in existing_emails:
                        merged_contacts.add(contact)

            # Create merged supplier
            bom.metadata.supplier = OrganizationalEntity(
                name=merged_name,
                urls=list(merged_urls),
                contacts=list(merged_contacts),
            )
        else:
            # Use backend supplier
            if override_sbom_metadata:
                logger.info("Replacing existing supplier information with sbomify data (override mode)")
            else:
                logger.info("Adding supplier information from sbomify (no existing supplier)")
            bom.metadata.supplier = backend_supplier

    # Add authors if present
    if "authors" in augmentation_data:
        author_count = len(augmentation_data["authors"])
        logger.info(f"Adding {author_count} author(s) from sbomify")

        for author_data in augmentation_data["authors"]:
            author = OrganizationalContact(
                name=author_data.get("name"), email=author_data.get("email"), phone=author_data.get("phone")
            )
            bom.metadata.authors.add(author)
            logger.debug(f"Added author: {author_data.get('name', 'Unknown')}")

    # Add licenses if present
    # Note: CycloneDX spec requires that if LicenseExpression is used, there can be ONLY ONE license
    # See: https://github.com/CycloneDX/specification/pull/205
    if "licenses" in augmentation_data:
        license_count = len(augmentation_data["licenses"])
        logger.info(f"Adding {license_count} license(s) from sbomify")

        # Check if any license contains operators (is an expression)
        has_expressions = any(
            isinstance(lic, str) and any(op in lic for op in SPDX_LOGICAL_OPERATORS)
            for lic in augmentation_data["licenses"]
        )

        if license_count == 0:
            # No licenses to add
            pass
        elif has_expressions or license_count > 1:
            # Combine all licenses into a single LicenseExpression
            # This is required when: (a) any license has operators, or (b) we have multiple licenses
            # Note: We use OR because multiple licenses typically represent alternatives (dual-licensing),
            # not requirements. E.g., "MIT OR Apache-2.0" means "choose one", not "satisfy both".
            license_parts = []
            for license_data in augmentation_data["licenses"]:
                if isinstance(license_data, str):
                    # Don't wrap in parentheses - trust the expression as provided by backend
                    # If the backend sends "Apache-2.0 OR GPL-3.0", that's already a valid expression
                    license_parts.append(license_data)
                elif isinstance(license_data, dict):
                    # For custom licenses, use the name
                    license_name = license_data.get("name", "")
                    if license_name:
                        license_parts.append(license_name)

            if license_parts:
                # Combine all licenses with OR (common pattern for dual/multi-licensing)
                combined_expression = " OR ".join(license_parts)
                bom.metadata.licenses.add(LicenseExpression(value=combined_expression))
                logger.info(
                    f"Combined {len(license_parts)} licenses with OR (treating as alternatives): {combined_expression}"
                )
        else:
            # Single license, no operators - safe to use DisjunctiveLicense
            license_data = augmentation_data["licenses"][0]
            license_obj = _process_license_data(license_data)
            if license_obj:
                bom.metadata.licenses.add(license_obj)
                if isinstance(license_data, str):
                    logger.debug(f"Added license: {license_data}")
                elif isinstance(license_data, dict):
                    license_name = license_data.get("name", "Unknown")
                    logger.debug(f"Added license: {license_name}")

    # Apply component name override if specified
    if component_name:
        if hasattr(bom.metadata, "component") and bom.metadata.component:
            existing_name = bom.metadata.component.name or "unknown"
            bom.metadata.component.name = component_name
        else:
            # Create component if it doesn't exist
            existing_name = "none (creating new component)"
            bom.metadata.component = Component(
                name=component_name, type=ComponentType.APPLICATION, version=component_version or "unknown"
            )
        logger.info(f"Overriding component name: '{existing_name}' -> '{component_name}'")

    # Apply component version override if specified
    if component_version:
        if hasattr(bom.metadata, "component") and bom.metadata.component:
            bom.metadata.component.version = component_version
        else:
            # Create component if it doesn't exist
            bom.metadata.component = Component(
                name=component_name or "unknown", type=ComponentType.APPLICATION, version=component_version
            )
        logger.info(f"Set component version from configuration: {component_version}")

    return bom


def _sanitize_license_ref_id(name: str) -> str:
    """
    Sanitize a license name to create a valid SPDX LicenseRef identifier.

    SPDX spec requires LicenseRef-[idstring] where idstring contains only:
    - Letters (a-z, A-Z)
    - Numbers (0-9)
    - Period (.)
    - Hyphen (-)

    Args:
        name: Original license name

    Returns:
        Sanitized identifier suitable for LicenseRef

    Raises:
        ValueError: If name cannot be sanitized to valid identifier
    """
    import re

    if not name or not name.strip():
        raise ValueError("License name cannot be empty")

    # Replace spaces and common separators with hyphens
    sanitized = name.strip()
    sanitized = re.sub(r"[\s_/\\]+", "-", sanitized)

    # Remove all characters that aren't alphanumeric, period, or hyphen
    sanitized = re.sub(r"[^a-zA-Z0-9.-]", "", sanitized)

    # Replace multiple consecutive hyphens/periods with single hyphen
    sanitized = re.sub(r"[-\.]{2,}", "-", sanitized)

    # Remove leading/trailing hyphens or periods
    sanitized = sanitized.strip("-.")

    # Ensure we have something left
    if not sanitized:
        raise ValueError(f"License name '{name}' cannot be sanitized to valid SPDX identifier")

    # Limit length to something reasonable (SPDX doesn't specify, but let's be practical)
    if len(sanitized) > 64:
        # Keep first part and add hash to ensure uniqueness
        import hashlib

        name_hash = hashlib.sha256(name.encode()).hexdigest()[:8]
        sanitized = f"{sanitized[:50]}-{name_hash}"

    return sanitized


def _convert_backend_licenses_to_spdx_expression(licenses: list) -> Tuple[str, List[ExtractedLicensingInfo]]:
    """
    Convert backend license data to SPDX license expression and ExtractedLicensingInfo objects.

    When multiple licenses are provided, they are combined with OR to indicate
    alternatives (dual/multi-licensing), not requirements.

    Args:
        licenses: List of license data from backend (strings or dicts)

    Returns:
        Tuple of (SPDX license expression string, list of ExtractedLicensingInfo objects for custom licenses)
    """
    spdx_parts = []
    extracted_licensing_infos = []
    seen_refs = set()  # Track custom license refs to avoid duplicates

    for license_item in licenses:
        if isinstance(license_item, str):
            # Already SPDX expression or simple license name
            spdx_parts.append(license_item)
        elif isinstance(license_item, dict) and license_item.get("name"):
            # Custom license - create LicenseRef with proper sanitization
            original_name = license_item["name"]
            try:
                sanitized_id = _sanitize_license_ref_id(original_name)
                license_ref = f"LicenseRef-{sanitized_id}"

                # Handle collisions by appending counter
                if license_ref in seen_refs:
                    counter = 2
                    while f"{license_ref}-{counter}" in seen_refs:
                        counter += 1
                    license_ref = f"{license_ref}-{counter}"

                seen_refs.add(license_ref)
                spdx_parts.append(license_ref)
                logger.debug(f"Created SPDX license reference: {license_ref} for '{original_name}'")

                # Create ExtractedLicensingInfo object for this custom license
                extracted_info = ExtractedLicensingInfo(
                    license_id=license_ref,
                    extracted_text=license_item.get("text", "License text not provided"),
                    license_name=original_name,
                    cross_references=[license_item["url"]] if license_item.get("url") else [],
                    comment=license_item.get("comment"),
                )
                extracted_licensing_infos.append(extracted_info)
                logger.debug(f"Created ExtractedLicensingInfo for {license_ref}")

            except ValueError as e:
                logger.warning(f"Skipping invalid license name '{original_name}': {e}")
                continue

    if not spdx_parts:
        return "NOASSERTION", []

    # Join with OR (common pattern for multi-licensing - user can choose any)
    expression = " OR ".join(spdx_parts) if len(spdx_parts) > 1 else spdx_parts[0]
    return expression, extracted_licensing_infos


def augment_spdx_sbom(
    document: Document,
    augmentation_data: Dict[str, Any],
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
) -> Document:
    """
    Augment SPDX SBOM with backend metadata using native library.

    Args:
        document: The SPDX Document object to augment
        augmentation_data: Metadata from backend
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override

    Returns:
        Augmented Document object
    """
    # Add sbomify tool to creators
    sbomify_tool_creator = Actor(ActorType.TOOL, f"{SBOMIFY_TOOL_NAME}-{SBOMIFY_VERSION}")
    if sbomify_tool_creator not in document.creation_info.creators:
        document.creation_info.creators.append(sbomify_tool_creator)
        logger.info("Added sbomify as processing tool to SPDX creators")

    # Apply supplier information
    if "supplier" in augmentation_data:
        supplier_data = augmentation_data["supplier"]
        supplier_name = supplier_data.get("name")
        logger.info(f"Adding supplier information: {supplier_name or 'Unknown'}")

        # Add to document creators
        if supplier_name:
            supplier_creator = Actor(ActorType.ORGANIZATION, supplier_name)
            if supplier_creator not in document.creation_info.creators:
                document.creation_info.creators.append(supplier_creator)

        # Apply supplier to main package only (first package represents the described component)
        # Dependencies in the SBOM have their own suppliers, not the backend's supplier
        if document.packages:
            main_package = document.packages[0]

            if supplier_name and (not main_package.supplier or override_sbom_metadata):
                main_package.supplier = Actor(ActorType.ORGANIZATION, supplier_name)

            # Add homepage from supplier URLs
            if supplier_data.get("url") and not main_package.homepage:
                urls = supplier_data["url"] if isinstance(supplier_data["url"], list) else [supplier_data["url"]]
                if urls and urls[0]:
                    main_package.homepage = urls[0]

            # Add external references for supplier info
            if supplier_data.get("url"):
                urls = supplier_data["url"] if isinstance(supplier_data["url"], list) else [supplier_data["url"]]
                for url in urls:
                    if url:
                        # Check if this URL already exists
                        existing_refs = [ref.locator for ref in main_package.external_references]
                        if url not in existing_refs:
                            ext_ref = ExternalPackageRef(
                                category=ExternalPackageRefCategory.OTHER,
                                reference_type="website",
                                locator=url,
                                comment="Supplier website",
                            )
                            main_package.external_references.append(ext_ref)

    # Apply authors information
    if "authors" in augmentation_data and augmentation_data["authors"]:
        authors_data = augmentation_data["authors"]
        logger.info(f"Adding {len(authors_data)} author(s) from sbomify")

        # Add authors to document creators
        for author_data in authors_data:
            author_name = author_data.get("name")
            author_email = author_data.get("email", "")
            if author_name:
                person_name = author_name
                if author_email:
                    person_name += f" ({author_email})"
                person_creator = Actor(ActorType.PERSON, person_name)
                if person_creator not in document.creation_info.creators:
                    document.creation_info.creators.append(person_creator)

        # Add first author as originator for main package only
        # Dependencies have their own originators, not the backend's authors
        if authors_data and document.packages:
            first_author = authors_data[0]
            author_name = first_author.get("name")
            author_email = first_author.get("email", "")

            if author_name:
                main_package = document.packages[0]
                if not main_package.originator or override_sbom_metadata:
                    originator_name = author_name
                    if author_email:
                        originator_name += f" ({author_email})"
                    main_package.originator = Actor(ActorType.PERSON, originator_name)

    # Apply license information
    if "licenses" in augmentation_data and augmentation_data["licenses"]:
        licenses_data = augmentation_data["licenses"]
        logger.info(f"Adding {len(licenses_data)} license(s) to SPDX main package")

        # Convert backend licenses to SPDX format and get ExtractedLicensingInfo objects
        spdx_license_expression, extracted_licensing_infos = _convert_backend_licenses_to_spdx_expression(licenses_data)

        # Add extracted licensing info for custom licenses to document
        if extracted_licensing_infos:
            # Add to document's extracted_licensing_info list
            document.extracted_licensing_info.extend(extracted_licensing_infos)
            logger.info(
                f"Added {len(extracted_licensing_infos)} custom license(s) to document extracted_licensing_info"
            )

        # Apply to main package only (dependencies have their own licenses)
        if document.packages:
            main_package = document.packages[0]

            # Set license_declared with the SPDX expression
            # Use license_declared as this represents what the package declares in its metadata
            if not main_package.license_declared or override_sbom_metadata:
                # Parse the SPDX expression string into a proper Expression object
                license_parser = LicenseExpressionParser()
                try:
                    parsed_expression = license_parser.parse_license_expression(spdx_license_expression)
                    main_package.license_declared = parsed_expression
                    logger.info(f"Set package license_declared: {spdx_license_expression}")
                except Exception as e:
                    # If parsing fails, add to comment instead
                    logger.warning(f"Failed to parse license expression '{spdx_license_expression}': {e}")
                    if main_package.license_comment:
                        main_package.license_comment += f" | Backend licenses: {spdx_license_expression}"
                    else:
                        main_package.license_comment = f"Backend licenses: {spdx_license_expression}"
            else:
                # If there's already a declared license and we're not overriding, add to comment
                logger.info("Package already has license_declared, adding backend licenses to comment")
                if main_package.license_comment:
                    main_package.license_comment += f" | Backend licenses: {spdx_license_expression}"
                else:
                    main_package.license_comment = f"Backend licenses: {spdx_license_expression}"

    # Apply component name override
    if component_name:
        # SPDX document name is in creation_info
        existing_name = document.creation_info.name
        document.creation_info.name = component_name
        logger.info(f"Overriding SPDX document name: '{existing_name}' -> '{component_name}'")

        # Also update main package if exists
        if document.packages:
            main_package = document.packages[0]  # Typically the first package is the main one
            main_package.name = component_name

    # Apply component version override
    if component_version and document.packages:
        main_package = document.packages[0]
        main_package.version = component_version
        logger.info(f"Set package version from configuration: {component_version}")

    return document


def augment_sbom_from_file(
    input_file: str,
    output_file: str,
    api_base_url: str,
    token: str,
    component_id: str,
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
) -> Literal["cyclonedx", "spdx"]:
    """
    Augment SBOM file with backend metadata.

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save augmented SBOM
        api_base_url: Backend API base URL
        token: Authentication token
        component_id: Component ID to fetch metadata for
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override

    Returns:
        SBOM format ('cyclonedx' or 'spdx')

    Raises:
        ValueError: If SBOM format is not supported
        Exception: For other errors during augmentation
    """
    # Fetch backend metadata
    logger.info("Fetching component metadata from sbomify API")
    augmentation_data = fetch_backend_metadata(api_base_url, token, component_id)

    # Detect format and parse
    input_path = Path(input_file)

    # Try CycloneDX first
    try:
        import json

        try:
            with open(input_path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Input SBOM file not found: {input_file}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in SBOM file: {e}")
        except PermissionError:
            raise PermissionError(f"Permission denied reading SBOM file: {input_file}")
        except OSError as e:
            raise OSError(f"Error reading SBOM file {input_file}: {e}")

        if data.get("bomFormat") == "CycloneDX":
            # Parse as CycloneDX
            bom = Bom.from_json(data)
            logger.info("Processing CycloneDX SBOM")

            # Augment
            bom = augment_cyclonedx_sbom(
                bom, augmentation_data, override_sbom_metadata, component_name, component_version
            )

            # Write output using version-aware serialization
            spec_version = data.get("specVersion", "1.6")
            serialized = serialize_cyclonedx_bom(bom, spec_version)

            output_path = Path(output_file)
            try:
                with open(output_path, "w") as f:
                    f.write(serialized)
            except PermissionError:
                raise PermissionError(f"Permission denied writing output file: {output_file}")
            except OSError as e:
                raise OSError(f"Error writing output file {output_file}: {e}")

            logger.info(f"Augmented CycloneDX SBOM written to: {output_file}")
            return "cyclonedx"

        elif data.get("spdxVersion"):
            # Parse as SPDX
            document = spdx_parse_file(str(input_path))
            logger.info("Processing SPDX SBOM")

            # Augment
            document = augment_spdx_sbom(
                document, augmentation_data, override_sbom_metadata, component_name, component_version
            )

            # Write output
            output_path = Path(output_file)
            try:
                spdx_write_file(document, str(output_path), validate=False)
            except PermissionError:
                raise PermissionError(f"Permission denied writing output file: {output_file}")
            except OSError as e:
                raise OSError(f"Error writing output file {output_file}: {e}")

            logger.info(f"Augmented SPDX SBOM written to: {output_file}")
            return "spdx"

        else:
            raise ValueError("Neither CycloneDX nor SPDX format detected")

    except Exception as e:
        logger.error(f"Failed to augment SBOM: {e}")
        raise
