"""SBOM augmentation with organizational metadata using plugin architecture.

This module augments SBOMs with organizational metadata from multiple sources,
addressing NTIA Minimum Elements and CISA 2025 requirements.

Metadata Providers (in priority order):
    1. JSON config file (sbomify.json) - local config takes precedence
    2. sbomify API - backend organizational metadata

NTIA Minimum Elements (July 2021):
    https://sbomify.com/compliance/ntia-minimum-elements/

    Augmentation adds:
    - Supplier Name: CycloneDX metadata.supplier / SPDX packages[].supplier
    - SBOM Author: CycloneDX metadata.authors[] / SPDX creationInfo.creators[]
    - Tool Name/Version: CycloneDX metadata.tools / SPDX creationInfo.creators[]

CISA 2025 Additional Fields:
    https://sbomify.com/compliance/cisa-minimum-elements/

    Augmentation adds:
    - Generation Context: CycloneDX metadata.lifecycles[].phase (1.5+ only)
                         SPDX creationInfo.creatorComment

Field mappings per schema crosswalk:
    https://sbomify.com/compliance/schema-crosswalk/

Version support:
    - CycloneDX: 1.3, 1.4, 1.5, 1.6, 1.7
    - SPDX: 2.2, 2.3
"""

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from cyclonedx.model import AttachedText, ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom, OrganizationalContact, OrganizationalEntity, Tool
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression
from cyclonedx.model.lifecycle import LifecyclePhase, PredefinedLifecycle
from cyclonedx.model.service import Service
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

# Import augmentation plugin architecture
from ._augmentation import create_default_registry

# Import lockfile constants from generation utils (single source of truth)
from ._generation.utils import ALL_LOCK_FILES
from .exceptions import SBOMValidationError
from .logging_config import logger
from .serialization import sanitize_dependency_graph, serialize_cyclonedx_bom
from .validation import validate_sbom_file_auto

# Constants for SPDX license parsing
SPDX_LOGICAL_OPERATORS = [" OR ", " AND ", " WITH "]

# Convert to set for O(1) lookup
LOCKFILE_NAMES = set(ALL_LOCK_FILES)


def _is_lockfile_component(component: Component) -> bool:
    """Check if a CycloneDX component represents a lockfile artifact."""
    if component.type != ComponentType.APPLICATION:
        return False
    if component.purl:
        return False
    if component.name and component.name in LOCKFILE_NAMES:
        return True
    return False


def _propagate_supplier_to_lockfile_components(bom: Bom) -> None:
    """
    Propagate supplier from metadata to lockfile components.

    Lockfile components (e.g., requirements.txt, uv.lock) are metadata artifacts
    that don't have their own supplier. After augmentation sets the metadata
    supplier from the backend, we propagate it to these components for NTIA compliance.
    """
    if not bom.metadata.supplier or not bom.components:
        return

    propagated_count = 0
    for component in bom.components:
        if _is_lockfile_component(component) and not component.supplier:
            component.supplier = bom.metadata.supplier
            propagated_count += 1
            logger.debug(f"Propagated supplier to lockfile component: {component.name}")

    if propagated_count > 0:
        logger.info(f"Propagated supplier to {propagated_count} lockfile component(s)")


def _get_package_version() -> str:
    """Get the package version for tool metadata."""
    try:
        from importlib.metadata import version

        return version("sbomify-action")
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
SBOMIFY_TOOL_NAME = "sbomify GitHub Action"
SBOMIFY_VENDOR_NAME = "sbomify"


def fetch_augmentation_metadata(
    api_base_url: Optional[str] = None,
    token: Optional[str] = None,
    component_id: Optional[str] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fetch augmentation metadata from multiple providers.

    Uses the plugin architecture to query metadata from multiple sources
    in priority order:
    1. JSON config file (sbomify.json) - priority 10
    2. sbomify API - priority 50

    Higher priority providers' values take precedence. This allows local
    config to override backend settings.

    Args:
        api_base_url: Base URL for the sbomify API (optional)
        token: Authentication token for sbomify API (optional)
        component_id: Component ID for sbomify API (optional)
        config_path: Path to JSON config file (optional, defaults to sbomify.json)

    Returns:
        Merged augmentation metadata dict from all providers
    """
    registry = create_default_registry()

    # Log registered providers
    providers = registry.list_providers()
    logger.debug(f"Registered augmentation providers: {[p['name'] for p in providers]}")

    # Fetch from all providers (merged by priority)
    metadata = registry.fetch_metadata(
        component_id=component_id,
        api_base_url=api_base_url,
        token=token,
        config_path=config_path,
    )

    if metadata and metadata.has_data():
        logger.info(f"Fetched augmentation metadata from: {metadata.source}")
        return metadata.to_dict()
    else:
        logger.debug("No augmentation metadata available from any provider")
        return {}


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


def _add_sbomify_tool_to_cyclonedx(bom: Bom, spec_version: Optional[str] = None) -> None:
    """
    Add sbomify as a tool in the CycloneDX SBOM metadata.

    Args:
        bom: The Bom object to update with tool metadata
        spec_version: CycloneDX spec version (e.g., "1.4", "1.5", "1.6", "1.7")
                     If None, defaults to "1.4" (legacy format)

    Note:
        Version-specific behavior:
        - CycloneDX 1.4: Uses legacy Tool format (tools array) with string vendor
        - CycloneDX 1.5+: Uses modern format (components/services) - sbomify added as Service

        According to CycloneDX spec:
        - Tool.vendor should be STRING (not OrganizationalEntity) in legacy format
        - Component.group should be STRING (represents vendor) in modern format
        - Service-based tools (like sbomify API) should go in tools.services for 1.5+
        - NEVER use OrganizationalEntity for tools in any version

        See: https://github.com/CycloneDX/cyclonedx-python-lib/issues/917
        See: https://cyclonedx.org/docs/1.7/json/#metadata_tools
    """
    # Use provided spec_version or default to 1.4
    if spec_version is None:
        spec_version = "1.4"

    spec_parts = spec_version.split(".")
    major = int(spec_parts[0]) if len(spec_parts) > 0 else 1
    minor = int(spec_parts[1]) if len(spec_parts) > 1 else 4
    is_v15_or_later = (major > 1) or (major == 1 and minor >= 5)

    if is_v15_or_later:
        # Modern format (1.5+): Use services for API/service-based tools
        # Keep existing components and services, add sbomify as a service
        logger.debug(f"Using modern tools format for CycloneDX {spec_version}")

        # Create sbomify as a Service (not a legacy Tool)
        # Services are appropriate for API/service-based tools like sbomify
        sbomify_service = Service(
            name=SBOMIFY_TOOL_NAME,
            version=SBOMIFY_VERSION,
        )

        # Add group field (equivalent to vendor in legacy format)
        sbomify_service.group = SBOMIFY_VENDOR_NAME

        # Add external references for the service
        try:
            # Website - main product page
            sbomify_service.external_references.add(
                ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri("https://sbomify.com"))
            )
            # VCS - source code repository
            sbomify_service.external_references.add(
                ExternalReference(type=ExternalReferenceType.VCS, url=XsUri("https://github.com/sbomify/github-action"))
            )
            # Issue tracker - where to report bugs
            sbomify_service.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.ISSUE_TRACKER,
                    url=XsUri("https://github.com/sbomify/github-action/issues"),
                )
            )
        except Exception as e:
            logger.debug(f"Failed to add external references to sbomify service: {e}")

        # Add to tools.services (do NOT clear existing services or components)
        bom.metadata.tools.services.add(sbomify_service)
        logger.info(f"Added sbomify as service to tools.services (CycloneDX {spec_version})")

    else:
        # Legacy format (1.4): Convert all to Tool objects
        logger.debug(f"Using legacy tools format for CycloneDX {spec_version}")

        # Convert components to Tools and add to tools collection
        # Tool.from_component() uses component.group (string) as vendor (string)
        for component in list(bom.metadata.tools.components):
            tool = Tool.from_component(component)
            bom.metadata.tools.tools.add(tool)

        # Clear components since we've converted them all to tools
        bom.metadata.tools.components.clear()

        # Convert services to Tools and add to tools collection
        for service in list(bom.metadata.tools.services):
            tool = Tool.from_service(service)
            bom.metadata.tools.tools.add(tool)

        # Clear services since we've converted them all to tools
        bom.metadata.tools.services.clear()

        # Create sbomify tool entry with STRING vendor (per spec)
        # This matches the format used by other tools (e.g., Trivy uses group="aquasecurity")
        sbomify_tool = Tool(vendor=SBOMIFY_VENDOR_NAME, name=SBOMIFY_TOOL_NAME, version=SBOMIFY_VERSION)

        # Add external references for the tool
        try:
            # Website - main product page
            sbomify_tool.external_references.add(
                ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri("https://sbomify.com"))
            )
            # VCS - source code repository
            sbomify_tool.external_references.add(
                ExternalReference(type=ExternalReferenceType.VCS, url=XsUri("https://github.com/sbomify/github-action"))
            )
            # Issue tracker - where to report bugs
            sbomify_tool.external_references.add(
                ExternalReference(
                    type=ExternalReferenceType.ISSUE_TRACKER,
                    url=XsUri("https://github.com/sbomify/github-action/issues"),
                )
            )
        except Exception as e:
            logger.debug(f"Failed to add external references to sbomify tool: {e}")

        # Add the tool to the metadata
        bom.metadata.tools.tools.add(sbomify_tool)
        logger.info(f"Added sbomify as legacy tool to tools.tools (CycloneDX {spec_version})")


def augment_cyclonedx_sbom(
    bom: Bom,
    augmentation_data: Dict[str, Any],
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    spec_version: Optional[str] = None,
) -> Bom:
    """
    Augment CycloneDX SBOM with backend metadata using native library.

    Args:
        bom: The Bom object to augment
        augmentation_data: Metadata from backend
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override
        spec_version: CycloneDX spec version (e.g., "1.4", "1.5", "1.6", "1.7")
                     Used to determine tool format (legacy vs modern)

    Returns:
        Augmented Bom object
    """
    # Add sbomify as a processing tool (version-aware)
    _add_sbomify_tool_to_cyclonedx(bom, spec_version)

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

        # Also propagate supplier to the root component (metadata.component) if it exists
        # This is needed for NTIA compliance - the root component needs its own supplier field
        if bom.metadata.component and not bom.metadata.component.supplier:
            bom.metadata.component.supplier = bom.metadata.supplier
            logger.debug("Propagated supplier to root component (metadata.component)")

        # Propagate supplier to lockfile components that don't have one
        # Lockfile components (e.g., requirements.txt, uv.lock) are metadata artifacts
        # that inherit supplier from the root/metadata supplier
        if bom.metadata.supplier and bom.components:
            _propagate_supplier_to_lockfile_components(bom)

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
            if existing_name != component_name:
                bom.metadata.component.name = component_name
                logger.info(f"Overriding component name: '{existing_name}' -> '{component_name}'")
        else:
            # Create component if it doesn't exist
            bom.metadata.component = Component(
                name=component_name, type=ComponentType.APPLICATION, version=component_version or "unknown"
            )
            logger.info(f"Overriding component name: 'none (creating new component)' -> '{component_name}'")

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

    # Add lifecycle phase if present (CISA 2025 Generation Context requirement)
    # See: https://sbomify.com/compliance/cisa-minimum-elements/
    # Crosswalk: https://sbomify.com/compliance/schema-crosswalk/
    # Only supported in CycloneDX 1.5+ (metadata.lifecycles field not available in 1.3/1.4)
    if "lifecycle_phase" in augmentation_data and augmentation_data["lifecycle_phase"]:
        # Parse spec version to check if 1.5+
        if spec_version:
            spec_parts = spec_version.split(".")
            major = int(spec_parts[0]) if len(spec_parts) > 0 else 1
            minor = int(spec_parts[1]) if len(spec_parts) > 1 else 4
            is_v15_or_later = (major > 1) or (major == 1 and minor >= 5)

            if is_v15_or_later:
                phase_value = augmentation_data["lifecycle_phase"].lower().replace("_", "-")
                # Map to CycloneDX LifecyclePhase enum
                phase_mapping = {
                    "design": LifecyclePhase.DESIGN,
                    "pre-build": LifecyclePhase.PRE_BUILD,
                    "build": LifecyclePhase.BUILD,
                    "post-build": LifecyclePhase.POST_BUILD,
                    "operations": LifecyclePhase.OPERATIONS,
                    "discovery": LifecyclePhase.DISCOVERY,
                    "decommission": LifecyclePhase.DECOMMISSION,
                }
                if phase_value in phase_mapping:
                    lifecycle = PredefinedLifecycle(phase=phase_mapping[phase_value])
                    bom.metadata.lifecycles.add(lifecycle)
                    logger.info(f"Added lifecycle phase: {phase_value}")
                else:
                    logger.warning(f"Unknown lifecycle phase '{phase_value}', skipping")
            else:
                logger.debug(f"Lifecycle phase not supported in CycloneDX {spec_version} (requires 1.5+)")

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

    # Add lifecycle phase if present (CISA 2025 Generation Context requirement)
    # See: https://sbomify.com/compliance/cisa-minimum-elements/
    # Crosswalk: https://sbomify.com/compliance/schema-crosswalk/
    # For SPDX, we add this to creator_comment since there's no dedicated field
    if "lifecycle_phase" in augmentation_data and augmentation_data["lifecycle_phase"]:
        phase_value = augmentation_data["lifecycle_phase"]
        lifecycle_comment = f"Lifecycle phase: {phase_value}"
        if document.creation_info.creator_comment:
            document.creation_info.creator_comment += f" | {lifecycle_comment}"
        else:
            document.creation_info.creator_comment = lifecycle_comment
        logger.info(f"Added lifecycle phase to SPDX creator comment: {phase_value}")

    return document


def augment_sbom_from_file(
    input_file: str,
    output_file: str,
    api_base_url: Optional[str] = None,
    token: Optional[str] = None,
    component_id: Optional[str] = None,
    override_sbom_metadata: bool = False,
    component_name: Optional[str] = None,
    component_version: Optional[str] = None,
    validate: bool = True,
    config_path: Optional[str] = None,
) -> Literal["cyclonedx", "spdx"]:
    """
    Augment SBOM file with metadata from multiple providers.

    Uses the plugin architecture to fetch metadata from:
    1. JSON config file (sbomify.json) - higher priority
    2. sbomify API - lower priority (fallback)

    After augmentation, the output SBOM is validated against its JSON schema
    (when validate=True).

    Args:
        input_file: Path to input SBOM file
        output_file: Path to save augmented SBOM
        api_base_url: Backend API base URL (optional, for sbomify API provider)
        token: Authentication token (optional, for sbomify API provider)
        component_id: Component ID (optional, for sbomify API provider)
        override_sbom_metadata: Whether to override existing metadata
        component_name: Optional component name override
        component_version: Optional component version override
        validate: Whether to validate the output SBOM (default: True)
        config_path: Path to JSON config file (optional, defaults to sbomify.json)

    Returns:
        SBOM format ('cyclonedx' or 'spdx')

    Raises:
        ValueError: If SBOM format is not supported
        SBOMValidationError: If output validation fails
        Exception: For other errors during augmentation
    """
    # Fetch metadata from all providers (merged by priority)
    logger.info("Fetching augmentation metadata from providers")
    augmentation_data = fetch_augmentation_metadata(
        api_base_url=api_base_url,
        token=token,
        component_id=component_id,
        config_path=config_path,
    )

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
            # Validate required fields before processing
            spec_version = data.get("specVersion")
            if spec_version is None:
                raise SBOMValidationError("CycloneDX SBOM is missing required 'specVersion' field")

            # Parse as CycloneDX
            try:
                bom = Bom.from_json(data)
            except Exception as e:
                raise SBOMValidationError(f"Failed to parse CycloneDX SBOM: {e}")
            logger.info("Processing CycloneDX SBOM")

            # Augment
            bom = augment_cyclonedx_sbom(
                bom, augmentation_data, override_sbom_metadata, component_name, component_version, spec_version
            )

            # Sanitize dependency graph (add stubs for orphaned references)
            sanitize_dependency_graph(bom)

            # Write output using version-aware serialization
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

            # Validate the augmented SBOM
            if validate:
                validation_result = validate_sbom_file_auto(output_file)
                if validation_result.valid is None:
                    logger.warning(
                        f"Augmented SBOM could not be validated ({validation_result.sbom_format} "
                        f"{validation_result.spec_version}): {validation_result.error_message}"
                    )
                elif not validation_result.valid:
                    raise SBOMValidationError(f"Augmented SBOM failed validation: {validation_result.error_message}")
                else:
                    logger.info(
                        f"Augmented SBOM validated: {validation_result.sbom_format} {validation_result.spec_version}"
                    )

            return "cyclonedx"

        elif data.get("spdxVersion"):
            # Parse as SPDX
            try:
                document = spdx_parse_file(str(input_path))
            except Exception as e:
                raise SBOMValidationError(f"Failed to parse SPDX SBOM: {e}")
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

            # Validate the augmented SBOM
            if validate:
                validation_result = validate_sbom_file_auto(output_file)
                if validation_result.valid is None:
                    logger.warning(
                        f"Augmented SBOM could not be validated ({validation_result.sbom_format} "
                        f"{validation_result.spec_version}): {validation_result.error_message}"
                    )
                elif not validation_result.valid:
                    raise SBOMValidationError(f"Augmented SBOM failed validation: {validation_result.error_message}")
                else:
                    logger.info(
                        f"Augmented SBOM validated: {validation_result.sbom_format} {validation_result.spec_version}"
                    )

            return "spdx"

        else:
            raise ValueError("Neither CycloneDX nor SPDX format detected")

    except Exception as e:
        logger.error(f"Failed to augment SBOM: {e}")
        raise
