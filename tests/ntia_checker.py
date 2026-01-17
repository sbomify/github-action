"""
Shared NTIA Minimum Elements compliance checker for tests.

Reference: https://sbomify.com/compliance/ntia-minimum-elements/

NTIA Minimum Elements for SBOM (July 2021):
1. Supplier Name - Entity that created/distributed the component
2. Component Name - Designation assigned by original supplier
3. Version - Change state identifier
4. Other Unique Identifiers - PURLs, CPE, etc.
5. Dependency Relationship - How components relate
6. Author of SBOM Data - Entity that created the SBOM
7. Timestamp - Date/time SBOM was assembled

Field Mappings (per https://sbomify.com/compliance/schema-crosswalk/):

CycloneDX (all versions 1.3-1.7):
- Supplier Name: components[].publisher OR components[].supplier.name
- Component Name: components[].name
- Component Version: components[].version
- Unique Identifiers: components[].purl, components[].cpe
- Dependency Relationship: dependencies[].ref + dependencies[].dependsOn[]
- SBOM Author: metadata.authors[]
- Timestamp: metadata.timestamp

SPDX (2.2 and 2.3):
- Supplier Name: packages[].supplier
- Component Name: packages[].name
- Component Version: packages[].versionInfo
- Unique Identifiers: packages[].externalRefs[] (referenceType: purl, cpe22Type, cpe23Type)
- Dependency Relationship: relationships[] (DEPENDS_ON, CONTAINS)
- SBOM Author: creationInfo.creators[]
- Timestamp: creationInfo.created
"""

import re
from typing import Any, Dict, List, Tuple, Union

# ISO-8601 timestamp regex pattern
# Matches: YYYY-MM-DDTHH:MM:SS with optional timezone
ISO8601_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

# Known lockfile names that should be excluded from NTIA compliance checks
LOCKFILE_NAMES = {
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "conda-lock.yml",
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "Gemfile.lock",
    "go.sum",
    "go.mod",
    "pubspec.lock",
    "conan.lock",
    "vcpkg.json",
}


class NTIAComplianceChecker:
    """Utility class to check NTIA Minimum Elements compliance."""

    @staticmethod
    def _is_lockfile_component(component: Dict[str, Any]) -> bool:
        """Check if a CycloneDX component is a lockfile artifact (not a real package)."""
        # Must be application type
        if component.get("type") != "application":
            return False
        # Must have no PURL
        if component.get("purl"):
            return False
        # Must match known lockfile name
        return component.get("name") in LOCKFILE_NAMES

    @staticmethod
    def _has_valid_supplier_cdx(component: Dict[str, Any]) -> bool:
        """Check if a CycloneDX component has a valid supplier."""
        if component.get("publisher"):
            return True
        supplier = component.get("supplier")
        if isinstance(supplier, dict) and supplier.get("name"):
            return True
        if isinstance(supplier, str) and supplier:
            return True
        return False

    @staticmethod
    def _has_valid_identifier_cdx(component: Dict[str, Any]) -> bool:
        """Check if a CycloneDX component has a valid unique identifier."""
        if component.get("purl") or component.get("cpe"):
            return True
        swid = component.get("swid")
        if isinstance(swid, dict) and swid.get("tagId") and swid.get("name"):
            return True
        return False

    @staticmethod
    def _has_valid_supplier_spdx(package: Dict[str, Any]) -> bool:
        """Check if an SPDX package has a valid supplier."""
        supplier = package.get("supplier")
        return supplier and supplier != "NOASSERTION"

    @staticmethod
    def _has_valid_identifier_spdx(package: Dict[str, Any]) -> bool:
        """Check if an SPDX package has a valid unique identifier."""
        valid_types = {"purl", "cpe22Type", "cpe23Type", "swid"}
        for ref in package.get("externalRefs", []):
            if ref.get("referenceType") in valid_types:
                return True
        return False

    @classmethod
    def check_cyclonedx(
        cls,
        data: Dict[str, Any],
        include_stats: bool = False,
        filter_library_only: bool = False,
    ) -> Union[Tuple[bool, List[str], List[str]], Tuple[bool, List[str], List[str], Dict[str, Any]]]:
        """
        Check CycloneDX SBOM for NTIA compliance.

        Note: Lockfile components (e.g., requirements.txt, uv.lock) are excluded
        from compliance checks as they are metadata artifacts, not software packages.

        Args:
            data: The CycloneDX SBOM as a dictionary.
            include_stats: If True, return a 4-tuple including stats dict.
            filter_library_only: If True, only check library-type components (for container SBOMs).

        Returns:
            Tuple of (is_compliant, present_elements, missing_elements) or
            Tuple of (is_compliant, present_elements, missing_elements, stats) if include_stats=True.
        """
        present: List[str] = []
        missing: List[str] = []
        stats: Dict[str, int] = {
            "total_components": 0,
            "components_with_supplier": 0,
            "components_with_name": 0,
            "components_with_version": 0,
            "components_with_identifiers": 0,
        }

        # 1. Timestamp (must be valid ISO-8601 format)
        timestamp = data.get("metadata", {}).get("timestamp")
        if timestamp and ISO8601_REGEX.match(timestamp):
            present.append("Timestamp")
        else:
            missing.append("Timestamp")

        # 2. Author of SBOM Data (authors - not tools, per NTIA standard)
        authors = data.get("metadata", {}).get("authors", [])
        if authors:
            present.append("Author of SBOM Data")
        else:
            missing.append("Author of SBOM Data")

        # Filter components
        all_components = data.get("components", [])
        if filter_library_only:
            components = [c for c in all_components if c.get("type") == "library"]
        else:
            components = [c for c in all_components if not cls._is_lockfile_component(c)]

        stats["total_components"] = len(components)

        if not components:
            missing.extend(["Component Name", "Version", "Supplier Name", "Unique Identifiers"])
            if include_stats:
                return (False, present, missing, stats)
            return (False, present, missing)

        # Check each component
        for c in components:
            if c.get("name"):
                stats["components_with_name"] += 1
            if c.get("version"):
                stats["components_with_version"] += 1
            if cls._has_valid_supplier_cdx(c):
                stats["components_with_supplier"] += 1
            if cls._has_valid_identifier_cdx(c):
                stats["components_with_identifiers"] += 1

        total = stats["total_components"]

        # 3. Component Name
        if stats["components_with_name"] == total:
            present.append("Component Name")
        else:
            if include_stats:
                missing.append(f"Component Name ({stats['components_with_name']}/{total})")
            else:
                missing.append("Component Name")

        # 4. Version
        if stats["components_with_version"] == total:
            present.append("Version")
        else:
            if include_stats:
                missing.append(f"Version ({stats['components_with_version']}/{total})")
            else:
                missing.append("Version")

        # 5. Supplier Name
        if stats["components_with_supplier"] == total:
            present.append("Supplier Name")
        else:
            if include_stats:
                missing.append(f"Supplier Name ({stats['components_with_supplier']}/{total})")
            else:
                missing.append("Supplier Name")

        # 6. Other Unique Identifiers
        if stats["components_with_identifiers"] == total:
            present.append("Unique Identifiers")
        else:
            if include_stats:
                missing.append(f"Unique Identifiers ({stats['components_with_identifiers']}/{total})")
            else:
                missing.append("Unique Identifiers")

        # 7. Dependency Relationship
        if data.get("dependencies"):
            present.append("Dependency Relationships")
        else:
            missing.append("Dependency Relationships")

        # Compliance check
        if include_stats:
            # Container-focused: just check if Supplier Name is present
            is_compliant = "Supplier Name" in present
            return (is_compliant, present, missing, stats)
        else:
            # Strict: require all elements
            is_compliant = len(missing) == 0
            return (is_compliant, present, missing)

    @classmethod
    def check_spdx(
        cls,
        data: Dict[str, Any],
        include_stats: bool = False,
        filter_library_only: bool = False,
    ) -> Union[Tuple[bool, List[str], List[str]], Tuple[bool, List[str], List[str], Dict[str, Any]]]:
        """
        Check SPDX SBOM for NTIA compliance.

        Args:
            data: The SPDX SBOM as a dictionary.
            include_stats: If True, return a 4-tuple including stats dict.
            filter_library_only: If True, filter packages by purpose (for container SBOMs).

        Returns:
            Tuple of (is_compliant, present_elements, missing_elements) or
            Tuple of (is_compliant, present_elements, missing_elements, stats) if include_stats=True.
        """
        present: List[str] = []
        missing: List[str] = []
        stats: Dict[str, int] = {
            "total_packages": 0,
            "packages_with_supplier": 0,
            "packages_with_name": 0,
            "packages_with_version": 0,
            "packages_with_identifiers": 0,
        }

        # 1. Timestamp (must be valid ISO-8601 format)
        timestamp = data.get("creationInfo", {}).get("created")
        if timestamp and ISO8601_REGEX.match(timestamp):
            present.append("Timestamp")
        else:
            missing.append("Timestamp")

        # 2. Author of SBOM Data (creators - excluding tools)
        # SPDX creators can be: "Tool: name", "Person: name", "Organization: name"
        # Only Person and Organization entries count as SBOM authors
        creators = data.get("creationInfo", {}).get("creators", [])
        entity_creators = [c for c in creators if not c.startswith("Tool:")]
        if entity_creators:
            present.append("Author of SBOM Data")
        else:
            missing.append("Author of SBOM Data")

        # Filter packages
        all_packages = data.get("packages", [])
        if filter_library_only:
            # Exclude container/application/source/OS packages
            excluded_purposes = {"CONTAINER", "APPLICATION", "SOURCE", "OPERATING-SYSTEM"}
            packages = [
                p
                for p in all_packages
                if p.get("primaryPackagePurpose") not in excluded_purposes or p.get("primaryPackagePurpose") is None
            ]
            # Also exclude packages that look like container images
            packages = [p for p in packages if not any(x in p.get("name", "").lower() for x in [":", "sha256", "@"])]
        else:
            packages = all_packages

        stats["total_packages"] = len(packages)

        if not packages:
            missing.extend(["Component Name", "Version", "Supplier Name", "Unique Identifiers"])
            if include_stats:
                return (False, present, missing, stats)
            return (False, present, missing)

        # Check each package
        for p in packages:
            if p.get("name"):
                stats["packages_with_name"] += 1
            if p.get("versionInfo"):
                stats["packages_with_version"] += 1
            if cls._has_valid_supplier_spdx(p):
                stats["packages_with_supplier"] += 1
            if cls._has_valid_identifier_spdx(p):
                stats["packages_with_identifiers"] += 1

        total = stats["total_packages"]

        # 3. Component Name
        if stats["packages_with_name"] == total:
            present.append("Component Name")
        else:
            if include_stats:
                missing.append(f"Component Name ({stats['packages_with_name']}/{total})")
            else:
                missing.append("Component Name")

        # 4. Version
        if stats["packages_with_version"] == total:
            present.append("Version")
        else:
            if include_stats:
                missing.append(f"Version ({stats['packages_with_version']}/{total})")
            else:
                missing.append("Version")

        # 5. Supplier Name
        if stats["packages_with_supplier"] == total:
            present.append("Supplier Name")
        else:
            if include_stats:
                missing.append(f"Supplier Name ({stats['packages_with_supplier']}/{total})")
            else:
                missing.append("Supplier Name")

        # 6. Other Unique Identifiers
        if stats["packages_with_identifiers"] == total:
            present.append("Unique Identifiers")
        else:
            if include_stats:
                missing.append(f"Unique Identifiers ({stats['packages_with_identifiers']}/{total})")
            else:
                missing.append("Unique Identifiers")

        # 7. Dependency Relationship (must be DEPENDS_ON or CONTAINS, not just DESCRIBES)
        relationships = data.get("relationships", [])
        has_deps = any(rel.get("relationshipType", "").upper() in ["DEPENDS_ON", "CONTAINS"] for rel in relationships)
        if has_deps:
            present.append("Dependency Relationships")
        else:
            missing.append("Dependency Relationships")

        # Compliance check
        if include_stats:
            # Container-focused: just check if Supplier Name is present
            is_compliant = "Supplier Name" in present
            return (is_compliant, present, missing, stats)
        else:
            # Strict: require all elements
            is_compliant = len(missing) == 0
            return (is_compliant, present, missing)
