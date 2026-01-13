#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="${SCRIPT_DIR}/../Dockerfile"

# Expected version format: digits and dots only (e.g., 0.67.2)
# Note: Using [0-9.]* not [0-9.]+ because basic sed doesn't support +
# The validation below catches empty matches anyway
VERSION_REGEX='[0-9.]*'

# Extract version from Dockerfile ENV declaration
# Usage: extract_version "TRIVY" "/path/to/Dockerfile"
extract_version() {
  local name="$1"
  local dockerfile="$2"
  sed -n "s/.*${name}_VERSION=\(${VERSION_REGEX}\).*/\1/p" "$dockerfile" | head -1
}

if [ ! -f "$DOCKERFILE" ]; then
  echo "ERROR: Dockerfile not found at $DOCKERFILE" >&2
  exit 1
fi

TRIVY_VERSION=$(extract_version "TRIVY" "$DOCKERFILE")
BOMCTL_VERSION=$(extract_version "BOMCTL" "$DOCKERFILE")
SYFT_VERSION=$(extract_version "SYFT" "$DOCKERFILE")
CARGO_CYCLONEDX_VERSION=$(extract_version "CARGO_CYCLONEDX" "$DOCKERFILE")

if [ -z "$TRIVY_VERSION" ]; then
  echo "ERROR: Could not extract TRIVY_VERSION from Dockerfile" >&2
  exit 1
fi

if [ -z "$BOMCTL_VERSION" ]; then
  echo "ERROR: Could not extract BOMCTL_VERSION from Dockerfile" >&2
  exit 1
fi

if [ -z "$SYFT_VERSION" ]; then
  echo "ERROR: Could not extract SYFT_VERSION from Dockerfile" >&2
  exit 1
fi

if [ -z "$CARGO_CYCLONEDX_VERSION" ]; then
  echo "ERROR: Could not extract CARGO_CYCLONEDX_VERSION from Dockerfile" >&2
  exit 1
fi

# Export for sourcing
export TRIVY_VERSION
export BOMCTL_VERSION
export SYFT_VERSION
export CARGO_CYCLONEDX_VERSION

# When executed directly (not sourced), output PURLs
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "pkg:golang/github.com/aquasecurity/trivy@v${TRIVY_VERSION}"
  echo "pkg:golang/github.com/bomctl/bomctl@v${BOMCTL_VERSION}"
  echo "pkg:golang/github.com/anchore/syft@v${SYFT_VERSION}"
  echo "pkg:cargo/cargo-cyclonedx@${CARGO_CYCLONEDX_VERSION}"
fi
