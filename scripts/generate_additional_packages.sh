#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="${SCRIPT_DIR}/../Dockerfile"

if [ ! -f "$DOCKERFILE" ]; then
  echo "ERROR: Dockerfile not found at $DOCKERFILE" >&2
  exit 1
fi

TRIVY=$(sed -n 's/.*TRIVY_VERSION=\([0-9.]*\).*/\1/p' "$DOCKERFILE" | head -1)
BOMCTL=$(sed -n 's/.*BOMCTL_VERSION=\([0-9.]*\).*/\1/p' "$DOCKERFILE" | head -1)

if [ -z "$TRIVY" ]; then
  echo "ERROR: Could not extract TRIVY_VERSION from Dockerfile" >&2
  exit 1
fi

if [ -z "$BOMCTL" ]; then
  echo "ERROR: Could not extract BOMCTL_VERSION from Dockerfile" >&2
  exit 1
fi

echo "pkg:golang/github.com/aquasecurity/trivy@v${TRIVY}"
echo "pkg:golang/github.com/bomctl/bomctl@v${BOMCTL}"
