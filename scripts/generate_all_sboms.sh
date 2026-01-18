#!/usr/bin/env bash
#
# Generate SBOMs from all supported distros using all available tools
#
# Usage:
#   ./scripts/generate_all_sboms.sh [output_dir]
#

set -euo pipefail

OUTPUT_DIR="${1:-sboms_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"

echo "Output directory: $OUTPUT_DIR"

# Docker images to test
declare -a DOCKER_IMAGES=(
    # Alpine
    "alpine:3.18"
    "alpine:3.19"
    "alpine:3.20"
    "alpine:3.21"
    
    # Debian
    "debian:10-slim"
    "debian:11-slim"
    "debian:12-slim"
    
    # Ubuntu LTS
    "ubuntu:20.04"
    "ubuntu:22.04"
    "ubuntu:24.04"
    
    # Rocky Linux
    "rockylinux:8-minimal"
    "rockylinux:9-minimal"
    
    # AlmaLinux
    "almalinux:8-minimal"
    "almalinux:9-minimal"
    
    # Amazon Linux
    "amazonlinux:2"
    "amazonlinux:2023"
    
    # CentOS Stream
    "quay.io/centos/centos:stream9"
    
    # Fedora
    "fedora:40"
    "fedora:41"
    
    # Wolfi
    "cgr.dev/chainguard/wolfi-base:latest"
    
    # Oracle Linux
    "oraclelinux:8-slim"
    "oraclelinux:9-slim"
    
    # openSUSE
    "opensuse/leap:15.5"
    "opensuse/leap:15.6"
    
    # Arch Linux
    "archlinux:latest"
    
    # Distroless
    "gcr.io/distroless/static-debian12:latest"
    "gcr.io/distroless/base-debian12:latest"
)

# Generate with trivy
generate_trivy() {
    local image="$1"
    local safe_name="${image//[:\/]/_}"
    
    echo "  [trivy] CycloneDX..."
    trivy image --format cyclonedx --output "$OUTPUT_DIR/${safe_name}_trivy.cdx.json" "$image" 2>/dev/null || echo "    FAILED"
    
    echo "  [trivy] SPDX..."
    trivy image --format spdx-json --output "$OUTPUT_DIR/${safe_name}_trivy.spdx.json" "$image" 2>/dev/null || echo "    FAILED"
}

# Generate with syft
generate_syft() {
    local image="$1"
    local safe_name="${image//[:\/]/_}"
    
    echo "  [syft] CycloneDX..."
    syft "$image" -o "cyclonedx-json=$OUTPUT_DIR/${safe_name}_syft.cdx.json" 2>/dev/null || echo "    FAILED"
    
    echo "  [syft] SPDX..."
    syft "$image" -o "spdx-json=$OUTPUT_DIR/${safe_name}_syft.spdx.json" 2>/dev/null || echo "    FAILED"
}

# Generate with cdxgen
generate_cdxgen() {
    local image="$1"
    local safe_name="${image//[:\/]/_}"
    
    echo "  [cdxgen] CycloneDX..."
    cdxgen -t container -o "$OUTPUT_DIR/${safe_name}_cdxgen.cdx.json" "$image" 2>/dev/null || echo "    FAILED"
}

# Main
echo "Generating SBOMs for ${#DOCKER_IMAGES[@]} images..."
echo ""

for image in "${DOCKER_IMAGES[@]}"; do
    echo "[$image]"
    
    if command -v trivy &>/dev/null; then
        generate_trivy "$image"
    fi
    
    if command -v syft &>/dev/null; then
        generate_syft "$image"
    fi
    
    if command -v cdxgen &>/dev/null; then
        generate_cdxgen "$image"
    fi
    
    echo ""
done

echo "Done! Generated SBOMs in $OUTPUT_DIR"
echo ""
echo "File counts:"
ls -1 "$OUTPUT_DIR"/*.cdx.json 2>/dev/null | wc -l | xargs echo "  CycloneDX:"
ls -1 "$OUTPUT_DIR"/*.spdx.json 2>/dev/null | wc -l | xargs echo "  SPDX:"
