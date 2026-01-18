#!/usr/bin/env bash
#
# Comprehensive license sanitization test across all tools, distros, and formats
#
# Designed to run inside the sbomify-action Docker container environment
# which has trivy, syft, and cdxgen pre-installed.
#
# Usage:
#   ./scripts/test_license_sanitization.sh [output_dir]
#
# This script generates SBOMs using all supported tools (trivy, syft, cdxgen)
# from various Docker images and tests that our license sanitization correctly
# handles invalid license IDs.
#
# Output:
#   - Creates a directory with all generated SBOMs (raw and sanitized)
#   - Generates a summary CSV and detailed log
#   - Creates a JSON database of all license issues found
#

set -euo pipefail

# Debug: show we're starting
echo "Starting license sanitization test script..." >&2

# Configuration
OUTPUT_DIR="${1:-license_test_$(date +%Y%m%d_%H%M%S)}"
LOG_FILE="$OUTPUT_DIR/test.log"
SUMMARY_CSV="$OUTPUT_DIR/summary.csv"
ISSUES_JSON="$OUTPUT_DIR/license_issues.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find project root - look for pyproject.toml
echo "DEBUG: SCRIPT_DIR=$SCRIPT_DIR" >&2
echo "DEBUG: pwd=$(pwd)" >&2
echo "DEBUG: checking $SCRIPT_DIR/../pyproject.toml" >&2

if [ -f "$SCRIPT_DIR/../pyproject.toml" ]; then
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    echo "DEBUG: Found pyproject.toml at $SCRIPT_DIR/.." >&2
elif [ -f "./pyproject.toml" ]; then
    PROJECT_ROOT="$(pwd)"
    echo "DEBUG: Found pyproject.toml in current dir" >&2
elif [ -f "/workspace/pyproject.toml" ]; then
    PROJECT_ROOT="/workspace"
    echo "DEBUG: Found pyproject.toml at /workspace" >&2
else
    # Inside container or project is installed - use current dir
    PROJECT_ROOT="$(pwd)"
    echo "DEBUG: No pyproject.toml found, using pwd" >&2
fi
echo "DEBUG: PROJECT_ROOT=$PROJECT_ROOT" >&2

# Determine Python command
# In container: use python directly (venv is at /opt/venv/bin)
# Outside container with uv: use uv run python
# Fallback: use python from PATH
if [ -x "/opt/venv/bin/python" ]; then
    PYTHON_CMD="/opt/venv/bin/python"
    echo "DEBUG: Using container Python at /opt/venv/bin/python" >&2
elif command -v uv &> /dev/null; then
    PYTHON_CMD="uv run python"
    echo "DEBUG: Using uv run python" >&2
elif command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    echo "DEBUG: Using python3 from PATH" >&2
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    echo "DEBUG: Using python from PATH" >&2
else
    echo "ERROR: No Python found!" >&2
    exit 1
fi
echo "DEBUG: PYTHON_CMD=$PYTHON_CMD" >&2

# Create output directory
mkdir -p "$OUTPUT_DIR/raw" "$OUTPUT_DIR/sanitized"

# Logging functions - output to stderr so we can capture stdout separately
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg" >> "$LOG_FILE"
    echo "$msg" >&2
}

log_section() {
    echo "" >> "$LOG_FILE"
    echo "" >&2
    echo "============================================================" >> "$LOG_FILE"
    echo "============================================================" >&2
    log "$*"
    echo "============================================================" >> "$LOG_FILE"
    echo "============================================================" >&2
}

# Supported tools and their format capabilities
# Format: tool:cyclonedx_format:spdx_format
declare -A TOOL_FORMATS=(
    ["trivy"]="cyclonedx:spdx-json"
    ["syft"]="cyclonedx-json:spdx-json"
    ["cdxgen"]="json:"  # cdxgen only supports CycloneDX
)

# Docker images to test - covering all supported distros
# trivy and syft will pull these directly (no docker client needed)
declare -a DOCKER_IMAGES=(
    # Alpine (all supported versions)
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
    
    # Rocky Linux (RHEL clone)
    "rockylinux:8-minimal"
    "rockylinux:9-minimal"
    
    # AlmaLinux (RHEL clone)
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
    
    # Wolfi (Chainguard) - security-focused
    "cgr.dev/chainguard/wolfi-base:latest"
    
    # Oracle Linux
    "oraclelinux:8-slim"
    "oraclelinux:9-slim"
    
    # openSUSE
    "opensuse/leap:15.5"
    "opensuse/leap:15.6"
    
    # Arch Linux (rolling)
    "archlinux:latest"
    
    # Distroless (Google) - minimal
    "gcr.io/distroless/static-debian12:latest"
    "gcr.io/distroless/base-debian12:latest"
)

# Check prerequisites
check_prerequisites() {
    log_section "Checking prerequisites"
    
    log "Project root: $PROJECT_ROOT"
    log "Working directory: $(pwd)"
    
    local available_tools=()
    
    log "Checking for SBOM generation tools..."
    
    if command -v trivy &> /dev/null; then
        log "✓ trivy found: $(trivy --version 2>&1 | head -1)"
        available_tools+=("trivy")
    else
        log "✗ trivy not found"
    fi
    
    if command -v syft &> /dev/null; then
        log "✓ syft found: $(syft version 2>&1 | head -1)"
        available_tools+=("syft")
    else
        log "✗ syft not found"
    fi
    
    if command -v cdxgen &> /dev/null; then
        log "✓ cdxgen found: $(cdxgen --version 2>&1 | head -1)"
        available_tools+=("cdxgen")
    else
        log "✗ cdxgen not found"
    fi
    
    log "Checking for required utilities..."
    
    log "✓ Python command: $PYTHON_CMD"
    
    # Verify Python works and has required modules
    if $PYTHON_CMD -c "from sbomify_action.serialization import sanitize_cyclonedx_licenses" 2>/dev/null; then
        log "✓ sbomify_action module available"
    else
        log "✗ sbomify_action module not found - is the package installed?"
        exit 1
    fi
    
    # jq is optional - we can work without it
    if command -v jq &> /dev/null; then
        log "✓ jq found: $(jq --version)"
    else
        log "⚠ jq not found (optional)"
    fi
    
    if [ ${#available_tools[@]} -eq 0 ]; then
        log "ERROR: No SBOM generation tools found (need at least one of: trivy, syft, cdxgen)"
        exit 1
    fi
    
    log "Available tools: ${available_tools[*]}"
    
    # Return available tools via stdout (log goes to stderr)
    printf '%s\n' "${available_tools[@]}"
}

# Generate SBOM with a specific tool
# Tools pull images directly - no docker client needed
generate_sbom() {
    local tool="$1"
    local image="$2"
    local format="$3"
    local output_file="$4"
    
    case "$tool" in
        trivy)
            trivy image --format "$format" --output "$output_file" "$image" 2>&1
            ;;
        syft)
            syft "$image" -o "$format=$output_file" 2>&1
            ;;
        cdxgen)
            cdxgen -t container -o "$output_file" "$image" 2>&1
            ;;
    esac
}

# Analyze and sanitize an SBOM
analyze_sbom() {
    local sbom_file="$1"
    local format="$2"  # cyclonedx or spdx
    local tool="$3"
    local image="$4"
    local sanitized_file="$5"
    
    $PYTHON_CMD << PYTHON_SCRIPT
import json
import sys
import copy

# Load SBOM
try:
    with open('$sbom_file') as f:
        data = json.load(f)
except Exception as e:
    print(f"ERROR:load_failed:{e}")
    sys.exit(1)

format_type = '$format'
tool = '$tool'
image = '$image'

if format_type == 'cyclonedx':
    from sbomify_action.serialization import sanitize_cyclonedx_licenses
    from license_expression import get_spdx_licensing
    
    spdx = get_spdx_licensing()
    
    # Find invalid license IDs before sanitization
    invalid_ids = []
    total_licenses = 0
    for comp in data.get('components', []):
        for lic in comp.get('licenses', []):
            license_obj = lic.get('license', {})
            lid = license_obj.get('id')
            lname = license_obj.get('name')
            expr = lic.get('expression')
            
            if lid:
                total_licenses += 1
                if not lid.startswith('LicenseRef-'):
                    try:
                        parsed = spdx.parse(lid, validate=False)
                        unknown = spdx.unknown_license_keys(parsed)
                        if unknown:
                            invalid_ids.append({
                                'component': comp.get('name'),
                                'field': 'license.id',
                                'value': lid
                            })
                    except:
                        invalid_ids.append({
                            'component': comp.get('name'),
                            'field': 'license.id', 
                            'value': lid
                        })
            elif expr:
                total_licenses += 1
                try:
                    parsed = spdx.parse(expr, validate=False)
                    unknown = spdx.unknown_license_keys(parsed)
                    for uk in unknown:
                        if not str(uk).startswith('LicenseRef-'):
                            invalid_ids.append({
                                'component': comp.get('name'),
                                'field': 'expression',
                                'value': str(uk)
                            })
                except:
                    invalid_ids.append({
                        'component': comp.get('name'),
                        'field': 'expression',
                        'value': expr
                    })
    
    # Sanitize
    data_copy = copy.deepcopy(data)
    sanitized_count = sanitize_cyclonedx_licenses(data_copy)
    
    # Save sanitized
    with open('$sanitized_file', 'w') as f:
        json.dump(data_copy, f, indent=2)
    
    # Output results
    print(f"FORMAT:cyclonedx")
    print(f"TOTAL_LICENSES:{total_licenses}")
    print(f"INVALID_BEFORE:{len(invalid_ids)}")
    print(f"SANITIZED:{sanitized_count}")
    for inv in invalid_ids:
        print(f"INVALID:{inv['component']}|{inv['field']}|{inv['value']}")

elif format_type == 'spdx':
    from sbomify_action.serialization import sanitize_spdx_licenses, _sanitize_spdx_license_expression
    
    # Debug: show top-level keys (to stdout so it's captured)
    print(f"DEBUG_KEYS:{list(data.keys())}")
    
    # Find invalid license expressions before sanitization
    invalid_exprs = []
    total_licenses = 0
    noassertion_count = 0
    total_packages = len(data.get('packages', []))
    
    # Debug
    print(f"DEBUG_TOTAL_PACKAGES:{total_packages}")
    if total_packages > 0:
        sample_pkg = data['packages'][0]
        print(f"DEBUG_SAMPLE_PKG_KEYS:{list(sample_pkg.keys())}")
        print(f"DEBUG_SAMPLE_LICENSE_CONCLUDED:{sample_pkg.get('licenseConcluded', 'NOT_FOUND')}")
        print(f"DEBUG_SAMPLE_LICENSE_DECLARED:{sample_pkg.get('licenseDeclared', 'NOT_FOUND')}")
    
    for pkg in data.get('packages', []):
        for field in ['licenseConcluded', 'licenseDeclared']:
            val = pkg.get(field, '')
            if val in ('NOASSERTION', 'NONE'):
                noassertion_count += 1
            elif val:
                total_licenses += 1
                sanitized, modified = _sanitize_spdx_license_expression(val)
                if modified:
                    # Extract which specific IDs were invalid
                    from license_expression import get_spdx_licensing
                    spdx = get_spdx_licensing()
                    try:
                        parsed = spdx.parse(val, validate=False)
                        unknown = spdx.unknown_license_keys(parsed)
                        for uk in unknown:
                            if not str(uk).startswith('LicenseRef-'):
                                invalid_exprs.append({
                                    'package': pkg.get('name'),
                                    'field': field,
                                    'value': str(uk)
                                })
                    except:
                        invalid_exprs.append({
                            'package': pkg.get('name'),
                            'field': field,
                            'value': val[:50]
                        })
    
    # Check licenseInfoFromFiles in files
    for file_obj in data.get('files', []):
        for lic in file_obj.get('licenseInfoInFiles', []):
            if lic and lic not in ('NOASSERTION', 'NONE'):
                total_licenses += 1
                sanitized, modified = _sanitize_spdx_license_expression(lic)
                if modified:
                    invalid_exprs.append({
                        'package': file_obj.get('fileName', 'unknown'),
                        'field': 'licenseInfoInFiles',
                        'value': lic[:50]
                    })
    
    # Sanitize
    data_copy = copy.deepcopy(data)
    sanitized_count = sanitize_spdx_licenses(data_copy)
    
    # Save sanitized
    with open('$sanitized_file', 'w') as f:
        json.dump(data_copy, f, indent=2)
    
    # Output results
    print(f"FORMAT:spdx")
    print(f"TOTAL_PACKAGES:{total_packages}")
    print(f"TOTAL_LICENSES:{total_licenses}")
    print(f"NOASSERTION:{noassertion_count}")
    print(f"INVALID_BEFORE:{len(invalid_exprs)}")
    print(f"SANITIZED:{sanitized_count}")
    for inv in invalid_exprs:
        print(f"INVALID:{inv['package']}|{inv['field']}|{inv['value']}")

else:
    print(f"ERROR:unknown_format:{format_type}")
    sys.exit(1)
PYTHON_SCRIPT
}

# Test a single image with a single tool
test_image_tool() {
    local image="$1"
    local tool="$2"
    local formats="${TOOL_FORMATS[$tool]}"
    local safe_image="${image//[:\/]/_}"
    
    IFS=':' read -r cdx_format spdx_format <<< "$formats"
    
    local results=()
    
    # Test CycloneDX if supported
    if [ -n "$cdx_format" ]; then
        local raw_file="$OUTPUT_DIR/raw/${safe_image}_${tool}.cdx.json"
        local sanitized_file="$OUTPUT_DIR/sanitized/${safe_image}_${tool}.cdx.json"
        
        log "  [$tool] Generating CycloneDX..."
        if generate_sbom "$tool" "$image" "$cdx_format" "$raw_file" >> "$LOG_FILE" 2>&1; then
            if [ -f "$raw_file" ] && [ -s "$raw_file" ]; then
                log "  [$tool] Analyzing CycloneDX..."
                local analysis
                analysis=$(analyze_sbom "$raw_file" "cyclonedx" "$tool" "$image" "$sanitized_file" 2>&1) || true
                
                local total invalid sanitized
                total=$(echo "$analysis" | grep "^TOTAL_LICENSES:" | cut -d: -f2 || echo "0")
                invalid=$(echo "$analysis" | grep "^INVALID_BEFORE:" | cut -d: -f2 || echo "0")
                sanitized=$(echo "$analysis" | grep "^SANITIZED:" | cut -d: -f2 || echo "0")
                
                log "    Total licenses: $total, Invalid: $invalid, Sanitized: $sanitized"
                results+=("$image,$tool,cyclonedx,$total,$invalid,$sanitized,success")
                
                # Extract invalid licenses for database (|| true to handle no matches)
                echo "$analysis" | grep "^INVALID:" | while read -r line; do
                    local parts="${line#INVALID:}"
                    echo "$image|$tool|cyclonedx|$parts" >> "$OUTPUT_DIR/all_invalid_licenses.txt"
                done || true
            else
                log "  [$tool] CycloneDX: Empty or missing output"
                results+=("$image,$tool,cyclonedx,0,0,0,empty_output")
            fi
        else
            log "  [$tool] CycloneDX: Generation failed"
            results+=("$image,$tool,cyclonedx,0,0,0,generation_failed")
        fi
    fi
    
    # Test SPDX if supported
    if [ -n "$spdx_format" ]; then
        local raw_file="$OUTPUT_DIR/raw/${safe_image}_${tool}.spdx.json"
        local sanitized_file="$OUTPUT_DIR/sanitized/${safe_image}_${tool}.spdx.json"
        
        log "  [$tool] Generating SPDX..."
        if generate_sbom "$tool" "$image" "$spdx_format" "$raw_file" >> "$LOG_FILE" 2>&1; then
            if [ -f "$raw_file" ] && [ -s "$raw_file" ]; then
                log "  [$tool] Analyzing SPDX..."
                local analysis
                analysis=$(analyze_sbom "$raw_file" "spdx" "$tool" "$image" "$sanitized_file" 2>&1) || true
                
                # Show debug output
                echo "$analysis" | grep "^DEBUG" | while read -r line; do
                    log "    $line"
                done || true
                
                local total_pkgs total noassertion invalid sanitized
                total_pkgs=$(echo "$analysis" | grep "^TOTAL_PACKAGES:" | cut -d: -f2 || echo "0")
                total=$(echo "$analysis" | grep "^TOTAL_LICENSES:" | cut -d: -f2 || echo "0")
                noassertion=$(echo "$analysis" | grep "^NOASSERTION:" | cut -d: -f2 || echo "0")
                invalid=$(echo "$analysis" | grep "^INVALID_BEFORE:" | cut -d: -f2 || echo "0")
                sanitized=$(echo "$analysis" | grep "^SANITIZED:" | cut -d: -f2 || echo "0")
                
                log "    Packages: $total_pkgs, Licenses: $total (NOASSERTION: $noassertion), Invalid: $invalid, Sanitized: $sanitized"
                results+=("$image,$tool,spdx,$total,$invalid,$sanitized,success")
                
                # Extract invalid licenses for database (|| true to handle no matches)
                echo "$analysis" | grep "^INVALID:" | while read -r line; do
                    local parts="${line#INVALID:}"
                    echo "$image|$tool|spdx|$parts" >> "$OUTPUT_DIR/all_invalid_licenses.txt"
                done || true
            else
                log "  [$tool] SPDX: Empty or missing output"
                results+=("$image,$tool,spdx,0,0,0,empty_output")
            fi
        else
            log "  [$tool] SPDX: Generation failed"
            results+=("$image,$tool,spdx,0,0,0,generation_failed")
        fi
    fi
    
    # Write results to CSV
    for result in "${results[@]}"; do
        echo "$result" >> "$SUMMARY_CSV"
    done
}

# Generate final JSON database
generate_json_database() {
    log "Creating JSON database of invalid licenses..."
    
    $PYTHON_CMD << PYTHON_SCRIPT
import json
import os
from collections import defaultdict

output_dir = '$OUTPUT_DIR'
issues = []
by_license = defaultdict(list)
by_tool = defaultdict(int)
by_format = defaultdict(int)
by_distro = defaultdict(int)

try:
    with open(f'{output_dir}/all_invalid_licenses.txt') as f:
        for line in f:
            line = line.strip()
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 6:
                    image, tool, fmt, component, field, license_id = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                    
                    # Extract distro from image name
                    distro = image.split(':')[0].split('/')[-1]
                    
                    issue = {
                        'image': image,
                        'distro': distro,
                        'tool': tool,
                        'format': fmt,
                        'component': component,
                        'field': field,
                        'license': license_id
                    }
                    issues.append(issue)
                    
                    by_license[license_id].append(issue)
                    by_tool[tool] += 1
                    by_format[fmt] += 1
                    by_distro[distro] += 1
except FileNotFoundError:
    pass

# Get unique licenses sorted by frequency
unique_licenses = sorted(by_license.keys(), key=lambda x: -len(by_license[x]))

result = {
    'summary': {
        'total_issues': len(issues),
        'unique_invalid_licenses': len(unique_licenses),
        'by_tool': dict(by_tool),
        'by_format': dict(by_format),
        'by_distro': dict(by_distro),
    },
    'unique_licenses': [
        {
            'license': lic,
            'count': len(by_license[lic]),
            'distros': list(set(i['distro'] for i in by_license[lic])),
            'tools': list(set(i['tool'] for i in by_license[lic])),
        }
        for lic in unique_licenses
    ],
    'all_issues': issues
}

with open(f'{output_dir}/license_issues.json', 'w') as f:
    json.dump(result, f, indent=2)

print(f"Total issues found: {len(issues)}")
print(f"Unique invalid licenses: {len(unique_licenses)}")
print()
print("Top 20 most common invalid licenses:")
for lic in unique_licenses[:20]:
    count = len(by_license[lic])
    distros = set(i['distro'] for i in by_license[lic])
    print(f"  {lic}: {count} occurrences in {len(distros)} distros")

print()
print("Issues by tool:")
for tool, count in sorted(by_tool.items(), key=lambda x: -x[1]):
    print(f"  {tool}: {count}")

print()
print("Issues by distro:")
for distro, count in sorted(by_distro.items(), key=lambda x: -x[1])[:10]:
    print(f"  {distro}: {count}")
PYTHON_SCRIPT
}

# Main function
main() {
    log_section "License Sanitization Comprehensive Test Suite"
    log "Output directory: $OUTPUT_DIR"
    log "Project root: $PROJECT_ROOT"
    log "Number of images: ${#DOCKER_IMAGES[@]}"
    
    # Check prerequisites and get available tools
    local available_tools
    available_tools=$(check_prerequisites)
    log "Available tools: $available_tools"
    
    # Initialize CSV
    echo "image,tool,format,total_licenses,invalid_before,sanitized,status" > "$SUMMARY_CSV"
    
    # Initialize invalid licenses file
    > "$OUTPUT_DIR/all_invalid_licenses.txt"
    
    log_section "Testing Docker Images"
    log "Note: Tools will pull images directly (no docker client needed)"
    
    local total_tests=0
    
    for image in "${DOCKER_IMAGES[@]}"; do
        log ""
        log "Testing: $image"
        log "-----------------------------------------------------------"
        
        for tool in $available_tools; do
            test_image_tool "$image" "$tool"
            total_tests=$((total_tests + 1))
        done
    done
    
    log_section "Generating Summary"
    
    # Generate JSON database
    generate_json_database | tee -a "$LOG_FILE"
    
    # Print CSV summary
    log ""
    log "CSV Summary:"
    if [ -f "$SUMMARY_CSV" ]; then
        # Count by status
        local success_count fail_count empty_count
        success_count=$(grep -c ",success$" "$SUMMARY_CSV" || echo "0")
        fail_count=$(grep -c ",generation_failed$" "$SUMMARY_CSV" || echo "0")
        empty_count=$(grep -c ",empty_output$" "$SUMMARY_CSV" || echo "0")
        
        log "  Successful generations: $success_count"
        log "  Failed generations: $fail_count"
        log "  Empty outputs: $empty_count"
        
        # Count total invalid licenses found
        local total_invalid
        total_invalid=$(awk -F',' 'NR>1 {sum+=$5} END {print sum+0}' "$SUMMARY_CSV")
        log "  Total invalid licenses found: $total_invalid"
        
        # Count total sanitized
        local total_sanitized
        total_sanitized=$(awk -F',' 'NR>1 {sum+=$6} END {print sum+0}' "$SUMMARY_CSV")
        log "  Total licenses sanitized: $total_sanitized"
    fi
    
    log_section "Output Files"
    log "  Raw SBOMs: $OUTPUT_DIR/raw/"
    log "  Sanitized SBOMs: $OUTPUT_DIR/sanitized/"
    log "  Summary CSV: $SUMMARY_CSV"
    log "  License issues JSON: $ISSUES_JSON"
    log "  Full log: $LOG_FILE"
    
    log ""
    log "Done!"
}

# Export OUTPUT_DIR for Python scripts
export OUTPUT_DIR

# Run main
main "$@"
