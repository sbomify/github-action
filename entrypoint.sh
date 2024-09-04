#!/bin/bash

# Define the token
TOKEN="$1"
SBOM_FILE="/github/workspace/$2"
COMPONENT_ID="$3"

robot_say() {
    local message="$1"
    local border=$(printf "%${#message}s" | tr ' ' '-')

    echo "::group::Robot Says"  # GitHub Actions log grouping for better readability
    echo " $border "
    echo "[ $message ]"
    echo " $border "
    echo "        _____"
    echo "       /     \\"
    echo "      | O   O |"
    echo "      |   ^   |"
    echo "      |  \\_/  |"
    echo "       \\_____/ "
    echo "       _|___|_"
    echo "     /       \\"
    echo "    | |     | |"
    echo "    |_|     |_|"
    echo "::endgroup::"  # End log group
}

# Check if the SBOM file exists
if [ ! -f "$SBOM_FILE" ]; then
  echo "[Error] SBOM file not found: $SBOM_FILE"
  exit 1
fi

# Make sure it's a JSON file
if ! jq -e '.' "$SBOM_FILE" > /dev/null; then
  echo "[Error] $SBOM_FILE is not a valid JSON file." >&2
  exit 1
fi

# Detect artifact type
if jq -e '.bomFormat == "CycloneDX"' "$SBOM_FILE" > /dev/null; then
  FORMAT="cyclonedx"
elif jq -e '.spdxVersion != null' "$SBOM_FILE" > /dev/null; then
  FORMAT="spdx"
else
  echo "[Error] Neither CycloneDX nor SPDX format found in JSON file."
  exit 1
fi

# Execute the curl command to upload the SBOM file
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d @"$SBOM_FILE" \
  "https://app.sbomify.com/api/v1/sboms/artifact/$FORMAT/$COMPONENT_ID" | jq

# Check the result of the curl command
if [ $? -ne 0 ]; then
  robot_say "Failed to upload SBOM file."
  exit 1
else
  robot_say "SBOM file uploaded successfully."
fi
