#!/bin/bash

# Define the token
TOKEN="$1"
SBOM_FILE="/github/workspace/$2"
COMPONENT_ID="$3"

print_message() {
    local message="$1"
    local border=$(printf "%${#message}s" | tr ' ' '-')

    echo " $border "
    echo " $message"
    echo " $border "
    echo "      _                     _  __"
    echo "     | |                   (_)/ _|"
    echo "  ___| |__   ___  _ __ ___  _| |_ _   _"
    echo " / __| '_ \ / _ \| '_ ' _ \| |  _| | | |"
    echo " \__ \ |_) | (_) | | | | | | | | | |_| |"
    echo " |___/_.__/ \___/|_| |_| |_|_|_|  \__, |"
    echo "                                   __/ |"
    echo " The SBOM sharing and easy        |___/"
    echo " and collaboration platform"
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
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d @"$SBOM_FILE" \
  "https://app.sbomify.com/api/v1/sboms/artifact/$FORMAT/$COMPONENT_ID" | jq

# Check the result of the curl command
if [ $? -ne 0 ]; then
  print_message "Failed to upload SBOM file." >> ${GITHUB_STEP_SUMMARY}
  exit 1
else
  print_message "SBOM file uploaded successfully." >> ${GITHUB_STEP_SUMMARY}
fi
