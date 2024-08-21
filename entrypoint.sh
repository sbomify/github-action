#!/bin/bash

# Get the inputs from the arguments
TOKEN="$1"
SBOM_FILE="$2"

# Check if the SBOM file exists
if [ ! -f "$SBOM_FILE" ]; then
  echo "SBOM file not found: $SBOM_FILE"
  exit 1
fi

# Detect artifact type
if jq -e '.bomFormat == "CycloneDX"' "$SBOM_FILE" > /dev/null; then
  FORMAT="cyclonedx"
elif jq -e '.spdxVersion != null' "$SBOM_FILE" > /dev/null; then
  FORMAT="spdx"
else
  echo "Neither CycloneDX nor SPDX format found in JSON file."
  exit 1
fi

# Execute the curl command to upload the SBOM file
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d @"$SBOM_FILE" \
  "https://app.sbomify.com/api/v1/sboms/artifact/$FORMAT"

# Check the result of the curl command
if [ $? -ne 0 ]; then
  echo "Failed to upload SBOM file."
  exit 1
else
  echo "SBOM file uploaded successfully."
fi
