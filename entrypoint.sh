#!/bin/bash

PATH_EXPANSION () {
  # @TODO: This needs to be patched to support relative paths.
  # Right now it only support absolute URLS and files in current folder.

  if [[ "$1" = /* ]]; then
    FILE_PATH="$1"  # If $1 is an absolute path, use it directly
  else
    FILE_PATH="/github/workspace/$1"  # If $1 is a relative path, prepend the base path
  fi
  echo "$FILE_PATH"
}

# Define the token
TOKEN="$1"
COMPONENT_ID="$2"
SBOM_FILE="$(PATH_EXPANSION $3)"
LOCK_FILE="$(PATH_EXPANSION $4)"
OUTPUT_FILE="$(PATH_EXPANSION $5)"

print_message() {
    local message="$1"
    echo \`\`\`
    echo " "
    echo " ## sbomify says"
    echo " "
    echo " $message"
    echo " "
    echo "      _                     _  __"
    echo "     | |                   (_)/ _|"
    echo "  ___| |__   ___  _ __ ___  _| |_ _   _"
    echo " / __| '_ \ / _ \| '_ ' _ \| |  _| | | |"
    echo " \__ \ |_) | (_) | | | | | | | | | |_| |"
    echo " |___/_.__/ \___/|_| |_| |_|_|_|  \__, |"
    echo "                                   __/ |"
    echo " The SBOM hub for secure          |___/"
    echo " sharing and distribution."
    echo \`\`\`
}

# Define library versions
CYCLONEDX_PYTHON_VERSION=4.5.0

VALIDATE_SBOM () {
  FILE="$1"

  if ! jq empty "$FILE" >/dev/null 2>&1; then
    echo "[Error] Invalid JSON."
    exit 1
  fi

  # Detect artifact type
  if jq -e '.bomFormat == "CycloneDX"' "$FILE" > /dev/null; then
    FORMAT="cyclonedx"
  elif jq -e '.spdxVersion != null' "$FILE" > /dev/null; then
    FORMAT="spdx"
  else
    echo "[Error] Neither CycloneDX nor SPDX format found in JSON file."
    exit 1
  fi
}

# Make sure required variables are defined
if [ -z "$TOKEN" ]; then
  echo "[Error] sbomify API token is not defined. Exiting."
  exit 1
fi

if [ -z "$COMPONENT_ID" ]; then
  echo "[Error] Component ID is not defined. Exiting."
  exit 1
fi

# Check if either SBOM_FILE or LOCK_FILE exists
if [ -f "$SBOM_FILE" ]; then
  FILE="$SBOM_FILE"
  FILE_TYPE="SBOM"
elif [ -f "$LOCK_FILE" ]; then
  FILE="$LOCK_FILE"
  FILE_TYPE="LOCK"
else
  echo "[Error] Neither SBOM file nor LOCK file found."
  exit 1
fi

# If SBOM_FILE is found, make sure it's a JSON file and detect artifact type
if [ "$FILE_TYPE" = "SBOM" ]; then
  VALIDATE_SBOM "$FILE"
fi

# If LOCK_FILE is found, perform necessary checks
if [ "$FILE_TYPE" = "LOCK" ]; then
  # Common Python lock file names
  COMMON_PYTHON_LOCK_FILES=("Pipfile.lock" "poetry.lock" "requirements.txt")

  # Check if the LOCK_FILE is a recognized Python lock file
  for lockfile in "${COMMON_PYTHON_LOCK_FILES[@]}"; do
    if [[ "$(basename "$FILE")" == "$lockfile" ]]; then
        PYTHON_LOCK_FILE="$lockfile"
        break
    fi
  done

  if [ -z "${PYTHON_LOCK_FILE+x}" ]; then
    # Install CycloneDX Python
    python -m pip install \
      cyclonedx-bom==${CYCLONEDX_PYTHON_VERSION}

    # Provide the appropriate argument
    if [[ "$(basename "$FILE")" == "requirements.txt" ]]; then
      CDX_PY_ARGUMENT="requirements"
    elif [[ "$(basename "$FILE")" == "poetry.lock" ]]; then
      CDX_PY_ARGUMENT="poetry"
    elif [[ "$(basename "$FILE")" == "Pipfile.lock" ]]; then
      CDX_PY_ARGUMENT="pipenv"
    fi

    # Generate SBOM using cyclonedx-py
    cyclonedx-py "$CDX_PY_ARGUMENT" \
      "$FILE" \
      --schema-version 1.6 \
      > "$OUTPUT_FILE"

    SBOM_FILE="$OUTPUT_FILE"
    VALIDATE_SBOM "$SBOM_FILE"
  else
    echo "[Warning] $FILE is not a recognized Python lock file."
  fi
fi

# Execute the curl command to upload the SBOM file
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @"$SBOM_FILE" \
  "https://app.sbomify.com/api/v1/sboms/artifact/$FORMAT/$COMPONENT_ID" | jq

# Check the result of the curl command
if [ $? -ne 0 ]; then
  print_message "Failed to upload SBOM file." >> ${GITHUB_STEP_SUMMARY}
  exit 1
else
  print_message "SBOM file uploaded successfully." >> ${GITHUB_STEP_SUMMARY}
fi
