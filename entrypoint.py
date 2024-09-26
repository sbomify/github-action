import json
import os
import subprocess
import sys

import requests


def path_expansion(path):
    """
    Takes a path/file and returns an absolute path.
    This function is needed to handle GitHub Action's
    somewhat custom path management in side Docker.
    """
    relative_path = os.path.join(os.getcwd(), path)
    workspace_relative_path = os.path.join("/github/workspace", path)

    if os.path.isfile(path):
        print("[Info] Using input file '{}'.".format(path))
        return os.path.join(os.getcwd(), path)
    elif os.path.isfile(relative_path):
        print("[Info] Using input file '{}'.".format(relative_path))
        return relative_path
    elif os.path.isfile(workspace_relative_path):
        print("[Info] Using input file '{}'.".format(workspace_relative_path))
        return workspace_relative_path
    else:
        print("[Error] Specified input file not found.")
        sys.exit(1)


def evaluate_boolean(value):
    return value.lower() in ["true", "yes", "yes", "yeah"]


def validate_sbom(file_path):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print("[Error] Invalid JSON.")
        sys.exit(1)
    # Detect artifact type
    if data.get("bomFormat") == "CycloneDX":
        print("[Info] Detected CycloneDX SBOM.")
        return "cyclonedx"
    elif data.get("spdxVersion") is not None:
        print("[Info] Detected SPDX SBOM.")
        return "spdx"
    else:
        print("[Error] Neither CycloneDX nor SPDX format found in JSON file.")
        sys.exit(1)


def generate_sbom_from_requirements(
    requirements_file, output_file, schema_version="1.6"
):
    """
    This should be rewritten as a native function.

    Returns an SBOM JSON object
    """
    cmd = [
        "cyclonedx-py",
        "requirements",
        requirements_file,
        "--schema-version",
        schema_version,
        "--outfile",
        output_file,
    ]

    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True
    )

    return result.returncode


def print_message(message, file=None):
    ascii_art = f"""
 ## sbomify says

 {message}

      _                     _  __
     | |                   (_)/ _|
  ___| |__   ___  _ __ ___  _| |_ _   _
 / __| '_ \\ / _ \\| '_ ' _ \\| |  _| | | |
 \\__ \\ |_) | (_) | | | | | | | | | |_| |
 |___/_.__/ \\___/|_| |_| |_|_|_|  \\__, |
                                   __/ |
 The SBOM hub for secure          |___/
 sharing and distribution.
"""
    print("```", file=file)
    print(ascii_art, file=file)
    print("```", file=file)


def main():
    # Make sure required variables are defined
    TOKEN = os.getenv("TOKEN")
    if not TOKEN:
        print("[Error] sbomify API token is not defined. Exiting.")
        sys.exit(1)

    COMPONENT_ID = os.getenv("COMPONENT_ID")
    if not COMPONENT_ID:
        print("[Error] Component ID is not defined. Exiting.")
        sys.exit(1)

    if os.getenv("SBOM_FILE"):
        SBOM_FILE = path_expansion(os.getenv("SBOM_FILE"))
    else:
        SBOM_FILE = None

    if os.getenv("LOCK_FILE"):
        LOCK_FILE = path_expansion(os.getenv("LOCK_FILE"))
    else:
        LOCK_FILE = None

    OUTPUT_FILE = os.getenv("OUTPUT_FILE", "sbom_output.json")

    # Default to upload
    UPLOAD = evaluate_boolean(os.getenv("UPLOAD", "True"))

    # Check if either SBOM_FILE or LOCK_FILE exists
    if SBOM_FILE:
        FILE = SBOM_FILE
        FILE_TYPE = "SBOM"
    elif LOCK_FILE:
        FILE = LOCK_FILE
        FILE_TYPE = "LOCK_FILE"
    else:
        print("[Error] Neither SBOM file nor LOCK file found.")
        sys.exit(1)

    # If SBOM_FILE is found, make sure it's a JSON file and detect artifact type
    if FILE_TYPE == "SBOM":
        FORMAT = validate_sbom(FILE)
        SBOM_FILE = FILE  # Ensure SBOM_FILE is set
    elif FILE_TYPE == "LOCK_FILE":

        LOCK_FILE_NAME = os.path.basename(FILE)

        # Common Python lock file names
        COMMON_PYTHON_LOCK_FILES = ["Pipfile.lock", "poetry.lock", "requirements.txt"]

        # Check if the LOCK_FILE is a recognized Python lock file
        if os.path.basename(FILE) in COMMON_PYTHON_LOCK_FILES:

            # Provide the appropriate parser
            if LOCK_FILE_NAME == "requirements.txt":
                sbom_generation = generate_sbom_from_requirements(
                    requirements_file=LOCK_FILE, output_file=OUTPUT_FILE
                )
            elif LOCK_FILE_NAME == "poetry.lock":
                print("placeholder")
            elif LOCK_FILE_NAME == "Pipfile.lock":
                print("placeholder")
            else:
                print(f"[Warning] {FILE} is not a recognized Python lock file.")
                sys.exit(1)

            if not sbom_generation == 0:
                print("[Error]: SBOM Generation failed.")

            SBOM_FILE = OUTPUT_FILE
            FORMAT = validate_sbom(SBOM_FILE)
        else:
            print(f"[Warning] {FILE} is not a recognized lock file.")
            sys.exit(1)
    else:
        print("[Error] Unrecognized FILE_TYPE.")
        sys.exit(1)

    if UPLOAD:
        # Execute the POST request to upload the SBOM file
        url = f"https://app.sbomify.com/api/v1/sboms/artifact/{FORMAT}/{COMPONENT_ID}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        }

        with open(SBOM_FILE, "r") as f:
            sbom_data = f.read()

        response = requests.post(url, headers=headers, data=sbom_data)

        # Check the result of the request
        GITHUB_STEP_SUMMARY = os.getenv(
            "GITHUB_STEP_SUMMARY", "github_step_summary.txt"
        )
        if response.status_code != 200:
            with open(GITHUB_STEP_SUMMARY, "a") as f:
                print_message("Failed to upload SBOM file.", file=f)
            sys.exit(1)
        else:
            with open(GITHUB_STEP_SUMMARY, "a") as f:
                print_message("SBOM file uploaded successfully.", file=f)


if __name__ == "__main__":
    main()
