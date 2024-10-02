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
    return value.lower() in ["true", "yes", "yeah", "1"]


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


def generate_sbom_from_python_lock_file(
    lock_file, lock_file_type, output_file, schema_version="1.6"
):
    """
    This should be rewritten as a native function.
    """
    cmd = [
        "cyclonedx-py",
        lock_file_type,
        lock_file,
        "--schema-version",
        schema_version,
        "--outfile",
        output_file,
    ]

    if lock_file_type == "poetry":
        cmd += ["--no-dev"]

    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True
    )

    return result.returncode


def enrich_sbom_with_parley(input_file, output_file):
    """
    Takes a path to an SBOM as input and returns an
    enriched SBOM as the output.
    """

    cmd = ["parlay", "ecosystems", "enrich", input_file]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True
        )

    except subprocess.CalledProcessError as e:
        print(f"[Error] Command failed with error: {e}")
        sys.exit(1)

    # Check if returncode is zero
    if result.returncode == 0:
        # Get the output
        output = result.stdout

        # Validate JSON
        try:
            json_data = json.loads(
                output
            )  # This will raise a ValueError if it's not valid JSON

            # Write the output to a file if it's valid JSON
            with open(output_file, "w") as f:
                json.dump(
                    json_data, f, indent=4
                )  # Write it as formatted JSON to the file

        except json.JSONDecodeError as e:
            print(f"[Error] Invalid JSON: {e}")

    else:
        print(
            f"[Error] Enrichment command failed with return code {result.returncode}."
        )
        sys.exit(1)

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

    # Add some duplication logic
    if SBOM_FILE and LOCK_FILE:
        print("[Error] Please provide SBOM_FILE of LOCK_FILE, not both.")
        sys.exit(1)

    OUTPUT_FILE = os.getenv("OUTPUT_FILE", "sbom_output.json")

    # Default to true
    UPLOAD = evaluate_boolean(os.getenv("UPLOAD", "True"))
    AUGMENT = evaluate_boolean(os.getenv("AUGMENT", "False"))
    ENRICH = evaluate_boolean(os.getenv("ENRICH", "False"))

    # Check if either SBOM_FILE or LOCK_FILE exists
    if SBOM_FILE:
        FILE = SBOM_FILE
        FILE_TYPE = "SBOM"
    elif LOCK_FILE:
        FILE = LOCK_FILE
        FILE_TYPE = "LOCK_FILE"
    else:
        print("[Error] Neither SBOM file nor lockfile found.")
        sys.exit(1)

    # If SBOM_FILE is found, make sure it's a JSON file and detect artifact type
    if FILE_TYPE == "SBOM":
        FORMAT = validate_sbom(FILE)
        SBOM_FILE = FILE
    elif FILE_TYPE == "LOCK_FILE":

        LOCK_FILE_NAME = os.path.basename(FILE)

        # Common Python lock file names
        COMMON_PYTHON_LOCK_FILES = [
            "Pipfile.lock",
            "poetry.lock",
            "pyproject.toml",
            "requirements.txt",
        ]

        # Check if the LOCK_FILE is a recognized Python lock file
        if os.path.basename(FILE) in COMMON_PYTHON_LOCK_FILES:

            # Provide the appropriate parser
            if LOCK_FILE_NAME == "requirements.txt":
                sbom_generation = generate_sbom_from_python_lock_file(
                    lock_file=LOCK_FILE,
                    lock_file_type="requirements",
                    output_file=OUTPUT_FILE,
                )
            elif LOCK_FILE_NAME == "poetry.lock" or LOCK_FILE_NAME == "pyproject.toml":
                # Poetry doesn't actually take the lock file, but rather the folder
                sbom_generation = generate_sbom_from_python_lock_file(
                    lock_file=os.path.dirname(LOCK_FILE),
                    lock_file_type="poetry",
                    output_file=OUTPUT_FILE,
                )
            elif LOCK_FILE_NAME == "Pipfile.lock":
                sbom_generation = generate_sbom_from_python_lock_file(
                    lock_file=LOCK_FILE,
                    lock_file_type="pipenv",
                    output_file=OUTPUT_FILE,
                )
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

    if AUGMENT:
        """
        Enrich SBOM with vendor/license information
        from sbomify's backend.
        """

    if ENRICH:
        """
        Enrich SBOM using Snyk's Parlay
        """

        enrich = enrich_sbom_with_parley(SBOM_FILE, OUTPUT_FILE)
        sbom_type = validate_sbom(OUTPUT_FILE)

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
