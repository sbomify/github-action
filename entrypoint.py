import json
import os
import shutil
import subprocess
import sys

import requests

"""

There are three steps in our SBOM generation.

# Step 1: Generation / Validation
In this step we either generate an SBOM from a lockfile
or we validate a provided SBOM.

The output of this phase is `step_1.json`.

# Step 2: Augmentation
This step augments the provided SBOM with data about
you as the software provider from sbomify's backend.
This includes merging in information about licensing,
supplier and vendor. This data is required for NTIA
Minimum Elements compliance.

The output of this `step_2.json`.


# Step 3: Enrichment
SBOMs will vary a lot in quality of the components.
As we aspire to reach NTIA Minimum Elements compliants
we will use an enrichment tool (Parlay) to ensure that
as many of our components in the SBOM as possible have
the required data.

The output of this step is `step_3.json`.

Since both step 2 and 3 are optional, we will only
write `OUTPUT_FILE` at the end of the run.

"""

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


def get_last_sbom_from_last_step():
    """
    Helper funtion to get the SBOM from the previous step.
    """
    steps = ["step_3.json", "step_2.json", "step_1.json"]
    for file in steps:
        if os.path.isfile(file):
            return file
    return


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
    Takes a Python lockfile and generates a CycloneDX SBOM.
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


def run_trivy_fs(lock_file, output_file):
    """
    Takes a supported lockfile and generates a CycloneDX SBOM.
    """
    cmd = [
        "trivy",
        "fs",
        lock_file,
        "--parallel",
        "0",
        "--format",
        "cyclonedx",
    ]

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


def print_banner():
    ascii_art = f"""

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
    print(ascii_art)


def main():
    print_banner()

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

    UPLOAD = evaluate_boolean(os.getenv("UPLOAD", "True"))
    AUGMENT = evaluate_boolean(os.getenv("AUGMENT", "False"))
    ENRICH = evaluate_boolean(os.getenv("ENRICH", "False"))

    # Step 1

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
        shutil.copy(SBOM_FILE, "step_1.json")
    elif FILE_TYPE == "LOCK_FILE":

        LOCK_FILE_NAME = os.path.basename(FILE)

        # Common Python lock file names
        COMMON_PYTHON_LOCK_FILES = [
            "Pipfile.lock",
            "poetry.lock",
            "pyproject.toml",
            "requirements.txt",
        ]

        # Common Rust lock file names
        COMMON_RUST_LOCK_FILES = [
            "Cargo.lock",
        ]

        # Common JavaScript lock file names
        COMMON_JAVASCRIPT_LOCK_FILES = [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ]

        # Common Ruby lock file names
        COMMON_RUBY_LOCK_FILES = [
            "Gemfile.lock",
        ]

        # Common Go lock file names
        COMMON_GO_LOCK_FILES = [
            "go.mod.lock",
        ]

        # Common Dart lock file names
        COMMON_DART_LOCK_FILES = [
            "pubspec.lock",
        ]

        # Check if the LOCK_FILE is a recognized Python lock file
        if os.path.basename(FILE) in COMMON_PYTHON_LOCK_FILES:

            print("[Info] Detected Python lockfile")
            # Provide the appropriate parser
            if LOCK_FILE_NAME == "requirements.txt":
                sbom_generation = generate_sbom_from_python_lock_file(
                    lock_file=LOCK_FILE,
                    lock_file_type="requirements",
                    output_file="step_1.json",
                )
            elif LOCK_FILE_NAME == "poetry.lock" or LOCK_FILE_NAME == "pyproject.toml":
                # Poetry doesn't actually take the lock file, but rather the folder
                sbom_generation = generate_sbom_from_python_lock_file(
                    lock_file=os.path.dirname(LOCK_FILE),
                    lock_file_type="poetry",
                    output_file="step_1.json",
                )
            elif LOCK_FILE_NAME == "Pipfile.lock":
                sbom_generation = generate_sbom_from_python_lock_file(
                    lock_file=LOCK_FILE,
                    lock_file_type="pipenv",
                    output_file="step_1.json",
                )


            else:
                print(f"[Warning] {FILE} is not a recognized Python lock file.")
                sys.exit(1)

            if not sbom_generation == 0:
                print("[Error]: SBOM Generation failed.")

            FORMAT = validate_sbom("step_1.json")

        # Rust
        elif os.path.basename(FILE) in COMMON_RUST_LOCK_FILES:
            print("[Info] Detected Rust lockfile")
            run_trivy_fs(
                lock_file=LOCK_FILE, output_file="step_1.json"
            )

        # JavaScript / Node.JS
        elif os.path.basename(FILE) in COMMON_JAVASCRIPT_LOCK_FILES:
            print("[Info] Detected JavaScript lockfile")
            run_trivy_fs(
                lock_file=LOCK_FILE, output_file="step_1.json"
            )

        # Ruby
        elif os.path.basename(FILE) in COMMON_RUBY_LOCK_FILES:
            print("[Info] Detected Ruby lockfile")
            run_trivy_fs(
                lock_file=LOCK_FILE, output_file="step_1.json"
            )

        # Go
        elif os.path.basename(FILE) in COMMON_GO_LOCK_FILES:
            print("[Info] Detected Go lockfile")
            run_trivy_fs(
                lock_file=LOCK_FILE, output_file="step_1.json"
            )

        # Dart
        elif os.path.basename(FILE) in COMMON_DART_LOCK_FILES:
            print("[Info] Detected Dart lockfile")
            run_trivy_fs(
                lock_file=LOCK_FILE, output_file="step_1.json"
            )
        else:
            print(f"[Error] {FILE} is not a recognized lock file.")
            sys.exit(1)
    else:
        print("[Error] Unrecognized FILE_TYPE.")
        sys.exit(1)

    # Step 2
    if AUGMENT:
        """
        Enrich SBOM with vendor/license information
        from sbomify's backend.
        """

    # Step 3
    if ENRICH:
        """
        Enrich SBOM using Snyk's Parlay
        """

        enrich = enrich_sbom_with_parley(get_last_sbom_from_last_step(), "step_3.json")
        sbom_type = validate_sbom("step_3.json")

    # Clean up and write final SBOM
    shutil.copy(get_last_sbom_from_last_step(), OUTPUT_FILE)
    while get_last_sbom_from_last_step():
        os.remove(get_last_sbom_from_last_step())

    if UPLOAD:
        # Execute the POST request to upload the SBOM file
        url = f"https://app.sbomify.com/api/v1/sboms/artifact/{FORMAT}/{COMPONENT_ID}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        }

        with open(OUTPUT_FILE, "r") as f:
            sbom_data = f.read()

        response = requests.post(url, headers=headers, data=sbom_data)

        if not response.ok:
            print(
                "[Error] Failed to upload SBOM file ({}).".format(response.status_code)
            )
            sys.exit(1)
        else:
            print("[Info] SBOM file uploaded successfully.")


if __name__ == "__main__":
    main()
