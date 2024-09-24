import os
import sys
import json
import requests
from cyclonedx.model.bom import Bom
from cyclonedx.output import get_instance as get_output_instance
from cyclonedx.parser.requirements import RequirementsFileParser
from cyclonedx.parser.pipenv import PipEnvFileParser
from cyclonedx.parser.poetry import PoetryFileParser

def path_expansion(path):
    # Check if the path is an absolute path
    if os.path.isabs(path):
        file_path = path
    else:
        # Check if the path is relative to the current folder
        if os.path.isfile(path) or os.path.isdir(path):
            file_path = os.path.join(os.getcwd(), path)
        else:
            file_path = os.path.join("/github/workspace", path)
    return file_path

def evaluate_boolean(value):
    return value.lower() in ['true', 'yes', 'yes', 'yeah']

def validate_sbom(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print("[Error] Invalid JSON.")
        sys.exit(1)
    # Detect artifact type
    if data.get('bomFormat') == 'CycloneDX':
        return 'cyclonedx'
    elif data.get('spdxVersion') is not None:
        return 'spdx'
    else:
        print("[Error] Neither CycloneDX nor SPDX format found in JSON file.")
        sys.exit(1)

def print_message(message, file=None):
    ascii_art = f'''
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
'''
    print("```", file=file)
    print(ascii_art, file=file)
    print("```", file=file)

def main():
    # Make sure required variables are defined
    TOKEN = os.getenv('TOKEN')
    if not TOKEN:
        print("[Error] sbomify API token is not defined. Exiting.")
        sys.exit(1)

    COMPONENT_ID = os.getenv('COMPONENT_ID')
    if not COMPONENT_ID:
        print("[Error] Component ID is not defined. Exiting.")
        sys.exit(1)

    SBOM_FILE = path_expansion(os.getenv('SBOM_FILE)'))
    LOCK_FILE = path_expansion(os.getenv('LOCK_FILE'))
    OUTPUT_FILE = os.getenv('OUTPUT_FILE', 'sbom_output.json')

    # Default to upload
    UPLOAD = os.getenv('UPLOAD', True)

    # Check if either SBOM_FILE or LOCK_FILE exists
    if SBOM_FILE and os.path.isfile(SBOM_FILE):
        FILE = SBOM_FILE
        FILE_TYPE = "SBOM"
    elif LOCK_FILE and os.path.isfile(LOCK_FILE):
        FILE = LOCK_FILE
        FILE_TYPE = "LOCK"
    else:
        print("[Error] Neither SBOM file nor LOCK file found.")
        sys.exit(1)

    # If SBOM_FILE is found, make sure it's a JSON file and detect artifact type
    if FILE_TYPE == "SBOM":
        FORMAT = validate_sbom(FILE)
        SBOM_FILE = FILE  # Ensure SBOM_FILE is set
    elif FILE_TYPE == "LOCK":
        # Common Python lock file names
        COMMON_PYTHON_LOCK_FILES = ["Pipfile.lock", "poetry.lock", "requirements.txt"]

        # Check if the LOCK_FILE is a recognized Python lock file
        if os.path.basename(FILE) in COMMON_PYTHON_LOCK_FILES:
            PYTHON_LOCK_FILE = os.path.basename(FILE)

            # Provide the appropriate parser
            if PYTHON_LOCK_FILE == "requirements.txt":
                parser = RequirementsFileParser(requirements_file=FILE)
            elif PYTHON_LOCK_FILE == "poetry.lock":
                parser = PoetryFileParser(poetry_lock_file=FILE)
            elif PYTHON_LOCK_FILE == "Pipfile.lock":
                parser = PipEnvFileParser(pipenv_lock_file=FILE)
            else:
                print(f"[Warning] {FILE} is not a recognized Python lock file.")
                sys.exit(1)

            # Generate SBOM
            bom = Bom(parser=parser)
            outputter = get_output_instance(
                bom=bom,
                output_format='json',
                schema_version=Bom.get_default_supported_schema_version()
            )
            with open(OUTPUT_FILE, 'w') as f:
                f.write(outputter.output_as_string())

            SBOM_FILE = OUTPUT_FILE
            FORMAT = validate_sbom(SBOM_FILE)
        else:
            print(f"[Warning] {FILE} is not a recognized Python lock file.")
            sys.exit(1)
    else:
        print("[Error] Unrecognized FILE_TYPE.")
        sys.exit(1)

    # Execute the POST request to upload the SBOM file
    url = f"https://app.sbomify.com/api/v1/sboms/artifact/{FORMAT}/{COMPONENT_ID}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {TOKEN}"
    }

    with open(SBOM_FILE, 'r') as f:
        sbom_data = f.read()

    response = requests.post(url, headers=headers, data=sbom_data)

    # Check the result of the request
    GITHUB_STEP_SUMMARY = os.getenv('GITHUB_STEP_SUMMARY', 'github_step_summary.txt')
    if response.status_code != 200:
        with open(GITHUB_STEP_SUMMARY, 'a') as f:
            print_message("Failed to upload SBOM file.", file=f)
        sys.exit(1)
    else:
        with open(GITHUB_STEP_SUMMARY, 'a') as f:
            print_message("SBOM file uploaded successfully.", file=f)

if __name__ == '__main__':
    main()