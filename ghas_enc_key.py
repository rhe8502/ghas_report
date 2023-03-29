#!/usr/bin/env python3
#
# Copyright (c) 2023 Rupert Herbst <rhe8502(at)pm.me>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Rupert Herbst <rhe8502(at)pm.me>
# Package: ghas_report.py
# Version: 1.0.0
# Project URL: https://github.com/rhe8502/ghas_report/

"""
Generate and store an encrypted GitHub API key for the GitHub Advanced Security (GHAS)
Vulnerability Report script.

This script allows the user to store an encrypted GitHub API key in a JSON configuration file.
The API key is encrypted using the Fernet symmetric encryption library, and the encryption key
is stored in a separate file.

If the encryption key file does not exist, a new encryption key is generated and saved. The script
is designed to be used in conjunction with the main GHAS Vulnerability Report script, which retrieves
the encrypted API key from the configuration file, decrypts it, and uses it to access the GitHub API.
"""

from cryptography.fernet import Fernet
import argparse
import getpass
import json
import os

# Configuration file name and encryption key file name
conf_file_name = "ghas_config.json"
env_file_name = ".ghas_env"

def load_fernet_key(script_dir):
    """
    Load or generate a Fernet encryption key and return a Fernet object.

    This function checks if a file named `env_file_name` exists in the `script_dir` directory.
    If the file exists, it reads the Fernet key from the file and creates a Fernet object using the key.
    If the file doesn't exist, it generates a new Fernet key, saves it to the file, and creates a Fernet object using the new key.
    In both cases, it returns the Fernet object.

    Args:
        script_dir (str): The directory where the script is located.

    Returns:
        Fernet: A Fernet object initialized with the encryption key.

    Raises:
        IOError: If there is an error reading from or writing to the env_file.
    """
    env_file = os.path.join(script_dir, env_file_name)

    # Check if .ghas_env file exists
    if os.path.exists(env_file):
        # If file exists, load the encryption key from the file
        try:
            with open(env_file, "rb") as f:
                key = f.read()
            print(f"Using encryption key from \"{env_file}\". If you want to generate a new encryption key delete \"{env_file_name}\" and re-run the script.")
            return Fernet(key)
        except IOError as e:
            raise SystemExit(f"Error reading from {e.filename}: {e}")
    else:
        # If file doesn't exist, generate a new encryption key and save it to the file
        key = Fernet.generate_key()
        try:
            with open(env_file, "wb") as f:
                f.write(key)
            # Set the permissions to read and write for the owner only
            os.chmod(env_file, 0o600)
            print(f"New key generated and saved to {env_file}")
            return Fernet(key)
        except IOError as e:
            raise SystemExit(f"Error writing to {e.filename}: {e}")

def store_api_key(script_dir):
    """
    Prompt the user for their GitHub API key, encrypt it, and store it in the JSON configuration file.

    This function prompts the user for their GitHub API key, encrypts the key using a Fernet object,
    and saves the encrypted key in the JSON configuration file located at `script_dir/conf_file_name`.
    If the JSON configuration file does not exist, it creates a new one before storing the encrypted key.

    Args:
        script_dir (str): The directory where the script is located.

    Raises:
        IOError: If there is an error reading from or writing to the configuration file.
    """
    conf_file = os.path.join(script_dir, conf_file_name)

    # Check if the JSON configuration file exists, if not create it
    if not os.path.exists(conf_file):
        print(f"{conf_file} file not found, creating new file.")
        create_config(conf_file)

    # Load the Fernet encryption key
    fernet_key = load_fernet_key(script_dir)

    # Prompt user for the GitHub API key
    print("\nNote: For security reasons, your GitHub API key will not be displayed as you type.")
    api_key = getpass.getpass("Enter your GitHub API key: ")

    # Encrypt the API key with the Fernet encryption key
    enc_api_key = fernet_key.encrypt(api_key.encode())

    # Load the JSON configuration file and store the encrypted GitHub API key
    try:
        with open(conf_file, "r") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise SystemExit(f"Error reading from {e.filename}: {e}")
    
    print(f"\nNew API key stored in {conf_file}\n")
    config["connection"]["gh_api_key"] = enc_api_key.decode()

    try:
        with open(conf_file, "w") as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        raise SystemExit(f"Error writing to {e.filename}: {e}")
    
def create_config(conf_file):
    """
    Create a new JSON configuration file with default values.

    This function creates a new JSON configuration file at the specified path and writes
    a default configuration with placeholders for the user to fill in.

    Args:
        conf_file (str): The path to the configuration file.

    Raises:
        IOError: If there is an error writing to the configuration file.
    """
    default_config = {
        "connection" : {
            "gh_api_url": "https://api.github.com",
            "gh_api_key": "",
            "gh_api_version": "2022-11-28"
        },
        "location": {
            "reports": "",
            "key_file": ""
        },
        "projects": {
            "YOUR_PROJECT_NAME": {
                "owner": "GITHUB_OWNER",
                "organizations": [
                        "ORG1",
                        "ORG2"
                ],
                "repositories": [
                        "REPO1",
                        "REPO2"
                ]
            }
        }
    }
    try:
        with open(conf_file, "w") as f:
            json.dump(default_config, f, indent=4)
    except IOError as e:
        raise SystemExit(f"Error writing to {e.filename}: {e}")

def main():
    # version, date, and author information
    version_number = "1.0.0"
    release_date = "2023-03-30"
    url = "https://github.com/rhe8502/ghas_report"

    # version string
    version_string = f"GHAS Reporting Setup Tool v{version_number} ({url})\nRelease Date: {release_date}\n"

    # Command-line arguments parser
    parser = argparse.ArgumentParser(description='''
Generate and store an encrypted GitHub API key for the GitHub Advanced Security (GHAS) Vulnerability Report script.
    ''', formatter_class=argparse.RawTextHelpFormatter)

    #Options group
    parser.add_argument('-v', '--version', action='version', version=(version_string), help="show program's version number and exit")

    # Parse the arguments
    args = parser.parse_args()
    
    # Determine script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    store_api_key(script_dir)

if __name__ == '__main__':
    main()