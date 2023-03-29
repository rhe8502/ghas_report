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
Generate encrypted API key for GitHub Advanced Security (GHAS) Vulnerability Report script.
"""

from cryptography.fernet import Fernet
import json
import os

# Configuration file name and encryption key file name. A full path can be used if required.
GHAS_CONFIG_FILE = "ghas_config.json"
GHAS_ENV_FILE = ".ghas_env"

def load_fernet_key():
    # Check if .ghas_env file exists
    if os.path.exists(GHAS_ENV_FILE):
        # If file exists, load the encryption key from the file
        try:
            with open(GHAS_ENV_FILE, "rb") as f:
                key = f.read()
            print(f"Using ecnryption key from \"{GHAS_ENV_FILE}\". If you want to generate a new encryption key delete \"{GHAS_ENV_FILE}\" and rerun the script.")
            return Fernet(key)
        except IOError as e:
            print(f"Error reading from {GHAS_ENV_FILE}: {e}")
            exit(1)
    else:
        # If file doesn't exist, generate a new encryption key and save it to the file
        key = Fernet.generate_key()
        try:
            with open(GHAS_ENV_FILE, "wb") as f:
                f.write(key)
            # Set the permissions to read and write for the owner only
            os.chmod(GHAS_ENV_FILE, 0o400)
            print(f"New key generated and saved to {GHAS_ENV_FILE}")
            return Fernet(key)
        except IOError as e:
            print(f"Error writing to {GHAS_ENV_FILE}: {e}")
            exit(1)

def store_api_key():
    # Check if the JSON configuration file exists, if not create it
    if not os.path.exists(GHAS_CONFIG_FILE):
        print(f"{GHAS_CONFIG_FILE} file not found, creating new file.")
        create_config()

    # Load the Fernet encryption key
    fernet_key = load_fernet_key()

    # Prompt user for the GitHub API key
    api_key = input("\nEnter your GitHub API key: ")

    # Encrypt the API key with the Fernet encryption key
    enc_api_key = fernet_key.encrypt(api_key.encode())

    # Load the JSON configuration file and store the encrypted GitHub API key
    with open(GHAS_CONFIG_FILE, "r") as f:
        config = json.load(f)
    print(f"New API key stored in {GHAS_CONFIG_FILE}\n")
    config["connection"]["gh_api_key"] = enc_api_key.decode()
    try:
        with open(GHAS_CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        print(f"Error writing to {GHAS_CONFIG_FILE}: {e}")
        exit(1)
    
def create_config():
    # Create a new JSON configuration file with some default values
    default_config = {
        "connection" : {
            "gh_api_url": "https://api.github.com",
            "gh_api_key": "",
            "gh_api_version": "2022-11-28"
        },
        "projects": {
            "PROJECT_NAME": {
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
        with open(GHAS_CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=4)
    except IOError as e:
        print(f"Error writing to {GHAS_CONFIG_FILE}: {e}")
        exit(1)

def main():
    store_api_key()

if __name__ == '__main__':
    main()