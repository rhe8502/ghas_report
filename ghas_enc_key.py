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
import getpass
import json
import os

# Configuration file name and encryption key file name
conf_file_name = "ghas_config.json"
env_file_name = ".ghas_env"

def load_fernet_key(script_dir):
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
            print(f"Error reading from {e.filename}: {e}")
            exit(1)
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
            print(f"Error writing to {e.filename}: {e}")
            exit(1)

def store_api_key(script_dir):   
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
        print(f"Error reading from {e.filename}: {e}")
        exit(1)
    
    print(f"\nNew API key stored in {conf_file}\n")
    config["connection"]["gh_api_key"] = enc_api_key.decode()

    try:
        with open(conf_file, "w") as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        print(f"Error writing to {conf_file}: {e}")
        exit(1)
    
def create_config(conf_file):
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
        with open(conf_file, "w") as f:
            json.dump(default_config, f, indent=4)
    except IOError as e:
        print(f"Error writing to {conf_file}: {e}")
        exit(1)

def main():
    # Determine script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    store_api_key(script_dir)

if __name__ == '__main__':
    main()