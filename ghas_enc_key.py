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
Generates encrypted API key for GitHub Advanced Security (GHAS) Vulnerability Report script.
"""

from cryptography.fernet import Fernet
import json
import os

GHAS_CONFIG_FILE = "_ghas_config.json"
GHAS_ENV_FILE = ".ghas_env"

def load_fernet_key():
    # Check if .ghas_env file exists
    if os.path.exists(GHAS_ENV_FILE):
        # If file exists, load the key from the file
        try:
            with open(GHAS_ENV_FILE, "rb") as f:
                key = f.read()
            print(f"\nKey loaded from {GHAS_ENV_FILE} file. If you want to generate a new key, delete the {GHAS_ENV_FILE} file.")
            return Fernet(key)
        except IOError as e:
            raise ValueError(f"\nError reading from {GHAS_ENV_FILE}: {e}")
    else:
        # If file doesn't exist, generate a new key and save it to the file
        key = Fernet.generate_key()
        try:
            with open(GHAS_ENV_FILE, "wb") as f:
                f.write(key)
            print(f"\nKey generated and saved to {GHAS_ENV_FILE} file.")
            return Fernet(key)
        except IOError as e:
            raise ValueError(f"\nError writing to {GHAS_ENV_FILE}: {e}")

def store_api_key():
    # Check if GHAS_CONFIG_FILE file exists, if not create it
    if not os.path.exists(GHAS_CONFIG_FILE):
        print(f"\n{GHAS_CONFIG_FILE} file not found, creating new file...")
        create_config()
    # Prompt user to add API key to config file
    api_key = input("\nEnter your GitHub API key: ")

    # Encrypt the API key with the Fernet key
    fernet_key = load_fernet_key()
    enc_api_key = fernet_key.encrypt(api_key.encode())

    with open(GHAS_CONFIG_FILE, "r") as f:
        config = json.load(f)
    print(f"\nNew API key stored in {GHAS_CONFIG_FILE} file.\n")
    config["connection"]["gh_api_key"] = enc_api_key.decode()
    try:
        with open(GHAS_CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except IOError as e:
            raise ValueError(f"\nError writing to {GHAS_CONFIG_FILE}: {e}")
    
def create_config():
    # Create a new ghas_config.json file with default values
    default_config = {
        "connection" : {
            "gh_api_url": "https://api.github.com",
            "gh_api_key": "",
            "gh_api_version": "2022-11-28"
        },
        "projects": {
            "<PROJECT1>": {
                "owner": "<OWNER>",
                "organizations": [
                        "<ORG1>",
                        "<ORG2>"
                ],
                "repositories": [
                        "<REPO1>",
                        "<REPO2>"
                ]
            }
        }
    }
    try:
        with open(GHAS_CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=4)
    except IOError as e:
            raise ValueError(f"\nError writing to {GHAS_CONFIG_FILE}: {e}")

def main():
    store_api_key()
    #create_config()

if __name__ == '__main__':
    main()