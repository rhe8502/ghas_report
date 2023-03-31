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
GHAS Reporting Setup Tool

This script is a command-line utility that allows users to store their GitHub API key securely
in a JSON configuration file for use with the GitHub Advanced Security (GHAS) Vulnerability
Report script. The script provides options for specifying custom locations for the configuration
file, the encryption key file, and the reports directory.

The script uses the argparse module to parse command-line arguments and offers a help message
with information about the available options.

Usage:
    python setup.py [-h] [-v] [-a] [-lc <PATH>] [-lk <PATH>] [-lr <PATH>]

Options:
    -h, --help      Show this help message and exit.
    -v, --version   Show program's version number and exit.
    -a, --api-key   Prompt for a GitHub API key; replaces existing GitHub API key, or generate a
                    new config & key file if none exist (first-time setup).
    -lc, --config   Specify file location for the "ghas_report.py" configuration file
                    ("ghas_conf.json").
    -lk, --keyfile  Specify file location for the "ghas_report.py" encryption key file (".ghas_env").
    -lr, --reports  Specify file location for the "ghas_report.py" reports directory.

Example:
    python setup.py -a -lc /path/to/config -lk /path/to/keyfile -lr /path/to/reports
"""

from cryptography.fernet import Fernet
import argparse
import getpass
import json
import os

# Configuration file name and encryption key file name
conf_file_name = "ghas_config.json"
env_file_name = ".ghas_env"

def enc_key(key_file):
    """
    Generates or loads a Fernet encryption key from the given key_file.

    If the specified key_file does not exist or the user chooses to overwrite it,
    a new Fernet encryption key will be generated, saved to key_file, and returned.
    If the key_file exists and the user chooses not to overwrite it,
    the existing key will be loaded from the key_file and returned.

    Args:
        key_file (str): The path to the key file.

    Returns:
        Fernet: A Fernet object initialized with the encryption key.

    Raises:
        SystemExit: If there is an error reading or writing the key file.
    """
    if not os.path.exists(key_file) or input(f"\nEncryption key file exists at {key_file}. Overwrite and generate a new key? (y/n): ").lower() == "y":
        key = Fernet.generate_key()
        try:
            with open(key_file, "wb") as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            print(f"New key generated and saved to {key_file}\n")
        except IOError as e:
            raise SystemExit(f"Error writing to {e.filename}: {e}")
    else:
        try:
            with open(key_file, "rb") as f:
                key = f.read()
            print(f"Using encryption key from \"{key_file}\".\n")
        except IOError as e:
            raise SystemExit(f"Error reading from {e.filename}: {e}")
    return Fernet(key)

def store_api_key(config_file, key_file, script_dir, report_dir):
    """
    Stores the user's GitHub API key in an encrypted form inside a configuration file.
    If the configuration file already exists, prompts the user to overwrite the file, add the API key to the existing
    file, or cancel the process. If the file doesn't exist, a new configuration file is created.

    Args:
        config_file (str): The path to the configuration file.
        key_file (str): The path to the encryption key file.
        script_dir (str): The path to the script directory.
        report_dir (str): The path to the report directory.

    Raises:
        SystemExit: If there is an error reading or writing the configuration file or the key file.
    """
    if os.path.exists(config_file):
        while True:
            choice = input(f"Configuration file already exists at {config_file}.\nChoose an action: (O)verwrite the file, (A)dd the API key to the existing file, or (C)ancel (O/A/C): ").lower()
            if choice == "a":
                break
            elif choice == "o":
                create_config(config_file)
                break
            elif choice == "c":
                print("Exiting.")
                exit()
            else:
                print("\nInvalid choice. Try again.\n")
    else:
        create_config(config_file)

    # Load the Fernet encryption key
    fernet_key = enc_key(key_file)

    # Prompt user for the GitHub API key
    print("\nNote: For security reasons, your GitHub API key will not be displayed as you type.")
    api_key = getpass.getpass("Enter your GitHub API key: ")

    # Encrypt the API key with the Fernet encryption key
    enc_api_key = fernet_key.encrypt(api_key.encode())

    # Load the JSON configuration file and store the encrypted GitHub API key
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise SystemExit(f"Error reading from {e.filename}: {e}")
    
    # Store the encrypted API key in config
    config["connection"]["gh_api_key"] = enc_api_key.decode()

    # Set the report directory and key file directory and store in config
    config["location"]["reports"] = report_dir if report_dir else ""
    config["location"]["keyfile"] = "" if os.path.dirname(key_file) == script_dir else os.path.dirname(key_file)
      
    try:
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)
        print(f"\nNew API key stored in {config_file}")
        if report_dir:
            print(f"Report directory set to {report_dir}")
        if os.path.dirname(key_file) != script_dir:
            print(f"Keyfile directory set to {os.path.dirname(key_file)}\n")
    except IOError as e:
        raise SystemExit(f"Error writing to {e.filename}: {e}")
    
def create_config(config_file):
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
            "keyfile": ""
        },
        "projects": {
            "YOUR_PROJECT_NAME": {
                "owner": "GITHUB_OWNER",
                "organizations": [
                        "ORG"
                ],
                "repositories": [
                        "REPO1"
                ]
            }
        }
    }
    try:
        with open(config_file, "w") as f:
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
    parser = argparse.ArgumentParser(description='Store a GitHub API key for the GitHub Advanced Security (GHAS) Vulnerability Report script securely in a JSON configuration file.')

    # Options group
    parser.add_argument('-v', '--version', action='version', version=(version_string), help="show program's version number and exit")

    # Setup group
    setup_group = parser.add_argument_group('Store GitHub API key')
    setup_group.add_argument('-a', '--api-key', action='store_true', help='prompt for a GitHub API key; replaces existing GitHub API key, or generate a new config & key file if none exist (first-time setup)')
    
    # Optional location arguments
    location_options_group = parser.add_argument_group('Optional file location arguments')
    location_options_group.add_argument('-lc', '--config', metavar='<PATH>', type=str, help='specify file location for the "ghas_report.py" configuration file ("ghas_conf.json")')
    location_options_group.add_argument('-lk', '--keyfile', metavar='<PATH>', type=str, help='specify file location for the "ghas_report.py" encryption key file (".ghas_env")')
    location_options_group.add_argument('-lr', '--reports', metavar='<PATH>', type=str, help='specify file location for the "ghas_report.py" reports directory')

    # Parse the arguments
    args = parser.parse_args()

    # If --api-key is not specified, print the help message and exit.
    if not args.api_key:
        print("No arguments specified. Use -h or --help for help.")
        parser.print_help()

    # Determine script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Joins the script directory, or specified file path (-lc, -lk), with the default configuration file name.
    config_file = os.path.join(args.config, conf_file_name) if args.config else os.path.join(script_dir, conf_file_name)
    key_file = os.path.join(args.keyfile, env_file_name) if args.keyfile else os.path.join(script_dir, env_file_name)
    report_dir = os.path.join(args.reports) if args.reports else ""

    if args.api_key:
        store_api_key(config_file, key_file, script_dir, report_dir)
 
if __name__ == '__main__':
    main()