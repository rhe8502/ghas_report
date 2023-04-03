#!/usr/bin/env python3
#-*- coding: utf-8 -*-

"""GitHub Advanced Security (GHAS) Vulnerability Report Generator

This script retrieves various types of GitHub Advanced Security (GHAS) alerts for a specified 
organization or repository and generates a report based on the specified options. 

The supported alert types include code scanning alerts, secret scanning alerts, and dependabot
alerts.

The script requires a configuration file ("conf_file") and an environment file ("env_file") to 
retrieve API credentials and settings. The API credentials are encrypted using the 
"ghas_enc_key.py" script, which generates and stores an encrypted GitHub API key

Command-line arguments can be passed to specify the alert types to process and the 
output format of the report. The supported output formats are CSV and JSON, and the 
default output format is CSV.

Functionality is provided to generate an alert count report, a code scanning alert report, a 
secret scanning alert report, and a dependabot alert report. Alert reports can be 
generated for open alerts only using the "-o" flag.

The script uses the GitHub API to retrieve alert data and requires valid API credentials. 
An API key can be added using the "ghas_enc_key.py" script.

Usage:
$ python script_name.py [-h] [-v] [-A] [-a] [-c] [-s] [-d] [-o] [-wA] [-wC] [-wJ]

Options:
-h, --help Show help message and exit.
-v, --version Show program's version number and exit.
-A, --all Generate Alert Count, Code Scanning, Secret Scanning, and Dependabot alert reports.
-a, --alerts Generate Alert Count report of all open alerts.
-c, --codescan Generate Code Scan alert report.
-s, --secretscan Generate Secret Scanning alert report.
-d, --dependabot Generate Dependabot alert report.
-o, --open Only generate reports for open alerts (Alert Count only reports open alerts).
-wA, --output-all Write output to all supported formats at once.
-wC, --output-csv Write output to a CSV file (default format).
-wJ, --output-json Write output to a JSON file.

The script also includes several helper functions to retrieve and process the alert data, including:

    alert_count(api_url, project_data): retrieves the total number of open alerts for a project.
    
    scan_alerts(api_url, project_data, alert_type, output_type, alert_state): retrieves detailed alert 
    data for a specific alert type and returns it in the specified output format (CSV or JSON).

    write_alerts(alert_data, project_name, output_type, report_dir, call_func): writes the alert data
    to a file in the specified output format.

The script uses the argparse module to parse command-line arguments and the json and os modules to 
read data from configuration and environment files.

Note: The script also contains commented-out code for measuring execution time for debugging purposes only.

Package: ghas_report.py
Version: 1.0.0
Date: 2023-04-XX

Author: Rupert Herbst <rhe8502(at)pm.me>
Project URL: https://github.com/rhe8502/ghas_report
License: Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
"""
# Copyright (c) 2023 Rupert Herbst
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

from cryptography.fernet import Fernet
from datetime import datetime
import argparse
import csv
import json
import requests
import os
import sys
import time

def api_error_response(response):
    """Generate error message from API response.

    Args:
        response (requests.Response): API response object.

    Returns:
        str: Error message.

    Examples:
        >>> response = requests.get('https://api.example.com')
        >>> api_error_response(response)
        'Error 404: Resource not found'
    """
    error_messages = {
        304: f"Error {response.status_code}: {response.json().get('message', 'Not modified')}" + (f", Errors: {response.json().get('errors', '')}" if response.json().get('errors') else ''),
        400: f"Error {response.status_code}: {response.json().get('message', 'Bad Request')}" + (f", Errors: {response.json().get('errors', '')}" if response.json().get('errors') else ''),
        403: f"Error {response.status_code}: {response.json().get('message', 'GitHub Advanced Security is not enabled for this repository')}" + (f", Errors: {response.json().get('errors', '')}" if response.json().get('errors') else ''),
        404: f"Error {response.status_code}: {response.json().get('message', 'Resource not found')}" + (f", Errors: {response.json().get('errors', '')}" if response.json().get('errors') else ''),
        422: f"Error {response.status_code}: {response.json().get('message', 'Validation failed, or the endpoint has been spammed')}" + (f", Errors: {response.json().get('errors', '')}" if response.json().get('errors') else ''),
        503: f"Error {response.status_code}: {response.json().get('message', 'Service unavailable')}" + (f", Errors: {response.json().get('errors', '')}" if response.json().get('errors') else '')
    }
    
    if response.status_code in error_messages:
        error_message = error_messages[response.status_code]
        raise Exception(error_message)
    else:
        raise Exception(f"Error {response.status_code}: {response.json().get('message', '')}" + (f", Errors: {response.json().get('errors', '')}" if response.json().get('errors') else ''))

def get_code_scanning_alerts(api_url, org_name=None, owner=None, repo_name=None, state=None):
    """Fetches the code scanning alerts for a given GitHub organization or repository and optionally filters them by state.

    Args:
        api_url (str): The base API URL for the GitHub instance.
        org_name (str, optional): The GitHub organization name. Should be provided if repo_name is not specified.
        owner (str, optional): The GitHub username of the repository owner. Required if repo_name is provided.
        repo_name (str, optional): The GitHub repository name. Should be provided if org_name is not specified.
        state (str, optional): The state of the alerts to fetch. Can be "open" or None. If None, returns all alerts.

    Returns:
        tuple: A tuple containing a list of code scanning alerts and the count of open alerts.
            If the API call fails, it will print an error message generated by the `api_error_response` function.
    """
    base_url = f"{api_url}/repos/{owner}/{repo_name}" if repo_name else f"{api_url}/orgs/{org_name}"
    state_query = '?state=open' if state == 'open' else ''
    url = f"{base_url}/code-scanning/alerts{state_query}"
        
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        code_scanning_alerts = response.json()
        code_scanning_alert_count = sum(1 for alert in code_scanning_alerts if alert['state'] == 'open')
        return code_scanning_alerts, code_scanning_alert_count
    else:
        print(api_error_response(response))

def get_secret_scanning_alerts(api_url, org_name=None, owner=None, repo_name=None, state=None):
    """Fetches the secret scanning alerts for a given GitHub organization or repository and optionally filters them by state.
    
    Args:
        api_url (str): The base API URL for the GitHub instance.
        org_name (str, optional): The GitHub organization name. Should be provided if repo_name is not specified.
        owner (str, optional): The GitHub username of the repository owner. Required if repo_name is provided.
        repo_name (str, optional): The GitHub repository name. Should be provided if org_name is not specified.
        state (str, optional): The state of the alerts to fetch. Can be "open" or None. If None, returns all alerts.
    
    Returns:
        tuple: A tuple containing a list of secret scanning alerts and the count of open alerts.
               If the API call fails, it will print an error message generated by the `api_error_response` function.
    """
    base_url = f"{api_url}/repos/{owner}/{repo_name}" if repo_name else f"{api_url}/orgs/{org_name}"
    state_query = '?state=open' if state == 'open' else ''
    url = f"{base_url}/secret-scanning/alerts{state_query}"
    
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        secret_scanning_alerts = response.json()
        secret_scanning_alert_count = sum(1 for alert in secret_scanning_alerts if alert['state'] == 'open')
        return secret_scanning_alerts, secret_scanning_alert_count
    else:
        print(api_error_response(response))
 
def get_dependabot_alerts(api_url, org_name=None, owner=None, repo_name=None, state=None):
    """Fetches the Dependabot alerts for a given GitHub organization or repository and optionally filters them by state.

    Args:
        api_url (str): The base API URL for the GitHub instance.
        org_name (str, optional): The GitHub organization name. Should be provided if repo_name is not specified.
        owner (str, optional): The GitHub username of the repository owner. Required if repo_name is provided.
        repo_name (str, optional): The GitHub repository name. Should be provided if org_name is not specified.
        state (str, optional): The state of the alerts to fetch. Can be "open" or None. If None, returns all alerts.

    Returns:
        tuple: A tuple containing a list of Dependabot alerts and the count of open alerts.
            If the API call fails, it will print an error message generated by the `api_error_response` function.
    """
    base_url = f"{api_url}/repos/{owner}/{repo_name}" if repo_name else f"{api_url}/orgs/{org_name}"
    state_query = '?state=open' if state == 'open' else ''
    url = f"{base_url}/dependabot/alerts{state_query}"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        dependabot_alerts = response.json()
        dependabot_alert_count = sum(1 for alert in dependabot_alerts if alert['state'] == 'open')
        return dependabot_alerts, dependabot_alert_count
    else:
        print(api_error_response(response))

def write_alerts(alert_data, project_name, output_type=None, report_dir='', call_func=None):
    """Writes alert data to a file in the specified format (CSV or JSON) for a given project.

    Args:
        alert_data (dict): A dictionary containing the alert data to be written.
        project_name (str): The name of the project.
        output_type (str, optional): The output format for the file, either 'csv' or 'json'. Defaults to 'csv'.
        report_dir (str, optional): The path to the directory where the file should be written. Defaults to an empty string.
        call_func (str, optional): The type of alert data being written. Used to determine the column headers for CSV files.

    Raises:
        IOError: If there is an error writing to the file.
    """
    # Set output type to CSV is none defined
    output_type = output_type if output_type is not None else 'csv'
    
    # Check if a report path is defined and create the file path, otherwise create a folder for the current date and create the file path
    if report_dir:
        filepath = os.path.join(report_dir, f"{project_name}-{call_func}-{datetime.now():%Y%m%d%H%M%S}.{output_type}")
    else:
        filepath = os.path.join(report_dir, f"{datetime.now().strftime('%Y%m%d')}", f"{project_name}-{call_func}-{datetime.now():%Y%m%d%H%M%S}.{output_type}")
    
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
   
    # Set the column headers for the CSV file depending on the type of alert
    scan_options = {
        'alert_count': ['Organization', 'Repository', 'Code Scanning Alerts', 'Secret Scanning Alerts', 'Dependabot Alerts'],
        'code_scan': ['Alert', 'Organization', 'Repository', 'Date Created', 'Date Updated', 'Days Open', 'Severity', 'State', 'Rule ID', 'Description', 'Category', 'File', 'Fixed At', 'Dismissed At', 'Dismissed By', 'Dismissed Reason', 'Dismissed Comment', 'Tool', 'GitHub URL'],
        'secret_scan': ['Alert', 'Organization', 'Repository', 'Date Created', 'Date Updated', 'Days Open', 'State', 'Resolved At', 'Resolved By', 'Resolved Reason', 'Secret Type Name', 'Secret Type', 'GitHub URL'],
        'dependabot_scan': ['Alert', 'Organization', 'Repository', 'Date Created', 'Date Updated', 'Days Open', 'Severity', 'State', 'Package Name', 'CVE ID', 'Summary', 'Fixed At', 'Dismissed At', 'Dismissed By', 'Dismissed Reason', 'Dismissed Comment', 'Scope', 'Manifest ID', 'GitHub URL']
    }
    
    # Write the alert data to a file in the specified format
    try:
        with open(filepath, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f) if output_type == 'csv' else None
            header_row = scan_options.get(call_func, scan_options['code_scan']) if output_type == 'csv' else None

            if output_type == 'json':
                json.dump(alert_data['raw_alerts'], f, indent=4)
            elif output_type == 'csv':
                writer.writerow(header_row)
                writer.writerows(alert_data['scan_alerts'])
                print(f"Wrote {call_func} for \"{project_name}\" to {filepath}")
    except IOError as e:
        raise SystemExit(f"Error writing to {e.filename}: {e}")

def alert_count(api_url, project_data): # Candidate for refactoring
    """Collects alert count data for the specified GitHub organizations and repositories.

    Args:
        api_url (str): The base API URL for the GitHub instance.
        project_data (dict): A dictionary containing the organizations and repositories for which to fetch the alert count.

    Returns:
        dict: A dictionary containing the raw alert count data and the formatted alert count data.
            The keys are "raw_alerts" and "scan_alerts", both containing a list of lists with the alert count information.
    """
    alert_count = []
    for gh_entity in ['organizations', 'repositories']:
        for gh_name in project_data.get(gh_entity, []):
            if gh_name:
                try:
                    if gh_entity == 'organizations':
                        alert_count.append([gh_name, 'N/A', get_code_scanning_alerts(api_url, org_name=gh_name)[1], get_secret_scanning_alerts(api_url, org_name=gh_name)[1], get_dependabot_alerts(api_url, org_name=gh_name)[1]])
                    elif gh_entity == 'repositories':
                        owner = project_data.get('owner')
                        alert_count.append(['N/A', gh_name, get_code_scanning_alerts(api_url, owner=owner, repo_name=gh_name)[1], get_secret_scanning_alerts(api_url, owner=owner, repo_name=gh_name)[1], get_dependabot_alerts(api_url, owner=owner, repo_name=gh_name)[1]])
                except Exception as e:
                    print(f"Error getting alert count for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")
    return {'raw_alerts': alert_count, 'scan_alerts': alert_count}

def safe_get(alert, keys, default=''):
    """Safely retrieves the value from a nested dictionary using a list of keys.

    Args:
        alert (dict): The dictionary from which to retrieve the value.
        keys (list): A list of keys to traverse the dictionary.
        default (any, optional): The default value to return if any of the keys are not found. Defaults to an empty string.

    Returns:
        any: The value found in the dictionary using the provided keys, or the default value if any of the keys are not found.
    """
    result = alert
   
    for key in keys:
        if result:
            result = result.get(key)
        else:
            break
    return default if result is None else result

def scan_alerts(api_url, project_data, alert_type, output_type=None ,state=None):
    """Retrieve and process security alerts from GitHub for a list of organizations and/or repositories.

    Args:
        api_url (str): The base GitHub API URL.
        project_data (dict): A dictionary containing lists of organizations and/or repositories to retrieve alerts from.
        alert_type (str): The type of alert to retrieve (codescan, secretscan, or dependabot).
        output_type (str, optional): The output format for the results (json or csv). Defaults to None.
        state (str, optional): The state of the alerts to retrieve (open or closed). Defaults to None.

    Returns:
        dict: A dictionary containing raw alerts and processed alerts for the specified alert type.
    """
    raw_alerts = []
    scan_alerts = []

    # Get the alerts for the specified alert type
    alert_functions = {
        'codescan': get_code_scanning_alerts,
        'secretscan': get_secret_scanning_alerts,
        'dependabot': get_dependabot_alerts,
    }

    # Iterate through each organization and repository and get the alerts
    for gh_entity in ['organizations', 'repositories']:
        for gh_name in project_data.get(gh_entity, []):
            if gh_name:
                try:
                    owner = project_data.get('owner') if gh_entity == 'repositories' else None
                    alerts = alert_functions[alert_type](api_url, owner=owner, org_name=gh_name, state=state if gh_entity == 'organizations' else None, repo_name=gh_name if gh_entity == 'repositories' else None)[0]

                    # If the output type is json return the raw alerts and ignore the rest of the function
                    if output_type == 'json':
                        raw_alerts = alerts
                        return({'raw_alerts': raw_alerts})

                    # Process alerts for each organization and repository and add them to a list
                    for alert in alerts:
                        # Get the days open since the alert was created
                        days_since_created = (datetime.now() - datetime.strptime(safe_get(alert, ['created_at']), '%Y-%m-%dT%H:%M:%SZ')).days if safe_get(alert, ['created_at']) != '' else ''
                        
                        # Add default values for all alert types to the list
                        alert_data = [
                            safe_get(alert, ['number']),
                            gh_name if gh_entity == 'organizations' else safe_get(alert, ['organization', 'name'], ''),
                            gh_name if gh_entity == 'repositories' else safe_get(alert, ['repository', 'name'], ''),
                            datetime.strptime(safe_get(alert, ['created_at']), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d') if safe_get(alert, ['created_at']) != '' else '',
                            datetime.strptime(safe_get(alert, ['updated_at']), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d') if safe_get(alert, ['updated_at']) != '' else '',
                            days_since_created if safe_get(alert, ['state']) == 'open' else '0'
                        ]

                        # Add Code Scanning alert data to the list
                        if alert_type == 'codescan':
                            alert_data.extend([
                                safe_get(alert, ['rule', 'security_severity_level'], ''),
                                safe_get(alert, ['state'], ''),
                                safe_get(alert, ['rule', 'id'], ''),
                                safe_get(alert, ['most_recent_instance', 'message', 'text'], ''),
                                safe_get(alert, ['most_recent_instance', 'category'], ''),
                                safe_get(alert, ['most_recent_instance', 'location', 'path'], ''),
                                datetime.strptime(safe_get(alert, ['fixed_at']), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d') if safe_get(alert, ['fixed_at']) != '' else '',
                                datetime.strptime(safe_get(alert, ['dismissed_at']), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d') if safe_get(alert, ['dismissed_at']) != '' else '',                               
                                safe_get(alert, ['dismissed_by', 'login'], ''),
                                safe_get(alert, ['dismissed_reason'], ''),
                                safe_get(alert, ['dismissed_comment'], ''),
                                safe_get(alert, ['tool', 'name'], '') + ' ' + safe_get(alert, ['tool', 'version'], ''),
                                safe_get(alert, ['html_url'], '')
                            ])
                                
                        # Add Secret Scanning alert data to the list
                        elif alert_type == 'secretscan':
                            alert_data.extend([
                                safe_get(alert, ['state'], ''),
                                datetime.strptime(safe_get(alert, ['resolved_at']), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d') if safe_get(alert, ['resolved_at']) != '' else '',
                                safe_get(alert, ['resolved_by', 'login'], ''),
                                safe_get(alert, ['resolution'], ''),
                                safe_get(alert, ['secret_type_display_name'], ''),
                                safe_get(alert, ['secret_type'], ''),
                                safe_get(alert, ['html_url'], '')
                            ])
                
                        # Add Dependabot alert data to the list
                        elif alert_type == 'dependabot':
                            alert_data.extend([
                                safe_get(alert, ['security_advisory', 'severity'], ''),
                                safe_get(alert, ['state'], ''),
                                safe_get(alert, ['dependency', 'package', 'name'], ''),
                                safe_get(alert, ['security_advisory', 'cve_id'], ''),
                                safe_get(alert, ['security_advisory', 'summary'], ''),
                                datetime.strptime(safe_get(alert, ['fixed_at']), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d') if safe_get(alert, ['fixed_at']) != '' else '',
                                datetime.strptime(safe_get(alert, ['dismissed_at']), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d') if safe_get(alert, ['dismissed_at']) != '' else '',
                                safe_get(alert, ['dismissed_by', 'login'], ''),
                                safe_get(alert, ['dismissed_reason'], ''),
                                safe_get(alert, ['dismissed_comment'], ''),
                                safe_get(alert, ['dependency', 'scope'], ''),
                                safe_get(alert, ['dependency', 'manifest_path'], ''),
                                safe_get(alert, ['html_url'], '')
                            ])
                        scan_alerts.append(alert_data)
                except Exception as e:
                    print(f"Error getting {alert_type} alerts for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")
    return {'raw_alerts': raw_alerts, 'scan_alerts': scan_alerts}

def load_configuration(args):
    """Loads configuration from a JSON file, decrypts the API key if,
    and returns the configuration as a dictionary and headers for API requests.

    :param args: Command-line arguments parsed by argparse.
    :type args: argparse.Namespace
    :return: A tuple containing the configuration dictionary and headers.
    :rtype: Tuple[Dict[str, Any], Dict[str, str]]

    The function reads the configuration from the 'ghas_config.json' file in the
    current directory or the directory specified by the '--config' command-line
    option. If the file is not found or cannot be parsed as JSON, the function
    raises a 'SystemExit' exception with an error message.

    The function decrypts the API key using the key stored in the '.ghas_env'
    file in the current directory or the directory specified by the '--keyfile'
    command-line option, or the path specified in the configuration file, if any.
    If the file is not found, the function raises a 'SystemExit' exception with
    an error message.

    The function returns the configuration as a dictionary and headers for
    API requests to GitHub. The headers include the API key, as well as the
    API version number ('2022-11-28').

    Example usage:

    >>> import argparse
    >>> args = argparse.Namespace()
    >>> config, headers = load_configuration(args)
    """

    # Configuration file name and encryption key file name
    conf_file_name = 'ghas_config.json'
    env_file_name = '.ghas_env'

    # Determine script location and check if a commandline argument was passed for the config file, and if so, use that instead of the default
    script_dir = os.path.dirname(os.path.abspath(__file__))
    conf_file = os.path.join(args.config, conf_file_name) if args.config else os.path.join(script_dir, conf_file_name)
   
    try:
        with open(conf_file) as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise SystemExit(f"Error loading {conf_file}: {e}\nYou might need to run the \"ghas_enc_key.py\" script first to generate a new \"{conf_file}\" file.")

    # Get API URL and API key from config    
    api_key = config.get('connection', {}).get('gh_api_key','')
    enc_path = config.get('location', {}).get('keyfile','')
 
    #Check if a commandline argument was passed for the keyfile, if not, check if the keyfile path was specified in the config file, and if not, use the default
    if args.keyfile:
        env_file = os.path.join(args.keyfile, env_file_name)
    elif enc_path:
        env_file = os.path.join(enc_path, env_file_name)
    else:
        env_file = os.path.join(script_dir, env_file_name)
    
    if not api_key:
        raise SystemExit(f"Error: No API key found in \"{conf_file}\". Please run the \"ghas_enc_key.py\" script to add your API key.")

    try:
        with open(env_file, 'rb') as f:
            f_key = f.read()
    except FileNotFoundError as e:
        raise SystemExit(f"Error loading {e.filename}: {e}\nYou might need to run the \"ghas_enc_key.py\" script first to generate a new \"{e.filename}\" file.")
    
    try:
        fernet = Fernet(f_key)
        api_key = fernet.decrypt(api_key.encode()).decode()
        config['connection']['gh_api_key'] = api_key
    except Exception :
        raise SystemExit(f"Error: Invalid key, your API key might be corrupted. Please run the \"ghas_enc_key.py\" script to encrypt the API key.") 

    # Define headers for API requests to GitHub
    headers = {
        "Authorization": f"token {api_key}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    return config, headers

def setup_argparse():
    """Creates and returns an ArgumentParser object for the GitHub Advanced Security (GHAS) reporting tool.

    The ArgumentParser is configured with arguments for generating different types of alert reports, output formats, and file locations.

    Returns:
        argparse.ArgumentParser: The configured ArgumentParser object.
    """
    # version, date, and author information
    version_number = '1.0.0'
    release_date = '2023-04-XX'
    url = 'https://github.com/rhe8502/ghas_report'
    
    # version string
    version_string = f"GHAS Reporting Tool v{version_number} ({url})\nRelease Date: {release_date}\n"

    # Command-line arguments parser
    parser = argparse.ArgumentParser(description='''The script is designed to retrieve various types of GitHub Advanced Security (GHAS) alerts for a specified organization or repository. GHAS alerts can include code scanning alerts, secret scanning alerts, and Dependabot alerts.
                                                    \nIt will generate a report based on the specified options and write the results to a file. The output format of the report can also be specified using command-line options. The supported formats are CSV and JSON. By default, the output is written to a CSV file. If the -oA option is specified, then the report will be written to all supported formats.''', formatter_class=argparse.RawTextHelpFormatter)

    #Options group
    parser.add_argument('-v', '--version', action='version', version=(version_string), help="show program's version number and exit")

    # Alert reports
    alert_group = parser.add_argument_group('Generate alert reports')
    alert_group.add_argument('-A', '--all', action='store_true', help='generate Alert Count, Code Scanning, Secret Scanning, and Dependabot alert reports')
    alert_group.add_argument('-a', '--alerts', action='store_true', help='generate Alert Count report of all open alerts')
    alert_group.add_argument('-c', '--codescan', action='store_true', help='generate Code Scan alert report')
    alert_group.add_argument('-s', '--secretscan', action='store_true', help='generate Secret Scanning alert report')
    alert_group.add_argument('-d', '--dependabot', action='store_true', help='generate Dependabot alert report')

    # Optional alert reports arguments
    alert_options_group = parser.add_argument_group('Optional alert report arguments')
    alert_options_group.add_argument('-o', '--open', action='store_true', help='only generate reports for open alerts (Alert Count only reports open alerts)')

    # Output file format arguments
    output_group = parser.add_argument_group('Output file format arguments')
    output_group.add_argument('-wA', '--output-all', action='store_true', help='write output to all formats at once')
    output_group.add_argument('-wC', '--output-csv', action='store_true', help='write output to a CSV file (default format)')
    output_group.add_argument('-wJ', '--output-json', action='store_true', help='write output to a JSON file')

    # Optional location arguments
    location_options_group = parser.add_argument_group('Optional location arguments')
    location_options_group.add_argument('-lc', '--config', metavar='<PATH>', type=str, help='specify file location for the configuration file ("ghas_conf.json")')
    location_options_group.add_argument('-lk', '--keyfile', metavar='<PATH>', type=str, help='specify file location for the encryption key file (".ghas_env") - overrides the location specified in the configuration file')
    location_options_group.add_argument('-lr', '--reports', metavar='<PATH>', type=str, help='specify file location for the reports directory - overrides the location specified in the configuration file')

    return parser

def process_args(parser):
    """Processes the command-line arguments, checks for errors, and extracts alert types, output types, and alert state.

    Args:
        parser (argparse.ArgumentParser): The configured ArgumentParser object.

    Returns:
        tuple: A tuple containing the following elements:
            - args (argparse.Namespace): The parsed command-line arguments.
            - alert_types (list): The selected alert types to process.
            - output_types (list): The chosen output formats for the report.
            - alert_state (str): The alert state, 'open' if the --open flag is present, otherwise an empty string.

    Raises:
        SystemExit: If no arguments are specified or if --output-all is used with --output-csv or --output-json.
    """
    args = parser.parse_args()

    # Check for errors in the arguments passed and print the help menu if an error is found
    if len(sys.argv) == 1:
        parser.print_help()
        raise SystemExit('\nError: No arguments specified. Please specify at least one alert type.\n')
    elif args.output_all and (args.output_csv or args.output_json):
        parser.print_help()
        raise SystemExit('\nError: --output-all cannot be used together with --output-csv or --output-json\n')
   
    # Define the list of alert types to process. If the -A flag is present, include all alert types. Otherwise, include only the alert types that were passed as arguments
    alert_types = ['alerts', 'codescan', 'secretscan', 'dependabot'] if args.all else [alert_type for alert_type in ['alerts', 'codescan', 'secretscan', 'dependabot'] if getattr(args, alert_type)]
    
    # Define the list of output types to process. If the -wA flag is present, include all output types. Otherwise, include only the output types that were passed as arguments, if no output types are specified, default to CSV
    output_types = ['csv', 'json'] if args.output_all else [output_type for output_type in ['csv', 'json'] if getattr(args, f'output_{output_type}')] or ['csv']

    # Set state to 'open' if the -o ,or --open flag is present
    alert_state = 'open' if args.open else ''

    return args, alert_types, output_types, alert_state

def main():
    # The following line is intended for debugging purposes only - do not uncomment 
    # start_time = time.perf_counter()
    
    parser = setup_argparse()
    args, alert_types, output_types, alert_state = process_args(parser)

    # Call the load_configuration function to load the configuration file and assign the returned values to the config and headers variables 
    global headers # Not too happy about this, but it's the only way I could get the headers variable to be accessible throughout the script
    config, headers = load_configuration(args)
    api_url = config.get('connection', {}).get('gh_api_url', '')
    report_dir = args.reports or config.get('location', {}).get('reports', '')
  
    # Process each project for the selected alert types
    for project_name, project_data in config.get('projects', {}).items():
        for alert_type in alert_types:
            for output_type in output_types:
                {
                    'alerts': lambda: write_alerts(alert_count(api_url, project_data), project_name, output_type, report_dir, call_func='alert_count'),
                    'codescan': lambda output_type=output_type: write_alerts(scan_alerts(api_url, project_data, 'codescan', output_type, alert_state), project_name, output_type, report_dir, call_func='code_scan'),
                    'secretscan': lambda output_type=output_type: write_alerts(scan_alerts(api_url, project_data, 'secretscan', output_type, alert_state), project_name, output_type, report_dir, call_func='secret_scan'),
                    'dependabot': lambda output_type=output_type: write_alerts(scan_alerts(api_url, project_data, 'dependabot', output_type, alert_state), project_name, output_type, report_dir, call_func='dependabot_scan'),
                }[alert_type]()
    
    # The following code is intended for debugging purposes only - do not uncomment
    # end_time = time.perf_counter()
    # elapsed_time = end_time - start_time
    # print(f"\nExecution time: {elapsed_time:.2f} seconds\n")

if __name__ == '__main__':
    main()