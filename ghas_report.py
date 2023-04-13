#!/usr/bin/env python3
#-*- coding: utf-8 -*-

"""GHAS Reporting Tool

This script retrieves various types of GitHub Advanced Security (GHAS) alerts for a specified
organization or repository. The types of alerts include Code scanning alerts, Secret scanning
alerts, and Dependabot alerts. The script generates reports based on the specified options and
writes the results to a file in CSV, JSON, or both formats.

The script uses the GitHub API to retrieve alert data and requires valid API credentials. 
An API key can be specified added using the "ghas_enc_key.py" script, or alternatively
specified in the GH_API_KEY environment variable.

Usage:
    python ghas_reporting_tool.py [options]

Options:
    -v, --version          Show program's version number and exit
    
    Alert reports:
    -a, --all              Generate all alert reports
    -l, --alerts           Generate Alert Count report of all open alerts
    -c, --codescan         Generate Code Scan alert report
    -s, --secretscan       Generate Secret Scanning alert report
    -d, --dependabot       Generate Dependabot alert report
    
    Optional alert report arguments:
    -o, --open             Generate report(s) for open alerts only
    -n, --owner            Specify the owner of a GitHub repository, or organization
    -r, --repo             Specify the name of a GitHub repository
    -g, --org              Specify the name of a GitHub organization
   
    Output file format arguments:
    -wA, --output-all      Write output to all formats at once
    -wC, --output-csv      Write output to a CSV file (default format)
    -wJ, --output-json     Write output to a JSON file
    
    Optional location arguments:
    -lc, --config          Specify file location for the configuration file
    -lk, --keyfile         Specify file location for the encryption key file
    -lr, --reports         Specify file location for the reports directory

Requirements:
    - Python 3.6 or later
    - requests
    - argparse
    - cryptography

Package: ghas_report.py
Version: 1.1.0
Date: 2023-04-13

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
import re

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

def get_scan_alerts(api_url, org_name=None, call_func=None, owner=None, repo_name=None, state=None):
    """Retrieve alerts for a specific scan type from the GitHub API and count the open alerts and their corresponding severity levels.

    Args:
        api_url (str): The base URL for the GitHub API.
        org_name (str, optional): The name of the organization to retrieve alerts for.
        call_func (str, optional): The type of scan alerts to retrieve ('codescan', 'secretscan', 'dependabot').
        owner (str, optional): The name of the repository owner.
        repo_name (str, optional): The name of the repository to retrieve alerts for.
        state (str, optional): The state of the alerts to retrieve ('open', 'closed', or None for all).

    Returns:
        tuple: A tuple containing a list of scan_alerts and a list of severity counts (sev_list).

    Nested Functions:
        alerts_count(alerts, sev_counts)
        get_next_page_link(link_header)
    """

    scan_types = {
        'codescan': 'code-scanning',
        'secretscan': 'secret-scanning',
        'dependabot': 'dependabot'
    }

    base_url = f"{api_url}/repos/{owner}/{repo_name}/{scan_types[call_func]}/alerts" if repo_name else f"{api_url}/orgs/{org_name}/{scan_types[call_func]}/alerts"
    state_query = '&state=open' if state == 'open' else ''

    scan_alerts = []
    open_alert_count = 0
    sev_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'warning': 0,
        'note': 0,
        'error': 0
    }

    def alerts_count(alerts, sev_counts):
        """Counts the open alerts and their corresponding severity levels for the given list of alerts.

        Args:
            alerts (list): A list of alert dictionaries.
            sev_counts (dict): A dictionary to store the counts for each severity level.

        Returns:
            None
        """

        nonlocal open_alert_count
        for alert in alerts:
            if alert['state'] == 'open':
                open_alert_count += 1
                sev = None

                if call_func == 'codescan':
                    sev = alert.get('rule', {}).get('security_severity_level') or alert.get('rule', {}).get('severity', '').lower()
                elif call_func == 'dependabot':
                    sev = alert['security_advisory']['severity'].lower() if 'severity' in alert['security_advisory'] else None

                if sev and sev in sev_counts:
                    sev_counts[sev] += 1

    def get_next_page_link(link_header):
        """Extracts the next page URL from the 'Link' header in a paginated API response.

        Args:
            link_header (str): The 'Link' header value from an API response.

        Returns:
            str: The URL of the next page, or None if not found.
        """

        if link_header:
            next_page_link = re.search(r'<(.+?)>; rel="next"', link_header)
            return next_page_link.group(1) if next_page_link else None
        return None

    if call_func == 'codescan':
        page_no = 1

        while True:
            url = f"{base_url}?page={page_no}{state_query}"
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                alerts = response.json()

                if not alerts:
                    break

                alerts_count(alerts, sev_counts)
                scan_alerts.extend(alerts)
                page_no += 1
            else:
                print(api_error_response(response))
                break

    elif call_func in ['secretscan', 'dependabot']:
        url = f"{base_url}?per_page=100{state_query}"

        while url:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                alerts = response.json()

                if not alerts:
                    break

                alerts_count(alerts, sev_counts)
                scan_alerts.extend(alerts)

                # Get the next page URL from the 'Link' header if present
                link_header = response.headers.get('Link')
                url = get_next_page_link(link_header)
            else:
                print(api_error_response(response))
                break

    sev_list = [val for val in sev_counts.values()]
    sev_list.insert(0, open_alert_count)

    return scan_alerts, sev_list

def process_alerts_count(api_url, project_data):
    """Processes and retrieves the alert count for each scan type (Code Scan, Secret Scan, Dependabot Scan)
       for the specified organizations and repositories.

    Description:
        The function iterates through the organizations and repositories provided in the project_data dictionary and retrieves the alert count
        for each scan type (Code Scan, Secret Scan, Dependabot Scan). It then appends the alert count for each organization or repository along
        with the corresponding scan type to a list.

    Args:
        api_url (str): The API URL to retrieve scan data.
        project_data (dict): A dictionary containing project data, including organizations, repositories, and owner (if repositories are specified).

    Returns:
        dict: A dictionary containing the raw alert count data and the processed alert count data as lists.
    """

    alert_count = []

    scan_types = {
        'Code Scan': 'codescan',
        'Secret Scan': 'secretscan',
        'Dependabot Scan': 'dependabot'
    }

    for gh_entity in ['organizations', 'repositories']:
        for gh_name in project_data.get(gh_entity, []):
            if gh_name:
                try:
                    for scan_label, call_func in scan_types.items():
                        if gh_entity == 'organizations':
                            sev_list = get_scan_alerts(api_url, org_name=gh_name, call_func=call_func)[1]
                        elif gh_entity == 'repositories':
                            owner = project_data.get('owner')
                            sev_list = get_scan_alerts(api_url, owner=owner, repo_name=gh_name, call_func=call_func)[1]

                        row = [gh_name if gh_entity == 'organizations' else '', gh_name if gh_entity == 'repositories' else '', scan_label, *sev_list]
                        alert_count.append(row)
                except Exception as e:
                    print(f"Error getting alert count for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")

    return {'raw_alerts': alert_count, 'scan_alerts': alert_count}

def write_alerts(alert_data, project_name, output_type=None, report_dir='', call_func=None):
    """Writes the processed scan alert data to a file in the specified format (CSV or JSON).

    Description:
        The function writes the processed scan alert data to a file in the specified output format (CSV or JSON). It sets the column headers for the CSV file depending on the type of alert. If the output type is not specified, it defaults to 'csv'. The function creates a file path based on the report directory, project name, alert type, and the current date and time.

    Args:
        alert_data (dict): A dictionary containing processed alert data.
        project_name (str): The name of the project.
        output_type (str, optional): The output format for the alert data file; either 'csv' or 'json'. Defaults to 'csv'.
        report_dir (str, optional): The directory where the report file should be saved. Defaults to an empty string, which means the file will be saved in a folder named after the current date.
        call_func (str, optional): The function to be called for processing alerts; either 'codescan', 'secretscan', or 'dependabot'. Defaults to None.

    Raises:
        SystemExit: If there's an error writing to the file.
    """

    # Set output type to CSV is none defined
    # output_type = output_type if output_type is not None else 'csv'
    output_type = 'csv' if output_type is None else output_type
    
    # Check if a report path is defined and create the file path, otherwise create a folder for the current date and create the file path
    if report_dir:
        filepath = os.path.join(report_dir, f"{project_name}-{call_func}-{datetime.now():%Y%m%d%H%M%S}.{output_type}")
    else:
        filepath = os.path.join(report_dir, f"{datetime.now().strftime('%Y%m%d')}", f"{project_name}-{call_func}-{datetime.now():%Y%m%d%H%M%S}.{output_type}")

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
   
    # Set the column headers for the CSV file depending on the type of alert
    scan_options = {
        'alert_count': ['Organization', 'Repository', 'Scan Type', 'Total Alerts', 'Critical', 'High', 'Medium', 'Low', 'Warning', 'Note', 'Error'],
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
                print(f"Wrote {call_func} for \"{project_name}\" to {filepath}")
            elif output_type == 'csv':
                writer.writerow(header_row)
                writer.writerows(alert_data['scan_alerts'])
                print(f"Wrote {call_func} for \"{project_name}\" to {filepath}")
    except IOError as e:
        raise SystemExit(f"Error writing to {e.filename}: {e}")

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

def process_scan_alerts(api_url, project_data, call_func, output_type=None ,state=None):
    """Retrieves and processes scan alerts from GitHub organizations and repositories.

    Description:
        The function iterates through each organization and repository, retrieves the corresponding scan alerts, processes them, and adds the processed alerts
        to a list. If output_type is set to 'json', the function returns raw alerts and skips further processing. The alerts are processed depending on the
        call_func parameter, which can be 'codescan', 'secretscan', or 'dependabot'. The function returns a dictionary containing the raw alerts and the processed
        scan alerts.

    Args:
        api_url (str): The base API URL for GitHub.
        project_data (dict): A dictionary containing project information such as owner, organizations, and repositories.
        call_func (str): The function to be called for processing alerts; either 'codescan', 'secretscan', or 'dependabot'.
        output_type (str, optional): The output type for raw alerts, defaults to None. If 'json', the function returns raw alerts and skips further processing.
        state (str, optional): Filter alerts based on their state, defaults to None.

    Returns:
        dict: A dictionary containing raw_alerts and processed scan_alerts.
    """

    raw_alerts = []
    scan_alerts = []

    # Iterate through each organization and repository and get the alerts
    for gh_entity in ['organizations', 'repositories']:
        for gh_name in project_data.get(gh_entity, []):
            if gh_name:
                try:
                    owner = project_data.get('owner') if gh_entity == 'repositories' else None
                    alerts = get_scan_alerts(api_url, owner=owner, org_name=gh_name, call_func=call_func, state=state, repo_name=gh_name if gh_entity == 'repositories' else None)[0]

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
                        if call_func == 'codescan':
                            alert_data.extend([
                                # safe_get(alert, ['rule', 'security_severity_level'], ''),
                                safe_get(alert, ['rule', 'security_severity_level']) or safe_get(alert, ['rule', 'severity'], ''),
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
                        elif call_func == 'secretscan':
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
                        elif call_func == 'dependabot':
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
                    print(f"Error getting {call_func} alerts for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")
    
    return {'raw_alerts': raw_alerts, 'scan_alerts': scan_alerts}

def load_configuration(args):
    """Load the configuration and API key for making requests to the GitHub API.

    This function reads a configuration file and API key from the file system, optionally using
    command-line arguments to specify the file paths, and returns the parsed configuration and
    headers for API requests. If the API key is encrypted, it will be decrypted using the
    encryption key from the specified keyfile. If any required files are missing or the API key
    is corrupted, an error message will be displayed and the script will exit.

    Args:
    args (argparse.Namespace): The command-line arguments passed to the script.

    Returns:
    tuple: A tuple containing the loaded configuration (as a dictionary) and headers
    (as a dictionary) for making requests to the GitHub API.

    Raises:
    SystemExit: If the configuration file, keyfile, or API key is not found or if the
    API key is corrupted.
    """

    # Configuration file name and encryption key file name
    conf_file_name = 'ghas_config.json'
    env_file_name = '.ghas_env'
    config = {}

    # Determine script location and check if a commandline argument was passed for the config file, and if so, use that instead of the default
    script_dir = os.path.dirname(os.path.abspath(__file__))
    conf_file = os.path.join(args.config, conf_file_name) if args.config else os.path.join(script_dir, conf_file_name)

    # Get API key from environment variable
    api_key = os.environ.get("GH_API_KEY")

    # Load configuration file and get API key from it if not specified as an environment variable
    try:
        with open(conf_file) as f:
            config = json.load(f)
        if not api_key:
            api_key = config.get('connection', {}).get('gh_api_key', '')
    except FileNotFoundError as e:
        if not api_key:
            raise SystemExit(f"Error: No API key specified, or \"{conf_file}\" not found. Please run the \"ghas_enc_key.py\" script to add your API key.")
    except json.JSONDecodeError as e:
        raise SystemExit(f"Error loading {e.docname}: {e}\nYou might need to run the \"ghas_enc_key.py\" script to add your API key.")
    
    # if the API key is not specified as an environment variable, get the encryption key from the keyfile and decrypt the API key from the config file
    if not os.environ.get("GH_API_KEY"):
        enc_path = config.get('location', {}).get('keyfile','')

        # Check if a commandline argument was passed for the keyfile, if not, check if the keyfile path was specified in the config file, and if not, use the default
        if args.keyfile:
            env_file = os.path.join(args.keyfile, env_file_name)
        elif enc_path:
            env_file = os.path.join(enc_path, env_file_name)
        else:
            env_file = os.path.join(script_dir, env_file_name)  
        
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
        "X-GitHub-Api-Version": "2022-11-28" # API version number, see https://docs.github.com/en/rest/overview/api-versions
    }

    return config, headers

def setup_argparse():
    """Creates and returns an ArgumentParser object for the GitHub Advanced Security (GHAS) reporting tool.

    The ArgumentParser is configured with arguments for generating different types of alert reports, output formats, and file locations.

    Returns:
        argparse.ArgumentParser: The configured ArgumentParser object.
    """
    # version, date, and project URL
    version_number = '1.1.0'
    release_date = '2023-04-13'
    url = 'https://github.com/rhe8502/ghas_report'

    # version string
    version_string = f"GHAS Reporting Tool v{version_number} ({url})\nRelease Date: {release_date}\n"
   
    # Command-line arguments parser
    parser = argparse.ArgumentParser(description='''The script is designed to retrieve various types of GitHub Advanced Security (GHAS) alerts for a specified organization or repository. GHAS alerts can include Code scanning alerts, Secret scanning alerts, and Dependabot alerts.
                                                    \nIt will generate a report based on the specified options and write the results to a file. The output format of the report can also be specified using command-line options. The supported formats are CSV and JSON. By default, the output is written to a CSV file. If the -wA option is specified, then the report will be written to all supported formats.''', formatter_class=argparse.RawTextHelpFormatter)

    # Options group
    parser.add_argument('-v', '--version', action='version', version=(version_string), help="show program's version number and exit")

    # Alert reports
    alert_group = parser.add_argument_group('Generate alert reports')
    alert_group.add_argument('-a', '--all', action='store_true', help='generate Alert Count, Code Scanning, Secret Scanning, and Dependabot alert reports')
    alert_group.add_argument('-l', '--alerts', action='store_true', help='generate Alert Count report of all open alerts')
    alert_group.add_argument('-c', '--codescan', action='store_true', help='generate Code Scan alert report')
    alert_group.add_argument('-s', '--secretscan', action='store_true', help='generate Secret Scanning alert report')
    alert_group.add_argument('-d', '--dependabot', action='store_true', help='generate Dependabot alert report')

    # Optional alert reports arguments
    alert_options_group = parser.add_argument_group('Optional alert report arguments')
    alert_options_group.add_argument('-o', '--open', action='store_true', help='generate report(s) for open alerts only (note: this has no effect on Alert Count report "-l)"')
    alert_options_group.add_argument('-n', '--owner', metavar='<owner>', type=str, help='specify the owner of a GitHub repository, or organization. required if the "--repo" or "--org" options are specified.')
    alert_options_group.add_argument('-r', '--repo', metavar='<repo>', type=str, help='specify the name of a GitHub repository. This option is mutually exclusive with the "--org" option. The "--owner" option is required if this option is specified.')
    alert_options_group.add_argument('-g', '--org', metavar='<org>', type=str, help='specify the name of a GitHub organization. This option is mutually exclusive with the "--repo" option. The "--owner" option is required if this option is specified.')
   
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

def check_args_errors(args, parser):
    """Check for errors in the command-line arguments and display appropriate error messages.

    This function checks the given command-line arguments for inconsistencies or errors, such as
    missing required arguments, conflicting arguments, or no arguments at all. If any issues are
    detected, the function will display an error message and the script will exit.

    Args:
        args (argparse.Namespace): The command-line arguments passed to the script.
        parser (argparse.ArgumentParser): The ArgumentParser object used for parsing the command-line arguments.

    Raises:
        SystemExit: If any errors or inconsistencies are detected in the command-line arguments.
    """

    if len(sys.argv) == 1:
        parser.print_help()
        raise SystemExit('\nError: No arguments specified. Please specify at least one alert type --all, --alerts, --codescan, --secretscan, or --dependabot.\n')
    elif not any([args.all, args.alerts, args.codescan, args.secretscan, args.dependabot]):
        parser.print_help()
        raise SystemExit('\nError: No alert type specified. Please specify at least one alert type --all, --alerts, --codescan, --secretscan, or --dependabot.\n')
    elif args.output_all and (args.output_csv or args.output_json):
        parser.print_help()
        raise SystemExit('\nError: --output-all cannot be used together with --output-csv or --output-json\n')
    elif args.repo and args.org:
        parser.print_help()
        raise SystemExit('\nError: --repo and --org cannot be used together.\n')
    elif args.repo and not args.owner:
        parser.print_help()
        raise SystemExit('\nError: --repo requires --owner to be specified.\n')
    elif args.org and not args.owner:
        parser.print_help()
        raise SystemExit('\nError: --org requires --owner to be specified.\n')
    elif args.owner and not (args.repo or args.org):
        parser.print_help()
        raise SystemExit('\nError: --owner requires --repo or --org to be specified.\n')

def process_args(parser):
    """Process the command-line arguments and execute the appropriate functions.

    This function parses the command-line arguments, checks for errors, and based on the provided
    arguments, calls the necessary functions to generate alert reports in the specified output
    formats. It also loads the configuration file and handles the processing of the alert types
    and output types.

    Args:
        parser (argparse.ArgumentParser): The ArgumentParser object used for parsing the command-line arguments.

    Raises:
        SystemExit: If any errors or inconsistencies are detected in the command-line arguments.
    """

    args = parser.parse_args()

    # Call the check_args_errors function with the arguments and parser
    check_args_errors(args, parser)

    # Define the list of alert types to process. If the -a flag is present, include all alert types. Otherwise, include only the alert types that were passed as arguments
    alert_types = ['alerts', 'codescan', 'secretscan', 'dependabot'] if args.all else [alert_type for alert_type in ['alerts', 'codescan', 'secretscan', 'dependabot'] if getattr(args, alert_type)]
    
    # Define the list of output types to process. If the -wA flag is present, include all output types. Otherwise, include only the output types that were passed as arguments, if no output types are specified, default to CSV
    output_types = ['csv', 'json'] if args.output_all else [output_type for output_type in ['csv', 'json'] if getattr(args, f'output_{output_type}')] or ['csv']

    # Set state to 'open' if the -o ,or --open flag is present
    alert_state = 'open' if args.open else ''

    # Call the load_configuration function to load the configuration file and assign the returned values to the config and headers variables 
    global headers # Not too happy about this, but it's the only way I could get the headers variable to be accessible throughout the script
    config, headers = load_configuration(args)
    api_url = config.get('connection', {}).get('gh_api_url', '') or "https://api.github.com"
    report_dir = args.reports or config.get('location', {}).get('reports', '')
    
    # Check if the org or repo arguments are present. If they are, set use_config to False. Otherwise, set use_config to True
    use_config = not (args.org or args.repo)

    projects = (
        {args.org or args.owner: {key: value for key, value in [('owner', args.owner), ('organizations', [args.org]), ('repositories', [args.repo])] if value}}
        if not use_config
        else config.get('projects', {})
    )

    # Three nested for loops to iterate through the projects, alert types, and output types
    for project_name, project_data in projects.items():
        for alert_type in alert_types:
            for output_type in output_types:
                {
                    'alerts': lambda: write_alerts(process_alerts_count(api_url, project_data), project_name, output_type, report_dir, call_func='alert_count'),
                    'codescan': lambda output_type=output_type: write_alerts(process_scan_alerts(api_url, project_data, 'codescan', output_type, alert_state), project_name, output_type, report_dir, call_func='code_scan'),
                    'secretscan': lambda output_type=output_type: write_alerts(process_scan_alerts(api_url, project_data, 'secretscan', output_type, alert_state), project_name, output_type, report_dir, call_func='secret_scan'),
                    'dependabot': lambda output_type=output_type: write_alerts(process_scan_alerts(api_url, project_data, 'dependabot', output_type, alert_state), project_name, output_type, report_dir, call_func='dependabot_scan'),
                }[alert_type]()

def execution_time(start_time):
    """Prints the script's execution time."""
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    min, sec = divmod(elapsed_time, 60)
    print(f"\nScript execution time: {elapsed_time:.2f} seconds\n") if elapsed_time < 60 else print(f"\nScript execution time: {int(min):02d}:{int(sec):02d} minutes\n")

def main():
    # Start the timer to measure the script's execution time
    start_time = time.perf_counter()

    # Call the setup_argparse function to configure the ArgumentParser object and assign the returned value to the parser variable, then call the process_args function to process the command-line arguments
    parser = setup_argparse()
    process_args(parser)
    
    # Call the execution_time function to print the script's execution time
    execution_time(start_time)

if __name__ == '__main__':
    main()