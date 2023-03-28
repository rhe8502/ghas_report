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
# Version: 1.0.0-beta
# Project URL: https://github.com/rhe8502/ghas_report/

"""
GitHub Advanced Security (GHAS) Vulnerability Report
"""

import argparse
import csv
import json
import requests
from datetime import datetime

# Handle API error responses
def api_error_response(response):
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

# Get Code Scanning alerts and alert count
def get_code_scanning_alerts(api_url, org_name=None, owner=None, repo_name=None):
    if repo_name:
        url = f"{api_url}/repos/{owner}/{repo_name}/code-scanning/alerts"
        #url = f"{api_url}/repos/{owner}/{repo_name}/code-scanning/alerts?state=open"
    elif org_name:
        #url = f"{api_url}/orgs/{org_name}/code-scanning/alerts?state=open"
        url = f"{api_url}/orgs/{org_name}/code-scanning/alerts"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        code_scanning_alerts = response.json()
        code_scanning_alert_count = len(code_scanning_alerts)
        return code_scanning_alerts, code_scanning_alert_count
    else:
        print(api_error_response(response))

# Get Secret Scanning alerts and alert count
def get_secret_scanning_alerts(api_url, org_name=None, owner=None, repo_name=None):
    if repo_name:       
        # url = f"{api_url}/repos/{owner}/{repo_name}/secret-scanning/alerts?state=open"
        url = f"{api_url}/repos/{owner}/{repo_name}/secret-scanning/alerts"
    elif org_name:
        # url = f"{api_url}/orgs/{org_name}/secret-scanning/alerts?state=open"
        url = f"{api_url}/orgs/{org_name}/secret-scanning/alerts"
    
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        secret_scanning_alerts = response.json()
        secret_scanning_alert_count = len(secret_scanning_alerts)
        return secret_scanning_alerts, secret_scanning_alert_count
    else:
        print(api_error_response(response))
 
# Get Dependabot alerts and alert count
def get_dependabot_alerts(api_url, org_name=None, owner=None, repo_name=None):
    if repo_name:
        # url = f"{api_url}/repos/{owner}/{repo_name}/dependabot/alerts?state=open"
        url = f"{api_url}/repos/{owner}/{repo_name}/dependabot/alerts"
    elif org_name:
        # url = f"{api_url}/orgs/{org_name}/dependabot/alerts?state=open"
        url = f"{api_url}/orgs/{org_name}/dependabot/alerts"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        dependabot_alerts = response.json()
        dependabot_alert_count = len(dependabot_alerts)  # get the total number of open Dependabot alerts
        return dependabot_alerts, dependabot_alert_count
    else:
        print(api_error_response(response))

# Write alerts to file
def write_alerts(alert_data, project_name, output_type=None, calling_function=None):    
    now = datetime.now()
    output_type = output_type if output_type is not None else 'csv'
    filename = f"{project_name}-{calling_function}-{now.strftime('%Y%m%d%H%M%S')}.{output_type}"

    # Set the column headers for the CSV file depending on the type of alert
    scan_options = {
        'alert_count': ['Organization', 'Repository', 'Code Scanning Alerts', 'Secret Scanning Alerts', 'Dependabot Alerts'],
        'code_scan': ['Alert', 'Organization', 'Repository', 'Date Created', 'Date Updated', 'Days Open', 'Severity', 'State', 'Fixed At', 'Rule ID', 'Description', 'Category', 'File', 'Dismissed At', 'Dismissed By', 'Dismissed Reason', 'Dismissed Comment', 'Tool', 'GitHub URL'],
        'secret_scan': ['Alert', 'Organization', 'Repository', 'Date Created', 'Date Updated', 'Days Open', 'State', 'Secret Type Name', 'Secret Type', 'GitHub URL'],
        'dependabot_scan': ['Alert', 'Organization', 'Repository', 'Date Created', 'Date Updated', 'Days Open', 'Severity', 'State', 'Fixed At', 'Package Name', 'CVE ID', 'Summary', 'Dismissed At', 'Dismissed By', 'Dismissed Reason', 'Dismissed Comment', 'Scope', 'Manifest ID', 'GitHub URL']
    }
    
    # Write the alert data to a file in the specified format
    try:
        with open(filename, 'w', encoding='utf-8', newline='') as f:
            if output_type == 'json':
                json.dump(alert_data["raw_alerts"], f, indent=4)
            elif output_type == 'csv':
                writer = csv.writer(f)
                header_row = scan_options.get(calling_function, scan_options['code_scan'])
                writer.writerow(header_row)
                for scan_alert in alert_data["scan_alerts"]:
                    writer.writerow(scan_alert)  
            print(f"Successfully wrote {calling_function} findings for project \"{project_name}\" to file {filename}")
    except IOError:
        print("Error: I/O error")
        exit(1)

# Process alert counts for each organization and repository and add them to a list (Candidate for refactoring)
def alert_count(api_url, project_data):
    alert_count = []
    for gh_entity in ['organizations', 'repositories']:
        for gh_name in project_data.get(gh_entity, []):
            if gh_name:
                try:
                    if gh_entity == 'organizations':
                        alert_count.append([gh_name, "N/A", get_code_scanning_alerts(api_url, org_name=gh_name)[1], get_secret_scanning_alerts(api_url, org_name=gh_name)[1], get_dependabot_alerts(api_url, org_name=gh_name)[1]])
                    elif gh_entity == 'repositories':
                        owner = project_data.get('owner')
                        alert_count.append(["N/A", gh_name, get_code_scanning_alerts(api_url, owner=owner, repo_name=gh_name)[1], get_secret_scanning_alerts(api_url, owner=owner, repo_name=gh_name)[1], get_dependabot_alerts(api_url, owner=owner, repo_name=gh_name)[1]])
                except Exception as e:
                    print(f"Error getting alert count for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")
    return {"raw_alerts": alert_count, "scan_alerts": alert_count}

# Helper function to avoid nonetype errors
def safe_get(alert, keys, default=""):
    result = alert
    for key in keys:
        if result:
            result = result.get(key)
        else:
            break
    return default if result is None else result

# Process alerts for each organization and repository
def scan_alerts(api_url, project_data, alert_type, output_type=None):
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
                    alerts = alert_functions[alert_type](api_url, owner=owner, org_name=gh_name if gh_entity == 'organizations' else None, repo_name=gh_name if gh_entity == 'repositories' else None)[0]

                    # If the output type is json just return the raw alerts and ignore the rest of the function
                    if output_type == 'json':
                        raw_alerts = alerts
                        return({"raw_alerts": raw_alerts})

                    # Process alerts for each organization and repository and add them to a list
                    for alert in alerts:
                        # Get the days open since the alert was created
                        days_since_created = (datetime.now() - datetime.strptime(safe_get(alert, ['created_at']), "%Y-%m-%dT%H:%M:%SZ")).days if safe_get(alert, ['created_at']) != "" else ""
                        
                        # Add default values for all alert types to the list
                        alert_data = [
                            safe_get(alert, ['number']),
                            gh_name if gh_entity == 'organizations' else safe_get(alert, ['organization', 'name'], ""),
                            gh_name if gh_entity == 'repositories' else safe_get(alert, ['repository', 'name'], ""),
                            datetime.strptime(safe_get(alert, ['created_at']), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d") if safe_get(alert, ['created_at']) != "" else "",
                            datetime.strptime(safe_get(alert, ['updated_at']), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d") if safe_get(alert, ['updated_at']) != "" else "",
                            days_since_created
                        ]

                        # Add Code Scanning alert data to the list
                        if alert_type == 'codescan':
                            alert_data.extend([
                                safe_get(alert, ['rule', 'security_severity_level'], ""),
                                safe_get(alert, ['state'], ""),
                                datetime.strptime(safe_get(alert, ['fixed_at']), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d") if safe_get(alert, ['fixed_at']) != "" else "",
                                safe_get(alert, ['rule', 'id'], ""),
                                safe_get(alert, ['most_recent_instance', 'message', 'text'], ""),
                                safe_get(alert, ['most_recent_instance', 'category'], ""),
                                safe_get(alert, ['most_recent_instance', 'location', 'path'], ""),
                                datetime.strptime(safe_get(alert, ['dismissed_at']), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d") if safe_get(alert, ['dismissed_at']) != "" else "",                               
                                safe_get(alert, ['dismissed_by', 'login'], ""),
                                safe_get(alert, ['dismissed_reason'], ""),
                                safe_get(alert, ['dismissed_comment'], ""),
                                safe_get(alert, ['tool', 'name'], "") + ' ' + safe_get(alert, ['tool', 'version'], ""),
                                safe_get(alert, ['html_url'], ""),
                            ])
                                
                        # Add Secret Scanning alert data to the list
                        elif alert_type == 'secretscan':
                            alert_data.extend([
                                safe_get(alert, ['state'], ""),
                                safe_get(alert, ['secret_type_display_name'], ""),
                                safe_get(alert, ['secret_type'], ""),
                                safe_get(alert, ['html_url'], "")
                            ])
                
                        # Add Dependabot alert data to the list
                        elif alert_type == 'dependabot':
                            alert_data.extend([
                                safe_get(alert, ['security_advisory', 'severity'], ""),
                                safe_get(alert, ['state'], ""),
                                datetime.strptime(safe_get(alert, ['fixed_at']), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d") if safe_get(alert, ['fixed_at']) != "" else "",
                                safe_get(alert, ['dependency', 'package', 'name'], ""),
                                safe_get(alert, ['security_advisory', 'cve_id'], ""),
                                safe_get(alert, ['security_advisory', 'summary'], ""),
                                datetime.strptime(safe_get(alert, ['dismissed_at']), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d") if safe_get(alert, ['dismissed_at']) != "" else "",
                                safe_get(alert, ['dismissed_by', 'login'], ""),
                                safe_get(alert, ['dismissed_reason'], " "),
                                safe_get(alert, ['dismissed_comment'], ""),
                                safe_get(alert, ['dependency', 'scope'], ""),
                                safe_get(alert, ['dependency', 'manifest_path'], ""),
                                safe_get(alert, ['html_url'], ""),
                            ])
                        scan_alerts.append(alert_data)
                except Exception as e:
                    print(f"Error getting {alert_type} alerts for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")
    return {"raw_alerts": raw_alerts, "scan_alerts": scan_alerts}

def main():
    # Load configuration from ghas_config.json file
    try:
        with open('ghas_config.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        print('Error: ghas_config.json file not found')
        exit(1)
    except json.JSONDecodeError:
        print('Error: ghas_config.json file is not valid JSON')
        exit(1)

    # Get API URL and API key from config    
    api_url = config.get('connection', {}).get('gh_api_url')
    api_key = config.get('connection', {}).get('gh_api_key')
    api_version = config.get('connection', {}).get('gh_api_version')
    
    # Define headers for API requests to GitHub as global variable
    global headers
    headers = {
        "Authorization": f"token {api_key}",
        "X-GitHub-Api-Version": f"{api_version}"
    }
    
    # version, date, and author information
    version_number = "1.0.0-beta"
    release_date = "2023-03-28"
    author = "Rupert Herbst <rhe8502(at)pm.me>"
    
    # version string
    version_string = f"GitHub Advanced Security Reporting (%(prog)s)\nVersion: {version_number}\nRelease date: {release_date}\nAuthor: {author}\n\n"

    # Command-line arguments parser
    parser = argparse.ArgumentParser(description='''
The script is designed to retrieve various types of GitHub Advanced Security (GHAS) alerts for a specified organization or repository. GHAS alerts can include code scanning alerts, secret scanning alerts, and Dependabot alerts.

It will generate a report based on the specified options and write the results to a file. The output format of the report can also be specified using command-line options. The supported formats are CSV and JSON. By default, the output is written to a CSV file. If the -oA option is specified, then the report will be written to all supported formats.
    ''', formatter_class=argparse.RawTextHelpFormatter)

    #Options group
    # parser.add_argument('-V', '--version', action='version', version='%(prog)s v1.0.0-beta', help='show program\'s version number and exit')
    parser.add_argument('-V', '--version', action='version', version=version_string, help="show program's version number and exit")

    # Alert reports
    alert_group = parser.add_argument_group('Generate alert reports')
    alert_group.add_argument('-A', '--all', action='store_true', help='generate Alert Count, Code Scanning, Secret Scanning, and Dependabot alert reports')
    alert_group.add_argument('-a', '--alerts', action='store_true', help='generate Alert Count report of all open alerts')
    alert_group.add_argument('-c', '--codescan', action='store_true', help='generate Code Scan alert report')
    alert_group.add_argument('-s', '--secretscan', action='store_true', help='generate Secret Scanning alert report')
    alert_group.add_argument('-d', '--dependabot', action='store_true', help='generate Dependabot alert report')

    # Output file format arguments
    output_group = parser.add_argument_group('Output file format arguments')
    output_group.add_argument('-wA', '--output-all', action='store_true', help='write output to all formats at once')
    output_group.add_argument('-wC', '--output-csv', action='store_true', help='write output to a CSV file (default format)')
    output_group.add_argument('-wJ', '--output-json', action='store_true', help='write output to a JSON file')
    
    # Parse the arguments
    args = parser.parse_args()

    # Define the list of alert types to process. If the -A flag is present, include all alert types. Otherwise, include only the alert types that were passed as arguments
    alert_types = ['alerts', 'codescan', 'secretscan', 'dependabot'] if args.all else [t for t in ['alerts', 'codescan', 'secretscan', 'dependabot'] if getattr(args, t)]
    
    # Define the list of output types to process. If the -wA flag is present, include all output types. Otherwise, include only the output types that were passed as arguments
    output_types = ['csv', 'json'] if args.output_all else [t for t in ['csv', 'json'] if getattr(args, f'output_{t}')]

    # Set CSV as the default output type if no output type is specified
    if not output_types:
        output_types = ['csv']
    
    # If no alert type is specified, print the help message, otherwise, process the alert types that were specified as arguments
    if not alert_types:
        print('\nError: No alert type specified.\n')
        parser.print_help()
    else:
        # Process each project for the selected alert types
        for project_name, project_data in config.get('projects', {}).items():
            for alert_type in alert_types:
                for output_type in output_types:
                    {
                        'alerts': lambda: write_alerts(alert_count(api_url, project_data), project_name, output_type, calling_function='alert_count'),
                        'codescan': lambda output_type=output_type: write_alerts(scan_alerts(api_url, project_data, 'codescan', output_type), project_name, output_type, calling_function='code_scan'),
                        'secretscan': lambda output_type=output_type: write_alerts(scan_alerts(api_url, project_data, 'secretscan', output_type), project_name, output_type, calling_function='secret_scan'),
                        'dependabot': lambda output_type=output_type: write_alerts(scan_alerts(api_url, project_data, 'dependabot', output_type), project_name, output_type, calling_function='dependabot_scan'),
                    }[alert_type]()
            
if __name__ == '__main__':
    main()