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
# Version: x.x.x
# Project URL: https://github.com/rhe8502/ghas_report/

"""
GitHub Advanced Security (GHAS) Vulnerability Report
"""

import requests
import csv
import json
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
        raise Exception(f"Errror {response.status_code}: {response.json().get('message', '')}" + (f", Errors: {response.json().get('errors', '')}" if response.json().get('errors') else ''))

# Get Code Scanning alerts and alert count
def get_code_scanning_alerts(api_url, org_name=None, owner=None, repo_name=None):
    if repo_name:
        url = f"{api_url}/repos/{owner}/{repo_name}/code-scanning/alerts?state=open"
    elif org_name:
        url = f"{api_url}/orgs/{org_name}/code-scanning/alerts?state=open"
   
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
        url = f"{api_url}/repos/{owner}/{repo_name}/secret-scanning/alerts?state=open"
    elif org_name:
        url = f"{api_url}/orgs/{org_name}/secret-scanning/alerts?state=open"
    
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
        url = f"{api_url}/repos/{owner}/{repo_name}/dependabot/alerts?state=open"
    elif org_name:
        url = f"{api_url}/orgs/{org_name}/dependabot/alerts?state=open"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        dependabot_alerts = response.json()
        dependabot_alert_count = len(dependabot_alerts)  # get the total number of open Dependabot alerts
        return dependabot_alerts, dependabot_alert_count
    else:
        print(api_error_response(response))

# Write alert count to a CSV file
def write_alert_count_csv(alert_count, project_name):
    now = datetime.now()
    filename = f"{project_name}-alert_count-{now.strftime('%Y%m%d%H%M%S')}.csv"

    # Write the header row
    alert_count.insert(0, ['Organization', "Repository", 'Code Scanning Alerts', 'Secret Scanning Alerts', 'Dependabot Alerts'])

    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for alerts in alert_count:
                writer.writerow(alerts)
            print(f"Successfully wrote alert count for project \"{project_name}\" to file {filename}")
    except IOError:
        print(f"Error writing alert count for project {project_name} to file {filename}")

# Write code scan findings to a CSV file
def write_codescan_alerts_csv(codescan_alerts, project_name):    
    now = datetime.now()
    filename = f"{project_name}-codescan_alerts-{now.strftime('%Y%m%d%H%M%S')}.csv"

    # Write the header row
    codescan_alerts.insert(0, ['Organization', 'Repository', 'Date Created', 'Date Updated', 'Severity', 'Rule ID', 'Description', 'File', 'Category', 'GitHub URL'])

    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for codeql_alert in codescan_alerts:
                writer.writerow(codeql_alert)
            print(f"Successfully wrote code scan findings for project \"{project_name}\" to file {filename}")
    except IOError:
        print("Error: I/O error")
        exit(1)

# Write secret scan findings to a CSV file
def write_secretscan_alerts_csv(secretscan_alerts, project_name):    
    now = datetime.now()
    filename = f"{project_name}-secretscan_alerts-{now.strftime('%Y%m%d%H%M%S')}.csv"

    # Write the header row
    secretscan_alerts.insert(0, ['Organization', 'Repository', 'Date Created', 'Date Updated', 'Secret Type Name', 'Secret Type', 'GitHub URL'])

    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for secretscan_alert in secretscan_alerts:
                writer.writerow(secretscan_alert)
            print(f"Successfully wrote secret scan findings for project \"{project_name}\" to file {filename}")
    except IOError:
        print("Error: I/O error")
        exit(1)

# Write DependaBot scan findings to a CSV file
def write_dependabot_alerts_csv(dependabot_alerts, project_name):    
    now = datetime.now()
    filename = f"{project_name}-dependabot_alerts-{now.strftime('%Y%m%d%H%M%S')}.csv"

    # Write the header row
    dependabot_alerts.insert(0, ['Organization', 'Repository', 'Date Created', 'Date Updated', 'Severity', 'Package Name', 'CVE ID', 'Summary', 'Scope', 'Manifest ID', 'GitHub URL'])

    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for dependabot_alert in dependabot_alerts:
                writer.writerow(dependabot_alert)
            print(f"Successfully wrote Dependabot scan findings for project \"{project_name}\" to file {filename}")
    except IOError:
        print("Error: I/O error")
        exit(1)

# Process alert counts for each organization and repository and add them to a list
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
    return alert_count


# Process code scan alerts for each organization and repository and add them to a list
def code_scanning_alerts(api_url, project_data):
    codescan_alerts = []

    for gh_entity in ['organizations', 'repositories']:
        for gh_name in project_data.get(gh_entity, []):
            if gh_name:
                try:
                    owner = project_data.get('owner') if gh_entity == 'repositories' else None
                    alerts = get_code_scanning_alerts(api_url, owner=owner, org_name=gh_name if gh_entity == 'organizations' else None, repo_name=gh_name if gh_entity == 'repositories' else None)[0]
                    for alert in alerts:
                        codescan_alerts.append([
                            gh_name if gh_entity == 'organizations' else alert.get('organization', {}).get('name', "N/A"),
                            gh_name if gh_entity == 'repositories' else alert.get('repository', {}).get('name', "N/A"),
                            datetime.strptime(alert.get('created_at', "N/A"), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                            datetime.strptime(alert.get('updated_at', "N/A"), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                            alert.get('rule', {}).get('security_severity_level', "N/A"),
                            alert.get('rule', {}).get('id', "N/A"),
                            alert.get('most_recent_instance', {}).get('message', {}).get('text', "N/A"),
                            alert.get('most_recent_instance', {}).get('location', {}).get('path', "N/A"),
                            alert.get('most_recent_instance', {}).get('category', "N/A"),
                            alert.get('html_url', "N/A")
                        ])
                except Exception as e:
                    print(f"Error getting CodeQL alerts for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")
    return codescan_alerts

# Process Secret Scanning alerts for each organization and repository and add them to a list
def secret_scanning_alerts(api_url, project_data):
    secretscan_alerts = []

    for gh_entity in ['organizations', 'repositories']:
        for gh_name in project_data.get(gh_entity, []):
            if gh_name:
                try:
                    owner = project_data.get('owner') if gh_entity == 'repositories' else None
                    alerts = get_secret_scanning_alerts(api_url, owner=owner, org_name=gh_name if gh_entity == 'organizations' else None, repo_name=gh_name if gh_entity == 'repositories' else None)[0]
                    for alert in alerts:
                        secretscan_alerts.append([
                            gh_name if gh_entity == 'organizations' else alert.get('organization', {}).get('name', "N/A"),
                            gh_name if gh_entity == 'repositories' else alert.get('repository', {}).get('name', "N/A"),
                            alert.get('repository', {}).get('name', "N/A"),
                            datetime.strptime(alert.get('created_at', "N/A"), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                            datetime.strptime(alert.get('updated_at', "N/A"), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                            alert.get('secret_type_display_name', "N/A"),
                            alert.get('secret_type', "N/A"),
                            alert.get('html_url', "N/A")
                        ])
                except Exception as e:
                    print(f"Error getting secret scanning alerts for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")
    return secretscan_alerts

# Process Dependabot alerts for each organization and repository and add them to a list
def dependabot_scanning_alerts(api_url, project_data):
    dependabot_alerts = []

    for gh_entity in ['organizations', 'repositories']:
        for gh_name in project_data.get(gh_entity, []):
            if gh_name:
                try:
                    owner = project_data.get('owner') if gh_entity == 'repositories' else None
                    alerts = get_dependabot_alerts(api_url, owner=owner, org_name=gh_name if gh_entity == 'organizations' else None, repo_name=gh_name if gh_entity == 'repositories' else None)[0]
                    for alert in alerts:
                        dependabot_alerts.append([
                            gh_name if gh_entity == 'organizations' else alert.get('organization', {}).get('name', "N/A"),
                            gh_name if gh_entity == 'repositories' else alert.get('repository', {}).get('name', "N/A"),
                            datetime.strptime(alert.get('created_at', "N/A"), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                            datetime.strptime(alert.get('updated_at', "N/A"), "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                            alert.get('security_advisory', {}).get('severity', "N/A"),
                            alert.get('dependency', {}).get('package', {}).get('name', "N/A"),
                            alert.get('security_advisory', {}).get('cve_id', "N/A"),
                            alert.get('security_advisory', {}).get('summary', "N/A"),
                            alert.get('dependency', {}).get('scope', "N/A"),
                            alert.get('dependency', {}).get('manifest_path', "N/A"),
                            alert.get('html_url', "N/A")
                        ])
                except Exception as e:
                    print(f"Error getting dependabot alerts for {'repository' if gh_entity == 'repositories' else 'organization'}: {gh_name} - {e}")
    return dependabot_alerts

def main():
    # Load configuration from config.json file
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        print('Error: config.json file not found')
        exit(1)
    except json.JSONDecodeError:
        print('Error: config.json file is not valid JSON')
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

    # Get Alert count for each project and write them to a CSV file
    for project_name, project_data in config.get('projects', {}).items():
        write_alert_count_csv(alert_count(api_url, project_data), project_name)
    
    # Get Code scan findings for each organization and write them to a CSV file
    for project_name, project_data in config.get('projects', {}).items():
        write_codescan_alerts_csv(code_scanning_alerts(api_url, project_data), project_name)
    
    # Get Secret scan findings for each organization and write them to a CSV file
    for project_name, project_data in config.get('projects', {}).items():
        write_secretscan_alerts_csv(secret_scanning_alerts(api_url, project_data), project_name)
   
    # Get Dependabot scan findings for each organization and write them to a CSV file
    for project_name, project_data in config.get('projects', {}).items():
        write_dependabot_alerts_csv(dependabot_scanning_alerts(api_url, project_data), project_name)
            
if __name__ == '__main__':
    main()