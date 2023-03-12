#!/usr/bin/env python3

import requests
import csv
import json
#from json import load, loads, JSONDecodeError
from datetime import datetime

# Load configuration from config.json 
def load_config():
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
            api_url = config['connection']['gh_api_url']
            api_key = config['connection']['gh_api_key']
            org_names = config['organizations']['gh_org_names']
    except FileNotFoundError:
        print('Error: config.json file not found')
        exit(1)
    except json.JSONDecodeError:
        print('Error: config.json file is not valid JSON')
        exit(1)
    
    return api_url, api_key, org_names

# Handle API error responses
def api_error_response(response, org_names):
    if response.status_code == 401:
        print("Error: Authentication failed. Please check your API key.")
        exit(1)
    elif response.status_code == 403:
        print(f"Error: Access to organization {org_names} is forbidden. Please check your API key permissions.")
        return
    elif response.status_code == 404:
        print(f"Error: Organization {org_names} not found.")
        return
    else:
        print(f"Error getting alerts for {org_names}: {response.status_code}")
        return

# Get Code Scanning alerts for an organization
def get_code_scanning_alerts(api_url, api_key, org_names):
    url = f"{api_url}/orgs/{org_names}/code-scanning/alerts?state=open"
    headers = {
        "Authorization" : f"token {api_key}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        code_scanning_alerts = response.json()
        code_scanning_alert_count = len(code_scanning_alerts)
    else:
        api_error_response(response, org_names)
        return
    
    return code_scanning_alerts, code_scanning_alert_count

# Get number of Secret Scanning alerts for an organization
def get_secret_scanning_alerts(api_url, api_key, org_names):
    url = f"{api_url}/orgs/{org_names}/secret-scanning/alerts?state=open"
    headers = {
        "Authorization" : f"token {api_key}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        secret_scanning_alerts = response.json()
        secret_scanning_alert_count = len(secret_scanning_alerts)
    else:
        api_error_response(response, org_names)
        return

    return secret_scanning_alerts, secret_scanning_alert_count,

# Get number of open Dependabot alerts for an organization
def get_dependabot_alerts(api_url, api_key, org_names):
    url = f"{api_url}/orgs/{org_names}/dependabot/alerts?state=open"
    headers = {
        "Authorization" : f"token {api_key}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        dependabot_alerts = response.json()
        dependabot_alert_count = len(dependabot_alerts)  # get the total number of open Dependabot alerts
    else:
        api_error_response(response, org_names)
        return

    return dependabot_alerts, dependabot_alert_count

# Write open code scan findings to a CSV file
def write_codeql_alerts(codeql_alerts):    
    # Get the current date and time (needed for the filename)
    now = datetime.now()
    filename = now.strftime("codeql_open_alerts_%Y%m%d%H%M%S.csv")

    # Write the header row
    codeql_alerts.insert(0, ['Organization', 'Date Created', 'Date Updated', 'Severity', 'Rule ID', 'Description', 'Repository', 'File', 'Category', 'URL'])

    # Write the alerts to a CSV file
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            print("\nWriting CodeQL findings.", end="")
            for codeql_alert in codeql_alerts:
                writer.writerow(codeql_alert)
            print("\n")
    except IOError:
        print("Error: I/O error")
        exit(1)

def get_codql_alerts(api_url, api_key, org_names):
    codeql_alerts = []

    for org_name in org_names:
        alerts = (get_code_scanning_alerts(api_url, api_key, org_name)[0])
        if len(alerts) > 0:
            for alert in alerts:
                codeql_alerts.append([
                    org_name,
                    # alert['number'],
                    datetime.strptime(alert['created_at'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                    datetime.strptime(alert['updated_at'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                    # alert['rule']['severity'],
                    alert['rule']['security_severity_level'],
                    alert['rule']['id'],
                    # alert['rule']['description'],
                    alert['most_recent_instance']['message']['text'],
                    alert['repository']['name'],
                    alert['most_recent_instance']['location']['path'],
                    alert['most_recent_instance']['category'],
                    alert['html_url']
                    ])

    return codeql_alerts

# Write open alert count to a CSV file
def write_alert_count(alert_count):

    # Get the current date and time (needed for the filename)
    now = datetime.now()
    filename = now.strftime("open_alert_count_%Y%m%d%H%M%S.csv")

    # Write the header row
    alert_count.insert(0, ['Organization', 'Code Scanning Alerts', 'Secret Scanning Alerts', 'Dependabot Alerts'])

    # Write the alert counts to a CSV file
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            print("Writing Vulnerability count.")
            for alerts in alert_count:
                writer.writerow(alerts)
            print("\n")
    except IOError:
        print("Error: I/O error")
        exit(1)

# Get alert counts for each organization and add them to a list
def get_alert_count(api_url, api_key, org_names):
    alert_count = []

    for org_name in org_names:
        alert_count.append([org_name, get_code_scanning_alerts(api_url, api_key, org_name)[1], get_secret_scanning_alerts(api_url, api_key, org_name)[1], get_dependabot_alerts(api_url, api_key, org_name)[1]])

    return alert_count

# Main function
def main():
    api_url, api_key, org_names = load_config()
    write_codeql_alerts(get_codql_alerts(api_url, api_key, org_names))
    write_alert_count(get_alert_count(api_url, api_key, org_names))
   
if __name__ == '__main__':
    main()