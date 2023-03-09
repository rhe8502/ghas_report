#!/usr/bin/env python3

import requests
import csv
from json import load, JSONDecodeError
from datetime import datetime

# Load configuration from config.json 
def load_config():
    try:
        with open('config.json', 'r') as config_file:
            config = load(config_file)
            api_url = config['connection']['gh_api_url']
            api_key = config['connection']['gh_api_key']
            org_names = config['organizations']['gh_org_names']
    except FileNotFoundError:
        print('Error: config.json file not found')
        exit(1)
    except JSONDecodeError:
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

# Get number of Code Scanning alerts for an organization
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
    
    return code_scanning_alert_count

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

    return secret_scanning_alert_count

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

    return dependabot_alert_count


# Write the alert counts to a CSV file
def write_csv(alert_list):

    # Get the current date and time (needed for the filename)
    now = datetime.now()
    filename = now.strftime("%Y%m%d%H%M%S.csv")

    # Write the header row
    alert_list.insert(0, ['Organization', 'Code Scanning Alerts', 'Secret Scanning Alerts', 'Dependabot Alerts'])

    # Write the alert counts to a CSV file
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for alerts in alert_list:
                writer.writerow(alerts)
    except IOError:
        print("Error: I/O error")
        exit(1)

# Main function
def main():
    alert_list = []
    api_url, api_key, org_names = load_config()

    # Get the alert count for each organization
    for org_name in org_names:
        alert_list.append([org_name, get_code_scanning_alerts(api_url, api_key, org_name), get_secret_scanning_alerts(api_url, api_key, org_name), get_dependabot_alerts(api_url, api_key, org_name)])

    write_csv(alert_list)

if __name__ == '__main__':
    main()