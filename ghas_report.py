#!/usr/bin/env python3

import requests
import csv
import json
from datetime import datetime

# Load configuration from config.json 
def load_config():
    project_names = []
    org_names = []

    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        print('Error: config.json file not found')
        exit(1)
    except json.JSONDecodeError:
        print('Error: config.json file is not valid JSON')
        exit(1)
    
    api_url = config['connection']['gh_api_url']
    api_key = config['connection']['gh_api_key']

    for project in config.get("project", {}).keys():
        project_names.append(project)
    print(project_names)

    for project in config.get("project", {}).values():
        org_names += [org for org in project.get("organizations", []) if org != ""]
    print(org_names)

    return config, api_url, api_key
    # return api_url, api_key, project_names, org_names

# Handle API error responses
def api_error_response(response, org_name,):
    if response.status_code == 401:
        print("Error: Authentication failed. Please check your API key.")
        exit(1)
    elif response.status_code == 503:
        print("Error: GitHub API is currently unavailable. Please try again later.")
        exit(1)
    elif response.status_code == 403:
        return(f"Error: Access to organization {org_name} is forbidden. Please check your API key permissions.")
    elif response.status_code == 404:
        return(f"Error: Organization {org_name} not found.")
    else:
        return(f"Error getting alerts for {org_name}: {response.status_code}")  
    
# Get Code Scanning alerts and alert count
def get_code_scanning_alerts(api_url, api_key, org_name):
    url = f"{api_url}/orgs/{org_name}/code-scanning/alerts?state=open"
    headers = {
        "Authorization" : f"token {api_key}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        code_scanning_alerts = response.json()
        code_scanning_alert_count = len(code_scanning_alerts)
    else:
        error_msg = api_error_response(response, org_name)
        if error_msg is not None:
            print(error_msg)
            return
                
    return code_scanning_alerts, code_scanning_alert_count

# Get Secret Scanning alerts and alert count
def get_secret_scanning_alerts(api_url, api_key, org_name):
    url = f"{api_url}/orgs/{org_name}/secret-scanning/alerts?state=open"
    headers = {
        "Authorization" : f"token {api_key}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        secret_scanning_alerts = response.json()
        secret_scanning_alert_count = len(secret_scanning_alerts)
    else:
        error_msg = api_error_response(response, org_name)
        if error_msg is not None:
            print(error_msg)
            return

    return secret_scanning_alerts, secret_scanning_alert_count

# Get Dependabot alerts and alert count
def get_dependabot_alerts(api_url, api_key, org_name):
    url = f"{api_url}/orgs/{org_name}/dependabot/alerts?state=open"
    headers = {
        "Authorization" : f"token {api_key}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        dependabot_alerts = response.json()
        dependabot_alert_count = len(dependabot_alerts)  # get the total number of open Dependabot alerts
    else:
        error_msg = api_error_response(response, org_name)
        if error_msg is not None:
            print(error_msg)
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
            for codeql_alert in codeql_alerts:
                writer.writerow(codeql_alert)
            print("\n")
    except IOError:
        print("Error: I/O error")
        exit(1)

def get_codql_alerts(api_url, api_key, org_names):
    codeql_alerts = []

    for org_name in org_names:
        try:
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
        except:
            pass

    return codeql_alerts
'''
# Write open alert count to a CSV file
def write_alert_count(alert_count):
    # Get the current date and time (needed for the filename)
    now = datetime.now()
    filename = now.strftime("open_alert_count_%Y%m%d%H%M%S.csv")
    # print(project_name)

    # Write the header row
    alert_count.insert(0, ['Organization', 'Code Scanning Alerts', 'Secret Scanning Alerts', 'Dependabot Alerts'])

    # Write the alert counts to a CSV file
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for alerts in alert_count:
                writer.writerow(alerts)
            print("\n")
    except IOError:
        print("Error: I/O error")
        exit(1)
'''

def write_alert_count(alert_count, project_name):
    # Get the current date and time (needed for the filename)
    now = datetime.now()
    filename = f"{project_name}_open_alert_count_{now.strftime('%Y%m%d%H%M%S')}.csv"

    # Write the header row
    alert_count.insert(0, ['Organization', 'Code Scanning Alerts', 'Secret Scanning Alerts', 'Dependabot Alerts'])

    # Write the alert counts to a CSV file
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for alerts in alert_count:
                writer.writerow(alerts)
            print(f"Successfully wrote alert count for project {project_name} to file {filename}")
    except IOError:
        print(f"Error writing alert count for project {project_name} to file {filename}")

# Get alert counts for a single organization
def get_alert_count_for_org(api_url, api_key, org_name):
    try:
        return [org_name, get_code_scanning_alerts(api_url, api_key, org_name)[1], get_secret_scanning_alerts(api_url, api_key, org_name)[1], get_dependabot_alerts(api_url, api_key, org_name)[1]]
    except:
        return [org_name, "this organization does not exist in your GitHub account"]

def get_alert_count_and_write_to_file(api_url, api_key, project_name, project_data):
    alert_count = []
    for org_name in project_data["organizations"]:
        alert_count.append(get_alert_count_for_org(api_url, api_key, org_name))
    write_alert_count(alert_count, project_name)

'''
# Get alert counts for each organization and add them to a list
def get_alert_count(api_url, api_key, org_names):
    alert_count = []

    for org_name in org_names:
        try:
            alert_count.append([org_name, get_code_scanning_alerts(api_url, api_key, org_name)[1], get_secret_scanning_alerts(api_url, api_key, org_name)[1], get_dependabot_alerts(api_url, api_key, org_name)[1]])
        except:
            pass

    return alert_count   
'''

# Main function
def main():
    # api_url, api_key, project_names, org_names = load_config()
    # write_alert_count(get_alert_count(api_url, api_key, org_names))
    # write_codeql_alerts(get_codql_alerts(api_url, api_key, org_names))
    # get_alert_count(api_url, api_key, org_names)

    # with open("config.json", "r") as input_file:
    #    data = json.load(input_file)
    
    config, api_url, api_key = load_config()

    print(config)
    exit(0)

    for project_name, project_data in config["project"].items():
        print(project_name, " --- ",project_data)
        # get_alert_count_and_write_to_file(api_url, api_key, project_name, project_data)

if __name__ == '__main__':
    main()