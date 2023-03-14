#!/usr/bin/env python3

import requests
import csv
import json
from datetime import datetime

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
def get_code_scanning_alerts(api_url, api_key, org_name=None, owner=None, repo_name=None):
    if repo_name:
        url = f"{api_url}/repos/{owner}/{repo_name}/code-scanning/alerts?state=open"
    elif org_name:
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
def get_secret_scanning_alerts(api_url, api_key, org_name=None, owner=None, repo_name=None):
    if repo_name:       
        url = f"{api_url}/repos/{owner}/{repo_name}/secret-scanning/alerts?state=open"
    elif org_name:
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
def get_dependabot_alerts(api_url, api_key, org_name=None, owner=None, repo_name=None):
    if repo_name:
        url = f"{api_url}/repos/{owner}/{repo_name}/dependabot/alerts?state=open"
    elif org_name:
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
def write_codeql_alerts_csv(codeql_alerts, project_name):    
    now = datetime.now()
    filename = f"{project_name}-codeql_alerts-{now.strftime('%Y%m%d%H%M%S')}.csv"

    # Write the header row
    codeql_alerts.insert(0, ['Organization', 'Repository', 'Date Created', 'Date Updated', 'Severity', 'Rule ID', 'Description', 'File', 'Category', 'URL'])

    # Write the alerts to a CSV file
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for codeql_alert in codeql_alerts:
                writer.writerow(codeql_alert)
            print(f"Successfully wrote open code scan findings for project \"{project_name}\" to file {filename}")
    except IOError:
        print("Error: I/O error")
        exit(1)

# Write alert counts to a CSV file
def write_alert_count_csv(alert_count, project_name):
    now = datetime.now()
    filename = f"{project_name}-alert_count-{now.strftime('%Y%m%d%H%M%S')}.csv"

    # Write the header row
    alert_count.insert(0, ['Organization', "Repository", 'Code Scanning Alerts', 'Secret Scanning Alerts', 'Dependabot Alerts'])

    # Write the alert counts to a CSV file
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            for alerts in alert_count:
                writer.writerow(alerts)
            print(f"Successfully wrote alert count for project \"{project_name}\" to file {filename}")
    except IOError:
        print(f"Error writing alert count for project {project_name} to file {filename}")

# Get alert counts for each organization and add them to a list
def get_alert_count(api_url, api_key, project_data):
    alert_count = []

    if "organizations" in project_data:
            for org_name in project_data["organizations"]:
                if org_name != "":
                    try:
                        alert_count.append([org_name, "", get_code_scanning_alerts(api_url, api_key, org_name=org_name)[1], get_secret_scanning_alerts(api_url, api_key, org_name=org_name)[1], get_dependabot_alerts(api_url, api_key, org_name=org_name)[1]])
                    except Exception as e:
                        print(f"Error getting alert count for org: {org_name} - {e}")
                        pass
   
    if "repositories" in project_data:
        for repo_name in project_data["repositories"]:
            if repo_name != "":
                try:
                    owner = project_data.get("owner")  # use .get() to avoid NoneType error
                    alert_count.append(["", repo_name, get_code_scanning_alerts(api_url, api_key, owner=owner, repo_name=repo_name)[1], get_secret_scanning_alerts(api_url, api_key, owner=owner, repo_name=repo_name)[1], get_dependabot_alerts(api_url, api_key, owner=owner, repo_name=repo_name)[1]])
                except Exception as e:
                    print(f"Error getting alert count for repo: {repo_name} - {e}")
                    pass

    return alert_count

def get_codql_alerts(api_url, api_key, project_data):
    codeql_alerts = []

    # Get CodeQL alerts for each organization listed in the project data   
    if "organizations" in project_data:                
        for org_name in project_data["organizations"]:
            if org_name != "":
                try:
                    alerts = (get_code_scanning_alerts(api_url, api_key, org_name=org_name)[0])
                    if len(alerts) > 0:
                        for alert in alerts:
                            codeql_alerts.append([
                                org_name,
                                alert['repository']['name'],
                                datetime.strptime(alert['created_at'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                                datetime.strptime(alert['updated_at'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                                alert['rule']['security_severity_level'],
                                alert['rule']['id'],
                                alert['most_recent_instance']['message']['text'],
                                alert['most_recent_instance']['location']['path'],
                                alert['most_recent_instance']['category'],
                                alert['html_url']
                                ])
                except Exception as e:
                    print(f"Error getting alerts for org: {org_name} - {e}")
                    pass

    # Get CodeQL alerts for each repository listed in the project data
    if "repositories" in project_data:
        for repo_name in project_data["repositories"]:
            if repo_name != "":
                try:
                    owner = project_data.get("owner")  # use .get() to avoid NoneType error
                    alerts = (get_code_scanning_alerts(api_url, api_key, owner=owner, repo_name=repo_name)[0])
                    if len(alerts) > 0:
                        for alert in alerts:
                            codeql_alerts.append([
                                "",
                                repo_name,
                                datetime.strptime(alert['created_at'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                                datetime.strptime(alert['updated_at'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                                alert['rule']['security_severity_level'],
                                alert['rule']['id'],
                                alert['most_recent_instance']['message']['text'],
                                alert['most_recent_instance']['location']['path'],
                                alert['most_recent_instance']['category'],
                                alert['html_url']
                                ])
                except Exception as e:
                    print(f"Error getting alerts for repo: {repo_name} - {e}")
                    pass

    return codeql_alerts

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
    api_url = config['connection']['gh_api_url']
    api_key = config['connection']['gh_api_key']

    # Get alert counts for each project and write them to a CSV file
    for project_name, project_data in config["projects"].items():
        if project_name != "":
            write_alert_count_csv(get_alert_count(api_url, api_key, project_data), project_name)

    # Get open code scan findings for each organization and write them to a CSV file
    for project_name, project_data in config["projects"].items():
        if project_name != "":
            write_codeql_alerts_csv(get_codql_alerts(api_url, api_key, project_data), project_name)

if __name__ == '__main__':
    main()