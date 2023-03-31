import requests
import json
from colorama import Fore, Style, init

init(autoreset=True)

def read_project_ids_from_file(file_path):
    with open(file_path, "r") as file:
        project_ids = [line.strip() for line in file.readlines()]
    return project_ids

def ignore_issue_in_multiple_projects(org_id, project_ids, issue_id, api_token, ignore_path="*", reason="", reason_type="We are not vulnerable to this CVE", disregard_if_fixable=False, expires=""):
    for project_id in project_ids:
        ignore_issue(org_id, project_id, issue_id, api_token, ignore_path, reason, reason_type, disregard_if_fixable, expires)


def list_project_ids(org_id, api_token):
    url = f"https://snyk.io/api/v1/org/{org_id}/projects"
    headers = {"Authorization": f"token {api_token}"}

    response = requests.post(url, headers=headers)

    if response.status_code == 200:
        projects_data = response.json()
        project_info = [
            (project["name"], project["id"]) for project in projects_data["projects"]
        ]
        print("Project IDs and Names:")
        for project_name, project_id in project_info:
            print(f"{project_id} : {project_name}")
    else:
        print(f"Error: {response.status_code}\n{response.text}")

def list_critical_vulnerabilities(org_id, api_token):
    try:
        url = f"https://snyk.io/api/v1/org/{org_id}/projects"
        headers = {"Authorization": f"token {api_token}"}

        response = requests.post(url, headers=headers)

        if response.status_code == 200:
            projects_data = response.json()
            project_info = [
                (project["name"], project["id"]) for project in projects_data["projects"]
            ]
            for project_name, project_id in project_info:
                issues_url = f"https://snyk.io/api/v1/org/{org_id}/project/{project_id}/aggregated-issues"
                issues_headers = {
                    "Authorization": f"token {api_token}",
                    "Content-Type": "application/json"
                }
                issues_params = {"filters": {"severities": ["critical"]}}
                issues_response = requests.post(issues_url, headers=issues_headers, data=json.dumps(issues_params))
                if issues_response.status_code == 200:
                    issues_data = issues_response.json()
                    print(f"{project_name}:")
                    for issue in issues_data["issues"]:
                        issue_data = issue["issueData"]
                        cve = issue_data['identifiers']['CVE'][0] if issue_data['identifiers']['CVE'] else "N/A"
                        severity = issue_data['severity']
                        issue_id = issue_data['id']
                        print(f"{cve}:{Fore.GREEN}{severity}{Style.RESET_ALL}:{issue_id}")
                    print()
                else:
                    print(f"Error: {issues_response.status_code}\n{issues_response.text}")
        else:
            print(f"Error: {response.status_code}\n{response.text}")
    except KeyboardInterrupt:
        print("\nEvil user interrupted me! Heeeeelp...")

def ignore_issue(org_id, project_id, issue_id, api_token, ignore_path="*", reason="", reason_type="not-vulnerable", disregard_if_fixable=False, expires=""):
    ignore_url = f"https://api.snyk.io/v1/org/{org_id}/project/{project_id}/ignore/{issue_id}"
    ignore_headers = {
        "Authorization": f"token {api_token}",
        "Content-Type": "application/json"
    }
    ignore_data = {
        "ignorePath": ignore_path,
        "reason": reason,
        "reasonType": reason_type,
        "disregardIfFixable": disregard_if_fixable,
        "expires": expires
    }
    ignore_response = requests.post(ignore_url, headers=ignore_headers, data=json.dumps(ignore_data))

    if ignore_response.status_code == 200:
        print(f"Issue {issue_id} successfully ignored in project {project_id}")
    else:
        print(f"Error: {ignore_response.status_code}\n{ignore_response.text}")

