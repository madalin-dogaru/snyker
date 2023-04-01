"""
Title: snyker
Author: Mădălin Dogaru
Discord: The Wallachian#4651
Date: 31-03-2023
Version: v0.1
License: MIT
Description: Snyker interacts with Snyk's API to manage and output data in various ways.
"""

import argparse
from utils import read_project_ids_from_file
from snyk_operations import list_project_ids, list_critical_vulnerabilities, ignore_issue, ignore_issue_in_multiple_projects

org_id = "org_id_value"
api_token = "api_token_value"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Snyk API tool")
    parser.add_argument("-lpid", "--list-project-ids", action="store_true", help="List projects IDs and Paths")
    parser.add_argument("-lpcve", "--list-project-critical-vulnerabilities", action="store_true", help="List CVE:Critical_Severities:Issue_ID")
    parser.add_argument("-ii", "--ignore-issue", nargs=2, metavar=("PROJECT_ID", "ISSUE_ID"), help="Ignore a specific issue in a project")
    parser.add_argument("-mii", "--multi-ignore-issue", nargs=2, metavar=("ISSUE_ID", "FILE_PATH"), help="Ignore a specific issue in multiple projects listed in a file")
    args = parser.parse_args()

    if args.list_project_ids:
        list_project_ids(org_id, api_token)
    elif args.list_project_critical_vulnerabilities:
        list_critical_vulnerabilities(org_id, api_token)
    elif args.ignore_issue:
        project_id, issue_id = args.ignore_issue
        # Customize these values based on your needs
        ignore_path = "*"
        reason = "We are not vulnerable to this CVE"
        reason_type = "not-vulnerable"
        disregard_if_fixable = False
        expires = "2054-12-31T23:59:59Z"
        ignore_issue(org_id, project_id, issue_id, api_token, ignore_path, reason, reason_type, disregard_if_fixable, expires)

    elif args.multi_ignore_issue:
        issue_id, file_path = args.multi_ignore_issue
        project_ids = read_project_ids_from_file(file_path)
        # Customize these values based on your needs
        ignore_path = "*"
        reason = "We are not vulnerable to this CVE"
        reason_type = "not-vulnerable"
        disregard_if_fixable = False
        expires = "2054-12-31T23:59:59Z"
        ignore_issue_in_multiple_projects(org_id, project_ids, issue_id, api_token, ignore_path, reason, reason_type, disregard_if_fixable, expires)
    else:
        print("No valid option selected. Please use -lpid to list project IDs or -lpcve to list critical vulnerabilities.")
 
