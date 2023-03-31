<img align="center" alt="PNG" src="https://github.com/madalin-dogaru/madalin-dogaru/blob/master/snyk3r.png?raw=true" width="1200" height="350" />


# snyker
A Snyk tool that uses its API to automate various jobs like puling a list of issues, ignoring them, corelating them with projects and more. The project is still in its infancy and I'm building it based on my needs but feel free to request new functionality.   

API Documentation that is used for this tool: https://snyk.docs.apiary.io/#   

Install
---
##### 1.Clone it:    
`https://github.com/madalin-dogaru/snyker.git`

##### 2. Install requirements (python 3.11+ recommended)   
`pip install -r requirements.txt`

Configuration
---
Both variables below are found in `snyker.py`.
- `org_id = "org_id_value"` Its the Organization ID found in Snyk, under organization/settings.   
- `api_token = "api_token_value"` Its your personal API Token found in your Snyk account. 


Examples
---
#### -lpid :   
List all Project IDs and their paths/names for a specific organization.  
`python3 -snyker.py -lpid`

#### -lpcve :   
List all critical vulnerabilities, in the following format, for all projects in an organization:CVE:Critical_Severities:Issue_ID.   
`python3 -snyker.py -lpcve `

#### -ii :   
Ignore a specific Issue for a specific Project based on the Issue ID.   
`python3 -snyker.py -ii project_id issue_id`

#### -mii :   
Ignore a specific issue for multiple projects, which are listed one per line in a file.    
`python3 -snyker.py -mii issue_id file_name`
