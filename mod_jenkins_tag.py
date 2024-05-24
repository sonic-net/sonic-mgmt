import json

with open('infra/Jira_tag.json') as f:
    jira_tag = json.load(f)

new_jira_tag = {}
scrum_leads = {
    'James An': "jamesan", 
    'Aravind Subbaroyan': "asubbaro", 
    'Shivu Vibhuti': "svibhuti", 
    'Alpesh Patel': "alpesh", 
    'Sunesh Rustagi': "sunrusta"
}

for test_suite in jira_tag:
    name = test_suite["NAME"]
    new_jira_tag[name] = {}

    #populate basic info
    new_jira_tag[name]["NAME"] = test_suite["NAME"]
    new_jira_tag[name]["TEAM"] = test_suite["TEAM"]
    new_jira_tag[name]["SCRUM_LEAD"] = {}
    new_jira_tag[name]["SCRUM_LEAD"]["NAME"] = test_suite["SCRUM_LEAD"]
    new_jira_tag[name]["SCRUM_LEAD"]["USER_ID"] = scrum_leads[test_suite["SCRUM_LEAD"]]
    new_jira_tag[name]["SCRUM_LEAD"]["EMAIL"] = new_jira_tag[name]["SCRUM_LEAD"]["USER_ID"] + "@cisco.com"

    #populate labels
    new_jira_tag[name]["labels"] = test_suite
    del new_jira_tag[name]["labels"]["NAME"]
    del new_jira_tag[name]["labels"]["TEAM"]
    del new_jira_tag[name]["labels"]["SCRUM_LEAD"]
    new_jira_tag[name]["labels"]["EXTRA_LABELS"] = new_jira_tag[name]["labels"]["EXTRA_LABEL"]
    del new_jira_tag[name]["labels"]["EXTRA_LABEL"]

with open("infra/sanity_suites_jira_info.json", 'w') as f:
    f.write(json.dumps(new_jira_tag, indent=4))

print(scrum_leads)
