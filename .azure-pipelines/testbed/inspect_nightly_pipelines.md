
# Inspect nightly pipelines

## Background
The nightly test pipelines will upload test results to kusto after a successful test run. If something went wrong on a testbed, the nightly test pipeline may exit early and no test results will be uploaded to Kusto. Just based on the test results already uploaded to Kusto, it is hard to figure out whether nightly test is reliably executed on the testbeds. The point is that the Kusto data does not have information of when a testbed is supposed to run a testbed and upload test results.

This job is to inspect the existing pipelines to find out all the nightly test pipelines. Then parse their yaml definition file to extract expected test run schedules. For each of the scheduled test run, upload a simple record with testbed name and expected nightly test trigger timestamp to Kusto.

With this information in Kusto, then it would be possible to figure out whether nightly test was reliably executed on each testbed using Kusto queries.

## Design

To collect expected runs data, we need a job to run once a day. It's because we may onboard new testbeds or update nightly run schedules.

For each run, a python script is called to gather the expected runs data. The script will find out all the enabled pipelines under folder "\\Nightly". Then it will pull yaml file of each pipeline from Git repository. Nightly test schedules are defined in pipeline's yaml file. The script will parse the yaml file to get timestamp of expected runs in the last calendar day. The gathered information is output in json format. Example output:

```
[
  { "testbed": "vms20-t1-dx010-6", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms1-t1-2700", "timestamp": "2022-01-10 04:10:00" },
  { "testbed": "vms6-t0-7060", "timestamp": "2022-01-10 12:00:00" },
  { "testbed": "vms6-t1-7060", "timestamp": "2022-01-10 12:00:00" },
  { "testbed": "vms7-t0-7260-2", "timestamp": "2022-01-10 10:00:00" },
  { "testbed": "vms24-dual-t0-7050-1", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms24-t0-7260-2", "timestamp": "2022-01-10 10:00:00" },
  { "testbed": "vms24-t1-7050qx-acs-01", "timestamp": "2022-01-10 01:00:00" },
  { "testbed": "vms20-t0-7050cx3-1", "timestamp": "2022-01-10 03:00:00" },
  { "testbed": "vms20-t1-7050cx3-3", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms21-dual-t0-7260", "timestamp": "2022-01-10 09:00:00" },
  { "testbed": "vms3-t1-dx010-1", "timestamp": "2022-01-10 05:00:00" },
  { "testbed": "vms7-t0-dx010-4", "timestamp": "2022-01-10 11:00:00" },
  { "testbed": "vms7-t0-dx010-5", "timestamp": "2022-01-10 11:00:00" },
  { "testbed": "vms12-9-t0-e1031", "timestamp": "2022-01-10 12:00:00" },
  { "testbed": "vms7-t1-s6100", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms11-t0-on-4", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms21-t0-z9332f-02", "timestamp": "2022-01-10 01:00:00" },
  { "testbed": "vms21-t1-z9332f-01", "timestamp": "2022-01-10 02:00:00" },
  { "testbed": "vms1-8", "timestamp": "2022-01-10 02:00:00" },
  { "testbed": "vms2-4-t0-2700", "timestamp": "2022-01-10 06:00:00" },
  { "testbed": "vms7-t0-4600c-2", "timestamp": "2022-01-10 14:00:00" },
  { "testbed": "vms12-t0-3800", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms18-t1-msn4600c-acs-1", "timestamp": "2022-01-10 14:00:00" },
  { "testbed": "vms20-t0-sn3800-2", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms21-t0-2700", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms21-t1-2700-2", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms20-t0-ixia-2", "timestamp": "2022-01-10 05:00:00" },
  { "testbed": "vms18-t0-7050qx-acs-02", "timestamp": "2022-01-10 07:00:00" },
  { "testbed": "vms18-t1-7050qx-acs-03", "timestamp": "2022-01-10 10:30:00" },
  { "testbed": "vms7-t0-s6100", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms21-t0-7215-acs-3", "timestamp": "2022-01-10 11:00:00" },
  { "testbed": "vms21-dual-t0-7050-3", "timestamp": "2022-01-10 08:00:00" },
  { "testbed": "vms21-t0-8102-01", "timestamp": "2022-01-10 09:00:00" },
  { "testbed": "vms28-t1-8102-02", "timestamp": "2022-01-10 09:00:00" },
  { "testbed": "vms2-t1-7260-7", "timestamp": "2022-01-10 11:00:00" },
  { "testbed": "vms3-t1-7280", "timestamp": "2022-01-10 11:00:00" },
  { "testbed": "vms28-dual-t0-8102", "timestamp": "2022-01-10 09:00:00" },
  { "testbed": "vms28-t0-4600c-03", "timestamp": "2022-01-10 14:00:00" },
  { "testbed": "vms20-t0-7050cx3-2", "timestamp": "2022-01-10 03:00:00" },
  { "testbed": "vms28-dual-t0-7260", "timestamp": "2022-01-10 09:00:00" },
  { "testbed": "vms24-dual-t0-7050-2", "timestamp": "2022-01-10 08:15:00" },
  { "testbed": "vms24-t0-3800-azd", "timestamp": "2022-01-10 04:00:00" },
  { "testbed": "vms28-t0-4600c-04", "timestamp": "2022-01-10 00:00:00" }
]
```

Then the test report uploading tool is called to upload this data to Kusto database SonicTestData and table ExpectedTestRuns.

## Implementation details
Reference: https://docs.microsoft.com/en-us/rest/api/azure/devops/?view=azure-devops-rest-6.1

The python script inspect_nightly_pipelines.py uses the python requests library to call REST APIs of Azure DevOps platform.

It firstly tries to get all build definitions. Result is a list of dict. Then the script filters build definitions to all enabled pipelines that are also under folder '\\Nightly'. Example result:
```
    {
    "options": [
        {
        "enabled": false,
        "definition": { "id": "5d58cc01-7c75-450c-be18-a388ddb129ec" },
        "inputs": {
            "branchFilters": "[\"+refs/heads/*\"]",
            "additionalFields": "{}"
        }
        },
        {
        "enabled": false,
        "definition": { "id": "a9db38f9-9fdc-478c-b0f9-464221e58316" },
        "inputs": {
            "workItemType": "Issue",
            "assignToRequestor": "true",
            "additionalFields": "{}"
        }
        },
        {
        "enabled": false,
        "definition": { "id": "57578776-4c22-4526-aeb0-86b6da17ee9c" },
        "inputs": {}
        }
    ],
    "triggers": [
        {
        "branchFilters": [],
        "pathFilters": [],
        "settingsSourceType": 2,
        "batchChanges": false,
        "maxConcurrentBuildsPerBranch": 1,
        "triggerType": "continuousIntegration"
        }
    ],
    "properties": {},
    "tags": [],
    "_links": {
        "self": {
        "href": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_apis/build/Definitions/403?revision=2"
        },
        "web": {
        "href": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_build/definition?definitionId=403"
        },
        "editor": {
        "href": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_build/designer?id=403&_a=edit-build-definition"
        },
        "badge": {
        "href": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_apis/build/status/403"
        }
    },
    "comment": "Update pipeline to run master",
    "jobAuthorizationScope": "projectCollection",
    "jobTimeoutInMinutes": 60,
    "jobCancelTimeoutInMinutes": 5,
    "process": {
        "yamlFilename": ".azure-pipelines/nightly/celestica/vms7-t0-dx010-5.2.yml",
        "type": 2
    },
    "repository": {
        "properties": {
        "cloneUrl": "https://mssonic@dev.azure.com/mssonic/internal/_git/sonic-mgmt-int",
        "fullName": "sonic-mgmt-int",
        "defaultBranch": "refs/heads/internal",
        "isFork": "False",
        "safeRepository": "5380e8f7-6e2a-4154-8dee-f3be7b096894",
        "reportBuildStatus": "true",
        "cleanOptions": "0",
        "fetchDepth": "0",
        "gitLfsSupport": "false",
        "skipSyncSource": "false",
        "checkoutNestedSubmodules": "false",
        "labelSources": "0",
        "labelSourcesFormat": "$(build.buildNumber)"
        },
        "id": "5380e8f7-6e2a-4154-8dee-f3be7b096894",
        "type": "TfsGit",
        "name": "sonic-mgmt-int",
        "url": "https://dev.azure.com/mssonic/internal/_git/sonic-mgmt-int",
        "defaultBranch": "refs/heads/internal",
        "clean": null,
        "checkoutSubmodules": false
    },
    "quality": "definition",
    "authoredBy": {
        "displayName": "Xin Wang",
        "url": "https://spsprodcus4.vssps.visualstudio.com/A322bbd8a-895f-4707-8e71-d0ff154b9620/_apis/Identities/f2868cb3-2ee6-680d-99d6-c310955a369d",
        "_links": {
        "avatar": {
            "href": "https://dev.azure.com/mssonic/_apis/GraphProfile/MemberAvatars/aad.ZjI4NjhjYjMtMmVlNi03ODBkLTk5ZDYtYzMxMDk1NWEzNjlk"
        }
        },
        "id": "f2868cb3-2ee6-680d-99d6-c310955a369d",
        "uniqueName": "xiwang5@microsoft.com",
        "imageUrl": "https://dev.azure.com/mssonic/_apis/GraphProfile/MemberAvatars/aad.ZjI4NjhjYjMtMmVlNi03ODBkLTk5ZDYtYzMxMDk1NWEzNjlk",
        "descriptor": "aad.ZjI4NjhjYjMtMmVlNi03ODBkLTk5ZDYtYzMxMDk1NWEzNjlk"
    },
    "drafts": [],
    "queue": {
        "_links": {
        "self": { "href": "https://dev.azure.com/mssonic/_apis/build/Queues/38" }
        },
        "id": 38,
        "name": "Azure Pipelines",
        "url": "https://dev.azure.com/mssonic/_apis/build/Queues/38",
        "pool": { "id": 9, "name": "Azure Pipelines", "isHosted": true }
    },
    "id": 403,
    "name": "vms7-t0-dx010-5.master",
    "url": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_apis/build/Definitions/403?revision=2",
    "uri": "vstfs:///Build/Definition/403",
    "path": "\\Nightly\\celestica",
    "type": "build",
    "queueStatus": "enabled",
    "revision": 2,
    "createdDate": "2021-12-02T02:20:05.27Z",
    "project": {
        "id": "12b9cbf4-b1d3-4768-8e49-669345c32e5d",
        "name": "internal",
        "description": "sonic internal repos",
        "url": "https://dev.azure.com/mssonic/_apis/projects/12b9cbf4-b1d3-4768-8e49-669345c32e5d",
        "state": "wellFormed",
        "revision": 72,
        "visibility": "organization",
        "lastUpdateTime": "2021-03-28T01:19:51.713Z"
    }
    }

```

The build definition has url for getting details of each build definition. Example build definition details:
```
    [
        {
        "_links": {
            "self": {
            "href": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_apis/build/Definitions/403?revision=2"
            },
            "web": {
            "href": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_build/definition?definitionId=403"
            },
            "editor": {
            "href": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_build/designer?id=403&_a=edit-build-definition"
            },
            "badge": {
            "href": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_apis/build/status/403"
            }
        },
        "quality": "definition",
        "authoredBy": {
            "displayName": "Xin Wang",
            "url": "https://spsprodcus4.vssps.visualstudio.com/A322bbd8a-895f-4707-8e71-d0ff154b9620/_apis/Identities/f2868cb3-2ee6-680d-99d6-c310955a369d",
            "_links": {
            "avatar": {
                "href": "https://dev.azure.com/mssonic/_apis/GraphProfile/MemberAvatars/aad.ZjI4NjhjYjMtMmVlNi03ODBkLTk5ZDYtYzMxMDk1NWEzNjlk"
            }
            },
            "id": "f2868cb3-2ee6-680d-99d6-c310955a369d",
            "uniqueName": "xiwang5@microsoft.com",
            "imageUrl": "https://dev.azure.com/mssonic/_apis/GraphProfile/MemberAvatars/aad.ZjI4NjhjYjMtMmVlNi03ODBkLTk5ZDYtYzMxMDk1NWEzNjlk",
            "descriptor": "aad.ZjI4NjhjYjMtMmVlNi03ODBkLTk5ZDYtYzMxMDk1NWEzNjlk"
        },
        "drafts": [],
        "queue": {
            "_links": {
            "self": {
                "href": "https://dev.azure.com/mssonic/_apis/build/Queues/38"
            }
            },
            "id": 38,
            "name": "Azure Pipelines",
            "url": "https://dev.azure.com/mssonic/_apis/build/Queues/38",
            "pool": {
            "id": 9,
            "name": "Azure Pipelines",
            "isHosted": true
            }
        },
        "id": 403,
        "name": "vms7-t0-dx010-5.master",
        "url": "https://dev.azure.com/mssonic/12b9cbf4-b1d3-4768-8e49-669345c32e5d/_apis/build/Definitions/403?revision=2",
        "uri": "vstfs:///Build/Definition/403",
        "path": "\\Nightly\\celestica",
        "type": "build",
        "queueStatus": "enabled",
        "revision": 2,
        "createdDate": "2021-12-02T02:20:05.27Z",
        "project": {
            "id": "12b9cbf4-b1d3-4768-8e49-669345c32e5d",
            "name": "internal",
            "description": "sonic internal repos",
            "url": "https://dev.azure.com/mssonic/_apis/projects/12b9cbf4-b1d3-4768-8e49-669345c32e5d",
            "state": "wellFormed",
            "revision": 72,
            "visibility": "organization",
            "lastUpdateTime": "2021-03-28T01:19:51.713Z"
        }
        },
    ]
```

The build definition has url to its yaml file. Then the script tries to get the yaml file and get the crontab string from yaml file. A python package `crontab` is used for parsing the crontab string. Based on the crontab string, it is easy to figure out the expected runs in the last calendar day.

After all the information are gathered and output to a file, the test report uploading tool is called to upload the results to Kusto.
