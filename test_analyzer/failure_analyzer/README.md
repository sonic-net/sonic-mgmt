# Test Failure Analyzer

The test failure analyzer is a script, run hourly, which ingests and performs analysis on test failure logs, for the purposes of more efficient issue triage.
It collates test failures to determine the most likely cause, and then creates an IcM containing these findings to serve as a starting point for further investigation into these issues.

## Run Locally

In order to run locally, ensure you export the following environment variables:
```
export ACCESS_TOKEN=$(az account get-access-token --resource https://api.kusto.windows.net | jq -r '.accessToken')
export AZURE_DEVOPS_MSAZURE_TOKEN=$(az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 | jq -r '.accessToken')
export ICM_KUSTO_CLUSTER="https://icmcluster.kusto.windows.net/"
export ADO_KUSTO_CLUSTER="https://1es.kusto.windows.net/"
export TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP="https://ingest-sonicrepodatadev.westus.kusto.windows.net"
```
