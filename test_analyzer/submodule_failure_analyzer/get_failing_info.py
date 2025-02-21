import os
import re
import requests
import json
import sys
import logging
from datetime import datetime, timedelta
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from azure.kusto.ingest import IngestionProperties
from azure.kusto.ingest import QueuedIngestClient
from azure.kusto.data.data_format import DataFormat

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)


REPO = "sonic-net/sonic-buildimage"
AUTHOR = "mssonicbld"
LABELS = ["Submodule Update :arrow_double_up:"]
STATE = "open"
BUILD_IMAGE_API_URL = f"https://api.github.com/repos/{REPO}/pulls"
TIME_DELTA = 3
FAILURE_INFO_FILE = "failed_pr_info.json"

DATABASE = 'SonicTestData'
ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
cluster = ingest_cluster.replace('ingest-', '')
access_token = os.environ.get('ACCESS_TOKEN', None)
INGEST_TABLE = 'SubmoduleFailure'
INGEST_TABLE_MAPPING = 'SubmoduleFailureV1'

IGNORE_LIST = {
    "202012": ["sonic-telemetry", "sonic-snmpagent"]
}


def get_prs_with_label(url, labels):
    params = {
        "state": "open",  # Change to "closed" if needed
        "per_page": 100,  # Maximum results per page
    }
    prs_with_label = []
    three_days_ago = datetime.now() - timedelta(days=TIME_DELTA)
    # Loop through pages of results
    while True:
        response = requests.get(url, params=params)
        if response.status_code != 200:
            logger.error(f"Failed to fetch pull requests: Status code {response.status_code}")
            break

        prs = response.json()
        for pr in prs:
            pr_author = pr["user"]["login"]
            if pr_author != AUTHOR:
                continue
            create_time = datetime.strptime(pr["created_at"], "%Y-%m-%dT%H:%M:%SZ")
            if create_time > three_days_ago:
                continue
            pr_labels = [label["name"] for label in pr.get("labels", [])]
            if set(labels).issubset(pr_labels):
                prs_with_label.append({
                    "number": pr["number"],
                    "title": pr["title"],
                    "url": pr["html_url"],
                    "create_time": pr["created_at"],
                })

        # Pagination
        if "next" in response.links:
            url = response.links["next"]["url"]
        else:
            break

    return prs_with_label


def should_ignore(submodule_name, branch):
    if branch in IGNORE_LIST:
        if submodule_name in IGNORE_LIST[branch]:
            return True
    return False


def parse_prs(prs_with_label):
    pr_list = []
    for pr in prs_with_label:
        match = re.search(r"\[submodule\]\[([^\]]+)\] Update submodule (\S+)", pr['title'])
        if match:
            pr_number = pr["number"]
            branch = match.group(1)
            submodule_name = match.group(2)
            pr_info = {
                "PRNumber": pr_number,
                "Branch": branch,
                "SubmoduleName": submodule_name,
                "CreateTime": pr["create_time"]
            }
            if not should_ignore(submodule_name, branch):
                pr_list.append(pr_info)
    return pr_list


def get_failed_test_plans(client_kusto, failed_pr_info):
    for pr in failed_pr_info:
        last_failed_info = []
        query = f"""
            TestPlans
            | where TestPlanType == "PR"
            | where TestPlanName contains "PullRequest_PR_{pr["PRNumber"]}"
            | extend TopoType = case(
                TestPlanName contains "kvmtest-t0_", "t0", 
                TestPlanName contains "kvmtest-t0-sonic_", "t0-sonic",
                TestPlanName contains "kvmtest-t0-2vlans_", "t0-2vlans",
                TestPlanName contains "kvmtest-t1-lag_", "t1-lag",
                TestPlanName contains "kvmtest-multi-asic-t1-lag_", "multi-asic-t1-lag",
                TestPlanName contains "kvmtest-dualtor-t0_", "dualtor-t0",
                TestPlanName contains "kvmtest-dpu_", "dpu", 
                "other")
            | where TopoType != "other"
            | summarize arg_max(StartTime, *) by TopoType
            | where Result == "FAILED"
            | distinct TestPlanId, TestPlanName, TopoType, Result, ErrorCode
        """
        query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
        for result in query_result:
            last_failed_info.append({
                "TopoType": result['TopoType'],
                "TestPlanId": result['TestPlanId'],
                "ErrorCode": result['ErrorCode']
            })
        pr["LastFailedInfo"] = last_failed_info

    return failed_pr_info


def get_failed_test_cases(client_kusto, failed_pr_info):
    for pr in failed_pr_info:
        for failed_info in pr["LastFailedInfo"]:
            case_info = []
            query = f"""
                V2TestCases
                | where TestPlanId == "{failed_info["TestPlanId"]}"
                | where Result in ("failure", "error")
                | where Attempt == 2 or Summary contains "sanity check"
                | distinct TestPlanId, ModulePath, TestCase, Result
            """
            query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
            for result in query_result:
                case_info.append({
                    "ModulePath": result['ModulePath'],
                    "TestCase": result['TestCase'],
                    "Result": result['Result']
                })
            failed_info["CaseInfo"] = case_info

    return failed_pr_info


def add_upload_time(failed_pr_info):
    for pr in failed_pr_info:
        pr["UploadTime"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    return failed_pr_info


def ingest_data_to_kusto(client_kusto_ingest, file_name, data_format):
    ingestion_props = IngestionProperties(
        database=DATABASE,
        table=INGEST_TABLE,
        data_format=data_format,
        ingestion_mapping_reference=INGEST_TABLE_MAPPING
    )
    client_kusto_ingest.ingest_from_file(file_name, ingestion_props)


if __name__ == "__main__":
    prs_with_label = get_prs_with_label(url=BUILD_IMAGE_API_URL, labels=LABELS)
    logger.info(f"prs_with_label: {prs_with_label}")
    failed_pr_info = parse_prs(prs_with_label)

    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster, access_token)
    client_kusto = KustoClient(kcsb)
    failed_pr_info = get_failed_test_plans(client_kusto, failed_pr_info)
    failed_pr_info = get_failed_test_cases(client_kusto, failed_pr_info)
    failed_pr_info = add_upload_time(failed_pr_info)
    logger.info(f"failed_pr_info: {failed_pr_info}")
    with open(FAILURE_INFO_FILE, "w") as f:
        json.dump(failed_pr_info, f, indent=4)

    kcsb_ingest = KustoConnectionStringBuilder.with_aad_application_token_authentication(ingest_cluster, access_token)
    client_kusto_ingest = QueuedIngestClient(kcsb_ingest)
    ingest_data_to_kusto(client_kusto_ingest, FAILURE_INFO_FILE, DataFormat.MULTIJSON)
