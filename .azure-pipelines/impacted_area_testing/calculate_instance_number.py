import os
import argparse
import math
import logging
from constant import PR_CHECKER_TOPOLOGY_NAME, MAX_INSTANCE_NUMBER, MAX_GET_TOKEN_RETRY_TIMES
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient

logging.basicConfig(level=logging.INFO)


def parse_list_from_str(s):
    # Since Azure Pipeline doesn't support to receive an empty parameter,
    # We use ' ' as a magic code for empty parameter.
    # So we should consider ' ' as en empty input.
    if isinstance(s, str):
        s = s.strip()
    if not s:
        return None
    return [single_str.strip()
            for single_str in s.split(',')
            if single_str.strip()]


def get_access_token():
    managed_identity_id = os.environ.get("SONIC_AUTOMATION_UMI")

    # 1. Run az login with re-try
    az_login_cmd = f"az login --identity --username {managed_identity_id}"
    az_login_attempts = 0
    while az_login_attempts < MAX_GET_TOKEN_RETRY_TIMES:
        try:
            result = os.popen(az_login_cmd)
            result.read()
            break
        except Exception as exception:
            az_login_attempts += 1
            raise Exception(
                f"Failed to az login with exception: {repr(exception)}. "
                f"Retry {MAX_GET_TOKEN_RETRY_TIMES - az_login_attempts} times to login."
            )

    # If az login failed, return with exception
    if az_login_attempts >= MAX_GET_TOKEN_RETRY_TIMES:
        raise Exception(f"Failed to az login after {MAX_GET_TOKEN_RETRY_TIMES} attempts.")

    # 2. Get access token with re-try
    get_token_cmd = "az account get-access-token --resource https://api.kusto.windows.net --query accessToken -o tsv"
    get_token_attempts = 0
    while get_token_attempts < MAX_GET_TOKEN_RETRY_TIMES:
        try:
            result = os.popen(get_token_cmd)
            access_token = result.read()
            if not access_token:
                raise Exception("Parse token from stdout failed, accessToken is None.")

            return access_token

        except Exception as exception:
            get_token_attempts += 1
            raise Exception(f"Failed to get token with exception: {repr(exception)}.")

    # If az get token failed, return with exception
    if get_token_attempts >= MAX_GET_TOKEN_RETRY_TIMES:
        raise Exception(f"Failed to get token after {MAX_GET_TOKEN_RETRY_TIMES} attempts")


def main(scripts, topology, branch, prepare_time):
    ingest_cluster = os.getenv("TEST_REPORT_QUERY_KUSTO_CLUSTER_BACKUP")
    access_token = get_access_token()

    if not ingest_cluster or not access_token:
        raise RuntimeError(
            "Could not load Kusto Credentials from environment")

    try:
        kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(ingest_cluster,
                                                                                      access_token)  # noqa F841
        client = KustoClient(kcsb)
    except Exception as e:
        raise Exception("Connect to kusto fails, error {}".format(e))

    scripts = parse_list_from_str(scripts)

    scripts_running_time = {}
    total_running_time = 0

    for script in scripts:
        # As baseline test is the universal set of PR test
        # we get the historical running time of one script here
        # We get recent 5 test plans and calculate the average running time
        query = "let FilteredTestPlans = TestPlans " \
                "| where TestPlanType == 'PR' and Result == 'FINISHED' " \
                f"and Topology == '{PR_CHECKER_TOPOLOGY_NAME[topology][0]}'" \
                f"and TestBranch == '{branch}' and TestPlanName contains '{PR_CHECKER_TOPOLOGY_NAME[topology][1]}'" \
                "and TestPlanName contains '_BaselineTest_' | order by UploadTime desc | take 5;" \
                "let FilteredCount = toscalar(FilteredTestPlans | summarize ActualCount = count());" \
                "V2TestCases | join kind=inner( FilteredTestPlans ) on TestPlanId" \
                f"| where FilePath == '{script}' | where Result !in ('failure', 'error')" \
                "| summarize TotalRuntime = sum(Runtime), ActualCount=FilteredCount"
        try:
            response = client.execute("SonicTestData", query)
        except Exception as e:
            raise Exception("Query results from Kusto fails, error {}".format(e))

        for row in response.primary_results[0]:
            # We have obtained the results of the most recent five times.
            # To get the result for a single time, we need to divide by five
            # If response.primary_results is None, which means where is no historical data in Kusto,
            # we will use the default 1800s for a script.
            running_time = row["TotalRuntime"]
            actual_count = row["ActualCount"]

            # There is no relevant records in Kusto
            if running_time == 0:
                average_running_time = 1800
            else:
                average_running_time = running_time / actual_count

        total_running_time += average_running_time
        scripts_running_time[script] = average_running_time
    logging.info(f"Time for each test script: {scripts_running_time}")
    logging.info(f"Total running time: {total_running_time}")
    # Total running time is calculated by seconds, divide by 60 to get minutes
    # Our goal is to limit the whole PR testing into 120 minutes
    # As we need some time to prepare testbeds, the prepare time should be subtracted.
    # Obtain the number of instances by rounding up the calculation.
    # To prevent unexpected situations, we set the maximum number of instance
    print(min(math.ceil(total_running_time / 60 / (120 - prepare_time)), MAX_INSTANCE_NUMBER))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", help="The topology of testplan", type=str, default="")
    parser.add_argument("--scripts", help="Test scripts to be executed", type=str, default="")
    parser.add_argument("--branch", help="Test branch", type=str, default="")
    parser.add_argument("--prepare_time", help="Time for preparing testbeds", type=int, default=30)
    args = parser.parse_args()

    scripts = args.scripts
    topology = args.topology
    branch = args.branch
    prepare_time = args.prepare_time
    main(scripts, topology, branch, prepare_time)
