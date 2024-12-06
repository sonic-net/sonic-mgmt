import os
import argparse
import math
import subprocess
import json
from datetime import datetime, timezone
from constant import PR_CHECKER_TOPOLOGY_NAME, MAX_INSTANCE_NUMBER, MAX_GET_TOKEN_RETRY_TIMES
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient


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


def run_cmd(cmd):
    process = subprocess.Popen(
        cmd.split(),
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    return_code = process.returncode

    if return_code != 0:
        raise Exception(f'Command {cmd} execution failed, rc={return_code}, error={stderr}')
    return stdout, stderr, return_code


def get_access_token():
    managed_identity_id = os.environ.get("SONIC_AUTOMATION_UMI")

    # 1. Run az login with re-try
    az_login_cmd = f"az login --identity --username {managed_identity_id}"
    az_login_attempts = 0
    while az_login_attempts < MAX_GET_TOKEN_RETRY_TIMES:
        try:
            stdout, _, _ = run_cmd(az_login_cmd)
            print(f"Az login successfully. Login time: {datetime.now(timezone.utc)}")
            break
        except Exception as exception:
            az_login_attempts += 1
            print(
                f"Failed to az login with exception: {repr(exception)}. "
                f"Retry {MAX_GET_TOKEN_RETRY_TIMES - az_login_attempts} times to login."
            )

    # If az login failed, return with exception
    if az_login_attempts >= MAX_GET_TOKEN_RETRY_TIMES:
        raise Exception(f"Failed to az login after {MAX_GET_TOKEN_RETRY_TIMES} attempts.")

    # 2. Get access token with re-try
    get_token_cmd = "az account get-access-token ---resource https://api.kusto.windows.net --query accessToken -o tsv"
    get_token_attempts = 0
    while get_token_attempts < MAX_GET_TOKEN_RETRY_TIMES:
        try:
            stdout, _, _ = run_cmd(get_token_cmd)

            token = json.loads(stdout.decode("utf-8"))
            access_token = token.get("accessToken", None)
            if not access_token:
                raise Exception("Parse token from stdout failed, accessToken is None.")

            # Parse token expires time from string
            token_expires_on = token.get("expiresOn", "")
            if token_expires_on:
                print(f"Get token successfully. Token will expire on {token_expires_on}.")

            return access_token

        except Exception as exception:
            get_token_attempts += 1
            print(f"Failed to get token with exception: {repr(exception)}.")

    # If az get token failed, return with exception
    if get_token_attempts >= MAX_GET_TOKEN_RETRY_TIMES:
        raise Exception(f"Failed to get token after {MAX_GET_TOKEN_RETRY_TIMES} attempts")
    pass


def main(scripts, topology, branch):
    ingest_cluster = os.getenv("TEST_REPORT_QUERY_KUSTO_CLUSTER_BACKUP")
    access_token = get_access_token()

    if not ingest_cluster or not access_token:
        raise RuntimeError(
            "Could not load Kusto Credentials from environment")
    else:
        kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(ingest_cluster,
                                                                                      access_token)  # noqa F841

    client = KustoClient(kcsb)

    scripts = parse_list_from_str(scripts)

    scripts_running_time = {}
    total_running_time = 0

    for script in scripts:
        # As baseline test is the universal set of PR test
        # we get the historical running time of one script here
        # We get recent 5 test plans and calculate the average running time
        query = "V2TestCases " \
                "| join kind=inner" \
                "(TestPlans " \
                "| where TestPlanType == 'PR' and Result == 'FINISHED' and Topology == '{}' " \
                "and TestBranch == '{}' and TestPlanName contains '{}' " \
                "and TestPlanName contains '_BaselineTest_'" \
                "| order by UploadTime desc | take 5) on TestPlanId " \
                "| where FilePath == '{}' " \
                "| summarize sum(Runtime)".format(PR_CHECKER_TOPOLOGY_NAME[topology][0], branch,
                                                  PR_CHECKER_TOPOLOGY_NAME[topology][1], script)
        response = client.execute("SonicTestData", query)

        average_running_time = 1800

        for row in response.primary_results[0]:
            # We have obtained the results of the most recent five times.
            # To get the result for a single time, we need to divide by five
            # If response.primary_results is None, which means where is no historical data in Kusto,
            # we will use the default 1800s for a script.
            average_running_time = row["sum_Runtime"] / 5

        total_running_time += average_running_time
        scripts_running_time[script] = average_running_time
    # Total running time is calculated by seconds, divide by 60 to get minutes
    # For one instance, we plan to assign 90 minutes to run test scripts
    # Obtain the number of instances by rounding up the calculation.
    # To prevent unexpected situations, we set the maximum number of instance
    print(min(math.ceil(total_running_time / 60 / 90), MAX_INSTANCE_NUMBER))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", help="The topology of testplan", type=str, default="")
    parser.add_argument("--scripts", help="Test scripts to be executed", type=str, default="")
    parser.add_argument("--branch", help="Test branch", type=str, default="")
    args = parser.parse_args()

    scripts = args.scripts
    topology = args.topology
    branch = args.branch
    main(scripts, topology, branch)
