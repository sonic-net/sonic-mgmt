import os
import argparse
import math
from constant import PR_CHECKER_TOPOLOGY_NAME, MAX_INSTANCE_NUMBER
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


def main(scripts, topology, branch):
    ingest_cluster = os.getenv("TEST_REPORT_QUERY_KUSTO_CLUSTER_BACKUP")
    access_token = os.getenv('ACCESS_TOKEN', None)

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
