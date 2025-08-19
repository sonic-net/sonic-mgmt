from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from azure.kusto.ingest import QueuedIngestClient, IngestionProperties
from azure.kusto.data.data_format import DataFormat
from azure.kusto.data.helpers import dataframe_from_result_table
import pandas as pd
from datetime import time, datetime, timedelta
import os
import sys
import logging
import argparse

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

# Kusto connection settings
DATABASE = 'SonicTestData'
NEWTABLE = 'PRTestCaseResultSummary'
ingest_cluster = os.getenv("KUSTO_CLUSTER_INGEST_URL")
cluster = ingest_cluster.replace('ingest-', '')
access_token = os.environ.get('ACCESS_TOKEN', None)

# Classify result types
result_mapping = {
    "success": "SuccessCount",
    "failure": "FailureCount",
    "error": "ErrorCount",
    "skipped": "SkipCount"
}


def get_start_and_end_time():
    current_datetime = datetime.now()
    logger.info("Current datetime: {}, day: {}".format(current_datetime, current_datetime.day))
    delt_start_day = 0
    delt_end_day = 0

    timestamp_1 = time(1, 30, 0)
    timestamp_2 = time(5, 30, 0)
    timestamp_3 = time(9, 30, 0)
    timestamp_4 = time(13, 30, 0)
    timestamp_5 = time(17, 30, 0)
    timestamp_6 = time(21, 30, 0)

    if timestamp_1 <= current_datetime.time() < timestamp_2:        # 01:30 - 05:30, query 20:00 - 00:00
        start_hour = 20
        end_hour = 0
        delt_start_day = 1
    elif timestamp_2 <= current_datetime.time() < timestamp_3:      # 05:30 - 09:30, query 00:00 - 04:00
        start_hour = 0
        end_hour = 4
    elif timestamp_3 <= current_datetime.time() < timestamp_4:      # 09:30 - 13:30, query 04:00 - 08:00
        start_hour = 4
        end_hour = 8
    elif timestamp_4 <= current_datetime.time() < timestamp_5:      # 13:30 - 17:30, query 08:00 - 12:00
        start_hour = 8
        end_hour = 12
    elif timestamp_5 <= current_datetime.time() < timestamp_6:      # 17:30 - 21:30, query 12:00 - 16:00
        start_hour = 12
        end_hour = 16
    elif timestamp_6 <= current_datetime.time():                    # 21:30 - 24:00, query 16:00 - 20:00
        start_hour = 16
        end_hour = 20
    elif time(0, 0, 0) <= current_datetime.time() < timestamp_1:    # 00:00 - 01:30, query 16:00 - 20:00
        start_hour = 16
        end_hour = 20
        delt_start_day = 1
        delt_end_day = 1

    start_time = current_datetime.replace(hour=start_hour, minute=0, second=0, microsecond=0) - timedelta(days=delt_start_day)
    end_time = current_datetime.replace(hour=end_hour, minute=0, second=0, microsecond=0) - timedelta(days=delt_end_day)
    return start_time, end_time


def get_pr_test_plans(kusto_client, start_time, end_time):
    query = f'''
    TestPlans
    | where TestPlanType == "PR"
    | where CreatedByType == "PR"
    | where TestPlanName !contains "optional"
    | where EndTime between (datetime({start_time}) .. datetime({end_time}))
    | join kind=leftouter TestBeds on TestPlanId
    | extend RunDate = todatetime(format_datetime(EndTime, "yyyy-MM-dd"))
    | extend TestType = case(
        TestPlanName matches regex "Baseline", "Baseline",
        "PR"
    )
    | distinct TestPlanId, TestType, TestbedName, Topology, TestBranch, RunDate
    '''
    query_result = kusto_client.execute_query(DATABASE, query)
    testplans_df = dataframe_from_result_table(query_result.primary_results[0])
    testplans = query_result.primary_results[0].to_dict()['data']
    testplan_ids = [item['TestPlanId'] for item in testplans]
    return testplans_df, testplan_ids


def get_pr_test_cases(kusto_client, testplan_ids):
    testplan_string = "({})".format(", ".join(f"'{item}'" for item in testplan_ids))
    query = f"""
    V2TestCases
    | where TestPlanId in {testplan_string}
    | extend TestCase = extract("^(.+?)(\\\\[|$)", 1, TestCase)
    | where Result in ("success", "failure", "error", "skipped")
    | project TestPlanId, FilePath, ModulePath, TestCase, Result
    """
    query_result = kusto_client.execute_query(DATABASE, query)
    testcases_df = dataframe_from_result_table(query_result.primary_results[0])
    logger.info(f"Test cases length: {len(testcases_df)}")
    return testcases_df


def merge_test_data(testplans_df, testcases_df):
    merged_df = pd.merge(
        testcases_df,
        testplans_df,
        on="TestPlanId",
        how="left"
    )
    # Group by the specified keys and count the Result occurrences
    agg_df = (
        merged_df.groupby(["TestBranch", "TestType", "TestbedName", "FilePath", "ModulePath", "TestCase", "RunDate"])["Result"]
        .value_counts()
        .unstack(fill_value=0)
        .reset_index()
    )

    # Rename columns
    agg_df = agg_df.rename(columns={
        "TestBranch": "Branch",
        "success": "SuccessCount",
        "failure": "FailureCount",
        "error": "ErrorCount",
        "skipped": "SkipCount"
    })

    agg_df["TotalCount"] = agg_df[list(result_mapping.values())].sum(axis=1)
    agg_df["UploadTime"] = datetime.now()
    csv_file = "PRTestSuccessRate.csv"
    agg_df.to_csv(csv_file, index=False)
    return csv_file


def Ingest_to_new_table(ingest_client, csv_file):
    # Ingest into Kusto
    ingestion_props = IngestionProperties(
        database=DATABASE,
        table=NEWTABLE,
        data_format=DataFormat.CSV,
        additional_properties={"ignoreFirstRecord": "true"}
    )
    ingest_client.ingest_from_file(csv_file, ingestion_properties=ingestion_props)
    logger.info("Ingestion completed.")


def main(start_time, end_time):
    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster, access_token)
    kusto_client = KustoClient(kcsb)
    ingest_client = QueuedIngestClient(kcsb)

    testplans_df, testplan_ids = get_pr_test_plans(kusto_client, start_time, end_time)
    testcases_df = get_pr_test_cases(kusto_client, testplan_ids)
    agg_csv = merge_test_data(testplans_df, testcases_df)
    Ingest_to_new_table(ingest_client, agg_csv)


def normalize_arg(value):
    if value in [None, "", "null", "None"]:
        return None
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Analyze test result")

    parser.add_argument(
        "--start_time",
        type=str,
        dest="start_time",
        required=False,
        default=None,
        help="Start time of test plan ends",
    )
    parser.add_argument(
        "--end_time",
        type=str,
        dest="end_time",
        required=False,
        default=None,
        help="End time of test plan ends",
    )
    args = parser.parse_args()

    start_time = normalize_arg(args.start_time)
    end_time = normalize_arg(args.end_time)
    if start_time and end_time:
        start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_time = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
    else:
        start_time, end_time = get_start_and_end_time()
    logger.info(f"Start Time: {start_time}, End Time: {end_time}")

    main(start_time, end_time)
