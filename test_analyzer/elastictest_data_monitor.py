import logging
import sys
import os
from datetime import datetime, timedelta
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from azure.loganalytics import LogAnalyticsDataClient
from azure.loganalytics.models import QueryBody
from azure.common.credentials import ServicePrincipalCredentials

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'SonicTestData'
ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
cluster = ingest_cluster.replace('ingest-', '')
tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID_BACKUP")
service_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID_BACKUP")
service_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY_BACKUP")
workspace_id = os.getenv("ELASTICTEST_LOG_ANALYTICS_WORKSPACE_ID")
client_id = os.getenv("ELASTICTEST_MSAL_CLIENT_ID")
client_secret = os.getenv("ELASTICTEST_MSAL_CLIENT_SECRET")
tenant_id = os.getenv("ELASTICTEST_MSAL_TENANT_ID")


# ----------------------- Test Plan ----------------------- #
def get_test_plans_from_log_analytics(client_loganalytics, start_time, end_time):
    query = '''
        AppServiceConsoleLogs
        | where ResultDescription has "[log_in_kusto]" 
        | where ResultDescription has "[test_plan]" 
        | project parse_json(tostring(split(ResultDescription, '>>>', 3)[0]))
        | project TestPlanId=tostring(ResultDescription_0.TestPlanId), EndTime=todatetime(ResultDescription_0.EndTime)
        | where EndTime between (datetime({}) .. datetime({}))
        | project TestPlanId
        '''.format(start_time, end_time)
    test_plan_query = QueryBody(query=query)
    query_result = client_loganalytics.query(workspace_id, test_plan_query).as_dict()['tables'][0]['rows']
    test_plans_query_result = [test_plan[0] for test_plan in query_result]
    test_plans_log_analytics = []
    for test_plan in test_plans_query_result:
        test_plans_log_analytics.append(test_plan)
    duplicate_data = find_duplicate_data(test_plans_log_analytics)
    return test_plans_log_analytics, duplicate_data


def get_test_plans_from_kusto(client_kusto, start_time, end_time):
    query = '''
        TestPlans
        | where EndTime between (datetime({}) .. datetime({}))
        | project TestPlanId
        '''.format(start_time, end_time)
    query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    test_plans_kusto = []
    for item in query_result:
        test_plans_kusto.append(item['TestPlanId'])
    duplicate_data = find_duplicate_data(test_plans_kusto)
    return test_plans_kusto, duplicate_data


def compare_test_plans(client_kusto, client_loganalytics, start_time, end_time):
    test_plans_log_analytics, duplicate_plan_log_analytics = get_test_plans_from_log_analytics(client_loganalytics, start_time, end_time)
    test_plans_kusto, duplicate_plan_kusto = get_test_plans_from_kusto(client_kusto, start_time, end_time)

    missing_test_plan = []
    for test_plan in test_plans_log_analytics:
        if test_plan not in test_plans_kusto:
            missing_test_plan.append(test_plan)

    more_test_plan = []
    for test_plan in test_plans_kusto:
        if test_plan not in test_plans_log_analytics:
            more_test_plan.append(test_plan)

    available_test_plan = list(set(test_plans_log_analytics) & set(test_plans_kusto))
    return available_test_plan, missing_test_plan, more_test_plan, duplicate_plan_log_analytics, duplicate_plan_kusto


# -----------------------Test Bed ----------------------- #
def get_test_beds_from_log_analytics(client_loganalytics, test_plan):
    query = '''
        AppServiceConsoleLogs
        | where ResultDescription has "log_in_kusto"
        | where ResultDescription has "[test_bed]"
        | project parse_json(tostring(split(ResultDescription, '>>>', 3)[0]))
        | project TestPlanId=tostring(ResultDescription_0.TestPlanId), TestbedName=tostring(ResultDescription_0.TestbedName), UpdateTime = todatetime(ResultDescription_0.UpdateTime)
        | extend UpdateTimeString = format_datetime(UpdateTime, 'yyyy-MM-dd HH:mm:ss')
        | where TestPlanId == '{}'
        | project TestPlanId, TestbedName, UpdateTimeString
        '''.format(test_plan)
    test_bed_query = QueryBody(query=query)
    query_result = client_loganalytics.query(workspace_id, test_bed_query).as_dict()['tables'][0]['rows']
    test_bed_log_analytics = []
    for item in query_result:
        test_case = {
            'TestPlanId': item[0],
            'TestbedName': item[1],
            'UpdateTimeString': item[2]
        }
        test_bed_log_analytics.append(test_case)
    duplicate_data = find_duplicate_data(test_bed_log_analytics)
    return len(test_bed_log_analytics), len(duplicate_data)


def get_test_beds_from_kusto(client_kusto, test_plan):
    query = '''
        TestBeds
        | where TestPlanId == '{}'
        | project TestPlanId, TestbedName, UpdateTime
        '''.format(test_plan)
    query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    test_bed_kusto = query_result
    duplicate_data = find_duplicate_data(test_bed_kusto)
    return len(test_bed_kusto), len(duplicate_data)


def compare_test_beds(client_kusto, client_loganalytics, test_plan):
    test_beds_log_analytics, duplicate_testbed_log_analytics = get_test_beds_from_log_analytics(client_loganalytics, test_plan)
    test_beds_kusto, duplicate_testbed_kusto = get_test_beds_from_kusto(client_kusto, test_plan)
    diff_testbed = test_beds_log_analytics - test_beds_kusto
    return diff_testbed, duplicate_testbed_log_analytics, duplicate_testbed_kusto


# ----------------------- Test Summary ----------------------- #
def get_test_summary_from_log_analytics(client_loganalytics, test_plan):
    query = '''
        AppServiceConsoleLogs
        | where ResultDescription has "log_in_kusto"
        | where ResultDescription has "[test_summary]"
        | project parse_json(tostring(split(ResultDescription, '>>>', 3)[0]))
        | project TestPlanId=tostring(ResultDescription_0.TestPlanId), TotalRuntime=tostring(ResultDescription_0.TotalRuntime)
        | where TestPlanId == '{}'
        | project TestPlanId, TotalRuntime
        '''.format(test_plan)
    test_summay_query = QueryBody(query=query)
    query_result = client_loganalytics.query(workspace_id, test_summay_query).as_dict()['tables'][0]['rows']
    test_summary_log_analytics = []
    for item in query_result:
        test_case = {
            'TestPlanId': item[0],
            'TotalRuntime': item[1]
        }
        test_summary_log_analytics.append(test_case)
    duplicate_data = find_duplicate_data(test_summary_log_analytics)
    return len(test_summary_log_analytics), len(duplicate_data)


def get_test_summary_from_kusto(client_kusto, test_plan):
    query = '''
        TestPlanSummary
        | where TestPlanId == '{}'
        | project TestPlanId, TotalRuntime
        '''.format(test_plan)
    query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    test_summary_kusto = query_result
    duplicate_data = find_duplicate_data(test_summary_kusto)
    return len(test_summary_kusto), len(duplicate_data)


def compare_test_summary(client_kusto, client_loganalytics, test_plan):
    test_summary_log_analytics_len, duplicate_summary_log_analytics = get_test_summary_from_log_analytics(client_loganalytics, test_plan)
    test_summary_kusto_len, duplicate_summary_kusto = get_test_summary_from_kusto(client_kusto, test_plan)
    diff_summary = test_summary_log_analytics_len - test_summary_kusto_len
    return diff_summary, duplicate_summary_log_analytics, duplicate_summary_kusto


# ----------------------- Test Case ----------------------- #
def get_test_cases_from_log_analytics(client_loganalytics, test_plan):
    query = '''
        AppServiceConsoleLogs
        | where ResultDescription has "log_in_kusto"
        | where ResultDescription has "[test_case]"
        | project parse_json(tostring(split(ResultDescription, '>>>', 3)[0])), TimeGenerated
        | project TestPlanId=tostring(ResultDescription_0.TestPlanId), TestCase=tostring(ResultDescription_0.name), 
        Attempt=tostring(ResultDescription_0.attempt), StartTime=todatetime(ResultDescription_0.start), EndTime=todatetime(ResultDescription_0.end)
        | where TestPlanId == '{}'
        | extend StartTimeString = format_datetime(StartTime, 'yyyy-MM-dd HH:mm:ss'), EndTimeString = format_datetime(EndTime, 'yyyy-MM-dd HH:mm:ss')
        | project TestCase, Attempt, StartTimeString, EndTimeString
        '''.format(test_plan)
    test_case_query = QueryBody(query=query)
    query_result = client_loganalytics.query(workspace_id, test_case_query).as_dict()['tables'][0]['rows']
    test_cases_log_analytics = []
    for item in query_result:
        test_case = {
            'TestCase': item[0],
            'Attempt': int(item[1]),
            'StartTimeString': item[2],
            'EndTimeString': item[3]
        }
        test_cases_log_analytics.append(test_case)
    duplicate_data = find_duplicate_data(test_cases_log_analytics)
    duplicate_case_list = []
    for item in duplicate_data:
        duplicate_case_list.append(item['TestCase'])
    return test_cases_log_analytics, duplicate_case_list


def get_test_cases_from_kusto(client_kusto, test_plan):
    query = '''
        V2TestCases
        | where TestPlanId == '{}'
        | extend StartTimeString = format_datetime(StartTime, 'yyyy-MM-dd HH:mm:ss'), EndTimeString = format_datetime(EndTime, 'yyyy-MM-dd HH:mm:ss')
        | project TestCase, Attempt, StartTimeString, EndTimeString
        '''.format(test_plan)
    query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    test_cases_kusto = query_result
    duplicate_data = find_duplicate_data(test_cases_kusto)
    duplicate_data_list = []
    for item in duplicate_data:
        duplicate_data_list.append(item['TestCase'])
    return test_cases_kusto, duplicate_data_list


def compare_test_cases(client_kusto, client_loganalytics, test_plan):
    test_cases_log_analytics, duplicate_cases_log_analytics = get_test_cases_from_log_analytics(client_loganalytics, test_plan)
    test_cases_kusto, duplicate_cases_kusto = get_test_cases_from_kusto(client_kusto, test_plan)

    missing_test_cases = []
    for item in test_cases_log_analytics:
        if item not in test_cases_kusto:
            missing_test_cases.append(item)

    more_test_cases = []
    for item in test_cases_kusto:
        if item not in test_cases_log_analytics:
            more_test_cases.append(item)

    return missing_test_cases, more_test_cases, duplicate_cases_log_analytics, duplicate_cases_kusto


def find_duplicate_data(data_list):
    duplicate_data = []
    for item in data_list:
        if data_list.count(item) > 1:
            duplicate_data.append(item)
    return duplicate_data


def main():
    kusto_conn_str_builder = KustoConnectionStringBuilder.with_aad_application_key_authentication(cluster, service_id, service_key, tenant_id)
    client_kusto = KustoClient(kusto_conn_str_builder)
    credentials = ServicePrincipalCredentials(client_id=client_id, secret=client_secret, tenant=tenant_id, resource='https://api.loganalytics.io')
    client_loganalytics = LogAnalyticsDataClient(credentials, base_url=None)

    missing_data = []
    more_data = []
    duplicate_data = []
    current_time = datetime.now()
    current_hour = current_time.replace(minute=0, second=0, microsecond=0)
    start_time = current_hour - timedelta(hours=5)
    end_time = current_hour - timedelta(hours=1)

    # Compare test plan
    available_test_plan, missing_test_plan, more_test_plan, duplicate_plan_log_analytics, duplicate_plan_kusto = compare_test_plans(client_kusto, client_loganalytics, start_time, end_time)
    if len(missing_test_plan) > 0:
        missing_data.append("Missing test plan in Kusto: {}".format(missing_test_plan))
    if len(more_test_plan) > 0:
        more_data.append("More test plan in Kusto: {}".format(more_test_plan))
    if len(duplicate_plan_log_analytics) > 0:
        duplicate_data.append("Got duplicate test plan in log analytics: {}".format(duplicate_plan_log_analytics))
    if len(duplicate_plan_kusto) > 0:
        duplicate_data.append("Got duplicate test plan in Kusto: {}".format(duplicate_plan_kusto))

    for test_plan in available_test_plan:
        # Compare test bed
        diff_testbed, duplicate_testbed_log_analytics, duplicate_testbed_kusto = compare_test_beds(client_kusto, client_loganalytics, test_plan)
        if diff_testbed > 0:
            missing_data.append("Got different test bed log in test_plan {}, {} logs miss in Kusto".format(test_plan, diff_testbed))
        elif diff_testbed < 0:
            more_data.append("Got different test bed log in test_plan {}, {} logs more in Kusto".format(test_plan, diff_testbed))
        if duplicate_testbed_log_analytics > 0:
            duplicate_data.append("Got duplicate test bed log in test_plan {} in log analytics, log number: {}".format(test_plan, duplicate_testbed_log_analytics))
        if duplicate_testbed_kusto > 0:
            duplicate_data.append("Got duplicate test bed log in test_plan {} in Kusto, log number: {}".format(test_plan, duplicate_testbed_kusto))

        # Compare test summary
        diff_summary, duplicate_summary_log_analytics, duplicate_summary_kusto = compare_test_summary(client_kusto, client_loganalytics, test_plan)
        if diff_summary > 0:
            missing_data.append("Got different test summary in test_plan {}, {} logs miss in Kusto".format(test_plan, diff_summary))
        elif diff_summary < 0:
            more_data.append("Got different test summary in test_plan {}, {} logs more in Kusto".format(test_plan, diff_summary))
        if duplicate_summary_log_analytics > 0:
            duplicate_data.append("Got duplicate test summary in test_plan {} in log analytics, log number: {}".format(test_plan, duplicate_summary_log_analytics))
        if duplicate_summary_kusto > 0:
            duplicate_data.append("Got duplicate test summary in test_plan {} in Kusto, log number: {}".format(test_plan, duplicate_summary_kusto))

        # Compare test case
        missing_test_cases, more_test_cases, duplicate_cases_log_analytics, duplicate_cases_kusto = compare_test_cases(client_kusto, client_loganalytics, test_plan)
        if len(missing_test_cases) > 0:
            missing_data.append("Missing test case in test_plan {}, testcase list: {}".format(test_plan, missing_test_cases))
        if len(more_test_cases) > 0:
            more_data.append("More test case in test_plan {}, testcase list: {}".format(test_plan, more_test_cases))
        if len(duplicate_cases_log_analytics) > 0:
            duplicate_data.append("Got duplicate test case in test_plan {} in log analytics, testcase list: {}".format(test_plan, duplicate_cases_log_analytics))
        if len(duplicate_cases_kusto) > 0:
            duplicate_data.append("Got duplicate test case in test_plan {} in Kusto, testcase list: {}".format(test_plan, duplicate_cases_kusto))

    logger.info("Missing data:")
    for item in missing_data:
        logger.info(item)
    logger.info("More data:")
    for item in more_data:
        logger.info(item)
    logger.info("Duplicate data:")
    for item in duplicate_data:
        logger.info(item)

    assert len(missing_data) == 0 and len(more_data) == 0, "Got missing data or more data, fail this pipeline"


if __name__ == '__main__':
    main()
