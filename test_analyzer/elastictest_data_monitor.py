import logging
import sys
import os
import json
from datetime import datetime, time, timedelta
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from azure.loganalytics import LogAnalyticsDataClient
from azure.loganalytics.models import QueryBody
from azure.core.credentials import AccessToken
from requests import Session


logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE = 'SonicTestData'
ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
cluster = ingest_cluster.replace('ingest-', '')
access_token = os.environ.get('ACCESS_TOKEN', None)
log_analytics_token = os.getenv("LOG_ANALYTICS_ACCESS_TOKEN")
workspace_id = os.getenv("ELASTICTEST_LOG_ANALYTICS_WORKSPACE_ID")
client_id = os.getenv("ELASTICTEST_MSAL_CLIENT_ID")
tenant_id = os.getenv("ELASTICTEST_MSAL_TENANT_ID")


def get_start_and_end_time():
    current_datetime = datetime.now()
    logger.info("Current datetime: {}, day: {}".format(current_datetime, current_datetime.day))
    delt_start_day = 0
    delt_end_day = 0

    timestamp_1 = time(0, 30, 0)
    timestamp_2 = time(4, 30, 0)
    timestamp_3 = time(8, 30, 0)
    timestamp_4 = time(12, 30, 0)
    timestamp_5 = time(16, 30, 0)
    timestamp_6 = time(20, 30, 0)

    if timestamp_1 <= current_datetime.time() < timestamp_2:        # 00:30 - 04:30, check 19:00 - 23:00
        start_hour = 19
        end_hour = 23
        delt_start_day = 1
        delt_end_day = 1
    elif timestamp_2 <= current_datetime.time() < timestamp_3:      # 04:30 - 08:30, check 23:00 - 03:00
        start_hour = 23
        end_hour = 3
        delt_start_day = 1
    elif timestamp_3 <= current_datetime.time() < timestamp_4:      # 08:30 - 12:30, check 03:00 - 07:00
        start_hour = 3
        end_hour = 7
    elif timestamp_4 <= current_datetime.time() < timestamp_5:      # 12:30 - 16:30, check 07:00 - 11:00
        start_hour = 7
        end_hour = 11
    elif timestamp_5 <= current_datetime.time() < timestamp_6:      # 16:30 - 20:30, check 11:00 - 15:00
        start_hour = 11
        end_hour = 15
    elif timestamp_6 <= current_datetime.time():                    # 20:30 - 23:59, check 15:00 - 19:00
        start_hour = 15
        end_hour = 19
    elif time(0, 0, 0) <= current_datetime.time() < timestamp_1:    # 00:00 - 00:30, check 15:00 - 19:00
        start_hour = 15
        end_hour = 19
        delt_start_day = 1
        delt_end_day = 1

    start_time = current_datetime.replace(hour=start_hour, minute=0, second=0, microsecond=0) - timedelta(days=delt_start_day)
    end_time = current_datetime.replace(hour=end_hour, minute=0, second=0, microsecond=0) - timedelta(days=delt_end_day)
    return start_time, end_time


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
    missing_test_plan = list(set(test_plans_log_analytics) - set(test_plans_kusto))
    more_test_plan = list(set(test_plans_kusto) - set(test_plans_log_analytics))

    available_test_plan = list(set(test_plans_log_analytics) & set(test_plans_kusto))
    unique_available_test_plan = []
    for item in available_test_plan:
        if item not in unique_available_test_plan:
            unique_available_test_plan.append(item)

    logger.info("Available test plan: {}".format(unique_available_test_plan))
    return unique_available_test_plan, missing_test_plan, more_test_plan, duplicate_plan_log_analytics, duplicate_plan_kusto


# -----------------------Test Bed ----------------------- #
def get_test_beds_from_log_analytics(client_loganalytics, test_plan):
    query = '''
        AppServiceConsoleLogs
        | where ResultDescription has "log_in_kusto"
        | where ResultDescription has "[test_bed]"
        | project parse_json(tostring(split(ResultDescription, '>>>', 3)[0]))
        | project TestPlanId=tostring(ResultDescription_0.TestPlanId), TestbedId=tostring(ResultDescription_0.TestbedId), 
        TestbedName=tostring(ResultDescription_0.TestbedName), UpdateTime = todatetime(ResultDescription_0.UpdateTime)
        | extend UpdateTimeString = format_datetime(UpdateTime, 'yyyy-MM-dd HH:mm:ss.fffffff')
        | where TestPlanId == '{}'
        | project TestPlanId, TestbedId, TestbedName, UpdateTimeString
        '''.format(test_plan)
    test_bed_query = QueryBody(query=query)
    query_result = client_loganalytics.query(workspace_id, test_bed_query).as_dict()['tables'][0]['rows']
    test_bed_log_analytics = []
    for item in query_result:
        test_case = {
            'TestPlanId': item[0],
            'TestbedId': item[1],
            'TestbedName': item[2],
            'UpdateTimeString': item[3]
        }
        test_bed_log_analytics.append(test_case)
    duplicate_data = find_duplicate_data(test_bed_log_analytics)
    return test_bed_log_analytics, duplicate_data


def get_test_beds_from_kusto(client_kusto, test_plan):
    query = '''
        TestBeds
        | where TestPlanId == '{}'
        | extend UpdateTimeString = format_datetime(UpdateTime, 'yyyy-MM-dd HH:mm:ss.fffffff')
        | project TestPlanId, TestbedId, TestbedName, UpdateTimeString
        '''.format(test_plan)
    query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    test_bed_kusto = query_result
    duplicate_data = find_duplicate_data(test_bed_kusto)
    return test_bed_kusto, duplicate_data


def compare_test_beds(client_kusto, client_loganalytics, test_plan):
    test_beds_log_analytics, duplicate_testbed_log_analytics = get_test_beds_from_log_analytics(client_loganalytics, test_plan)
    test_beds_kusto, duplicate_testbed_kusto = get_test_beds_from_kusto(client_kusto, test_plan)
    missing_testbed, more_testbed = get_diff_dict_list(test_beds_log_analytics, test_beds_kusto)
    return missing_testbed, more_testbed, duplicate_testbed_log_analytics, duplicate_testbed_kusto


# ----------------------- Test Summary ----------------------- #
def get_test_summary_from_log_analytics(client_loganalytics, test_plan):
    query = '''
        AppServiceConsoleLogs
        | where ResultDescription has "log_in_kusto"
        | where ResultDescription has "[test_summary]"
        | project parse_json(tostring(split(ResultDescription, '>>>', 3)[0]))
        | project TestPlanId=tostring(ResultDescription_0.TestPlanId), TotalRuntime=todouble(ResultDescription_0.TotalRuntime)
        | where TestPlanId == '{}'
        | extend TotalRuntimeDouble = round(TotalRuntime, 3)
        | project TestPlanId, TotalRuntimeDouble
        '''.format(test_plan)
    test_summay_query = QueryBody(query=query)
    query_result = client_loganalytics.query(workspace_id, test_summay_query).as_dict()['tables'][0]['rows']
    test_summary_log_analytics = []
    for item in query_result:
        test_case = {
            'TestPlanId': item[0],
            'TotalRuntimeDouble': item[1]
        }
        test_summary_log_analytics.append(test_case)
    duplicate_data = find_duplicate_data(test_summary_log_analytics)
    return test_summary_log_analytics, duplicate_data


def get_test_summary_from_kusto(client_kusto, test_plan):
    query = '''
        TestPlanSummary
        | where TestPlanId == '{}'
        | extend TotalRuntimeDouble = round(TotalRuntime, 3)
        | project TestPlanId, TotalRuntimeDouble
        '''.format(test_plan)
    query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    test_summary_kusto = query_result
    duplicate_data = find_duplicate_data(test_summary_kusto)
    return test_summary_kusto, duplicate_data


def compare_test_summary(client_kusto, client_loganalytics, test_plan):
    test_summary_log_analytics_len, duplicate_summary_log_analytics = get_test_summary_from_log_analytics(client_loganalytics, test_plan)
    test_summary_kusto_len, duplicate_summary_kusto = get_test_summary_from_kusto(client_kusto, test_plan)
    missing_test_summary, more_test_summary = get_diff_dict_list(test_summary_log_analytics_len, test_summary_kusto_len)
    return missing_test_summary, more_test_summary, duplicate_summary_log_analytics, duplicate_summary_kusto


# ----------------------- Test Case ----------------------- #
def get_test_cases_from_log_analytics(client_loganalytics, test_plan):
    query = '''
        AppServiceConsoleLogs
        | where ResultDescription has "log_in_kusto"
        | where ResultDescription has "[test_case]"
        | project parse_json(tostring(split(ResultDescription, '>>>', 3)[0])), TimeGenerated
        | project TestPlanId=tostring(ResultDescription_0.TestPlanId), TestCase=tostring(ResultDescription_0.name), 
        ModulePath=tostring(ResultDescription_0.classname), 
        StartTime=todatetime(ResultDescription_0.start), EndTime=todatetime(ResultDescription_0.end)
        | where TestPlanId == '{}'
        | extend StartTimeString = format_datetime(StartTime, 'yyyy-MM-dd HH:mm:ss.fffffff'), EndTimeString = format_datetime(EndTime, 'yyyy-MM-dd HH:mm:ss.fffffff')
        | project TestCase, ModulePath, StartTimeString, EndTimeString
        '''.format(test_plan)
    test_case_query = QueryBody(query=query)
    query_result = client_loganalytics.query(workspace_id, test_case_query).as_dict()['tables'][0]['rows']
    test_cases_log_analytics = []
    for item in query_result:
        test_case = {
            'TestCase': item[0],
            'ModulePath': item[1],
            'StartTimeString': item[2],
            'EndTimeString': item[3]
        }
        test_cases_log_analytics.append(test_case)
    duplicate_data = find_duplicate_data(test_cases_log_analytics)
    return test_cases_log_analytics, duplicate_data


def get_test_cases_from_kusto(client_kusto, test_plan):
    query = '''
        V2TestCases
        | where TestPlanId == '{}'
        | extend StartTimeString = format_datetime(StartTime, 'yyyy-MM-dd HH:mm:ss.fffffff'), EndTimeString = format_datetime(EndTime, 'yyyy-MM-dd HH:mm:ss.fffffff')
        | project TestCase, ModulePath, StartTimeString, EndTimeString
        '''.format(test_plan)
    query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    test_cases_kusto = query_result
    duplicate_data = find_duplicate_data(test_cases_kusto)
    return test_cases_kusto, duplicate_data


def compare_test_cases(client_kusto, client_loganalytics, test_plan):
    test_cases_log_analytics, duplicate_cases_log_analytics = get_test_cases_from_log_analytics(client_loganalytics, test_plan)
    test_cases_kusto, duplicate_cases_kusto = get_test_cases_from_kusto(client_kusto, test_plan)
    missing_test_cases, more_test_cases = get_diff_dict_list(test_cases_log_analytics, test_cases_kusto)
    return missing_test_cases, more_test_cases, duplicate_cases_log_analytics, duplicate_cases_kusto


def find_duplicate_data(data_list):
    duplicate_data = []
    for item in data_list:
        if data_list.count(item) > 1:
            duplicate_data.append(item)
    return duplicate_data


def get_diff_dict_list(log_analytic_data, kusto_data):
    missing_data = []
    more_data = []
    for item in log_analytic_data:
        if item not in kusto_data:
            missing_data.append(item)
    for item in kusto_data:
        if item not in log_analytic_data:
            more_data.append(item)
    return missing_data, more_data


def add_data_to_dict(data_dict, testplan, key, value):
    if testplan not in data_dict:
        data_dict[testplan] = {}
    data_dict[testplan][key] = value
    return data_dict


class AccessTokenCredential:
    def __init__(self, token):
        self.token = token

    def get_token(self):
        return AccessToken(self.token, float('inf'))

    def signed_session(self, session=None):
        if not session:
            session = self.create_session()
        session.headers.update({
            "Authorization": f"Bearer {self.token}"
        })
        return session

    def create_session(self):
        return Session()


def main():
    kusto_conn_str_builder = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster, access_token)
    client_kusto = KustoClient(kusto_conn_str_builder)
    credentials = AccessTokenCredential(log_analytics_token)
    client_loganalytics = LogAnalyticsDataClient(credentials, base_url=None)

    missing_data = {}
    more_data = {}
    duplicate_log_analytic = {}
    duplicate_kusto = {}

    start_time, end_time = get_start_and_end_time()
    logger.info("Compare start time: {}, end time: {}".format(start_time, end_time))

    # Compare test plan
    available_test_plan, missing_test_plan, more_test_plan, duplicate_plan_log_analytics, duplicate_plan_kusto = compare_test_plans(client_kusto, client_loganalytics, start_time, end_time)
    if len(missing_test_plan) > 0:
        for test_plan in missing_test_plan:
            missing_data[test_plan] = {}
            missing_data[test_plan]['missing_testplan'] = test_plan
        logger.info("Missing test plan in Kusto: {}".format(missing_test_plan))
    if len(more_test_plan) > 0:
        for test_plan in more_test_plan:
            more_data[test_plan] = {}
            more_data[test_plan]['more_testplan'] = test_plan
        logger.info("More test plan in Kusto: {}".format(more_test_plan))
    if len(duplicate_plan_log_analytics) > 0:
        for test_plan in duplicate_plan_log_analytics:
            duplicate_log_analytic[test_plan] = {}
            duplicate_log_analytic[test_plan]['duplicate_testplan'] = test_plan
        logger.info("Got duplicate test plan in log analytics: {}".format(duplicate_plan_log_analytics))
    if len(duplicate_plan_kusto) > 0:
        for test_plan in duplicate_kusto:
            duplicate_kusto[test_plan] = {}
            duplicate_kusto[test_plan]['duplicate_testplan'] = test_plan
        logger.info("Got duplicate test plan in Kusto: {}".format(duplicate_plan_kusto))

    for test_plan in available_test_plan:
        logger.info("Compare test plan: {}".format(test_plan))
        # Compare test bed
        missing_testbed, more_testbed, duplicate_testbed_log_analytics, duplicate_testbed_kusto = compare_test_beds(client_kusto, client_loganalytics, test_plan)
        if len(missing_testbed) > 0:
            add_data_to_dict(missing_data, test_plan, 'missing_testbed', missing_testbed)
            logger.info("Missing testbed log in test plan {}, testbed: {}".format(test_plan, missing_testbed))
        if len(more_testbed) > 0:
            add_data_to_dict(more_data, test_plan, 'more_testbed', more_testbed)
            logger.info("More testbed log in test plan {}, testbed: {}".format(test_plan, more_testbed))
        if len(duplicate_testbed_log_analytics) > 0:
            add_data_to_dict(duplicate_log_analytic, test_plan, 'duplicate_testbed', duplicate_testbed_log_analytics)
            logger.info("Got duplicate testbed log in test plan {} in log analytics, testbed: {}".format(test_plan, duplicate_testbed_log_analytics))
        if len(duplicate_testbed_kusto) > 0:
            add_data_to_dict(duplicate_kusto, test_plan, 'duplicate_testbed', duplicate_testbed_kusto)
            logger.info("Got duplicate testbed log in test plan {} in Kusto, testbed: {}".format(test_plan, duplicate_testbed_kusto))

        # Compare test summary
        missing_summary, more_summary, duplicate_summary_log_analytics, duplicate_summary_kusto = compare_test_summary(client_kusto, client_loganalytics, test_plan)
        if len(missing_summary) > 0:
            add_data_to_dict(missing_data, test_plan, 'missing_testsummary', missing_summary)
            logger.info("Missing test summary in test plan {}, summary: {}".format(test_plan, missing_summary))
        if len(more_summary) > 0:
            add_data_to_dict(more_data, test_plan, 'more_testsummary', more_summary)
            logger.info("More test summary in test plan {}, summary: {}".format(test_plan, more_summary))
        if len(duplicate_summary_log_analytics) > 0:
            add_data_to_dict(duplicate_log_analytic, test_plan, 'duplicate_testsummary', duplicate_summary_log_analytics)
            logger.info("Got duplicate test summary in test plan {} in log analytics, summary: {}".format(test_plan, duplicate_summary_log_analytics))
        if len(duplicate_summary_kusto) > 0:
            add_data_to_dict(duplicate_kusto, test_plan, 'duplicate_testsummary', duplicate_summary_kusto)
            logger.info("Got duplicate test summary in test plan {} in Kusto, summary: {}".format(test_plan, duplicate_summary_kusto))

        # Compare test case
        missing_test_cases, more_test_cases, duplicate_cases_log_analytics, duplicate_cases_kusto = compare_test_cases(client_kusto, client_loganalytics, test_plan)
        if len(missing_test_cases) > 0:
            add_data_to_dict(missing_data, test_plan, 'missing_testcase', missing_test_cases)
            logger.info("Missing testcase in test plan {}, testcase: {}".format(test_plan, missing_test_cases))
        if len(more_test_cases) > 0:
            add_data_to_dict(more_data, test_plan, 'more_testcase', more_test_cases)
            logger.info("More testcase in test plan {}, testcase: {}".format(test_plan, more_test_cases))
        if len(duplicate_cases_log_analytics) > 0:
            add_data_to_dict(duplicate_log_analytic, test_plan, 'duplicate_testcase', duplicate_cases_log_analytics)
            logger.info("Got duplicate testcase in test plan {} in log analytics, testcase: {}".format(test_plan, duplicate_cases_log_analytics))
        if len(duplicate_cases_kusto) > 0:
            add_data_to_dict(duplicate_kusto, test_plan, 'duplicate_testcase', duplicate_cases_kusto)
            logger.info("Got duplicate testcase in test plan {} in Kusto, testcase: {}".format(test_plan, duplicate_cases_kusto))

    result = {}
    result['missing_data'] = missing_data
    result['more_data'] = more_data
    result['duplicate_log_analytic_data'] = duplicate_log_analytic
    result['duplicate_kusto_data'] = duplicate_kusto
    json_formatted_result = json.dumps(result, indent=4)
    logger.info("############################## Final result ##############################")
    logger.info("{}".format(json_formatted_result))

    assert len(missing_data) == 0 and len(more_data) == 0, "Got missing data or more data, fail this pipeline"


if __name__ == '__main__':
    main()
