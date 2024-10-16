import logging
import sys
import os
import requests
import argparse
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from analyze_test_result import RC, is_current_pass_rate_ok

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

elastictest_community_url = os.getenv('ELASTICTEST_COMMUNITY_URL')
DATABASE = 'SonicTestData'
ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
cluster = ingest_cluster.replace('ingest-', '')
access_token = os.environ.get('ACCESS_TOKEN', None)


def get_history_pass_rate(client_kusto):
    query = '''
        TestPlans
        | where EndTime > ago(30d)
        | join kind=leftouter TestPlanSummary on TestPlanId
        | where TestPlanName contains "SmokeTest"
        | where TestPlanType == "NIGHTLY"
        | where CreatedByType == "NIGHTLY"
        | distinct TestPlanId, TotalCasesRun, Passes, Failures, Errors, Xfails, EndTime
        | order by EndTime desc
        | take 3
        '''
    query_result = client_kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    pass_rates = []
    for item in query_result:
        total_tests = item['Passes'] + item['Failures'] + item['Xfails']
        if total_tests == 0:
            continue
        pass_rate = item['Passes'] / total_tests
        pass_rates.append(pass_rate)
    return pass_rates


def get_test_plan_status(test_plan_id):
    poll_url = f"{elastictest_community_url}/get_test_plan_status/{test_plan_id}"
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.get(poll_url, headers=headers)

    logger.info(f"Get test plan status from elastictest-scheduler: resp={response}")
    response = response.json()

    if not response['success']:
        logger.error(
            f"Get test plan {test_plan_id} status failed with error: {response['errmsg']}")
        raise RuntimeError(f"Get test plan {test_plan_id} status failed with error: {response['errmsg']}")

    test_plan_status = response['data']

    if test_plan_status:
        test_plan_summary = test_plan_status.get("runtime", {}).get("test_summary", "")
        logger.info(f"Get test plan {test_plan_id} data: {test_plan_summary}")
        return test_plan_summary
    else:
        raise RuntimeError(f"Get test plan {test_plan_id} data failed")


def get_current_pass_rate(test_plan_summary):
    count_passes = int(test_plan_summary['passes'])
    count_failures = int(test_plan_summary['failures'])
    count_xfails = int(test_plan_summary['xfails'])

    total_tests = count_passes + count_failures + count_xfails
    pass_rate = count_passes / total_tests
    return total_tests, pass_rate


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     description="Analyze test result")
    parser.add_argument('-i', '--test-plan-id',
        type=str,
        dest='test_plan_id',
        required=True,
        help='Test report json file.'
    )
    parser.add_argument('-m', '--min-passing-rate',
        type=int,
        dest='min_passing_rate',
        default=60,
        help='The int will used as percentage. For example, 3 means 3%.'
             'This argument specifies the minimum passing rate. If the current passing rate is below than this number,'
             'then the test results would be unacceptable.'
    )
    parser.add_argument('-t', '--passing-rate-tolerance',
        type=int,
        dest='passing_rate_tolerance',
        default=3,
        help='The int will used as percentage. For example, 3 means 3%.'
             'This argument specifies the allowed passing rate dropping. If the average history passing rate is 95%,'
             'and this parameter is 3, then current passing rate 91% would not be acceptable.'
    )
    args = parser.parse_args()
    kusto_conn_str_builder = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster, access_token)
    client_kusto = KustoClient(kusto_conn_str_builder)

    thresholds = {
        'TESTED_CASES': 200,
        'MIN_PASSING_RATE': args.min_passing_rate / 100.0,
        'TOLERANCE': args.passing_rate_tolerance / 100.0
    }

    test_plan_summary = get_test_plan_status(args.test_plan_id)
    total_tests, current_pass_rate = get_current_pass_rate(test_plan_summary)
    if total_tests < thresholds['TESTED_CASES']:
        logger.error('Total tested cases {} is less than threshold: {}'.format(total_tests, thresholds['TESTED_CASES']))
        sys.exit(RC.LOW_TESTED_CASES)

    history_pass_rates = get_history_pass_rate(client_kusto)
    logger.info('Current pass_rate {:.2f}'.format(current_pass_rate))
    logger.info('History pass rate: {}'.format(history_pass_rates))

    result = is_current_pass_rate_ok(current_pass_rate, history_pass_rates, thresholds)
    logger.info('Result of analyzing test results: {} - {}'.format(result, RC.meaning(result)))
    sys.exit(result)


if __name__ == '__main__':
    main()
