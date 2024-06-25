#!/bin/env python3
'''Analyze test result

This tool accept a test result json file parsed from nightly test junit xml files as input.
Based on the metadata in the result file, it query Kusto test data to find out recent history test results of
same testbed and same branch. Take the most recent 3 runs.

If no history test data is found in Kusto, just return the passing rate of input test result file.

If history test data is found, sort the passing rate. Get average passing rate.
'''

from __future__ import print_function, division

import argparse
import json
import logging
import os
import sys

from azure.kusto.data import KustoConnectionStringBuilder, KustoClient

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s:%(name)s:%(lineno)d %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


DATABASE = 'SonicTestData'


class RC(object):
    '''Return code constants.
    '''
    SUCCESS = 0
    LOW_PASS_RATE = 1
    LOW_TESTED_CASES = 2
    ERROR = 255

    @staticmethod
    def meaning(rc):
        _mapping = {
            0: 'Success',
            1: 'Low pass rate',
            2: 'Tested case number is low',
            255: 'Encountered error'
        }
        return _mapping[rc]


class KustoChecker(object):

    def __init__(self, cluster, access_token, database):
        self.cluster = cluster
        self.access_token = access_token
        self.database = database

        self.logger = logging.getLogger('KustoChecker')

        kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(
            self.cluster,
            self.access_token
            )

        self.client = KustoClient(kcsb)

    def query(self, query):
        self.logger.debug('Query String: {}'.format(query))
        return self.client.execute(self.database, query)

    def query_test_summary(self, testbed, release):
        query_str = '''
            FlatTestSummaryViewV2
            | where TestbedName == '{testbed}'
            | where OSVersion contains '{release}'
            | order by StartTimeUTC desc
            | limit 3
            '''.format(
                testbed=testbed,
                release=release
                )
        return self.query(query_str)


def create_kusto_checker():

    ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER")
    cluster = ingest_cluster.replace('ingest-', '')
    access_token = os.environ.get('ACCESS_TOKEN', None)

    if not all([cluster, access_token]):
        raise RuntimeError('Could not load Kusto credentials from environment')

    return KustoChecker(cluster, access_token, DATABASE)


def get_pass_rate(test_report):
    test_summary = test_report['test_summary']

    count_failures = int(test_summary['failures'])
    count_skipped = int(test_summary['skipped'])
    count_total = int(test_summary['tests'])
    count_xfails = int(test_summary['xfails'])
    count_success = count_total - count_failures - count_skipped - count_xfails

    pass_rate = count_success / (count_failures + count_xfails + count_success)
    return pass_rate


def get_kusto_pass_rates(kusto_response):
    pass_rates = []
    for row in kusto_response.primary_results[0].rows:
        count_failures = row['Failures']
        count_xfails = row['Xfails']
        count_success = row['Successes']
        pass_rates.append(count_success/(count_failures + count_xfails + count_success))
    return pass_rates


def is_current_pass_rate_ok(pass_rate, history_pass_rates, thresholds):
    if len(history_pass_rates) == 0:
        if pass_rate > thresholds['MIN_PASSING_RATE']:
            return RC.SUCCESS
        else:
            return RC.LOW_PASS_RATE
    else:
        average = sum(history_pass_rates)/len(history_pass_rates)
        base = average - thresholds['TOLERANCE']
        if pass_rate > base:
            return RC.SUCCESS
        else:
            return RC.LOW_PASS_RATE


def main(args):
    try:
        with open(args.report) as f:
            tr = json.load(f)

        thresholds = {
            'TESTED_CASES': 200,
            'MIN_PASSING_RATE': args.min_passing_rate / 100.0,
            'TOLERANCE': args.tolerance / 100.0
        }

        cases = []
        for feature in tr['test_cases']:
            cases.extend(tr['test_cases'][feature])
        if len(cases) < thresholds['TESTED_CASES']:
            sys.exit(RC.LOW_TESTED_CASES)

        logger.debug('Test Metadata:\n{}'.format(json.dumps(tr['test_metadata'], indent=2)))
        logger.debug('Test Summary:\n{}'.format(json.dumps(tr['test_summary'], indent=2)))

        testbed = tr['test_metadata']['testbed']
        os_version = tr['test_metadata']['os_version']

        pass_rate = get_pass_rate(tr)
        kusto_checker = create_kusto_checker()
        history_pass_rates = get_kusto_pass_rates(kusto_checker.query_test_summary(testbed, os_version.split('.')[0]))

        logger.info('Current pass_rate {:.2f}'.format(pass_rate))
        logger.info('History pass rate: {}'.format(history_pass_rates))

        result = is_current_pass_rate_ok(pass_rate, history_pass_rates, thresholds)
        logger.info('Result of analyzing test results: {} - {}'.format(result, RC.meaning(result)))
        sys.exit(result)
    except Exception as e:
        logger.error('Something went wrong: {}'.format(RC.meaning(RC.ERROR)))
        logger.exception(e)
        sys.exit(RC.ERROR)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Analyze test result")

    parser.add_argument('-r', '--report',
        type=str,
        dest='report',
        required=True,
        help='Test report json file.')

    parser.add_argument('-m', '--min-passing-rate',
        type=int,
        dest='min_passing_rate',
        default=60,
        help='The int will used as percentage. For example, 3 means 3%.'
             'This argument specifies the minimum passing rate. If the current passing rate is below than this number,'
             'then the test results would be unacceptable.'
    )

    parser.add_argument('-t', '--tolerance',
        type=int,
        dest='tolerance',
        default=3,
        help='The int will used as percentage. For example, 3 means 3%.'
             'This argument specifies the allowed passing rate dropping. If the average history passing rate is 95%,'
             'and this parameter is 3, then current passing rate 91% would not be acceptable.'
    )

    args = parser.parse_args()

    main(args)
