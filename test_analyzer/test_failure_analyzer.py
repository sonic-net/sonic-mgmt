from __future__ import print_function, division
from bdb import Breakpoint
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
import tempfile
from datetime import datetime, timezone, timedelta
import traceback
import requests
import uuid
import argparse
import time

from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from azure.kusto.data.helpers import dataframe_from_result_table
import pandas as pd
try:
    from azure.kusto.ingest import KustoIngestClient
except ImportError:
    from azure.kusto.ingest import QueuedIngestClient as KustoIngestClient

from azure.kusto.ingest import IngestionProperties

# Resolve azure.kusto.ingest compatibility issue
try:
    from azure.kusto.ingest import DataFormat
except ImportError:
    from azure.kusto.data.data_format import DataFormat

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s %(filename)s:%(name)s:%(lineno)d %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CONFI_FILE = 'test_failure_config.json'
DATABASE = 'SonicTestData'
ICM_DATABASE = 'IcMDataWarehouse'
PARENT_ID = "13410203"
ICM_PREFIX = '[SONiC_Nightly][Failed_Case]'
ICM_NUMBER_THRESHOLD = 9
INCLUDED_BRANCH = ["20201231", "master", "internal", "20220531"]

TOKEN = os.environ.get('AZURE_DEVOPS_MSAZURE_TOKEN')
if not TOKEN:
    raise Exception(
        'Must export environment variable AZURE_DEVOPS_MSSONIC_TOKEN')
AUTH = ('', TOKEN)


def config_logging():
    """Configure log to rotating file

    * Remove the default handler from app.logger.
    * Add RotatingFileHandler to the app.logger.
        File size: 10MB
        File number: 3
    * The Werkzeug handler is untouched.
    """
    rfh = RotatingFileHandler(
        '/tmp/test_failure_analyzer.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3)
    fmt = logging.Formatter(
        '%(asctime)s %(levelname)s:%(funcName)s %(lineno)d:%(message)s')
    rfh.setFormatter(fmt)
    logger.addHandler(rfh)


class KustoConnector(object):
    """connect the Kusto and run query"""
    TEST_CASE_ANALYSIS_TABLE = "TestcaseAnalysis"
    AUTO_BLAME_REPORT_TABLE = "AutoBlameReport"

    TABLE_FORMAT_LOOKUP = {
        TEST_CASE_ANALYSIS_TABLE: DataFormat.JSON,
        AUTO_BLAME_REPORT_TABLE: DataFormat.JSON
    }

    TABLE_MAPPING_LOOKUP = {
        TEST_CASE_ANALYSIS_TABLE: "FlatTestCaseAnalysisMappingV1",
        AUTO_BLAME_REPORT_TABLE: "AutoBlameReportMapping"
    }

    def __init__(self, config_info):
        self.logger = logging.getLogger('KustoChecker')

        self.config_info = config_info
        self.db_name = DATABASE
        self.icm_db_name = ICM_DATABASE
        self.current_timestamp = datetime.utcnow()

        ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER")
        tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID")
        service_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID")
        service_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY")

        if not ingest_cluster or not tenant_id or not service_id or not service_key:
            logger.error(
                "Could not load primary Kusto Credentials from environment, please check your environment setting.")
            self._ingestion_client = None
        else:
            cluster = ingest_cluster.replace('ingest-', '')

            if not all([cluster, tenant_id, service_id, service_key]):
                raise RuntimeError(
                    'Could not load Kusto credentials from environment')

            kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(cluster,
                                                                                        service_id,
                                                                                        service_key,
                                                                                        tenant_id)
            kcsb_ingest = KustoConnectionStringBuilder.with_aad_application_key_authentication(ingest_cluster,
                                                                                               service_id,
                                                                                               service_key,
                                                                                               tenant_id)
            self.client = KustoClient(kcsb)
            self._ingestion_client = KustoIngestClient(kcsb_ingest)

        """
            Kusto performance depends on the work load of cluster, to improve the high availability of test result data service 
            by hosting a backup cluster, which is optional. 
        """
        ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
        tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID_BACKUP")
        service_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID_BACKUP")
        service_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY_BACKUP")

        icm_cluster = os.getenv("ICM_KUSTO_CLUSTER")

        if not ingest_cluster or not tenant_id or not service_id or not service_key:
            logger.error(
                "Could not load backup Kusto Credentials from environment, please check your environment setting.")
            self._ingestion_client_backup = None
        else:
            cluster = ingest_cluster.replace('ingest-', '')
            kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(cluster,
                                                                                        service_id,
                                                                                        service_key,
                                                                                        tenant_id)
            kcsb_ingest = KustoConnectionStringBuilder.with_aad_application_key_authentication(ingest_cluster,
                                                                                               service_id,
                                                                                               service_key,
                                                                                               tenant_id)
            self.client_backup = KustoClient(kcsb)
            self._ingestion_client_backup = KustoIngestClient(kcsb_ingest)

        if not icm_cluster:
            logger.error(
                "Could not load IcM cluster url from environment, please check your environment setting.")
            self._icm_client = None
        else:
            icm_kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(icm_cluster,
                                                                                            service_id,
                                                                                            service_key,
                                                                                            tenant_id)

            self.icm_client = KustoClient(icm_kcsb)

    def icm_query(self, query):
        self.logger.debug('Query String: {}'.format(query))
        return self.icm_client.execute(self.icm_db_name, query)

    def query(self, query):
        self.logger.debug('Query String: {}'.format(query))
        return self.client_backup.execute(self.db_name, query)

    def query_active_icm(self):
        """
        Query active IcMs for SONiC Nightly Test queue.
        """
        query_str = '''
            IncidentsSnapshotV2()
            | where OwningTeamName == "CLOUDNET\\\\SONiCNightlyTest"
            | where Title contains "[Failed_Case]"
            | where Status == "ACTIVE"
            | project IncidentId, Title, SourceCreateDate, ModifiedDate, Status
            | sort by SourceCreateDate
            '''
        logger.info("Query active icm:{}".format(query_str))
        return self.icm_query(query_str)

    def query_summary_results(self):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        query_str = '''
            FlatTestSummaryView
            | where Timestamp > ago({})
            | where TotalCasesRun > {}
            '''.format(self.config_info['threshold']['duration'], self.config_info['threshold']['totalcase'])
        return self.query(query_str)

    def query_test_setup_failure(self):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        start_time = self.current_timestamp - \
            timedelta(days=int(self.config_info['threshold']['duration_days']))
        end_time = self.current_timestamp

        query_str = '''
        let ProdQualOSList = dynamic({});
        let ResultFilterList = dynamic(["failure", "error"]);
        let ExcludeTestbedList = dynamic({});
        let ExcludeBranchList = dynamic({});
        let ExcludeHwSkuList = dynamic({});
        let ExcludeTopoList = dynamic({});
        let ExcludeAsicList = dynamic({});
        let timeBefore = {};
        let totalcase_threshod = {};
        FlatTestSummaryView
        | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
        | where TotalCasesRun > totalcase_threshod
        | join kind=innerunique FlatTestReportViewV4 on ReportId
        | where OSVersion has_any(ProdQualOSList)
        | where Result in (ResultFilterList)
        | where not(TestbedName has_any(ExcludeTestbedList))
        | where not (HardwareSku has_any(ExcludeHwSkuList))
        | where not(TopologyType has_any(ExcludeTopoList))
        | where not(AsicType has_any(ExcludeAsicList))
        | where Summary contains "test setup failure"
        | extend opTestCase = case(TestCase has'[', split(TestCase, '[')[0], TestCase)
        | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
        | join kind = inner LatestTestCaseRunFailureV2(timeBefore, ProdQualOSList, ResultFilterList)
                                                        on $left.OSVersion == $right.OSVersion,
                                                            $left.ModulePath == $right.ModulePath,
                                                            $left.opTestCase == $right.opTestCase,
                                                            $left.Result == $right.Result
        | extend BranchName = tostring(split(OSVersion, '.')[0])
        | where not(BranchName has_any(ExcludeBranchList))
        | where BranchName has_any(ProdQualOSList)
        | project ReproCount, Timestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, Result, BranchName, OSVersion, TestbedName, Asic, TopologyType, Summary, BuildId
        | distinct Timestamp, Feature, ModulePath, OSVersion, BranchName, Summary, BuildId,  TestbedName, ReproCount
        | where ReproCount >= {}
        | sort by ReproCount, ModulePath
        '''.format(self.config_info["branch"]["included_branch"], self.config_info["testbeds"]["excluded_testbed_keywords_setup_error"],
            self.config_info["branch"]["excluded_branch_setup_error"], self.config_info["hwsku"]["excluded_hwsku"],
            self.config_info['topo']['excluded_topo'], self.config_info['asic']['excluded_asic'],
            str(self.config_info['threshold']['duration_days']) + "d",
            self.config_info['threshold']['totalcase'], start_time, end_time, self.config_info['threshold']['repro_count_limit_setup_error'])
        logger.info("Query test setup failure cases:{}".format(query_str))
        return self.query(query_str)

    def query_failed_testcase(self):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        start_time = self.current_timestamp - \
            timedelta(days=int(self.config_info['threshold']['duration_days']))
        end_time = self.current_timestamp

        query_str = '''
        let ProdQualOSList = dynamic({});
        let ResultFilterList = dynamic(["failure", "error"]);
        let ExcludeTestbedList = dynamic({});
        let ExcludeBranchList = dynamic({});
        let ExcludeHwSkuList = dynamic({});
        let ExcludeTopoList = dynamic({});
        let ExcludeAsicList = dynamic({});
        let timeBefore = {};
        let totalcase_threshod = {};
        FlatTestSummaryView
        | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
        | where TotalCasesRun > totalcase_threshod
        | join kind=innerunique FlatTestReportViewV4 on ReportId 
        | where OSVersion has_any(ProdQualOSList)
        | where Result in (ResultFilterList)
        | where not(TestbedName has_any(ExcludeTestbedList))
        | where not (HardwareSku has_any(ExcludeHwSkuList))
        | where not(TopologyType has_any(ExcludeTopoList))
        | where not(AsicType has_any(ExcludeAsicList))
        | extend opTestCase = case(TestCase has'[', split(TestCase, '[')[0], TestCase)
        | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
        | join kind = inner LatestTestCaseRunFailure(timeBefore, ProdQualOSList, ResultFilterList)
                                                        on $left.OSVersion == $right.OSVersion,
                                                            $left.ModulePath == $right.ModulePath,
                                                            $left.opTestCase == $right.opTestCase,
                                                            $left.Result == $right.Result
        | extend BranchName = tostring(split(OSVersion, '.')[0])
        | where not(BranchName has_any(ExcludeBranchList))
        | where BranchName has_any(ProdQualOSList)
        | where ReproCount >= {}
        | where ModulePath != ""
        | project ReproCount, Timestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, Result, BranchName, OSVersion, TestbedName, Asic, TopologyType
        | sort by ReproCount, ModulePath, opTestCase, Result
        '''.format(self.config_info["branch"]["included_branch"], self.config_info["testbeds"]["excluded_testbed_keywords"],
            self.config_info["branch"]["excluded_branch"], self.config_info["hwsku"]["excluded_hwsku"],
            self.config_info['topo']['excluded_topo'], self.config_info['asic']['excluded_asic'],
            str(self.config_info['threshold']['duration_days']) + "d", self.config_info['threshold']['totalcase'],
            start_time, end_time, self.config_info['threshold']['repro_count_limit'])
        logger.info("Query failed cases:{}".format(query_str))
        return self.query(query_str)

    def query_history_results(self, testcase_name, module_path, is_module_path=False):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        project Timestamp, OSVersion, HardwareSku, TotalCasesRun, Successes, Failures, Errors, Skipped, TestbedName, TotalRuntime, AsicType, Platform, Topology, ReportId, UploadTimestamp, Asic, TopologyType, RunDate, BuildId, TestbedSponsor, Feature, TestCase, ModulePath, FilePath, StartLine, Runtime, Result, Error, Summary, StartTime, EndTime, FullTestPath, opTestCase
        """
        start_time = self.current_timestamp - \
            timedelta(days=int(self.config_info['threshold']['history_days']))
        end_time = self.current_timestamp
        if is_module_path:
            query_str = '''
                let ProdQualOSList = dynamic({});
                let ResultFilterList = dynamic(["failure", "error"]);
                let ExcludeTestbedList = dynamic({});
                let ExcludeBranchList = dynamic({});
                let ExcludeHwSkuList = dynamic({});
                let ExcludeTopoList = dynamic({});
                let ExcludeAsicList = dynamic({});
                let totalcase_threshod = {};
                FlatTestSummaryView
                | where Timestamp > datetime({}) and Timestamp <= datetime({})
                | where TotalCasesRun > totalcase_threshod
                | join kind=innerunique FlatTestReportViewV4 on ReportId
                | where OSVersion has_any(ProdQualOSList)
                | where Result !in ("skipped")
                | where not(TestbedName has_any(ExcludeTestbedList))
                | where not (HardwareSku has_any(ExcludeHwSkuList))
                | where not(TopologyType has_any(ExcludeTopoList))
                | where not(AsicType has_any(ExcludeAsicList))
                | extend opTestCase = case(TestCase has'[', split(TestCase, '[')[0], TestCase)
                | extend BranchName = tostring(split(OSVersion, '.')[0])
                | where not(BranchName has_any(ExcludeBranchList))
                | where BranchName has_any(ProdQualOSList)
                | where ModulePath == "{}"
                | order by StartTimeUTC desc
                | project Timestamp, OSVersion, BranchName, HardwareSku, TestbedName, AsicType, Platform, Topology, Asic, TopologyType, Feature, TestCase, opTestCase, ModulePath, Result
                '''.format(self.config_info["branch"]["included_branch"], self.config_info["testbeds"]["excluded_testbed_keywords_setup_error"],
                    self.config_info["branch"]["excluded_branch_setup_error"], self.config_info["hwsku"]["excluded_hwsku"],
                    self.config_info['topo']['excluded_topo'], self.config_info['asic']['excluded_asic'],
                    self.config_info['threshold']['totalcase'], start_time, end_time,  module_path)
        else:
            query_str = '''
                let ProdQualOSList = dynamic({});
                let ResultFilterList = dynamic(["failure", "error"]);
                let ExcludeTestbedList = dynamic({});
                let ExcludeBranchList = dynamic({});
                let ExcludeHwSkuList = dynamic({});
                let ExcludeTopoList = dynamic({});
                let ExcludeAsicList = dynamic({});
                let totalcase_threshod = {};
                FlatTestSummaryView
                | where Timestamp > datetime({}) and Timestamp <= datetime({})
                | where TotalCasesRun > totalcase_threshod
                | join kind=innerunique FlatTestReportViewV4 on ReportId 
                | where OSVersion has_any(ProdQualOSList)
                | where Result !in ("skipped")
                | where not(TestbedName has_any(ExcludeTestbedList))
                | where not (HardwareSku has_any(ExcludeHwSkuList))
                | where not(TopologyType has_any(ExcludeTopoList))
                | where not(AsicType has_any(ExcludeAsicList))
                | extend opTestCase = case(TestCase has'[', split(TestCase, '[')[0], TestCase)
                | extend BranchName = tostring(split(OSVersion, '.')[0])
                | where not(BranchName has_any(ExcludeBranchList))
                | where BranchName has_any(ProdQualOSList)
                | where opTestCase == "{}" and ModulePath == "{}"
                | order by StartTimeUTC desc
                | project Timestamp, OSVersion, BranchName, HardwareSku, TestbedName, AsicType, Platform, Topology, Asic, TopologyType, Feature, TestCase, opTestCase, ModulePath, Result
                '''.format(self.config_info["branch"]["included_branch"], self.config_info["testbeds"]["excluded_testbed_keywords"],
                    self.config_info["branch"]["excluded_branch"], self.config_info["hwsku"]["excluded_hwsku"],
                    self.config_info['topo']['excluded_topo'], self.config_info['asic']['excluded_asic'],
                    self.config_info['threshold']['totalcase'], start_time, end_time, testcase_name, module_path)
        logger.info("Query hisotry results:{}".format(query_str))
        return self.query(query_str)

    def query_previsou_upload_record(self):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        query_str = '''
            TestcaseAnalysis
            | where UploadTimestamp > ago({})
            | project UploadTimestamp, ModulePath, TestCase, Branch, Subject
            '''.format(str(self.config_info['threshold']['previous_days']) + "d")
        return self.query(query_str)

    def upload_analyzed_data(self, report_data):
        self._ingest_data(self.TEST_CASE_ANALYSIS_TABLE, report_data)
        return

    def upload_autoblame_data(self, upload_datas):
        # self.logger.info('Upload {} autoblame records:{}'.format(len(upload_datas), upload_datas))
        self._ingest_data(self.AUTO_BLAME_REPORT_TABLE, upload_datas)

    def _ingest_data(self, table, data):
        props = IngestionProperties(
            database=self.db_name,
            table=table,
            data_format=self.TABLE_FORMAT_LOOKUP[table],
            ingestion_mapping_reference=self.TABLE_MAPPING_LOOKUP[table]
        )

        with tempfile.NamedTemporaryFile(mode="w+") as temp:
            if isinstance(data, list):
                temp.writelines(
                    '\n'.join([json.dumps(entry) for entry in data]))
            else:
                temp.write(json.dumps(data))
            temp.seek(0)

            if self._ingestion_client_backup:
                logger.info("Ingest to backup cluster...")
                self._ingestion_client_backup.ingest_from_file(temp.name, ingestion_properties=props)
        return


class Analyzer(object):
    """analyze failed test cases"""

    def __init__(self, kusto_connector, config_info) -> None:
        self.kusto_connector = kusto_connector
        self.config_info = config_info

        self.child_standby_list = []

        logger.info("worker number: {}".format(
            self.config_info['worker_number']))
        logger.info(
            "====== initiate target parent relationships into memory list ======")
        self.init_parent_relations2list(PARENT_ID)

    def run(self, icm_limit):
        logger.info(
            "========== Start searching failed test case ==============")
        waiting_list = []
        setup_errors_failures = self.collect_test_setup_failure()
        setup_errors_list = list(setup_errors_failures.keys())
        for setup_error in setup_errors_list:
            waiting_list.append((setup_error, True))
        logger.info("waiting_list for setup error={}".format(waiting_list))
        failed_testcases = self.collect_failed_testcase()

        failed_testcases_list = list(failed_testcases.keys())
        for failed_testcase in failed_testcases_list:
            waiting_list.append((failed_testcase, False))
        logger.info("Total failed cases: {} waiting_list={}".format(len(waiting_list), waiting_list))
        logger.info(
            "=============== Analyze active IcM ================")
        active_icm_list, count_dict = self.analyze_active_icm()

        logger.info(
            "============== Start searching history result ================")

        new_icm_table = []
        duplicated_icm_table = []
        autoblame_table = []
        if icm_limit is None:
            icm_limit = int(
                self.config_info["threshold"]["new_icm_number_limit"])
        new_icm_count = 0
        break_flag = False

        # We can use a with statement to ensure threads are cleaned up promptly
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config_info['worker_number']) as executor:
            for (test_case_branch, is_module_path) in waiting_list:
                # Start the load operations and mark each future with test case name
                logger.info("Start analysising test_case_branch={}, is_module_path={}".format(test_case_branch, is_module_path))
                future_to_testcase = {executor.submit(
                    self.analysis_process, test_case_branch, is_module_path): test_case_branch}
                for future in concurrent.futures.as_completed(future_to_testcase):
                    testcase_task = future_to_testcase[future]
                    try:
                        kusto_data, autoblame_data = future.result()
                    except Exception as exc:
                        logger.error("Task {} generated an exception: {}".format(
                            (testcase_task, exc)))
                        logger.error(traceback.format_exc())
                    new_icm_list = []
                    duplicated_icm_list = []
                    for idx, icm in enumerate(kusto_data):
                        duplicated_flag = False
                        # For loop every active IcM title, avoid generating smaller level IcM for same failure
                        for icm_title in active_icm_list:
                            # For platform_test, we aggregate branches, don't trigger same IcM for different branches
                            if 'platform_tests' in icm['module_path']:
                                icm_branch = icm['branch']
                                for branch_name in INCLUDED_BRANCH:
                                    replaced_title = icm['subject'].replace(icm_branch, branch_name)
                                    if icm_title in ICM_PREFIX + replaced_title:
                                        logger.info("For platform_tests, found same case for branch {}, not trigger IcM: \
                                            active IcM {}, duplicated one {}".format(icm_branch, icm_title, ICM_PREFIX + icm['subject']))
                                        icm['trigger_icm'] = False
                                        duplicated_icm_list.append(icm)
                                        duplicated_flag = True
                                        break
                                if duplicated_flag:
                                    break
                            elif icm_title in ICM_PREFIX + icm['subject']:
                                # Don't trigger IcM for duplicated cases, avoid IcM throttling
                                logger.info("Found duplicated item in active IcM list, not trigger IcM: \
                                    active IcM {}, duplicated one {}".format(icm_title, ICM_PREFIX + icm['subject']))
                                icm['trigger_icm'] = False
                                duplicated_icm_list.append(icm)
                                duplicated_flag = True
                                break
                        temp_uploading_list = []
                        temp_uploading_list.extend(new_icm_list)
                        temp_uploading_list.extend(new_icm_table)
                        # For loop every uploading IcM title, avoid generating smaller level IcM for same failure
                        for uploading_new_icm in temp_uploading_list:
                            # For platform_test, we aggregate branches, don't trigger same IcM for different branches
                            if 'platform_tests' in icm['module_path']:
                                icm_branch = icm['branch']
                                for branch_name in INCLUDED_BRANCH:
                                    replaced_title = icm['subject'].replace(icm_branch, branch_name)
                                    if uploading_new_icm['subject'] in replaced_title or replaced_title in uploading_new_icm['subject']:
                                        logger.info("For platform_tests, found same case for branch {}, not trigger IcM: \
                                            uploading IcM {}, duplicated one {}".format(icm_branch, icm_title, icm['subject']))
                                        icm['trigger_icm'] = False
                                        duplicated_icm_list.append(icm)
                                        duplicated_flag = True
                                        break
                                if duplicated_flag:
                                    break
                            elif uploading_new_icm['subject'] in icm['subject'] or icm['subject'] in uploading_new_icm['subject']:
                                # Don't trigger IcM for duplicated cases, avoid IcM throttling
                                logger.info("Found duplicated item in uploading IcM list, not trigger IcM: \
                                    uploading IcM {}, duplicated one {}".format(uploading_new_icm['subject'], icm['subject']))
                                icm['trigger_icm'] = False
                                duplicated_icm_list.append(icm)
                                duplicated_flag = True
                                break

                        if not duplicated_flag:
                            module_path = icm['module_path']
                            items = module_path.split('.')
                            if new_icm_count >= icm_limit:
                                logger.info(
                                    "We limit the number of new IcM to {}, idx={}".format(icm_limit, idx))
                                break_flag = True
                                kusto_data = kusto_data[:idx]
                                break
                            if 'everflow' in items[0]:
                                if count_dict['everflow_count'] >= self.config_info['threshold']['max_icm_count_per_module']:
                                    logger.info("There are already 10 IcMs for everflow, inhibit this one avoid generating so many similar cases.")
                                    kusto_data = kusto_data[:idx]
                                    logger.info("kusto_data={}".format(kusto_data))
                                    break
                                else:
                                    count_dict['everflow_count'] += 1
                            if len(items) > 1 and 'test_qos_sai' in items[1]:
                                if count_dict['qos_sai_count'] >= self.config_info['threshold']['max_icm_count_per_module']:
                                    logger.info("There are already 10 IcMs for qos_sai, inhibit this one avoid generating so many similar cases.")
                                    kusto_data = kusto_data[:idx]
                                    logger.info("kusto_data={}".format(kusto_data))
                                    break
                                else:
                                    count_dict['qos_sai_count'] += 1
                            if 'acl' in items[0]:
                                if count_dict['acl_count'] >= self.config_info['threshold']['max_icm_count_per_module']:
                                    logger.info("There are already 10 IcMs for acl, inhibit this one avoid generating so many similar cases.")
                                    kusto_data = kusto_data[:idx]
                                    break
                                else:
                                    count_dict['acl_count'] += 1
                            logger.info("New IcM for this run: {} idx = {}".format(
                                icm['subject'], idx))
                            new_icm_list.append(icm)
                            new_icm_count += 1
                    if len(kusto_data) != 0:
                        autoblame_table.extend(autoblame_data)
                    if len(new_icm_list) != 0:
                        new_icm_table.extend(new_icm_list)
                    if len(duplicated_icm_list) != 0:
                        duplicated_icm_table.extend(duplicated_icm_list)
                    if break_flag:
                        logger.info(
                            "Stop handling as_complete more case... Last task {}...".format(testcase_task))
                        break
                if break_flag:
                    logger.info(
                        "Stop handling more case... Last case {}.".format(test_case_branch))
                    break

        logger.info("================= Upload to kusto =====================")
        for kusto_row_data in duplicated_icm_table:
            logger.info("Upload duplicated icm to kusto = {}".format(
                json.dumps(kusto_row_data, indent=4)))
        for kusto_row_data in new_icm_table:
            logger.info("Upload new icm to kusto = {}".format(
                json.dumps(kusto_row_data, indent=4)))
        for index, duplicated_icm in enumerate(duplicated_icm_table):
            logger.info("{} Duplicated IcM subject = {}".format(index + 1, duplicated_icm["subject"]))
        for index, new_icm in enumerate(new_icm_table):
            logger.info("{} New IcM subject = {}".format(index + 1, new_icm["subject"]))
        logger.info("There are {} duplicated IcMs in total for this run.".format(len(duplicated_icm_table)))
        logger.info("There are {} new IcMs in total for this run.".format(len(new_icm_table)))
        logger.info("There are {} Autoblame commit in total.".format(
            len(autoblame_table)))

        # The actual ingested time is about 5 mins later after uploading to kusto
        # In order to make Geneva to capture incidents in time,
        # move upload_timestamp to 5 mins ago
        ingested_time = str(datetime.utcnow() - timedelta(minutes=5))
        for row in autoblame_table:
            row['upload_timestamp'] = ingested_time
        self.kusto_connector.upload_autoblame_data(autoblame_table)

        icm_count = 0
        upload_icm_table = []
        for idx, new_icm in enumerate(new_icm_table):
            upload_icm_table.append(new_icm)
            if icm_count < ICM_NUMBER_THRESHOLD - 1 and idx != len(new_icm_table) - 1:
                icm_count += 1
            else:
                logger.info("Upload {} new IcMs table to kusto.".format(len(upload_icm_table)))
                # Set same upload timestamp for uploaded items
                ingested_time = str(datetime.utcnow() + timedelta(minutes=7))
                for item in upload_icm_table:
                    item['upload_timestamp'] = ingested_time
                self.kusto_connector.upload_analyzed_data(upload_icm_table)
                upload_icm_table = []
                icm_count = 0
                # Don't need to sleep for the last upload
                if idx != len(new_icm_table) - 1:
                    logger.info("Sleep for 30 mins to cover kusto ingestion delay and avoid IcM throttling...")
                    time.sleep(30*60)

        ingested_time = str(datetime.utcnow() + timedelta(minutes=7))
        for row in duplicated_icm_table:
            row['upload_timestamp'] = ingested_time
        logger.info("Upload {} duplicated IcMs table to kusto.".format(len(duplicated_icm_table)))
        self.kusto_connector.upload_analyzed_data(duplicated_icm_table)

    def collect_previous_upload_record(self):
        """ The table header looks like this, save all of these information
        project project UploadTimestamp, ModulePath, TestCase, Branch, Subject
        """
        previous_upload_results_response = self.kusto_connector.query_previsou_upload_record()
        previous_upload_results_df = dataframe_from_result_table(
            previous_upload_results_response.primary_results[0])
        logger.info(previous_upload_results_df)

        return previous_upload_results_df

    def collect_active_icm(self):
        """The table header looks like this, save all of these information
        project IncidentId, Title, SourceCreateDate, ModifiedDate, Status
        """
        active_icm_response = self.kusto_connector.query_active_icm()
        active_icm_df = dataframe_from_result_table(
            active_icm_response.primary_results[0])
        return active_icm_df

    def analyze_active_icm(self):
        active_icm_df = self.collect_active_icm()
        active_icm_list = active_icm_df['Title'].tolist()
        active_icm_df["IcMPrintInfo"] = "Created at " + \
            active_icm_df["SourceCreateDate"].astype(
                str) + ": " + active_icm_df['Title'].astype(str)
        print_list = active_icm_df['IcMPrintInfo'].tolist()
        logger.info("There are {} active IcMs so far.".format(
            len(active_icm_list)))

        for icm_title in print_list:
            logger.info("{}".format(icm_title))
        everflow_count = 0
        qos_sai_count = 0
        acl_count = 0
        for active_icm_title in active_icm_list:
            if active_icm_title.startswith(ICM_PREFIX):
                subtitle = active_icm_title[len(ICM_PREFIX)+1:]
                index = subtitle.find(']')
                subtitle = subtitle[:index]
            items = subtitle.split('.')
            if 'everflow' in items[0]:
                everflow_count += 1
            if len(items) > 1 and 'test_qos_sai' in items[1]:
                qos_sai_count += 1
            if 'acl' in items[0]:
                acl_count += 1

        count_dict = {
                'everflow_count': everflow_count,
                'qos_sai_count': qos_sai_count,
                'acl_count': acl_count
                }
        logger.info("count for active IcM:{}".format(count_dict))
        return active_icm_list, count_dict

    def collect_summary_results(self):
        """ The table header looks like this, save all of these information
        Timestamp	OSVersion	HardwareSku	TotalCasesRun	Successes	Failures	Errors	Skipped	TestbedName	TrackingId	TotalRuntime	AsicType	Platform	Topology	ReportId	UploadTimestamp
        """
        summary_response = self.kusto_connector.query_summary_results()
        summary_df = dataframe_from_result_table(
            summary_response.primary_results[0])
        logger.info(summary_df)

        logger.info("Found {} valid pipeline results.".format(len(summary_df)))
        return summary_df

    def collect_test_setup_failure(self):
        """The table header looks like this, save all of these information
        project ReproCount, Timestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, Result, BranchName, OSVersion, TestbedName, Asic, TopologyType, Summary, BuildId
        """
        setup_error_response = self.kusto_connector.query_test_setup_failure()
        # setup_error_df = dataframe_from_result_table(setup_error_response.primary_results[0])
        search_cases = {}
        for row in setup_error_response.primary_results[0].rows:
            module_path = row['ModulePath']
            branch = row['BranchName']
            key = module_path + "#" + branch
            if module_path in search_cases:
                continue

            else:
                if key not in search_cases:
                    search_cases[key] = {}
                    search_cases[key]['ReproCount'] = int(row['ReproCount'])
                    search_cases[key]['OSVersion'] = row['OSVersion']
                    search_cases[key]['BranchName'] = row['BranchName']
                    search_cases[key]['BuildId'] = row['BuildId']

        total_setup_error_count = len(
            setup_error_response.primary_results[0].rows)
        logger.info("Found {} test setup failure in total.".format(
            total_setup_error_count))
        logger.info("Found {} kinds of test setup failure.".format(
            len(search_cases)))
        return search_cases

    def collect_failed_testcase(self):
        """The table header looks like this, save all of these information
        project ReproCount, Timestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, Result, BranchName, OSVersion,TestbedName, Summary, ReportId, UploadTimestamp, Asic, TopologyType, RunDate, BuildId, TestbedSponsor, StartLine, Runtime
        """
        failedcases_response = self.kusto_connector.query_failed_testcase()

        search_cases = {}
        for row in failedcases_response.primary_results[0].rows:
            module_path = row['ModulePath']
            testcase = row['opTestCase']
            branch = row['BranchName']
            key = module_path + '.' + testcase + "#" + branch
            if testcase in search_cases:
                continue

            else:
                if key not in search_cases:
                    search_cases[key] = {}
                    search_cases[key]['opTestCase'] = row['opTestCase']
                    search_cases[key]['ReproCount'] = int(row['ReproCount'])
                    search_cases[key]['Result'] = row['Result']
                    search_cases[key]['OSVersion'] = row['OSVersion']
                    search_cases[key]['BranchName'] = row['BranchName']

        total_failedcase_count = len(
            failedcases_response.primary_results[0].rows)
        logger.info("Found {} failed test cases in total.".format(
            total_failedcase_count))
        logger.info("Found {} kinds of failed test cases.".format(
            len(search_cases)))
        return search_cases

    def analysis_process(self, test_case_branch, is_module_path=False):
        history_testcases, history_case_df = self.search_and_parse_history_results(
            test_case_branch, is_module_path)
        kusto_data, autoblame_data = self.generate_kusto_data(
            test_case_branch, history_testcases, history_case_df, is_module_path)
        logger.info("There are {} IcM for case {}.".format(
            len(kusto_data), test_case_branch))
        logger.info("There are {} Autoblame commits for case {}.".format(
            len(autoblame_data), test_case_branch))
        return kusto_data, autoblame_data

    def search_and_parse_history_results(self, test_case_branch, is_module_path=False):
        """The table header looks like this, save all of these information
        project Timestamp, OSVersion, HardwareSku, TestbedName, TotalRuntime, AsicType, Platform, Topology, ReportId, UploadTimestamp, Asic, TopologyType, RunDate, BuildId, TestbedSponsor, Feature, TestCase, ModulePath, FilePath, StartLine, Runtime, Result, Summary, StartTime, EndTime, FullTestPath, opTestCase
        """
        if is_module_path:
            items = test_case_branch.split("#")
            module_path = items[0]
            branch = items[1]
            response = self.kusto_connector.query_history_results(
                None, module_path, True)
        else:
            items = test_case_branch.split("#")
            testcase = items[0].split('.')[-1]
            module_path = items[0][:-len(testcase)-1]
            branch = items[1]
            response = self.kusto_connector.query_history_results(
                testcase, module_path, False)
        case_df = dataframe_from_result_table(response.primary_results[0])
        case_branch_df = case_df[case_df['BranchName'] == branch]

        history_testcases = {}
        history_testcases[test_case_branch] = {}

        tb_results = self.calculate_success_rate(
            case_branch_df, 'TestbedName', 'testbed')
        asic_results = self.calculate_success_rate(case_branch_df, 'AsicType', 'asic')
        hwsku_results = self.calculate_success_rate(
            case_branch_df, 'HardwareSku', 'hwsku')
        os_results = self.calculate_success_rate(
            case_branch_df, 'OSVersion', 'os_version')

        hwsku_topo_results = {
            'success_rate': {},
            "consistent_failure_hwsku_topo": []
        }

        success_rate_result = {}
        sorted_results_dict = []
        for index, row in case_branch_df.iterrows():
            hwsku = row['HardwareSku']
            topo = row['TopologyType']
            hwsku_topo = hwsku + "_" + topo
            if hwsku_topo not in success_rate_result:
                hwsku_topo_aggr_df = case_branch_df[(case_branch_df['HardwareSku'] == hwsku) & (
                    case_branch_df['TopologyType'] == topo)]
                hwsku_topo_total_num = hwsku_topo_aggr_df.shape[0]
                hwsku_topo_success = hwsku_topo_aggr_df[hwsku_topo_aggr_df['Result'] == 'success']
                hwsku_topo_success_num = hwsku_topo_success.shape[0]
                hwsku_topo_pass_rate = round(
                    hwsku_topo_success_num * 100 / hwsku_topo_total_num)
                if hwsku_topo_pass_rate == 0:
                    hwsku_topo_results["consistent_failure_hwsku_topo"].append(
                        hwsku_topo)
                success_rate_result.update({hwsku_topo: "{}%/{}/{}".format(
                    hwsku_topo_pass_rate, hwsku_topo_success_num, hwsku_topo_total_num)})
        for k, v in sorted(success_rate_result.items(), key=lambda item: int(item[1].split("%")[0])):
            sorted_results_dict.append(k + " : " + v)

        hwsku_topo_results['success_rate'] = sorted_results_dict

        # Find out the latest failure row
        options = ['error', 'failure']
        fmt = '%Y-%m-%d %H:%M:%S'
        failed_df = case_branch_df[case_branch_df['Result'].isin(options)]
        if failed_df.shape[0] != 0:
            latest_row = failed_df.iloc[0]
            tb_results["latest_failure_testbed"] = latest_row['TestbedName']
            asic_results["latest_failure_asic"] = latest_row['AsicType']
            hwsku_results["latest_failure_hwsku"] = latest_row['HardwareSku']
            hwsku_topo_results["latest_failure_hwsku_topo"] = latest_row['HardwareSku'] + \
                "_" + latest_row['TopologyType']
            os_results["latest_failure_os_version"] = latest_row['OSVersion']
            latest_failure_timestamp_ori = latest_row['Timestamp']
            latest_failure_timestamp = latest_failure_timestamp_ori.to_pydatetime()
            latest_failure_timestr = latest_failure_timestamp.strftime(fmt)
            # Get the oldest failure row
            oldest_row = failed_df.iloc[-1]
            oldest_failure_timestamp_ori = oldest_row['Timestamp']
            oldest_failure_timestamp = oldest_failure_timestamp_ori.to_pydatetime()
            oldest_failure_timestr = oldest_failure_timestamp.strftime(fmt)
            history_testcases[test_case_branch]['latest_failure_timestamp'] = latest_failure_timestr
            history_testcases[test_case_branch]['oldest_failure_timestamp'] = oldest_failure_timestr

        total_success_num = case_branch_df[case_branch_df['Result'] == 'success'].shape[0]
        total_num = case_branch_df.shape[0]
        history_testcases[test_case_branch]['total_success_rate'] = "{}%/{}/{}".format(
            round(total_success_num * 100 / total_num), total_success_num, total_num)

        # history_testcases[test_case_branch]['repro_count'] = self.search_testcases[test_case_branch].get("ReproCount", 0)
        history_testcases[test_case_branch]['per_testbed_info'] = tb_results
        history_testcases[test_case_branch]['per_asic_info'] = asic_results
        history_testcases[test_case_branch]['per_hwsku_info'] = hwsku_results
        history_testcases[test_case_branch]['per_hwsku_topo_info'] = hwsku_topo_results
        history_testcases[test_case_branch]['per_os_version_info'] = os_results

        module_path = case_branch_df.iloc[0]["ModulePath"]
        feature = case_branch_df.iloc[0]["Feature"]
        history_testcases[test_case_branch]['module_path'] = module_path
        history_testcases[test_case_branch]['feature'] = feature

        # Check if recent test cases all failed, but previous ones are success.
        # Threshold is recent_failure_tolerance_day in config file, in case of flaky case
        time_df = case_branch_df[(case_branch_df['Timestamp'] > latest_failure_timestamp_ori) & (
            case_branch_df['Result'] == 'success')]
        if time_df.shape[0] == 0:
            logger.info("{} Since {}, all test cases are failed.".format(
                test_case_branch, oldest_failure_timestamp))
            current_time = datetime.now(timezone.utc)
            td = current_time - oldest_failure_timestamp
            td_hours = int(round(td.total_seconds() / 3600))
            if round(td_hours / 24) > self.config_info['threshold']['recent_failure_tolerance_day']:
                logger.info("{} All recent test cases  failed for more than {} days".format(
                    test_case_branch, self.config_info['threshold']['recent_failure_tolerance_day']))
                history_testcases[test_case_branch]['is_recent_failure'] = True

        return history_testcases, case_df

    def calculate_success_rate(self, data_df, column_name, category):
        results_dict = {}
        success_rate_result = {}
        consistent_failure_list = []
        sorted_results_dict = []
        for index, row in data_df.iterrows():
            column_value = row[column_name]
            if column_value not in success_rate_result:
                aggr_df = data_df[data_df[column_name] == column_value]
                total_num = aggr_df.shape[0]
                success_df = aggr_df[aggr_df['Result'] == 'success']
                success_num = success_df.shape[0]
                pass_rate = round(success_num * 100 / total_num)
                if pass_rate == 0:
                    consistent_failure_list.append(column_value)
                success_rate_result.update(
                    {column_value: "{}%/{}/{}".format(pass_rate, success_num, total_num)})
        if category == "os_version":
            for k, v in sorted(success_rate_result.items(), key=lambda item: item[0]):
                sorted_results_dict.append(k + " : " + v)
        else:
            for k, v in sorted(success_rate_result.items(), key=lambda item: int(item[1].split("%")[0])):
                sorted_results_dict.append(k + " : " + v)
        results_dict['success_rate'] = sorted_results_dict
        results_dict["consistent_failure_" +
                     category] = consistent_failure_list
        return results_dict

    def generate_kusto_data(self, case_name_branch, history_testcases, history_case_df, is_module_path=False):
        kusto_table = []
        autoblame_table = []
        kusto_row_data = {
            'failure_level_info': {},
            'trigger_icm': False,
            'autoblame_id': ''
        }
        if is_module_path:
            items = case_name_branch.split("#")
            module_path = items[0]
            case_name = module_path
            branch = items[1]
        else:
            items = case_name_branch.split("#")
            case_name = items[0].split('.')[-1]
            module_path = items[0][:-len(case_name)-1]
            branch = items[1]

        kusto_row_data['testcase'] = case_name
        kusto_row_data['branch'] = branch.lower()
        kusto_row_data['module_path'] = module_path
        kusto_row_data['per_testbed_info'] = history_testcases[case_name_branch]['per_testbed_info']
        kusto_row_data['per_asic_info'] = history_testcases[case_name_branch]['per_asic_info']
        kusto_row_data['per_hwsku_info'] = history_testcases[case_name_branch]['per_hwsku_info']
        kusto_row_data['per_hwsku_topo_info'] = history_testcases[case_name_branch]['per_hwsku_topo_info']
        kusto_row_data['per_os_version_info'] = history_testcases[case_name_branch]['per_os_version_info']
        kusto_row_data['failure_level_info']['latest_failure_timestamp'] = history_testcases[case_name_branch]['latest_failure_timestamp']
        kusto_row_data['failure_level_info']['oldest_failure_timestamp'] = history_testcases[case_name_branch]['oldest_failure_timestamp']

        kusto_row_data['failure_level_info']['total_success_rate_' + branch] = history_testcases[case_name_branch]['total_success_rate']
        for branch_name in INCLUDED_BRANCH:
            # import pdb;pdb.set_trace()
            if branch_name != branch:
                case_branch_df = history_case_df[history_case_df['BranchName'] == branch_name]
                total_success_num = case_branch_df[case_branch_df['Result'] == 'success'].shape[0]
                total_num = case_branch_df.shape[0]
                if total_num == 0:
                    logger.info("{} is not ran on {}.".format(case_name, branch_name))
                    continue
                else:
                    kusto_row_data['failure_level_info']['total_success_rate_' + branch_name] = "{}%/{}/{}".format(
                        round(total_success_num * 100 / total_num), total_success_num, total_num)

        if is_module_path:
            kusto_row_data['failure_level_info']['test_setup_failure'] = True
            kusto_row_data['failure_level_info']['is_module_path'] = True
        else:
            kusto_row_data['failure_level_info']['is_test_case'] = True

        # Search related ADO work items with case name
        related_workitem = self.search_ADO([case_name, module_path], False)
        if len(related_workitem) == 0:
            logger.info("Didn't find any related ADO work item for case {} module path {}.".format(
                case_name, module_path))
        else:
            kusto_row_data['failure_level_info']['found_related_workitem'] = True
            logger.info("Found {} related ADO work item for case {} module path {}".format(
                len(related_workitem), case_name, module_path))
            logger.debug("Related ADO work item:{}".format(related_workitem))

        # Search related commits with keywords and bracnh
        keywords = [case_name]
        keywords.extend(kusto_row_data['module_path'].split("."))
        tag = ''
        if branch.lower() == '20220531' or branch.lower() == '20201231':
            consistent_failure_os_version = history_testcases[case_name_branch][
                'per_os_version_info']["consistent_failure_os_version"]
            if consistent_failure_os_version and len(consistent_failure_os_version) > 0:
                tag = consistent_failure_os_version[0]
            else:
                tag = history_testcases[case_name_branch]['per_os_version_info']['latest_failure_os_version']

        fmt = '%Y-%m-%d %H:%M:%S'
        end_time = history_testcases[case_name_branch]['oldest_failure_timestamp']
        end_time = datetime.strptime(end_time, fmt)
        end_time_str = end_time.strftime(fmt)
        start_time = end_time - timedelta(days=7)
        start_time_str = start_time.strftime(fmt)
        logger.info("keywords={} tag={} start_time={}, end_time={}".format(
            keywords, tag, start_time_str, end_time_str))
        report_uuid, commit_results = self.search_autoblame(
            keywords, branch, tag, start_time_str, end_time_str)
        if report_uuid is not None:
            kusto_row_data['failure_level_info']['found_related_commit'] = True
            logger.info("Found {} related commits for case {} autoblame_id={}".format(
                len(commit_results['commits']), case_name_branch, report_uuid))
            logger.debug("Related commits for case {}:{}".format(
                case_name_branch, commit_results['commits']))
            autoblame_table.extend(commit_results['commits'])
        kusto_row_data["autoblame_id"] = report_uuid

        # Check and set trigger icm flag
        history_case_branch_df = history_case_df[history_case_df['BranchName'] == branch]
        kusto_table = self.trigger_icm(
            case_name_branch, history_testcases, history_case_branch_df, kusto_row_data, is_module_path)
        return kusto_table, autoblame_table

    def trigger_icm(self, case_name_branch, history_testcases, history_case_branch_df, kusto_row_data, is_module_path=False):
        kusto_table = []
        regression_success_rate_threshold = self.config_info[
            "threshold"]["regression_success_rate_percent"]
        if is_module_path:
            items = case_name_branch.split("#")
            module_path = items[0]
            case_name = module_path
            branch = items[1]
        else:
            items = case_name_branch.split("#")
            case_name = items[0].split('.')[-1]
            module_path = items[0][:-len(case_name)-1]
            branch = items[1]

        if "internal" in branch or "master" in branch:
            internal_version = True
        else:
            internal_version = False

        total_success_rate = int(
            history_testcases[case_name_branch]['total_success_rate'].split("%")[0])
        # Step 1. If total success rate for this case#branch is lower than threshold, it will generate ine IcM with title [case][branch]
        if total_success_rate == 0:
            logger.info("All cases for {} on branch {} failed in 30 days.".format(
                case_name, branch))
            kusto_row_data['failure_level_info']['is_full_failure'] = True
            kusto_row_data['trigger_icm'] = True
            if is_module_path:
                kusto_row_data['subject'] = "[" + module_path + "][" + branch + "]"
            else:
                kusto_row_data['subject'] = "[" + module_path + "][" + case_name + "][" + branch + "]"
            kusto_table.append(kusto_row_data)
        elif total_success_rate < regression_success_rate_threshold:
            logger.info("Success rate of {} on branch {} is lower than {}.".format(
                case_name, branch, regression_success_rate_threshold))
            # kusto_row_data['failure_level_info']['is_regression'] = True
            kusto_row_data['trigger_icm'] = True
            if is_module_path:
                kusto_row_data['subject'] = "[" + module_path + "][" + branch + "]"
            else:
                kusto_row_data['subject'] = "[" + module_path + "][" + case_name + "][" + branch + "]"
            kusto_table.append(kusto_row_data)
        else:
            # Step 2. Check if every os version has success rate lower than threshold
            # For one specific os version, for 202012 and 202205, only check its success rate when total case is higher than 3,
            # for internal and master, only check its success rate when total case is higher than 2,
            # otherwise ignore this os version.
            per_os_version_info = history_testcases[case_name_branch]["per_os_version_info"]
            total_case_minimum_release_version = self.config_info[
                'threshold']['total_case_minimum_release_version']
            total_case_minimum_internal_version = self.config_info[
                'threshold']['total_case_minimum_internal_version']

            for os_version_pass_rate in per_os_version_info["success_rate"]:
                os_version = os_version_pass_rate.split(":")[0].strip()
                success_rate = os_version_pass_rate.split(":")[1].strip()
                total_number = int(success_rate.split("/")[2])
                pass_rate = int(success_rate.split("%")[0])
                if (internal_version and total_number > total_case_minimum_internal_version) or (not internal_version and total_number > total_case_minimum_release_version):
                    if pass_rate < regression_success_rate_threshold:
                        # kusto_row_data['failure_level_info']['is_regression'] = True
                        kusto_row_data['trigger_icm'] = True
                        if is_module_path:
                            kusto_row_data['subject'] = "[" + module_path + "][" + branch + "]"
                        else:
                            kusto_row_data['subject'] = "[" + module_path + "][" + case_name + "][" + branch + "]"
                        kusto_table.append(kusto_row_data)
                        logger.info("{} os_version {} success_rate {} generate one IcM.".format(
                            case_name_branch, os_version, success_rate))
                        return kusto_table
                else:
                    logger.info("{} os_version {} success_rate {} total case number is higher than threshold, ignore this os version.".format(
                        case_name_branch, os_version, success_rate))
                    continue

            # Step 3. Check asic level
            per_asic_info = history_testcases[case_name_branch]["per_asic_info"]
            asic_hwsku_results = {}

            for asic_pass_rate in per_asic_info["success_rate"]:
                asic = asic_pass_rate.split(":")[0].strip()
                success_rate = asic_pass_rate.split(":")[1].strip()
                if int(success_rate.split("%")[0]) < regression_success_rate_threshold:
                    new_kusto_row_data_asic = kusto_row_data.copy()
                    # new_kusto_row_data_asic['failure_level_info']['is_regression'] = True
                    new_kusto_row_data_asic['trigger_icm'] = True
                    if is_module_path:
                        new_kusto_row_data_asic['subject'] = "[" + module_path + "][" + branch + "][" + asic + "]"
                    else:
                        new_kusto_row_data_asic['subject'] = "[" + module_path + "][" + case_name + "][" + branch + "][" + asic + "]"
                    kusto_table.append(new_kusto_row_data_asic)
                elif int(success_rate.split("%")[0]) == 100:
                    logger.info("{} The success rate on asic {} is 100%, skip it.".format(
                        case_name_branch, asic))
                    continue
                else:
                    asic_case_df = history_case_branch_df[history_case_branch_df['AsicType'] == asic]
                    logger.info("{} asic_case_df for asic {} is :{}".format(
                        case_name_branch, asic, asic_case_df))
                    filter_success_rate_results = self.calculate_success_rate(
                        asic_case_df, 'HardwareSku', 'hwsku')
                    logger.info("{} success rate after filtering by asic {}: {}".format(
                        case_name_branch, asic, json.dumps(filter_success_rate_results, indent=4)))
                    asic_hwsku_results.update(
                        {asic: filter_success_rate_results})
            # Step 4. Check hwsku level
            for asic, result in asic_hwsku_results.items():
                asic_case_df = history_case_branch_df[history_case_branch_df['AsicType'] == asic]
                for hwsku_pass_rate in result["success_rate"]:
                    hwsku = hwsku_pass_rate.split(":")[0].strip()
                    success_rate = hwsku_pass_rate.split(":")[1].strip()
                    hwsku_df = asic_case_df[asic_case_df['HardwareSku'] == hwsku]
                    latest_row = hwsku_df.iloc[0]
                    oldest_result = latest_row['Result']
                    if int(success_rate.split("%")[0]) < regression_success_rate_threshold:
                        if oldest_result == "success":
                            logger.info("{} Latest row for hwsku {} asic {} is success, skip it. Latest row {}".format(
                                case_name_branch, hwsku, asic, latest_row))
                            continue
                        new_kusto_row_data_hwsku = kusto_row_data.copy()
                        # new_kusto_row_data_hwsku['failure_level_info']['is_regression'] = True
                        new_kusto_row_data_hwsku['trigger_icm'] = True
                        if is_module_path:
                            new_kusto_row_data_hwsku['subject'] = "[" + module_path + "][" + branch + "][" + asic + "][" + hwsku + "]"
                        else:
                            new_kusto_row_data_hwsku['subject'] = "[" + module_path + "][" + case_name + \
                                    "][" + branch + "][" + asic + "][" + hwsku + "]"
                        kusto_table.append(new_kusto_row_data_hwsku)

        # TODO: check if case is recent failure
        # if 'is_recent_failure' in history_testcases[case_name_branch] and history_testcases[case_name_branch]['is_recent_failure']:
        #     kusto_row_data['failure_level_info']['is_recent_failure'] = True
        #     kusto_row_data['trigger_icm'] = True
        return kusto_table

    def is_flaky(self, case_name, history_testcases):
        pass

    def search_autoblame(self, keywords, branch, tag, starttime, endtime):
        """
        Search keywords in Autoblame II with specific repo and branch
        Call Auboblame's API to get results
        """
        valid_branches = self.config_info['auto_blame_branch']['branches']
        if branch not in valid_branches:
            logger.error(
                "Get autoblame response failed with invalid branch: {}".format(branch))
            return None, None
        branch_list = self.config_info['auto_blame_branch'][branch]
        repo_list = self.config_info['auto_blame_repo'][branch]
        return self.search_autoblame_upload(keywords, repo_list, branch_list, starttime, endtime, tag)

    def search_autoblame_upload(self, keywords, repo_list, branch_list, starttime, endtime, tag):
        """
        Search keywords in Autoblame II with specific repo and branch
        Call Auboblame's API to get results

        """
        reportid = str(uuid.uuid4())
        # keywords is a list
        res = {}
        res['reportid'] = reportid
        res['commits'] = []
        params = {}
        params['repo'] = repo_list
        params['branch'] = branch_list
        params['keywords'] = keywords
        params['starttime'] = starttime
        params['endtime'] = endtime
        params['tag'] = tag
        AUTO_BLAME_URL = 'https://sonic-webtools-backend-dev.azurewebsites.net/vue-admin-template/blame/analyzer'
        try:
            resp = requests.get(AUTO_BLAME_URL, params=params).json()
            item_list = resp.get('data')['items']
            upload_datas = []
            for report in item_list:
                report.update({
                    'reportid': reportid,
                    'keyword': ','.join(keywords)
                })
                upload_datas.append(report)

            # timestamp +items uuid,list
            # store to kusto
            if len(upload_datas) == 0:
                logger.info("No commit found for keywords {} on branch {}".format(
                    keywords, branch_list))
                return None, None
            res['commits'] = upload_datas
        except Exception as e:
            logger.error(
                "Get autoblame response failed with exception: {}".format(repr(e)))
            logger.error(traceback.format_exc())
            return None, None
        return reportid, res

    def init_parent_relations2list(self, parent_id):
        """
        Request url of given parent_id to get its relations including parent, child, relative
        Get child fields by above children url, then store one standby list for next function search_ADO
        """
        workitem_parent_url = "https://dev.azure.com/msazure/One/_apis/wit/workitems?id=" + \
            str(parent_id) + "&$expand=all"
        logger.info("parent workitem url:{}".format(workitem_parent_url))
        try:
            parent_relations = requests.get(
                workitem_parent_url, auth=AUTH).json()["relations"]
            if not parent_relations:
                logger.error(
                    "Failed to get work items from parent_id {}".format(parent_id))
                return

            child_url_set = set()
            for relation in parent_relations:
                if relation and relation["attributes"]["name"] == "Child":
                    child_url_set.add(relation["url"])
            child_url_list = list(child_url_set)
        except Exception as e:
            logger.error(
                "Get parent work item but throw an exception: {}".format((repr(e))))
            logger.error(traceback.format_exc())
            return

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(
                self.child_url_extract_fields, url) for url in child_url_list]
            for future in as_completed(futures):
                self.child_standby_list.append(future.result())

    def child_url_extract_fields(self, child_url):
        if not child_url:
            logger.eror("child url is null")
            return
        try:
            child_dict = requests.get(child_url, auth=AUTH).json()
            child_fields_dict = child_dict["fields"]
            if not child_fields_dict:
                logger.eror(
                    "Failed to get fields of work items from child_id {}".format(child_dict["id"]))
                return
        except Exception as e:
            logger.error(
                "Get child work items but throw an exception: {}".format((repr(e))))
            logger.error(traceback.format_exc())
            return
        child_core_attribute = {
            "ID": child_dict["id"],
            "title": child_fields_dict.get("System.Title", "No title"),
            "URL": child_dict["url"],
            "status": child_fields_dict.get("System.State", "No status"),
            "owner": child_fields_dict["System.CreatedBy"].get("displayName", "No owner"),
            "tags": child_fields_dict.get("System.Tags", "No tag"),
            "createdDate": child_fields_dict.get("System.CreatedDate", "No CreatedDate"),
            "changedDate": child_fields_dict.get("System.ChangedDate", "No ChangedDate")
        }
        return child_core_attribute

    def search_ADO(self, keywords, is_resolved_included=False):
        """
        Search title or content in ADO with keywords
        Call ADO's API to get results
        parent ID: 13410102
        keywords: not a single word for test case name, it should be a list, contains test case name and module path.
        is_resovled_included: True, all of results included Done ones. False, only return work items which is not Done.
        return results should be a list:
        The relation is OR, the return result contains related work items both for test case and module path.
        ID, title, URL, status, owner, tags.
        """
        result_list = []
        for child_dict in self.child_standby_list:
            child_title = child_dict["title"]
            if child_title == "No title":
                continue

            for keyword in keywords:
                if child_title.lower().find(keyword.lower()) != -1:
                    if is_resolved_included:
                        result_list.append(child_dict)
                    elif child_dict["status"] != "Done":
                        result_list.append(child_dict)
                    break

        return result_list


def parse_config_file():
    configuration = {}
    with open(CONFI_FILE) as f:
        configuration = json.load(f)

    if not configuration:
        logger.error("Config config doesn't exist, please check.")
        sys.exit(1)
    return configuration


def main(icm_limit):
    start_time = datetime.utcnow()
    configuration = parse_config_file()
    kusto_connector = KustoConnector(configuration)
    analyzer = Analyzer(kusto_connector, configuration)

    analyzer.run(icm_limit)

    end_time = datetime.utcnow()
    logger.info("Cost {} for this run.".format(end_time - start_time))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Analyze test result")

    parser.add_argument(
        "--new_icm_limit", "-n",
        type=int,
        required=False,
        help="The maximum number of new IcM for this run.",
    )

    args = parser.parse_args()
    new_icm_limit = args.new_icm_limit
    logger.info("new_icm_limit={}".format(new_icm_limit))
    main(new_icm_limit)
