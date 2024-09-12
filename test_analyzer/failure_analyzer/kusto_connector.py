import os
import logging
from config import configuration
from datetime import timedelta
import tempfile
import json
import sys


from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
from azure.kusto.data.helpers import dataframe_from_result_table
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

CONFI_FILE = 'test_failure_config.json'
DATABASE = 'SonicTestData'
ICM_DATABASE = 'IcMDataWarehouse'
ADO_DATABASE = 'AzureDevOps'
PARENT_ID1 = "13410203"
PARENT_ID2 = "16726166"

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)


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

    def __init__(self, config_info, current_time):
        self.logger = logging.getLogger('KustoChecker')

        configuration = config_info
        self.db_name = DATABASE
        self.icm_db_name = ICM_DATABASE
        self.ado_db_name = ADO_DATABASE
        self.search_end_time = current_time
        self.search_start_time = self.search_end_time - \
            timedelta(days=int(configuration['threshold']['duration_days']))
        self.history_start_time = self.search_end_time - \
            timedelta(days=int(configuration['threshold']['history_days']))

        logger.info("Select 7 days' start time: {}, 30 days' start time: {}, current time: {}".format(self.search_start_time, self.history_start_time, self.search_end_time))

        ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
        access_token = os.environ.get('ACCESS_TOKEN', None)

        icm_cluster = os.getenv("ICM_KUSTO_CLUSTER")
        ado_cluster = os.getenv("ADO_KUSTO_CLUSTER")

        if not ingest_cluster or not access_token:
            logger.error(
                "Could not load backup Kusto Credentials from environment, please check your environment setting.")
            self._ingestion_client_backup = None
        else:
            cluster = ingest_cluster.replace('ingest-', '')
            kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster,
                                                                                        access_token)
            kcsb_ingest = KustoConnectionStringBuilder.with_aad_application_token_authentication(ingest_cluster,
                                                                                               access_token)
            self.client_backup = KustoClient(kcsb)
            self._ingestion_client_backup = KustoIngestClient(kcsb_ingest)

        if not icm_cluster:
            logger.error(
                "Could not load IcM cluster url from environment, please check your environment setting.")
            self._icm_client = None
        else:
            icm_kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(icm_cluster,
                                                                                            access_token)

            self.icm_client = KustoClient(icm_kcsb)
        if not ado_cluster:
            logger.error(
                "Could not load ADO cluster url from environment, please check your environment setting.")
            self._ado_client = None
        else:
            ado_kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(ado_cluster,
                                                                                            access_token)

            self.ado_client = KustoClient(ado_kcsb)

    def icm_query(self, query):
        self.logger.debug('Query String: {}'.format(query))
        return self.icm_client.execute(self.icm_db_name, query)

    def ado_query(self, query):
        self.logger.debug('Query String: {}'.format(query))
        return self.ado_client.execute(self.ado_db_name, query)

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
            | where Title contains "[SONiC_Nightly][Failed_Case]"
            | where Status == "ACTIVE"
            | where IsPurged == false or isempty(IsPurged)
            | project IncidentId, Title, SourceCreateDate, ModifiedDate, Status
            | sort by SourceCreateDate
            '''
        logger.info("Query active icm:{}".format(query_str))
        return self.icm_query(query_str)

    def query_ado(self):
        """
        Query active IcMs for SONiC Nightly Test queue.
        """
        query_str = '''
            WorkItem
            | where TeamProject == "One" and Tags contains "sonic-nightly" and WorkItemType == "Product Backlog Item"
            | where IsDeleted != true
            | summarize arg_max(CreatedDate,*) by WorkItemId
            | extend URL =strcat("https://msazure.visualstudio.com/One/_workitems/edit/", WorkItemId)
            | extend Owner=AssignedToDisplayName
            | project WorkItemId,Title, Tags, Owner, CreatedDate, ChangedDate, State,URL
            | sort by CreatedDate desc
            '''
        logger.info("Query ado:{}".format(query_str))
        return self.ado_query(query_str)

    def query_summary_results(self):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        query_str = '''
            let ProdQualOSList = dynamic({});
            let ResultFilterList = dynamic(["failure", "error"]);
            let ExcludeTestbedList = dynamic({});
            let ExcludeBranchList = dynamic({});
            let ExcludeHwSkuList = dynamic({});
            let ExcludeTopoList = dynamic({});
            let ExcludeAsicList = dynamic({});
            let SummaryWhileList = dynamic({});
            TestReportUnionData
            | where PipeStatus == 'FINISHED'
            | where TestbedName != ''
            | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
            | where OSVersion has_any(ProdQualOSList)
            | where Result in (ResultFilterList)
            | where not(TestbedName has_any(ExcludeTestbedList))
            | where not (HardwareSku has_any(ExcludeHwSkuList))
            | where not(TopologyType has_any(ExcludeTopoList))
            | where not(AsicType has_any(ExcludeAsicList))
            | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
            | join kind = inner (TestReportUnionData
            | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({}) and OSVersion has_any(ProdQualOSList)
            | where Result in (ResultFilterList)
            | where Summary !in (SummaryWhileList)
            | where not(BranchName has_any(ExcludeBranchList))
            | summarize arg_max(RunDate, *) by opTestCase, BranchName, ModulePath, TestbedName, Result
            | summarize ReproCount = count() by BranchName, ModulePath, Summary, Result
            | project ReproCount, Result, BranchName,ModulePath,Summary)
                                                            on $left.BranchName == $right.BranchName,
                                                                $left.ModulePath == $right.ModulePath,
                                                                $left.Summary == $right.Summary,
                                                                $left.Result == $right.Result
                                                                | sort by ReproCount desc
            | where not(BranchName has_any(ExcludeBranchList))
            | where BranchName in(ProdQualOSList)
            | where OSVersion !contains "cisco"
            | where OSVersion !contains "nokia"
            | project ReproCount, UploadTimestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, FullCaseName, Result, BranchName, OSVersion, TestbedName, Asic, TopologyType, Summary, BuildId, PipeStatus
            | distinct ModulePath,BranchName,ReproCount, Result,Summary
            | where ReproCount >= {}
            | sort by ReproCount, ModulePath
            '''.format(configuration["branch"]["included_branch"], configuration["testbeds"]["excluded_testbed_keywords_setup_error"],
                   configuration["branch"]["excluded_branch_setup_error"], configuration["hwsku"]["excluded_hwsku"],
                   configuration['topo']['excluded_topo'], configuration['asic']['excluded_asic'], configuration['summary_white_list'],
                   self.search_start_time, self.search_end_time, self.search_start_time, self.search_end_time,
                   configuration['threshold']['repro_count_limit_summary'])
        logger.info("Query common summary cases:{}".format(query_str))
        return self.query(query_str)

    def query_common_summary_results(self):
        """
        Query common summary failed test cases for the past 7 days
        """
        query_str = '''
        let ProdQualOSList = dynamic({});
        let ResultFilterList = dynamic(["failure", "error"]);
        let ExcludeTestbedList = dynamic({});
        let ExcludeBranchList = dynamic({});
        let ExcludeHwSkuList = dynamic({});
        let ExcludeTopoList = dynamic({});
        let ExcludeAsicList = dynamic({});
        let SummaryWhileList = dynamic({});
        TestReportUnionData
        | where PipeStatus == 'FINISHED'
        | where TestbedName != ''
        | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
        | where OSVersion has_any(ProdQualOSList)
        | where Result in (ResultFilterList)
        | where not(TestbedName has_any(ExcludeTestbedList))
        | where not (HardwareSku has_any(ExcludeHwSkuList))
        | where not(TopologyType has_any(ExcludeTopoList))
        | where not(AsicType has_any(ExcludeAsicList))
        | where Summary in (SummaryWhileList)
        | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
        | join kind = inner (TestReportUnionData
            | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({}) and OSVersion has_any(ProdQualOSList)
            | where Result in (ResultFilterList)
            | where Summary in (SummaryWhileList)
            | where not(BranchName has_any(ExcludeBranchList))
            | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
            | summarize ReproCount = count() by OSVersion, ModulePath, opTestCase, Result)
                                                           on $left.OSVersion == $right.OSVersion,
                                                            $left.ModulePath == $right.ModulePath,
                                                            $left.opTestCase == $right.opTestCase,
                                                            $left.Result == $right.Result
        | where not(BranchName has_any(ExcludeBranchList))
        | where BranchName in(ProdQualOSList)
        | where OSVersion !contains "cisco"
        | where OSVersion !contains "nokia"
        | project ReproCount, UploadTimestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, FullCaseName, Result, BranchName, OSVersion, TestbedName, Asic, TopologyType, Summary, BuildId, PipeStatus
        | distinct UploadTimestamp, Feature, ModulePath, OSVersion, BranchName, Summary, BuildId, TestbedName, ReproCount
        | where ReproCount >= {}
        | sort by ReproCount, ModulePath
        '''.format(configuration["branch"]["included_branch"], configuration["testbeds"]["excluded_testbed_keywords_setup_error"],
                   configuration["branch"]["excluded_branch_setup_error"], configuration["hwsku"]["excluded_hwsku"],
                   configuration['topo']['excluded_topo'], configuration['asic']['excluded_asic'], configuration['summary_white_list'],
                   self.search_start_time, self.search_end_time, self.search_start_time, self.search_end_time,
                   configuration['threshold']['repro_count_limit'])
        logger.info("Query common summary failure cases:{}".format(query_str))
        return self.query(query_str)

    def query_test_setup_failure(self):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        query_str = '''
        let ProdQualOSList = dynamic({});
        let ResultFilterList = dynamic(["failure", "error"]);
        let ExcludeTestbedList = dynamic({});
        let ExcludeBranchList = dynamic({});
        let ExcludeHwSkuList = dynamic({});
        let ExcludeTopoList = dynamic({});
        let ExcludeAsicList = dynamic({});
        TestReportUnionData
        | where PipeStatus == 'FINISHED'
        | where TestbedName != ''
        | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
        | where OSVersion has_any(ProdQualOSList)
        | where Result in (ResultFilterList)
        | where not(TestbedName has_any(ExcludeTestbedList))
        | where not (HardwareSku has_any(ExcludeHwSkuList))
        | where not(TopologyType has_any(ExcludeTopoList))
        | where not(AsicType has_any(ExcludeAsicList))
        | where Summary contains "test setup failure"
        | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
        | join kind = inner (TestReportUnionData
            | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({}) and OSVersion has_any(ProdQualOSList)
            | where Result in (ResultFilterList)
            | where Summary contains "test setup failure"
            | where not(BranchName has_any(ExcludeBranchList))
            | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
            | summarize ReproCount = count() by OSVersion, ModulePath, opTestCase, Result)
                                                           on $left.OSVersion == $right.OSVersion,
                                                            $left.ModulePath == $right.ModulePath,
                                                            $left.opTestCase == $right.opTestCase,
                                                            $left.Result == $right.Result
        | where not(BranchName has_any(ExcludeBranchList))
        | where BranchName in(ProdQualOSList)
        | where OSVersion !contains "cisco"
        | where OSVersion !contains "nokia"
        | project ReproCount, UploadTimestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, FullCaseName, Result, BranchName, OSVersion, TestbedName, Asic, TopologyType, Summary, BuildId, PipeStatus
        | distinct UploadTimestamp, Feature, ModulePath, OSVersion, BranchName, Summary, BuildId, TestbedName, ReproCount
        | where ReproCount >= {}
        | sort by ReproCount, ModulePath
        '''.format(configuration["branch"]["included_branch"], configuration["testbeds"]["excluded_testbed_keywords_setup_error"],
                   configuration["branch"]["excluded_branch_setup_error"], configuration["hwsku"]["excluded_hwsku"],
                   configuration['topo']['excluded_topo'], configuration['asic']['excluded_asic'],
                   self.search_start_time, self.search_end_time, self.search_start_time, self.search_end_time,
                   configuration['threshold']['repro_count_limit_setup_error'])
        logger.info("Query test setup failure cases:{}".format(query_str))
        return self.query(query_str)

    def query_failed_testcase(self):
        """
        Query failed test cases for the past 7 days, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        query_str = '''
        let ProdQualOSList = dynamic({});
        let ResultFilterList = dynamic(["failure", "error"]);
        let ExcludeTestbedList = dynamic({});
        let ExcludeBranchList = dynamic({});
        let ExcludeHwSkuList = dynamic({});
        let ExcludeTopoList = dynamic({});
        let ExcludeAsicList = dynamic({});
        TestReportUnionData
        | where PipeStatus == 'FINISHED'
        | where TestbedName != ''
        | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
        | where OSVersion has_any(ProdQualOSList)
        | where Result in (ResultFilterList)
        | where not(TestbedName has_any(ExcludeTestbedList))
        | where not (HardwareSku has_any(ExcludeHwSkuList))
        | where not(TopologyType has_any(ExcludeTopoList))
        | where not(AsicType has_any(ExcludeAsicList))
        | extend opTestCase = case(TestCase has'[', split(TestCase, '[')[0], TestCase)
        | extend FullCaseName = strcat(ModulePath,".",opTestCase)
        | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
        | join kind = inner (TestReportUnionData
            | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({}) and OSVersion has_any(ProdQualOSList)
            | where Result in (ResultFilterList)
            | where Summary !contains "test setup failure"
            | where not(BranchName has_any(ExcludeBranchList))
            | summarize arg_max(RunDate, *) by opTestCase, OSVersion, ModulePath, TestbedName, Result
            | summarize ReproCount = count() by OSVersion, ModulePath, opTestCase, Result)
                                                        on $left.OSVersion == $right.OSVersion,
                                                            $left.ModulePath == $right.ModulePath,
                                                            $left.opTestCase == $right.opTestCase,
                                                            $left.Result == $right.Result
        | where not(BranchName has_any(ExcludeBranchList))
        | where BranchName in(ProdQualOSList)
        | where OSVersion !contains "cisco"
        | where OSVersion !contains "nokia"
        | where ReproCount >= {}
        | where ModulePath != ""
        | project ReproCount, UploadTimestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, FullCaseName, Result, BranchName, OSVersion, TestbedName, Asic, TopologyType, Summary, BuildId, PipeStatus
        | sort by ReproCount, ModulePath, opTestCase, Result
        '''.format(configuration["branch"]["included_branch"], configuration["testbeds"]["excluded_testbed_keywords"],
                   configuration["branch"]["excluded_branch"], configuration["hwsku"]["excluded_hwsku"],
                   configuration['topo']['excluded_topo'], configuration['asic']['excluded_asic'],
                   self.search_start_time, self.search_end_time, self.search_start_time, self.search_end_time,
                   configuration['threshold']['repro_count_limit'])
        logger.info("Query failed cases:{}".format(query_str))
        return self.query(query_str)

    def query_failed_testcase_release(self, release_branch):

        query_str = '''
        let ProdQualOSList = dynamic(["{}"]);
        let ResultFilterList = dynamic(["failure", "error"]);
        let ExcludeTestbedList = dynamic({});
        let ExcludeBranchList = dynamic({});
        let ExcludeHwSkuList = dynamic({});
        let ExcludeTopoList = dynamic({});
        let ExcludeAsicList = dynamic({});
        let SummaryWhileList = dynamic({});
        TestReportUnionData
        | where PipeStatus == 'FINISHED'
        | where TestbedName != ''
        | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
        | where OSVersion has_any(ProdQualOSList)
        | where Result in (ResultFilterList)
        | where not(TestbedName has_any(ExcludeTestbedList))
        | where not (HardwareSku has_any(ExcludeHwSkuList))
        | where not(TopologyType has_any(ExcludeTopoList))
        | where not(AsicType has_any(ExcludeAsicList))
        | where not(BranchName has_any(ExcludeBranchList))
        | where BranchName in(ProdQualOSList)
        | where OSVersion !contains "cisco"
        | where OSVersion !contains "nokia"
        | where Summary !in (SummaryWhileList)
        | where ModulePath != ""
        | project UploadTimestamp, Feature, ModulePath, FullTestPath, TestCase, opTestCase, FullCaseName, Summary, Result, BranchName, OSVersion, TestbedName, Asic, TopologyType, BuildId, PipeStatus
        | sort by ModulePath, opTestCase, Result
        '''.format(release_branch, configuration["testbeds"]["excluded_testbed_keywords"],
                   configuration["branch"]["excluded_branch"], configuration["hwsku"]["excluded_hwsku"],
                   configuration['topo']['excluded_topo'], configuration['asic']['excluded_asic'], configuration['summary_white_list'],
                   self.search_start_time, self.search_end_time)
        logger.info(
            "Query 7 days's failed cases for branch {}:{}".format(release_branch, query_str))
        return self.query(query_str)

    def query_failed_testcase_cross_branch(self):
        query_str = '''
        let ProdQualOSList = dynamic({});
        let ResultFilterList = dynamic(["failure", "error"]);
        let ExcludeTestbedList = dynamic({});
        let ExcludeBranchList = dynamic({});
        let ExcludeHwSkuList = dynamic({});
        let ExcludeTopoList = dynamic({});
        let ExcludeAsicList = dynamic({});
        let SummaryWhileList = dynamic({});
        TestReportUnionData
        | where PipeStatus == 'FINISHED'
        | where TestbedName != ''
        | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
        | where OSVersion has_any(ProdQualOSList)
        | where Result in (ResultFilterList)
        | where not(TestbedName has_any(ExcludeTestbedList))
        | where not (HardwareSku has_any(ExcludeHwSkuList))
        | where not(TopologyType has_any(ExcludeTopoList))
        | where not(AsicType has_any(ExcludeAsicList))
        | where not(BranchName has_any(ExcludeBranchList))
        | where BranchName in(ProdQualOSList)
        | where OSVersion !contains "cisco"
        | where OSVersion !contains "nokia"
        | where ModulePath != ""
        | where Summary !in (SummaryWhileList)
        | project UploadTimestamp, Feature, ModulePath, FullTestPath, FullCaseName, TestCase, opTestCase, Summary, Result, BranchName, OSVersion, TestbedName, Asic, AsicType, TopologyType, HardwareSku, BuildId, PipeStatus
        | sort by UploadTimestamp desc
        '''.format(configuration["branch"]["included_branch"], configuration["testbeds"]["excluded_testbed_keywords"],
                   configuration["branch"]["excluded_branch"], configuration["hwsku"]["excluded_hwsku"],
                   configuration['topo']['excluded_topo'], configuration['asic']['excluded_asic'], configuration['summary_white_list'],
                   self.search_start_time, self.search_end_time)
        logger.info(
            "Query 7 days's failed cases cross branches:{}".format(query_str))
        return self.query(query_str)

    def query_history_results(self, testcase_name, module_path, is_module_path=False):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        project UploadTimestamp, OSVersion, BranchName, HardwareSku, TestbedName, AsicType, Platform, Topology, Asic, TopologyType, Feature, TestCase, opTestCase, ModulePath, FullCaseName, Result
        """
        if is_module_path:
            query_str = '''
                let ProdQualOSList = dynamic({});
                let ResultFilterList = dynamic(["failure", "error"]);
                let ExcludeTestbedList = dynamic({});
                let ExcludeBranchList = dynamic({});
                let ExcludeHwSkuList = dynamic({});
                let ExcludeTopoList = dynamic({});
                let ExcludeAsicList = dynamic({});
                TestReportUnionData
                | where PipeStatus == 'FINISHED'
                | where TestbedName != ''
                | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
                | where OSVersion has_any(ProdQualOSList)
                | where Result !in ("skipped", "xfail_forgive", "xfail_expected", "xfail_unexpected")
                | where not(TestbedName has_any(ExcludeTestbedList))
                | where not (HardwareSku has_any(ExcludeHwSkuList))
                | where not(TopologyType has_any(ExcludeTopoList))
                | where not(AsicType has_any(ExcludeAsicList))
                | where not(BranchName has_any(ExcludeBranchList))
                | where BranchName in(ProdQualOSList)
                | where OSVersion !contains "cisco"
                | where OSVersion !contains "nokia"
                | where ModulePath == "{}"
                | order by UploadTimestamp desc
                | project UploadTimestamp, OSVersion, BranchName, HardwareSku, TestbedName, AsicType, Platform, Topology, Asic, TopologyType, Feature, TestCase, opTestCase, ModulePath, FullCaseName, Result, BuildId, PipeStatus
                '''.format(configuration["branch"]["included_branch"], configuration["testbeds"]["excluded_testbed_keywords_setup_error"],
                           configuration["branch"]["excluded_branch_setup_error"], configuration["hwsku"]["excluded_hwsku"],
                           configuration['topo']['excluded_topo'], configuration['asic']['excluded_asic'],
                           self.history_start_time, self.search_end_time,  module_path)
        else:
            query_str = '''
                let ProdQualOSList = dynamic({});
                let ResultFilterList = dynamic(["failure", "error"]);
                let ExcludeTestbedList = dynamic({});
                let ExcludeBranchList = dynamic({});
                let ExcludeHwSkuList = dynamic({});
                let ExcludeTopoList = dynamic({});
                let ExcludeAsicList = dynamic({});
                TestReportUnionData
                | where PipeStatus == 'FINISHED'
                | where TestbedName != ''
                | where UploadTimestamp > datetime({}) and UploadTimestamp <= datetime({})
                | where OSVersion has_any(ProdQualOSList)
                | where Result !in ("skipped", "xfail_forgive", "xfail_expected", "xfail_unexpected")
                | where not(TestbedName has_any(ExcludeTestbedList))
                | where not (HardwareSku has_any(ExcludeHwSkuList))
                | where not(TopologyType has_any(ExcludeTopoList))
                | where not(AsicType has_any(ExcludeAsicList))
                | where not(BranchName has_any(ExcludeBranchList))
                | where BranchName in(ProdQualOSList)
                | where OSVersion !contains "cisco"
                | where OSVersion !contains "nokia"
                | where opTestCase == "{}" and ModulePath == "{}"
                | order by UploadTimestamp desc
                | project UploadTimestamp, OSVersion, BranchName, HardwareSku, TestbedName, AsicType, Platform, Topology, Asic, TopologyType, Feature, TestCase, opTestCase, ModulePath, FullCaseName, Result, BuildId, PipeStatus
                '''.format(configuration["branch"]["included_branch"], configuration["testbeds"]["excluded_testbed_keywords"],
                           configuration["branch"]["excluded_branch"], configuration["hwsku"]["excluded_hwsku"],
                           configuration['topo']['excluded_topo'], configuration['asic']['excluded_asic'],
                           self.history_start_time, self.search_end_time, testcase_name, module_path)
        logger.info("Query hisotry results:{}".format(query_str))
        return self.query(query_str)

    def query_previsou_upload_record(self, title):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        query_str = '''
            TestcaseAnalysis
            | where Subject == "{}"
            | where TriggerIcM == 'true'
            | project UploadTimestamp, ModulePath, TestCase, Branch, Subject, FailureSummary
            | sort by UploadTimestamp
            | take 1
            '''.format(title)
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
