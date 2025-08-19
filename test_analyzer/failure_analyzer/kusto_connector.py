import os
import logging
from config import configuration, logger, DATABASE, ICM_DATABASE, ADO_DATABASE
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


class KustoConnector(object):
    """connect the Kusto and run query"""
    TEST_CASE_ANALYSIS_TABLE = "NightlyTestFailureAnalysis"
    AUTO_BLAME_REPORT_TABLE = "AutoBlameReport"

    TABLE_FORMAT_LOOKUP = {
        TEST_CASE_ANALYSIS_TABLE: DataFormat.JSON,
        AUTO_BLAME_REPORT_TABLE: DataFormat.JSON
    }

    TABLE_MAPPING_LOOKUP = {
        TEST_CASE_ANALYSIS_TABLE: "NightlyTestFailureAnalysisMappingV1",
        AUTO_BLAME_REPORT_TABLE: "AutoBlameReportMapping"
    }

    def __init__(self, current_time):
        self.logger = logging.getLogger('KustoChecker')

        self.db_name = DATABASE
        self.icm_db_name = ICM_DATABASE
        self.ado_db_name = ADO_DATABASE
        self.search_end_time = current_time
        self.search_start_time = self.search_end_time - \
            timedelta(days=int(configuration['threshold']['duration_days']))
        self.history_start_time = self.search_end_time - \
            timedelta(days=int(configuration['threshold']['history_days']))

        # Contains all of the common variables for queries to share, based on configuration
        self.query_head = f'''
            let exact_match_os_list = dynamic(['master', 'internal']);
            let prefix_match_os_list = dynamic({configuration["branch"]["released_branch"]});
            let prod_branch_name_prefix_pattern = strcat("^(", strcat_array(prefix_match_os_list, "|"), @")\\d{{2}}$");
            let prod_os_version_prefix_pattern = strcat("^(", strcat_array(prefix_match_os_list, "|"), @")\\d{{2}}\\.\\d{{1,3}}$");
            let ResultFilterList = dynamic(["failure", "error"]);
            let ResultList = dynamic(["failure", "error", "success"]);
            let ExcludeTestbedList = dynamic({configuration["testbeds"]["excluded_testbed_keywords_setup_error"]});
            let ExcludeBranchList = dynamic({configuration["branch"]["excluded_branch_setup_error"]});
            let ExcludeHwSkuList = dynamic({configuration["hwsku"]["excluded_hwsku"]});
            let ExcludeTopoList = dynamic({configuration['topo']['excluded_topo']});
            let ExcludeAsicList = dynamic({configuration['asic']['excluded_asic']});
            let SummaryWhileList = dynamic({configuration['summary_white_list']});
        '''.rstrip()
        self.query_valid_condition = f'''
            | where PipeStatus == 'FINISHED'
            | where OSVersion has_any(exact_match_os_list) or OSVersion matches regex prod_os_version_prefix_pattern
            | where BranchName in(exact_match_os_list) or BranchName matches regex prod_branch_name_prefix_pattern
            | where TestBranch !contains "/"
            | extend BranchVersion = substring(BranchName, 0, 6)
            | where (
                    BranchName in ('master', 'internal') and TestBranch == 'internal'
                ) or (
                    BranchName !in ('master', 'internal') and (
                        TestBranch == strcat('internal-', BranchVersion) or
                        TestBranch == strcat('internal-', BranchVersion, '-chassis') or
                        TestBranch == strcat('internal-', BranchVersion, '-dev')
                    )
                ) or isempty(TestBranch)
        '''.rstrip()
        self.query_common_condition = f'''
            | where TestbedName != ''
            | where BranchName != ''
            | where not(TestbedName has_any(ExcludeTestbedList))
            | where not(HardwareSku has_any(ExcludeHwSkuList))
            | where not(TopologyType has_any(ExcludeTopoList))
            | where not(AsicType has_any(ExcludeAsicList))
            | where not(BranchName has_any(ExcludeBranchList))
        '''.rstrip()

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
        return self.icm_client.execute(self.icm_db_name, query)

    def ado_query(self, query):
        return self.ado_client.execute(self.ado_db_name, query)

    def query(self, query):
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

    def query_common_summary_results(self):
        """
        Query common summary failed test cases for the past 7 days
        """
        query_str = self.query_head + f'''
        TestReportUnionData
        | where UploadTimestamp > datetime({self.search_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
        '''.rstrip()
        query_str += self.query_valid_condition + self.query_common_condition + f'''
        | where Summary in (SummaryWhileList)
        | project UploadTimestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, FullCaseName, Result, BranchName, OSVersion, TestbedName, HardwareSku, Asic, AsicType, Topology, TopologyType, Summary, BuildId, PipeStatus
        | distinct UploadTimestamp, Feature, ModulePath, OSVersion, BranchName, Summary, BuildId, TestbedName, HardwareSku, Asic, AsicType, Topology, TopologyType
        | sort by ModulePath
        '''.rstrip()
        logger.info("Query common summary failure cases:\n{}".format(query_str))
        return self.query(query_str)

    def query_flaky_failure(self):
        """
        Query flaky cases in past 7 days.
        """
        query_str = self.query_head + f'''
        let buildsWithRetry = TestReportUnionData
        | where UploadTimestamp > datetime({self.search_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
        '''.rstrip()
        query_str += self.query_valid_condition + f'''
        | summarize maxAttempt = max(toint(Attempt)) by BuildId
        | where maxAttempt >= 1
        | project BuildId
        | distinct BuildId;
        let dataClean = TestReportUnionData
        | where Result in (ResultList)
        | where BuildId in (buildsWithRetry)
        | extend AttemptInt = toint(Attempt);
        let flakySummary = dataClean
        | summarize
            hasFailure = countif(Result in (ResultFilterList)) > 0,
            hasSuccess = countif(Result == "success") > 0
        by BuildId, FullCaseName
        | where hasFailure and hasSuccess;
        flakySummary
        | join kind=innerunique  (
            dataClean
        ) on BuildId, FullCaseName
        | where Result in (ResultFilterList)
        '''.rstrip()
        query_str += self.query_common_condition + f'''
        | extend FailedType = case(Summary contains "Pre-test sanity check failed","pre_sanity_check_failed",
                                    Summary contains "Recovery of sanity check failed","recovery_sanity_check_failed",
                                    Summary contains "stage_pre_test sanity check after recovery failed","stage_pre_test_sanity_check_failed",
                                    Summary contains "Did not receive expected packet" or Summary contains "Received expected packet", "PacketLoss",
                                    Summary contains "Match Messages:" and Summary contains "analyze_logs" ,"loganalyzer",
                                    Summary contains "bin/ptf --test-dir ptftests", "PtfScriptFailed",
                                    Summary contains "Not all critical processes are healthy","CriticalProcessUnhealthy",
                                    Summary contains "system cpu and memory usage check fails", "cpu memory check failed",
                                    Summary contains "tests.common.errors.RunAnsibleModuleFail: run module" and Summary contains "failed, Ansible Results", "RunAnsibleModuleFail",
                                    Summary contains "PSU", "PSU",
                                    Summary contains "fan ", "fan",
                                    Summary contains "AssertionError", "AssertionError",
                                    Summary contains "Host unreachable in the inventory", 'unreachable',
                                    Summary contains "memory usage" and Summary contains "exceeds high threshold", "MemoryExceed",
                                    Summary contains "failed on setup with", "SetupError",
                                    Summary contains "failed on teardown with", 'Teardown',
                                    "Others")
        | where FailedType in ("loganalyzer","PacketLoss","PtfScriptFailed","AssertionError","PSU")
        | where Summary !in (SummaryWhileList)
        | project UploadTimestamp, Feature, ModulePath, FullTestPath, FullCaseName, TestCase, opTestCase, Summary, FailedType, Result, BranchName, OSVersion, TestbedName, Asic, AsicType, TopologyType, Topology, HardwareSku, BuildId, PipeStatus
        | sort by UploadTimestamp desc
        '''.rstrip()
        logger.info("Query flaky failure cases:\n{}".format(query_str))
        return self.query(query_str)

    def query_consistent_failure(self):
        """
        Query consistent failure cases in past 7 days - cases that fail on all retry attempts.
        """
        query_str = self.query_head + f'''
        let buildsWithRetry = TestReportUnionData
        | where UploadTimestamp > datetime({self.search_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
        '''.rstrip()
        query_str += self.query_valid_condition + f'''
        | summarize maxAttempt = max(toint(Attempt)) by BuildId
        | where maxAttempt >= 1
        | project BuildId
        | distinct BuildId;
        let dataClean = TestReportUnionData
        | where Result in (ResultList)
        | where BuildId in (buildsWithRetry)
        | extend AttemptInt = toint(Attempt);
        let consistentFailures = dataClean
        | summarize
            totalAttempts = count(),
            failedAttempts = countif(Result in (ResultFilterList)),
            minAttempt = min(AttemptInt),
            maxAttempt = max(AttemptInt)
          by BuildId, FullCaseName
        | where totalAttempts == failedAttempts;
        consistentFailures
        | join kind=innerunique (
            dataClean
        ) on BuildId, FullCaseName
        | where Result in (ResultFilterList)
        | where Summary !in (SummaryWhileList)
        '''.rstrip()
        query_str += self.query_common_condition + f'''
        | where AttemptInt == maxAttempt
        | project UploadTimestamp, Feature, ModulePath, FullTestPath, FullCaseName, TestCase, opTestCase, Summary, Result, BranchName, OSVersion, TestbedName, Asic, AsicType, TopologyType, Topology, HardwareSku, BuildId, PipeStatus, minAttempt, maxAttempt
        | sort by UploadTimestamp desc
         '''.rstrip()
        logger.info("Query consistent failed cases:\n{}".format(query_str))
        return self.query(query_str)

    def query_legacy_failure(self):
        query_str = self.query_head + f'''
        let buildsWithoutRetry = TestReportUnionData
        | where UploadTimestamp > datetime({self.search_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
        '''.rstrip()
        query_str += self.query_valid_condition + f'''
        | summarize maxAttempt = max(toint(Attempt)) by BuildId
        | where maxAttempt == 0 or isnull(maxAttempt)
        | project BuildId
        | extend BuildId = case(BuildId has':', split(BuildId, ':')[0], BuildId)
        | distinct BuildId;
        TestReportUnionData
        | where UploadTimestamp > datetime({self.search_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
        '''.rstrip()
        query_str += self.query_common_condition + f'''
        | extend BuildId = case(BuildId has':', split(BuildId, ':')[0], BuildId)
        | where BuildId in (buildsWithoutRetry)
        | where Result in (ResultFilterList)
        | where Summary !in (SummaryWhileList)
        | extend AttemptInt = toint(Attempt)
        | project UploadTimestamp, Feature, ModulePath, FullTestPath, FullCaseName, TestCase, opTestCase, Summary, Result, BranchName, OSVersion, TestbedName, Asic, AsicType, TopologyType, Topology, HardwareSku, BuildId, PipeStatus, AttemptInt
        | sort by UploadTimestamp desc
        '''.rstrip()
        logger.info("Query 7 days's legacy failure cases:\n{}".format(query_str))
        return self.query(query_str)

    def query_history_results(self, testcase_name, module_path, is_common=False, is_legacy=False, is_consistent=False, is_flaky=False):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        project UploadTimestamp, Feature, ModulePath, FullTestPath, FullCaseName, TestCase, opTestCase, Summary, Result, BranchName, OSVersion, TestbedName, Asic, AsicType, TopologyType, Topology, HardwareSku, BuildId, PipeStatus        """
        common_query_tail = '''
                | project UploadTimestamp, Feature, ModulePath, FullTestPath, FullCaseName, TestCase, opTestCase, Summary, Result, BranchName, OSVersion, TestbedName, Asic, AsicType, TopologyType, Topology, HardwareSku, BuildId, PipeStatus
                | order by UploadTimestamp desc
                '''.rstrip()
        if is_common:
            common_query_head = f'''
                TestReportUnionData
                | where UploadTimestamp > datetime({self.history_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
                '''.rstrip()
            common_query_head += self.query_valid_condition + self.query_common_condition
            query_str = self.query_head + common_query_head + f'''
                | where ModulePath == "{module_path}"
                | where Result in (ResultList)
                '''.rstrip() + common_query_tail
            logger.info("Query common history results:\n{}".format(query_str))
            return self.query(query_str)
        elif is_legacy:
            legacy_query_str = self.query_head + f'''
                let buildsWithoutRetry = TestReportUnionData
                | where UploadTimestamp > datetime({self.history_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
                '''.rstrip()
            legacy_query_str += self.query_valid_condition + f'''
                | summarize maxAttempt = max(toint(Attempt)) by BuildId
                | where maxAttempt == 0 or isnull(maxAttempt)
                | project BuildId
                | extend BuildId = case(BuildId has':', split(BuildId, ':')[0], BuildId)
                | distinct BuildId;
                TestReportUnionData
                | where UploadTimestamp > datetime({self.history_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
                '''.rstrip()
            legacy_query_str += self.query_common_condition + f'''
                | extend BuildId = case(BuildId has':', split(BuildId, ':')[0], BuildId)
                | where BuildId in (buildsWithoutRetry)
                | where Summary !in (SummaryWhileList)
                | where opTestCase == "{testcase_name}" and ModulePath == "{module_path}"
                | where Result in (ResultList)
                '''.rstrip()
            legacy_query_str += common_query_tail
            logger.info("Query legacy history results:\n{}".format(legacy_query_str))
            return self.query(legacy_query_str)
        elif is_consistent or is_flaky:
            # for consistent type, only search 7 days results to do data statistic
            consistent_query_str = self.query_head + f'''
                let buildsWithRetry = TestReportUnionData
                | where UploadTimestamp > datetime({self.search_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
                '''.rstrip()
            consistent_query_str += self.query_valid_condition + f'''
                | summarize maxAttempt = max(toint(Attempt)) by BuildId
                | where maxAttempt >= 1
                | project BuildId
                | distinct BuildId;
                TestReportUnionData
                | where UploadTimestamp > datetime({self.search_start_time}) and UploadTimestamp <= datetime({self.search_end_time})
                '''.rstrip()
            consistent_query_str += self.query_common_condition + f'''
                | where BuildId in (buildsWithRetry)
                | extend AttemptInt = toint(Attempt)
                | where Summary !in (SummaryWhileList)
                | where opTestCase == "{testcase_name}" and ModulePath == "{module_path}"
                | where Result in (ResultList)
                | project UploadTimestamp, Feature, ModulePath, FullTestPath, FullCaseName, TestCase, opTestCase, Summary, Result, BranchName, OSVersion, TestbedName, Asic, AsicType, TopologyType, Topology, HardwareSku, BuildId, PipeStatus, AttemptInt
                | order by UploadTimestamp desc
                '''.rstrip()
            logger.info("Query consistent or flaky history results:\n{}".format(consistent_query_str))
            return self.query(consistent_query_str)
        else:
            logger.warning("No valid query type specified. Please check the flags.")
            return None

    def query_all_upload_records_with_trigger_icm(self):
        """
        Query all upload records where TriggerIcM is true.
        This is more efficient than querying one by one for each active ICM.
        """
        query_str = '''
            NightlyTestFailureAnalysis
            | where TriggerIcM == 'true'
            | project UploadTimestamp, ModulePath, TestCase, Branch, Subject, FailureSummary
            | sort by UploadTimestamp desc
            '''
        return self.query(query_str)

    def query_previsou_upload_record(self, title):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        query_str = '''
            NightlyTestFailureAnalysis
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
                if configuration["upload"]:
                    logger.info("Ingest to backup cluster...")
                    self._ingestion_client_backup.ingest_from_file(temp.name, ingestion_properties=props)
                else:
                    logger.info("Skip ingestion to backup cluster, upload is set to False")
        return
