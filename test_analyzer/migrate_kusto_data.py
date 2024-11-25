
"""
This script migrates data from FlatTestReportViewV5 to TestReportUnionData.
The script will be run hourly to sync data.
"""
import os
from datetime import datetime, timezone, timedelta
import pytz
import json
import logging
import time
import os
import pandas as pd
import sys
from logging.handlers import RotatingFileHandler
import tempfile
import argparse
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

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATABASE = 'SonicTestData'
class KustoConnector(object):
    """connect the Kusto and run query"""
    TEST_REPORT_UNION_TABLE = "TestReportUnionData"

    TABLE_FORMAT_LOOKUP = {
        TEST_REPORT_UNION_TABLE: DataFormat.JSON
    }

    TABLE_MAPPING_LOOKUP = {
        TEST_REPORT_UNION_TABLE: "TestReportUnionDataMapping"
    }
    def __init__(self):
        self.logger = logging.getLogger('KustoChecker')
        self.db_name = DATABASE
        ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
        access_token = os.environ.get('ACCESS_TOKEN', None)

        if not ingest_cluster or not access_token:
            logger.info(
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

    def query(self, query):
        self.logger.debug('Query String: {}'.format(query))
        return self.client_backup.execute(self.db_name, query)

    def upload_data(self, report_data):
        self._ingest_data(self.TEST_REPORT_UNION_TABLE, report_data)
        return

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

    def get_latest_timestamp(self):
        query_str = '''
            TestReportUnionData
            | order by UploadTimestamp desc
            | project UploadTimestamp
            | take 1
            '''
        logger.info("Query the latest timestamp from TestReportUnionData:{}".format(query_str))
        result = self.query(query_str)
        latest_timestamp = result.primary_results[0].rows[0][0]
        return latest_timestamp

    def query_data(self, testplan_ids):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """
        query_str = '''
            let IncludedTestplan = dynamic({});
            FlatTestReportViewV5
            | where BuildId in (IncludedTestplan)
            | order by UploadTimestamp asc
            '''.format(testplan_ids)
        logger.info("Query cases:{}".format(query_str))
        return self.query(query_str)

    def query_total_count(self):
        """
        Query failed test cases for the past one day, which total case number should be more than 100
        in case of collecting test cases from unhealthy testbed.
        """

        query_str = '''
            TestReportUnionData
            | summarize count()
            '''
        logger.info("Query total count:{}".format(query_str))
        result = self.query(query_str)
        total_count = result.primary_results[0].rows[0][0]
        logger.info("The total count is:{}".format(total_count))
        return total_count

    def query_missing_testplan(self, upload_time_start, upload_time_end):
        query_str = '''
            let ExcludeTestbedList = dynamic(['3132', '7280', 'slx', '3164', 'azd']);
            let ExcludeAsicList = dynamic(['barefoot']);
            let newTestBeds = TestBeds
            | where UploadTime between (datetime({}) .. datetime({}))
            | project-away CreateTime, UpdateTime,UploadTime,Dut
            | where TestbedType == 'PHYSICAL'
            | where isnotempty(HardwareSku)
            | distinct *;
            let newTestplans = TestPlans
            | where UploadTime between (datetime({}) .. datetime({}))
            | where TestPlanType == 'NIGHTLY'
            | distinct *
            | summarize arg_max(UploadTime, *) by TestPlanId;
            let ElasticTest = V2TestCases
            | where UploadTime between (datetime({}) .. datetime({}))
            | join kind=leftouter newTestBeds on TestPlanId and TestbedId
            | join kind=leftouter newTestplans on TestPlanId
            | where TestPlanType == 'NIGHTLY'
            | project-rename TestPlanResult=Result1, TestplanStartTime=StartTime1, TestplanEndTime=EndTime1,TestplanUploadTime=UploadTime1,TestbedPlatform=Platform
            | project-away TestbedId1, TestPlanId1,TestPlanId2,HardwareSku1,AsicType1,Topology1,Platform1,Asic1,UploadTime
            | distinct *
            | extend Asic = case(HardwareSku has_any ("7050CX3"), "TD3",
                                HardwareSku has_any ("7050", "7050qx","S6000","Nexus-3164"), "TD2",
                                HardwareSku has_any ("7060CX", "DX010", "S6100"), "TH",
                                HardwareSku has_any ("7260CX3"), "TH2",
                                HardwareSku has_any ("Z9332f"), "TH3",
                                HardwareSku has_any ("7050DX5"), "TH4",
                                HardwareSku has_any ("7060X6"), "TH5",
                                HardwareSku has_any ("MSN4600C"), "Spectrum3",
                                HardwareSku has_any ("64x100Gb"), "SiliconOne",
                                HardwareSku has_any ("Celestica-E1031-T48S4"), "Helix4",
                                HardwareSku has_any ("7215"), "Marvell",
                                HardwareSku has_any ("7280CR3"), "J2C",
                                HardwareSku has_any ("IXR7250E", "7800R3A", "7800R3AK"), "J2C+",
                                HardwareSku has_any ("8102"), "Q201L",
                                HardwareSku has_any ("8101"), "Q200",
                                HardwareSku has_any ("9516"), "Tofino2",
                                HardwareSku has_any ("ACS-MSN2700", "Mellanox-SN2700", "Mellanox-SN2700-D48C8", "ACS-MSN2740", "ACS-MSN2100", "ACS-MSN2410", "ACS-MSN2010", "ACS-MSN2201"), "SPC1",
                                HardwareSku has_any ("ACS-MSN3700", "ACS-MSN3700C", "ACS-MSN3800", "Mellanox-SN3800-D112C8", "ACS-MSN3420"), "SPC2",
                                HardwareSku has_any ("ACS-MSN4700", "ACS-MSN4600C", "ACS-MSN4410", "ACS-MSN4600", "Mellanox-SN4600C-D112C8", "Mellanox-SN4600C-C64", 'Mellanox-SN4700-O8C48', 'Mellanox-SN4700-O8V48', "ACS-SN4280"), "SPC3",
                                HardwareSku has_any ("ACS-SN5600" , "Mellanox-SN5600-V256"), "SPC4",
                                "FIXME"),
                TopologyType = case(Topology has "dualtor", "dualtor",
                                    Topology has "t0", "t0",
                                    Topology has "t1", "t1",
                                    Topology has "t2", "t2",
                                    Topology has "m0", "m0",
                                    Topology has "mx", "mx",
                                    "FIXME"),
                RunDate = make_datetime(datetime_part("Year", TestplanStartTime),
                                        datetime_part("Month", TestplanStartTime),
                                        datetime_part("Day", TestplanStartTime))
            | extend FullTestPath = strcat(ModulePath, ".", TestCase)
            | extend OSVersion=case(isempty(OSVersion), substring(OSVersion1, 6),substring(OSVersion, 6))
            | extend Result = case(Result in ("xfail_skipped"), "xfail_expected",
                                Result in ("xfail_failure", "xfail_error"), "xfail_unexpected",
                                Result in ("xfail_success"), "xfail_forgive",
                                Result);
            FlatTestReportViewLatest
            | join kind=leftouter TestReportPipeline on ReportId
            | extend PipeStatus = case (FailedTasks != "", "Sanity Failure", CancelledTasks != "", "Canceled", "FINISHED")
            | project-away ReportId1,TestbedName1,OSVersion1
            | project-rename TestplanStartTime=StartTimestamp,TestplanEndTime=UploadTimestamp
            | project-rename UploadTimestamp = UploadTimeUTC
            | union ( ElasticTest
                | extend BuildId = TestPlanId
                | extend StartTimeUTC= TestplanStartTime
                | extend PipeStatus = TestPlanResult
                | extend UploadTimestamp = TestplanUploadTime
            )
            | project-away TestPlanId,TestPlanResult,TestplanUploadTime,TestbedSponsor
            | extend opTestCase = case(TestCase has'[', split(TestCase, '[')[0], TestCase)
            | extend opTestCase = case(isempty(opTestCase), TestCase, opTestCase)
            | extend BranchName = tostring(split(OSVersion, '.')[0])
            | extend FullCaseName = strcat(ModulePath,".",opTestCase)
            | extend TestType = case(strlen(BuildId)>10, "ElasticTest",strlen(BuildId)<=10, "PipeplineTest", "Unknow")
            | extend Pipeline = case(strlen(BuildId)>10, strcat("https://elastictest.org/scheduler/testplan/",BuildId),strlen(BuildId)<=10,strcat("https://dev.azure.com/mssonic/internal/_build/results?buildId=", BuildId, "&view=logs"),"Unknow URL")
            | extend URL = case(FilePath has'test_pretest' or FilePath has 'test_posttest',strcat(FilePath,"%7C%7C%7C0"),FilePath has 'drop_packets.py',replace_string(FilePath, "drop_packets.py", "test_drop_counters.py"),FilePath)
            | extend URL = case(strlen(URL)>0,strcat("?testcase=",replace_string(URL, "/", "%2F"),"&type=console"),"")
            | extend Pipeline=case(strlen(BuildId)>10,strcat(Pipeline,URL),Pipeline)
            | project-away URL
            | where not(TestbedName has_any(ExcludeTestbedList))
            | where not(AsicType has_any(ExcludeAsicList))
            | project-away CancelledTasks,CreatedByType,FailedTasks,ImageSrc,ImageSrcType,JenkinsId,RawTestbed,RawTestCase,RawTestPlan,ReportId,Server,SuccessTasks,TestbedPlatform,TestbedType,TestPlanName,TestPlanType,TestRepo,TrackingId,VmType
            | order by UploadTimestamp desc
            | where UploadTimestamp > ago(30d)
            | distinct BuildId
            | join kind=leftanti TestReportUnionData on BuildId
            | take 20
            '''.format(upload_time_start, upload_time_end, upload_time_start, upload_time_end, upload_time_start, upload_time_end)
        logger.info("Query missing testplan IDs:{}".format(query_str))
        result = self.query(query_str)
        # testplan_ids = result.primary_results[0].rows
        testplan_ids = list(set(row["BuildId"] for row in result.primary_results[0]))
        logger.info("The missing testplan IDs are:{}".format(testplan_ids))
        return testplan_ids

def backup_history_data(kusto_connector):
    """
    It is used to migrate all of history data from FlatTestReportViewV5 to TestReportUnionData.
    One day data could be empty, so we need to plus one more day to get extra data upload to avoid forever loop.
    """
    total_count = []
    upload_count = []
    loop_count = 1
    list_of_dicts = None
    program_start_time = datetime.now(tz=pytz.UTC)
    number_of_data = kusto_connector.query_total_count()
    logger.info("Before running, the total number of data for TestReportUnionData is:{}".format(number_of_data))
    total_count.append(number_of_data)
    delta_day = 1
    while True:
        current_time = datetime.now(tz=pytz.UTC)
        latest_timestamp = kusto_connector.get_latest_timestamp()
        if list_of_dicts == []:
            delta_day += 1
            logger.info("Delta day={}.".format(delta_day))
        end_time = latest_timestamp + timedelta(days=delta_day)
        if current_time > end_time:
            response = kusto_connector.query_data(start_time=latest_timestamp, end_time=end_time)
            df = dataframe_from_result_table(response.primary_results[0])
            list_of_dicts = df.to_dict(orient="records")
            for row in list_of_dicts:
                for column_name, column_value in row.items():
                    if isinstance(column_value, pd.Timestamp):
                        # Convert the Timestamp to a string in your desired format
                        row[column_name] = str(column_value)
                    elif pd.isna(column_value):
                        row[column_name] = ''

            logger.info("Ingest {} rows data into TestReportUnionData".format(len(list_of_dicts)))
            if len(list_of_dicts) == 0:
                logger.info("No data has been transferred into backup table. Plus one more day.")
                continue
            delta_day = 1
            kusto_connector.upload_data(list_of_dicts)
            upload_count.append(len(list_of_dicts))
        else:
            logger.info("No data has been transferred into backup table.")
            break

        loop_count += 1
        sleep_mins = 0
        while True:
            number_of_data = kusto_connector.query_total_count()
            logger.info("Total number for TestReportUnionData:{}".format(number_of_data))
            if number_of_data == total_count[-1] + len(list_of_dicts):
                total_count.append(number_of_data)
                logger.info("Total counts for TestReportUnionData:{}".format(total_count))
                logger.info("Upload counts for TestReportUnionData:{}".format(upload_count))
                logger.info("Upload {} rows data into table, start the {}th loop".format(upload_count[-1], loop_count))
                time.sleep(10)
                break
            sleep_mins += 1
            # sleep 1 min to wait for the data exist in kusto
            logger.info("Sleep for {} mins in total to wait for the data exist in kusto...".format(sleep_mins))
            time.sleep(60)
    program_end_time = datetime.now(tz=pytz.UTC)
    logger.info("Total counts for TestReportUnionData:{}".format(total_count))
    logger.info("Upload counts for TestReportUnionData:{}".format(upload_count))
    logger.info("Cost {} for this run.".format(program_end_time - program_start_time))
    return

def main(testplan_id_list):
    program_start_time = datetime.now(tz=pytz.UTC)
    kusto_connector = KustoConnector()

    list_of_dicts = None
    existing_number = kusto_connector.query_total_count()
    logger.info("Before running, the existing total number of data for TestReportUnionData is:{}".format(existing_number))

    # current_time = datetime.now(tz=pytz.UTC)
    # # There will be 5-6 minutes delay if data is upload to kusto
    # # If we use current timestamp, there is uploading right now, these part of data would probably be missed
    # # We need to minus 7 mins to avoid this issue
    # end_time = current_time - timedelta(minutes=7)
    latest_timestamp = kusto_connector.get_latest_timestamp()
    logger.info("The latest UploadTimestamp in TestReportUnionData is:{}".format(latest_timestamp))
    current_datetime = datetime.utcnow() - timedelta(days=1)
    next_day_datetime = datetime.utcnow() + timedelta(days=0.1)
    # Format the datetime object as a string in the desired format
    start_date = current_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
    # Format the next day's datetime object as a string in the desired format
    end_date = next_day_datetime.strftime('%Y-%m-%dT%H:%M:%SZ')
    if testplan_id_list:
        logger.info("Will upload those specific missing testplan:{}".format(testplan_id_list))
        missing_testplan_ids = testplan_id_list
    else:
        missing_testplan_ids = kusto_connector.query_missing_testplan(start_date, end_date)
        logger.info("Regularly perform migrations for testplans:{}".format(missing_testplan_ids))
    response = kusto_connector.query_data(missing_testplan_ids)
    df = dataframe_from_result_table(response.primary_results[0])
    list_of_dicts = df.to_dict(orient="records")
    for row in list_of_dicts:
        for column_name, column_value in row.items():
            if isinstance(column_value, pd.Timestamp):
                # Convert the Timestamp to a string in your desired format
                row[column_name] = str(column_value)
            elif pd.isna(column_value):
                row[column_name] = ''

    logger.info("Ingest {} rows data into TestReportUnionData".format(len(list_of_dicts)))
    if len(list_of_dicts) == 0:
        logger.info("No data need to be transferred into backup table.")
        return

    kusto_connector.upload_data(list_of_dicts)
    upload_data_number = len(list_of_dicts)

    sleep_mins = 0
    while True:
        number_of_data = kusto_connector.query_total_count()
        logger.info("Total number for TestReportUnionData:{}".format(number_of_data))
        if number_of_data >= existing_number + upload_data_number:
            logger.info("Upload {} rows data into table.".format(upload_data_number))
            break
        sleep_mins += 1
        # sleep 1 min to wait for the data exist in kusto
        logger.info("Sleep for {} min in total to wait for the data exist in kusto...".format(sleep_mins))
        time.sleep(60)
    program_end_time = datetime.now(tz=pytz.UTC)
    logger.info("Cost {} for this run.".format(program_end_time - program_start_time))
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Analyze test result")

    parser.add_argument(
        "--testplans", "-t",
        type=str,
        required=False,
        default="",
        help="Testplan IDs",
    )
    args = parser.parse_args()
    testplans = args.testplans
    testplan_id_list = []
    if testplans:
        testplan_ids = testplans.strip().split(',')
        testplan_id_list = [id.strip() for id in testplan_ids]
    main(testplan_id_list)
