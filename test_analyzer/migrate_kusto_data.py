
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
        tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID_BACKUP")
        service_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID_BACKUP")
        service_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY_BACKUP")

        if not ingest_cluster or not tenant_id or not service_id or not service_key:
            logger.info(
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

    def query_missing_testplan(self):
        query_str = '''
            FlatTestReportViewV5
            | where UploadTimestamp > ago(30d)
            | distinct BuildId
            | join kind=leftanti TestReportUnionData on BuildId
            | take 20
            '''
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

def main():
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
    missing_testplan_ids = kusto_connector.query_missing_testplan()
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
    main()