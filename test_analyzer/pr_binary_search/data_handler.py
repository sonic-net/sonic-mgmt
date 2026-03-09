import os
import json
import logging
from io import StringIO
from azure.kusto.ingest import QueuedIngestClient, IngestionProperties
from azure.kusto.data.data_format import DataFormat
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient


logging.basicConfig(level=logging.INFO, format='[%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

DATABASE = 'SonicTestData'
ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
cluster = ingest_cluster.replace('ingest-', '')
access_token = os.environ.get('ACCESS_TOKEN', None)


class KustoConnector(object):
    def __init__(self):

        kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster, access_token)
        kcsb_ingest = KustoConnectionStringBuilder.with_aad_application_token_authentication(
            ingest_cluster, access_token)
        self.client = KustoClient(kcsb)
        self.ingest_client = QueuedIngestClient(kcsb_ingest)

    def query_kusto(self, query: str):
        """Execute a Kusto query and return the results."""
        logger.info(f"Executing Kusto query:\n{query}")
        response = self.client.execute(DATABASE, query)
        return response.primary_results[0]

    def ingest_data(self, table: str, data: str):
        """Ingest data into a specified Kusto table."""
        ingestion_properties = IngestionProperties(
            database=DATABASE,
            table=table,
            data_format=DataFormat.JSON
        )
        logger.info(f"Ingesting data into table {table}")
        self.ingest_client.ingest_from_stream(StringIO(data), ingestion_properties)

    def query_test_results(self, test_name: str, since: str):
        """Query test results for a specific test name since a given date."""
        query = f"""
        TestResults
        | where TestName == "{test_name}" and Timestamp >= datetime({since})
        | order by Timestamp desc
        """
        return self.query_kusto(query)

    def ingest_test_results(self, commit: str, test_info: dict, result: str):
        """Ingest test results data into the TestResults table."""
        data_list = []
        for checker, tests in test_info.items():
            for test in tests:
                data = json.dumps({
                    "Commit": commit,
                    "Checker": checker,
                    "FilePath": test,
                    "Result": result
                })
                data_list.append(data)

        if data_list:
            for data in data_list:
                self.ingest_data("TestResults", data)
