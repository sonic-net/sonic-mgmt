"""Wrappers and utilities for storing test cases."""
import json
import os
import tempfile

from azure.kusto.data import KustoConnectionStringBuilder
from azure.kusto.ingest import QueuedIngestClient as KustoIngestClient
from azure.kusto.ingest import IngestionProperties
from azure.kusto.data.data_format import DataFormat
from datetime import datetime


class KustoConnector():
    """KustoReportDB is a wrapper for storing test reports in Kusto/Azure Data Explorer."""

    def __init__(self, db_name: str, db_table: str, db_table_mapping: str):
        """Initialize a Kusto report DB connector.

        Args:
            db_name: The Kusto database to connect to.
        """
        self.db_name = db_name
        self.db_table = db_table
        self.db_table_mapping = db_table_mapping

        ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_URL")
        access_token = os.getenv('ACCESS_TOKEN', None)

        if not ingest_cluster or not access_token:
            raise RuntimeError(
                "Could not load Kusto Credentials from environment")
        else:
            kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(ingest_cluster, access_token)
            self._ingestion_client = KustoIngestClient(kcsb)

    def upload_results(self, results):
        uploadtime = str(datetime.now())

        for test_case in results:
            test_case["uploadtime"] = uploadtime

        print("Upload test cases")
        self._ingest_data(self.db_table, results)

    def _ingest_data(self, table, data):
        props = IngestionProperties(
            database=self.db_name,
            table=table,
            data_format=DataFormat.JSON,
            ingestion_mapping_reference=self.db_table_mapping
        )

        with tempfile.NamedTemporaryFile(mode="w+") as temp:
            if isinstance(data, list):
                temp.writelines(
                    '\n'.join([json.dumps(entry) for entry in data]))
            else:
                temp.write(json.dumps(data))
            temp.seek(0)
            if self._ingestion_client:
                print("Ingest to cluster...")
                self._ingestion_client.ingest_from_file(
                    temp.name, ingestion_properties=props)
