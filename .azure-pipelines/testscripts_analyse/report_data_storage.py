"""Wrappers and utilities for storing test reports."""
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

    TESTSCRIPT_TABLE = "TestScripts"

    TABLE_FORMAT_LOOKUP = {
        TESTSCRIPT_TABLE: DataFormat.JSON,
    }

    TABLE_MAPPING_LOOKUP = {
        TESTSCRIPT_TABLE: "TestScriptsMapping"
    }

    def __init__(self, db_name: str):
        """Initialize a Kusto report DB connector.

        Args:
            db_name: The Kusto database to connect to.
        """
        self.db_name = db_name

        """
            Kusto performance depends on the work load of cluster,
            to improve the high availability of test result data service
            by hosting a backup cluster, which is optional.
        """
        ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP")
        access_token = os.getenv('ACCESS_TOKEN', None)

        if not ingest_cluster or not access_token:
            raise RuntimeError(
                "Could not load Kusto Credentials from environment")
        else:
            kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(ingest_cluster, access_token)
            self._ingestion_client_backup = KustoIngestClient(kcsb)

    def upload_testscripts(self, test_scripts):
        uploadtime = str(datetime.now())

        for script in test_scripts:
            script["uploadtime"] = uploadtime

        print("Upload test scripts")
        self._ingest_data(self.TESTSCRIPT_TABLE, test_scripts)

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
                print("Ingest to backup cluster...")
                self._ingestion_client_backup.ingest_from_file(
                    temp.name, ingestion_properties=props)
