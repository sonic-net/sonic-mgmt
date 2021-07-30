"""Wrappers and utilities for storing test reports."""
import json
import os
import tempfile

from abc import ABC, abstractmethod
from azure.kusto.data import KustoConnectionStringBuilder

try:
    from azure.kusto.ingest import KustoIngestClient
except ImportError:
    from azure.kusto.ingest import QueuedIngestClient as KustoIngestClient

from azure.kusto.ingest import IngestionProperties
from azure.kusto.ingest import DataFormat

from utilities import validate_json_file
from datetime import datetime
from typing import Dict, List


class ReportDBConnector(ABC):
    """ReportDBConnector is a wrapper for a back-end data store for JUnit test reports.

    The ReportDBConnector API is intentionally very high-level so that different data stores
    with (possibly) drastically different data models can be used interchangeably.

    Subclasses of ReportDBConnector should not add ANY data store/data model/schema specific
    details into the ReportDBConnector DB API.
    """

    @abstractmethod
    def upload_report(self, report_json: Dict, external_tracking_id: str = "", report_guid: str = "") -> None:
        """Upload a report to the back-end data store.

        Args:
            report_json: A JUnit test report in JSON format. See junit_xml_parser.
            external_tracking_id: An identifier that a client can use to map a test report
                to some external system of their choosing (e.g. Jenkins, Travis CI, JIRA, etc.).
                This id does not have to be unique.
            report_guid: A randomly generated UUID that is used to query for a specific test run across tables.
        """
        pass

    @abstractmethod
    def upload_reachability_data(self, ping_output: List) -> None:
        """Upload testbed reachability data to the back-end data store.

        Args:
            ping_output: A list of ICMP ping results from devutils.
        """
        pass

    @abstractmethod
    def upload_pdu_status_data(self, pdu_status_output: List) -> None:
        """Upload PDU status data to the back-end data store.

        Args:
            pdu_status_output: A list of PDU status results from devutils.
        """

    @abstractmethod
    def upload_reboot_report(self, path_name: str = "", report_guid: str = "") -> None:
        """Upload reboot test report to the back-end data store.

        Args:
            path_name: Path to reboot report/summary file
            report_guid: A randomly generated UUID that is used to query for a specific test run across tables.
        """

class KustoConnector(ReportDBConnector):
    """KustoReportDB is a wrapper for storing test reports in Kusto/Azure Data Explorer."""

    METADATA_TABLE = "TestReportMetadata"
    SUMMARY_TABLE = "TestReportSummary"
    RAW_CASE_TABLE = "RawTestCases"
    RAW_REACHABILITY_TABLE = "RawReachabilityData"
    RAW_PDU_STATUS_TABLE = "RawPduStatusData"
    RAW_REBOOT_TIMING_TABLE = "RawRebootTimingData"
    REBOOT_TIMING_TABLE = "RebootTimingData"

    TABLE_FORMAT_LOOKUP = {
        METADATA_TABLE: DataFormat.JSON,
        SUMMARY_TABLE: DataFormat.JSON,
        RAW_CASE_TABLE: DataFormat.MULTIJSON,
        RAW_REACHABILITY_TABLE: DataFormat.MULTIJSON,
        RAW_PDU_STATUS_TABLE: DataFormat.MULTIJSON,
        RAW_REBOOT_TIMING_TABLE: DataFormat.JSON,
        REBOOT_TIMING_TABLE: DataFormat.MULTIJSON
    }

    TABLE_MAPPING_LOOKUP = {
        METADATA_TABLE: "FlatMetadataMappingV1",
        SUMMARY_TABLE: "FlatSummaryMappingV1",
        RAW_CASE_TABLE: "RawCaseMappingV1",
        RAW_REACHABILITY_TABLE: "RawReachabilityMappingV1",
        RAW_PDU_STATUS_TABLE: "RawPduStatusMapping",
        RAW_REBOOT_TIMING_TABLE: "RawRebootTimingDataMapping",
        REBOOT_TIMING_TABLE: "RebootTimingDataMapping"
    }

    def __init__(self, db_name: str):
        """Initialize a Kusto report DB connector.

        Args:
            db_name: The Kusto database to connect to.
        """
        self.db_name = db_name

        ingest_cluster = os.getenv("TEST_REPORT_INGEST_KUSTO_CLUSTER")
        tenant_id = os.getenv("TEST_REPORT_AAD_TENANT_ID")
        service_id = os.getenv("TEST_REPORT_AAD_CLIENT_ID")
        service_key = os.getenv("TEST_REPORT_AAD_CLIENT_KEY")

        if not ingest_cluster or not tenant_id or not service_id or not service_key:
            raise RuntimeError("Could not load Kusto Credentials from environment")

        kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(ingest_cluster,
                                                                                    service_id,
                                                                                    service_key,
                                                                                    tenant_id)
        self._ingestion_client = KustoIngestClient(kcsb)

    def upload_report(self, report_json: Dict, external_tracking_id: str = "", report_guid: str = "") -> None:
        """Upload a report to the back-end data store.

        Args:
            report_json: A JUnit test report in JSON format. See junit_xml_parser.
            external_tracking_id: An identifier that a client can use to map a test report
                to some external system of their choosing (e.g. Jenkins, Travis CI, JIRA, etc.).
                This id does not have to be unique.
            report_guid: A randomly generated UUID that is used to query for a specific test run across tables.
        """
        self._upload_metadata(report_json, external_tracking_id, report_guid)
        self._upload_summary(report_json, report_guid)
        self._upload_test_cases(report_json, report_guid)

    def upload_reachability_data(self, ping_output: List) -> None:
        ping_time = str(datetime.utcnow())
        for result in ping_output:
            result.update({"Timestamp": ping_time})

        reachability_data = {"data": ping_output}
        self._ingest_data(self.RAW_REACHABILITY_TABLE, reachability_data)

    def upload_pdu_status_data(self, pdu_status_output: List) -> None:
        time = str(datetime.utcnow())
        pdu_output = []
        for result in pdu_status_output:
            if not result["PDU status"]:
                status = {"Timestamp": time, "Host": result["Host"], "data_present": False}
                pdu_output.append(status)
                continue

            for status in result["PDU status"]:
                status.update({"Timestamp": time, "Host": result["Host"], "data_present": True})
                pdu_output.append(status)

        pdu_status_data = {"data": pdu_output}
        self._ingest_data(self.RAW_PDU_STATUS_TABLE, pdu_status_data)

    def upload_reboot_report(self, path_name: str = "", report_guid: str = "") -> None:
        reboot_timing_data = {
            "id": report_guid
        }
        reboot_timing_dict = validate_json_file(path_name)
        reboot_timing_data.update(reboot_timing_dict)
        print("Uploading {} report with contents: {}".format(path_name, reboot_timing_data))
        if "reboot_summary" in path_name:
            self._ingest_data(self.REBOOT_TIMING_TABLE, reboot_timing_data)
        elif "reboot_report" in path_name:
             self._ingest_data(self.RAW_REBOOT_TIMING_TABLE, reboot_timing_data)

    def _upload_metadata(self, report_json, external_tracking_id, report_guid):
        metadata = {
            "id": report_guid,
            "tracking_id": external_tracking_id,
            "upload_time": str(datetime.utcnow())
        }
        metadata.update(report_json["test_metadata"])

        self._ingest_data(self.METADATA_TABLE, metadata)

    def _upload_summary(self, report_json, report_guid):
        summary = {
            "id": report_guid
        }
        summary.update(report_json["test_summary"])

        self._ingest_data(self.SUMMARY_TABLE, summary)

    def _upload_test_cases(self, report_json, report_guid):
        test_cases = []
        for feature, cases in report_json["test_cases"].items():
            for case in cases:
                case.update({
                    "id": report_guid,
                    "feature": feature
                })
                test_cases.append(case)
        test_cases = {"cases": test_cases}

        self._ingest_data(self.RAW_CASE_TABLE, test_cases)

    def _ingest_data(self, table, data):
        props = IngestionProperties(
            database=self.db_name,
            table=table,
            data_format=self.TABLE_FORMAT_LOOKUP[table],
            ingestion_mapping_reference=self.TABLE_MAPPING_LOOKUP[table]
        )

        with tempfile.NamedTemporaryFile(mode="w+") as temp:
            temp.write(json.dumps(data))
            temp.seek(0)
            self._ingestion_client.ingest_from_file(temp.name, ingestion_properties=props)
