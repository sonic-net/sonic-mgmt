import os
import sys
import json
import datetime
import logging
import requests
from io import StringIO
from typing import Any, Dict, List
from azure.kusto.ingest import QueuedIngestClient, IngestionProperties
from azure.kusto.data.data_format import DataFormat
from azure.kusto.data import KustoConnectionStringBuilder


logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)


ELASTICTEST_URL = "https://sonic-elastictest-prod-management-webapp.azurewebsites.net"
elastictest_token = os.environ.get('ELASTICTEST_TOKEN', None)

DATABASE = 'SonicTestData'
KUSTO_TABLE = 'TestbedHistory'
ingest_cluster = os.getenv("KUSTO_CLUSTER_INGEST_URL")
kusto_token = os.environ.get('KUSTO_TOKEN', None)


def build_kusto_ingest_client(cluster_uri: str) -> QueuedIngestClient:
    """Create a Kusto ingest client using AAD token auth."""
    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster_uri, kusto_token)
    logger.info("Initialized Kusto ingest client: cluster=%s", cluster_uri)
    return QueuedIngestClient(kcsb)


def build_ingestion_properties(database: str, table: str) -> IngestionProperties:
    """Build ingestion properties for JSON with default mapping."""
    logger.info("Preparing ingestion properties: database=%s table=%s", database, table)
    return IngestionProperties(database=database, table=table, data_format=DataFormat.JSON)


def get_physical_testbeds_info(base_url: str, token: str):
    url = f"{base_url}/api/v1/testbeds/query_by_keyword"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    params = {
        "keyword": "",
        "testbed_type": "PHYSICAL",
        "page": 0,
        "page_size": 0
    }

    resp = requests.get(url, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    testbed_info = resp.json()["data"]

    return testbed_info


def ingest_testbed_info_to_kusto(testbed_info: List[Dict[str, Any]],
                                 ingest_client: QueuedIngestClient,
                                 ingestion_props: IngestionProperties):
    # Ingest testbed info
    if not testbed_info:
        logger.warning("No testbed info to ingest, skip.")
        return

    # Kusto JSON ingestion expects either:
    # 1) newline-delimited JSON objects, or
    # 2) a JSON array (depends on table mapping)
    #
    # Safest approach: newline-delimited JSON
    json_lines = []
    ingest_time = datetime.datetime.utcnow().isoformat()

    for tb in testbed_info:
        tb["upload_time"] = ingest_time
        json_lines.append(json.dumps(tb, ensure_ascii=False))

    payload = "\n".join(json_lines)

    stream = StringIO(payload)

    logger.info("Ingesting %d testbed records into Kusto table %s.%s",
                len(testbed_info), DATABASE, KUSTO_TABLE)

    ingest_client.ingest_from_stream(
        stream,
        ingestion_properties=ingestion_props
    )

    logger.info("Ingest request submitted successfully.")


def main():
    """End-to-end copy: Mongo -> transform -> Kusto using env-derived defaults.

    Values are read from environment variables defined at the top of the file.
    Override them by exporting env vars before running, or import and call the
    functional pieces directly from other code.
    """
    testbed_info = get_physical_testbeds_info(ELASTICTEST_URL, elastictest_token)
    logger.info("Fetched %d physical testbeds from management webapp.", len(testbed_info))
    logger.info(f"Testbeds info: {testbed_info}")

    # Create ingest client and ingestion properties
    ingest_client = build_kusto_ingest_client(ingest_cluster)
    ingestion_props = build_ingestion_properties(DATABASE, KUSTO_TABLE)

    ingest_testbed_info_to_kusto(testbed_info, ingest_client, ingestion_props)


if __name__ == "__main__":
    main()
