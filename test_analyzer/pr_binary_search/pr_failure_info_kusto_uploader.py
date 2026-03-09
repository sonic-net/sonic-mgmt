import os
import sys
import json
import logging
import argparse
from io import StringIO
from azure.kusto.ingest import IngestionProperties
from azure.kusto.data import KustoConnectionStringBuilder

try:
    from azure.kusto.ingest import QueuedIngestClient as KustoIngestClient
except Exception:
    from azure.kusto.ingest import KustoIngestClient  # type: ignore

try:
    from azure.kusto.ingest import DataFormat
except Exception:
    from azure.kusto.data.data_format import DataFormat  # type: ignore


logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_DATABASE = "SonicTestData"
DEFAULT_TABLE = "PRBinarySearchFailureInfo"
DEFAULT_MAPPING = "PRBinarySearchFailureInfoMappingV1"


def load_records(input_file):
    with open(input_file, "r") as f:
        records = json.load(f)
    if not isinstance(records, list):
        raise ValueError(f"Input file must contain a JSON array: {input_file}")
    return records


def ingest_records(records, ingest_cluster, access_token, database, table, mapping):
    if not records:
        logger.info("No records to ingest, skip.")
        return

    kcsb_ingest = KustoConnectionStringBuilder.with_aad_application_token_authentication(
        ingest_cluster, access_token
    )
    ingest_client = KustoIngestClient(kcsb_ingest)

    payload = "\n".join(json.dumps(r) for r in records)
    stream = StringIO(payload)

    props = IngestionProperties(
        database=database,
        table=table,
        data_format=DataFormat.JSON,
        ingestion_mapping_reference=mapping,
    )
    ingest_client.ingest_from_stream(stream, ingestion_properties=props)
    logger.info("Submitted ingest request: %d rows -> %s.%s (mapping=%s)", len(records), database, table, mapping)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input_file", type=str, default="failure_info.json")
    p.add_argument("--database", type=str, default=DEFAULT_DATABASE)
    p.add_argument("--table", type=str, default=DEFAULT_TABLE)
    p.add_argument("--mapping", type=str, default=DEFAULT_MAPPING)
    args = p.parse_args()

    ingest_cluster = os.getenv("KUSTO_CLUSTER_INGEST_URL")
    access_token = os.getenv("ACCESS_TOKEN")
    if not ingest_cluster or not access_token:
        raise RuntimeError("Missing required envs: KUSTO_CLUSTER_INGEST_URL and ACCESS_TOKEN")

    records = load_records(args.input_file)
    ingest_records(records, ingest_cluster, access_token, args.database, args.table, args.mapping)


if __name__ == "__main__":
    main()
