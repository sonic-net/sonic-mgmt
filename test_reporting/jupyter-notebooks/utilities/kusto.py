"""
Utilities for helping with Jupyter notebooks.
"""

import os

from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.helpers import dataframe_from_result_table
from azure.kusto.ingest import QueuedIngestClient
from pandas import DataFrame

KUSTO_CLIENTS = {}

KUSTO_AUTH_MODE = os.getenv("KUSTO_AUTH_MODE", "interactive").strip().lower()

# Veritas cluster owners require pipeline (az_cli) reads to go through the follower;
# interactive/local users must hit the primary.
VERITAS_CLUSTER = (
    "vnetkustofollower.northcentralus"
    if KUSTO_AUTH_MODE == "az_cli"
    else "vnetkusto.northcentralus"
)
VERITAS_CLUSTER_URI = f"{VERITAS_CLUSTER}.kusto.windows.net"


def init_kusto_clients():

    """
    Need to be logged in with `az login` before the clients will connect
    """

    TENANT_ID = "72f988bf-86f1-41af-91ab-2d7cd011db47"

    def build_kusto_client(cluster: str) -> KustoClient:
        cluster_uri = f"https://{cluster}.kusto.windows.net/"
        if KUSTO_AUTH_MODE == "az_cli":
            kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(cluster_uri)
        elif KUSTO_AUTH_MODE == "interactive":
            kcsb = KustoConnectionStringBuilder.with_interactive_login(cluster_uri)
        else:
            raise ValueError(f"Unsupported KUSTO_AUTH_MODE: {KUSTO_AUTH_MODE}")
        kcsb.authority_id = TENANT_ID
        return KustoClient(kcsb)

    global KUSTO_CLIENTS
    if not KUSTO_CLIENTS:
        clusters = ['azwan', 'aznwsdn', 'azphynet', VERITAS_CLUSTER, 'sonicrepodatadev.westus']
        KUSTO_CLIENTS = {
            cluster: build_kusto_client(cluster) for cluster in clusters
        }


# Init the kusto clients the moment this module is imported
init_kusto_clients()


def execute_kusto_query(connection: str, database: str, query: str) -> DataFrame:
    res = KUSTO_CLIENTS[connection].execute_query(database, query)
    df_res = dataframe_from_result_table(res.primary_results[0])
    return df_res


def execute_kusto_command(connection: str, database: str, command: str) -> DataFrame:
    """Execute a Kusto control/management command (e.g. .delete) and return the result table."""
    res = KUSTO_CLIENTS[connection].execute_mgmt(database, command)
    df_res = dataframe_from_result_table(res.primary_results[0])
    return df_res


def build_ingest_client(ingest_uri: str) -> QueuedIngestClient:
    """Build a QueuedIngestClient for the given ingest URI.
    Centralizes Kusto ingest authentication: tries az CLI auth (used in CI) and
    falls back to interactive browser login (used in local dev).
    """
    # TODO: When a second ingest destination is added, refactor to a shared
    # KUSTO_CLIENTS-style registry so ingest clients get the same handling as
    # the read clusters.
    try:
        kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(ingest_uri)
    except Exception:
        kcsb = KustoConnectionStringBuilder.with_interactive_login(ingest_uri)
    return QueuedIngestClient(kcsb)
