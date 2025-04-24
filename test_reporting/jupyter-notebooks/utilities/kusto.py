"""
Utilities for helping with Jupyter notebooks.
"""

from azure.kusto.data import KustoClient
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.helpers import dataframe_from_result_table
from pandas import DataFrame

KUSTO_CLIENTS = {}

def init_kusto_clients():

    """
    Need to be logged in with `az login` before the clients will connect
    """

    TENANT_ID = "72f988bf-86f1-41af-91ab-2d7cd011db47"

    def build_kusto_client(cluster: str) -> KustoClient:
        # kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(f"https://{cluster}.kusto.windows.net/")
        kcsb = KustoConnectionStringBuilder.with_interactive_login(f"https://{cluster}.kusto.windows.net/")
        kcsb.authority_id = TENANT_ID
        return KustoClient(kcsb)

    global KUSTO_CLIENTS
    if not KUSTO_CLIENTS:
        clusters = ['azwan', 'aznwsdn', 'azphynet']
        KUSTO_CLIENTS = {
            cluster: build_kusto_client(cluster) for cluster in clusters
        }

# Init the kusto clients the moment this module is imported
init_kusto_clients()


def execute_kusto_query(connection: str, database: str, query: str) -> DataFrame:
    res = KUSTO_CLIENTS[connection].execute_query(database, query)
    df_res = dataframe_from_result_table(res.primary_results[0])
    return df_res