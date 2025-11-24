import time
import argparse
from datetime import datetime, timedelta, timezone

from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from jinja2 import Environment, FileSystemLoader

DEBUG = False


def load_query(name, dataset={}):
    base_path = './templates/'
    env = Environment(loader=FileSystemLoader(searchpath=base_path))

    template_name = "{}.j2".format(name)
    template = env.get_template(template_name)
    result = template.render(dataset)

    return result


def get_latest_agg_time(client, ingest_db):
    query = load_query('get_latest_agg_time')
    result = client.execute(ingest_db, query)
    return result.primary_results[0][0]["ReloadCause_Time"]


def ingest_data(client, ingest_db, name, start_time):
    query = load_query(name, {'start_time': start_time})
    if DEBUG:
        print(query)
        return

    result = client.execute_mgmt(ingest_db, query)
    return result


def print_result_as_value_list(response):
    if DEBUG:
        return

    # Create a list of columns
    cols = (col.column_name for col in response.primary_results[0].columns)

    # Print the values for each row
    for row in response.primary_results[0]:
        print("Result:")
        for col in cols:
            print("\t", col, "-", row[col])


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Ingest reboot data into Kusto")
    parser.add_argument("--auth-mode", choices=["interactive", "azcli"],
                        default="interactive",
                        help="Authentication mode: interactive (default) or azcli")
    parser.add_argument("--ingest-cluster-uri", type=str,
                        default="https://sonicrepodatadev.westus.kusto.windows.net/",
                        help="Kusto cluster URI for ingestion")
    parser.add_argument("--ingest-database", type=str,
                        default="SonicTestData",
                        help="Kusto database name for ingestion")
    args = parser.parse_args()

    # Connection information
    ingestion_cluster_uri = args.ingest_cluster_uri
    ingestion_database = args.ingest_database

    # Establish connection based on auth mode
    if args.auth_mode == 'azcli':
        kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(ingestion_cluster_uri)
    else:
        kcsb = KustoConnectionStringBuilder.with_interactive_login(ingestion_cluster_uri)

    with KustoClient(kcsb) as client:

        print("=== Step 1 Get latest aggregation timestamp ===")
        latest_agg_time = get_latest_agg_time(client, ingestion_database)
        print("Got {}".format(latest_agg_time))
        print("\n")

        print("=== Step 2 Ingest data")
        timestamp = latest_agg_time
        now = datetime.now(timezone.utc)
        while timestamp < now:
            print("Start ingestion from {}".format(timestamp))
            print("Ingesting basic data...")
            result = ingest_data(client, ingestion_database, 'ingest_basic_data', timestamp)
            print_result_as_value_list(result)

            # NOTE: The cluster('azcis.kusto.windows.net').database('azcispub').SignaltoLiveTracking Table no longer
            #       exists, so we are skipping CIS data ingestion until there is a replacement.
            # print("Ingesting CIS data...")
            # result = ingest_data(client, ingestion_database, 'ingest_cis_data', timestamp)
            # print_result_as_value_list(result)

            print("Ingesting FUSE data...")
            result = ingest_data(client, ingestion_database, 'ingest_fuse_data', timestamp)
            print_result_as_value_list(result)

            timestamp += timedelta(days=1)
            if (timestamp < now):
                print("Delay 60s in case throttling...")
                time.sleep(60)
            print("\n")


if __name__ == "__main__":
    main()
