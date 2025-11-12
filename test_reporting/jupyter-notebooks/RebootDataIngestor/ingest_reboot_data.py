import time
from datetime import datetime, timedelta, timezone

from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from jinja2 import Environment, FileSystemLoader

DATABASE = "SonicInsights"
DEBUG = False


def load_query(name, dataset={}):
    base_path = './templates/'
    env = Environment(loader=FileSystemLoader(searchpath=base_path))

    template_name = "{}.j2".format(name)
    template = env.get_template(template_name)
    result = template.render(dataset)

    return result


def get_latest_agg_time(client):
    query = load_query('get_latest_agg_time')
    result = client.execute(DATABASE, query)
    return result.primary_results[0][0]["ReloadCause_Time"]


def ingest_data(client, name, start_time):
    query = load_query(name, {'start_time': start_time})
    if DEBUG:
        print(query)
        return

    result = client.execute_mgmt(DATABASE, query)
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
    # Connection information
    cluster_uri = "https://chinaazure.kusto.windows.net/"

    # Establish connection
    kcsb = KustoConnectionStringBuilder.with_interactive_login(cluster_uri)

    with KustoClient(kcsb) as client:

        print("=== Step 1 Get latest aggregation timestamp ===")
        latest_agg_time = get_latest_agg_time(client)
        print("Got {}".format(latest_agg_time))
        print("\n")

        print("=== Step 2 Ingest data")
        timestamp = latest_agg_time
        now = datetime.now(timezone.utc)
        while timestamp < now:
            print("Start ingestion from {}".format(timestamp))
            print("Ingesting basic data...")
            result = ingest_data(client, 'ingest_basic_data', timestamp)
            print_result_as_value_list(result)

            print("Ingesting CIS data...")
            result = ingest_data(client, 'ingest_cis_data', timestamp)
            print_result_as_value_list(result)

            print("Ingesting FUSE data...")
            result = ingest_data(client, 'ingest_fuse_data', timestamp)
            print_result_as_value_list(result)

            timestamp += timedelta(days=1)
            if (timestamp < now):
                print("Delay 600s in case throttling...")
                time.sleep(600)
            print("\n")


if __name__ == "__main__":
    main()
