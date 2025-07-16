import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta

import pandas as pd
from azure.kusto.data import KustoConnectionStringBuilder, KustoClient, DataFormat
from azure.kusto.data.exceptions import KustoServiceError, KustoClientError
from azure.kusto.data.helpers import dataframe_from_result_table
from azure.kusto.ingest import QueuedIngestClient, IngestionProperties

from sonic_daily_metric_hwsku_strategies import HwSkuFactory, SONIC_DEVICE_TYPE, VENDOR_DEVICE_TYPE


logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)


AZPHYNET_CLUSTER = os.getenv("AZPHYNET_KUSTO_CLUSTER_URL")
SONIC_INGEST_CLUSTER = os.getenv("KUSTO_CLUSTER_INGEST_URL")
SONIC_CLUSTER = SONIC_INGEST_CLUSTER.replace("ingest-", "")
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", None)
SONIC_TEST_DATA_DB = "SonicTestData"
ICM_DB = "IcMDataWarehouse"
METRIC_TABLE = "SonicDailyMetric"
METRIC_ROLE = "SonicDailyMetricSyncPipeline"

MAX_RETRIES = 3
RETRY_DELAY = 120


def execute_kusto_query_with_retry(kusto_client, database, query, operation_name):
    """Execute Kusto query with retry logic. Raises exception if all retries fail."""
    for attempt in range(MAX_RETRIES):
        try:
            query_result = kusto_client.execute_query(database, query)
            return query_result
        except (KustoServiceError, KustoClientError) as ke:
            logger.warning("Kusto query error on attempt {}/{} for {}: {}".format(
                attempt + 1,
                MAX_RETRIES,
                operation_name,
                ke,
            ))

            if attempt == MAX_RETRIES - 1:
                logger.error("Kusto query failed after {} attempts for {}. "
                             "Manual investigation required.".format(MAX_RETRIES, operation_name))
                raise

            time.sleep(RETRY_DELAY * (attempt + 1))
        except Exception as e:
            logger.error("Unexpected error during {}: {}".format(operation_name, e))
            raise

    return None # Should not reach here if retries are implemented correctly


def get_device_incidents_df(azphynet_kusto_client, device_names, start_datetime):
    logger.info("Starting incidents query with start datetime: {}".format(start_datetime))
    start_time = time.time()

    query = """
    IncidentsSnapshotV2()
    | where OccurringDeviceName in~ ({})
    | where OwningTeamName !contains "Test"
    | where CreateDate > datetime({})
    | project IncidentId, Severity, Status, CreateDate, OccurringDeviceName
    """.format(device_names, start_datetime)

    op_name = "Device Incidents Query"
    query_result = execute_kusto_query_with_retry(azphynet_kusto_client, ICM_DB, query, op_name)
    result_data = query_result.primary_results[0]
    incidents_df = dataframe_from_result_table(result_data)

    exec_time = time.time() - start_time
    logger.info("Incidents query completed in {:.2f}s, found {} incidents".format(exec_time, len(incidents_df)))
    return incidents_df


def get_most_recent_metric_df(sonic_kusto_client, hw_sku_name):
    logger.info("Starting most recent metric query for HwSKU: {}".format(hw_sku_name))
    start_time = time.time()

    query = """
    {}
    | where HwSKU == "{}"
    | summarize MaxTimestamp = max(MetricTimestamp)
    | join kind=inner ( 
        {}
    ) on $left.MaxTimestamp == $right.MetricTimestamp
    """.format(METRIC_TABLE, hw_sku_name, METRIC_TABLE)

    op_name = "Most Recent Metric Query"
    query_result = execute_kusto_query_with_retry(sonic_kusto_client, SONIC_TEST_DATA_DB, query, op_name)
    result_data = query_result.primary_results[0]
    metric_df = dataframe_from_result_table(result_data)

    exec_time = time.time() - start_time
    logger.info("Most recent metric query completed in {:.2f}s, found {} rows".format(exec_time, len(metric_df)))
    return metric_df


def get_prev_metric_data(sonic_kusto_client, hw_sku_name):
    prev_metric_df = get_most_recent_metric_df(sonic_kusto_client, hw_sku_name)
    if prev_metric_df.empty:
        logger.warning("No most recent metric data found. Using default values.")
        one_day_ago_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        return one_day_ago_str, 0
    else:
        prev_metric_timestamp = prev_metric_df["MetricTimestamp"].values[0]
        prev_sonic_device_count = prev_metric_df[
            prev_metric_df["DeviceType"] == SONIC_DEVICE_TYPE
        ]["DeviceCountSnapshot"].sum()
        prev_metric_timestamp_str = pd.Timestamp(prev_metric_timestamp).strftime('%Y-%m-%dT%H:%M:%SZ')
        logger.info(
            "Most recent metric found - prev_metric_timestamp_str: {}, prev_sonic_device_count: {}".format(
                prev_metric_timestamp_str,
                prev_sonic_device_count,
            )
        )

        return prev_metric_timestamp_str, prev_sonic_device_count


def get_device_data_from_hw_sku_strategy(azphynet_kusto_client, hw_sku_strategy):
    for attempt in range(MAX_RETRIES):
        try:
            return hw_sku_strategy.get_all_units_df(azphynet_kusto_client)
        except (KustoServiceError, KustoClientError) as ke:
            logger.warning("Kusto query error on attempt {}/{} for Device Data Query: {}".format(
                attempt + 1,
                MAX_RETRIES,
                ke,
            ))

            if attempt == MAX_RETRIES - 1:
                logger.error("Kusto query failed after {} attempts for Device Data Query. ".format(MAX_RETRIES))
                raise

            time.sleep(RETRY_DELAY * (attempt + 1))
        except Exception as e:
            logger.error("Unexpected error during Device Data Query: {}".format(e))
            raise

    return pd.DataFrame()  # Should not reach here if retries are implemented correctly


def process_os_version_data(os_version, metric_timestamp, sonic_modules_df, vendor_devices_df, incidents_df,
                            hw_sku_strategy):
    logger.info("Processing OS version: {}".format(os_version))
    os_version_data = {
        "MetricTimestamp": metric_timestamp,
        "CreatedBy": METRIC_ROLE,
        "CreatedTimestamp": metric_timestamp,
        "UpdatedBy": METRIC_ROLE,
        "UpdatedTimestamp": metric_timestamp,
        "OSVersion": os_version,
        "HwSKU": hw_sku_strategy.get_hw_sku_name(),
    }

    if SONIC_DEVICE_TYPE in os_version.lower():
        os_version_data["DeviceType"] = SONIC_DEVICE_TYPE
        sonic_version_df = sonic_modules_df[sonic_modules_df["OSVersion"] == os_version]
        sonic_module_count_snapshot = len(sonic_version_df)
        sonic_device_count_snapshot = hw_sku_strategy.get_sonic_device_count(sonic_version_df)

        os_version_data["ModuleCountSnapshot"] = sonic_module_count_snapshot
        os_version_data["DeviceCountSnapshot"] = sonic_device_count_snapshot
        sonic_device_names = set(sonic_version_df["DeviceName"].str.casefold())
        filtered_incidents_df = incidents_df[
            incidents_df["OccurringDeviceName"].str.casefold().isin(sonic_device_names)
        ]
    else:
        os_version_data["DeviceType"] = VENDOR_DEVICE_TYPE
        vendor_version_df = vendor_devices_df[vendor_devices_df["OSVersion"] == os_version]
        vendor_device_count_snapshot = len(vendor_version_df)
        os_version_data["ModuleCountSnapshot"] = vendor_device_count_snapshot
        os_version_data["DeviceCountSnapshot"] = vendor_device_count_snapshot
        vendor_device_names = set(vendor_version_df["DeviceName"].str.casefold())
        filtered_incidents_df = incidents_df[
            incidents_df["OccurringDeviceName"].str.casefold().isin(vendor_device_names)
        ]

    os_version_data["TotalIncidentCountSincePrevious"] = len(filtered_incidents_df)
    severities = [2, 25, 3, 4]
    if not filtered_incidents_df.empty:
        os_version_data["NonSev2CountSincePrevious"] = len(filtered_incidents_df[filtered_incidents_df["Severity"] != 2])
        for sev in severities:
            sev_col = "Sev{}CountSincePrevious".format(sev)
            os_version_data[sev_col] = len(filtered_incidents_df[filtered_incidents_df["Severity"] == sev])
    else:
        os_version_data["NonSev2CountSincePrevious"] = 0
        for sev in severities:
            sev_col = "Sev{}CountSincePrevious".format(sev)
            os_version_data[sev_col] = 0

    return os_version_data


def create_daily_metric_df(azphynet_kusto_client, sonic_kusto_client, hw_sku_name):
    logger.info("Creating daily metric for HwSKU: {}".format(hw_sku_name))
    start_time = time.time()

    hw_sku_strategy = HwSkuFactory.create_strategy(hw_sku_name)

    # Get most recent metric data
    prev_metric_timestamp, prev_sonic_device_count = get_prev_metric_data(sonic_kusto_client, hw_sku_name)

    # Start building the current daily metric DataFrame
    metric_timestamp = datetime.now(timezone.utc)
    all_units_df = get_device_data_from_hw_sku_strategy(azphynet_kusto_client, hw_sku_strategy)
    if all_units_df.empty:
        logger.warning("No devices found. Returning empty DataFrame.")
        return all_units_df

    all_unit_names = "'" + all_units_df["DeviceName"].str.cat(sep="','") + "'"
    incidents_df = get_device_incidents_df(azphynet_kusto_client, all_unit_names, prev_metric_timestamp)

    sonic_modules_df = all_units_df[all_units_df["DeviceType"] == SONIC_DEVICE_TYPE]
    vendor_devices_df = all_units_df[all_units_df["DeviceType"] == VENDOR_DEVICE_TYPE]
    all_os_versions = all_units_df["OSVersion"].unique()
    results = []
    for os_version in all_os_versions:
        os_version_data = process_os_version_data(
            os_version,
            metric_timestamp,
            sonic_modules_df,
            vendor_devices_df,
            incidents_df,
            hw_sku_strategy,
        )

        results.append(os_version_data)

    daily_metric_df = pd.DataFrame(results)
    total_sonic_device_count = hw_sku_strategy.get_sonic_device_count(sonic_modules_df)
    daily_metric_df["TotalSonicDeviceSnapshot"] = total_sonic_device_count
    daily_metric_df["SonicDeviceCountSincePrevious"] = total_sonic_device_count - prev_sonic_device_count

    exec_time = time.time() - start_time
    logger.info("Daily metric creation completed in {:.2f}s".format(exec_time))
    return daily_metric_df


def ingest_metric_data(sonic_ingest_client, df_to_ingest):
    if df_to_ingest.empty:
        logger.warning("DataFrame is empty. No data to ingest")
        return

    ingestion_props = IngestionProperties(
        database=SONIC_TEST_DATA_DB,
        table=METRIC_TABLE,
        data_format=DataFormat.CSV
    )

    logger.info("Starting ingestion of {} records".format(len(df_to_ingest)))
    df_to_ingest["IngestionTimestamp"] = datetime.now(timezone.utc)
    try:
        sonic_ingest_client.ingest_from_dataframe(df_to_ingest, ingestion_properties=ingestion_props)
        logger.info("Data ingestion completed successfully")
    except Exception as e:
        logger.error("Failed to ingest data to {}.{}: {}".format(SONIC_TEST_DATA_DB, METRIC_TABLE, e))
        raise


def create_kusto_client(cluster_url, access_token):
    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster_url, access_token)
    return KustoClient(kcsb)


def create_ingest_client(cluster_url, access_token):
    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster_url, access_token)
    return QueuedIngestClient(kcsb)


def main():
    logger.info("Starting sonic daily sync pipeline")
    try:
        azphynet_kusto_client = create_kusto_client(AZPHYNET_CLUSTER, ACCESS_TOKEN)
        sonic_kusto_client = create_kusto_client(SONIC_CLUSTER, ACCESS_TOKEN)

        all_metric_dfs = []
        for hw_sku_name in HwSkuFactory.get_available_hw_skus():
            daily_metric_df = create_daily_metric_df(
                azphynet_kusto_client,
                sonic_kusto_client,
                hw_sku_name,
            )

            if not daily_metric_df.empty:
                all_metric_dfs.append(daily_metric_df)

        if all_metric_dfs:
            combined_metric_df = pd.concat(all_metric_dfs, ignore_index=True)
            sonic_ingest_client = create_ingest_client(SONIC_INGEST_CLUSTER, ACCESS_TOKEN)
            ingest_metric_data(sonic_ingest_client, combined_metric_df)
        else:
            logger.warning("No data to ingest. All metric DataFrames are empty.")
    except Exception as e:
        logger.error("An error occurred in sonic daily metric sync pipeline: {}".format(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
