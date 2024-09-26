import argparse
import json
import sys
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timedelta
from croniter import croniter

import requests
import pandas as pd
import os

# Elastictest Nightly Test (Centralized) Pipeline ID
PIPELINE_ID = "2076"
# Azure DevOps Access Token
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", None)
# Elastictest Nightly Test (Centralized) Pipeline ID
PIPELINE_YAML_BRANCH = "refs/heads/internal"
# Trigger Nightly Test Time Window, Please set same as Nightly Test Trigger schedule
TIME_WINDOW_INTERVAL = 10  # minutes
# Centralized nightly tests csv file
NIGHTLYTEST_FILE = "elastictest_nightlytests.csv"

# ThreadPool
THREAD_POOL = ThreadPoolExecutor(max_workers=20, thread_name_prefix="elastictest_nightlytest_trigger")


def is_time_to_run(pipeline_name: str, cron_expression: str):
    """
    Check if it's time to run the scheduled task.
    Based on time window and cron expression.

    For example:
        If time window interval is 10 minutes.
        If current time is 03:01, or whatever a value in [03:00, 03:10), Friday.
        Then trigger time window will be [03:00, 03:10)
        If the scheduled task is set to run every Friday at 03:03.
        It will check if this time falls within the trigger window.
        Since 03:03 is within [03:00, 03:10), the task is due to run.
    """
    # Get the current time in UTC
    current_time = datetime.utcnow()
    print("Current time: ", current_time)

    # Calculate the start of the current {TIME_WINDOW_INTERVAL}-minute window
    window_start_minute = (current_time.minute // TIME_WINDOW_INTERVAL) * TIME_WINDOW_INTERVAL
    window_start_time = current_time.replace(minute=window_start_minute, second=0, microsecond=0)
    window_end_time = window_start_time + timedelta(minutes=TIME_WINDOW_INTERVAL)

    print(f"Current trigger time window: [{window_start_time}, {window_end_time})")

    # Create a croniter object with the cron expression and the current window start time
    # Subtract 1 second to include the start time of the interval
    iterator = croniter(cron_expression, window_start_time - timedelta(seconds=1))
    # Get the next scheduled time from the cron expression
    next_run_time = iterator.get_next(datetime)
    print(f"{pipeline_name} next run time: {next_run_time}")

    # Check if the next scheduled time is within the {TIME_WINDOW_INTERVAL}-minute window [start, end)
    return window_start_time <= next_run_time < window_end_time


def trigger_pipeline(pipeline_info):
    """
    Trigger pipeline according to the pipeline info, by sending HTTP request.
    """

    pipeline_name = pipeline_info["pipeline_name"]

    json_body = {
        "templateParameters": {
            "PIPELINE_NAME": pipeline_name,
            "TESTBED_NAME": pipeline_info["testbed_name"],
            "MIN_WORKER": pipeline_info["min_worker"],
            "MAX_WORKER": pipeline_info["max_worker"],
            "IMAGE_URL": pipeline_info["image_url"],
            "MGMT_BRANCH": pipeline_info["mgmt_branch"],
            "SCRIPTS": pipeline_info["scripts"] if pipeline_info["scripts"] else " ",
            "FEATURES": pipeline_info["features"] if pipeline_info["features"] else " ",
            "SCRIPTS_EXCLUDE": pipeline_info["scripts_exclude"] if pipeline_info["scripts_exclude"] else " ",
            "FEATURES_EXCLUDE": pipeline_info["features_exclude"] if pipeline_info["features_exclude"] else " ",
            "COMMON_EXTRA_PARAMS": pipeline_info["common_extra_params"] if pipeline_info["common_extra_params"] else " ",
            "SPECIFIC_PARAM": pipeline_info["specific_param"].replace("'", "\"") if pipeline_info["specific_param"] else " ",
            "MAX_RUN_TEST_MINUTES": pipeline_info["max_run_test_minutes"],
            "AFFINITY": pipeline_info["affinity"].replace("'", "\"") if pipeline_info["affinity"] else "[]"
        },
        "resources": {
            "repositories": {
                "self": {
                    "refName": PIPELINE_YAML_BRANCH
                }
            }
        }
    }

    print(f"Triggering pipeline {pipeline_name} with parameters: {json.dumps(json_body, indent=4)}")

    # Prepare the API request
    url = f"https://dev.azure.com/mssonic/internal/_apis/pipelines/{PIPELINE_ID}/runs?api-version=7.1"
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}

    # Trigger the pipeline
    response = requests.post(url, headers=headers, json=json_body)
    if response.status_code == 200 or response.status_code == 201:
        resp = response.json()
        href = resp.get("_links", {}).get("self", {}).get("href", "")
        build_url = ""
        if href:
            build_id = href.split("/")[-1]
            build_url = f"https://dev.azure.com/mssonic/internal/_build/results?buildId={build_id}&view=results"
        print(
            f"Triggered pipeline {pipeline_name} successfully. {build_url}")

        return pipeline_name, build_url
    else:
        raise Exception(f"Failed to trigger pipeline. Response: {response.text}")


def trigger_pipeline_by_name(pipeline_name: str):
    """
    Trigger a pipeline by pipeline name.
    """
    print(f"Starting trigger pipeline {pipeline_name} ...")

    # Read the CSV file, filling NaN with ""
    df = pd.read_csv(NIGHTLYTEST_FILE, sep=",").fillna(value="")

    succeeded_pipeline_name = ""

    # Iterate CSV, each row contains the definition of a pipeline
    for index, row in df.iterrows():
        # Check if it's the specific pipeline to run
        if pipeline_name == row["pipeline_name"]:
            succeeded_pipeline_name = trigger_pipeline(row)
            break

    if not succeeded_pipeline_name:
        raise Exception(f"Error: Invalid pipeline name {pipeline_name}.")


def trigger_pipelines_by_schedule():
    """
    Trigger multiple pipelines by schedule.
    """
    print(f"Starting trigger pipelines by schedule ...")

    # Read the CSV file, filling NaN with ""
    df = pd.read_csv(NIGHTLYTEST_FILE, sep=",").fillna(value="")

    # Collect multi thread result
    futures = []
    future_pipeline_map = {}

    # Iterate CSV, each row contains the definition of a pipeline
    for index, row in df.iterrows():

        print("=" * 40)

        pipeline_name = row["pipeline_name"]

        # If pipeline is enabled
        enabled = row["enabled"]

        if not enabled:
            print(f"{pipeline_name} is not enabled. Skipped.")
            continue
        # If it's time to run the scheduled pipeline
        cron_expression = row["cron"]
        if not is_time_to_run(pipeline_name, cron_expression):
            print(f"It is not time to execute {pipeline_name} yet.")
            continue

        # Submit task in parallel
        future = THREAD_POOL.submit(trigger_pipeline, pipeline_info=row)

        # Collect result
        futures.append(future)
        future_pipeline_map[future] = pipeline_name

    # Summarize
    pipelines_succeeded = {}
    pipelines_failed = {}

    # Iterate over the submitted tasks
    for future in as_completed(futures):

        trigger_pipeline_name = future_pipeline_map[future]

        try:
            # Get the result of the task
            succeeded_pipeline_name, succeeded_url = future.result()
            pipelines_succeeded[succeeded_pipeline_name] = succeeded_url
        except Exception as e:
            pipelines_failed[trigger_pipeline_name] = str(e)

    # Print summary
    print("=" * 40)
    print("Summary:")
    print(f"Pipelines triggered successfully: {json.dumps(pipelines_succeeded, indent=4)}")
    print(f"Pipelines triggered failed: {json.dumps(pipelines_failed, indent=4)}")

    # If not all pipelines (need to trigger) run successfully, return False to notify user
    if pipelines_failed:
        raise Exception("Not all pipelines (need to trigger) run successfully, please check logs.")


def main():
    parser = argparse.ArgumentParser(description="Trigger Nightly Test Pipeline Commands")

    parser.add_argument(
        '-n',
        '--pipeline_name',
        type=str,
        required=False,
        nargs='?',
        const=None,
        default="",
        help='Specify pipeline name to trigger.')

    args = parser.parse_args()

    try:
        # Check required env
        if not ACCESS_TOKEN:
            raise Exception("Environment variable required! ACCESS_TOKEN not existed.")

        # Check not required argument
        if args.pipeline_name:
            trigger_pipeline_by_name(args.pipeline_name)
        else:
            trigger_pipelines_by_schedule()

    except Exception as e:
        print(f"Error: {repr(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
