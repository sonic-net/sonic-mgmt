"""Script to collect failed/cancelled/success tasks for specific azure pipeline and save it to json file."""
import os
import requests
import argparse
import json


TOKEN = os.environ.get('AZURE_DEVOPS_MSSONIC_TOKEN')
if not TOKEN:
    raise Exception('Must export environment variable AZURE_DEVOPS_MSSONIC_TOKEN')
AUTH = ('', TOKEN)

TASK_RESULT_FILE = "pipeline_task_results.json"


def get_tasks_results(buildid):
    """Collect previous tasks' results and save to file'

    Returns:
        dict: Dict of tasks' results
    """
    task_results = {
        "start_time": "",
        "success_tasks": "",
        "failed_tasks": "",
        "cancelled_tasks": ""
    }

    pipeline_url = "https://dev.azure.com/mssonic/internal/_apis/build/builds/"+ str(buildid)
    print("Collect pipeline startTime from here:{}".format(pipeline_url))
    api_result = requests.get(pipeline_url, auth=AUTH)
    starttime_str = api_result.json()["startTime"]

    # Convert the time format from 2022-08-09T03:00:32.7088577Z
    # to 2022-08-09 03:00:32.7088577
    starttime_str = starttime_str.replace("T", " ")
    starttime_str = starttime_str.replace("Z", "")
    task_results["start_time"] = starttime_str

    timeline_url = "https://dev.azure.com/mssonic/internal/_apis/build/builds/" + str(buildid) + "/timeline?api-version=5.1"
    print("Collect task results from here:{}".format(timeline_url))
    api_result = requests.get(timeline_url, auth=AUTH)
    build_records = api_result.json()["records"]
    if not build_records:
        print("Failed to get build records for buildid {}".format(buildid))
        return
    for task in build_records:
        if task and task["state"] == "completed":
            if task["result"] == 'succeeded':
                task_results["success_tasks"] += task["name"] + ";"
            if task["result"] == 'failed':
                task_results["failed_tasks"] += task["name"] + ";"
            if task["result"] == 'canceled':
                task_results["cancelled_tasks"] += task["name"] + ";"
    with open(TASK_RESULT_FILE, "w") as f:
        json.dump(task_results, f)
    return task_results

def main():
    parser = argparse.ArgumentParser(
        description="Upload test reports to Kusto.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
            Examples:
            python3 collect_azp_results.py 88888
            """,
    )
    parser.add_argument("build_id", metavar="buildid", type=str, help="build ids of pipeline, ie 88888")

    args = parser.parse_args()
    build_id = args.build_id
    get_tasks_results(build_id)


if __name__ == "__main__":
    main()
