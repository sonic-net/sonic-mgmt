import os
import re
import logging
import argparse
import subprocess
import uuid

from concurrent.futures import ThreadPoolExecutor
from report_data_storage import KustoConnector
from natsort import natsorted
from datetime import datetime


def collect_test_scripts(location):
    """
        Collect all test scripts under the given location that match the 'test_*.py' pattern.
    """
    scripts = []
    for root, dirs, script in os.walk(location):
        for s in script:
            if s.startswith("test_") and s.endswith(".py"):
                scripts.append(os.path.join(root, s))
    return natsorted(scripts)


def extract_topology(script_path):
    """
        Extract topology information from a test script using regex.
    """
    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")
    try:
        with open(script_path, 'r') as script:
            match = pattern.search(script.read())
            return match.group(1) if match else None
    except Exception as e:
        logging.error(f'Failed to read script {script_path}, error: {e}')


def run_pytest_collection(location):
    """
        Run pytest once to collect all test cases under the given location.
    """
    command = [
        "python3", "-m", "pytest", location,
        "--inventory", "../ansible/veos_vtb", "--host-pattern", "all",
        "--testbed_file", "../ansible/vtestbed.yaml", "--testbed", "vms-kvm-t0",
        "--ignore", "saitests", "--ignore", "ptftests", "--ignore", "acstests",
        "--ignore", "scripts", "--ignore", "sai_qualify", "--ignore", "common",
        "--ignore-conditional-mark", "--color=no", "--collect-only",
        "--continue-on-collection-errors", "--disable-warnings", "--capture=no", "-q"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    output = result.stdout
    test_cases = re.findall(r'.+::.+', output, re.MULTILINE)
    return test_cases


def upload_results(test_cases, db_name, db_table, db_table_mapping):
    kusto_db = KustoConnector(db_name, db_table, db_table_mapping)
    kusto_db.upload_results(test_cases)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--location", help="The path of test cases", type=str, default="")
    parser.add_argument("--db_name", help="The Kusto database to connect to", type=str, default="")
    parser.add_argument("--db_table", help="The Kusto table to ingest data to", type=str, default="")
    parser.add_argument("--db_table_mapping", help="The json mapping to ingest data", type=str, default="")
    parser.add_argument("--repo_url", help="The url of the repo", type=str, default="")
    parser.add_argument("--branch", help="The checkout branch", type=str, default="")
    parser.add_argument("--scan_time", help="The snapshot of PR checkout date", type=str, default="")
    args = parser.parse_args()

    location = args.location
    db_name = args.db_name
    db_table = args.db_table
    db_table_mapping = args.db_table_mapping
    repo_url = args.repo_url
    branch = args.branch
    scan_time = args.scan_time

    # Collect all test scripts (file names)
    scripts = collect_test_scripts(location)
    # Use a thread pool to extract topologies in parallel
    topology_dict = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(extract_topology, scripts)
        for script, topology in zip(scripts, results):
            script_name = script[len(location) + 1:]
            topology_dict[script_name] = topology

    # Run pytest once to collect all test cases
    collected_test_cases = run_pytest_collection(location)

    # Match test cases with their corresponding topology
    test_cases = []
    # Add additionally field to mark one running
    trackid = str(uuid.uuid4())

    if scan_time:
        parsed_date = datetime.strptime(scan_time, "%Y-%m-%d")
        scan_time = parsed_date.strftime("%Y-%m-%d %H:%M:%S")
    else:
        scan_time = str(datetime.now())

    for test_case in collected_test_cases:
        script_name = test_case.split("::", 1)[0]  # Extract script file name
        test_case_name = test_case.split("::", 1)[1]
        topology = topology_dict.get(script_name, None)

        test_cases.append({
            "testcase": test_case_name,
            "filepath": script_name,
            "topology": topology,
            "scantime": scan_time,
            "trackid": trackid,
            "repository": repo_url,
            "branch": branch
        })

    upload_results(test_cases, db_name, db_table, db_table_mapping)


if __name__ == "__main__":
    main()
