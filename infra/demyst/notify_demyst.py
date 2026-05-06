#!/usr/bin/env python3
"""
Notify demyst server with run information after ring4 test completion.
Called from CICD after collect-results step.

Usage:
    python3 notify_demyst.py --pipeline-type <TYPE> -t <TESTBED> -b <BUILD_ID> -r <RUN_ID> -m <STREAM> --results-json <PATH>

Arguments:
    --pipeline-type     Pipeline type (e.g., ring4)
    -t, --testbed       Testbed name (key in hw_cfg.json)
    -b, --build_id      Sonic buildimage build ID (p2build_job_id)
    -r, --run_id        Jenkins job build ID
    -m, --stream        Stream name (e.g., 202405, master) for container lookup
    --results-json      Path to results.json file containing report_link and log_tarball_link

Requirements:
    - pipeline-type must be "ring4" to send notification
    - Testbed must be listed in supported_testbeds.txt
    - hw_cfg.json must have topology for the testbed
    - results.json must contain report_link and log_tarball_link
"""
import os
import sys
import json
import logging
import argparse
import paramiko
import requests
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hw_setup_utils import getTestbedInfoDict, getSonicMgmtContainterName
from utils import _run_cmd_in_ssh

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SUPPORTED_TESTBEDS_FILE = os.path.join(SCRIPT_DIR, "supported_testbeds.txt")
DEMYST_SERVER_URL = "https://demyst.cisco.com:10003/api/v1/analysis/offline"


def init_logging(name):
    """Initialize logging with file and stream handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    file_handler = logging.FileHandler(os.path.join('./', '%s.log' % name))
    file_handler.setLevel(logging.DEBUG)
    
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter(
        '%(asctime)s [%(filename)s:%(lineno)d] %(levelname)s: %(message)s'
    )
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


log = init_logging("NOTIFY_DEMYST")


def is_ring4_run(pipeline_type):
    """Check if this is a ring4 pipeline run."""
    is_ring4 = pipeline_type.lower() == "ring4"
    if not is_ring4:
        log.info(f"Not a ring4 run (pipeline_type={pipeline_type}), skipping demyst notification")
    return is_ring4


def parse_results_json(results_json_path):
    """Parse results.json and extract required fields."""
    try:
        with open(results_json_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        log.error(f"results.json not found at: {results_json_path}")
        return None
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse results.json: {e}")
        return None
    
    report_link = data.get("report_link")
    log_tarball_link = data.get("log_tarball_link")
    
    if not report_link:
        log.error("Missing required field 'report_link' in results.json")
        return None
    if not log_tarball_link:
        log.error("Missing required field 'log_tarball_link' in results.json")
        return None
    
    log.info(f"Parsed results.json: report_link={report_link}, log_tarball_link={log_tarball_link}")
    return {
        "report_link": report_link,
        "log_tarball_link": log_tarball_link
    }


def is_testbed_supported(testbed):
    """Check if testbed is in supported_testbeds.txt."""
    try:
        with open(SUPPORTED_TESTBEDS_FILE, 'r') as f:
            supported = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if testbed not in supported:
            log.info(f"Testbed '{testbed}' not in supported_testbeds.txt")
            return False
        return True
    except FileNotFoundError:
        log.warning(f"{SUPPORTED_TESTBEDS_FILE} not found")
        return False


def get_sonic_test_commit(client, container_name):
    """Get sonic-test repo commit ID from the container's mounted directory."""
    try:
        # Get the sonic-test mount path from container
        cmd = f"docker inspect {container_name} --format '{{{{range .Mounts}}}}{{{{.Source}}}} {{{{end}}}}' | tr ' ' '\\n' | grep sonic-test | head -1"
        out, _, rc = _run_cmd_in_ssh(client, cmd)
        if rc == 0 and out.strip():
            # Get parent directory of sonic-test mount (the repo root)
            sonic_test_path = out.strip().split('\n')[0]  # Take first line only
            sonic_test_dir = os.path.dirname(sonic_test_path)
            git_cmd = f"cd {sonic_test_dir} && git rev-parse HEAD"
            commit_out, _, rc2 = _run_cmd_in_ssh(client, git_cmd)
            if rc2 == 0 and commit_out.strip():
                return commit_out.strip()
    except Exception as e:
        log.warning(f"Failed to get sonic_test commit id: {e}")
    return ""


def get_syslogs_url(base_url):
    """Check if sanity_logs.tar.gz exists at the URL and return full URL."""
    if base_url.endswith('/'):
        full_url = base_url + "sanity_logs.tar.gz"
    else:
        full_url = base_url + "/sanity_logs.tar.gz"
    
    try:
        response = requests.head(full_url, timeout=10)
        if response.status_code == 200:
            log.info(f"Found syslogs at: {full_url}")
            return full_url
        log.warning(f"sanity_logs.tar.gz not found at {full_url} (status: {response.status_code})")
        return None
    except Exception as e:
        log.warning(f"Failed to check syslogs URL: {e}")
        return None


def build_payload(args, testbed_info, results_data):
    """Build the payload to send to demyst server."""
    topology = testbed_info.get("topology", "")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_run_id = f"{args.testbed}_{args.run_id}_{timestamp}"
    
    syslogs_url = get_syslogs_url(results_data["log_tarball_link"])
    if not syslogs_url:
        log.warning("Could not find sanity_logs.tar.gz, skipping demyst notification")
        return None
    
    # Get sonic_test commit from UCS container
    sonic_test_commit = ""
    if args.stream:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=testbed_info['ucs_host'],
                username=testbed_info['ucs_username'],
                password=testbed_info['ucs_password']
            )
            container_name = getSonicMgmtContainterName(args.stream, args.testbed)
            sonic_test_commit = get_sonic_test_commit(client, container_name)
            client.close()
            if sonic_test_commit:
                log.info(f"Got sonic_test commit: {sonic_test_commit}")
        except Exception as e:
            log.warning(f"Failed to get sonic_test commit: {e}")
    
    return {
        "build_id": args.build_id,
        "run_id": unique_run_id,
        "sonic_test_commit_id": sonic_test_commit,
        "log_source": "allure_url",
        "allure_report_url": results_data["report_link"],
        "syslogs_url": syslogs_url,
        "testbed": args.testbed,
        "topo_type": topology,
        "run_type": "hardware",
        "sonic_test_repo_url": "sonic-test",
    }


def send_to_demyst(payload):
    """Send payload to demyst server."""
    log.info(f"Sending to {DEMYST_SERVER_URL}")
    log.debug(f"Payload: {json.dumps(payload, indent=2)}")
    
    headers = {"Content-Type": "application/json"}
    
    # Try with system proxy first
    try:
        response = requests.post(DEMYST_SERVER_URL, json=payload, headers=headers, timeout=30)
        if response.status_code in [200, 202]:
            log.info(f"Successfully sent to demyst: {response.status_code}")
            return 0
    except Exception as e:
        log.debug(f"System proxy failed: {e}")
    
    # Fallback: no proxy
    try:
        response = requests.post(
            DEMYST_SERVER_URL, json=payload, headers=headers, timeout=30,
            proxies={"http": None, "https": None}
        )
        if response.status_code in [200, 202]:
            log.info(f"Successfully sent to demyst (direct): {response.status_code}")
            return 0
        log.error(f"Server returned {response.status_code}: {response.text}")
        return 1
    except Exception as e:
        log.error(f"Failed to send to demyst: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(description='Notify demyst server after ring4 test completion')
    parser.add_argument("-p","--pipeline-type", required=True, help="Pipeline type (e.g., ring4)")
    parser.add_argument("-t", "--testbed", required=True, help="Testbed name (key in hw_cfg.json)")
    parser.add_argument("-b", "--build_id", required=True, help="Sonic buildimage build ID (p2build_job_id)")
    parser.add_argument("-r", "--run_id", required=True, help="Jenkins job build ID")
    parser.add_argument("-m", "--stream", required=True, help="Stream name (e.g., 202405, master) for container lookup")
    parser.add_argument("-j","--results-json", required=True, help="Path to results.json file")
    args = parser.parse_args()
    
    log.info(f"Starting demyst notification: testbed={args.testbed}, build_id={args.build_id}, run_id={args.run_id}")
    
    if not is_ring4_run(args.pipeline_type):
        return 0  # Skip, not an error
    
    if not is_testbed_supported(args.testbed):
        return 0 #Skip sending payload to demyst server if testbed is not supported. 
    
    results_data = parse_results_json(args.results_json)
    if results_data is None:
        return 1
    
    testbed_info = getTestbedInfoDict(args.testbed)
    if not testbed_info:
        log.error(f"Testbed '{args.testbed}' not found in hw_cfg.json")
        return 1
    
    payload = build_payload(args, testbed_info, results_data)
    if payload is None:
        return 1
    
    log.debug(f"Payload: {json.dumps(payload, indent=2)}")
    return send_to_demyst(payload)


if __name__ == "__main__":
    sys.exit(main())
