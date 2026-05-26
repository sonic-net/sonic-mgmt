#!/usr/bin/env python3
"""
Notify demyst server with run information after ring4 test completion.
Called from do_full_run.py collect_results() function.
"""
import os
import sys
import logging
from typing import Tuple, Optional

# Add demyst directory to path for utils import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from demyst.utils import (
    is_ring4_pipeline,
    validate_demyst_inputs,
    validate_testbed_config,
    get_sonic_test_commit,
    get_syslogs_url,
    send_to_demyst
)

DEMYST_SERVER_URL = "https://demyst.cisco.com:10003/api/v1/analysis/offline"

log = logging.getLogger("HW_SANITY_LOGS.NOTIFY_DEMYST")


def notify_demyst(
    testbed: str,
    build_id: str,
    jenkins_build_id: str,
    stream: str,
    allure_report_url: str,
    syslogs_url: str,
    testbed_info_dict: dict,
    container_name: str,
    pipeline_type: str
) -> Tuple[bool, Optional[str]]:
    """
    Send notification to demyst server.
    
    Args:
        testbed: Testbed name (e.g., t1-m3-4-cmono)
        build_id: Sonic buildimage build ID (p2build_job_id)
        jenkins_build_id: Jenkins job build ID
        stream: Stream name (e.g., cisco.202511.signed)
        allure_report_url: URL to allure report
        syslogs_url: Base URL for syslogs (sanity_logs.tar.gz will be appended)
        testbed_info_dict: Testbed info dictionary from hw_cfg.json
        container_name: sonic-mgmt container name
        pipeline_type: Pipeline type (e.g., 'ring4')
    
    Returns:
        tuple: (success: bool, results_url: str or None)
            - success=True, results_url=URL: Successfully sent, demyst URL returned
            - success=True, results_url=None: Skipped (not ring4 pipeline)
            - success=False, results_url=None: Validation failed or error occurred
    """
    log.info(f"Demyst notification: testbed={testbed}, stream={stream}, build_id={build_id}, jenkins_build_id={jenkins_build_id}")
    
    # Check if ring4 pipeline
    if not is_ring4_pipeline(pipeline_type):
        log.info(f"Skipping - pipeline type is '{pipeline_type}', not 'ring4'")
        return True, None
    
    # Validate required fields
    if not validate_demyst_inputs(jenkins_build_id, allure_report_url, syslogs_url):
        log.error("Validation failed: missing required fields")
        return False, None
    
    full_syslogs_url = get_syslogs_url(syslogs_url)
    if not full_syslogs_url:
        log.error("Validation failed: syslogs not found")
        return False, None
    
    # Validate testbed configuration
    testbed_config = validate_testbed_config(testbed_info_dict, testbed)
    if not testbed_config:
        log.error("Validation failed: invalid testbed configuration")
        return False, None
    
    # Get sonic_test commit from UCS
    sonic_test_commit = get_sonic_test_commit(
        testbed_config["ucs_host"],
        testbed_config["ucs_username"],
        testbed_config["ucs_password"],
        container_name
    )
    
    # Build and send payload
    return send_to_demyst({
        "build_id": build_id,
        "submitter_cec_id": f"cicd_{testbed}",
        "run_id": f"{testbed}_{jenkins_build_id}",
        "sonic_test_commit_id": sonic_test_commit,
        "log_source": "allure_url",
        "allure_report_url": allure_report_url,
        "syslogs_url": full_syslogs_url,
        "testbed": testbed,
        "stream": stream,
        "topo_type": testbed_config["topology"],
        "run_type": "hardware",
        "sonic_test_repo_url": "sonic-test",
        "require_approval": False,
    }, DEMYST_SERVER_URL)
