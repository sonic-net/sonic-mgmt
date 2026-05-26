#!/usr/bin/env python3
"""
Utility functions for demyst notification.

Includes validation, SSH operations, URL checking, and server communication.
Stream and testbed validation is now handled by demyst server.
"""
import os
import json
import logging
import paramiko
import requests
import urllib3

# Disable SSL warnings for internal servers with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("HW_SANITY_LOGS.NOTIFY_DEMYST")


# =============================================================================
# Validation Utilities
# =============================================================================

def is_ring4_pipeline(pipeline_type):
    """Check if pipeline type is ring4.
    
    Args:
        pipeline_type: Pipeline type string from environment
    
    Returns:
        bool: True if ring4 (case-insensitive), False otherwise
    """
    return pipeline_type.lower() == "ring4"


def validate_demyst_inputs(run_id, allure_report_url, syslogs_url):
    """Validate required fields for demyst notification.
    
    Args:
        run_id: Jenkins job build ID
        allure_report_url: URL to allure report
        syslogs_url: Base URL for syslogs
    
    Returns:
        bool: True if all fields are present, False otherwise
    """
    missing = []
    if not run_id:
        missing.append("run_id")
    if not allure_report_url:
        missing.append("allure_report_url")
    if not syslogs_url:
        missing.append("syslogs_url")
    
    if missing:
        log.info(f"Missing required fields: {', '.join(missing)}")
        return False
    
    return True


def validate_testbed_config(testbed_info_dict, testbed_name):
    """Validate testbed configuration has required fields.
    
    Args:
        testbed_info_dict: Testbed configuration dictionary from hw_cfg.json
        testbed_name: Testbed name for logging
    
    Returns:
        dict | None: Dictionary with topology and UCS credentials if valid, None otherwise
            Returns: {"topology": str, "ucs_host": str, "ucs_username": str, "ucs_password": str}
    """
    topology = testbed_info_dict.get("topology", "")
    ucs_host = testbed_info_dict.get("ucs_host", "")
    ucs_username = testbed_info_dict.get("ucs_username", "")
    ucs_password = testbed_info_dict.get("ucs_password", "")
    
    if not topology:
        log.info(f"Missing topology in testbed config for {testbed_name}")
        return None
    
    if not all([ucs_host, ucs_username, ucs_password]):
        log.info(f"Missing UCS credentials in testbed config for {testbed_name}")
        return None
    
    return {
        "topology": topology,
        "ucs_host": ucs_host,
        "ucs_username": ucs_username,
        "ucs_password": ucs_password
    }


# =============================================================================
# SSH Utilities
# =============================================================================

def run_ssh_cmd(client, cmd):
    """Run command over SSH and return (stdout, stderr, return_code)."""
    stdin, stdout, stderr = client.exec_command(cmd)
    rc = stdout.channel.recv_exit_status()
    return stdout.read().decode('utf-8'), stderr.read().decode('utf-8'), rc


def get_sonic_test_commit(ucs_host, ucs_username, ucs_password, container_name):
    """Get sonic-test repo commit ID from the UCS container.
    
    Args:
        ucs_host: UCS server hostname/IP
        ucs_username: SSH username for UCS
        ucs_password: SSH password for UCS
        container_name: sonic-mgmt container name
    
    Returns:
        str: Commit hash or empty string if failed
    """
    try:
        # AutoAddPolicy for internal UCS infrastructure (consistent with sonic-test pattern)
        with paramiko.SSHClient() as client:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=ucs_host, username=ucs_username, password=ucs_password)
            
            # Get sonic-test mount path from container
            cmd = f"docker inspect {container_name} --format '{{{{range .Mounts}}}}{{{{.Source}}}} {{{{end}}}}' | tr ' ' '\\n' | grep sonic-test | head -1"
            out, _, rc = run_ssh_cmd(client, cmd)
            
            if rc == 0 and out.strip():
                sonic_test_path = out.strip().split('\n')[0]
                sonic_test_dir = os.path.dirname(sonic_test_path)
                git_cmd = f"cd {sonic_test_dir} && git rev-parse HEAD"
                commit_out, _, rc_git = run_ssh_cmd(client, git_cmd)
                if rc_git == 0 and commit_out.strip():
                    commit = commit_out.strip()
                    log.debug(f"sonic_test commit: {commit}")
                    return commit
    except Exception as e:
        log.debug(f"Could not get sonic_test commit: {e}")
    
    return ""


# =============================================================================
# URL Utilities
# =============================================================================

def get_syslogs_url(base_url):
    """Check if sanity_logs.tar.gz exists at the URL and return full URL.
    
    Args:
        base_url: Base URL where syslogs should be located
    
    Returns:
        str | None: Full URL to sanity_logs.tar.gz or None if not found
    """
    if not base_url:
        return None
    
    if base_url.endswith('/'):
        full_url = base_url + "sanity_logs.tar.gz"
    else:
        full_url = base_url + "/sanity_logs.tar.gz"
    
    try:
        # verify=False for internal log server with self-signed cert
        response = requests.head(full_url, timeout=10, verify=False)
        if response.status_code == 200:
            log.debug(f"Found syslogs: {full_url}")
            return full_url
        log.info(f"Syslogs not found, skipping demyst notification")
        return None
    except Exception as e:
        log.debug(f"Could not check syslogs URL: {e}")
        return None


# =============================================================================
# Server Communication
# =============================================================================

def send_to_demyst(payload, server_url):
    """Send payload to demyst server and return (success, results_url).
    
    Args:
        payload: Dictionary containing request data
        server_url: Demyst server URL endpoint
    
    Returns:
        tuple: (success: bool, results_url: str | None)
            - (True, URL): Successfully sent, demyst URL returned
            - (True, None): Skipped by server (not supported) or no URL in response
            - (False, None): Error occurred
    """
    log.debug(f"Sending to {server_url}")
    log.debug(f"Payload: {json.dumps(payload, indent=2)}")
    
    headers = {"Content-Type": "application/json"}
    response = None
    
    # Try with system proxy first (verify=False for self-signed cert)
    try:
        response = requests.post(server_url, json=payload, headers=headers, timeout=30, verify=False)
        if response.status_code in [200, 202]:
            log.debug(f"Request sent: {response.status_code}")
    except Exception as e:
        log.debug(f"System proxy failed, trying without proxy: {e}")
        response = None
    
    # Fallback: no proxy
    if response is None or response.status_code not in [200, 202]:
        try:
            response = requests.post(
                server_url, json=payload, headers=headers, timeout=30,
                proxies={"http": None, "https": None}, verify=False
            )
        except Exception as e:
            log.error(f"Failed to send to demyst: {e}")
            return False, None
    
    if response.status_code in [200, 202]:
        try:
            resp_data = response.json()
            results_url = resp_data.get("results_url")
            request_id = resp_data.get("request_id")
            log.info(f"Queued: request_id={request_id}")
            return True, results_url
        except Exception as e:
            log.debug(f"Could not parse response: {e}")
            return True, None
    
    # Handle allowlist rejection (not_supported)
    elif response.status_code == 400:
        try:
            resp_data = response.json()
            if resp_data.get("status") == "not_supported":
                log.info(f"Skipped: {resp_data.get('error')}")
                return True, None
        except:
            pass
        log.error(f"Bad request: {response.text}")
        return False, None
    
    log.error(f"Server error {response.status_code}: {response.text}")
    return False, None
