import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

# Wait time for system to come back after reboot (in seconds)
REBOOT_WAIT_TIME = 300

s1_cli_dict_general = {
    "devices": [""],
    "lag": ["status", "usage", "members"],
    "multipath": ["groups", "usage", "group-members"],
    "acl": ["acl-table-rules", "acl-table-statistic", "acl-table-def", "attachment-circuit", 
        "acl-group", "eth-port-lookup-order", "eth-port-dense", "resource-usage-acl-type", 
        "eth-port-mix-mode", "object-group-pcl-entries"],
    "switch": ["properties","status", "usage", "ports", "mac-table", "multicast-routes", "copc", "attachment-circuits","mac-table-detailed"],
    "vrf": ["next-hops usage", "for-us", "ports details", "port-detailed", "hosts usage", "router-usage", "lpm-usage", "status", 
        "route-table", "nat", "multicast-routes", "router-macs usage", "properties"],
    "multicast": ["l3-mcg members", "l2-mcg members"],
    "cpu-ports": ["counters"],
    "device": ["management-ports status", "ecc-counters", "properties",
           "npu-error-counters", "health", "hash-fields-config", "notification-caching configuration"],
    "ports": ["status", "ber", "ingress-qos-profile", "output-queue-info", "serdes-parameters", 
          "port-config", "port-anlt-status", "serdes-status", "port-an37-status", "fec-data", "eth-port config"],
    "shared-buffer": ["usage"],
    "sflow": [""],
    "qos": ["pbts-mapping", "pbts-map-profile", "pbts-group", "qos-mapping"],
    "traps": ["status", "counters"],
    "mirror-commands": ["status", "l2", "erspan"],
    "attachment-circuits": ["status", "l2", "l2-acl", "l2-detailed", "svi", "svi-acl", "l3", "l3-acl"],
    "vxlan": ["l2-port", "switch", "router", "next-hop"],
    "telemetry": ["tm-traps-status", "tm-traps-counters"]
}
# Q200-specific commands
s1_cli_dict_q200 = {
    "device":["forward-drop-counters"]
}

def get_asic_str(duthost, asic):
    if duthost.is_multi_asic:
        return f" --asic-num {asic}"
    else:
        return ""

def check_syncd_status(duthost, asic=''):
    """
    Check if syncd is running
    """
    if duthost.is_multi_asic:
        result = duthost.shell(f'docker ps | grep syncd{asic}', module_ignore_errors=True)
    else:
        result = duthost.shell('docker ps | grep syncd', module_ignore_errors=True)
    
    return result["rc"] == 0 and "Up" in result["stdout"]

def reboot_and_wait_for_syncd(duthost, asic=''):
    """
    Reboot the DUT and wait for syncd to come back up
    """
    logging.warning("Syncd crashed - initiating reboot...")
    
    # Trigger reboot using module_async to avoid connection errors
    duthost.shell('sudo reboot', module_async=True)
    
    logging.warning(f"Waiting {REBOOT_WAIT_TIME} seconds for system to reboot and syncd to come back up...")
    time.sleep(REBOOT_WAIT_TIME)
    
    # Verify syncd is back up
    max_retries = 5
    retry_interval = 30
    for retry in range(max_retries):
        try:
            if check_syncd_status(duthost, asic):
                logging.info("Syncd is back up after reboot")
                return True
        except Exception as e:
            logging.warning(f"Error checking syncd status: {e}")
        
        logging.warning(f"Syncd not ready yet, retry {retry + 1}/{max_retries}")
        time.sleep(retry_interval)
    
    # Syncd failed to come back up - assert error
    error_msg = "CRITICAL: Syncd failed to come back up after reboot"
    logging.error(error_msg)
    pytest_assert(False, error_msg)
    
def test_s1_clis(duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index):
    """
    @summary: Verify output of s1-cli's and check for ERROR or Traceback in command output.
    If a CLI causes syncd crash, reboot system, wait 300s, retry to check if syncd comes back.
    If syncd doesn't come up after retries, throw error and end test. Otherwise continue with next CLI.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    error_result_list = []
    s1_cli_dict = s1_cli_dict_general.copy()
    
    # Check if platform is Q200 and append Q200-specific commands
    if duthost.facts["platform"] in ["x86_64-8101_32h_o-r0","x86_64-8102_64h_o-r0", "x86_64-8101_32fh_o-r0"]:
        s1_cli_dict.update(s1_cli_dict_q200)

    for cli in s1_cli_dict:
        if duthost.is_multi_asic:
            asic = enum_rand_one_asic_index
        else:
            asic = ''
        for opt in s1_cli_dict[cli]:
            if duthost.is_multi_asic:
                result = duthost.shell('/usr/bin/s1-cli {} -c "show {} {}"'.
                        format(get_asic_str(duthost, asic), cli, opt), module_ignore_errors=True)
                logging.info(result["stdout"])
            else: 
                result = duthost.shell("s1-cli -c 'show {} {}' {}".
                        format(cli, opt, get_asic_str(duthost, asic)), module_ignore_errors=True)
                logging.info(result["stdout"])

            # Check for syncd crash first (Error (UNAVAILABLE): Socket closed)
            if "Socket closed" in result["stdout"] + " " + result["stderr"]:
                error_msg = "SYNCD CRASH: s1-cli 'show {} {}' caused syncd to crash".format(cli, opt)
                logging.error(error_msg)
                error_result_list.append(error_msg)
                
                # Reboot and wait for syncd to come back (will assert if syncd doesn't come up)
                reboot_and_wait_for_syncd(duthost, asic)
                
                logging.info("Syncd recovered after reboot - continuing with next CLI")
                continue
            
            if result["stderr"]:
                error_result_list.append("Error found for s1-cli show {} {}".format(cli, opt))
            elif result is None or not result["stdout"]:
                error_result_list.append("No output for this s1 CLI show {} {}".format(cli, opt))
            elif "Traceback" in result["stdout"]:
                error_result_list.append("Traceback found for s1 CLI show {} {}".format(cli, opt))

    # Log all errors
    for result in error_result_list:
        logging.error(result)

    assert not error_result_list, "One or more s1-cli's have failed {}".format(error_result_list) 
