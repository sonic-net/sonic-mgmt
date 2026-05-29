from tabulate import tabulate

from tests.common.utilities import (wait, wait_until)  # noqa F401
from tests.common.helpers.assertions import pytest_assert  # noqa F401
from tests.common.snappi_tests.uhd.uhd_helpers import NetworkConfigSettings  # noqa: F403, F401
from tests.common.snappi_tests.ixload.snappi_helper import saveAs # noqa:  F403, F401

from typing import Optional, Dict, List
from dataclasses import dataclass
from queue import Queue
from enum import Enum
from collections import defaultdict
from netmiko import ConnectHandler

import multiprocessing  # noqa: F401
import threading
import requests
import re
import time
import json
import logging

logger = logging.getLogger(__name__)


def run_ha_test(duthosts, localhost, tbinfo, ha_test_case, config_npu_dpu, config_snappi_l47):

    passing_dpus = config_npu_dpu[0]
    # static_ipmacs_dict = config_npu_dpu[1]
    # duthost1 = duthosts[0]
    # duthost2 = duthosts[1]

    if config_snappi_l47['config_build']:
        api = config_snappi_l47['api']
        file_name = config_snappi_l47['test_type_dict']['test_filename']
        initial_cps_value = config_snappi_l47['initial_cps_value']

        nw_config = NetworkConfigSettings()
        nw_config.set_mac_addresses(tbinfo['l47_tg_clientmac'], tbinfo['l47_tg_servermac'], tbinfo['dut_mac'])

        # Configure SmartSwitch
        # dpu_if_ips = duthost_ha_config(duthost, nw_config, tbinfo, ha_test_case)
        linkloss_pattern = r'linkloss\d*'

        # Traffic Starts
        if ha_test_case == 'cps':
            api = run_cps_search(api, file_name, initial_cps_value, passing_dpus)
            logger.info("Test Ending")
        elif ha_test_case == 'planned_switchover':
            api = run_planned_switchover(duthosts, tbinfo, file_name, api, initial_cps_value)
        elif ha_test_case == 'dpuloss':
            api = run_dpuloss(duthosts, tbinfo, file_name, api, initial_cps_value)
        elif bool(re.search(linkloss_pattern, ha_test_case)):
            api = run_linkloss(duthosts, tbinfo, api, initial_cps_value, ha_test_case)
    else:
        logger.info("Skipping running an HA test")

    return


def is_smartswitch(duthost):

    pattern = r'"subtype"\s*:\s*"SmartSwitch"'
    result = duthost.shell('sonic-cfggen -d --var-json DEVICE_METADATA')
    match = re.search(pattern, result['stdout'])

    logger.info(f"Checking if SONiC device {duthost.hostname} is a SmartSwitch")
    if match:
        # Found subtype is a SmartSwitch
        logger.info(f"SONiC device {duthost.hostname} is a SmartSwitch")
        return True
    else:
        logger.info(f"SONiC device {duthost.hostname} is not a SmartSwitch")
        return False


def duthost_ha_config(duthost, tbinfo, static_ipmacs_dict, ha_test_case):

    static_ips = static_ipmacs_dict['static_ips']

    dpu_if_ips = {
        'dpu1': {'loopback_ip': '',
                 'if_ip': ''},
        'dpu2': {'loopback_ip': '',
                 'if_ip': ''}
    }

    if_ips_keys = [k for k in static_ips if k.startswith("221.1")]
    if_ips_keys = sorted(if_ips_keys, key=lambda ip: int(ip.split('.')[-1]))
    lb_ips = [k for k in static_ips if k.startswith("221.0.")]

    dpu_if_ips['dpu1']['loopback_ip'] = lb_ips[0]
    dpu_if_ips['dpu1']['if_ip'] = static_ips[if_ips_keys[0]]
    dpu_if_ips['dpu2']['loopback_ip'] = lb_ips[2]
    dpu_if_ips['dpu2']['if_ip'] = static_ips[if_ips_keys[2]]

    if ha_test_case != 'cps':
        dpu_active_ip = tbinfo['dpu_active_ip']
        dpu_active_mac = tbinfo['dpu_active_mac']
        dpu_active_if = tbinfo['dpu_active_if']
        dpu_standby_ip = tbinfo['dpu_standby_ip']
        dpu_standby_mac = tbinfo['dpu_standby_mac']
        dpu_standby_if = tbinfo['dpu_standby_if']

        logger.info('Configuring static routes for DPU1 and DPU2')
        try:
            duthost.shell('sudo ip route add {}/32 dev {}'.format(dpu_active_ip, dpu_active_if))
            duthost.shell('sudo ip route add {}/32 dev {}'.format(dpu_standby_ip, dpu_standby_if))
        except Exception as e:  # noqa: F841
            pass

        logger.info('Configuring static arps for DPU1 and DPU2')
        duthost.shell('sudo arp -s {} {}'.format(dpu_active_ip, dpu_active_mac))
        duthost.shell('sudo arp -s {} {}'.format(dpu_standby_ip, dpu_standby_mac))

    return dpu_if_ips


def ha_switchTraffic(tbinfo, switchover=True):

    # The JSON payload equivalent to the config file
    switchover_enable_config = {
        "enable": True
    }

    switchover_disable_config = {
        "enable": False
    }

    if switchover is True:
        switchover_config = switchover_enable_config
    else:
        switchover_config = switchover_disable_config

    api_path = "/connect/api/v1/control/operations/switchover"

    headers = {
        "Content-Type": "application/json"
    }

    try:
        target_ip = tbinfo['uhd_ip']

        # Construct the full URL
        url = f"https://{target_ip}{api_path}"  # noqa: E231

        logger.info("Executing switchover")
        logger.info(f"Payload: {json.dumps(switchover_config, indent=2)}")

        # Execute POST request (verify=False is equivalent to curl's -k flag)
        response = requests.post(
            url,
            json=switchover_config,
            headers=headers,
            verify=False,
            timeout=30
        )

        # Check response
        logger.info(f"Switchover response status: {response.status_code}")
        logger.info(f"Switchover response body: {response.text}")

        if response.status_code in [200, 201, 202]:
            logger.info("Switchover to successful")
            return True
        else:
            logger.error(f"Switchover failed with status code: {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error during switchover: {e}")
        return False
    except Exception as e:
        logger.error(f"Error during switchover: {e}")
        return False


def power_off_dpu(duthost, dpu_id):

    # For taking down links
    # sudo config interface shutdown Ethernet-BP0
    # sudo config interface startup Ethernet-BP0

    # For powering down DPU
    # sudo config chassis module shutdown <DPU id>
    # sudo config chassis module startup <DPU id>
    try:
        # duthost.shell(f"sudo config interface shutdown {dpu_id}")
        logger.info(f"Powering off DPU{dpu_id}")
        duthost.shell(f"sudo config chassis module shutdown DPU{dpu_id}")
    except Exception as e:
        logger.error(f"Error powering off dpu{dpu_id}: {e}")

    return


def power_on_dpu(duthost, dpu_id):

    # For taking down links
    # sudo config interface shutdown Ethernet-BP0
    # sudo config interface startup Ethernet-BP0

    # For powering down DPU
    # sudo config chassis module shutdown <DPU id>
    # sudo config chassis module startup <DPU id>

    try:
        # duthost.shell(f"sudo config interface shutdown {dpu_id}")
        logger.info(f"Powering on DPU{dpu_id}")
        duthost.shell(f"sudo config chassis module startup DPU{dpu_id}")
    except Exception as e:
        logger.error(f"Error powering on dpu{dpu_id}: {e}")

    return


def shutdown_link_npu_dpu(duthost, dpu_id, tbinfo):

    dpu_if = tbinfo['dpu_active_if']
    try:
        duthost.shell(f"sudo config interface shutdown {dpu_if}")
        logger.info(f"Shutting down link between NPU and DPU{dpu_id}")
    except Exception as e:
        logger.error(f"Error shutting down {dpu_if}: {e}")

    return


def startup_link_npu_dpu(duthost, dpu_id, tbinfo):

    dpu_if = tbinfo['dpu_active_if']
    try:
        duthost.shell(f"sudo config interface startup {dpu_if}")
        logger.info(f"Starting up link between NPU and DPU{dpu_id}")
    except Exception as e:
        logger.error(f"Error starting up link {dpu_if}: {e}")

    return


'''
def duthost_ha_config(duthost, nw_config, tbinfo, ha_test_case):

    # Smartswitch configure
    """
    logger.info('Cleaning up config')
    duthost.command("sudo cp {} {}".
                    format("/etc/sonic/config_db_backup.json",
                           "/etc/sonic/config_db.json"))
    duthost.shell("sudo config reload -y \n")
    logger.info("Wait until all critical services are fully started")
    pytest_assert(wait_until(360, 10, 1,
                             duthost.critical_services_fully_started),
                  "Not all critical services are fully started")
    """

    dpu_if_ips = {
        'dpu1': {'loopback_ip': '',
                 'if_ip': '',
                 'if_midplane_ip': ''},
        'dpu2': {'loopback_ip': '',
                 'if_ip': '',
                 'if_midplane_ip': ''}
    }

    config_db_stdout = duthost.shell("cat /etc/sonic/config_db.json")["stdout"]
    config_db = json.loads(config_db_stdout)

    static_ips = []
    if_ip = []
    if_midplane_ip = []
    lb_ip = []

    for key in config_db['STATIC_ROUTE'].keys():
        if key.endswith('/16'):
            ip = config_db['STATIC_ROUTE'][key]['nexthop']
            static_ips.append(ip)
        elif key.endswith('/32'):
            loopback_list = list(config_db['STATIC_ROUTE'].keys())
            ip = config_db['STATIC_ROUTE'][key]['nexthop']
            if_ip.append(ip)
            lb_ip.append(loopback_list)

    dhcp_config = config_db.get('DHCP_SERVER_IPV4_PORT', {})
    for key in dhcp_config:
        try:
            if key.startswith('bridge-midplane|dpu'):
                ip = dhcp_config[key]['ips'][0]
                if_midplane_ip.append(ip)
        except (KeyError, IndexError) as e:
            logger.warning(f"Could not get IP for DHCP server config {key}: {e}")

    # Collecting DPU data for switchover commands
    dpu_if_ips['dpu1']['loopback_ip'] = lb_ip[0][0].split('|')[1].split('/')[0]
    dpu_if_ips['dpu1']['if_ip'] = if_ip[0]
    dpu_if_ips['dpu1']['if_midplane_ip'] = if_midplane_ip[0]

    dpu_if_ips['dpu2']['loopback_ip'] = lb_ip[0][0].split('|')[1].split('/')[0]
    dpu_if_ips['dpu2']['if_ip'] = if_ip[2]
    dpu_if_ips['dpu2']['if_midplane_ip'] = if_midplane_ip[2]

    tmp_mac = ""
    static_macs = []
    for x, arp_mac in enumerate(range(len(static_ips))):
        if x == 0:
            tmp_mac = nw_config.first_staticArpMac
            static_macs.append(nw_config.first_staticArpMac)
        else:
            tmp = tmp_mac.split(':')
            tmp[5] = "0{}".format(int(tmp[5]) + 1)
            static_arp_mac = ":".join(tmp)
            static_macs.append(static_arp_mac)
            tmp_mac = static_arp_mac

    # Install Static Routes
    logger.info('Configuring static routes')
    for x, arp in enumerate(range(len(static_ips))):
        duthost.shell('sudo arp -s {} {}'.format(static_ips[x], static_macs[x]))

    if ha_test_case != 'cps':
        dpu_active_ip = tbinfo['dpu_active_ip']
        dpu_active_mac = tbinfo['dpu_active_mac']
        dpu_active_if = tbinfo['dpu_active_if']
        dpu_standby_ip = tbinfo['dpu_standby_ip']
        dpu_standby_mac = tbinfo['dpu_standby_mac']
        dpu_standby_if = tbinfo['dpu_standby_if']

        logger.info('Configuring static routes for DPU1 and DPU2')
        try:
            duthost.shell('sudo ip route add {}/32 dev {}'.format(dpu_active_ip, dpu_active_if))
            duthost.shell('sudo ip route add {}/32 dev {}'.format(dpu_standby_ip, dpu_standby_if))
        except Exception as e:  # noqa: F841
            pass

        logger.info('Configuring static arps for DPU1 and DPU2')
        duthost.shell('sudo arp -s {} {}'.format(dpu_active_ip, dpu_active_mac))
        duthost.shell('sudo arp -s {} {}'.format(dpu_standby_ip, dpu_standby_mac))

    return dpu_if_ips
'''


class HATestPhase(Enum):
    BEFORE_SWITCH = "before_switch"
    DURING_FIRST_SWITCH = "during_first_switch"
    AFTER_FIRST_SWITCH = "after_first_switch"
    DURING_SECOND_SWITCH = "during_second_switch"
    AFTER_SECOND_SWITCH = "after_second_switch"


class ContinuousMetricsCollector:
    def __init__(self, collection_interval=1):
        self.running = False
        self.current_phase = HATestPhase.BEFORE_SWITCH
        self.collection_interval = collection_interval
        self.metrics = defaultdict(list)
        self.thread = None
        self._lock = threading.Lock()

    def start_collection(self, api, client_req, server_req):
        def collect_metrics():
            while self.running:
                try:
                    # Configure client request
                    client_req.choice = "httpclient"
                    client_req.httpclient.stat_name = ["Connection Rate", "HTTP Concurrent Connections",
                                                       "TCP Resets Sent", "TCP Retries"]
                    # client_req.httpclient.end_test = True

                    # Configure server request
                    server_req.choice = "httpserver"
                    server_req.httpserver.stat_name = ["TCP Resets Sent", "TCP Retries"]
                    # server_req.httpclient.end_test = False

                    # Get metrics
                    client_metrics = api.get_metrics(client_req).httpclient_metrics
                    server_metrics = api.get_metrics(server_req).httpserver_metrics

                    with self._lock:
                        self.metrics[self.current_phase].append({
                            'timestamp': time.time(),
                            'client_metrics': client_metrics,
                            'server_metrics': server_metrics
                        })
                    logger.info(f"Collected metrics for phase {self.current_phase.value}")
                    time.sleep(self.collection_interval)
                except Exception as e:
                    logger.info(f"Error collecting metrics: {e}")
                    time.sleep(1)  # Add delay on error to prevent rapid retries

        self.running = True
        self.thread = threading.Thread(target=collect_metrics)
        self.thread.start()

    def set_phase(self, phase: HATestPhase):
        with self._lock:
            self.current_phase = phase

    def stop_collection(self):
        self.running = False
        if self.thread:
            self.thread.join()

    def get_metrics(self) -> Dict[HATestPhase, List]:
        with self._lock:
            return dict(self.metrics)


@dataclass
class MetricsResult:
    client_metrics: Optional[object] = None
    server_metrics: Optional[object] = None
    error: Optional[Exception] = None


def collect_metrics_threaded(api, client_req, server_req=None):
    result = ContinuousMetricsCollector()
    result_queue = Queue()

    def get_client_metrics():
        try:
            metrics = api.get_metrics(client_req).httpclient_metrics
            result_queue.put(('client', metrics, None))
        except Exception as e:
            result_queue.put(('client', None, e))

    def get_server_metrics():
        try:
            metrics = api.get_metrics(server_req).httpserver_metrics
            result_queue.put(('server', metrics, None))
        except Exception as e:
            result_queue.put(('server', None, e))

    threads = []
    # Start client metrics thread
    client_thread = threading.Thread(target=get_client_metrics)
    client_thread.start()
    threads.append(client_thread)

    # Start server metrics thread if server_req is provided
    if server_req:
        server_thread = threading.Thread(target=get_server_metrics)
        server_thread.start()
        threads.append(server_thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Collect results
    while not result_queue.empty():
        metric_type, metrics, error = result_queue.get()
        if error:
            result.error = error
        elif metric_type == 'client':
            result.client_metrics = metrics
        elif metric_type == 'server':
            result.server_metrics = metrics

    if result.error:
        raise result.error

    return result


def analyze_cps_performance(timestamps, values):

    cps_values = [int(x) for x in values if x.isdigit()]

    # Find peak performance
    peak_cps = max(cps_values)
    peak_index = values.index(str(peak_cps))
    peak_time = int(timestamps[peak_index])

    # Calculate stable performance
    non_zero_values = [int(x) for x in values if x.isdigit() and int(x) > 0]
    stable_values = non_zero_values[len(non_zero_values) // 5:4 * len(non_zero_values) // 5]
    stable_performance = sum(stable_values) / len(stable_values)

    # Detect failure phase (looking for significant drops in the middle)
    failure_detected = False
    failure_start_time = None
    failure_cps = None

    # Using 50% drop from stable performance as failure threshold
    failure_threshold = stable_performance * 0.5

    # Check for failures
    check_until = int(len(values) * 0.9)
    for i in range(1, check_until):
        if values[i].isdigit():
            current_cps = int(values[i])
            if current_cps < failure_threshold and current_cps > 0:
                # Check if prev value was normal
                if i > 0 and values[i - 1].isdigit() and int(values[i - 1]) > failure_threshold:
                    failure_detected = True
                    failure_start_time = int(timestamps[i])
                    failure_cps = current_cps
                    break

    results = {
        "peak_performance": {
            "cps": peak_cps,
            "time_ms": peak_time
        },
        "stable_performance": {
            "avg_cps": round(stable_performance, 2)
        }
    }

    if failure_detected:
        results["failure_phase"] = {
            "detected": True,
            "time_ms": failure_start_time,
            "cps_at_failure": failure_cps
        }
    else:
        results["failure_phase"] = {
            "detected": False
        }

    return results


def analyze_tcp_retries_resets(stats_client_result, stats_server_result):

    def parse_values(values_list):
        return [int(v) if isinstance(v, str) and v.isdigit() else 0 for v in values_list or []]

    def parse_times(times_list):
        out = []
        for t in times_list or []:
            try:
                out.append(int(t))
            except Exception:
                out.append(0)
        return out

    def window_indices(n):
        if n <= 1:
            return 0, 1
        start = max(0, int(n * 0.4))
        end = max(start + 1, int(n * 0.6))
        end = min(end, n)
        return start, end

    # Client metrics
    c_ret = stats_client_result.get('TCP Retries', {'timestamp_ids': [], 'values': []})
    c_rst = stats_client_result.get('TCP Resets Sent', {'timestamp_ids': [], 'values': []})
    c_ret_vals = parse_values(c_ret.get('values'))
    c_rst_vals = parse_values(c_rst.get('values'))

    # Server metrics
    s_ret = stats_server_result.get('TCP Retries', {'timestamp_ids': [], 'values': []})
    s_rst = stats_server_result.get('TCP Resets Sent', {'timestamp_ids': [], 'values': []})
    s_ret_vals = parse_values(s_ret.get('values'))
    s_rst_vals = parse_values(s_rst.get('values'))

    # Client calculations
    n_c = max(len(c_ret_vals), len(c_rst_vals))
    cs, ce = window_indices(n_c)
    c_ret_slice = c_ret_vals[cs:ce] if len(c_ret_vals) >= ce else c_ret_vals
    c_rst_slice = c_rst_vals[cs:ce] if len(c_rst_vals) >= ce else c_rst_vals
    c_max_ret = max(c_ret_slice) if c_ret_slice else 0
    c_max_rst = max(c_rst_slice) if c_rst_slice else 0

    # Server calculations
    n_s = max(len(s_ret_vals), len(s_rst_vals))
    ss, se = window_indices(n_s)
    s_ret_slice = s_ret_vals[ss:se] if len(s_ret_vals) >= se else s_ret_vals
    s_rst_slice = s_rst_vals[ss:se] if len(s_rst_vals) >= se else s_rst_vals
    s_max_ret = max(s_ret_slice) if s_ret_slice else 0
    s_max_rst = max(s_rst_slice) if s_rst_slice else 0

    retries_resets = {
        "client": {
            "max_around_mid": {
                "tcp_retries": c_max_ret,
                "tcp_resets_sent": c_max_rst
            },
        },
        "server": {
            "max_around_mid": {
                "tcp_retries": s_max_ret,
                "tcp_resets_sent": s_max_rst
            },
        }
    }

    return retries_resets


def create_and_apply_acl_rules(duthost, dpu_ip, npu_ip, l4_src_port1, l4_src_port2, dpu_midplane_if="169.254.200.1"):
    """
    Creates ACL rules JSON file and apply it to the DPU.
    """
    acl_rules = {
        "ACL_RULE": {
            "ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP1": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "SRC_IP": npu_ip,
                "DST_IP": dpu_ip,
                "IP_TYPE": "IP",
                "L4_SRC_PORT": l4_src_port1
            },
            "ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP2": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "SRC_IP": dpu_ip,
                "DST_IP": npu_ip,
                "IP_TYPE": "IP",
                "L4_SRC_PORT": l4_src_port2
            }
        }
    }

    acl_json = json.dumps(acl_rules, indent=4)
    duthost.shell("echo '{}' > /tmp/acl_drop_rule.json".format(acl_json))

    # Connect to jump host
    target_username = 'admin'  # noqa: F841
    target_password = 'password'
    username = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_user']
    password = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_password']
    jump_host = {
        'device_type': 'linux',
        'ip': f'{duthost.mgmt_ip}',
        'username': f'{username}',
        'password': f'{password}',
    }
    net_connect_jump = ConnectHandler(**jump_host)
    scp_command = (f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /tmp/acl_drop_rule.json "
                   f"admin@{dpu_midplane_if}:/home/admin/")  # noqa: E231
    try:
        net_connect_jump.write_channel(f"{scp_command}\n")
        time.sleep(2)  # Wait for password prompt

        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} SCP output: {output}")

        if 'password' in output.lower():
            net_connect_jump.write_channel(f"{target_password}\n")
            time.sleep(3)  # Wait for SCP to complete

        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} SCP transfer output: {output}")
    except Exception as e:
        logger.error(f"Error during SCP transfer: {e}")

    net_connect_jump = ConnectHandler(**jump_host)
    # SSH from jump host to target device using proper netmiko method
    # First, create the SSH command
    ssh_command = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@{dpu_ip}"
    try:
        net_connect_jump.write_channel(f"{ssh_command}\n")
        time.sleep(2)  # Wait for password prompt

        # Check if we got a password prompt
        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} SSH output: {output}")

        if 'password' in output.lower():
            net_connect_jump.write_channel(f"{target_password}\n")
            time.sleep(3)  # Wait for login to complete

        # Clear the buffer and set the base prompt
        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} Login output: {output}")

        # Now use send_command_timing instead of send_command for better compatibility
        logger.info(f"{duthost.hostname} Execute on DPU Target - Connected")
        output = net_connect_jump.write_channel('sudo config load -y /home/admin/acl_drop_rule.json\n')
        time.sleep(5)  # Wait for command to complete
        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} Execute on DPU Target {output}")
    except Exception as e:
        logger.error(f"Error applying ACL rules: {e}")

    duthost.shell("rm -f /tmp/acl_drop_rule.json")

    return


def remove_acl_rules(duthost, dpu_midplane_if="169.254.200.1"):

    target_password = 'password'
    username = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_user']
    password = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_password']
    jump_host = {
        'device_type': 'linux',
        'ip': f'{duthost.mgmt_ip}',
        'username': f'{username}',
        'password': f'{password}',
    }

    net_connect_jump = ConnectHandler(**jump_host)
    ssh_command = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@{dpu_midplane_if}"
    try:
        net_connect_jump.write_channel(f"{ssh_command}\n")
        time.sleep(2)  # Wait for password prompt

        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} SSH output: {output}")

        if 'password' in output.lower():
            net_connect_jump.write_channel(f"{target_password}\n")
            time.sleep(3)  # Wait for login to complete

        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} Login output: {output}")

        logger.info(f"{duthost.hostname} Execute on DPU Target - Connected, removing ACL rules")

        # Delete ACL_RULE entries
        net_connect_jump.write_channel(
            'redis-cli -n 4 DEL "ACL_RULE|ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP1"\n'
        )
        time.sleep(2)
        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} DEL LOCAL_PROBE_DROP1 output: {output}")

        net_connect_jump.write_channel(
            'redis-cli -n 4 DEL "ACL_RULE|ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP2"\n'
        )
        time.sleep(2)
        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} DEL LOCAL_PROBE_DROP2 output: {output}")

        # Delete ACL_TABLE entry
        net_connect_jump.write_channel(
            'redis-cli -n 4 DEL "ACL_TABLE|ACL_LINK_DROP_TEST"\n'
        )
        time.sleep(2)
        output = net_connect_jump.read_channel()
        logger.info(f"{duthost.hostname} DEL ACL_TABLE output: {output}")

    except Exception as e:
        logger.error(f"Error removing ACL rules: {e}")
    finally:
        net_connect_jump.disconnect()

    return


def get_ip_routes(duthost, interface):
    duthost_stdout = duthost.shell(f'show ip route {interface}')

    return "".join(duthost_stdout['stdout_lines'])


def extract_bgp_interfaces(route_text):
    # Find protocol in: Known via "BGP"
    proto_match = re.search(r'Known via\s+"?([A-Za-z0-9._/-]+)"?', route_text, re.IGNORECASE)
    protocol = proto_match.group(1).lower() if proto_match else ''

    interfaces: List[str] = []
    if protocol == 'bgp':
        # Capture interface tokens after 'via', e.g., 'via Ethernet-BP0'
        found = re.findall(r'\bvia\s+([A-Za-z0-9./:-]+)', route_text)
        seen = set()
        for iface in found:
            if iface not in seen:
                seen.add(iface)
                interfaces.append(iface)

    return protocol, interfaces


def disable_ecmp_interfaces_one(duthost, ifaces):

    # Disable all but one interface
    for iface in ifaces[:-1]:
        duthost.shell(f"sudo config interface shutdown {iface}")

    return


def disable_last_ecmp_interface(duthost, ifaces):

    # Disable last interface
    for iface in ifaces[-1:]:
        duthost.shell(f"sudo config interface shutdown {iface}")

    return


def get_linkloss_range(ha_test_case):
    m = re.search(r'(\d+)$', ha_test_case)
    if not m:
        return None
    n = int(m.group(1))
    if 4 <= n <= 7:
        return "4-7"
    elif 8 <= n <= 11:
        return "8-11"
    return None


def run_cps_search(api, file_name, initial_cps_value, passing_dpus):

    error_threshold = 0.01  # noqa: F841
    MAX_CPS = 30000000
    MIN_CPS = 0
    threshold = 1000000
    test_iteration = 1
    test_value = initial_cps_value
    activityList_url = "ixload/test/activeTest/communityList/0"
    constraint_url = "ixload/test/activeTest/communityList/0/activityList/0"
    releaseConfig_url = "ixload/test/operations/abortAndReleaseConfigWaitFinish"
    testRuns = []

    while ((MAX_CPS - MIN_CPS) > threshold):

        collector = ContinuousMetricsCollector(collection_interval=1)
        clientStat_req = api.metrics_request()
        serverStat_req = api.metrics_request()

        test_result = ""
        logger.info(
            "----Test Iteration %d------------------------------------------------------------------"
            % test_iteration)
        old_value = test_value
        logger.info("Testing CPS Objective = %d" % test_value)
        cps_objective_value = test_value

        activityList_json = {  # noqa: F841
            'totalUserObjectiveValue': test_value,
            'userObjectiveType': 'connectionRate',
        }

        constriant_json = {  # noqa: F841
            'enableConstraint': False
        }

        logger.info("Updating CPS objective value settings...")
        try:
            # Code that may raise an exception
            res = api.ixload_configure("patch", activityList_url, activityList_json)
            res = api.ixload_configure("patch", constraint_url, constriant_json)  # noqa: F841
        except Exception as e:
            # Handle any exception
            logger.info(f"An error occurred: {e}")
        logger.info("CPS objective value updated.")

        logger.info("Applying config...")
        saveAs(api, file_name)
        logger.info("Starting Traffic")
        cs = api.control_state()
        cs.app.state = 'start'  # cs.app.state.START
        response1 = api.set_control_state(cs)
        logger.info(response1)
        collector.start_collection(api, clientStat_req, serverStat_req)
        time.sleep(150)

        collector.set_phase(HATestPhase.AFTER_SECOND_SWITCH)
        time.sleep(60)
        collector.stop_collection()

        all_metrics = collector.get_metrics()
        logger.info(f"Collected metrics for {len(all_metrics)} phases")

        pattern = r"- name:\s*([^\n]*)\n(.*?)(?=- name|\Z)"

        stats_client_tmp = re.findall(pattern, str(all_metrics[HATestPhase.AFTER_SECOND_SWITCH][0]['client_metrics']),
                                      re.DOTALL)
        stats_server_tmp = re.findall(pattern, str(all_metrics[HATestPhase.AFTER_SECOND_SWITCH][0]['server_metrics']),
                                      re.DOTALL)

        stats_client_result = {}
        for match in stats_client_tmp:
            name = match[0].strip()
            timestamp_id = re.findall(r"- timestamp_id:\s*'([^']*)'", match[1])
            values = re.findall(r"value:\s*'([^']*)'", match[1])

            if name not in stats_client_result:
                stats_client_result[name] = {}

            stats_client_result[name]['timestamp_ids'] = timestamp_id
            stats_client_result[name]['values'] = values

        stats_server_result = {}
        for match in stats_server_tmp:
            name = match[0].strip()
            timestamp_id = re.findall(r"- timestamp_id:\s*'([^']*)'", match[1])
            values = re.findall(r"value:\s*'([^']*)'", match[1])

            if name not in stats_server_result:
                stats_server_result[name] = {}

            stats_server_result[name]['timestamp_ids'] = timestamp_id
            stats_server_result[name]['values'] = values

        cps_result = analyze_cps_performance(stats_client_result['Connection Rate']['timestamp_ids'],
                                             stats_client_result['Connection Rate']['values'])
        retries_resets = analyze_tcp_retries_resets(stats_client_result, stats_server_result)

        cps_max = cps_result['peak_performance']['cps']
        c_ret = retries_resets['client']['max_around_mid']['tcp_retries']
        c_rst = retries_resets['client']['max_around_mid']['tcp_resets_sent']
        s_ret = retries_resets['server']['max_around_mid']['tcp_retries']
        s_rst = retries_resets['server']['max_around_mid']['tcp_resets_sent']

        ret_rst_pairs = [("Client Retries", c_ret), ("Client Resets", c_rst), ("Server Retries", s_ret),
                         ("Server Resets", s_rst)]
        err_maxname, err_maxvalue = max(ret_rst_pairs, key=lambda p: p[1])
        error_percent = err_maxvalue/cps_objective_value  # noqa: F841

        if cps_max < test_value:
            test = False
        else:
            test = True

        if test:
            logger.info('Test Iteration Pass')
            test_result = "Pass"
            MIN_CPS = test_value
            test_value = (MAX_CPS + MIN_CPS) / 2
        else:
            logger.info('Test Iteration Fail')
            test_result = "Fail"
            MAX_CPS = test_value
            test_value = (MAX_CPS + MIN_CPS) / 2

        if len(passing_dpus) == 0:
            passing_dpus = 0

        columns = ['#Run', 'CPS Objective', 'Max CPS', f'{err_maxname}', 'Number of DPUs (Indexes)', 'Test Result']
        testRuns.append([test_iteration, cps_objective_value, cps_max, err_maxvalue, passing_dpus, test_result])
        table = tabulate(testRuns, headers=columns, tablefmt='psql')
        logger.info(table)

        logger.info("Iteration Ended...")
        logger.info('MIN_CPS = %d' % MIN_CPS)
        logger.info('Current MAX_CPS = %d' % MAX_CPS)
        logger.info('Previous CPS Objective value = %d' % old_value)
        logger.info(' ')
        test_iteration += 1
        logger.info("Releasing config...")
        try:
            # Code that may raise an exception
            param = {}
            res = api.ixload_configure("post", releaseConfig_url, param)  # noqa: F841
        except Exception as e:
            # Handle any exception
            logger.info(f"An error occurred: {e}")
        logger.info("Releasing config completed..")

        logger.info("Changing app state to stop")
        cs.app.state = 'stop'  # cs.app.state.START
        api.set_control_state(cs)

    return api


def run_planned_switchover(duthosts, tbinfo, file_name, api, initial_cps_value):

    # Setup metric collection
    collector = ContinuousMetricsCollector(collection_interval=1)
    clientStat_req = api.metrics_request()
    serverStat_req = api.metrics_request()

    activityList_url = "ixload/test/activeTest/communityList/0"
    constraint_url = "ixload/test/activeTest/communityList/0/activityList/0"

    try:
        # Configure and start traffic
        logger.info("Configuring traffic parameters...")
        activityList_json = {  # noqa: F841
            'totalUserObjectiveValue': initial_cps_value,
            'userObjectiveType': 'connectionRate',
        }

        constriant_json = {  # noqa: F841
            'enableConstraint': False
        }

        '''
        activityList_json = {
            'constraintType': 'ConnectionRateConstraint',
            'constraintValue': initial_cps_value,
            'enableConstraint': True,
            'userObjectiveType': 'simulatedUsers',
            'userObjectiveValue': 64500
        }
        '''
        api.ixload_configure("patch", activityList_url, activityList_json)
        api.ixload_configure("patch", constraint_url, constriant_json)
        saveAs(api, file_name)

        # Start traffic
        logger.info("Starting traffic...")
        cs = api.control_state()
        cs.app.state = 'start'
        api.set_control_state(cs)

        # Give traffic time to start
        logger.info("Waiting for traffic to initialize...")
        time.sleep(10)

        # Start metrics collection
        logger.info("Starting metrics collection...")
        collector.start_collection(api, clientStat_req, serverStat_req)

        # Initial collection period
        logger.info("Collecting initial metrics...")
        time.sleep(30)

        # First switchover
        logger.info("Executing first switchover...")
        collector.set_phase(HATestPhase.DURING_FIRST_SWITCH)
        ha_switchTraffic(tbinfo, True)
        # ha_switchTraffic(duthost, dpu_if_ips, 'dpu2')
        collector.set_phase(HATestPhase.AFTER_FIRST_SWITCH)

        # Stabilization period
        logger.info("Waiting for stabilization...")
        time.sleep(60)

        # Second switchover
        logger.info("Executing second switchover...")
        collector.set_phase(HATestPhase.DURING_SECOND_SWITCH)
        ha_switchTraffic(tbinfo, False)
        # ha_switchTraffic(duthost, dpu_if_ips, 'dpu1')
        collector.set_phase(HATestPhase.AFTER_SECOND_SWITCH)

        # Final collection period
        logger.info("Collecting final metrics...")
        time.sleep(30)

    finally:
        # Stop collection and cleanup
        logger.info("Stopping metrics collection...")
        collector.stop_collection()

        logger.info("Stopping traffic...")
        cs.app.state = 'stop'
        api.set_control_state(cs)

    # Get and process metrics
    all_metrics = collector.get_metrics()
    logger.info(f"Collected metrics for {len(all_metrics)} phases")

    pattern = r"- name:\s*([^\n]*)\n(.*?)(?=- name|\Z)"
    stats_client_tmp = re.findall(pattern, str(all_metrics[HATestPhase.AFTER_SECOND_SWITCH][0]['client_metrics']),
                                  re.DOTALL)
    stats_server_tmp = re.findall(pattern, str(all_metrics[HATestPhase.AFTER_SECOND_SWITCH][0]['server_metrics']),
                                  re.DOTALL)

    stats_client_result = {}
    for match in stats_client_tmp:
        name = match[0].strip()
        timestamp_id = re.findall(r"- timestamp_id:\s*'([^']*)'", match[1])
        values = re.findall(r"value:\s*'([^']*)'", match[1])

        if name not in stats_client_result:
            stats_client_result[name] = {}

        stats_client_result[name]['timestamp_ids'] = timestamp_id
        stats_client_result[name]['values'] = values

    stats_server_result = {}
    for match in stats_server_tmp:
        name = match[0].strip()
        timestamp_id = re.findall(r"- timestamp_id:\s*'([^']*)'", match[1])
        values = re.findall(r"value:\s*'([^']*)'", match[1])

        if name not in stats_server_result:
            stats_server_result[name] = {}

        stats_server_result[name]['timestamp_ids'] = timestamp_id
        stats_server_result[name]['values'] = values

    cps_results = analyze_cps_performance(stats_client_result['Connection Rate']['timestamp_ids'],
                                          stats_client_result['Connection Rate']['values'])

    logger.info("\nPerformance Analysis:")
    peak_performance = (f"{cps_results['peak_performance']['cps']} CPS @ "
                        f"{cps_results['peak_performance']['time_ms']}ms").ljust(30)

    # stable_performance = f"Stable Performance: {cps_results['stable_performance']['avg_cps']} CPS"
    stable_performance = f"{cps_results['stable_performance']['avg_cps']} CPS".ljust(30)

    if cps_results['failure_phase']['detected']:
        failure_detected = (
            f"{cps_results['failure_phase']['cps_at_failure']} CPS @ "
            f"{cps_results['failure_phase']['time_ms']}ms").ljust(30)

    else:
        failure_detected = "No mid-test failure detected"

    columns = ['Peak Performance', 'Stable Performance', 'Failure Detected']
    testRun = [[peak_performance, stable_performance, failure_detected]]
    table = tabulate(testRun, headers=columns, tablefmt='grid')
    logger.info(table)

    return


def run_dpuloss(duthosts, tbinfo, file_name, api, initial_cps_value):

    # DPU IDs, active is 0, standby is 1
    dpu_active_id = 0
    # dpu_standby_id = 1

    duthost0 = duthosts[0]
    # duthost1 = duthosts[1]

    collector = ContinuousMetricsCollector(collection_interval=1)
    clientStat_req = api.metrics_request()
    serverStat_req = api.metrics_request()

    try:
        # Configure and start traffic
        logger.info("Configuring traffic parameters...")
        activityList_json = {
            'constraintType': 'ConnectionRateConstraint',
            'constraintValue': initial_cps_value,
            'enableConstraint': False,
        }
        api.ixload_configure("patch", "ixload/test/activeTest/communityList/0/activityList/0", activityList_json)
        saveAs(api, file_name)

        # Start traffic
        logger.info("Starting traffic...")
        cs = api.control_state()
        cs.app.state = 'start'
        api.set_control_state(cs)

        # Give traffic time to start
        logger.info("Waiting for traffic to initialize...")
        time.sleep(10)

        # Start metrics collection
        logger.info("Starting metrics collection...")
        collector.start_collection(api, clientStat_req, serverStat_req)

        # Initial collection period
        logger.info("Collecting initial metrics...")
        time.sleep(30)

        # First switchover
        logger.info("Executing first switchover...")
        collector.set_phase(HATestPhase.DURING_FIRST_SWITCH)
        power_off_dpu(duthost0, dpu_active_id)
        time.sleep(1)
        # ha_switchTraffic(duthost, dpu_if_ips, 'dpu2')
        ha_switchTraffic(tbinfo, True)
        collector.set_phase(HATestPhase.AFTER_FIRST_SWITCH)

        # Stabilization period
        logger.info("Waiting for stabilization...")
        time.sleep(60)

        # Final collection period
        logger.info("Collecting final metrics...")
        time.sleep(30)

    finally:
        # Stop collection and cleanup
        logger.info("Stopping metrics collection...")
        collector.stop_collection()

        # ha_switchTraffic(duthost, dpu_if_ips, 'dpu1')
        ha_switchTraffic(tbinfo, False)
        power_on_dpu(duthost0, dpu_active_id)
        logger.info("Stopping traffic...")
        cs.app.state = 'stop'
        api.set_control_state(cs)

    # Get and process metrics
    all_metrics = collector.get_metrics()
    logger.info(f"Collected metrics for {len(all_metrics)} phases")

    pattern = r"- name:\s*([^\n]*)\n(.*?)(?=- name|\Z)"
    stats_client_tmp = re.findall(pattern, str(all_metrics[HATestPhase.AFTER_FIRST_SWITCH][0]['client_metrics']),
                                  re.DOTALL)
    stats_server_tmp = re.findall(pattern, str(all_metrics[HATestPhase.AFTER_FIRST_SWITCH][0]['server_metrics']),
                                  re.DOTALL)

    stats_client_result = {}
    for match in stats_client_tmp:
        name = match[0].strip()
        timestamp_id = re.findall(r"- timestamp_id:\s*'([^']*)'", match[1])
        values = re.findall(r"value:\s*'([^']*)'", match[1])

        if name not in stats_client_result:
            stats_client_result[name] = {}

        stats_client_result[name]['timestamp_ids'] = timestamp_id
        stats_client_result[name]['values'] = values

    stats_server_result = {}
    for match in stats_server_tmp:
        name = match[0].strip()
        timestamp_id = re.findall(r"- timestamp_id:\s*'([^']*)'", match[1])
        values = re.findall(r"value:\s*'([^']*)'", match[1])

        if name not in stats_server_result:
            stats_server_result[name] = {}

        stats_server_result[name]['timestamp_ids'] = timestamp_id
        stats_server_result[name]['values'] = values

    cps_results = analyze_cps_performance(stats_client_result['Connection Rate']['timestamp_ids'],
                                          stats_client_result['Connection Rate']['values'])

    logger.info("\nPerformance Analysis:")
    peak_performance = (f"{cps_results['peak_performance']['cps']} CPS @ "
                        f"{cps_results['peak_performance']['time_ms']}ms").ljust(30)

    # stable_performance = f"Stable Performance: {cps_results['stable_performance']['avg_cps']} CPS"
    stable_performance = f"{cps_results['stable_performance']['avg_cps']} CPS".ljust(30)

    if cps_results['failure_phase']['detected']:
        failure_detected = (
            f"{cps_results['failure_phase']['cps_at_failure']} CPS @ "
            f"{cps_results['failure_phase']['time_ms']}ms").ljust(30)

    else:
        failure_detected = "No mid-test failure detected"

    columns = ['Peak Performance', 'Stable Performance', 'Failure Detected']
    testRun = [[peak_performance, stable_performance, failure_detected]]
    table = tabulate(testRun, headers=columns, tablefmt='grid')
    logger.info(table)

    return


def run_linkloss(duthosts, tbinfo, api, initial_cps_value, ha_test_case):

    switchedTraffic_enabled = False

    if ha_test_case == "linkloss4":
        # Traffic starts on active side
        duthost = duthosts[0]

        # NPU1 to DPU 1 link to drop
        link_to_drop = tbinfo['dpu_active_if']
    elif ha_test_case == "linkloss5":
        # Start by sending traffic to standby side
        duthost = duthosts[1]
        ha_switchTraffic(tbinfo, True)
        switchedTraffic_enabled = True

        # NPU1 to DPU 1 link to drop
        link_to_drop = tbinfo['dpu_active_if']
    elif ha_test_case == "linkloss6":
        # Start by sending traffic to active side
        duthost = duthosts[0]

        # NPU2 to DPU2 link to drop
        link_to_drop = tbinfo['dpu_standby_if']
    elif ha_test_case == "linkloss7":
        # Start by sending traffic to standby side
        duthost = duthosts[1]
        ha_switchTraffic(tbinfo, True)
        switchedTraffic_enabled = True

        # NPU2 to DPU2 link to drop
        link_to_drop = tbinfo['dpu_standby_if']
    elif ha_test_case == "linkloss8":
        # Traffic starts on active side
        duthost = duthosts[0]

        # NPU1 to DPU 1 link to drop
        link_to_drop = tbinfo['dpu_active_if']
    elif ha_test_case == "linkloss9":
        # Start by sending traffic to standby side
        duthost = duthosts[1]
        ha_switchTraffic(tbinfo, True)
        switchedTraffic_enabled = True

        # NPU1 to DPU 1 link to drop
        link_to_drop = tbinfo['dpu_active_if']
    elif ha_test_case == "linkloss10":
        # Traffic starts on active side
        duthost = duthosts[0]

        # NPU1 to DPU 1 link to drop
        link_to_drop = tbinfo['dpu_active_if']
    elif ha_test_case == "linkloss11":
        # Start by sending traffic to standby side
        duthost = duthosts[1]
        ha_switchTraffic(tbinfo, True)
        switchedTraffic_enabled = True  # noqa: F841

        # NPU1 to DPU 1 link to drop
        link_to_drop = tbinfo['dpu_active_if']
    else:
        return None

    collector = ContinuousMetricsCollector(collection_interval=1)
    clientStat_req = api.metrics_request()
    serverStat_req = api.metrics_request()

    try:
        # Configure and start traffic
        logger.info("Configuring traffic parameters...")
        activityList_json = {
            'constraintType': 'ConnectionRateConstraint',
            'constraintValue': initial_cps_value,
            'enableConstraint': False,
        }

        api.ixload_configure("patch", "ixload/test/activeTest/communityList/0/activityList/0", activityList_json)

        # Start traffic
        logger.info("Starting traffic...")
        cs = api.control_state()
        cs.app.state = 'start'
        api.set_control_state(cs)

        # Give traffic time to start
        logger.info("Waiting for traffic to initialize...")
        time.sleep(10)

        # Start metrics collection
        logger.info("Starting metrics collection...")
        collector.start_collection(api, clientStat_req, serverStat_req)

        # Initial collection period
        logger.info("Collecting initial metrics...")
        time.sleep(30)
        logger.info("Executing acl rules drop...")
        collector.set_phase(HATestPhase.DURING_FIRST_SWITCH)

        # Select between linkloss testcases
        r = get_linkloss_range(ha_test_case)
        if r == "4-7":
            shutdown_link_npu_dpu(duthost, link_to_drop, tbinfo)
            result = create_and_apply_acl_rules(  # noqa: 841
                duthost=duthost,
                dpu_ip="169.254.200.1",
                npu_ip=duthost.mgmt_ip,
                l4_src_port1="3784",
                l4_src_port2="3784",
                dpu_midplane_if="169.254.200.1"  # Optional, defaults to 169.254.200.1
            )
        elif r == "8-11":
            route_text = get_ip_routes(duthost)
            protocol, interfaces = extract_bgp_interfaces(route_text)
            disable_last_ecmp_interface(duthost, interfaces)
        time.sleep(1)
        # ha_switchTraffic(duthost, dpu_if_ips, 'dpu2')
        collector.set_phase(HATestPhase.AFTER_FIRST_SWITCH)

        # Stabilization period
        logger.info("Waiting for stabilization...")
        time.sleep(60)

        # Final collection period
        logger.info("Collecting final metrics...")
        time.sleep(30)

    finally:
        # Stop collection and cleanup
        logger.info("Stopping metrics collection...")
        collector.stop_collection()

        # ha_switchTraffic(duthost, dpu_if_ips, 'dpu1')
        if r == "4-7":
            startup_link_npu_dpu(duthost, link_to_drop, tbinfo)
        logger.info("Stopping traffic...")
        cs.app.state = 'stop'
        # remove ACL rules and switch back traffic to original side
        api.set_control_state(cs)
        remove_acl_rules(duthost)
        if switchedTraffic_enabled:
            ha_switchTraffic(tbinfo, False)
        else:
            ha_switchTraffic(tbinfo, True)

    # Get and process metrics
    all_metrics = collector.get_metrics()
    logger.info(f"Collected metrics for {len(all_metrics)} phases")

    pattern = r"- name:\s*([^\n]*)\n(.*?)(?=- name|\Z)"
    stats_client_tmp = re.findall(pattern, str(all_metrics[HATestPhase.AFTER_FIRST_SWITCH][0]['client_metrics']),
                                  re.DOTALL)
    stats_server_tmp = re.findall(pattern, str(all_metrics[HATestPhase.AFTER_FIRST_SWITCH][0]['server_metrics']),
                                  re.DOTALL)

    stats_client_result = {}
    for match in stats_client_tmp:
        name = match[0].strip()
        timestamp_id = re.findall(r"- timestamp_id:\s*'([^']*)'", match[1])
        values = re.findall(r"value:\s*'([^']*)'", match[1])

        if name not in stats_client_result:
            stats_client_result[name] = {}

        stats_client_result[name]['timestamp_ids'] = timestamp_id
        stats_client_result[name]['values'] = values

    stats_server_result = {}
    for match in stats_server_tmp:
        name = match[0].strip()
        timestamp_id = re.findall(r"- timestamp_id:\s*'([^']*)'", match[1])
        values = re.findall(r"value:\s*'([^']*)'", match[1])

        if name not in stats_server_result:
            stats_server_result[name] = {}

        stats_server_result[name]['timestamp_ids'] = timestamp_id
        stats_server_result[name]['values'] = values

    cps_results = analyze_cps_performance(stats_client_result['Connection Rate']['timestamp_ids'],
                                          stats_client_result['Connection Rate']['values'])

    logger.info("\nPerformance Analysis:")
    peak_performance = (f"{cps_results['peak_performance']['cps']} CPS @ "
                        f"{cps_results['peak_performance']['time_ms']}ms").ljust(30)

    # stable_performance = f"Stable Performance: {cps_results['stable_performance']['avg_cps']} CPS"
    stable_performance = f"{cps_results['stable_performance']['avg_cps']} CPS".ljust(30)

    if cps_results['failure_phase']['detected']:
        failure_detected = (
            f"{cps_results['failure_phase']['cps_at_failure']} CPS @ "
            f"{cps_results['failure_phase']['time_ms']}ms").ljust(30)

    else:
        failure_detected = "No mid-test failure detected"

    columns = ['Peak Performance', 'Stable Performance', 'Failure Detected']
    testRun = [[peak_performance, stable_performance, failure_detected]]
    table = tabulate(testRun, headers=columns, tablefmt='grid')
    logger.info(table)

    return
