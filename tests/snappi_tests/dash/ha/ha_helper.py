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

        # Traffic Starts
        if ha_test_case == 'cps':
            api = run_cps_search(api, file_name, initial_cps_value, passing_dpus)
            logger.info("Test Ending")
        elif ha_test_case == 'planned_switchover':
            api = run_planned_switchover(duthosts, tbinfo, file_name, api, initial_cps_value)
        elif ha_test_case == 'dpuloss':
            api = run_dpuloss(duthosts, tbinfo, file_name, api, initial_cps_value)
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


''''
def ha_switchTraffic(duthost, dut_if_ips, traffic_direction='dpu2'):

    ha_switch_config = ()
    new_active = traffic_direction
    new_standby = 'dpu1' if traffic_direction == 'dpu2' else 'dpu2'

    dpu1_lb_ip = dut_if_ips['dpu1']['loopback_ip']
    dpu1_if_ip = dut_if_ips['dpu1']['if_ip']
    dpu2_lb_ip = dut_if_ips['dpu2']['loopback_ip']
    dpu2_if_ip = dut_if_ips['dpu2']['if_ip']

    import pdb; pdb.set_trace()

    if traffic_direction == 'dpu2':
        # Moves traffic to DPU2

        ha_switch_config = (
            "vtysh "
            "-c 'configure terminal' "
            f"-c 'ip route {dpu1_lb_ip}/32 {dpu1_if_ip} 10' "
            f"-c 'ip route {dpu2_lb_ip}/32 {dpu2_if_ip} 1' "
            "-c 'exit' "
        )
    else:
        # Sets traffic back to DPU0
        ha_switch_config = (
            "vtysh "
            "-c 'configure terminal' "
            f"-c 'no ip route {dpu2_lb_ip}/32 {dpu2_if_ip} 1' "
            f"-c 'ip route {dpu1_lb_ip}/32 {dpu1_if_ip} 1' "
            "-c 'exit' "
        )

    logger.info(f"HA traffic moved from {new_standby} to {new_active}")

    import pdb; pdb.set_trace()
    duthost.shell(ha_switch_config)

    return
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
