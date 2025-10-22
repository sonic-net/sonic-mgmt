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
import re
import time
import logging

logger = logging.getLogger(__name__)


def run_ha_test(duthost, localhost, tbinfo, ha_test_case, passing_dpus, config_snappi_l47):

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
    else:
        logger.info("Skipping running an HA test")

    return


def ha_switchTraffic(duthost, ha_test_case):

    # Moves traffic to DPU2
    ha_switch_config = (
        "vtysh "
        "-c 'configure' "
        "-c 'ip route 221.0.0.1/32 18.0.202.1 10' "
        "-c 'ip route 221.0.0.1/32 18.2.202.1 1' "
        "-c 'exit' "
    )

    logger.info("HA switch shell 1")
    duthost.shell(ha_switch_config)

    # Sets traffic back to DPU0
    ha_switch_config = (
        "vtysh "
        "-c 'configure' "
        "-c 'no ip route 221.0.0.1/32 18.2.202.1 1' "
        "-c 'ip route 221.0.0.1/32 18.0.202.1 1' "
        "-c 'exit' "
    )
    logger.info("HA switch shell 4")
    duthost.shell(ha_switch_config)

    return


class TestPhase(Enum):
    BEFORE_SWITCH = "before_switch"
    DURING_FIRST_SWITCH = "during_first_switch"
    AFTER_FIRST_SWITCH = "after_first_switch"
    DURING_SECOND_SWITCH = "during_second_switch"
    AFTER_SECOND_SWITCH = "after_second_switch"


class ContinuousMetricsCollector:
    def __init__(self, collection_interval=1):
        self.running = False
        self.current_phase = TestPhase.BEFORE_SWITCH
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

    def set_phase(self, phase: TestPhase):
        with self._lock:
            self.current_phase = phase

    def stop_collection(self):
        self.running = False
        if self.thread:
            self.thread.join()

    def get_metrics(self) -> Dict[TestPhase, List]:
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

        collector.set_phase(TestPhase.AFTER_SECOND_SWITCH)
        time.sleep(60)
        collector.stop_collection()

        all_metrics = collector.get_metrics()
        logger.info(f"Collected metrics for {len(all_metrics)} phases")

        pattern = r"- name:\s*([^\n]*)\n(.*?)(?=- name|\Z)"

        stats_client_tmp = re.findall(pattern, str(all_metrics[TestPhase.AFTER_SECOND_SWITCH][0]['client_metrics']),
                                      re.DOTALL)
        stats_server_tmp = re.findall(pattern, str(all_metrics[TestPhase.AFTER_SECOND_SWITCH][0]['server_metrics']),
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

        """
        if (err_maxvalue < cps_max) and (error_percent <= error_threshold):
            test = True
        else:
            test = False
        """
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
