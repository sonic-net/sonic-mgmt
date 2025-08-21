import snappi  # noqa: F401
import re
import time
import json
import logging
import threading

from typing import Optional, Dict, List
from dataclasses import dataclass
from queue import Queue
from enum import Enum
from collections import defaultdict

from tabulate import tabulate
from tests.common.utilities import (wait, wait_until)  # noqa F401
from tests.common.helpers.assertions import pytest_assert  # noqa F401
from tests.common.snappi_tests.uhd.uhd_helpers import NetworkConfigSettings  # noqa: F403, F401

logger = logging.getLogger(__name__)


def run_ha_test(duthost, tbinfo, ha_test_case, config_snappi_l47):

    api = config_snappi_l47['api']
    initial_cps_value = config_snappi_l47['initial_cps_value']

    nw_config = config_snappi_l47['nw_config']
    nw_config.set_mac_addresses(tbinfo['l47_tg_clientmac'], tbinfo['l47_tg_servermac'], tbinfo['dut_mac'])

    # Configure SmartSwitch
    dpu_if_ips = duthost_ha_config(duthost, nw_config, tbinfo, ha_test_case)

    linkloss_pattern = r'linkloss\d*'

    # Traffic Starts
    if ha_test_case == 'cps':
        api = run_cps_search(api, initial_cps_value)
    elif ha_test_case == 'plannedswitchover':
        api = run_planned_switchover(duthost, api, dpu_if_ips, initial_cps_value)
    elif ha_test_case == 'dpuloss':
        api = run_dpuloss(duthost, tbinfo, api, dpu_if_ips, initial_cps_value)
    elif bool(re.search(linkloss_pattern, ha_test_case)):
        api = run_linkloss(duthost, tbinfo, api, dpu_if_ips, initial_cps_value, ha_test_case)
    else:
        return

    logger.info("Test case {} Ending".format(ha_test_case))

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
                    # client_req.httpclient.end_test = False

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
                    logger.error(f"Error collecting metrics: {e}")
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


def collect_metrics_threaded(api, client_req, server_req=None) -> MetricsResult:
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


def dpu_config(duthost, ha_test_case):

    pass


def ha_switchTraffic(duthost, dut_if_ips, traffic_direction='dpu2'):

    ha_switch_config = ()
    new_active = traffic_direction
    new_standby = 'dpu1' if traffic_direction == 'dpu2' else 'dpu2'

    dpu1_lb_ip = dut_if_ips['dpu1']['loopback_ip']
    dpu1_if_ip = dut_if_ips['dpu1']['if_ip']
    dpu2_lb_ip = dut_if_ips['dpu2']['loopback_ip']
    dpu2_if_ip = dut_if_ips['dpu2']['if_ip']

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

    duthost.shell(ha_switch_config)

    return


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
        duthost.shell(f"sudo config interface shutdown {dpu_if}")
        logger.info(f"Starting up link between NPU and DPU{dpu_id}")
    except Exception as e:
        logger.error(f"Error starting up link {dpu_if}: {e}")

    return


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


def analyze_cps_performance(timestamps, values):
    # Convert values to integers, ignoring empty strings
    cps_values = [int(x) for x in values if x.isdigit()]

    # Find peak performance
    peak_cps = max(cps_values)
    peak_index = values.index(str(peak_cps))
    peak_time = int(timestamps[peak_index])

    # Calculate stable performance (excluding initial spikes and end zeros)
    # Using the middle 60% of non-zero values for stable calculation
    non_zero_values = [int(x) for x in values if x.isdigit() and int(x) > 0]
    stable_values = non_zero_values[len(non_zero_values) // 5:4 * len(non_zero_values) // 5]
    stable_performance = sum(stable_values) / len(stable_values)

    # Detect failure phase (looking for significant drops in the middle)
    failure_detected = False
    failure_start_time = None
    failure_cps = None

    # Using 50% drop from stable performance as failure threshold
    failure_threshold = stable_performance * 0.5

    # Check for failures (excluding last 10% of the test)
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


def run_cps_search(api, initial_cps_value):

    MAX_CPS = 12000000
    MIN_CPS = 0
    threshold = 1000000
    test_iteration = 1
    test_value = initial_cps_value
    activityList_url = "ixload/test/activeTest/communityList/0/activityList/0"
    releaseConfig_url = "ixload/test/operations/abortAndReleaseConfigWaitFinish"
    testRuns = []

    while ((MAX_CPS - MIN_CPS) > threshold):
        test_result = ""
        logger.info(
            "----Test Iteration %d------------------------------------------------------------------"
            % test_iteration)
        old_value = test_value
        logger.info("Testing CPS Objective = %d" % test_value)
        cps_objective_value = test_value
        activityList_json = {
            'constraintType': 'ConnectionRateConstraint',
            'constraintValue': test_value,
            'enableConstraint': False,
        }
        logger.info("Updating CPS objective value settings...")
        try:
            # Code that may raise an exception
            res = api.ixload_configure("patch", activityList_url, activityList_json)
        except Exception as e:
            # Handle any exception
            logger.info(f"An error occurred: {e}")
        logger.info("CPS objective value updated.")

        logger.info("Applying config...")
        logger.info("Starting Traffic")
        cs = api.control_state()
        cs.app.state = 'start'  # cs.app.state.START
        response1 = api.set_control_state(cs)
        logger.info(response1)
        req = api.metrics_request()

        # HTTP client
        stats_client = []
        req.choice = "httpclient"
        req.httpclient.stat_name = ["Connection Rate"]
        # req.httpclient.stat_name = ["HTTP Simulated Users", "HTTP Concurrent Connections", "HTTP Connect Time (us)",
        # "TCP Connections Established", "HTTP Bytes Received"]
        # req.httpclient.all_stats = True # for all stats

        res = api.get_metrics(req).httpclient_metrics
        stats_client.append(res)
        time.sleep(60)

        res = api.get_metrics(req).httpclient_metrics
        stats_client.append(res)
        time.sleep(60)

        res = api.get_metrics(req).httpclient_metrics
        stats_client.append(res)
        time.sleep(60)

        # req1 = api.metrics_request()
        # req1.choice= "httpserver"
        # req1.httpserver.stat_name = ["TCP Connections in ESTABLISHED State", "TCP FIN Received","HTTP Bytes Received"]
        # #req1.httpserver.all_stats=True # for all stats - True
        # res1 = api.get_metrics(req1).httpserver_metrics
        # logger.info("#### res1 = {} ####".format(res1))

        cps_max = 0
        client_stat_values = []
        for stat in stats_client:
            tmp = re.findall(r"value: '(\d+)'", str((stat)))
            client_stat_values += tmp
            client_stat_values = [int(item) for item in client_stat_values]
        cps_max = max(client_stat_values)

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

        columns = ['#Run', 'CPS Objective', 'Max CPS', 'Test Result']
        testRuns.append([test_iteration, cps_objective_value, cps_max, test_result])
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
            res = api.ixload_configure("post", releaseConfig_url, param)
        except Exception as e:
            # Handle any exception
            logger.info(f"An error occurred: {e}")
        logger.info("Releasing config completed..")

        logger.info("Changing app state to stop")
        cs.app.state = 'stop'  # cs.app.state.START
        api.set_control_state(cs)

    return api


def run_planned_switchover(duthost, api, dpu_if_ips, initial_cps_value):
    # Setup metric collection
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

        # First switchover
        logger.info("Executing first switchover...")
        collector.set_phase(TestPhase.DURING_FIRST_SWITCH)
        ha_switchTraffic(duthost, dpu_if_ips, 'dpu2')
        collector.set_phase(TestPhase.AFTER_FIRST_SWITCH)

        # Stabilization period
        logger.info("Waiting for stabilization...")
        time.sleep(60)

        # Second switchover
        logger.info("Executing second switchover...")
        collector.set_phase(TestPhase.DURING_SECOND_SWITCH)
        ha_switchTraffic(duthost, dpu_if_ips, 'dpu1')
        collector.set_phase(TestPhase.AFTER_SECOND_SWITCH)

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


def run_dpuloss(duthost, tbinfo, api, dpu_if_ips, initial_cps_value):

    dpu_active_id = tbinfo['dpu_active_id']
    dpu_standby_id = tbinfo['dpu_standby_id']  # noqa: F841

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

        # First switchover
        logger.info("Executing first switchover...")
        collector.set_phase(TestPhase.DURING_FIRST_SWITCH)
        power_off_dpu(duthost, dpu_active_id)
        time.sleep(1)
        ha_switchTraffic(duthost, dpu_if_ips, 'dpu2')
        collector.set_phase(TestPhase.AFTER_FIRST_SWITCH)

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

        ha_switchTraffic(duthost, dpu_if_ips, 'dpu1')
        power_on_dpu(duthost, dpu_active_id)
        logger.info("Stopping traffic...")
        cs.app.state = 'stop'
        api.set_control_state(cs)

    # Get and process metrics
    all_metrics = collector.get_metrics()
    logger.info(f"Collected metrics for {len(all_metrics)} phases")

    pattern = r"- name:\s*([^\n]*)\n(.*?)(?=- name|\Z)"
    stats_client_tmp = re.findall(pattern, str(all_metrics[TestPhase.AFTER_FIRST_SWITCH][0]['client_metrics']),
                                  re.DOTALL)
    stats_server_tmp = re.findall(pattern, str(all_metrics[TestPhase.AFTER_FIRST_SWITCH][0]['server_metrics']),
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

    scp_command = f"""sudo python3 -c 'import pexpect
child = pexpect.spawn("scp /tmp/acl_drop_rule.json admin@{dpu_midplane_if}:/home/admin/")
child.expect("password:")
child.sendline("password")
child.expect(pexpect.EOF)
child.close()'"""

    duthost.shell(scp_command)

    apply_command = f"""sudo python3 -c 'import pexpect
child = pexpect.spawn("ssh admin@{dpu_midplane_if}")
child.expect("password:")
child.sendline("password")
child.expect("\\$")
child.sendline("sudo config load -y /home/admin/acl_drop_rule.json")
child.expect("\\$")
child.sendline("exit")
child.close()'"""

    result = duthost.shell(apply_command)
    logger.info(f"ACL rules application result: {result}")

    duthost.shell("rm -f /tmp/acl_drop_rule.json")

    return result


def run_linkloss(duthost, tbinfo, api, dpu_if_ips, initial_cps_value, ha_test_case):

    if ha_test_case == "linkloss4":
        npu_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
        dpu_ip = dpu_if_ips['dpu1']['if_ip']
        dpu_midplane_ip = dpu_if_ips['dpu1']['if_midplane_ip']
    elif ha_test_case == "linkloss5":
        npu_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
        dpu_ip = dpu_if_ips['dpu1']['if_ip']
        dpu_midplane_ip = dpu_if_ips['dpu1']['if_midplane_ip']
    elif ha_test_case == "linkloss6":
        npu_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
        dpu_ip = dpu_if_ips['dpu2']['if_ip']
        dpu_midplane_ip = dpu_if_ips['dpu2']['if_midplane_ip']
    elif ha_test_case == "linkloss7":
        npu_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']
        dpu_ip = dpu_if_ips['dpu2']['if_ip']
        dpu_midplane_ip = dpu_if_ips['dpu2']['if_midplane_ip']
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

        # First switchover
        logger.info("Executing first switchover...")
        collector.set_phase(TestPhase.DURING_FIRST_SWITCH)
        shutdown_link_npu_dpu(duthost, dpu_if_ips)
        result = create_and_apply_acl_rules(  # noqa: 841
            duthost=duthost,
            dpu_ip=dpu_ip,
            npu_ip=npu_ip,
            l4_src_port1="3784",
            l4_src_port2="3784",
            dpu_midplane_if=dpu_midplane_ip  # Optional, defaults to 169.254.200.1
        )
        time.sleep(1)
        ha_switchTraffic(duthost, dpu_if_ips, 'dpu2')
        collector.set_phase(TestPhase.AFTER_FIRST_SWITCH)

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

        ha_switchTraffic(duthost, dpu_if_ips, 'dpu1')
        startup_link_npu_dpu(duthost, dpu_if_ips)
        logger.info("Stopping traffic...")
        cs.app.state = 'stop'
        api.set_control_state(cs)

    # Get and process metrics
    all_metrics = collector.get_metrics()
    logger.info(f"Collected metrics for {len(all_metrics)} phases")

    pattern = r"- name:\s*([^\n]*)\n(.*?)(?=- name|\Z)"
    stats_client_tmp = re.findall(pattern, str(all_metrics[TestPhase.AFTER_FIRST_SWITCH][0]['client_metrics']),
                                  re.DOTALL)
    stats_server_tmp = re.findall(pattern, str(all_metrics[TestPhase.AFTER_FIRST_SWITCH][0]['server_metrics']),
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


def save_test(api, test_filename):

    saveAs_operation = 'ixload/test/operations/saveAs'
    # url = "{}/{}".format(base_url, saveAs_operation)
    paramDict = {
        'fullPath': "C:\\automation\\{}.rxf".format(test_filename),
        'overWrite': True
    }

    # response = requests.post(url, data=json.dumps(paramDict), headers=headers)
    try:
        # Code that may raise an exception
        res = api.ixload_configure("post", saveAs_operation, paramDict)  # noqa: F841
    except Exception as e:
        # Handle any exception
        logger.info(f"An error occurred: {e}")

    return
