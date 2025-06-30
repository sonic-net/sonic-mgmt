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

    # Traffic Starts
    if ha_test_case == 'cps':
        api = run_cps_search(api, initial_cps_value)
    elif ha_test_case == 'plannedswitchover':

        api = run_planned_switchover(duthost, api, dpu_if_ips, initial_cps_value)

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

                    # Configure server request
                    server_req.choice = "httpserver"
                    server_req.httpserver.stat_name = ["TCP Resets Sent", "TCP Retries"]

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
    """Collect metrics using threads"""
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
                 'if_ip': ''},
        'dpu2': {'loopback_ip': '',
                 'if_ip': ''}
    }

    config_db_stdout = duthost.shell("cat /etc/sonic/config_db.json")["stdout"]
    config_db = json.loads(config_db_stdout)

    static_ips = []
    if_ip = []
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

    # Collecting DPU data for switchover commands
    dpu_if_ips['dpu1']['loopback_ip'] = lb_ip[0][0].split('|')[1].split('/')[0]
    dpu_if_ips['dpu1']['if_ip'] = if_ip[0]
    dpu_if_ips['dpu2']['loopback_ip'] = lb_ip[0][0].split('|')[1].split('/')[0]
    dpu_if_ips['dpu2']['if_ip'] = if_ip[2]

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


def run_cps_search(api, initial_cps_value):

    MAX_CPS = 5000000
    MIN_CPS = 0
    threshold = 100000
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
            'enableConstraint': True,
            'userObjectiveType': 'simulatedUsers',
            'userObjectiveValue': 64500
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
            'enableConstraint': True,
            'userObjectiveType': 'simulatedUsers',
            'userObjectiveValue': 64500
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

    for phase, metrics_list in all_metrics.items():
        logger.info(f"Phase {phase.value}: {len(metrics_list)} samples collected")
        for metric in metrics_list:
            logger.info(f"Sample at {metric['timestamp']}: "
                        f"Client metrics: {metric['client_metrics']}, "
                        f"Server metrics: {metric['server_metrics']}")

    return all_metrics


def test_saveAs(api, test_filename):

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
