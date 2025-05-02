from tabulate import tabulate
from tests.common.utilities import (wait, wait_until)  # noqa F401
from tests.common.helpers.assertions import pytest_assert  # noqa F401
import snappi
import ipaddress
import re
import macaddress
import time

import logging

logger = logging.getLogger(__name__)

ipp = ipaddress.ip_address
maca = macaddress.MAC


def run_ha_test(duthost, localhost, ha_test_case, config_snappi_ixl):

    test_type_dict = config_snappi_ixl['test_type_dict']
    connection_dict = config_snappi_ixl['connection_dict']


    # Configure SmartSwitch
    #duthost_ha_config(duthost, ha_test_case)

    api = config_snappi_ixl['api']
    config = config_snappi_ixl['config']
    initial_cps_value = config_snappi_ixl['initial_cps_value']

    # Configure IxLoad traffic
    import pdb; pdb.set_trace()

    #ha_switchTraffic(duthost, ha_test_case)

    # Traffic Starts
    if ha_test_case == 'cps':
        api = run_cps_search(api, initial_cps_value)
        # cs.app.state = 'stop' #cs.app.state.START
        # api.set_control_state(cs)
    elif ha_test_case == 'plannedswitchover':
        api = run_plannedswitchover(api, duthost, ha_test_case, initial_cps_value)

    logger.info("Test case {} Ending".format(ha_test_case))

    return


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


def run_plannedswitchover(api, duthost, ha_test_case, initial_cps_value):

    import pdb; pdb.set_trace()
    test_value = initial_cps_value
    activityList_url = "ixload/test/activeTest/communityList/0/activityList/0"
    releaseConfig_url = "ixload/test/operations/abortAndReleaseConfigWaitFinish"
    testRuns = []
    test_iteration = 1

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
    pdb.set_trace()
    ha_switch_config = (
        "vtysh "
        "-c 'configure' "
        "-c 'no ip route 221.0.0.1/32 18.2.202.1 1' "
        "-c 'ip route 221.0.0.1/32 18.0.202.1 1' "
        "-c 'exit' "
    )
    logger.info("HA switch shell 4")
    duthost.shell(ha_switch_config)

    pdb.set_trace()

    return
