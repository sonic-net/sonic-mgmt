import logging
import json
import os
import re
import pytest
import ast
from tests.common.helpers.sensor_control_test_helper import BaseMocker
from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.gnmi_utils import gnmi_container
from tests.common import config_reload
# The interval of EVENT_PUBLISHED is 60 seconds by default.
# To left some buffer, the timeout for gnmi LD event is set to 90 seconds
WAIT_GNMI_LD_EVENT_TIMEOUT = 90
# To left some buffer for the thread timeout,the timeout for gnmi event is set to 120 seconds
WAIT_GNMI_EVENT_TIMEOUT = WAIT_GNMI_LD_EVENT_TIMEOUT + 30


class LiquidLeakageMocker(BaseMocker):
    """
    Liquid leakage mocker. Vendor should implement this class to provide a liquid leakage mocker.
    This class could mock liquid leakage detection status.
    """

    def mock_leakage(self):
        """
        Change the mocked liquid leakage detection status to 'Leakage'.
        :return:
        """
        pass

    def mock_no_leakage(self):
        """
        Change the mocked liquid leakage detection status to 'No Leakage'.
        :return:
        """
        pass

    def verify_leakage(self):
        """
        Verify the leakage status of the DUT.
        :return:
        """
        pass

    def verify_no_leakage(self):
        """
        Verify the leakage status of the DUT.
        :return:
        """
        pass


def get_leakage_status(dut):
    """
    Get the leakage status of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :return: The leakage status of the DUT.
    """
    return dut.show_and_parse("show platform leakage status")


def get_leakage_status_in_health_system(dut):
    """
    Get the health system status of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :return: The health system status of the DUT.
    """
    system_health_status = dut.show_and_parse("sudo show system-health detail")
    system_health_leakage_status_list = []
    for status in system_health_status:
        if status['name'].startswith('leakage'):
            system_health_leakage_status_list.append(status)
    logging.info(f"System health leakage status list: {system_health_leakage_status_list}")
    return system_health_leakage_status_list


def get_state_db(dut):
    return ast.literal_eval(dut.shell('sonic-db-dump -n STATE_DB -y')['stdout'])


def verify_leakage_status(dut, leakage_index_list, expected_status):
    """
    Verify the leak status of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :param expected_status: Expected status of the DUT.
    :return:
    """
    logging.info(f"Verify leakage status of {leakage_index_list} is : {expected_status}")
    leakage_status_list = get_leakage_status(dut)
    failed_leakage_list = []
    success_leakage_list = []
    for index in leakage_index_list:
        for leak_status in leakage_status_list:
            if leak_status['name'] == f"leakage{index}":
                if leak_status['leak'].lower() != expected_status.lower():
                    failed_leakage_list.append(index)
                    logging.info(f"Leakage status is not as expected: {leak_status}")
                else:
                    success_leakage_list.append(index)
                    logging.info(f"Leakage status is as expected: {leak_status}")
    assert len(failed_leakage_list) == 0, f"Leakage status is not as expected: {failed_leakage_list}"
    assert len(success_leakage_list) == len(leakage_index_list), \
        f"Not all leakage status are detected: test leakage index list: {leakage_index_list}, " \
        f"success leakage index list:  {success_leakage_list}"
    return True


def verify_leakage_status_in_health_system(dut, leakage_index_list, expected_status):
    """
    Verify the leakage status in health system of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :param expected_status: Expected status of the DUT.
    :return:
    """
    logging.info(f"Verify leakage status in health system of {leakage_index_list} is: {expected_status}")
    health_system_leakage_status_list = get_leakage_status_in_health_system(dut)
    failed_leakage_list = []
    success_leakage_list = []
    for index in leakage_index_list:
        for leak_status in health_system_leakage_status_list:
            if f"leakage{index}" == leak_status['name']:
                if leak_status['status'].lower() != expected_status.lower():
                    failed_leakage_list.append(index)
                    logging.info(f"Leakage status in health system is not as expected: {leak_status}")
                else:
                    success_leakage_list.append(index)
                    logging.info(f"Leakage status in health system is as expected: {leak_status}")
    assert len(failed_leakage_list) == 0, f"Leakage status is not as expected: {failed_leakage_list}"
    assert len(success_leakage_list) == len(leakage_index_list), \
        f"Not all leakage status are detected: test leakage index list: {leakage_index_list}, " \
        f"success leakage index list:  {success_leakage_list}"
    return True


def verify_leakage_status_in_state_db(dut, leakage_index_list, expected_status):
    """
    Verify the leakage status in state db of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :param expected_status: Expected status of the DUT.
    :return:
    """
    logging.info(f"Verify leakage status in state db of {leakage_index_list} is: {expected_status}")
    state_db = get_state_db(dut)
    failed_leakage_list = []
    success_leakage_list = []
    for index in leakage_index_list:
        leak_status = state_db.get(f"LIQUID_COOLING_INFO|leakage{index}", {}).get("value", {}).get("leak_status")
        if leak_status != expected_status:
            failed_leakage_list.append(index)
            logging.info(f"Leakage status in state db is not as expected: {leak_status}")
        else:
            success_leakage_list.append(index)
            logging.info(f"Leakage status in state db is as expected: {leak_status}")
    assert len(failed_leakage_list) == 0, f"Leakage status is not as expected: {failed_leakage_list}"
    assert len(success_leakage_list) == len(leakage_index_list), \
        f"Not all leakage status are detected: test leakage index list: {leakage_index_list}, " \
        f"success leakage index list:  {success_leakage_list}"
    return True


def verify_gnmi_msg_is_sent(leakage_index_list, gnmi_result, msg_type):
    """
    Verify the gnmi msg of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :param gnmi_result: gnmi result of the DUT.
    :return:
    """
    logging.info(
        f"Verify gnmi msg is sent for {leakage_index_list} with type: {msg_type} \n gnmi result: {gnmi_result}")
    msg_common_prefix = "sonic-events-host:liquid-cooling-leak"
    for index in leakage_index_list:
        if msg_type == "leaking":
            expected_msg_regex = f".*{msg_common_prefix}.*sensor report leaking event.*leakage{index}.*"
        else:
            expected_msg_regex = f".*{msg_common_prefix}.*leaking sensor report recoveried.*leakage{index}.*"
        assert re.search(expected_msg_regex, gnmi_result), f"Gnmi msg is not as expected: {gnmi_result}"
    return True


def startmonitor_gnmi_event(duthost, ptfhost):
    """
    Monitor the gnmi event of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :param ptfhost: PTF object representing a PTF switch under test.
    :param result_queue: Queue object to store the result.
    :return:
    """
    dut_mgmt_ip = duthost.mgmt_ip
    timeout = WAIT_GNMI_LD_EVENT_TIMEOUT
    gnmi_subscribe_cmd = f"python /root/gnxi/gnmi_cli_py/py_gnmicli.py  -g -t {dut_mgmt_ip} -p 50052 -m subscribe \
    -x all[heartbeat=2] -xt EVENTS -o ndastreamingservertest --subscribe_mode 0 --submode 1 --interval 0 \
        --update_count 0 --create_connections 1 --filter_event_regex sonic-events-host --timeout {timeout} "
    result = ptfhost.shell(gnmi_subscribe_cmd, module_ignore_errors=True)['stdout']
    logging.info(f"gnmi subscribe cmd: {gnmi_subscribe_cmd} \n gnmi event result: {result}")
    return result


def get_pmon_daemon_control_dict(dut):
    """
    Get the pmon daemon control dict of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :return: The pmon daemon control dict of the DUT.
    """
    pmon_daemon_control_file_path = os.path.join(
        "/usr/share/sonic/device", dut.facts["platform"], "pmon_daemon_control.json")
    return json.loads(dut.shell(f"cat {pmon_daemon_control_file_path} ")['stdout'])


def is_liquid_cooling_system_supported(dut):
    """
    Check if the liquid cooling system is supported on the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :return: True if the liquid cooling system is supported, False otherwise.
    """
    pmon_daemon_control_dict = get_pmon_daemon_control_dict(dut)
    if pmon_daemon_control_dict.get("enable_liquid_cooling"):
        logging.info("Liquid cooling system is supported")
        return True
    else:
        logging.info("Liquid cooling system is not supported")
        return False


def get_liquid_cooling_update_interval(dut):
    """
    Get the liquid cooling update interval of the DUT.
    :param dut: DUT object representing a SONiC switch under test.
    :return: The liquid cooling update interval of the DUT.
    """
    pmon_daemon_control_dict = get_pmon_daemon_control_dict(dut)
    return pmon_daemon_control_dict.get("liquid_cooling_update_interval")


@pytest.fixture(scope="function")
def setup_gnmi_server(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    '''
    Setup GNMI server with client certificates
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Check if GNMI is enabled on the device
    pyrequire(
        check_container_state(duthost, gnmi_container(duthost), should_be_running=True),
        "Test was not supported on devices which do not support GNMI!")
    duthost.shell("sonic-db-cli CONFIG_DB hset 'GNMI|gnmi' port 50052")
    duthost.shell("sonic-db-cli CONFIG_DB hset 'GNMI|gnmi' client_auth true")
    duthost.shell("sonic-db-cli CONFIG_DB hset 'GNMI|certs' ca_crt /etc/sonic/telemetry/dsmsroot.cer")
    duthost.shell(
        "sonic-db-cli CONFIG_DB hset 'GNMI|certs' server_crt /etc/sonic/telemetry/streamingtelemetryserver.cer")
    duthost.shell(
        "sonic-db-cli CONFIG_DB hset 'GNMI|certs' server_key /etc/sonic/telemetry/streamingtelemetryserver.key")
    duthost.shell('sonic-db-cli CONFIG_DB HSET "GNMI|gnmi" "client_auth" "false"')
    duthost.shell('sudo systemctl reset-failed gnmi')
    duthost.shell('sudo service gnmi restart')

    yield

    logging.info("Recover gnmi config")
    config_reload(duthost, safe_reload=True)
