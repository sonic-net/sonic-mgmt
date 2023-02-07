import time

import logging
import re
import pytest

from tests.common.helpers.assertions import pytest_assert
from telemetry_utils import assert_equal, get_list_stdout, get_dict_stdout, skip_201911_and_older, generate_client_cli

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

TELEMETRY_PORT = 50051
METHOD_SUBSCRIBE = "subscribe"
METHOD_GET = "get"


def test_config_db_parameters(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verifies required telemetry parameters from config_db.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    gnmi = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "TELEMETRY|gnmi"', module_ignore_errors=False)['stdout_lines']
    pytest_assert(gnmi is not None, "TELEMETRY|gnmi does not exist in config_db")

    certs = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "TELEMETRY|certs"', module_ignore_errors=False)['stdout_lines']
    pytest_assert(certs is not None, "TELEMETRY|certs does not exist in config_db")

    d = get_dict_stdout(gnmi, certs)
    for key, value in d.items():
        if str(key) == "port":
            port_expected = str(TELEMETRY_PORT)
            pytest_assert(str(value) == port_expected, "'port' value is not '{}'".format(port_expected))
        if str(key) == "ca_crt":
            ca_crt_value_expected = "/etc/sonic/telemetry/dsmsroot.cer"
            pytest_assert(str(value) == ca_crt_value_expected, "'ca_crt' value is not '{}'".format(ca_crt_value_expected))
        if str(key) == "server_key":
            server_key_expected = "/etc/sonic/telemetry/streamingtelemetryserver.key"
            pytest_assert(str(value) == server_key_expected, "'server_key' value is not '{}'".format(server_key_expected))
        if str(key) == "server_crt":
            server_crt_expected = "/etc/sonic/telemetry/streamingtelemetryserver.cer"
            pytest_assert(str(value) == server_crt_expected, "'server_crt' value is not '{}'".format(server_crt_expected))

def test_telemetry_enabledbydefault(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify telemetry should be enabled by default
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    status = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "FEATURE|telemetry"', module_ignore_errors=False)['stdout_lines']
    status_list = get_list_stdout(status)
    # Elements in list alternate between key and value. Separate them and combine into a dict.
    status_key_list = status_list[0::2]
    status_value_list = status_list[1::2]
    status_dict = dict(zip(status_key_list, status_value_list))
    for k, v in status_dict.items():
        if str(k) == "status":
            status_expected = "enabled"
            pytest_assert(str(v) == status_expected, "Telemetry feature is not enabled")

def test_telemetry_ouput(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, setup_streaming_telemetry, localhost, gnxi_path):
    """Run pyclient from ptfdocker and show gnmi server outputself.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    logger.info('start telemetry output testing')
    dut_ip = duthost.mgmt_ip
    cmd = 'python ' + gnxi_path + 'gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m get -x COUNTERS/Ethernet0 -xt COUNTERS_DB \
           -o "ndastreamingservertest"'.format(dut_ip, TELEMETRY_PORT)
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    inerrors_match = re.search("SAI_PORT_STAT_IF_IN_ERRORS", result)
    pytest_assert(inerrors_match is not None, "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi_output")

def test_osbuild_version(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, localhost, gnxi_path):
    """ Test osbuild/version query.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_GET, target="OTHERS", xpath="osversion/build")
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    result = str(show_gnmi_out)

    assert_equal(len(re.findall('"build_version": "sonic\.', result)), 1, "build_version value at {0}".format(result))
    assert_equal(len(re.findall('sonic\.NA', result, flags=re.IGNORECASE)), 0, "invalid build_version value at {0}".format(result))

def test_sysuptime(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, localhost, gnxi_path):
    """
    @summary: Run pyclient from ptfdocker and test the dataset 'system uptime' to check
              whether the value of 'system uptime' was float number and whether the value was
              updated correctly.
    """
    logger.info("start test the dataset 'system uptime'")
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_201911_and_older(duthost)
    dut_ip = duthost.mgmt_ip
    cmd = 'python '+ gnxi_path + 'gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m get -x proc/uptime -xt OTHERS \
           -o "ndastreamingservertest"'.format(dut_ip, TELEMETRY_PORT)
    system_uptime_info = ptfhost.shell(cmd)["stdout_lines"]
    system_uptime_1st = 0
    found_system_uptime_field = False
    for line_info in system_uptime_info:
        if "total" in line_info:
            try:
                system_uptime_1st = float(line_info.split(":")[1].strip())
                found_system_uptime_field = True
            except ValueError as err:
                pytest.fail("The value of system uptime was not a float. Error message was '{}'".format(err))

    if not found_system_uptime_field:
        pytest.fail("The field of system uptime was not found.")

    # Wait 10 seconds such that the value of system uptime was added 10 seconds.
    time.sleep(10)
    system_uptime_info = ptfhost.shell(cmd)["stdout_lines"]
    system_uptime_2nd = 0
    found_system_uptime_field = False
    for line_info in system_uptime_info:
        if "total" in line_info:
            try:
                system_uptime_2nd = float(line_info.split(":")[1].strip())
                found_system_uptime_field = True
            except ValueError as err:
                pytest.fail("The value of system uptime was not a float. Error message was '{}'".format(err))

    if not found_system_uptime_field:
        pytest.fail("The field of system uptime was not found.")

    if system_uptime_2nd - system_uptime_1st < 10:
        pytest.fail("The value of system uptime was not updated correctly.")

def test_virtualdb_table_streaming(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, localhost, gnxi_path):
    """Run pyclient from ptfdocker to stream a virtual-db query multiple times.
    """
    logger.info('start virtual db sample streaming testing')

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE, update_count = 3)
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    result = str(show_gnmi_out)

    assert_equal(len(re.findall('Max update count reached 3', result)), 1, "Streaming update count in:\n{0}".format(result))
    assert_equal(len(re.findall('name: "Ethernet0"\n', result)), 4, "Streaming updates for Ethernet0 in:\n{0}".format(result)) # 1 for request, 3 for response
    assert_equal(len(re.findall('timestamp: \d+', result)), 3, "Timestamp markers for each update message in:\n{0}".format(result))


def backup_monit_config_files(duthost):
    """Backs up Monit configuration files on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Backing up Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("cp -f /etc/monit/monitrc /tmp/")
    duthost.shell("mv -f /etc/monit/conf.d/monit_* /tmp/")
    duthost.shell("cp -f /tmp/monit_telemetry /etc/monit/conf.d/")
    logger.info("Monit configuration files on DuT '{}' is backed up.".format(duthost.hostname))


def customize_monit_config_files(duthost, temp_config_line):
    """Customizes the Monit configuration file on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.
        temp_config_line: A string to replace the initial Monit configuration.

    Returns:
        None.
    """
    logger.info("Modifying Monit config to eliminate start delay and decrease interval ...")
    duthost.shell("sed -i '$s/^./#/' /etc/monit/conf.d/monit_telemetry")
    duthost.shell("echo '{}' | tee -a /etc/monit/conf.d/monit_telemetry".format(temp_config_line))
    duthost.shell("sed -i '/with start delay 300/s/^./#/' /etc/monit/monitrc")
    logger.info("Modifying Monit config to eliminate start delay and decrease interval are done.")


def restore_monit_config_files(duthost):
    """Restores the initial Monit configuration file on DuT.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Restoring original Monit configuration files on DuT '{}' ...".format(duthost.hostname))
    duthost.shell("mv -f /tmp/monitrc /etc/monit/")
    duthost.shell("mv -f /tmp/monit_* /etc/monit/conf.d/")
    logger.info("Original Monit configuration files on DuT '{}' are restored.".format(duthost.hostname))


def check_monit_running(duthost):
    """Checks whether Monit is running or not.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        Returns True if Monit is running; Otherwist, returns False.
    """
    monit_services_status = duthost.get_monit_services_status()
    if not monit_services_status:
        return False

    return True


def restart_monit_service(duthost):
    """Restarts Monit service and polls Monit running status.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    logger.info("Restarting Monit service ...")
    duthost.shell("systemctl restart monit")
    logger.info("Monit service is restarted.")

    logger.info("Checks whether Monit is running or not after restarted ...")
    is_monit_running = wait_until(MONIT_RESTART_THRESHOLD_SECS,
                                  MONIT_CHECK_INTERVAL_SECS,
                                  0,
                                  check_monit_running,
                                  duthost)
    pytest_assert(is_monit_running, "Monit is not running after restarted!")
    logger.info("Monit is running!")


def check_critical_processes(duthost, container_name):
    """Checks whether the critical processes are running after container was restarted.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Returns:
        None.
    """
    status_result = duthost.critical_process_status(container_name)
    if status_result["status"] is False or len(status_result["exited_critical_process"]) > 0:
        return False

    return True


def postcheck_critical_processes(duthost, container_name):
    """Checks whether the critical processes are running after container was restarted.

    Args:
        duthost: The AnsibleHost object of DuT.
        container_name: Name of container.

    Returns:
        None.
    """
    logger.info("Checking the running status of critical processes in '{}' container ..."
                .format(container_name))
    is_succeeded = wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS, 0,
                              check_critical_processes, duthost, container_name)
    if not is_succeeded:
        pytest.fail("Not all critical processes in '{}' container are running!"
                    .format(container_name))
    logger.info("All critical processes in '{}' container are running.".format(container_name))


@pytest.fixture(params=['if status == 3 for 1 times within 2 cycles then exec "/usr/bin/restart_service telemetry" repeat every 2 cycles'],
                ids=["monit_config_line"])
def test_mem_spike_setup_and_cleanup(duthosts, rand_one_dut_hostname, setup_streaming_telemetry, request):
    """Customizes Monit configuration files before testing and restores them after testing.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: The fixture returns a randomly selected DuT.
        setup_streaming_telemetry: Fixture to setup telemetry server authentication before testing.

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]

    backup_monit_config_files(duthost)
    customize_monit_config_files(duthost, request.param)
    restart_monit_service(duthost)

    yield

    restore_monit_config_files(duthost)
    restart_monit_service(duthost)


@pytest.mark.disable_loganalyzer
def test_mem_spike(duthosts, rand_one_dut_hostname, ptfhost, test_mem_spike_setup_and_cleanup, gnxi_path):
    """Test whether memory usage of telemetry container will increase and be restarted
    or not by Monit if python gNMI client continuously creates channels with gNMI server.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: The fixture returns a randomly selected DuT.
        pfthost: PTF docker binding to the selected DuT.
        test_mem_spike_setup_and_cleanup: Fixture does testing setup and cleanup.

    Returns:
        None.
    """
    logger.info("Starting to test the memory spike issue of '{}' ...".format(CONTAINER_NAME))

    duthost = duthosts[rand_one_dut_hostname]
    dut_ip = duthost.mgmt_ip

    logger.info("Checking whether the '{}' container is running before testing...".format(CONTAINER_NAME))
    is_running = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                            CONTAINER_CHECK_INTERVAL_SECS,
                            0,
                            check_container_state, duthost, CONTAINER_NAME, True)
    pytest_assert(is_running, "'{}' is not running on DuT!".format(CONTAINER_NAME))
    logger.info("'{}' is running on DuT!".format(CONTAINER_NAME))

    expected_alerting_messages = []
    expected_alerting_messages.append(".*restart_service.*Restarting service 'telemetry'.*")
    expected_alerting_messages.append(".*Stopping Telemetry container.*")
    expected_alerting_messages.append(".*Stopped Telemetry container.*")
    expected_alerting_messages.append(".*Starting Telemetry container.*")
    expected_alerting_messages.append(".*Started Telemetry container.*")

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="container_restart_due_to_memory")
    loganalyzer.expect_regex = []
    loganalyzer.expect_regex.extend(expected_alerting_messages)
    marker = loganalyzer.init()

    client_thread = ThreadPool(processes=1)
    client_thread.apply_async(run_gnmi_client, (ptfhost, dut_ip, gnxi_path, -1))

    logger.info("Sleep '{}' seconds to wait for the syslog messages related to '{}' container restarted ..."
                .format(WAITING_SYSLOG_MSG_SECS, CONTAINER_NAME))
    time.sleep(WAITING_SYSLOG_MSG_SECS)

    logger.info("Checking the syslog messages related to '{}' container restarted ...".format(CONTAINER_NAME))
    analyzing_result = loganalyzer.analyze(marker, fail=False)
    if analyzing_result["total"]["expected_match"] < len(expected_alerting_messages):
        duthost.service(name="telemetry", state="restarted")
        pytest.fail("Failed to find all expected syslog messages!")
    else:
        logger.info("Found all the expected syslog messages!")

    logger.info("Checking whether the '{}' container is running after testing...".format(CONTAINER_NAME))
    is_running = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                            CONTAINER_CHECK_INTERVAL_SECS,
                            0,
                            check_container_state, duthost, CONTAINER_NAME, True)
    pytest_assert(is_running, "'{}' is not running on DuT!".format(CONTAINER_NAME))
    logger.info("'{}' is running on DuT!".format(CONTAINER_NAME))

    postcheck_critical_processes(duthost, CONTAINER_NAME)
