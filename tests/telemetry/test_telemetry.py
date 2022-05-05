import time
from multiprocessing.pool import ThreadPool

import logging
import re
import pytest

from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.dut_utils import is_container_running
from tests.common.utilities import wait_until, wait_tcp_connection
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

TELEMETRY_PORT = 50051
METHOD_SUBSCRIBE = "subscribe"
METHOD_GET = "get"

SUBSCRIBE_MODE_STREAM = 0
SUBSCRIBE_MODE_ONCE = 1
SUBSCRIBE_MODE_POLL = 2

SUBMODE_TARGET_DEFINED = 0
SUBMODE_ON_CHANGE = 1
SUBMODE_SAMPLE = 2

CHECK_MEM_USAGE_COUNTER = 10
CONTAINER_NAME = "telemetry"
WAITING_SYSLOG_MSG_SECS = 200
CONTAINER_STOP_THRESHOLD_SECS = 200
CONTAINER_RESTART_THRESHOLD_SECS = 180
CONTAINER_CHECK_INTERVAL_SECS = 1
MONIT_RESTART_THRESHOLD_SECS = 320
MONIT_CHECK_INTERVAL_SECS = 5


# Helper functions
def get_dict_stdout(gnmi_out, certs_out):
    """ Extracts dictionary from redis output.
    """
    gnmi_list = []
    gnmi_list = get_list_stdout(gnmi_out) + get_list_stdout(certs_out)
    # Elements in list alternate between key and value. Separate them and combine into a dict.
    key_list = gnmi_list[0::2]
    value_list = gnmi_list[1::2]
    params_dict = dict(zip(key_list, value_list))
    return params_dict

def get_list_stdout(cmd_out):
    out_list = []
    for x in cmd_out:
        result = x.encode('UTF-8')
        out_list.append(result)
    return out_list


def setup_telemetry_forpyclient(duthost):
    """ Set client_auth=false. This is needed for pyclient to sucessfully set up channel with gnmi server.
        Restart telemetry process
    """
    client_auth_out = duthost.shell('sonic-db-cli CONFIG_DB HGET "TELEMETRY|gnmi" "client_auth"', module_ignore_errors=False)['stdout_lines']
    client_auth = str(client_auth_out[0])
    if client_auth == "true":
        duthost.shell('sonic-db-cli CONFIG_DB HSET "TELEMETRY|gnmi" "client_auth" "false"', module_ignore_errors=False)
        duthost.service(name="telemetry", state="restarted")
    else:
        logger.info('client auth is false. No need to restart telemetry')


def generate_client_cli(duthost, method=METHOD_GET, xpath="COUNTERS/Ethernet0", target="COUNTERS_DB", subscribe_mode=SUBSCRIBE_MODE_STREAM, submode=SUBMODE_SAMPLE, intervalms=0, update_count=3):
    """Generate the py_gnmicli command line based on the given params.
    """
    cmdFormat = 'python /root/gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m {2} -x {3} -xt {4} -o {5}'
    cmd = cmdFormat.format(duthost.mgmt_ip, TELEMETRY_PORT, method, xpath, target, "ndastreamingservertest")

    if method == METHOD_SUBSCRIBE:
        cmd += " --subscribe_mode {0} --submode {1} --interval {2} --update_count {3}".format(subscribe_mode, submode, intervalms, update_count)
    return cmd


def assert_equal(actual, expected, message):
    """Helper method to compare an expected value vs the actual value.
    """
    pytest_assert(actual == expected, "{0}. Expected {1} vs actual {2}".format(message, expected, actual))


@pytest.fixture(scope="module", autouse=True)
def verify_telemetry_dockerimage(duthosts, rand_one_dut_hostname):
    """If telemetry docker is available in image then return true
    """
    docker_out_list = []
    duthost = duthosts[rand_one_dut_hostname]
    docker_out = duthost.shell('docker images docker-sonic-telemetry', module_ignore_errors=False)['stdout_lines']
    docker_out_list = get_list_stdout(docker_out)
    matching = [s for s in docker_out_list if "docker-sonic-telemetry" in s]
    if not (len(matching) > 0):
        pytest.skip("docker-sonic-telemetry is not part of the image")


@pytest.fixture
def setup_streaming_telemetry(duthosts, rand_one_dut_hostname, localhost,  ptfhost):
    """
    @summary: Post setting up the streaming telemetry before running the test.
    """
    duthost = duthosts[rand_one_dut_hostname]
    setup_telemetry_forpyclient(duthost)

    # Wait until telemetry was restarted
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "telemetry"), "TELEMETRY not started.")
    logger.info("telemetry process restarted. Now run pyclient on ptfdocker")

    # Wait until the TCP port was opened
    dut_ip = duthost.mgmt_ip
    wait_tcp_connection(localhost, dut_ip, TELEMETRY_PORT, timeout_s=60)

    # pyclient should be available on ptfhost. If it was not available, then fail pytest.
    file_exists = ptfhost.stat(path="/root/gnxi/gnmi_cli_py/py_gnmicli.py")
    pytest_assert(file_exists["stat"]["exists"] is True)


def skip_201911_and_older(duthost):
    """ Skip the current test if the DUT version is 201911 or older.
    """
    if parse_version(duthost.kernel_version) <= parse_version('4.9.0'):
        pytest.skip("Test not supported for 201911 images. Skipping the test")


def test_config_db_parameters(duthosts, rand_one_dut_hostname):
    """Verifies required telemetry parameters from config_db.
    """
    duthost = duthosts[rand_one_dut_hostname]

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


def test_telemetry_enabledbydefault(duthosts, rand_one_dut_hostname):
    """Verify telemetry should be enabled by default
    """
    duthost = duthosts[rand_one_dut_hostname]

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


def test_telemetry_ouput(duthosts, rand_one_dut_hostname, ptfhost, setup_streaming_telemetry, localhost):
    """Run pyclient from ptfdocker and show gnmi server outputself.
    """
    duthost = duthosts[rand_one_dut_hostname]

    logger.info('start telemetry output testing')
    dut_ip = duthost.mgmt_ip
    cmd = 'python /root/gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m get -x COUNTERS/Ethernet0 -xt COUNTERS_DB \
           -o "ndastreamingservertest"'.format(dut_ip, TELEMETRY_PORT)
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    inerrors_match = re.search("SAI_PORT_STAT_IF_IN_ERRORS", result)
    pytest_assert(inerrors_match is not None, "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi_output")


def test_osbuild_version(duthosts, rand_one_dut_hostname, ptfhost, localhost):
    """ Test osbuild/version query.
    """
    duthost = duthosts[rand_one_dut_hostname]
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(duthost=duthost, method=METHOD_GET, target="OTHERS", xpath="osversion/build")
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    result = str(show_gnmi_out)

    assert_equal(len(re.findall('"build_version": "sonic\.', result)), 1, "build_version value at {0}".format(result))
    assert_equal(len(re.findall('sonic\.NA', result, flags=re.IGNORECASE)), 0, "invalid build_version value at {0}".format(result))


def test_sysuptime(duthosts, rand_one_dut_hostname, ptfhost, setup_streaming_telemetry, localhost):
    """
    @summary: Run pyclient from ptfdocker and test the dataset 'system uptime' to check
              whether the value of 'system uptime' was float number and whether the value was
              updated correctly.
    """
    logger.info("start test the dataset 'system uptime'")
    duthost = duthosts[rand_one_dut_hostname]
    skip_201911_and_older(duthost)
    dut_ip = duthost.mgmt_ip
    cmd = 'python /root/gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m get -x proc/uptime -xt OTHERS \
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


def test_virtualdb_table_streaming(duthosts, rand_one_dut_hostname, ptfhost, localhost):
    """Run pyclient from ptfdocker to stream a virtual-db query multiple times.
    """
    logger.info('start virtual db sample streaming testing')

    duthost = duthosts[rand_one_dut_hostname]
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(duthost=duthost, method=METHOD_SUBSCRIBE, update_count = 3)
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    result = str(show_gnmi_out)

    assert_equal(len(re.findall('Max update count reached 3', result)), 1, "Streaming update count in:\n{0}".format(result))
    assert_equal(len(re.findall('name: "Ethernet0"\n', result)), 4, "Streaming updates for Ethernet0 in:\n{0}".format(result)) # 1 for request, 3 for response
    assert_equal(len(re.findall('timestamp: \d+', result)), 3, "Timestamp markers for each update message in:\n{0}".format(result))


def run_gnmi_client(ptfhost, dut_ip):
    """Runs python gNMI client in the corresponding PTF docker to query valid/invalid
    tables from 'STATE_DB'.

    Args:
        pfthost: PTF docker binding to the selected DuT.
        dut_ip: Mgmt IP of DuT.

    Returns:
        None.
    """
    gnmi_cli_cmd = 'python /root/gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m subscribe --subscribe_mode 0\
                   -x DOCKER_STATS,TEST_STATS -xt STATE_DB -o ndastreamingservertest --trigger_mem_spike &'.format(dut_ip, TELEMETRY_PORT)
    logger.info("Starting to run python gNMI client with command '{}' in PTF docker '{}'"
                .format(gnmi_cli_cmd, ptfhost.mgmt_ip))
    ptfhost.shell(gnmi_cli_cmd)


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
        temp_config_line: A stirng to replace the initial Monit configuration.

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

    '''
    logger.info("Checks whether Monit is running or not after restarted ...")
    is_monit_running = wait_until(MONIT_RESTART_THRESHOLD_SECS,
                                  MONIT_CHECK_INTERVAL_SECS,
                                  0,
                                  check_monit_running,
                                  duthost)
    pytest_assert(is_monit_running, "Monit is not running after restarted!")
    logger.info("Monit is running!")
    '''


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


@pytest.fixture
def test_mem_spike_setup_and_cleanup(duthosts, rand_one_dut_hostname, setup_streaming_telemetry, request):
    """Customizes Monit configuration files before testing and restores them after testing.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: The fixture returns a randomly selected DuT.
        pfthost: PTF docker binding to the selected DuT.

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


@pytest.mark.parametrize("test_mem_spike_setup_and_cleanup",
                         ['    if status == 3 for 1 times within 2 cycles then exec "/usr/bin/restart_service telemetry" repeat every 2 cycles'],
                         indirect=["test_mem_spike_setup_and_cleanup"])
def test_mem_spike(duthosts, rand_one_dut_hostname, ptfhost, test_mem_spike_setup_and_cleanup):
    """Test whether telemetry will be restarted or not by Monit if python gNMI client
    continuously creates TCP connections but did not explicitly close them.

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

    skip_201911_and_older(duthost)

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
    client_thread.apply_async(run_gnmi_client, (ptfhost, dut_ip))

    logger.info("Sleep '{}' seconds to wait for the syslog messages related to '{}' container restarted ..."
                .format(WAITING_SYSLOG_MSG_SECS, CONTAINER_NAME))
    time.sleep(WAITING_SYSLOG_MSG_SECS)

    logger.info("Checking the syslog messages related to '{}' container restarted ...".format(CONTAINER_NAME))
    loganalyzer.analyze(marker)
    logger.info("Found all the expected syslog messages!")

    logger.info("Checking whether the '{}' container is running after testing...".format(CONTAINER_NAME))
    is_running = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                            CONTAINER_CHECK_INTERVAL_SECS,
                            0,
                            check_container_state, duthost, CONTAINER_NAME, True)
    pytest_assert(is_running, "'{}' is not running on DuT!".format(CONTAINER_NAME))
    logger.info("'{}' is running on DuT!".format(CONTAINER_NAME))

    postcheck_critical_processes(duthost, CONTAINER_NAME)
