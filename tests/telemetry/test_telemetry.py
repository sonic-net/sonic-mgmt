import time

import logging
import re
import pytest

from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import restart_container_and_check_running
from tests.common.utilities import wait_until, wait_tcp_connection

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
    cmdFormat = 'python /gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m {2} -x {3} -xt {4} -o {5}'
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
    file_exists = ptfhost.stat(path="/gnxi/gnmi_cli_py/py_gnmicli.py")
    pytest_assert(file_exists["stat"]["exists"] is True)

def skip_201911_and_older(duthost):
    """ Skip the current test if the DUT version is 201911 or older.
    """
    if parse_version(duthost.kernel_version) <= parse_version('4.9.0'):
        pytest.skip("Test not supported for 201911 images. Skipping the test")

# Test functions
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
    cmd = 'python /gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m get -x COUNTERS/Ethernet0 -xt COUNTERS_DB \
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
    cmd = 'python /gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m get -x proc/uptime -xt OTHERS \
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
    """Runs gNMI client in the corresponding PTF docker.

    Args:
        pfthost: PTF docker binding to the selected DuT.
        dut_ip: Mgmt IP of DuT.

    Returns:
        None.
    """
    gnmi_cli_cmd = 'python /gnxi/gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m subscribe --trigger_mem_spike \
                    -x DOCKER_STATS -xt STATE_DB -o "ndastreamingservertest" &'.format(dut_ip, TELEMETRY_PORT)
    logger.info("Starting gNMI client command in PTF docker: {}".format(gnmi_cli_cmd))
    cmd_result = ptfhost.shell(gnmi_cli_cmd)
    exit_code = cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to run gNMI client in PTF docker!")


def terminate_gnmi_client(ptfhost):
    """Terminate the gNMI client running in the PTF docker.

    Args:
        pfthost: PTF docker binding to the selected DuT.

    Returns:
        None.
    """
    gnmi_client_pid = ""

    ps_cmd = "ps -aux | grep 'python /gnxi/gnmi_cli_py/py_gnmicli' | grep -v grep"
    logger.info("Running ps command to get process information of gNMI client: {}".format(ps_cmd))
    for line in ptfhost.shell(ps_cmd)["stdout_lines"]:
        if "py_gnmicli" in line:
            gnmi_client_pid = line.split()[1].strip()

        if not gnmi_client_pid:
            pytest.fail("Failed to find PID of gNMI client in PTF docker!")

        logger.info("PID of gNMI client in PTF docker is: '{}'".format(gnmi_client_pid))
        terminate_client_cmd = "kill -9 {}".format(gnmi_client_pid)
        logger.info("Terminating gNMI client with PID: '{}' ...".format(gnmi_client_pid))
        terminate_cmd_result = ptfhost.shell(terminate_client_cmd)
        exit_code = terminate_cmd_result["rc"]
        pytest_assert(exit_code == 0, "Failed to terminate gNMI client with PID '{}'!".format(gnmi_client_pid))
        logger.info("gNMI client with PID: '{}' was terminated!".format(gnmi_client_pid))


def test_mem_spike(duthosts, rand_one_dut_hostname, ptfhost):
    """Test whether memory usage on gNMI server will increase or not if gNMI client
    continuously creates TCP connections but did not explicitly close them.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: The fixture returns a randomly selected DuT.
        pfthost: PTF docker binding to the selected DuT.

    Returns:
        None.
    """
    logger.info("Start testing the memory spike issue on gNMI server side ...")

    duthost = duthosts[rand_one_dut_hostname]
    skip_201911_and_older(duthost)

    dut_ip = duthost.mgmt_ip
    client_thread = threading.Thread(target=run_gnmi_client, args=(ptfhost, dut_ip))
    client_thread.start()

    mem_usage_val = 0
    for index in range(CHECK_MEM_USAGE_COUNTER):
        get_mem_usage_cmd = "docker stats --no-stream --format \{{\{{.MemUsage\}}\}} {}".format(CONTAINER_NAME)
        mem_info = duthost.shell(get_mem_usage_cmd)["stdout_lines"]
        if not mem_info:
            pytest.fail("Failed to get memory usage of '{}'!".format(CONTAINER_NAME))
        mem_usage = mem_info[0].split()[0]
        logger.info("Memory usage of '{}' is: '{}'.".format(CONTAINER_NAME, mem_usage))

        try:
            mem_val = float(mem_usage[:-3])
        except ValueError as err:
            pytest.fail("Failed to convert the memory usage of telemetry from string to float type!")

        pytest_assert(mem_val > mem_usage_val, "Memory usage of telemetry did not increase as expected!")
        mem_usage_val = mem_val
        # Wait for 2 seconds such that memory usage can continuously increase
        time.sleep(2)

    terminate_gnmi_client(ptfhost)

    logger.info("Restarting '{}' container ...".format(CONTAINER_NAME))
    restart_container_and_check_running(duthost, CONTAINER_NAME)
    logger.info("Container '{}' was restarted!".format(CONTAINER_NAME))

    logger.info("Testing the memory spike issue on gNMI server side was done!")
