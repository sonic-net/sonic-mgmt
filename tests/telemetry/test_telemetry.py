import time
import threading
import logging
import re
import pytest
import random

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from telemetry_utils import assert_equal, get_list_stdout, get_dict_stdout, skip_201911_and_older
from telemetry_utils import generate_client_cli, parse_gnmi_output, check_gnmi_cli_running

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

METHOD_SUBSCRIBE = "subscribe"
METHOD_GET = "get"
MEMORY_CHECKER_WAIT = 1
MEMORY_CHECKER_CYCLES = 60
SUBMODE_ONCHANGE = 1


def test_config_db_parameters(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verifies required telemetry parameters from config_db.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)

    gnmi = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "%s|gnmi"' % (env.gnmi_config_table),
                         module_ignore_errors=False)['stdout_lines']
    pytest_assert(gnmi is not None,
                  "%s|gnmi does not exist in config_db" % (env.gnmi_config_table))

    certs = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "%s|certs"' % (env.gnmi_config_table),
                          module_ignore_errors=False)['stdout_lines']
    pytest_assert(certs is not None,
                  "%s|certs does not exist in config_db" % (env.gnmi_config_table))

    d = get_dict_stdout(gnmi, certs)
    for key, value in list(d.items()):
        if str(key) == "port":
            port_expected = str(env.gnmi_port)
            pytest_assert(str(value) == port_expected,
                          "'port' value is not '{}'".format(port_expected))
        if str(key) == "ca_crt":
            ca_crt_value_expected = "/etc/sonic/telemetry/dsmsroot.cer"
            pytest_assert(str(value) == ca_crt_value_expected,
                          "'ca_crt' value is not '{}'".format(ca_crt_value_expected))
        if str(key) == "server_key":
            server_key_expected = "/etc/sonic/telemetry/streamingtelemetryserver.key"
            pytest_assert(str(value) == server_key_expected,
                          "'server_key' value is not '{}'".format(server_key_expected))
        if str(key) == "server_crt":
            server_crt_expected = "/etc/sonic/telemetry/streamingtelemetryserver.cer"
            pytest_assert(str(value) == server_crt_expected,
                          "'server_crt' value is not '{}'".format(server_crt_expected))


def test_telemetry_enabledbydefault(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify telemetry should be enabled by default
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)

    status = duthost.shell('sonic-db-cli CONFIG_DB HGETALL "FEATURE|%s"' % (env.gnmi_container),
                           module_ignore_errors=False)['stdout_lines']
    status_list = get_list_stdout(status)
    # Elements in list alternate between key and value. Separate them and combine into a dict.
    status_key_list = status_list[0::2]
    status_value_list = status_list[1::2]
    status_dict = dict(list(zip(status_key_list, status_value_list)))
    for k, v in list(status_dict.items()):
        if str(k) == "status":
            status_expected = "enabled"
            pytest_assert(str(v) == status_expected,
                          "Telemetry feature is not enabled")


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_telemetry_ouput(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                         setup_streaming_telemetry, gnxi_path):
    """Run pyclient from ptfdocker and show gnmi server outputself.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    if duthost.is_supervisor_node():
        pytest.skip(
            "Skipping test as no Ethernet0 frontpanel port on supervisor")
    logger.info('start telemetry output testing')
    dut_ip = duthost.mgmt_ip
    cmd = 'python ' + gnxi_path + 'gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m get -x COUNTERS/Ethernet0 -xt COUNTERS_DB \
           -o "ndastreamingservertest"'.format(dut_ip, env.gnmi_port)
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    inerrors_match = re.search("SAI_PORT_STAT_IF_IN_ERRORS", result)
    pytest_assert(inerrors_match is not None,
                  "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi_output")


def test_osbuild_version(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, gnxi_path):
    """ Test osbuild/version query.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path,
                              method=METHOD_GET, target="OTHERS", xpath="osversion/build")
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    result = str(show_gnmi_out)

    assert_equal(len(re.findall(r'"build_version": "SONiC\.', result)),
                 1, "build_version value at {0}".format(result))
    assert_equal(len(re.findall(r'SONiC\.NA', result, flags=re.IGNORECASE)),
                 0, "invalid build_version value at {0}".format(result))


def test_sysuptime(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, gnxi_path):
    """
    @summary: Run pyclient from ptfdocker and test the dataset 'system uptime' to check
              whether the value of 'system uptime' was float number and whether the value was
              updated correctly.
    """
    logger.info("start test the dataset 'system uptime'")
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    skip_201911_and_older(duthost)
    dut_ip = duthost.mgmt_ip
    cmd = 'python ' + gnxi_path + 'gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m get -x proc/uptime -xt OTHERS \
           -o "ndastreamingservertest"'.format(dut_ip, env.gnmi_port)
    system_uptime_info = ptfhost.shell(cmd)["stdout_lines"]
    system_uptime_1st = 0
    found_system_uptime_field = False
    for line_info in system_uptime_info:
        if "total" in line_info:
            try:
                system_uptime_1st = float(line_info.split(":")[1].strip())
                found_system_uptime_field = True
            except ValueError as err:
                pytest.fail(
                    "The value of system uptime was not a float. Error message was '{}'".format(err))

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
                pytest.fail(
                    "The value of system uptime was not a float. Error message was '{}'".format(err))

    if not found_system_uptime_field:
        pytest.fail("The field of system uptime was not found.")

    if system_uptime_2nd - system_uptime_1st < 10:
        pytest.fail("The value of system uptime was not updated correctly.")


def test_virtualdb_table_streaming(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, gnxi_path):
    """Run pyclient from ptfdocker to stream a virtual-db query multiple times.
    """
    logger.info('start virtual db sample streaming testing')

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip(
            "Skipping test as no Ethernet0 frontpanel port on supervisor")
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(
        duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE, update_count=3)
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    result = str(show_gnmi_out)

    assert_equal(len(re.findall('Max update count reached 3', result)),
                 1, "Streaming update count in:\n{0}".format(result))
    assert_equal(len(re.findall('name: "Ethernet0"\n', result)), 4,
                 "Streaming updates for Ethernet0 in:\n{0}".format(result))  # 1 for request, 3 for response
    assert_equal(len(re.findall(r'timestamp: \d+', result)), 3,
                 "Timestamp markers for each update message in:\n{0}".format(result))


def invoke_py_cli_from_ptf(ptfhost, cmd, callback):
    ret = ptfhost.shell(cmd)
    assert ret["rc"] == 0, "PTF docker did not get a response"
    callback(ret["stdout"])


def test_on_change_updates(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, gnxi_path):
    logger.info("Testing on change update notifications")

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              submode=SUBMODE_ONCHANGE, update_count=2, xpath="NEIGH_STATE_TABLE",
                              target="STATE_DB")

    bgp_nbrs = list(duthost.get_bgp_neighbors().keys())
    bgp_neighbor = random.choice(bgp_nbrs)
    bgp_info = duthost.get_bgp_neighbor_info(bgp_neighbor)
    original_state = bgp_info["bgpState"]
    new_state = "Established" if original_state.lower() == "active" else "Active"

    def callback(result):
        logger.info("Assert that ptf client output is non empty and contains on change update")
        try:
            assert result != "", "Did not get output from PTF client"
        finally:
            duthost.shell("sonic-db-cli STATE_DB HSET \"NEIGH_STATE_TABLE|{}\" \"state\" {}".format(bgp_neighbor,
                                                                                                    original_state))
        ret = parse_gnmi_output(result, 1, bgp_neighbor)
        assert ret is True, "Did not find key in update"

    client_thread = threading.Thread(target=invoke_py_cli_from_ptf, args=(ptfhost, cmd, callback,))
    client_thread.start()

    wait_until(5, 1, 0, check_gnmi_cli_running, ptfhost)
    duthost.shell("sonic-db-cli STATE_DB HSET \"NEIGH_STATE_TABLE|{}\" \"state\" {}".format(bgp_neighbor,
                                                                                            new_state))
    client_thread.join(60)  # max timeout of 60s, expect update to come in <=30s


@pytest.mark.disable_loganalyzer
def test_mem_spike(duthosts, rand_one_dut_hostname, ptfhost, gnxi_path):
    """Test whether memory usage of telemetry container will exceed threshold
    if python gNMI client continuously creates channels with gNMI server.
    """
    logger.info("Starting to test the memory spike issue of telemetry container")

    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)

    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              xpath="DOCKER_STATS", target="STATE_DB", update_count=1, create_connections=2000)
    client_thread = threading.Thread(target=invoke_py_cli_from_ptf, args=(ptfhost, cmd, None))
    client_thread.start()

    for i in range(MEMORY_CHECKER_CYCLES):
        ret = duthost.shell("python3 /usr/bin/memory_checker %s 419430400" % (env.gnmi_container),
                            module_ignore_errors=True)
        assert ret["rc"] == 0, "Memory utilization has exceeded threshold"
        time.sleep(MEMORY_CHECKER_WAIT)

    client_thread.join()
