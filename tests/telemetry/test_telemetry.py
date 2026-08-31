import time
import threading
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from telemetry_utils import get_list_stdout, get_dict_stdout
from telemetry_utils import generate_client_cli

pytestmark = [
    pytest.mark.topology('any', 't1-multi-asic')
]

logger = logging.getLogger(__name__)

METHOD_SUBSCRIBE = "subscribe"
MEMORY_CHECKER_WAIT = 1
MEMORY_CHECKER_CYCLES = 60


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


def invoke_py_cli_from_ptf(ptfhost, cmd, callback):
    ret = ptfhost.shell(cmd)
    assert ret["rc"] == 0, "PTF docker did not get a response"
    if callback is not None:
        callback(ret["stdout"])


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
@pytest.mark.disable_loganalyzer
def test_mem_spike(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, gnxi_path, setup_streaming_telemetry):
    """Test whether memory usage of telemetry container will exceed threshold
    if python gNMI client continuously creates channels with gNMI server.
    """
    logger.info("Starting to test the memory spike issue of telemetry container")

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
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
