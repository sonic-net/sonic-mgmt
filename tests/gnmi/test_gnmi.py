import pytest
import logging

from tests.common.helpers.gnmi_utils import gnmi_capabilities, add_gnmi_client_common_name, \
                                            del_gnmi_client_common_name
from .helper import gnmi_set, dump_gnmi_log, gnmi_subscribe_streaming_sample
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure


logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


def test_gnmi_capabilities(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI capabilities
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnmi_capabilities(duthost, localhost)
    assert ret == 0, (
        "GNMI capabilities command failed (non-zero return code).\n"
        "- Error message: {}"
    ).format(msg)

    assert "sonic-db" in msg, (
        "'sonic-db' not found in GNMI capabilities response message.\n"
        "- Actual message: {}"
    ).format(msg)

    assert "JSON_IETF" in msg, (
        "'JSON_IETF' not found in GNMI capabilities response message.\n"
        "- Actual message: {}"
    ).format(msg)


def test_gnmi_capabilities_authenticate(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI capabilities with different roles
    '''
    duthost = duthosts[rand_one_dut_hostname]

    with allure.step("Verify GNMI capabilities with noaccess role"):
        role = "gnmi_noaccess"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        ret, msg = gnmi_capabilities(duthost, localhost)
        assert ret != 0, (
            "GNMI capabilities authenticate with noaccess role command unexpectedly succeeded "
            "(zero return code) for a client with noaccess role.\n"
            "- Error message: {}"
        ).format(msg)

        assert role in msg, (
            "Expected role '{}' in GNMI capabilities authenticate with noaccess role response, but got: {}"
        ).format(role, msg)

    with allure.step("Verify GNMI capabilities with readonly role"):
        role = "gnmi_readonly"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        ret, msg = gnmi_capabilities(duthost, localhost)
        assert ret == 0, (
            "GNMI capabilities authenticate readonly command failed (non-zero return code).\n"
            "- Error message: {}"
        ).format(msg)

        assert "sonic-db" in msg, (
            "Expected 'sonic-db' in GNMI capabilities authenticate with readonly role response, but got: {}"
        ).format(msg)

        assert "JSON_IETF" in msg, (
            "Expected 'JSON_IETF' in GNMI capabilities authenticate with readonly role  response, but got: {}"
        ).format(msg)

    with allure.step("Verify GNMI capabilities with readwrite role"):
        role = "gnmi_readwrite"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        ret, msg = gnmi_capabilities(duthost, localhost)
        assert ret == 0, (
            "GNMI capabilities authenticate readwrite role command failed (non-zero return code).\n"
            "- Error message: {}"
        ).format(msg)

        assert "sonic-db" in msg, (
            "Expected 'sonic-db' in GNMI capabilities with readwrite role response, but got: {}"
        ).format(msg)

        assert "JSON_IETF" in msg, (
            "Expected 'JSON_IETF' in GNMI capabilities  with readwrite role response, but got: {}"
        ).format(msg)

    with allure.step("Verify GNMI capabilities with empty role"):
        role = ""
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        ret, msg = gnmi_capabilities(duthost, localhost)
        assert ret == 0, (
            "GNMI capabilities authenticate with empty role command failed (non-zero return code).\n"
            "- Error message: {}"
        ).format(msg)

        assert "sonic-db" in msg, (
            "Expected 'sonic-db' in GNMI capabilities with empty role response, but got: {}"
        ).format(msg)

        assert "JSON_IETF" in msg, (
            "Expected 'JSON_IETF' in GNMI capabilities with empty role response, but got: {}"
        ).format(msg)

    # Restore default role
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


@pytest.fixture(scope="function")
def setup_invalid_client_cert_cname(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    add_gnmi_client_common_name(duthost, "invalid.cname")

    keys = duthost.shell('sudo sonic-db-cli CONFIG_DB keys GNMI*')["stdout_lines"]
    logger.debug("GNMI client cert keys: {}".format(keys))

    yield

    del_gnmi_client_common_name(duthost, "invalid.cname")
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def gnmi_create_vnet(duthost, ptfhost, cert=None):
    file_name = "vnet.txt"
    text = "{\"Vnet1\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE:@/root/%s" % (file_name)]
    msg = ""
    try:
        gnmi_set(duthost, ptfhost, [], update_list, [], cert)
    except Exception as e:
        logger.info("Failed to set: " + str(e))
        msg = str(e)

    gnmi_log = dump_gnmi_log(duthost)

    return msg, gnmi_log


def test_gnmi_authorize_failed_with_invalid_cname(duthosts,
                                                  rand_one_dut_hostname,
                                                  ptfhost,
                                                  setup_invalid_client_cert_cname):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    msg, gnmi_log = gnmi_create_vnet(duthost, ptfhost)

    assert "Unauthenticated" in msg, (
        "'Unauthenticated' error message not found in GNMI response. "
        "- Actual message: '{}'"
    ).format(msg)

    assert "Failed to retrieve cert common name mapping" in gnmi_log, (
        "'Failed to retrieve cert common name mapping' message not found in GNMI log. "
        "- Actual GNMI log: '{}'"
    ).format(gnmi_log)


@pytest.fixture(scope="function")
def setup_crl_server_on_ptf(ptfhost, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    # Determine which address to bind the CRL server to
    dut_facts = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts']
    is_mgmt_ipv6_only = dut_facts.get('is_mgmt_ipv6_only', False)

    if is_mgmt_ipv6_only and ptfhost.mgmt_ipv6:
        # Bind to IPv6 address when DUT is IPv6-only
        bind_addr = ptfhost.mgmt_ipv6
        logger.info(f"DUT is IPv6-only, binding CRL server to IPv6: {bind_addr}")
    else:
        # Bind to all interfaces (default behavior) for IPv4 or mixed environments
        bind_addr = ''
        logger.info("Binding CRL server to all interfaces (IPv4 compatible)")

    ptfhost.shell('rm -f /root/crl.log')

    # Start CRL server with appropriate bind address
    if bind_addr:
        ptfhost.shell(f'nohup /root/env-python3/bin/python /root/crl_server.py --bind {bind_addr} &')
    else:
        ptfhost.shell('nohup /root/env-python3/bin/python /root/crl_server.py &')

    logger.warning("crl server started")

    # Wait untill HTTP server ready
    def server_ready_log_exist(ptfhost):
        res = ptfhost.shell("sed -n '/Ready handle request/p'  /root/crl.log", module_ignore_errors=True)
        logger.debug("crl.log: {}".format(res["stdout_lines"]))
        return len(res["stdout_lines"]) > 0

    wait_until(60, 1, 0, server_ready_log_exist, ptfhost)
    logger.warning("crl server ready")

    yield

    # pkill will use the kill signal -9 as exit code, need ignore error
    ptfhost.shell("pkill -9 -f '/root/env-python3/bin/python /root/crl_server.py'", module_ignore_errors=True)


def test_gnmi_subscribe_sample(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI subscribe sample request
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Skip test for supervisor nodes as they don't have Ethernet0 frontpanel port
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    interval_ms = 5000  # 5 second interval
    count = 5

    def validates_subscribe_sample(output: str):
        respCnt = output.count("response received")

        # expected <count> responses + 1 sync response
        assert respCnt == count + 1, f"expected {count + 1} responses, got {respCnt}"

        timestamps = [ts for ts in output.split("\n") if "timestamp" in ts]
        for i in range(len(timestamps) - 1):
            if i == 0:
                break
            # format "timestamp: <timestamp in nanoseconds>"
            currTs = int(timestamps[i].split(': ')[1])
            nextTs = int(timestamps[i + 1].split(': ')[1])
            # round to the nearest second
            assert round(nextTs - currTs, -8) == 5000000000, (
                "expected 5 second timestamp diff," f"currTs: {currTs}, nextTs: {nextTs}"
            )

        logger.info(f"Successfully received exactly {count} gNMI subscribe sample responses")

    with allure.step("Perform gNMI subscribe sample request to state DB"):
        stdout_msg, _ = gnmi_subscribe_streaming_sample(
            duthost, ptfhost,  ["/PSU_INFO"], interval_ms, count, target="STATE_DB"
        )
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)

    with allure.step("Perform gNMI subscribe sample request to sonic DB"):
        stdout_msg, _ = gnmi_subscribe_streaming_sample(
            duthost, ptfhost, ["/COUNTERS_DB/localhost/COUNTERS"], interval_ms, count, origin="sonic-db"
        )
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)


def test_gnmi_authorize_failed_with_revoked_cert(duthosts,
                                                 rand_one_dut_hostname,
                                                 ptfhost,
                                                 setup_crl_server_on_ptf):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]

    retry = 3
    msg = ""
    gnmi_log = ""
    while retry > 0:
        retry -= 1
        msg, gnmi_log = gnmi_create_vnet(duthost, ptfhost, "gnmiclient.revoked")
        # retry when download crl failed, ptf device network not stable
        if "desc = Peer certificate revoked" in gnmi_log:
            break

    assert "Unauthenticated" in msg, (
        "'Unauthenticated' error message not found in GNMI response. "
        "- Actual message: '{}'"
    ).format(msg)

    assert "desc = Peer certificate revoked" in gnmi_log, (
        "'desc = Peer certificate revoked' message not found in GNMI log. "
        "- Actual GNMI log: '{}'"
    ).format(gnmi_log)
