import pytest
import logging

from tests.common.helpers.gnmi_utils import add_gnmi_client_common_name, \
                                            del_gnmi_client_common_name
from .helper import gnmi_set, dump_gnmi_log, gnmi_subscribe_streaming_sample
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.pygnmi_client import PygnmiClient, PygnmiClientCallError, PygnmiClientConnectionError  # noqa: F401


logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server")
]


def test_gnmi_capabilities(duthosts, rand_one_dut_hostname, gnmi_tls):
    '''
    Verify GNMI capabilities
    '''
    with allure.step("Verify GNMI capabilities response"):
        result = gnmi_tls.pygnmi_client.capabilities()
        assert "gnmi_version" in result, (
            "'gnmi_version' key not found in GNMI capabilities response.\n"
            "- Actual keys: {}"
        ).format(list(result.keys()))

        assert any(enc == "json_ietf" for enc in result.get("supported_encodings", [])), (
            "'json_ietf' not found in GNMI capabilities supported_encodings.\n"
            "- Actual encodings: {}"
        ).format(result.get("supported_encodings", []))

        assert any("sonic-db" in m.get("name", "") for m in result.get("supported_models", [])), (
            "'sonic-db' not found in any supported_models name.\n"
            "- Actual models: {}"
        ).format([m.get("name") for m in result.get("supported_models", [])])


def test_gnmi_capabilities_authenticate(duthosts, rand_one_dut_hostname, gnmi_tls):
    '''
    Verify GNMI capabilities with different roles
    '''
    duthost = duthosts[rand_one_dut_hostname]

    try:
        with allure.step("Verify GNMI capabilities with noaccess role"):
            add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", "gnmi_noaccess")
            with pytest.raises((PygnmiClientCallError, PygnmiClientConnectionError)) as exc_info:
                gnmi_tls.pygnmi_client.capabilities()
            error = str(exc_info.value).lower()
            assert "does not have access" in error or \
                   "permission denied" in error or "unauthenticated" in error, (
                "Expected an authorization error for noaccess role, but got: {}"
            ).format(str(exc_info.value))

        with allure.step("Verify GNMI capabilities with readonly role"):
            add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", "gnmi_readonly")
            result = gnmi_tls.pygnmi_client.capabilities()
            assert "gnmi_version" in result, (
                "'gnmi_version' key not found in capabilities response for readonly role.\n"
                "- Actual keys: {}"
            ).format(list(result.keys()))
            assert any(enc == "json_ietf" for enc in result.get("supported_encodings", [])), (
                "'json_ietf' not found in supported_encodings for readonly role.\n"
                "- Actual encodings: {}"
            ).format(result.get("supported_encodings", []))
            assert any("sonic-db" in m.get("name", "") for m in result.get("supported_models", [])), (
                "'sonic-db' not found in any supported_models name for readonly role.\n"
                "- Actual models: {}"
            ).format([m.get("name") for m in result.get("supported_models", [])])

        with allure.step("Verify GNMI capabilities with readwrite role"):
            add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", "gnmi_readwrite")
            result = gnmi_tls.pygnmi_client.capabilities()
            assert "gnmi_version" in result, (
                "'gnmi_version' key not found in capabilities response for readwrite role.\n"
                "- Actual keys: {}"
            ).format(list(result.keys()))
            assert any(enc == "json_ietf" for enc in result.get("supported_encodings", [])), (
                "'json_ietf' not found in supported_encodings for readwrite role.\n"
                "- Actual encodings: {}"
            ).format(result.get("supported_encodings", []))
            assert any("sonic-db" in m.get("name", "") for m in result.get("supported_models", [])), (
                "'sonic-db' not found in any supported_models name for readwrite role.\n"
                "- Actual models: {}"
            ).format([m.get("name") for m in result.get("supported_models", [])])

        with allure.step("Verify GNMI capabilities with empty role"):
            add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", "")
            result = gnmi_tls.pygnmi_client.capabilities()
            assert "gnmi_version" in result, (
                "'gnmi_version' key not found in capabilities response for empty role.\n"
                "- Actual keys: {}"
            ).format(list(result.keys()))
            assert any(enc == "json_ietf" for enc in result.get("supported_encodings", [])), (
                "'json_ietf' not found in supported_encodings for empty role.\n"
                "- Actual encodings: {}"
            ).format(result.get("supported_encodings", []))
            assert any("sonic-db" in m.get("name", "") for m in result.get("supported_models", [])), (
                "'sonic-db' not found in any supported_models name for empty role.\n"
                "- Actual models: {}"
            ).format([m.get("name") for m in result.get("supported_models", [])])

    finally:
        # Restore default role so subsequent tests start from a known state
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


@pytest.fixture(scope="function")
def setup_invalid_client_cert_cname(duthosts, rand_one_dut_hostname, gnmi_tls):
    duthost = duthosts[rand_one_dut_hostname]
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    add_gnmi_client_common_name(duthost, "invalid.cname")

    keys = duthost.shell('sudo sonic-db-cli CONFIG_DB keys GNMI*')["stdout_lines"]
    logger.debug("GNMI client cert keys: {}".format(keys))

    yield

    del_gnmi_client_common_name(duthost, "invalid.cname")
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def gnmi_create_vnet(duthost, pygnmi_client: PygnmiClient):
    vnet_value = {"Vnet1": {"vni": "1000", "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2"}}
    msg = ""
    try:
        pygnmi_client.set(update=[("/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE", vnet_value)])
    except (PygnmiClientCallError, PygnmiClientConnectionError) as e:
        msg = str(e)

    gnmi_log = dump_gnmi_log(duthost)

    return msg, gnmi_log


def test_gnmi_authorize_failed_with_invalid_cname(duthosts,
                                                  rand_one_dut_hostname,
                                                  setup_invalid_client_cert_cname,
                                                  gnmi_tls):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    msg, gnmi_log = gnmi_create_vnet(duthost, gnmi_tls.pygnmi_client)

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


def test_gnmi_subscribe_sample(duthosts, rand_one_dut_hostname, ptfhost,
                               setup_gnmi_server, setup_gnmi_rotated_server,
                               check_dut_timestamp):
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


@pytest.mark.parametrize(
    "gnmi_tls", [{"transport": "tls", "crl": True}], indirect=True)
def test_gnmi_authorize_failed_with_revoked_cert(duthosts,
                                                 rand_one_dut_hostname,
                                                 gnmi_tls):
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
        revoked_client = None
        msg = ""
        try:
            revoked_client = PygnmiClient(
                gnmi_tls.host,
                gnmi_tls.port,
                ca_cert=gnmi_tls.revoked_cert_paths.ca_cert,
                client_cert=gnmi_tls.revoked_cert_paths.client_cert,
                client_key=gnmi_tls.revoked_cert_paths.client_key,
                connect=False,
            )
            revoked_client.set(update=[(
                "/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE",
                {"Vnet1": {
                    "vni": "1000",
                    "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2",
                }},
            )])
        except (PygnmiClientCallError, PygnmiClientConnectionError) as e:
            msg = str(e)
        finally:
            if revoked_client is not None:
                revoked_client.close()
        gnmi_log = dump_gnmi_log(duthost)
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
