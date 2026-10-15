import pytest
import logging
import re
import time
import random
import threading
import json
import os
from contextlib import closing

from tests.common.helpers import gnmi_cli_helpers as helper
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.pygnmi_client import Encoding, PygnmiClient, StreamMode
from .helper import gnmi_set, dump_gnmi_log, gnmi_subscribe_streaming_sample, \
                    apply_cert_config, \
                    gnmi_subscribe_stream_connections
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure


logger = logging.getLogger(__name__)
allure.logger = logger

MEMORY_CHECKER_WAIT = 1
MEMORY_CHECKER_CYCLES = 60

SHOW_PATHS_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "cli_paths.json")


@pytest.fixture
def skip_non_container_test(request):
    if not request.config.getoption("--container_test", default=""):
        pytest.skip("Testcase skipped for non container test")


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
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PygnmiClient(
        duthost.mgmt_ip, env.gnmi_port,
        ca_cert="gnmiCA.pem", client_cert="gnmiclient.crt",
        client_key="gnmiclient.key", connect=False,
    )
    msg = client.capabilities()
    assert any(model.get("name") == "sonic-db" for model in msg.get("supported_models", [])), (
        "'sonic-db' not found in GNMI capabilities response message.\n"
        "- Actual message: {}"
    ).format(msg)

    assert "json_ietf" in msg.get("supported_encodings", []), (
        "'JSON_IETF' not found in GNMI capabilities response message.\n"
        "- Actual message: {}"
    ).format(msg)


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
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PygnmiClient(
        duthost.mgmt_ip, env.gnmi_port,
        ca_cert="gnmiCA.pem", client_cert="gnmiclient.crt",
        client_key="gnmiclient.key", connect=False,
    )

    def validates_subscribe_sample(output):
        # The initial synchronized batch must contain data; a sync-only shell
        # does not count as a sample. Multiple fields still count as one batch.
        respCnt = sum(bool(response.get("update", {}).get("update")) for response in output)
        assert respCnt == count, f"expected {count} update responses, got {respCnt}"
        assert output[0].get("sync_response"), "Initial SAMPLE response did not synchronize"

        logger.info(f"Successfully received exactly {count} gNMI subscribe sample responses")

    with allure.step("Perform gNMI subscribe sample request to state DB"):
        stdout_msg = list(client.subscribe(
            ["/PSU_INFO"], sample_interval=interval_ms / 1000, count=count,
            collect_seconds=30, target="STATE_DB", encoding=Encoding.JSON_IETF,
        ))
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)

    with allure.step("Perform gNMI subscribe sample request to sonic DB"):
        stdout_msg = list(client.subscribe(
            ["/COUNTERS_DB/localhost/COUNTERS"], sample_interval=interval_ms / 1000, count=count,
            collect_seconds=30, prefix="sonic-db://", encoding=Encoding.JSON_IETF,
        ))
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


def test_osbuild_version(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI GET of the OTHERS/osversion/build non-DB path returns a valid
    SONiC build_version.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PygnmiClient(
        duthost.mgmt_ip, env.gnmi_port,
        ca_cert="gnmiCA.pem", client_cert="gnmiclient.crt",
        client_key="gnmiclient.key", connect=False,
    )
    msg_list = client.get(["osversion/build"], target="OTHERS")
    result = "\n".join(
        json.dumps(update["val"])
        for notification in msg_list["notification"] for update in notification["update"]
    )

    assert len(re.findall(r'"build_version": "SONiC\.', result)) == 1, (
        "build_version value not found in gnmi output: {}".format(result))
    assert len(re.findall(r'SONiC\.NA', result, flags=re.IGNORECASE)) == 0, (
        "invalid build_version value in gnmi output: {}".format(result))


def _get_sysuptime_total(duthost, ptfhost):
    """GET OTHERS/proc/uptime and return the 'total' field as a float."""
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PygnmiClient(
        duthost.mgmt_ip, env.gnmi_port,
        ca_cert="gnmiCA.pem", client_cert="gnmiclient.crt",
        client_key="gnmiclient.key", connect=False,
    )
    msg_list = client.get(["proc/uptime"], target="OTHERS")
    result = "\n".join(
        json.dumps(update["val"])
        for notification in msg_list["notification"] for update in notification["update"]
    )
    match = re.search(r'"total":\s*([0-9.]+)', result)
    assert match is not None, (
        "system uptime 'total' field not found in gnmi output: {}".format(result))
    return float(match.group(1))


def test_sysuptime(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI GET of the OTHERS/proc/uptime non-DB path returns a float that
    increases over time.
    '''
    duthost = duthosts[rand_one_dut_hostname]

    uptime_first = _get_sysuptime_total(duthost, ptfhost)
    time.sleep(10)
    uptime_second = _get_sysuptime_total(duthost, ptfhost)

    assert uptime_second - uptime_first >= 10, (
        "system uptime did not advance by at least 10s: {} -> {}".format(
            uptime_first, uptime_second))


def test_on_change_updates(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI subscribe ON_CHANGE on STATE_DB NEIGH_STATE_TABLE reports a BGP
    neighbor state change.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    ns = random.choice(duthost.get_asic_namespace_list())
    bgp_neighbor = random.choice(list(duthost.get_bgp_neighbors(ns).keys()))
    asic_id = duthost.get_asic_id_from_namespace(ns)
    original_state = duthost.get_bgp_neighbor_info(bgp_neighbor, asic_id)["bgpState"]
    new_state = "Established" if original_state.lower() == "active" else "Active"

    namespace_name = ns if ns else "localhost"
    path_list = ["/sonic-db:STATE_DB/{}/NEIGH_STATE_TABLE".format(namespace_name)]

    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PygnmiClient(
        duthost.mgmt_ip, env.gnmi_port,
        ca_cert="gnmiCA.pem", client_cert="gnmiclient.crt",
        client_key="gnmiclient.key", connect=False,
    )
    try:
        with closing(client.subscribe(
                path_list, stream_mode=StreamMode.ON_CHANGE, count=2, collect_seconds=60)) as subscription:
            # The native client runs on the runner, not the PTF. Its initial
            # synchronized response establishes readiness before changing state.
            msg = [next(subscription)]
            cmd = "sonic-db-cli STATE_DB HSET \"NEIGH_STATE_TABLE|{}\" \"state\" {}".format(bgp_neighbor, new_state)
            cmd = duthost.get_cli_cmd_for_namespace(cmd, ns)
            duthost.shell(cmd)
            msg.extend(subscription)
    finally:
        # Restore the original neighbor state after closing the subscription.
        cmd = "sonic-db-cli STATE_DB HSET \"NEIGH_STATE_TABLE|{}\" \"state\" {}".format(bgp_neighbor, original_state)
        cmd = duthost.get_cli_cmd_for_namespace(cmd, ns)
        duthost.shell(cmd)

    msg = json.dumps(msg)
    assert msg != "", "Did not get output from native on-change client"
    assert bgp_neighbor in msg, (
        "Did not find neighbor {} in on-change update: {}".format(bgp_neighbor, msg))


def test_mem_spike(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    The gnmi container memory must stay under threshold when a client continuously
    creates channels with the gnmi server.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)

    def client_worker():
        gnmi_subscribe_stream_connections(duthost, ptfhost, ["DOCKER_STATS"], target="STATE_DB",
                                          create_connections=2000, update_count=1)

    client_thread = threading.Thread(target=client_worker)
    client_thread.start()

    for _ in range(MEMORY_CHECKER_CYCLES):
        ret = duthost.shell("python3 /usr/bin/memory_checker %s 419430400" % env.gnmi_container,
                            module_ignore_errors=True)
        assert ret["rc"] == 0, "Memory utilization has exceeded threshold"
        time.sleep(MEMORY_CHECKER_WAIT)

    client_thread.join()


def test_telemetry_show_non_get(duthosts, rand_one_dut_hostname, ptfhost, skip_non_container_test):
    '''
    The SHOW target only supports GET; a SUBSCRIBE must fail.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    msg, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, ["reboot-cause"], 0, 1,
                                             origin=None, target="SHOW")
    assert "error" in msg.lower(), (
        "SHOW subscribe should fail, but got: {}".format(msg))


def test_telemetry_show_get(duthosts, localhost, rand_one_dut_hostname, ptfhost, request,
                            skip_non_container_test):
    '''
    Test all SHOW GET paths from cli_paths.json: run each path's setup, gnmi GET
    against the SHOW target, and verify.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PygnmiClient(
        duthost.mgmt_ip, env.gnmi_port,
        ca_cert="gnmiCA.pem", client_cert="gnmiclient.crt",
        client_key="gnmiclient.key", connect=False,
    )

    # Resolve "duthost" to the DUT selected for this test so setup/verify act on
    # the same host the GET queries (request.getfixturevalue("duthost") would
    # resolve to the session DUT index, which can differ on multi-DUT testbeds).
    def resolve_fixture(fx):
        return duthost if fx == "duthost" else request.getfixturevalue(fx)

    with open(SHOW_PATHS_FILE, 'r') as show_paths_file:
        show_paths_data = json.load(show_paths_file)

    for path, test_config in show_paths_data.items():
        if test_config["setup"]:
            setup_fixtures = [resolve_fixture(fx) for fx in test_config["setup_fixtures"]]
            getattr(helper, test_config["setup"])(*setup_fixtures, *test_config["setup_args"])
            # The setup step reboots the DUT, which drops the non-persistent gnmi
            # cert server; re-apply it so the SHOW GET runs against the configured server.
            apply_cert_config(duthost)

        show_gnmi_out = client.get([path], target="SHOW")

        if test_config["verify"]:
            output = show_gnmi_out["notification"][0]["update"][0]["val"]
            verify_fixtures = [resolve_fixture(fx) for fx in test_config["verify_fixtures"]]
            getattr(helper, test_config["verify"])(*verify_fixtures, *test_config["verify_args"], output)
