import pytest
import logging
import re
import random
import threading

from tests.common.helpers.gnmi_utils import gnmi_capabilities, GNMIEnvironment
from .helper import gnmi_subscribe_streaming_sample, gnmi_get, \
                    gnmi_subscribe_streaming_onchange
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure


logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures(
        "setup_gnmi_ntp_client_server",
        "setup_gnmi_server",
        "check_dut_timestamp",
    )
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


def test_osbuild_version(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI GET of the OTHERS/osversion/build non-DB path returns a valid
    SONiC build_version.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    msg_list = gnmi_get(duthost, ptfhost, ["osversion/build"], target="OTHERS", origin=None)
    result = "\n".join(msg_list)

    assert len(re.findall(r'"build_version": "SONiC\.', result)) == 1, (
        "build_version value not found in gnmi output: {}".format(result))
    assert len(re.findall(r'SONiC\.NA', result, flags=re.IGNORECASE)) == 0, (
        "invalid build_version value in gnmi output: {}".format(result))


def _gnmi_client_connected(duthost, ptfhost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    res = ptfhost.shell('netstat -tn | grep ":{} .*ESTABLISHED"'.format(env.gnmi_port),
                        module_ignore_errors=True)
    return res["rc"] == 0


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

    result_holder = {}

    def subscribe_worker():
        msg, _ = gnmi_subscribe_streaming_onchange(duthost, ptfhost, path_list, 2)
        result_holder["msg"] = msg

    client_thread = threading.Thread(target=subscribe_worker)
    client_thread.start()
    try:
        # Wait for the subscribe client to connect before triggering the change,
        # otherwise the on-change update can be missed.
        wait_until(60, 1, 0, _gnmi_client_connected, duthost, ptfhost)
        cmd = "sonic-db-cli STATE_DB HSET \"NEIGH_STATE_TABLE|{}\" \"state\" {}".format(bgp_neighbor, new_state)
        cmd = duthost.get_cli_cmd_for_namespace(cmd, ns)
        duthost.shell(cmd)
        client_thread.join(60)  # max timeout of 60s, expect update to come in <=30s
    finally:
        # Restore the original neighbor state.
        cmd = "sonic-db-cli STATE_DB HSET \"NEIGH_STATE_TABLE|{}\" \"state\" {}".format(bgp_neighbor, original_state)
        cmd = duthost.get_cli_cmd_for_namespace(cmd, ns)
        duthost.shell(cmd)

    msg = result_holder.get("msg", "")
    assert msg != "", "Did not get output from PTF on-change client"
    assert bgp_neighbor in msg, (
        "Did not find neighbor {} in on-change update: {}".format(bgp_neighbor, msg))
