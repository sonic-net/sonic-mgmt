import logging
import pytest
import time
import json

import grpc

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.gnmi_audit import collect_rpc_timeout_evidence, get_diagnostic_log_cursors
from tests.common.helpers.gnmi_connection import build_native_set_request, gnmi_connection

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp")
]


def get_first_interface(duthost):
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    port_table = cfg_facts["PORT"]

    # Find the first interface with lanes (physical port, not portchannel)
    for interface_name, interface_config in port_table.items():
        if 'lanes' in interface_config:
            # Check if admin status is up
            if interface_config.get('admin_status', '').lower() == 'up':
                return interface_name

    # If no interface with admin_status up found, return the first one with lanes
    for interface_name, interface_config in port_table.items():
        if 'lanes' in interface_config:
            return interface_name

    return None


def test_gnmi_latency_01(duthosts, rand_one_dut_hostname, ptfhost, gnmi_tls):  # noqa: F811
    '''
    Verify GNMI native write latency
    Update interface description repeatedly and check latency
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("gnmi test relies on port data not present on supervisor card '%s'" % rand_one_dut_hostname)
    interface = get_first_interface(duthost)
    if interface is None:
        pytest.skip("No valid interface found on DUT '%s'" % rand_one_dut_hostname)

    test_loop = 10
    text = "\"down\""
    down_list = ["/sonic-db:CONFIG_DB/localhost/PORT/%s/description" % interface]
    down_request = build_native_set_request(down_list[0].split(":", 1)[1].split("/"), json.loads(text))
    text = "\"up\""
    up_list = ["/sonic-db:CONFIG_DB/localhost/PORT/%s/description" % interface]
    up_request = build_native_set_request(up_list[0].split(":", 1)[1].split("/"), json.loads(text))

    # Initialize latency tracking
    total_latencies = []

    cursors = get_diagnostic_log_cursors(duthost)
    calls = []
    try:
        with gnmi_connection(gnmi_tls) as (channel, client):
            grpc.channel_ready_future(channel).result(timeout=30)
            logger.info("Latency measures paired Set calls on a ready shared TLS channel; "
                        "excludes legacy PTF/CLI setup")
            for i in range(test_loop):
                logger.info(f"Starting iteration {i+1}/{test_loop}")
                for value, rpc_request in (("down", down_request), ("up", up_request)):
                    call = {"iteration": i + 1, "value": value, "path": down_list[0],
                            "started_at": time.time(), "deadline_seconds": 60, "status": "started"}
                    calls.append(call)
                    started = time.monotonic()
                    try:
                        client.Set(rpc_request, timeout=60)
                        call["status"] = "OK"
                    except grpc.RpcError as error:
                        call["status"] = error.code().name
                        raise
                    finally:
                        call["elapsed_seconds"] = time.monotonic() - started
                        logger.info("GNMI_SET_CALL %s", json.dumps(call))

                total_latency = sum(call["elapsed_seconds"] for call in calls[-2:]) / 2 * 1000
                total_latencies.append(total_latency)
                logger.info(f"Total iteration latency: {total_latency:.2f} ms")
    except grpc.RpcError as error:
        # The shared channel has closed: Ansible may now fork safely. Collect
        # before fixture rollback changes the configuration under investigation.
        if error.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            try:
                collect_rpc_timeout_evidence(
                    duthost, cursors, calls, "/gnmi.gNMI/Set", "test.client.gnmi.sonic",
                    down_list[0].split(":", 1)[1], timeout=60)
            except Exception:
                logger.exception("Failed to collect gNMI timeout evidence; preserving original RPC error")
        raise

    # Calculate and log statistics
    avg_total = sum(total_latencies) / len(total_latencies)
    min_total = min(total_latencies)
    max_total = max(total_latencies)

    logger.info("=== GNMI SET LATENCY STATISTICS ===")
    logger.info(f"Total per iteration - Avg: {avg_total:.2f}ms, Min: {min_total:.2f}ms, Max: {max_total:.2f}ms")
    logger.info(f"Test completed: {test_loop} iterations on interface {interface}")
    cmd = "lscpu"
    output = duthost.shell(cmd)
    logger.info("CPU Info:\n%s" % output['stdout'])
