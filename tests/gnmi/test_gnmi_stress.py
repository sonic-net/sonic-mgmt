import logging
import pytest
import time
import json

import grpc

from tests.gnmi_benchmark.helpers import build_native_set_request, gnmi_connection
from .tls_setup import gnmi_server_context

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


@pytest.fixture(scope="module")
def setup_gnmi_server(duthosts, rand_one_dut_hostname, localhost, ptfhost, vrf_config,
                      setup_vrf_configuration, setup_gnmi_ntp_client_server):
    duthost = duthosts[rand_one_dut_hostname]
    with gnmi_server_context(duthost, localhost, ptfhost, vrf_config) as server:
        yield server


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


def test_gnmi_latency_01(duthosts, rand_one_dut_hostname, ptfhost, setup_gnmi_server):
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

    with gnmi_connection(setup_gnmi_server) as (channel, client):
        grpc.channel_ready_future(channel).result(timeout=30)
        logger.info("Latency measures paired Set calls on a ready shared TLS channel; excludes legacy PTF/CLI setup")
        for i in range(test_loop):
            logger.info(f"Starting iteration {i+1}/{test_loop}")

            # Measure total latency for both operations
            start_time = time.time()

            # Update description
            client.Set(down_request, timeout=30)
            # Update description
            client.Set(up_request, timeout=30)

            total_latency = (time.time() - start_time) / 2 * 1000  # Convert to milliseconds
            total_latencies.append(total_latency)
            logger.info(f"Total iteration latency: {total_latency:.2f} ms")

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
