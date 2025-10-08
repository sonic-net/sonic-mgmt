import logging
import pytest
import time

from .helper import gnmi_set

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
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


def test_gnmi_latency_01(duthosts, rand_one_dut_hostname, ptfhost):
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
    down_file = "down.txt"
    down_list = ["/sonic-db:CONFIG_DB/localhost/PORT/%s/description:@/root/%s" % (interface, down_file)]
    with open(down_file, 'w') as file:
        file.write(text)
    text = "\"up\""
    up_file = "up.txt"
    up_list = ["/sonic-db:CONFIG_DB/localhost/PORT/%s/description:@/root/%s" % (interface, up_file)]
    with open(up_file, 'w') as file:
        file.write(text)
    ptfhost.copy(src=down_file, dest='/root')
    ptfhost.copy(src=up_file, dest='/root')

    # Initialize latency tracking
    total_latencies = []

    for i in range(test_loop):
        logger.info(f"Starting iteration {i+1}/{test_loop}")

        # Measure total latency for both operations
        start_time = time.time()

        # Update description
        gnmi_set(duthost, ptfhost, [], down_list, [])
        # Update description
        gnmi_set(duthost, ptfhost, [], up_list, [])

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
