"""
1. On a dual ToR testbed, confirm that the tunnel packet handler service is running
in the SWSS container on active Tor (supervisorctl status tunnel_packet_handler)
2. Send a continuous stream of IPinIP packets similar to those sent from the standby
ToR to the active ToR
3. Check SWSS container memory consumption
"""
import pytest
import logging
import random
import time
import contextlib
from ptf import testutils
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type  # noqa F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host  # noqa F401
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import delete_neighbor
from tests.common.helpers.dut_utils import get_program_info
from tests.common.fixtures.ptfhost_utils import run_garp_service, run_icmp_responder    # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                       # noqa F401
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]

PACKET_COUNT = 1000
# It's normal to see the mem usage increased a little bit
# set threshold buffer to 0.03%
MEM_THRESHOLD_BUFFER = 0.03


def validate_neighbor_entry_exist(duthost, neighbor_addr):
    """Validate if neighbor entry exist on duthost

    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        neighbor_addr (str): neighbor's ip address

    Returns:
        bool: True if neighbor exists. Otherwise, return False.
    """
    command = "ip neighbor show %s" % neighbor_addr
    output = [_.strip() for _ in duthost.shell(command)["stdout_lines"]]
    if not output or "REACHABLE" not in output[0]:
        return False
    return True


def is_tunnel_packet_handler_running(duthost):
    """Check if tunnel_packet_handler is running on duthost

    Args:
        duthost (AnsibleHost): Device Under Test (DUT)

    Returns:
        bool: True if tunnel_packet_handler is running. Otherwise, return False.
    """
    status, _ = get_program_info(duthost, "swss", "tunnel_packet_handler")
    return status == 'RUNNING'


def get_memory_info(duthost):
    stdout_lines = duthost.command("docker stats swss --no-stream")["stdout_lines"]
    header = stdout_lines[0]
    # Find the position of category "MEM USAGE", "MEM %" and "NET I/O"
    pos1 = header.index("MEM USAGE")
    pos2 = header.index("MEM %")
    pos3 = header.index("NET I/O")
    if len(stdout_lines) < 2:
        pytest.fail("Collect swss stat failed, swss container may die.")
    line = stdout_lines[-1]
    # Get the value of "MEM USAGE", "LIMIT" and "MEM %"
    mem_info = line[pos1:pos2].strip().split("/")
    mem_usage = mem_info[0].strip()
    mem_limit = mem_info[1].strip()
    mem_percent = line[pos2:pos3].strip()
    return mem_usage, mem_limit, mem_percent


def check_memory_leak(duthost, target_mem_percent, delay=10, timeout=15, interval=5):
    """Check if it has memory leak on duthost with retry

    Args:
        duthost (AnsibleHost): Device Under Test (DUT)
        target_mem_percent: the max threshold of the memory percent
        delay: the delay before the first try
        timeout: the total timeout for the check
        interval: the interval between tries

    Returns:
        bool: True if there is memory leak. Otherwise, return False.
    """

    def _check_memory(duthost):
        mem_usage, _, mem_percent = get_memory_info(duthost)
        mem_percent = float(mem_percent.strip('%'))
        if mem_percent > target_mem_percent:
            logging.error(
                "SWSS container MEM percent exceeds the threshold. current percent:{}%, threshold percent: {}%".format(
                    mem_percent, target_mem_percent))
            return False
        else:
            logging.info(
                "SWSS container MEM percent is in expected range. current percent:{}%, target percent: {}%".format(
                    mem_percent, target_mem_percent))
            return True

    return not wait_until(timeout, interval, delay, _check_memory, duthost)


def test_tunnel_memory_leak(toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host,    # noqa F811
                            ptfhost, ptfadapter, conn_graph_facts, tbinfo, vmhost, run_arp_responder,   # noqa F811
                            skip_traffic_test):                                                         # noqa F811
    """
    Test if there is memory leak for service tunnel_packet_handler.
    Send ip packets from standby TOR T1 to Server, standby TOR will
    forward the packets to active TOR with tunnel, active TOR will
    decapsulate the IPinIP packets, but there is no neighbor for destination
    as we remove neighbor before test, tunnel_packet_handler will be
    triggered and neighbor will be added. Server will receive the packets.
    Check if memory usage is increased after tunnel_packet_handler's
    operation. Since tunnel_packet_handler is only triggered by the
    first packet, loop the process for all severs to trigger it as much
    as possible.
    """
    @contextlib.contextmanager
    def prepare_services(ptfhost):
        """
        Temporarily start arp and icmp service. Make sure to stop garp service,
        otherwise, it will add neighbor entry back automatically.
        It has to stop garp_service for triggering tunnel_packet_handler.
        It has to start arp and icmp service for receiving packets at server side.
        """
        ptfhost.shell("supervisorctl stop garp_service")
        ptfhost.shell("supervisorctl start arp_responder")
        ptfhost.shell("supervisorctl start icmp_responder")
        yield
        ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)
        ptfhost.shell("supervisorctl stop icmp_responder")

    pytest_assert(is_tunnel_packet_handler_running(upper_tor_host),
                  "tunnel_packet_handler is not running in SWSS conainter.")

    ptf_t1_intf = random.choice(get_t1_ptf_ports(lower_tor_host, tbinfo))

    all_servers_ips = mux_cable_server_ip(upper_tor_host)
    unexpected_count = 0
    expected_count = 0

    with prepare_services(ptfhost):
        # Delete the neighbors
        for iface, server_ips in list(all_servers_ips.items()):
            server_ipv4 = server_ips["server_ipv4"].split("/")[0]
            pytest_assert(wait_until(10, 1, 0, delete_neighbor, upper_tor_host, server_ipv4),
                          "server ip {} hasn't been deleted from neighbor table.".format(server_ipv4))
        # sleep 10s to wait memory usage stable
        time.sleep(10)
        # Get the original memory percent before test
        mem_usage, mem_limit, origin_mem_percent = get_memory_info(upper_tor_host)
        logging.info("SWSS MEM USAGE:{} LIMIT:{} PERCENT:{}".format(mem_usage, mem_limit, origin_mem_percent))
        for iface, server_ips in list(all_servers_ips.items()):
            server_ipv4 = server_ips["server_ipv4"].split("/")[0]
            logging.info("Select DUT interface {} and server IP {} to test.".format(iface, server_ipv4))

            pkt, exp_pkt = build_packet_to_server(lower_tor_host, ptfadapter, server_ipv4)

            if skip_traffic_test is True:
                logging.info("Skip traffic test.")
                continue
            server_traffic_monitor = ServerTrafficMonitor(
                upper_tor_host, ptfhost, vmhost, tbinfo, iface,
                conn_graph_facts, exp_pkt, existing=True, is_mocked=False
            )
            try:
                with server_traffic_monitor:
                    testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=PACKET_COUNT)
                    logging.info("Sent {} packets from ptf t1 interface {} on standby TOR {}"
                                 .format(PACKET_COUNT, ptf_t1_intf, lower_tor_host.hostname))
                    # Log memory usage for every operation, used for debugging if test failed
                    mem_usage, mem_limit, mem_percent = get_memory_info(upper_tor_host)
                    logging.info(
                        "SWSS MEM USAGE:{} LIMIT:{} PERCENT:{}".format(mem_usage, mem_limit, mem_percent))
                    if not skip_traffic_test:
                        pytest_assert(validate_neighbor_entry_exist(upper_tor_host, server_ipv4),
                                      "The server ip {} doesn't exist in neighbor table on dut {}. \
                                      tunnel_packet_handler isn't triggered."
                                      .format(server_ipv4, upper_tor_host.hostname))
            except Exception as e:
                logging.error("Capture exception {}, continue the process.".format(repr(e)))
            if len(server_traffic_monitor.matched_packets) == 0:
                logging.error("Didn't receive any expected packets for server {}.".format(server_ipv4))
                unexpected_count += 1
            else:
                expected_count += 1
        logging.info("The amount of expected scenarios: {}, the amount of unexpected scenarios: {}."
                     .format(expected_count, unexpected_count))
        # sleep 10s to wait memory usage stable, check if there is memory leak
        time.sleep(10)
        check_result = check_memory_leak(upper_tor_host, float(origin_mem_percent.strip('%')) + MEM_THRESHOLD_BUFFER)
        pytest_assert(check_result is False, "Test failed because there is memory leak on {}"
                      .format(upper_tor_host.hostname))
