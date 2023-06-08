"""
This module tests ARP scenarios specific to dual ToR testbeds
"""
from ipaddress import ip_address, ip_interface
import logging
import random
import time
import pytest

import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, \
    show_muxcable_status, config_dualtor_arp_responder      # noqa F401
from tests.common.dualtor.dual_tor_common import mux_config     # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service, \
    change_mac_addresses, run_icmp_responder, pause_garp_service  # noqa F401

from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('dualtor')
]

logger = logging.getLogger(__name__)

FAILED = "FAILED"
INCOMPLETE = "INCOMPLETE"
STALE = "STALE"
REACHABLE = "REACHABLE"


@pytest.fixture
def restore_mux_auto_config(duthosts):
    """
    Fixture to ensure ToRs have all mux interfaces set to auto after testing
    """

    yield

    for duthost in duthosts:
        duthost.shell("sudo config mux mode auto all")


@pytest.fixture
def pause_arp_update(duthosts):
    """
    Temporarily stop arp_update process during test cases

    Some test cases manually call arp_update so we use this fixture to pause it on
    the testbed to prevent interference with the test case
    """
    arp_update_stop_cmd = "docker exec -t swss supervisorctl stop arp_update"
    for duthost in duthosts:
        duthost.shell(arp_update_stop_cmd)

    yield

    arp_update_start_cmd = "docker exec -t swss supervisorctl start arp_update"
    for duthost in duthosts:
        duthost.shell(arp_update_start_cmd)


@pytest.fixture(params=['IPv4', 'IPv6'])
def neighbor_ip(request, mux_config):       # noqa F811
    """
    Provide the neighbor IP used for testing

    Randomly select an IP from the server IPs configured in the config DB MUX_CABLE table
    """
    ip_version = request.param
    selected_intf = random.choice(list(mux_config.values()))
    neigh_ip = ip_interface(selected_intf["SERVER"][ip_version]).ip
    logger.info("Using {} as neighbor IP".format(neigh_ip))
    return neigh_ip


@pytest.fixture
def clear_neighbor_table(duthosts, pause_arp_update, pause_garp_service):       # noqa F811
    logger.info("Clearing neighbor table on {}".format(duthosts))
    for duthost in duthosts:
        duthost.shell("sudo ip neigh flush all")

    return


def verify_neighbor_status(duthost, neigh_ip, expected_status):
    ip_version = 'v4' if ip_address(neigh_ip).version == 4 else 'v6'
    neighbor_table = duthost.switch_arptable()['ansible_facts']['arptable']
    return expected_status.lower() in neighbor_table[ip_version][str(neigh_ip)]['state'].lower()


def test_proxy_arp_for_standby_neighbor(proxy_arp_enabled, ip_and_intf_info, restore_mux_auto_config,
                                        ptfadapter, packets_for_test, upper_tor_host,   # noqa F811
                                        toggle_all_simulator_ports_to_upper_tor):   # noqa F811
    """
    Send an ARP request or neighbor solicitation (NS) to the DUT for an IP address
    within the subnet of the DUT's VLAN that is routed via the IPinIP tunnel
    (i.e. that IP points to a standby neighbor)

    DUT should reply with an ARP reply or neighbor advertisement (NA) containing the DUT's own MAC

    Test steps:
    1. During setup, learn neighbor IPs on ToR interfaces using `run_garp_service` fixture
    2. Pick a learned IP address as the target IP and generate an ARP request/neighbor solicitation for it
    3. Set the interface this IP is learned on to standby. This will ensure the route for the IP points to the
       IPinIP tunnel
    4. Send the ARP request/NS packet to the ToR on some other active interface
    5. Expect the ToR to still proxy ARP for the IP and send an ARP reply/neighbor advertisement back, even though
       the route for the requested IP is pointing to the tunnel
    """
    # This should never fail since we are only running on dual ToR platforms
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs, check dual ToR configuration')

    ptf_intf_ipv4_addr, _, ptf_intf_ipv6_addr, _, ptf_intf_index = ip_and_intf_info
    ip_version, outgoing_packet, expected_packet = packets_for_test

    if ip_version == 'v4':
        pytest_require(ptf_intf_ipv4_addr is not None, 'No IPv4 VLAN address configured on device')
        intf_name_cmd = "show arp | grep -m 1 '{}' | awk '{{ print $3 }}'".format(ptf_intf_ipv4_addr)
    elif ip_version == 'v6':
        pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')
        intf_name_cmd = "show ndp | grep -m 1 '{}' | awk '{{ print $3 }}'".format(ptf_intf_ipv6_addr)

    # Find the interface on which the target IP is learned and set it to standby to force it to point to a tunnel route
    intf_name = upper_tor_host.shell(intf_name_cmd)['stdout']
    mux_mode_cmd = "sudo config mux mode standby {}".format(intf_name)
    upper_tor_host.shell(mux_mode_cmd)
    pytest_assert(wait_until(5, 1, 0, lambda: show_muxcable_status(upper_tor_host)[intf_name]['status'] == "standby"),
                  "Interface {} not standby on {}".format(intf_name, upper_tor_host))
    ptfadapter.dataplane.flush()
    testutils.send_packet(ptfadapter, ptf_intf_index, outgoing_packet)
    testutils.verify_packet(ptfadapter, expected_packet, ptf_intf_index, timeout=10)


def test_arp_update_for_failed_standby_neighbor(
    config_dualtor_arp_responder, neighbor_ip, clear_neighbor_table,            # noqa F811
    toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host     # noqa F811
):
    """
    Test the standby ToR's ability to recover from having a failed neighbor entry

    Test steps:
    1. For the same neighbor IP, create a failed neighbor entry on the standby ToR
       and a reachable entry on the active ToR
    2. Run `arp_update` on the standby ToR
    3. Verify the failed entry is now incomplete and stays incomplete for 10 seconds
    4. Run `arp_update` on the active ToR
    5. Verify the incomplete entry is now reachable
    """
    # We only use ping to trigger an ARP request from the kernel, so exit early to save time
    ping_cmd = "timeout 0.2 ping -c1 -W1 -i0.2 -n -q {}".format(neighbor_ip)

    # Important to run on lower (standby) ToR first so that the lower ToR neighbor entry will be failed
    # Otherwise, the ARP reply/NA message generated by the active ToR will create a REACHABLE entry on the lowwer ToR
    lower_tor_host.shell(ping_cmd, module_ignore_errors=True)
    pytest_assert(wait_until(5, 1, 0, lambda: verify_neighbor_status(lower_tor_host, neighbor_ip, FAILED)))
    upper_tor_host.shell(ping_cmd, module_ignore_errors=True)
    pytest_assert(wait_until(5, 1, 0, lambda: verify_neighbor_status(upper_tor_host, neighbor_ip, REACHABLE)))

    # For IPv4 neighbors, the ARP reply generated when the upper/active ToR sends an ARP request will also
    # be learned by the lower/standby ToR, so we expect it already be reachable at this stage.
    # However, IPv6 neighbors are not learned by the kernel the same way, so it we expect it the standby ToR
    # neighbor entry to be INCOMPLETE as a result of the arp_update script
    expected_midpoint_state = REACHABLE if ip_address(neighbor_ip).version == 4 else INCOMPLETE

    arp_update_cmd = "docker exec -t swss supervisorctl start arp_update"
    lower_tor_host.shell(arp_update_cmd)
    pytest_assert(wait_until(
        5, 1, 0, lambda: verify_neighbor_status(lower_tor_host, neighbor_ip, expected_midpoint_state)))

    # Need to make sure the entry does not auto-transition to FAILED
    time.sleep(10)
    pytest_assert(verify_neighbor_status(lower_tor_host, neighbor_ip, expected_midpoint_state))

    upper_tor_host.shell(arp_update_cmd)
    pytest_assert(wait_until(5, 1, 0, lambda: verify_neighbor_status(lower_tor_host, neighbor_ip, REACHABLE)))


def test_standby_unsolicited_neigh_learning(
    config_dualtor_arp_responder, neighbor_ip, clear_neighbor_table,            # noqa F811
    toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host     # noqa F811
):
    """
    Test the standby ToR's ability to perform unsolicited neighbor learning (GARP and unsolicited NA)

    Test steps:
    1. Create a reachable neighbor entry on the active ToR only
    2. Run arp_update on the active ToR
    3. Confirm that the standby ToR learned the entry and it is REACHABLE
    """
    ping_cmd = "timeout 0.2 ping -c1 -W1 -i0.2 -n -q {}".format(neighbor_ip)

    upper_tor_host.shell(ping_cmd, module_ignore_errors=True)
    pytest_assert(wait_until(5, 1, 0, lambda: verify_neighbor_status(upper_tor_host, neighbor_ip, REACHABLE)))
    lower_tor_host.shell("sudo ip neigh flush all")

    arp_update_cmd = "docker exec -t swss supervisorctl start arp_update"
    upper_tor_host.shell(arp_update_cmd)

    pytest_assert(wait_until(5, 1, 0, lambda: verify_neighbor_status(lower_tor_host, neighbor_ip, REACHABLE)))
