"""
This module tests ARP scenarios specific to dual ToR testbeds
"""
import ptf.testutils as testutils
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor
from tests.common.dualtor.dual_tor_utils import upper_tor_host, show_muxcable_status  # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_garp_service, change_mac_addresses, run_icmp_responder
from tests.common.utilities import wait_until

pytestmark= [
    pytest.mark.topology('dualtor')
]

@pytest.fixture
def restore_mux_auto_config(duthosts):
    """
    Fixture to ensure ToRs have all mux interfaces set to auto after testing
    """

    yield

    for duthost in duthosts:
        duthost.shell("sudo config mux mode auto all")

def test_proxy_arp_for_standby_neighbor(proxy_arp_enabled, ip_and_intf_info, restore_mux_auto_config,
    ptfadapter, packets_for_test, upper_tor_host, toggle_all_simulator_ports_to_upper_tor):
    """
    Send an ARP request or neighbor solicitation (NS) to the DUT for an IP address within the subnet of the DUT's VLAN that is
    routed via the IPinIP tunnel (i.e. that IP points to a standby neighbor)

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

    ptf_intf_ipv4_addr, _, ptf_intf_ipv6_addr, _, ptf_intf_index  = ip_and_intf_info
    ip_version, outgoing_packet, expected_packet = packets_for_test

    if ip_version == 'v4':
        pytest_require(ptf_intf_ipv4_addr is not None, 'No IPv4 VLAN address configured on device')
        intf_name_cmd = "show arp | grep '{}' | awk '{{ print $3 }}'".format(ptf_intf_ipv4_addr)
    elif ip_version == 'v6':
        pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')
        intf_name_cmd= "show ndp | grep '{}' | awk '{{ print $3 }}'".format(ptf_intf_ipv6_addr)

    # Find the interface on which the target IP is learned and set it to standby to force it to point to a tunnel route
    intf_name = upper_tor_host.shell(intf_name_cmd)['stdout']
    mux_mode_cmd = "sudo config mux mode standby {}".format(intf_name)
    upper_tor_host.shell(mux_mode_cmd)
    pytest_assert(wait_until(5, 1, 0, lambda: show_muxcable_status(upper_tor_host)[intf_name]['status'] == "standby"),
                  "Interface {} not standby on {}".format(intf_name, upper_tor_host))
    ptfadapter.dataplane.flush()
    testutils.send_packet(ptfadapter, ptf_intf_index, outgoing_packet)
    testutils.verify_packet(ptfadapter, expected_packet, ptf_intf_index, timeout=10)
