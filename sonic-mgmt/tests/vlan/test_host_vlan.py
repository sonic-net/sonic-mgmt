import contextlib
import pytest
import random
import time
import tempfile

from scapy.all import sniff
from ptf import testutils

from tests.common.dualtor.mux_simulator_control import mux_server_url                                   # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # lgtm[py/unused-import]
from tests.common.utilities import is_ipv4_address
from tests.common.utilities import wait_until
from tests.common.utilities import skip_release


pytestmark = [
    pytest.mark.topology("t0")
]

DUT_VLAN_INTF_MAC = "00:00:11:22:33:44"
DUT_ICMP_DUMP_FILE = "/tmp/icmp.pcap"
HOST_PORT_FLOODING_CHECK_COUNT = 5
ICMP_PKT_SRC_IP = "1.1.1.1"
ICMP_PKT_COUNT = 10
ICMP_PKT_FINGERPRINT = "HOSTVLANFLOODINGTEST"


@contextlib.contextmanager
def log_icmp_updates(duthost, iface, save_path):
    """Capture icmp packets to file."""
    start_pcap = "tcpdump -i %s -w %s icmp" % (iface, save_path)
    stop_pcap = "pkill -f '%s'" % start_pcap
    start_pcap = "nohup %s &" % start_pcap
    duthost.shell(start_pcap)
    try:
        yield
    finally:
        duthost.shell(stop_pcap, module_ignore_errors=True)


@pytest.fixture(scope="module")
def testbed_params(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    skip_release(duthost, ["201811", "201911"])
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    vlan_intf_name = mg_facts["minigraph_vlans"].keys()[0]
    vlan_member_ports = mg_facts["minigraph_vlans"][vlan_intf_name]["members"]
    vlan_member_ports_to_ptf_ports = {_: mg_facts["minigraph_ptf_indices"][_] for _ in vlan_member_ports}
    vlan_intf = [_ for _ in mg_facts["minigraph_vlan_interfaces"] if _["attachto"] == vlan_intf_name and is_ipv4_address(_["addr"])][0]
    return vlan_intf, vlan_member_ports_to_ptf_ports


@pytest.fixture(scope="module")
def verify_host_port_vlan_membership(duthosts, rand_one_dut_hostname, testbed_params):
    vlan_intf, vlan_member_ports_to_ptf_ports = testbed_params
    vlan_id = vlan_intf["attachto"].lstrip("Vlan")
    duthost = duthosts[rand_one_dut_hostname]
    bridge_vlan_show = duthost.shell("bridge vlan show vid %s" % vlan_id)["stdout"]
    bridge_vlan_host_ports = set([line.split()[0] for line in bridge_vlan_show.splitlines() if line])
    for vlan_member_port in vlan_member_ports_to_ptf_ports.keys():
        if vlan_member_port not in bridge_vlan_host_ports:
            raise ValueError("Port %s not in host bridge VLAN %s" % (vlan_member_port, vlan_id))

def get_new_vlan_intf_mac_mellanox(dut_vlan_intf_mac):
    '''
        Get a new dut vlan interface mac address for Mellanox dut
        Args:
            dut_vlan_intf_mac: the original mac address of the switch
        Returns:
            new_dut_vlan_intf_mac: the new mac address
    '''
    dut_vlan_intf_mac_last_octet = dut_vlan_intf_mac.split(':')[-1]
    # Get a different mac address under the same mac prefix, flap the bits in the last octet
    new_dut_vlan_intf_mac_last_octet = hex(int(dut_vlan_intf_mac_last_octet, 16) ^ 255).strip('0x')
    new_dut_vlan_intf_mac = dut_vlan_intf_mac.split(':')
    new_dut_vlan_intf_mac[-1] = new_dut_vlan_intf_mac_last_octet
    new_dut_vlan_intf_mac = ':'.join(new_dut_vlan_intf_mac)
    return new_dut_vlan_intf_mac

@pytest.fixture(scope="module")
def setup_host_vlan_intf_mac(duthosts, rand_one_dut_hostname, testbed_params, verify_host_port_vlan_membership):
    vlan_intf, _ = testbed_params
    duthost = duthosts[rand_one_dut_hostname]
    dut_vlan_mac = duthost.get_dut_iface_mac('%s' % vlan_intf["attachto"])
    # There is a restriction in configuring interface mac address on Mellanox asics, assign a valid value for the vlan interface mac address
    global DUT_VLAN_INTF_MAC
    if duthost.get_facts()['asic_type'] == 'mellanox':
        DUT_VLAN_INTF_MAC = get_new_vlan_intf_mac_mellanox(dut_vlan_mac)
    duthost.shell('redis-cli -n 4 hmset "VLAN|%s" mac %s' % (vlan_intf["attachto"], DUT_VLAN_INTF_MAC))
    wait_until(10, 2, 2, lambda: duthost.get_dut_iface_mac(vlan_intf["attachto"]) == DUT_VLAN_INTF_MAC)

    yield
    
    duthost.shell('redis-cli -n 4 hmset "VLAN|%s" mac %s' % (vlan_intf["attachto"], dut_vlan_mac))
    wait_until(10, 2, 2, lambda: duthost.get_dut_iface_mac(vlan_intf["attachto"]) == dut_vlan_mac)


def test_host_vlan_no_floodling(
    duthosts,
    rand_one_dut_hostname,
    ptfadapter,
    setup_host_vlan_intf_mac,
    testbed_params,
    toggle_all_simulator_ports_to_rand_selected_tor,
):
    """
    Aims to verify that for packets detinated to the host vlan interface, the packets should not be flooding
    in the host bridge vlan member ports.
    """
    duthost = duthosts[rand_one_dut_hostname]
    vlan_intf, vlan_member_ports_to_ptf_ports = testbed_params
    vlan_intf_mac = duthost.get_dut_iface_mac(vlan_intf["attachto"])
    selected_test_ports = random.sample(vlan_member_ports_to_ptf_ports, HOST_PORT_FLOODING_CHECK_COUNT + 1)
    test_dut_port = selected_test_ports[0]
    test_ptf_port = vlan_member_ports_to_ptf_ports[test_dut_port]
    test_ptf_port_mac = ptfadapter.dataplane.get_mac(0, test_ptf_port)
    dut_ports_to_check = selected_test_ports[1:]

    icmp_pkt = testutils.simple_icmp_packet(
        eth_dst=vlan_intf_mac,
        eth_src=test_ptf_port_mac,
        ip_src=ICMP_PKT_SRC_IP,
        ip_dst=vlan_intf["addr"],
        icmp_data=ICMP_PKT_FINGERPRINT
    )

    ptfadapter.before_send = lambda *kargs, **kwargs: time.sleep(.5)
    for dut_port_to_check in dut_ports_to_check:
        with log_icmp_updates(duthost, iface=dut_port_to_check, save_path=DUT_ICMP_DUMP_FILE):
            testutils.send(ptfadapter, test_ptf_port, icmp_pkt, count=ICMP_PKT_COUNT)

        with tempfile.NamedTemporaryFile() as tmp_pcap:
            duthost.fetch(src=DUT_ICMP_DUMP_FILE, dest=tmp_pcap.name, flat=True)
            icmp_pkts = sniff(offline=tmp_pcap.name)

            if len([_ for _ in icmp_pkts if ICMP_PKT_FINGERPRINT in str(_)]) > 0:
                pytest.fail("Received ICMP packet destinated to VLAN interface %s on host interface %s" % (vlan_intf["attachto"], dut_port_to_check))
