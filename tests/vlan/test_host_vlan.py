import contextlib
import pytest
import random
import time
import tempfile
import json

from scapy.all import sniff, Raw
from ptf import testutils

from tests.common.dualtor.mux_simulator_control import mux_server_url                                   # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa: F401
from tests.common.utilities import is_ipv4_address, is_ipv6_address
from tests.common.utilities import wait_until, delete_running_config
from tests.common.utilities import skip_release
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology("t0", "m0", "mx", 't0-2vlans')
]

DUT_VLAN_INTF_MAC = "00:00:11:22:33:44"
DUT_ICMP_DUMP_FILE = "/tmp/icmp.pcap"
HOST_PORT_FLOODING_CHECK_COUNT = 5
ICMP_PKT_SRC_IP = "1.1.1.1"
ICMP_PKT_SRC_IPV6 = "2001:db8::1"
ICMP_PKT_COUNT = 10
ICMP_PKT_FINGERPRINT = "HOSTVLANFLOODINGTEST"


@contextlib.contextmanager
def log_icmp_updates(duthost, iface, save_path, ns_arg=""):
    """Capture icmp packets to file."""
    start_pcap = "tcpdump -i %s -w %s icmp or icmp6" % (iface, save_path)
    stop_pcap = "pkill -f '%s'" % start_pcap
    start_pcap = "nohup %s%s &" % (ns_arg, start_pcap)
    duthost.shell(start_pcap)
    try:
        yield
    finally:
        duthost.shell(stop_pcap, module_ignore_errors=True)


@pytest.fixture(scope="module")
def vlan_asic(duthosts, rand_one_dut_hostname, tbinfo):
    """
    On multi-ASIC DUTs, return the first front-end ASIC with a VLAN: the VLAN, its member ports and its
    CONFIG_DB entry are in the namespace of that ASIC, not in the host namespace.
    Return None on single-ASIC DUTs.
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not duthost.is_multi_asic:
        return None
    for asic in duthost.frontend_asics:
        if asic.get_extended_minigraph_facts(tbinfo)["minigraph_vlans"]:
            return asic
    pytest.fail("No front-end ASIC with a VLAN on %s" % duthost.hostname)


@pytest.fixture(scope="module")
def testbed_params(duthosts, rand_one_dut_hostname, tbinfo, vlan_asic):
    duthost = duthosts[rand_one_dut_hostname]
    skip_release(duthost, ["201811", "201911"])
    mg_facts = (vlan_asic or duthost).get_extended_minigraph_facts(tbinfo)

    vlan_intf_name = list(mg_facts["minigraph_vlans"].keys())[0]
    vlan_member_ports = mg_facts["minigraph_vlans"][vlan_intf_name]["members"]
    vlan_member_ports_to_ptf_ports = {_: mg_facts["minigraph_ptf_indices"][_] for _ in vlan_member_ports}

    # Try to find IPv4 address first, fall back to IPv6 if not found
    vlan_intf_ipv4 = [_ for _ in mg_facts["minigraph_vlan_interfaces"] if _["attachto"] == vlan_intf_name
                      and is_ipv4_address(_["addr"])]
    vlan_intf_ipv6 = [_ for _ in mg_facts["minigraph_vlan_interfaces"] if _["attachto"] == vlan_intf_name
                      and is_ipv6_address(_["addr"])]

    # Prefer IPv4, but use IPv6 if no IPv4 is available
    if vlan_intf_ipv4:
        vlan_intf = vlan_intf_ipv4[0]
    elif vlan_intf_ipv6:
        vlan_intf = vlan_intf_ipv6[0]
    else:
        pytest.fail("No IPv4 or IPv6 address found for VLAN interface %s" % vlan_intf_name)

    return vlan_intf, vlan_member_ports_to_ptf_ports


def get_vlan_intf_mac(duthost, vlan_asic, vlan_intf_name):
    if vlan_asic is None:
        return duthost.get_dut_iface_mac(vlan_intf_name)
    return duthost.command("%scat /sys/class/net/%s/address" % (vlan_asic.ns_arg, vlan_intf_name))["stdout"]


@pytest.fixture(scope="module")
def verify_host_port_vlan_membership(duthosts, rand_one_dut_hostname, testbed_params, vlan_asic):
    vlan_intf, vlan_member_ports_to_ptf_ports = testbed_params
    vlan_id = vlan_intf["attachto"].lstrip("Vlan")
    duthost = duthosts[rand_one_dut_hostname]
    ns_arg = vlan_asic.ns_arg if vlan_asic else ""
    bridge_vlan_show = duthost.shell("%sbridge vlan show vid %s" % (ns_arg, vlan_id))["stdout"]
    bridge_vlan_host_ports = set([line.split()[0] for line in bridge_vlan_show.splitlines() if line])
    for vlan_member_port in list(vlan_member_ports_to_ptf_ports.keys()):
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
def setup_host_vlan_intf_mac(duthosts, rand_one_dut_hostname, testbed_params, verify_host_port_vlan_membership, tbinfo,
                             vlan_asic):
    vlan_intf, _ = testbed_params
    duthost = duthosts[rand_one_dut_hostname]
    config_db_cmd = "redis-cli -n 4" if vlan_asic is None else "%s CONFIG_DB" % vlan_asic.sonic_db_cli
    dut_vlan_mac = get_vlan_intf_mac(duthost, vlan_asic, vlan_intf["attachto"])
    orig_cfg_vlan_mac = None
    if vlan_asic is not None:
        orig_cfg_vlan_mac = duthost.shell('%s hget "VLAN|%s" mac' % (config_db_cmd, vlan_intf["attachto"]))["stdout"]
        orig_cfg_vlan_mac = orig_cfg_vlan_mac.strip()
    # There is a restriction in configuring interface mac address on Mellanox asics,
    # assign a valid value for the vlan interface mac address
    global DUT_VLAN_INTF_MAC
    if duthost.get_facts()['asic_type'] == 'mellanox':
        DUT_VLAN_INTF_MAC = get_new_vlan_intf_mac_mellanox(dut_vlan_mac)
    duthost.shell('%s hmset "VLAN|%s" mac %s' % (config_db_cmd, vlan_intf["attachto"], DUT_VLAN_INTF_MAC))
    pytest_assert(wait_until(10, 2, 2,
                             lambda: get_vlan_intf_mac(duthost, vlan_asic, vlan_intf["attachto"]) == DUT_VLAN_INTF_MAC),
                  "Failed to set mac address for vlan interface %s" % vlan_intf["attachto"])

    yield

    # Restore the original mac address of the vlan interface
    duthost.shell('%s hmset "VLAN|%s" mac %s' % (config_db_cmd, vlan_intf["attachto"], dut_vlan_mac))
    pytest_assert(wait_until(10, 2, 2,
                             lambda: get_vlan_intf_mac(duthost, vlan_asic, vlan_intf["attachto"]) == dut_vlan_mac),
                  "Failed to restore mac address for vlan interface %s" % vlan_intf["attachto"])

    if vlan_asic is not None:
        # configlet only updates the CONFIG_DB of the host namespace, restore the mac field in the ASIC namespace
        if orig_cfg_vlan_mac:
            duthost.shell('%s hset "VLAN|%s" mac %s' % (config_db_cmd, vlan_intf["attachto"], orig_cfg_vlan_mac))
        else:
            duthost.shell('%s hdel "VLAN|%s" mac' % (config_db_cmd, vlan_intf["attachto"]))
    elif "dualtor" not in tbinfo["topo"]["name"]:
        del_vlan_json = json.loads("""
                [{
                    "VLAN":{
                        "%s":{
                            "mac": "%s"
                        }
                    }
                }]
            """ % (vlan_intf["attachto"], dut_vlan_mac))
        delete_running_config(del_vlan_json, duthost)


def test_host_vlan_no_floodling(
    duthosts,
    rand_one_dut_hostname,
    ptfadapter,
    setup_host_vlan_intf_mac,
    testbed_params,
    vlan_asic,
    toggle_all_simulator_ports_to_rand_selected_tor,    # noqa: F811
):
    """
    Aims to verify that for packets detinated to the host vlan interface, the packets should not be flooding
    in the host bridge vlan member ports.
    """
    duthost = duthosts[rand_one_dut_hostname]
    vlan_intf, vlan_member_ports_to_ptf_ports = testbed_params
    vlan_intf_mac = get_vlan_intf_mac(duthost, vlan_asic, vlan_intf["attachto"])
    selected_test_ports = random.sample(list(vlan_member_ports_to_ptf_ports), HOST_PORT_FLOODING_CHECK_COUNT + 1)
    test_dut_port = selected_test_ports[0]
    test_ptf_port = vlan_member_ports_to_ptf_ports[test_dut_port]
    test_ptf_port_mac = ptfadapter.dataplane.get_mac(0, test_ptf_port)
    dut_ports_to_check = selected_test_ports[1:]

    # Determine if we're using IPv4 or IPv6 and create appropriate ICMP packet
    is_ipv4 = is_ipv4_address(vlan_intf["addr"])

    if is_ipv4:
        icmp_pkt = testutils.simple_icmp_packet(
            eth_dst=vlan_intf_mac,
            eth_src=test_ptf_port_mac,
            ip_src=ICMP_PKT_SRC_IP,
            ip_dst=vlan_intf["addr"],
            icmp_data=ICMP_PKT_FINGERPRINT
        )
    else:
        # For IPv6, simple_icmpv6_packet doesn't support icmp_data parameter
        # So we build the packet and add Raw payload manually
        icmp_pkt = testutils.simple_icmpv6_packet(
            eth_dst=vlan_intf_mac,
            eth_src=test_ptf_port_mac,
            ipv6_src=ICMP_PKT_SRC_IPV6,
            ipv6_dst=vlan_intf["addr"]
        )
        # Add custom payload data to the ICMPv6 packet for fingerprinting
        icmp_pkt = icmp_pkt / Raw(load=ICMP_PKT_FINGERPRINT)

    ptfadapter.before_send = lambda *kargs, **kwargs: time.sleep(.5)
    for dut_port_to_check in dut_ports_to_check:
        with log_icmp_updates(duthost, iface=dut_port_to_check, save_path=DUT_ICMP_DUMP_FILE,
                              ns_arg=vlan_asic.ns_arg if vlan_asic else ""):
            testutils.send(ptfadapter, test_ptf_port, icmp_pkt, count=ICMP_PKT_COUNT)

        with tempfile.NamedTemporaryFile() as tmp_pcap:
            duthost.fetch(src=DUT_ICMP_DUMP_FILE, dest=tmp_pcap.name, flat=True)
            icmp_pkts = sniff(offline=tmp_pcap.name)

            if len([_ for _ in icmp_pkts if ICMP_PKT_FINGERPRINT in str(_)]) > 0:
                pytest.fail("Received ICMP packet destinated to VLAN interface %s on host interface %s" %
                            (vlan_intf["attachto"], dut_port_to_check))
