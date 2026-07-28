import ipaddress
import logging
import os
import time

import pytest
from ptf.mask import Mask
from ptf.packet import Ether, IP, IPv6, UDP, TCP
import ptf.testutils as testutils

from tests.common.config_reload import config_reload
from tests.common.fixtures.grpc_fixtures import gnmi_tls    # noqa: F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.vxlan_ecmp_utils import Ecmp_Utils

ecmp_utils = Ecmp_Utils()

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.device_type('physical'),
    pytest.mark.asic('cisco-8000')
]

CONFIG_DB_PATH = '/etc/sonic/config_db.json'
EXABGP_CONFIG_PATH = "/etc/exabgp/exabgp_vnet_bgp.conf"
EXABGP_PORT = 5100

PORTCHANNEL_NAMES = ["PortChannel1031", "PortChannel1032"]
VXLAN_PORT = 4789
TUNNEL_ENDPOINT = "100.0.1.10"
INNER_SRC_IP = "2.2.2.2"
INNER_SRC_MAC = "00:11:22:33:44:55"
INNER_SRC_IPV6 = "2001:db8:2::2"

BASE_VNI = 1000
NUM_VNETS = 2

V6_SUBINT_BASE = "fc00:11::"

VNET_V6_PREFIX_BASE = "2001:db8:30::"
BGP_V6_DECAP_ROUTE = "2001:db8:40::/64"
BGP_V6_DECAP_IP = "2001:db8:40::1"

GNMI_PATH_PREFIX = "CONFIG_DB/localhost"

ACL_TYPE_NAME = "INNER_SRC_MAC_REWRITE_TYPE"
ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"
ACL_TYPE_NAME_V6 = "INNER_SRC_MAC_REWRITE_TYPE_V6"
ACL_TABLE_NAME_V6 = "INNER_SRC_MAC_REWRITE_TABLE_V6"

temp_files = []

RA_SEND_SCRIPT = '''#!/usr/bin/env python3
"""Send periodic IPv6 Router Advertisements out an interface.
Replaces radvd for unnumbered-BGP testing where the peer (FRR) needs to
learn our LL via RA but we don't want radvd / sysctl forwarding=1."""
import argparse
import time

from scapy.all import (
    sendp, get_if_hwaddr, in6_getifaddr,
    Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr,
)


def get_iface_ll(iface):
    for addr, _scope, ifname in in6_getifaddr():
        if ifname == iface and addr.lower().startswith("fe80"):
            return addr
    raise RuntimeError("No fe80::/10 address on %s — bring it up first" % iface)


def build_ra(iface):
    src_mac = get_if_hwaddr(iface)
    src_ll = get_iface_ll(iface)
    return (
        Ether(src=src_mac, dst="33:33:00:00:00:01")
        / IPv6(src=src_ll, dst="ff02::1", hlim=255)        # hlim=255 REQUIRED
        / ICMPv6ND_RA(chlim=64, M=0, O=0,
                      routerlifetime=1800, reachabletime=0, retranstimer=0)
        / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)             # populate peer NDP
    ), src_ll, src_mac


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("--interval", type=float, default=3.0)
    ap.add_argument("--count", type=int, default=0)
    args = ap.parse_args()

    pkt, src_ll, src_mac = build_ra(args.iface)
    print("[ra_send] iface=%s src_ll=%s src_mac=%s interval=%ss" % (
        args.iface, src_ll, src_mac, args.interval), flush=True)

    sent = 0
    while True:
        sendp(pkt, iface=args.iface, verbose=False)
        sent += 1
        if args.count and sent >= args.count:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
'''


def validate_encap_wl_to_t1(duthost, ptfadapter, test_configs):
    """
    Test WL→T1 VXLAN encap with IPv4 and IPv6.
    """
    logger.info("Starting WL to T1 VXLAN encapsulation test...")

    for configs in test_configs:
        for addr_family in ["v4", "v6"]:
            # Build inner TCP packet
            if addr_family == "v4":
                pkt_opts = {
                    "eth_dst": duthost.facts['router_mac'],
                    "eth_src": ptfadapter.dataplane.get_mac(0, configs["outgoing_port"]),
                    "ip_dst": configs["inner_dst_ip_v4"],
                    "ip_src": INNER_SRC_IP,
                    "ip_id": 105,
                    "ip_ttl": 64,
                    "dl_vlan_enable": True,
                    "vlan_vid": configs["vlan"],
                    "tcp_sport": 1234,
                    "tcp_dport": 5000,
                    "pktlen": 100,
                }
                inner_pkt = testutils.simple_tcp_packet(**pkt_opts)
            else:
                pkt_opts = {
                    "eth_dst": duthost.facts['router_mac'],
                    "eth_src": ptfadapter.dataplane.get_mac(0, configs["outgoing_port"]),
                    "ipv6_dst": configs["inner_dst_ip_v6"],
                    "ipv6_src": INNER_SRC_IPV6,
                    "ipv6_hlim": 64,
                    "dl_vlan_enable": True,
                    "vlan_vid": configs["vlan"],
                    "tcp_sport": 1234,
                    "tcp_dport": 5000,
                    "pktlen": 100,
                }
                inner_pkt = testutils.simple_tcpv6_packet(**pkt_opts)

        pkt_opts["eth_src"] = INNER_SRC_MAC    # expected rewritten inner src MAC
        pkt_opts["eth_dst"] = configs["expected_dst_mac"]
        pkt_opts["dl_vlan_enable"] = False
        pkt_opts.pop("vlan_vid", None)
        pkt_opts["pktlen"] = 96

        if addr_family == "v4":
            pkt_opts["ip_ttl"] = 63
            inner_exp_pkt = testutils.simple_tcp_packet(**pkt_opts)
        else:
            pkt_opts["ipv6_hlim"] = 63
            inner_exp_pkt = testutils.simple_tcpv6_packet(**pkt_opts)

        expected_pkt = testutils.simple_vxlan_packet(
            eth_dst="aa:bb:cc:dd:ee:ff",
            eth_src=duthost.facts['router_mac'],
            ip_src=configs["expected_src_ip"],
            ip_dst=configs["expected_dst_ip"],
            ip_id=0, ip_flags=0x2,
            udp_sport=1234, udp_dport=VXLAN_PORT, with_udp_chksum=False,
            vxlan_vni=int(configs["expected_vni"]),
            inner_frame=inner_exp_pkt,
        )
        masked_expected_pkt = Mask(expected_pkt)
        masked_expected_pkt.set_ignore_extra_bytes()
        masked_expected_pkt.set_do_not_care_packet(Ether, 'dst')
        masked_expected_pkt.set_do_not_care_packet(UDP, 'sport')
        masked_expected_pkt.set_do_not_care_packet(UDP, 'chksum')
        masked_expected_pkt.set_do_not_care_packet(IP, "ttl")
        masked_expected_pkt.set_do_not_care_packet(IP, "chksum")
        masked_expected_pkt.set_do_not_care_packet(IP, "id")
        masked_expected_pkt.set_do_not_care_packet(IP, "len")
        masked_expected_pkt.set_do_not_care_packet(IP, "tos")

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, configs["outgoing_port"], inner_pkt)
        testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, configs["expected_ports"], timeout=2)

    logger.info("WL to T1 VXLAN encapsulation test (IPv6 inner) passed.")


def validate_decap_t1_to_wl(duthost, ptfadapter, test_configs):
    """
    Test T1→WL VXLAN decap with IPv4 and IPv6.
    """
    logger.info("Starting T1 to WL VXLAN decapsulation test...")

    for configs in test_configs:
        for addr_family in ["v4", "v6"]:
            # Build inner TCP packet
            if addr_family == "v4":
                pkt_opts = {
                    "eth_dst": "aa:bb:cc:dd:ee:ff",
                    "eth_src": duthost.facts['router_mac'],
                    "ip_src": "8.8.8.8",
                    "ip_dst": configs["inner_dst_ip_v4"],
                    "tcp_sport": 1234,
                    "tcp_dport": 4321,
                    "pktlen": 100,
                }
                inner_pkt = testutils.simple_tcp_packet(**pkt_opts)
            else:
                pkt_opts = {
                    "eth_dst": "aa:bb:cc:dd:ee:ff",
                    "eth_src": duthost.facts['router_mac'],
                    "ipv6_src": "2001:db8:1::1",
                    "ipv6_dst": configs["inner_dst_ip_v6"],
                    "tcp_sport": 1234,
                    "tcp_dport": 4321,
                    "pktlen": 100,
                }
                inner_pkt = testutils.simple_tcpv6_packet(**pkt_opts)

            # Build VXLAN encapsulated packet to inject from T1 side
            vxlan_pkt = testutils.simple_vxlan_packet(
                eth_dst=duthost.facts['router_mac'],
                eth_src=ptfadapter.dataplane.get_mac(0, configs["outgoing_port"]),
                ip_src="1.1.1.1",
                ip_dst=configs["expected_dst_ip"],
                udp_sport=1234, udp_dport=VXLAN_PORT, with_udp_chksum=False,
                vxlan_vni=int(configs["vni"]),
                inner_frame=inner_pkt,
            )

            pkt_opts["vlan_vid"] = configs["vlan"]
            pkt_opts["dl_vlan_enable"] = True
            pkt_opts["pktlen"] = 104        # 100 + 4, add vlan tag length

            if addr_family == "v4":
                expected_inner_pkt = testutils.simple_tcp_packet(**pkt_opts)
                masked_expected_pkt = Mask(expected_inner_pkt)
                masked_expected_pkt.set_ignore_extra_bytes()
                masked_expected_pkt.set_do_not_care_packet(Ether, 'dst')
                masked_expected_pkt.set_do_not_care_packet(IP, "ttl")
                masked_expected_pkt.set_do_not_care_packet(IP, "chksum")
                masked_expected_pkt.set_do_not_care_packet(IP, "id")
                masked_expected_pkt.set_do_not_care_packet(IP, "len")
                masked_expected_pkt.set_do_not_care_packet(IP, "tos")
                masked_expected_pkt.set_do_not_care_packet(TCP, 'chksum')
            else:
                expected_inner_pkt = testutils.simple_tcpv6_packet(**pkt_opts)
                masked_expected_pkt = Mask(expected_inner_pkt)
                masked_expected_pkt.set_ignore_extra_bytes()
                masked_expected_pkt.set_do_not_care_packet(Ether, 'dst')
                masked_expected_pkt.set_do_not_care_packet(IPv6, 'hlim')
                masked_expected_pkt.set_do_not_care_packet(TCP, 'chksum')

            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, configs["outgoing_port"], vxlan_pkt)
            testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, configs["expected_ports"], timeout=2)

    logger.info("T1 to WL VXLAN decapsulation test passed.")


def cleanup(duthost, ptfhost, localhost, wl_portchannel_info, subintfs_info):
    """
    Return duthost and ptfhost to original state.
    Args:
        duthost: DUT host
        ptfhost: PTF host
        wl_portchannel_info: map of WL portchannel info
        subintfs_info: map of sub-interface info
    """
    logger.debug("cleanup: Loading backup config db json.")
    duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

    cmds = []
    if subintfs_info:
        try:
            for _, val in subintfs_info.items():
                sub_port = val["bond_name"]
                cmds.append("ip link del {}".format(sub_port))
            ptfhost.shell_cmds(cmds=cmds)
        except Exception as e:
            logger.error(f"Error occurred while cleaning up sub interfaces: {e}")

    cmds = []
    if wl_portchannel_info:
        try:
            for key, val in wl_portchannel_info.items():
                bond_port = val["bond_port"]
                port_name = val["ptf_port_name"]
                cmds.append("ip link set {} nomaster".format(bond_port))
                cmds.append("ip link set {} nomaster".format(port_name))
                cmds.append("ip link set {} up".format(port_name))
                cmds.append("ip link del {}".format(bond_port))
            ptfhost.shell_cmds(cmds=cmds)
        except Exception as e:
            logger.error(f"Error occurred while cleaning up bond interfaces: {e}")

    kill_exabgp = f"""
MAIN_PID=$(pgrep -f "exabgp {EXABGP_CONFIG_PATH}")
if [ -n "$MAIN_PID" ]; then
    echo "Killing test ExaBGP instance PID=$MAIN_PID"
    kill -9 $MAIN_PID 2>/dev/null
fi
"""
    ptfhost.shell(kill_exabgp, module_ignore_errors=True)

    kill_http_api = f"""
API_PID=$(pgrep -f "/usr/share/exabgp/http_api.py {EXABGP_PORT}")
if [ -n "$API_PID" ]; then
    echo "Killing test http_api.py PID=$API_PID"
    kill -9 $API_PID 2>/dev/null
fi
"""
    ptfhost.shell(kill_http_api, module_ignore_errors=True)

    kill_ra_send = """
RA_SEND_PIDS=$(pgrep -f "/tmp/ra_send.py")
if [ -n "$RA_SEND_PIDS" ]; then
    echo "Killing RA sender processes"
    kill -9 $RA_SEND_PIDS 2>/dev/null
fi
"""
    ptfhost.shell(kill_ra_send, module_ignore_errors=True)

    for file in temp_files:
        if os.path.exists(file):
            os.remove(file)


def get_available_vlan_id_and_ports(cfg_facts, num_ports_needed):
    """
    Return vlan id and available ports in that vlan if there are enough ports available.
    """
    port_status = cfg_facts["PORT"]
    vlan_id = -1
    available_ports = []
    pytest_require("VLAN_MEMBER" in cfg_facts, "Can't get vlan member")
    for vlan_name, members in list(cfg_facts["VLAN_MEMBER"].items()):
        if len(members) < num_ports_needed:
            continue

        possible_ports = []
        for vlan_member in members:
            if port_status[vlan_member].get("admin_status", "down") != "up":
                continue
            possible_ports.append(vlan_member)
            if len(possible_ports) == num_ports_needed:
                available_ports = possible_ports[:]
                vlan_id = int(''.join([i for i in vlan_name if i.isdigit()]))
                break

        if vlan_id != -1:
            break

    logger.debug(f"Vlan {vlan_id} has available ports: {available_ports}")
    return vlan_id, available_ports


def check_vrf_bgp_sessions_established(duthost, vnet_vnis):
    for vni in vnet_vnis:
        for addr_family in ["ip", "ipv6"]:
            vnet_bgps = duthost.show_and_parse(f"show {addr_family} bgp vrf Vnet{vni} summary")
            pytest_assert(len(vnet_bgps) > 0, f"No BGP sessions found for vnet Vnet{vni}.")
            for val in vnet_bgps:
                pytest_assert(val["neighborname"] == "WL_PARTNER_ROUTER" and val["state/pfxrcd"].isdigit()
                              and int(val["state/pfxrcd"]) > 0, f"BGP neighbor not found for vnet Vnet{vni}.")


def generate_vnet_routes_v6(vnet_vnis, start_vni, num_routes_per_vnet, include_default_route=True):
    """
    Generate VNET tunnel routes with IPv6 overlay prefixes and IPv4 VTEP endpoints.
    """
    base = int(ipaddress.IPv6Address(VNET_V6_PREFIX_BASE))
    endpoint_base = int(ipaddress.IPv4Address(TUNNEL_ENDPOINT))
    routes = {vni: [] for vni in vnet_vnis}
    for i, vni in enumerate(vnet_vnis):
        for j in range(1, num_routes_per_vnet + 1):
            prefix_addr = ipaddress.IPv6Address(base + (i << 8) + j)
            endpoint_int = endpoint_base + (i << 8) + j
            route = {
                "prefix": f"{prefix_addr}/128",
                "endpoint": str(ipaddress.IPv4Address(endpoint_int)),
                "vni": start_vni + (i * num_routes_per_vnet) + j,
                "mac_address": f"52:54:00:{(i << 8 + j) // 256:02x}:{(i << 8 + j) % 256:02x}:aa",
                "vnet_vni": vni,
            }
            routes[vni].append(route)
        if include_default_route:
            route = {
                "prefix": "::/0",
                "endpoint": str(ipaddress.IPv4Address(endpoint_base)),
                "vni": start_vni,
                "mac_address": "52:54:00:00:00:00",
                "vnet_vni": vni,
            }
            routes[vni].append(route)
    return routes


def generate_vnet_routes_v4(vnet_vnis, start_prefix_int, start_endpoint_int, start_vni,
                         num_routes_per_vnet, include_default_route=True, offset=0):
    """
    Generate vnet routes with prefix, endpoint, mac, and vni.
    """
    routes = {vni: [] for vni in vnet_vnis}
    for i, vni in enumerate(vnet_vnis):
        for j in range(1, num_routes_per_vnet + 1):
            prefix_int = start_prefix_int + (i << 8) + j
            endpoint_int = start_endpoint_int + (i << 8) + j + offset
            route = {
                "prefix": f"{ipaddress.IPv4Address(prefix_int)}/32",
                "endpoint": str(ipaddress.IPv4Address(endpoint_int)),
                "vni": start_vni + (i * num_routes_per_vnet) + j,
                "mac_address": f"52:54:00:{(i << 8 + j + offset)//256:02x}:{(i << 8 + j + offset)%256:02x}:aa",
                "vnet_vni": vni
            }
            routes[vni].append(route)

        if include_default_route:
            route = {
                "prefix": "0.0.0.0/0",
                "endpoint": str(ipaddress.IPv4Address(start_endpoint_int)),
                "vni": start_vni,
                "mac_address": "52:54:00:00:00:00",
                "vnet_vni": vni
            }
            routes[vni].append(route)

    return routes


def gnmic_set_with_bypass(gnmi_tls, path, value, filename="test_config"):     # noqa: F811
    """
    Send GNMI set request with bypass.
    """
    gnmi_tls.gnmic.set(path, value, metadata="x-sonic-ss-bypass-validation=true", filename=filename)


def get_link_local_ipv6_on_interface(duthost, interface_name):
    """
    Return the link-local IPv6 address (without prefix) on an interface.
    """
    result = duthost.shell(f"ip -6 -o addr show dev {interface_name} scope link")
    for line in result.get("stdout_lines", []):
        fields = line.split()
        if "inet6" in fields:
            return fields[fields.index("inet6") + 1].split("/")[0]

    pytest.fail(f"No link-local IPv6 found on interface {interface_name}.")


def get_ptf_link_local_ipv6_on_interface(ptfhost, interface_name):
    """
    Return the PTF link-local IPv6 address with prefix from `ip -6 -br` output.
    """
    result = ptfhost.shell(f"ip -6 -br addr show dev {interface_name}")
    for line in result.get("stdout_lines", []):
        fields = line.split()
        for field in fields[2:]:
            if field.startswith("fe80::") and "/" in field:
                return field

    pytest.fail(f"No PTF link-local IPv6 found on interface {interface_name}.")


def ensure_localhost_deployment_id(duthost, gnmi_tls, deployment_id="26"):
    """
    Ensure DEVICE_METADATA localhost deployment_id is set to the expected value.
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    localhost_metadata = config_facts.get("DEVICE_METADATA", {}).get("localhost", {})
    if localhost_metadata.get("deployment_id") == deployment_id:
        return

    gnmic_set_with_bypass(
        gnmi_tls,
        f"{GNMI_PATH_PREFIX}/DEVICE_METADATA/localhost/deployment_id",
        deployment_id,
        "device_metadata"
    )

    duthost.shell("config save -y")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, yang_validate=False)
    time.sleep(10)


def ensure_device_neighbor_metadata(duthost, gnmi_tls):
    """
    Ensure the WL partner neighbor metadata exists in CONFIG_DB.
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    device_neighbor_metadata = config_facts.get("DEVICE_NEIGHBOR_METADATA", {})
    if "WL_PARTNER_ROUTER" in device_neighbor_metadata:
        return

    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/DEVICE_NEIGHBOR_METADATA/WL_PARTNER_ROUTER", {
        "type": "WlPartnerRouter"
    }, "device_neighbor_metadata")


def setup_acl_config(duthost, ports, vnet_vnis, vnet_routes_v4, vnet_routes_v6, gnmi_tls):     # noqa: F811
    """
    Configure a single ACL table for inner src MAC rewrite — both IPv4 and IPv6 rules in one table.
    Each rule matches one IP type (INNER_SRC_IP for v4, INNER_SRC_IPV6 for v6) + TUNNEL_VNI.
    """
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/ACL_TABLE_TYPE", {
        ACL_TYPE_NAME: {
            "BIND_POINTS": ["PORT", "PORTCHANNEL"],
            "MATCHES": ["INNER_SRC_IP", "INNER_SRC_IPV6", "TUNNEL_VNI"],
            "ACTIONS": ["COUNTER", "INNER_SRC_MAC_REWRITE_ACTION"]
        }
    }, "acl_type")

    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/ACL_TABLE", {
        ACL_TABLE_NAME: {
            "policy_desc": ACL_TABLE_NAME,
            "ports": ports,
            "stage": "egress",
            "type": ACL_TYPE_NAME
        }
    }, "acl_table")

    acl_rules = {}
    for vni in vnet_vnis:
        for route in vnet_routes_v4[vni]:
            if route["prefix"] == "0.0.0.0/0":
                continue
            acl_rules[f"{ACL_TABLE_NAME}|rule_{route['vni']}_v4"] = {
                "INNER_SRC_IP": f"{INNER_SRC_IP}/32",
                "INNER_SRC_MAC_REWRITE_ACTION": INNER_SRC_MAC,
                "TUNNEL_VNI": f"{route['vni']}",
                "PRIORITY": f"{route['vni']}"
            }
        for route in vnet_routes_v6[vni]:
            if route["prefix"] == "::/0":
                continue
            acl_rules[f"{ACL_TABLE_NAME}|rule_{route['vni']}_v6"] = {
                "INNER_SRC_IPV6": f"{INNER_SRC_IPV6}/128",
                "INNER_SRC_MAC_REWRITE_ACTION": INNER_SRC_MAC,
                "TUNNEL_VNI": f"{route['vni']}",
                "PRIORITY": f"{route['vni']}"
            }
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/ACL_RULE", acl_rules, "acl_rule")

    def _acl_tables_and_rules_active(duthost):
        rule_key = "STATE_DB/localhost/ACL_RULE_TABLE"
        acl_rule_states = gnmi_tls.gnmic.get(rule_key)[0].get("updates")[0].get("values", {}).get(rule_key, {})
        table_key = f"STATE_DB/localhost/ACL_TABLE_TABLE/{ACL_TABLE_NAME}/status"
        status = gnmi_tls.gnmic.get(table_key)[0].get("updates")[0].get("values", {}).get(table_key, {})
        if status.lower() != "active":
            return False
        for rule_key_name in acl_rules:
            rule_name = rule_key_name.split("|", 1)[1]
            if acl_rule_states.get(f"{ACL_TABLE_NAME}|{rule_name}", {}).get("status", "").lower() != "active":
                return False
        return True

    pytest_assert(wait_until(60, 2, 0, _acl_tables_and_rules_active, duthost),
                  f"ACL tables or rules not active after 60 seconds.")


def setup_vnet_routes(vnet_vnis, vni_to_routes, gnmi_tls):     # noqa: F811
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/VNET_ROUTE_TUNNEL", {
        f"Vnet{vni}|{route['prefix']}": {
            "endpoint": route["endpoint"],
            "vni": route["vni"],
            "mac_address": route["mac_address"]
        } for vni in vnet_vnis for route in vni_to_routes[vni]
    }, "vnet_routes")

    time.sleep(5)
    for vni in vnet_vnis:
        for route in vni_to_routes[vni]:
            route_key = "STATE_DB/localhost/VNET_ROUTE_TUNNEL_TABLE"
            route_status = gnmi_tls.gnmic.get(route_key)[0].get("updates")[0].get("values", {}).get(route_key, {})\
                .get(f"Vnet{vni}|{route['prefix']}", {}).get("state", "")
            pytest_assert(route_status.lower() == "active",
                          f"VNET route tunnel for Vnet{vni}|{route['prefix']} not active.")


def setup_ra_sender(ptfhost, subintfs_info):
    """
    Deploy IPv6 RA sender script to PTF and start it for all subinterfaces.
    Sends periodic Router Advertisements to help BGP link-local peer discovery.
    """
    # Write the RA sender script to a temp file locally, then copy to PTF
    ra_script_local = "/tmp/ra_send.py"
    with open(ra_script_local, "w") as f:
        f.write(RA_SEND_SCRIPT)
    temp_files.append(ra_script_local)

    # Copy to PTF
    ptfhost.copy(src=ra_script_local, dest="/tmp/ra_send.py")
    ptfhost.shell("chmod +x /tmp/ra_send.py")

    # Start RA sender for each subinterface
    for subintf, values in subintfs_info.items():
        bond_name = values["bond_name"]
        logger.info(f"Starting RA sender on {bond_name}")
        ptfhost.shell(
            f"nohup python3 /tmp/ra_send.py {bond_name} --interval 3 > /var/log/exabgp_vnet.log 2>&1 &",
            module_ignore_errors=True
        )
    
    time.sleep(2)


def setup_bgp(duthost, ptfhost, vnet_vnis, subint_info,
              subnet_ip, bgp_port, gnmi_tls):     # noqa: F811
    """
    Setup MP-BGP peer range WLPARTNER_PASSIVE_V4 per VNET for dual-stack decap testing.
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    dut_asn = config_facts['DEVICE_METADATA']['localhost']['bgp_asn']
    neighbors = config_facts['BGP_NEIGHBOR']
    peer_asn = list(neighbors.values())[0]["asn"]

    for subint, value in subint_info.items():
        gnmic_set_with_bypass(
            gnmi_tls,
            f"{GNMI_PATH_PREFIX}/BGP_NEIGHBOR/Vnet{value['vnet_vni']}|{subint}",
            {
                "admin_status": "up",
                "name": "WL_PARTNER_ROUTER",
                "asn": peer_asn,
            },
            f"bgp_peer_{value['vnet_vni']}_{subint}")
        
    prefix_lists = {}
    for vni in vnet_vnis:
        prefix_lists[f"IPV4_DOWNSTREAM_PREFIXES_VNET_Vnet{vni}|{subnet_ip}"] = {"action": "permit"}
        prefix_lists[f"IPV6_DOWNSTREAM_PREFIXES_VNET_Vnet{vni}|{BGP_V6_DECAP_ROUTE}"] = {"action": "permit"}

    gnmic_set_with_bypass(
        gnmi_tls,
        f"{GNMI_PATH_PREFIX}/PREFIX_LIST",
        prefix_lists,
        f"prefix_list_vnet{vni}"
    )

    exabgp_config = f"""
process api-vnets {{
    run /usr/bin/python /usr/share/exabgp/http_api.py {bgp_port};
    encoder json;
}}
"""

    # MP-BGP neighbors: IPv4 session advertising both IPv4 WL subnet and IPv6 decap route.
    # The IPv6 route uses the PTF subinterface IPv6 address as next-hop (RFC 4760).
    for subint, value in subint_info.items():
        dut_ipv6 = value["dut_ipv6"]
        ptf_ipv6 = value["ptf_ipv6"]
        exabgp_config += f"""
neighbor {dut_ipv6.split('/')[0]}%{value['bond_name']} {{
    router-id 10.10.10.10;
    local-address {ptf_ipv6.split('/')[0]}%{value['bond_name']};
    local-as {peer_asn};
    peer-as {dut_asn};
    api {{
        processes [api-vnets];
    }}
    family {{
        ipv4 unicast;
        ipv6 unicast;
    }}
    static {{
        route {subnet_ip} next-hop {ptf_ipv6.split('/')[0]};
        route {BGP_V6_DECAP_ROUTE} next-hop {ptf_ipv6.split('/')[0]};
    }}
}}
"""

    with open('/tmp/exabgp_update.conf', "w") as f:
        f.write(exabgp_config)

    ptfhost.copy(src='/tmp/exabgp_update.conf', dest=EXABGP_CONFIG_PATH)
    ptfhost.shell(f"nohup exabgp {EXABGP_CONFIG_PATH} > /var/log/exabgp_all_vnets.log 2>&1 &")


def setup_portchannel_subintfs(duthost, ptfhost, portchannel_info,
                               vnet_vnis, base_vlan, gnmi_tls):     # noqa: F811
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    has_subintfs = len(config_facts.get("VLAN_SUB_INTERFACE", {})) > 0

    subintfs_info = {}

    cmds = []
    for i in range(len(vnet_vnis)):
        for j, (key, val) in enumerate(portchannel_info.items()):
            po_num = val["portchannel_num"]
            bond_port = val["bond_port"]
            subintf_name = f"Po{po_num}.{base_vlan + i}"

            if not has_subintfs:
                gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/VLAN_SUB_INTERFACE", {
                    subintf_name: {
                        "admin_status": "up",
                        "vlan": str(base_vlan + i),
                        "vnet_name": f"Vnet{vnet_vnis[i]}",
                        "ipv6_use_link_local_only": "enable"
                    }
                }, subintf_name)
                has_subintfs = True
            else:
                gnmic_set_with_bypass(
                    gnmi_tls,
                    f"{GNMI_PATH_PREFIX}/VLAN_SUB_INTERFACE/{subintf_name}",
                    {
                        "admin_status": "up",
                        "vlan": str(base_vlan + i),
                        "vnet_name": f"Vnet{vnet_vnis[i]}",
                        "ipv6_use_link_local_only": "enable"
                    },
                    subintf_name)

            dut_link_local_ipv6 = get_link_local_ipv6_on_interface(duthost, subintf_name)

            # Configure ptf port commands
            cmds.append(f"ip link add link {bond_port} name {bond_port}.{base_vlan + i} type vlan id {base_vlan + i}")
            cmds.append(f"ip link set {bond_port}.{base_vlan + i} up")

            subintfs_info[subintf_name] = {
                "portchannel_name": key,
                "portchannel_num": po_num,
                "ptf_port_index": val["ptf_port_index"],
                "bond_name": f"{bond_port}.{base_vlan + i}",
                "dut_ipv6": dut_link_local_ipv6,
                "ptf_ipv6": "",
                "vlan": base_vlan + i,
                "vnet": f"Vnet{vnet_vnis[i]}",
                "vnet_vni": vnet_vnis[i],
            }

    ptfhost.shell_cmds(cmds=cmds)
    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)

    for subintf, values in subintfs_info.items():
        values["ptf_ipv6"] = get_ptf_link_local_ipv6_on_interface(ptfhost, values["bond_name"])

    interfaces_key = "STATE_DB/localhost/INTERFACE_TABLE"
    interfaces = gnmi_tls.gnmic.get(interfaces_key)[0].get("updates")[0].get("values", {}).get(interfaces_key, {})
    for subintf, values in subintfs_info.items():
        subintf_vnet = interfaces.get(subintf, {}).get("vrf", "")

        pytest_assert(subintf_vnet.lower() == values["vnet"].lower(),
                      f"Subinterface {subintf} not in correct vnet. Expected {values['vnet']}, got {subintf_vnet}.")

    return subintfs_info


def setup_portchannels(duthost, ptfhost, config_facts, port_indexes,
                       ptf_ports_available_in_topo, gnmi_tls):     # noqa: F811
    vlan_id, ports = get_available_vlan_id_and_ports(config_facts, len(PORTCHANNEL_NAMES))
    pytest_assert(len(ports) == len(PORTCHANNEL_NAMES),
                  f"Found {len(ports)} available ports. Needed {len(PORTCHANNEL_NAMES)} ports for the test.")

    cmds = []
    # Pre-cleanup: remove stale bonds from previous interrupted runs
    pre_cleanup = []
    for i in range(len(PORTCHANNEL_NAMES)):
        dut_port_index = port_indexes.get(ports[i])
        if dut_port_index is not None and dut_port_index in ptf_ports_available_in_topo:
            ptf_port_name = ptf_ports_available_in_topo[dut_port_index]["name"]
            ptf_port_index = ptf_ports_available_in_topo[dut_port_index]["index"]
            bond_port = 'bond{}'.format(ptf_port_index)
            pre_cleanup.append(f"ip link set {ptf_port_name} nomaster 2>/dev/null || true")
            pre_cleanup.append(f"ip link del {bond_port} 2>/dev/null || true")
            pre_cleanup.append(f"ip link set {ptf_port_name} up 2>/dev/null || true")
    if pre_cleanup:
        ptfhost.shell_cmds(cmds=pre_cleanup)

    wl_portchannel_mapping_info = {}
    for i in range(len(PORTCHANNEL_NAMES)):
        duthost.shell(f'config vlan member del {vlan_id} {ports[i]}')

        gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/PORTCHANNEL/{PORTCHANNEL_NAMES[i]}", {
            "admin_status": "up"
        }, PORTCHANNEL_NAMES[i])
        gnmic_set_with_bypass(
            gnmi_tls,
            f"{GNMI_PATH_PREFIX}/PORTCHANNEL_MEMBER/{PORTCHANNEL_NAMES[i]}|{ports[i]}",
            {},
            f"{PORTCHANNEL_NAMES[i]}_member")

        dut_port_index = port_indexes[ports[i]]
        ptf_port_name = ptf_ports_available_in_topo[dut_port_index]["name"]
        ptf_port_index = ptf_ports_available_in_topo[dut_port_index]["index"]

        bond_port = 'bond{}'.format(ptf_port_index)
        cmds.append("ip link add {} type bond".format(bond_port))
        cmds.append("ip link set {} type bond miimon 100 mode 802.3ad".format(bond_port))
        cmds.append("ip link set {} down".format(ptf_port_name))
        cmds.append("ip link set {} master {}".format(ptf_port_name, bond_port))
        cmds.append("ip link set dev {} up".format(bond_port))
        cmds.append("ifconfig {} mtu 9216 up".format(bond_port))

        wl_portchannel_mapping_info[PORTCHANNEL_NAMES[i]] = {
            "portchannel_num": ''.join(filter(str.isdigit, PORTCHANNEL_NAMES[i])),
            "ptf_port_name": ptf_port_name,
            "ptf_port_index": ptf_port_index,
            "bond_port": bond_port,
        }

    ptfhost.shell_cmds(cmds=cmds)
    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)

    for portchannel_name in PORTCHANNEL_NAMES:
        portchannel_key = f"STATE_DB/localhost/LAG_TABLE/{portchannel_name}"
        portchannel_status = gnmi_tls.gnmic.get(portchannel_key)[0].get("updates")[0].get("values", {})\
            .get(portchannel_key, {})

        pytest_assert(portchannel_status.get("admin_status", "").lower() == "up"
                      and portchannel_status.get("oper_status", "").lower() == "up",
                      f"Portchannel {portchannel_name} not up in state db.")

    return wl_portchannel_mapping_info


def setup_vnets(num_vnets, tunnel, base_vni, gnmi_tls):     # noqa: F811
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/VNET", {
        f"Vnet{base_vni + i}": {
            "vni": f"{base_vni + i}",
            "vxlan_tunnel": tunnel
        } for i in range(num_vnets)
    }, "vnet")

    for i in range(num_vnets):
        vnet_name = f"Vnet{base_vni + i}"
        vnet_key = f"STATE_DB/localhost/VRF_TABLE/{vnet_name}/state"
        vnet_status = gnmi_tls.gnmic.get(vnet_key)[0].get("updates")[0].get("values", {}).get(vnet_key, {})
        pytest_assert(vnet_status.lower() == "ok", f"Vnet {vnet_name} not in ok state.")

    return [base_vni + i for i in range(num_vnets)]


def setup_vxlan_tunnel(duthost, ptfhost, name, src_ip, gnmi_tls):     # noqa: F811
    tunnel_entry = {"src_ip": src_ip}
    # On cisco-8000, base topology IP-in-IP decap tunnels may already use pipe TTL mode.
    # Set VXLAN decap ttl_mode to pipe so orchagent passes DECAP_TTL_MODE consistently.
    if duthost.facts.get("asic_type") == "cisco-8000":
        tunnel_entry["ttl_mode"] = "pipe"

    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/VXLAN_TUNNEL", {
        name: tunnel_entry
    }, "vxlan")


@pytest.fixture(scope="module")
def common_setup_and_teardown(tbinfo, duthosts, rand_one_dut_hostname,
                              ptfhost, ptfadapter, localhost, gnmi_tls):     # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]

    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    wl_portchannel_info = None
    subintfs_info = None

    try:
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

        port_indexes = config_facts['port_index_map']
        duts_map = tbinfo["duts_map"]
        dut_indx = duts_map[duthost.hostname]
        host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
        ptf_ports_available_in_topo = {}
        for key in host_interfaces:
            ptf_ports_available_in_topo[host_interfaces[key]] = {
                "index": int(key),
                "name": "eth{}".format(int(key))
            }

        # This test uses features that require deployment_id 26
        ensure_localhost_deployment_id(duthost, gnmi_tls, "26")

        # Ensure DEVICE_NEIGHBOR_METADATA for bgp neighbor exists in CONFIG_DB
        ensure_device_neighbor_metadata(duthost, gnmi_tls)

        # Remove everflow acl tables
        duthost.remove_acl_table("EVERFLOW")
        duthost.remove_acl_table("EVERFLOWV6")
        duthost.remove_acl_table(ACL_TABLE_NAME_V6)

        # Create loopback interface
        duthost.shell("config int ip add Loopback6 10.10.1.1")
        duthost.shell("config int ip add Loopback7 10.10.2.2")
        loopback_ip = "10.10.1.1"

        subnet_ip = "10.11.0.0/16"

        # Set up vxlan
        setup_vxlan_tunnel("tunnel_v4", loopback_ip, gnmi_tls)

        # Set up vnets
        vnet_vnis = setup_vnets(NUM_VNETS, "tunnel_v4", BASE_VNI, gnmi_tls)

        # Set up portchannels
        wl_portchannel_info = setup_portchannels(duthost, ptfhost, config_facts,
                                                 port_indexes, ptf_ports_available_in_topo, gnmi_tls)

        # Set up subintfs (IPv4 + IPv6 addresses for MP-BGP next-hop resolution)
        subintfs_info = setup_portchannel_subintfs(
            duthost,
            ptfhost,
            wl_portchannel_info,
            vnet_vnis,
            base_vlan=10,
            gnmi_tls=gnmi_tls)

        # Set up bgps
        setup_bgp(duthost,
            ptfhost,
            vnet_vnis,
            subintfs_info,
            subnet_ip=subnet_ip,
            bgp_port=EXABGP_PORT,
            gnmi_tls=gnmi_tls)
        
        # Start IPv6 RA sender on subinterfaces for peer NDP discovery
        setup_ra_sender(ptfhost, subintfs_info)

        # Check bgp sessions are up
        time.sleep(30)
        check_vrf_bgp_sessions_established(duthost, vnet_vnis)

        # Generate and setup vnet routes
        vnet_routes_v6 = generate_vnet_routes_v6(vnet_vnis, start_vni=10000, num_routes_per_vnet=5,
                                                  include_default_route=False)
        vnet_routes_v4 = generate_vnet_routes_v4(
            vnet_vnis,
            start_prefix_int=int(ipaddress.IPv4Address("30.0.0.0")),
            start_endpoint_int=int(ipaddress.IPv4Address(TUNNEL_ENDPOINT)),
            start_vni=10000, num_routes_per_vnet=5)
        all_vnet_routes = {vni: vnet_routes_v4[vni] + vnet_routes_v6[vni] for vni in vnet_vnis}
        setup_vnet_routes(vnet_vnis, all_vnet_routes, gnmi_tls)

        # Setup acl configs
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        setup_acl_config(duthost, list(config_facts.get("PORTCHANNEL", {}).keys()),
                         vnet_vnis, vnet_routes_v4, vnet_routes_v6, gnmi_tls)

        # Install IPv6 overlay routes after ACL setup
        setup_vnet_routes(vnet_vnis, vnet_routes_v6, gnmi_tls)

        # Configure vxlan port
        ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

        # Get ptf eth of T1 portchannels
        t1_ptf_port_nums = []
        portchannel_members = config_facts.get("PORTCHANNEL_MEMBER", {})
        for key in portchannel_members:
            for intf in list(portchannel_members[key].keys()):
                dut_port_idx = port_indexes.get(intf)
                if dut_port_idx is None:
                    continue
                ptf_port = ptf_ports_available_in_topo.get(dut_port_idx)
                if ptf_port is None:
                    continue
                if key not in wl_portchannel_info:
                    t1_ptf_port_nums.append(ptf_port["index"])

        # Check have enough T1 ports to run tests
        pytest_assert(len(t1_ptf_port_nums) > 0, "No T1 side portchannel member ports found in PTF topo.")
    except Exception as e:
        # Cleanup on failure during setup
        logger.error(f"Exception during setup: {repr(e)}.")
        cleanup(duthost, ptfhost, localhost, wl_portchannel_info, subintfs_info)
        pytest.fail(f"Setup failed: {repr(e)}")

    ports_per_vnet = {}
    for _, val in subintfs_info.items():
        vni = val["vnet_vni"]
        if vni not in ports_per_vnet:
            ports_per_vnet[vni] = []
        ports_per_vnet[vni].append(val["ptf_port_index"])

    # Unified configs: each entry carries both IPv4 and IPv6 inner dst fields.
    # v4 functions use "inner_dst_ip_v4", v6 functions use "inner_dst_ip_v6".
    # Both share same VNI/endpoint/outer tunnel — only inner packet type differs.
    decap_test_configs = [
        {
            "inner_dst_ip_v4": "10.11.255.255",
            "inner_dst_ip_v6": BGP_V6_DECAP_IP,
            "expected_dst_ip": loopback_ip,
            "vni": val["vnet_vni"],
            "vlan": val["vlan"],
            "outgoing_port": t1_ptf_port_nums[0],
            "expected_ports": ports_per_vnet[val["vnet_vni"]],
        } for _, val in subintfs_info.items()
    ]
    encap_test_configs = [
        {
            "inner_dst_ip_v4": route_v4["prefix"].split('/')[0] if route_v4["prefix"] != "0.0.0.0/0" else "150.0.0.10",
            "inner_dst_ip_v6": route_v6["prefix"].split('/')[0] if route_v6["prefix"] != "::/0" else "2000:db8:1::10",
            "expected_dst_mac": route_v4["mac_address"],
            "expected_vni": route_v4["vni"],
            "expected_dst_ip": route_v4["endpoint"],
            "expected_src_ip": loopback_ip,
            "vlan": val["vlan"],
            "vni": val["vnet_vni"],
            "outgoing_port": val["ptf_port_index"],
            "expected_ports": t1_ptf_port_nums,
            "route_v4": route_v4,
            "route_v6": route_v6,
        }
        for _, val in subintfs_info.items()
        for route_v4, route_v6 in zip(
            vnet_routes_v4[val["vnet_vni"]],
            vnet_routes_v6[val["vnet_vni"]]
        )
    ]

    yield duthost, ptfhost, ptfadapter, vnet_vnis, subintfs_info, encap_test_configs, decap_test_configs

    # Cleanup
    cleanup(duthost, ptfhost, localhost, wl_portchannel_info, subintfs_info)


def modify_routes_mac_vni_v4(gnmi_tls, encap_test_configs, offset=0):
    """
    Modify IPv4 VNET tunnel route VNI, endpoint, and MAC by offset.
    """
    modified_routes = set()
    acl_rule_value = {}

    for config in encap_test_configs:
        route = config["route_v4"]
        if route["prefix"] not in modified_routes:
            route["vni"] += offset
            route["mac_address"] = route["mac_address"][:-2] + \
                "{:02x}".format((int(route["mac_address"][-2:], 16) + offset) % 256)
            route["endpoint"] = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(route["endpoint"])) + offset))
            gnmic_set_with_bypass(
                gnmi_tls,
                f"{GNMI_PATH_PREFIX}/VNET_ROUTE_TUNNEL/Vnet{route['vnet_vni']}|{route['prefix'].replace('/','~1')}",
                {"endpoint": route["endpoint"], "vni": route["vni"], "mac_address": route["mac_address"]},
                f"vnet_route_{route['vnet_vni']}_{route['prefix'].replace('/','_')}",
            )
            acl_rule_value[f"{ACL_TABLE_NAME}|rule_{route['vni']}"] = {
                "INNER_SRC_IP": f"{INNER_SRC_IP}/32",
                "INNER_SRC_MAC_REWRITE_ACTION": INNER_SRC_MAC,
                "TUNNEL_VNI": f"{route['vni']}",
                "PRIORITY": f"{route['vni']}"
            }
            modified_routes.add(route["prefix"])
        config["expected_vni"] = route["vni"]
        config["expected_dst_mac"] = route["mac_address"]
        config["expected_dst_ip"] = route["endpoint"]

    # Update src mac rewrite acl to match new vnis
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/ACL_RULE", acl_rule_value, "acl_rule")

    # Check vnet routes are updated
    time.sleep(5)
    for config in encap_test_configs:
        route_key = "STATE_DB/localhost/VNET_ROUTE_TUNNEL_TABLE"
        route = config["route_v4"]
        route_status = gnmi_tls.gnmic.get(route_key)[0].get("updates")[0].get("values", {}).get(route_key, {})\
            .get(f"Vnet{route['vnet_vni']}|{route['prefix']}", {}).get("state", "")
        pytest_assert(route_status.lower() == "active",
                      f"VNET route tunnel for Vnet{route['vnet_vni']}|"
                      f"{route['prefix']} not active after mac/vni update.")


def modify_routes_mac_vni_v6(gnmi_tls, encap_test_configs, offset=1):
    """
    Modify IPv6 VNET tunnel route VNI, endpoint, and MAC by offset.
    """
    modified_routes = set()
    acl_rule_value = {}

    for config in encap_test_configs:
        route = config["route_v6"]

        if route["prefix"] not in modified_routes:
            route["vni"] += offset
            route["mac_address"] = route["mac_address"][:-2] + \
                "{:02x}".format((int(route["mac_address"][-2:], 16) + offset) % 256)
            route["endpoint"] = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(route["endpoint"])) + offset))

            gnmic_set_with_bypass(
                gnmi_tls,
                f"{GNMI_PATH_PREFIX}/VNET_ROUTE_TUNNEL/Vnet{route['vnet_vni']}|{route['prefix'].replace('/','~1')}",
                {
                    "endpoint": route["endpoint"],
                    "vni": route["vni"],
                    "mac_address": route["mac_address"],
                },
                f"vnet_route_{route['vnet_vni']}_{route['prefix'].replace('/','_')}",
            )
            acl_rule_value[f"{ACL_TABLE_NAME}|rule_{route['vni']}_v6"] = {
                "INNER_SRC_IPV6": f"{INNER_SRC_IPV6}/128",
                "INNER_SRC_MAC_REWRITE_ACTION": INNER_SRC_MAC,
                "TUNNEL_VNI": f"{route['vni']}",
                "PRIORITY": f"{route['vni']}"
            }
            modified_routes.add(route["prefix"])

        config["expected_vni"] = route["vni"]
        config["expected_dst_mac"] = route["mac_address"]
        config["expected_dst_ip"] = route["endpoint"]

    # Update src mac rewrite acl to match new vnis
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/ACL_RULE", acl_rule_value, "acl_rule_v6")

    # Check vnet routes are updated
    time.sleep(5)
    for config in encap_test_configs:
        route_key = "STATE_DB/localhost/VNET_ROUTE_TUNNEL_TABLE"
        route = config["route_v6"]
        route_status = gnmi_tls.gnmic.get(route_key)[0].get("updates")[0].get("values", {}).get(route_key, {})\
            .get(f"Vnet{route['vnet_vni']}|{route['prefix']}", {}).get("state", "")
        pytest_assert(route_status.lower() == "active",
                      f"VNET route tunnel for Vnet{route['vnet_vni']}|"
                      f"{route['prefix']} not active after mac/vni update.")


def test_vnet_with_bgp_intf_smacrewrite(common_setup_and_teardown, gnmi_tls):     # noqa: F811

    duthost, ptfhost, ptfadapter, vnet_vnis, subintfs_info, encap_test_configs, decap_test_configs = common_setup_and_teardown

    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)

    # Test datapath after modifying route mac and vni
    modify_routes_mac_vni_v4(gnmi_tls, encap_test_configs, offset=1)
    modify_routes_mac_vni_v6(gnmi_tls, encap_test_configs, offset=1)
    time.sleep(5)

    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)

    # Test datapath again after config reload
    duthost.shell("config save -y")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, yang_validate=False)
    time.sleep(10)

    # Start IPv6 RA sender
    setup_ra_sender(ptfhost, subintfs_info)

    # Check bgp sessions are up
    time.sleep(30)
    check_vrf_bgp_sessions_established(duthost, vnet_vnis)

    ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)
