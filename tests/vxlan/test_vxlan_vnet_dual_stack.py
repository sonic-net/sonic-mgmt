"""
Test dual-stack (IPv4 + IPv6 underlay) VXLAN support on VNET.

The swss change introduces a new ``vxlan_tunnel_list`` field on the VNET
table which allows a single VNET to be associated with multiple VXLAN
tunnels (up to one IPv4-underlay and one IPv6-underlay). orchagent picks
the tunnel whose ``src_ip`` address-family matches the address-family of
the ``VNET_ROUTE_TUNNEL`` endpoint (``getTunnelNameForNextHop``), so
v4 endpoints are encapsulated over ``tunnel_v4`` and v6 endpoints over
``tunnel_v6``.

This test is a derivative of
tests/vxlan/test_vxlan_vnet_bgp_subintf.py from PR sonic-net/sonic-mgmt#26716.
The additions/modifications are the minimum required to exercise the new
dual-stack code path:

    * ``setup_vnets`` accepts either a tunnel name (str) or a list of
      tunnel names. A list is programmed as the new ``vxlan_tunnel_list``
      field, written directly to CONFIG_DB with ``sonic-db-cli``.
    * A second VXLAN tunnel (``tunnel_v6``) with an IPv6 ``src_ip`` from
      an IPv6 loopback is set up in ``common_setup_and_teardown`` and
      attached to each VNET together with ``tunnel_v4``.
    * ``generate_vnet_routes_v6_endpoint`` (NEW) generates
      ``VNET_ROUTE_TUNNEL`` entries whose endpoint is IPv6.
    * ``validate_encap_wl_to_t1_v6_endpoint`` (NEW) verifies that the
      DUT encapsulates traffic to those routes with an IPv6 outer header
      sourced from the IPv6 loopback.
    * ``test_vnet_with_dual_stack_vxlan_encap`` (NEW) runs the new
      v6-underlay encap check alongside the existing v4-underlay one.

CONFIG_DB is programmed through the gNMI native-write server using
``gnmi_set_update_config_db_json`` (same as test_vxlan_vnet_bgp_subintf.py);
STATE_DB is verified with ``sonic-db-cli``.
"""
import ipaddress
import json
import logging
import os
import time

import pytest
from ptf.mask import Mask
from ptf.packet import Ether, IP, IPv6, UDP
import ptf.testutils as testutils

from tests.common.config_reload import config_reload
from tests.common.gnmi_setup import apply_cert_config, recover_cert_config
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.gnmi_utils import GNMIEnvironment, gnmi_container, create_gnmi_certs, \
    delete_gnmi_certs
from tests.common.helpers.ntp_helper import setup_ntp_context, check_ntp_sync_status
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

PORTCHANNEL_NAMES = ["PortChannel1031", "PortChannel1032"]
VXLAN_PORT = 4789
TUNNEL_ENDPOINT = "100.0.1.10"
INNER_SRC_IP = "2.2.2.2"
INNER_SRC_MAC = "00:11:22:33:44:55"
INNER_SRC_IPV6 = "2001:db8:2::2"

# IPv6-underlay tunnel constants (dual-stack additions).
# TUNNEL_ENDPOINT_V6 is reachable via the ``::/0`` default route that T1 VMs
# announce in every non-storage-backend t0 topology (see
# ansible/library/announce_routes.py).
LOOPBACK_V6_NAME = "Loopback8"
LOOPBACK_V6_IP = "fc00:1::1"
TUNNEL_V4_NAME = "tunnel_v4"
TUNNEL_V6_NAME = "tunnel_v6"
TUNNEL_ENDPOINT_V6 = "20c0:a800::10"
VNET_V6_ENDPOINT_PREFIX_BASE = "2001:db8:50::"

BASE_VNI = 1000
NUM_VNETS = 2

VNET_V6_PREFIX_BASE = "2001:db8:30::"

GNMI_PATH_PREFIX = "/CONFIG_DB/localhost"

ACL_TYPE_NAME = "INNER_SRC_MAC_REWRITE_TYPE"
ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"
ACL_TYPE_NAME_V6 = "INNER_SRC_MAC_REWRITE_TYPE_V6"
ACL_TABLE_NAME_V6 = "INNER_SRC_MAC_REWRITE_TABLE_V6"

temp_files = []


def validate_encap_wl_to_t1(duthost, ptfadapter, test_configs):
    """
    Test WL->T1 VXLAN encap with IPv4 and IPv6.
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


def validate_encap_wl_to_t1_v6_endpoint(duthost, ptfadapter, test_configs):
    """
    Dual-stack addition: verify that when a VNET_ROUTE_TUNNEL entry has an
    IPv6 endpoint the DUT encapsulates traffic with an IPv6 outer header
    sourced from the IPv6 loopback that ``tunnel_v6`` was created with.
    """
    logger.info("Starting WL to T1 VXLAN encapsulation test (v6 underlay)...")

    for configs in test_configs:
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

        # No ACL rewrite for v6-endpoint prefixes -> egress inner src = DUT router_mac.
        pkt_opts["eth_src"] = configs["expected_inner_src_mac"]
        pkt_opts["eth_dst"] = configs["expected_dst_mac"]
        pkt_opts["dl_vlan_enable"] = False
        pkt_opts.pop("vlan_vid", None)
        pkt_opts["pktlen"] = 96
        pkt_opts["ip_ttl"] = 63
        inner_exp_pkt = testutils.simple_tcp_packet(**pkt_opts)

        expected_pkt = testutils.simple_vxlanv6_packet(
            eth_dst="aa:bb:cc:dd:ee:ff",
            eth_src=duthost.facts['router_mac'],
            ipv6_src=configs["expected_src_ip_v6"],
            ipv6_dst=configs["expected_dst_ip_v6"],
            udp_sport=1234, udp_dport=VXLAN_PORT, with_udp_chksum=False,
            vxlan_vni=int(configs["expected_vni"]),
            inner_frame=inner_exp_pkt,
        )
        masked_expected_pkt = Mask(expected_pkt)
        masked_expected_pkt.set_ignore_extra_bytes()
        masked_expected_pkt.set_do_not_care_packet(Ether, 'dst')
        masked_expected_pkt.set_do_not_care_packet(UDP, 'sport')
        masked_expected_pkt.set_do_not_care_packet(UDP, 'chksum')
        masked_expected_pkt.set_do_not_care_packet(UDP, 'len')
        masked_expected_pkt.set_do_not_care_packet(IPv6, "hlim")
        masked_expected_pkt.set_do_not_care_packet(IPv6, "plen")
        masked_expected_pkt.set_do_not_care_packet(IPv6, "tc")
        masked_expected_pkt.set_do_not_care_packet(IPv6, "fl")

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, configs["outgoing_port"], inner_pkt)
        testutils.verify_packet_any_port(
            ptfadapter, masked_expected_pkt, configs["expected_ports"], timeout=2)

    logger.info("WL to T1 VXLAN encapsulation test (v6 underlay) passed.")


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

    # Restore the default gnmi server and remove the test client certs config
    recover_cert_config(duthost)

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

    for file in temp_files:
        if os.path.exists(file):
            os.remove(file)
    temp_files.clear()

    # Remove local gnmi cert files
    delete_gnmi_certs(localhost)


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
                "mac_address": f"52:54:00:{((i << 8) + j) // 256:02x}:{((i << 8) + j) % 256:02x}:aa",
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
                "mac_address": f"52:54:00:{((i << 8) + j + offset)//256:02x}:{((i << 8) + j + offset) % 256:02x}:aa",
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


def generate_vnet_routes_v6_endpoint(vnet_vnis, start_prefix_int, start_vni, num_routes_per_vnet,
                                     endpoint_offset=0, include_vni_mac=True):
    """
    Dual-stack addition: generate VNET tunnel routes whose ``endpoint`` is an
    IPv6 address so orchagent selects the IPv6-underlay tunnel
    (``tunnel_v6``) via ``getTunnelNameForNextHop``.

    When ``include_vni_mac`` is False the ``vni`` and ``mac_address`` fields
    are omitted, so orchagent applies its defaults (VNET's own VNI and
    SWITCH_VXLAN_ROUTER_MAC).
    """
    endpoint_base = int(ipaddress.IPv6Address(TUNNEL_ENDPOINT_V6))
    routes = {vni: [] for vni in vnet_vnis}
    for i, vni in enumerate(vnet_vnis):
        for j in range(1, num_routes_per_vnet + 1):
            prefix_int = start_prefix_int + (i << 8) + j
            endpoint_int = endpoint_base + (i << 8) + j + endpoint_offset
            route = {
                "prefix": f"{ipaddress.IPv4Address(prefix_int)}/32",
                "endpoint": str(ipaddress.IPv6Address(endpoint_int)),
                "vnet_vni": vni,
            }
            if include_vni_mac:
                route["vni"] = start_vni + (i * num_routes_per_vnet) + j
                route["mac_address"] = \
                    f"52:54:00:{((i << 8) + j) // 256:02x}:{((i << 8) + j) % 256:02x}:bb"
            routes[vni].append(route)
    return routes


def gnmi_set_update_config_db_json(duthost, ptfhost, path, value, filename="test_config"):
    """
    Send GNMI set request with GNMI client. This helper will only send add/update requests with a json value format.
    """
    filename += ".txt"
    with open(filename, 'w') as file:
        file.write(json.dumps(value))
    ptfhost.copy(src=filename, dest='/tmp')

    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = duthost.mgmt_ip
    port = env.gnmi_port

    cmd = f"/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py \
        --timeout 10 -t {ip} -p {port} -xo sonic-db -rcert /root/gnmiCA.pem \
        -pkey /root/gnmiclient.key -cchain /root/gnmiclient.crt -m set-update \
        --xpath \"{path}\" --value \"@/tmp/{filename}\""
    ptfhost.shell(cmd)

    temp_files.append(filename)


def get_state_db_field(duthost, key, field):
    """
    Return a single STATE_DB hash field value (empty string if missing).
    """
    result = duthost.shell(f"sonic-db-cli STATE_DB HGET '{key}' '{field}'", module_ignore_errors=True)
    return result.get("stdout", "").strip()


def setup_gnmi_server(duthost, localhost, ptfhost):
    """
    Setup GNMI server with client certificates
    """
    pytest_require(
        check_container_state(duthost, gnmi_container(duthost), should_be_running=True),
        "Test was not supported on devices which do not support GNMI!")

    create_gnmi_certs(duthost, localhost, ptfhost)

    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0' or check_ntp_sync_status(duthost):
        apply_cert_config(duthost)
    else:
        duthost_mgmt_info = duthost.get_mgmt_ip()
        use_v6 = duthost_mgmt_info["version"] == "v6"
        with setup_ntp_context(ptfhost, duthost, use_v6):
            apply_cert_config(duthost)


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


def setup_acl_config(duthost, ptfhost, ports, vnet_vnis, vnet_routes_v4, vnet_routes_v6):
    """
    Configure a single ACL table for inner src MAC rewrite - both IPv4 and IPv6 rules in one table.
    Each rule matches one IP type (INNER_SRC_IP for v4, INNER_SRC_IPV6 for v6) + TUNNEL_VNI.
    """
    gnmi_set_update_config_db_json(duthost, ptfhost, f"{GNMI_PATH_PREFIX}/ACL_TABLE_TYPE", {
        ACL_TYPE_NAME: {
            "BIND_POINTS": ["PORT", "PORTCHANNEL"],
            "MATCHES": ["INNER_SRC_IP", "INNER_SRC_IPV6", "TUNNEL_VNI"],
            "ACTIONS": ["COUNTER", "INNER_SRC_MAC_REWRITE_ACTION"]
        }
    }, "acl_type")

    gnmi_set_update_config_db_json(duthost, ptfhost, f"{GNMI_PATH_PREFIX}/ACL_TABLE", {
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
    gnmi_set_update_config_db_json(duthost, ptfhost, f"{GNMI_PATH_PREFIX}/ACL_RULE", acl_rules, "acl_rule")

    def _acl_tables_and_rules_active(duthost):
        status = get_state_db_field(duthost, f"ACL_TABLE_TABLE|{ACL_TABLE_NAME}", "status")
        if status.lower() != "active":
            return False
        for rule_key_name in acl_rules:
            rule_name = rule_key_name.split("|", 1)[1]
            rule_status = get_state_db_field(duthost, f"ACL_RULE_TABLE|{ACL_TABLE_NAME}|{rule_name}", "status")
            if rule_status.lower() != "active":
                return False
        return True

    pytest_assert(wait_until(60, 2, 0, _acl_tables_and_rules_active, duthost),
                  "ACL tables or rules not active after 60 seconds.")


def setup_vnet_routes(duthost, ptfhost, vnet_vnis, vni_to_routes):
    payload = {}
    for vni in vnet_vnis:
        for route in vni_to_routes[vni]:
            entry = {"endpoint": route["endpoint"]}
            if "vni" in route:
                entry["vni"] = str(route["vni"])
            if "mac_address" in route:
                entry["mac_address"] = route["mac_address"]
            payload[f"Vnet{vni}|{route['prefix']}"] = entry
    gnmi_set_update_config_db_json(duthost, ptfhost, f"{GNMI_PATH_PREFIX}/VNET_ROUTE_TUNNEL", payload, "vnet_routes")

    time.sleep(5)
    for vni in vnet_vnis:
        for route in vni_to_routes[vni]:
            route_status = get_state_db_field(
                duthost, f"VNET_ROUTE_TUNNEL_TABLE|Vnet{vni}|{route['prefix']}", "state")
            pytest_assert(route_status.lower() == "active",
                          f"VNET route tunnel for Vnet{vni}|{route['prefix']} not active.")


def setup_portchannel_subintfs(duthost, ptfhost, portchannel_info, vnet_vnis, base_vlan):
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
                gnmi_set_update_config_db_json(duthost, ptfhost, f"{GNMI_PATH_PREFIX}/VLAN_SUB_INTERFACE", {
                    subintf_name: {
                        "admin_status": "up",
                        "vlan": str(base_vlan + i),
                        "vnet_name": f"Vnet{vnet_vnis[i]}",
                        "ipv6_use_link_local_only": "enable"
                    }
                }, subintf_name)
                has_subintfs = True
            else:
                gnmi_set_update_config_db_json(
                    duthost,
                    ptfhost,
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

    for subintf, values in subintfs_info.items():
        subintf_vnet = get_state_db_field(duthost, f"INTERFACE_TABLE|{subintf}", "vrf")

        pytest_assert(subintf_vnet.lower() == values["vnet"].lower(),
                      f"Subinterface {subintf} not in correct vnet. Expected {values['vnet']}, got {subintf_vnet}.")

    return subintfs_info


def setup_portchannels(duthost, ptfhost, config_facts, port_indexes, ptf_ports_available_in_topo):
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

        gnmi_set_update_config_db_json(duthost, ptfhost, f"{GNMI_PATH_PREFIX}/PORTCHANNEL/{PORTCHANNEL_NAMES[i]}", {
            "admin_status": "up"
        }, PORTCHANNEL_NAMES[i])
        gnmi_set_update_config_db_json(
            duthost,
            ptfhost,
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
        portchannel_key = f"LAG_TABLE|{portchannel_name}"
        admin_status = get_state_db_field(duthost, portchannel_key, "admin_status")
        oper_status = get_state_db_field(duthost, portchannel_key, "oper_status")

        pytest_assert(admin_status.lower() == "up" and oper_status.lower() == "up",
                      f"Portchannel {portchannel_name} not up in state db.")

    return wl_portchannel_mapping_info


def setup_vnets(duthost, num_vnets, tunnel, base_vni):
    """
    Program VNETs by writing directly to CONFIG_DB via ``sonic-db-cli``,
    bypassing translib yang validation. vnetorch subscribes to CONFIG_DB
    and picks up the entry the same way.

    ``tunnel`` may be a single tunnel name (str) or a list of tunnel names.
    When a list is supplied the new ``vxlan_tunnel_list`` field is written
    (dual-stack). ``vxlan_tunnel`` is also set
    to the first entry because sonic-vnet.yang keeps it ``mandatory true``.
    orchagent enforces that at most one v4 and one v6 tunnel are present
    in the list and picks the tunnel matching each next-hop endpoint's
    address family.
    """
    if isinstance(tunnel, (list, tuple)):
        fields = {"vxlan_tunnel": tunnel[0], "vxlan_tunnel_list": ",".join(tunnel)}
    else:
        fields = {"vxlan_tunnel": tunnel}

    for i in range(num_vnets):
        vnet_name = f"Vnet{base_vni + i}"
        entry = {**fields, "vni": str(base_vni + i)}
        args = " ".join(f"{k} {v}" for k, v in entry.items())
        cmd = f"sonic-db-cli CONFIG_DB HSET 'VNET|{vnet_name}' {args}"
        logger.info("setup_vnets: %s entry=%s", vnet_name, entry)
        logger.info("setup_vnets: cmd=%s", cmd)
        duthost.shell(cmd)

    for i in range(num_vnets):
        vnet_name = f"Vnet{base_vni + i}"
        vnet_status = get_state_db_field(duthost, f"VRF_TABLE|{vnet_name}", "state")
        pytest_assert(vnet_status.lower() == "ok", f"Vnet {vnet_name} not in ok state.")

    return [base_vni + i for i in range(num_vnets)]


def setup_vxlan_tunnel(duthost, name, src_ip):
    """
    Write a single VXLAN_TUNNEL entry directly to CONFIG_DB.

    A gnmi ``set`` on the ``VXLAN_TUNNEL`` container path with one key in the
    payload is translated by translib as "the container should have exactly
    these keys", so back-to-back calls for tunnel_v4 then tunnel_v6 wipe
    tunnel_v4. Writing straight to redis keeps both keys.
    """
    entry = {"src_ip": src_ip}
    if duthost.facts.get("asic_type") == "cisco-8000":
        entry["ttl_mode"] = "pipe"
    args = " ".join(f"{k} {v}" for k, v in entry.items())
    cmd = f"sonic-db-cli CONFIG_DB HSET 'VXLAN_TUNNEL|{name}' {args}"
    logger.info("setup_vxlan_tunnel: %s entry=%s", name, entry)
    logger.info("setup_vxlan_tunnel: cmd=%s", cmd)
    duthost.shell(cmd)


@pytest.fixture(scope="module")
def common_setup_and_teardown(tbinfo, duthosts, rand_one_dut_hostname,
                              ptfhost, ptfadapter, localhost):
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

        # setup gnmi server (native write mode) and client certificates
        setup_gnmi_server(duthost, localhost, ptfhost)

        # Remove everflow acl tables
        duthost.remove_acl_table("EVERFLOW")
        duthost.remove_acl_table("EVERFLOWV6")
        duthost.remove_acl_table(ACL_TABLE_NAME_V6)

        # Create loopback interfaces for v4 and v6 tunnel sources (dual-stack).
        duthost.shell("config int ip add Loopback6 10.10.1.1")
        duthost.shell("config int ip add Loopback7 10.10.2.2")
        duthost.shell(f"config interface add {LOOPBACK_V6_NAME}", module_ignore_errors=True)
        duthost.shell(f"config int ip add {LOOPBACK_V6_NAME} {LOOPBACK_V6_IP}/128")
        loopback_ip = "10.10.1.1"
        loopback_v6_ip = LOOPBACK_V6_IP

        # Set up two vxlan tunnels: IPv4-underlay + IPv6-underlay.
        # Written straight to CONFIG_DB: back-to-back gnmi sets on the VXLAN_TUNNEL
        # container path replace each other (tunnel_v4 gets wiped by the
        # tunnel_v6 write).
        setup_vxlan_tunnel(duthost, TUNNEL_V4_NAME, loopback_ip)
        setup_vxlan_tunnel(duthost, TUNNEL_V6_NAME, loopback_v6_ip)

        # Set up vnets - dual-stack via `vxlan_tunnel_list`.
        # orchagent enforces max 1 v4 + 1 v6 tunnel and dispatches per endpoint AF.
        # Written straight to CONFIG_DB to bypass translib yang (VNET yang lacks vxlan_tunnel_list).
        vnet_vnis = setup_vnets(duthost, NUM_VNETS, [TUNNEL_V4_NAME, TUNNEL_V6_NAME], BASE_VNI)

        # Set up portchannels
        wl_portchannel_info = setup_portchannels(duthost, ptfhost, config_facts,
                                                 port_indexes, ptf_ports_available_in_topo)

        # Set up subintfs (IPv4 + IPv6 addresses for MP-BGP next-hop resolution)
        subintfs_info = setup_portchannel_subintfs(
            duthost,
            ptfhost,
            wl_portchannel_info,
            vnet_vnis,
            base_vlan=10)

        # Generate and setup vnet routes
        vnet_routes_v6 = generate_vnet_routes_v6(vnet_vnis, start_vni=10000, num_routes_per_vnet=5,
                                                 include_default_route=False)
        vnet_routes_v4 = generate_vnet_routes_v4(
            vnet_vnis,
            start_prefix_int=int(ipaddress.IPv4Address("30.0.0.0")),
            start_endpoint_int=int(ipaddress.IPv4Address(TUNNEL_ENDPOINT)),
            start_vni=10000, num_routes_per_vnet=5)
        # Dual-stack addition: VNET routes with IPv6 endpoints. Overlay prefix
        # is IPv4 so we can reuse the same inner-packet builder; the outer
        # header will be IPv6 because orchagent picks tunnel_v6 for these.
        # Two variants: with explicit vni + mac_address, and without (orchagent
        # applies VNET default vni + SWITCH_VXLAN_ROUTER_MAC).
        vnet_routes_v6_endpoint = generate_vnet_routes_v6_endpoint(
            vnet_vnis,
            start_prefix_int=int(ipaddress.IPv4Address("40.0.0.0")),
            start_vni=20000,
            num_routes_per_vnet=5,
            include_vni_mac=True)
        vnet_routes_v6_endpoint_defaults = generate_vnet_routes_v6_endpoint(
            vnet_vnis,
            start_prefix_int=int(ipaddress.IPv4Address("41.0.0.0")),
            start_vni=25000,
            num_routes_per_vnet=5,
            endpoint_offset=0x10,
            include_vni_mac=False)
        all_vnet_routes = {
            vni: (vnet_routes_v4[vni] + vnet_routes_v6[vni]
                  + vnet_routes_v6_endpoint[vni] + vnet_routes_v6_endpoint_defaults[vni])
            for vni in vnet_vnis
        }
        setup_vnet_routes(duthost, ptfhost, vnet_vnis, all_vnet_routes)

        # Setup acl configs (only for the v4/v6-overlay routes; the v6-endpoint
        # routes are exercised through a separate, non-ACL packet-test path.)
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        setup_acl_config(duthost, ptfhost, list(config_facts.get("PORTCHANNEL", {}).keys()),
                         vnet_vnis, vnet_routes_v4, vnet_routes_v6)

        # Install IPv6 overlay routes after ACL setup
        setup_vnet_routes(duthost, ptfhost, vnet_vnis, vnet_routes_v6)

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
    # Dual-stack addition: encap configs for the v6-endpoint routes. Inner is
    # IPv4 traffic destined to the v6-endpoint prefix; expected outer is
    # VXLAN over IPv6 with src = Loopback8 v6 and dst = v6 endpoint.
    _router_mac = duthost.facts['router_mac']
    encap_test_configs_v6_endpoint = [
        {
            "inner_dst_ip_v4": route_v6ep["prefix"].split('/')[0],
            "expected_dst_mac": route_v6ep["mac_address"],
            "expected_vni": route_v6ep["vni"],
            "expected_inner_src_mac": _router_mac,
            "expected_dst_ip_v6": route_v6ep["endpoint"],
            "expected_src_ip_v6": loopback_v6_ip,
            "vlan": val["vlan"],
            "vni": val["vnet_vni"],
            "outgoing_port": val["ptf_port_index"],
            "expected_ports": t1_ptf_port_nums,
            "route_v6_endpoint": route_v6ep,
        }
        for _, val in subintfs_info.items()
        for route_v6ep in vnet_routes_v6_endpoint[val["vnet_vni"]]
    ]
    # When VNET_ROUTE_TUNNEL omits vni/mac_address, orchagent uses the VNET's
    # own vni and SWITCH_VXLAN_ROUTER_MAC (set via configure_vxlan_switch).
    encap_test_configs_v6_endpoint_defaults = [
        {
            "inner_dst_ip_v4": route_v6ep["prefix"].split('/')[0],
            "expected_dst_mac": "00:12:34:56:78:9a",
            "expected_vni": val["vnet_vni"],
            "expected_inner_src_mac": _router_mac,
            "expected_dst_ip_v6": route_v6ep["endpoint"],
            "expected_src_ip_v6": loopback_v6_ip,
            "vlan": val["vlan"],
            "vni": val["vnet_vni"],
            "outgoing_port": val["ptf_port_index"],
            "expected_ports": t1_ptf_port_nums,
            "route_v6_endpoint": route_v6ep,
        }
        for _, val in subintfs_info.items()
        for route_v6ep in vnet_routes_v6_endpoint_defaults[val["vnet_vni"]]
    ]

    yield (duthost, ptfhost, ptfadapter, vnet_vnis, subintfs_info,
           encap_test_configs,
           encap_test_configs_v6_endpoint, encap_test_configs_v6_endpoint_defaults)

    # Cleanup
    cleanup(duthost, ptfhost, localhost, wl_portchannel_info, subintfs_info)


def test_vnet_with_dual_stack_vxlan_encap(common_setup_and_teardown):
    """
    Dual-stack addition test:

    With each VNET bound to both ``tunnel_v4`` and ``tunnel_v6`` via
    ``vxlan_tunnel_list``, verify that a ``VNET_ROUTE_TUNNEL`` entry whose
    endpoint is an IPv6 address is encapsulated using the IPv6-underlay
    tunnel (``tunnel_v6``) with the outer src equal to the IPv6 loopback
    (``Loopback8``) and outer dst equal to the v6 endpoint - while the
    existing v4-underlay path continues to work in parallel.
    """
    (duthost, _ptfhost, ptfadapter, _vnet_vnis, _subintfs_info,
     encap_test_configs,
     encap_test_configs_v6_endpoint,
     encap_test_configs_v6_endpoint_defaults) = common_setup_and_teardown

    # Sanity check: v4-underlay encap path still works with vxlan_tunnel_list.
    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)

    logger.info("v6-endpoint encap configs (with vni/mac): %s", encap_test_configs_v6_endpoint)
    logger.info("v6-endpoint encap configs (defaults): %s", encap_test_configs_v6_endpoint_defaults)

    # v6-underlay encap: route carries explicit vni + mac_address.
    validate_encap_wl_to_t1_v6_endpoint(duthost, ptfadapter, encap_test_configs_v6_endpoint)
    # v6-underlay encap: route omits vni/mac; orchagent applies VNET default
    # vni and SWITCH_VXLAN_ROUTER_MAC.
    validate_encap_wl_to_t1_v6_endpoint(duthost, ptfadapter, encap_test_configs_v6_endpoint_defaults)
