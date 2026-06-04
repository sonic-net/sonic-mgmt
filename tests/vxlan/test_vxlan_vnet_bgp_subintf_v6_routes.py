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
TUNNEL_ENDPOINT = "100.0.1.10"              # IPv4 outer VTEP (default-route endpoint)
INNER_SRC_IPV6 = "2001:db8:2::2"           # inner IPv6 source (workload side)
BASE_VNI = 1000
NUM_VNETS = 2

# IPv6 overlay: VNET tunnel routes use /128 prefixes from this base.
VNET_V6_PREFIX_BASE = "2001:db8:30::"
# IPv6 BGP: exabgp advertises this /64 per VRF (ECMP across sub-interfaces).
BGP_V6_DECAP_ROUTE = "2001:db8:40::/64"
BGP_V6_DECAP_IP = "2001:db8:40::1"         # address inside BGP_V6_DECAP_ROUTE for decap test

# IPv6 BGP transport addressing.
V6_LOOPBACK_IP = "fc00:1::1"               # Loopback6 v6 address (BGP src_address)
V6_SUBINT_BASE = "fc00:11::"               # base for per-(portchannel, vnet) /127 pairs
V6_BGP_RANGE = "fc00:11::/64"             # passive listener ip_range

GNMI_PATH_PREFIX = "CONFIG_DB/localhost"

temp_files = []


def _ensure_underlay_route(duthost, prefix, endpoint_probe):
    """
        Install a static v4 underlay route via vtysh if FRR does not already have it.
    """
    import json as _json

    probe_out = duthost.shell(
        f"vtysh -c 'show ip route {endpoint_probe}'",
        module_ignore_errors=True,
    )["stdout"]
    if "Routing entry" in probe_out:
        return

    bgp_out = duthost.shell("vtysh -c 'show ip bgp summary json'", module_ignore_errors=True)["stdout"]
    peer_ip = None
    try:
        peers = _json.loads(bgp_out).get("ipv4Unicast", {}).get("peers", {}) or {}
        peer_ip = next((ip for ip, p in peers.items() if p.get("state") == "Established"), None)
    except ValueError:
        pass
    pytest_assert(peer_ip, f"No established IPv4 BGP peer found for underlay route {prefix}")

    install_out = duthost.shell(
        f"vtysh -c 'configure terminal' -c 'ip route {prefix} {peer_ip}' -c 'end'",
        module_ignore_errors=True,
    )


def validate_encap_wl_to_t1(duthost, ptfadapter, test_configs):
    logger.info("Starting WL to T1 VXLAN encapsulation test...")

    for configs in test_configs:
        pkt_opts = {
            "eth_dst": duthost.facts['router_mac'],
            "eth_src": ptfadapter.dataplane.get_mac(0, configs["outgoing_port"]),
            "ipv6_dst": configs["inner_dst_ip"],
            "ipv6_src": INNER_SRC_IPV6,
            "ipv6_hlim": 64,
            "dl_vlan_enable": True,
            "vlan_vid": configs["vlan"],
            "tcp_sport": 1234,
            "tcp_dport": 5000,
            "pktlen": 100,
        }
        inner_pkt = testutils.simple_tcpv6_packet(**pkt_opts)

        # Expected inner after routing: VLAN stripped, hlim decremented, dst MAC rewritten.
        # DUT also rewrites inner src MAC to its own router_mac (no ACL to override it here).
        pkt_opts["eth_dst"] = configs["expected_dst_mac"]
        pkt_opts["ipv6_hlim"] = 63
        pkt_opts["dl_vlan_enable"] = False
        pkt_opts.pop("vlan_vid", None)  # must remove — PTF adds VLAN tag if vlan_vid is present
        pkt_opts["pktlen"] = 96  # 100 - 4 (no vlan tag)
        inner_exp_pkt = testutils.simple_tcpv6_packet(**pkt_opts)

        expected_pkt = testutils.simple_vxlan_packet(
            eth_dst="aa:bb:cc:dd:ee:ff",
            eth_src=duthost.facts['router_mac'],
            ip_src=configs["expected_src_ip"],
            ip_dst=configs["expected_dst_ip"],
            ip_id=0,
            ip_flags=0x2,
            udp_sport=1234,
            udp_dport=VXLAN_PORT,
            with_udp_chksum=False,
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
        # Mask inner Ether src MAC: DUT rewrites to its own router_mac during routing.
        # Inner frame starts at: outer Ether(14) + IP(20) + UDP(8) + VXLAN(8) = 50 bytes
        # Inner Ether src starts at byte 56 (50 + 6 inner dst MAC bytes)
        masked_expected_pkt.set_do_not_care(56 * 8, 6 * 8)

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, configs["outgoing_port"], inner_pkt)
        testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, configs["expected_ports"], timeout=2)

    logger.info("WL to T1 VXLAN encapsulation test passed.")


def validate_decap_t1_to_wl(duthost, ptfadapter, test_configs):
    logger.info("Starting T1 to WL VXLAN decapsulation test...")

    for configs in test_configs:
        pkt_opts = {
            "eth_dst": "aa:bb:cc:dd:ee:ff",
            "eth_src": duthost.facts['router_mac'],
            "ipv6_src": "2001:db8:1::1",
            "ipv6_dst": configs["inner_dst_ip"],
            "tcp_sport": 1234,
            "tcp_dport": 4321,
            "pktlen": 100,
        }
        inner_pkt = testutils.simple_tcpv6_packet(**pkt_opts)

        vxlan_pkt = testutils.simple_vxlan_packet(
            eth_dst=duthost.facts['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, configs["outgoing_port"]),
            ip_src="1.1.1.1",
            ip_dst=configs["expected_dst_ip"],
            udp_sport=1234,
            udp_dport=VXLAN_PORT,
            with_udp_chksum=False,
            vxlan_vni=int(configs["vni"]),
            inner_frame=inner_pkt,
        )

        pkt_opts["vlan_vid"] = configs["vlan"]
        pkt_opts["dl_vlan_enable"] = True
        pkt_opts["pktlen"] = 104  # 100 + 4 (add vlan tag)
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
    """Return duthost and ptfhost to original state."""
    logger.debug("cleanup: Loading backup config db json.")
    duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

    cmds = []
    try:
        for _, val in subintfs_info.items():
            sub_port = val["bond_name"]
            ip = val['ptf_ip']
            cmds.append("ip address del {} dev {}".format(ip, sub_port))
            cmds.append("ip link del {}".format(sub_port))
        ptfhost.shell_cmds(cmds=cmds)
    except Exception as e:
        logger.error(f"Error occurred while cleaning up sub interfaces: {e}")

    cmds = []
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

    for file in temp_files:
        if os.path.exists(file):
            os.remove(file)


def get_available_vlan_id_and_ports(cfg_facts, num_ports_needed):
    """Return vlan id and available ports in that vlan if there are enough ports available."""
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


def convert_ip_int_to_str(ip_int, prefix_size=31):
    """Convert integer IP to string format with prefix size."""
    return f"{ip_int >> 24 & 0xFF}.{ip_int >> 16 & 0xFF}.{ip_int >> 8 & 0xFF}.{ip_int & 0xFF}/{prefix_size}"


def convert_str_to_ip_int(ip_str):
    """Convert string IP to integer format."""
    ip_parts = ip_str.split('/')
    ip = ip_parts[0]
    octets = ip.split('.')
    ip_int = int(octets[0]) << 24 | int(octets[1]) << 16 | int(octets[2]) << 8 | int(octets[3])
    prefix = int(ip_parts[1]) if len(ip_parts) > 1 else 32
    return ip_int, prefix


def generate_subintfs_ips(num_vnets, num_portchannels, start_ip_int, prefix_size=31):
    """Generate IPv4 /31 subnets for sub-interfaces, one per (portchannel, vnet) pair."""
    num_ips_per_prefix = 2 ** (32 - prefix_size)
    pytest_assert(num_ips_per_prefix * num_portchannels + (start_ip_int & 0xFF) < 0xFF,
                  "Not enough IP addresses in last octet to allocate for subinterfaces.")
    pytest_assert(num_vnets + (start_ip_int >> 8 & 0xFF) < 0xFF,
                  "Not enough IP addresses in third octet to allocate for subinterfaces.")

    all_subintf_ips = []
    all_ptf_ips = []

    for i in range(num_portchannels):
        subintf_ips = []
        ptf_ips = []
        fourth_octet_offset = i * num_ips_per_prefix
        for j in range(num_vnets):
            ip_int = start_ip_int + fourth_octet_offset + (j << 8)
            subintf_ips.append(convert_ip_int_to_str(ip_int, prefix_size))
            ptf_ips.append(convert_ip_int_to_str(ip_int + 1, prefix_size))

        all_subintf_ips.append(subintf_ips)
        all_ptf_ips.append(ptf_ips)

    return all_subintf_ips, all_ptf_ips


def generate_subintfs_v6_ips(num_vnets, num_portchannels, prefix_size=127):
    """Generate IPv6 /127 subnets for BGP transport on sub-interfaces."""
    base = int(ipaddress.IPv6Address(V6_SUBINT_BASE))
    all_dut, all_ptf = [], []
    for j in range(num_portchannels):
        dut_row, ptf_row = [], []
        for i in range(num_vnets):
            offset = (j * num_vnets + i) * 2
            dut_row.append(f"{ipaddress.IPv6Address(base + offset)}/{prefix_size}")
            ptf_row.append(f"{ipaddress.IPv6Address(base + offset + 1)}/{prefix_size}")
        all_dut.append(dut_row)
        all_ptf.append(ptf_row)
    return all_dut, all_ptf


def generate_vnet_routes_v6(vnet_vnis, start_vni, num_routes_per_vnet, include_default_route=True):
    """Generate VNET tunnel routes with IPv6 overlay prefixes and IPv4 VTEP endpoints."""
    base = int(ipaddress.IPv6Address(VNET_V6_PREFIX_BASE))
    endpoint_base, _ = convert_str_to_ip_int(TUNNEL_ENDPOINT)
    routes = {vni: [] for vni in vnet_vnis}
    for i, vni in enumerate(vnet_vnis):
        for j in range(1, num_routes_per_vnet + 1):
            prefix_addr = ipaddress.IPv6Address(base + (i << 8) + j)
            endpoint_int = endpoint_base + (i << 8) + j
            route = {
                "prefix": f"{prefix_addr}/128",
                "endpoint": convert_ip_int_to_str(endpoint_int).split('/')[0],
                "vni": start_vni + (i * num_routes_per_vnet) + j,
                "mac_address": (f"52:54:00:{(i * num_routes_per_vnet + j) // 256:02x}:"
                                f"{(i * num_routes_per_vnet + j) % 256:02x}:aa"),
                "vnet_vni": vni,
            }
            routes[vni].append(route)
        if include_default_route:
            routes[vni].append({
                "prefix": "::/0",
                "endpoint": convert_ip_int_to_str(endpoint_base).split('/')[0],
                "vni": start_vni,
                "mac_address": "52:54:00:00:00:00",
                "vnet_vni": vni,
            })
        vni: [(r["prefix"], r["endpoint"], r["vni"]) for r in rlist]
        for vni, rlist in routes.items()
    })
    return routes


def gnmic_set_with_bypass(gnmi_tls, path, value, filename="test_config"):     # noqa: F811
    """Send GNMI set request with bypass."""
    gnmi_tls.gnmic.set(path, value, metadata="x-sonic-ss-bypass-validation=true", filename=filename)


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


def setup_bgp(duthost, ptfhost, vnet_vnis, dut_ips_v6, ptf_ips_v6,
              v6_subnet_ip, loopback_v6, bgp_port, gnmi_tls):     # noqa: F811
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    dut_asn = config_facts['DEVICE_METADATA']['localhost']['bgp_asn']
    neighbors = config_facts['BGP_NEIGHBOR']
    peer_asn = list(neighbors.values())[0]["asn"]
                dut_asn, peer_asn, loopback_v6, v6_subnet_ip)

    for vni in vnet_vnis:
        gnmic_set_with_bypass(
            gnmi_tls,
            f"{GNMI_PATH_PREFIX}/BGP_PEER_RANGE/Vnet{vni}|WLPARTNER_PASSIVE_V6",
            {
                "ip_range": [v6_subnet_ip],
                "name": "WLPARTNER_PASSIVE_V6",
                "peer_asn": peer_asn,
                "src_address": loopback_v6,
            },
            f"bgp_peer_v6_{vni}")

        # FRR 8+ blocks IPv6 EBGP updates without explicit route-maps unless this is set.
        duthost.shell(
            f"vtysh -c 'configure terminal' -c 'router bgp {dut_asn} vrf Vnet{vni}' "
            f"-c 'no bgp ebgp-requires-policy'",
            module_ignore_errors=True)

    exabgp_config = f"""
process api-vnets {{
    run /usr/bin/python /usr/share/exabgp/http_api.py {bgp_port};
    encoder json;
}}
"""

    idx = 0
    for dut_ips_pc, ptf_ips_pc in zip(dut_ips_v6, ptf_ips_v6):
        for dut_ip, ptf_ip in zip(dut_ips_pc, ptf_ips_pc):
            router_id = f"1.0.0.{idx + 1}"
            exabgp_config += f"""
neighbor {dut_ip.split('/')[0]} {{
    router-id {router_id};
    local-address {ptf_ip.split('/')[0]};
    local-as {peer_asn};
    peer-as {dut_asn};
    api {{
        processes [api-vnets];
    }}
    family {{
        ipv6 unicast;
    }}
    static {{
        route {BGP_V6_DECAP_ROUTE} next-hop {ptf_ip.split('/')[0]};
    }}
}}
"""
            idx += 1

    with open('/tmp/exabgp_update.conf', "w") as f:
        f.write(exabgp_config)

    ptfhost.copy(src='/tmp/exabgp_update.conf', dest=EXABGP_CONFIG_PATH)
    ptfhost.shell("pkill -9 -f 'exabgp' 2>/dev/null || true; sleep 2", module_ignore_errors=True)
    ptfhost.shell(f"nohup exabgp {EXABGP_CONFIG_PATH} > /var/log/exabgp_all_vnets.log 2>&1 &")

    time.sleep(60)
    for vni in vnet_vnis:
        vnet_bgps = duthost.show_and_parse(f"show ipv6 bgp vrf Vnet{vni} summary")
        pytest_assert(len(vnet_bgps) > 0, f"No IPv6 BGP sessions found for Vnet{vni}.")
        for val in vnet_bgps:
            pytest_assert(
                val["neighborname"] == "WLPARTNER_PASSIVE_V6"
                and val["state/pfxrcd"].isdigit()
                and int(val["state/pfxrcd"]) > 0,
                f"IPv6 BGP neighbor not up or no routes received for Vnet{vni}.")


def setup_portchannel_subintfs(duthost, ptfhost, portchannel_info,
                               vnet_vnis, base_vlan, dut_ips, ptf_ips,
                               dut_ips_v6, ptf_ips_v6, gnmi_tls):     # noqa: F811
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
                        "vnet_name": f"Vnet{vnet_vnis[i]}"
                    },
                    f"{subintf_name}|{dut_ips[j][i]}": {}
                }, subintf_name)
                has_subintfs = True
            else:
                gnmic_set_with_bypass(
                    gnmi_tls,
                    f"{GNMI_PATH_PREFIX}/VLAN_SUB_INTERFACE/{subintf_name}",
                    {
                        "admin_status": "up",
                        "vlan": str(base_vlan + i),
                        "vnet_name": f"Vnet{vnet_vnis[i]}"
                    },
                    subintf_name)
                gnmic_set_with_bypass(
                    gnmi_tls,
                    f"{GNMI_PATH_PREFIX}/VLAN_SUB_INTERFACE/{subintf_name}|{dut_ips[j][i].replace('/','~1')}",
                    {},
                    f"{subintf_name}_ip")

            # Add IPv6 address to sub-interface for BGP transport.
                        subintf_name, dut_ips[j][i], dut_ips_v6[j][i], ptf_ips[j][i], ptf_ips_v6[j][i])
            duthost.shell(f"config interface ip add {subintf_name} {dut_ips_v6[j][i]}",
                          module_ignore_errors=True)

            cmds.append(f"ip link add link {bond_port} name {bond_port}.{base_vlan + i} type vlan id {base_vlan + i}")
            cmds.append(f"ip address add {ptf_ips[j][i]} dev {bond_port}.{base_vlan + i}")
            cmds.append(f"ip -6 address add {ptf_ips_v6[j][i]} dev {bond_port}.{base_vlan + i}")
            cmds.append(f"ip link set {bond_port}.{base_vlan + i} up")

            subintfs_info[subintf_name] = {
                "portchannel_name": key,
                "portchannel_num": po_num,
                "ptf_port_index": val["ptf_port_index"],
                "bond_name": f"{bond_port}.{base_vlan + i}",
                "dut_ip": dut_ips[j][i],
                "ptf_ip": ptf_ips[j][i],
                "vlan": base_vlan + i,
                "vnet": f"Vnet{vnet_vnis[i]}",
                "vnet_vni": vnet_vnis[i],
            }

    ptfhost.shell_cmds(cmds=cmds)
    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)

    interfaces_key = "STATE_DB/localhost/INTERFACE_TABLE"
    interfaces = gnmi_tls.gnmic.get(interfaces_key)[0].get("updates")[0].get("values", {}).get(interfaces_key, {})
    for subintf, values in subintfs_info.items():
        subintf_vnet = interfaces.get(subintf, {}).get("vrf", "")
        subintf_status = interfaces.get(f"{subintf}|{values['dut_ip']}", {}).get("state", "")

        pytest_assert(subintf_vnet.lower() == values["vnet"].lower(),
                      f"Subinterface {subintf} not in correct vnet. Expected {values['vnet']}, got {subintf_vnet}.")
        pytest_assert(subintf_status.lower() == "ok", f"Subinterface {subintf} not in ok state.")

    return subintfs_info


def setup_portchannels(duthost, ptfhost, config_facts, port_indexes,
                       ptf_ports_available_in_topo, gnmi_tls):     # noqa: F811
    vlan_id, ports = get_available_vlan_id_and_ports(config_facts, len(PORTCHANNEL_NAMES))
    pytest_assert(len(ports) == len(PORTCHANNEL_NAMES),
                  f"Found {len(ports)} available ports. Needed {len(PORTCHANNEL_NAMES)} ports for the test.")

    cmds = []
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
                    PORTCHANNEL_NAMES[i], bond_port, ptf_port_name, ptf_port_index)

    ptfhost.shell_cmds(cmds=cmds)
    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)

    for portchannel_name in PORTCHANNEL_NAMES:
        portchannel_key = f"STATE_DB/localhost/LAG_TABLE/{portchannel_name}"
        portchannel_status = gnmi_tls.gnmic.get(portchannel_key)[0].get("updates")[0].get("values", {})\
            .get(portchannel_key, {})
                    portchannel_name,
                    portchannel_status.get("admin_status"),
                    portchannel_status.get("oper_status"))

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


def setup_vxlan_tunnel(name, src_ip, gnmi_tls):     # noqa: F811
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/VXLAN_TUNNEL", {
        name: {
            "src_ip": src_ip
        }
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

        duthost.remove_acl_table("EVERFLOW")
        duthost.remove_acl_table("EVERFLOWV6")

        # Loopback6: IPv4 address for VTEP, IPv6 address for BGP src_address.
        duthost.shell("config int ip add Loopback6 10.10.1.1")
        loopback_ip = "10.10.1.1"
        duthost.shell(f"config interface ip add Loopback6 {V6_LOOPBACK_IP}/128")
        loopback_v6 = V6_LOOPBACK_IP

        subnet_ip = "10.11.0.0/16"
        subnet_ip_int, _ = convert_str_to_ip_int(subnet_ip)

        setup_vxlan_tunnel("tunnel_v4", loopback_ip, gnmi_tls)
        vnet_vnis = setup_vnets(NUM_VNETS, "tunnel_v4", BASE_VNI, gnmi_tls)

        wl_portchannel_info = setup_portchannels(duthost, ptfhost, config_facts,
                                                 port_indexes, ptf_ports_available_in_topo, gnmi_tls)

        dut_ips, ptf_ips = generate_subintfs_ips(NUM_VNETS, len(PORTCHANNEL_NAMES), start_ip_int=subnet_ip_int)
        dut_ips_v6, ptf_ips_v6 = generate_subintfs_v6_ips(NUM_VNETS, len(PORTCHANNEL_NAMES))

        subintfs_info = setup_portchannel_subintfs(
            duthost,
            ptfhost,
            wl_portchannel_info,
            vnet_vnis,
            base_vlan=10,
            dut_ips=dut_ips,
            ptf_ips=ptf_ips,
            dut_ips_v6=dut_ips_v6,
            ptf_ips_v6=ptf_ips_v6,
            gnmi_tls=gnmi_tls)

        setup_bgp(duthost,
            ptfhost,
            vnet_vnis,
            dut_ips_v6,
            ptf_ips_v6,
            v6_subnet_ip=V6_BGP_RANGE,
            loopback_v6=loopback_v6,
            bgp_port=EXABGP_PORT,
            gnmi_tls=gnmi_tls)

        vnet_routes = generate_vnet_routes_v6(vnet_vnis, start_vni=10000, num_routes_per_vnet=5)
        setup_vnet_routes(vnet_vnis, vnet_routes, gnmi_tls)

        # Collect all unique /24 subnets used as tunnel endpoint destinations and
        # install a static underlay route for each.
        tunnel_ep_subnets: dict[str, str] = {}  # subnet -> one sample endpoint
        for vni_routes in vnet_routes.values():
            for route in vni_routes:
                ep = route.get("endpoint", "")
                if ep:
                    subnet = str(ipaddress.IPv4Network(f"{ep}/24", strict=False))
                    tunnel_ep_subnets.setdefault(subnet, ep)
        for subnet, probe_ep in sorted(tunnel_ep_subnets.items()):
            _ensure_underlay_route(duthost, subnet, probe_ep)

        ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

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

        pytest_assert(len(t1_ptf_port_nums) > 0, "No T1 side portchannel member ports found.")
    except Exception as e:
        logger.error(f"Exception during setup: {repr(e)}.")
        cleanup(duthost, ptfhost, localhost, wl_portchannel_info, subintfs_info)
        pytest.fail(f"Setup failed: {repr(e)}")

    ports_per_vnet = {}
    for _, val in subintfs_info.items():
        vni = val["vnet_vni"]
        if vni not in ports_per_vnet:
            ports_per_vnet[vni] = []
        ports_per_vnet[vni].append(val["ptf_port_index"])

    decap_test_configs = [
        {
            "inner_dst_ip": BGP_V6_DECAP_IP,
            "expected_dst_ip": loopback_ip,
            "vni": val["vnet_vni"],
            "vlan": val["vlan"],
            "outgoing_port": t1_ptf_port_nums[0],
            "expected_ports": ports_per_vnet[val["vnet_vni"]],
        } for _, val in subintfs_info.items()
    ]
    encap_test_configs = [
        {
            "inner_dst_ip": route["prefix"].split('/')[0] if route["prefix"] != "::/0" else "2001:db8:fa::10",
            "expected_dst_mac": route["mac_address"],
            "expected_vni": route["vni"],
            "expected_dst_ip": route["endpoint"],
            "expected_src_ip": loopback_ip,
            "vlan": val["vlan"],
            "vni": val["vnet_vni"],
            "outgoing_port": val["ptf_port_index"],
            "expected_ports": t1_ptf_port_nums,
            "route": route,
        } for _, val in subintfs_info.items() for route in vnet_routes[val["vnet_vni"]]
    ]

    yield duthost, ptfadapter, encap_test_configs, decap_test_configs

    cleanup(duthost, ptfhost, localhost, wl_portchannel_info, subintfs_info)


def modify_routes_mac_vni_v6(gnmi_tls, encap_test_configs, offset=1):
    modified_routes = set()

    for config in encap_test_configs:
        route = config["route"]

        if route["prefix"] not in modified_routes:
            route["vni"] += offset
            route["mac_address"] = route["mac_address"][:-2] + \
                "{:02x}".format((int(route["mac_address"][-2:], 16) + offset) % 256)
            route["endpoint"] = convert_ip_int_to_str(
                convert_str_to_ip_int(route["endpoint"])[0] + offset
            ).split('/')[0]

            logger.info("modify_routes_mac_vni_v6: updating Vnet%s|%s -> endpoint=%s vni=%s mac=%s",
                        route['vnet_vni'], route['prefix'],
                        route['endpoint'], route['vni'], route['mac_address'])
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
            modified_routes.add(route["prefix"])

        config["expected_vni"] = route["vni"]
        config["expected_dst_mac"] = route["mac_address"]
        config["expected_dst_ip"] = route["endpoint"]

    time.sleep(5)
    for config in encap_test_configs:
        route_key = "STATE_DB/localhost/VNET_ROUTE_TUNNEL_TABLE"
        route_status = gnmi_tls.gnmic.get(route_key)[0].get("updates")[0].get("values", {}).get(route_key, {})\
            .get(f"Vnet{config['route']['vnet_vni']}|{config['route']['prefix']}", {}).get("state", "")
        pytest_assert(route_status.lower() == "active",
                      f"VNET route tunnel for Vnet{config['route']['vnet_vni']}|"
                      f"{config['route']['prefix']} not active after mac/vni update.")


def test_vnet_with_bgp_intf_v6_routes(common_setup_and_teardown, gnmi_tls):     # noqa: F811
    #Validate VXLAN VNET tunnel routes with IPv6 inner packets (outer IPv4).

    duthost, ptfadapter, encap_test_configs, decap_test_configs = common_setup_and_teardown
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    logger.debug("post-setup config_facts: {}".format(config_facts))
    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)
    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)


def test_vnet_with_bgp_intf_v6_routes_modify_mac_vni(common_setup_and_teardown, gnmi_tls):     # noqa: F811
    duthost, ptfadapter, encap_test_configs, decap_test_configs = common_setup_and_teardown

    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)
    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)

    # Modify route mac/vni/endpoint and verify datapath.
    modify_routes_mac_vni_v6(gnmi_tls, encap_test_configs, offset=1)

    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)
    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)
