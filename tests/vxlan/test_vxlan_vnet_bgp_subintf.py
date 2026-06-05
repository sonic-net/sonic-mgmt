import logging
import os
from ptf.mask import Mask
from ptf.packet import Ether, IP, UDP, TCP
import ptf.testutils as testutils
import pytest
import time
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.fixtures.grpc_fixtures import gnmi_tls    # noqa: F401

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
INNER_SRC_MAC = "00:11:22:33:44:55"
INNER_SRC_IP = "2.2.2.2"
BASE_VNI = 1000
NUM_VNETS = 2

ACL_TYPE_NAME = "INNER_SRC_MAC_REWRITE_TYPE"
ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"

GNMI_PATH_PREFIX = "CONFIG_DB/localhost"

temp_files = []


def validate_encap_wl_to_t1(duthost, ptfadapter, test_configs):
    logger.info("Starting WL to T1 VXLAN encapsulation test...")

    for configs in test_configs:
        # Build inner TCP packet to inject from southbound side
        pkt_opts = {
            "eth_dst": duthost.facts['router_mac'],
            "eth_src": ptfadapter.dataplane.get_mac(0, configs["outgoing_port"]),
            "ip_dst": configs["inner_dst_ip"],
            "ip_src": INNER_SRC_IP,
            "ip_id": 105,
            "ip_ttl": 64,
            "dl_vlan_enable": True,
            "vlan_vid": configs["vlan"],
            "tcp_sport": 1234,
            "tcp_dport": 5000,
            "pktlen": 100
        }

        inner_pkt = testutils.simple_tcp_packet(**pkt_opts)

        # Build expected packet
        pkt_opts["eth_src"] = INNER_SRC_MAC  # expected rewritten inner src mac
        pkt_opts["eth_dst"] = configs["expected_dst_mac"]
        pkt_opts["ip_ttl"] = 63
        pkt_opts["dl_vlan_enable"] = False
        pkt_opts["pktlen"] = 96  # 100 - 4, remove vlan tag length

        inner_exp_pkt = testutils.simple_tcp_packet(**pkt_opts)

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
            inner_frame=inner_exp_pkt
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

        # Clear packet queue on all ports and get initial acl counter
        ptfadapter.dataplane.flush()

        # Send TCP packet from WL port
        testutils.send(ptfadapter, configs["outgoing_port"], inner_pkt)

        # Verify VXLAN encapsulated pkt on T1 port with rewritten inner src MAC
        testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, configs["expected_ports"], timeout=2)

    logger.info("WL to T1 VXLAN encapsulation test passed.")


def validate_decap_t1_to_wl(duthost, ptfadapter, test_configs):
    logger.info("Starting T1 to WL VXLAN decapsulation test...")

    for configs in test_configs:
        pkt_opts = {
            "eth_dst": "aa:bb:cc:dd:ee:ff",
            "eth_src": duthost.facts['router_mac'],
            "ip_src": "8.8.8.8",
            "ip_dst": configs["inner_dst_ip"],
            "tcp_sport": 1234,
            "tcp_dport": 4321,
            "pktlen": 100
        }

        # Build inner TCP packet expected on WL port
        inner_pkt = testutils.simple_tcp_packet(**pkt_opts)

        # Build VXLAN encapsulated packet to inject from T1 side
        vxlan_pkt = testutils.simple_vxlan_packet(
            eth_dst=duthost.facts['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, configs["outgoing_port"]),
            ip_src="1.1.1.1",
            ip_dst=configs["expected_dst_ip"],
            udp_sport=1234,
            udp_dport=VXLAN_PORT,
            with_udp_chksum=False,
            vxlan_vni=int(configs["vni"]),
            inner_frame=inner_pkt
        )

        # Build expected inner packet after decapsulation
        pkt_opts["vlan_vid"] = configs["vlan"]
        pkt_opts["dl_vlan_enable"] = True
        pkt_opts["pktlen"] = 104     # 100 + 4, add vlan tag length
        expected_inner_pkt = testutils.simple_tcp_packet(**pkt_opts)

        masked_expected_pkt = Mask(expected_inner_pkt)
        masked_expected_pkt.set_ignore_extra_bytes()
        masked_expected_pkt.set_do_not_care_packet(Ether, 'dst')
        masked_expected_pkt.set_do_not_care_packet(IP, "ttl")
        masked_expected_pkt.set_do_not_care_packet(IP, "chksum")
        masked_expected_pkt.set_do_not_care_packet(IP, "id")
        masked_expected_pkt.set_do_not_care_packet(TCP, 'chksum')
        masked_expected_pkt.set_do_not_care_packet(IP, "len")
        masked_expected_pkt.set_do_not_care_packet(IP, "tos")

        # Clear packet queue on all ports
        ptfadapter.dataplane.flush()

        # Send VXLAN encapsulated pkt from T1 port
        testutils.send(ptfadapter, configs["outgoing_port"], vxlan_pkt)

        # Verify decapsulated unencapsulated packet on southbound port
        testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, configs["expected_ports"], timeout=2)

    logger.info("T1 to WL VXLAN decapsulation test passed.")


def cleanup(duthost, ptfhost, localhost, wl_portchannel_info, subintfs_info):
    """
    Return duthost and ptfhost to original state.

    Args:
        duthost: DUT host
        ptfhost: PTF host
        bond_port_mapping: map of bond port name (bond#) to ptf port name (eth#)
    """
    # Restore config db
    logger.debug("cleanup: Loading backup config db json.")
    duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

    cmds = []
    # Remove sub port
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
    # Remove bond ports
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

    # Stop exabgp process
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

    # Remove tmp files
    for file in temp_files:
        if os.path.exists(file):
            os.remove(file)


def get_available_vlan_id_and_ports(cfg_facts, num_ports_needed):
    """
    Return vlan id and available ports in that vlan if there are enough ports available.

    Args:
        cfg_facts: DUT config facts
        num_ports_needed: number of available ports needed for test
    """
    port_status = cfg_facts["PORT"]
    vlan_id = -1
    available_ports = []
    pytest_require("VLAN_MEMBER" in cfg_facts, "Can't get vlan member")
    for vlan_name, members in list(cfg_facts["VLAN_MEMBER"].items()):
        # Number of members in vlan is insufficient
        if len(members) < num_ports_needed:
            continue

        # Get available ports in vlan
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
    """
    Convert integer IP to string format with prefix size.
    """
    return f"{ip_int >> 24 & 0xFF}.{ip_int >> 16 & 0xFF}.{ip_int >> 8 & 0xFF}.{ip_int & 0xFF}/{prefix_size}"


def convert_str_to_ip_int(ip_str):
    """
    Convert string IP to integer format.
    """
    ip_parts = ip_str.split('/')
    ip = ip_parts[0]
    octets = ip.split('.')
    ip_int = int(octets[0]) << 24 | int(octets[1]) << 16 | int(octets[2]) << 8 | int(octets[3])
    prefix = int(ip_parts[1]) if len(ip_parts) > 1 else 32
    return ip_int, prefix


def generate_subintfs_ips(num_vnets, num_portchannels, start_ip_int, prefix_size=31):
    """
    Generate subnets for subintfs, incrementing third octect for each vnet, and fourth octet for each portchannel.
    """
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
            subintf_ips.append(
                convert_ip_int_to_str(ip_int, prefix_size)
            )
            ptf_ips.append(
                convert_ip_int_to_str(ip_int + 1, prefix_size)
            )

        all_subintf_ips.append(subintf_ips)
        all_ptf_ips.append(ptf_ips)

    return all_subintf_ips, all_ptf_ips


def generate_vnet_routes(vnet_vnis, start_prefix_int, start_endpoint_int, start_vni,
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
                "prefix": convert_ip_int_to_str(prefix_int, 32),
                "endpoint": convert_ip_int_to_str(endpoint_int).split('/')[0],
                "vni": start_vni + (i * num_routes_per_vnet) + j,
                "mac_address": f"52:54:00:{(i << 8 + j + offset)//256:02x}:{(i << 8 + j + offset)%256:02x}:aa",
                "vnet_vni": vni
            }
            routes[vni].append(route)

        if include_default_route:
            route = {
                "prefix": "0.0.0.0/0",
                "endpoint": convert_ip_int_to_str(start_endpoint_int).split('/')[0],
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


def setup_acl_config(duthost, ports, vnet_vnis, vnet_routes, gnmi_tls):     # noqa: F811
    """
    Add a custom ACL table type definition to CONFIG_DB.
    """
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/ACL_TABLE_TYPE", {
        ACL_TYPE_NAME: {
            "BIND_POINTS": [
                "PORT",
                "PORTCHANNEL"
            ],
            "MATCHES": [
                "INNER_SRC_IP",
                "TUNNEL_VNI"
            ],
            "ACTIONS": [
                "COUNTER",
                "INNER_SRC_MAC_REWRITE_ACTION"
            ]
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

    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/ACL_RULE", {
        f"{ACL_TABLE_NAME}|rule_{route['vni']}": {
            "INNER_SRC_IP": f"{INNER_SRC_IP}/32",
            "INNER_SRC_MAC_REWRITE_ACTION": INNER_SRC_MAC,
            "TUNNEL_VNI": f"{route['vni']}",
            "PRIORITY": f"{route['vni']}"
        } for vni in vnet_vnis for route in vnet_routes[vni]
    }, "acl_rule")

    # Check acl table and rules are set
    def _acl_table_and_rule_active(duthost):
        table_key = f"STATE_DB/localhost/ACL_TABLE_TABLE/{ACL_TABLE_NAME}/status"
        acl_table_status = gnmi_tls.gnmic.get(table_key)[0].get("updates")[0].get("values", {}).get(table_key, {})
        if acl_table_status.lower() != "active":
            return False

        rule_key = "STATE_DB/localhost/ACL_RULE_TABLE"
        acl_rules = gnmi_tls.gnmic.get(rule_key)[0].get("updates")[0].get("values", {}).get(rule_key, {})
        for vni in vnet_vnis:
            for route in vnet_routes[vni]:
                acl_rule_status = acl_rules.get(f"{ACL_TABLE_NAME}|rule_{route['vni']}", {}).get("status", "")
                if acl_rule_status.lower() != "active":
                    return False
        return True

    pytest_assert(wait_until(60, 2, 0, _acl_table_and_rule_active, duthost),
                  f"ACL table {ACL_TABLE_NAME} or its rules not active after 60 seconds.")


def setup_vnet_routes(vnet_vnis, vni_to_routes, gnmi_tls):     # noqa: F811
    gnmic_set_with_bypass(gnmi_tls, f"{GNMI_PATH_PREFIX}/VNET_ROUTE_TUNNEL", {
        f"Vnet{vni}|{route['prefix']}": {
            "endpoint": route["endpoint"],
            "vni": route["vni"],
            "mac_address": route["mac_address"]
        } for vni in vnet_vnis for route in vni_to_routes[vni]
    }, "vnet_routes")

    # Check vnet routes are set
    time.sleep(5)
    for vni in vnet_vnis:
        for route in vni_to_routes[vni]:
            route_key = "STATE_DB/localhost/VNET_ROUTE_TUNNEL_TABLE"
            route_status = gnmi_tls.gnmic.get(route_key)[0].get("updates")[0].get("values", {}).get(route_key, {})\
                .get(f"Vnet{vni}|{route['prefix']}", {}).get("state", "")
            pytest_assert(route_status.lower() == "active",
                          f"VNET route tunnel for Vnet{vni}|{route['prefix']} not active.")


def setup_bgp(duthost, ptfhost, vnet_vnis, dut_ips, ptf_ips,
              subnet_ip, loopback_ip, bgp_port, vnet_route_ip, gnmi_tls):     # noqa: F811
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    dut_asn = config_facts['DEVICE_METADATA']['localhost']['bgp_asn']
    neighbors = config_facts['BGP_NEIGHBOR']
    peer_asn = list(neighbors.values())[0]["asn"]

    for vni in vnet_vnis:
        gnmic_set_with_bypass(
            gnmi_tls,
            f"{GNMI_PATH_PREFIX}/BGP_PEER_RANGE/Vnet{vni}|WLPARTNER_PASSIVE_V4",
            {
                "ip_range": [subnet_ip],
                "name": "WLPARTNER_PASSIVE_V4",
                "peer_asn": peer_asn,
                "src_address": loopback_ip
            },
            f"bgp_peer_{vni}")

    exabgp_config = f"""
process api-vnets {{
    run /usr/bin/python /usr/share/exabgp/http_api.py {bgp_port};
    encoder json;
}}
"""

    for dut_ips_per_portchannel, ptf_ips_per_portchannel in zip(dut_ips, ptf_ips):
        for dut_ip, ptf_ip in zip(dut_ips_per_portchannel, ptf_ips_per_portchannel):
            exabgp_config += f"""
neighbor {dut_ip.split('/')[0]} {{
    router-id {ptf_ip.split('/')[0]};
    local-address {ptf_ip.split('/')[0]};
    local-as {peer_asn};
    peer-as {dut_asn};
    api {{
        processes [api-vnets];
    }}
    family {{
        ipv4 unicast;
    }}
    static {{
        route {vnet_route_ip} next-hop {ptf_ip.split('/')[0]};
    }}
}}
"""

    with open('/tmp/exabgp_update.conf', "w") as f:
        f.write(exabgp_config)

    ptfhost.copy(src='/tmp/exabgp_update.conf', dest=EXABGP_CONFIG_PATH)
    ptfhost.shell(f"nohup exabgp {EXABGP_CONFIG_PATH} > /var/log/exabgp_all_vnets.log 2>&1 &")

    # Check vrf bgp session is up
    time.sleep(40)
    for vni in vnet_vnis:
        vnet_bgps = duthost.show_and_parse(f"show ip bgp vrf Vnet{vni} summary")
        pytest_assert(len(vnet_bgps) > 0, f"No BGP sessions found for vnet Vnet{vni}.")
        for val in vnet_bgps:
            pytest_assert(val["neighborname"] == "WLPARTNER_PASSIVE_V4" and val["state/pfxrcd"].isdigit()
                          and int(val["state/pfxrcd"]) > 0, f"BGP neighbor not found for vnet Vnet{vni}.")


def setup_portchannel_subintfs(duthost, ptfhost, portchannel_info,
                               vnet_vnis, base_vlan, dut_ips, ptf_ips, gnmi_tls):     # noqa: F811
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

            # Configure ptf port commands
            cmds.append(f"ip link add link {bond_port} name {bond_port}.{base_vlan + i} type vlan id {base_vlan + i}")
            cmds.append(f"ip address add {ptf_ips[j][i]} dev {bond_port}.{base_vlan + i}")
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

    # Check subinterfaces are up in state db
    interfaces_key = "STATE_DB/localhost/INTERFACE_TABLE"
    interfaces = gnmi_tls.gnmic.get(interfaces_key)[0].get("updates")[0].get("values", {}).get(interfaces_key, {})
    for subintf, values in subintfs_info.items():
        subintf_vnet = interfaces.get(subintf, {}).get("vrf", "")
        subintf_status = interfaces.get(f"{subintf}|{values['dut_ip']}", {}).get("state", "")

        pytest_assert(subintf_vnet.lower() == values["vnet"].lower(), f"Subinterface {subintf} not in correct vnet. \
                      Expected {values['vnet']}, got {subintf_vnet}.")
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

        # Configure ptf port commands
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

    # Validate portchannel is up in state db
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

    # Validate vnet is set in state db
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

    # backup config_db.json for cleanup
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    wl_portchannel_info = None
    subintfs_info = None

    try:
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

        port_indexes = config_facts['port_index_map']  # map of dut port name to dut port index
        duts_map = tbinfo["duts_map"]
        dut_indx = duts_map[duthost.hostname]
        # Get available ports in PTF
        host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]  # map of ptf port index to dut port index
        ptf_ports_available_in_topo = {}
        for key in host_interfaces:
            ptf_ports_available_in_topo[host_interfaces[key]] = {  # map of dut port index to ptf port info
                "index": int(key),
                "name": "eth{}".format(int(key))
            }

        # Remove everflow acl tables
        duthost.remove_acl_table("EVERFLOW")
        duthost.remove_acl_table("EVERFLOWV6")

        # Create loopback interface
        duthost.shell("config int ip add Loopback6 10.10.1.1")
        loopback_ip = "10.10.1.1"

        subnet_ip = "10.11.0.0/16"
        subnet_ip_int, _ = convert_str_to_ip_int(subnet_ip)

        # Set up vxlan
        setup_vxlan_tunnel("tunnel_v4", loopback_ip, gnmi_tls)

        #  Set up vnets
        vnet_vnis = setup_vnets(NUM_VNETS, "tunnel_v4", BASE_VNI, gnmi_tls)

        # Set up portchannels
        wl_portchannel_info = setup_portchannels(duthost, ptfhost, config_facts,
                                                 port_indexes, ptf_ports_available_in_topo, gnmi_tls)

        # Set up subintfs
        dut_ips, ptf_ips = generate_subintfs_ips(NUM_VNETS, len(PORTCHANNEL_NAMES), start_ip_int=subnet_ip_int)
        subintfs_info = setup_portchannel_subintfs(
            duthost,
            ptfhost,
            wl_portchannel_info,
            vnet_vnis,
            base_vlan=10,
            dut_ips=dut_ips,
            ptf_ips=ptf_ips,
            gnmi_tls=gnmi_tls)

        # Set up bgps
        setup_bgp(
            duthost,
            ptfhost,
            vnet_vnis,
            dut_ips,
            ptf_ips,
            subnet_ip,
            loopback_ip,
            bgp_port=EXABGP_PORT,
            vnet_route_ip=subnet_ip,
            gnmi_tls=gnmi_tls)

        # Set up vnet routes
        vnet_routes = generate_vnet_routes(vnet_vnis, start_prefix_int=convert_str_to_ip_int("30.0.0.0")[0],
                                           start_endpoint_int=convert_str_to_ip_int(TUNNEL_ENDPOINT)[0],
                                           start_vni=10000, num_routes_per_vnet=5)
        setup_vnet_routes(vnet_vnis, vnet_routes, gnmi_tls)

        # Setup acl configs
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        setup_acl_config(duthost, list(config_facts.get("PORTCHANNEL", {}).keys()), vnet_vnis, vnet_routes, gnmi_tls)

        # Configure vxlan port
        ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

        # Get ptf eth of T1 portchannels
        t1_ptf_port_nums = []
        portchannel_members = config_facts.get("PORTCHANNEL_MEMBER", {})
        for key in portchannel_members:
            members = list(portchannel_members[key].keys())
            for intf in members:
                dut_port_idx = port_indexes.get(intf)
                if dut_port_idx is None:
                    continue
                ptf_port = ptf_ports_available_in_topo.get(dut_port_idx)
                if ptf_port is None:
                    # Port not in this DUT's ptf_map (e.g. dualtor: port on other ToR)
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

    decap_test_configs = [
        {
            "inner_dst_ip": "10.11.255.255",
            "expected_dst_ip": loopback_ip,
            "vni": val["vnet_vni"],
            "vlan": val["vlan"],
            "outgoing_port": t1_ptf_port_nums[0],
            "expected_ports": ports_per_vnet[val["vnet_vni"]]
        } for _, val in subintfs_info.items()
    ]
    encap_test_configs = [
        {
            "inner_dst_ip": route["prefix"].split('/')[0] if route["prefix"] != "0.0.0.0/0" else "150.0.0.10",
            "expected_dst_mac": route["mac_address"],
            "expected_vni": route["vni"],
            "expected_dst_ip": route["endpoint"],
            "expected_src_ip": loopback_ip,
            "vlan": val["vlan"],
            "vni": val["vnet_vni"],
            "outgoing_port": val["ptf_port_index"],
            "expected_ports": t1_ptf_port_nums,
            "route": route
        } for _, val in subintfs_info.items() for route in vnet_routes[val["vnet_vni"]]
    ]
    yield duthost, ptfadapter, encap_test_configs, decap_test_configs

    # Cleanup
    cleanup(duthost, ptfhost, localhost, wl_portchannel_info, subintfs_info)


def modify_routes_mac_vni(gnmi_tls, encap_test_configs, offset=0):     # noqa: F811
    modified_routes = set()
    acl_rule_value = {}

    for config in encap_test_configs:
        route = config["route"]

        if route["prefix"] not in modified_routes:
            route["vni"] += offset
            route["mac_address"] = route["mac_address"][:-2] + \
                "{:02x}".format((int(route["mac_address"][-2:], 16) + offset) % 256)
            route["endpoint"] = convert_ip_int_to_str(
                convert_str_to_ip_int(route["endpoint"])[0] + offset
            ).split('/')[0]

            gnmic_set_with_bypass(
                gnmi_tls,
                f"{GNMI_PATH_PREFIX}/VNET_ROUTE_TUNNEL/Vnet{route['vnet_vni']}|{route['prefix'].replace('/','~1')}",
                {
                    "endpoint": route["endpoint"],
                    "vni": route["vni"],
                    "mac_address": route["mac_address"]
                },
                f"vnet_route_{route['vnet_vni']}_{route['prefix'].replace('/','_')}"
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
        route_status = gnmi_tls.gnmic.get(route_key)[0].get("updates")[0].get("values", {}).get(route_key, {})\
            .get(f"Vnet{config['route']['vnet_vni']}|{config['route']['prefix']}", {}).get("state", "")
        pytest_assert(route_status.lower() == "active",
                      f"VNET route tunnel for Vnet{config['route']['vnet_vni']}|\
                        {config['route']['prefix']} not active.")


def test_vnet_with_bgp_intf_smacrewrite(common_setup_and_teardown, gnmi_tls):     # noqa: F811
    duthost, ptfadapter, encap_test_configs, decap_test_configs = common_setup_and_teardown

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    logger.debug("post-setup config_facts: {}".format(config_facts))

    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)

    # Test datapath after modifying route mac and vni
    modify_routes_mac_vni(gnmi_tls, encap_test_configs, offset=1)

    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)

    # Test datapath again after config reload
    duthost.shell("config save -y")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, yang_validate=False)
    time.sleep(10)

    # Configure vxlan port
    ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

    validate_decap_t1_to_wl(duthost, ptfadapter, decap_test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, encap_test_configs)
