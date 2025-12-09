import logging
import json
import os
from ptf.mask import Mask
from ptf.packet import Ether, IP, UDP, TCP
import ptf.testutils as testutils
import pytest
import time
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.config_reload import config_reload
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
INNER_SRC_MAC = "00:11:22:33:44:55"
INNER_SRC_IP = "2.2.2.2"
BASE_VNI = 1000
NUM_VNETS = 2

ACL_TYPE_NAME = "INNER_SRC_MAC_REWRITE_TYPE"
ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"


def validate_encap_wl_to_t1(duthost, ptfadapter, wl_portchannel_info, subintfs_info, test_configs):
    logger.info("Starting WL to T1 VXLAN encapsulation test...")

    for key, val in subintfs_info.items():
        # Build inner TCP packet to inject from southbound side
        pkt_opts = {
            "eth_dst": duthost.facts['router_mac'],
            "eth_src": ptfadapter.dataplane.get_mac(0, val["ptf_port_index"]),
            "ip_dst": "150.0.0.10",
            "ip_src": INNER_SRC_IP,
            "ip_id": 105,
            "ip_ttl": 64,
            "tcp_sport": 1234,
            "tcp_dport": 5000,
            "pktlen": 100
        }

        inner_pkt = testutils.simple_tcp_packet(**pkt_opts)

        # Build expected packet
        vxlan_router_mac = duthost.shell("sonic-db-cli APPL_DB HGET 'SWITCH_TABLE:switch' 'vxlan_router_mac'")
        pkt_opts["eth_src"] = INNER_SRC_MAC  # expected rewritten inner src mac
        pkt_opts["eth_dst"] = vxlan_router_mac['stdout'].strip()
        pkt_opts["ip_ttl"] = 63

        inner_exp_pkt = testutils.simple_tcp_packet(**pkt_opts)

        expected_pkt = testutils.simple_vxlan_packet(
            eth_dst="aa:bb:cc:dd:ee:ff",
            eth_src=duthost.facts['router_mac'],
            ip_src=test_configs["loopback_ip"],
            ip_dst=TUNNEL_ENDPOINT,
            ip_id=0,
            ip_flags=0x2,
            udp_sport=1234,
            udp_dport=VXLAN_PORT,
            with_udp_chksum=False,
            vxlan_vni=int(val["vnet_vni"]),
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

        # Clear packet queue on all ports and get initial acl counter
        ptfadapter.dataplane.flush()

        # Send TCP packet from WL port
        testutils.send(ptfadapter, val['ptf_port_index'], inner_pkt)

        # Verify VXLAN encapsulated pkt on T1 port with rewritten inner src MAC
        testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, test_configs["t1_ptf_port_nums"], timeout=2)

    logger.info("WL to T1 VXLAN encapsulation test passed.")


def validate_decap_t1_to_wl(duthost, ptfadapter, wl_portchannel_info, subintfs_info, test_configs):
    logger.info("Starting T1 to WL VXLAN decapsulation test...")

    for key, val in subintfs_info.items():
        # Build inner TCP packet expected on WL port
        expected_inner_pkt = testutils.simple_tcp_packet(
            eth_dst="aa:bb:cc:dd:ee:ff",
            eth_src=duthost.facts['router_mac'],
            ip_src="8.8.8.8",
            ip_dst="193.5.0.0",
            tcp_sport=1234,
            tcp_dport=4321,
        )

        # Build VXLAN encapsulated packet to inject from T1 side
        vxlan_pkt = testutils.simple_vxlan_packet(
            eth_dst=duthost.facts['router_mac'],
            eth_src=ptfadapter.dataplane.get_mac(0, test_configs["t1_ptf_port_num"][0]),
            ip_src="1.1.1.1",
            ip_dst=test_configs["loopback_ip"],
            udp_sport=1234,
            udp_dport=VXLAN_PORT,
            with_udp_chksum=False,
            vxlan_vni=int(val["vnet_vni"]),
            inner_frame=expected_inner_pkt
        )

        masked_expected_pkt = Mask(expected_inner_pkt)
        masked_expected_pkt.set_ignore_extra_bytes()
        masked_expected_pkt.set_do_not_care_packet(Ether, 'dst')
        masked_expected_pkt.set_do_not_care_packet(IP, "ttl")
        masked_expected_pkt.set_do_not_care_packet(IP, "chksum")
        masked_expected_pkt.set_do_not_care_packet(IP, "id")
        masked_expected_pkt.set_do_not_care_packet(TCP, 'chksum')

        # Clear packet queue on all ports
        ptfadapter.dataplane.flush()

        # Send VXLAN encapsulated pkt from T1 port
        testutils.send(ptfadapter, test_configs["t1_ptf_port_num"][0], vxlan_pkt)

        # Verify decapsulated unencapsulated packet on southbound port
        testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, val['ptf_port_index'], timeout=2)

    logger.info("T1 to WL VXLAN decapsulation test passed.")


def cleanup(duthost, ptfhost, wl_portchannel_info=None, subintfs_info=None):
    """
    Return duthost and ptfhost to original state.

    Args:
        duthost: DUT host
        ptfhost: PTF host
        bond_port_mapping: map of bond port name (bond#) to ptf port name (eth#)
    """
    logger.debug("cleanup: Loading backup config db json.")
    duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}")

    # Reload to restore configuration
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

    cmds = []
    # Remove bond ports
    if wl_portchannel_info:
        for key, val in wl_portchannel_info.items():
            bond_port = val["bond_port"]
            port_name = val["ptf_port_name"]
            cmds.append("ip link set {} nomaster".format(bond_port))
            cmds.append("ip link set {} nomaster".format(port_name))
            cmds.append("ip link set {} up".format(port_name))
            cmds.append("ip link del {}".format(bond_port))

    # Remove sub port
    if subintfs_info:
        for key, val in subintfs_info.items():
            sub_port = key
            ip = val['ptf_ip']
            cmds.append("ip address del {} dev {}".format(ip, sub_port))
            cmds.append("ip link del {}".format(sub_port))

    ptfhost.shell_cmds(cmds=cmds)

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
    # for file in ["/tmp/acl_patch.patch", "/tmp/vnet_route_patch.patch", "/tmp/bgp_and_vnet_interface_update.json",
    #              "/tmp/vxlan_patch.patch", "/tmp/vnet_patch.patch"]:
    #     if os.path.exists(file):
    #         os.remove(file)


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


def generate_subintfs_ips(num_subintfs, start_ip_int, prefix_size=31):
    block_size = 2 ** (32 - prefix_size)
    pytest_assert(num_subintfs * block_size + start_ip_int < 0xFFFFFFFF, "Not enough IPs available to assign to subinterfaces.")
    subintf_ips = []
    ptf_ips = []
    for i in range(num_subintfs):
        ip_int = start_ip_int + i * 2
        subintf_ips.append(
            f"{ip_int >> 24 & 0xFF}.{ip_int >> 16 & 0xFF}.{ip_int >> 8 & 0xFF}.{ip_int & 0xFF}/{prefix_size}"
        )
        ptf_ips.append(
            f"{(ip_int + 1) >> 24 & 0xFF}.{(ip_int + 1) >> 16 & 0xFF}.{(ip_int + 1) >> 8 & 0xFF}.{(ip_int + 1) & 0xFF}/{prefix_size}"
        )

    return subintf_ips, ptf_ips


def apply_patch_helper(duthost, op, path, value, filename="test_config"):
    patch = [{
        "op": op,
        "path": path,
        "value": value
    }]
    logger.info("Programming patch onto DUT: " + str(patch))
    duthost.copy(content=json.dumps(patch, indent=2), dest=f"/tmp/{filename}.patch")
    duthost.shell(f"config apply-patch /tmp/{filename}.patch")


def setup_acl_config(duthost, ports, vnet_vnis):
    """
    Add a custom ACL table type definition to CONFIG_DB.
    """
    apply_patch_helper(duthost, "add", "/ACL_TABLE_TYPE", {
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

    apply_patch_helper(duthost, "add", "/ACL_TABLE", {
        ACL_TABLE_NAME: {
            "policy_desc": ACL_TABLE_NAME,
            "ports": ports,
            "stage": "egress",
            "type": ACL_TYPE_NAME
        }
    }, "acl_table")

    apply_patch_helper(duthost, "add", "/ACL_RULE", {
        f"{ACL_TABLE_NAME}|rule_{vni}": {
            "INNER_SRC_IP": f"{INNER_SRC_IP}/32",
            "INNER_SRC_MAC_REWRITE_ACTION": INNER_SRC_MAC,
            "TUNNEL_VNI": f"{vni}",
            "PRIORITY": f"{vni}"
        } for vni in vnet_vnis
    }, "acl_rule")

    # Check acl table and rules are set
    time.sleep(5)
    acl_table = duthost.shell(f"sonic-db-cli STATE_DB HGET 'ACL_TABLE_TABLE|{ACL_TABLE_NAME}' 'status'")
    pytest_assert(acl_table['stdout'].strip().lower() == "active", f"ACL table {ACL_TABLE_NAME} not active.")

    acl_rule = duthost.shell(f"sonic-db-cli STATE_DB HGET 'ACL_RULE_TABLE|{ACL_TABLE_NAME}|rule_1' 'status'")
    pytest_assert(acl_rule['stdout'].strip().lower() == "active",
                  f"ACL rule 'rule_1' for {ACL_TABLE_NAME} not active.")


def setup_vnet_routes(duthost, vnet_vnis):
    apply_patch_helper(duthost, "add", "/VNET_ROUTE_TUNNEL", {
        f"Vnet{vni}|0.0.0.0/0": {
            "endpoint": TUNNEL_ENDPOINT
        } for vni in vnet_vnis
    }, f"vnet_route_{vni}")

    # Check vnet routes are set
    time.sleep(5)
    for vni in vnet_vnis:
        route_tunnel = duthost.shell(f"sonic-db-cli STATE_DB HGET \
                                     'VNET_ROUTE_TUNNEL_TABLE|Vnet{vni}|0.0.0.0/0' 'state'")
        pytest_assert(route_tunnel['stdout'].strip().lower() == "active",
                      f"VNET route tunnel for Vnet{vni} not active.")


def setup_bgp(duthost, ptfhost, vnet_vnis, dut_ips, ptf_ips, bgp_port, vnet_route_ip):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    dut_asn = config_facts['DEVICE_METADATA']['localhost']['bgp_asn']
    neighbors = config_facts['BGP_NEIGHBOR']
    peer_asn = list(neighbors.values())[0]["asn"]
    
    for vni in vnet_vnis:
        apply_patch_helper(duthost, "add", f"BGP_PEER_RANGE/Vnet{vni}|WLPARTNER_PASSIVE_V4", {
            "ip_range": [dut_ips[vni]],
            "name": "WLPARTNER_PASSIVE_V4",
            "peer_asn": peer_asn,
            "src_address": dut_ips[vni].split('/')[0]
        }, f"bgp_peer_{vni}")

    exabgp_config = f"""
process api-vnets {{
    run /usr/bin/python /usr/share/exabgp/http_api.py {bgp_port};
    encoder json;
}}
"""

    for dut_ip, ptf_ip in zip(dut_ips, ptf_ips):
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
        
    with open(EXABGP_CONFIG_PATH, "w") as f:
        f.write(exabgp_config)

    ptfhost.shell(f"nohup exabgp {EXABGP_CONFIG_PATH} > /var/log/exabgp_all_vnets.log 2>&1 &")

    # Check vrf bgp session is up
    time.sleep(5)
    for vni in vnet_vnis:
        vnet_bgps = duthost.show_and_parse(f"show ip bgp vrf Vnet{vni} summary")
        pytest_assert(len(vnet_bgps) > 0 and vnet_bgps[0]["neighborname"] == "WLPARTNER_PASSIVE_V4"
                  and vnet_bgps[0]["state/pfxrcd"].isdigit(), f"BGP neighbor not found for vnet Vnet{vni}.")


def setup_portchannel_subintfs(duthost, ptfhost, portchannel_info, vnet_vnis, base_vlan, dut_ips, ptf_ips):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    has_subintfs = len(config_facts.get("VNET", {})) > 0

    subintfs_info = {}

    cmds = []
    for i in range(vnet_vnis):
        for j, (key, val) in enumerate(portchannel_info.items()):
            po_num = val["portchannel_num"]
            bond_port = val["bond_port"]
            subintf_name = f"Po{po_num}.{base_vlan + i}"

            if not has_subintfs:
                apply_patch_helper(duthost, "add", f"/VLAN_SUB_INTERFACE", {
                    subintf_name: {
                        "admin_status": "up",
                        "vlan": base_vlan + i,
                        "vnet_name": f"Vnet{vnet_vnis[i]}"
                    },
                    f"{subintf_name}|{dut_ips[j]}": {}
                }, subintf_name)
                has_subintfs = True
            else:
                apply_patch_helper(duthost, "add", f"/VLAN_SUB_INTERFACE/{subintf_name}", {
                    "admin_status": "up",
                    "vlan": base_vlan + i,
                    "vnet_name": f"Vnet{vnet_vnis[i]}"
                }, subintf_name)
                apply_patch_helper(duthost, "add", f"/VLAN_SUB_INTERFACE/{subintf_name}|{dut_ips[j]}", {}, f"{subintf_name}_ip")

            # Configure ptf port commands
            cmds.append(f"ip link add link {bond_port} name {bond_port}.{base_vlan + i} type vlan id {base_vlan + i}")
            cmds.append(f"ip address add {ptf_ips[j]} dev {bond_port}.{base_vlan + i}")
            cmds.append(f"ip link set {bond_port}.{base_vlan + i} up")

            subintfs_info[subintf_name] = {
                "portchannel_name": key,
                "portchannel_num": po_num,
                "dut_ip": dut_ips[j],
                "ptf_ip": ptf_ips[j],
                "vlan": base_vlan + i,
                "vnet": f"Vnet{vnet_vnis[i]}",
                "vnet_vni": vnet_vnis[i],
            }

    ptfhost.shell_cmds(cmds=cmds)
    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)

    return subintfs_info


def setup_portchannels(duthost, ptfhost, config_facts, port_indexes, ptf_ports_available_in_topo):
    vlan_id, ports = get_available_vlan_id_and_ports(config_facts, len(PORTCHANNEL_NAMES))
    pytest_assert(len(ports) == len(PORTCHANNEL_NAMES), f"Found {len(ports)} available ports. Needed {len(PORTCHANNEL_NAMES)} ports for the test.")

    cmds = []
    wl_portchannel_mapping_info = {}
    for i in range(len(PORTCHANNEL_NAMES)):
        duthost.shell(f'config vlan member del {vlan_id} {ports[i]}')

        apply_patch_helper(duthost, "add", f"/PORTCHANNEL/{PORTCHANNEL_NAMES[i]}", {
            "admin_status": "up"
        }, PORTCHANNEL_NAMES[i])
        apply_patch_helper(duthost, "add", f"/PORTCHANNEL_MEMBER/{PORTCHANNEL_NAMES[i]}|{ports[i]}", {}, f"{PORTCHANNEL_NAMES[i]}_member")

        # Configure ptf port commands
        ptf_port_index = port_indexes[ports[i]]
        ptf_port_name = ptf_ports_available_in_topo[ptf_port_index]["name"]

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

    return wl_portchannel_mapping_info


def setup_vnets(duthost, num_vnets, tunnel, base_vni):
    apply_patch_helper(duthost, "add", "/VNET", {
        f"Vnet{base_vni + i}": {
            "vni": f"{base_vni + i}",
            "vxlan_tunnel": tunnel
        } for i in range(num_vnets)
    }, "vnet")

    return [base_vni + i for i in range(num_vnets)]


def setup_vxlan_tunnel(duthost, name, src_ip):
    apply_patch_helper(duthost, "add", "/VXLAN_TUNNEL", {
        name: {
            "src_ip": src_ip
        }
    }, "vxlan")


@pytest.fixture(scope="module")
def common_setup_and_teardown(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ptfadapter, localhost):
    duthost = duthosts[rand_one_dut_hostname]

    # backup config_db.json for cleanup
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    try:
        wl_portchannel_info = None
        subintfs_info = None
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

        port_indexes = config_facts['port_index_map']  # map of dut port name to dut port index
        duts_map = tbinfo["duts_map"]
        dut_indx = duts_map[duthost.hostname]
        # Get available ports in PTF
        host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]  # map of ptf port index to dut port index
        ptf_ports_available_in_topo = {}
        for key in host_interfaces:
            ptf_ports_available_in_topo[host_interfaces[key]] = { # map of dut port index to ptf port info
                "index": int(key),
                "name": "eth{}".format(int(key))
            }

        # Remove everflow acl tables
        duthost.remove_acl_table("EVERFLOW")
        duthost.remove_acl_table("EVERFLOWV6")

        # Create loopback interface
        duthost.shell("config int ip add Loopback6 10.10.1.1")
        loopback_ip = "10.10.1.1"

        # Set up vxlan
        setup_vxlan_tunnel(duthost, "tunnel_v4", loopback_ip)

        #  Set up vnets
        vnet_vnis = setup_vnets(duthost, NUM_VNETS, "tunnel_v4", BASE_VNI)

        # Set up portchannels
        wl_portchannel_info = setup_portchannels(duthost, ptfhost, config_facts, port_indexes, ptf_ports_available_in_topo)

        # Set up subintfs
        dut_ips, ptf_ips = generate_subintfs_ips(NUM_VNETS, start_ip_int=(10 << 24 + 11 << 16))
        subintfs_info = setup_portchannel_subintfs(duthost, ptfhost, wl_portchannel_info, vnet_vnis, base_vlan=10, dut_ips=dut_ips, ptf_ips=ptf_ips)

        # Set up bgps
        setup_bgp(duthost, ptfhost, vnet_vnis, dut_ips, ptf_ips, bgp_port=EXABGP_PORT, vnet_route_ip="193.5.0.0/16")

        # Set up vnet routes
        setup_vnet_routes(duthost, vnet_vnis)

        # Setup acl configs
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        setup_acl_config(duthost, list(config_facts.get("PORTCHANNEL", {}).keys()), vnet_vnis)

        # Configure vxlan port
        ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

        # Get ptf eth of T1 portchannels
        t1_ptf_port_nums = []
        portchannel_members = config_facts.get("PORTCHANNEL_MEMBER", {})
        for key in portchannel_members:
            members = list(portchannel_members[key].keys())
            for intf in members:
                if key not in wl_portchannel_info:
                    t1_ptf_port_nums.append(ptf_ports_available_in_topo[port_indexes[intf]]["index"])

        # Check have enough T1 ports to run tests
        pytest_assert(len(t1_ptf_port_nums) > 0, "No T1 side portchannel member ports found in PTF topo.")
    except Exception as e:
        # Cleanup on failure during setup
        logger.error(f"Exception during setup: {repr(e)}.")
        cleanup(duthost, ptfhost, wl_portchannel_info, subintfs_info)
        pytest.fail(f"Setup failed: {repr(e)}")

    yield duthost, ptfadapter, wl_portchannel_info, subintfs_info, {"vnet_vnis": vnet_vnis, "t1_ptf_port_nums": t1_ptf_port_nums, "loopback_ip": loopback_ip}

    # Cleanup
    cleanup(duthost, ptfhost, wl_portchannel_info, subintfs_info)


def test_vnet_with_bgp_intf_smacrewrite(common_setup_and_teardown):
    duthost, ptfadapter, wl_portchannel_info, subintfs_info, test_configs = common_setup_and_teardown

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    logger.debug("post-setup config_facts: {}".format(config_facts))

    validate_decap_t1_to_wl(duthost, ptfadapter, wl_portchannel_info, subintfs_info, test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, wl_portchannel_info, subintfs_info, test_configs)

    # Test datapath again after config reload
    duthost.shell("config save -y")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, yang_validate=False)
    time.sleep(10)

    # Configure vxlan port
    ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

    validate_decap_t1_to_wl(duthost, ptfadapter, wl_portchannel_info, subintfs_info, test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, wl_portchannel_info, subintfs_info, test_configs)
