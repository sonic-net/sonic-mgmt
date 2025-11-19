import logging
import json
import os
from ptf.mask import Mask
from ptf.packet import Ether, IP, UDP, TCP
import ptf.testutils as testutils
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
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

VXLAN_PORT = 4789
TUNNEL_ENDPOINT = "100.0.1.10"
VNET_NAME = "Vnet1"
INNER_SRC_MAC = "00:11:22:33:44:55"
INNER_SRC_IP = "2.2.2.2"
VNI = "10000"

ACL_TYPE_NAME = "INNER_SRC_MAC_REWRITE_TYPE"
ACL_TABLE_NAME = "INNER_SRC_MAC_REWRITE_TABLE"


def validate_encap_wl_to_t1(duthost, ptfadapter, test_configs):
    logger.info("Starting WL to T1 VXLAN encapsulation test...")

    # Build inner TCP packet to inject from southbound side
    pkt_opts = {
        "eth_dst": duthost.facts['router_mac'],
        "eth_src": ptfadapter.dataplane.get_mac(0, test_configs["wl_ptf_port_num"][0]),
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
        vxlan_vni=int(VNI),
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
    testutils.send(ptfadapter, test_configs["wl_ptf_port_num"][0], inner_pkt)

    # Verify VXLAN encapsulated pkt on T1 port with rewritten inner src MAC
    testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, test_configs["t1_ptf_port_num"], timeout=2)

    logger.info("WL to T1 VXLAN encapsulation test passed.")


def validate_decap_t1_to_wl(duthost, ptfadapter, test_configs):
    logger.info("Starting T1 to WL VXLAN decapsulation test...")

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
        vxlan_vni=int(VNI),
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
    testutils.verify_packet_any_port(ptfadapter, masked_expected_pkt, test_configs["wl_ptf_port_num"])

    logger.info("T1 to WL VXLAN decapsulation test passed.")


def cleanup(duthost, ptfhost):
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

    # Remove tmp files
    for file in ["/tmp/acl_update.json", "/tmp/vnet_route_update.json", "/tmp/bgp_and_interface_update.json",
                 "/tmp/vnet_vxlan_update.json"]:
        if os.path.exists(file):
            os.remove(file)


def setup_acl_config(duthost, ports):
    """
    Add a custom ACL table type definition to CONFIG_DB.
    """
    acl_update = {
        "ACL_TABLE": {},
        "ACL_RULE": {},
        "ACL_TABLE_TYPE": {}
    }

    acl_update["ACL_TABLE_TYPE"][ACL_TYPE_NAME] = {
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
    acl_update["ACL_TABLE"][ACL_TABLE_NAME] = {
        "policy_desc": ACL_TABLE_NAME,
        "ports": ports,
        "stage": "egress",
        "type": ACL_TYPE_NAME
    }
    acl_update["ACL_RULE"][f"{ACL_TABLE_NAME}|rule_1"] = {
        "INNER_SRC_IP": INNER_SRC_IP,
        "INNER_SRC_MAC_REWRITE_ACTION": INNER_SRC_MAC,
        "TUNNEL_VNI": VNI,
        "PRIORITY": "1005"
    }

    logger.info("Programming acl table type onto DUT: " + str(acl_update))
    duthost.copy(content=json.dumps(acl_update, indent=2), dest="/tmp/acl_update.json")
    duthost.shell("sonic-cfggen -j /tmp/acl_update.json --write-to-db")


def setup_vnet_routes(duthost, vnet_name):
    config_update = {
        "VNET_ROUTE_TUNNEL": {
            f"{vnet_name}|150.0.0.0/24": {
                "endpoint": TUNNEL_ENDPOINT
            }
        }
    }

    logger.info("Programming vnet routes onto DUT: " + str(config_update))
    duthost.copy(content=json.dumps(config_update, indent=2), dest="/tmp/vnet_route_update.json")
    duthost.shell("sonic-cfggen -j /tmp/vnet_route_update.json --write-to-db")


def setup_bgp_and_vnet_interfaces(duthost, vnet_name, bgp_neighs):
    wl_portchannel = None
    wl_portchannel_ip = None
    wl_bgp_name = None
    wl_bgp_ip = None

    ip_int = duthost.show_and_parse("show ip int")
    for entry in ip_int:
        bgp_neigh = entry.get("bgp neighbor", "N/A")
        if bgp_neigh != "" and bgp_neigh != "N/A":
            wl_bgp_name = bgp_neigh
            wl_portchannel = entry.get("interface")
            wl_portchannel_ip = entry.get("ipv4 address/mask")
            wl_bgp_ip = entry.get("neighbor ip")
            break

    pytest_assert(wl_portchannel is not None or wl_bgp_name is not None,
                  "Cannot find a portchannel with a bgp neighbor.")
    pytest_assert(wl_portchannel_ip is not None,
                  f"Cannot find IP address for portchannel {wl_portchannel}.")
    pytest_assert(wl_bgp_ip is not None,
                  f"Cannot find BGP neighbor IP for BGP session {wl_bgp_name}.")

    # Get BGP ASN and remove existing bgp neighbor
    asn = bgp_neighs[wl_bgp_ip]["asn"]
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'BGP_NEIGHBOR|{wl_bgp_ip}'")

    # Add BGP peer range and put portchannel in vnet
    bgp_peers = {
        f"{vnet_name}|WLPARTNER_PASSIVE_V4": {
            "ip_range": [wl_portchannel_ip],
            "name": "WLPARTNER_PASSIVE_V4",
            "peer_asn": asn,
            "src_address": wl_portchannel_ip.split('/')[0]
        }
    }
    portchannel_intfs = {
        wl_portchannel: {
            "vnet_name": vnet_name
        }
    }

    config_update = {
        "BGP_PEER_RANGE": bgp_peers,
        "PORTCHANNEL_INTERFACE": portchannel_intfs,
    }

    logger.info("Programming bgp and portchannels onto DUT: " + str(config_update))
    duthost.copy(content=json.dumps(config_update, indent=2), dest="/tmp/bgp_and_interface_update.json")
    duthost.shell("sonic-cfggen -j /tmp/bgp_and_interface_update.json --write-to-db")

    return {
        "wl_portchannel": wl_portchannel,
        "wl_portchannel_ip": wl_portchannel_ip,
        "wl_bgp_ip": wl_bgp_ip
    }


def setup_vxlan_tunnel(duthost, loopback_ip):
    config_update = {
        "VXLAN_TUNNEL": {
            "tunnel_v4": {
                "src_ip": loopback_ip
            }
        },
        "VNET": {
            VNET_NAME: {
                "vni": VNI,
                "vxlan_tunnel": "tunnel_v4"
            }
        }
    }

    logger.info("Programming vxlan and vnet configs onto DUT: " + str(config_update))
    duthost.copy(content=json.dumps(config_update, indent=2), dest="/tmp/vnet_vxlan_update.json")
    duthost.shell("sonic-cfggen -j /tmp/vnet_vxlan_update.json --write-to-db")


@pytest.fixture(scope="module")
def common_setup_and_teardown(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, ptfadapter, localhost):
    duthost = duthosts[rand_one_dut_hostname]

    # backup config_db.json for cleanup
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True

    try:
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        bgp_neighs = config_facts.get("BGP_NEIGHBOR", {})

        port_indexes = config_facts['port_index_map']  # map of dut port name to dut port index
        duts_map = tbinfo["duts_map"]
        dut_indx = duts_map[duthost.hostname]
        # Get available ports in PTF
        host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]  # map of ptf port index to dut port index
        ptf_ports_available_in_topo = {}
        for key in host_interfaces:
            ptf_ports_available_in_topo[host_interfaces[key]] = int(key)  # map of dut port index to ptf port index

        # Create loopback interface
        duthost.shell("config int ip add Loopback6 10.10.1.1")
        loopback_ip = "10.10.1.1"

        # Set up vnet and vxlan
        setup_vxlan_tunnel(duthost, loopback_ip)

        # Set up WL BGP session and put associated portchannel in vnet
        wl_intf_info = setup_bgp_and_vnet_interfaces(duthost, VNET_NAME, bgp_neighs)

        # Set up vnet routes
        setup_vnet_routes(duthost, VNET_NAME)

        # Setup acl configs
        setup_acl_config(duthost, list(config_facts.get("PORTCHANNEL", {}).keys()))

        # save and reload configs to ensure all configs are applied properly
        duthost.shell("config save -y")
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True, yang_validate=False)
        time.sleep(10)

        # Configure vxlan port
        ecmp_utils.configure_vxlan_switch(duthost, VXLAN_PORT, "00:12:34:56:78:9a")

        # Check vrf bgp session is up
        vnet_bgps = duthost.show_and_parse(f"show ip bgp vrf {VNET_NAME} summary")
        pytest_assert(len(vnet_bgps) > 0 and vnet_bgps[0]["neighborname"] == "WLPARTNER_PASSIVE_V4"
                      and vnet_bgps[0]["state/pfxrcd"].isdigit(), f"BGP neighbor not found for vnet {VNET_NAME}.")

        # Check acl table and rules are set
        acl_table = duthost.shell(f"sonic-db-cli STATE_DB HGET 'ACL_TABLE_TABLE|{ACL_TABLE_NAME}' 'status'")
        pytest_assert(acl_table['stdout'].strip().lower() == "active", f"ACL table {ACL_TABLE_NAME} not active.")

        acl_rule = duthost.shell(f"sonic-db-cli STATE_DB HGET 'ACL_RULE_TABLE|{ACL_TABLE_NAME}|rule_1' 'status'")
        pytest_assert(acl_rule['stdout'].strip().lower() == "active",
                      f"ACL rule 'rule_1' for {ACL_TABLE_NAME} not active.")

        # Check vnet routes are set
        route_tunnel = duthost.shell(f"sonic-db-cli STATE_DB HGET \
                                     'VNET_ROUTE_TUNNEL_TABLE|{VNET_NAME}|150.0.0.0/24' 'state'")
        pytest_assert(route_tunnel['stdout'].strip().lower() == "active",
                      f"VNET route tunnel for {VNET_NAME} not active.")

        # Get ptf eth of portchannels
        wl_ptf_port_num = []
        t1_ptf_port_num = []
        portchannel_members = config_facts.get("PORTCHANNEL_MEMBER", {})
        for key in portchannel_members:
            members = list(portchannel_members[key].keys())
            for intf in members:
                if key == wl_intf_info["wl_portchannel"]:
                    wl_ptf_port_num.append(ptf_ports_available_in_topo[port_indexes[intf]])
                else:
                    t1_ptf_port_num.append(ptf_ports_available_in_topo[port_indexes[intf]])

        test_configs = {
            "wl_portchannel": wl_intf_info["wl_portchannel"],
            "wl_bgp_ip": wl_intf_info["wl_bgp_ip"],
            "wl_ptf_port_num": wl_ptf_port_num,
            "loopback_ip": loopback_ip,
            "t1_ptf_port_num": t1_ptf_port_num
        }

        # Check have enough ports to run tests
        pytest_assert(len(wl_ptf_port_num) > 0, "No WL portchannel member ports found in PTF topo.")
        pytest_assert(len(t1_ptf_port_num) > 0, "No T1 side portchannel member ports found in PTF topo.")
    except Exception as e:
        # Cleanup on failure during setup
        logger.error(f"Exception during setup: {repr(e)}.")
        cleanup(duthost, ptfhost)
        pytest.fail(f"Setup failed: {repr(e)}")

    yield duthost, ptfadapter, test_configs

    # Cleanup
    cleanup(duthost, ptfhost)


def test_vnet_with_bgp_intf_smacrewrite(common_setup_and_teardown):
    duthost, ptfadapter, test_configs = common_setup_and_teardown

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    logger.debug("post-setup config_facts: {}".format(config_facts))

    validate_decap_t1_to_wl(duthost, ptfadapter, test_configs)

    validate_encap_wl_to_t1(duthost, ptfadapter, test_configs)
