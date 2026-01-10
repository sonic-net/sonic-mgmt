import pytest
import logging
import random
import json
import sys
import os
import configs.privatelink_config as pl
import ptf.testutils as testutils
import ptf.packet as scapy

from ptf.mask import Mask
from dash_utils import render_template_to_host, apply_swssconfig_file
from tests.dash.conftest import get_interface_ip
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.interface_utils import get_dpu_npu_ports_from_hwsku
from packets import generate_inner_packet, set_do_not_care_layer
from tests.common import config_reload
from constants import *  # noqa: F403
SONIC_MGMT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, os.path.join(SONIC_MGMT_ROOT, 'ansible', 'module_utils'))
from smartswitch_utils import smartswitch_hwsku_config  # noqa: E402

pytestmark = [
    pytest.mark.topology('smartswitch'),
]

VIP = "10.1.0.5"
VNET_NAME = "Vnet1000"
VNI = 1000
ENI1_MAC = "F4:93:9F:EF:C4:7F"
ENI2_MAC = "F4:93:9F:EF:C4:80"
# ENI that is hosted in the T1 cluster but not the T1 that is tested
NON_EXISTING_ENI_MAC = "F4:93:9F:EF:C4:81"

logger = logging.getLogger(__name__)
dataplane_logger = logging.getLogger("dataplane")
dataplane_logger.setLevel(logging.ERROR)


@pytest.fixture(scope="module", autouse=True)
def setup_gnmi_server():
    """Override the conftest autouse fixture to skip it, this test does not use gNMI"""
    yield


@pytest.fixture(scope="module")
def dpu_num(duthost):
    npu_hwsku = duthost.facts["hwsku"]
    dpu_num = smartswitch_hwsku_config[npu_hwsku]["dpu_num"]
    logger.info(f"DPU number: {dpu_num}")
    return dpu_num


@pytest.fixture(scope="module")
def apply_peer_route(duthost, loopback_ips, dash_pl_config):
    _, peer_loopback0_ip = loopback_ips
    nexthop_ip = str(get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1)
    logger.info(f"Apply the tunnel route {peer_loopback0_ip}/32 with nexthop {nexthop_ip}")
    duthost.shell(f"ip route replace {peer_loopback0_ip}/32 via {nexthop_ip}")

    yield

    logger.info(f"Delete the tunnel route {peer_loopback0_ip}/32")
    duthost.shell(f"ip route del {peer_loopback0_ip}/32 via {nexthop_ip}", module_ignore_errors=True)


@pytest.fixture(scope="function")
def update_peer_route(duthost, loopback_ips, dash_pl_config):
    _, peer_loopback0_ip = loopback_ips
    nexthop_ip = str(get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1)
    logger.info(f"Update the tunnel route {peer_loopback0_ip}/32 with nexthop {nexthop_ip}")
    duthost.shell(f"ip route replace {peer_loopback0_ip}/32 via {nexthop_ip}")

    yield

    nexthop_ip = str(get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1)
    logger.info(f"Restore the tunnel route {peer_loopback0_ip}/32 with nexthop {nexthop_ip}")
    duthost.shell(f"ip route replace {peer_loopback0_ip}/32 via {nexthop_ip}")


@pytest.fixture(scope="module")
def apply_config_db(duthost, dpu_num, mock_pa_ipv4, loopback_ips,
                    dash_pl_config, vdpus_info, apply_peer_route):  # noqa: F811
    loopback0_ip, peer_loopback0_ip = loopback_ips
    template_name = "eni_based_forwarding_config_db.j2"
    dest_path = "/tmp/eni_based_forwarding_config_db.json"
    _, dpu_under_test_index, _ = vdpus_info
    config_db_params = {
        "loopback0_ip": loopback0_ip,
        "peer_loopback0_ip": peer_loopback0_ip,
        "vnet_name": VNET_NAME,
        "vni": VNI,
        "vip": VIP,
        "dpu_num": dpu_num,
        "mock_pa_ipv4": mock_pa_ipv4,
        "vnet_interface": dash_pl_config[REMOTE_DUT_INTF],
        "dpu_under_test_index": dpu_under_test_index
    }
    render_template_to_host(template_name, duthost, dest_path, **config_db_params)
    rendered_config = duthost.shell(f"cat {dest_path}")['stdout']
    logger.info(f"Apply configrations to config_db: \n{rendered_config}")
    duthost.shell(f"config load {dest_path} -y")

    yield

    config_reload(duthost, safe_reload=True)


@pytest.fixture(scope="module")
def vdpus_info(dpu_num):
    dpu_index = random.randrange(dpu_num)
    vdpus = [f"vdpu0_{dpu_index}", f"vdpu1_{dpu_index}"]
    logger.info(f"Randomly selected vDPUs to test {vdpus}")
    vdpus_all_remote = [f"vdpu1_{(dpu_index + 1) % dpu_num}", f"vdpu1_{(dpu_index + 2) % dpu_num}"]
    return vdpus, dpu_index, vdpus_all_remote


@pytest.fixture(scope="module")
def mock_pa_ipv4(duthost, dash_pl_config):
    """ Mock the PA IPv4 IP for the local DPU dataplane interface. """
    return str(get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1)


@pytest.fixture(scope="module")
def loopback_ips(duthost):
    loopback0_ip = get_interface_ip(duthost, "Loopback0").ip
    peer_loopback0_ip = "100.100.100.1"
    return str(loopback0_ip), peer_loopback0_ip


@pytest.fixture(scope="module")
def apply_appl_db_and_check_acl_rules(duthost, vdpus_info, apply_config_db, mock_pa_ipv4, loopback_ips):  # noqa: F811
    _, peer_loopback0_ip = loopback_ips
    apply_dash_eni_forward_table(duthost, vdpus_info, active_eni_mac=ENI1_MAC, standby_eni_mac=ENI2_MAC)
    logger.info("Check the ENI forwarding ACL rules are applied correctly.")
    pytest_assert(
        wait_until(10, 5, 0, check_acl_table_and_type_tables, duthost),
        "ACL table and type tables are not applied correctly.")
    pytest_assert(wait_until(
        10, 5, 0, check_acl_rules, duthost, mock_pa_ipv4, peer_loopback0_ip,
        active_eni_mac=ENI1_MAC, standby_eni_mac=ENI2_MAC),
        "ACL rules are not applied correctly.")


def apply_dash_eni_forward_table(
    duthost, vdpus_info, active_eni_mac=ENI1_MAC, standby_eni_mac=ENI2_MAC,
    non_existing_eni_mac=NON_EXISTING_ENI_MAC
):
    template_name = "eni_based_forwarding_appl_db.j2"
    dest_path = "/tmp/eni_based_forwarding_appl_db.json"
    vdpus, _, vdpus_all_remote = vdpus_info
    appl_db_params = {
        "vnet_name": VNET_NAME,
        "active_eni_mac": active_eni_mac,
        "standby_eni_mac": standby_eni_mac,
        "non_existing_eni_mac": non_existing_eni_mac,
        "vdpus": vdpus,
        "vdpus_all_remote": vdpus_all_remote,
        "op": "SET"
    }
    render_template_to_host(template_name, duthost, dest_path, **appl_db_params)
    rendered_config = duthost.shell(f"cat {dest_path}")['stdout']
    logger.info(f"Apply configrations to appl_db: \n{rendered_config}")
    apply_swssconfig_file(duthost, dest_path)


def check_acl_table_and_type_tables(duthost):
    ip_interfaces = []
    dpc_ports = get_dpu_npu_ports_from_hwsku(duthost)
    for intf in duthost.show_ip_interface()["ansible_facts"]["ip_interfaces"]:
        if (intf.startswith("Ethernet") or intf.startswith("PortChannel")) and intf not in dpc_ports:
            ip_interfaces.append(intf)
    ip_interfaces.sort()
    ip_interfaces = ','.join(ip_interfaces)
    expected_tables = {
        "ACL_TABLE_TABLE:ENI": {
            "POLICY_DESC": "Contains Rule for DASH ENI Based Forwarding",
            "STAGE": "INGRESS",
            "PORTS": ip_interfaces,
            "TYPE": "ENI_REDIRECT"
        },
        "ACL_TABLE_TYPE_TABLE:ENI_REDIRECT": {
            "MATCHES": "DST_IP,INNER_DST_MAC,TUNNEL_TERM",
            "ACTIONS": "REDIRECT_ACTION",
            "BIND_POINTS": "PORT,PORTCHANNEL"
        }
    }
    logger.info(f"Expected ACL tables for ENI based forwarding: \n{expected_tables}")
    for table, table_fields in expected_tables.items():
        actual_table = json.loads(duthost.shell(f"redis-cli --json -n 0 HGETALL {table}")['stdout'])
        logger.info(f"Actual table for key {table}: {actual_table}")
        if not actual_table == table_fields:
            logger.error(
                f"ACL table {table} is not applied correctly. Expected: {table_fields}, Actual: {actual_table}")
            return False
    return True


def check_acl_rules(duthost, mock_pa_ipv4, peer_loopback0_ip,
                    active_eni_mac=ENI1_MAC, standby_eni_mac=ENI2_MAC,
                    non_existing_eni_mac=NON_EXISTING_ENI_MAC):
    expected_rules = {
        f"ACL_RULE_TABLE:ENI:{VNET_NAME}_{active_eni_mac.replace(':', '')}": {
            "PRIORITY": "9996",
            "DST_IP": f"{VIP}/32",
            "INNER_DST_MAC": active_eni_mac.lower(),
            "REDIRECT_ACTION": mock_pa_ipv4
        },
        f"ACL_RULE_TABLE:ENI:{VNET_NAME}_{active_eni_mac.replace(':', '')}_TERM": {
            "PRIORITY": "9997",
            "DST_IP": f"{VIP}/32",
            "INNER_DST_MAC": active_eni_mac.lower(),
            "TUNNEL_TERM": "true",
            "REDIRECT_ACTION": mock_pa_ipv4
        },
        f"ACL_RULE_TABLE:ENI:{VNET_NAME}_{standby_eni_mac.replace(':', '')}": {
            "PRIORITY": "9996",
            "DST_IP": f"{VIP}/32",
            "INNER_DST_MAC": f"{standby_eni_mac.lower()}",
            "REDIRECT_ACTION": f"{peer_loopback0_ip}@tunnel_v4,{VNI}"
        },
        f"ACL_RULE_TABLE:ENI:{VNET_NAME}_{standby_eni_mac.replace(':', '')}_TERM": {
            "PRIORITY": "9997",
            "DST_IP": f"{VIP}/32",
            "INNER_DST_MAC": f"{standby_eni_mac.lower()}",
            "TUNNEL_TERM": "true",
            "REDIRECT_ACTION": mock_pa_ipv4
        },
        f"ACL_RULE_TABLE:ENI:{VNET_NAME}_{non_existing_eni_mac.replace(':', '')}": {
            "PRIORITY": "9996",
            "DST_IP": f"{VIP}/32",
            "INNER_DST_MAC": f"{non_existing_eni_mac.lower()}",
            "REDIRECT_ACTION": f"{peer_loopback0_ip}@tunnel_v4,{VNI}"
        }
    }
    logger.info(
        f"3 ENIs are configured in this test, expected {len(expected_rules)} ACL rules: \n{expected_rules}")
    actual_rule_num = int(duthost.shell("redis-cli -n 0 keys 'ACL_RULE_TABLE:ENI*' | grep 'ACL' | wc -l")['stdout'])
    if not actual_rule_num == len(expected_rules):
        logger.error(f"Expected {len(expected_rules)} ENI forwarding ACL rules, but got {actual_rule_num}")
        return False
    for rule_name, rule_fields in expected_rules.items():
        actual_rule = json.loads(duthost.shell(f"redis-cli --json -n 0 HGETALL {rule_name}")['stdout'])
        logger.info(f"Actual rule for key {rule_name}: {actual_rule}")
        if not actual_rule == rule_fields:
            logger.error(
                f"ACL rule {rule_name} is not applied correctly. Expected: {rule_fields}, Actual: {actual_rule}")
            return False
    return True


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(duthost, apply_appl_db_and_check_acl_rules, dpu_num):  # noqa: F811

    yield


def generate_packet(config, eni_mac, eni_status, loopback_ips=None):
    inner_packet = generate_inner_packet(packet_type='udp')(
        eth_src=pl.VM_MAC,
        eth_dst=eni_mac,
        ip_src=pl.VM1_CA,
        ip_dst=pl.PE_CA
    )

    outer_packet = testutils.simple_vxlan_packet(
        eth_src=config[REMOTE_PTF_MAC],
        eth_dst=config[DUT_MAC],
        ip_src=pl.VM1_PA,
        ip_dst=VIP,
        udp_dport=4789,
        udp_sport=1234,
        with_udp_chksum=False,
        vxlan_vni=55,
        inner_frame=inner_packet
    )

    if eni_status == 'active':
        expected_packet = outer_packet.copy()
        expected_packet['Ethernet'].src = config[DUT_MAC]
        expected_packet['Ethernet'].dst = config[LOCAL_PTF_MAC]
        expected_packet['IP'].ttl -= 1
    elif eni_status == 'standby' or eni_status == 'non_existing':
        if not loopback_ips:
            raise ValueError("Loopback IPs are not provided.")
        loopback0_ip, peer_loopback0_ip = loopback_ips
        expected_packet = Mask(testutils.simple_vxlan_packet(
            eth_src=config[DUT_MAC],
            eth_dst=config[REMOTE_PTF_MAC],
            ip_src=loopback0_ip,
            ip_dst=peer_loopback0_ip,
            udp_sport=8080,
            udp_dport=4789,
            with_udp_chksum=False,
            vxlan_vni=VNI,
            inner_frame=outer_packet
        ))
        expected_packet.set_do_not_care_packet(scapy.IP, "ttl")
        expected_packet.set_do_not_care_packet(scapy.IP, "id")
        expected_packet.set_do_not_care_packet(scapy.IP, "flags")
        expected_packet.set_do_not_care_packet(scapy.IP, "chksum")
        expected_packet.set_do_not_care_packet(scapy.UDP, "sport")
        set_do_not_care_layer(expected_packet, scapy.IP, "chksum", 2)
        set_do_not_care_layer(expected_packet, scapy.Ether, "src", 2)
        set_do_not_care_layer(expected_packet, scapy.Ether, "dst", 2)
        set_do_not_care_layer(expected_packet, scapy.IP, "ttl", 2)
    else:
        raise ValueError(f"Invalid ENI status: {eni_status}")

    return outer_packet, expected_packet


def test_eni_based_forwarding_active_eni(ptfadapter, dash_pl_config):
    """
    Validate for the active ENI, the packet is redirected
    to the local DPU(mock local DPU dataplane interface).
    """
    packet, expected_packet = generate_packet(dash_pl_config, ENI1_MAC, 'active')
    logger.info("Send a packet of the active ENI to VIP and expect"
                " to receive it on the mock local DPU dataplane interface.")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], packet, 1)
    testutils.verify_packet(ptfadapter, expected_packet, dash_pl_config[LOCAL_PTF_INTF])


def test_eni_based_forwarding_standby_eni(ptfadapter, dash_pl_config, loopback_ips):
    """
    Validate for the standby ENI, the packet is redirected to the tunnel.
    """
    packet, expected_packet = generate_packet(
        dash_pl_config, ENI2_MAC, 'standby', loopback_ips)
    logger.info("Send a packet of the standby ENI to VIP and expect"
                " to receive it on the tunnel interface.")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], packet, 1)
    testutils.verify_packet_any_port(ptfadapter, expected_packet, dash_pl_config[REMOTE_PTF_RECV_INTF])


def test_eni_based_forwarding_tunnel_route_update(
    ptfadapter, dash_pl_config, loopback_ips, update_peer_route  # noqa: F811
):
    """
    Validate when the tunnel route is updated,
    the packet can be redirected to the new egress interface.
    """
    packet, expected_packet = generate_packet(
        dash_pl_config, ENI2_MAC, 'standby', loopback_ips)
    expected_packet.exp_pkt['Ethernet'].dst = dash_pl_config[LOCAL_PTF_MAC]
    logger.info("Send a packet of the standby ENI to VIP and expect"
                " to receive it on the tunnel interface.")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], packet, 1)
    testutils.verify_packet(ptfadapter, expected_packet, dash_pl_config[LOCAL_PTF_INTF])


def test_eni_based_forwarding_non_existing_eni(ptfadapter, dash_pl_config, loopback_ips):
    """
    Validate for the non-existing ENI, the packet is redirected to the tunnel.
    """
    packet, expected_packet = generate_packet(
        dash_pl_config, NON_EXISTING_ENI_MAC, 'non_existing', loopback_ips)
    logger.info("Send a packet of non-existing ENI to VIP and expect"
                " to receive it on the tunnel interface.")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], packet, 1)
    testutils.verify_packet_any_port(ptfadapter, expected_packet, dash_pl_config[REMOTE_PTF_RECV_INTF])


def test_eni_based_forwarding_eni_state_change(
    duthost, ptfadapter, dash_pl_config, vdpus_info, loopback_ips, mock_pa_ipv4
):
    """
    Validate when the ENI state changes, the ACL rules are updated correctly.
    """
    _, peer_loopback0_ip = loopback_ips
    try:
        logger.info("Change the active ENI to standby ENI and vice versa.")
        apply_dash_eni_forward_table(duthost, vdpus_info, active_eni_mac=ENI2_MAC, standby_eni_mac=ENI1_MAC)
        pytest_assert(wait_until(
            10, 5, 0, check_acl_rules, duthost, mock_pa_ipv4, peer_loopback0_ip,
            active_eni_mac=ENI2_MAC, standby_eni_mac=ENI1_MAC),
            "ACL rules are not applied correctly.")
        logger.info("Send a packet of the original standby ENI to VIP and expect"
                    " to receive it on the mock local DPU dataplane interface.")
        packet, expected_packet = generate_packet(dash_pl_config, ENI2_MAC, 'active')
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], packet, 1)
        testutils.verify_packet(ptfadapter, expected_packet, dash_pl_config[LOCAL_PTF_INTF])
        logger.info("Send a packet of the original active ENI to VIP and expect"
                    " to receive it on the tunnel interface.")
        packet, expected_packet = generate_packet(dash_pl_config, ENI1_MAC, 'standby', loopback_ips)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], packet, 1)
        testutils.verify_packet_any_port(ptfadapter, expected_packet, dash_pl_config[REMOTE_PTF_RECV_INTF])
    finally:
        logger.info("Restore the ENI to their original states.")
        apply_dash_eni_forward_table(duthost, vdpus_info, active_eni_mac=ENI1_MAC, standby_eni_mac=ENI2_MAC)
        pytest_assert(wait_until(
            10, 5, 0, check_acl_rules, duthost, mock_pa_ipv4, peer_loopback0_ip,
            active_eni_mac=ENI1_MAC, standby_eni_mac=ENI2_MAC),
            "ACL rules are not applied correctly.")


def test_eni_based_forwarding_tunnel_termination(
    ptfadapter, dash_pl_config, loopback_ips, vxlan_udp_dport
):
    """
    Validate the tunnel termination of the ENI based forwarding.
    The VxLAN UDP dst port is configured to a random port.
    """
    loopback0_ip, _ = loopback_ips

    logger.info("Send a double encaped packet of active ENI to VIP and expect to"
                "receive a decaped packet on the local PTF dataplane interface.")
    packet, expected_packet = generate_packet(dash_pl_config, ENI1_MAC, 'active')
    # The double encapped packet sent from peer T1 will have Inner Dst Mac set to 00:00:00:00:00:00
    # since the Tunnel NH created by EniFwd Orchagent doesn't have mac attribute set
    packet['Ethernet'].dst = "00:00:00:00:00:00"
    tunnel_packet = testutils.simple_vxlan_packet(
        eth_src="00:aa:bb:cc:dd:ee",
        eth_dst=dash_pl_config[DUT_MAC],
        ip_src="20.0.0.1",
        ip_dst=loopback0_ip,
        udp_sport=8080,
        udp_dport=vxlan_udp_dport,
        with_udp_chksum=False,
        vxlan_vni=VNI,
        inner_frame=packet
    )
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], tunnel_packet, 1)
    testutils.verify_packet(ptfadapter, expected_packet, dash_pl_config[LOCAL_PTF_INTF])

    logger.info("Send a double encaped packet of standby ENI to VIP and expect to"
                "receive a decaped packet on the local PTF dataplane interface.")
    packet, expected_packet = generate_packet(dash_pl_config, ENI2_MAC, 'active')
    packet['Ethernet'].dst = "00:00:00:00:00:00"
    tunnel_packet = testutils.simple_vxlan_packet(
        eth_src="00:aa:bb:cc:dd:ee",
        eth_dst=dash_pl_config[DUT_MAC],
        ip_src="20.0.0.1",
        ip_dst=loopback0_ip,
        udp_sport=8080,
        udp_dport=vxlan_udp_dport,
        with_udp_chksum=False,
        vxlan_vni=VNI,
        inner_frame=packet
    )

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], tunnel_packet, 1)
    testutils.verify_packet(ptfadapter, expected_packet, dash_pl_config[LOCAL_PTF_INTF])
