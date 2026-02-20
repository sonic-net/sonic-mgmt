import json
import logging
import ptf.packet as scapy
import ptf.testutils as testutils
import pytest
from scapy.all import Ether, IP, VXLAN, IPv6, UDP, GRE
from constants import (
    LOCAL_PTF_INTF,
    REMOTE_PTF_RECV_INTF,
    REMOTE_PTF_SEND_INTF,
    LOCAL_DUT_INTF,
    REMOTE_DUT_INTF,
    VXLAN_UDP_BASE_SRC_PORT,
    VXLAN_UDP_SRC_PORT_MASK
)
from conftest import get_interface_ip
from configs.privatelink_config import TUNNEL1_ENDPOINT_IP
import configs.privatelink_config as pl
from dash_utils import apply_swssconfig_file
from gnmi_utils import apply_messages
from packets import (
    get_pl_overlay_dip,
    get_overlay_pkt_details,
    get_underlay_pkt_details,
    get_plnsg_gre_pkt_details,
    generate_packets
)
from tests.common.helpers.assertions import (
    pytest_assert, pytest_require as pt_require
)
from tests.common import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("smartswitch"),
    pytest.mark.skip_check_dut_health
]

"""
Test prerequisites:
- Assign IPs to DPU-NPU dataplane interfaces
"""


def send_and_receive_packet(
    ptfadapter, pkt_to_sent, pkt_protocol,
    expected_pkt, tx_port, rx_port, direction=''
):
    logger.info(f"Sending {pkt_protocol} packet from {direction}")
    logger.info(f"{direction} Packet:\n{pkt_to_sent.show}")
    testutils.send(ptfadapter, tx_port, pkt_to_sent, 1)

    logger.info(f"Verifying {pkt_protocol} packet from {direction}")
    logger.info(f"Expected PE Packet:\n{expected_pkt.exp_pkt.show}")
    received_port_index, packet = testutils.verify_packet_any_port(
        ptfadapter,
        expected_pkt,
        rx_port
    )

    pytest_assert(
        packet is not None,
        f"Packet sent from {tx_port}\n "
        f"!!! {pkt_protocol} Packet is not forwarded to PE "
        f"as expected / Packet not received on {rx_port}!!!\n "
        f"Packet received port index {received_port_index}."
    )

    return scapy.Ether(packet)


def assert_pkt_info(packet_dic):
    def detailed_packet_info():
        logger.info("---- Detailed Packet Info ----")
        logger.info("Sent Packet:")
        logger.info(packet_dic['sent_pkt'].show(dump=True))
        logger.info("Received Packet:")
        logger.info(packet_dic['received_packet'].show(dump=True))
        logger.info("Expected Packet:")
        logger.info(packet_dic['expected_pkt'].show(dump=True))

    for item in packet_dic['To_verify']:
        assert item['expected_value'] == item['received_value'], (
            f"{item['field_name']} mismatch: "
            f"Expected {item['expected_value']}, "
            f"Received {item['received_value']}\n"
            f"{detailed_packet_info()}"
        )

        logger.info(
            f"{item['field_name']} verification passed: "
            f"received : {item['received_value']}, "
            f"expected : {item['expected_value']}"
        )


def verify_pl_redirect(
    sent_pkt, received_packet, expected_pkt,
    **verify_kwargs
):
    plnsg = verify_kwargs.get('plnsg', False)
    verify_plnsg_vxlan_udp_port = verify_kwargs.get(
        'verify_plnsg_vxlan_udp_port', False
    )
    # Extract overlay info
    overlay_received = get_overlay_pkt_details(
        received_packet, plnsg=plnsg
    )
    overlay_expected = get_overlay_pkt_details(
        expected_pkt.exp_pkt, plnsg=plnsg
    )

    # Extract underlay info
    underlay_received = get_underlay_pkt_details(received_packet)
    underlay_expected = get_underlay_pkt_details(expected_pkt.exp_pkt)

    # Verify packets
    pkt_type = verify_kwargs.get('packet_type', '')
    logger.info(
        f"Verifying PrivateLink Redirected Packet: "
        f"Packet Type - {pkt_type}"
    )
    logger.info("**********************")
    logger.info(f"Packet Sent: from {verify_kwargs.get('sent_from', '')}")
    logger.info(f"{sent_pkt}")
    logger.info("**********************")
    logger.info(
        f"Packet Received: at {verify_kwargs.get('received_at', '')}"
    )
    logger.info(f"{received_packet}")
    logger.info("**********************")
    logger.info("Packet Expected :")
    logger.info(f"{expected_pkt.exp_pkt}")
    logger.info("**********************")

    # Overlay verifications
    # Src IP, Dst IP, Src Port, Dst Port
    assert_pkt_info({
        'sent_pkt': sent_pkt,
        'received_packet': received_packet,
        'expected_pkt': expected_pkt.exp_pkt,
        'To_verify': [
            {
                'field_name': 'Overlay Src IP',
                'expected_value': overlay_expected['src_ip'],
                'received_value': overlay_received['src_ip']
            },
            {
                'field_name': 'Overlay Dst IP',
                'expected_value': overlay_expected['dst_ip'],
                'received_value': overlay_received['dst_ip']
            },
            {
                'field_name': 'Overlay Src Port',
                'expected_value': overlay_expected['sport'],
                'received_value': overlay_received['sport']
            },
            {
                'field_name': 'Overlay Dst Port',
                'expected_value': overlay_expected['dport'],
                'received_value': overlay_received['dport']
            },
            {
                'field_name': 'Underlay Src IP',
                'expected_value': underlay_expected['src_ip'],
                'received_value': underlay_received['src_ip']
            },
            {
                'field_name': 'Underlay Dst IP',
                'expected_value': underlay_expected['dst_ip'],
                'received_value': underlay_received['dst_ip']
            }
        ]
    })
    if plnsg:
        logger.info("Verifying PrivateLink NSG Underlay GRE Packet")
        logger.info("**********************")
        plnsg_received = get_plnsg_gre_pkt_details(received_packet)
        plnsg_expected = get_plnsg_gre_pkt_details(expected_pkt.exp_pkt)
        assert_pkt_info({
            'sent_pkt': sent_pkt,
            'received_packet': received_packet,
            'expected_pkt': expected_pkt.exp_pkt,
            'To_verify': [
                {
                    'field_name': 'PLNSG Underlay GRE Src IP',
                    'expected_value': plnsg_expected['src_ip'],
                    'received_value': plnsg_received['src_ip']
                },
                {
                    'field_name': 'PLNSG Underlay GRE Dst IP',
                    'expected_value': plnsg_expected['dst_ip'],
                    'received_value': plnsg_received['dst_ip']
                }
            ]
        })
        if verify_plnsg_vxlan_udp_port:
            logger.info(
                "Verifying PrivateLink NSG VXLAN UDP source port is "
                "within configured range"
            )
            sport = received_packet[UDP].sport
            port_range_end = (
                VXLAN_UDP_BASE_SRC_PORT +
                (1 << VXLAN_UDP_SRC_PORT_MASK) - 1
            )
            assert_msg = (
                f"VXLAN source port {sport} not in expected range "
                f"{VXLAN_UDP_BASE_SRC_PORT}-{port_range_end}"
            )
            pytest_assert(
                VXLAN_UDP_BASE_SRC_PORT <= sport <= port_range_end,
                assert_msg,
            )


def send_receive_verify_pl_redirect_packets(
    ptfadapter,
    send_pkt,
    exp_pkt,
    protocol,
    send_port,
    recv_port,
    direction,
    sent_from,
    received_at,
    plnsg=False,
    verify_plnsg_vxlan_udp_port=False
):
    received_packet_at_pe = send_and_receive_packet(
        ptfadapter,
        send_pkt,
        protocol,
        exp_pkt,
        send_port,
        recv_port,
        direction=direction
    )
    verify_pl_redirect(
        send_pkt,
        received_packet_at_pe,
        exp_pkt,
        packet_type=protocol,
        sent_from=sent_from,
        received_at=received_at,
        plnsg=plnsg,
        verify_plnsg_vxlan_udp_port=verify_plnsg_vxlan_udp_port
    )


def verify_packets(
    ptfadapter, dash_pl_config, packet_dict,
    plnsg=False, verify_plnsg_vxlan_udp_port=False
):
    for protocol, pkt_set in packet_dict.items():
        for index, (
            vm_to_dpu_pkt, exp_dpu_to_pe_pkt,
            pe_to_dpu_pkt, exp_dpu_to_vm_pkt
        ) in enumerate(pkt_set, start=1):
            logger.info(f"[--- Verify {protocol} Packet {index} ---]")
            logger.info(f"Verifying VM to PE flow for {protocol} packet")
            send_receive_verify_pl_redirect_packets(
                ptfadapter,
                vm_to_dpu_pkt,
                exp_dpu_to_pe_pkt,
                protocol,
                dash_pl_config[LOCAL_PTF_INTF],
                dash_pl_config[REMOTE_PTF_RECV_INTF],
                direction='VM to PE',
                sent_from='VM',
                received_at='PE',
                plnsg=plnsg
            )
            logger.info(f"Verifying PE to VM flow for {protocol} packet")
            send_receive_verify_pl_redirect_packets(
                ptfadapter,
                pe_to_dpu_pkt,
                exp_dpu_to_vm_pkt,
                protocol,
                dash_pl_config[REMOTE_PTF_SEND_INTF],
                [dash_pl_config[LOCAL_PTF_INTF]],  # list of ports
                direction='PE to VM',
                sent_from='PE',
                received_at='VM',
                plnsg=plnsg,
                verify_plnsg_vxlan_udp_port=verify_plnsg_vxlan_udp_port
            )
            logger.info(
                f"[--- Completed verification of {protocol} "
                f"Packet {index} ---]\n"
            )
        logger.info(
            f"All packets for {protocol} protocol "
            f"verified successfully"
        )


@pytest.fixture(scope="class", autouse=True)
def set_vxlan_udp_sport_range_redirect(dpuhosts, dpu_index):
    """
    Configure VXLAN UDP source port range in dpu configuration.
    Similar to the fixture(function scope) in conftest.py, but here in 'Class' scope.
    """
    dpuhost = dpuhosts[dpu_index]
    vxlan_sport_config = [
        {
            "SWITCH_TABLE:switch": {
                "vxlan_sport": VXLAN_UDP_BASE_SRC_PORT,
                "vxlan_mask": VXLAN_UDP_SRC_PORT_MASK
            },
            "OP": "SET"
        }
    ]

    logger.info(f"Setting VXLAN source port config: {vxlan_sport_config}")
    config_path = "/tmp/vxlan_sport_config.json"
    dpuhost.copy(
        content=json.dumps(vxlan_sport_config, indent=4),
        dest=config_path,
        verbose=False
    )
    apply_swssconfig_file(dpuhost, config_path)
    if 'pensando' in dpuhost.facts['asic_type']:
        logger.warning("Applying Pensando DPU VXLAN sport workaround")
        dpuhost.shell(
            "pdsctl debug update device --vxlan-port 4789 "
            "--vxlan-src-ports 5120-5247"
        )
    yield
    stdout = dpuhost.shell(
        "redis-cli -n 0 hget SWITCH_TABLE:switch vxlan_sport"
    )['stdout']
    if str(VXLAN_UDP_BASE_SRC_PORT) in stdout:
        config_reload(dpuhost, safe_reload=True, yang_validate=False)


@pytest.fixture(scope="class", autouse=True)
def dpu_setup(duthost, dpuhosts, dpu_index, skip_config):
    if skip_config:

        return
    dpuhost = dpuhosts[dpu_index]
    # explicitly add mgmt IP route so default route doesn't disrupt SSH
    dpuhost.shell(
        f'ip route replace {duthost.mgmt_ip}/32 via 169.254.200.254'
    )
    intfs = dpuhost.shell("show ip int")["stdout"]
    dpu_cmds = list()
    if "Loopback0" not in intfs:
        dpu_cmds.append("config loopback add Loopback0")
        dpu_cmds.append(
            f"config int ip add Loopback0 {pl.APPLIANCE_VIP}/32"
        )
    if 'pensando' in dpuhost.facts['asic_type']:
        if "Ethernet0" not in intfs:
            dpu_cmds.append("config int add Ethernet0")
            dpu_cmds.append(
                f"config int ip add Ethernet0 {dpuhost.dpu_data_port_ip}/31"
            )
    pt_require(dpuhost.npu_data_port_ip, "DPU data port IP is not set")
    dpu_cmds.append(
        f"ip route replace default via {dpuhost.npu_data_port_ip}"
    )
    dpuhost.shell_cmds(cmds=dpu_cmds)


@pytest.fixture(scope="class", autouse=True)
def add_npu_static_routes(
    duthost, dash_pl_config, skip_config, skip_cleanup, dpu_index, dpuhosts
):
    dpuhost = dpuhosts[dpu_index]
    if not skip_config:
        cmds = []
        vm_nexthop_ip = (
            get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1
        )
        pe_nexthop_ip = (
            get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1
        )

        pt_require(
            vm_nexthop_ip,
            "VM nexthop interface does not have an IP address"
        )
        pt_require(
            pe_nexthop_ip,
            "PE nexthop interface does not have an IP address"
        )

        cmds.append(
            f"ip route replace {pl.APPLIANCE_VIP}/32 "
            f"via {dpuhost.dpu_data_port_ip}"
        )
        cmds.append(
            f"ip route replace {pl.VM1_PA}/32 via {vm_nexthop_ip}"
        )

        return_tunnel_endpoints = (
            pl.TUNNEL1_ENDPOINT_IPS + pl.TUNNEL2_ENDPOINT_IPS
        )
        for tunnel_ip in return_tunnel_endpoints:
            cmds.append(
                f"ip route replace {tunnel_ip}/32 via {vm_nexthop_ip}"
            )
        nsg_tunnel_endpoints = (
            pl.TUNNEL3_ENDPOINT_IPS + pl.TUNNEL4_ENDPOINT_IPS
        )
        for tunnel_ip in nsg_tunnel_endpoints:
            cmds.append(
                f"ip route replace {tunnel_ip}/32 via {pe_nexthop_ip}"
            )

        cmds.append(
            f"ip route replace {pl.PE_PA}/32 via {pe_nexthop_ip}"
        )
        cmds.append(
            f"ip route replace {pl.PL_REDIRECT_BACKEND_IP}/32 "
            f"via {pe_nexthop_ip}"
        )
        logger.info(f"Adding static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        cmds = []
        cmds.append(
            f"ip route del {pl.APPLIANCE_VIP}/32 "
            f"via {dpuhost.dpu_data_port_ip}"
        )
        cmds.append(
            f"ip route del {pl.VM1_PA}/32 via {vm_nexthop_ip}"
        )
        for tunnel_ip in return_tunnel_endpoints:
            cmds.append(
                f"ip route replace {tunnel_ip}/32 via {vm_nexthop_ip}"
            )
        cmds.append(
            f"ip route del {pl.PE_PA}/32 via {pe_nexthop_ip}"
        )
        cmds.append(
            f"ip route del {pl.PL_REDIRECT_BACKEND_IP}/32 "
            f"via {pe_nexthop_ip}"
        )
        logger.info(f"Removing static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="class")
def privatelink_redirect_fnic_config(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts
):
    if skip_config:
        yield
        return
    dpuhost = dpuhosts[dpu_index]
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)

    tunnel_config = pl.TUNNEL1_CONFIG

    base_config_messages = {
        **pl.APPLIANCE_FNIC_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.ROUTING_TYPE_VNET_CONFIG,
        **pl.VNET_CONFIG,
        **pl.VNET2_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG,
        **pl.RD_PORTMAP_CONFIG,
        **pl.RD_PORTMAP_RANGE_CONFIG,
        **tunnel_config
    }
    logger.info(base_config_messages)

    apply_messages(
        localhost, duthost, ptfhost,
        base_config_messages, dpuhost.dpu_index
    )

    route_and_mapping_messages = {
        **pl.PL_REDIRECT_PE_VNET_MAPPING_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT
    }
    logger.info(route_and_mapping_messages)
    apply_messages(
        localhost, duthost, ptfhost,
        route_and_mapping_messages, dpuhost.dpu_index
    )

    # inbound routing not implemented in Pensando SAI yet
    if 'pensando' not in dpuhost.facts['asic_type']:
        route_rule_messages = {
            **pl.VM_VNI_ROUTE_RULE_CONFIG,
            **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
            **pl.TRUSTED_VNI_ROUTE_RULE_CONFIG
        }
        logger.info(route_rule_messages)
        apply_messages(
            localhost, duthost, ptfhost,
            route_rule_messages, dpuhost.dpu_index
        )

    meter_rule_messages = {
        **pl.METER_RULE1_V4_CONFIG,
        **pl.METER_RULE2_V4_CONFIG,
    }
    logger.info(meter_rule_messages)
    apply_messages(
        localhost, duthost, ptfhost,
        meter_rule_messages, dpuhost.dpu_index
    )

    logger.info(pl.ENI_FNIC_CONFIG)
    apply_messages(
        localhost, duthost, ptfhost,
        pl.ENI_FNIC_CONFIG, dpuhost.dpu_index
    )

    logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
    apply_messages(
        localhost, duthost, ptfhost,
        pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index
    )

    yield

    # Route rule removal is broken so config reload to cleanup for now
    # https://github.com/sonic-net/sonic-buildimage/issues/23590
    config_reload(dpuhost, safe_reload=True, yang_validate=False)


@pytest.fixture(scope="class")
def privatelink_redirect_nsg_config(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts
):
    if skip_config:
        yield
        return
    dpuhost = dpuhosts[dpu_index]
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)

    tunnel_config = pl.TUNNEL3_CONFIG

    base_config_messages = {
        **pl.APPLIANCE_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.ROUTING_TYPE_VNET_CONFIG,
        **pl.VNET_CONFIG,
        **pl.VNET2_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG,
        **pl.RD_PORTMAP_CONFIG,
        **pl.RD_PORTMAP_RANGE_CONFIG,
        **tunnel_config,
    }
    logger.info(base_config_messages)

    apply_messages(
        localhost, duthost, ptfhost,
        base_config_messages, dpuhost.dpu_index
    )

    route_and_mapping_messages = {
        **pl.PL_REDIRECT_PE_PLNSG_SINGLE_ENDPOINT_VNET_MAPPING_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_CONFIG,
    }
    logger.info(route_and_mapping_messages)
    apply_messages(
        localhost, duthost, ptfhost,
        route_and_mapping_messages, dpuhost.dpu_index
    )

    if 'pensando' not in dpuhost.facts['asic_type']:
        route_rule_messages = {
            **pl.VM_VNI_ROUTE_RULE_CONFIG,
            **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
        }
        logger.info(route_rule_messages)
        apply_messages(
            localhost, duthost, ptfhost,
            route_rule_messages, dpuhost.dpu_index
        )

    meter_rule_messages = {
        **pl.METER_RULE1_V4_CONFIG,
        **pl.METER_RULE2_V4_CONFIG,
    }
    logger.info(meter_rule_messages)
    apply_messages(
        localhost, duthost, ptfhost,
        meter_rule_messages, dpuhost.dpu_index
    )

    logger.info(pl.ENI_CONFIG)
    apply_messages(
        localhost, duthost, ptfhost,
        pl.ENI_CONFIG, dpuhost.dpu_index
    )

    logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
    apply_messages(
        localhost, duthost, ptfhost,
        pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index
    )

    yield

    # Route rule removal is broken so config reload to cleanup for now
    # https://github.com/sonic-net/sonic-buildimage/issues/23590
    config_reload(dpuhost, safe_reload=True, yang_validate=False)


@pytest.mark.usefixtures("privatelink_redirect_fnic_config")
class TestPrivateLinkRedirectFNIC:
    """
    Test class for PrivateLink redirect tests

    Config PL redirect with port map range 8001-9000 and
    backend_port_base 42001, and backend_ip_base 60.60.60.1.
    Test packets TCP and UDP with inner destination port below the
    port map range, above the port map range, start, middle and end
    value of the port map range.
    Verify packets are received and header values are as expected.
    """
    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_below_port_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        below the port map range.
        1. VM to dpu packets sent with inner dest port 8000
        2. VM to PE packets are not sdn modified by DPU and
           forwarded to PE
        3. PE to VM packets are not sdn modified by DPU and
           forwarded to VM
        4. Verify packets are received and header values are
           as expected.
        """

        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 8000  # below port map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            vni=pl.ENI_TRUSTED_VNI,
            floating_nic=True,
        )

        # modify expected packets and update the payload
        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for _a, _b, _c, exp_dpu_to_vm_pkt in pkt_set:
                exp_dpu_to_vm_pkt.exp_pkt[IP].dst = TUNNEL1_ENDPOINT_IP
                exp_dpu_to_vm_pkt = ptfadapter.update_payload(
                    exp_dpu_to_vm_pkt
                )
                new_pkt_set.append((
                    _a, _b, _c, exp_dpu_to_vm_pkt
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(ptfadapter, dash_pl_config, packet_set_dic)

        logger.info("*** Test Completed ***")

    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_above_port_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        above the port map range.
        1. VM to dpu packets sent with inner dest port 9001
        2. VM to PE packets are not sdn modified by DPU and
           forwarded to PE
        3. PE to VM packets are not sdn modified by DPU and
           forwarded to VM
        4. Verify packets are received and header values are
           as expected.
        """

        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 9001  # above port map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            vni=pl.ENI_TRUSTED_VNI,
            floating_nic=True,
        )

        # modify expected packets and update the payload
        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for _a, _b, _c, exp_dpu_to_vm_pkt in pkt_set:
                exp_dpu_to_vm_pkt.exp_pkt[IP].dst = TUNNEL1_ENDPOINT_IP
                exp_dpu_to_vm_pkt = ptfadapter.update_payload(
                    exp_dpu_to_vm_pkt
                )
                new_pkt_set.append((
                    _a, _b, _c, exp_dpu_to_vm_pkt
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(ptfadapter, dash_pl_config, packet_set_dic)

        logger.info("*** Test Completed ***")

    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_is_start_port_in_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        is start port of the port map range.
        1. VM to dpu packets sent with inner dest port 8001
        2. DPU to PE packets are sdn modified (inner dport: 42001,
           encoded inner dst ipv6, outer ipv4: 60.60.60.1,
           encap: GRE) and forwarded to PE
        3. Packets send from PE to dpu with PE parameters.
        4. DPU to VM packets are sdn modified to have same VM/vnic
           parameters (encap: VXLAN) and forwarded to VM
        5. Verify packets are received and header values are as
           expected on both PE and VM side.
        """
        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 8001  # start port in map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            vni=pl.ENI_TRUSTED_VNI,
            floating_nic=True,
        )

        # modify expected packets and update the payload

        # overlay_pe_ipv6 changes per encoding of 60.60.60.1
        overlay_pe_ipv6 = get_pl_overlay_dip(
            pl.PL_REDIRECT_BACKEND_IP,
            pl.PL_REDIRECT_OVERLAY_DIP,
            pl.PL_REDIRECT_OVERLAY_DIP_MASK
        )

        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for (
                _a, exp_dpu_to_pe_pkt,
                pe_to_dpu_pkt, exp_dpu_to_vm_pkt
            ) in pkt_set:

                # modify exp_dpu_to_pe_pkt to have mapped backend
                exp_dpu_to_pe_pkt.exp_pkt[IP].dst = (
                    pl.PL_REDIRECT_BACKEND_IP
                )
                exp_dpu_to_pe_pkt.exp_pkt[GRE][Ether][IPv6].dport = 42001
                exp_dpu_to_pe_pkt.exp_pkt[GRE][Ether][IPv6].dst = (
                    overlay_pe_ipv6
                )

                # modify pe_to_dpu_pkt to have mapped backend port
                pe_to_dpu_pkt[IP].src = pl.PL_REDIRECT_BACKEND_IP
                pe_to_dpu_pkt[GRE][Ether][IPv6].sport = 42001
                pe_to_dpu_pkt[GRE][Ether][IPv6].src = overlay_pe_ipv6

                # modify exp_dpu_to_vm_pkt
                exp_dpu_to_vm_pkt.exp_pkt[VXLAN][Ether][IP].sport = (
                    vm_to_pe_inner_dport
                )
                exp_dpu_to_vm_pkt.exp_pkt[IP].dst = TUNNEL1_ENDPOINT_IP

                exp_dpu_to_vm_pkt = ptfadapter.update_payload(
                    exp_dpu_to_vm_pkt
                )
                new_pkt_set.append((
                    _a, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(ptfadapter, dash_pl_config, packet_set_dic)

        logger.info("*** Test Completed ***")

    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_is_end_port_in_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        is end port of the port map range.
        1. VM to dpu packets sent with inner dest port 9000
        2. DPU to PE packets are sdn modified (inner dport: 43000,
           encoded inner dst ipv6, outer ipv4: 60.60.60.1,
           encap: GRE) and forwarded to PE
        3. Packets send from PE to dpu with PE parameters.
        4. DPU to VM packets are sdn modified to have same VM/vnic
           parameters (encap: VXLAN) and forwarded to VM
        5. Verify packets are received and header values are as
           expected on both PE and VM side.
        """
        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 9000  # end port in map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            vni=pl.ENI_TRUSTED_VNI,
            floating_nic=True,
        )

        # modify expected packets and update the payload

        # overlay_pe_ipv6 changes per encoding of 60.60.60.1
        overlay_pe_ipv6 = get_pl_overlay_dip(
            pl.PL_REDIRECT_BACKEND_IP,
            pl.PL_REDIRECT_OVERLAY_DIP,
            pl.PL_REDIRECT_OVERLAY_DIP_MASK
        )

        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for (
                _a, exp_dpu_to_pe_pkt,
                pe_to_dpu_pkt, exp_dpu_to_vm_pkt
            ) in pkt_set:

                # modify exp_dpu_to_pe_pkt to have mapped backend
                exp_dpu_to_pe_pkt.exp_pkt[IP].dst = (
                    pl.PL_REDIRECT_BACKEND_IP
                )
                exp_dpu_to_pe_pkt.exp_pkt[GRE][Ether][IPv6].dport = 43000
                exp_dpu_to_pe_pkt.exp_pkt[GRE][Ether][IPv6].dst = (
                    overlay_pe_ipv6
                )

                # modify pe_to_dpu_pkt to have mapped backend port
                pe_to_dpu_pkt[IP].src = pl.PL_REDIRECT_BACKEND_IP
                pe_to_dpu_pkt[GRE][Ether][IPv6].sport = 43000
                pe_to_dpu_pkt[GRE][Ether][IPv6].src = overlay_pe_ipv6

                # modify exp_dpu_to_vm_pkt
                exp_dpu_to_vm_pkt.exp_pkt[VXLAN][Ether][IP].sport = (
                    vm_to_pe_inner_dport
                )
                exp_dpu_to_vm_pkt.exp_pkt[IP].dst = TUNNEL1_ENDPOINT_IP

                exp_dpu_to_vm_pkt = ptfadapter.update_payload(
                    exp_dpu_to_vm_pkt
                )
                new_pkt_set.append((
                    _a, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(ptfadapter, dash_pl_config, packet_set_dic)

        logger.info("*** Test Completed ***")

    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_is_middle_port_in_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        is middle port of the port map range.
        1. VM to dpu packets sent with inner dest port 8500
        2. DPU to PE packets are sdn modified (inner dport: 42500,
           encoded inner dst ipv6, outer ipv4: 60.60.60.1,
           encap: GRE) and forwarded to PE
        3. Packets send from PE to dpu with PE parameters.
        4. DPU to VM packets are sdn modified to have same VM/vnic
           parameters (encap: VXLAN) and forwarded to VM
        5. Verify packets are received and header values are as
           expected on both PE and VM side.
        """
        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 8500  # middle port in port map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            vni=pl.ENI_TRUSTED_VNI,
            floating_nic=True,
        )

        # modify expected packets and update the payload

        # overlay_pe_ipv6 changes per encoding of 60.60.60.1
        overlay_pe_ipv6 = get_pl_overlay_dip(
            pl.PL_REDIRECT_BACKEND_IP,
            pl.PL_REDIRECT_OVERLAY_DIP,
            pl.PL_REDIRECT_OVERLAY_DIP_MASK
        )

        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for (
                _a, exp_dpu_to_pe_pkt,
                pe_to_dpu_pkt, exp_dpu_to_vm_pkt
            ) in pkt_set:

                # modify exp_dpu_to_pe_pkt to have mapped backend
                exp_dpu_to_pe_pkt.exp_pkt[IP].dst = (
                    pl.PL_REDIRECT_BACKEND_IP
                )
                exp_dpu_to_pe_pkt.exp_pkt[GRE][Ether][IPv6].dport = 42500
                exp_dpu_to_pe_pkt.exp_pkt[GRE][Ether][IPv6].dst = (
                    overlay_pe_ipv6
                )

                # modify pe_to_dpu_pkt to have mapped backend port
                pe_to_dpu_pkt[IP].src = pl.PL_REDIRECT_BACKEND_IP
                pe_to_dpu_pkt[GRE][Ether][IPv6].sport = 42500
                pe_to_dpu_pkt[GRE][Ether][IPv6].src = overlay_pe_ipv6

                # modify exp_dpu_to_vm_pkt
                exp_dpu_to_vm_pkt.exp_pkt[VXLAN][Ether][IP].sport = (
                    vm_to_pe_inner_dport
                )
                exp_dpu_to_vm_pkt.exp_pkt[IP].dst = TUNNEL1_ENDPOINT_IP

                exp_dpu_to_vm_pkt = ptfadapter.update_payload(
                    exp_dpu_to_vm_pkt
                )
                new_pkt_set.append((
                    _a, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(ptfadapter, dash_pl_config, packet_set_dic)

        logger.info("*** Test Completed ***")


@pytest.mark.usefixtures("privatelink_redirect_nsg_config")
class TestPrivateLinkRedirectPLNSG:
    """
    Test class for PrivateLink redirect With PLNSG tests

    Config PL redirect with PLNSG with port map range 8001-9000 and
    backend_port_base 42001, and backend_ip_base 60.60.60.1.
    Test packets TCP and UDP with inner destination port below the
    port map range, above the port map range, start, middle and end
    value of the port map range.
    Verify packets are received and header values are as expected.
    """
    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_below_port_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        below the port map range.
        1. VM to dpu packets sent with inner dest port 8000
        2. VM to PE packets are not sdn modified by DPU and
           forwarded to PE
        3. PE to VM packets are not sdn modified by DPU and
           forwarded to VM
        4. Verify packets are received and header values are
           as expected.
        """

        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 8000  # below port map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            plnsg=True,
        )

        # modify expected packets and update the payload
        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for _a, exp_dpu_to_pe_pkt, _c, _d in pkt_set:
                # modify exp_dpu_to_pe_pkt to have as per the
                # plnsg config tunnel 3 ip : 80.80.80.80
                exp_dpu_to_pe_pkt.exp_pkt[IP].dst = pl.TUNNEL3_ENDPOINT_IP
                exp_dpu_to_pe_pkt = ptfadapter.update_payload(
                    exp_dpu_to_pe_pkt
                )
                new_pkt_set.append((
                    _a, exp_dpu_to_pe_pkt, _c, _d
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(
            ptfadapter, dash_pl_config, packet_set_dic,
            plnsg=True, verify_plnsg_vxlan_udp_port=True
        )

        logger.info("*** Test Completed ***")

    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_above_port_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        above the port map range.
        1. VM to dpu packets sent with inner dest port 9001
        2. VM to PE packets are not sdn modified by DPU and
           forwarded to PE
        3. PE to VM packets are not sdn modified by DPU and
           forwarded to VM
        4. Verify packets are received and header values are
           as expected.
        """

        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 9001  # above port map range

        # generate packets to test
        # return is dict packet_set_dic = {'tcp': [(),(),..], 'udp': []}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            plnsg=True,
        )

        # modify expected packets and update the payload
        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for _a, exp_dpu_to_pe_pkt, _c, _d in pkt_set:
                # modify exp_dpu_to_pe_pkt to have as per the
                # plnsg config tunnel 3 ip : 80.80.80.80
                exp_dpu_to_pe_pkt.exp_pkt[IP].dst = pl.TUNNEL3_ENDPOINT_IP
                exp_dpu_to_pe_pkt = ptfadapter.update_payload(
                    exp_dpu_to_pe_pkt
                )

                new_pkt_set.append((
                    _a, exp_dpu_to_pe_pkt, _c, _d
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(
            ptfadapter, dash_pl_config, packet_set_dic,
            plnsg=True, verify_plnsg_vxlan_udp_port=True
        )

        logger.info("*** Test Completed ***")

    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_is_start_port_in_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        is start port of the port map range.
        1. VM to dpu packets sent with inner dest port 8001
        2. DPU to PE packets are sdn modified (inner dport: 42001,
           encoded inner dst ipv6, outer ipv4: 60.60.60.1,
           encap: GRE) and forwarded to PE
        3. Packets send from PE to dpu with PE parameters.
        4. DPU to VM packets are sdn modified to have same VM/vnic
           parameters (encap: VXLAN) and forwarded to VM
        5. Verify packets are received and header values are as
           expected on both PE and VM side.
        """
        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 8001  # start port in map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            plnsg=True,
        )

        # modify expected packets and update the payload

        # overlay_pe_ipv6 changes per encoding of 60.60.60.1
        overlay_pe_ipv6 = get_pl_overlay_dip(
            pl.PL_REDIRECT_BACKEND_IP,
            pl.PL_REDIRECT_OVERLAY_DIP,
            pl.PL_REDIRECT_OVERLAY_DIP_MASK
        )

        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for (
                _a, exp_dpu_to_pe_pkt,
                pe_to_dpu_pkt, exp_dpu_to_vm_pkt
            ) in pkt_set:

                # modify exp_dpu_to_pe_pkt as per the
                # plnsg config tunnel 3 ip: 80.80.80.80
                exp_dpu_to_pe_pkt.exp_pkt[IP].dst = pl.TUNNEL3_ENDPOINT_IP
                # modify exp_dpu_to_pe_pkt to have mapped backend
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][IP].dst = (
                    pl.PL_REDIRECT_BACKEND_IP
                )
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][GRE][Ether][
                    IPv6
                ].dport = 42001
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][GRE][Ether][
                    IPv6
                ].dst = overlay_pe_ipv6

                # modify pe_to_dpu_pkt to have mapped backend port
                pe_to_dpu_pkt[IP].src = pl.PL_REDIRECT_BACKEND_IP
                pe_to_dpu_pkt[GRE][Ether][IPv6].sport = 42001
                pe_to_dpu_pkt[GRE][Ether][IPv6].src = overlay_pe_ipv6

                # modify exp_dpu_to_vm_pkt
                exp_dpu_to_vm_pkt.exp_pkt[VXLAN][Ether][IP].sport = (
                    vm_to_pe_inner_dport
                )

                new_pkt_set.append((
                    _a, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(
            ptfadapter, dash_pl_config, packet_set_dic,
            plnsg=True, verify_plnsg_vxlan_udp_port=True
        )

        logger.info("*** Test Completed ***")

    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_is_end_port_in_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        is end port of the port map range.
        1. VM to dpu packets sent with inner dest port 9000
        2. DPU to PE packets are sdn modified (inner dport: 43000,
           encoded inner dst ipv6, outer ipv4: 60.60.60.1,
           encap: GRE) and forwarded to PE
        3. Packets send from PE to dpu with PE parameters.
        4. DPU to VM packets are sdn modified to have same VM/vnic
           parameters (encap: VXLAN) and forwarded to VM
        5. Verify packets are received and header values are as
           expected on both PE and VM side.
        """
        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 9000  # end port in map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            plnsg=True,
        )

        # modify expected packets and update the payload

        # overlay_pe_ipv6 changes per encoding of 60.60.60.1
        overlay_pe_ipv6 = get_pl_overlay_dip(
            pl.PL_REDIRECT_BACKEND_IP,
            pl.PL_REDIRECT_OVERLAY_DIP,
            pl.PL_REDIRECT_OVERLAY_DIP_MASK
        )

        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for (
                _a, exp_dpu_to_pe_pkt,
                pe_to_dpu_pkt, exp_dpu_to_vm_pkt
            ) in pkt_set:

                # modify exp_dpu_to_pe_pkt to have as per the
                # plnsg config tunnel 3 ip : 80.80.80.80
                exp_dpu_to_pe_pkt.exp_pkt[IP].dst = pl.TUNNEL3_ENDPOINT_IP
                # modify exp_dpu_to_pe_pkt to have mapped backend
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][IP].dst = (
                    pl.PL_REDIRECT_BACKEND_IP
                )
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][GRE][Ether][
                    IPv6
                ].dport = 43000
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][GRE][Ether][
                    IPv6
                ].dst = overlay_pe_ipv6

                # modify pe_to_dpu_pkt to have mapped backend port
                pe_to_dpu_pkt[IP].src = pl.PL_REDIRECT_BACKEND_IP
                pe_to_dpu_pkt[GRE][Ether][IPv6].sport = 43000
                pe_to_dpu_pkt[GRE][Ether][IPv6].src = overlay_pe_ipv6

                # modify exp_dpu_to_vm_pkt
                exp_dpu_to_vm_pkt.exp_pkt[VXLAN][Ether][IP].sport = (
                    vm_to_pe_inner_dport
                )

                new_pkt_set.append((
                    _a, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(
            ptfadapter, dash_pl_config, packet_set_dic,
            plnsg=True, verify_plnsg_vxlan_udp_port=True
        )

        logger.info("*** Test Completed ***")

    @pytest.mark.parametrize(
        "l4_protocols", [['tcp'], ['udp']], ids=['tcp', 'udp']
    )
    def test_dst_port_is_middle_port_in_map_range(
        self, ptfadapter, dash_pl_config, l4_protocols
    ):
        """
        Test:
        Create UDP and TCP packets with inner destination port
        is middle port of the port map range.
        1. VM to dpu packets sent with inner dest port 8500
        2. DPU to PE packets are sdn modified (inner dport: 42500,
           encoded inner dst ipv6, outer ipv4: 60.60.60.1,
           encap: GRE) and forwarded to PE
        3. Packets send from PE to dpu with PE parameters.
        4. DPU to VM packets are sdn modified to have same VM/vnic
           parameters (encap: VXLAN) and forwarded to VM
        5. Verify packets are received and header values are as
           expected on both PE and VM side.
        """
        logger.info(f"dash_pl_config: \n{dash_pl_config}")

        # for reverse flow, sport, dport will be reversed
        vm_to_pe_inner_sport = 12345
        vm_to_pe_inner_dport = 8500  # middle port in port map range

        # packet_set_dic = {'tcp': [(),(),..], 'udp': [(),(),..]}
        packet_set_dic = generate_packets(
            ptfadapter,
            dash_pl_config,
            packets=3,
            l4_protocols=l4_protocols,
            inner_sport=vm_to_pe_inner_sport,
            inner_dport=vm_to_pe_inner_dport,
            plnsg=True,
        )

        # modify expected packets and update the payload

        # overlay_pe_ipv6 changes per encoding of 60.60.60.1
        overlay_pe_ipv6 = get_pl_overlay_dip(
            pl.PL_REDIRECT_BACKEND_IP,
            pl.PL_REDIRECT_OVERLAY_DIP,
            pl.PL_REDIRECT_OVERLAY_DIP_MASK
        )

        for protocol, pkt_set in packet_set_dic.items():
            new_pkt_set = []
            for (
                _a, exp_dpu_to_pe_pkt,
                pe_to_dpu_pkt, exp_dpu_to_vm_pkt
            ) in pkt_set:

                # modify exp_dpu_to_pe_pkt as per the
                # plnsg config tunnel 3 ip: 80.80.80.80
                exp_dpu_to_pe_pkt.exp_pkt[IP].dst = pl.TUNNEL3_ENDPOINT_IP
                # modify exp_dpu_to_pe_pkt to have mapped backend
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][IP].dst = (
                    pl.PL_REDIRECT_BACKEND_IP
                )
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][GRE][Ether][
                    IPv6
                ].dport = 42500
                exp_dpu_to_pe_pkt.exp_pkt[VXLAN][Ether][GRE][Ether][
                    IPv6
                ].dst = overlay_pe_ipv6

                # modify pe_to_dpu_pkt to have mapped backend port
                pe_to_dpu_pkt[IP].src = pl.PL_REDIRECT_BACKEND_IP
                pe_to_dpu_pkt[GRE][Ether][IPv6].sport = 42500
                pe_to_dpu_pkt[GRE][Ether][IPv6].src = overlay_pe_ipv6

                # modify exp_dpu_to_vm_pkt
                exp_dpu_to_vm_pkt.exp_pkt[VXLAN][Ether][IP].sport = (
                    vm_to_pe_inner_dport
                )

                new_pkt_set.append((
                    _a, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt
                ))
            packet_set_dic[protocol] = new_pkt_set

        ptfadapter.dataplane.flush()

        verify_packets(
            ptfadapter, dash_pl_config, packet_set_dic,
            plnsg=True, verify_plnsg_vxlan_udp_port=True
        )

        logger.info("*** Test Completed ***")
