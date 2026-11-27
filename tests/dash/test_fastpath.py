import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import packets
from scapy.all import Ether, IP, VXLAN, IPv6, UDP, GRE, TCP
from constants import LOCAL_PTF_INTF, LOCAL_DUT_INTF, REMOTE_DUT_INTF,\
                      REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from gnmi_utils import apply_messages
from tests.common import config_reload
from tests.dash.dash_utils import verify_tunnel_packets
from tests.dash.conftest import get_interface_ip

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("smartswitch"),
    pytest.mark.skip_check_dut_health
]

PL_FLOW_TCP_PORT = pl.FASTPATH_PL_FLOW_TCP_PORT
PLREDIRECT_FLOW_TCP_PORT = pl.FASTPATH_PLREDIRECT_FLOW_TCP_PORT

FASTPATH_FLOW = {"1": {
                    "exp_pl_outer_dip": pl.PE_PA,
                    "fastpath_redirected_flow": True,
                    "fastpath_redirected_dip_hex": pl.FASTPATH_FLOW1_REDIRECTED_DIP_HEX,
                    "fastpath_redirected_dip": pl.FASTPATH_FLOW1_REDIRECTED_DIP,
                    "fastpath_redirected_dmac": pl.FASTPATH_FLOW1_REDIRECTED_DMAC,
                    "send_icmpv6_redirect_before_synack": True
                 },
                 "2": {
                    "exp_pl_outer_dip": pl.PE_PA,
                    "fastpath_redirected_flow": True,
                    "fastpath_redirected_dip_hex": pl.FASTPATH_FLOW2_REDIRECTED_DIP_HEX,
                    "fastpath_redirected_dip": pl.FASTPATH_FLOW2_REDIRECTED_DIP,
                    "fastpath_redirected_dmac": pl.FASTPATH_FLOW2_REDIRECTED_DMAC,
                    "send_icmpv6_redirect_before_synack": False
                 },
                 "3": {
                    "exp_pl_outer_dip": pl.PE_PA,
                    "fastpath_redirected_flow": False
                 }
                }


@pytest.fixture(scope="module")
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
        dpu_cmds.append(f"config interface ip add Loopback0 {pl.APPLIANCE_VIP}/32")

    if 'pensando' in dpuhost.facts['asic_type']:
        if "Ethernet0" not in intfs:
            dpu_cmds.append(f"config interface ip add Ethernet0 {dpuhost.dpu_data_port_ip}/31")
    dpuhost.shell_cmds(cmds=dpu_cmds)

    intfs = dpuhost.shell("show ip interfaces")["stdout"]
    if dpuhost.dpu_data_port_ip  in intfs and dpuhost.npu_data_port_ip is not None:
        dpu_cmds.append(f"ip route replace default via {dpuhost.npu_data_port_ip}")
        dpuhost.shell_cmds(cmds=f"ip route replace default via {dpuhost.npu_data_port_ip}")
        dpuhost.shell("show ip interfaces")["stdout"]


@pytest.fixture(scope="module")
def setup_npu_routes(duthost, dash_pl_config, skip_config, skip_cleanup, dpu_index, dpuhosts):
    dpuhost = dpuhosts[dpu_index]

    if not skip_config:
        cmds = []
        vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1
        pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1

        if dpuhost.dpu_data_port_ip is not None and dpuhost.npu_data_port_ip is not None:
            cmds.append(f"config route add prefix {pl.APPLIANCE_VIP}/32 nexthop {dpuhost.dpu_data_port_ip}")

        cmds.append(f"config route add prefix {pl.VM1_PA}/32 nexthop {vm_nexthop_ip}")
        cmds.append(f"config route add prefix {pl.PE_PA}/32 nexthop {pe_nexthop_ip}")
        cmds.append(f"config route add prefix {pl.FASTPATH_FLOW1_REDIRECTED_DIP}/32 nexthop {pe_nexthop_ip}")
        cmds.append(f"config route add prefix {pl.FASTPATH_FLOW2_REDIRECTED_DIP}/32 nexthop {pe_nexthop_ip}")
        cmds.append(f"config route add prefix {pl.PL_REDIRECT_BACKEND_IP}/32 nexthop {pe_nexthop_ip}")
        return_tunnel_endpoints = pl.TUNNEL1_ENDPOINT_IPS
        for tunnel_ip in return_tunnel_endpoints:
            cmds.append(f"config route add prefix {tunnel_ip}/32 nexthop {vm_nexthop_ip}")
        nsg_tunnel_endpoints = pl.TUNNEL3_ENDPOINT_IPS
        for tunnel_ip in nsg_tunnel_endpoints:
            cmds.append(f"config route add prefix {tunnel_ip}/32 nexthop {pe_nexthop_ip}")

        logger.info(f"Adding static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)
        cleanup_cmds = [cmd.replace("add", "del") for cmd in cmds]

    yield

    if not skip_config and not skip_cleanup:
        logger.info(f"Removing static routes: {cmds}")
        duthost.shell_cmds(cmds=cleanup_cmds, continue_on_fail=True, module_ignore_errors=True)


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    setup_npu_routes,
    dpu_setup
):
    if skip_config:
        yield
        return
    dpuhost = dpuhosts[dpu_index]
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)

    base_config_messages = {
        **pl.APPLIANCE_FNIC_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.ROUTING_TYPE_VNET_CONFIG,
        **pl.VNET_CONFIG,
        **pl.VNET2_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG,
        **pl.FP_RD_PORTMAP_CONFIG,
        **pl.FP_RD_PORTMAP_RANGE_CONFIG,
        **pl.TUNNEL1_CONFIG,
        **pl.TUNNEL3_CONFIG
    }
    logger.info(base_config_messages)
    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

    vm_subnet_route_config = pl.VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT
    route_and_mapping_messages = {
        **pl.PE_VNET_MAPPING_WITH_PORTMAP_CONFIG,
        **pl.PLNSG_ENDPOINT_VNET_MAPPING_2_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **vm_subnet_route_config
    }
    logger.info(route_and_mapping_messages)
    apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

    # inbound routing not implemented in Pensando SAI yet, so skip route rule programming
    if 'pensando' not in dpuhost.facts['asic_type']:
        route_rule_messages = {
            **pl.VM_VNI_ROUTE_RULE_CONFIG,
            **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
            **pl.TRUSTED_VNI_ROUTE_RULE_CONFIG
        }
        logger.info(route_rule_messages)
        apply_messages(localhost, duthost, ptfhost, route_rule_messages, dpuhost.dpu_index)

    meter_rule_messages = {
        **pl.METER_RULE1_V4_CONFIG,
        **pl.METER_RULE2_V4_CONFIG,
    }
    logger.info(meter_rule_messages)
    apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index)

    logger.info(pl.ENI_FNIC_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_FNIC_CONFIG, dpuhost.dpu_index)

    logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield

    if 'pensando' in dpuhost.facts['asic_type']:
        # unconfiguring DASH configs in reverse order
        unconfig_order = {
            **pl.ENI_ROUTE_GROUP1_CONFIG,
            **pl.ENI_FNIC_CONFIG,
            **pl.PLNSG_ENDPOINT_VNET_MAPPING_2_CONFIG,
            **pl.PE_VNET_MAPPING_WITH_PORTMAP_CONFIG,
            **pl.PE_SUBNET_ROUTE_CONFIG,
            **pl.VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT,
            **pl.TUNNEL3_CONFIG,
            **pl.TUNNEL1_CONFIG,
            **pl.FP_RD_PORTMAP_RANGE_CONFIG,
            **pl.FP_RD_PORTMAP_CONFIG,
            **pl.METER_POLICY_V4_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.VNET2_CONFIG,
            **pl.VNET_CONFIG,
            **pl.APPLIANCE_FNIC_CONFIG
        }
        apply_messages(localhost, duthost, ptfhost, unconfig_order, dpuhost.dpu_index, False)
    else:
        # Route rule removal is broken so config reload to cleanup for now
        # https://github.com/sonic-net/sonic-buildimage/issues/23590
        config_reload(dpuhost, safe_reload=True, yang_validate=False)


@pytest.mark.parametrize("fastpath_tc", ['PL_FASTPATH', 'PL_REDIRECT_FASTPATH'])
def test_pl_fastpath(ptfadapter, dash_pl_config, fastpath_tc):
    """
    Flow-1
    ======
     VM -------------------DPU ------------------------- PL Endpoint
          TCP SYN------->
                                    <------ICMPv6 redirect (FastPath)
                                    <------- TCP SYN+ACK
          TCP ACK ------>               (Verify Flow fixup by checking Outer DIP & Inner DMAC)
                   [Session Closure]
          TCP FIN+ACK --->
                                    <------- TCP FIN+ACK
          TCP ACK -------->
    Flow-2
    ======
     VM -------------------DPU ------------------------- PL Endpoint
          TCP SYN------->
                                    <------- TCP SYN+ACK
                                    <------ICMPv6 redirect (FastPath)
          TCP ACK ------>               (Verify Flow fixup by checking Outer DIP & Inner DMAC)
                   [Session Closure]
          TCP FIN+ACK --->
                                    <------- TCP RST
    Flow-3
    ======
     VM -------------------DPU ------------------------- PL Endpoint
          TCP SYN------->
                                    <------- TCP SYN+ACK
          TCP ACK ------>
                   [Session Closure]
          TCP FIN+ACK --->
                                    <------- TCP FIN+ACK
          TCP ACK -------->
    """
    tunnel_endpoint_counts = {ip: 0 for ip in pl.TUNNEL1_ENDPOINT_IPS}
    vm_to_dpu_pkt = exp_dpu_to_pe_pkt = pe_to_dpu_pkt = exp_dpu_to_vm_pkt = None

    # Build test packet
    _flow_num = 0
    for eachflow in FASTPATH_FLOW:
        if fastpath_tc == 'PL_FASTPATH':
            FASTPATH_FLOW[eachflow]["tcp_sport"] = PL_FLOW_TCP_PORT + _flow_num
            FASTPATH_FLOW[eachflow]["tcp_dport"] = PL_FLOW_TCP_PORT + _flow_num
        elif fastpath_tc == 'PL_REDIRECT_FASTPATH':
            FASTPATH_FLOW[eachflow]["tcp_sport"] = PLREDIRECT_FLOW_TCP_PORT + _flow_num
            FASTPATH_FLOW[eachflow]["tcp_dport"] = PLREDIRECT_FLOW_TCP_PORT + _flow_num

        _flow_params = FASTPATH_FLOW[eachflow]
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = packets.generate_pl_pkts_with_inner_l4_parameters(
                                       dash_pl_config, floating_nic=True,
                                       vni=pl.ENI_TRUSTED_VNI, inner_packet_type="tcp",
                                       inner_sport=_flow_params["tcp_sport"],
                                       inner_dport=_flow_params["tcp_dport"])
        if fastpath_tc == 'PL_REDIRECT_FASTPATH':
            exp_dpu_to_pe_pkt.exp_pkt[Ether][IP].dst = pl.PL_REDIRECT_BACKEND_IP
            update_exp_overlay_dip = packets.get_pl_overlay_dip(pl.PL_REDIRECT_BACKEND_IP,
                                                                pl.PL_REDIRECT_OVERLAY_DIP,
                                                                pl.PL_REDIRECT_OVERLAY_DIP_MASK)
            exp_dpu_to_pe_pkt.exp_pkt[Ether][IP][GRE][Ether][IPv6].dst = update_exp_overlay_dip
            exp_dpu_to_pe_pkt.exp_pkt[Ether][IP][GRE][Ether][IPv6][TCP].dport = pl.PL_REDIRECT_BACKEND_PORT_BASE + _flow_num
            pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].sport = pl.PL_REDIRECT_BACKEND_PORT_BASE + _flow_num
            pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6].src = update_exp_overlay_dip
            pe_to_dpu_pkt[Ether][IP].src = pl.PL_REDIRECT_BACKEND_IP

        exp_dpu_to_vm_pkt.exp_pkt[Ether][IP].dst = pl.TUNNEL1_ENDPOINT_IP
        exp_dpu_to_vm_pkt = ptfadapter.update_payload(exp_dpu_to_vm_pkt)

        if _flow_params["fastpath_redirected_flow"]:
            _dst_port = _flow_params["tcp_dport"]
            backend_ip = None
            if fastpath_tc == 'PL_REDIRECT_FASTPATH':
                _dst_port = pl.PL_REDIRECT_BACKEND_PORT_BASE + _flow_num
                backend_ip = pl.PL_REDIRECT_BACKEND_IP
            _flow_params['fastpath_pkt'] = packets.fastpath_icmpv6_redirect_packets(
                                             dash_pl_config,
                                             inner_sport=_flow_params["tcp_sport"],
                                             inner_dport=_dst_port,
                                             redirected_dmac=_flow_params["fastpath_redirected_dmac"],
                                             redirected_dip=_flow_params["fastpath_redirected_dip_hex"],
                                             backend_ip=backend_ip)
            FASTPATH_FLOW[eachflow]['fastpath_pkt'] = _flow_params['fastpath_pkt']

        _flow_params['pkt_sets'] = (vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt)
        FASTPATH_FLOW[eachflow]['pkt_sets'] = _flow_params['pkt_sets']

        _flow_num += 1

    ptfadapter.dataplane.flush()

    # TCP Session establishment
    for eachflow in FASTPATH_FLOW:
        _flow_params = FASTPATH_FLOW[eachflow]
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = _flow_params['pkt_sets']

        # Sending TCP SYN Packet from VM---> DPU ---> PL Endpoint
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])

        if _flow_params["fastpath_redirected_flow"]:
            exp_dpu_to_pe_pkt.exp_pkt[Ether][IP].dst = _flow_params["fastpath_redirected_dip"]
            FASTPATH_FLOW[eachflow]['pkt_sets'] = (vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt)

        # Flow-1 send fastpath ICMPv6 redirect packet before SYNACK is send to DPU
        if _flow_params["fastpath_redirected_flow"] and \
           _flow_params["send_icmpv6_redirect_before_synack"]:
            dp_device, dp_port = testutils.port_to_tuple(dash_pl_config[REMOTE_PTF_SEND_INTF])
            ptfadapter.dataplane.send(dp_device, dp_port, _flow_params['fastpath_pkt'])

        # Sending TCP SYN+ACK Packet from PL ENDPOINT---> DPU ---> VM
        pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].ack = 47
        pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].flags = 'SA'

        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        verify_tunnel_packets(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], exp_dpu_to_vm_pkt, tunnel_endpoint_counts)

        # Flow-2 send fastpath ICMPv6 redirect packet before SYNACK is send to DPU
        if _flow_params["fastpath_redirected_flow"] and \
               not _flow_params["send_icmpv6_redirect_before_synack"]:
            dp_device, dp_port = testutils.port_to_tuple(dash_pl_config[REMOTE_PTF_SEND_INTF])
            ptfadapter.dataplane.send(dp_device, dp_port, _flow_params['fastpath_pkt'])

        # Sending TCP ACK Packet from VM---> DPU ---> PL Endpoint
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].ack = 27
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].seq = 47
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].flags = 'A'

        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])

    # TCP Session closure
    for eachflow in FASTPATH_FLOW:
        _flow_params = FASTPATH_FLOW[eachflow]
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = _flow_params['pkt_sets']

        # Sending TCP FIN+ACK Packet from VM---> DPU ---> PL Endpoint
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].ack = 27
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].seq = 93
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].flags = 'FA'

        # Flow-2 send fastpath ICMPv6 redirect packet before SYNACK is send to DPU
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])

        # Sending TCP SYN+ACK Packet from PL ENDPOINT---> DPU ---> VM
        pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].ack = 140
        pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].seq = 27
        if _flow_params.get('send_tcp_rst_from_pl', False):
            pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].flags = 'R'
        else:
            pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].flags = 'FA'
        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        verify_tunnel_packets(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], exp_dpu_to_vm_pkt, tunnel_endpoint_counts)

        if _flow_params.get('send_tcp_rst_from_pl', False):
            # If PL endpoint send TCP RST for session closure
            # No need to send final ACK packet to close the session
            continue

        # Sending TCP ACK Packet from VM---> DPU ---> PL Endpoint
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].seq = 140
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].ack = 54
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].flags = 'A'
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])


@pytest.mark.parametrize("fastpath_tc", ['PL_FASTPATH', 'PL_REDIRECT_FASTPATH'])
#@pytest.mark.skip
def test_plnsg_fastpath(ptfadapter, dash_pl_config, fastpath_tc):
    """
    Flow-1
    ======
     VM -------------------DPU --------PLNSG----------------- PL Endpoint
          TCP SYN------->
                                    <------ICMPv6 redirect (FastPath)
                                    <------- TCP SYN+ACK
          TCP ACK ------>               (Verify Flow fixup by checking Outer DIP & Inner DMAC)
                   [Session Closure]
          TCP FIN+ACK --->
                                    <------- TCP FIN+ACK
          TCP ACK -------->
    Flow-2
    ======
     VM -------------------DPU ------------------------- PL Endpoint
          TCP SYN------->
                                    <------- TCP SYN+ACK
                                    <------ICMPv6 redirect (FastPath)
          TCP ACK ------>               (Verify Flow fixup by checking Outer DIP & Inner DMAC)
                   [Session Closure]
          TCP FIN+ACK --->
                                    <------- TCP RST
    Flow-3
    ======
     VM -------------------DPU ------------------------- PL Endpoint
          TCP SYN------->
                                    <------- TCP SYN+ACK
          TCP ACK ------>
                   [Session Closure]
          TCP FIN+ACK --->
                                    <------- TCP FIN+ACK
          TCP ACK -------->
    """
    tunnel_endpoint_counts = {ip: 0 for ip in pl.TUNNEL1_ENDPOINT_IPS}
    vm_to_dpu_pkt = exp_dpu_to_pe_pkt = pe_to_dpu_pkt = exp_dpu_to_vm_pkt = None

    # Build test packet
    _flow_num = 0
    for eachflow in FASTPATH_FLOW:
        if fastpath_tc == 'PL_FASTPATH':
            FASTPATH_FLOW[eachflow]["tcp_sport"] = PL_FLOW_TCP_PORT + _flow_num
            FASTPATH_FLOW[eachflow]["tcp_dport"] = PL_FLOW_TCP_PORT + _flow_num
        elif fastpath_tc == 'PL_REDIRECT_FASTPATH':
            FASTPATH_FLOW[eachflow]["tcp_sport"] = PLREDIRECT_FLOW_TCP_PORT + _flow_num
            FASTPATH_FLOW[eachflow]["tcp_dport"] = PLREDIRECT_FLOW_TCP_PORT + _flow_num

        _flow_params = FASTPATH_FLOW[eachflow]

        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = packets.generate_pl_pkts_with_inner_l4_parameters(
                          dash_pl_config, floating_nic=True,
                          vni=pl.ENI_TRUSTED_VNI, inner_packet_type="tcp",
                          plnsg=True, inner_sport=_flow_params["tcp_sport"],
                          inner_dport=_flow_params["tcp_dport"],
                          inner_dip=pl.PE_CA2)

        if fastpath_tc == 'PL_REDIRECT_FASTPATH':
            exp_dpu_to_pe_pkt.exp_pkt[Ether][IP][UDP][VXLAN][Ether][IP].dst = pl.PL_REDIRECT_BACKEND_IP
            update_exp_overlay_dip = packets.get_pl_overlay_dip(pl.PL_REDIRECT_BACKEND_IP,
                                                                pl.PL_REDIRECT_OVERLAY_DIP,
                                                                pl.PL_REDIRECT_OVERLAY_DIP_MASK)
            exp_dpu_to_pe_pkt.exp_pkt[Ether][IP][UDP][VXLAN][Ether][IP][GRE][Ether][IPv6].dst = update_exp_overlay_dip
            exp_dpu_to_pe_pkt.exp_pkt[Ether][IP][UDP][VXLAN][Ether][IP][GRE][Ether][IPv6][TCP].dport = \
                                                      pl.PL_REDIRECT_BACKEND_PORT_BASE + _flow_num
            pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].sport = pl.PL_REDIRECT_BACKEND_PORT_BASE + _flow_num
            pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6].src = update_exp_overlay_dip
            pe_to_dpu_pkt[Ether][IP].src = pl.PL_REDIRECT_BACKEND_IP

        exp_dpu_to_vm_pkt.exp_pkt[Ether][IP].dst = pl.TUNNEL1_ENDPOINT_IP
        exp_dpu_to_vm_pkt = ptfadapter.update_payload(exp_dpu_to_vm_pkt)

        if _flow_params["fastpath_redirected_flow"]:
            _dst_port = _flow_params["tcp_dport"]
            backend_ip = None
            if fastpath_tc == 'PL_REDIRECT_FASTPATH':
                _dst_port = pl.PL_REDIRECT_BACKEND_PORT_BASE + _flow_num
                backend_ip = pl.PL_REDIRECT_BACKEND_IP
            _flow_params['fastpath_pkt'] = packets.fastpath_icmpv6_redirect_packets(
                                             dash_pl_config,
                                             inner_sport=_flow_params["tcp_sport"],
                                             inner_dport=_dst_port,
                                             redirected_dmac=_flow_params["fastpath_redirected_dmac"],
                                             redirected_dip=_flow_params["fastpath_redirected_dip_hex"],
                                             backend_ip=backend_ip)
            FASTPATH_FLOW[eachflow]['fastpath_pkt'] = _flow_params['fastpath_pkt']

        _flow_params['pkt_sets'] = (vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt)
        FASTPATH_FLOW[eachflow]['pkt_sets'] = _flow_params['pkt_sets']

        _flow_num += 1

    ptfadapter.dataplane.flush()

    # TCP Session state transition
    for eachflow in FASTPATH_FLOW:
        _flow_params = FASTPATH_FLOW[eachflow]
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = _flow_params['pkt_sets']

        # Sending TCP SYN Packet from VM---> DPU ---> PL Endpoint
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])

        if _flow_params["fastpath_redirected_flow"]:
            # Before fastpath PLNSG Flow  VM ---> DPU ---- PLNSG ---- MUX ---- PLENDPOINT
            # After Fastpath PLNSG Flow  VM ---> DPU ---- PLENDPOINT
            # So for fastpath plnsg scenario update the exp_dpu_to_pe_pkt..
            # Remove outer PLNSG vxlan header on the exp_dpu_to_pe_pkt
            exp_dpu_to_pe_pkt = packets.exp_pkt_strip_plnsg_outer_encap(exp_dpu_to_pe_pkt, inner_packet_type='tcp')
            exp_dpu_to_pe_pkt.exp_pkt[Ether][IP].dst = _flow_params["fastpath_redirected_dip"]
            FASTPATH_FLOW[eachflow]['pkt_sets'] = (vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt)

        # Flow-1 send fastpath ICMPv6 redirect packet before SYNACK is send to DPU
        if _flow_params["fastpath_redirected_flow"] and \
           _flow_params["send_icmpv6_redirect_before_synack"]:
            dp_device, dp_port = testutils.port_to_tuple(dash_pl_config[REMOTE_PTF_SEND_INTF])
            ptfadapter.dataplane.send(dp_device, dp_port, _flow_params['fastpath_pkt'])

        # Sending TCP SYN+ACK Packet from PL ENDPOINT---> DPU ---> VM
        pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].ack = 47
        pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].flags = 'SA'
        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        verify_tunnel_packets(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], exp_dpu_to_vm_pkt, tunnel_endpoint_counts)

        # Flow-2 send fastpath ICMPv6 redirect packet before SYNACK is send to DPU
        if _flow_params["fastpath_redirected_flow"] and \
               not _flow_params["send_icmpv6_redirect_before_synack"]:
            dp_device, dp_port = testutils.port_to_tuple(dash_pl_config[REMOTE_PTF_SEND_INTF])
            ptfadapter.dataplane.send(dp_device, dp_port, _flow_params['fastpath_pkt'])

        # Sending TCP ACK Packet from VM---> DPU ---> PL Endpoint
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].ack = 27
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].seq = 47
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].flags = 'A'
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])

    # TCP Session closure
    for eachflow in FASTPATH_FLOW:
        _flow_params = FASTPATH_FLOW[eachflow]
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = _flow_params['pkt_sets']

        # Sending TCP FIN+ACK Packet from VM---> DPU ---> PL Endpoint
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].ack = 27
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].seq = 93
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].flags = 'FA'

        # Flow-2 send fastpath ICMPv6 redirect packet before SYNACK is send to DPU
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])

        # Sending TCP SYN+ACK Packet from PL ENDPOINT---> DPU ---> VM
        pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].ack = 140
        pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].seq = 27
        if _flow_params.get('send_tcp_rst_from_pl', False):
            pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].flags = 'R'
        else:
            pe_to_dpu_pkt[Ether][IP][GRE][Ether][IPv6][TCP].flags = 'FA'
        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        verify_tunnel_packets(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], exp_dpu_to_vm_pkt, tunnel_endpoint_counts)

        if _flow_params.get('send_tcp_rst_from_pl', False):
            # If PL endpoint send TCP RST for session closure
            # No need to send final ACK packet to close the session
            continue

        # Sending TCP ACK Packet from VM---> DPU ---> PL Endpoint
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].seq = 140
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].ack = 54
        vm_to_dpu_pkt[Ether][IP][UDP][VXLAN][Ether][IP][TCP].flags = 'A'
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
