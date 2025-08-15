import logging
import time

import ptf.packet as scapy
import configs.privatelink_config as pl
import ptf.testutils as testutils
import ptf
import pytest
from constants import LOCAL_PTF_INTF, LOCAL_DUT_INTF, REMOTE_DUT_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from gnmi_utils import apply_messages
from packets import rand_udp_port_packets
from tests.common.helpers.assertions import pytest_assert
from tests.dash.conftest import get_interface_ip
from tests.common.helpers.smartswitch_util import get_dpu_dataplane_port
from configs.privatelink_config import TUNNEL1_ENDPOINT_IPS, TUNNEL2_ENDPOINT_IPS
from tests.common import config_reload

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("t1"), pytest.mark.skip_check_dut_health]


"""
Test prerequisites:
- Assign IPs to DPU-NPU dataplane interfaces
"""


@pytest.fixture(scope="module")
def floating_nic(duthost):
    return True


@pytest.fixture(scope="function", autouse=True)
def dpu_setup(duthost, dpuhosts, dpu_index, skip_config):
    if skip_config:

        return
    dpuhost = dpuhosts[dpu_index]
    intfs = dpuhost.shell("show ip int")["stdout"]
    dpu_cmds = list()
    if "Loopback0" not in intfs:
        dpu_cmds.append("config loopback add Loopback0")
        dpu_cmds.append(f"config int ip add Loopback0 {pl.APPLIANCE_VIP}/32")

    npu_data_port = get_dpu_dataplane_port(duthost, dpu_index)
    npu_data_ip = get_interface_ip(duthost, npu_data_port)

    dpu_cmds.append(
        'who am i | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | xargs -I{} sudo ip route replace {}/32 via 169.254.200.254'  # noqa W605
    )
    dpu_cmds.append(f"ip route replace default via {npu_data_ip.ip}")
    dpuhost.shell_cmds(cmds=dpu_cmds)


@pytest.fixture(scope="function", autouse=True)
def add_npu_static_routes(
    duthost, dash_pl_config, skip_config, skip_cleanup, dpu_index, dpuhosts, dpu_setup, single_endpoint
):
    dpuhost = dpuhosts[dpu_index]
    if not skip_config:
        cmds = []
        vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1
        pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1

        # cmds.append(f"ip route replace {pl.APPLIANCE_VIP}/32 via {dpuhost.dpu_data_port_ip}")
        cmds.append(f"config route add prefix {pl.APPLIANCE_VIP}/32 nexthop {dpuhost.dpu_data_port_ip}")
        cmds.append(f"ip route replace {pl.VM1_PA}/32 via {vm_nexthop_ip}")

        if single_endpoint:
            tunnel_endpoints = TUNNEL1_ENDPOINT_IPS
        else:
            tunnel_endpoints = TUNNEL2_ENDPOINT_IPS
        for tunnel_ip in tunnel_endpoints:
            cmds.append(f"ip route replace {tunnel_ip}/32 via {vm_nexthop_ip}")
        cmds.append(f"ip route replace {pl.PE_PA}/32 via {pe_nexthop_ip}")
        logger.info(f"Adding static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        cmds = []
        cmds.append(f"ip route del {pl.APPLIANCE_VIP}/32 via {dpuhost.dpu_data_port_ip}")
        cmds.append(f"ip route del {pl.VM1_PA}/32 via {vm_nexthop_ip}")
        for tunnel_ip in tunnel_endpoints:
            cmds.append(f"ip route replace {tunnel_ip}/32 via {vm_nexthop_ip}")
        cmds.append(f"ip route del {pl.PE_PA}/32 via {pe_nexthop_ip}")
        logger.info(f"Removing static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="module", params=[True, False], ids=["single-endpoint", "multi-endpoint"])
def single_endpoint(request):
    return request.param


@pytest.fixture(autouse=True, scope="function")
def common_setup_teardown(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    set_vxlan_udp_sport_range,
    add_npu_static_routes,  # manually invoke to ensure routes are added before DASH configs are programmed
    single_endpoint,
):
    if skip_config:
        yield
        return
    dpuhost = dpuhosts[dpu_index]
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)

    if single_endpoint:
        tunnel_config = pl.TUNNEL1_CONFIG
    else:
        tunnel_config = pl.TUNNEL2_CONFIG

    base_config_messages = {
        **pl.APPLIANCE_FNIC_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.ROUTING_TYPE_VNET_CONFIG,
        **pl.VNET_CONFIG,
        **pl.VNET2_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG,
        **tunnel_config,
    }
    logger.info(base_config_messages)

    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

    if single_endpoint:
        vm_subnet_route_config = pl.VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT
    else:
        vm_subnet_route_config = pl.VM_SUBNET_ROUTE_WITH_TUNNEL_MULTI_ENDPOINT
    route_and_mapping_messages = {
        **pl.PE_VNET_MAPPING_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **vm_subnet_route_config,
        **pl.INBOUND_VM_ROUTE_RULE_CONFIG,
        **pl.ROUTE_RULE1_CONFIG,
    }
    logger.info(route_and_mapping_messages)
    apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

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

    # DASH object deletion not fully supported on all platforms so cleanup via config reload for now.
    config_reload(dpuhost, safe_reload=True, yang_validate=False)
    # apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, pl.ENI_TRUSTED_VNI_CONFIG, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index, False)


def verify_tunnel_packets(ptfadapter, dash_pl_config, exp_dpu_to_vm_pkt, tunnel_endpoint_counts):
    start_time = time.time()
    timeout = 1
    while True:
        if (time.time() - start_time) > timeout:
            break

        result = testutils.dp_poll(ptfadapter, port_number=dash_pl_config[LOCAL_PTF_INTF], timeout=timeout)
        if isinstance(result, ptfadapter.dataplane.PollSuccess):
            pkt_repr = scapy.Ether(result.packet)
            if "IP" not in pkt_repr:
                logging.error(f"Packet missing IP layer: {pkt_repr}")
                continue

            if pkt_repr["IP"].dst in tunnel_endpoint_counts:
                if ptf.dataplane.match_exp_pkt(exp_dpu_to_vm_pkt, result.packet):
                    tunnel_endpoint_counts[pkt_repr["IP"].dst] += 1
                    logging.info(
                        f"Packet sent to tunnel endpoint {pkt_repr['IP'].dst} matches:\
                            \n{result.format()} \nExpected:\n{exp_dpu_to_vm_pkt}"
                    )
                    return
                else:
                    logging.error(
                        f"Packet sent to tunnel endpoint {pkt_repr['IP'].dst} does not match expected pkt\
                          \n{result.format()} \nExpected:\n{exp_dpu_to_vm_pkt}"
                    )
            else:
                logging.info(f"Unexpected destination IP, not a relevant packet: {pkt_repr['IP'].dst}, continue")
        else:
            logging.error(f"DP poll failed:\n{result.format()}")

    pytest.fail(f"Failed to match expected packet {exp_dpu_to_vm_pkt}")


def test_fnic(ptfadapter, dash_pl_config, floating_nic, single_endpoint):
    pkt_sets = list()

    if single_endpoint:
        num_packets = 5
    else:
        # need a lot of packets to check ECMP distribution
        num_packets = 1000

    for _ in range(num_packets):
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = rand_udp_port_packets(
            dash_pl_config, floating_nic
        )
        exp_dpu_to_vm_pkt = ptfadapter.update_payload(exp_dpu_to_vm_pkt)
        pkt_sets.append((vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt))
    # vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config, "vxlan", floating_nic)
    # pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config, floating_nic)

    if single_endpoint:
        tunnel_endpoint_counts = {ip: 0 for ip in TUNNEL1_ENDPOINT_IPS}
    else:
        tunnel_endpoint_counts = {ip: 0 for ip in TUNNEL2_ENDPOINT_IPS}

    ptfadapter.dataplane.flush()
    for vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt in pkt_sets:
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)

        verify_tunnel_packets(ptfadapter, dash_pl_config, exp_dpu_to_vm_pkt, tunnel_endpoint_counts)

    recvd_pkts = sum(tunnel_endpoint_counts.values())
    logger.info(f"Received packets: {recvd_pkts}, Tunnel endpoint counts: {tunnel_endpoint_counts}")
    pytest_assert(
        recvd_pkts == num_packets,
        f"Expected {num_packets} packets, but received {recvd_pkts} packets. " f"Counts: {tunnel_endpoint_counts}",
    )
    # TODO: Currently the packet goes back to the same tunnel endpoint for a unique 5-tuple,
    # overlay src/dst IP, overlay udp src/dst port,
    # so this check wouldn't hold true for nvidia-bluefield platform
    # Either send a different flavor or packet

    expected_pkt_per_endpoint = num_packets // len(tunnel_endpoint_counts)
    pkt_count_low = expected_pkt_per_endpoint * 0.75
    pkt_count_high = expected_pkt_per_endpoint * 1.25
    for ip, count in tunnel_endpoint_counts.items():
        pytest_assert(
            pkt_count_low <= count <= pkt_count_high, f"Packet count for {ip} is out of expected range: {count}"
        )
