import logging
import time
import ptf
import configs.privatelink_config as pl
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert
import pytest
from constants import LOCAL_PTF_INTF, LOCAL_DUT_INTF, REMOTE_DUT_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from gnmi_utils import apply_messages
from tests.dash.conftest import get_interface_ip
from packets import outbound_pl_packets, inbound_pl_packets, generate_plnsg_packets

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.skip_check_dut_health
]


"""
Test prerequisites:
- DPU needs the Appliance VIP configured as its loopback IP
- Assign IPs to DPU-NPU dataplane interfaces
- Default route on DPU to NPU
"""


@pytest.fixture(scope="module", autouse=True)
def add_npu_static_routes(duthost, dpu_ip, dash_pl_config, skip_config, skip_cleanup):
    if not skip_config:
        cmds = []
        vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1
        pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1
        cmds.append(f"ip route replace {pl.APPLIANCE_VIP}/32 via {dpu_ip}")
        cmds.append(f"ip route replace {pl.VM1_PA}/32 via {vm_nexthop_ip}")
        cmds.append(f"ip route replace {pl.PE_PA}/32 via {pe_nexthop_ip}")
        logger.info(f"Adding static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        cmds = []
        cmds.append(f"ip route del {pl.APPLIANCE_VIP}/32 via {dpu_ip}")
        cmds.append(f"ip route del {pl.VM1_PA}/32 via {vm_nexthop_ip}")
        cmds.append(f"ip route del {pl.PE_PA}/32 via {pe_nexthop_ip}")
        logger.info(f"Removing static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)


@pytest.fixture(autouse=True)
def common_setup_teardown(localhost, duthost, ptfhost, dpu_index, skip_config):
    if skip_config:
        return

    logger.info(pl.ROUTING_TYPE_PL_CONFIG)
    base_config_messages = {
        **pl.APPLIANCE_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.VNET_CONFIG,
        **pl.ENI_CONFIG,
        **pl.PE1_VNET_MAPPING_CONFIG,
        **pl.PE2_VNET_MAPPING_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG
    }
    logger.info(base_config_messages)

    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpu_index)


@pytest.mark.parametrize("encap_proto", ["vxlan", "gre"])
def test_privatelink_basic_transform(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    ptfadapter,
    dash_pl_config,
    encap_proto
):
    route_messages = {
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_CONFIG
    }
    apply_messages(localhost, duthost, ptfhost, route_messages, dpu_index)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpu_index)

    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config, outer_encap=encap_proto)
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config)

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
    testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt, dash_pl_config[LOCAL_PTF_INTF])


@pytest.mark.parametrize("encap_proto", ["vxlan", "gre"])
def test_pl_nsg(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    ptfadapter,
    dash_pl_config,
    encap_proto
):
    route_messages = {
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_CONFIG
    }
    apply_messages(localhost, duthost, ptfhost, route_messages, dpu_index)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpu_index)
    num_packets = 1000

    pkts = generate_plnsg_packets(dash_pl_config, inner_encap=encap_proto,
                                  outer_encap=encap_proto, num_packets=num_packets)

    timeout = 5
    ptfadapter.dataplane.flush()
    tunnel_endpoint_counts = {ip: 0 for ip in pl.TUNNEL1_ENDPOINT_IPS}
    for pkt_set in pkts:
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = pkt_set
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
        start_time = time.time()
        while True:
            if (time.time() - start_time) > timeout:
                break

            result = testutils.dp_poll(ptfadapter, timeout=timeout)
            if isinstance(result, ptfadapter.dataplane.PollSuccess):
                if result.port in dash_pl_config[REMOTE_PTF_RECV_INTF] and \
                   ptf.dataplane.match_exp_pkt(exp_dpu_to_pe_pkt, result.packet):
                    if result.packet["IP"].dst in tunnel_endpoint_counts:
                        tunnel_endpoint_counts[result.packet["IP"].dst] += 1
                    else:
                        pytest.fail(f"Unexpected destination IP: {result.pkt['IP'].dst}")
            else:
                pytest.fail(f"Expected packet not received:\n{result.format()}")

        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt, dash_pl_config[LOCAL_PTF_INTF])

    recvd_pkts = sum(tunnel_endpoint_counts.values())
    pytest_assert(
        recvd_pkts == num_packets,
        f"Expected {num_packets} packets, but received {recvd_pkts} packets. "
        f"Counts: {tunnel_endpoint_counts}"
    )
    expected_pkt_per_endpoint = num_packets // len(pl.TUNNEL1_ENDPOINT_IPS)
    pkt_count_low = expected_pkt_per_endpoint * 0.75
    pkt_count_high = expected_pkt_per_endpoint * 1.25
    for ip, count in tunnel_endpoint_counts.items():
        pytest_assert(
            pkt_count_low <= count <= pkt_count_high,
            f"Packet count for {ip} is out of expected range: {count}"
        )
