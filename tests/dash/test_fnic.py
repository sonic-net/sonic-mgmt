import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from gnmi_utils import apply_messages
from packets import rand_udp_port_packets
from tests.common.helpers.assertions import pytest_assert
from configs.privatelink_config import TUNNEL1_ENDPOINT_IPS, TUNNEL2_ENDPOINT_IPS
from tests.common import config_reload
from tests.dash.dash_utils import verify_tunnel_packets

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t1"),
    pytest.mark.topology("smartswitch"),
    pytest.mark.skip_check_dut_health
]


"""
Test prerequisites:
- Assign IPs to DPU-NPU dataplane interfaces

Note: It's also necessary for the DPU to learn the neighbor info of the dataplane port to the NPU before any
DASH configs are programmed. This should be handled automatically by fixture ordering and does not require
manual steps.

The neighbor info is learned when appling the default route as orchagent will attempt to resolve the next hop IP.
"""


@pytest.fixture(autouse=True)
def common_setup_teardown(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    set_vxlan_udp_sport_range,
    # manually invoke setup_npu_dpu to ensure routes are added before DASH configs are programmed
    setup_npu_dpu,  # noqa: F811
    single_endpoint
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

    # Route rule removal is broken so config reload to cleanup for now
    # https://github.com/sonic-net/sonic-buildimage/issues/23590
    config_reload(dpuhost, safe_reload=True, yang_validate=False)
    # apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, pl.ENI_TRUSTED_VNI_CONFIG, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index, False)


def test_fnic(ptfadapter, dash_pl_config, single_endpoint):
    pkt_sets = list()

    if single_endpoint:
        num_packets = 5
    else:
        # need a lot of packets to check ECMP distribution
        num_packets = 1000

    for _ in range(num_packets):
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = rand_udp_port_packets(
            dash_pl_config, floating_nic=True, outbound_vni=pl.ENI_TRUSTED_VNI
        )
        # Usually `testutils.send` automatically updates the packet payload to include the test nome
        # and `testutils.verify_packet*` updates the expected packet payload to match. Since we are polling
        # the dataplane directly for the DPU to VM packet, we need to manually update the payload
        exp_dpu_to_vm_pkt = ptfadapter.update_payload(exp_dpu_to_vm_pkt)
        pkt_sets.append((vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt))

    if single_endpoint:
        tunnel_endpoint_counts = {ip: 0 for ip in TUNNEL1_ENDPOINT_IPS}
    else:
        tunnel_endpoint_counts = {ip: 0 for ip in TUNNEL2_ENDPOINT_IPS}

    ptfadapter.dataplane.flush()
    for vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt in pkt_sets:
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        verify_tunnel_packets(
            ptfadapter,
            dash_pl_config[LOCAL_PTF_INTF],
            exp_dpu_to_vm_pkt,
            tunnel_endpoint_counts
        )

    recvd_pkts = sum(tunnel_endpoint_counts.values())
    logger.info(f"Received packets: {recvd_pkts}, Tunnel endpoint counts: {tunnel_endpoint_counts}")
    pytest_assert(
        recvd_pkts == num_packets,
        f"Expected {num_packets} packets, but received {recvd_pkts} packets. " f"Counts: {tunnel_endpoint_counts}",
    )

    expected_pkt_per_endpoint = num_packets // len(tunnel_endpoint_counts)
    pkt_count_low = expected_pkt_per_endpoint * 0.75
    pkt_count_high = expected_pkt_per_endpoint * 1.25
    for ip, count in tunnel_endpoint_counts.items():
        pytest_assert(
            pkt_count_low <= count <= pkt_count_high, f"Packet count for {ip} is out of expected range: {count}"
        )
