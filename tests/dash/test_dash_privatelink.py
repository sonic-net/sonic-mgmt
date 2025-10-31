import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import random
import ptf.packet as scapy
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from constants import VXLAN_UDP_BASE_SRC_PORT, VXLAN_UDP_SRC_PORT_MASK
from gnmi_utils import apply_messages
from packets import outbound_pl_packets, inbound_pl_packets
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('smartswitch'),
    pytest.mark.skip_check_dut_health
]


"""
Test prerequisites:
- Assign IPs to DPU-NPU dataplane interfaces
"""


@pytest.fixture(autouse=True, scope="function")
def common_setup_teardown(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    set_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    if skip_config:
        return
    dpuhost = dpuhosts[dpu_index]
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)
    base_config_messages = {
        **pl.APPLIANCE_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.VNET_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG
    }
    logger.info(base_config_messages)

    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

    route_and_mapping_messages = {
        **pl.PE_VNET_MAPPING_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_CONFIG
    }
    logger.info(route_and_mapping_messages)
    apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

    meter_rule_messages = {
        **pl.METER_RULE1_V4_CONFIG,
        **pl.METER_RULE2_V4_CONFIG,
    }
    logger.info(meter_rule_messages)
    apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index)

    logger.info(pl.ENI_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index)

    logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield

    config_reload(dpuhost, safe_reload=True, yang_validate=False)
    # apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index, False)
    # apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index, False)


@pytest.mark.parametrize("encap_proto", ["vxlan", "gre"])
def test_privatelink_basic_transform(
    ptfadapter,
    dash_pl_config,
    encap_proto
):
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config, encap_proto)
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config)

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
    testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt, dash_pl_config[LOCAL_PTF_INTF])


def test_privatelink_udp_sport_range_negative(
    ptfadapter,
    dash_pl_config
):
    """
    Validate that when the VXLAN UDP source port is not in the configured
    range, the packet is dropped by the DPU.
    """
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config, "vxlan")
    min_valid_sport = VXLAN_UDP_BASE_SRC_PORT
    max_valid_sport = VXLAN_UDP_BASE_SRC_PORT + 2**VXLAN_UDP_SRC_PORT_MASK - 1
    invalid_sport_list = [1,
                          random.randint(2, min_valid_sport - 2),
                          min_valid_sport - 1,
                          max_valid_sport + 1,
                          random.randint(max_valid_sport + 2, 65534),
                          65535]
    logger.info(f"Send the vxlan encaped outbound packets with invalid sport: \
        {invalid_sport_list}")
    logger.info("Check the packets are all dropped.")
    for invalid_sport in invalid_sport_list:
        vm_to_dpu_pkt[scapy.UDP].sport = invalid_sport
        ptfadapter.dataplane.flush()
        logger.info(f"Sending packet with sport: {invalid_sport}")
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_no_packet_any(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
