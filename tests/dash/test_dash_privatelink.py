import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
import random
import ptf.packet as scapy
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from constants import VXLAN_UDP_BASE_SRC_PORT, VXLAN_UDP_SRC_PORT_MASK
from packets import outbound_pl_packets, inbound_pl_packets
from tests.common.config_reload import config_reload
from tests.common.dash_utils import apply_dash_configs

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

    # ``INBOUND_VNI_ROUTE_RULE_CONFIG`` is only programmed on Bluefield DPUs;
    # on other platforms ROUTE_RULE entries are skipped at the source.
    bluefield_route_rule_configs = []
    if 'bluefield' in dpuhost.facts['asic_type']:
        bluefield_route_rule_configs = [pl.INBOUND_VNI_ROUTE_RULE_CONFIG]

    # ``apply_dash_configs`` buckets entries by DASH table name and applies
    # them in dependency order (see ``DashPhase`` in ``tests/common/dash_utils.py``):
    # GROUP_1 (APPLIANCE) -> GROUP_2 (ROUTING_TYPE/METER_POLICY/OUTBOUND_PORT_MAP/VNET) ->
    # GROUP_3 (METER_RULE) -> GROUP_4 (TUNNEL/OUTBOUND_PORT_MAP_RANGE/ENI/ROUTE_GROUP) ->
    # GROUP_5 (ROUTE_RULE/ROUTE/VNET_MAPPING) -> GROUP_6 (ENI_ROUTE).
    apply_dash_configs(
        localhost, duthost, ptfhost, dpuhost.dpu_index,
        pl.APPLIANCE_CONFIG,
        pl.ROUTING_TYPE_PL_CONFIG,
        pl.VNET_CONFIG,
        pl.ROUTE_GROUP1_CONFIG,
        pl.METER_POLICY_V4_CONFIG,
        pl.PE_VNET_MAPPING_CONFIG,
        pl.PE_SUBNET_ROUTE_CONFIG,
        pl.VM_SUBNET_ROUTE_CONFIG,
        *bluefield_route_rule_configs,
        pl.METER_RULE1_V4_CONFIG,
        pl.METER_RULE2_V4_CONFIG,
        pl.ENI_CONFIG,
        pl.ENI_ROUTE_GROUP1_CONFIG,
    )

    yield

    config_reload(dpuhost, safe_reload=True, yang_validate=False)


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


@pytest.mark.parametrize("vxlan_security", ["true", "false"])
def test_privatelink_udp_sport_range_negative(
    ptfadapter,
    dash_pl_config,
    vxlan_security,
    request
):
    """
    Validate that when the VXLAN UDP source port is not in the configured
    range, the packet is dropped by the DPU when vxlan_security is true.
    When vxlan_security is false, the packet is not dropped.
    """
    # vxlan_security is enabled by default, disable it when vxlan_security is false
    if vxlan_security == "false":
        request.getfixturevalue("disable_vxlan_security")

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

    logger.info(f"Validate the traffic when vxlan_security is {vxlan_security}.")
    for invalid_sport in invalid_sport_list:
        vm_to_dpu_pkt[scapy.UDP].sport = invalid_sport
        ptfadapter.dataplane.flush()
        logger.info(f"Sending packet with sport: {invalid_sport}")
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        if vxlan_security == "true":
            logger.info("Check the packet is dropped.")
            testutils.verify_no_packet_any(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
        else:
            logger.info("Check the packet is not dropped.")
            testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
