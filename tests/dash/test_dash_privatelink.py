import logging

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
from constants import LOCAL_PTF_INTF, LOCAL_DUT_INTF, REMOTE_DUT_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from gnmi_utils import apply_messages
from packets import outbound_pl_packets, inbound_pl_packets
from tests.dash.conftest import get_interface_ip

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1', 'smartswitch'),
    pytest.mark.skip_check_dut_health
]


"""
Test prerequisites:
- DPU needs the Appliance VIP configured as its loopback IP
- Assign IPs to DPU-NPU dataplane interfaces
- Default route on DPU to NPU
"""


@pytest.fixture(scope="module", autouse=True)
def add_npu_static_routes(duthost, dash_pl_config, skip_config, skip_cleanup, dpu_index, dpuhosts):
    dpuhost = dpuhosts[dpu_index]
    if not skip_config:
        cmds = []
        vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1
        pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1

        cmds.append(f"ip route replace {pl.APPLIANCE_VIP}/32 via {dpuhost.dpu_data_port_ip}")
        cmds.append(f"ip route replace {pl.VM1_PA}/32 via {vm_nexthop_ip}")
        cmds.append(f"ip route replace {pl.PE_PA}/32 via {pe_nexthop_ip}")
        logger.info(f"Adding static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        cmds = []
        cmds.append(f"ip route del {pl.APPLIANCE_VIP}/32 via {dpuhost.dpu_data_port_ip}")
        cmds.append(f"ip route del {pl.VM1_PA}/32 via {vm_nexthop_ip}")
        cmds.append(f"ip route del {pl.PE_PA}/32 via {pe_nexthop_ip}")
        logger.info(f"Removing static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="module")
def common_setup_teardown(localhost, duthost, ptfhost, dpu_index, skip_config, dpuhosts,
                          set_vxlan_udp_sport_range):
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
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index, False)


@pytest.fixture(scope="module")
def common_setup_teardown_fnic(localhost, duthost, ptfhost, dpu_index, skip_config, dpuhosts,
                               set_vxlan_udp_sport_range):
    if skip_config:
        return
    dpuhost = dpuhosts[dpu_index]
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)
    base_config_messages_fnic = {
        **pl.APPLIANCE_CONFIG_FNIC,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.ROUTING_TYPE_VNET_CONFIG,
        **pl.VNET_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG
    }

    logger.info(base_config_messages_fnic)
    apply_messages(localhost, duthost, ptfhost, base_config_messages_fnic, dpuhost.dpu_index)

    route_and_mapping_messages = {
        **pl.PE_VNET_MAPPING_CONFIG_FNIC,
        **pl.VM1_VNET_MAPPING_CONFIG_FNIC,
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

    logger.info(pl.ENI_CONFIG_FNIC)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG_FNIC, dpuhost.dpu_index)

    logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG_FNIC, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, base_config_messages_fnic, dpuhost.dpu_index, False)


@pytest.mark.parametrize("encap_proto", ["vxlan", "gre"])
def test_privatelink_basic_transform(
    ptfadapter,
    dash_pl_config,
    encap_proto,
    common_setup_teardown
):
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config, encap_proto)
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config)

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
    testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt, dash_pl_config[LOCAL_PTF_INTF])


@pytest.mark.parametrize("encap_proto", ["vxlan", "gre"])
def test_privatelink_fnic_basic_transform(
    ptfadapter,
    dash_pl_config,
    encap_proto,
    common_setup_teardown_fnic
):
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config, encap_proto, True)
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config, True)

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])

    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
    testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt, dash_pl_config[LOCAL_PTF_INTF])
