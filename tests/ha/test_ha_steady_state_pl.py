import logging

import ptf.testutils as testutils
import pytest
from configs.privatelink_config import APPLIANCE_VIP
from tests.common.helpers.assertions import pytest_assert
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from packets import outbound_pl_packets, inbound_pl_packets
from tests.ha.conftest import apply_dash_pl_pipeline_config
from ha_bgp_utils import check_vip_advertised_to_t2
from ha_dash_flow_utils import compare_flow_tables
from ha_utils import parallel_config_reload_dpuhosts

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]

"""
Test prerequisites:
- Assign IPs to DPU-NPU dataplane interfaces
"""


@pytest.fixture(autouse=True, scope="module")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    setup_ha_config,
    ha_owner,
    setup_gnmi_server,
    set_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    if skip_config:
        return

    apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost)

    yield
    parallel_config_reload_dpuhosts(dpuhosts)


@pytest.mark.parametrize("encap_proto", ["vxlan", "gre"])
def test_privatelink_basic_transform(
    ptfadapter,
    duthosts,
    dpuhosts,
    nbrhosts,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config,
    encap_proto
):
    # traffic to active
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[0], encap_proto)
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config[0])

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[0][REMOTE_PTF_RECV_INTF])
    flow_op = compare_flow_tables(dpuhosts[0], dpuhosts[1], verbose=True, flow_state=True)
    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")
    testutils.send(ptfadapter, dash_pl_config[0][REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
    testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt, dash_pl_config[0][LOCAL_PTF_INTF])

    # traffic to standby
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config[1], encap_proto)
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config[1])

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[1][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[0][REMOTE_PTF_RECV_INTF])
    flow_op = compare_flow_tables(dpuhosts[0], dpuhosts[1], verbose=True, flow_state=True)
    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")
    testutils.send(ptfadapter, dash_pl_config[1][REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
    testutils.verify_packet(ptfadapter, exp_dpu_to_vm_pkt, dash_pl_config[0][LOCAL_PTF_INTF])

    check_vip_advertised_to_t2(duthosts, APPLIANCE_VIP)
