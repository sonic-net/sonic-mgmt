import logging
import random
import concurrent.futures

import configs.privatelink_config as pl
import ptf.packet as scapy
import ptf.testutils as testutils
import pytest
from tests.common.helpers.assertions import pytest_assert
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from gnmi_utils import apply_messages
from packets import inbound_pl_packets, outbound_pl_packets
from tests.common.config_reload import config_reload
from tests.common.dash_utils import verify_tunnel_packets
from ha_dash_flow_utils import compare_flow_tables_pdsctl

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]


NUM_PACKETS = 5


def reload_config_for_host(dpuhost):
    logger.info(f"config reload on {dpuhost.hostname}")
    config_reload(dpuhost, safe_reload=True, yang_validate=False)


def _build_fnic_pkt_set(config, encap_proto, ptfadapter):
    """Build a list of NUM_PACKETS bidirectional fnic packet tuples for a given DPU config."""
    pkt_sets = []
    for _ in range(NUM_PACKETS):
        sport = random.randint(49152, 65535)
        dport = random.randint(49152, 65535)
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(
            config, encap_proto, floating_nic=True,
            inner_sport=sport, inner_dport=dport, vni=pl.ENI_TRUSTED_VNI
        )
        pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(
            config, floating_nic=True, inner_sport=dport, inner_dport=sport
        )
        exp_dpu_to_vm_pkt.set_do_not_care_packet(scapy.IP, "dst")
        exp_dpu_to_vm_pkt = ptfadapter.update_payload(exp_dpu_to_vm_pkt)
        pkt_sets.append((vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt))
    return pkt_sets


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

    for i in range(len(duthosts)):
        duthost = duthosts[i]
        dpuhost = dpuhosts[i]
        base_config_messages = {
            **pl.APPLIANCE_FNIC_CONFIG,
            **pl.ROUTING_TYPE_PL_CONFIG,
            **pl.ROUTING_TYPE_VNET_CONFIG,
            **pl.VNET_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.METER_POLICY_V4_CONFIG,
            **pl.TUNNEL1_CONFIG,
        }
        logger.info(f"configure on {duthost.hostname} dpu {dpuhost.dpu_index} {base_config_messages}")
        apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

        route_and_mapping_messages = {
            **pl.PE_VNET_MAPPING_CONFIG,
            **pl.PE_SUBNET_ROUTE_CONFIG,
            **pl.VM_VNET_MAPPING_CONFIG,
            **pl.VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT,
        }
        logger.info(route_and_mapping_messages)
        apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

        if 'pensando' not in dpuhost.facts['asic_type']:
            route_rule_messages = {
                **pl.VM_VNI_ROUTE_RULE_CONFIG,
                **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
                **pl.TRUSTED_VNI_ROUTE_RULE_CONFIG,
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
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
        executor.map(reload_config_for_host, dpuhosts)


@pytest.mark.parametrize("encap_proto", ["vxlan", "gre"])
def test_fnic_basic_transform(
    ptfadapter,
    duthosts,
    dpuhosts,
    activate_dash_ha_from_json,
    ha_owner,
    dash_pl_config,
    get_t2_info,
    encap_proto
):
    active_t2_ports = get_t2_info[duthosts[0].hostname]

    # traffic to active DPU
    pkt_sets = _build_fnic_pkt_set(dash_pl_config[0], encap_proto, ptfadapter)
    tunnel_endpoint_counts = {ip: 0 for ip in pl.TUNNEL1_ENDPOINT_IPS}
    ptfadapter.dataplane.flush()
    for vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt in pkt_sets:
        testutils.send(ptfadapter, dash_pl_config[0][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[0][REMOTE_PTF_RECV_INTF])
        testutils.send(ptfadapter, dash_pl_config[0][REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        verify_tunnel_packets(
            ptfadapter,
            active_t2_ports,
            exp_dpu_to_vm_pkt,
            tunnel_endpoint_counts,
        )

    pytest_assert(sum(tunnel_endpoint_counts.values()) == NUM_PACKETS, "Expected active return-path packets")

    flow_op = compare_flow_tables_pdsctl(dpuhosts[0], dpuhosts[1])
    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")

    # traffic to standby DPU (forwarded through active for processing)
    pkt_sets = _build_fnic_pkt_set(dash_pl_config[1], encap_proto, ptfadapter)
    tunnel_endpoint_counts = {ip: 0 for ip in pl.TUNNEL1_ENDPOINT_IPS}
    ptfadapter.dataplane.flush()
    for vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt in pkt_sets:
        testutils.send(ptfadapter, dash_pl_config[1][LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[0][REMOTE_PTF_RECV_INTF])
        testutils.send(ptfadapter, dash_pl_config[1][REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        verify_tunnel_packets(
            ptfadapter,
            active_t2_ports,
            exp_dpu_to_vm_pkt,
            tunnel_endpoint_counts,
        )

    pytest_assert(sum(tunnel_endpoint_counts.values()) == NUM_PACKETS, "Expected standby return-path packets")

    flow_op = compare_flow_tables_pdsctl(dpuhosts[0], dpuhosts[1])
    pytest_assert(flow_op, "Expected identical flow tables on primary and standby")
