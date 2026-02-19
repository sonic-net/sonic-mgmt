import logging
import time

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
from dash_eni_counter_utils import get_eni_counter_oid, get_eni_meter_counters

logger = logging.getLogger(__name__)

pytestmark = [
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
        **pl.METER_POLICY_V4_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.ROUTE_GROUP2_CONFIG,
        **pl.ROUTE_GROUP3_CONFIG,
        **tunnel_config,
    }
    logger.info(base_config_messages)

    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

    if single_endpoint:
        rg1_vm_subnet_route_config = pl.VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT
        rg2_vm_subnet_route_config = pl.RG2_VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT
        rg3_vm_subnet_route_config = pl.RG3_VM_SUBNET_ROUTE_WITH_TUNNEL_SINGLE_ENDPOINT
    else:
        rg1_vm_subnet_route_config = pl.VM_SUBNET_ROUTE_WITH_TUNNEL_MULTI_ENDPOINT
        rg2_vm_subnet_route_config = pl.RG2_VM_SUBNET_ROUTE_WITH_TUNNEL_MULTI_ENDPOINT
        rg3_vm_subnet_route_config = pl.RG3_VM_SUBNET_ROUTE_WITH_TUNNEL_MULTI_ENDPOINT

    # Route-Group1 rule creation
    route_messages = {
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **rg1_vm_subnet_route_config
    }
    logger.info(route_messages)
    apply_messages(localhost, duthost, ptfhost, route_messages, dpuhost.dpu_index)

    # Route-Group2 rule creation
    route_messages = {
        **pl.METERCLASSOR_PE_SUBNET_ROUTE_CONFIG,
        **rg2_vm_subnet_route_config,
    }
    logger.info(route_messages)
    apply_messages(localhost, duthost, ptfhost, route_messages, dpuhost.dpu_index)

    # Route-Group3 rule creation
    route_messages = {
        **pl.METERCLASSAND_PE_SUBNET_ROUTE_CONFIG,
        **rg3_vm_subnet_route_config,
    }
    logger.info(route_messages)
    apply_messages(localhost, duthost, ptfhost, route_messages, dpuhost.dpu_index)

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


@pytest.mark.parametrize("metering_tc", ['ENI_METERPOLICY_HIT', 'MAPPING_METERCLASS_HIT',
                                         'ROUTE_METERCLASS_OR_HIT', 'ROUTE_MAPPING_METERCLASS_OR_HIT',
                                         'ROUTE_METERCLASS_AND_HIT', 'ROUTE_MAPPING_METERCLASS_ANDOR_HIT'])
def test_fnic_dash_metering(localhost, duthost, ptfhost, ptfadapter, dash_pl_config,
                            dpuhosts, dpu_index, metering_tc, single_endpoint):
    """
    Testcases:
    ENI_METERPOLICY_HIT:
       [Test: ENI MeterPolicy]
       Associate Meter policy on ENI and verify meter-rule specific meterclass
       stats 520 is getting incremented

    MAPPING_METERCLASS_HIT:
       [Test: Mapping Meter_class_or]
       Associate meterclass_or(1038) to Mapping entries and verify mapping
       meterclass(1038) stats is getting incremented.
             Mapping meterclass_or   : 1038
             Default meterclass_and  : 0xfff (default value)
             Final derived meterclass: 1038 && 0xfff = 1038

    ROUTE_METERCLASS_OR_HIT:
       [Test: Route meter_class_or]
       Associate meterclass_or(2566) to Route entries and verify
       meterclass(2566) stats is getting incremented.
             Route entry meterclass_or : 2566
             Default meterclass_and    : 0xfff (default value)
             Final derived meterclass  : 2566 && 0xfff = 2566

    ROUTE_MAPPING_METERCLASS_OR_HIT:
       [Test: Route meter_class_or, Mapping Meter_class_or]
       Associate Meterclass_or(2566) to Route entries and associate
       meterclass_or(1038) to mapping entries.Verify meterclass(3598) stats
       is getting incremented.
             Route entry meterclass_or   : 2566
             Mapping entry meterclass_or : 1038
             Aggegate meterclass_or      : 2566 || 1038 = 3598
             Default meterclass_and      : 0xfff (default value)
             Final derived meterclass    : 3598 && 0xfff = 3598

    ROUTE_METERCLASS_AND_HIT:
       [Test: Route meter_class_or, Route meter_class_and]
       Associate meterclass_and(2566) meterclass_and(0xff0) to Route entries
       and verify meterclass stats(2560) is getting incremented.
             Route entry meterclass_or : 2566
             Configured meterclass_and : 0xff0
             Final derived meterclass  : 2566 && 0xff0 = 2560

    ROUTE_MAPPING_METERCLASS_ANDOR_HIT:
       [Test: Route meter_class_or, Mapping Meter_class_or, Route meter_class_and]
       Associate meterclass_or(2566) meterclass_and(0xff0) to Route entries.
       Associate meterclass_or(1038) to mapping entries and verify meterclass(3584) stats
       is getting incremented.
             Route entry meterclass_or   : 2566
             Mapping entry meterclass_or : 1038
             Aggegate meterclass_or      : 2566 || 1038 = 3598
             Configured meterclass_and   : 0xff0
             Final derived meterclass    : 3598 && 0xff0 = 3584
    """
    dpuhost = dpuhosts[dpu_index]
    pkt_sets = list()

    if single_endpoint:
        num_packets = 5
    else:
        # need a lot of packets to check ECMP distribution
        num_packets = 1000

    # For PL Rx packets, in case of PT (6to4), adjust packet length field used
    # for metering and vnic stats such that the translation is also taken into consideration.
    # Default PL rx inner packet length is 100 bytes.
    # Expected Meter Rx Bytes = 100 - 20(IPv6 headerlen 40 bytes - IPv4 header len 20 bytes)
    # so expected Rx packet meter is 80 bytes.
    exp_rx_bytes = num_packets * 80

    # Default Tx inner packet length is 100 bytes
    exp_tx_bytes = num_packets * 100

    # Associate Route-Group2 with ENI
    if metering_tc == 'ROUTE_METERCLASS_OR_HIT' or metering_tc == 'ROUTE_MAPPING_METERCLASS_OR_HIT':
        route_messages = {
            **pl.ENI_ROUTE_GROUP2_CONFIG
        }
        logger.info(route_messages)
        apply_messages(localhost, duthost, ptfhost, route_messages, dpuhost.dpu_index)

    # Associate Route-Group3 with ENI
    if metering_tc == 'ROUTE_METERCLASS_AND_HIT' or metering_tc == 'ROUTE_MAPPING_METERCLASS_ANDOR_HIT':
        route_messages = {
            **pl.ENI_ROUTE_GROUP3_CONFIG
        }
        logger.info(route_messages)
        apply_messages(localhost, duthost, ptfhost, route_messages, dpuhost.dpu_index)

    if metering_tc == 'ENI_METERPOLICY_HIT':
        exp_meterclass = pl.ENI_METERPOLICY_CLASS
    elif metering_tc == 'MAPPING_METERCLASS_HIT':
        exp_meterclass = pl.MAPPING_METERCLASS_OR
    elif metering_tc == 'ROUTE_METERCLASS_OR_HIT':
        exp_meterclass = pl.ROUTE_METERCLASS_OR
    elif metering_tc == 'ROUTE_METERCLASS_AND_HIT':
        exp_meterclass = pl.METERCLASSAND_RESULT
    elif metering_tc == 'ROUTE_MAPPING_METERCLASS_OR_HIT':
        exp_meterclass = pl.METERCLASSOR_RESULT
    elif metering_tc == 'ROUTE_MAPPING_METERCLASS_ANDOR_HIT':
        exp_meterclass = pl.METERCLASSANDOR_RESULT

    # Configure MAPPING entries
    if metering_tc in ['MAPPING_METERCLASS_HIT', 'ROUTE_MAPPING_METERCLASS_OR_HIT',
                       'ROUTE_MAPPING_METERCLASS_ANDOR_HIT']:
        pl.PE_VNET_MAPPING_CONFIG[f"DASH_VNET_MAPPING_TABLE:{pl.VNET1}:{pl.PE_CA}"]["metering_class_or"] = \
                          pl.MAPPING_METERCLASS_OR
    elif metering_tc in ['ROUTE_METERCLASS_AND_HIT', 'ROUTE_METERCLASS_OR_HIT', 'ENI_METERPOLICY_HIT']:
        # Remove meter_class_or fields
        if 'metering_class_or' in pl.PE_VNET_MAPPING_CONFIG[f"DASH_VNET_MAPPING_TABLE:{pl.VNET1}:{pl.PE_CA}"]:
            del pl.PE_VNET_MAPPING_CONFIG[f"DASH_VNET_MAPPING_TABLE:{pl.VNET1}:{pl.PE_CA}"]["metering_class_or"]
    apply_messages(localhost, duthost, ptfhost, pl.PE_VNET_MAPPING_CONFIG, dpuhost.dpu_index)

    for _ in range(num_packets):
        vm_to_dpu_pkt, exp_dpu_to_pe_pkt, pe_to_dpu_pkt, exp_dpu_to_vm_pkt = rand_udp_port_packets(
            dash_pl_config, floating_nic=True, outbound_vni=pl.ENI_TRUSTED_VNI
        )
        # Usually `testutils.send` automatically updates the packet payload to include the test name
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
    # Just waiting for 10 sec to get all complete statistics
    time.sleep(10)
    recvd_pkts = sum(tunnel_endpoint_counts.values())
    logger.info(f"Received packets: {recvd_pkts}, Tunnel endpoint counts: {tunnel_endpoint_counts}")

    pytest_assert(
        recvd_pkts == num_packets,
        f"Expected {num_packets} packets, but received {recvd_pkts} packets. " f"Counts: {tunnel_endpoint_counts}",
    )

    # Get eni oid
    eni = pl.ENI_ID
    eni_oid = get_eni_counter_oid(dpuhost, eni)
    logger.info(f'Expecting meterclass stats {exp_meterclass} to be incremented for ENI {eni_oid}')

    # Get DPU SAI Meter statistics
    meter_stats = get_eni_meter_counters(dpuhost)
    logger.info(f'Actual DPU Meterclass stats: {meter_stats}')

    # verify Meter class stats
    if exp_meterclass in meter_stats[eni_oid]:
        pytest_assert(
            meter_stats[eni_oid][exp_meterclass]['tx_bytes'] == str(exp_tx_bytes),
            f"Meterclass {exp_meterclass} tx_bytes stats doesn't matches expected  value"
            )
        pytest_assert(
            meter_stats[eni_oid][exp_meterclass]['rx_bytes'] == str(exp_rx_bytes),
            f"Meterclass {exp_meterclass} rx_bytes stats doesn't matches expected  value"
            )
    else:
        pytest_assert(False, "Expected MeterClass stats is not getting updated")

    expected_pkt_per_endpoint = num_packets // len(tunnel_endpoint_counts)
    pkt_count_low = expected_pkt_per_endpoint * 0.75
    pkt_count_high = expected_pkt_per_endpoint * 1.25

    for ip, count in tunnel_endpoint_counts.items():
        logger.info(f'Received packet count for {ip} is {count}')
        pytest_assert(
            pkt_count_low <= count <= pkt_count_high, f"Packet count for {ip} is out of expected range: {count}"
        )
