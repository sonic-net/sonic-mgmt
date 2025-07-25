import logging
import time

import ptf.packet as scapy
import configs.privatelink_config as pl
import ptf.testutils as testutils
import ptf
import pytest
from constants import LOCAL_PTF_INTF, LOCAL_DUT_INTF, REMOTE_DUT_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from gnmi_utils import apply_messages
from packets import outbound_pl_packets, inbound_pl_packets
from tests.common.helpers.assertions import pytest_assert
from tests.dash.conftest import get_interface_ip

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


@pytest.fixture(scope="module")
def floating_nic(duthost):
    return True


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


@pytest.fixture(autouse=True, scope="module")
def common_setup_teardown(localhost, duthost, ptfhost, dpu_index, skip_config, dpuhosts, set_vxlan_udp_sport_range):
    if skip_config:
        return
    dpuhost = dpuhosts[dpu_index]
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)
    base_config_messages = {
        **pl.APPLIANCE_FNIC_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.VNET_CONFIG,
        **pl.VNET2_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG,
        **pl.TUNNEL2_CONFIG
    }
    logger.info(base_config_messages)

    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

    route_and_mapping_messages = {
        **pl.PE1_VNET_MAPPING_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_WITH_TUNNEL_CONFIG,
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

    logger.info(pl.ENI_TRUSTED_VNI_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_TRUSTED_VNI_CONFIG, dpuhost.dpu_index)

    logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_TRUSTED_VNI_CONFIG, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index, False)
    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index, False)


def test_privatelink_trusted_vni(
    ptfadapter,
    dash_pl_config,
    floating_nic,
    localhost,
    duthost,
    ptfhost,
    dpuhost,
):
    vm_to_dpu_pkt, exp_dpu_to_pe_pkt = outbound_pl_packets(dash_pl_config, "vxlan", floating_nic)
    pe_to_dpu_pkt, exp_dpu_to_vm_pkt = inbound_pl_packets(dash_pl_config, floating_nic)
    exp_dpu_to_vm_pkt.set_do_not_care_packet(scapy.IP, "dst")

    num_packets = 1000
    timeout = 5
    ptfadapter.dataplane.flush()
    tunnel_endpoint_counts = {ip: 0 for ip in pl.TUNNEL2_ENDPOINT_IPS}
    for i in range(num_packets):
        testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vm_to_dpu_pkt, 1)
        import pdb; pdb.set_trace()
        testutils.verify_packet_any_port(ptfadapter, exp_dpu_to_pe_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
        testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pe_to_dpu_pkt, 1)
        start_time = time.time()
        while True:
            if (time.time() - start_time) > timeout:
                break

            result = testutils.dp_poll(ptfadapter, timeout=timeout)
            if isinstance(result, ptfadapter.dataplane.PollSuccess):
                if result.port in dash_pl_config[REMOTE_PTF_RECV_INTF] and \
                 result.packet["IP"].dst in tunnel_endpoint_counts:
                    if ptf.dataplane.match_exp_pkt(exp_dpu_to_vm_pkt, result.packet['Raw']):
                        tunnel_endpoint_counts[result.packet["IP"].dst] += 1
                else:
                    pytest.fail(f"Unexpected destination IP: {result.pkt['IP'].dst}")
            else:
                pytest.fail(f"Expected packet not received:\n{result.format()}")

    recvd_pkts = sum(tunnel_endpoint_counts.values())
    pytest_assert(
        recvd_pkts == num_packets,
        f"Expected {num_packets} packets, but received {recvd_pkts} packets. "
        f"Counts: {tunnel_endpoint_counts}"
    )
    expected_pkt_per_endpoint = num_packets // len(pl.TUNNEL2_ENDPOINT_IPS)
    pkt_count_low = expected_pkt_per_endpoint * 0.75
    pkt_count_high = expected_pkt_per_endpoint * 1.25
    for ip, count in tunnel_endpoint_counts.items():
        pytest_assert(
            pkt_count_low <= count <= pkt_count_high,
            f"Packet count for {ip} is out of expected range: {count}"
        )