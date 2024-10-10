import logging
from ipaddress import ip_interface

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
from constants import LOCAL_PTF_INTF
from gnmi_utils import apply_messages
from packets import outbound_pl_packets

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def dpu_ip(duthost, dpu_index):
    cmd = f"ip addr show | grep Ethernet-BP{dpu_index} | grep inet | awk '{{print $2}}'"
    npu_interface_ip = ip_interface(duthost.shell(cmd)["stdout"].strip())
    return npu_interface_ip.ip + 1


@pytest.fixture(scope="module", autouse=True)
def add_dpu_static_route(duthost, dpu_ip):
    cmd = f"ip route replace {pl.SIP}/32 via {dpu_ip}"
    duthost.shell(cmd)

    yield

    duthost.shell(f"ip route del {pl.SIP}")


@pytest.fixture(autouse=True)
def common_setup_teardown(localhost, duthost, ptfhost, dpu_index):
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ROUTING_TYPE_PL_CONFIG, dpu_index)
    messages = {
        **pl.APPLIANCE_CONFIG,
        **pl.VNET_CONFIG,
        **pl.ENI_CONFIG,
        **pl.VNET_MAPPING_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG
    }
    logger.info(messages)

    apply_messages(localhost, duthost, ptfhost, messages, dpu_index)

    messages = {
        **pl.ROUTE_VNET_CONFIG,
        **pl.ENI_ROUTE_GROUP1_CONFIG
    }
    logger.info(messages)
    apply_messages(localhost, duthost, ptfhost, messages, dpu_index)

    return


def test_privatelink_basic_transform(
    ptfadapter,
    dash_pl_config,
    minigraph_facts,
    config_facts,
):
    pc_member_config = config_facts["PORTCHANNEL_MEMBER"]
    member_ports = []
    for member_config in pc_member_config.values():
        for member in member_config:
            member_ports.append(member)

    expected_ptf_ports = [minigraph_facts["minigraph_ptf_indices"][port] for port in member_ports]
    logger.info(f"Expecting transformed packet on PTF ports: {expected_ptf_ports}")
    pkt, exp_pkt = outbound_pl_packets(dash_pl_config)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, expected_ptf_ports)
