import json
import logging
import time
from ipaddress import ip_interface

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
from constants import LOCAL_PTF_INTF, LOCAL_DUT_INTF, REMOTE_DUT_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from gnmi_utils import apply_messages
from packets import outbound_pl_packets, inbound_pl_packets

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


def get_dpu_dataplane_port(duthost, dpu_index):
    platform = duthost.facts["platform"]
    platform_json = json.loads(duthost.shell(f"cat /usr/share/sonic/device/{platform}/platform.json")["stdout"])
    try:
        interface = list(platform_json["DPUS"][f"dpu{dpu_index}"]["interface"].keys())[0]
    except KeyError:
        interface = f"Ethernet-BP{dpu_index}"

    logger.info(f"DPU dataplane interface: {interface}")
    return interface


def get_interface_ip(duthost, interface):
    cmd = f"ip addr show {interface} | grep -w inet | awk '{{print $2}}'"
    output = duthost.shell(cmd)["stdout"].strip()
    return ip_interface(output)


@pytest.fixture(scope="module")
def dpu_ip(duthost, dpu_index):
    dpu_port = get_dpu_dataplane_port(duthost, dpu_index)
    npu_interface_ip = get_interface_ip(duthost, dpu_port)
    return npu_interface_ip.ip + 1


@pytest.fixture(scope="module", autouse=True)
def add_npu_static_routes(duthost, dpu_ip, dash_pl_config):
    cmds = []
    vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1
    pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1
    cmds.append(f"ip route replace {pl.APPLIANCE_VIP}/32 via {dpu_ip}")
    cmds.append(f"ip route replace {pl.VM1_PA}/32 via {vm_nexthop_ip}")
    cmds.append(f"ip route replace {pl.PE_PA}/32 via {pe_nexthop_ip}")
    logger.info(f"Adding static routes: {cmds}")
    duthost.shell_cmds(cmds=cmds)

    yield

    cmds = []
    cmds.append(f"ip route del {pl.APPLIANCE_VIP}/32 via {dpu_ip}")
    cmds.append(f"ip route del {pl.VM1_PA}/32 via {vm_nexthop_ip}")
    cmds.append(f"ip route del {pl.PE_PA}/32 via {pe_nexthop_ip}")
    logger.info(f"Removing static routes: {cmds}")
    duthost.shell_cmds(cmds=cmds)


@pytest.fixture(autouse=True)
def common_setup_teardown(localhost, duthost, ptfhost, dpu_index):
    logger.info(pl.ROUTING_TYPE_PL_CONFIG)
    base_config_messages = {
        **pl.APPLIANCE_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.VNET_CONFIG,
        **pl.ENI_CONFIG,
        **pl.PE_VNET_MAPPING_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG
    }
    logger.info(base_config_messages)

    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpu_index)

    route_messages = {
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_CONFIG
    }
    logger.info(route_messages)
    apply_messages(localhost, duthost, ptfhost, route_messages, dpu_index)

    logger.info(pl.ENI_ROUTE_GROUP1_CONFIG)
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpu_index)


def test_privatelink_basic_transform(
    ptfadapter,
    dash_pl_config,
):
    vxlan_pkt, gre_pkt, exp_pkt = outbound_pl_packets(dash_pl_config)
    ipkt, iexp_pkt = inbound_pl_packets(dash_pl_config)

    logger.info("Sending VXLAN outbound packet")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], vxlan_pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], ipkt, 1)
    testutils.verify_packet(ptfadapter, iexp_pkt, dash_pl_config[LOCAL_PTF_INTF])

    time.sleep(1)  # wait for connection tracking table to timeout/clear

    logger.info("Sending GRE outbound packet")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_pl_config[LOCAL_PTF_INTF], gre_pkt, 1)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, dash_pl_config[REMOTE_PTF_RECV_INTF])
    testutils.send(ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], ipkt, 1)
    testutils.verify_packet(ptfadapter, iexp_pkt, dash_pl_config[LOCAL_PTF_INTF])
