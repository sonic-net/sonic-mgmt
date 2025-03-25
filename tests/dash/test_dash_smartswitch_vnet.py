import logging
import pytest
import ptf.testutils as testutils
import packets

from constants import LOCAL_PTF_INTF, REMOTE_PA_IP, REMOTE_PTF_RECV_INTF, REMOTE_DUT_INTF
from gnmi_utils import apply_gnmi_file
from dash_utils import render_template_to_host, apply_swssconfig_file
from tests.dash.conftest import get_interface_ip

APPLIANCE_VIP = "10.1.0.5"
ENABLE_GNMI_API = True

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

"""
Test prerequisites:
- DPU needs the Appliance VIP configured as its loopback IP
- Assign IPs to DPU-NPU dataplane interfaces
- Default route on DPU to NPU
"""


@pytest.fixture(scope="module", autouse=True)
def add_dpu_static_route(duthost, dpu_ip):
    cmd = f"ip route replace {APPLIANCE_VIP}/32 via {dpu_ip}"
    duthost.shell(cmd)

    yield

    duthost.shell(f"ip route del {APPLIANCE_VIP}/32 via {dpu_ip}")


@pytest.fixture(scope="module", autouse=True)
def add_npu_static_routes(duthost, dpu_ip, dash_smartswitch_vnet_config, skip_config, skip_cleanup):
    if not skip_config:
        cmds = []
        pe_nexthop_ip = get_interface_ip(duthost, dash_smartswitch_vnet_config[REMOTE_DUT_INTF]).ip + 1
        cmds.append(f"ip route replace {dash_smartswitch_vnet_config[REMOTE_PA_IP]}/32 via {pe_nexthop_ip}")
        logger.info(f"Adding static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        cmds = []
        cmds.append(f"ip route del {dash_smartswitch_vnet_config[REMOTE_PA_IP]}/32 via {pe_nexthop_ip}")
        logger.info(f"Removing static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)


@pytest.fixture(autouse=True)
def common_setup_teardown(localhost, duthost, ptfhost, dpu_index, dash_smartswitch_vnet_config, skip_config):
    if skip_config:
        return

    host = f"dpu{dpu_index}"
    op = "SET"
    for i in range(0, 4):
        config = f"dash_smartswitch_vnet_{i}"
        template_name = "{}.j2".format(config)
        dest_path = "/tmp/{}.json".format(config)
        render_template_to_host(template_name, duthost, dest_path, dash_smartswitch_vnet_config, op=op)
        if ENABLE_GNMI_API:
            apply_gnmi_file(localhost, duthost, ptfhost, dest_path, None, 5, 1024, host)
        else:
            apply_swssconfig_file(duthost, dest_path)

    yield

    op = "DEL"
    for i in reversed(range(0, 4)):
        config = f"dash_smartswitch_vnet_{i}"
        template_name = "{}.j2".format(config)
        dest_path = "/tmp/{}.json".format(config)
        render_template_to_host(template_name, duthost, dest_path, dash_smartswitch_vnet_config, op=op)
        if ENABLE_GNMI_API:
            apply_gnmi_file(localhost, duthost, ptfhost, dest_path, None, 5, 1024, host)
        else:
            apply_swssconfig_file(duthost, dest_path)


def test_smartswitch_outbound_vnet(
        ptfadapter,
        dash_smartswitch_vnet_config,
        skip_dataplane_checking,
        inner_packet_type,
        vxlan_udp_dport):

    if skip_dataplane_checking:
        return
    _, vxlan_packet, expected_packet = packets.outbound_smartswitch_vnet_packets(dash_smartswitch_vnet_config,
                                                                                 vxlan_udp_dport=vxlan_udp_dport,
                                                                                 inner_packet_type=inner_packet_type)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, dash_smartswitch_vnet_config[LOCAL_PTF_INTF], vxlan_packet, 1)
    testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_smartswitch_vnet_config[REMOTE_PTF_RECV_INTF])
