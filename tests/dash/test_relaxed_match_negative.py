import logging
import pytest
import ptf.testutils as testutils

from constants import LOCAL_PTF_INTF, REMOTE_PTF_INTF
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.dash.conftest import config_vxlan_udp_dport
import packets

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('dpu'),
]


@pytest.fixture(autouse=True)
def skip_underlay_route(request):
    if 'with-underlay-route' in request.node.name:
        pytest.skip('Skip the test with param "with-underlay-route", '
                    'it is unnecessary to cover all underlay route scenarios.')


@pytest.fixture()
def restore_vxlan_udp_dport(duthost):

    yield

    config_vxlan_udp_dport(duthost, 4789)


def test_relaxed_match_negative(duthost, ptfadapter, apply_vnet_configs, dash_config_info,
                                acl_default_rule, restore_vxlan_udp_dport):
    """
    Negative test of dynamically changing the VxLAN UDP dst port
    """
    with allure.step("Check the traffic with default port 4789 is forwarded by the DPU"):
        _, vxlan_packet, expected_packet = packets.outbound_vnet_packets(dash_config_info)
        testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
        testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    with allure.step("Change the port to 13330, check the packet with port 4789 is dropped"):
        config_vxlan_udp_dport(duthost, 13330)
        testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
        testutils.verify_no_packet_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    with allure.step("Change the port back to 4789, check the packet with port 4789 is forwarded"):
        config_vxlan_udp_dport(duthost, 4789)
        testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
        testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
    with allure.step("Check the packet with port 13330 is dropped"):
        _, vxlan_packet, expected_packet = packets.outbound_vnet_packets(dash_config_info, vxlan_udp_dport=13330)
        testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
        testutils.verify_no_packet_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
