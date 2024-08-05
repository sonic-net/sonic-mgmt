import logging
import pytest
import ptf.testutils as testutils
import packets

from constants import LOCAL_PTF_INTF, REMOTE_PTF_INTF
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from gnmi_utils import apply_gnmi_file
from dash_utils import render_template_to_host
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('dpu')
]


@pytest.fixture(autouse=True)
def skip_underlay_route(request):
    if 'with-underlay-route' in request.node.name:
        pytest.skip('Skip the test with param "with-underlay-route", '
                    'it is unnecessary to cover all underlay route scenarios.')


def test_dash_disable_enable_eni(ptfadapter, localhost, duthost, ptfhost, apply_vnet_configs,
                                 dash_config_info, asic_db_checker, acl_default_rule):
    """
    The test is to verify that after the ENI is disabled, the corresponding traffic should be dropped by the DPU.
    """
    asic_db_checker(["SAI_OBJECT_TYPE_VNET", "SAI_OBJECT_TYPE_ENI"])
    with allure.step("Verify the dash traffic when ENI is enabled"):
        _, vxlan_packet, expected_packet = packets.outbound_vnet_packets(dash_config_info)
        testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
        testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])

    def _set_eni_admin_state(state):
        eni_set_state_config = "dash_set_eni_admin_state"
        template_name = f"{eni_set_state_config}.j2"
        dest_path = f"/tmp/{eni_set_state_config}.json"
        render_template_to_host(template_name, duthost, dest_path, dash_config_info, eni_admin_state=state)
        apply_gnmi_file(localhost, duthost, ptfhost, dest_path)

    def _check_eni_admin_state(state):
        asic_db_eni_state = duthost.shell(
            f"redis-cli -n 1 hget {asic_db_eni_key} SAI_ENI_ATTR_ADMIN_STATE")["stdout"]
        return asic_db_eni_state == state

    with allure.step("Disabled the ENI"):
        _set_eni_admin_state("disabled")

    with allure.step("Check ASIC db to confirm the ENI is disabled"):
        asic_db_eni_key = duthost.shell("redis-cli -n 1 keys *ENI:oid*")["stdout"]
        pytest_assert(wait_until(10, 2, 0, _check_eni_admin_state, "false"),
                      "The ENI admin state in ASIC_DB is still true")

    with allure.step("Verify the dash traffic is dropped after ENI is disabled"):
        testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
        testutils.verify_no_packet_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])

    with allure.step("Enable the ENI"):
        _set_eni_admin_state("enabled")

    with allure.step("Check ASIC db to confirm the ENI is enabled"):
        asic_db_eni_key = duthost.shell("redis-cli -n 1 keys *ENI:oid*")["stdout"]
        pytest_assert(wait_until(10, 2, 0, _check_eni_admin_state, "true"),
                      "The ENI admin state in ASIC_DB is still false")

    with allure.step("Verify the dash traffic is forwarded after ENI is enabled"):
        testutils.send(ptfadapter, dash_config_info[LOCAL_PTF_INTF], vxlan_packet, 1)
        testutils.verify_packets_any(ptfadapter, expected_packet, ports=dash_config_info[REMOTE_PTF_INTF])
