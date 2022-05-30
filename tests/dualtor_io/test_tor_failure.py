import logging
import pytest
import time

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action                                  # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                                                                  # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor                                                  # lgtm[py/unused-import]
from tests.common.dualtor.tor_failure_utils import reboot_tor, tor_blackhole_traffic, wait_for_device_reachable                                 # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, change_mac_addresses                                      # lgtm[py/unused-import]
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC
from tests.common.dualtor.dual_tor_common import cable_type 

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("dualtor")
]


def toggle_pdu_outlet(controller):
    logger.info("Toggling PDU for {}".format(controller.dut_hostname))
    controller.turn_off_outlet()
    time.sleep(10)
    controller.turn_on_outlet()


@pytest.fixture(scope='module')
def toggle_upper_tor_pdu(upper_tor_host, get_pdu_controller):
    pdu_controller = get_pdu_controller(upper_tor_host)
    return lambda: toggle_pdu_outlet(pdu_controller)


@pytest.fixture(scope='module')
def toggle_lower_tor_pdu(lower_tor_host, get_pdu_controller):
    pdu_controller = get_pdu_controller(lower_tor_host)
    return lambda: toggle_pdu_outlet(pdu_controller)


@pytest.mark.disable_loganalyzer
def test_active_tor_reboot_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor, toggle_upper_tor_pdu,
    wait_for_device_reachable
):
    """
    Send upstream traffic and reboot the active ToR. Confirm switchover
    occurred and disruption lasts < 1 second
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=toggle_upper_tor_pdu, stop_after=60
    )
    wait_for_device_reachable(upper_tor_host)
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host
    )


@pytest.mark.disable_loganalyzer
def test_active_tor_reboot_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor, toggle_upper_tor_pdu,
    wait_for_device_reachable
):
    """
    Send downstream traffic to the standby ToR and reboot the active ToR.
    Confirm switchover occurred and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=toggle_upper_tor_pdu, stop_after=60
    )
    wait_for_device_reachable(upper_tor_host)
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host
    )


@pytest.mark.disable_loganalyzer
def test_standby_tor_reboot_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,
    toggle_all_simulator_ports_to_upper_tor, toggle_lower_tor_pdu,
    wait_for_device_reachable
):
    """
    Send upstream traffic and reboot the standby ToR. Confirm no switchover
    occurred and no disruption
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True,
        action=toggle_lower_tor_pdu, stop_after=60
    )
    wait_for_device_reachable(lower_tor_host)
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


@pytest.mark.disable_loganalyzer
def test_standby_tor_reboot_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,
    toggle_all_simulator_ports_to_upper_tor, toggle_lower_tor_pdu,
    wait_for_device_reachable
):
    """
    Send downstream traffic to the active ToR and reboot the standby ToR.
    Confirm no switchover occurred and no disruption
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True,
        action=toggle_lower_tor_pdu, stop_after=60
    )
    wait_for_device_reachable(lower_tor_host)
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )
