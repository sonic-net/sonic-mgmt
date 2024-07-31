import logging
import pytest
import time

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action      # noqa F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                                      # noqa F401
from tests.common.dualtor.dual_tor_utils import check_simulator_flap_counter                                        # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor                      # noqa F401
from tests.common.dualtor.tor_failure_utils import reboot_tor, tor_blackhole_traffic, wait_for_device_reachable     # noqa F401
from tests.common.dualtor.tor_failure_utils import wait_for_mux_container, wait_for_pmon_container                  # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, change_mac_addresses          # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                                                   # noqa F401
from tests.common.dualtor.nic_simulator_control import mux_status_from_nic_simulator                                # noqa F401
from tests.common.dualtor.nic_simulator_control import ForwardingState
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor                                        # noqa F401
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC
from tests.common.dualtor.dual_tor_common import cable_type                                                         # noqa F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_common import ActiveActivePortID
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer


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
def toggle_upper_tor_pdu(upper_tor_host, get_pdu_controller):       # noqa F811
    pdu_controller = get_pdu_controller(upper_tor_host)
    if pdu_controller is None:
        # restart the kernel instantly through system request if there is no pdu information present
        return lambda: upper_tor_host.shell("nohup sh -c 'sleep 2; echo b > /proc/sysrq-trigger;' > /dev/null &")
    else:
        return lambda: toggle_pdu_outlet(pdu_controller)


@pytest.fixture(scope='module')
def toggle_lower_tor_pdu(lower_tor_host, get_pdu_controller):       # noqa F811
    pdu_controller = get_pdu_controller(lower_tor_host)
    if pdu_controller is None:
        return lambda: lower_tor_host.shell("nohup sh -c 'sleep 2; echo b > /proc/sysrq-trigger;' > /dev/null &")
    else:
        return lambda: toggle_pdu_outlet(pdu_controller)


@pytest.mark.enable_active_active
@pytest.mark.disable_loganalyzer
def test_active_tor_reboot_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor, toggle_upper_tor_pdu,      # noqa F811
    wait_for_device_reachable, wait_for_mux_container, cable_type,      # noqa F811
    wait_for_pmon_container, skip_traffic_test                          # noqa F811
):
    """
    Send upstream traffic and reboot the active ToR. Confirm switchover
    occurred and disruption lasts < 1 second
    """
    with LogAnalyzer(ansible_host=lower_tor_host,
                     marker_prefix="test_active_tor_reboot_upstream"):
        send_server_to_t1_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            action=toggle_upper_tor_pdu, stop_after=60,
            skip_traffic_test=skip_traffic_test
        )
        wait_for_device_reachable(upper_tor_host)
        wait_for_mux_container(upper_tor_host)
        wait_for_pmon_container(upper_tor_host)

        if cable_type == CableType.active_standby:
            verify_tor_states(
                expected_active_host=lower_tor_host,
                expected_standby_host=upper_tor_host
            )
        elif cable_type == CableType.active_active:
            verify_tor_states(
                expected_active_host=[upper_tor_host, lower_tor_host],
                expected_standby_host=None,
                cable_type=cable_type,
                verify_db_timeout=60
            )


@pytest.mark.disable_loganalyzer
def test_active_tor_reboot_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor, toggle_upper_tor_pdu,      # noqa F811
    wait_for_device_reachable, wait_for_mux_container,                  # noqa F811
    wait_for_pmon_container, skip_traffic_test                          # noqa F811
):
    """
    Send downstream traffic to the standby ToR and reboot the active ToR.
    Confirm switchover occurred and disruption lasts < 1 second
    """
    with LogAnalyzer(ansible_host=lower_tor_host,
                     marker_prefix="test_active_tor_reboot_downstream_standby"):
        send_t1_to_server_with_action(
            lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            action=toggle_upper_tor_pdu, stop_after=60,
            skip_traffic_test=skip_traffic_test
        )
        wait_for_device_reachable(upper_tor_host)
        wait_for_mux_container(upper_tor_host)
        wait_for_pmon_container(upper_tor_host)
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host
        )


@pytest.mark.disable_loganalyzer
def test_standby_tor_reboot_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor, toggle_lower_tor_pdu,      # noqa F811
    wait_for_device_reachable, wait_for_mux_container,                  # noqa F811
    wait_for_pmon_container, skip_traffic_test                          # noqa F811
):
    """
    Send upstream traffic and reboot the standby ToR. Confirm no switchover
    occurred and no disruption
    """
    with LogAnalyzer(ansible_host=upper_tor_host,
                     marker_prefix="test_standby_tor_reboot_upstream"):
        send_server_to_t1_with_action(
            upper_tor_host, verify=True,
            action=toggle_lower_tor_pdu, stop_after=60,
            skip_traffic_test=skip_traffic_test
        )
        wait_for_device_reachable(lower_tor_host)
        wait_for_mux_container(lower_tor_host)
        wait_for_pmon_container(lower_tor_host)
        verify_tor_states(
            expected_active_host=upper_tor_host,
            expected_standby_host=lower_tor_host
        )


@pytest.mark.disable_loganalyzer
def test_standby_tor_reboot_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor, toggle_lower_tor_pdu,      # noqa F811
    wait_for_device_reachable, wait_for_mux_container,                  # noqa F811
    wait_for_pmon_container, skip_traffic_test                          # noqa F811
):
    """
    Send downstream traffic to the active ToR and reboot the standby ToR.
    Confirm no switchover occurred and no disruption
    """
    with LogAnalyzer(ansible_host=upper_tor_host,
                     marker_prefix="test_standby_tor_reboot_downstream_active"):
        send_t1_to_server_with_action(
            upper_tor_host, verify=True,
            action=toggle_lower_tor_pdu, stop_after=60,
            skip_traffic_test=skip_traffic_test
        )
        wait_for_device_reachable(lower_tor_host)
        wait_for_mux_container(lower_tor_host)
        wait_for_pmon_container(lower_tor_host)
        verify_tor_states(
            expected_active_host=upper_tor_host,
            expected_standby_host=lower_tor_host
        )


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
@pytest.mark.disable_loganalyzer
def test_active_tor_reboot_downstream(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_upper_tor_pdu, wait_for_device_reachable, cable_type,        # noqa F811
    tunnel_traffic_monitor, mux_status_from_nic_simulator,              # noqa F811
    wait_for_mux_container,wait_for_pmon_container                      # noqa F811
):
    def check_forwarding_state(upper_tor_forwarding_state, lower_tor_forwarding_state):
        mux_status = mux_status_from_nic_simulator()
        logging.debug(
            "Check forwarding state, upper ToR: %s, lower ToR: %s",
            upper_tor_forwarding_state,
            lower_tor_forwarding_state
        )
        logging.debug("Mux status from nic_simulator:\n%s", mux_status)
        for port in mux_status:
            if ((mux_status[port][ActiveActivePortID.UPPER_TOR] != upper_tor_forwarding_state) or
                    (mux_status[port][ActiveActivePortID.LOWER_TOR] != lower_tor_forwarding_state)):
                logging.debug("Port %s mux status is not expected", port)
                return False
        return True

    # verify all ToRs are in active state
    verify_tor_states(
        expected_active_host=[upper_tor_host, lower_tor_host],
        expected_standby_host=None,
        cable_type=cable_type
    )

    # use loganalyzer to collect logs from the lower tor during reboot
    with LogAnalyzer(ansible_host=lower_tor_host, marker_prefix="test_active_tor_reboot_downstream"):
        # reboot the upper ToR and verify the upper ToR forwarding state is changed to standby
        toggle_upper_tor_pdu()
        pytest_assert(
            wait_until(60, 5, 5, check_forwarding_state, ForwardingState.STANDBY, ForwardingState.ACTIVE),
            "Forwarding state check failed after reboot."
        )
        lower_tor_host.shell("show mux grpc mux", module_ignore_errors=True)

        # verify the upper ToR changes back to active after the upper comes back from reboot
        wait_for_device_reachable(upper_tor_host)
        wait_for_mux_container(upper_tor_host)
        wait_for_pmon_container(upper_tor_host)
        pytest_assert(
            wait_until(180, 5, 60, check_forwarding_state, ForwardingState.ACTIVE, ForwardingState.ACTIVE),
            "Forwarding state check failed after the upper ToR comes back from reboot."
        )
        verify_tor_states(
            expected_active_host=[upper_tor_host, lower_tor_host],
            expected_standby_host=None,
            cable_type=cable_type
        )

    # verify the server receives packets with no disrupts, no tunnel traffic
    with tunnel_traffic_monitor(upper_tor_host, existing=False):
        send_t1_to_server_with_action(upper_tor_host, verify=True, stop_after=60)
