import pytest
import logging

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, \
                                                  send_server_to_t1_with_action                 # noqa F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                  # noqa F401
from tests.common.dualtor.dual_tor_utils import check_simulator_flap_counter                    # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa F401
from tests.common.dualtor.tor_failure_utils import shutdown_tor_heartbeat                       # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, \
                                                copy_ptftests_directory, change_mac_addresses   # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                               # noqa F401
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC
from tests.common.dualtor.dual_tor_common import cable_type                                     # noqa F401
from tests.common.dualtor.dual_tor_common import CableType


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(loganalyzer, duthosts):

    ignore_errors = [
        r".* ERR monit.*: 'container_checker' status failed \(3\) -- Expected containers not running: mux"
    ]

    if loganalyzer:
        for duthost in duthosts:
            loganalyzer[duthost.hostname].ignore_regex.extend(ignore_errors)

    return None


def test_active_tor_heartbeat_failure_upstream(
    toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host,     # noqa F811
    send_server_to_t1_with_action, shutdown_tor_heartbeat, cable_type, skip_traffic_test        # noqa F811
):
    """
    Send upstream traffic and stop the LinkProber module on the active ToR.
    Confirm switchover and disruption lasts < 1 second.
    """
    logging.info("skip_traffic_test: {}".format(skip_traffic_test))
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=lambda: shutdown_tor_heartbeat(upper_tor_host),
        skip_traffic_test=skip_traffic_test
    )

    if cable_type == CableType.active_standby:
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            cable_type=cable_type
        )

    if cable_type == CableType.active_active:
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            cable_type=cable_type
        )


@pytest.mark.enable_active_active
def test_active_tor_heartbeat_failure_downstream_active(
    toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host,    # noqa F811
    send_t1_to_server_with_action, shutdown_tor_heartbeat, cable_type, skip_traffic_test        # noqa F811
):
    """
    Send downstream traffic from T1 to the active ToR and stop the LinkProber module on the active ToR.
    Confirm switchover and disruption lasts < 1 second.
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=lambda: shutdown_tor_heartbeat(upper_tor_host),
        skip_traffic_test=skip_traffic_test
    )

    if cable_type == CableType.active_standby:
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            cable_type=cable_type
        )

    if cable_type == CableType.active_active:
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            cable_type=cable_type
        )


def test_active_tor_heartbeat_failure_downstream_standby(
    toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host,    # noqa F811
    send_t1_to_server_with_action, shutdown_tor_heartbeat, skip_traffic_test):                     # noqa F811
    """
    Send downstream traffic from T1 to the standby ToR and stop the LinkProber module on the active ToR.
    Confirm switchover and disruption lasts < 1 second.
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        action=lambda: shutdown_tor_heartbeat(upper_tor_host),
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host
    )


def test_standby_tor_heartbeat_failure_upstream(
    toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host,    # noqa F811
    send_server_to_t1_with_action, shutdown_tor_heartbeat, skip_traffic_test):                     # noqa F811
    """
    Send upstream traffic and stop the LinkProber module on the standby ToR.
    Confirm no switchover and no disruption.
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True,
        action=lambda: shutdown_tor_heartbeat(lower_tor_host),
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


def test_standby_tor_heartbeat_failure_downstream_active(
    toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host,    # noqa F811
    send_t1_to_server_with_action, shutdown_tor_heartbeat, skip_traffic_test):                     # noqa F811
    """
    Send downstream traffic from T1 to the active ToR and stop the LinkProber module on the standby ToR.
    Confirm no switchover and no disruption.
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True,
        action=lambda: shutdown_tor_heartbeat(lower_tor_host),
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )


def test_standby_tor_heartbeat_failure_downstream_standby(
    toggle_all_simulator_ports_to_upper_tor, upper_tor_host, lower_tor_host,    # noqa F811
    send_t1_to_server_with_action, shutdown_tor_heartbeat, skip_traffic_test):                     # noqa F811
    """
    Send downstream traffic from T1 to the standby ToR and stop the LinkProber module on the standby ToR.
    Confirm no switchover and no disruption.
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True,
        action=lambda: shutdown_tor_heartbeat(lower_tor_host),
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host
    )
