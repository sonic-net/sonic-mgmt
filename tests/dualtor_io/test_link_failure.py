import pytest

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action, \
                                                  send_soc_to_t1_with_action, send_t1_to_soc_with_action    # noqa F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, shutdown_fanout_upper_tor_intfs, \
                                                shutdown_fanout_lower_tor_intfs, upper_tor_fanouthosts, \
                                                lower_tor_fanouthosts, shutdown_upper_tor_downlink_intfs, \
                                                shutdown_lower_tor_downlink_intfs                   # noqa F401
from tests.common.dualtor.dual_tor_utils import check_simulator_flap_counter                        # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor      # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, \
                                                copy_ptftests_directory, change_mac_addresses       # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                                   # noqa F401
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC
from tests.common.dualtor.dual_tor_common import active_active_ports                                # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type                                         # noqa F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.config_reload import config_reload


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.mark.enable_active_active
def test_active_link_down_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_fanout_upper_tor_intfs, cable_type, skip_traffic_test      # noqa F811
):
    """
    Send traffic from server to T1 and shutdown the active ToR link.
    Verify switchover and disruption lasts < 1 second
    """
    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=1, action=shutdown_fanout_upper_tor_intfs,
            skip_traffic_test=skip_traffic_test
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
            skip_state_db=True
        )

    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=3, action=shutdown_fanout_upper_tor_intfs,
            skip_traffic_test=skip_traffic_test
        )

        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
        )


@pytest.mark.enable_active_active
def test_active_link_down_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_fanout_upper_tor_intfs, cable_type, skip_traffic_test      # noqa F811
):
    """
    Send traffic from T1 to active ToR and shutdown the active ToR link.
    Verify switchover and disruption lasts < 1 second
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=3, action=shutdown_fanout_upper_tor_intfs,
            skip_traffic_test=skip_traffic_test
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy'
        )

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=1, action=shutdown_fanout_upper_tor_intfs,
            skip_traffic_test=skip_traffic_test
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
            skip_state_db=True
        )


def test_active_link_down_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_fanout_upper_tor_intfs, skip_traffic_test                  # noqa F811
):
    """
    Send traffic from T1 to standby ToR and shutdown the active ToR link.
    Verify switchover and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=3, action=shutdown_fanout_upper_tor_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_link_down_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_fanout_lower_tor_intfs, skip_traffic_test                  # noqa F811
):
    """
    Send traffic from server to T1 and shutdown the standby ToR link.
    Verify no switchover and no disruption
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2, action=shutdown_fanout_lower_tor_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_link_down_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_fanout_lower_tor_intfs, skip_traffic_test                  # noqa F811
):
    """
    Send traffic from T1 to active ToR and shutdown the standby ToR link.
    Confirm no switchover and no disruption
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2, action=shutdown_fanout_lower_tor_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_link_down_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_fanout_lower_tor_intfs, skip_traffic_test                  # noqa F811
):
    """
    Send traffic from T1 to standby ToR and shutdwon the standby ToR link.
    Confirm no switchover and no disruption
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=2, action=shutdown_fanout_lower_tor_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_active_tor_downlink_down_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_upper_tor_downlink_intfs, skip_traffic_test                # noqa F811
):
    """
    Send traffic from server to T1 and shutdown the active ToR downlink on DUT.
    Verify switchover and disruption lasts < 1 second
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_upper_tor_downlink_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health='unhealthy'
    )


def test_active_tor_downlink_down_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_upper_tor_downlink_intfs, skip_traffic_test                # noqa F811
):
    """
    Send traffic from T1 to active ToR and shutdown the active ToR downlink on DUT.
    Verify switchover and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_upper_tor_downlink_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health='unhealthy'
    )


def test_active_tor_downlink_down_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_upper_tor_downlink_intfs, skip_traffic_test                # noqa F811
):
    """
    Send traffic from T1 to standby ToR and shutdown the active ToR downlink on DUT.
    Verify switchover and disruption lasts < 1 second
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_upper_tor_downlink_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=lower_tor_host,
        expected_standby_host=upper_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_tor_downlink_down_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_lower_tor_downlink_intfs, skip_traffic_test                # noqa F811
):
    """
    Send traffic from server to T1 and shutdown the standby ToR downlink on DUT.
    Verify no switchover and no disruption
    """
    send_server_to_t1_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_lower_tor_downlink_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_tor_downlink_down_downstream_active(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_lower_tor_downlink_intfs, skip_traffic_test                # noqa F811
):
    """
    Send traffic from T1 to active ToR and shutdown the standby ToR downlink on DUT.
    Confirm no switchover and no disruption
    """
    send_t1_to_server_with_action(
        upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_lower_tor_downlink_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


def test_standby_tor_downlink_down_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    toggle_all_simulator_ports_to_upper_tor,                            # noqa F811
    shutdown_lower_tor_downlink_intfs, skip_traffic_test                # noqa F811
):
    """
    Send traffic from T1 to standby ToR and shutdwon the standby ToR downlink on DUT.
    Confirm no switchover and no disruption
    """
    send_t1_to_server_with_action(
        lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
        allowed_disruption=1, action=shutdown_lower_tor_downlink_intfs,
        skip_traffic_test=skip_traffic_test
    )
    verify_tor_states(
        expected_active_host=upper_tor_host,
        expected_standby_host=lower_tor_host,
        expected_standby_health='unhealthy'
    )


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_active_link_down_upstream_soc(
    upper_tor_host, lower_tor_host, send_soc_to_t1_with_action,         # noqa F811
    shutdown_fanout_upper_tor_intfs, cable_type                         # noqa F811
):
    """
    Send traffic from soc to T1 and shutdown the active ToR link.
    Verify switchover and disruption lasts < 1 second
    """
    if cable_type == CableType.active_active:
        send_soc_to_t1_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=1, action=shutdown_fanout_upper_tor_intfs
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
            skip_state_db=True
        )


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_active_link_down_downstream_active_soc(
    upper_tor_host, lower_tor_host, send_t1_to_soc_with_action,         # noqa F811
    shutdown_fanout_upper_tor_intfs, cable_type                         # noqa F811
):
    """
    Send traffic from T1 to active ToR and shutdown the active ToR link.
    Verify switchover and disruption lasts < 1 second
    """
    if cable_type == CableType.active_active:
        send_t1_to_soc_with_action(
            upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
            allowed_disruption=1, action=shutdown_fanout_upper_tor_intfs
        )
        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
            skip_state_db=True
        )


def config_interface_admin_status(duthost, ports, admin_status="up"):
    """Config interface admin status."""
    if admin_status == "up":
        cmd = "config interface startup %s"
    elif admin_status == "down":
        cmd = "config interface shutdown %s"
    else:
        return

    cmds = []
    for port in ports:
        cmds.append(cmd % port)
    duthost.shell_cmds(cmds=cmds)


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_active_link_admin_down_config_reload_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,       # noqa F811
    cable_type, active_active_ports                                      # noqa F811
):
    if cable_type == CableType.active_active:
        try:
            config_interface_admin_status(upper_tor_host, active_active_ports, "down")

            upper_tor_host.shell("config save -y")

            send_server_to_t1_with_action(
                lower_tor_host, verify=True, allowed_disruption=0,
                action=lambda: config_reload(upper_tor_host, wait=0)
            )

            verify_tor_states(
                expected_active_host=lower_tor_host,
                expected_standby_host=upper_tor_host,
                expected_standby_health='unhealthy',
                cable_type=cable_type,
                skip_state_db=True  # state db will be 'unknown'
            )

        finally:
            config_interface_admin_status(upper_tor_host, active_active_ports, "up")
            upper_tor_host.shell("config save -y")


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_active_link_admin_down_config_reload_downstream(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,       # noqa F811
    cable_type, active_active_ports                                      # noqa F811
):
    if cable_type == CableType.active_active:
        try:
            config_interface_admin_status(upper_tor_host, active_active_ports, "down")

            upper_tor_host.shell("config save -y")
            config_reload(upper_tor_host, wait=60)

            verify_tor_states(
                expected_active_host=lower_tor_host,
                expected_standby_host=upper_tor_host,
                expected_standby_health='unhealthy',
                cable_type=cable_type,
                skip_state_db=True
            )

            send_t1_to_server_with_action(
                upper_tor_host, verify=True,
                stop_after=180,
                allowed_disruption=0,
                allow_disruption_before_traffic=True
            )

        finally:
            config_interface_admin_status(upper_tor_host, active_active_ports, "up")
            upper_tor_host.shell("config save -y")


@pytest.mark.disable_loganalyzer
@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_active_link_admin_down_config_reload_link_up_upstream(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    cable_type, active_active_ports                                     # noqa F811
):
    """
    Send traffic from server to T1 and unshut the active-active mux ports.
    Verify switchover and disruption.
    """
    if cable_type == CableType.active_active:
        try:
            config_interface_admin_status(upper_tor_host, active_active_ports, "down")

            verify_tor_states(
                expected_active_host=lower_tor_host,
                expected_standby_host=upper_tor_host,
                expected_standby_health='unhealthy',
                cable_type=cable_type,
                skip_state_db=True
            )

            upper_tor_host.shell("config save -y")
            config_reload(upper_tor_host, wait=60)

            verify_tor_states(
                expected_active_host=lower_tor_host,
                expected_standby_host=upper_tor_host,
                expected_standby_health='unhealthy',
                cable_type=cable_type,
                skip_state_db=True,
                verify_db_timeout=60
            )

            send_server_to_t1_with_action(
                upper_tor_host,
                verify=True,
                allowed_disruption=0,
                action=lambda: config_interface_admin_status(upper_tor_host, active_active_ports, "up")
            )

            verify_tor_states(
                expected_active_host=[upper_tor_host, lower_tor_host],
                expected_standby_host=None,
                cable_type=cable_type
            )

        finally:
            config_interface_admin_status(upper_tor_host, active_active_ports, "up")
            upper_tor_host.shell("config save -y")


@pytest.mark.disable_loganalyzer
@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_active_link_admin_down_config_reload_link_up_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    cable_type, active_active_ports                                     # noqa F811
):
    """
    Send traffic from T1 to standby ToR and unshut the active-active mux ports.
    Verify switchover and disruption.
    """
    if cable_type == CableType.active_active:
        try:
            config_interface_admin_status(upper_tor_host, active_active_ports, "down")

            verify_tor_states(
                expected_active_host=lower_tor_host,
                expected_standby_host=upper_tor_host,
                expected_standby_health='unhealthy',
                cable_type=cable_type,
                skip_state_db=True
            )

            upper_tor_host.shell("config save -y")
            config_reload(upper_tor_host, wait=60)

            verify_tor_states(
                expected_active_host=lower_tor_host,
                expected_standby_host=upper_tor_host,
                expected_standby_health='unhealthy',
                cable_type=cable_type,
                skip_state_db=True,
                verify_db_timeout=60
            )

            # after config reload, it takes time to setup the zero-mac tunnel routes for
            # the mux server ips, so there will be disruption before traffic.
            send_t1_to_server_with_action(
                upper_tor_host,
                verify=True,
                allowed_disruption=0,
                action=lambda: config_interface_admin_status(upper_tor_host, active_active_ports, "up"),
                allow_disruption_before_traffic=True
            )

            verify_tor_states(
                expected_active_host=[upper_tor_host, lower_tor_host],
                expected_standby_host=None,
                cable_type=cable_type
            )

        finally:
            config_interface_admin_status(upper_tor_host, active_active_ports, "up")
            upper_tor_host.shell("config save -y")
