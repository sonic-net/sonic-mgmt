import pytest

from tests.common.config_reload import config_reload
from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action, send_server_to_t1_with_action, \
                                                  send_soc_to_t1_with_action, send_t1_to_soc_with_action, \
                                                  send_server_to_server_with_action, select_test_mux_ports  # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type     # noqa F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, \
                                                force_active_tor, force_standby_tor                 # noqa F401
from tests.common.dualtor.dual_tor_utils import show_muxcable_status
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor      # noqa F401
from tests.common.dualtor.dual_tor_utils import check_simulator_flap_counter                        # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service, \
                                                copy_ptftests_directory, change_mac_addresses       # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                                   # noqa F401
from tests.common.dualtor.constants import MUX_SIM_ALLOWED_DISRUPTION_SEC, CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.mark.enable_active_active
def test_normal_op_upstream(upper_tor_host, lower_tor_host,             # noqa F811
                            send_server_to_t1_with_action,              # noqa F811
                            toggle_all_simulator_ports_to_upper_tor,    # noqa F811
                            cable_type,                                 # noqa F811
                            skip_traffic_test):                         # noqa F811
    """Send upstream traffic and confirm no disruption or switchover occurs"""
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(upper_tor_host, verify=True,
                                      stop_after=60, skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=upper_tor_host,
                          expected_standby_host=lower_tor_host,
                          skip_tunnel_route=False)

    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(upper_tor_host, verify=True,
                                      stop_after=60, skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type,
                          skip_tunnel_route=False)


@pytest.mark.enable_active_active
def test_normal_op_downstream_upper_tor(upper_tor_host, lower_tor_host,             # noqa F811
                                        send_t1_to_server_with_action,              # noqa F811
                                        toggle_all_simulator_ports_to_upper_tor,    # noqa F811
                                        cable_type,                                 # noqa F811
                                        skip_traffic_test):                         # noqa F811
    """
    Send downstream traffic to the upper ToR and confirm no disruption or
    switchover occurs
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(upper_tor_host, verify=True,
                                      stop_after=60, skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=upper_tor_host,
                          expected_standby_host=lower_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(upper_tor_host, verify=True,
                                      stop_after=60, skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type)


@pytest.mark.enable_active_active
def test_normal_op_downstream_lower_tor(upper_tor_host, lower_tor_host,             # noqa F811
                                        send_t1_to_server_with_action,              # noqa F811
                                        toggle_all_simulator_ports_to_upper_tor,    # noqa F811
                                        cable_type,                                 # noqa F811
                                        skip_traffic_test):                         # noqa F811
    """
    Send downstream traffic to the lower ToR and confirm no disruption or
    switchover occurs
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(lower_tor_host, verify=True,
                                      stop_after=60, skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=upper_tor_host,
                          expected_standby_host=lower_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(lower_tor_host, verify=True,
                                      stop_after=60, skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type)


@pytest.mark.enable_active_active
def test_normal_op_active_server_to_active_server(upper_tor_host, lower_tor_host,               # noqa F811
                                                  send_server_to_server_with_action,            # noqa F811
                                                  toggle_all_simulator_ports_to_upper_tor,      # noqa F811
                                                  cable_type,                                   # noqa F811
                                                  select_test_mux_ports,                        # noqa F811
                                                  skip_traffic_test):                           # noqa F811
    """
    Send server to server traffic in active-active setup and confirm no disruption or switchover occurs.
    """

    test_mux_ports = select_test_mux_ports(cable_type, 2)

    if cable_type == CableType.active_standby:
        send_server_to_server_with_action(upper_tor_host, test_mux_ports, verify=True,
                                          stop_after=60, skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=upper_tor_host,
                          expected_standby_host=lower_tor_host,
                          skip_tunnel_route=False)

    if cable_type == CableType.active_active:
        send_server_to_server_with_action(upper_tor_host, test_mux_ports, verify=True,
                                          stop_after=60, skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type,
                          skip_tunnel_route=False)


@pytest.mark.enable_active_active
def test_normal_op_active_server_to_standby_server(upper_tor_host, lower_tor_host,                  # noqa F811
                                                   send_server_to_server_with_action,               # noqa F811
                                                   toggle_all_simulator_ports_to_upper_tor,         # noqa F811
                                                   cable_type, force_standby_tor,                   # noqa F811
                                                   select_test_mux_ports,                           # noqa F811
                                                   skip_traffic_test):                              # noqa F811
    """
    Send server to server traffic in active-standby setup and confirm no disruption or switchover occurs.
    """

    def _is_mux_port_standby(duthost, mux_port):
        return show_muxcable_status(duthost)[mux_port]["status"] == "standby"

    test_mux_ports = select_test_mux_ports(cable_type, 2)

    tx_mux_port = test_mux_ports[1]
    force_standby_tor(upper_tor_host, [tx_mux_port])
    pytest_assert(wait_until(10, 2, 0, _is_mux_port_standby, upper_tor_host, tx_mux_port),
                  "failed to toggle mux port %s to standby on DUT %s" % (tx_mux_port, upper_tor_host.hostname))

    if cable_type == CableType.active_standby:
        send_server_to_server_with_action(upper_tor_host, test_mux_ports, verify=True,
                                          stop_after=60, skip_traffic_test=skip_traffic_test)

    if cable_type == CableType.active_active:
        send_server_to_server_with_action(upper_tor_host, test_mux_ports, verify=True,
                                          stop_after=60, skip_traffic_test=skip_traffic_test)

    # TODO: Add per-port db check


@pytest.mark.disable_loganalyzer
@pytest.mark.enable_active_active
def test_upper_tor_config_reload_upstream(upper_tor_host, lower_tor_host,               # noqa F811
                                          send_server_to_t1_with_action,                # noqa F811
                                          toggle_all_simulator_ports_to_upper_tor,      # noqa F811
                                          cable_type,                                   # noqa F811
                                          skip_traffic_test):                           # noqa F811
    """
    Send upstream traffic and `config reload` the active ToR.
    Confirm switchover occurs and disruption lasted < 1 second for active-standby ports.
    Confirm both ToRs in active after config reload and no disruption for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(upper_tor_host, verify=True, delay=CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC,
                                      action=lambda: config_reload(upper_tor_host, wait=0),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=lower_tor_host,
                          expected_standby_host=upper_tor_host)

    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                      action=lambda: config_reload(upper_tor_host, wait=0),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type)


@pytest.mark.disable_loganalyzer
def test_lower_tor_config_reload_upstream(upper_tor_host, lower_tor_host,               # noqa F811
                                          send_server_to_t1_with_action,                # noqa F811
                                          toggle_all_simulator_ports_to_upper_tor,      # noqa F811
                                          cable_type,                                   # noqa F811
                                          skip_traffic_test):                           # noqa F811
    """
    Send upstream traffic and `config reload` the lower ToR.
    Confirm no switchover occurs and no disruption.
    """
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(upper_tor_host, verify=True,
                                      action=lambda: config_reload(lower_tor_host, wait=0),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=upper_tor_host,
                          expected_standby_host=lower_tor_host)


@pytest.mark.disable_loganalyzer
@pytest.mark.enable_active_active
def test_lower_tor_config_reload_downstream_upper_tor(upper_tor_host, lower_tor_host,           # noqa F811
                                                      send_t1_to_server_with_action,            # noqa F811
                                                      toggle_all_simulator_ports_to_upper_tor,  # noqa F811
                                                      cable_type,                               # noqa F811
                                                      skip_traffic_test):                       # noqa F811
    """
    Send downstream traffic to the upper ToR and `config reload` the lower ToR.
    Confirm no switchover occurs and no disruption
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(upper_tor_host, verify=True,
                                      action=lambda: config_reload(lower_tor_host, wait=0),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=upper_tor_host,
                          expected_standby_host=lower_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(upper_tor_host, verify=True,
                                      action=lambda: config_reload(lower_tor_host, wait=0),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type)


@pytest.mark.disable_loganalyzer
def test_upper_tor_config_reload_downstream_lower_tor(upper_tor_host, lower_tor_host,           # noqa F811
                                                      send_t1_to_server_with_action,            # noqa F811
                                                      toggle_all_simulator_ports_to_upper_tor,  # noqa F811
                                                      cable_type,                               # noqa F811
                                                      skip_traffic_test):                       # noqa F811
    """
    Send downstream traffic to the lower ToR and `config reload` the upper ToR.
    Confirm switchover occurs and disruption lasts < 1 second for active-standby ports.
    Confirm no state change in the end and no disruption for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(lower_tor_host, verify=True, delay=CONFIG_RELOAD_ALLOWED_DISRUPTION_SEC,
                                      action=lambda: config_reload(upper_tor_host, wait=0),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=lower_tor_host,
                          expected_standby_host=upper_tor_host)


@pytest.mark.enable_active_active
def test_tor_switch_upstream(upper_tor_host, lower_tor_host,                # noqa F811
                             send_server_to_t1_with_action,                 # noqa F811
                             toggle_all_simulator_ports_to_upper_tor,       # noqa F811
                             force_active_tor, force_standby_tor,           # noqa F811
                             cable_type,                                    # noqa F811
                             skip_traffic_test):                            # noqa F811
    """
    Send upstream traffic and perform switchover via CLI.
    Confirm switchover occurs and disruption lasts < 1 second for active-standby ports.
    Confirm switchover occurs and no disruption for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_server_to_t1_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                      action=lambda: force_active_tor(lower_tor_host, 'all'),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=lower_tor_host,
                          expected_standby_host=upper_tor_host)

    if cable_type == CableType.active_active:
        send_server_to_t1_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                      action=lambda: force_standby_tor(upper_tor_host, 'all'),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=lower_tor_host,
                          expected_standby_host=upper_tor_host,
                          expected_standby_health="healthy",
                          cable_type=cable_type)


@pytest.mark.enable_active_active
def test_tor_switch_downstream_active(upper_tor_host, lower_tor_host,               # noqa F811
                                      send_t1_to_server_with_action,                # noqa F811
                                      toggle_all_simulator_ports_to_upper_tor,      # noqa F811
                                      force_active_tor, force_standby_tor,          # noqa F811
                                      cable_type,                                   # noqa F811
                                      skip_traffic_test):                           # noqa F811
    """
    Send downstream traffic to the upper ToR and perform switchover via CLI.
    Confirm switchover occurs and disruption lasts < 1 second for active-standby ports.
    Confirm switchover occurs and disruption lasts < 1 second for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                      action=lambda: force_active_tor(lower_tor_host, 'all'),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=lower_tor_host,
                          expected_standby_host=upper_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(upper_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                      action=lambda: force_standby_tor(upper_tor_host, 'all'),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=lower_tor_host,
                          expected_standby_host=upper_tor_host,
                          expected_standby_health="healthy",
                          cable_type=cable_type)


@pytest.mark.enable_active_active
def test_tor_switch_downstream_standby(upper_tor_host, lower_tor_host,              # noqa F811
                                       send_t1_to_server_with_action,               # noqa F811
                                       toggle_all_simulator_ports_to_upper_tor,     # noqa F811
                                       force_active_tor, force_standby_tor,         # noqa F811
                                       cable_type,                                  # noqa F811
                                       skip_traffic_test):                          # noqa F811
    """
    Send downstream traffic to the lower ToR and perform switchover via CLI.
    Confirm switchover occurs and disruption lasts < 1 second for active-standby ports.
    Confirm switchover occurs and no disruption for active-active ports.
    """
    if cable_type == CableType.active_standby:
        send_t1_to_server_with_action(lower_tor_host, verify=True, delay=MUX_SIM_ALLOWED_DISRUPTION_SEC,
                                      action=lambda: force_active_tor(lower_tor_host, 'all'),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=lower_tor_host,
                          expected_standby_host=upper_tor_host)

    if cable_type == CableType.active_active:
        send_t1_to_server_with_action(lower_tor_host, verify=True,
                                      action=lambda: force_standby_tor(upper_tor_host, 'all'),
                                      skip_traffic_test=skip_traffic_test)
        verify_tor_states(expected_active_host=lower_tor_host,
                          expected_standby_host=upper_tor_host,
                          expected_standby_health="healthy",
                          cable_type=cable_type)


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_mux_port_switch_active_server_to_active_server(upper_tor_host, lower_tor_host,                 # noqa F811
                                                        send_server_to_server_with_action,              # noqa F811
                                                        cable_type, force_standby_tor,                  # noqa F811
                                                        select_test_mux_ports):                         # noqa F811
    """
    Send server to server traffic in active-active setup and config the tx mux port to standby.
    Confirm switchover occurs and no disruption.
    """

    def _is_mux_port_standby(duthost, mux_port):
        return show_muxcable_status(duthost)[mux_port]["status"] == "standby"

    if cable_type == CableType.active_active:
        test_mux_ports = select_test_mux_ports(cable_type, 2)
        tx_mux_port = test_mux_ports[1]

        send_server_to_server_with_action(upper_tor_host, test_mux_ports, verify=True,
                                          action=lambda: force_standby_tor(upper_tor_host, [tx_mux_port]),
                                          send_interval=0.0035,
                                          stop_after=60,)

        pytest_assert(_is_mux_port_standby(upper_tor_host, tx_mux_port),
                      "mux port %s on DUT %s failed to toggle to standby" % (upper_tor_host.hostname, tx_mux_port))

        # TODO: Add per-port db check


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_mux_port_switch_active_server_to_standby_server(upper_tor_host, lower_tor_host,                 # noqa F811
                                                         send_server_to_server_with_action,              # noqa F811
                                                         cable_type, force_standby_tor,                  # noqa F811
                                                         force_active_tor,                              # noqa F811
                                                         select_test_mux_ports):                         # noqa F811
    """
    Send server to server traffic in active-standby setup and config the tx mux port to auto.
    Confirm switchover occurs and no disruption.
    """

    def _is_mux_port_standby(duthost, mux_port):
        return show_muxcable_status(duthost)[mux_port]["status"] == "standby"

    def _is_mux_port_active(duthost, mux_port):
        return show_muxcable_status(duthost)[mux_port]["status"] == "active"

    if cable_type == CableType.active_active:
        test_mux_ports = select_test_mux_ports(cable_type, 2)
        tx_mux_port = test_mux_ports[1]
        force_standby_tor(upper_tor_host, [tx_mux_port])
        pytest_assert(wait_until(10, 2, 0, _is_mux_port_standby, upper_tor_host, tx_mux_port),
                      "failed to toggle mux port %s to standby on DUT %s" % (tx_mux_port, upper_tor_host.hostname))

        send_server_to_server_with_action(upper_tor_host, test_mux_ports, verify=True,
                                          action=lambda: force_active_tor(upper_tor_host, [tx_mux_port]),
                                          send_interval=0.0035,
                                          stop_after=60)

        pytest_assert(_is_mux_port_active(upper_tor_host, tx_mux_port),
                      "mux port %s on DUT %s failed to toggle back to active" % (upper_tor_host.hostname, tx_mux_port))

        # TODO: Add per-port db check


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_normal_op_upstream_soc(upper_tor_host, lower_tor_host,             # noqa F811
                                send_soc_to_t1_with_action, cable_type):    # noqa F811
    """Send upstream traffic and confirm no disruption or switchover occurs"""
    if cable_type == CableType.active_active:
        send_soc_to_t1_with_action(upper_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type)


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_normal_op_downstream_upper_tor_soc(upper_tor_host, lower_tor_host,             # noqa F811
                                            send_t1_to_soc_with_action, cable_type):    # noqa F811
    """
    Send downstream traffic to the upper ToR and confirm no disruption or
    switchover occurs
    """
    if cable_type == CableType.active_active:
        send_t1_to_soc_with_action(upper_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type)


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_normal_op_downstream_lower_tor_soc(upper_tor_host, lower_tor_host,             # noqa F811
                                            send_t1_to_soc_with_action, cable_type):    # noqa F811
    """
    Send downstream traffic to the lower ToR and confirm no disruption or
    switchover occurs
    """
    if cable_type == CableType.active_active:
        send_t1_to_soc_with_action(lower_tor_host, verify=True, stop_after=60)
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None,
                          cable_type=cable_type)
