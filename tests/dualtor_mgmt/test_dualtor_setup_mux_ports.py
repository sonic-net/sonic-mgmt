"""Test script to verify the test infrastructure mux port setup functionality."""
import logging
import json
import pytest

from tests.common.dualtor.dual_tor_common import active_active_ports                                        # noqa: F401
from tests.common.dualtor.dual_tor_common import active_standby_ports                                       # noqa: F401
from tests.common.dualtor.dual_tor_common import cable_type                                                 # noqa: F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host                                              # noqa: F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                                              # noqa: F401
from tests.common.dualtor.dual_tor_utils import show_muxcable_status
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor      # noqa: F401
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology("dualtor")
]


def check_target_dut_mux_port_status(duthost, ports, status):
    logging.debug("Check mux status for ports %s is %s", ports, status)
    show_mux_status_ret = show_muxcable_status(duthost)
    logging.debug("show mux status ret: %s",
                  json.dumps(show_mux_status_ret, indent=4))
    for port in ports:
        if port not in show_mux_status_ret:
            return False
        elif show_mux_status_ret[port]['status'] != status:
            return False
    return True


def check_target_dut_mux_port_config(duthost, ports, config):
    def show_muxcable_config(duthost):
        """
        Show muxcable config and parse into a dict
        """
        command = "show muxcable config --json"
        output = json.loads(duthost.shell(command)["stdout"])
        return output["MUX_CABLE"]["PORTS"]

    logging.debug("Check mux config for ports %s is %s", ports, config)
    mux_configs = show_muxcable_config(duthost)
    logging.debug("show mux config ret: %s", json.dumps(mux_configs, indent=4))
    for port in ports:
        if port not in mux_configs or mux_configs[port]["STATE"] != config:
            return False
    return True


@pytest.mark.dualtor_skip_setup_mux_ports
def tet_dualtor_setup_marker_skip(setup_dualtor_mux_ports):
    """Verify setup_dualtor_mux_ports fixture is skipped."""
    pytest_assert(not setup_dualtor_mux_ports)


def test_dualtor_setup_random_duthost_with_custom_toggle_fixture(
    active_standby_ports, cable_type, rand_selected_dut, rand_unselected_dut,                               # noqa:F811
    setup_dualtor_mux_ports, toggle_all_simulator_ports_to_rand_selected_tor                                # noqa:F811
):
    """Verify setup_dualtor_mux_ports does nothing if test function has a custom toggle fixture."""
    pytest_assert(not setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(rand_selected_dut, active_standby_ports, "active"),
                  "%s mux ports are not active" % rand_selected_dut.hostname)
    pytest_assert(check_target_dut_mux_port_status(rand_unselected_dut, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % rand_unselected_dut.hostname)


def test_dualtor_setup_enum_duthost(cable_type, duthosts, enum_frontend_dut_hostname,                       # noqa:F811
                                    setup_dualtor_mux_ports):
    """Verify setup_dualtor_mux_ports is skipped if duthost is enumerated."""
    pytest_assert(not setup_dualtor_mux_ports)


def test_dualtor_setup_random_duthost(active_standby_ports, cable_type,                                     # noqa:F811
                                      rand_selected_dut, rand_unselected_dut,
                                      setup_dualtor_mux_ports):
    """Verify setup_dualtor_mux_ports toggles mux ports to the rand_selected_dut."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(rand_selected_dut, active_standby_ports, "active"),
                  "%s mux ports are not active" % rand_selected_dut.hostname)
    pytest_assert(check_target_dut_mux_port_status(rand_unselected_dut, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % rand_unselected_dut.hostname)


def test_dualtor_setup_duthost(active_standby_ports, cable_type, duthosts, duthost,                         # noqa:F811
                               setup_dualtor_mux_ports):
    """Verify setup_dualtor_mux_ports toggles mux ports to the duthost."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(duthost, active_standby_ports, "active"),
                  "%s mux ports are not active" % duthost.hostname)
    standby_dut = [_ for _ in duthosts if _.hostname != duthost.hostname][0]
    pytest_assert(check_target_dut_mux_port_status(standby_dut, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % standby_dut.hostname)


def test_dualtor_setup_no_specified_duthost(active_standby_ports, cable_type,                               # noqa:F811
                                            upper_tor_host, lower_tor_host,                                 # noqa:F811
                                            setup_dualtor_mux_ports):
    """Verify setup_dualtor_mux_ports toggles mux ports to the upper ToR by default."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(upper_tor_host, active_standby_ports, "active"),
                  "%s mux ports are not active" % upper_tor_host.hostname)
    pytest_assert(check_target_dut_mux_port_status(lower_tor_host, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % lower_tor_host.hostname)


@pytest.mark.dualtor_active_standby_toggle_to_enum_tor_manual_mode
def test_dualtor_setup_marker_toggle_to_enum_manual_mode(active_standby_ports, cable_type,                  # noqa:F811
                                                         duthosts, enum_frontend_dut_hostname,
                                                         setup_dualtor_mux_ports):
    """Verify setup_dualtor_mux_ports toggle to enum marker."""
    pytest_assert(setup_dualtor_mux_ports)
    active_dut = duthosts[enum_frontend_dut_hostname]
    pytest_assert(check_target_dut_mux_port_status(active_dut, active_standby_ports, "active"),
                  "%s mux ports are not active" % enum_frontend_dut_hostname)
    standby_dut = [_ for _ in duthosts if _.hostname != enum_frontend_dut_hostname][0]
    pytest_assert(check_target_dut_mux_port_status(standby_dut, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % standby_dut.hostname)
    pytest_assert(all(check_target_dut_mux_port_config(_, active_standby_ports, "manual") for _ in duthosts),
                  "All mux ports should be in manual mode")


@pytest.mark.dualtor_active_standby_toggle_to_upper_tor_manual_mode
def test_dualtor_setup_marker_toggle_to_upper_manual_mode(active_standby_ports, cable_type,                 # noqa:F811
                                                          duthosts, setup_dualtor_mux_ports,
                                                          upper_tor_host, lower_tor_host):                  # noqa:F811
    """Verify setup_dualtor_mux_ports toggle to upper marker."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(upper_tor_host, active_standby_ports, "active"),
                  "%s mux ports are not active" % upper_tor_host.hostname)
    pytest_assert(check_target_dut_mux_port_status(lower_tor_host, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % lower_tor_host.hostname)
    pytest_assert(all(check_target_dut_mux_port_config(_, active_standby_ports, "manual") for _ in duthosts),
                  "All mux ports should be in manual mode")


@pytest.mark.dualtor_active_standby_toggle_to_lower_tor_manual_mode
def test_dualtor_setup_marker_toggle_to_lower_manual_mode(active_standby_ports, cable_type,                 # noqa:F811
                                                          duthosts, setup_dualtor_mux_ports,
                                                          upper_tor_host, lower_tor_host):                  # noqa:F811
    """Verify setup_dualtor_mux_ports toggle to lower marker."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(lower_tor_host, active_standby_ports, "active"),
                  "%s mux ports are not active" % lower_tor_host.hostname)
    pytest_assert(check_target_dut_mux_port_status(upper_tor_host, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % upper_tor_host.hostname)
    pytest_assert(all(check_target_dut_mux_port_config(_, active_standby_ports, "manual") for _ in duthosts),
                  "All mux ports should be in manual mode")


@pytest.mark.dualtor_active_standby_toggle_to_random_tor_manual_mode
def test_dualtor_setup_marker_toggle_to_random_manual_mode(active_standby_ports, cable_type,                # noqa:F811
                                                           rand_selected_dut, rand_unselected_dut,
                                                           duthosts, setup_dualtor_mux_ports):
    """Verify setup_dualtor_mux_ports toggle to random marker."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(rand_selected_dut, active_standby_ports, "active"),
                  "%s mux ports are not active" % rand_selected_dut.hostname)
    pytest_assert(check_target_dut_mux_port_status(rand_unselected_dut, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % rand_unselected_dut.hostname)
    pytest_assert(all(check_target_dut_mux_port_config(_, active_standby_ports, "manual") for _ in duthosts),
                  "All mux ports should be in manual mode")


@pytest.mark.dualtor_active_standby_toggle_to_random_unselected_tor_manual_mode
def test_dualtor_setup_marker_toggle_to_random_unselected_manual_mode(active_standby_ports, cable_type,     # noqa:F811
                                                                      rand_selected_dut, rand_unselected_dut,
                                                                      duthosts, setup_dualtor_mux_ports):
    """Verify setup_dualtor_mux_ports toggle to random unselected marker."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(rand_unselected_dut, active_standby_ports, "active"),
                  "%s mux ports are not active" % rand_unselected_dut.hostname)
    pytest_assert(check_target_dut_mux_port_status(rand_selected_dut, active_standby_ports, "standby"),
                  "%s mux ports are not standby" % rand_selected_dut.hostname)
    pytest_assert(all(check_target_dut_mux_port_config(_, active_standby_ports, "manual") for _ in duthosts),
                  "All mux ports should be in manual mode")


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_dualtor_active_active_default_behavior(active_active_ports, cable_type, duthosts,                  # noqa:F811
                                                upper_tor_host, lower_tor_host, setup_dualtor_mux_ports):   # noqa:F811
    """Verify setup_dualtor_mux_ports is skipped for active-active dualtor by default."""
    pytest_assert(not setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(upper_tor_host, active_active_ports, "active"),
                  "%s mux ports are not active" % upper_tor_host.hostname)
    pytest_assert(check_target_dut_mux_port_status(lower_tor_host, active_active_ports, "active"),
                  "%s mux ports are not active" % lower_tor_host.hostname)
    pytest_assert(all(check_target_dut_mux_port_config(_, active_active_ports, "auto") for _ in duthosts),
                  "All mux ports should be in manual mode")


@pytest.mark.dualtor_active_active_setup_standby_on_enum_tor_manual_mode
@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_dualtor_setup_marker_standby_on_enum_manual_mode(active_active_ports, cable_type, duthosts,        # noqa:F811
                                                          enum_frontend_dut_hostname, setup_dualtor_mux_ports):
    """Verify dualtor_active_active_setup_standby_on_enum_tor marker."""
    pytest_assert(setup_dualtor_mux_ports)
    standby_dut = duthosts[enum_frontend_dut_hostname]
    pytest_assert(check_target_dut_mux_port_status(standby_dut, active_active_ports, "standby"),
                  "%s mux ports are not standby" % enum_frontend_dut_hostname)
    active_dut = [_ for _ in duthosts if _.hostname !=
                  enum_frontend_dut_hostname][0]
    pytest_assert(check_target_dut_mux_port_status(active_dut, active_active_ports, "active"),
                  "%s mux ports are not active" % active_dut.hostname)

    pytest_assert(check_target_dut_mux_port_config(active_dut, active_active_ports, "manual"))
    pytest_assert(check_target_dut_mux_port_config(standby_dut, active_active_ports, "manual"))


@pytest.mark.dualtor_active_active_setup_standby_on_upper_tor_manual_mode
@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_dualtor_setup_marker_standby_on_upper_manual_mode(active_active_ports, cable_type,                 # noqa:F811
                                                           setup_dualtor_mux_ports,
                                                           upper_tor_host, lower_tor_host):                 # noqa:F811
    """Verify dualtor_active_active_setup_standby_on_upper_tor marker."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(upper_tor_host, active_active_ports, "standby"),
                  "%s mux ports are not standby" % upper_tor_host.hostname)
    pytest_assert(check_target_dut_mux_port_status(lower_tor_host, active_active_ports, "active"),
                  "%s mux ports are not active" % lower_tor_host.hostname)

    pytest_assert(check_target_dut_mux_port_config(lower_tor_host, active_active_ports, "manual"))
    pytest_assert(check_target_dut_mux_port_config(upper_tor_host, active_active_ports, "manual"))


@pytest.mark.dualtor_active_active_setup_standby_on_lower_tor_manual_mode
@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_dualtor_setup_marker_standby_on_lower_manual_mode(active_active_ports, cable_type,                 # noqa:F811
                                                           setup_dualtor_mux_ports,
                                                           upper_tor_host, lower_tor_host):                 # noqa:F811
    """Verify dualtor_active_active_setup_standby_on_lower_tor marker."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(lower_tor_host, active_active_ports, "standby"),
                  "%s mux ports are not standby" % lower_tor_host.hostname)
    pytest_assert(check_target_dut_mux_port_status(upper_tor_host, active_active_ports, "active"),
                  "%s mux ports are not active" % upper_tor_host.hostname)

    pytest_assert(check_target_dut_mux_port_config(upper_tor_host, active_active_ports, "manual"))
    pytest_assert(check_target_dut_mux_port_config(lower_tor_host, active_active_ports, "manual"))


@pytest.mark.dualtor_active_active_setup_standby_on_random_tor_manual_mode
@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_dualtor_setup_marker_standby_on_random_manual_mode(active_active_ports, cable_type,                # noqa:F811
                                                            setup_dualtor_mux_ports,
                                                            rand_selected_dut, rand_unselected_dut):
    """Verify dualtor_active_active_setup_standby_on_random_tor marker."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(rand_selected_dut, active_active_ports, "standby"),
                  "%s mux ports are not standby" % rand_selected_dut.hostname)
    pytest_assert(check_target_dut_mux_port_status(rand_unselected_dut, active_active_ports, "active"),
                  "%s mux ports are not active" % rand_unselected_dut.hostname)

    pytest_assert(check_target_dut_mux_port_config(rand_unselected_dut, active_active_ports, "manual"))
    pytest_assert(check_target_dut_mux_port_config(rand_selected_dut, active_active_ports, "manual"))


@pytest.mark.dualtor_active_active_setup_standby_on_random_unselected_tor_manual_mode
@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_dualtor_setup_marker_standby_on_random_unselected_manual_mode(active_active_ports, cable_type,     # noqa:F811
                                                                       setup_dualtor_mux_ports,
                                                                       rand_selected_dut, rand_unselected_dut):
    """Verify dualtor_active_active_setup_standby_on_random_unselected_tor marker."""
    pytest_assert(setup_dualtor_mux_ports)
    pytest_assert(check_target_dut_mux_port_status(rand_unselected_dut, active_active_ports, "standby"),
                  "%s mux ports are not standby" % rand_unselected_dut.hostname)
    pytest_assert(check_target_dut_mux_port_status(rand_selected_dut, active_active_ports, "active"),
                  "%s mux ports are not active" % rand_selected_dut.hostname)

    pytest_assert(check_target_dut_mux_port_config(rand_selected_dut, active_active_ports, "manual"))
    pytest_assert(check_target_dut_mux_port_config(rand_unselected_dut, active_active_ports, "manual"))


@pytest.mark.dualtor_active_standby_toggle_to_upper_tor
@pytest.mark.dualtor_active_active_setup_standby_on_lower_tor
def test_example(active_active_ports, active_standby_ports, tbinfo,                                         # noqa:F811
                 upper_tor_host, lower_tor_host, setup_dualtor_mux_ports):                                  # noqa:F811
    """Example case to demonstrate how to use the active-active/active-standby dualtor markers."""
    pytest_assert(setup_dualtor_mux_ports)
    is_dualtor_aa = "dualtor-aa" in tbinfo["topo"]["name"]
    if is_dualtor_aa:
        mux_ports = active_active_ports
        expected_active_side_mux_mode = "auto"
        expected_standby_side_mux_mode = "standby"
    else:
        mux_ports = active_standby_ports
        expected_active_side_mux_mode = "auto"
        expected_standby_side_mux_mode = "auto"
    pytest_assert(check_target_dut_mux_port_status(upper_tor_host, mux_ports, "active"))
    pytest_assert(check_target_dut_mux_port_status(lower_tor_host, mux_ports, "standby"))
    pytest_assert(check_target_dut_mux_port_config(upper_tor_host, mux_ports, expected_active_side_mux_mode))
    pytest_assert(check_target_dut_mux_port_config(lower_tor_host, mux_ports, expected_standby_side_mux_mode))


@pytest.mark.dualtor_active_standby_toggle_to_upper_tor_manual_mode
@pytest.mark.dualtor_active_active_setup_standby_on_lower_tor_manual_mode
def test_example_with_manual(active_active_ports, active_standby_ports, tbinfo,                             # noqa:F811
                             upper_tor_host, lower_tor_host, setup_dualtor_mux_ports):                      # noqa:F811
    """Example case to demonstrate how to use the active-active/active-standby dualtor markers."""
    pytest_assert(setup_dualtor_mux_ports)
    is_dualtor_aa = "dualtor-aa" in tbinfo["topo"]["name"]
    if is_dualtor_aa:
        mux_ports = active_active_ports
    else:
        mux_ports = active_standby_ports
    pytest_assert(check_target_dut_mux_port_status(upper_tor_host, mux_ports, "active"))
    pytest_assert(check_target_dut_mux_port_status(lower_tor_host, mux_ports, "standby"))
    pytest_assert(check_target_dut_mux_port_config(upper_tor_host, mux_ports, "manual"))
    pytest_assert(check_target_dut_mux_port_config(lower_tor_host, mux_ports, "manual"))
