import logging
import json
import pytest

from tests.common.dualtor.dual_tor_common import active_active_ports                                        # noqa: F401
from tests.common.dualtor.dual_tor_common import active_standby_ports                                       # noqa: F401
from tests.common.dualtor.dual_tor_common import cable_type                                                 # noqa: F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_utils import upper_tor_host                                              # noqa: F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                                              # noqa: F401
from tests.common.dualtor.dual_tor_utils import show_muxcable_status
from tests.common.dualtor.icmp_responder_control import shutdown_icmp_responder                             # noqa: F401
from tests.common.dualtor.icmp_responder_control import start_icmp_responder                                # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor              # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                                          # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.conftest import rand_selected_dut                                                                # noqa: F401


pytestmark = [
    pytest.mark.topology("dualtor")
]


LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 60,
    'diagnose': 100
}


@pytest.fixture
def loop_times(get_function_completeness_level):
    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'
    return LOOP_TIMES_LEVEL_MAP[normalized_level]


@pytest.fixture
def heartbeat_control(request, start_icmp_responder, shutdown_icmp_responder):                      # noqa: F811
    heartbeat = request.param
    if heartbeat == "off":
        shutdown_icmp_responder()

    yield heartbeat

    if heartbeat == "off":
        start_icmp_responder()


def check_mux_port_status_after_linkmgrd_restart(rand_selected_dut, ports, loop_times,              # noqa: F811
                                                 status=None, health=None):
    def _check_mux_port_status(duthost, ports, status, health):
        show_mux_status_ret = show_muxcable_status(duthost)
        logging.debug("show_mux_status_ret: {}".format(json.dumps(show_mux_status_ret, indent=4)))

        for port in ports:
            if port not in show_mux_status_ret:
                return False

            if health is None:
                # Active-Active case
                health = 'healthy' if status == 'active' else 'unhealthy'
                if show_mux_status_ret[port]['status'] != status:
                    logging.debug(f"Port {port} status-{show_mux_status_ret[port]['status']}, expected status-{status}")
                    return False

            if show_mux_status_ret[port]['health'] != health or show_mux_status_ret[port]['hwstatus'] != 'consistent':
                logging.debug(f"Port {port} health-{show_mux_status_ret[port]['health']}, expected health-{health};"
                              f"hwstatus-{show_mux_status_ret[port]['hwstatus']}, expected hwstatus-consistent")
                return False
        return True

    for _ in range(loop_times):
        rand_selected_dut.shell("docker exec mux supervisorctl restart linkmgrd")
        pytest_assert(wait_until(30, 5, 0, lambda: "RUNNING" in rand_selected_dut.
                                 command("docker exec mux supervisorctl status linkmgrd")
                                 ["stdout"]), "linkmgrd is not running after restart")
        pytest_assert(wait_until(120, 10, 0, _check_mux_port_status, rand_selected_dut, ports, status, health),
                      "MUX port status is not correct after linkmgrd restart")


@pytest.mark.enable_active_active
@pytest.mark.parametrize("heartbeat_control", ["on", "off"], indirect=True)
def test_dualtor_linkmgrd_restart_mux_port_status(cable_type, heartbeat_control, rand_selected_dut,   # noqa: F811
                                                  active_active_ports, active_standby_ports,          # noqa: F811
                                                  loop_times):
    """
    Test MUX port status on dual ToR after linkmgrd restart with heartbeat on/off

    Note: Skip mux status checking for active-standby case due to initialization timing issue.
          Only health and hwstatus are checked in this scenario.
    """
    ports = active_active_ports if cable_type == CableType.active_active else active_standby_ports

    # skip test if topology mismatch
    if not ports:
        pytest.skip(f'Skipping toggle on dualtor for cable_type={cable_type}.')

    # Check MUX port status after linkmgrd restart
    if cable_type == CableType.active_active:
        expected_status = 'active' if heartbeat_control == "on" else 'standby'
        check_mux_port_status_after_linkmgrd_restart(rand_selected_dut, ports, loop_times, expected_status)
    if cable_type == CableType.active_standby:  # active-standby
        health = 'healthy' if heartbeat_control == "on" else 'unhealthy'
        check_mux_port_status_after_linkmgrd_restart(rand_selected_dut, ports, loop_times,
                                                     status=None, health=health)
