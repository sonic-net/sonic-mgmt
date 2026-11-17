import ast
import logging
import os
import pytest
import random

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.dual_tor_common import active_standby_ports                                       # noqa: F401
from tests.common.dualtor.dual_tor_utils import show_muxcable_status
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_unselected_tor    # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                                          # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_utils import check_container_state
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(simulated_faulty_side, loganalyzer):
    """Ignore the pmon error."""
    error_str = [
        ".*Could not establish the active side for Y cable port.*"
    ]
    if loganalyzer:  # Skip if loganalyzer is disabled
        loganalyzer[simulated_faulty_side.hostname].ignore_regex.extend(error_str)


@pytest.fixture(scope="module")
def simulated_faulty_side(rand_unselected_dut):
    return rand_unselected_dut


@pytest.fixture(scope="module")
def simulated_good_side(rand_selected_dut):
    return rand_selected_dut


@pytest.fixture
def setup_faulted_y_cable_driver(
    simulated_faulty_side, simulated_good_side, active_standby_ports,  # noqa: F811
    run_icmp_responder, toggle_all_simulator_ports_to_rand_unselected_tor,  # noqa: F811
    simulate_probe_unknown, simulate_peer_link_down
):
    """Set up the faulted Y-cable driver and yield the selected mux port."""
    pytest_require(active_standby_ports, "No active-standby mux ports, skip...")
    select_mux_port = random.choice(active_standby_ports)

    def _remove_pmon_container(duthost):
        logging.info("Stopping pmon container.")
        duthost.shell("systemctl stop pmon.service")
        logging.info("pmon container is stopped.")

        logging.info("Removing pmon container.")
        duthost.shell("docker rm pmon")
        logging.info("pmon container is removed.")

    def _restart_pmon_container(duthost):
        logging.info("Resetting pmon status.")
        logging.info("systemctl reset-failed pmon.service")
        logging.info("Restarting pmon container ...")
        duthost.shell("systemctl restart pmon.service")

    y_cable_simulated_path = None
    try:
        extra_vars = {
            "SIMULATE_PROBE_UNKNOWN": simulate_probe_unknown,
            "SIMULATE_PEER_LINK_DOWN": simulate_peer_link_down
        }
        simulated_faulty_side.host.options['variable_manager'].extra_vars.update(
            extra_vars)
        simulated_faulty_side.template(
            src="dualtor/files/y_cable_simulated.py.j2",
            dest="/tmp/y_cable_simulated.py",
            force=True
        )
        find_path_res = simulated_faulty_side.shell(
            "docker exec pmon find / -name y_cable_simulated.py 2>/dev/null", module_ignore_errors=True)["stdout"]
        # Let's check the file exist before patching
        simulated_faulty_side.shell("docker exec pmon stat %s" % find_path_res)
        y_cable_simulated_path = os.path.dirname(find_path_res)
        simulated_faulty_side.shell(
            "docker exec pmon mv {path}/y_cable_simulated.py {path}/y_cable_simulated.py.orig".format(
                path=y_cable_simulated_path
            )
        )
        simulated_faulty_side.shell(
            "docker cp /tmp/y_cable_simulated.py pmon:%s/" % y_cable_simulated_path)
        simulated_faulty_side.shell(
            "docker exec pmon supervisorctl restart ycabled")
        pytest_assert(_wait_for_ycabled_startup(simulated_faulty_side),
                      "Failed to start ycabled on {}".format(simulated_faulty_side.hostname))
        yield select_mux_port
    finally:
        if y_cable_simulated_path:
            simulated_faulty_side.shell(
                "docker exec pmon mv {path}/y_cable_simulated.py.orig {path}/y_cable_simulated.py".format(
                    path=y_cable_simulated_path
                )
            )
        simulated_faulty_side.shell(
            "docker exec pmon supervisorctl restart ycabled")
        if not _wait_for_recovery(simulated_faulty_side, simulated_good_side, select_mux_port, active_standby_ports):
            logging.warning("Y-cable or mux health did not recover; recreating PMON on %s",
                            simulated_faulty_side.hostname)
            _remove_pmon_container(simulated_faulty_side)
            _restart_pmon_container(simulated_faulty_side)

            logging.info("Waiting for PMON to start ...")
            restarted = wait_until(
                60, 5, 0, check_container_state, simulated_faulty_side, "pmon", True)
            pytest_assert(restarted, "Failed to start PMON on {}".format(simulated_faulty_side.hostname))
            logging.info("PMON is running.")
            pytest_assert(
                _wait_for_recovery(simulated_faulty_side, simulated_good_side, select_mux_port, active_standby_ports),
                "Failed to recover Y-cable state or mux health after PMON recovery")


def get_tor_mux_status(duthost, mux_port):
    """Get the target ToR mux status."""
    res = duthost.show_and_parse("show muxcable status %s" % mux_port)
    if res:
        return res[0]["status"]
    return None


def get_tor_mux_probe_state(duthost, mux_port):
    """Get the target ToR mux probe response state."""
    return duthost.shell("sonic-db-cli APPL_DB hget MUX_CABLE_RESPONSE_TABLE:%s response" % mux_port)["stdout"]


def get_tor_mux_cable_info(duthost, mux_port):
    """Get the target ToR mux port info."""
    return ast.literal_eval(duthost.shell("sonic-db-cli STATE_DB hgetall \"MUX_CABLE_INFO|%s\"" % mux_port)["stdout"])


def _wait_for_ycabled_startup(duthost):
    return wait_until(60, 5, 0, lambda: duthost.get_pmon_daemon_status("ycabled")[0] == "RUNNING")


def _wait_for_recovery(faulty_side, good_side, mux_port, ports):
    if not _wait_for_ycabled_startup(faulty_side):
        logging.warning("ycabled did not reach RUNNING on %s", faulty_side.hostname)
        return False

    def _check_fault_cleared():
        return (get_tor_mux_probe_state(faulty_side, mux_port) in ("active", "standby") and
                get_tor_mux_cable_info(faulty_side, mux_port).get("link_status_peer") == "up")

    def _check_mux_ports_healthy():
        for duthost in (faulty_side, good_side):
            mux_status = show_muxcable_status(duthost)
            for port in ports:
                if port not in mux_status:
                    logging.debug("MUX status is missing on %s %s", duthost.hostname, port)
                    return False
                if mux_status[port]["health"] != "healthy" or mux_status[port]["hwstatus"] != "consistent":
                    logging.debug("MUX status has not recovered on %s %s: %s", duthost.hostname, port, mux_status[port])
                    return False
        return True

    # ycabled is RUNNING, but as of 2026-11-17 its info worker waits 60s
    # after worker startup (following daemon initialization) before its first periodic refresh.
    return (wait_until(90, 10, 0, _check_fault_cleared) and
            wait_until(120, 10, 0, _check_mux_ports_healthy))


@pytest.mark.parametrize("simulate_probe_unknown, simulate_peer_link_down", [(True, False)])
def test_switchover_probe_unknown(
    simulated_good_side,
    simulated_faulty_side,
    setup_faulted_y_cable_driver
):
    select_mux_port = setup_faulted_y_cable_driver
    logging.info("Use mux port %s to test", select_mux_port)
    # ensure that no switchover after the ycabled restart
    pytest_assert(get_tor_mux_status(
        simulated_faulty_side, select_mux_port) == "active")
    pytest_assert(get_tor_mux_status(
        simulated_good_side, select_mux_port) == "standby")

    try:
        logging.info("Toggle to active via cli on %s", simulated_good_side)
        simulated_good_side.shell("config mux mode active %s" % select_mux_port)
        # With the faulty ycable driver returning mux unknown, the unselected ToR is still
        # able to honor the mux toggle requested by the selected ToR.
        verify_tor_states(simulated_good_side,
                          simulated_faulty_side, intf_names=[select_mux_port])
        pytest_assert(get_tor_mux_probe_state(
            simulated_faulty_side, select_mux_port) == "unknown")
    finally:
        simulated_good_side.shell("config mux mode auto all")


@pytest.mark.parametrize("simulate_probe_unknown, simulate_peer_link_down", [(False, True)])
def test_switchover_peer_link_down(
    simulated_good_side,
    simulated_faulty_side,
    setup_faulted_y_cable_driver
):
    select_mux_port = setup_faulted_y_cable_driver
    logging.info("Use mux port %s to test", select_mux_port)
    # ensure that no switchover after the ycabled restart
    pytest_assert(get_tor_mux_status(
        simulated_faulty_side, select_mux_port) == "active")
    pytest_assert(get_tor_mux_status(
        simulated_good_side, select_mux_port) == "standby")

    try:
        logging.info("Toggle to active via cli on %s", simulated_good_side)
        simulated_good_side.shell("config mux mode active %s" % select_mux_port)
        # With the faulty ycable driver returning peer link down, the unselected ToR will try
        # toggle back as the peer link is down. And as the ycabled polls the link status every
        # 60s, let's wait for 90 seconds here.
        verify_tor_states(simulated_faulty_side, simulated_good_side, intf_names=[
                          select_mux_port], verify_db_timeout=90)
        pytest_assert(get_tor_mux_cable_info(simulated_faulty_side, select_mux_port)[
                      "link_status_peer"] == "down")
    finally:
        simulated_good_side.shell("config mux mode auto all")
