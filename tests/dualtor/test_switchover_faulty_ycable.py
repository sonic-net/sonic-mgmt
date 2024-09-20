import ast
import contextlib
import logging
import os
import pytest
import random
import time

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.dual_tor_common import active_standby_ports                                       # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_unselected_tor    # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                                          # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.dut_utils import check_container_state
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]


@contextlib.contextmanager
def setup_faulted_y_cable_driver(rand_unselected_dut, simulate_probe_unknown=False, simulate_peer_link_down=False):
    """Setup the faulted Y cable driver on the active ToR."""
    try:
        extra_vars = {
            "SIMULATE_PROBE_UNKNOWN": simulate_probe_unknown,
            "SIMULATE_PEER_LINK_DOWN": simulate_peer_link_down
        }
        rand_unselected_dut.host.options['variable_manager'].extra_vars.update(
            extra_vars)
        rand_unselected_dut.template(
            src="dualtor/files/y_cable_simulated.py.j2",
            dest="/tmp/y_cable_simulated.py",
            force=True
        )
        find_path_res = rand_unselected_dut.shell(
            "docker exec pmon find / -name y_cable_simulated.py")["stdout"]
        # Let's check the file exist before patching
        rand_unselected_dut.shell("docker exec pmon stat %s" % find_path_res)
        y_cable_simulated_path = os.path.dirname(find_path_res)
        rand_unselected_dut.shell(
            "docker exec pmon mv {path}/y_cable_simulated.py {path}/y_cable_simulated.py.orig".format(
                path=y_cable_simulated_path
            )
        )
        rand_unselected_dut.shell(
            "docker cp /tmp/y_cable_simulated.py pmon:%s/" % y_cable_simulated_path)
        rand_unselected_dut.shell(
            "docker exec pmon supervisorctl restart ycabled")
        # Sleep 10 seconds for ycabled restart
        time.sleep(10)
        yield
    finally:
        rand_unselected_dut.shell(
            "docker exec pmon mv {path}/y_cable_simulated.py.orig {path}/y_cable_simulated.py".format(
                path=y_cable_simulated_path
            )
        )
        rand_unselected_dut.shell(
            "docker exec pmon supervisorctl restart ycabled")
        # Sleep 10 seconds for ycabled restart
        time.sleep(10)


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


@pytest.fixture(scope="module")
def select_mux_port(active_standby_ports):  # noqa: F811
    """Select an active-standby mux port to test."""
    pytest_require(active_standby_ports,
                   "No active-standby mux ports, skip...")
    return random.choice(active_standby_ports)


@pytest.fixture
def restore_pmon(rand_unselected_dut, select_mux_port):
    """Restore pmon container."""

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

        logging.info("Waiting for '{}' container to be restarted ...")
        restarted = wait_until(
            60, 5, 0, check_container_state, duthost, "pmon", True)
        pytest_assert(restarted, "Failed to restart '{}' container!")
        logging.info("'{}' container is restarted.")

    mux_port = select_mux_port

    yield

    # If the simulated fault still persist, let's remove pmon and
    # and restart the pmon service to restore.
    if (get_tor_mux_probe_state(rand_unselected_dut, mux_port) == "unknown" or
            get_tor_mux_cable_info(rand_unselected_dut, mux_port)["link_status_peer"] == "down"):
        _remove_pmon_container(rand_unselected_dut)
        _restart_pmon_container(rand_unselected_dut)


def test_switchover_probe_unknown(
    rand_selected_dut,
    rand_unselected_dut,
    restore_pmon,                                           # noqa: F811
    select_mux_port,
    toggle_all_simulator_ports_to_rand_unselected_tor       # noqa: F811
):
    mux_port = select_mux_port
    logging.info("Use mux port %s to test", mux_port)
    with setup_faulted_y_cable_driver(rand_unselected_dut, simulate_probe_unknown=True):
        # ensure that no switchover after the ycabled restart
        pytest_assert(get_tor_mux_status(
            rand_unselected_dut, mux_port) == "active")
        pytest_assert(get_tor_mux_status(
            rand_selected_dut, mux_port) == "standby")

        try:
            logging.info("Toggle to active via cli on %s", rand_selected_dut)
            rand_selected_dut.shell("config mux mode active %s" % mux_port)
            # With the faulty ycable driver returning mux unknown, the unselected ToR is still
            # able to honor the mux toggle requested by the selected ToR.
            verify_tor_states(rand_selected_dut,
                              rand_unselected_dut, intf_names=[mux_port])
            pytest_assert(get_tor_mux_probe_state(
                rand_unselected_dut, mux_port) == "unknown")
        finally:
            rand_selected_dut.shell("config mux mode auto all")


def test_switchover_peer_link_down(
    rand_selected_dut,
    rand_unselected_dut,
    restore_pmon,                                           # noqa: F811
    select_mux_port,
    toggle_all_simulator_ports_to_rand_unselected_tor       # noqa: F811
):
    mux_port = select_mux_port
    logging.info("Use mux port %s to test", mux_port)
    with setup_faulted_y_cable_driver(rand_unselected_dut, simulate_peer_link_down=True):
        # ensure that no switchover after the ycabled restart
        pytest_assert(get_tor_mux_status(
            rand_unselected_dut, mux_port) == "active")
        pytest_assert(get_tor_mux_status(
            rand_selected_dut, mux_port) == "standby")

        try:
            logging.info("Toggle to active via cli on %s", rand_selected_dut)
            rand_selected_dut.shell("config mux mode active %s" % mux_port)
            # With the faulty ycable driver returning peer link down, the unselected ToR will try
            # toggle back as the peer link is down. And as the ycabled polls the link status every
            # 60s, let's wait for 90 seconds here.
            verify_tor_states(rand_unselected_dut, rand_selected_dut, intf_names=[
                              mux_port], verify_db_timeout=90)
            pytest_assert(get_tor_mux_cable_info(rand_unselected_dut, mux_port)[
                          "link_status_peer"] == "down")
        finally:
            rand_selected_dut.shell("config mux mode auto all")
