import logging
import datetime
import json
import pytest
import random
import time

from tests.common.dualtor.dual_tor_common import active_active_ports                            # noqa F401
from tests.common.dualtor.dual_tor_common import ActiveActivePortID
from tests.common.dualtor.dual_tor_utils import upper_tor_host                                  # noqa F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                                  # noqa F401
from tests.common.dualtor.icmp_responder_control import pause_icmp_responder                    # noqa F401
from tests.common.dualtor.nic_simulator_control import ForwardingState
from tests.common.dualtor.nic_simulator_control import mux_status_from_nic_simulator            # noqa F401
from tests.common.dualtor.nic_simulator_control import toggle_active_active_simulator_ports     # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                              # noqa F401

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]
TEST_COUNT = 4


@pytest.fixture(scope="module")
def test_duthost(upper_tor_host, lower_tor_host):           # noqa F811
    today = datetime.datetime.fromtimestamp(time.time())
    if today.day % 2 == 1:
        duthost = upper_tor_host
        portid = ActiveActivePortID.UPPER_TOR
    else:
        duthost = lower_tor_host
        portid = ActiveActivePortID.LOWER_TOR
    return duthost, portid


@pytest.fixture(scope="module")
def test_mux_ports(active_active_ports):                    # noqa F811
    if not active_active_ports:
        pytest.skip("Skip as no 'active-active' mux ports available")
    test_ports = random.sample(active_active_ports, min(len(active_active_ports), TEST_COUNT))
    logging.info("Select ports %s to test", test_ports)
    return test_ports


@pytest.fixture(params=[ForwardingState.ACTIVE, ForwardingState.STANDBY])
def init_port_state(request):
    return request.param


@pytest.fixture
def setup_test_ports(init_port_state, mux_status_from_nic_simulator,    # noqa F811
                     pause_icmp_responder, test_mux_ports):             # noqa F811

    def check_forwarding_state(mux_ports, upper_tor_forwarding_state, lower_tor_forwarding_state):
        mux_status = mux_status_from_nic_simulator(mux_ports)
        logging.debug(
            "Check forwarding state of mux ports %s, upper ToR state: %s, lower ToR state: %s",
            mux_ports,
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

    if init_port_state == ForwardingState.STANDBY:
        pause_icmp_responder(test_mux_ports)

    pytest_assert(
        wait_until(60, 5, 0, check_forwarding_state, test_mux_ports, init_port_state, init_port_state),
        "failed to set ports %s initial state to %s" %
        (test_mux_ports, "active" if init_port_state == ForwardingState.ACTIVE else "standby")
    )

    return test_mux_ports


def test_grpc_server_failure(init_port_state, setup_test_ports, test_duthost,
                             toggle_active_active_simulator_ports):             # noqa F811
    """
    This testcase aims to verify that, if the nic_simulator arbitrarily toggles a
    port, SONiC could detect and recover the mux status.

    Steps:
    1. set the initial mux status(active or standby) for the selected active-active mux ports
    2. set the nic_simulator mux status to the opposite
    3. verify that SONiC does recover the mux status
        3.1 verify mux status from show mux status
        3.2 verify SONiC does request extra toggles to recover via the last switchover time from show mux status
        3.3 verify the mux status from nic_simulator
    """

    def get_mux_status(duthost, mux_ports):
        all_mux_status = json.loads(duthost.shell("show mux status --json")["stdout"])["MUX_CABLE"]
        return {port: status for port, status in list(all_mux_status.items()) if port in mux_ports}

    def check_mux_status_recovery(duthost, mux_ports, orig_mux_status):
        current_mux_status = get_mux_status(duthost, mux_ports)
        logging.debug("Current mux status:\n%s\n", json.dumps(current_mux_status))
        for port, status in list(current_mux_status.items()):
            orig_status = orig_mux_status[port]
            # check if both linkmgrd status and server status are stored
            if status["STATUS"] != orig_status["STATUS"] or status["SERVER_STATUS"] != orig_status["STATUS"]:
                return False
            # check if there is a newer switchover
            if status["LAST_SWITCHOVER_TIME"] == orig_status["LAST_SWITCHOVER_TIME"]:
                return False
        return True

    duthost, portid = test_duthost
    mux_ports = setup_test_ports
    orig_mux_status = get_mux_status(duthost, mux_ports)
    logging.debug("Original mux status:\n%s\n", json.dumps(orig_mux_status))

    if init_port_state == ForwardingState.ACTIVE:
        toggle_active_active_simulator_ports(mux_ports, portid, ForwardingState.STANDBY)
    elif init_port_state == ForwardingState.STANDBY:
        toggle_active_active_simulator_ports(mux_ports, portid, ForwardingState.ACTIVE)

    pytest_assert(
        wait_until(30, 5, 5, check_mux_status_recovery, duthost, mux_ports, orig_mux_status),
        "Failed to recover mux status from gRPC server failure"
    )
