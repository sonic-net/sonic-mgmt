import logging
import json
import pytest
import random

from tests.common.dualtor.dual_tor_common import active_active_ports        # noqa F401
from tests.common.dualtor.dual_tor_common import active_standby_ports       # noqa F401
from tests.common.dualtor.dual_tor_common import ActiveActivePortID
from tests.common.dualtor.dual_tor_common import cable_type                 # noqa F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_utils import upper_tor_host              # noqa F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host              # noqa F401
from tests.common.dualtor.dual_tor_utils import verify_upstream_traffic
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_lower_tor      # noqa F401
from tests.common.dualtor.nic_simulator_control import ForwardingState
from tests.common.dualtor.nic_simulator_control import mux_status_from_nic_simulator    # noqa F401
from tests.common.dualtor.nic_simulator_control import stop_nic_simulator               # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                      # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                       # noqa F401

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.fixture
def setup_mux(
    active_active_ports, cable_type,            # noqa F811
    mux_status_from_nic_simulator,              # noqa F811
    stop_nic_simulator,                         # noqa F811
    toggle_all_simulator_ports_to_lower_tor,    # noqa F811
    upper_tor_host, lower_tor_host              # noqa F811
):

    def _check_active_active_mux_status_from_nic_simulator(upper_tor_forwarding_state, lower_tor_forwarding_state):
        mux_status = mux_status_from_nic_simulator()
        logging.debug("Mux status from nic_simulator:\n%s", json.dumps(mux_status))
        for port in mux_status:
            if ((mux_status[port][ActiveActivePortID.UPPER_TOR] != upper_tor_forwarding_state) or
                    (mux_status[port][ActiveActivePortID.LOWER_TOR] != lower_tor_forwarding_state)):
                logging.debug("Port %s mux status is not expected", port)
                return False
        return True

    def _check_active_active_mux_status_from_dut(duthost, forwarding_state):
        all_mux_status = json.loads(duthost.shell("show mux status --json")["stdout"])["MUX_CABLE"]
        mux_status = {port: status for port, status in list(all_mux_status.items()) if port in active_active_ports}
        target_status = "active" if forwarding_state else "standby"
        for port in mux_status:
            status = mux_status[port]["STATUS"].lower()
            if status != target_status:
                return False
        return True

    def _restore_mux_config_auto():
        upper_tor_host.shell("config mux mode auto all")
        lower_tor_host.shell("config mux mode auto all")

    try:
        if cable_type == CableType.active_active:
            pytest_assert(
                _check_active_active_mux_status_from_nic_simulator(ForwardingState.ACTIVE, ForwardingState.ACTIVE),
                "Not all 'active-active' ports are in active state."
            )

            lower_tor_host.shell("config mux mode standby all")

            pytest_assert(
                wait_until(15, 3, 3, _check_active_active_mux_status_from_nic_simulator,
                           ForwardingState.ACTIVE, ForwardingState.STANDBY),
                "failed to toggle the lower ToR 'active-active' ports to standby"
            )

            stop_nic_simulator()

            upper_tor_host.shell("config mux mode standby all")

            pytest_assert(
                wait_until(15, 3, 3, _check_active_active_mux_status_from_dut, upper_tor_host, ForwardingState.STANDBY),
                "failed to toggle the lower ToR 'active-active' ports to standby"
            )
    except Exception:
        _restore_mux_config_auto()

    yield

    if cable_type == CableType.active_active:
        _restore_mux_config_auto()


@pytest.fixture
def selected_mux_port(cable_type, active_active_ports, active_standby_ports):       # noqa F811
    all_ports = []
    if cable_type == CableType.active_active:
        all_ports = active_active_ports
    elif cable_type == CableType.active_standby:
        all_ports = active_standby_ports

    return random.choice(all_ports)


@pytest.mark.enable_active_active
def test_ingress_drop(cable_type, ptfadapter, setup_mux, tbinfo, selected_mux_port, upper_tor_host, skip_traffic_test):    # noqa F811
    """
    Aims to verify if orchagent installs ingress drop ACL when the port comes to standby.

    For 'active-standby' mux ports, an ingress drop ACL is installed if the port comes to standby.
    For 'active-active' mux ports, no such ingress drop ACL is installed if the port comes to standby.

    Test steps:

    'active-standby':
        1) make the upper ToR as standby
        2) send upstream packets from the ptf(as the mux duplicates packets to both ToR)
        3) verify no packets are received from the T1 injected ptf ports connected to the upper ToR

    'active-active':
        1) make the lower ToR standby
        2) stop the nic simulator to freeze the forwarding behavior
            (for upstream packet, the mux only send packet to the upper ToR)
        3) make the upper ToR standby
        4) send upstream packets from the ptf
        5) verify those upstream packets could be received from the T1 injected ptf ports connected to the upper ToR
    """

    server_ip = "10.10.0.100"

    if cable_type == CableType.active_active:
        verify_upstream_traffic(upper_tor_host, ptfadapter, tbinfo, selected_mux_port,
                                server_ip, pkt_num=10, drop=False, skip_traffic_test=skip_traffic_test)
    elif cable_type == CableType.active_standby:
        verify_upstream_traffic(upper_tor_host, ptfadapter, tbinfo, selected_mux_port,
                                server_ip, pkt_num=10, drop=True, skip_traffic_test=skip_traffic_test)
