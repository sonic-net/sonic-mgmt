import enum
import logging
import pytest

from tests.common.config_reload import config_reload
from tests.common.fixtures.ptfhost_utils import run_icmp_responder          # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_garp_service            # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.common.dualtor.dual_tor_utils import check_tunnel_balance
from tests.common.dualtor.dual_tor_utils import dualtor_info                # noqa: F401
from tests.common.dualtor.dual_tor_utils import show_muxcable_status        # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa: F401


pytestmark = [
    pytest.mark.topology("dualtor")
]
PKT_SRC_IP = "10.10.10.10"
PKT_SRC_PORT = 5700
JUMBO_PKT_SIZE = 9000


class PreOp(enum.Enum):
    NONE = 0
    RELOAD = 1
    REBOOT = 2


@pytest.fixture(autouse=True)
def setup_loganalyzer_collect_only(duthosts, loganalyzer):
    """Make loganalyzer collect only without analyzing syslog."""
    if loganalyzer:
        for duthost in duthosts:
            loganalyzer[duthost.hostname].match_regex = []
            loganalyzer[duthost.hostname].expect_regex = []
            loganalyzer[duthost.hostname].ignore_regex = []


@pytest.fixture
def test_params(rand_selected_dut, rand_unselected_dut, ptfhost, tbinfo):
    params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    params["pktlen"] = JUMBO_PKT_SIZE
    params["hash_keys"] = ["src-port", "dst-port"]
    return params


@pytest.mark.parametrize("pre_op", [PreOp.NONE, PreOp.RELOAD, PreOp.REBOOT])
def test_standby_downstream_jumbo(localhost, pre_op, rand_selected_dut, test_params):

    def _validate_mux_port_status(duthost, mux_port, state):
        mux_states = show_muxcable_status(duthost)
        return mux_states[mux_port]['status'] == state

    def _validate_tunnel_route(duthost, mux_port, server_ip):
        tunnels = duthost.show_and_parse("show mux tunnel")
        for tunnel in tunnels:
            if tunnel["port"] == mux_port and tunnel["dest_address"].split("/")[0] == server_ip:
                return tunnel["kernel"] == "added" and tunnel["asic"] == "added"
        return False

    logging.info("Perform Pre OP: {pre_op}")
    if pre_op == PreOp.RELOAD:
        config_reload(rand_selected_dut, safe_reload=True, wait_for_bgp=True)
    elif pre_op == PreOp.REBOOT:
        reboot(rand_selected_dut, localhost, safe_reboot=True, wait_for_bgp=True)

    mux_port = test_params["selected_port"]
    server_ip = test_params["target_server_ip"]

    try:
        logging.info(f"Toggle mux port {rand_selected_dut}:{mux_port} to standby")
        rand_selected_dut.shell(f"config mux mode standby {mux_port}")
        pytest_assert(
            wait_until(30, 5, 0, _validate_mux_port_status, rand_selected_dut, mux_port, 'standby'),
            f"mux port {mux_port} is not toggled to standby as expected"
        )
        pytest_assert(
            wait_until(15, 5, 0, _validate_tunnel_route, rand_selected_dut, mux_port, server_ip),
            f"tunnel route is not present for {server_ip}"
        )

        logging.info(f"Send downstream traffic to server {server_ip} "
                        "and validate tunnel encap/balance")
        import pdb; pdb.set_trace()
        check_tunnel_balance(**test_params)
    finally:
        rand_selected_dut.shell("config mux mode auto all")
