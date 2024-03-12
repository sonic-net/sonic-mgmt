import pytest

from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.data_plane_utils import send_t1_to_server_with_action     # noqa F401
from tests.common.dualtor.data_plane_utils import send_server_to_t1_with_action     # noqa F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host                      # noqa F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                      # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                  # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service                    # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory             # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                # noqa F401
from tests.common.dualtor.dual_tor_common import active_active_ports                # noqa F401
from tests.common.dualtor.dual_tor_common import cable_type                         # noqa F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.nic_simulator_control import stop_nic_grpc_server         # noqa F401
from tests.common.dualtor.nic_simulator_control import restart_nic_simulator        # noqa F401


pytestmark = [
    pytest.mark.topology("dualtor")
]


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_grpc_server_failure_config_standby_config_auto_upstream_active(
    upper_tor_host, lower_tor_host, send_server_to_t1_with_action,      # noqa F811
    cable_type, active_active_ports, stop_nic_grpc_server               # noqa F811
):
    if cable_type == CableType.active_active:
        stop_nic_grpc_server(active_active_ports)
        upper_tor_host.shell_cmds(cmds=["config mux mode standby %s" % _ for _ in active_active_ports])

        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
            skip_state_db=True,
        )

        send_server_to_t1_with_action(
            upper_tor_host,
            verify=True,
            allowed_disruption=0,
            action=lambda: upper_tor_host.shell("config mux mode auto all")
        )

        verify_tor_states(
            expected_active_host=[upper_tor_host, lower_tor_host],
            expected_standby_host=None,
            cable_type=cable_type,
            skip_state_db=True
        )


@pytest.mark.enable_active_active
@pytest.mark.skip_active_standby
def test_grpc_server_failure_config_standby_config_auto_downstream_standby(
    upper_tor_host, lower_tor_host, send_t1_to_server_with_action,      # noqa F811
    cable_type, active_active_ports, stop_nic_grpc_server               # noqa F811
):
    if cable_type == CableType.active_active:
        stop_nic_grpc_server(active_active_ports)
        upper_tor_host.shell_cmds(cmds=["config mux mode standby %s" % _ for _ in active_active_ports])

        verify_tor_states(
            expected_active_host=lower_tor_host,
            expected_standby_host=upper_tor_host,
            expected_standby_health='unhealthy',
            cable_type=cable_type,
            skip_state_db=True,
        )

        send_t1_to_server_with_action(
            upper_tor_host,
            verify=True,
            allowed_disruption=0,
            action=lambda: upper_tor_host.shell("config mux mode auto all")
        )

        verify_tor_states(
            expected_active_host=[upper_tor_host, lower_tor_host],
            expected_standby_host=None,
            cable_type=cable_type,
            skip_state_db=True
        )
