# Test cases to validate functionality of the arp_update script

import logging
import pytest

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa: F401
from tests.common.fixtures.ptfhost_utils import setup_vlan_arp_responder  # noqa: F401
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0")
]


@pytest.fixture
def setup(rand_selected_dut):
    cmds = [
        "docker exec swss supervisorctl stop arp_update",
        "ip neigh flush all"
    ]
    rand_selected_dut.shell_cmds(cmds)
    yield
    cmds[0] = "docker exec swss supervisorctl start arp_update"
    # rand_selected_dut.shell_cmds(cmds)


def neighbor_learned(dut, target_ip):
    neigh_output = dut.shell(f"ip neigh show {target_ip}")['stdout']
    return "REACHABLE" in neigh_output or "STALE" in neigh_output


@pytest.mark.parametrize("ip_version", [4, 6])
def test_kernel_asic_mac_mismatch(
    toggle_all_simulator_ports_to_rand_selected_tor, config_facts,  # noqa: F811
    rand_selected_dut, ip_version, setup_vlan_arp_responder  # noqa: F811
):
    vlan_name, ipv4_base, ipv6_base = setup_vlan_arp_responder
    if ip_version == 4:
        target_ip = ipv4_base.ip + 2
    else:
        target_ip = ipv6_base.ip + 2

    rand_selected_dut.shell(f"ping -c1 -W1 {target_ip}; true")

    wait_until(10, 1, 0, neighbor_learned, rand_selected_dut, target_ip)

    neighbor_info = rand_selected_dut.shell(f"ip neigh show {target_ip}")["stdout"].split()
    pt_assert(neighbor_info[2] == vlan_name)

    asic_db_mac = rand_selected_dut.shell(
        f"sonic-db-cli APPL_DB hget 'NEIGH_TABLE:{vlan_name}:{target_ip}' 'neigh'"
    )['stdout']
    pt_assert(neighbor_info[4].lower() == asic_db_mac.lower())

    rand_selected_dut.shell(
        f"sonic-db-cli APPL_DB hset 'NEIGH_TABLE:{vlan_name}:{target_ip}' 'neigh' '00:00:00:00:00:00'"
    )
    asic_db_mac = rand_selected_dut.shell(
        f"sonic-db-cli APPL_DB hget 'NEIGH_TABLE:{vlan_name}:{target_ip}' 'neigh'"
    )['stdout']
    pt_assert(neighbor_info[4].lower() != asic_db_mac.lower())

    rand_selected_dut.shell("docker exec swss supervisorctl start arp_update")

    wait_until(10, 1, 0, lambda dut, ip: not neighbor_learned(dut, ip), rand_selected_dut, target_ip)
