from tests.common.snappi.snappi_fixtures import cvg_api
from tests.common.snappi.snappi_fixtures import (
    snappi_api_serv_ip, snappi_api_serv_port, tgen_ports)
from tests.snappi.reboot.files.reboot_helper import run_reboot_test
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts, fanout_graph_facts)
import pytest


pytestmark = [pytest.mark.topology('snappi')]


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['cold'])
def test_reboot(cvg_api,
                duthost,
                localhost,
                tgen_ports,
                conn_graph_facts,
                fanout_graph_facts,
                reboot_type,):

    """
    Topo:
    TGEN1 --- DUT --- TGEN(2..N)
    Steps:
    1) Create 2 servers and a T1 device with dual stack BGP
    2) Configure LAG for the T1 Device
    3) Send Traffic from Server1 to Server2, server2 to Server1,
       T1 to Server1, T1 to server2, Server1 to T1 and Server2 to T1
    4) Make sure there is no loss observed while sending trafic
    5) Reboot the dut with cold-reboot command
    6) Make sure after reboot the traffic has converged
    Verification:
    1) Make sure the control plane is up after the reboot is complete and
       the dut is back up
    2) Traffic must have converged after the dut is back up
    Args:
        cvg_api (pytest fixture): Snappi Convergence API
        duthost (pytest fixture): duthost fixture
        localhost (pytest fixture): localhost fixture
        tgen_ports (pytest fixture): Ports mapping info of testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        reboot_type (parameter): Reboot command
    """
    run_reboot_test(cvg_api,
                    duthost,
                    localhost,
                    tgen_ports,
                    reboot_type,)
