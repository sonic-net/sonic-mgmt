import logging
import pytest

from tests.common.helpers.assertions import pytest_require
from tests.snappi_tests.ecn.files.ecnhelper import run_ecn_test_cisco8000
from tests.common.cisco_data import is_cisco_device
from tests.common.snappi_tests.snappi_fixtures import is_snappi_multidut


logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('tgen')]

# ecn counter is per TC
# Two streams are started for the indicated line rate.
# first stream from first tx port is for TC 3 and 4
# second stream from second tx port is for TC 3 and 4
# line rate percent/2 for TC 3, 4 from tx two ports


@pytest.fixture(autouse=True, scope="module")
def number_of_tx_rx_ports():
    yield (2, 1)


@pytest.fixture
def skip_ecn_multilossless_prio(
        duthosts,
        rand_one_dut_portname_oper_up,
        rand_one_dut_hostname,
        tgen_port_info):
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    duthost = duthosts[rand_one_dut_hostname]
    if not is_cisco_device(duthost):
        pytest.skip("Test is supported on Cisco device only")

    if is_snappi_multidut(duthosts):
        pytest.skip("Test is not supported on multi-dut")

    yield testbed_config, port_config_list, snappi_ports, duthost, dut_port


def test_ecn_multi_lossless_prio(snappi_api,
                                 conn_graph_facts,
                                 fanout_graph_facts,
                                 duthosts,
                                 rand_one_dut_hostname,
                                 rand_one_dut_portname_oper_up,
                                 lossless_prio_list,
                                 prio_dscp_map,
                                 skip_ecn_multilossless_prio
                                 ):

    """
    Test if ECN counter increments post interface flap

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        skip_ecn_multilossless_prio (pytest fixture): validated testbed objects for this test

    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports, dut_host, dut_port = skip_ecn_multilossless_prio
    test_prio_list = lossless_prio_list

    run_ecn_test_cisco8000(api=snappi_api,
                           testbed_config=testbed_config,
                           port_config_list=port_config_list,
                           conn_data=conn_graph_facts,
                           fanout_data=fanout_graph_facts,
                           duthost=dut_host,
                           dut_port=dut_port,
                           test_prio_list=test_prio_list,
                           prio_dscp_map=prio_dscp_map,
                           snappi_ports=snappi_ports)
