import pytest
import random
from tests.common.helpers.assertions import pytest_require, pytest_assert                               # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts                 # noqa: F401
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports,\
    get_multidut_tgen_peer_port_set, cleanup_config                                                     # noqa: F401
from tests.common.snappi.qos_fixtures import prio_dscp_map_dut_base, lossless_prio_list_dut_base        # noqa: F401
from tests.snappi.variables import config_set, line_card_choice
from files.pfcwd_multidut_runtime_traffic_helper import run_pfcwd_runtime_traffic_test

pytestmark = [pytest.mark.topology('snappi')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_runtime_traffic(snappi_api,                  # noqa: F811
                               conn_graph_facts,            # noqa: F811
                               fanout_graph_facts,          # noqa: F811
                               duthosts,
                               line_card_choice,
                               linecard_configuration_set,
                               get_multidut_snappi_ports    # noqa: F811
                               ):
    """
    Test PFC watchdog's impact on runtime traffic

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]      # noqa: E501
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)
    tgen_ports = [port['location'] for port in snappi_ports]

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            tgen_ports,
                                                                            snappi_ports,
                                                                            snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()

    run_pfcwd_runtime_traffic_test(api=snappi_api,
                                   testbed_config=testbed_config,
                                   port_config_list=port_config_list,
                                   conn_data=conn_graph_facts,
                                   fanout_data=fanout_graph_facts,
                                   duthost1=duthost1,
                                   rx_port=snappi_ports[0],
                                   rx_port_id=snappi_ports[0]["port_id"],
                                   duthost2=duthost2,
                                   tx_port=snappi_ports[1],
                                   tx_port_id=snappi_ports[1]["port_id"],
                                   dut_port=snappi_ports[0]['peer_port'],
                                   prio_list=all_prio_list,
                                   prio_dscp_map=prio_dscp_map)

    cleanup_config(dut_list, snappi_ports)
