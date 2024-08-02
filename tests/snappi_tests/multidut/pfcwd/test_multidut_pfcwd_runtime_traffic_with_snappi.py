import pytest
import random
from tests.common.helpers.assertions import pytest_require, pytest_assert                               # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts                 # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports,\
    get_multidut_tgen_peer_port_set, cleanup_config                                                     # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map                                        # noqa: F401
from tests.snappi_tests.variables import config_set, line_card_choice
from tests.snappi_tests.multidut.pfcwd.files.pfcwd_multidut_runtime_traffic_helper import run_pfcwd_runtime_traffic_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

pytestmark = [pytest.mark.topology('snappi')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_runtime_traffic(snappi_api,                  # noqa: F811
                               conn_graph_facts,            # noqa: F811
                               fanout_graph_facts,          # noqa: F811
                               duthosts,
                               prio_dscp_map,               # noqa: F811
                               line_card_choice,
                               linecard_configuration_set,
                               get_multidut_snappi_ports    # noqa: F811
                               ):
    """
    Test PFC watchdog's impact on runtime traffic

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """
    pytest_assert(line_card_choice in linecard_configuration_set.keys(), "Invalid line_card_choice in parameter")

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]      # noqa: E501
        duthost1, duthost2 = dut_list[0], dut_list[0]
    elif len(linecard_configuration_set[line_card_choice]['hostname']) == 0:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_require(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    all_prio_list = prio_dscp_map.keys()

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.duthost1 = duthost1
    snappi_extra_params.rx_port = snappi_ports[0]
    snappi_extra_params.rx_port_id = snappi_ports[0]["port_id"]
    snappi_extra_params.duthost2 = duthost2
    snappi_extra_params.tx_port = snappi_ports[1]
    snappi_extra_params.tx_port_id = snappi_ports[1]["port_id"]

    run_pfcwd_runtime_traffic_test(api=snappi_api,
                                   testbed_config=testbed_config,
                                   port_config_list=port_config_list,
                                   conn_data=conn_graph_facts,
                                   fanout_data=fanout_graph_facts,
                                   dut_port=snappi_ports[0]['peer_port'],
                                   prio_list=all_prio_list,
                                   prio_dscp_map=prio_dscp_map,
                                   snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)
