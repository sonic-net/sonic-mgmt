import pytest
import random
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                            # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts                                                                              # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports, \
     get_multidut_tgen_peer_port_set, cleanup_config                                                 # noqa: F401
from tests.common.snappi_tests.qos_fixtures import lossless_prio_list, prio_dscp_map                # noqa: F401
from tests.snappi_tests.variables import config_set, line_card_choice
from tests.snappi_tests.multidut.pfc.files.multidut_helper import run_pfc_test                      # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_global_pause(snappi_api,                                   # noqa: F811
                      conn_graph_facts,                             # noqa: F811
                      fanout_graph_facts,                           # noqa: F811
                      duthosts,
                      prio_dscp_map,                                # noqa: F811
                      lossless_prio_list,                           # noqa: F811
                      line_card_choice,
                      linecard_configuration_set,
                      get_multidut_snappi_ports                     # noqa: F811
                      ):
    """
    Test if IEEE 802.3X pause (a.k.a., global pause) will impact any priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
    Returns:
        N/A
    """

    pytest_assert(line_card_choice in linecard_configuration_set.keys(), "Invalid line_card_choice in parameter")
    pytest_require(len(linecard_configuration_set[line_card_choice]['hostname']) != 0,
                   "Hostname can't be an empty list")
    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]      # noqa: E501
        duthost1, duthost2 = dut_list[0], dut_list[0]

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_assert(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    all_prio_list = prio_dscp_map.keys()
    test_prio_list = lossless_prio_list
    bg_prio_list = [x for x in all_prio_list if x not in test_prio_list]

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 global_pause=True,
                 pause_prio_list=None,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)
