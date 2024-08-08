import pytest
import random
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
    fanout_graph_facts                                                                          # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports, \
    get_multidut_tgen_peer_port_set                                             # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list                                                                          # noqa: F401
from tests.snappi_tests.variables import config_set, line_card_choice
from tests.snappi_tests.multidut.pfc.files.m2o_oversubscribe_lossless_helper import (
     run_m2o_oversubscribe_lossless_test
    )
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_m2o_oversubscribe_lossless(snappi_api,                              # noqa: F811
                                    conn_graph_facts,                        # noqa: F811
                                    fanout_graph_facts,                      # noqa: F811
                                    line_card_choice,
                                    duthosts,
                                    prio_dscp_map,                           # noqa: F811
                                    lossless_prio_list,                      # noqa: F811
                                    linecard_configuration_set,
                                    get_multidut_snappi_ports,):             # noqa: F811

    """
    Run PFC oversubsription lossless for many to one traffic pattern

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossy_prio_list (pytest fixture): list of lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)

    Brief Description:
        This test uses the m2o_oversubscribe_lossless_helper.py file and generates 2 Background traffic and
        2 Test flow traffic. The test data traffic will include two lossless traffic streams, with the SONiC default
        lossless priorities of 3 and 4, for one stream to be at 25% while the other is at 30% bandwidth.
        The background traffic will consist of two lossy traffic streams, each with randomly chosen priorities
        (0..2, 5..7), and each having 25% bandwidth. The __gen_traffic() generates the flows. run_traffic()
        starts the flows and returns the flows stats. The verify_m2o_oversubscribtion_results() takes in the
        flows stats and verifies the loss criteria mentioned in the flag. Ex: 'loss': '16' means the flows to
        have 16% loss, 'loss': '0' means there shouldn't be any loss

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        pytest_assert(False, "Invalid line_card_choice value passed in parameter")
    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        pytest_assert(False, "Hostname can't be an empty list")
    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 3:
        pytest_assert(False, "Need Minimum of 3 ports for the test")
    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 3)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    all_prio_list = prio_dscp_map.keys()
    test_prio_list = lossless_prio_list
    pause_prio_list = test_prio_list
    bg_prio_list = [x for x in all_prio_list if x not in pause_prio_list]

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_m2o_oversubscribe_lossless_test(api=snappi_api,
                                        testbed_config=testbed_config,
                                        port_config_list=port_config_list,
                                        conn_data=conn_graph_facts,
                                        fanout_data=fanout_graph_facts,
                                        dut_port=snappi_ports[0]['peer_port'],
                                        pause_prio_list=pause_prio_list,
                                        test_prio_list=test_prio_list,
                                        bg_prio_list=bg_prio_list,
                                        prio_dscp_map=prio_dscp_map,
                                        snappi_extra_params=snappi_extra_params)
