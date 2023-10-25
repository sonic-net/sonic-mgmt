import pytest
import random
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports, \
    get_multidut_tgen_peer_port_set, cleanup_config                                         # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list
from tests.snappi_tests.variables import config_set, line_card_choice
from tests.snappi_tests.multidut.pfcwd.files.pfcwd_multidut_multi_node_helper import run_pfcwd_multi_node_test
from tests.snappi_tests.pfcwd.files.helper import skip_pfcwd_test            # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

pytestmark = [pytest.mark.topology('snappi')]


@pytest.mark.parametrize("trigger_pfcwd", [True])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_many_to_one(snappi_api,              # noqa: F811
                           conn_graph_facts,        # noqa: F811
                           fanout_graph_facts,      # noqa: F811
                           duthosts,
                           line_card_choice,
                           linecard_configuration_set,
                           get_multidut_snappi_ports,   # noqa: F811
                           trigger_pfcwd):

    """
    Run PFC watchdog test under many to one traffic pattern

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): lossless priority to test, e.g., 's6100-1|3'
        lossy_prio_list (pytest fixture): list of lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
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
        dut_list = [dut for dut in duthosts if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 3:
        assert False, "Need Minimum of 3 ports for the test"
    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 3)
    tgen_ports = [port['location'] for port in snappi_ports]

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            tgen_ports,
                                                                            snappi_ports,
                                                                            snappi_api)

    all_prio_list = prio_dscp_map.keys()
    test_prio_list = lossless_prio_list
    pause_prio_list = test_prio_list
    bg_prio_list = [x for x in all_prio_list if x not in pause_prio_list]
    skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
    skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_multi_node_test(api=snappi_api,
                              testbed_config=testbed_config,
                              port_config_list=port_config_list,
                              conn_data=conn_graph_facts,
                              fanout_data=fanout_graph_facts,
                              dut_port=snappi_ports[0]['peer_port'],
                              pause_prio_list=pause_prio_list,
                              test_prio_list=test_prio_list,
                              bg_prio_list=bg_prio_list,
                              prio_dscp_map=prio_dscp_map,
                              trigger_pfcwd=trigger_pfcwd,
                              pattern="many to one",
                              snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)
