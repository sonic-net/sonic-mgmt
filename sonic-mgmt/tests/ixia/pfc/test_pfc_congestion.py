import pytest

from files.pfc_congestion_helper import run_pfc_congestion
from tests.common.cisco_data import is_cisco_device    # noqa: F401
from tests.common.helpers.assertions import pytest_require    # noqa: F401
from tests.common.fixtures.conn_graph_facts import (      # noqa: F401
    conn_graph_facts,
    fanout_graph_facts)
from tests.common.ixia.ixia_fixtures import (    # noqa: F401
    ixia_api_serv_ip,
    ixia_api_serv_port,
    ixia_api_serv_user,
    ixia_api_serv_passwd,
    ixia_api,
    ixia_testbed_config)
from tests.common.ixia.qos_fixtures import (    # noqa: F401
    prio_dscp_map,
    all_prio_list,
    lossless_prio_list)

pytestmark = [pytest.mark.topology('tgen')]


def test_pfc_congestion(ixia_api,     # noqa: F811
                        ixia_testbed_config,     # noqa: F811
                        conn_graph_facts,     # noqa: F811
                        fanout_graph_facts,     # noqa: F811
                        duthosts,
                        rand_one_dut_hostname,
                        rand_one_dut_portname_oper_up,
                        lossless_prio_list,     # noqa: F811
                        all_prio_list,     # noqa: F811
                        prio_dscp_map):     # noqa: F811
    """
    Test if Lossless Traffic is not dropped when there is congestion.

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 'dut|eth1'
        lossless_prio_list : list of lossless priorities
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = ixia_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    lossy_prio_list = \
        list(set([p for p in all_prio_list]) - set(lossless_prio_list))

    run_pfc_congestion(api=ixia_api,
                       testbed_config=testbed_config,
                       port_config_list=port_config_list,
                       conn_data=conn_graph_facts,
                       fanout_data=fanout_graph_facts,
                       duthost=duthost,
                       dut_port=dut_port,
                       lossless_prio_list=lossless_prio_list,
                       lossy_prio_list=lossy_prio_list,
                       prio_dscp_map=prio_dscp_map
                       )
