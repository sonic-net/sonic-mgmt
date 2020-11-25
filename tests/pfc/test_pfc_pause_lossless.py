import logging
import time
import pytest

from files.experiment import run_pfc_test
from files.qos_fixtures import prio_dscp_map, all_prio_list
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api
from tests.common.ixia.common_helpers import ansible_stdout_to_str

@pytest.mark.topology("t0")
@pytest.mark.disable_loganalyzer

def test_pfc_pause_single_lossless_prio(ixia_api,
                                        conn_graph_facts,
                                        fanout_graph_facts,
                                        duthost, 
                                        enum_dut_portname_oper_up, 
                                        enum_dut_lossless_prio, 
                                        all_prio_list,
                                        prio_dscp_map):

    pause_prio_list = [enum_dut_lossless_prio]
    test_prio_list = [enum_dut_lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(enum_dut_lossless_prio)

    run_pfc_test(api=ixia_api,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 port=ansible_stdout_to_str(enum_dut_portname_oper_up),
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=True)
    