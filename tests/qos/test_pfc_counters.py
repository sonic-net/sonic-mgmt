from tests.common.fixtures.conn_graph_facts import conn_graph_facts, enum_fanout_graph_facts     # noqa: F401
from tests.common.helpers.pfc_counters import leaf_fanouts      # noqa: F401
from tests.common.helpers.pfc_counters import run_test
import pytest
import logging

"""
This module implements test cases for PFC counters of SONiC.
The PFC Rx counter should be increased when the switch receives a priority-based flow control (PFC) pause/unpause frame.
The PFC Rx counter should NOT be updated when the switch receives a global flow control pause/unpause frame.

In each test case, we send a specific number of pause/unpause frames to a given priority queue of a given port at the
device under test (DUT). Then we check the SONiC PFC Rx counters.
"""

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module', autouse=True)
def enable_flex_port_counter(rand_selected_dut):
    get_cmd = 'sonic-db-cli CONFIG_DB hget "FLEX_COUNTER_TABLE|PORT" "FLEX_COUNTER_STATUS"'
    status = rand_selected_dut.shell(get_cmd)['stdout']
    if status == 'enable':
        yield
        return
    set_cmd = 'sonic-db-cli CONFIG_DB hset "FLEX_COUNTER_TABLE|PORT" "FLEX_COUNTER_STATUS" "{}"'
    logger.info("Enable flex counter for port")
    rand_selected_dut.shell(set_cmd.format('enable'))
    yield
    logger.info("Disable flex counter for port")
    rand_selected_dut.shell(set_cmd.format('disable'))


def test_pfc_pause(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                   conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):          # noqa: F811
    """ @Summary: Run PFC pause frame (pause time quanta > 0) tests """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts)


def test_pfc_unpause(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                     conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):        # noqa: F811
    """ @Summary: Run PFC unpause frame (pause time quanta = 0) tests """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts, pause_time=0)


def test_fc_pause(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                  conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):           # noqa: F811
    """ @Summary: Run FC pause frame (pause time quanta > 0) tests """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts, is_pfc=False)


def test_fc_unpause(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                    conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):         # noqa: F811
    """ @Summary: Run FC pause frame (pause time quanta = 0) tests """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts, is_pfc=False, pause_time=0)


def test_continous_pfc(fanouthosts, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                       conn_graph_facts, enum_fanout_graph_facts, leaf_fanouts):     # noqa: F811
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    run_test(fanouthosts, duthost, conn_graph_facts,
             enum_fanout_graph_facts, leaf_fanouts, check_continuous_pfc=True)
