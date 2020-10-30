import time
import datetime
import pytest
import logging

from abstract_open_traffic_generator.result import FlowRequest
from abstract_open_traffic_generator.control import *

from tests.common.helpers.assertions import pytest_assert

from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts

from tests.common.tgen.tgen_fixtures import api

from files.configs.pfc_wd_basic import run_pfc_disabled_pfcwd_enabled

logger = logging.getLogger(__name__)
lossless_prio_list = [3,4]


@pytest.mark.parametrize('prio', lossless_prio_list)
def test_pfcwd_disabled_pfcwd_enabled(api, 
                                      port_id,
                                      duthost,
                                      prio,
                                      conn_graph_facts,
                                      fanout_graph_facts):
    """
    +-----------------+           +--------------+           +-----------------+       
    | Keysight Port 1 |------ et1 |   SONiC DUT  | et2 ------| Keysight Port 2 | 
    +-----------------+           +--------------+           +-----------------+

    Configuration:
    1. Disable PFC at value Pi(3).
    2. Enable watchdog with default storm detection time (400ms) and restoration time (2sec).
    3. On Keysight Chassis, create bi-directional traffic between Port 1 and Port 2
       with DSCP value mapped to lossless priority Pi
       a. Traffic 1->2
       b. Traffic 2->1
    6. Create PFC pause storm: Persistent PFC pause frames from Keysight port 2 to et2 of DUT.
        Priority of the PFC pause frames should be same as that of Pi
        and the inter-frame transmission interval should be lesser than per-frame pause duration.

    # Workflow
    1. start all the bi-directional lossless traffic items.
    2. At time TstartPause , start PFC pause storm.
    3. Verify the following:
        a. Verify that PFC pause storm traffic doesn't have any effect on the data traffic.
        b. Also verify that PFCWD is not triggered on the port for any priority.

    @param api: open tgen api fixture
    @param port_id: starting index of port_id from topo file 
    @param prio: dscp priority
    @param duthost: Sonic DUT duthost fixture
    @param conn_graph_facts: conn_graph_facts fixture to get testbed connection information
    @param fanout_graph_facts: fanout_graph_facts fixture to get testbed connection information
    """

    run_pfc_disabled_pfcwd_enabled(api=api,
                                   port_id=port_id,
                                   prio=prio,
                                   duthost=duthost,
                                   conn_graph_facts=conn_graph_facts,
                                   fanout_graph_facts=fanout_graph_facts)