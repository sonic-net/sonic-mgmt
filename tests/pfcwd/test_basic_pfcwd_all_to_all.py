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

from files.configs.pfc_wd_basic import run_basic_pfcwd_all_to_all_test

logger = logging.getLogger(__name__)
lossless_prio_list = [3,4]


@pytest.mark.parametrize('prio', lossless_prio_list)
def test_basic_pfcwd_all_to_all(api,
                                port_id,
                                duthost,
                                prio,
                                conn_graph_facts,
                                fanout_graph_facts):
    """
    +-----------------+           +--------------+           +-----------------+       
    | Keysight Port 1 |------ et1 |   SONiC DUT  | et2 ------| Keysight Port 2 | 
    +-----------------+           +--------------+           +-----------------+ 
                                       et3
                                        |
                                        |
                                        |
                                +-----------------+
                                | Keysight Port 3 |
                                +-----------------+

    Configuration:
    1. Configure a single lossless priority value Pi (0 <= i <= 7).
    2. Enable watchdog with default storm detection time (400ms) and restoration time (2sec).
    3. On Keysight Chassis, create bi-directional traffic between Port 1 and Port 2
       with DSCP value mapped to lossless priority Pi
       a. Traffic 1->2
       b. Traffic 2->1
    4. Create bi-directional traffic between Port 2 and Port 3 with DSCP value mapped 
       to lossless priority Pi
       a. Traffic 2->3
       b. Traffic 3->2
    5. Create bi-directional traffic between Port 1 and Port 3 with DSCP value mapped 
       to lossless priority Pi
       a. Traffic 3->1
       b. Traffic 1->3
    6. Create PFC pause storm: Persistent PFC pause frames from Keysight port 3 to et3 of DUT.
        Priority of the PFC pause frames should be same as that configured in DUT 
        and the inter-frame transmission interval should be lesser than per-frame pause duration.

    # Workflow
    1. At time TstartTraffic , start all the bi-directional lossless traffic items.
    2. At time TstartPause , start PFC pause storm.
    3. At time TstopPause , stop PFC pause storm. (TstopPause - TstartPause) should be larger than
        PFC storm detection time + PFC watchdog polling interval to trigger PFC watchdog.
    4. At time TstopTraffic , stop lossless traffic items. Note that (TstopTraffic - TstopPause) should 
        be larger than PFC storm restoration time to re-enable PFC.
    5. Verify the following:
        --> PFC watchdog is triggered on the corresponding lossless priorities at DUT interface et3.
        --> 'Traffic 1->2' and 'Traffic 2->1' must not experience any packet loss in both directions. 
            Its throughput should be close to 50% of the line rate.
        --> For 'Traffic 2->3', 'Traffic 3->2', 'Traffic 1->3' and 'Traffic 3->1' between TstartPause and TstopPause , 
            there should be almost 100% packet loss in both directions.
        --> After TstopPause , the traffic throughput should gradually increase and become 50% of line rate in both directions.
        --> There should not be any traffic loss after PFC storm restoration time has elapsed.

    @param api: open tgen api fixture
    @param port_id: starting index of port_id from topo file 
    @param prio: dscp priority
    @param duthost: Sonic DUT duthost fixture
    @param conn_graph_facts: conn_graph_facts fixture to get testbed connection information
    @param fanout_graph_facts: fanout_graph_facts fixture to get testbed connection information
    """

    run_basic_pfcwd_all_to_all_test(api=api,
                                    port_id=port_id,
                                    prio=prio,
                                    duthost=duthost,
                                    conn_graph_facts=conn_graph_facts,
                                    fanout_graph_facts=fanout_graph_facts)