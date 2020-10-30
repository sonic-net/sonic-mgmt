import pytest
import logging
from .files.pfcwd import run_pfcwd_impact_test
from tests.common.tgen.tgen_fixtures import api
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts


def test_pfcwd_impact(api, duthost, port_id, conn_graph_facts, fanout_graph_facts):
    """
    +-----------------+           +--------------+           +-----------------+       
    | Keysight Port 1 |------ et1 |   SONiC DUT  | et2 ------| Keysight Port 2 | 
    +-----------------+           +--------------+           +-----------------+ 

    Configuration:
    1. Configure lossless priorities on the DUT interface.
    2. Disable PFC Watch dog.
    3. On Keysight Chassis, create one unidirectional traffic with lossless priorities and
    one unidirectional traffic with lossy priorities with 50% line rate each.
    
    # Workflow
    1. Start both lossless and lossy traffic on Keysight ports.
    2. Verify the traffic when pfc disabled state.
    3. Wait for 5 seconds and Enable the PFC watch dog on DUT.
    4. Verify the traffic when pfc enabled state.
    5. Disable PFC on DUT.
    6. verify the traffic when pfc disabled state again.
    
    Traffic Verfication:
        In all above traffic verification, No traffic loss and No change in line rate shall be observed.
    """
    
    run_pfcwd_impact_test(api=api,
                duthost=duthost,
                port_id=port_id,
                conn_graph_facts=conn_graph_facts,
                fanout_graph_facts=fanout_graph_facts)

