#### Test
import time
import datetime
import pytest
import logging

from abstract_open_traffic_generator.result import FlowRequest
from abstract_open_traffic_generator.control import *

from tests.common.helpers.assertions import pytest_assert

from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, api

from files.configs.pfc_wd import pfcwd_disabled_pfcwd_enabled_configs, ports_config
from files.qos_fixtures import lossless_prio_dscp_map

logger = logging.getLogger(__name__)

START_DELAY = [1]
PAUSE_LINE_RATE = [50]
TRAFFIC_LINE_RATE = [50]
FRAME_SIZE = [1024]
T_START_PAUSE = [5]
T_STOP_PAUSE = [20]
T_STOP_TRAFFIC = [40]
STORM_DETECTION_TIME = [400]
STORM_RESTORATION_TIME = [2000]
TOLERANCE_PERCENT = [1]


@pytest.mark.parametrize('start_delay', START_DELAY)
@pytest.mark.parametrize('pause_line_rate', PAUSE_LINE_RATE)
@pytest.mark.parametrize('traffic_line_rate', TRAFFIC_LINE_RATE)
@pytest.mark.parametrize('frame_size', FRAME_SIZE)
@pytest.mark.parametrize('t_start_pause', T_START_PAUSE)
@pytest.mark.parametrize('storm_detection_time', STORM_DETECTION_TIME)
@pytest.mark.parametrize('storm_restoration_time', STORM_RESTORATION_TIME)
@pytest.mark.parametrize('tolerance_percent', TOLERANCE_PERCENT)
def test_pfcwd_disabled_pfcwd_enabled(api, 
                                      duthost,
                                      pfcwd_disabled_pfcwd_enabled_configs,
                                      lossless_prio_dscp_map,
                                      start_delay,
                                      t_start_pause,
                                      storm_detection_time,
                                      storm_restoration_time,
                                      tolerance_percent):
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
    """

    ########################################################################################
    # DUT Configuration
    # Note : The test is done considering the DUT has lossless priorities configured as 3,4
    ########################################################################################
    #take config backup
    duthost.shell("sudo cp /etc/sonic/config_db.json /tmp/config_db_pfc.json")

    prio_list = [prio for prio in lossless_prio_dscp_map]
    for prio in prio_list:
        logger.info("Test for priority {}".format(prio))
        if prio == 3:
            duthost.replace(path="/etc/sonic/config_db.json", 
                            regexp='"pfc_enable": ".*"', 
                            replace='"pfc_enable": "{0}"'.format(4))
        elif prio == 4:
            duthost.replace(path="/etc/sonic/config_db.json", 
                regexp='"pfc_enable": ".*"', 
                replace='"pfc_enable": "{0}"'.format(3))

        duthost.shell("sudo config reload -y")
        time.sleep(90)

        duthost.shell('sudo pfcwd stop')

        cmd = 'sudo pfcwd start --action drop ports all detection-time {} \
            --restoration-time {}'.format(storm_detection_time,storm_restoration_time)
        duthost.shell(cmd)

        duthost.shell('pfcwd show config')
        
        configs = pfcwd_disabled_pfcwd_enabled_configs(prio)
        # Repeat the test for each config with different port combinations
        for config in configs:
            api.set_state(State(ConfigState(config=config, state='set')))
            ###############################################################################################
            # Start all flows 
            # 1. check for no loss in the flows Traffic 1->2,Traffic 2->1
            ###############################################################################################
            
            api.set_state(State(FlowTransmitState(state='start')))

            # Sleeping till t_start_pause as t_start_pause is added as delay for the flow
            time.sleep(start_delay+t_start_pause)

            # Keep checking traffic for 10 seconds
            from pandas import DataFrame
            retry = 0
            while True:
                time.sleep(2)
                retry = retry + 1
                for flow in ['Traffic 1->2','Traffic 2->1']:
                    request = FlowRequest(flow_names=[flow])
                    results = api.get_flow_results(request)
                    df = DataFrame.from_dict(results)
                    tolerance = (df.frames_tx * tolerance_percent) / 100
                    logger.info("\n{} during Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                .format(df.name[0],df.frames_tx[0],df.frames_rx[0],df.loss[0]))
                    if df.frames_tx.sum() > df.frames_rx.sum() + int(tolerance):
                        pytest_assert(False,
                                      "Observing loss for %s during pause storm which is not expected" % (df.name))
                if retry == 5:
                    break
            
            # stop all flows
            api.set_state(State(FlowTransmitState(state='stop')))

            output = duthost.command("pfcwd show stats")["stdout_lines"]
            for each_line in output:
                if 'Ethernet' in each_line:
                    pytest_assert(False,
                                "PFCWD triggerd on ports which is not expected")

    # Revert the config to original
    duthost.shell("sudo rm -rf /etc/sonic/config_db.json")
    duthost.shell("sudo cp /tmp/config_db_pfc.json /etc/sonic/config_db.json")
    duthost.shell("sudo config reload -y")