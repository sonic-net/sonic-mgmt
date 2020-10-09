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

from files.configs.pfc_wd import pfcwd_configs, ports_config
from files.qos_fixtures import lossless_prio_dscp_map

logger = logging.getLogger(__name__)

START_DELAY = [1]
TRAFFIC_LINE_RATE = [50]
PAUSE_LINE_RATE = [50]
FRAME_SIZE = [1024]
T_START_PAUSE = [5]
T_STOP_PAUSE = [20]
T_STOP_TRAFFIC = [40]
STORM_DETECTION_TIME = [400]
STORM_RESTORATION_TIME = [2000]
TOLERANCE_PERCENT = [1]


@pytest.mark.parametrize('start_delay', START_DELAY)
@pytest.mark.parametrize('traffic_line_rate', TRAFFIC_LINE_RATE)
@pytest.mark.parametrize('pause_line_rate', PAUSE_LINE_RATE)
@pytest.mark.parametrize('frame_size', FRAME_SIZE)
@pytest.mark.parametrize('t_start_pause', T_START_PAUSE)
@pytest.mark.parametrize('t_stop_pause', T_STOP_PAUSE)
@pytest.mark.parametrize('t_stop_traffic', T_STOP_TRAFFIC)
@pytest.mark.parametrize('storm_detection_time', STORM_DETECTION_TIME)
@pytest.mark.parametrize('storm_restoration_time', STORM_RESTORATION_TIME)
@pytest.mark.parametrize('tolerance_percent', TOLERANCE_PERCENT)
def test_pfcwd_two_senders_two_receivers(api,
                                         duthost,
                                         pfcwd_configs,
                                         lossless_prio_dscp_map,
                                         start_delay,
                                         t_start_pause,
                                         t_stop_pause,
                                         t_stop_traffic,
                                         storm_detection_time,
                                         storm_restoration_time,
                                         tolerance_percent):
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
    5. Create PFC pause storm: Persistent PFC pause frames from Keysight port 3 to et3 of DUT.
        Priority of the PFC pause frames should be same as that configured in DUT 
        and the inter-frame transmission interval should be lesser than per-frame pause duration.

    # Workflow
    1. At time TstartTraffic , start all the bi-directional lossless traffic items.
    2. At time TstartPause , start PFC pause storm.
    3. At time TstopPause , stop PFC pause storm. (TstopPause - TstartPause)
        should be larger than PFC storm detection time + PFC watchdog polling interval to trigger PFC watchdog.
    4. At time TstopTraffic , stop lossless traffic items. Note that (TstopTraffic - TstopPause) should 
        be larger than PFC storm restoration time to re-enable PFC.
    5. Verify the following:
        --> PFC watchdog is triggered on the corresponding lossless priorities at DUT interface et3.
        --> 'Traffic 1->2' and 'Traffic 2->1' must not experience any packet loss.
            Its throughput should be close to 50% of the line rate.
        --> For 'Traffic 2->3' and 'Traffic 3->2' , between TstartPause and TstopPause , 
            there should be some packet loss.
        --> There should not be any traffic loss after PFC storm restoration time has elapsed.
    """

    #######################################################################
    # DUT Configuration
    #######################################################################
    duthost.shell('sudo pfcwd stop')

    cmd = 'sudo pfcwd start --action drop ports all detection-time {} \
           --restoration-time {}'.format(storm_detection_time,storm_restoration_time)
    duthost.shell(cmd)

    duthost.shell('pfcwd show config')

    t_btwn_start_pause_and_stop_pause = t_stop_pause - t_start_pause
    t_btwn_stop_pause_and_stop_traffic = t_stop_traffic - t_stop_pause

    prio_list = [prio for prio in lossless_prio_dscp_map]
    #######################################################################
    # TGEN Config and , Repeating TEST for Lossless priority 3 and 4
    #######################################################################

    for prio in prio_list: 
        logger.info("Test for priority {}".format(prio))
        configs = pfcwd_configs(prio)
        # Repeat the test for each config with different port combinations
        for config in configs:
            api.set_state(State(ConfigState(config=config, state='set')))            

            ##############################################################################################
            # Start all flows 
            # 1. check for no loss in the flows Traffic 1->2,Traffic 2->1
            # 2. check for loss in 'Traffic 2->3','Traffic 3->2' during pause storm
            ##############################################################################################
            api.set_state(State(FlowTransmitState(state='start')))

            # Sleeping till t_start_pause as t_start_pause is added as delay for the flow
            time.sleep(start_delay+t_start_pause)

            t_to_stop_pause  = datetime.datetime.now() + datetime.timedelta(seconds=t_btwn_start_pause_and_stop_pause)

            #Check for traffic observations for two timestamps in t_btwn_start_pause_and_stop_pause
            while True:
                if datetime.datetime.now() >= t_to_stop_pause:
                    break
                else:
                    time.sleep(t_btwn_start_pause_and_stop_pause/2)   
                    # Get statistics
                    test_stat = api.get_flow_results(FlowRequest())
                    for flow in test_stat :
                        if flow['name'] in ['Traffic 1->2','Traffic 2->1'] :
                            tx_frame_rate = int(flow['frames_tx_rate'])
                            rx_frame_rate = int(flow['frames_rx_rate'])
                            tolerance = (tx_frame_rate * tolerance_percent)/100
                            logger.info("\n{} during Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                         \n{} during Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                        .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                                flow['frames_tx'],flow['frames_rx'],flow['loss']))
                            if tx_frame_rate > (rx_frame_rate + tolerance):
                                pytest_assert(False,
                                              "Observing loss for %s during pause storm which is not expected" %(flow['name']))
                        elif flow['name'] in ['Traffic 2->3','Traffic 3->2']:
                            tx_frame_rate = int(flow['frames_tx_rate'])
                            rx_frame_rate = int(flow['frames_rx_rate'])
                            logger.info("\n{} during Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                         \n{} during Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                        .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                                flow['frames_tx'],flow['frames_rx'],flow['loss']))
                            if (tx_frame_rate == 0) or (rx_frame_rate != 0):
                                pytest_assert(False,
                                              "Expecting loss for %s during pause storm, which didn't occur" %(flow['name']))
                        
            ###############################################################################################
            # Stop Pause Storm
            # 1. check for no loss in the flows Traffic 1->2,Traffic 2->1
            # 2. check for no loss in 'Traffic 2->3','Traffic 3->2' after stopping Pause Storm
            ###############################################################################################
            # pause storm will stop once loop completes, once the current time reaches t_stop_pause
            api.set_state(State(FlowTransmitState(state='stop',flow_names=['Pause Storm'])))
            logger.info("PFC Pause Storm stopped")
            
            # Verification after pause storm is stopped
            t_to_stop_traffic = datetime.datetime.now() + datetime.timedelta(seconds=t_btwn_stop_pause_and_stop_traffic)
            
            #Check for traffic observations for two timestamps in t_btwn_stop_pause_and_stop_traffic
            while True:
                if datetime.datetime.now() >= t_to_stop_traffic:
                    break
                else:
                    time.sleep(t_btwn_stop_pause_and_stop_traffic/2)
                    # Get statistics
                    test_stat = api.get_flow_results(FlowRequest())
                    
                    for flow in test_stat:
                        if flow['name'] in ['Traffic 1->2','Traffic 2->1']:
                            tx_frame_rate = int(flow['frames_tx_rate'])
                            rx_frame_rate = int(flow['frames_rx_rate'])
                            tolerance = (tx_frame_rate * tolerance_percent)/100
                            logger.info("\n{} after stopping Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                         \n{} after stopping Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                        .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                                flow['frames_tx'],flow['frames_rx'],flow['loss']))
                            if tx_frame_rate > (rx_frame_rate + tolerance):
                                pytest_assert(False,
                                              "Observing loss for %s after pause storm stopped which is not expected" %(flow['name']))
                        elif flow['name'] in ['Traffic 2->3','Traffic 3->2']:
                            tx_frame_rate = int(flow['frames_tx_rate'])
                            rx_frame_rate = int(flow['frames_rx_rate'])
                            tolerance = (tx_frame_rate * tolerance_percent)/100
                            logger.info("\n{} after stopping Pause Storm Tx Frame Rate: {} Rx Frame Rate: {} \
                                         \n{} after stopping Pause Storm Tx Frames: {} Rx Frames: {} Loss%: {}"
                                        .format(flow['name'],tx_frame_rate,rx_frame_rate,flow['name'],
                                                flow['frames_tx'],flow['frames_rx'],flow['loss']))
                            if tx_frame_rate > (rx_frame_rate + tolerance):
                                pytest_assert(False,
                                              "Observing loss for %s after pause storm stopped which is not expected" %(flow['name']))
            
            # stop all flows
            api.set_state(State(FlowTransmitState(state='stop')))