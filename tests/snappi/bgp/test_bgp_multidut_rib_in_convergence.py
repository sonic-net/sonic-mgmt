from unittest import result
from tests.common.snappi.snappi_fixtures import cvg_api
from tests.common.snappi.snappi_fixtures import (
   snappi_api_serv_ip, snappi_api_serv_port, get_multidut_snappi_ports,
   get_dut_interconnected_ports,
   create_ip_list, get_tgen_peer_ports)
from tests.common.fixtures.conn_graph_facts import fanout_graph_facts
from tests.common.helpers.assertions import pytest_assert
logger = logging.getLogger(__name__)
from tabulate import tabulate
from tests.common.utilities import (wait, wait_until)
import pytest
from files.bgp_variable import *
from files.bgp_helper import *

"""
This covers following testcase from testplan :

BGP-Convergence test with MUltiple DUTs

Test Steps :


            
Topology Used :
    
									 --------         
									|        |        
									|        |   Rx1  
							--------|  DUT2  |---------
						   |		|        |         |
						   |		|        |         |
						   |		 --------          |
       ------          --------                    --------
      |      |        |        |                  |        |
      |      |   Tx   |        |                  |        |
      | TGEN |--------|  DUT1  |                  |  TGEN  |
      |      |        |        |                  |        |
      |      |        |        |                  |        |
       ------          --------                    --------
	                       |                           |
	                       |         --------          |
                           |        |        |         |
                           |        |        |   Rx2   |
                            --------|  DUT3  |-------- 
                                    |        |        
                                    |        |        
                                     --------   
"""

###############################################################
#                   Start of Test Procedure
###############################################################

def test_bgp_multidut_rib_in_convergence(cvg_api, duthosts, get_multidut_snappi_ports, conn_graph_facts):
    
    # Initial steps
    dut_ports, tg_ports = [], []
    for i in range(0,len(RX_DUTS_PORT_RATIO)):
        if i ==0:
            port_set = get_tgen_peer_ports(get_multidut_snappi_ports, duthosts[i].hostname)[0:NO_OF_TX_PORTS+RX_DUTS_PORT_RATIO[i][1]]            
        else:
            port_set = get_tgen_peer_ports(get_multidut_snappi_ports, duthosts[i].hostname)[0:RX_DUTS_PORT_RATIO[i][1]]
        dut_ports.extend([val[1] for val in port_set])
        tg_ports.extend([val[0] for val in port_set])

    logger.info("dut_ports {}".format(dut_ports))
    logger.info("tg_ports {}".format(tg_ports))

    #declare result
    result = True

    # save current config in DUTs before start of test
    logger.info("Save configuration before start of test ...")
    for i in range(0,len(RX_DUTS_PORT_RATIO)):
        save_current_config(duthosts[i])

    # Step 1 Configure DUTs
    logger.info("Configure DUTs to TGEN and inter DUTs ...")
    configure_duts(duthosts, dut_ports, route_type=ROUTE_TYPE)

    # Step 2 Configure TGEN  
    logger.info("Configure TGEN") 
    bgp_config  = bgp_convergence_config(cvg_api, tg_ports, route_type=ROUTE_TYPE)
    rx_port_names = []
    for i in range(1, len(bgp_config.config.ports)):
        rx_port_names.append(bgp_config.config.ports[i].name)
    bgp_config.rx_rate_threshold = 90/(len(tg_ports)-int(NO_OF_TX_PORTS))
    cvg_api.set_config(bgp_config)

    # Step 3 Start the protocol
    logger.info("Starting all protocols ...")
    cs = cvg_api.convergence_state()
    cs.protocol.state = cs.protocol.START
    cvg_api.set_state(cs)
    wait(TIMEOUT, "For Protocols To start")

    # Step 4 Verify Interfaces Up Initially
    logger.info("Verify Interfaces States Initially UP")
    verify_interfaces(duthosts, dut_ports)
    
    # Step 5: Verify Ping from DUT to IXIA
    logger.info("Verify ping to TGEN successful")
    if not verify_ping(duthosts, tgenIps):
        result = False
    
    # Step 6: verify BGP neighbors established
    logger.info("Verify BGP neighbors established")
    if not verify_bgp_neighbors(duthosts, tgenIps[NO_OF_TX_PORTS:], route_type=ROUTE_TYPE):
        result = False
        
    # Step 7: verify ip route summary initially
    logger.info("Verify routes injected")
    if not verify_routes(duthosts, route_type=ROUTE_TYPE):
        result = False

    # Step 8: Verify convergence with remote link failures
    logger.info("Run the convergence test by withdrawing all routes at once and calculate the convergence")
    route_names = ['Network_Group%s'%i for i in range(2, len(tg_ports)+1)]
    table = get_rib_in_convergence_time(cvg_api, route_names, route_type=ROUTE_TYPE)
    columns = ['Event Name', 'Route Type', 'No. of Routes','Iterations', 'Frames Delta', 'Avg RIB-IN Convergence Time(ms)']
    logger.info("\n%s" % tabulate([table], headers=columns, tablefmt="psql"))

    # Step 9: cleanup_config
    logger.info("Cleanup configs from DUTs")
    for i in range(0,len(RX_DUTS_PORT_RATIO)):
        cleanup_config(duthosts[i])

    # Step 10: Final Result
    logger.info("Determine the final result of the test")
    pytest_assert(result == True, 'Test case test_bgp_multidut_rib_in_convergence failed')
