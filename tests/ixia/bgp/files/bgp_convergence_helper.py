import pytest
import time
from tabulate import tabulate
from statistics import mean
from tests.common.utilities import wait
from tests.common.helpers.assertions import pytest_assert
logger = logging.getLogger(__name__)

DUT_AS_NUM = 65100
TGEN_AS_NUM = 65200
TIMEOUT = 30
BGP_TYPE = 'ebgp'
MAX_DP_CONVERGENCE = 100
MAX_CPDP_CONVERGENCE = 3
MAX_RIBIN_CONVERGENCE = 3
def run_bgp_local_link_failover_test(cvg_api,
                                     duthost,
                                     tgen_ports,
                                     iteration,
                                     multipath,
                                     number_of_ipv4_routes):
    """
    Run BGP Convergence test
    
    Args:
        cvg_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        number_of_ipv4_routes:  Number of IPV4 Routes
    """
    port_count = multipath+1
    # Create bgp config on dut
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       multipath) 

    # Create bgp config on TGEN 
    tgen_bgp_config = __tgen_bgp_config(cvg_api,
                                        tgen_ports,
                                        port_count,
                                        number_of_ipv4_routes)

    # Run the convergence test by flapping all the rx links one by one and calculate the convergence values
    get_convergence_for_local_link_failover(cvg_api,
                              tgen_bgp_config,
                              iteration,
                              multipath,
                              number_of_ipv4_routes)

    # Cleanup the dut configs after getting the convergence numbers
    cleanup_config(duthost,
                   tgen_ports,
                   port_count)

def run_bgp_remote_link_failover_test(cvg_api,
                                duthost,
                                tgen_ports,
                                iteration,
                                multipath,
                                number_of_ipv4_routes):
    """
    Run BGP Convergence test
    
    Args:
        cvg_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        number_of_ipv4_routes:  Number of IPV4 Routes
    """
    port_count = multipath+1
    # Create bgp config on dut
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       multipath) 

    # Create bgp config on TGEN 
    tgen_bgp_config = __tgen_bgp_config(cvg_api,
                                        tgen_ports,
                                        port_count,
                                        number_of_ipv4_routes)

    # Run the convergence test by flapping all the rx links one by one and calculate the convergence values
    get_convergence_for_remote_link_failover(cvg_api,
                                             tgen_bgp_config,
                                             iteration,
                                             multipath,
                                             number_of_ipv4_routes)

    # Cleanup the dut configs after getting the convergence numbers
    cleanup_config(duthost,
                   tgen_ports,
                   port_count)

def run_RIB_IN_convergence_test(cvg_api,
                                duthost,
                                tgen_ports,
                                iteration,
                                multipath,
                                number_of_ipv4_routes):
    """
    Run BGP Convergence test
    
    Args:
        cvg_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        number_of_ipv4_routes:  Number of IPV4 Routes
    """
    port_count = multipath+1
    # Create bgp config on dut
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       multipath) 

    # Create bgp config on TGEN 
    tgen_bgp_config = __tgen_bgp_config(cvg_api,
                                        tgen_ports,
                                        port_count,
                                        number_of_ipv4_routes)

    # Run the convergence test by flapping all the rx links one by one and calculate the convergence values
    get_RIB_IN_convergence(cvg_api,
                            tgen_bgp_config,
                            iteration,
                            multipath,
                            number_of_ipv4_routes)

    # Cleanup the dut configs after getting the convergence numbers
    cleanup_config(duthost,
                   tgen_ports,
                   port_count)

def duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       multipath):
    """
    Configures BGP on the DUT with N-1 ecmp
    
    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count:multipath + 1
        multipath: ECMP value for BGP config
    """
    for i in range(0,port_count):
        intf_config = (
            "vtysh "
            "-c 'configure terminal' "
            "-c 'interface %s' "
            "-c 'ip address %s/%s' "
        )
        intf_config %= (tgen_ports[i]['peer_port'],tgen_ports[i]['peer_ip'],tgen_ports[i]['prefix'])
        logger.info('Configuring IP Address %s' %tgen_ports[i]['ip'])
        duthost.shell(intf_config)
    bgp_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'bgp bestpath as-path multipath-relax' "
        "-c 'maximum-paths %s' "
        "-c 'exit' "
    )
    bgp_config %= (DUT_AS_NUM,multipath)
    duthost.shell(bgp_config)
    for i in range(1,port_count):
        bgp_config_neighbor = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'neighbor %s remote-as %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'neighbor %s activate' "
        "-c 'exit' "
        )        
        bgp_config_neighbor %= (DUT_AS_NUM,tgen_ports[i]['ip'],TGEN_AS_NUM,tgen_ports[i]['ip'])
        logger.info('Configuring BGP Neighbor %s' %tgen_ports[i]['ip'])
        duthost.shell(bgp_config_neighbor)


def __tgen_bgp_config(cvg_api,
                      tgen_ports,
                      port_count,
                      number_of_ipv4_routes):
    """
    Creating  BGP config on TGEN
    
    Args:
        cvg_api (pytest fixture): snappi API
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count: multipath + 1
        number_of_ipv4_routes:  Number of IPV4 Routes
    """
    conv_config = cvg_api.convergence_config()
    config = conv_config.config
    for i in range(1,port_count+1):
        config.ports.port(name = 'Test_Port_%d'%i,location = tgen_ports[i-1]['location'])
        config.devices.device(name = 'Topology %d'%i)
        config.devices[i-1].container_name = config.ports[i-1].name

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = "speed_100_gbps"
    layer1.auto_negotiate = False

    def create_topo():
        config.devices[0].ethernet.name = 'Ethernet 1'
        config.devices[0].ethernet.ipv4.name = 'IPv4 1'
        config.devices[0].ethernet.ipv4.address = tgen_ports[0]['ip']
        config.devices[0].ethernet.ipv4.gateway = tgen_ports[0]['peer_ip']
        config.devices[0].ethernet.ipv4.prefix = int(tgen_ports[0]['prefix'])
        rx_flow_name = []
        for i in range(2,port_count+1):
            ethernet_stack = config.devices[i-1].ethernet
            ethernet_stack.name = 'Ethernet %d'%i
            ipv4_stack = ethernet_stack.ipv4
            ipv4_stack.name = 'IPv4 %d'%i
            ipv4_stack.address = tgen_ports[i-1]['ip']
            ipv4_stack.gateway = tgen_ports[i-1]['peer_ip']
            ipv4_stack.prefix = tgen_ports[i-1]['prefix']
            bgpv4_stack = ipv4_stack.bgpv4
            bgpv4_stack.name = 'BGP %d'%i
            bgpv4_stack.as_type = BGP_TYPE
            bgpv4_stack.dut_address = tgen_ports[i-1]['peer_ip']
            bgpv4_stack.as_number = int(TGEN_AS_NUM)
            route_range = bgpv4_stack.bgpv4_routes.bgpv4route(name = "Network Group %d"%i)[-1]
            route_range.addresses.bgpv4routeaddress(address = '200.1.0.1', prefix = 32, count = number_of_ipv4_routes, step = 1)
            rx_flow_name.append(route_range.name)
        return rx_flow_name
    
    rx_flows = create_topo()
    flow = config.flows.flow(name = 'convergence_test')[-1]
    flow.tx_rx.device.tx_names = [config.devices[0].name]
    flow.tx_rx.device.rx_names = rx_flows
    flow.size.fixed = 1024
    flow.rate.percentage = 100
    flow.metrics.enable = True
    return conv_config,config,rx_flows
    
def get_flow_stats(cvg_api):
        """
        Args:
            cvg_api (pytest fixture): Snappi API
        """
        request = cvg_api.convergence_request()
        request.metrics.flow_names = []
        return cvg_api.get_results(request).flow_metric

def get_convergence_for_local_link_failover(cvg_api,
                                            bgp_config,
                                            iteration,
                                            multipath,
                                            number_of_ipv4_routes):
    """
    Args:
        cvg_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_ipv4_routes:  Number of IPV4 Routes
    """
    conv_config = bgp_config[0]
    config = bgp_config[1]
    rx_port_names = []
    conv_config.convergence_event = (conv_config.LINK_UP_DOWN)
    cvg_api.set_config(conv_config)
    for i in range(1,len(config.ports)):
        rx_port_names.append(config.ports[i].name)

    def get_avg_dpdp_convergence_time(port_name,
                                      rx_port_names):
        """
        Args:
            port_name: Name of the port
            rx_port_names:List of rx port names
        """

        table,avg,tx_frate,rx_frate = [],[],[],[]
        for i in range(0,iteration):
            logger.info('|---- {} Link Flap Iteration : {} ----|'.format(port_name,i+1))

            #Start Traffic
            logger.info('Starting Traffic')
            cs = cvg_api.convergence_state()
            cs.transmit.state = cs.transmit.START
            cvg_api.set_state(cs)
            wait(TIMEOUT,"For Traffic To start")
            flow_stats = get_flow_stats(cvg_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0,"Traffic has not started"

            #Link Flap
            logger.info('Simulating Link Failure on {} link'.format(port_name))
            cs = cvg_api.convergence_state()
            cs.link.port_names = [port_name]
            cs.link.state = cs.link.DOWN
            cvg_api.set_state(cs)
            wait(TIMEOUT,"For Link to go down")
            flows = get_flow_stats(cvg_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_tx_rate)
            assert sum(tx_frate) == sum(rx_frate),"Traffic has not converged after link flap: TxFrameRate:{},RxFrameRate:{}".format(sum(tx_frate),sum(rx_frate))
            logger.info("Traffic has converged after link flap")
            tx_frame_rate = flow_stats[0].frames_tx_rate

            # Stop traffic
            logger.info('Stopping Traffic')
            cs = cvg_api.convergence_state()
            cs.transmit.state = cs.transmit.STOP
            cvg_api.set_state(cs)
            wait(TIMEOUT,"For Traffic To Stop")
            flow_stats = get_flow_stats(cvg_api)
            assert flow_stats[0].frames_tx_rate == 0
            tx_frames = flow_stats[0].frames_tx
            rx_frames = sum([fs.frames_rx for fs in flow_stats])
            
            # Calculate DPDP Convergence
            dp_convergence = (tx_frames - rx_frames) * 1000 / tx_frame_rate
            logger.info("DP Convergence Time: {} ms".format(int(dp_convergence)))  
            avg.append(int(dp_convergence))
            logger.info(dp_convergence)
            assert dp_convergence < MAX_DP_CONVERGENCE,"DP Convergence is greater than 100 ms"
            logger.info('Simulating Link Up on {} at the end of iteration {}'.format(port_name,i+1))
            
            #Performing link up at the end of iteration
            cs = cvg_api.convergence_state()
            cs.link.port_names = [port_name]
            cs.link.state = cs.link.UP
            cvg_api.set_state(cs)
        table.append('%s Link Failure'%port_name)
        table.append(number_of_ipv4_routes)
        table.append(iteration)
        table.append(mean(avg))
        return table
    table = []
    #Iterating link flap test on all the rx ports
    for i,port_name in enumerate(rx_port_names):
        table.append(get_avg_dpdp_convergence_time(port_name,rx_port_names))
    
    columns = ['Event Name','No. of IPV4 Routes','Iterations','Avg Calculated Data Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table,headers = columns,tablefmt = "psql"))

def get_convergence_for_remote_link_failover(cvg_api,
                                             bgp_config,
                                             iteration,
                                             multipath,
                                             number_of_ipv4_routes):
    """
    Args:
        cvg_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_ipv4_routes:  Number of IPV4 Routes
    """
    route_names = []
    conv_config = bgp_config[0]
    for device in bgp_config[1].devices:
        if device.name not in ['Topology 1']:
            for route in device.ethernet.ipv4.bgpv4.bgpv4_routes:
                route_names.append(route.name)
    conv_config = bgp_config[0]
    conv_config.rx_rate_threshold = 90/(multipath-1)
    conv_config.convergence_event = (conv_config.ROUTE_ADVERTISE_WITHDRAW)
    cvg_api.set_config(conv_config)
    

    def get_avg_cpdp_convergence_time(route_name):
        """
        Args:
            route_name: name of the route

        """
        table,avg,tx_frate,rx_frate = [],[],[],[]
        for i in range(0,iteration):
            logger.info('|---- {} Route Withdraw Iteration : {} ----|'.format(route_name,i+1))

            #Start Traffic
            logger.info('Starting Traffic')
            cs = cvg_api.convergence_state()
            cs.transmit.state = cs.transmit.START
            cvg_api.set_state(cs)
            wait(TIMEOUT,"For Traffic To start")
            flow_stats = get_flow_stats(cvg_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0,"Traffic has not started"

            #Withdraw routes from a BGP peer
            logger.info('Withdrawing Routes from {}'.format(route_name))
            cs = cvg_api.convergence_state()
            cs.route.names = [route_name]
            cs.route.state = cs.route.WITHDRAW
            cvg_api.set_state(cs)
            wait(TIMEOUT,"For routes to be withdrawn")
            flows = get_flow_stats(cvg_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_tx_rate)
            assert sum(tx_frate) == sum(rx_frate),"Traffic has not converged after lroute withdraw TxFrameRate:{},RxFrameRate:{}".format(sum(tx_frate),sum(rx_frate))
            logger.info("Traffic has converged after route withdraw")
            
            #Get control plane to data plane convergence
            request = cvg_api.convergence_request()
            request.convergence.flow_names = []
            convergence_metrics = cvg_api.get_results(request).flow_convergence
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms): {}'.format(metrics.control_plane_data_plane_convergence_us/1000))
                assert metrics.control_plane_data_plane_convergence_us < MAX_CPDP_CONVERGENCE*1000000,"CP/DP Convergence is greater than 100s"
            avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))

            #Advertise the routes back at the end of iteration
            cs = cvg_api.convergence_state()
            cs.route.names = [route_name]
            cs.route.state = cs.route.ADVERTISE
            cvg_api.set_state(cs)
            logger.info('Readvertise {} routes back at the end of iteration {}'.format(route_name,i+1))
            
        table.append('%s route withdraw'%route_name)
        table.append(number_of_ipv4_routes)
        table.append(iteration)
        table.append(mean(avg))
        return table
    table = []
    #Iterating route withdrawal on all BGP peers
    for route in route_names:
        table.append(get_avg_cpdp_convergence_time(route))
    
    columns = ['Event Name','No. of IPV4 Routes','Iterations','Avg Control to Data Plane Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table,headers = columns,tablefmt = "psql"))

def get_RIB_IN_convergence(cvg_api,
                           bgp_config,
                           iteration,
                           multipath,
                           number_of_ipv4_routes):
    """
    Args:
        cvg_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_ipv4_routes:  Number of IPV4 Routes
    """

    route_names = []
    conv_config = bgp_config[0]
    for device in bgp_config[1].devices:
        if device.name not in ['Topology 1']:
            for route in device.ethernet.ipv4.bgpv4.bgpv4_routes:
                route_names.append(route.name)
    conv_config.rx_rate_threshold = 90/(multipath-1)
    conv_config.convergence_event = (conv_config.ROUTE_ADVERTISE_WITHDRAW)
    cvg_api.set_config(conv_config)

    table,avg,tx_frate,rx_frate = [],[],[],[]
    for i in range(0,iteration):
        logger.info('|---- RIB-IN Convergence test, Iteration : {} ----|'.format(i+1))
        
        #withdraw all routes before starting traffic
        logger.info('Withdraw All Routes before starting traffic')
        cs = cvg_api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.WITHDRAW
        cvg_api.set_state(cs)
        wait(TIMEOUT,"For Routes to be withdrawn")

        #Start Traffic
        logger.info('Starting Traffic')
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.START
        cvg_api.set_state(cs)
        wait(TIMEOUT,"For Traffic To start")
        flow_stats = get_flow_stats(cvg_api)
        tx_frame_rate = flow_stats[0].frames_tx_rate
        rx_frame_rate = flow_stats[0].frames_rx_rate
        assert tx_frame_rate != 0,"Traffic has not started"
        assert rx_frame_rate == 0

        #Advertise All Routes
        logger.info('Advertising all Routes from {}'.format(route_names))
        cs = cvg_api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.ADVERTISE
        cvg_api.set_state(cs)
        wait(TIMEOUT,"For all routes to be ADVERTISED")
        flows = get_flow_stats(cvg_api)
        for flow in flows:
            tx_frate.append(flow.frames_tx_rate)
            rx_frate.append(flow.frames_tx_rate)
        assert sum(tx_frate) == sum(rx_frate),"Traffic has not convergedv, TxFrameRate:{},RxFrameRate:{}".format(sum(tx_frate),sum(rx_frate))
        logger.info("Traffic has converged after route advertisement")
        
        #Get RIB-IN convergence
        request = cvg_api.convergence_request()
        request.convergence.flow_names = []
        convergence_metrics = cvg_api.get_results(request).flow_convergence
        for metrics in convergence_metrics:
            logger.info('RIB-IN Convergence time (ms): {}'.format(metrics.control_plane_data_plane_convergence_us/1000))
            assert metrics.control_plane_data_plane_convergence_us < MAX_RIBIN_CONVERGENCE*1000000
        avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
        
        #Stop traffic at the end of iteration
        logger.info('Stopping Traffic at the end of iteration{}'.format(i+1))
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.STOP
        cvg_api.set_state(cs)
        wait(TIMEOUT,"For Traffic To stop")
        
    table.append('Advertise All BGP Routes')
    table.append(number_of_ipv4_routes)
    table.append(iteration)
    table.append(mean(avg))
    columns = ['Event Name','No. of IPV4 Routes','Iterations','Avg RIB-IN Convergence Time(ms)']
    logger.info("\n%s" % tabulate([table],headers = columns,tablefmt = "psql"))

def cleanup_config(duthost,
                   tgen_ports,
                   port_count):
    """
    Cleaning up dut config at the end of the test
    
    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count:multipath + 1
    """
    logger.info('Cleaning Up Interface and BGP config')
    bgp_config_cleanup = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no router bgp %s' "
    )
    bgp_config_cleanup %= (DUT_AS_NUM)
    duthost.shell(bgp_config_cleanup)
    for i in range(0,port_count):
        intf_config_cleanup = (
            "vtysh "
            "-c 'configure terminal' "
            "-c 'interface %s' "
            "-c 'no ip address %s/%s' "
        )
        intf_config_cleanup %= (tgen_ports[i]['peer_port'],tgen_ports[i]['peer_ip'],tgen_ports[i]['prefix'])
        duthost.shell(intf_config_cleanup)
    logger.info('Convergence Test Completed')
