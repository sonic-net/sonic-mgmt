logger = logging.getLogger(__name__)
import re
from bgp_variable import *
from tests.common.utilities import (wait, wait_until)
from tests.common.snappi.snappi_fixtures import (
   snappi_api_serv_ip, snappi_api_serv_port, get_multidut_snappi_ports,
   get_dut_interconnected_ports,
   create_ip_list, get_tgen_peer_ports)
from statistics import mean
from tests.common.helpers.assertions import pytest_assert


###############################################################
#                   supporting functions
###############################################################

def bgp_convergence_config(cvg_api, tg_ports, route_type='ipv4'):
    """
    1.Configure IPv4 EBGP sessions between Keysight ports(rx & tx)
    2.Configure and advertise IPv4 routes from rx
    """
    port_count = len(tg_ports)
    conv_config = cvg_api.convergence_config()
    config = conv_config.config

    for i in range(1, port_count+1):
        config.ports.port(name='Test_Port_%d' % i, location=tg_ports[i-1])
        c_lag = config.lags.lag(name="lag%d" % i)[-1]
        lp = c_lag.ports.port(port_name='Test_Port_%d' % i)[-1]
        lp.ethernet.name = 'lag_eth_%d' % i
        if len(str(hex(i).split('0x')[1])) == 1:
            m = '0'+hex(i).split('0x')[1]
        else:
            m = hex(i).split('0x')[1]
        lp.protocol.lacp.actor_system_id = "00:10:00:00:00:%s" % m
        lp.ethernet.name = "lag_Ethernet %s" % i
        lp.ethernet.mac = "00:10:01:00:00:%s" % m
        config.devices.device(name='Topology %d' % i)

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = port_speed
    layer1.auto_negotiate = False

    def create_v4_topo():
        eth = config.devices[0].ethernets.add()
        eth.port_name = config.lags[0].name
        eth.name = 'Ethernet 1'
        eth.mac = "00:00:00:00:00:01"
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'IPv4 1'
        ipv4.address = tgenIps[0]
        ipv4.gateway = dutIps[0]
        ipv4.prefix = int(ipMask)
        rx_flow_name = []
        for i in range(2, port_count+1):
            NG_LIST.append('Network_Group%s'%i)
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]

            ethernet_stack = config.devices[i-1].ethernets.add()
            ethernet_stack.port_name = config.lags[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv4_stack = ethernet_stack.ipv4_addresses.add()
            ipv4_stack.name = 'IPv4 %d' % i
            ipv4_stack.address = tgenIps[i-1]
            ipv4_stack.gateway = dutIps[i-1]
            ipv4_stack.prefix = ipMask
            bgpv4 = config.devices[i-1].bgp
            bgpv4.router_id =  dutIps[i-1] 
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4_stack.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'BGP %d' % i
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = dutIps[i-1]
            bgpv4_peer.as_number = int(TGEN_AS_NUM)
            route_range = bgpv4_peer.v4_routes.add(name=NG_LIST[-1]) #snappi object named Network Group 2 not found in internal db
            route_range.addresses.add(address='200.1.0.1', prefix=32, count=NO_OF_ROUTES)
            rx_flow_name.append(route_range.name)
        return rx_flow_name

    def create_v6_topo():
        eth = config.devices[0].ethernets.add()
        eth.port_name = config.lags[0].name
        eth.name = 'Ethernet 1'
        eth.mac = "00:00:00:00:00:01"
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'IPv6 1'
        ipv6.address = tgenV6Ips[0]
        ipv6.gateway = dutV6Ips[0]
        ipv6.prefix = int(ipv6Mask) 
        rx_flow_name = []
        for i in range(2, port_count+1):
            NG_LIST.append('Network_Group%s'%i)
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]
            ethernet_stack = config.devices[i-1].ethernets.add()
            ethernet_stack.port_name = config.lags[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv6_stack = ethernet_stack.ipv6_addresses.add()
            ipv6_stack.name = 'IPv6 %d' % i
            ipv6_stack.address = tgenV6Ips[i-1]
            ipv6_stack.gateway = dutV6Ips[i-1]
            ipv6_stack.prefix = int(ipv6Mask)
            
            bgpv6 = config.devices[i-1].bgp
            bgpv6.router_id = dutIps[i-1]
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6_stack.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name  = 'BGP+_%d' % i
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = dutV6Ips[i-1]
            bgpv6_peer.as_number = int(TGEN_AS_NUM)
            route_range = bgpv6_peer.v6_routes.add(name=NG_LIST[-1])
            route_range.addresses.add(address='3000::1', prefix=64, count=NO_OF_ROUTES)
            rx_flow_name.append(route_range.name)
        return rx_flow_name

    if route_type == 'ipv4':
        rx_flows = create_v4_topo()
        flow = config.flows.flow(name='IPv4 Traffic')[-1]
    elif route_type == 'ipv6':
        rx_flows = create_v6_topo()
        flow = config.flows.flow(name='IPv6 Traffic')[-1]
    else:
        raise Exception('Invalid route type given')
    flow.tx_rx.device.tx_names = [config.devices[0].name]
    flow.tx_rx.device.rx_names = rx_flows
    flow.size.fixed = 1024
    flow.rate.percentage = 100
    flow.metrics.enable = True
    return conv_config

def configure_duts(duthosts, ports, route_type="ipv4"):
    logger.info("Configure DUTS initially")
    j, port_count=0, 0
    for val in RX_DUTS_PORT_RATIO:
        host = duthosts[val[0]-1]
        dut="dut" + str(val[0])
        dutAs=dutsAsNum[val[0]-1]
        if j == 0:
            port_count = NO_OF_TX_PORTS + val[1]
        else:
            port_count +=val[1]
        for i in range(j, port_count): 
            if route_type =='ipv4':
                portchannel_config = (
                    " sudo config int fec %s rs \n"
                    " sudo config portchannel add PortChannel%s \n"
                    " sudo config portchannel member add PortChannel%s %s \n"
                    " sudo config interface ip add PortChannel%s %s/%s \n"
                )%(ports[i], i+1, i+1, ports[i], i+1, dutIps[i], ipMask )
                host.shell(portchannel_config) 
                if i>NO_OF_TX_PORTS-1:
                    bgp_config = (
                        "vtysh "
                        "-c 'configure terminal' "
                        "-c 'router bgp %s' "
                        "-c 'no bgp ebgp-requires-policy' "
                        "-c 'bgp bestpath as-path multipath-relax' "
                        "-c 'maximum-paths 64' "
                        "-c 'neighbor %s peer-group' "
                        "-c 'neighbor %s remote-as %s' "
                        "-c 'neighbor %s peer-group %s' "
                        "-c 'address-family ipv4 unicast' "
                        "-c 'neighbor %s activate' "
                        "-c 'exit' "
                    )
                    bgp_config %= (dutAs, dut, dut, TGEN_AS_NUM, tgenIps[i], dut, dut)
                    host.shell(bgp_config)
            else:
                dut = dut + "v6"
                portchannel_config = (
                    " sudo config int fec %s rs \n"
                    " sudo config portchannel add PortChannel%s \n"
                    " sudo config portchannel member add PortChannel%s %s \n"
                    " sudo config interface ip add PortChannel%s %s/%s \n"
                )%(ports[i], i+1, i+1, ports[i], i+1, dutV6Ips[i], ipv6Mask )
                host.shell(portchannel_config)
                if (i>0) :
                    bgp_config = (
                        "vtysh "
                        "-c 'configure terminal' "
                        "-c 'router bgp %s' "
                        "-c 'no bgp ebgp-requires-policy' "
                        "-c 'bgp bestpath as-path multipath-relax' "
                        "-c 'maximum-paths 64' "
                        "-c 'neighbor %s peer-group' "
                        "-c 'neighbor %s remote-as %s' "
                        "-c 'neighbor %s peer-group %s' "
                        "-c 'address-family ipv4 unicast' "
                        "-c 'no neighbor %s activate' "
                        "-c 'address-family ipv6 unicast' "
                        "-c 'neighbor %s activate' "
                        "-c 'exit' "
                    )
                    bgp_config %= (dutAs, dut, dut, TGEN_AS_NUM, tgenV6Ips[i], dut, dut, dut)
                    host.shell(bgp_config)
            j+=1

def get_flow_stats(cvg_api):
    """
    Args:
        cvg_api (pytest fixture): Snappi API
    """
    request = cvg_api.convergence_request()
    request.metrics.flow_names = []
    return cvg_api.get_results(request).flow_metric

def get_avg_dpdp_convergence_time(cvg_api, port_name, route_type="ipv4"):
    """
    Args:
        port_name: Name of the port
    """

    table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
    for i in range(0, ITERATION):
        logger.info('|---- {} Link Flap Iteration : {} ----|'.format(port_name, i+1))

        """ Starting Traffic """
        logger.info('Starting Traffic')
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.START
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Traffic To start")
        flow_stats = get_flow_stats(cvg_api)
        tx_frame_rate = int(flow_stats[0].frames_tx_rate)
        rx_frame_rate = int(flow_stats[0].frames_rx_rate)
        max_tol = int(tx_frame_rate) + tolerence_pkts
        min_tol = int(tx_frame_rate) - tolerence_pkts
        assert tx_frame_rate != 0, "Traffic has not started"
        assert (rx_frame_rate > max_tol or rx_frame_rate < min_tol) == False, "traffic is not converged initially"
        
        """ Flapping Link """
        logger.info('Simulating Link Failure on {} link'.format(port_name))
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.STOP
        cvg_api.set_state(cs)
        wait(10, "For Traffic Stats Clear")
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.START
        cvg_api.set_state(cs)
        wait(5, "For Traffic to start")
        cs = cvg_api.convergence_state()
        cs.link.port_names = [port_name]
        cs.link.state = cs.link.DOWN
        cvg_api.set_state(cs)
        wait(FLAP_TIME, "For Link to go down")
        flow_stats = get_flow_stats(cvg_api)
        tx_frame_rate = int(flow_stats[0].frames_tx_rate)
        rx_frame_rate = int(flow_stats[0].frames_rx_rate)
        max_tol = int(tx_frame_rate) + tolerence_pkts
        min_tol = int(tx_frame_rate) - tolerence_pkts
        logger.info("TxFrameRate:{},RxFrameRate:{}".format(tx_frame_rate, rx_frame_rate))
        assert (rx_frame_rate > max_tol or rx_frame_rate < min_tol) == False, "Traffic has not converged after link flap" 
        logger.info("Traffic has converged after link flap")
        """ Get control plane to data plane convergence value """
        request = cvg_api.convergence_request()
        request.convergence.flow_names = []
        convergence_metrics = cvg_api.get_results(request).flow_convergence
        for metrics in convergence_metrics:
            logger.info('DP/DP Convergence Time (ms): {}'.format(metrics.control_plane_data_plane_convergence_us/1000))
        avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
        avg_delta.append(int(flow_stats[0].frames_tx)-int(flow_stats[0].frames_rx))
        """ Performing link up at the end of iteration """
        logger.info('Simulating Link Up on {} at the end of iteration {}'.format(port_name, i+1))
        cs = cvg_api.convergence_state()
        cs.link.port_names = [port_name]
        cs.link.state = cs.link.UP
        cvg_api.set_state(cs)
    table.append('%s Link Failure' % port_name)
    table.append(route_type)
    table.append(NO_OF_ROUTES)
    table.append(ITERATION)
    table.append(mean(avg_delta))
    table.append(mean(avg))
    return table 

def get_avg_cpdp_convergence_time(cvg_api, route_name, route_type="ipv4"):
        """
        Args:
            route_name: name of the route
        """
        table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = cvg_api.convergence_state()
        cs.protocol.state = cs.protocol.START
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        for i in range(0, ITERATION):
            logger.info('|---- {} Route Withdraw Iteration : {} ----|'.format(route_name, i+1))
            """ Starting Traffic """
            logger.info('Starting Traffic')
            cs = cvg_api.convergence_state()
            cs.transmit.state = cs.transmit.START
            cvg_api.set_state(cs)
            wait(TIMEOUT, "For Traffic To start")
            flow_stats = get_flow_stats(cvg_api)
            tx_frame_rate = int(flow_stats[0].frames_tx_rate)
            rx_frame_rate = int(flow_stats[0].frames_rx_rate)
            max_tol = int(tx_frame_rate) + tolerence_pkts
            min_tol = int(tx_frame_rate) - tolerence_pkts
            assert tx_frame_rate != 0, "Traffic has not started"
            assert (rx_frame_rate > max_tol or rx_frame_rate < min_tol) == False, "traffic is not converged initially"

            """ Withdrawing routes from a BGP peer """
            logger.info('Withdrawing Routes from {}'.format(route_name))
            cs = cvg_api.convergence_state()
            cs.transmit.state = cs.transmit.STOP
            cvg_api.set_state(cs)
            wait(10, "For Traffic Stats Clear")
            cs = cvg_api.convergence_state()
            cs.transmit.state = cs.transmit.START
            cvg_api.set_state(cs)
            wait(5, "For Traffic to start")
            cs = cvg_api.convergence_state()
            cs.route.names = [route_name]
            cs.route.state = cs.route.WITHDRAW
            cvg_api.set_state(cs)
            wait(FLAP_TIME, "For routes to be withdrawn")
            flow_stats = get_flow_stats(cvg_api)
            tx_frame_rate = int(flow_stats[0].frames_tx_rate)
            rx_frame_rate = int(flow_stats[0].frames_rx_rate)
            max_tol = int(tx_frame_rate) + tolerence_pkts
            min_tol = int(tx_frame_rate) - tolerence_pkts
            logger.info("TxFrameRate:{},RxFrameRate:{}".format(tx_frame_rate, rx_frame_rate))
            assert (rx_frame_rate > max_tol or rx_frame_rate < min_tol) == False, "Traffic has not converged after link flap" 
            logger.info("Traffic has converged after route withdraw")

            """ Get control plane to data plane convergence value """
            request = cvg_api.convergence_request()
            request.convergence.flow_names = []
            convergence_metrics = cvg_api.get_results(request).flow_convergence
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms): {}'.format(metrics.control_plane_data_plane_convergence_us/1000))
            avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
            avg_delta.append(int(flow_stats[0].frames_tx)-int(flow_stats[0].frames_rx))
            """ Advertise the routes back at the end of iteration """
            cs = cvg_api.convergence_state()
            cs.route.names = [route_name]
            cs.route.state = cs.route.ADVERTISE
            cvg_api.set_state(cs)
            logger.info('Readvertise {} routes back at the end of iteration {}'.format(route_name, i+1))
        table.append('%s route withdraw' % route_name)
        table.append(route_type)
        table.append(NO_OF_ROUTES)
        table.append(ITERATION)
        table.append(mean(avg_delta))
        table.append(mean(avg))
        return table

def configure_inter_duts(duthosts, conn_graph_facts, route_type ='ipv4'):
    nwlist = create_ip_list(inter_dut_network_start, len(duthosts)-1, 8) 
    for i in range(0, len(duthosts)-1):
        host1 = duthosts[i]
        host2 = duthosts[i+1]
        h1_h2_ports = get_dut_interconnected_ports(conn_graph_facts, host1.hostname, host2.hostname)
        iplist = create_ip_list(nwlist[i], 2, 32)
        h1_h2_port = h1_h2_ports[0]
        host1.shell("sudo config interface ip add %s %s/%s \n"%(h1_h2_port[0], iplist[0], ipMask))
        host2.shell("sudo config interface ip add %s %s/%s \n"%(h1_h2_port[1], iplist[1], ipMask))
        bgp_config1 = (
                    "vtysh "
                    "-c 'configure terminal' "
                    "-c 'router bgp %s' "
                    "-c 'neighbor %s remote-as %s' "
                    "-c 'address-family ipv4 unicast' "
                    "-c 'neighbor %s activate' "
                    "-c 'exit' "
        )%(dutsAsNum[i], iplist[1], dutsAsNum[i+1], iplist[1] )
        host1.shell(bgp_config1)
        bgp_config2 = (
                    "vtysh "
                    "-c 'configure terminal' "
                    "-c 'router bgp %s' "
                    "-c 'neighbor %s remote-as %s' "
                    "-c 'address-family ipv4 unicast' "
                    "-c 'neighbor %s activate' "
                    "-c 'exit' "
        )%(dutsAsNum[i+1], iplist[0], dutsAsNum[i], iplist[0] )
        host2.shell(bgp_config2)

def save_current_config(duthost):
    duthost.command("sudo config save -y")
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db.json", "/etc/sonic/config_db_backup.json"))

def cleanup_config(duthost):
    """
    Cleaning up dut config at the end of the test

    Args:
        duthost (pytest fixture): duthost fixture
    """
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db_backup.json","/etc/sonic/config_db.json"))
    duthost.shell("sudo config reload -y \n")
    logger.info("Wait until all critical services are fully started")
    wait_until(120, 10, 1, duthost.critical_services_fully_started)
    logger.info('Convergence Test Completed')

def get_rib_in_convergence_time(cvg_api, route_names, route_type="ipv4"):
    """
    Args:
        route_name: name of the route
    """
    table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
    for i in range(0, ITERATION):
        logger.info('|---- RIB-IN Convergence test, Iteration : {} ----|'.format(i+1))
        """ withdraw all routes before starting traffic """
        logger.info('Withdraw All Routes before starting traffic')
        cs = cvg_api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.WITHDRAW
        cvg_api.set_state(cs)
        wait(TIMEOUT-25, "For Routes to be withdrawn")
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = cvg_api.convergence_state()
        cs.protocol.state = cs.protocol.START
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        """ Start Traffic """
        logger.info('Starting Traffic')
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.START
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For Traffic To start")
        flow_stats = get_flow_stats(cvg_api)
        tx_frame_rate = int(flow_stats[0].frames_tx_rate)
        rx_frame_rate = int(flow_stats[0].frames_rx_rate)
        assert tx_frame_rate != 0, "Traffic has not started"
        assert rx_frame_rate == 0

        """ Advertise All Routes """
        logger.info('Advertising all Routes from {}'.format(route_names))
        cs = cvg_api.convergence_state()
        cs.route.names = route_names
        cs.route.state = cs.route.ADVERTISE
        cvg_api.set_state(cs)
        wait(TIMEOUT, "For all routes to be ADVERTISED")
        flow_stats = get_flow_stats(cvg_api)
        tx_frame_rate = int(flow_stats[0].frames_tx_rate)
        rx_frame_rate = int(flow_stats[0].frames_rx_rate)
        max_tol = int(tx_frame_rate) + tolerence_pkts
        min_tol = int(tx_frame_rate) - tolerence_pkts
        logger.info("TxFrameRate:{},RxFrameRate:{}".format(tx_frame_rate, rx_frame_rate))
        assert (rx_frame_rate > max_tol or rx_frame_rate < min_tol) == False, "Traffic has not converged" 
        logger.info("Traffic has converged after route advertisement")

        """ Get RIB-IN convergence """
        request = cvg_api.convergence_request()
        request.convergence.flow_names = []
        convergence_metrics = cvg_api.get_results(request).flow_convergence
        for metrics in convergence_metrics:
            logger.info('RIB-IN Convergence time (ms): {}'.format(metrics.control_plane_data_plane_convergence_us/1000))
        avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
        avg_delta.append(int(flow_stats[0].frames_tx)-int(flow_stats[0].frames_rx))
        """ Stop traffic at the end of iteration """
        logger.info('Stopping Traffic at the end of iteration{}'.format(i+1))
        cs = cvg_api.convergence_state()
        cs.transmit.state = cs.transmit.STOP
        cvg_api.set_state(cs)
        wait(TIMEOUT-20, "For Traffic To stop")
        """ Stopping Protocols """
        logger.info("Stopping all protocols ...")
        cs = cvg_api.convergence_state()
        cs.protocol.state = cs.protocol.STOP
        cvg_api.set_state(cs)
        wait(TIMEOUT-20, "For Protocols To STOP")
    table.append('Advertise All BGP Routes')
    table.append(route_type)
    table.append(NO_OF_ROUTES)
    table.append(ITERATION)
    table.append(mean(avg_delta))
    table.append(mean(avg))
    return table

def verify_loadshare(tx_pkt, rx_pkt):
    tol_val = tx_pkt * tolerenceVal / 100
    if rx_pkt > tx_pkt + tol_val or rx_pkt < tx_pkt - tol_val :
        raise Exception("Traffic Loadshare failed")

def verify_interface(duthost,interface):
    """
       proc : verify_interface
       :param :
       :return admin and oper state of interface

    """
    admin_status = ""
    oper_status = ""
    out = duthost.command("show interfaces status {}".format(interface))['stdout']
    logger.info(out)
    match = re.search("%s.*\w+\s+(\w+)\s+(\w+)\s+\S+\s+\S+" % interface, out)
    if match:
        admin_status = match.group(1)
        oper_status = match.group(2)
    return (admin_status, oper_status)

def verify_ping_from_dut(duthost, ip):
    """
       proc: verify_ping_from_dut
       :return True/False
    """
    logger.info("Verify ping to {} from DUT".format(ip))
    try:
        res = duthost.command("ping -c 5 {}".format(ip))['stdout']
    except:
        res = "100% packet loss"
    if re.search(" 0% packet loss",res):
        logger.info("ping successful to {}. PASSED!!".format(ip))
        return True
    else:
        logger.info("ping unsuccessful to {}. FAILED!!".format(ip))
        return False

def verify_bgp_neighbor_state(duthost, ipAddress, iterVal=1, sleepVal=10, expState ="Established", route_type='ipv4'):
    """
       proc : verify_bgp_neighbor_state
       :param :
       :return : True/False

    """
    logger.info("Verify BGP Neighbor state {}".format(ipAddress))
    for count in range(iterVal):
        if route_type == 'ipv4':
            ret = duthost.command("show ip bgp neighbors {}".format(ipAddress))["stdout"]
        else:
            ret = duthost.command("show ipv6 bgp neighbors {}".format(ipAddress))["stdout"]
        if re.search('BGP\s+state\s+=\s+%s'%(expState), ret):
            logger.info(ret)
            logger.info("BGP neighbor {} Established between {} and IXIA PASSED".format(ipAddress, duthost.hostname))
            return True
        else:
            logger.info("Waiting for bgp neighbors to come up")
            wait(sleepVal, "For Protocols To start")
    else:
        logger.info("BGP neighbor {} Established between {} and IXIA FAILED".format(ipAddress, duthost.hostname))
        return False

def verify_route_summary(duthost, expRts, version="ip", protocol="ebgp", iterVal=1, sleepVal =2):
    result = True
    availableRoutes = 0

    for i in range (iterVal):
        logger.info("ITERATION : {}".format(i))
        out = duthost.command("show {} route summary".format(version))["stdout"]
        logger.info(out)
        match = re.search("%s\s+\d+\s+(\d+)"%protocol, out)
        if match:
            availableRoutes = int(match.group(1))
            if availableRoutes == int(expRts):
                logger.info("Verify routes  in {} via ebgp PASSED!!".format(duthost.hostname))
                break
            else:
                logger.info("Expected {} routes {}, actual {}".format(protocol, expRts,
                                                                       availableRoutes))
                wait(sleepVal, "For routes to update")
    else:
        logger.info("Verify routes in {} via ebgp FAILED!!".format(duthost.hostname))
        result = False

    return {'result' : result, 'avlRoutes' : availableRoutes}

def get_system_stats(duthost):
    """Gets Memory and CPU usage from DUT"""
    stdout_lines = duthost.command("vmstat")["stdout_lines"]
    data = list(map(float, stdout_lines[2].split()))

    total_memory  = sum(data[2:6])
    used_memory = sum(data[4:6])

    total_cpu = sum(data[12:15])
    used_cpu = sum(data[12:14])

    return (used_memory, total_memory, used_cpu, total_cpu)

def verify_interfaces(duthosts, ports):
    j, port_count=0, 0
    for val in RX_DUTS_PORT_RATIO:
        host = duthosts[val[0]-1]
        if j == 0:
            port_count = NO_OF_TX_PORTS + val[1]
        else:
            port_count +=val[1]
        for i in range(j, port_count):  
            admin_state, oper_state = verify_interface(host, ports[i])
            if not (admin_state == "up" and oper_state == "up"):
                logger.info("port {} is not up initially. Hence Aborting!!".format(ports[i]))
                raise Exception("Initial port Check failed for {} in dut {}".format(ports[i], host.hostname))
            j +=1

def verify_ping(duthosts, tgenIps):
    result = True
    j, port_count=0, 0
    for val in RX_DUTS_PORT_RATIO:
        host = duthosts[val[0]-1]
        if j == 0:
            port_count = NO_OF_TX_PORTS + val[1]
        else:
            port_count +=val[1]
        for i in range(j, port_count):   
            if not verify_ping_from_dut(host, tgenIps[i]):
                result = False
            j+=1
    logger.info("return verify ping {}".format(result))
    return result

def verify_bgp_neighbors(duthosts, tgenIps, route_type='ipv4'):
    result = True
    j, port_count=0, 0
    for val in RX_DUTS_PORT_RATIO:
        host = duthosts[val[0]-1]
        port_count +=val[1]
        for i in range(j, port_count): 
            if not verify_bgp_neighbor_state(host, tgenIps[i], route_type=route_type):   
                result = False
            j+=1
    logger.info("return verify bgp neighbors {}".format(result))
    return result

def verify_routes(duthosts , route_type = 'ipv4'):
    result = True
    for val in RX_DUTS_PORT_RATIO:
        duthost = duthosts[val[0]-1]
        if val[1] >0:
            if route_type == 'ipv4':
                if not verify_route_summary(duthost, NO_OF_ROUTES)['result']:
                    result = False
            else:
                if not verify_route_summary(duthost, NO_OF_ROUTES, version=route_type)['result']:
                    result = False
    logger.info("return verify routes {}".format(result))
    return result

