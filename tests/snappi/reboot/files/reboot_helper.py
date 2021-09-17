from tabulate import tabulate
from tests.common.utilities import (wait, wait_until)
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot
import json
import ipaddr
logger = logging.getLogger(__name__)

TGEN_AS_NUM = 65200
TIMEOUT = 30
BGP_TYPE = 'ebgp'
temp_tg_port = dict()


def run_reboot_test(cvg_api,
                    duthost,
                    localhost,
                    reboot_type,):
    """
    Run Local link failover test

    Args:
        cvg_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        localhost (pytest fixture): localhost handle
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        reboot_type : Type of reboot
    """

    """ Create bgp config on dut """
    #duthost_bgp_config(duthost, tgen_ports)

    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(cvg_api)

    """
        Run the convergence test by flapping all the rx
        links one by one and calculate the convergence valuess
    """
    get_convergence_for_reboot_test(duthost, localhost, cvg_api, tgen_bgp_config, reboot_type,)

    #cleanup_config(duthost)


def duthost_bgp_config(duthost, tgen_ports):
    """
    Configures BGP on the DUT with N-1 ecmp

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    global temp_tg_port
    duthost.command("sudo config save -y")
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db.json", "/etc/sonic/config_db_backup.json"))
    temp_tg_port = tgen_ports
    for i in range(1, 4):
        intf_config = (
            "sudo config interface ip remove %s %s/%s \n"
            "sudo config interface ip remove %s %s/%s \n"
        )
        intf_config %= (tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ip'], tgen_ports[i]['prefix'], tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ipv6'], tgen_ports[i]['ipv6_prefix'])
        logger.info('Removing configured IP and IPv6 Address from %s' % (tgen_ports[i]['peer_port']))
        duthost.shell(intf_config)
    vlan_config=(
        'sudo config vlan add 1000\n'
        'sudo config vlan member add -u 1000 %s\n'
        'sudo config vlan member add -u 1000 %s\n'
        'sudo config interface ip add Vlan1000 192.168.1.1/16\n'
        'sudo config interface ip add Vlan1000 5001::1/64\n'
    )
    vlan_config %= (tgen_ports[3]['peer_port'], tgen_ports[2]['peer_port'])
    logger.info('Adding %s and %s to Vlan 1000' % (tgen_ports[3]['peer_port'], tgen_ports[2]['peer_port']))
    duthost.shell(vlan_config)
    portchannel_config = (
        "sudo config portchannel add PortChannel1 \n"
        "sudo config portchannel member add PortChannel1 %s\n"
        "sudo config interface ip add PortChannel1 %s/%s\n"
        "sudo config interface ip add PortChannel1 %s/%s\n"
    )
    portchannel_config %= (tgen_ports[1]['peer_port'], tgen_ports[1]['peer_ip'], tgen_ports[1]['prefix'], tgen_ports[1]['peer_ipv6'], 64)
    logger.info('Configuring %s to PortChannel1' % (tgen_ports[1]['peer_port']))
    logger.info('Portchannel1 (IPv4,IPv6)  : ({},{})'.format(tgen_ports[1]['peer_ip'], tgen_ports[1]['peer_ipv6']))
    duthost.shell(portchannel_config)
    loopback = (
        "sudo config interface ip add Loopback1 1.1.1.1/32\n"
    )
    logger.info('Configuring 1.1.1.1/32 on the loopback interface')
    duthost.shell(loopback)
    logger.info('Configuring BGP in config_db.json')
    bgp_neighbors = {tgen_ports[1]['ipv6']: {"rrclient": "0","name": "ARISTA08T0","local_addr": tgen_ports[1]['peer_ipv6'],"nhopself": "0","holdtime": "90","asn": TGEN_AS_NUM,"keepalive": "30"},tgen_ports[1]['ip']: {"rrclient": "0","name": "ARISTA08T0","local_addr": tgen_ports[1]['peer_ip'],"nhopself": "0","holdtime": "90","asn": TGEN_AS_NUM,"keepalive": "30"}}
    cdf = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
    for neighbor, neighbor_info in bgp_neighbors.items():
        cdf["BGP_NEIGHBOR"][neighbor] = neighbor_info

    with open("/tmp/sconfig_db.json", 'w') as fp:
        json.dump(cdf, fp, indent=4)
    duthost.copy(src="/tmp/sconfig_db.json", dest="/tmp/config_db_temp.json")
    cdf = json.loads(duthost.shell("sonic-cfggen -j /tmp/config_db_temp.json --print-data")['stdout'])
    print(cdf)
    duthost.command("sudo cp {} {} \n".format("/tmp/config_db_temp.json", "/etc/sonic/config_db.json"))
    logger.info('Reloading config to apply BGP config')
    duthost.shell("sudo config reload -y \n")
    wait(TIMEOUT+60, "For Config to reload \n")


def get_flow_stats(cvg_api, name):
    """
    Args:
        cvg_api (pytest fixture): Snappi API
    """
    request = cvg_api.convergence_request()
    request.metrics.flow_names = [name]
    return cvg_api.get_results(request).flow_metric


def get_macs(mac, count, offset=1):
    """
    Take mac as start mac returns the count of macs in a list
    """
    mac_list = list()
    for i in range(count):
        mac_address = "{:012X}".format(int(mac, 16) + offset * i)
        mac_address = ":".join(
            format(s, "02x") for s in bytearray.fromhex(mac_address)
        )
        mac_list.append(mac_address)
    return mac_list


def get_ip_addresses(ip, count,type='ipv4'):
    """
    Take ip as start ip returns the count of ips in a list
    """
    ip_list = list()
    for i in range(count):
        if type == 'ipv6':
            ipaddress = ipaddr.IPv6Address(ip)
        else:
            ipaddress = ipaddr.IPv4Address(ip)
        ipaddress = ipaddress + i
        value = ipaddress._string_from_ip_int(ipaddress._ip)
        ip_list.append(value)
    return ip_list


def __tgen_bgp_config(cvg_api,):
    """
    Creating  BGP config on TGEN

    Args:
        cvg_api (pytest fixture): snappi API
    """
    temp_tg_port=[{'ip': '24.1.1.2', 'card_id': '4', 'peer_port': 'Ethernet76', 'prefix': u'24', 'location': '10.36.78.53;4;4', 'ipv6': '2000:4::8', 'ipv6_prefix': u'124', 'port_id': '4', 'peer_ip': u'24.1.1.1', 'speed': 'speed_100_gbps', 'peer_device': 'sonic-s6100-dut', 'peer_ipv6': u'2000:4::1'}, {'ip': '23.1.1.2', 'card_id': '4', 'peer_port': 'Ethernet72', 'prefix': u'24', 'location': '10.36.78.53;4;3', 'ipv6': '2000:3::3', 'ipv6_prefix': u'124', 'port_id': '3', 'peer_ip': u'23.1.1.1', 'speed': 'speed_100_gbps', 'peer_device': 'sonic-s6100-dut', 'peer_ipv6': u'2000:3::1'}, {'ip': '22.1.1.2', 'card_id': '4', 'peer_port': 'Ethernet68', 'prefix': u'24', 'location': '10.36.78.53;4;2', 'ipv6': '2000:2::f', 'ipv6_prefix': u'124', 'port_id': '2', 'peer_ip': u'22.1.1.1', 'speed': 'speed_100_gbps', 'peer_device': 'sonic-s6100-dut', 'peer_ipv6': u'2000:2::1'}, {'ip': '21.1.1.2', 'card_id': '4', 'peer_port': 'Ethernet64', 'prefix': u'24', 'location': '10.36.78.53;4;1', 'ipv6': '2000:1::a', 'ipv6_prefix': u'124', 'port_id': '1', 'peer_ip': u'21.1.1.1', 'speed': 'speed_100_gbps', 'peer_device': 'sonic-s6100-dut', 'peer_ipv6': u'2000:1::1'}]
    conv_config = cvg_api.convergence_config()
    cvg_api.enable_scaling(True)
    config = conv_config.config
    p1, p2, p3 = (
        config.ports.port(name="t1", location=temp_tg_port[1]['location'])
        .port(name="server2", location=temp_tg_port[2]['location'])
        .port(name="server1", location=temp_tg_port[3]['location'])
    )
    lag3 = config.lags.lag(name="lag1")[-1]
    lp3 = lag3.ports.port(port_name=p1.name)[-1]
    lp3.protocol.lacp.actor_system_id = "00:11:03:00:00:03"
    lp3.ethernet.name = "lag_Ethernet 3"
    lp3.ethernet.mac = "00:13:01:00:00:01"

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = "speed_100_gbps"
    layer1.auto_negotiate = False

    conf_values = dict()
    num_of_devices = 1000
    conf_values['server_1_ipv4'] = get_ip_addresses("192.168.1.2", 2000)[::2]
    conf_values['server_2_ipv4'] = get_ip_addresses("192.168.1.2", 2000)[1::2]
    conf_values['server_1_ipv6'] = get_ip_addresses("5000::2", 2000, 'ipv6')[::2]
    conf_values['server_2_ipv6'] = get_ip_addresses("5000::2", 2000, 'ipv6')[1::2]
    conf_values['server_1_mac'] = get_macs("001700000011", num_of_devices)
    conf_values['server_2_mac'] = get_macs("001600000011", num_of_devices)
    for i in range(1, num_of_devices+1):
        #server1
        d1 = config.devices.device(name='Server_1_{}'.format(i-1))[-1]
        d1.container_name = p3.name
        eth_1 = d1.ethernet
        eth_1.name = 'Ethernet 1_{}'.format(i-1)
        eth_1.mac = conf_values['server_1_mac'][i-1]
        ipv4_1 = d1.ethernet.ipv4
        ipv4_1.name = 'IPv4 1_{}'.format(i-1)
        ipv4_1.address = conf_values['server_1_ipv4'][i-1]
        ipv4_1.gateway = '192.168.1.1'
        ipv4_1.prefix = 16
        ipv6_1 = d1.ethernet.ipv6
        ipv6_1.name = 'IPv6 1_{}'.format(i-1)
        ipv6_1.address = conf_values['server_1_ipv6'][i-1]
        ipv6_1.gateway = '5001::1'
        ipv6_1.prefix = 64
        #server2
        d2 = config.devices.device(name='Server_2_{}'.format(i-1))[-1]
        d2.container_name = p2.name
        eth_2 = d2.ethernet
        eth_2.name = 'Ethernet 2_{}'.format(i-1)
        eth_2.mac = conf_values['server_2_mac'][i-1]
        ipv4_2 = d2.ethernet.ipv4
        ipv4_2.name = 'IPv4 2_{}'.format(i-1)
        ipv4_2.address = conf_values['server_2_ipv4'][i-1]
        ipv4_2.gateway = '192.168.1.1'
        ipv4_2.prefix = 16
        ipv6_2 = d2.ethernet.ipv6
        ipv6_2.name = 'IPv6 2_{}'.format(i-1)
        ipv6_2.address = conf_values['server_2_ipv6'][i-1]
        ipv6_2.gateway = '5001::1'
        ipv6_2.prefix = 64

    #T1
    d3 = config.devices.device(name="T1")[-1]
    d3.container_name = lag3.name
    eth_3 = d3.ethernet
    eth_3.name = 'Ethernet 3'
    eth_3.mac = "00:14:01:00:00:01"
    ipv4_3 = eth_3.ipv4
    ipv4_3.name = 'IPv4 3'
    ipv4_3.address = temp_tg_port[1]['ip']
    ipv4_3.gateway = temp_tg_port[1]['peer_ip']
    ipv4_3.prefix = 24
    ipv6_3 = eth_3.ipv6
    ipv6_3.name = 'IPv6 3'

    ipv6_3.address = temp_tg_port[1]['ipv6']
    ipv6_3.gateway = temp_tg_port[1]['peer_ipv6']
    ipv6_3.prefix = 64
    bgpv4_stack = ipv4_3.bgpv4
    bgpv4_stack.name = 'BGP 3'
    bgpv4_stack.as_type = BGP_TYPE
    bgpv4_stack.dut_address = temp_tg_port[1]['peer_ip']
    bgpv4_stack.local_address = temp_tg_port[1]['ip']
    bgpv4_stack.as_number = int(TGEN_AS_NUM)
    route_range1 = bgpv4_stack.bgpv4_routes.bgpv4route(name="Network Group 1")[-1]
    route_range1.addresses.bgpv4routeaddress(address='200.1.0.1', prefix=32, count=1)
    bgpv6_stack = ipv6_3.bgpv6
    bgpv6_stack.name = r'BGP+_3'
    bgpv6_stack.as_type = BGP_TYPE
    bgpv6_stack.dut_address = temp_tg_port[1]['peer_ipv6']
    bgpv6_stack.local_address = temp_tg_port[1]['ipv6']
    bgpv6_stack.as_number = int(TGEN_AS_NUM)
    route_range2 = bgpv6_stack.bgpv6_routes.bgpv6route(name="Network Group 2")[-1]
    route_range2.addresses.bgpv6routeaddress(address='3000::1', prefix=64, count=1)

    def createTrafficItem(traffic_name, src, dest, rate=50):
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = src
        flow1.tx_rx.device.rx_names = dest
        flow1.size.fixed = 1024
        flow1.rate.percentage = rate
        flow1.metrics.enable = True
    ipv4_1_names = ["IPv4 1_{}".format(i-1) for i in range(1, num_of_devices + 1)]
    ipv4_2_names = ["IPv4 2_{}".format(i-1) for i in range(1, num_of_devices + 1)]
    ipv6_1_names = ["IPv6 1_{}".format(i-1) for i in range(1, num_of_devices + 1)]
    ipv6_2_names = ["IPv6 2_{}".format(i-1) for i in range(1, num_of_devices + 1)]
    createTrafficItem("IPv4_1-IPv4_2", ipv4_1_names, ipv4_2_names)
    createTrafficItem("IPv6_2-IPv6_1", ipv6_2_names, ipv6_1_names)
    createTrafficItem("IPv4_1-T1", ipv4_1_names, [route_range1.name])
    createTrafficItem("IPv6_2-T1", ipv6_2_names, [route_range2.name])
    createTrafficItem("T1-IPv4_1", [route_range1.name], ipv4_1_names)
    return conv_config


def get_convergence_for_reboot_test(duthost,
                                    localhost,
                                    cvg_api,
                                    bgp_config,
                                    reboot_type):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        localhost (pytest fixture): localhost handle
        cvg_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        reboot_type: Type of reboot
    """
    table, dp = [], []
    bgp_config.rx_rate_threshold = 90
    cvg_api.set_config(bgp_config)
    logger.info('Starting Traffic')
    cs = cvg_api.convergence_state()
    flow_names = ["IPv4_1-IPv4_2", "IPv6_2-IPv6_1", "IPv4_1-T1", "IPv6_2-T1", "T1-IPv4_1"]
    cs.transmit.flow_names = flow_names
    cs.transmit.state = cs.transmit.START
    cvg_api.set_state(cs)
    wait(TIMEOUT-10, "For Traffic To start")

    def check_bgp_state():
        req = cvg_api.convergence_request()
        req.bgpv4.peer_names = []
        bgpv4_metrics = cvg_api.get_results(req).bgpv4_metrics
        assert bgpv4_metrics[-1].session_state == "up", "BGP v4 Session State is not UP"
        logger.info("BGP v4 Session State is UP")
        req.bgpv6.peer_names = []
        bgpv6_metrics = cvg_api.get_results(req).bgpv6_metrics
        assert bgpv6_metrics[-1].session_state == "up", "BGP v6 Session State is not UP"
        logger.info("BGP v6 Session State is UP")

    check_bgp_state()
    req = cvg_api.ping_request()
    p1 = req.endpoints.ipv4()[-1]
    p1.src_name = 'IPv4 3'
    p1.dst_ip = "1.1.1.1"
    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
    reboot(duthost, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(360, 10, duthost.critical_services_fully_started), "Not all critical services are fully started")
    check_bgp_state()
    responses = cvg_api.send_ping(req).responses
    assert responses[-1].result == "success"
    logger.info('Ping from IPv4 3 --> {} : {} after {} seconds after {}'.format(p1.dst_ip, responses[-1].result, 180, reboot_type))
    request = cvg_api.convergence_request()
    for i in cs.transmit.flow_names:
        request.metrics.flow_names = [i]
        flow = cvg_api.get_results(request).flow_metric
        assert int(flow[0].frames_tx_rate) != 0, "No Frames sent for traffic item: {}".format(i)
        assert flow[0].frames_tx_rate == flow[0].frames_tx_rate, "Loss observed for Traffic Item: {}".format(i)
        logger.info("No Loss Observed in Traffic Item {}".format(i))

    request.convergence.flow_names = flow_names
    convergence_metrics = cvg_api.get_results(request).flow_convergence
    for metrics in convergence_metrics:
        dp.append(metrics.data_plane_convergence_us/1000)
        logger.info('DP/DP Convergence Time (ms) of {} : {}'.format(i, metrics.data_plane_convergence_us/1000))

    for j, i in enumerate(flow_names):
        table.append([reboot_type, i, dp[j]])
    columns = ['Reboot Type', 'Traffic Item Name', 'Data Plane Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))

def cleanup_config(duthost):
    """
    Cleaning up dut config at the end of the test

    Args:
        duthost (pytest fixture): duthost fixture
    """
    logger.info('Cleaning up config')
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db_backup.json", "/etc/sonic/config_db.json"))
    duthost.shell("sudo config reload -y \n")
    wait(TIMEOUT+30, "For Cleanup to complete \n")
    logger.info('Convergence Test Completed')
