import logging
import time
import pytest
import enum
import random
from datetime import datetime

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_tgen_location,\
    get_dut_port_id

from tests.common.ixia.common_helpers import get_vlan_subnet, get_addrs_in_subnet,\
    get_peer_ixia_chassis, get_vlan_member, get_portchannel_member, get_dut_intfs,\
    get_intf_ipv4_addr, get_mac

from abstract_open_traffic_generator.port import Port
from abstract_open_traffic_generator.config import Options, Config
from abstract_open_traffic_generator.layer1 import Layer1, FlowControl,\
    Ieee8021qbb, AutoNegotiation
import abstract_open_traffic_generator.lag as lag

from abstract_open_traffic_generator.device import Device, Ethernet, Ipv4,\
    Pattern
from ixnetwork_open_traffic_generator.ixnetworkapi import IxNetworkApi
from abstract_open_traffic_generator.port import Options as PortOptions

from abstract_open_traffic_generator.flow import DeviceTxRx, TxRx, Flow, Header,\
    Size, Rate,Duration, FixedSeconds, PortTxRx, PfcPause, EthernetPause, Continuous
from abstract_open_traffic_generator.flow_ipv4 import Priority, Dscp
from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.control import State, ConfigState, FlowTransmitState
from abstract_open_traffic_generator.result import FlowRequest

@pytest.mark.topology("tgen")
@pytest.mark.disable_loganalyzer

def gen_mac(id):
    return '00:11:02:00:00:{:02d}'.format(id)

class PortType(enum.Enum):
    IPInterface = 1
    PortChannelMember = 2
    VlanMember = 3

class PortConfig:
    def __init__(self, id, ip, mac, gw, gw_mac, prefix_len, port_type, peer_port):
        self.id = id
        self.ip = ip
        self.mac = mac
        self.gateway = gw
        self.gateway_mac = gw_mac
        self.prefix_len = prefix_len
        self.type = port_type
        self.peer_port = peer_port

def gen_testbed(conn_data, fanout_data, duthost):
    """
    Returns:
        - config (obj): L2/L3 config of the testbed
        - port_config_list (list): list of port configurations
    """
    empty = None, None

    port_config_list = []

    vlan_member = get_vlan_member(host_ans=duthost)
    portchannel_member = get_portchannel_member(host_ans=duthost)
    dut_mac = get_mac(duthost)

    dut_intfs = get_dut_intfs(conn_data=conn_data,
                              dut_hostname=duthost.hostname)

    """ Filter interfaces """
    for pc in portchannel_member:
        members = portchannel_member[pc]
        portchannel_member[pc] =[x for x in members if x in dut_intfs]

    for vlan in vlan_member:
        members = vlan_member[vlan]
        vlan_member[vlan] =[x for x in members if x in dut_intfs]

    """ Get IP addresses of all the interfaces (L3/Portchannel/Vlan) on DUT """
    intf_ipv4_addrs = get_intf_ipv4_addr(host_ans=duthost)

    """ A DUT should only have one Vlan """
    pytest_require(len(vlan_member) == 1, 'The DUT should only have one Vlan')

    """ A DUT should have at least one portchannel interface """
    pytest_require(len(portchannel_member) > 0,
                   'The DUT should have at least one portchannel interface')

    """ Generate L1 config """
    ixia_fanout = get_peer_ixia_chassis(conn_data=conn_data,
                                        dut_hostname=duthost.hostname)

    if ixia_fanout is None:
        return empty

    ixia_fanout_id = list(fanout_data.keys()).index(ixia_fanout)
    ixia_fanout_list = IxiaFanoutManager(fanout_data)
    ixia_fanout_list.get_fanout_device_details(device_number=ixia_fanout_id)

    ixia_ports = ixia_fanout_list.get_ports(peer_device=duthost.hostname)

    ports = list()
    port_names = list()
    port_speed = None

    for i in range(len(ixia_ports)):
        port = Port(name='Port {}'.format(i),
                    location=get_tgen_location(ixia_ports[i]))

        ports.append(port)
        port_names.append(port.name)

        if port_speed is None:
            port_speed = int(ixia_ports[i]['speed'])
        pytest_assert(port_speed == int(ixia_ports[i]['speed']))

    pfc = Ieee8021qbb(pfc_delay=0,
                      pfc_class_0=0,
                      pfc_class_1=1,
                      pfc_class_2=2,
                      pfc_class_3=3,
                      pfc_class_4=4,
                      pfc_class_5=5,
                      pfc_class_6=6,
                      pfc_class_7=7)

    flow_ctl = FlowControl(choice=pfc)

    auto_negotiation = AutoNegotiation(link_training=True,
                                       rs_fec=True)

    speed_gbps = int(port_speed/1000)

    l1_config = Layer1(name='L1 config',
                       speed='speed_{}_gbps'.format(speed_gbps),
                       auto_negotiate=False,
                       auto_negotiation=auto_negotiation,
                       ieee_media_defaults=False,
                       flow_control=flow_ctl,
                       port_names=port_names)

    config = Config(ports=ports,
                    layer1=[l1_config],
                    options=Options(PortOptions(location_preemption=True)))

    """ Configure interfaces attached to the Vlan """
    for vlan_intf in vlan_member:
        vlan_phy_intfs = vlan_member[vlan_intf]
        vlan_subnet = str(intf_ipv4_addrs[vlan_intf])
        gw_addr, prefix = vlan_subnet.split('/')
        vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, len(vlan_phy_intfs))

        for i in range(len(vlan_phy_intfs)):
            vlan_phy_intf = vlan_phy_intfs[i]
            vlan_ip_addr = vlan_ip_addrs[i]

            port_ids = [id for id, ixia_pot in enumerate(ixia_ports) if ixia_pot['peer_port'] == vlan_phy_intf]
            pytest_assert(len(port_ids) == 1)
            port_id = port_ids[0]
            mac = gen_mac(port_id)

            ip_stack = Ipv4(name='Ipv4 Port {}'.format(port_id),
                            address=Pattern(vlan_ip_addr),
                            prefix=Pattern(prefix),
                            gateway=Pattern(gw_addr),
                            ethernet=Ethernet(name='Ethernet Port {}'.format(port_id),
                                              mac=Pattern(mac)))

            device = Device(name='Device Port {}'.format(port_id),
                            device_count=1,
                            container_name=port_names[port_id],
                            choice=ip_stack)

            config.devices.append(device)

            port_config = PortConfig(id=port_id,
                                     ip=vlan_ip_addr,
                                     mac=mac,
                                     gw=gw_addr,
                                     gw_mac=dut_mac,
                                     prefix_len=prefix,
                                     port_type=PortType.VlanMember,
                                     peer_port=vlan_phy_intf)

            port_config_list.append(port_config)

    """ Configure interfaces attached to the portchannel """
    for pc_intf in portchannel_member:
        pc_phy_intfs = portchannel_member[pc_intf]
        pc_subnet = str(intf_ipv4_addrs[pc_intf])
        gw_addr, prefix = pc_subnet.split('/')
        pc_ip_addr = get_addrs_in_subnet(pc_subnet, 1)[0]

        lag_ports = []

        for i in range(len(pc_phy_intfs)):
            pc_phy_intf = pc_phy_intfs[i]

            port_ids = [id for id, ixia_pot in enumerate(ixia_ports) if ixia_pot['peer_port'] == pc_phy_intf]
            pytest_assert(len(port_ids) == 1)
            port_id = port_ids[0]
            mac = gen_mac(port_id)

            proto = lag.Protocol(choice=lag.Lacp(
                actor_system_id='00:00:00:00:00:01',
                actor_system_priority=1,
                actor_port_priority=1,
                actor_port_number=1,
                actor_key=1))

            eth = lag.Ethernet(name='Ethernet Port {}'.format(port_id),
                               mac=mac)

            lag_port = lag.Port(port_name=ports[port_id].name, protocol=proto, ethernet=eth)
            lag_ports.append(lag_port)

            port_config = PortConfig(id=port_id,
                                     ip=pc_ip_addr,
                                     mac=mac,
                                     gw=gw_addr,
                                     gw_mac=dut_mac,
                                     prefix_len=prefix,
                                     port_type=PortType.PortChannelMember,
                                     peer_port=pc_phy_intf)

            port_config_list.append(port_config)

        lag_intf = lag.Lag(name='Lag {}'.format(pc_intf), ports=lag_ports)
        config.lags.append(lag_intf)

        ip_stack = Ipv4(name='Ipv4 {}'.format(pc_intf),
                        address=Pattern(pc_ip_addr),
                        prefix=Pattern(prefix),
                        gateway=Pattern(gw_addr),
                        ethernet=Ethernet(name='Ethernet {}'.format(pc_intf)))

        device = Device(name='Device {}'.format(pc_intf),
                        device_count=1,
                        container_name=lag_intf.name,
                        choice=ip_stack)

        config.devices.append(device)

    return config, port_config_list

def gen_traffic(testbed_config, duthost, vlan_port_config_list, pc_port_config_list, active_pc_port_id):
    """ Generate all to all traffic among all the Vlan ports and a portchannel port """

    """ Shutdown unused portchannel members """
    for i in range(len(pc_port_config_list)):
        dut_port = pc_port_config_list[i].peer_port
        if i == active_pc_port_id:
            duthost.shell('sudo config interface startup {}'.format(dut_port))
        else:
            duthost.shell('sudo config interface shutdown {}'.format(dut_port))

    active_port_config_list = vlan_port_config_list + [pc_port_config_list[active_pc_port_id]]

    flows = []
    rate_percent = 90 / len(active_port_config_list)
    duration_sec = 2
    pkt_size = 1024

    for tx_port_config in active_port_config_list:
        for rx_port_config in active_port_config_list:
            src_id = tx_port_config.id
            dst_id = rx_port_config.id

            if src_id == dst_id:
                continue

            src_ip = tx_port_config.ip
            dst_ip = rx_port_config.ip

            src_mac = tx_port_config.mac
            if tx_port_config.gateway == rx_port_config.gateway and \
               tx_port_config.prefix_len == rx_port_config.prefix_len:
                """ If soruce and destination port are in the same subnet """
                dst_mac = rx_port_config.mac
            else:
                dst_mac = tx_port_config.gateway_mac

            flow_name = 'Test Flow {} -> {}'.format(src_id, dst_id)

            endpoint = PortTxRx(tx_port_name=testbed_config.ports[src_id].name,
                                rx_port_name=testbed_config.ports[dst_id].name)

            eth_hdr = EthernetHeader(src=FieldPattern(src_mac),
                                     dst=FieldPattern(dst_mac))

            flow_dscp = Priority(Dscp(phb=FieldPattern(choice=[3])))
            ipv4_hdr = Ipv4Header(src=FieldPattern(src_ip),
                                  dst=FieldPattern(dst_ip),
                                  priority=flow_dscp)

            flow = Flow(
                name=flow_name,
                tx_rx=TxRx(endpoint),
                packet=[Header(choice=eth_hdr), Header(choice=ipv4_hdr)],
                size=Size(pkt_size),
                rate=Rate('line', rate_percent),
                duration=Duration(FixedSeconds(seconds=duration_sec))
            )
            flows.append(flow)

    return flows

def run_traffic(api, config):
    flow_names = [flow.name for flow in config.flows]
    pkt_size = config.flows[0].size.fixed
    rate_percent = config.flows[0].rate.value
    duration_sec = config.flows[0].duration.seconds.seconds

    port_speed = config.layer1[0].speed
    words = port_speed.split('_')
    pytest_assert(len(words) == 3 and words[1].isdigit(),
                  'Fail to get port speed from {}'.format(port_speed))
    speed_gbps = int(words[1])

    api.set_state(State(ConfigState(config=config, state='set')))

    api.set_state(State(FlowTransmitState(state='start')))

    time.sleep(duration_sec + 1)

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        rows = api.get_flow_results(FlowRequest(flow_names=flow_names))
        transmit_states = [row['transmit'] for row in rows]
        if len(rows) == len(flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            time.sleep(1)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    rows = api.get_flow_results(FlowRequest(flow_names=flow_names))
    api.set_state(State(FlowTransmitState(state='stop')))

    tolerance = 0.05

    for row in rows:
        tx_frames = row['frames_tx']
        rx_frames = row['frames_rx']
        flow_name = row['name']

        pytest_assert(tx_frames == rx_frames,
                      '{} should not have any dropped packet'.format(flow_name))

        exp_rx_pkts =  rate_percent / 100.0 * speed_gbps * 1e9 * duration_sec / 8.0 / pkt_size
        deviation = (rx_frames - exp_rx_pkts) / float(exp_rx_pkts)

        pytest_assert(abs(deviation) < tolerance,
                      '{} should receive {} packets (actual {})'.\
                      format(flow_name, exp_rx_pkts, rx_frames))

def test_tgen_vlan_lag(ixia_api,
                       conn_graph_facts,
                       fanout_graph_facts,
                       duthosts,
                       rand_one_dut_hostname):

    duthost = duthosts[rand_one_dut_hostname]
    config, port_config_list = gen_testbed(conn_data=conn_graph_facts,
                                           fanout_data=fanout_graph_facts,
                                           duthost=duthost)

    vlan_port_config_list  = [x for x in port_config_list if x.type == PortType.VlanMember]
    pc_port_config_list  = [x for x in port_config_list if x.type == PortType.PortChannelMember]

    for pc_port_id in range(len(pc_port_config_list)):
        config.flows = gen_traffic(testbed_config=config,
                                   duthost=duthost,
                                   vlan_port_config_list=vlan_port_config_list,
                                   pc_port_config_list=pc_port_config_list,
                                   active_pc_port_id=pc_port_id)

        run_traffic(api=ixia_api, config=config)
