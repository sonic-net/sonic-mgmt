import time
import pytest
import sys

from tests.common.reboot import logger
from tests.common.helpers.assertions import pytest_assert
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_location

from tests.common.ixia.common_helpers import get_vlan_subnet, \
    get_addrs_in_subnet

###############################################################################
# Imports for Tgen and IxNetwork abstract class
###############################################################################

from abstract_open_traffic_generator.port import Port
from abstract_open_traffic_generator.result import PortRequest
from abstract_open_traffic_generator.config import Options
from abstract_open_traffic_generator.config import Config

from abstract_open_traffic_generator.layer1 import\
    Layer1, OneHundredGbe, FlowControl, Ieee8021qbb

from abstract_open_traffic_generator.device import *

from abstract_open_traffic_generator.flow import \
    Flow, TxRx, DeviceTxRx, PortTxRx, Header, Size, Rate, Duration, \
    Continuous, PfcPause

from abstract_open_traffic_generator.flow_ipv4 import\
    Priority, Dscp

from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.port import Options as PortOptions


@pytest.fixture
def ports_config(conn_graph_facts,
                 fanout_graph_facts) :
    """
    ports_config fixture to create traffic generator configs

    :param conn_graph_facts: Testbed topology
    :param fanout_graph_facts: Fanout Graph Facts
    """

    class PortsConfig(object):
        def __init__(self,
                     conn_graph_facts,
                     fanout_graph_facts):
            self.conn_graph_facts = conn_graph_facts
            self.fanout_graph_facts = fanout_graph_facts

        def get_available_phy_ports(self):
            """
            Adds interface speed and returns available physical ports

            Return:
                [{'card_id': u'9',
                'ip': u'10.36.78.53',
                'peer_port': u'Ethernet0',
                'port_id': u'1',
                'speed': 100000},
                {'card_id': u'9',
                'ip': u'10.36.78.53',
                'peer_port': u'Ethernet4',
                'port_id': u'2',
                'speed': 100000},
                {'card_id': u'9',
                'ip': u'10.36.78.53',
                'peer_port': u'Ethernet8',
                'port_id': u'3',
                'speed': 100000}]
            """
            fanout_devices = IxiaFanoutManager(self.fanout_graph_facts)
            fanout_devices.get_fanout_device_details(device_number=0)
            device_conn = self.conn_graph_facts['device_conn']
            available_phy_port = fanout_devices.get_ports()
            for intf in available_phy_port:
                peer_port = intf['peer_port']
                intf['speed'] = int(device_conn[peer_port]['speed'])
            return available_phy_port

        def create_ports_list(self,no_of_ports):
            """
            A Function creates ports_list as the testcase needs to be repeated for 
            all available ports in the testbed even if the test needs n number of ports

            :param no_of_ports: Number of minimum required ports for the test

            Ex: If a test needs 2 ports and testbed has 3 ports. A 3 ports testbed will 
                get 2 combinations of ports [1,2] and [2,3]
            Return: 
                [[{'card_id': '9',
                'ip': '10.36.78.53',
                'peer_port': 'Ethernet0',
                'port_id': '1',
                'speed': 100000},
                {'card_id': '9',
                'ip': '10.36.78.53',
                'peer_port': 'Ethernet4',
                'port_id': '2',
                'speed': 100000}],
                [{'card_id': '9',
                'ip': '10.36.78.53',
                'peer_port': 'Ethernet4',
                'port_id': '2',
                'speed': 100000},
                {'card_id': '9',
                'ip': '10.36.78.53',
                'peer_port': 'Ethernet8',
                'port_id': '3',
                'speed': 100000}]] 
            """
            available_phy_port = self.get_available_phy_ports()
            overlap_size = no_of_ports - 1
            ports_list = [available_phy_port[i:i+no_of_ports]
                          for i in range(0, len(available_phy_port), no_of_ports-overlap_size)]
            ports_list = [ele for ele in ports_list if len(ele) == no_of_ports]
            return ports_list

        def create_config(self,phy_ports):
            """
            Creates config for traffic generator with given physical ports

            :param phy_ports: Physical ports config creation on traffic generator
            """
            ports = []
            one_hundred_gbe_ports = []

            for index,phy_port in enumerate(phy_ports,1):
                port_location = get_location(phy_port)
                port = Port(name='Port'+str(index),location=port_location)
                if (phy_port['speed']/1000==100):
                    one_hundred_gbe_ports.append(port.name)
                else:
                    pytest_assert(False,
                                  "This test supports only 100gbe speed as of now, need to enhance the script based on requirement")

                ports.append(port)
            
            pfc = Ieee8021qbb(pfc_delay=1,
                              pfc_class_0=0,
                              pfc_class_1=1,
                              pfc_class_2=2,
                              pfc_class_3=3,
                              pfc_class_4=4,
                              pfc_class_5=5,
                              pfc_class_6=6,
                              pfc_class_7=7)

            flow_ctl = FlowControl(choice=pfc)

            one_hundred_gbe = OneHundredGbe(link_training=True,
                                            ieee_media_defaults=False,
                                            auto_negotiate=False,
                                            speed='one_hundred_gbps',
                                            flow_control=flow_ctl,
                                            rs_fec=True)

            layer1 = Layer1(name='Layer1 settings',
                            choice=one_hundred_gbe,
                            port_names=one_hundred_gbe_ports)

            config = Config(ports=ports,
                            layer1=[layer1],
                            options=Options(PortOptions(location_preemption=True)))

            return config
    
    return PortsConfig(conn_graph_facts,
                       fanout_graph_facts)

@pytest.fixture
def pfcwd_configs(duthost,
                  ports_config,
                  start_delay,
                  traffic_line_rate,
                  pause_line_rate,
                  frame_size,
                  t_start_pause) :
    """
    A fixture to create pfcwd configs on traffic generator using open traffic generator model

    :param duthost: duthost fixture
    :param ports_config: ports_config fixture returns ports config object to create pfcwd configs
    :param start_delay: start_delay parameter to delay start of traffic
    :param traffic_line_rate: Traffic line rate
    :param pause_line_rate: Line rate for Pause Storm
    :param frame_size: Traffic item frame size
    :param t_start_pause: Time to Start Pause Storm Traffic
    """

    def _pfcwd_configs(prio):
        """
         A fixture to create pfcwd configs on traffic generator using open traffic genertor model

        :param prio: dscp priority 3 or 4
        """

        vlan_subnet = get_vlan_subnet(duthost) 
        pytest_assert(vlan_subnet is not None,
                      "Fail to get Vlan subnet information")

        vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 3)

        gw_addr = vlan_subnet.split('/')[0]

        device1_ip = vlan_ip_addrs[0]
        device2_ip = vlan_ip_addrs[1]
        device3_ip = vlan_ip_addrs[2]

        device1_gateway_ip = gw_addr
        device2_gateway_ip = gw_addr
        device3_gateway_ip = gw_addr

        available_phy_port = ports_config.get_available_phy_ports()
        pytest_assert(len(available_phy_port) > 3,
                      "Number of physical ports must be at least 3")

        ports_list = ports_config.create_ports_list(no_of_ports=3)

        configs = []
        for phy_ports in ports_list:
            config = ports_config.create_config(phy_ports)

            line_rate = traffic_line_rate
                
            ######################################################################
            # Device Configuration
            ######################################################################
            port1 = config.ports[0]
            port2 = config.ports[1]
            port3 = config.ports[2]

            #Device 1 configuration
            port1.devices = [
                Device(name='Port 1',
                       device_count=1,
                       choice=Ipv4(name='Ipv4 1',
                                   address=Pattern(device1_ip),
                                   prefix=Pattern('24'),
                                   gateway=Pattern(device1_gateway_ip),
                                   ethernet=Ethernet(name='Ethernet 1')
                                  )
                       )
            ]

            #Device 2 configuration
            port2.devices = [
                Device(name='Port 2',
                       device_count=1,
                       choice=Ipv4(name='Ipv4 2',
                                   address=Pattern(device2_ip),
                                   prefix=Pattern('24'),
                                   gateway=Pattern(device2_gateway_ip),
                                   ethernet=Ethernet(name='Ethernet 2')
                                  )
                       )
            ]

            #Device 3 configuration
            port3.devices = [
                Device(name='Port 3',
                       device_count=1,
                       choice=Ipv4(name='Ipv4 3',
                                   address=Pattern(device3_ip),
                                   prefix=Pattern('24'),
                                   gateway=Pattern(device3_gateway_ip),
                                   ethernet=Ethernet(name='Ethernet 3')
                                  )
                     )
            ]

            device1 = port1.devices[0]
            device2 = port2.devices[0]
            device3 = port3.devices[0]
            ######################################################################
            # Traffic configuration Traffic 1->2
            ######################################################################

            dscp_prio = Priority(Dscp(phb=FieldPattern(choice=[str(prio)])))

            flow_1to2 = Flow(name="Traffic 1->2",
                             tx_rx=TxRx(DeviceTxRx(tx_device_names=[device1.name],rx_device_names=[device2.name])),
                             packet=[
                                Header(choice=EthernetHeader()),
                                Header(choice=Ipv4Header(priority=dscp_prio)),
                             ],
                             size=Size(frame_size),
                             rate=Rate('line', line_rate),
                             duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                             )

            config.flows.append(flow_1to2)

            ######################################################################
            # Traffic configuration Traffic 2->1
            ######################################################################

            flow_2to1 = Flow(name="Traffic 2->1",
                             tx_rx=TxRx(DeviceTxRx(tx_device_names=[device2.name],rx_device_names=[device1.name])),
                             packet=[
                                Header(choice=EthernetHeader()),
                                Header(choice=Ipv4Header(priority=dscp_prio)),
                             ],
                             size=Size(frame_size),
                             rate=Rate('line', line_rate),
                             duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                             )

            config.flows.append(flow_2to1)
            ######################################################################
            # Traffic configuration Traffic 2->3
            #######################################################################

            flow_2to3 = Flow(name="Traffic 2->3",
                             tx_rx=TxRx(DeviceTxRx(tx_device_names=[device2.name],rx_device_names=[device3.name])),
                             packet=[
                                Header(choice=EthernetHeader()),
                                Header(choice=Ipv4Header(priority=dscp_prio)),
                             ],
                             size=Size(frame_size),
                             rate=Rate('line', line_rate),
                             duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                             )

            config.flows.append(flow_2to3)

            ######################################################################
            # Traffic configuration Traffic 3->2
            #######################################################################
            
            flow_3to2 = Flow(name="Traffic 3->2",
                             tx_rx=TxRx(DeviceTxRx(tx_device_names=[device3.name],rx_device_names=[device2.name])),
                             packet=[
                                Header(choice=EthernetHeader()),
                                Header(choice=Ipv4Header(priority=dscp_prio)),
                             ],
                             size=Size(frame_size),
                             rate=Rate('line', line_rate),
                             duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                            )

            config.flows.append(flow_3to2)

            #######################################################################
            # Traffic configuration Pause
            #######################################################################

            if prio == 3:
                pause = Header(PfcPause(
                    dst=FieldPattern(choice='01:80:C2:00:00:01'),
                    src=FieldPattern(choice='00:00:fa:ce:fa:ce'),
                    class_enable_vector=FieldPattern(choice='8'),
                    pause_class_0=FieldPattern(choice='0'),
                    pause_class_1=FieldPattern(choice='0'),
                    pause_class_2=FieldPattern(choice='0'),
                    pause_class_3=FieldPattern(choice='ffff'),
                    pause_class_4=FieldPattern(choice='0'),
                    pause_class_5=FieldPattern(choice='0'),
                    pause_class_6=FieldPattern(choice='0'),
                    pause_class_7=FieldPattern(choice='0'),
                ))
            elif prio == 4:
                pause = Header(PfcPause(
                    dst=FieldPattern(choice='01:80:C2:00:00:01'),
                    src=FieldPattern(choice='00:00:fa:ce:fa:ce'),
                    class_enable_vector=FieldPattern(choice='10'),
                    pause_class_0=FieldPattern(choice='0'),
                    pause_class_1=FieldPattern(choice='0'),
                    pause_class_2=FieldPattern(choice='0'),
                    pause_class_3=FieldPattern(choice='0'),
                    pause_class_4=FieldPattern(choice='ffff'),
                    pause_class_5=FieldPattern(choice='0'),
                    pause_class_6=FieldPattern(choice='0'),
                    pause_class_7=FieldPattern(choice='0'),
                ))
            else:
                pytest_assert(False,
                              "This testcase supports only lossless priorities 3 & 4, need to enhance the script based on requirement")

            pause_flow = Flow(name='Pause Storm',
                              tx_rx=TxRx(PortTxRx(tx_port_name=port3.name,rx_port_names=[port3.name])),
                              packet=[pause],
                              size=Size(64),
                              rate=Rate('line', value=pause_line_rate),
                              duration=Duration(Continuous(delay= t_start_pause * (10**9), delay_unit='nanoseconds'))
            )

            config.flows.append(pause_flow)

            configs.append(config)

        return configs

    return _pfcwd_configs


@pytest.fixture
def pfcwd_multi_host_configs(start_delay,
                             traffic_line_rate,
                             frame_size,
                             pfcwd_configs) :
    """
    Fixture to create multihost configuration, this takes up pfcwd_configs fixture and adds
    remaining traffic to create all to all traffic mesh

    :param start_delay: start_delay parameter to delay start of traffic
    :param traffic_line_rate: Traffic line rate
    :param frame_size: Traffic item frame size
    :param pfcwd_configs: pfcwd_configs fixture
    """
    
    def _pfcwd_multi_host_configs(prio):
        """
        Fixture to create multihost configuration

        :param prio: dscp priority
        """

        line_rate = traffic_line_rate

        configs = pfcwd_configs(prio)

        for config in configs:

            ######################################################################
            # Traffic configuration Traffic 1->3
            #######################################################################

            dscp_prio = Priority(Dscp(phb=FieldPattern(choice=[str(prio)])))

            flow_1to3 = Flow(name="Traffic 1->3",
                             tx_rx=TxRx(DeviceTxRx(tx_device_names=[config.ports[0].devices[0].name],
                                                   rx_device_names=[config.ports[2].devices[0].name])),
                             packet=[
                                    Header(choice=EthernetHeader()),
                                    Header(choice=Ipv4Header(priority=dscp_prio)),
                                    ],
                             size=Size(frame_size),
                             rate=Rate('line', line_rate),
                             duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                             )

            config.flows.append(flow_1to3)

            ######################################################################
            # Traffic configuration Traffic 3->1
            #######################################################################

            flow_3to1 = Flow(name="Traffic 3->1",
                             tx_rx=TxRx(DeviceTxRx(tx_device_names=[config.ports[2].devices[0].name],
                                                   rx_device_names=[config.ports[0].devices[0].name])),
                             packet=[
                                Header(choice=EthernetHeader()),
                                Header(choice=Ipv4Header(priority=dscp_prio)),
                             ],
                             size=Size(frame_size),
                             rate=Rate('line', line_rate),
                             duration=Duration(Continuous(delay=start_delay, delay_unit='nanoseconds'))
                             )

            config.flows.append(flow_3to1)

        return configs

    return _pfcwd_multi_host_configs