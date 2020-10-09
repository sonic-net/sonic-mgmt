import time
import pytest
import sys

from tests.common.helpers.assertions import pytest_assert
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

from abstract_open_traffic_generator.device import\
     Device, Ethernet, Vlan, Ipv4, Pattern

from abstract_open_traffic_generator.flow import\
    DeviceTxRx, TxRx, Flow, Header, Size, Rate,\
    Duration, FixedPackets, PortTxRx, PfcPause, Counter, Random,\
    EthernetPause, FixedSeconds, Continuous

from abstract_open_traffic_generator.flow_ipv4 import\
    Priority, Dscp

from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.port import Options as PortOptions


def base_configs(conn_graph_facts,
                 duthost,
                 lossless_prio_dscp_map,
                 one_hundred_gbe,
                 start_delay,
                 traffic_duration,
                 pause_line_rate,
                 traffic_line_rate,
                 frame_size,
                 ecn_thresholds,
                 number_of_packets,
                 serializer) :

    for config in one_hundred_gbe :


        test_dscp_list = [str(prio) for prio in lossless_prio_dscp_map]

        tx = config.ports[0]
        rx = config.ports[1]

        vlan_subnet = get_vlan_subnet(duthost)
        pytest_assert(vlan_subnet is not None,
                      "Fail to get Vlan subnet information")

        vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 2)

        gw_addr = vlan_subnet.split('/')[0]
        interface_ip_addr = vlan_ip_addrs[0]

        tx_port_ip = vlan_ip_addrs[1]
        rx_port_ip = vlan_ip_addrs[0]

        tx_gateway_ip = gw_addr
        rx_gateway_ip = gw_addr

        test_flow_name = 'Test Data'

        test_line_rate = traffic_line_rate
        pause_line_rate = pause_line_rate

        pytest_assert(test_line_rate <= pause_line_rate,
            "test_line_rate + should be less than pause_line_rate")

        ######################################################################
        # Create TX stack configuration
        ######################################################################
        tx_ipv4 = Ipv4(name='Tx Ipv4',
                       address=Pattern(tx_port_ip),
                       prefix=Pattern('24'),
                       gateway=Pattern(tx_gateway_ip),
                       ethernet=Ethernet(name='Tx Ethernet'))

        tx.devices.append(Device(name='Tx Device',
                                        device_count=1,
                                        choice=tx_ipv4))

        ######################################################################
        # Create RX stack configuration
        ######################################################################
        rx_ipv4 = Ipv4(name='Rx Ipv4',
                       address=Pattern(rx_port_ip),
                       prefix=Pattern('24'),
                       gateway=Pattern(rx_gateway_ip),
                       ethernet=Ethernet(name='Rx Ethernet'))


        rx.devices.append(Device(name='Rx Device',
                                        device_count=1,
                                        choice=rx_ipv4))

        ######################################################################
        # Traffic configuration Test data
        ######################################################################
        data_endpoint = DeviceTxRx(
            tx_device_names=[tx.devices[0].name],
            rx_device_names=[rx.devices[0].name],
        )


        pytest_assert(ecn_thresholds < 1024 * 1024,
            "keep the ECN thresholds less than 1MB")

        test_dscp = Priority(Dscp(phb=FieldPattern(choice=test_dscp_list),
                                  ecn=FieldPattern(Dscp.ECN_CAPABLE_TRANSPORT_1)))

        # ecn_thresholds in bytes 
        #number_of_packets = int(2 * (ecn_thresholds / frame_size))
        logger.info("Total number of packets to send = %s" %(number_of_packets))
   
        delay = start_delay * 1000000000.0
        test_flow = Flow(
            name=test_flow_name,
            tx_rx=TxRx(data_endpoint),
            packet=[
                Header(choice=EthernetHeader()),
                Header(choice=Ipv4Header(priority=test_dscp))
            ],
            size=Size(frame_size),
            rate=Rate('line', test_line_rate),
            duration=Duration(FixedPackets(packets=number_of_packets, delay=delay, delay_unit='nanoseconds'))
        )

        config.flows.append(test_flow)

        #######################################################################
        # Traffic configuration Pause
        #######################################################################
        pause_endpoint = PortTxRx(tx_port_name='Rx', rx_port_names=['Rx'])
        pause = Header(PfcPause(
            dst=FieldPattern(choice='01:80:C2:00:00:01'),
            src=FieldPattern(choice='00:00:fa:ce:fa:ce'),
            class_enable_vector=FieldPattern(choice='18'),
            pause_class_0=FieldPattern(choice='0'),
            pause_class_1=FieldPattern(choice='0'),
            pause_class_2=FieldPattern(choice='0'),
            pause_class_3=FieldPattern(choice='ffff'),
            pause_class_4=FieldPattern(choice='ffff'),
            pause_class_5=FieldPattern(choice='0'),
            pause_class_6=FieldPattern(choice='0'),
            pause_class_7=FieldPattern(choice='0'),
        ))

        pause_duration = start_delay + traffic_duration
        pause_flow = Flow(
            name='Pause Storm',
            tx_rx=TxRx(pause_endpoint),
            packet=[pause],
            size=Size(64),
            rate=Rate('line', value=100),
            duration=Duration(Continuous(delay=0, delay_unit='nanoseconds'))
        )

        config.flows.append(pause_flow)

    return one_hundred_gbe


@pytest.fixture
def start_delay(request):
    return request


@pytest.fixture
def traffic_duration(request):
    return request


@pytest.fixture
def bw_multiplier(request):
    return request


@pytest.fixture
def pause_line_rate(request):
    return request


@pytest.fixture
def traffic_line_rate(request):
    return request


@pytest.fixture
def frame_size(request):
    return request

@pytest.fixture
def outstanding_packets(request):
    return request

@pytest.fixture(scope='session')
def serializer(request):
    class Serializer(object):
        def __init__(self, request):
            self.request = request
            self.test_name = getattr(request.node, "name")

        def json(self, obj):
            import json
            json_str = json.dumps(obj, indent=2, default=lambda x: x.__dict__)
            return '\n[%s] %s: %s\n' % (self.test_name, obj.__class__.__name__, json_str)

        def yaml(self, obj):
            import yaml
            yaml_str = yaml.dump(obj, indent=2)
            return '\n[%s] %s: %s\n' % (self.test_name, obj.__class__.__name__, yaml_str)

        def obj(self, json_string):
            a_dict = json.loads(json_string)
            return json.loads(json_string, object_hook=self._object_hook)

        def _object_hook(self, converted_dict):
            return namedtuple('X', converted_dict.keys())(*converted_dict.values())

    return Serializer(request)


@pytest.fixture
def port_bandwidth(conn_graph_facts,
                   fanout_graph_facts,
                   bw_multiplier) :

   fanout_devices = IxiaFanoutManager(fanout_graph_facts)
   fanout_devices.get_fanout_device_details(device_number=0)
   device_conn = conn_graph_facts['device_conn']
   available_phy_port = fanout_devices.get_ports()
   reference_peer = available_phy_port[0]['peer_port']
   reference_speed = int(device_conn[reference_peer]['speed'])

   for intf in available_phy_port:
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed'])
        pytest_assert(intf['speed'] == reference_speed,
            "speed of all the ports are not same")

   return reference_speed * bw_multiplier


@pytest.fixture
def one_hundred_gbe(conn_graph_facts,
                    fanout_graph_facts,
                    serializer) :

    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number=0)
    device_conn = conn_graph_facts['device_conn']

    # The number of ports should be at least two for this test
    available_phy_port = fanout_devices.get_ports()
    pytest_assert(len(available_phy_port) > 2,
                  "Number of physical ports must be at least 2")

    configs = []
    for i in range(len(available_phy_port)):
        rx_id = i
        tx_id = (i + 1) % len(available_phy_port)

        phy_tx_port = get_location(available_phy_port[tx_id])
        phy_rx_port = get_location(available_phy_port[rx_id])

        #########################################################################
        # common L1 configuration
        #########################################################################

        tx = Port(name='Tx', location=phy_tx_port)
        rx = Port(name='Rx', location=phy_rx_port)

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

        l1_oneHundredGbe = OneHundredGbe(link_training=True,
                                         ieee_media_defaults=False,
                                         auto_negotiate=False,
                                         speed='one_hundred_gbps',
                                         flow_control=flow_ctl,
                                         rs_fec=True)

        common_l1_config = Layer1(name='common L1 config',
                                  choice=l1_oneHundredGbe,
                                  port_names=[tx.name, rx.name])

        config = Config(ports=[tx, rx],
            layer1=[common_l1_config],
            options=Options(PortOptions(location_preemption=True)))

        configs.append(config)

    return configs


@pytest.fixture
def ecn_marking_at_ecress(conn_graph_facts,
                          duthost,
                          lossless_prio_dscp_map,
                          one_hundred_gbe,
                          start_delay,
                          traffic_duration,
                          pause_line_rate,
                          traffic_line_rate,
                          frame_size,
                          ecn_thresholds,
                          serializer) :

    number_of_packets = int(2 * (ecn_thresholds / frame_size))
    return(base_configs(conn_graph_facts=conn_graph_facts,
                        duthost=duthost,
                        lossless_prio_dscp_map=lossless_prio_dscp_map,
                        one_hundred_gbe=one_hundred_gbe,
                        start_delay=start_delay,
                        traffic_duration=traffic_duration,
                        pause_line_rate=pause_line_rate,
                        traffic_line_rate=traffic_line_rate,
                        frame_size=frame_size,
                        ecn_thresholds=ecn_thresholds,
                        number_of_packets=number_of_packets,
                        serializer=serializer))


@pytest.fixture
def marking_accuracy(conn_graph_facts,
                     duthost,
                     lossless_prio_dscp_map,
                     one_hundred_gbe,
                     start_delay,
                     traffic_duration,
                     pause_line_rate,
                     traffic_line_rate,
                     frame_size,
                     ecn_thresholds,
                     outstanding_packets,
                     serializer) :

    number_of_packets = int(4 * (ecn_thresholds / frame_size) + outstanding_packets)
    return(base_configs(conn_graph_facts=conn_graph_facts,
                        duthost=duthost,
                        lossless_prio_dscp_map=lossless_prio_dscp_map,
                        one_hundred_gbe=one_hundred_gbe,
                        start_delay=start_delay,
                        traffic_duration=traffic_duration,
                        pause_line_rate=pause_line_rate,
                        traffic_line_rate=traffic_line_rate,
                        frame_size=frame_size,
                        ecn_thresholds=ecn_thresholds,
                        number_of_packets=number_of_packets,
                        serializer=serializer))

