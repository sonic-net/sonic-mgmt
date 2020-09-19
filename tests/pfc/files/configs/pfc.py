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

from abstract_open_traffic_generator.device import\
    DeviceGroup, Device, Ethernet, Vlan, Ipv4, Pattern

from abstract_open_traffic_generator.flow import\
    DeviceEndpoint, Endpoint, Flow, Header, Size, Rate,\
    Duration, Fixed, PortEndpoint, PfcPause, Counter, Random

from abstract_open_traffic_generator.flow_ipv4 import\
    Priority, Dscp

from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.port import Options as PortOptions

@pytest.fixture
def start_delay():
    start_delay = 1
    return start_delay


@pytest.fixture
def traffic_duration():
    traffic_duration = 5
    return traffic_duration  


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
def one_hundred_gbe(testbed,
                    conn_graph_facts,
                    fanout_graph_facts,
                    serializer) :

    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number=0)
    device_conn = conn_graph_facts['device_conn']

    # The number of ports should be at least two for this test
    available_phy_port = fanout_devices.get_ports()
    pytest_assert(len(available_phy_port) > 2,
                  "Number of physical ports must be at least 2")

    # Get interface speed of peer port
    for intf in available_phy_port:
        peer_port = intf['peer_port']
        intf['speed'] = int(device_conn[peer_port]['speed'])

    configs = []
    for i in range(len(available_phy_port)):
        rx_id = i
        tx_id = (i + 1) % len(available_phy_port)

        phy_tx_port = get_location(available_phy_port[tx_id])
        phy_rx_port = get_location(available_phy_port[rx_id])

        tx_speed = available_phy_port[tx_id]['speed']
        rx_speed = available_phy_port[rx_id]['speed']

        pytest_assert(tx_speed == rx_speed,
            "Tx bandwidth must be equal to Rx bandwidth")

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
def lossy_configs(testbed,
                  conn_graph_facts,
                  duthost,
                  lossless_prio_dscp_map,
                  one_hundred_gbe,
                  start_delay,
                  serializer) :

    for config in one_hundred_gbe :

        bg_dscp_list = [prio for prio in lossless_prio_dscp_map]
        test_dscp_list = [x for x in range(64) if x not in bg_dscp_list]

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
        background_flow_name = 'Background Data'

        test_line_rate = 50
        background_line_rate = 50
        pause_line_rate = 100

        configure_pause_frame = 1
        ######################################################################
        # Create TX stack configuration
        ######################################################################
        tx_ipv4 = Ipv4(name='Tx Ipv4',
                       address=Pattern(tx_port_ip),
                       prefix=Pattern('24'),
                       gateway=Pattern(tx_gateway_ip))

        tx_ethernet = Ethernet(name='Tx Ethernet', ipv4=tx_ipv4)

        tx_device = Device(name='Tx Device',
                           devices_per_port=1,
                           ethernets=[tx_ethernet])

        tx_device_group = DeviceGroup(name='Tx Device Group',
                                      port_names=['Tx'],
                                      devices=[tx_device])

        config.device_groups.append(tx_device_group)

        ######################################################################
        # Create RX stack configuration
        ######################################################################
        rx_ipv4 = Ipv4(name='Rx Ipv4',
                       address=Pattern(rx_port_ip),
                       prefix=Pattern('24'),
                       gateway=Pattern(rx_gateway_ip))

        rx_ethernet = Ethernet(name='Rx Ethernet', ipv4=rx_ipv4)

        rx_device = Device(name='Rx Device',
                           devices_per_port=1,
                           ethernets=[rx_ethernet])

        rx_device_group = DeviceGroup(name='Rx Device Group',
                                      port_names=['Rx'],
                                      devices=[rx_device])

        config.device_groups.append(rx_device_group)
        ######################################################################
        # Traffic configuration Test data
        ######################################################################
        data_endpoint = DeviceEndpoint(
            tx_device_names=[tx_device.name],
            rx_device_names=[rx_device.name],
            packet_encap='ipv4',
            src_dst_mesh='',
            route_host_mesh='',
            bi_directional=False,
            allow_self_destined=False
        )

        test_dscp = Priority(Dscp(phb=FieldPattern(choice=test_dscp_list)))

        test_flow = Flow(
            name=test_flow_name,
            endpoint=Endpoint(data_endpoint),
            packet=[
                Header(choice=EthernetHeader()),
                Header(choice=Ipv4Header(priority=test_dscp))
            ],
            size=Size(1024),
            rate=Rate('line', test_line_rate),
            duration=Duration(Fixed(packets=0, delay=start_delay, delay_unit='nanoseconds'))
        )

        config.flows.append(test_flow)
        #######################################################################
        # Traffic configuration Background data
        #######################################################################
        background_dscp = Priority(Dscp(phb=FieldPattern(choice=bg_dscp_list)))
        background_flow = Flow(
            name=background_flow_name,
            endpoint=Endpoint(data_endpoint),
            packet=[
                Header(choice=EthernetHeader()),
                Header(choice=Ipv4Header(priority=background_dscp))
            ],
            size=Size(1024),
            rate=Rate('line', background_line_rate),
            duration=Duration(Fixed(packets=0, delay=start_delay, delay_unit='nanoseconds'))
        )
        config.flows.append(background_flow)

        #######################################################################
        # Traffic configuration Pause
        #######################################################################
        if (configure_pause_frame) :
            pause_endpoint = PortEndpoint(tx_port_name='Rx', rx_port_names=['Rx'])
            pause = Header(PfcPause(
                dst=FieldPattern(choice='01:80:C2:00:00:01'),
                src=FieldPattern(choice='00:00:fa:ce:fa:ce'),
                class_enable_vector=FieldPattern(choice='E7'),
                pause_class_0=FieldPattern(choice='ffff'),
                pause_class_1=FieldPattern(choice='ffff'),
                pause_class_2=FieldPattern(choice='ffff'),
                pause_class_3=FieldPattern(choice='0'),
                pause_class_4=FieldPattern(choice='0'),
                pause_class_5=FieldPattern(choice='ffff'),
                pause_class_6=FieldPattern(choice='ffff'),
                pause_class_7=FieldPattern(choice='ffff'),
            ))

            pause_flow = Flow(
                name='Pause Storm',
                endpoint=Endpoint(pause_endpoint),
                packet=[pause],
                size=Size(64),
                rate=Rate('line', value=pause_line_rate),
                duration=Duration(Fixed(packets=0, delay=0, delay_unit='nanoseconds'))
            )

            config.flows.append(pause_flow)

    return one_hundred_gbe

