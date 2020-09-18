import logging
import time
import pytest
import json

from ixnetwork_open_traffic_generator.ixnetworkapi import IxNetworkApi
from abstract_open_traffic_generator.result import FlowRequest

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts 

from tests.common.helpers.assertions import pytest_assert

from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, \
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_dev, ixia_api_serv_port,\
    ixia_api_serv_session_id, api

from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_location

from tests.common.ixia.common_helpers import get_vlan_subnet, \
    get_addrs_in_subnet

from files.qos_fixtures import lossless_prio_dscp_map
from abstract_open_traffic_generator.control import FlowTransmit

START_DELAY = 1
TRAFFIC_DURATION = 5

###############################################################################
# Imports for Tgen and IxNetwork abstract class
###############################################################################
import json
import sys

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

from abstract_open_traffic_generator.flow import Pattern as PATTERN
from abstract_open_traffic_generator.flow import Ipv4 as IPV4
from abstract_open_traffic_generator.flow import Vlan as VLAN
from abstract_open_traffic_generator.flow import Ethernet as ETHERNET
from abstract_open_traffic_generator.port import Options as PortOptions
################################################################################

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

@pytest.fixture(scope="function")
def novus_100_gig_layer1(testbed,
                         conn_graph_facts,
                         api,
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

        api.set_config(None)

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


@pytest.fixture(scope="function")
def lossy_configs(testbed,
                  conn_graph_facts,
                  duthost,
                  api,
                  fanout_graph_facts,
                  lossless_prio_dscp_map,
                  novus_100_gig_layer1,
                  serializer) :

    for config in novus_100_gig_layer1 :

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

        start_delay = START_DELAY 
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

        test_dscp = Priority(Dscp(phb=PATTERN(choice=test_dscp_list)))

        test_flow = Flow(
            name=test_flow_name,
            endpoint=Endpoint(data_endpoint),
            packet=[
                Header(choice=ETHERNET()),
                Header(choice=IPV4(priority=test_dscp))
            ],
            size=Size(1024),
            rate=Rate('line', test_line_rate),
            duration=Duration(Fixed(packets=0, delay=start_delay, delay_unit='nanoseconds'))
        )

        config.flows.append(test_flow)
        #######################################################################
        # Traffic configuration Background data
        #######################################################################
        background_dscp = Priority(Dscp(phb=PATTERN(choice=bg_dscp_list)))
        background_flow = Flow(
            name=background_flow_name,
            endpoint=Endpoint(data_endpoint),
            packet=[
                Header(choice=ETHERNET()),
                Header(choice=IPV4(priority=background_dscp))
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
                dst=PATTERN(choice='01:80:C2:00:00:01'),
                src=PATTERN(choice='00:00:fa:ce:fa:ce'),
                class_enable_vector=PATTERN(choice='E7'),
                pause_class_0=PATTERN(choice='ffff'),
                pause_class_1=PATTERN(choice='ffff'),
                pause_class_2=PATTERN(choice='ffff'),
                pause_class_3=PATTERN(choice='0'),
                pause_class_4=PATTERN(choice='0'),
                pause_class_5=PATTERN(choice='ffff'),
                pause_class_6=PATTERN(choice='ffff'),
                pause_class_7=PATTERN(choice='ffff'),
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

    return novus_100_gig_layer1


def test_pfc_pause_lossy_traffic(api, duthost, lossy_configs, serializer) :
    """
    This test case checks the behaviour of the SONiC DUT when it receives 
    a PFC pause frame on lossy priorities.

                                +-----------+
    [Keysight Chassis Tx Port]  |           | [Keysight Chassis Rx Port]
    --------------------------->| SONiC DUT |<---------------------------
    Test Data Traffic +         |           |  PFC pause frame on 
    Background Dada Traffic     +-----------+  "lossy" priorities.

    1. Configure SONiC DUT with multipul lossless priorities. 
    2. On SONiC DUT enable PFC on several lossless priorities e.g priority 
       3 and 4.
    3. On the Keysight chassis Tx port create two flows - a) 'Test Data Traffic'
       and b) 'Background Data traffic'.
    4. Configure 'Test Data Traffic' such that it contains traffic items
       with all lossy priorities.
    5. Configure 'Background Data Traffic' it contains traffic items with
       all lossless priorities.
    6. From Rx port send pause frames on all lossless priorities. Then
       start 'Test Data Traffic' and 'Background Data Traffic'.
    7. Verify the following: 
       (a) When Pause Storm are running, Keysight Rx port is receiving
       both 'Test Data Traffic' and 'Background Data traffic'.
       (b) When Pause Storm are stoped, then also Keysight Rx port is receiving
       both 'Test Data Traffic' and 'Background Data traffic'.
    """
    duthost.shell('sudo pfcwd stop')
    import json

    for base_config in lossy_configs:

        # create the configuration
        api.set_config(base_config)

        # start all flows
        api.set_flow_transmit(FlowTransmit(state='start'))

        exp_dur = START_DELAY + TRAFFIC_DURATION
        logger.info("Traffic is running for %s seconds" %(exp_dur))
        time.sleep(exp_dur)

        # stop all flows
        api.set_flow_transmit(FlowTransmit(state='stop'))

        # Get statistics
        test_stat = api.get_flow_results(FlowRequest())

        for rows in test_stat['rows'] :
            tx_frame_index = test_stat['columns'].index('frames_tx')
            rx_frame_index = test_stat['columns'].index('frames_rx')
            caption_index = test_stat['columns'].index('name')   
            if ((rows[caption_index] == 'Test Data') or
                (rows[caption_index] == 'Background Data')):
                if rows[tx_frame_index] != rows[rx_frame_index] :
                    pytest_assert(False,
                        "Not all %s reached Rx End" %(rows[caption_index]))

