import pytest

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
from abstract_open_traffic_generator.config import Options
from abstract_open_traffic_generator.config import Config

from abstract_open_traffic_generator.layer1 import\
    Layer1, OneHundredGbe, FlowControl, Ieee8021qbb

from abstract_open_traffic_generator.device import\
     Device, Ethernet, Ipv4, Pattern

from abstract_open_traffic_generator.flow import\
    DeviceTxRx, TxRx, Flow, Header, Size, Rate,\
    Duration, FixedSeconds, PortTxRx, PfcPause, EthernetPause, Continuous

from abstract_open_traffic_generator.flow_ipv4 import\
    Priority, Dscp

from abstract_open_traffic_generator.flow import Pattern as FieldPattern
from abstract_open_traffic_generator.flow import Ipv4 as Ipv4Header
from abstract_open_traffic_generator.flow import Ethernet as EthernetHeader
from abstract_open_traffic_generator.port import Options as PortOptions

def calculate_priority_vector(v) :
    """
    This function calculates the priority vector field of PFC Pause packets.

    Args:
        v (list of string) : This is a list of 8 items and indicates pause 
            class values. It's format is ['0', 'ffff', '0', '0', '0', '0', '0'], 
            where 'ffff' indicates that pause class is enabled for that index.

    Returns:
        Value of priority vector in hex format 
    """
    s = 0
    for i in range(8)  :
        if v[i] != '0' :
           s += 2**7
    return "%x"%(s)

def lossless_iteration_list (lst) :
    """
    This function converts a list of priorities into list of list of priorities
    such that test functions can iterate over by taking one priority list at
    a time. For Example: if lst == [3, 4] the return value is [[3], [4], [3, 4]] 

    Args:
      lst (list of integerrs): list of priorites. Example [3, 4]

    Return : 
       list of list of priorities (integers). Example [[3], [4], [3, 4]]
 
    """
    retval = [[x] for x in lst]
    if (len(lst) > 1):
        retval.append(lst)
    return retval

def base_configs(conn_graph_facts,
                 duthost,
                 lossless_prio_dscp_map,
                 l1_config,
                 start_delay,
                 traffic_duration,
                 pause_line_rate,
                 traffic_line_rate,
                 pause_frame_type,
                 frame_size,
                 serializer) :

    for config in l1_config :

        delay = start_delay * 1000000000.0

        bg_dscp_list = [str(prio) for prio in lossless_prio_dscp_map]
        test_dscp_list = [str(x) for x in range(64) if str(x) not in bg_dscp_list]

        tx = config.ports[0]
        rx = config.ports[1]

        vlan_subnet = get_vlan_subnet(duthost)
        pytest_assert(vlan_subnet is not None,
                      "Fail to get Vlan subnet information")

        vlan_ip_addrs = get_addrs_in_subnet(vlan_subnet, 2)

        gw_addr = vlan_subnet.split('/')[0]
        prefix = vlan_subnet.split('/')[1]
        tx_port_ip = vlan_ip_addrs[1]
        rx_port_ip = vlan_ip_addrs[0]

        tx_gateway_ip = gw_addr
        rx_gateway_ip = gw_addr

        test_flow_name = 'Test Data'
        background_flow_name = 'Background Data'

        test_line_rate = traffic_line_rate
        background_line_rate = traffic_line_rate

        pytest_assert(test_line_rate + background_line_rate <= 100,
            "test_line_rate + background_line_rate should be less than 100")

        ######################################################################
        # Create TX stack configuration
        ######################################################################
        tx_ipv4 = Ipv4(name='Tx Ipv4',
                       address=Pattern(tx_port_ip),
                       prefix=Pattern(prefix),
                       gateway=Pattern(tx_gateway_ip),
                       ethernet=Ethernet(name='Tx Ethernet'))

        tx_device = Device(container_name=tx.name,
                           name='Tx Device', 
                           device_count=1,
                           choice=tx_ipv4)
        config.devices.append(tx_device) 
        ######################################################################
        # Create RX stack configuration
        ######################################################################
        rx_ipv4 = Ipv4(name='Rx Ipv4',
                       address=Pattern(rx_port_ip),
                       prefix=Pattern(prefix),
                       gateway=Pattern(rx_gateway_ip),
                       ethernet=Ethernet(name='Rx Ethernet'))

        rx_device = Device(container_name=rx.name,
                           name='Rx Device',
                           device_count=1,
                           choice=rx_ipv4)
        config.devices.append(rx_device)


        data_endpoint = DeviceTxRx(
            tx_device_names=[tx_device.name],
            rx_device_names=[rx_device.name],
        )
        ######################################################################
        # Traffic configuration Test data
        ######################################################################
        test_flow_name = 'Test Data'
        test_dscp = Priority(Dscp(phb=FieldPattern(choice=test_dscp_list)))
        test_flow = Flow(
            name=test_flow_name,
            tx_rx=TxRx(data_endpoint),
            packet=[
                Header(choice=EthernetHeader()),
                Header(choice=Ipv4Header(priority=test_dscp))
            ],
            size=Size(frame_size),
            rate=Rate('line', test_line_rate),
            duration=Duration(FixedSeconds(seconds=traffic_duration, delay=delay, delay_unit='nanoseconds'))
        )

        config.flows.append(test_flow)
        #######################################################################
        # Traffic configuration Background data
        #######################################################################
        background_flow_name = 'Background Data'
        background_dscp = Priority(Dscp(phb=FieldPattern(choice=bg_dscp_list)))
        background_flow = Flow(
            name=background_flow_name,
            tx_rx=TxRx(data_endpoint),
            packet=[
                Header(choice=EthernetHeader()),
                Header(choice=Ipv4Header(priority=background_dscp))
            ],
            size=Size(frame_size),
            rate=Rate('line', background_line_rate),
            duration=Duration(FixedSeconds(seconds=traffic_duration, delay=delay, delay_unit='nanoseconds'))
        )
        config.flows.append(background_flow)

        #######################################################################
        # Traffic configuration Pause
        #######################################################################
        pause_src_point = PortTxRx(tx_port_name='Rx', rx_port_names=['Rx'])
        if (pause_frame_type == 'priority') :
            p = ['0' if str(x) in test_dscp_list else 'ffff' for x in range(8)]
            v = calculate_priority_vector(p) 
            pause = Header(PfcPause(
                dst=FieldPattern(choice='01:80:C2:00:00:01'),
                src=FieldPattern(choice='00:00:fa:ce:fa:ce'),
                class_enable_vector=FieldPattern(choice=v),
                pause_class_0=FieldPattern(choice=p[0]),
                pause_class_1=FieldPattern(choice=p[1]),
                pause_class_2=FieldPattern(choice=p[2]),
                pause_class_3=FieldPattern(choice=p[3]),
                pause_class_4=FieldPattern(choice=p[4]),
                pause_class_5=FieldPattern(choice=p[5]),
                pause_class_6=FieldPattern(choice=p[6]),
                pause_class_7=FieldPattern(choice=p[7]),
            ))

            pause_flow = Flow(
                name='Pause Storm',
                tx_rx=TxRx(pause_src_point),
                packet=[pause],
                size=Size(64),
                rate=Rate('line', value=100),
                duration=Duration(Continuous(delay=0, delay_unit='nanoseconds'))
            )
        elif (pause_frame_type == 'global') :
            pause = Header(EthernetPause(
                dst=FieldPattern(choice='01:80:C2:00:00:01'),
                src=FieldPattern(choice='00:00:fa:ce:fa:ce')
            ))

            pause_flow = Flow(
                name='Pause Storm',
                tx_rx=TxRx(pause_src_point),
                packet=[pause],
                size=Size(64),
                rate=Rate('line', value=pause_line_rate),
                duration=Duration(Continuous(delay=0, delay_unit='nanoseconds'))
            )
        else :
            pass   

        config.flows.append(pause_flow)

    return l1_config


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
            return json.loads(json_string, object_hook=self._object_hook)

        def _object_hook(self, converted_dict):
            return namedtuple('X', converted_dict.keys())(*converted_dict.values())

    return Serializer(request)


@pytest.fixture
def port_bandwidth(conn_graph_facts,
                   fanout_graph_facts,
                   bw_multiplier) :
   """
   This fixture extracts the ixia port bandwidth from fanout_graph_facts,
   and verifies it with the port speed of the DUT. The speed of all the 
   ixia ports and dut port must be same. 

   Args:
      conn_graph_facts (fixture): connection graph fact.
      fanout_graph_facts (fixture): fanout graph facts
      bw_multiplier (int): multiplier to convert the port speed into bandwidth in 
         bps unit, its value is 1000000.

   Returns:
      Port bandwidth in bps unit.
   """  
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
def l1_config(conn_graph_facts,
                    fanout_graph_facts,
                    serializer) :

    fanout_devices = IxiaFanoutManager(fanout_graph_facts)
    fanout_devices.get_fanout_device_details(device_number=0)

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
def lossy_configs(conn_graph_facts,
                  duthost,
                  lossless_prio_dscp_map,
                  l1_config,
                  start_delay,
                  traffic_duration,
                  pause_line_rate,
                  traffic_line_rate,
                  frame_size, 
                  serializer) :

    for p in lossless_iteration_list(lossless_prio_dscp_map) :
        yield (base_configs(conn_graph_facts=conn_graph_facts,
                            duthost=duthost,
                            lossless_prio_dscp_map = p,
                            l1_config=l1_config,
                            traffic_duration=traffic_duration,
                            start_delay=start_delay,
                            pause_line_rate=pause_line_rate,
                            traffic_line_rate=traffic_line_rate,
                            pause_frame_type='priority',
                            frame_size=frame_size,
                            serializer=serializer))


@pytest.fixture
def global_pause(conn_graph_facts,
                 duthost,
                 lossless_prio_dscp_map,
                 l1_config,
                 start_delay,
                 traffic_duration,
                 pause_line_rate,
                 traffic_line_rate,
                 frame_size,
                 serializer) :

    for p in lossless_iteration_list(lossless_prio_dscp_map) :
        yield (base_configs(conn_graph_facts=conn_graph_facts,
                            duthost=duthost,
                            lossless_prio_dscp_map=p,
                            l1_config=l1_config,
                            traffic_duration=traffic_duration,
                            start_delay=start_delay,
                            pause_line_rate=pause_line_rate,
                            traffic_line_rate=traffic_line_rate,
                            pause_frame_type='global',
                            frame_size=frame_size,
                            serializer=serializer))

