""" The abstract Test Generator Data Model
"""
from typing import Union, List, Dict
from common.reboot import logger


class Port(object):
    """Port model
       Port is a list of dict  
    """
    __slots__ = ['_port_list']

    def __init__(self, port_list):
        self._port_list = []   
        if (isinstance(port_list, list)):
           for port in port_list:
               if (isinstance(port, dict)):
                   temp = {}
                   for key in port.keys():
                       if key in ['ip', 'card_id', 'port_id']:
                          temp[key] = port[key]   
                   self._port_list.append(temp)
           logger.info(self._port_list)                   
        else :
           logger.info('Port must be a list of dict')
           pytest_assert(0)  


Ports = Union[Port, List[Port], Dict]
class Layer1(object):
    #def __init__(ports: Union[Port, List[Port]]):
    def __init__(ports):
        self.ports = ports

    def novus_hundred_gig_lan(auto_instrumentation='floating', bad_blocks_number=4):
        """Novus 100 Gb Lan card settings
        """
        pass

    def uhd(auto_instrumentation='floating'):
        """Uhd appliance settings
        """
        pass

    def ethernet_vm():
        """Ethernet virtual machine settings
        """
        pass

class Topology (object):
     def __init__(self, ip_address) :
        self._ip_address = {}
        if (isinstance(ip_address, dict)) :
            for key in ip_address.keys() :
                if key in ['if_ip', 'if_ip_step', 'gw_ip', 'gw_ip_step', 'topo_name']:
                    self._ip_address[key] = ip_address[key]
            logger.info(self._ip_address)
        else:
            logger.info('Port must be a list of dict')
                       

class Ethernet(object):
    """Ethernet II traffic protocol header

    Properties
    ----------  
    dst_address (str=01:80:C2:00:00:01): Destination address  
    src_address (str=00:00:AA:00:00:01): Source address  
    ether_type (str=0x8808): Ethernet type  
    pfc_queue (str=0): PFC Queue
    """
    __STACK_TYPE_ID = 'ethernet'
    __FIELD_MAP = {
        'dst_address': {
            'fieldTypeId': 'ethernet.header.destinationAddress',
            'default': '00:00:00:00:00:00'
        },
        'src_address': {
            'fieldTypeId': 'ethernet.header.sourceAddress',
            'default': '00:00:00:00:00:00'
        },
        'ether_type': {
            'fieldTypeId': 'ethernet.header.etherType',
            'default': '0xFFFF'
        },
        'pfc_queue': {
            'fieldTypeId': 'ethernet.header.pfcQueue',
            'default': '0'
        }
    }
    __slots__ = ['dst_address', 'src_address', 'ether_type', 'pfc_queue']

    def __init__(self):
        self.dst_address = Ethernet.__FIELD_MAP['dst_address']['default']
        self.src_address = Ethernet.__FIELD_MAP['src_address']['default']
        self.ether_type = Ethernet.__FIELD_MAP['ether_type']['default']
        self.pfc_queue = Ethernet.__FIELD_MAP['pfc_queue']['default']


class Ipv4(object):
    """Ethernet II traffic protocol header

    Properties
    ----------  
    dst_address (str=01:80:C2:00:00:01): Destination address  
    src_address (str=00:00:AA:00:00:01): Source address   
    """
    __STACK_TYPE_ID = 'ipv4'
    __FIELD_MAP = {
        'dst_address': {
            'fieldTypeId': 'ipv4.header.dstIp',
            'default': '0.0.0.0'
        },
        'src_address': {
            'fieldTypeId': 'ipv4.header.srcIp',
            'default': '0.0.0.0'
        }
    }
    __slots__ = ['dst_address', 'src_address']

    def __init__(self):
        self.dst_address = Ipv4.__FIELD_MAP['dst_address']['default']
        self.src_address = Ipv4.__FIELD_MAP['src_address']['default']


class PfcPause(object):
    """PFC PAUSE (802.1Qbb) traffic protocol header

    Properties
    ----------  
    dst_address (str=01:80:C2:00:00:01): Destination address  
    src_address (str=00:00:AA:00:00:01): Source address  
    ether_type (str=0x8808): Ethernet type  
    control_op_code (str=0x0101): Control operation code
    """
    __FIELD_MAP = {
        'dst_address': {
            'fieldTypeId': 'pfcPause.header.header.dstAddress',
            'default': '01:80:C2:00:00:01'
        },
        'src_address': {
            'fieldTypeId': 'pfcPause.header.header.srcAddress',
            'default': '00:00:AA:00:00:01'
        },
        'ether_type': {
            'fieldTypeId': 'pfcPause.header.header.etherType',
            'default': '0x8808'
        },
        'control_op_code': {
            'fieldTypeId': 'pfcPause.header.macControl.controlOpCode',
            'default': '0x0101'
        }
    }
    __slots__ = ['dst_address', 'src_address', 'ether_type', 'control_op_code']

    def __init__(self):
        self.dst_address = PfcPause.__FIELD_MAP['dst_address']['default']
        self.src_address = PfcPause.__FIELD_MAP['src_address']['default']
        self.ether_type = PfcPause.__FIELD_MAP['ether_type']['default']
        self.control_op_code = PfcPause.__FIELD_MAP['control_op_code']['default']
   
   
class Flow(object):
    """Traffic flow container

    Properties
    ----------
    - name (str): Unique name of the traffic flow
    - tx_port (Union[str, Port]): The name of a Port object that will transmit 
        traffic
    - rx_ports (list(str)): Intended receive ports
    - packet (list(Union[Ethernet, Ipv4, PfcPause])): The traffic protocols 
        that define the packet for the flow  
    """
    __slots__ = ['name', 'tx_port', 'rx_ports', 'packet']

    def __init__(self, name, tx_port, rx_ports=None, packet=None):
        self.name = name
        self.tx_port = tx_port
        self.rx_ports = rx_ports
        self.packet = packet


Flows = Union[Flow, List[Flow]]
class Config(object):
    """Test tool confguration container

    Properties
    ----------
    - ports (list(Port)): A list of Port objects  
    - layer1 (list(Layer1)): A list of Layer1 objects  
    - flows (list(Flow)): A list of Flow objects  
    """
    __slots__ = ['ports', 'layer1', 'topo', 'flows']

    def __init__(self, ports = None, layer1 = None, topo = None,  flows = None):

        # Add port
        if ports is not None:
            if isinstance(ports, Port):
                self.ports = ports
        # Add layer 1
        if layer1 is not None:
            if isinstance(layer1, Layer1):
                self.layer1 = layer1
        # Add IP
        if topo is not None:
            if isinstance(topo, Topology):
                self.topo = topo
        
        # Add flows
        self.flows = []
        if flows is not None:
            if isinstance(flows, list):
                self.flows = flows
            else:
                self.flows.append(flows)

