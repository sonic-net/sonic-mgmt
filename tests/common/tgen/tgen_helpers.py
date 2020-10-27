import ipaddr
from netaddr import IPNetwork
from abstract_open_traffic_generator.port import Port
from abstract_open_traffic_generator.config import Options
from abstract_open_traffic_generator.config import Config
from abstract_open_traffic_generator.layer1 import\
    Layer1, OneHundredGbe, FlowControl, Ieee8021qbb
from abstract_open_traffic_generator.layer1 import \
    Ethernet as EthernetPort
from abstract_open_traffic_generator.port import Options as PortOptions


class FanoutManager():
    """Class for managing multiple chassis and extracting the information
     like chassis IP, card, port etc. from fanout_graph_fact."""

    def __init__(self, fanout_data):
        """ When multiple chassis are available inside fanout_graph_facts
        this method makes a  list of chassis connection-details out of it.
        So each chassis and details  associated with it can be accessed by
        a integer index (starting from 0)

        Args:
           fanout_data (dict): the dictionary returned by fanout_graph_fact.
           Example format of the fanout_data is given below

        {u'ixia-sonic': {
            u'device_conn': {
                u'Card9/Port1': {
                    u'peerdevice': u'sonic-s6100-dut',
                    u'peerport': u'Ethernet0',
                    u'speed': u'100000'
                },
                u'Card9/Port2': {
                    u'peerdevice': u'sonic-s6100-dut',
                    u'peerport': u'Ethernet4',
                    u'speed': u'100000'
                },
                u'Card9/Port3': {
                    u'peerdevice': u'sonic-s6100-dut',
                    u'peerport': u'Ethernet8',
                    u'speed': u'100000'
                },
                'Card9/Port4': {
                    u'peerdevice': u'sonic-s6100-dut',
                    u'peerport': u'Ethernet12',
                    u'speed': u'100000'
                },
                u'Card9/Port5': {
                    u'peerdevice': u'sonic-s6100-dut',
                    u'peerport': u'Ethernet16',
                    u'speed': u'100000'
                },
                u'Card9/Port6': {
                    u'peerdevice': u'sonic-s6100-dut',
                    u'peerport': u'Ethernet20',
                    u'speed': u'100000'
                }
            },
            u'device_info': {
                u'HwSku': u'IXIA-tester',
                u'ManagementGw': u'10.36.78.54',
                u'ManagementIp': u'10.36.78.53/32',
                u'Type': u'DevIxiaChassis',
                u'mgmtip': u'10.36.78.53'
            },
            u'device_port_vlans': {
                u'Card9/Port1': {
                    u'mode': u'Access',
                    u'vlanids': u'300',
                    u'vlanlist': [300]
                },
                u'Card9/Port2': {
                    u'mode': u'Access',
                    u'vlanids': u'301',
                    u'vlanlist': [301]
                },
                u'Card9/Port3': {
                    u'mode': u'Access',
                    u'vlanids': u'302',
                    u'vlanlist': [302]
                },
                u'Card9/Port4': {
                    u'mode': u'Access',
                    u'vlanids': u'300',
                    u'vlanlist': [300]
                },
                u'Card9/Port5': {
                    u'mode': u'Access',
                    u'vlanids': u'301',
                    u'vlanlist': [301]
                },
                u'Card9/Port6': {
                    u'mode': u'Access',
                    u'vlanids': u'302',
                    u'vlanlist': [302]
                }
            },
            u'device_vlan_list': [301, 302, 300, 302, 300, 301],
            u'device_vlan_range': [u'300-302']
            }
        }
        """
        self.last_fanout_assessed = None
        self.fanout_list = []
        self.last_device_connection_details = None
        self.current_tgen_port_list = None
        self.ip_address = '0.0.0.0'
        for i in fanout_data.keys():
            self.fanout_list.append(fanout_data[i])

    def __parse_fanout_connections__(self):
        device_conn = self.last_device_connection_details
        retval = []
        for key in device_conn.keys():
            pp = device_conn[key]['peerport']
            string = self.ip_address + '/' + key + '/' + pp
            retval.append(string)
        retval.sort()
        return (retval)

    def get_fanout_device_details(self, device_number):
        """With the help of this function you can select the chassis you want
        to access. For example get_fanout_device_details(0) selects the
        first chassis. It just select the chassis but does not return
        anything. The rest of  the function then used to extract chassis
        information like "get_chassis_ip()" will the return the ip address
        of chassis 0 - the first chassis in the list.

        Note:
            Counting or indexing starts from 0. That is 0 = 1st cassis,
            1 = 2nd chassis ...

        Args:
           device_number (int): the chassis index (0 is the first)

        Returns:
           None
        """

        # Pointer to chassis info
        self.last_fanout_assessed = device_number

        # Chassis connection details
        self.last_device_connection_details = \
            self.fanout_list[self.last_fanout_assessed]['device_conn']

        # Chassis ip details
        self.ip_address = \
            self.fanout_list[self.last_fanout_assessed]['device_info']['mgmtip']

        # List of chassis cards and ports
        self.current_tgen_port_list = \
            self.__parse_fanout_connections__()

        # return self.fanout_list[self.last_fanout_assessed]

    def get_ports(self) :
        """This function returns list of ports associated with a chassis
        (selected earlier using get_fanout_device_details() function)
        as a list of dictionary.

        Note: If you have not used get_fanout_device_details(), by default 0th
            (first) chassis remains selected.

        Args:
            This function takes no argument.

        Returns:
            Dictionary of chassis card port information.
        """
        retval = []
        for port in self.current_tgen_port_list:
            info_list = port.split('/')
            dict_element = {
                'ip': info_list[0],
                'card_id': info_list[1].replace('Card', ''),
                'port_id': info_list[2].replace('Port', ''),
                'peer_port': info_list[3],
            }
            retval.append(dict_element)

        return retval


class TgenPorts(object):
    """
    TgenPorts Class used by ports_config fixture
    """
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
        # fanout_devices = FanoutManager(self.fanout_graph_facts)
        # import pdb; pdb.set_trace()
        fanout_devices = FanoutManager(self.fanout_graph_facts)
        fanout_devices.get_fanout_device_details(device_number=0)
        device_conn = self.conn_graph_facts['device_conn']
        available_phy_port = fanout_devices.get_ports()
        
        for intf in available_phy_port:
            peer_port = intf['peer_port']
            intf['speed'] = int(device_conn[peer_port]['speed'])
        return available_phy_port

    def verify_required_ports(self, no_of_ports_required):
        """
        Verifies the number of physical ports required and fails if not satisfied
        
        :param no_of_ports_required: No of Ports mandatory for the test.
                                If Topo doesn't statisfy throws error.
        """
        available_phy_ports = self.get_available_phy_ports()
        if no_of_ports_required is None:
            return
        if len(available_phy_ports) < no_of_ports_required:
            pytest_assert(False,
                          "Number of physical ports must be at least {}".format(no_of_ports_required))

    def create_ports_list(self,no_of_ports, start_index):
        """
        A Function creates ports_list as the testcase needs to be repeated for 
        all available ports in the testbed even if the test needs n number of ports

        :param no_of_ports: Number of minimum required ports for the test
        :start_index: index of the available port list

        Ex: If a test needs 2 ports and testbed has 3 ports. A 3 ports testbed will 
            get 2 combinations of ports [1,2], [2,3] and [3, 1] then start index determines
            which combinition to return.
        Return: 
            [{'card_id': '9',
            'ip': '10.36.78.53',
            'peer_port': 'Ethernet0',
            'port_id': '1',
            'speed': 100000},
            {'card_id': '9',
            'ip': '10.36.78.53',
            'peer_port': 'Ethernet4',
            'port_id': '2',
            'speed': 100000}],
        """
        avail_ports = self.get_available_phy_ports()
        if start_index > len(avail_ports)-1:
            pytest.fail("Port list index is out of range")
        slice_range = start_index + no_of_ports
        num = slice_range - len(avail_ports)
        return avail_ports[start_index: None if slice_range > len(avail_ports)-1 else slice_range] \
            + avail_ports[0:num if num>=0 else 0]


    def l1_config(self, phy_ports):
        """
        Creates config for traffic generator with given physical ports

        :param phy_ports: Physical ports config creation on traffic generator
        """
        
        # [one_hundred_gbps, fifty_gbps, forty_gbps, twenty_five_gpbs, ten_gbps]
        # [one_thousand_mbps, one_hundred_fd_mbps, one_hundred_hd_mbps, ten_fd_mbps, ten_hd_mbps]
        port_speeds = {
            100 : ['OneHundredGbe','one_hundred_gbps'],
            50  : ['OneHundredGbe','fifty_gbps'],
            40  : ['OneHundredGbe','forty_gbps'],
            25  : ['OneHundredGbe','twenty_five_gpbs'],
            10  : ['OneHundredGbe','ten_gbps'],
            1   : ['Ethernet','one_thousand_mbps'],
        }
        
        ports = []
        port_names = {port_speeds[speed][0]+'.'+port_speeds[speed][1] : [] for speed in port_speeds}

        # Finding the port speed from the DUT conn_facts
        for index,phy_port in enumerate(phy_ports,1):
            port_location = get_location(phy_port)
            port = Port(name='Port'+str(index),location=port_location)
            speed = phy_port['speed']/1000
            if port_speeds.get(speed) is None:
                pytest.fail("Currently port speed of {} gbe is not supported".format(speed))
            else:
                key = port_speeds.get(speed)[0]+'.'+port_speeds.get(speed)[1]
                port_names[key].append(port.name)
            ports.append(port)
        #######################################################################
        # currently setting the flow control for all the oneHunderdGbe objects.
        # Need to add the code to get the options from dut to set the auto neg
        # and ieee standards
        #######################################################################
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

        l1_obj_list = []
        for port_combi in port_names:
            if len(port_names[port_combi]) == 0:
                continue
            obj_class, speed = port_combi.split(".",1)
            if obj_class == "OneHundredGbe":
                l1_obj_list.append(
                    Layer1(name='{} settings'.format(speed),
                           port_names=port_names[port_combi],
                           choice=OneHundredGbe(link_training=True,
                                                ieee_media_defaults=False,
                                                auto_negotiate=False,
                                                rs_fec=True,
                                                flow_control=flow_ctl,
                                                speed=speed))
                )
            elif obj_class == "Ethernet":
                l1_obj_list.append(
                    Layer1(name='{} settings'.format(speed),
                           port_names=port_names[port_combi],
                           choice=EthernetPort(auto_negotiate=False,                                                
                                               flow_control=flow_ctl,
                                               speed=speed))
                )

        config = Config(ports=ports,
                        layer1=l1_obj_list,
                        options=Options(PortOptions(location_preemption=True)))

        return config


def ansible_stdout_to_str(ansible_stdout):
    """
    The stdout of Ansible host is essentially a list of unicode characters.
    This function converts it to a string.

    Args:
        ansible_stdout: stdout of Ansible

    Returns:
        Return a string
    """
    result = ""
    for x in ansible_stdout:
        result += x.encode('UTF8')
    return result


def get_vlan_subnet(host_ans):
    """
    Get VLAN subnet of a T0 device

    Args:
        host_ans: Ansible host instance of the device

    Returns:
        VLAN subnet, e.g., "192.168.1.1/24" where 192.168.1.1 is gateway
        and 24 is prefix length
    """
    mg_facts = host_ans.minigraph_facts(host=host_ans.hostname)['ansible_facts']
    mg_vlans = mg_facts['minigraph_vlans']

    if len(mg_vlans) != 1:
        print 'There should be only one Vlan at the DUT'
        return None

    mg_vlan_intfs = mg_facts['minigraph_vlan_interfaces']
    prefix_len = mg_vlan_intfs[0]['prefixlen']
    gw_addr = ansible_stdout_to_str(mg_vlan_intfs[0]['addr'])
    return gw_addr + '/' + str(prefix_len)


def get_addrs_in_subnet(subnet, number_of_ip):
    """
    Get N IP addresses in a subnet.

    Args:
        subnet (str): IPv4 subnet, e.g., '192.168.1.1/24'
        number_of_ip (int): Number of IP addresses to get

    Return:
        Return n IPv4 addresses in this subnet in a list.
    """
    ip_addr = subnet.split('/')[0]
    ip_addrs = [str(x) for x in list(IPNetwork(subnet))]
    ip_addrs.remove(ip_addr)

    """ Try to avoid network and broadcast addresses """
    if len(ip_addrs) >= number_of_ip + 2:
        del ip_addrs[0]
        del ip_addrs[-1]

    return ip_addrs[:number_of_ip]


def get_location(intf):
    """ Extracting location from interface, since TgenApi accepts location
    in terms of chassis ip, card, and port in different format.

    Note: Interface must have the keys 'ip', 'card_id' and 'port_id'

    Args:
    intf (dict) : intf must containg the keys 'ip', 'card_id', 'port_id'.
        Example format :
        {'ip': u'10.36.78.53',
         'port_id': u'1',
         'card_id': u'9',
         'speed': 100000,
         'peer_port': u'Ethernet0'}

    Returns: location in string format. Example: '10.36.78.5;1;2' where
    1 is card_id and 2 is port_id.
    """
    location = None
    try:
        location = str("%s;%s;%s" % (intf['ip'], intf['card_id'], intf['port_id']))
    except:
        pytest_assert(False,
                      "Interface must have the keys 'ip', 'card_id' and 'port_id'")
    return location


def increment_ip_address (ip, incr=1) :
    """
    Increment IP address by an integer number.

    Args: 
       ip (str): IP address in string format.
       incr (int): Increment by the specified number.

    Return:
       IP address in the argument incremented by the given integer.
    """
    ipaddress = ipaddr.IPv4Address(ip)
    ipaddress = ipaddress + incr
    return_value = ipaddress._string_from_ip_int(ipaddress._ip)
    return(return_value)


##################################################################
# Currently supporting only ixia and will
# add the provision to other tgen once this approach is approved
##################################################################

import xml.etree.ElementTree as ET

def _get_xml_root(file_name):
    """ return xml root object """
    return ET.parse(file_name)

def _find_device_links_from_root(root, device_tuple_list):
    """ return list of device links from connection_graph.xml """
    devices = root.findall('./PhysicalNetworkGraphDeclaration/Devices')[0]
    if len(devices) == 0:
        return None

    dev_attr_values = [(each_device.attrib['Hostname'], each_device.attrib['Type']) \
                        for each_device in devices]
    
    result = True
    for dev_tuple in device_tuple_list:
        if dev_tuple not in dev_attr_values:
            result = None
            break
    if result:
        return (dev_attr_values, root.findall('./PhysicalNetworkGraphDeclaration/DeviceInterfaceLinks')[0])
    return None


def _get_links(device_interfaces):
    """ return list of interfaces for between ixia """
    dev_tuple = device_interfaces[0]
    intfs = device_interfaces[1]
    end_devices = [dev[0] for dev in dev_tuple if dev[1] == "DevIxiaChassis"]
    links = [link for link in intfs \
             if link.attrib['EndDevice'] in end_devices]
    return links


def _find_xml_file():
    """ find connection_graph.xmls from ../ansible/files path """
    import os
    file_path = "../ansible/files"
    path = os.walk(file_path)
    xml_list = [os.path.join(file_path,xml) for xml in path.next()[2] if "connection_graph.xml" in xml]
    try:
        xml_list.pop(xml_list.index(os.path.join(file_path,'example_ixia_connection_graph.xml')))
    except:
        pass
    return xml_list


def _get_dev_from_testbed(tb_file, tb_name):
    """ return the duts list from the Testbed file.csv"""
    # Currently supporting csv file formatted testbed file
    # shall add support for yaml formatted testbed file in future
    from tests.conftest import TestbedInfo
    tb = TestbedInfo(tb_file)
    duts = tb.testbed_topo[tb_name]['duts']
    duts = [(dut, 'DevSonic') for dut in duts]
    return duts


def get_tgen_links(request):
    """ will return the tgen links connected to duts """
    tb_file = request.config.getoption('testbed_file')
    tb_name = request.config.getoption('testbed')
    devs = _get_dev_from_testbed(tb_file, tb_name)
    all_links = None
    for xml in _find_xml_file():
        root = _get_xml_root(xml)
        all_links = _find_device_links_from_root(root, devs)
        if all_links:
            break
    if all_links is None:
        pytest.fail("Could not fetch the links from xml")
    tgen_links = _get_links(all_links)
    return list(range(len(tgen_links)))


