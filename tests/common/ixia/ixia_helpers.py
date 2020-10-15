# -*- coding: utf-8 -*-
"""This module contains the high-level wrapper function using the APIs defined
by Ixia/Keysights ixnetwork_restpy library functions. Intention of providing
these to SONiC group is to avoid writing multiple low-level rest API calls for
doing the top-level tasks like configure ports, create topology, 
start protocols, start traffic etc.

This module also contains a definition of a simple helper class 
"IxiaFanoutManager" which can be used to manage cards and ports of ixia 
chassis instead of reading it from fanout_graph_facts fixture.
"""

from tests.common.reboot import logger
from ixnetwork_restpy import SessionAssistant, Files

class IxiaFanoutManager () :
    """Class for managing multiple chassis and extracting the information 
     like chassis IP, card, port etc. from fanout_graph_fact."""

    def __init__(self,fanout_data) :
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
        self.current_ixia_port_list = None
        self.ip_address = '0.0.0.0' 
        for i in fanout_data.keys() :
            self.fanout_list.append(fanout_data[i])

    def __parse_fanout_connections__ (self) :
        device_conn = self.last_device_connection_details
        retval = []
        for key in device_conn.keys() :
            pp =  device_conn[key]['peerport']
            string = self.ip_address + '/' + key + '/' + pp
            retval.append(string)
        retval.sort()
        return(retval)

    def get_fanout_device_details (self, device_number) :
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
        self.current_ixia_port_list = \
             self.__parse_fanout_connections__()

        #return self.fanout_list[self.last_fanout_assessed]

    def get_connection_details (self) :
        """This function returns all the details associated with a particular
        chassis (selected earlier using get_fanout_device_details() function).
        Details of the chassis will be available like chassis IP, card, ports, 
        peer port etc. in a dictionary format.

        Note: If you have not used get_fanout_device_details(), by default 0th
            (first) chassis remains selected.

        Args:
            This function takes no argument.

        Returns:
            Details of the chassis connection as dictionary format.
        """
        return(self.last_device_connection_details)
  
    def get_chassis_ip (self) :
        """This function returns IP address of a particular chassis 
        (selected earlier using get_fanout_device_details() function).

        Note: If you have not used get_fanout_device_details(), by default 0th
            (first) chassis remains selected.

        Args:
            This function takes no argument.

        Returns:
            The IP address 
        """
        return self.ip_address
       
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
        for port in self.current_ixia_port_list:   
            info_list = port.split('/')
            dict_element = {
                'ip': info_list[0],
                'card_id': info_list[1].replace('Card', ''),
                'port_id': info_list[2].replace('Port', ''),
                'peer_port': info_list[3],
            }
            retval.append(dict_element)   

        return retval 


def clean_configuration(session) :
    """Clean up the configurations cteated in IxNetwork API server.
        
    Args:
        session (IxNetwork Session object): IxNetwork session.    
         
    Returns:
        None 
    """
    ixNetwork = session.Ixnetwork
    ixNetwork.NewConfig()
      

def configure_ports(session, port_list, start_name='port') :
    """Configures ports of the IXIA chassis and returns the list 
       of configured Ixia ports

    Note: This is like the return value of the method,
        IxiaFanoutManager.get_ports()

    Args:
        session (obj): IXIA session object
        port_list (list): List of dictionaries.  like below -
           [{'ip': 10.0.0.1, card_id: '1', 'port_id': '1'},
           {'ip': 10.0.0.1, card_id: '1', 'port_id': '2'}, ...]. 'ip', 
           'card_id' and 'port_id' are the mandatory keys.    
        start_name (str): (optional) The port name to start with, port
           names will be incremented automatically like port1, port2 ...


    Returns: The list of Ixia port objects if the configuration
        succeeds. Otherwise return None
    """

    port_map = session.PortMapAssistant()
    ixnetwork = session.Ixnetwork
    vports = list()

    # Add default vport properties here. If vport property is not available in
    # port_list dictionary get it from here 
    port_property = {
        'speed': 10000000,
        'ieee_l1_defaults': False,
        'pfc_priotity_groups': [0,1,2,3,4,5,6,7],
        'card_type': 'novusHundredGigLanFcoe',
        'enable_auto_negotiation': False
    } 
        
    index = 1
    for port in port_list:
        port_name = start_name + '-' + str(index)
        index += 1
        """ Map a test port location (ip, card, port) to a virtual port (name) """
        vports.append(port_map.Map(
            IpAddress=port['ip'],
            CardId=port['card_id'],
            PortId=port['port_id'],
            Name=port_name)
        )
    
    """ Connect all mapped virtual ports to test port locations """
    port_map.Connect()
 
    # Set L1 config
    i = 0
    for vport in ixnetwork.Vport.find():
        vport.L1Config.CurrentType = \
            port_list[i].get('card_type', port_property['card_type'])

        vport.L1Config.NovusHundredGigLan.Fcoe.PfcPriorityGroups = \
            port_list[i].get('pfc_priotity_groups',
                port_property['pfc_priotity_groups'])


        vport.L1Config.NovusHundredGigLan.IeeeL1Defaults = \
            port_list[i].get('ieee_l1_defaults',
                port_property['ieee_l1_defaults']) 

        vport.L1Config.NovusHundredGigLan.EnableAutoNegotiation = \
            port_list[i].get('enable_auto_negotiation',
                port_property['enable_auto_negotiation']) 

        port_speed = port_list[i].get('speed', port_property['speed'])
        vport.L1Config.NovusHundredGigLan.Speed = \
            'speed{}g'.format(port_speed/1000)

        i += 1
        
    return vports


def create_topology(
        session, 
        ports, 
        name='Topology 1', 
        ip_type='ipv4', 
        ip_start='10.0.0.1', 
        ip_incr_step='0.0.0.1', 
        gw_start='10.0.0.2', 
        gw_incr_step='0.0.0.0'):

    """ This function creates a topology with ethernet and IP stack on 
    IxNetwork

    Note: ipv6 stack option is left for future extension.

    Args:
        session (obj): Ixia session object.
        ports (list): List of IxNetwork port objects, returned by the
            function 'configure_ports'  
        name (str): The name of the topology.    
        ip_type (str): IP stack type - ipv4 or ipv6.
        ip_start (str): Starting interface IP address.
        ip_incr_step (str): IP address increment step in IP format like 
            "0.0.0.1"
        gw_start (str): Starting gateway IP address. 
        gw_incr_step (str): IP address increment step in IP format like
            "0.0.0.1"
  
    Return: IxNetwork topology obect.       
    """

    ixnetwork = session.Ixnetwork
    
    topology = ixnetwork.Topology.add(Name=name, Ports=ports)
    ixnetwork.info('Creating Topology Group {}'.format(name))
    
    device_group = topology.DeviceGroup.add(Name=name+' DG', Multiplier='1')
    ethernet = device_group.Ethernet.add(Name='Ethernet')
    if (ip_type == 'ipv4') : 
        ixnetwork.info('Configure IPv4')
        ipv4 = ethernet.Ipv4.add(Name='Ipv4')
        ipv4.Address.Increment(start_value=ip_start, step_value=ip_incr_step)
        ipv4.Address.Steps.Step = ip_incr_step
    
        ipv4.GatewayIp.Increment(start_value=gw_start, step_value=gw_incr_step)
        ipv4.GatewayIp.Steps.Step = gw_incr_step
    elif (ip_type == 'ipv6') :
        # ipv6 stack option is left for future extension. 
        pass
    else :
        logger.info("Unsupported address-type")  
        pytest_assert(0) 
    
    return topology


def start_protocols(session):
    """This function starts all the protocols configured on the IxNetwork
       protocol stack (e.g., IP and Ethernet).
       
    Args:
        session (obj) : IxNetwork session object.
     
    Returns:
        None    
    """ 
    ixnetwork = session.Ixnetwork
    ixnetwork.StartAllProtocols(Arg1='sync')
    protocolSummary = session.StatViewAssistant('Protocols Summary')
    protocolSummary.CheckCondition('Sessions Not Started', protocolSummary.EQUAL, 0)
    protocolSummary.CheckCondition('Sessions Down', protocolSummary.EQUAL, 0)
    logger.info(protocolSummary)


def stop_protocols(session) :
    """This function stops all the protocols configured on the IxNetwork
       protocol stack (e.g., IP and Ethernet).

    Args:
        session (obj) : IxNetwork session object.

    Returns:
        None
    """
    ixnetwork = session.Ixnetwork
    ixnetwork.StopAllProtocols(Arg1='sync')


def get_traffic_statistics(session, stat_view_name='Flow Statistics'):
    """This function fetches the traffic statistics information.
       
    Args:
        session (obj) : IxNetwork session object.
        stat_view_name (str, optional): Statistics view name. Default 
            value is 'Flow Statistics'

    Returns:
        traffic statistics dictionary. 
    """
    ixnetwork = session.Ixnetwork
    traffic_statistics = session.StatViewAssistant(stat_view_name)
    ixnetwork.info('{}\n'.format(traffic_statistics))
    return traffic_statistics


def stop_traffic(session):
    """ This function stops all the IxNetwork traffic items configured 
        on all the ports.
    Args:
        session (obj): IxNetwork session object.

    Returns:
        None.   
    """
    ixnetwork = session.Ixnetwork
    ixnetwork.Traffic.StopStatelessTrafficBlocking()


def start_traffic(session):
    """ This function starts all the IxNetwork traffic items configured 
        on all the ports.
    Args:
        session (obj): IxNetwork session object.

    Returns:
        None.   
    """
    ixnetwork = session.Ixnetwork
    """ Apply traffic to hardware """
    ixnetwork.Traffic.Apply()
    """ Run traffic """
    ixnetwork.Traffic.StartStatelessTrafficBlocking()


def create_ip_traffic_item (
        session,
        src_start_port,
        src_port_count,
        src_first_route_index,
        src_route_count,
        dst_start_port,
        dst_port_count,
        dst_first_route_index,
        dst_route_count,
        name='example_traffic',
        traffic_type='ipv4') :

    """
    This function creates a traffic item where source and destination ports 
    belong to same IxNetwork topology-object. Since source and destination 
    belong to same topology, source and destination endpoints may be
    selected by selecting starting source port, source port count, first
    route address index on the source port, source route count, destination
    start port, destination port count, destination first-route index,
    and destination route count.

    Args:
        session (obj): IxNetwork session object. 
        src_start_port (int): The start port number.
        src_port_count (int): The number of ports involved in sending traffic 
            starting from src_start_port number. Example, if the start port is 
            port2 and port2 to port5 is sending traffic then src_start_port = 2
            and src_port_count = 3.   
        src_first_route_index (int): The first route address index. Conceptually
            assume the routes (source IP address) are organized as list. Choose 
            the starting route index.
        src_route_count (int): Number of routes starting from the 
            src_first_route_index. So this together src_first_route_index will 
            determine total number of sources.
        dst_start_port (int): The first destination port number.  
        dst_port_count (int): Number of ports involved in receiving the traffic
            starting from dst_start_port number. Example, if the rx port is
            port6 and port7 then dst_start_port = 6 and dst_port_count = 2
        dst_first_route_index (int): The first destination IP index. Conceptually
            assume the routes (destination IP address) organized as list. Choose
            the starting destination route index.
        dst_route_count (int): Number of destination IPs starting from
           dst_first_route_index. So this together with dst_first_route_index
           will  determine the total number of destinations.
        name (str, optional): Name of the traffic item. Default name is
           'example_traffic'.
        traffic_type (str, optional): Type of the IP source and destination
        (ipv4/ipv6). Default traffic_type is 'ipv4'.

    Returns:
        IxNetwork traffic item object. 

    """ 

    traffic_item = session.Ixnetwork.Traffic.TrafficItem.add(
                   Name = name,
                   TrafficType = traffic_type)

    if (traffic_type == 'ipv4') :
        obj = '/api/v1/sessions/1/ixnetwork/topology/1/deviceGroup/1/ethernet/1/ipv4/1'
    elif (traffic_type == 'ipv6'):
        obj = '/api/v1/sessions/1/ixnetwork/topology/1/deviceGroup/1/ethernet/1/ipv6/1'
    else :
        pytest_assert(0) 
    
    src = [{'arg1': obj,
            'arg2': src_start_port,
            'arg3': src_port_count,
            'arg4': src_first_route_index,
            'arg5': dst_route_count}
    ]

    dst = [{'arg1': obj, 
            'arg2': dst_start_port,
            'arg3': dst_port_count,
            'arg4': dst_first_route_index,
            'arg5': dst_route_count}
    ]
        
    endPoint = traffic_item.EndpointSet.add()
    endPoint.ScalableSources = src
    endPoint.ScalableDestinations = dst

    # Enable tracking.
    traffic_item.Tracking.find().TrackBy = ['trackingenabled0']
    return traffic_item


def create_ipv4_traffic(session,
                        name,
                        source,
                        destination,
                        pkt_size=64,
                        pkt_count=None,
                        duration=None,
                        rate_percent=100,
                        start_delay=0,
                        dscp_list=None,
                        lossless_prio_list=None,
                        ecn_capable=False):
    """
    Create an IPv4 traffic item on IxNetwork.

    Args:
        session (obj): IxNetwork session object.
        name (str): Name of traffic item
        source (obj list): Source endpoints - list of IxNetwork vport objects.
        destination (obj list): Destination endpoints - list of IxNetwork 
            vport objects.
        pkt_size (int): Packet size.
        pkt_count (int): Packet count.
        duration (int): Traffic duration in second (positive integer only!)
        rate_percent (int): Percentage of line rate.
        start_delay (int): Start delay in second.
        dscp_list(int list): List of DSCPs.
        lossless_prio_list (int list): List of lossless priorities.
        ecn_capable (bool): If packets can get ECN marked.

    Returns:
        The created traffic item or None in case of error.
    """
    ixnetwork = session.Ixnetwork

    traffic_item = ixnetwork.Traffic.TrafficItem.add(Name=name, 
                                                     BiDirectional=False, 
                                                     TrafficType='ipv4')

    traffic_item.EndpointSet.add(Sources=source, Destinations=destination)

    traffic_config  = traffic_item.ConfigElement.find()[0]

    # Todo: add sending rate support
    traffic_config.FrameRate.update(Type='percentLineRate', Rate=rate_percent)
    traffic_config.FrameRateDistribution.PortDistribution = 'splitRateEvenly'
    traffic_config.FrameSize.FixedSize = pkt_size

    if pkt_count is not None and duration is not None:
        logger.error('You can only specify either pkt_count or duration')
        return None

    if pkt_count is not None:
        traffic_config.TransmissionControl.update(Type='fixedFrameCount', 
                                                  FrameCount=pkt_count)
    elif duration is not None:
        if type(duration) != int or duration <= 0:
            logger.error('Invalid duration value {} (positive integer only)'.
                format(duration))

            return None
        else:
            traffic_config.TransmissionControl.update(
                Type='fixedDuration', 
                Duration=duration)
    else:
        traffic_config.TransmissionControl.update(Type='continuous')

    if start_delay > 0:
        traffic_config.TransmissionControl.update(
            StartDelayUnits='nanoseconds',
            StartDelay=start_delay*(10**6))

    if dscp_list is not None and len(dscp_list) > 0:
        phb_field = traffic_item.ConfigElement.find().Stack.find('IPv4').Field.\
            find(DisplayName='Default PHB')

        phb_field.ActiveFieldChoice = True
        phb_field.ValueType = 'valueList'
        phb_field.ValueList = dscp_list

    # Set ECN bits to 10 (ECN capable).
    if ecn_capable:
        phb_field = traffic_item.ConfigElement.find().Stack.find('IPv4').\
            Field.find(FieldTypeId='ipv4.header.priority.ds.phb.defaultPHB.unused')

        phb_field.ActiveFieldChoice = True
        phb_field.ValueType = 'singleValue'
        phb_field.SingleValue = 2

    if lossless_prio_list is not None and len(lossless_prio_list) > 0:
        eth_stack = traffic_item.ConfigElement.find()[0].Stack.find(
            DisplayName='Ethernet II')

        pfc_queue = eth_stack.Field.find(DisplayName='PFC Queue')
        pfc_queue.ValueType = 'valueList'
        pfc_queue.ValueList = lossless_prio_list

    traffic_item.Tracking.find()[0].TrackBy = ['flowGroup0']

    # Push ConfigElement settings down to HighLevelStream resources.
    traffic_item.Generate()

    return traffic_item


def create_pause_traffic(session, name, source, pkt_per_sec, pkt_count=None, 
                         duration=None, start_delay=0, global_pause=False,
                         pause_prio_list=[]):
    """
    Create a pause traffic item.

    Args:
        session (obj): IxNetwork session object.
        name (str): Name of traffic item.
        source (obj list): Source endpoints - list of IxNetwork vport objects.
        pkt_per_sec (int): Packets per second.
        pkt_count (int): Packet count.
        duration (int): Traffic duration in second (positive integer only!).
        start_delay (int): Start delay in second.
        global_pause (bool): If the generated packets are global pause
            (IEEE 802.3X PAUSE).
        pause_prio_list: list of priorities to pause. Only valid when
            global_pause is False.

    Returns:
        The created traffic item or None if any errors happen.
    """
    if pause_prio_list is not None:
        for prio in pause_prio_list:
            if prio < 0 or prio > 7:
                logger.error('Invalid pause priorities {}'.
                    format(pause_prio_list))
                return None

    ixnetwork = session.Ixnetwork
    traffic_item = ixnetwork.Traffic.TrafficItem.add(Name=name, 
                                                     BiDirectional=False, 
                                                     TrafficType='raw')

    # Since PFC packets will not be forwarded by the switch, so 
    # destinations are actually not used. 
    traffic_item.EndpointSet.add(Sources=source.Protocols.find(),
                                 Destinations=source.Protocols.find())

    traffic_config = traffic_item.ConfigElement.find()[0]
    traffic_config.FrameRate.update(Type='framesPerSecond', Rate=pkt_per_sec)
    traffic_config.FrameRateDistribution.PortDistribution = 'splitRateEvenly'
    traffic_config.FrameSize.FixedSize = 64

    if pkt_count is not None and duration is not None:
        logger.error('You can only specify either pkt_count or duration')
        return None

    if pkt_count is not None:
        traffic_config.TransmissionControl.update(
            Type='fixedFrameCount', 
            FrameCount=pkt_count)

    elif duration is not None:
        if type(duration) != int or duration <= 0:
            logger.error('Invalid duration value {} (positive integer only)'.
                format(duration))

            return None
        else:
            traffic_config.TransmissionControl.update(
                Type='fixedDuration', 
                Duration=duration)

    else:
        traffic_config.TransmissionControl.update(Type='continuous')

    if start_delay > 0:
        traffic_config.TransmissionControl.update(
            StartDelayUnits='nanoseconds',
            StartDelay=start_delay*(10**9))

    # Add PFC header
    pfc_stack_obj = __create_pkt_hdr(
        ixnetwork=ixnetwork,
        traffic_item=traffic_item,
        pkt_hdr_to_add='^PFC PAUSE \(802.1Qbb\)',
        append_to_stack='Ethernet II')

    # Construct global pause and PFC packets.
    if global_pause:
        __set_global_pause_fields(pfc_stack_obj)
    else:
        __set_pfc_fields(pfc_stack_obj, pause_prio_list)

    # Remove Ethernet header.
    traffic_item.ConfigElement.find()[0].Stack.\
        find(DisplayName="Ethernet II").Remove()

    traffic_item.Tracking.find()[0].TrackBy = ['flowGroup0']

    # Push ConfigElement settings down to HighLevelStream resources.
    traffic_item.Generate()

    return traffic_item

# This section defines helper function used in the module. These functions
# should not be called from test script.
# 1. __set_global_pause_fields 
# 2. __set_eth_fields
# 3. __set_pfc_fields
# 4. __create_pkt_hdr

def __set_global_pause_fields(pfc_stack_obj):
    code = pfc_stack_obj.find(DisplayName='Control opcode')
    code.ValueType = 'singleValue'
    code.SingleValue = '1'

    # This field is pause duration in global pause packet.
    prio_enable_vector = pfc_stack_obj.find(DisplayName='priority_enable_vector')

    prio_enable_vector.ValueType = 'singleValue'
    prio_enable_vector.SingleValue = 'ffff'

    # pad bytes
    for i in range(8):
        pause_duration = pfc_stack_obj.find(DisplayName='PFC Queue {}'.format(i))

        pause_duration.ValueType = 'singleValue'
        pause_duration.SingleValue = '0'


def __set_eth_fields(eth_stack_obj, src_mac, dst_mac):
    if src_mac is not None:
        src_mac_field = eth_stack_obj.find(DisplayName='Source MAC Address')
        src_mac_field.ValueType = 'singleValue'
        src_mac_field.SingleValue = src_mac

    if dst_mac is not None:
        dst_mac_field = eth_stack_obj.find(DisplayName='Destination MAC Address')

        dst_mac_field.ValueType = 'singleValue'
        dst_mac_field.SingleValue = dst_mac


def __set_ip_fields(ip_stack_obj, src_ip, dst_ip, dscp_list):
    if src_ip is not None:
        src_ip_field = ip_stack_obj.find(DisplayName='Source Address')
        src_ip_field.ValueType = 'singleValue'
        src_ip_field.SingleValue = src_ip

    if dst_ip is not None:
        dst_ip_field = ip_stack_obj.find(DisplayName='Destination Address')
        dst_ip_field.ValueType = 'singleValue'
        dst_ip_field.SingleValue = dst_ip

    if dscp_list is not None and len(dscp_list) > 0:
        phb_field = ip_stack_obj.find(DisplayName='Default PHB')
        phb_field.ActiveFieldChoice = True
        phb_field.ValueType = 'valueList'
        phb_field.ValueList = dscp_list


def __set_pfc_fields(pfc_stack_obj, pause_prio_list):
    code = pfc_stack_obj.find(DisplayName='Control opcode')
    code.ValueType = 'singleValue'
    code.SingleValue = '101'

    prio_enable_vector = pfc_stack_obj.find(DisplayName='priority_enable_vector')
    prio_enable_vector.ValueType = 'singleValue'

    val = 0
    for prio in pause_prio_list:
        val += (1 << prio)
    prio_enable_vector.SingleValue = hex(val)

    for i in range(8):
        pause_duration = pfc_stack_obj.find(DisplayName='PFC Queue {}'.format(i))
        pause_duration.ValueType = 'singleValue'

        if i in pause_prio_list:
            pause_duration.SingleValue = 'ffff'
        else:
            pause_duration.SingleValue = '0'


def __create_pkt_hdr(ixnetwork, 
                       traffic_item, 
                       pkt_hdr_to_add,
                       append_to_stack):
    #Add new packet header in traffic item
    config_element = traffic_item.ConfigElement.find()[0]

    # Do the followings to add packet headers on the new traffic item

    # Uncomment this to show a list of all the available protocol templates 
    # to create (packet headers)
    #for protocolHeader in ixNetwork.Traffic.ProtocolTemplate.find():
    #    ixNetwork.info('Protocol header: -- {} --'.
    #        format(protocolHeader.DisplayName))

    # 1> Get the <new packet header> protocol template from the ProtocolTemplate 
    #   list.
    pkt_hdr_proto_template = \
        ixnetwork.Traffic.ProtocolTemplate.find(DisplayName=pkt_hdr_to_add)
    #ixNetwork.info('protocolTemplate: {}'.format(packetHeaderProtocolTemplate))

    # 2> Append the <new packet header> object after the specified packet 
    #   header stack.
    append_to_stack_obj = config_element.Stack.find(
        DisplayName=append_to_stack
    )
    #ixNetwork.info('appendToStackObj: {}'.format(appendToStackObj))
    append_to_stack_obj.Append(Arg2=pkt_hdr_proto_template)

    # 3> Get the new packet header stack to use it for appending an 
    # IPv4 stack after it. Look for the packet header object and stack ID.
    pkt_hdr_stack_obj = config_element.Stack.find(DisplayName=pkt_hdr_to_add)

    # 4> In order to modify the fields, get the field object
    pkt_hdr_field_obj = pkt_hdr_stack_obj.Field.find()
    #ixNetwork.info('packetHeaderFieldObj: {}'.format(packetHeaderFieldObj))

    # 5> Save the above configuration to the base config file.
    #   ixNetwork.SaveConfig(Files('baseConfig.ixncfg', local_file=True))
    return pkt_hdr_field_obj

