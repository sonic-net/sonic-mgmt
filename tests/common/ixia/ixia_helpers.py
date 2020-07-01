import re 
from common.reboot import *
"""
@summary: given a DUT interface, return the management IP address of its neighbor IXIA device
@param intf: DUT interface
@param conn_graph_facts: testbed connectivity graph
@param ixia_dev: the mapping of hostname to IP address of IXIA devices
@return the management IP address of its neighbor IXIA device or None if we cannot find it
"""
def get_neigh_ixia_mgmt_ip(intf, conn_graph_facts, ixia_dev):
    device_conn = conn_graph_facts['device_conn']
    if intf not in device_conn:
        return None 
    
    ixia_dev_hostname = device_conn[intf]['peerdevice']
    if ixia_dev_hostname not in ixia_dev:
        return None 
    
    return ixia_dev[ixia_dev_hostname]

"""
@summary: given a DUT interface, return the card of its neighbor IXIA device
@param intf: DUT interface
@param conn_graph_facts: testbed connectivity graph
@return the card of its neighbor IXIA device or None if we cannot find it
"""
def get_neigh_ixia_card(intf, conn_graph_facts):
    device_conn = conn_graph_facts['device_conn']
    if intf not in device_conn:
        return None 
    
    ixia_intf = device_conn[intf]['peerport']
    pattern = r'Card(\d+)/Port(\d+)'
    m = re.match(pattern, ixia_intf)

    if m is None:
        return None 
    else:
        return m.group(1)    

"""
@summary: given a DUT interface, return the port of its neighbor IXIA device
@param intf: DUT interface
@param conn_graph_facts: testbed connectivity graph
@return the port of its neighbor IXIA device or None if we cannot find it
"""
def get_neigh_ixia_port(intf, conn_graph_facts):
    device_conn = conn_graph_facts['device_conn']
    if intf not in device_conn:
        return None
    
    ixia_intf = device_conn[intf]['peerport']
    pattern = r'Card(\d+)/Port(\d+)'
    m = re.match(pattern, ixia_intf)

    if m is None:
        return None 
    else:
        return m.group(2)

def parseFanoutConnections (device_conn) :
    retval = []
    for key in device_conn.keys() :
        pp =  device_conn[key]['peerport']
        string = key + '/' + pp
        retval.append(string)
    retval.sort()
    return(retval)

def getCardPort(i) :
    crd = (i.split('/')[0]).replace('Card', '')
    prt = (i.split('/')[1]).replace('Port', '')
    return (crd, prt)

class IxiaFanoutManager () :
    def __init__(self,fanout_data) :
        self.last_fanout_assessed = None
        self.fanout_list = []
        self.last_device_connection_details = None
        self.current_ixia_port_list = None
        self.ip_address = '0.0.0.0' 
        for i in fanout_data.keys() :
            self.fanout_list.append(fanout_data[i])

    def get_fanout_device_details (self, device_number) :

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
             self.__parseFanoutConnections__()

        #return self.fanout_list[self.last_fanout_assessed]

    def __parseFanoutConnections__ (self) :
        device_conn = self.last_device_connection_details
        retval = []
        for key in device_conn.keys() :
            pp =  device_conn[key]['peerport']
            string = key + '/' + pp
            retval.append(string)
        retval.sort()
        return(retval)
  
    def getCardPort (self, crd_prt) :
        ip  = self.ip_address
        crd = (crd_prt.split('/')[0]).replace('Card', '')
        prt = (crd_prt.split('/')[1]).replace('Port', '')
        return (ip, crd, prt)

    def get_chassis_ip (self) :
        return self.ip_address
       
    def ports(self) :
        return self.current_ixia_port_list  

