import re 

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
