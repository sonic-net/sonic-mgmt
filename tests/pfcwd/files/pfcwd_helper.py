import datetime
import ipaddress

from tests.common import constants


class TrafficPorts(object):
    """ Generate a list of ports needed for the PFC Watchdog test"""
    def __init__(self, mg_facts, neighbors, vlan_nw):
        """
        Args:
            mg_facts (dict): parsed minigraph info
            neighbors (list):  'device_conn' info from connection graph facts
            vlan_nw (string): ip in the vlan range specified in the DUT

        """
        self.mg_facts = mg_facts
        self.bgp_info = self.mg_facts['minigraph_bgp']
        self.port_idx_info = self.mg_facts['minigraph_port_indices']
        self.pc_info = self.mg_facts['minigraph_portchannels']
        self.vlan_info = self.mg_facts['minigraph_vlans']
        self.neighbors = neighbors
        self.vlan_nw = vlan_nw
        self.test_ports = dict()
        self.pfc_wd_rx_port = None
        self.pfc_wd_rx_port_addr = None
        self.pfc_wd_rx_neighbor_addr = None
        self.pfc_wd_rx_port_id = None

    def build_port_list(self):
        """
        Generate a list of ports to be used for the test

        For T0 topology, the port list is built parsing the portchannel and vlan info and for T1,
        port list is constructed from the interface info
        """
        if self.mg_facts['minigraph_interfaces']:
            self.parse_intf_list()
        elif self.mg_facts['minigraph_portchannels']:
            self.parse_pc_list()
        elif 'minigraph_vlan_sub_interfaces' in self.mg_facts:
            self.parse_vlan_sub_interface_list()
        if self.mg_facts['minigraph_vlans']:
            self.test_ports.update(self.parse_vlan_list())
        return self.test_ports

    def parse_intf_list(self):
        """
        Built the port info from the ports in 'minigraph_interfaces'

        The constructed port info is a dict with a port as the key (transmit port) and value contains
        all the info associated with this port (its fanout neighbor, receive port, receive ptf id,
        transmit ptf id, neighbor addr etc).  The first port in the list is assumed to be the Rx port.
        The rest of the ports will use this port as the Rx port while populating their dict
        info. The selected Rx port when used as a transmit port will use the next port in
        the list as its associated Rx port
        """
        pfc_wd_test_port = None
        first_pair = False
        for intf in self.mg_facts['minigraph_interfaces']:
            if ipaddress.ip_address(unicode(intf['addr'])).version != 4:
                continue
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_port = intf['attachto']
                self.pfc_wd_rx_port_addr = intf['addr']
                self.pfc_wd_rx_port_id = self.port_idx_info[self.pfc_wd_rx_port]
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_port = intf['attachto']
                pfc_wd_test_port_addr = intf['addr']
                pfc_wd_test_port_id = self.port_idx_info[pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for item in self.bgp_info:
                    if ipaddress.ip_address(unicode(item['addr'])).version != 4:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and item['peer_addr'] == self.pfc_wd_rx_port_addr:
                        self.pfc_wd_rx_neighbor_addr = item['addr']
                    if item['peer_addr'] == pfc_wd_test_port_addr:
                        pfc_wd_test_neighbor_addr = item['addr']

                self.test_ports[pfc_wd_test_port] = {'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                                                     'rx_port': [self.pfc_wd_rx_port],
                                                     'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                                     'peer_device': self.neighbors[pfc_wd_test_port]['peerdevice'],
                                                     'test_port_id': pfc_wd_test_port_id,
                                                     'rx_port_id': [self.pfc_wd_rx_port_id],
                                                     'test_port_type': 'interface'
                                                    }
            # populate info for the first port
            if first_pair:
                self.test_ports[self.pfc_wd_rx_port] = {'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                                        'rx_port': [pfc_wd_test_port],
                                                        'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                                                        'peer_device': self.neighbors[self.pfc_wd_rx_port]['peerdevice'],
                                                        'test_port_id': self.pfc_wd_rx_port_id,
                                                        'rx_port_id': [pfc_wd_test_port_id],
                                                        'test_port_type': 'interface'
                                                       }

            first_pair = False

    def parse_pc_list(self):
        """
        Built the port info from the ports in portchannel

        The constructed port info is a dict with a port as the key (transmit port) and value contains
        all the info associated with this port (its fanout neighbor, receive ports, receive
        ptf ids, transmit ptf ids, neighbor portchannel addr, its own portchannel addr etc).
        The first port in the list is assumed to be the Rx port. The rest
        of the ports will use this port as the Rx port while populating their dict
        info. The selected Rx port when used as a transmit port will use the next port in
        the list as its associated Rx port
        """
        pfc_wd_test_port = None
        first_pair = False
        for item in self.mg_facts['minigraph_portchannel_interfaces']:
            if ipaddress.ip_address(unicode(item['addr'])).version != 4:
                continue
            pc = item['attachto']
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_portchannel = pc
                self.pfc_wd_rx_port = self.pc_info[pc]['members']
                self.pfc_wd_rx_port_addr = item['addr']
                self.pfc_wd_rx_port_id = [self.port_idx_info[port] for port in self.pfc_wd_rx_port]
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_portchannel = pc
                pfc_wd_test_port = self.pc_info[pc]['members']
                pfc_wd_test_port_addr = item['addr']
                pfc_wd_test_port_id = [self.port_idx_info[port] for port in pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for bgp_item in self.bgp_info:
                    if ipaddress.ip_address(unicode(bgp_item['addr'])).version != 4:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and bgp_item['peer_addr'] == self.pfc_wd_rx_port_addr:
                        self.pfc_wd_rx_neighbor_addr = bgp_item['addr']
                    if bgp_item['peer_addr'] == pfc_wd_test_port_addr:
                        pfc_wd_test_neighbor_addr = bgp_item['addr']

                for port in pfc_wd_test_port:
                    self.test_ports[port] = {'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                                             'rx_port': self.pfc_wd_rx_port,
                                             'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                             'peer_device': self.neighbors[port]['peerdevice'],
                                             'test_port_id': self.port_idx_info[port],
                                             'rx_port_id': self.pfc_wd_rx_port_id,
                                             'test_portchannel_members': pfc_wd_test_port_id,
                                             'test_port_type': 'portchannel'
                                            }
            # populate info for the first port
            if first_pair:
                for port in self.pfc_wd_rx_port:
                    self.test_ports[port] = {'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                             'rx_port': pfc_wd_test_port,
                                             'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                                             'peer_device': self.neighbors[port]['peerdevice'],
                                             'test_port_id': self.port_idx_info[port],
                                             'rx_port_id': pfc_wd_test_port_id,
                                             'test_portchannel_members': self.pfc_wd_rx_port_id,
                                             'test_port_type': 'portchannel'
                                            }

            first_pair = False

    def parse_vlan_list(self):
        """
        Add vlan specific port info to the already populated port info dict.

        Each vlan interface will be the key and value contains all the info associated with this port
        (receive fanout neighbor, receive port receive ptf id, transmit ptf id, neighbor addr etc).

        Args:
            None

        Returns:
            temp_ports (dict): port info constructed from the vlan interfaces
        """
        temp_ports = dict()
        vlan_details = self.vlan_info.values()[0]
        vlan_members = vlan_details['members']
        vlan_type = vlan_details.get('type')
        vlan_id = vlan_details['vlanid']
        rx_port = self.pfc_wd_rx_port if isinstance(self.pfc_wd_rx_port, list) else [self.pfc_wd_rx_port]
        rx_port_id = self.pfc_wd_rx_port_id if isinstance(self.pfc_wd_rx_port_id, list) else [self.pfc_wd_rx_port_id]
        for item in vlan_members:
            temp_ports[item] = {'test_neighbor_addr': self.vlan_nw,
                                'rx_port': rx_port,
                                'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                'peer_device': self.neighbors[item]['peerdevice'],
                                'test_port_id': self.port_idx_info[item],
                                'rx_port_id': rx_port_id,
                                'test_port_type': 'vlan'
                               }
            if hasattr(self, 'pfc_wd_rx_port_vlan_id'):
                temp_ports[item]['rx_port_vlan_id'] = self.pfc_wd_rx_port_vlan_id
            if vlan_type is not None and vlan_type == 'Tagged':
                temp_ports[item]['test_port_vlan_id'] = vlan_id

        return temp_ports

    def parse_vlan_sub_interface_list(self):
        """Build the port info from the vlan sub-interfaces."""
        pfc_wd_test_port = None
        first_pair = False
        for sub_intf in self.mg_facts['minigraph_vlan_sub_interfaces']:
            if ipaddress.ip_address(unicode(sub_intf['addr'])).version != 4:
                continue
            intf_name, vlan_id = sub_intf['attachto'].split(constants.VLAN_SUB_INTERFACE_SEPARATOR)
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_port = intf_name
                self.pfc_wd_rx_port_addr = sub_intf['addr']
                self.pfc_wd_rx_port_id = self.port_idx_info[self.pfc_wd_rx_port]
                self.pfc_wd_rx_port_vlan_id = vlan_id
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_port = intf_name
                pfc_wd_test_port_addr = sub_intf['addr']
                pfc_wd_test_port_id = self.port_idx_info[pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for item in self.bgp_info:
                    if ipaddress.ip_address(unicode(item['addr'])).version != 4:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and item['peer_addr'] == self.pfc_wd_rx_port_addr:
                        self.pfc_wd_rx_neighbor_addr = item['addr']
                    if item['peer_addr'] == pfc_wd_test_port_addr:
                        pfc_wd_test_neighbor_addr = item['addr']

                self.test_ports[pfc_wd_test_port] = {'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                                                     'rx_port': [self.pfc_wd_rx_port],
                                                     'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                                     'peer_device': self.neighbors[pfc_wd_test_port]['peerdevice'],
                                                     'test_port_id': pfc_wd_test_port_id,
                                                     'rx_port_id': [self.pfc_wd_rx_port_id],
                                                     'rx_port_vlan_id': self.pfc_wd_rx_port_vlan_id,
                                                     'test_port_vlan_id': vlan_id,
                                                     'test_port_type': 'interface'
                                                    }
            # populate info for the first port
            if first_pair:
                self.test_ports[self.pfc_wd_rx_port] = {'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                                        'rx_port': [pfc_wd_test_port],
                                                        'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                                                        'peer_device': self.neighbors[self.pfc_wd_rx_port]['peerdevice'],
                                                        'test_port_id': self.pfc_wd_rx_port_id,
                                                        'rx_port_id': [pfc_wd_test_port_id],
                                                        'rx_port_vlan_id': vlan_id,
                                                        'test_port_vlan_id': self.pfc_wd_rx_port_vlan_id,
                                                        'test_port_type': 'interface'
                                                       }

            first_pair = False


def set_pfc_timers():
    """
    Set PFC timers

    Args:
        None

    Returns:
        pfc_timers (dict)
    """
    pfc_timers = {'pfc_wd_detect_time': 400,
                  'pfc_wd_restore_time': 400,
                  'pfc_wd_restore_time_large': 3000,
                  'pfc_wd_poll_time': 400
                 }
    return pfc_timers


def select_test_ports(test_ports):
    """
    Select a subset of ports from the generated port info

    Args:
        test_ports (dict): Constructed port info

    Returns:
        selected_ports (dict): random port info or set of ports matching seed
    """
    selected_ports = dict()
    rx_ports = set()
    seed = int(datetime.datetime.today().day)
    for port, port_info in test_ports.items():
        rx_port = port_info["rx_port"]
        if isinstance(rx_port, (list, tuple)):
            rx_ports.update(rx_port)
        else:
            rx_ports.add(rx_port)
        if (int(port_info['test_port_id']) % 15) == (seed % 15):
            selected_ports[port] = port_info

    # filter out selected ports that also act as rx ports
    selected_ports = {p: pi for p, pi in selected_ports.items()
                      if p not in rx_port}

    if not selected_ports:
        random_port = test_ports.keys()[0]
        selected_ports[random_port] = test_ports[random_port]

    return selected_ports


def start_wd_on_ports(duthost, port, restore_time, detect_time, action="drop"):
    """
    Starts PFCwd on ports

    Args:
        port (string): single port or space separated list of ports
        restore_time (int): PFC storm restoration time
        detect_time (int): PFC storm detection time
        action (string): PFCwd action. values include 'drop', 'forward'
    """
    duthost.command("pfcwd start --action {} --restoration-time {} {} {}"
                    .format(action, restore_time, port, detect_time))
