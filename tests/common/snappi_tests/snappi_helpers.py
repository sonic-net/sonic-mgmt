# -*- coding: utf-8 -*-
"""
This module contains a definition of a simple helper class
"SnappiFanoutManager" which can be used to manage cards and ports of Snappi
chassis instead of reading it from fanout_graph_facts fixture.
"""

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.common_helpers import ansible_stdout_to_str, get_peer_snappi_chassis
import time


class SnappiFanoutManager():
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

        {u'snappi-sonic': {
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
                    }
            },
            u'device_info': {
                u'HwSku': u'SNAPPI-tester',
                u'ManagementGw': u'10.36.78.54',
                u'ManagementIp': u'10.36.78.53/32',
                u'Type': u'DevSnappiChassis',
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
        self.current_snappi_port_list = None
        self.ip_address = '0.0.0.0'

        for fanout in list(fanout_data.keys()):
            # only snappi fanout, skip other fanout type(eos, sonic, etc.)
            if fanout_data[fanout]['device_info']['HwSku'] in ('SNAPPI-tester', 'IXIA-tester'):
                self.fanout_list.append(fanout_data[fanout])

    def __parse_fanout_connections__(self):
        device_conn = self.last_device_connection_details
        retval = []
        for key in list(device_conn.keys()):
            fanout_port = ansible_stdout_to_str(key)
            peer_port = ansible_stdout_to_str(device_conn[key]['peerport'])
            peer_device = ansible_stdout_to_str(device_conn[key]['peerdevice'])
            speed = ansible_stdout_to_str(device_conn[key]['speed'])
            string = "{}/{}/{}/{}/{}".\
                format(self.ip_address, fanout_port, peer_port, peer_device, speed)
            retval.append(string)

        return (retval)

    def get_fanout_device_details(self, device_number):
        """With the help of this function you can select the chassis you want
        to access. For example get_fanout_device_details(0) selects the
        first chassis. It just select the chassis but does not return
        anything. The rest of  the function then used to extract chassis
        information like "get_chassis_ip()" will the return the ip address
        of chassis 0 - the first chassis in the list.

        Note:
            Counting or indexing starts from 0. That is 0 = 1st chassis,
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
        chassis_ip = self.fanout_list[self.last_fanout_assessed]['device_info']['mgmtip']
        self.ip_address = ansible_stdout_to_str(chassis_ip)

        # List of chassis cards and ports
        self.current_snappi_port_list = \
            self.__parse_fanout_connections__()

    def get_connection_details(self):
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
        return (self.last_device_connection_details)

    def get_chassis_ip(self):
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

    def get_ports(self, peer_device=None):
        """This function returns list of ports that are (1) associated with a
        chassis (selected earlier using get_fanout_device_details() function)
        and (2) connected to a peer device (SONiC DUT) as a list of dictionary.

        Note: If you have not used get_fanout_device_details(), by default 0th
            (first) chassis remains selected. If you do not specify peer_device,
            this function will return all the ports of the chassis.

        Args:
            peer_device (str): hostname of the peer device

        Returns:
            Dictionary of chassis card port information.
        """
        retval = []
        for port in self.current_snappi_port_list:
            info_list = port.split('/')
            dict_element = {
                'ip': info_list[0],
                'card_id': info_list[1].replace('Card', ''),
                'port_id': info_list[2].replace('Port', ''),
                'peer_port': info_list[3],
                'peer_device': info_list[4],
                'speed': info_list[5]
            }

            if peer_device is None or info_list[4] == peer_device:
                retval.append(dict_element)

        return retval


def get_snappi_port_location(intf):
    """
    Extracting location from interface, since Snappi Api accepts location
    in terms of chassis ip, card, and port in different format.

    Note: Interface must have the keys 'ip', 'card_id' and 'port_id'

    Args:
    intf (dict) : intf must contain the keys 'ip', 'card_id', 'port_id'.
        Example format :
        {'ip': u'10.36.78.53',
         'port_id': u'1',
         'card_id': u'9',
         'speed': 100000,
         'peer_port': u'Ethernet0'}

    Returns: location in string format. Example: '10.36.78.5;1;2' where
    1 is card_id and 2 is port_id.
    """
    keys = set(['ip', 'card_id', 'port_id'])
    pytest_assert(keys.issubset(set(intf.keys())), "intf does not have all the keys")

    return "{};{};{}".format(intf['ip'], intf['card_id'], intf['port_id'])


def get_dut_port_id(dut_hostname, dut_port, conn_data, fanout_data):
    snappi_fanout = get_peer_snappi_chassis(conn_data=conn_data,
                                            dut_hostname=dut_hostname)

    if snappi_fanout is None:
        return None

    snappi_fanout_id = list(fanout_data.keys()).index(snappi_fanout)
    snappi_fanout_list = SnappiFanoutManager(fanout_data)
    snappi_fanout_list.get_fanout_device_details(device_number=snappi_fanout_id)

    snappi_ports = snappi_fanout_list.get_ports(peer_device=dut_hostname)

    for i in range(len(snappi_ports)):
        if snappi_ports[i]['peer_port'] == dut_port:
            return i

    return None


def wait_for_arp(snappi_api, max_attempts=10, poll_interval_sec=1):
    """
    This function waits for arp to get resolved for ipv4/ipv6 in the snappi config

    Args:
    snappi_api: snappi api
    max_attempts: maximum attempts for timeout
    poll_interval_sec: interval poll second

    Return:
    returns number of attempts if arp is resolved within max attempts else fail
    """
    attempts = 0
    v4_gateway_macs_resolved = False
    v6_gateway_macs_resolved = False

    get_config = snappi_api.get_config()
    v4_addresses = []
    v6_addresses = []

    for device in get_config.devices:
        for ethernet in device.ethernets:
            for v4_address in ethernet.ipv4_addresses:
                v4_addresses.append(v4_address.address)
            for v6_address in ethernet.ipv6_addresses:
                v6_addresses.append(v6_address.address)

    while attempts < max_attempts:
        request = snappi_api.states_request()
        request.choice = request.IPV4_NEIGHBORS
        states = snappi_api.get_states(request)

        if len(v4_addresses) > 0:
            v4_link_layer_address = [
                state.link_layer_address
                for state in states.ipv4_neighbors
                if state.link_layer_address is not None
            ]
            if len(v4_addresses) == len(v4_link_layer_address):
                v4_gateway_macs_resolved = True
        else:
            v4_gateway_macs_resolved = True

        request = snappi_api.states_request()
        request.choice = request.IPV6_NEIGHBORS
        states = snappi_api.get_states(request)

        if len(v6_addresses) > 0:
            v6_link_layer_address = [
                state.link_layer_address
                for state in states.ipv6_neighbors
                if state.link_layer_address is not None
            ]
            if len(v6_addresses) == len(v6_link_layer_address):
                v6_gateway_macs_resolved = True
        else:
            v6_gateway_macs_resolved = True

        if v4_gateway_macs_resolved and v6_gateway_macs_resolved:
            break
        else:
            time.sleep(poll_interval_sec)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "ARP is not resolved in {} seconds".format(max_attempts * poll_interval_sec))

    return attempts


def fetch_snappi_flow_metrics(api, flow_names):
    """
    Fetches the flow metrics from the corresponding snappi session using the api

    Args:
    api: snappi api
    flow_names: list of flow names

    Returns:
    flow_metrics (obj): list of metrics
    """
    request = api.metrics_request()
    request.flow.flow_names = flow_names
    flow_metrics = api.get_metrics(request).flow_metrics

    return flow_metrics
