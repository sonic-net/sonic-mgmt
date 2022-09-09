import re
import logging

logger = logging.getLogger(__name__)


class LLDPProtocol:
    def __init__(self, dut_handler):
        self.device_handler = dut_handler

    def check_lldp(self, list_of_interfaces):
        """
        :param list_of_interfaces: List of interface for which LLDP details are needed
        :return status, lldp_neighbor_info
        """
        lldp_neighbors = self.device_handler.get_lldp_neighbors()
        converted_list_of_interfaces = self.device_handler.convert_interface_prefix(list_of_interfaces)
        lldp_missing = []
        # Need to check if either the converted or the original naming convention present in lldp_neighbors
        for index, interface in enumerate(converted_list_of_interfaces):
            if interface not in lldp_neighbors:
                if list_of_interfaces[index] not in lldp_neighbors:
                    lldp_missing.append(list_of_interfaces[index])
        if lldp_missing:
            return False, "LLDP neighbors missing: {}".format(lldp_missing)
        return True, "LLDP up for {}".format(list_of_interfaces)

    def check_graph_via_lldp(self, list_of_interfaces):
        """
        :param list_of_interfaces: List of interface for which is supported in graph
        :return status, lldp_neighbor_info
        """
        lldp_neighbors = self.device_handler.get_lldp_neighbors()
        converted_list_of_interfaces = self.device_handler.convert_interface_prefix(list_of_interfaces)
        lldp_missing = []
        # Need to check if either the converted or the original naming convention present in lldp_neighbors
        for interface in lldp_neighbors.keys():
            if interface not in converted_list_of_interfaces and interface not in list_of_interfaces:
                lldp_missing.append(interface)
        if lldp_missing:
            return False, "LLDP neighbors missing from DeviceInterfaceLinks: {}".format(lldp_missing)
        return True, "LLDP neighbors are all listed in DeviceInterfaceLinks: {}".format(list_of_interfaces)

    def get_lldp_parse_peer_details(self, dut_interface=None):
        """
        :param dut_interface: Interface for which LLDP details are needed
        :return lldp_rx_parsed: dictionary containing platform, version, ip, mac, and port
        """
        lldp_rx_parsed = dict()
        # Get output of "show lldp neighbor" command
        lldp_details = self.device_handler.get_all_lldp_neighbor_details_for_port(dut_interface)
        # parse the output to get the specific info required
        lldp_rx_parsed = self.device_handler.parse_lldp_peer_required_info(lldp_details)
        return lldp_rx_parsed

    def get_lldp_peer_name_and_port(self, dut_interface=None):
        """
        :param dut_interface: Interface for which LLDP details are needed
        :return peer_name, peer_port
        """
        # Get output of "show lldp neighbor" command
        lldp_details = self.device_handler.get_all_lldp_neighbor_details_for_port(dut_interface)
        # parse the output
        lldp_rx_parsed = self.device_handler.parse_lldp_peer_required_info(lldp_details)
        # parse the output to get the specific info required
        peer_name = lldp_rx_parsed["name"]
        peer_port = lldp_rx_parsed["port"]

        return peer_name, peer_port

    def get_lldp_topology(self, topologies):
        """
        :param topologies: dictionary of expected topology
        e.g.
        {
            "PortChannel15": [
                {
                    "DeviceA": "rwa02.str01",
                    "DeviceB": "ibr02.str01",
                    "InterfaceA": "et-2/0/12",
                    "InterfaceB": "HundredGigE0/2/0/10",
                    "PortChannelA": "PortChannel15",
                    "PortChannelB": "PortChannel15"
                },
                {
                    "DeviceA": "rwa02.str01",
                    "DeviceB": "ibr02.str01",
                    "InterfaceA": "et-2/0/13",
                    "InterfaceB": "HundredGigE0/2/0/11",
                    "PortChannelA": "PortChannel15",
                    "PortChannelB": "PortChannel15"
                }
            ],
            "PortChannel206": [
                {
                    "DeviceA": "rwa02.str01",
                    "DeviceB": "str06-0100-0001-02sw",
                    "InterfaceA": "et-2/0/9",
                    "InterfaceB": "Ethernet5/24/1",
                    "PortChannelA": "PortChannel206",
                    "PortChannelB": "PortChannel206"
                },
                {
                    "DeviceA": "rwa02.str01",
                    "DeviceB": "str06-0100-0001-02sw",
                    "InterfaceA": "et-2/0/8",
                    "InterfaceB": "Ethernet5/23/1",
                    "PortChannelA": "PortChannel206",
                    "PortChannelB": "PortChannel206"
                }
            ]
        }

        :return lldp_topology_dict: Dictionary with expected peer details and actual LLDP peer details
        e.g.
        {
            "PortChannel15": [
                {
                    "lldp_peer_name": "ibr02.str01",
                    "lldp_peer_port": "HundredGigE0/2/0/10",
                    "topo_peer_name": "ibr02.str01",
                    "topo_peer_port": "HundredGigE0/2/0/10"
                },
                {
                    "lldp_peer_name": "ibr02.str01",
                    "lldp_peer_port": "HundredGigE0/2/0/11",
                    "topo_peer_name": "ibr02.str01",
                    "topo_peer_port": "HundredGigE0/2/0/11"
                }
            ],
            "PortChannel206": [
                {
                    "lldp_peer_name": "str06-0100-0001-02sw",
                    "lldp_peer_port": "Ethernet5/24/1",
                    "topo_peer_name": "str06-0100-0001-02sw",
                    "topo_peer_port": "Ethernet5/24/1"
                },
                {
                    "lldp_peer_name": "str06-0100-0001-02sw",
                    "lldp_peer_port": "Ethernet5/23/1",
                    "topo_peer_name": "str06-0100-0001-02sw",
                    "topo_peer_port": "Ethernet5/23/1"
                }
            ]
        }
        """
        lldp_topology_dict = {}
        for pc, topo in topologies.items():
            for link in topo:
                lldp_peer, lldp_port = self.get_lldp_peer_name_port(link["InterfaceA"])
                if re.search(r"Hu\d", lldp_port):
                    lldp_port = lldp_port.replace("Hu", "HundredGigE")
                elif re.search(r"FH\d", lldp_port):
                    lldp_port = lldp_port.replace("FH", "FourHundredGigE")
                # lldp_topology_dict[pc] = dict(topo_peer_name=link['DeviceB'], topo_peer_port=link['InterfaceB'],
                #                               lldp_peer_name=lldp_peer.lower(), lldp_peer_port=lldp_port)
                if pc not in lldp_topology_dict.keys():
                    lldp_topology_dict[pc] = [
                        dict(
                            topo_peer_name=link["DeviceB"],
                            topo_peer_port=link["InterfaceB"],
                            lldp_peer_name=lldp_peer.lower(),
                            lldp_peer_port=lldp_port,
                        )
                    ]
                else:
                    # if the Portchannel name is already present as key in the dictionary, then append this link
                    # to the existing list of links
                    lldp_topology_dict[pc].append(
                        dict(
                            topo_peer_name=link["DeviceB"],
                            topo_peer_port=link["InterfaceB"],
                            lldp_peer_name=lldp_peer.lower(),
                            lldp_peer_port=lldp_port,
                        )
                    )
        return lldp_topology_dict

    def validate_lldp_rx(self, dut_interface=None, neighbor_handler=None, neighbor_name=None, neighbor_interface=None):
        """
        :param dut_interface: DUT interface to check LLDP neighbor details for
        :param neighbor_handler: neighbor device
        :param neighbor_name: name of the neighbor device
        :param neighbor_interface: neighbor device interface
        :return result, result_message
        """
        device_b = neighbor_handler
        peer_info = dict()
        # Gather neighbor device information
        peer_info["platform"] = device_b.get_platform_from_cli()
        peer_info["version"] = device_b.get_version_from_cli()
        # Ignoring as we have issue with Cisco Management IP
        # peer_info['ip'] = device_b.get_mgmt_ip_from_cli()
        peer_info["chassis_id"] = device_b.get_chassis_id_from_cli()
        peer_info["port"] = neighbor_interface
        peer_info["name"] = neighbor_name
        # Get same information via LLDP on the DUT
        lldp_rx_info = self.get_lldp_parse_peer_details(dut_interface)
        if peer_info == lldp_rx_info:
            result = True
            result_message = "LLDP information received from neighbor matches neighbor information."
        else:
            result = False
            result_message = "LLDP information received from neighbor does not match neighbor information.\n"
            result_message += "Peer information: " + str(peer_info) + "\n"
            result_message += "LLDP received information: " + str(lldp_rx_info)
        return result, result_message
