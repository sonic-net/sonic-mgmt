import re
import logging
import time
from paramiko import SSHClient, AutoAddPolicy
from tests.common.devices.base import AnsibleHostBase


logger = logging.getLogger(__name__)

SAMPLE_COMMAND_DATA = """ vlab-04#show lldp neighbors | json
{
    "tablesLastChangeTime": 1652231658.9400651,
    "tablesAgeOuts": 2,
    "tablesInserts": 5,
    "lldpNeighbors": [
        {
            "ttl": 120,
            "neighborDevice": "vlab-03",
            "neighborPort": "fortyGigE0/12",
            "port": "Ethernet4"
        },
        {
            "ttl": 120,
            "neighborDevice": "ARISTA02T1",
            "neighborPort": "fortyGigE0/0",
            "port": "Ethernet7"
        }
    ],
    "tablesDeletes": 3,
    "tablesDrops": 0
} """


class AristaHost(AnsibleHostBase):
    """
    @summary: Class for Arista host
    """

    def __init__(self, ansible_adhoc, hostname, ansible_user, ansible_passwd):
        """Initialize an object for interacting with arista device using ansible modules
        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the arista device
            ansible_user (string): Username for accessing the arista CLI interface
            ansible_passwd (string): Password for the ansible_user
        """
        self.ansible_user = ansible_user
        self.ansible_passwd = ansible_passwd
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        # Reserved for execute ansible commands in local device
        self.localhost = ansible_adhoc(inventory="localhost", connection="local", host_pattern="localhost")[
            "localhost"
        ]

    def __getattr__(self, module_name):
        if module_name.startswith("eos_"):
            evars = {
                "ansible_connection": "network_cli",
                "ansible_network_os": module_name.split("_", 1)[0],
                "ansible_ssh_user": self.ansible_user,
                "ansible_ssh_pass": self.ansible_passwd,
                "ansible_become_method": "enable",
            }
        else:
            raise Exception("Does not have module: {}".format(module_name))
        self.host.options["variable_manager"].extra_vars.update(evars)
        return super(AristaHost, self).__getattr__(module_name)

    def __str__(self):
        return "<AristaHost {}>".format(self.hostname)

    def __repr__(self):
        return self.__str__()

    def commands(self, *args, **kwargs):
        return self.eos_command(*args, **kwargs)

    def config(self, *args, **kwargs):
        return self.eos_config(*args, **kwargs)

    def convert_mac_to_standard_format(self, mac_address):
        if mac_address.count(".") == 2 or mac_address.count(":") == 2:
            mac_address = mac_address.replace(".", "")
            mac = ""
            for index in range(12):
                mac += mac_address[index]
                if index > 0 and index < 11 and index % 2 == 1:
                    mac += ":"
        elif mac_address.count(".") == 5:
            mac = mac_address.replace(".", ":")
        else:
            return mac_address
        return mac

    def get_lldp_neighbor(self, local_iface=None):
        try:
            if local_iface is not None:
                match = re.match(r"Ethernet(\d+)", local_iface)
            if match:
                command = "show lldp neighbors Ethernet {} | json".format(match.group(1))
            else:
                command = "show lldp neighbors | json"
            output = self.commands(commands=[command])
            return output["stdout_lines"][0] if output["failed"] is False else False
        except Exception as e:
            logger.error("command {} failed. exception: {}".format(command, repr(e)))
            return False

    def isis_config_auth(self, key):
        # configure lsp authentication key
        output = self.config(
            lines=["authentication mode md5", "authentication key {} level-2".format(key)],
            parents=["router isis test1"],
        )
        logger.debug("configure lsp authentication key: %s" % (output))

        # configure hello authentication key
        output = self.config(
            lines=["isis authentication mode md5", "isis authentication key {} level-2".format(key)],
            parents=["interface Port-Channel2"],
        )
        logger.debug("configure hello authentication key: %s" % (output))

    def isis_remove_auth(self, key):
        # remove lsp authentication key
        output = self.config(
            lines=["no authentication mode md5", "no authentication key {} level-2".format(key)],
            parents=["router isis test1"],
        )
        logger.debug("remove lsp authentication key: %s" % (output))

        # remove hello authentication key
        output = self.config(
            lines=["no isis authentication mode md5", "no isis authentication key {} level-2".format(key)],
            parents=["interface Port-Channel2"],
        )
        logger.debug("remove hello authentication key: %s" % (output))

    def show_command_to_json(self, command, lookup_key=None, lookup_val=None):
        try:
            json_command = command + " | json"
            output = self.commands(commands=[json_command])
            if all([lookup_key, lookup_val]):
                return self.extract_key_val_pair_from_json(output["stdout_lines"], lookup_key, lookup_val)
            elif lookup_key is not None and lookup_val is None:
                return self.extract_val_from_json(output["stdout_lines"], lookup_key)
            else:
                return output["stdout_lines"]
        except Exception as e:
            return {"error": e}

    def extract_val_from_json(self, json_data, lookup_key):
        """
        Function to recursivly match provided key in all levels and put the matched key's value into a list for return
        """
        result = []

        def help(data, lookup_key, result):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == lookup_key:
                        result.append(v)
                    elif isinstance(v, (list, dict)):
                        sub_result = help(v, lookup_key, result)
                        if sub_result:
                            result.append(sub_result)
            elif isinstance(data, list):
                for ele in data:
                    if isinstance(ele, (list, dict)):
                        sub_result = help(ele, lookup_key, result)
                        if sub_result:
                            result.append(sub_result)

        help(json_data, lookup_key, result)
        return result

    def extract_key_val_pair_from_json(self, data, lookup_key, lookup_val):
        """
        Function to recursivly match provided key in all levels and put
        the matched key and value pair into a list for return
        """
        result = []

        def help(data, lookup_key, lookup_val, result):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == lookup_key and v == lookup_val:
                        result.append(data)
                    elif isinstance(v, (list, dict)):
                        sub_result = help(v, lookup_key, lookup_val, result)
                        if sub_result:
                            result.append(sub_result)
            elif isinstance(data, list):
                for ele in data:
                    if isinstance(ele, (list, dict)):
                        sub_result = help(ele, lookup_key, lookup_val, result)
                        if sub_result:
                            result.append(sub_result)

        help(data, lookup_key, lookup_val, result)
        return result

    def capture_prechange_config(self, prechange_filename):
        try:
            command = "copy running-config flash:/{}".format(prechange_filename)
            output = self.commands(commands=[command])
            if "Copy completed successfully" in output["stdout"][0]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to capture prechange config due to {}".format(str(e))

    def load_prechange_config(self, prechange_filename):
        try:
            command = "copy flash:/{} running-config".format(prechange_filename)
            output = self.commands(commands=[command])
            if "Copy completed successfully" in output["stdout"][0]:
                del_command = "delete flash:/{}".format(prechange_filename)
                output["stdout"][0] += self.commands(commands=[del_command])["stdout"][0]
                return True, output
            return False, "Failed to load prechange config due to {}".format(output)
        except Exception as e:
            return False, "Failed to load prechange config due to {}".format(str(e))

    def get_lldp_neighbors(self):
        lldp_details = {}
        try:
            logger.info("Gathering LLDP details")
            command = "show lldp neighbors | json"
            json_output = self.commands(commands=[command])
            if not json_output["failed"]:
                for row in json_output["stdout_lines"][0]["lldpNeighbors"]:
                    lldp_details.update(
                        {
                            row["port"]: {
                                "neighbor": row["neighborDevice"],
                                "local_interface": row["port"],
                                "neighbor_interface": row["neighborPort"],
                            }
                        }
                    )
                return lldp_details
            return "Falied to get lldp neighbors info due to {}".format(json_output)
        except Exception as e:
            return "Falied to get lldp neighbors info due to {}".format(str(e))

    def convert_interface_prefix(self, list_of_interfaces):
        """
        :param list_of_interfaces: List of interfaces which need to be updated for vendor naming convention
        :return converted_list_of_interfaces, converted list of interface names
        """
        converted_list_of_interfaces = []
        for interface in list_of_interfaces:
            converted_list_of_interfaces.append(interface.replace("Ethernet", "Et"))
        return converted_list_of_interfaces

    def get_all_lldp_neighbor_details_for_port(self, physical_port):
        """
        :param physical_port:
        :return:complete lldp details for the port from json formatted output converted to dictionary
        """
        command = "show lldp neighbors {} detail | json".format(physical_port)
        try:
            json_output = self.commands(commands=[command])
            if not json_output["failed"]:
                return json_output["stdout_lines"][0]
            return "Failed to get lldp neighbor details due to {}".format(json_output)
        except Exception as e:
            return "Failed to get lldp neighbor details due to {}".format(str(e))

    def get_chassis_id_from_cli(self):
        """
        :param interface: Name of the interface you need to get the MAC address for
        :return platform
        """
        try:
            command = "show lldp local-info | json"
            json_output = self.commands(commands=[command])
            if not json_output["failed"]:
                return json_output["stdout_lines"][0]["chassisId"]
            return "Failed to get chassis id due to {}".format(json_output)
        except Exception as e:
            return "Failed to get chassis id due to {}".format(str(e))

    def get_mgmt_ip_from_cli(self):
        """
        :return ip
        """
        try:
            command = "show lldp local-info | json"
            json_output = self.commands(commands=[command])
            if not json_output["failed"]:
                return json_output["stdout_lines"][0]["managementAddresses"][0]["address"]
            return "Failed to get mgmt IP due to {}".format(json_output)
        except Exception as e:
            return "Failed to get mgmt IP due to {}".format(str(e))

    def get_platform_from_cli(self):
        """
        :return platform
        """
        try:
            command = "show version | json"
            json_output = self.commands(commands=[command])
            if not json_output["failed"]:
                return json_output["stdout_lines"][0]["modelName"]
            return "Failed to get platform info due to {}".format(json_output)
        except Exception as e:
            return "Failed to get platform info due to {}".format(str(e))

    def get_version_from_cli(self):
        """
        :return version
        """
        try:
            command = "show version | json"
            json_output = self.commands(commands=[command])
            if not json_output["failed"]:
                return json_output["stdout_lines"][0]["version"]
            return "Failed to get platform info due to {}".format(json_output)
        except Exception as e:
            return "Failed to get platform info due to {}".format(str(e))

    def parse_lldp_peer_required_info(self, lldp_details=None):
        """
        :param lldp_details: Output of "show lldp neighbor"
        :return chassis
        """
        # Initialize dictionary to return
        lldp_required_info = dict()

        # Get the interface name
        interface = list(lldp_details["lldpNeighbors"].keys())[0]
        lldp_detail = None
        for interface_detail in lldp_details["lldpNeighbors"][interface]["lldpNeighborInfo"]:
            # Ignoring Cisco BE from LLDP
            if "Bundle-Ether" not in interface_detail["neighborInterfaceInfo"]["interfaceId"]:
                lldp_detail = interface_detail
        # Get Chassis ID:
        chassis_dotted = lldp_detail["chassisId"]
        chassis = self.convert_mac_to_standard_format(chassis_dotted)  # Convert to XX:XX:XX:XX:XX:XX format
        lldp_required_info["chassis_id"] = chassis

        # Get peer management IP:
        """
        Ignoring as we have issue with Cisco Management IP
        ip = lldp_detail['managementAddresses'][0]['address']
        lldp_required_info['ip'] = ip
        """

        # Get peer name:
        peer_name = lldp_detail["systemName"]
        peer_name = peer_name.replace(".str.msn.net", "")  # get rid of ".str.msn.net" if it exists
        peer_name = peer_name.replace(".network.microsoft.com", "")  # get rid of "microsoft.com" if it exists
        lldp_required_info["name"] = peer_name.lower()

        # Get system description
        system_description = lldp_detail["systemDescription"]

        # From this description, extract platform:
        # Juniper output looks like: Juniper Networks, Inc. jnp10016 internet router, kernel JUNOS 18.2X75-D51.9 ...
        if "Juniper" in system_description:
            description_list = system_description.split(" ")
            platform = description_list[3]
        # Cisco output looks like " 6.3.3, NCS-5500"
        elif "NCS" in system_description:
            description_list = system_description.split(",")
            platform = description_list[1].strip()
            """Arista output:
            Arista Networks EOS version 4.25.1F-DPE-20172666.fennercrystalnettrain0 (engineering build)
            running on an Arista Networks DCS-7804-CH"""
        elif "Arista" in system_description:
            description_list = system_description.split()
            platform = description_list[-1]
        # Cisco output looks like "'7.3.15.07I, 8000'"
        elif "8000" in system_description:
            description_list = system_description.split(",")
            platform = description_list[1].strip()

        lldp_required_info["platform"] = platform

        # From the same system description, extract version:
        # Juniper output looks like "Juniper Networks, Inc. jnp10008 internet router, kernel JUNOS 18.2X75-D51.9, ..."
        if "Juniper" in system_description:
            description_list = system_description.split(" ")
            # Find the word "JUNOS" and the version number is the next word
            index = 0
            while not description_list[index] == "JUNOS":
                index += 1
            version = description_list[index + 1][:-1]  # Get rid of last character, because it is a ","
        # Cisco output looks like " 6.3.3, NCS-5500"
        elif "NCS" in system_description:
            description_list = system_description.split(",")
            version = description_list[0].strip()
        # 'Arista Networks EOS version 4.25.1F-DPE-20172666.fennercrystalnettrain0 (engineering build) '
        elif "Arista" in system_description:
            regex = r"(?<=version ).*(?= running )"
            matches = re.search(regex, system_description, re.MULTILINE)
            version = matches.group()
        # Cisco output looks like "7.3.15.07I, 8000"
        elif "8000" in system_description:
            description_list = system_description.split(",")
            version = description_list[0].strip()

        lldp_required_info["version"] = version

        # Get the peer port ID
        peer_port = lldp_detail["neighborInterfaceInfo"]["interfaceId"]
        peer_port = peer_port.replace('"', "")  # Arista returns interface name with quotes which are unnecessary
        lldp_required_info["port"] = peer_port

        return lldp_required_info

    @staticmethod
    def convert_pc_name(pc_name):
        """
        :param pc_name: port-channel to be converted to Arista Port-Channel format
        :return: BE formatted ie. portchannel5 returns Bundle-Ether5
        """
        if "Port-Channel" in pc_name:
            return pc_name

        pc_name = pc_name.lower()

        if "portchannel" in pc_name:
            pc_name = pc_name.replace("portchannel", "Port-Channel")
        elif "ae" in pc_name:
            pc_name = pc_name.replace("ae", "Port-Channel")

        return pc_name

    def get_all_interfaces_in_pc(self, pc_name):
        """
        :param pc_name: port-channel/ae used for this test
        :return interfaces: list of port channel member interfaces
        """
        # Convert PortChannel to Bundle-Ether
        try:
            pc_name = self.convert_pc_name(pc_name)
            pc_on = pc_name.replace("Port-Channel", "")
            command = "show lacp {} aggregates | json".format(pc_on)
            json_output = self.commands(commands=[command])
            if not json_output["failed"]:
                return json_output["stdout_lines"][0]["portChannels"][pc_name]["bundledPorts"]
            return "Failed to get interfaces in port chancel due to {}".format(json_output)
        except Exception as e:
            return "Failed to get interfaces in port chancel due to {}".format(str(e))

    def check_interface_status(self, interface):
        """
        :param
        interface: str - port number e.g. ae15, Port-channel15
        :return:
        is_up: boolean , True if interface is up
        intf_status_output: str - raw output of show interface OR error message
        """
        # Convert PortChannel to Bundle-Ether
        pc_name = self.convert_pc_name(interface)
        command = "show interfaces {}".format(pc_name)
        try:
            success_criteria = "line protocol is up"
            intf_status_output = self.commands(commands=[command])
            if not intf_status_output["failed"]:
                logger.info("Interface status check: {} sent to {}".format(command, self.hostname))
                is_up = success_criteria in intf_status_output["stdout"][0].lower()
                return is_up, intf_status_output["stdout_lines"][0]
            return False, intf_status_output
        except Exception as e:
            return False, "Failed to check interface status due to {}".format(str(e))

    def get_isis_adjacency(self):
        """Method to gather isis adjacency details"""
        isis_details = {}
        try:
            logger.info("Gathering ISIS adjacency details")
            command = "show isis neighbors| json"
            output = self.commands(commands=[command])
            if not output["failed"]:
                isis_instances = output["stdout"][0]["vrfs"]["default"]["isisInstances"].keys()
                for instance in isis_instances:
                    for key, line in output["stdout"][0]["vrfs"]["default"]["isisInstances"][instance][
                        "neighbors"
                    ].items():
                        for adjacencies in line["adjacencies"]:
                            isis_details.update(
                                {
                                    adjacencies["interfaceName"]: {
                                        "neighbor": adjacencies.get("hostname", key),
                                        "state": adjacencies["state"],
                                    }
                                }
                            )
            return isis_details
        except Exception as e:
            msg = "Failed to get isis adjacency due to {}".format(str(e))
            logger.exception(msg)
            isis_details["Result"] = msg
            return isis_details

    def check_isis_adjacency(self, neighbor_device, expected_adjacency_ports):
        adjacency = []
        isis_adj = self.get_isis_adjacency()
        exception = isis_adj.get("Result")
        if exception:
            return False, exception
        for isis_pc, isis_neighbor in isis_adj.items():
            if neighbor_device in isis_neighbor.values() and "up" in isis_neighbor.values():
                adjacency.append(isis_adj[isis_pc])
        if len(adjacency) == expected_adjacency_ports:
            return True, adjacency
        return False, adjacency

    def get_isis_database(self, queue=None):
        try:
            command = "show isis database"
            output = self.commands(commands=[command])
            lsp_entries = {}
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if "00-0" in line:
                        outline = line.strip().split()
                        lsp_entries[outline[0].strip()] = {
                            "sequence-number": int(outline[1]),
                            "checksum": int(outline[2]),
                        }
                if queue:
                    queue.put(lsp_entries)
                return lsp_entries
            return output
        except Exception as e:
            msg = "Failed to get isis database due to {} {}".format(command, str(e))
            logger.error(msg)
            return msg

    def get_bgp_status(self):
        """
        :return bgp session status
        """
        command = "show ip bgp summary | json"
        try:
            output = self.commands(commands=[command])
            bgp_status = {}
            if not output["failed"]:
                bgp_peer_info = output["stdout"][0]["vrfs"]["default"]["peers"]
                for peer_ip, peer_info in bgp_peer_info.items():
                    bgp_status[peer_ip] = peer_info["peerState"]
                return bgp_status
            return "Failed to get bgp status from device due to {}".format(output)
        except Exception as e:
            logger.error(str(e))
            return "Failed to get bgp status from device due to {}".format(str(e))

    def get_bgp_session_details(self, peer_ip):
        """
        :param peer_ip: bgp peer ip
        :return: dictionary with bgp session details
        """
        try:
            command = "show bgp neighbor {} | json".format(peer_ip)
            json_output = self.commands(commands=[command])
            return json_output
        except Exception as e:
            return {"msg": str(e)}

    def get_bgp_session_status(self, peer_ip):
        """
        :param peer_ip:
        :return: bgp session status e.g. Established
        """
        try:
            bgp_peer_details = self.get_bgp_session_details(peer_ip)
            if not bgp_peer_details["failed"]:
                bgp_session_status = bgp_peer_details["stdout"][0]["vrfs"]["default"]["peerList"][0]["state"]

            else:
                bgp_session_status = "failed to get bgp session status"
            return bgp_session_status
        except Exception as e:
            return "Failed to get bgp session status due to {}".format(str(e))

    def is_prefix_advertised_to_peer(self, prefix, peer_ip):
        """
        :param prefix:
        :param peer_ip:
        :return: Boolean status of whether prefix is advertised to the peer or not
        """
        command = "show ip bgp neighbors {} advertised-routes {} | json".format(peer_ip, prefix)
        try:
            json_output = self.commands(commands=[command])
            prefix_adv_status = False
            if not json_output["failed"]:
                bgp_route_entries = json_output["stdout"][0]["vrfs"]["default"]["bgpRouteEntries"]
                if len(bgp_route_entries) > 0 and prefix in bgp_route_entries:
                    prefix_adv_status = True
            return prefix_adv_status, json_output
        except Exception as e:
            logger.error(str(e))
            return False, "Failed to check is prefix advertised to peer due to {}".format(str(e))

    """
    LDP
    """

    def check_remote_ldp_sessions(self):
        """
        :param dut: The Device Under Test
        :return: boolean, message
        """
        # get a list of ldp neighbors marked as operational
        try:
            command = "show mpls ldp neighbor summary | json"
            json_output = self.commands(commands=[command])
            ldp_op_list = []
            if not json_output["failed"]:
                for neighbor in json_output["stdout"][0]["vrfs"]["default"]["neighbors"]:
                    if "state" in neighbor and neighbor["state"] == "stateOperational":
                        ldp_op_list.append(neighbor["tcpPeerIp"]["ip"])

                if ldp_op_list:
                    return self.get_core_interfaces(ldp_op_list)
            return False, "Failed to get ldp neighbor info due to {}".format(json_output)

        except Exception as e:
            message = "Failed to check remote ldp session due to {}".format(str(e))
            logger.error(message)
            return False, message

    def get_core_interfaces(self, ldp_op_list):
        """
        :param dut: The Device Under Test
        :param ldp_op_list: list of ldp neighbors marked as operational
        :return: boolean, message
        """
        # for each operational ldp session check the route to get the next-hop
        try:
            ldp_int_list = []
            for ldpneighbor in ldp_op_list:
                command = "show ip route {}".format(ldpneighbor)
                output = self.commands(commands=[command])
                if not output["failed"]:
                    for line in output["stdout_lines"][0]:
                        if "Port-Channel" in line:
                            ldp_int_list.append(line.split(",")[1].strip())
            if ldp_int_list:
                return self.verify_core_path(ldp_int_list)
            return False, "Failed to collect ldp interfaces"
        except Exception as e:
            return False, "Failed to collect ldp interfaces due to {}".format(str(e))

    def verify_core_path(self, ldp_int_list):
        """
        :param dut: The Device Under Test
        :param ldp_int_list: list of next-hop interfaces for operational ldp sessions
        :return: boolean, message
        """
        # check each next-hop address and see if the neighbor is an IBR or owr device
        list_of_physical_interface = []
        for interface in ldp_int_list:
            list_of_physical_interface += self.get_all_interfaces_in_pc(interface)

        for interface in list_of_physical_interface:
            interface = interface.replace("Ethernet", "")
            command = "show lldp neighbors | in {}".format(interface)
            output = self.commands(commands=[command])["stdout"][0]
            if "ibr" in output.lower() or "owr" in output.lower():
                # if more than one match is returned by the router, only take the first
                message = "{} ldp session traverses the core via: {}".format(self.hostname, "Ethernet" + interface)
                return True, message
        return False, "could not find an operational ldp session on {} traversing an IBR or OWR".format(self.hostname)

    """
    MACSEC
    """

    def get_macsec_connection_status_details(self, interface):
        """
        :param interface: interface of macsec adjacency
        :return: boolean, failure message or dict_out containing dictionary of attributes
        Example of output:
        {
            "interfaces": {
                "Ethernet5/26/1": {
                    "participants": {
                        "01123456789abcdef526": {
                            "details": {
                                "keyServerAddr": "28:99:3a:32:2e:10",
                                "llpnExhaustion": 0,
                                "sakTransmit": true,
                                "livePeerList": [
                                    "e2ab9925a29f883d4c737648"
                                ],
                                "keyServerMsgId": "e2ab9925a29f883d4c737648",
                                "keyNum": 24,
                                "keyServerPortId": 855,
                                "potentialPeerList": []
                            },
                            "success": true,
                            "electedSelf": false,
                            "msgId": "d329b9155706bcf0d0454bec",
                            "defaultActor": false,
                            "principalActor": true
                        },
                        "00123456789abcdef526fb": {
                            "details": {
                                "keyServerAddr": "28:99:3a:32:2e:10",
                                "llpnExhaustion": 0,
                                "sakTransmit": false,
                                "livePeerList": [
                                    "87d7de58d84defb8f1fea603"
                                ],
                                "keyServerMsgId": "",
                                "keyNum": 0,
                                "keyServerPortId": 855,
                                "potentialPeerList": []
                            },
                            "success": true,
                            "electedSelf": false,
                            "msgId": "9f2b3498de06bfa009a884ff",
                            "defaultActor": true,
                            "principalActor": false
                        }
                    }
                }
            }
        }
        """
        command = "show mac security participants {} detail | json".format(interface)
        json_output = self.commands(commands=[command])["stdout"][0]
        for interface_name in json_output["interfaces"].keys():
            if interface.lower() == interface_name.lower():
                break
        else:
            return False, "No session found on {}".format(interface)
        dict_out = {"cipher-suite": "gcm-aes-xpn-256", "pre-shared-key": {}, "fallback-key": {}}
        dict_out["pre-shared-key"]["ckn"] = "unassigned"
        dict_out["fallback-key"]["ckn"] = "unassigned"
        for ckn in json_output["interfaces"][interface]["participants"]:
            if json_output["interfaces"][interface]["participants"][ckn]["principalActor"]:
                dict_out["pre-shared-key"]["ckn"] = ckn
            elif not json_output["interfaces"][interface]["participants"][ckn]["principalActor"]:
                dict_out["fallback-key"]["ckn"] = ckn
        return True, dict_out

    def set_rekey_period(self, profile_name, rekey_period_value):
        """
        :param profile_name: policy to change rekey value on
        :param rekey_period_value: value to set rekey in seconds
        :return: boolean, output from rekey implementation
        """
        try:
            commands = ["mka session rekey-period {}".format(rekey_period_value)]
            parents = ["mac security", "profile {}".format(profile_name)]
            output = self.config(lines=commands, parents=parents)
            if not output["failed"]:
                return True, output
            return False, "Failed to set rekey period due to {}".format(output)
        except Exception as e:
            return False, "Failed to set rekey period due to {}".format(str(e))

    def get_macsec_profile(self, interface):
        """
        :param interface: interface of device to capture profile name
        :return: profile name
        """
        try:
            command = 'show run int {} | grep "mac security profile"'.format(interface)
            output = self.commands(commands=[command])
            """example of output:
            mac security profile macsec-profile-juniper-256-64CKN-64CAK-fallback
            """
            if not output["failed"]:
                return True, output["stdout_lines"][0][-1].split()[-1]
            return False, "Failed to get macsec profile due to {}".format(output)
        except Exception as e:
            return False, "Failed to get macsec profile due to {}".format(str(e))

    def get_macsec_status_logs(self, interface, last_count="30", log_type="ESTABLISHED"):
        """
        :param interface: interface of macsec adjacency
        :param log_type: ESTABLISHED, FAILURE, ROLLOVER
        :param last_count: optional field to capture number of logs
        :return: boolean, output from logs
        """
        try:
            if log_type == "ESTABLISHED":
                log_type = "established"
            elif log_type == "ROLLOVER":
                return True, "Device {} not support {} log".format(self.hostname, log_type)
            command = "show logging all | grep MKA | grep {} | grep {}".format(interface, log_type)
            output = self.commands(commands=[command])
            if not output["failed"]:
                return len(output["stdout_lines"][0]) > 0, output["stdout"][0]
            return False, "Failed to get macsec status logs due to {}".format(output)
        except Exception as e:
            return False, "Failed to get macsec status logs due to {}".format(str(e))

    def get_key_name(self, profile_name, key_type):
        return False, "Method not implemented for Arista"

    def set_macsec_key(self, profile_name, key, key_type, interface):
        """
        :param profile_name: macsec profile name used for key
        :param key: string key to apply
        :param key_type: fallback or primary
        :param interface: unused for arista
        :return: boolean and test_msg string
        """
        if key_type == "primary":
            parents = ["mac security", "profile {}".format(profile_name)]
            commands = ["key {} 0 {} ".format(key, key)]
            output = self.config(lines=commands, parents=parents)
            test_msg = "Output: {}".format(output)
            return True, test_msg
        elif key_type == "fallback":
            parents = ["mac security", "profile {}".format(profile_name)]
            commands = ["key {} 0 {} fallback".format(key, key)]
            output = self.config(lines=commands, parents=parents)
            test_msg = "Output: {}".format(output)
            return True, test_msg
        else:
            test_msg = "Key type {} not supported".format(key_type)
            return False, test_msg

    def get_interface_ip(self, interface):
        """
        :param interface: name
        :return: ipv4 & ipv6 address for the interface
        """
        pc_num = re.findall("[0-9]+", interface)[0]
        pc_interface = "Port-Channel{}".format(pc_num)
        command_ipv4 = "show interfaces {} | json".format(pc_interface)
        command_output_ipv4 = self.commands(commands=[command_ipv4])["stdout"][0]
        ipv4_address = command_output_ipv4["interfaces"][pc_interface]["interfaceAddress"][0]["primaryIp"]["address"]

        command_ipv6 = "show ipv6 interface {} | json".format(pc_interface)
        command_output_ipv6 = self.commands(commands=[command_ipv6])["stdout"][0]
        ipv6_address = command_output_ipv6["interfaces"][pc_interface]["addresses"][0]["address"]
        return ipv4_address, ipv6_address

    def get_macsec_config(self, interface):
        """
        :param interface: interface of device to capture profile name
        :return: interface config
        """
        try:
            command = "show running-config interfaces {} | include mac security ".format(interface)
            output = self.commands(commands=[command])
            """example of output:
            mac security profile macsec-profile-juniper-256-64CKN-64CAK-fallback
            """
            if not output["failed"]:
                # Returning only MACSEC config.
                for config in output["stdout_lines"][0]:
                    if "security" in config:
                        return True, "interface {} \n {}".format(interface, config)
            # if psk is not found return false
            return False, "Failed to get macsec config due to {}".format(output)
        except Exception as e:
            return False, "Failed to get macsec config due to {}".format(str(e))

    def apply_macsec_interface_config(self, commands):
        """
        :param commands: List command which need to execute on DTU.
        :return: boolean
        """
        try:
            parents = []
            list_command = []
            for line in commands:
                if "\n" in line:
                    line = line.split("\n")
                    parents.append(line[0])
                    list_command.append(line[1])
            if len(list_command) > 0:
                output = self.config(lines=commands, parents=parents)
                if not output["failed"]:
                    return True, output
                return False, "Failed to apply macsec interface config due to {}".format(output)
            return False, "Failed to apply macsec interface config due to no commmand available."
        except Exception as e:
            return False, "Failed to apply macsec interface config due to {}".format(str(e))

    def delete_macsec_interface_config(self, interface):
        """
        :param interface: remove MACSEC from physical interface
        :return: bool
        """
        try:
            parents = ["interface {}".format(interface)]
            commands = ["no mac security profile"]
            output = self.config(lines=commands, parents=parents)
            if not output["failed"]:
                return True, output
            return False, "Failed to delete macsec interface config due to {}".format(output)
        except Exception as e:
            return False, "Failed to delete macsec interface config due to {}".format(str(e))

    def get_macsec_interface_statistics(self, interface):
        """
        :param interface: interface of macsec
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        command = "show mac security counters interface {} detail | json".format(interface)
        try:
            json_output = self.commands(commands=[command])
            """json_output example:
            {
                "interfaces": {
                    "Ethernet3/35/1": {
                        "outPktsEncrypted": 118455438940,
                        "countersDetail": {
                            "inPktsUnchecked": 0,
                            "inPktsNotUsingSA": 0,
                            "inPktsNoTag": 0,
                            "inPktsNoSCI": 0,
                            "inPktsOK": 565345090,
                            "outPktCtrl": 118455791086,
                            "inPktsCtrl": 565651895,
                            "inPktsTagged": 0,
                            "inPktsBadTag": 0,
                            "outPktsUntagged": 352145,
                            "outPktsTooLong": 0,
                            "inPktsNotValid": 0,
                            "inPktsLate": 0
                        },
                        "outOctetsEncrypted": 39998450940134,
                        "inPktsDecrypted": 565345090,
                        "inOctetsDecrypted": 193046154738
                    }
                }
            }
            """
            if not json_output["failed"]:
                counter = json_output["stdout"][0]["interfaces"][interface]
                validated_bytes = counter["countersDetail"]["inPktsOK"]
                decrypted_bytes = counter["inPktsDecrypted"]
                if int(validated_bytes) == int(decrypted_bytes) and int(validated_bytes) > 0:
                    return (
                        True,
                        "validated-bytes {0} and decrypted-bytes {1} is the same on interface {2}".format(
                            validated_bytes, decrypted_bytes, interface
                        ),
                    )
                else:
                    return (
                        False,
                        "validated-bytes {0} and decrypted-bytes {1} is not the same on interface {2}".format(
                            validated_bytes, decrypted_bytes, interface
                        ),
                    )
            return False, "Failed to get macsec interface statistics due to {}".format(json_output)
        except Exception as e:
            return False, "Failed to get macsec interface statistics due to {}".format(str(e))

    def check_rsvp_nbr(self, neighbor):
        """
        :param neighbor: neighbor of rsvp
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        try:
            command = "show mpls rsvp neighbor {}".format(neighbor)
            output_list = self.commands(commands=[command])["stdout_lines"][0]
            for line in output_list:
                if neighbor in line:
                    return True, "RSVP neighor {0} is up".format(neighbor)
            else:
                return False, "RSVP neighor {0} is not found".format(neighbor)
        except Exception as e:
            return False, "Failed to get RSVP neighbor info due to {}".format(str(e))

    def get_loopback_ipv4_addr(self):
        """
        :return: loopback ipv4 addr string
        """
        try:
            command = "show running-config interfaces loopback 99"
            output = self.commands(commands=[command])
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if "ip address" in line:
                        lb_ipv4_addr = line.split()[-1].strip("/32")
                        return lb_ipv4_addr
            return "Failed to get loopback ipv4 address due to {}".format(output)
        except Exception as e:
            return "Failed to get loopback ipv4 address due to {}".format(str(e))

    def remove_int_from_portchan(self, interface, pcnum):
        """
        remove interface from interface ether-bundle
        :param interface: The interface name
        :param pcnum: portchannel number
        :return: boolean, message
        """
        try:
            command = ["no channel-group"]
            parents = ["interface {}".format(interface)]
            output = self.config(lines=command, parents=parents)
            if not output["failed"]:
                return True, "remove interface {} from ether-bundle {}".format(interface, pcnum)
            else:
                return False, "Failed to remove interface {} from ether-bundle {}".format(interface, pcnum)
        except Exception as e:
            return False, "Failed to remove interface {} from ether-bundle {} due to {}".format(
                interface, pcnum, str(e)
            )

    def put_int_in_portchan(self, interface, pcnum):
        """
        remove interface from channel-group
        :param interface: The interface name
        :param pcnum: channel-group number
        :return:  boolean, message
        """
        try:
            command = ["channel-group {} mode active".format(pcnum)]
            parents = ["interface {}".format(interface)]
            output = self.config(lines=command, parents=parents)
            if not output["failed"]:
                return True, "Added interface {} from channel-group  {}".format(interface, pcnum)
            else:
                return False, "Failed to add interface {} to channel-group {}".format(interface, pcnum)
        except Exception as e:
            return False, "Failed to add interface {} to channel-group {} due to {}".format(interface, pcnum, str(e))

    """
    TACACS
    """

    def run_configure_command_test(self):
        """
        This function is intend to test current account can get into config mode and do harmless config
        and confirm the account has priviliage to configure the router.
        """
        try:
            parents = []
            command = ["alias testversion show version"]
            output = self.config(lines=command, parents=parents)
            if not output["failed"]:
                rollback_command = "no alias testversion"
                self.config(lines=[rollback_command], parents=parents)
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to run configure command test due to {}".format(str(e))

    def apply_check_tacacs_config_and_rollback(self, prod_tacacsserver, tacacs_secret, accounting_secret, user, pwd):
        """
        :param prod_tacacsserver: production TACACS servers ip address
        :param tacacs_secret: TACACS secret key
        :param acccounting_secret: TACACS secret key
        :param source_address: lab router source IP address
        :param user: production username for tacacs test
        :param pwd: production password for tacacs test
        :return: Boolean, message

        This function pushes production TACACS configurations to the router.
        At the end it executes a "commit timer 00:02:00" command on the router.
        then, start another ssh session to run "show version" command on the router to test the prod tacacs server.
        After 120 seconds the router will automatically restore the original configurations.
        """
        prod_configs = ["configure session"]
        prod_configs.append("no tacacs-server host")
        prod_configs.append("no tacacs-server key")
        prod_configs.append("tacacs-server key 7 {}".format(tacacs_secret))
        prod_configs.append("tacacs-server host {}".format(prod_tacacsserver))
        prod_configs.append("commit timer 00:02:00")
        prod_configs.append("show tacacs")
        try:
            config_ssh_session = SSHClient()
            config_ssh_session.set_missing_host_key_policy(AutoAddPolicy())
            config_ssh_session.load_system_host_keys()
            config_ssh_session.connect(self.hostname, username=self.ansible_user, password=self.ansible_passwd)
            cli_shell = config_ssh_session.invoke_shell()
            for line in prod_configs:
                cli_shell.send(line + "\n")
            output = cli_shell.recv(1024).decode("utf-8")
            # wait for 20 seconds for tacacs connection
            time.sleep(20)
            # start 2nd ssh session to test prod tacacs server
            test_ssh_session = SSHClient()
            test_ssh_session.set_missing_host_key_policy(AutoAddPolicy())
            test_ssh_session.load_system_host_keys()
            test_ssh_session.connect(self.hostname, username=user, password=pwd)
            stdin, stdout, stderr = test_ssh_session.exec_command("show version")
            if not stderr.readlines():
                cli_shell.close()
                return True, stdout.readlines()
            else:
                return False, "Failed to apply/check tacacs configuration due to {}".format(output)
        except Exception as e:
            return False, "Failed to apply/check tacacs configuration due to {}".format(str(e))

    def check_for_aggregate_route_generation(self, agg_prefix):
        """
        :param agg_prefix: aggregate prefix
        :return: Boolean status of Aggregate prefix
        """
        try:
            command = "show ip route aggregate | include {}".format(agg_prefix)
            agg_route_gen_status = False
            output = self.commands(commands=[command])
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if agg_prefix in line:
                        agg_route_gen_status = True
                        break
            return agg_route_gen_status, output
        except Exception as e:
            return False, "Failed to verify the aggregate route {} due to {}".format(agg_prefix, str(e))

    def get_ipfix_export_data_count(self):
        try:
            packets_exported = 0
            command = "show flow tracking sampled counters | include messages"
            output = self.commands(commands=[command])
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if "messages" in line:
                        counter = line.split()[1].lstrip("(").rstrip(")")
                        packets_exported += int(counter)
            return packets_exported
        except Exception as e:
            return {"error": str(e)}

    def is_ipfix_exporting_data(self):
        first_time_packets_exported = self.get_ipfix_export_data_count()
        # wait for 30 seconds
        time.sleep(30)
        second_time_packets_exported = self.get_ipfix_export_data_count()
        if first_time_packets_exported == second_time_packets_exported:
            return False, "The total packets exported ipfix data are NOT increasing"
        else:
            return True, "The total packets exported ipfix data are increasing"

    def apply_sample_filter_to_interface(self, filter_name, interface):
        try:
            parents = ["interface {}".format(interface)]
            commands = ["flow tracker sampled {}".format(filter_name)]
            output = self.config(lines=commands, parents=parents)
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to apply sample filter to interface due to {}".format(str(e))

    def reboot_chassis(self):
        try:
            command = "reload all now"
            output = self.commands(commands=[command])
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to reboot the device {}. due to {}".format(self.hostname, str(e))
