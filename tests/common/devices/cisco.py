import re
import os
import sys
import logging
import functools
import time
from paramiko import SSHClient, AutoAddPolicy
from tests.common.devices.base import AnsibleHostBase
from ansible.utils.unsafe_proxy import AnsibleUnsafeText

# If the version of the Python interpreter is greater or equal to 3, set the unicode variable to the str class.
if sys.version_info[0] >= 3:
    unicode = str

logger = logging.getLogger(__name__)

SAMPLE_COMMAND_DATA = '''
RP/0/RP0/CPU0:vlab-01#show operational LLDP NodeTable Node/NodeName/Rack=0;
Slot=0;Instance=CPU0 Neighbors DeviceTable Device/DeviceID=vlab-02/Interf$
Wed Aug 10 08:45:43.126 UTC
......
      "Operational": {
        "LLDP": {
          "@MajorVersion": "1",
          "@MinorVersion": "2",
          "NodeTable": {
            "Node": {
              "Naming": {
                "NodeName": {
                  "Rack": "0",
                  "Slot": "0",
                  "Instance": "CPU0"
                }
              },
              "Neighbors": {
                "DeviceTable": {
                  "Device": {
                    "Naming": {
                      "DeviceID": "vlab-02",
                      "InterfaceName": "GigabitEthernet0/0/0/1"
                    },
                    "Entry": {
                      "ReceivingInterfaceName": "GigabitEthernet0/0/0/1",
                      "ReceivingParentInterfaceName": "Bundle-Ether1",
                      "DeviceID": "vlab-02",
                      "ChassisID": "5254.0085.5c1c",
                      "PortIDDetail": "fortyGigE0/4",
                      "HeaderVersion": "0",
                      "HoldTime": "120",
                      "EnabledCapabilities": "B,R",
                      "Detail": {
......
'''


def adapt_interface_name(func):
    """Decorator to adapt interface name used in topology to cisco interface name."""
    @functools.wraps(func)
    def _decorated(self, *args):
        args_list = list(args)
        new_list = []
        for item in args_list:
            new_item = item
            if isinstance(new_item, str) or isinstance(new_item, unicode) or isinstance(new_item, AnsibleUnsafeText):
                if 'Ethernet' in new_item and 'GigabitEthernet' not in new_item:
                    new_item = re.sub(r'(^|\s)Ethernet', 'GigabitEthernet0/0/0/', new_item)
                elif 'Port-Channel' in new_item:
                    new_item = re.sub(r'(^|\s)Port-Channel', 'Bundle-Ether', new_item)
            new_list.append(new_item)
        new_args = tuple(new_list)
        return func(self, *new_args)
    return _decorated


class CiscoHost(AnsibleHostBase):
    """
    @summary: Class for Cisco host
    """
    def __init__(self, ansible_adhoc, hostname, ansible_user, ansible_passwd):
        '''Initialize an object for interacting with cisco device using ansible modules
        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the cisco device
            ansible_user (string): Username for accessing the cisco CLI interface
            ansible_passwd (string): Password for the ansible_user
        '''
        self.ansible_user = ansible_user
        self.ansible_passwd = ansible_passwd
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        # Reserved for execute ansible commands in local device
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

    def __getattr__(self, module_name):
        if module_name.startswith('iosxr_'):
            evars = {
                'ansible_connection': 'network_cli',
                'ansible_network_os': module_name.split('_', 1)[0],
                'ansible_user': self.ansible_user,
                'ansible_password': self.ansible_passwd,
                'ansible_ssh_user': self.ansible_user,
                'ansible_ssh_pass': self.ansible_passwd,
            }
        else:
            raise Exception("Does not have module: {}".format(module_name))
        self.host.options['variable_manager'].extra_vars.update(evars)
        return super(CiscoHost, self).__getattr__(module_name)

    def __str__(self):
        return '<CiscoHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()

    def commands(self, *args, **kwargs):
        return self.iosxr_command(*args, **kwargs)

    def config(self, *args, **kwargs):
        return self.iosxr_config(*args, **kwargs)

    @adapt_interface_name
    def shutdown(self, interface_name=None):
        out = self.config(
            lines=['shutdown'],
            parents=['interface {}'.format(interface_name)])
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def shutdown_multiple(self, interfaces):
        intf_str = ','.join(interfaces)
        return self.shutdown(interface_name=intf_str)

    @adapt_interface_name
    def no_shutdown(self, interface_name):
        out = self.config(
            lines=['no shutdown'],
            parents=['interface {}'.format(interface_name)])
        logging.info('No shut interface [%s]' % interface_name)
        return out

    def no_shutdown_multiple(self, interfaces):
        intf_str = ','.join(interfaces)
        return self.no_shutdown(intf_str)

    @adapt_interface_name
    def rm_member_from_channel_grp(self, interface_name, channel_group):
        out = self.config(
            lines=['no bundle id {} mode active'.format(channel_group)],
            parents=['interface {}'.format(interface_name)])
        logging.info('Rm interface {} from bundle-ethernet {}'.format(interface_name, channel_group))
        return out

    @adapt_interface_name
    def add_member_to_channel_grp(self, interface_name, channel_group):
        out = self.config(
            lines=['bundle id {} mode active'.format(channel_group)],
            parents=['interface {}'.format(interface_name)])
        logging.info('Add interface {} to bundle-ethernet {}'.format(interface_name, channel_group))
        return out

    @adapt_interface_name
    def check_intf_link_state(self, interface_name):
        show_int_result = self.commands(
            commands=['show interfaces %s' % interface_name])
        return 'line protocol is up' in show_int_result['stdout_lines'][0]

    @adapt_interface_name
    def set_interface_lacp_rate_mode(self, interface_name, mode):
        if mode == 'fast':
            command = 'lacp period short'
        else:
            command = 'no lacp period'

        out = self.config(
            lines=[command],
            parents='interface %s' % interface_name)
        return out

    def get_lldp_neighbor(self, local_iface=None, remote_device=None):
        try:
            if (local_iface is not None and remote_device is not None):
                command = 'show operational LLDP NodeTable ' \
                    'Node/NodeName/Rack=0;Slot=0;Instance=CPU0 Neighbors DeviceTable ' \
                    'Device/DeviceID={}/InterfaceName={} json'.format(local_iface, remote_device)
            else:
                command = 'show operational LLDP json'
            output = self.commands(
                    commands=[command],
                    module_ignore_errors=True)
            logger.debug('cisco lldp output: %s' % (output))
            return output['stdout_lines'][0]['Response']['Get']['Operational'] if output['failed'] is False else False
        except Exception as e:
            logger.error('command {} failed. exception: {}'.format(command, repr(e)))
        return False

    def config_key_chain(self, name, key):
        # create key chain
        output = self.config(
                lines=['key chain {} key 1'.format(name)])
        logger.debug('config key chain: %s' % (output))

        # configure key chain parameters
        output = self.config(
                lines=['accept-lifetime 00:00:00 december 01 2014 infinite',
                       'send-lifetime 00:00:00 december 01 2014 infinite',
                       'cryptographic-algorithm HMAC-MD5',
                       'key-string clear {}'.format(key)],
                parents=['key chain {} key 1'.format(name)])
        logger.debug('config key chain parameters: %s' % (output))

    def remove_key_chain(self, name):
        # remove key chain
        output = self.config(lines=['no key chain {}'.format(name)])
        logger.debug('remove key chain: %s' % (output))

    def isis_config_auth(self, key):
        key_chain_name = 'ISIS'
        self.config_key_chain(key_chain_name, key)

        # configure key chain to isis
        output = self.config(
                lines=['lsp-password keychain {} level 2'.format(key_chain_name),
                       'interface Bundle-Ether1 hello-password keychain {}'.format(key_chain_name)],
                parents=['router isis test'])
        logger.debug('config key chain to isis: %s' % (output))

    def isis_remove_auth(self, key):
        key_chain_name = 'ISIS'
        # remove key chain from isis
        output = self.config(
                lines=['no lsp-password keychain {} level 2'.format(key_chain_name),
                       'no interface Bundle-Ether1 hello-password keychain {}'.format(key_chain_name)],
                parents=['router isis test'])
        logger.debug('remove key chain from isis: %s' % (output))

        self.remove_key_chain(key_chain_name)

    def ping_dest(self, dest):
        try:
            command = 'ping {} count 5'.format(dest)
            output = self.commands(commands=[command])
            logger.debug('ping result: %s' % (output))
            return re.search('!!!!!', output['stdout'][0]) is not None if output['failed'] is False else False
        except Exception as e:
            logger.error('command {} failed. exception: {}'.format(command, repr(e)))
        return False

    def show_command_to_json(self, command, lookup_key=None, lookup_val=None):
        """
        This function will pull the show operational command output as json string and convert it json object and return
        """
        try:
            json_command = command + " json"
            output = self.commands(commands=[json_command])
            if all([lookup_key, lookup_val]):
                return self.extract_key_val_pair_from_json(output['stdout_lines'], lookup_key)
            elif lookup_key is not None and lookup_val is None:
                return self.extract_val_from_json(output['stdout_lines'], lookup_key)
            else:
                return output['stdout_lines']
        except Exception as e:
            return {"error": e}

    def extract_key_val_pair_from_json(self, data, lookup_key):
        """
        Function to recursivly match provided key in all levels and return list of same level data
        """
        result = []

        def help(data, lookup_key, result):
            if isinstance(data, dict):
                for k, v in list(data.items()):
                    if k == lookup_key:
                        result.append(data)
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
        help(data, lookup_key, result)
        return result

    def extract_val_from_json(self, json_data, lookup_key):
        """
        Function to recursivly match provided key in all levels and return matched key's value into a list
        """
        result = []

        def help(data, lookup_key, result):
            if isinstance(data, dict):
                for k, v in list(data.items()):
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

    def _has_cli_cmd_failed(self, cmd_output_obj):
        err_out = False
        if 'stdout' in cmd_output_obj:
            stdout = cmd_output_obj['stdout']
            msg = stdout[-1] if type(stdout) == list else stdout
            err_out = 'Cannot advertise' in msg

        return ('failed' in cmd_output_obj and cmd_output_obj['failed']) or err_out

    def load_configuration(self, config_file, backup_file=None):
        if backup_file is None:
            out = self.config(
                src=config_file,
                replace='config',
            )
        else:
            out = self.config(
                src=config_file,
                replace='line',
                backup='yes',
                backup_options={
                    'filename': os.path.basename(backup_file),
                    'dir_path': os.path.dirname(backup_file),
                }
            )
        return not self._has_cli_cmd_failed(out)

    @adapt_interface_name
    def get_portchannel_by_member(self, member_intf):
        try:
            command = 'show lacp {}'.format(member_intf)
            output = self.commands(commands=[command])['stdout'][0]
            regex_pc = re.compile(r'Bundle-Ether([0-9]+)', re.U)
            for line in [item.strip().rstrip() for item in output.splitlines()]:
                if regex_pc.match(line):
                    return re.sub('Bundle-Ether', 'Port-Channel', line)
        except Exception as e:
            logger.error('Failed to get PortChannel for member interface "{}", exception: {}'.format(
                        member_intf, repr(e)
                        ))
            return None

    @adapt_interface_name
    def no_isis_interface(self, isis_instance, interface):
        out = self.config(
            lines=['no interface {}'.format(interface)],
            parents=['router isis {}'.format(isis_instance)])
        return not self._has_cli_cmd_failed(out)

    @adapt_interface_name
    def set_isis_metric(self, interface, metric, isis_instance='test'):
        out = self.config(
            lines=['metric {}'.format(metric)],
            parents=['router isis {}'.format(isis_instance),
                     'interface {}'.format(interface),
                     'address-family ipv4 unicast'])
        return not self._has_cli_cmd_failed(out)

    @adapt_interface_name
    def no_isis_metric(self, interface, isis_instance='test'):
        out = self.config(
            lines=['no metric'],
            parents=['router isis {}'.format(isis_instance),
                     'interface {}'.format(interface),
                     'address-family ipv4 unicast'])
        return not self._has_cli_cmd_failed(out)

    def get_lldp_neighbors(self):
        """
        run show lldp neighbros command to get lldp neighbors
        """
        try:
            logger.info("Gathering LLDP details")
            lldp_details = {}
            command = "show lldp neighbors"
            output = self.commands(commands=[command], module_ignore_errors=True)
            header_line = "Device ID       Local Intf                      Hold-time  Capability      Port ID"
            end_line = "Total entries displayed:"
            content_idx = 0
            if not output['failed']:
                output = [line.strip() for line in output['stdout_lines'][0] if len(line) > 0]
                for idx, line in enumerate(output):
                    if end_line in line:
                        break
                    if header_line in line:
                        content_idx = idx
                    if content_idx != 0 and content_idx < idx:
                        line = re.split(r'\s+', line.strip())
                        lldp_details.update(
                            {line[1]: {'neighbor': line[0], 'local_interface': line[1], 'neighbor_interface': line[4]}}
                        )
                return lldp_details
            else:
                return "Falied to get lldp neighbors info due to {}".format(output)
        except Exception as e:
            return "Failed to get lldp neighbors info due to {}".format(str(e))

    def get_all_lldp_neighbor_details_for_port(self, physical_port):
        """
        :param physical_port:
        :return: complete lldp details for the port
        """
        try:
            command = "show lldp neigh {} detail".format(physical_port)
            output = self.commands(commands=[command], module_ignore_errors=True)
            if not output['failed']:
                logger.debug('cisco lldp output: %s' % (output))
                return output['stdout_lines'][0]
            return "Failed to get lldp detail info for {} due to {}".format(physical_port, output)
        except Exception as e:
            return "Failed to get lldp detail info due to {}".format(str(e))

    def get_platform_from_cli(self):
        """
        run show version command to get device platform info
        """
        try:
            command = "show version | i ^cisco | utility head -n 1"
            output = self.commands(commands=[command], module_ignore_errors=True)
            if not output['failed']:
                logger.debug('cisco lldp output: %s' % (output))
                return output['stdout_lines'][0][0].split()[1]
            return "Failed to get platform info due to {}".format(output)
        except Exception as e:
            return "Failed to get platform info due to {}".format(str(e))

    def get_version_from_cli(self):
        """
        run show version command to get device version info
        """
        try:
            command = 'show version | in "Version      :"'
            output = self.commands(commands=[command], module_ignore_errors=True)
            if not output['failed']:
                logger.debug('cisco lldp output: %s' % (output))
                return output['stdout'][0].split()[-1].strip()
            return "Failed to get version info due to {}".format(output)
        except Exception as e:
            return "Failed to get version info due to {}".format(str(e))

    def get_chassis_id_from_cli(self):
        """
        run show lldp command to get device chassis id via cli
        """
        try:
            command = "show lldp | i Chassis ID:"
            output = self.commands(commands=[command], module_ignore_errors=True)
            if not output['failed']:
                logger.debug('cisco lldp output: %s' % (output))
                return output['stdout_lines'][0][0].split()[-1]
            return "Failed to get chassis id info due to {}".format(output)
        except Exception as e:
            return "Failed to get chassis id info due to {}".format(str(e))

    def get_mgmt_ip_from_cli(self):
        """
        :return ip
        """
        try:
            # On Cisco devices, the management IP is the IP of the management interface on the RP that is not active
            # First, find which RP is the active one
            # Example output:
            """
            RP/0/RP0/CPU0:IBR02.STR01#show redundancy | i STANDBY
            Mon Apr 13 04:44:43.271 UTC
            Partner node (0/RP1/CPU0) is in STANDBY role
            """
            command = "show redundancy | i STANDBY"
            output = (
                self.commands(commands=[command], module_ignore_errors=True)["stdout_lines"][0][0].strip().splitlines()
            )
            standby_rp = output[-1].split("/")[1]

            # Get management IP of Standby RP
            # Example output:
            """
            RP/0/RP0/CPU0:IBR02.STR01#sh run formal interface MgmtEth 0/RP1/CPU0/0 ipv4 address
            Mon Apr 13 04:29:46.371 UTC
            interface MgmtEth0/RP1/CPU0/0 ipv4 address 10.3.151.104 255.255.255.0
            """
            command2 = "show run formal interface MgmtEth 0/" + standby_rp + "/CPU0/0 ipv4 address"
            output2 = (
                self.commands(commands=[command2], module_ignore_errors=True)["stdout_lines"][0][0]
                .strip()
                .splitlines()
            )
            ip = output2[-1].split(" ")[4]
            return ip
        except IndexError:
            command2 = "show ip interface brief | inc MANAGEMENT"
            output2 = (
                self.commands(commands=[command2], module_ignore_errors=True)["stdout_lines"][0][0]
                .strip()
                .splitlines()
            )
            ip = output2[-1].split()[1]
            return ip
        except Exception as error:
            return "Failed to get mgmt ip due to {}".format(str(error))

    def parse_lldp_peer_required_info(self, lldp_details=None):
        """
        :param lldp_details: Output of "show lldp neighbor interface detail"
        :return lldp_peer_info
        """
        # Initialize dictionary to return
        if "Total entries displayed: 0" in lldp_details:
            return None
        elif "Warning: " in str.join(" ", lldp_details):
            return None
        lldp_required_info = dict()

        # Get Chassis ID:
        chassis_dotted = re.findall("Chassis id: (.*)", str.join("\n", lldp_details))[0]
        chassis = self.convert_mac_to_standard_format(chassis_dotted)  # Convert to XX:XX:XX:XX:XX:XX format
        lldp_required_info["chassis_id"] = chassis

        # Get peer management IP:
        """
        Ignoring as we have issue with Cisco Management IP
        ip = re.findall("IPv4 address: (.*)", str.join("\n", lldp_details))[-1]
        lldp_required_info['ip'] = ip
        """

        # Get peer name:
        index = 0
        while "System Name:" not in lldp_details[index]:
            index += 1
        peer_name = lldp_details[index].split(":")[1].strip()
        peer_name = peer_name.replace(".str.msn.net", "")  # get rid of ".str.msn.net" if it exists
        lldp_required_info["name"] = peer_name.lower()

        # Get system description
        index = 0
        while "System Description:" not in lldp_details[index]:
            index += 1
        index += 1  # System description appears after the line that says: "System Description:"
        system_description = lldp_details[index]

        # From this description, extract platform:
        # Juniper output looks like: Juniper Networks, Inc. jnp10016 internet router, kernel JUNOS 18.2X75-D51.9 ...
        if "Juniper" in system_description:
            description_list = system_description.split(" ")
            platform = description_list[3]
        # Arista output looks like "Arista Networks EOS version 4.23.2.1F-DPE running on an Arista Networks DCS-7504"
        elif "Arista" in system_description:
            description_list = system_description.split()
            platform = description_list[-1]
        elif "NCS" in system_description:
            description_list = system_description.split(",")
            platform = description_list[-1].strip()
        elif "8000" in system_description:
            description_list = system_description.split(",")
            platform = description_list[-1].strip()
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
        # Arista output looks like "Arista Networks EOS version 4.23.2.1F-DPE running on an Arista Networks DCS-7504"
        elif "Arista" in system_description:
            regex = r"(?<=version ).*(?= running )"
            matches = re.search(regex, system_description, re.MULTILINE)
            version = matches.group()
        elif "NCS" in system_description:
            description_list = system_description.split(",")
            version = description_list[0].strip()
        elif "8000" in system_description:
            description_list = system_description.split(",")
            version = description_list[0].strip()
        lldp_required_info["version"] = version

        # Get the peer port ID
        peer_port = re.findall("Port id: (.*)", str.join("\n", lldp_details))[-1]
        lldp_required_info["port"] = self.elongate_cisco_interface(peer_port)

        return lldp_required_info

    def convert_interface_prefix(self, list_of_interfaces):
        """
        :param list_of_interfaces: List of interfaces which need to be updated for vendor naming convention
        :return converted_list_of_interfaces, converted list of interface names
        """
        converted_list_of_interfaces = []
        for interface in list_of_interfaces:
            converted_list_of_interfaces.append(interface.replace("HundredGigE", "Hu"))
        return converted_list_of_interfaces

    @staticmethod
    def convert_pc_to_be(pc_name):
        """
        :param pc_name: port-channel to be converted to Cisco BE format
        :return: BE formatted ie. portchannel5 returns Bundle-Ether5
        """
        pc_name = pc_name.lower()
        if "portchannel" in pc_name:
            pc_name = pc_name.replace("portchannel", "Bundle-Ether")
        elif "port-channel" in pc_name:
            pc_name = pc_name.replace("port-channel", "Bundle-Ether")
        return pc_name

    def get_all_interfaces_in_pc(self, pc_name):
        """
        :param pc_name: port-channel/ae used for this test
        :return interfaces: list of port channel member interfaces
        """
        # Convert PortChannel to Bundle-Ether
        try:
            pc_name = self.convert_pc_to_be(pc_name)
            command = "show lacp {} | begin eceive".format(pc_name)
            output = self.commands(commands=[command], module_ignore_errors=True)
            if not output["failed"]:
                logger.debug("cisco lldp output: %s" % (output))
                interface = [
                    self.elongate_cisco_interface(line.split()[0])
                    for line in output["stdout_lines"][0]
                    if "Current" in line
                ]
                return interface
            return "Failed to get chassis id info due to {}".format(output)
        except Exception as e:
            return "Failed to get chassis id info due to {}".format(str(e))

    def check_interface_status(self, interface):
        """
        :param
        interface: str - port number e.g. ae15, Port-channel15
        :return:
        is_up: boolean , True if interface is up
        intf_status_output: str - raw output of show interface OR error message
        """
        try:
            # Convert PortChannel to Bundle-Ether
            pc_name = self.convert_pc_to_be(interface)
            command = "show interfaces {}".format(pc_name)
            success_criteria = "line protocol is up"
            intf_status_output = self.commands(commands=[command], module_ignore_errors=True)
            if not intf_status_output["failed"]:
                logger.info("Interface status check: {} sent to {}".format(command, self.hostname))
                is_up = success_criteria in intf_status_output["stdout"][0].lower()
                return is_up, intf_status_output["stdout_lines"][0]
            return False, intf_status_output
        except Exception as e:
            msg = "Failed to execute command due to {}".format(str(e))
            logger.error(msg)
            return False, msg

    def get_isis_adjacency(self):
        """Method to gather isis adjacency details"""
        isis_details = {}
        try:
            logger.info("Gathering ISIS adjacency details")
            command = "show isis adjacency"
            output = self.commands(commands=[command], module_ignore_errors=True)
            if not output["failed"]:
                for row in output["stdout_lines"][0][3:-2]:
                    row = row.split()
                    isis_details[row[0]] = dict()
                    isis_details[row[0]]["neighbor"] = row[0]
                    isis_details[row[0]]["interface_name"] = row[1]
                    isis_details[row[0]]["state"] = row[3]
            return isis_details
        except Exception as e:
            err = "Failed to get isis for device: {}. Exception: {}".format(self.hostname, e)
            logger.exception(err)
            isis_details["Result"] = "Exception occurred while collecting isis adjacency information {}".format(err)
            return isis_details

    def check_isis_adjacency(self, neighbor_device, expected_adjacency_ports=1):
        """
        :param device_b: device adjacent to device_a
        :param expected_adjacency_ports: number of adjacencies between device a and device a
        :return: Boolean, List of adjacency information
        """
        adjacency = []
        isis_adj = self.get_isis_adjacency()
        for isis_neighbor in isis_adj:
            if isis_neighbor.lower() == neighbor_device and isis_adj[isis_neighbor]["state"] == "Up":
                adjacency.append(
                    "isis_adj[isis_neighbor]['interface_name']_{}_isis_adj[isis_neighbor]['state']".format(
                        isis_neighbor
                    )
                )
        if len(adjacency) == expected_adjacency_ports:
            return True, adjacency
        return False, adjacency

    def get_isis_database(self, queue=None):
        try:
            command = "show isis database"
            output = self.commands(commands=[command], module_ignore_errors=True)
            lsp_entries = {}
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if "*" in line:
                        outline = line.replace("*", "").split()
                        lsp_entries[outline[0].strip()] = {
                            "sequence-number": int(outline[1], base=16),
                            "checksum": int(outline[2], base=16),
                        }
                    elif "0x0" in line.lower():
                        outline = line.split()
                        lsp_entries[outline[0].strip()] = {
                            "sequence-number": int(outline[1], base=16),
                            "checksum": int(outline[2], base=16),
                        }
                if queue:
                    queue.put(lsp_entries)
                return lsp_entries
            return output
        except Exception as e:
            msg = "Failed to get isis database due to {}".format(str(e))
            logger.error(msg)
            return msg

    def get_bgp_status(self):
        """
        :return bgp session status
        """
        command = "show bgp summary | b Neighbor"
        try:
            output = self.commands(commands=[command], module_ignore_errors=True)
            bgp_status = {}
            if not output["failed"]:
                for line in output["stdout_lines"][0][1:]:
                    line = line.strip().split()
                    if line[-1].isdigit():
                        neighbor_status = "Established"
                    else:
                        neighbor_status = line[-1]
                    bgp_status[line[0]] = neighbor_status
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
            command = "show bgp neighbor {}".format(peer_ip)
            output = self.commands(commands=[command], module_ignore_errors=True)
            return output
        except Exception as e:
            return {"msg": "Failed to get bgp session details due to {}".format(str(e))}

    def get_bgp_session_status(self, peer_ip):
        """
        :param peer_ip:
        :return: bgp session status e.g. Established
        """
        bgp_peer_details = self.get_bgp_session_details(peer_ip)
        try:
            if not bgp_peer_details["failed"]:
                for line in bgp_peer_details["stdout_lines"][0]:
                    if "BGP state" in line:
                        bgp_session_status = line.strip().split()[3].strip(",")
                        break
                else:
                    bgp_session_status = "bgp session status not find"
                return bgp_session_status
            return "Failed to get bgp session status"
        except Exception as e:
            return "Failed to get bgp session status due to {}".format(str(e))

    def is_prefix_advertised_to_peer(self, prefix, peer_ip):
        """
        :param prefix:
        :param peer_ip:
        :return: Boolean status of whether prefix is advertised to the peer or not
        """
        try:
            command = "show bgp advertised neighbor {} summary | in {}".format(peer_ip, prefix)
            output = self.commands(commands=[command], module_ignore_errors=True)
            prefix_adv_status = False
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if prefix in line:
                        prefix_adv_status = True
                        break
            return prefix_adv_status, output
        except Exception as e:
            logger.error(str(e))
            return False, "Failed to check is prefix advertised to peer due to {}".format(str(e))

    """
    LDP
    """

    def get_ldp_oper_neighbor_ips(self):
        try:
            command = 'show mpls ldp neighbor | include "Peer LDP Identifier:|State:"'
            output = self.commands(commands=[command], module_ignore_errors=True)
            if not output["failed"]:
                ldp_op_list = []
                for idx in range(0, len(output["stdout_lines"][0]), 2):
                    line1 = output["stdout_lines"][0][idx]
                    line2 = output["stdout_lines"][0][idx + 1]
                    if "Peer LDP Identifier:" in line1 and "State: Oper" in line2:
                        ldp_neighbor_ip = line1.split(":")[1].strip()
                        ldp_op_list.append(ldp_neighbor_ip)
                if ldp_op_list:
                    return True, ldp_op_list
            return False, output
        except Exception as e:
            return False, "Failed to get ldp neighbors ip due to {}".format(str(e))

    def get_next_hop_physical_interface_list(self, destination_ip):
        try:
            destination_ip = destination_ip + "/32"
            command = "show route {} | include via".format(destination_ip)
            output = self.commands(commands=[command], module_ignore_errors=True)
            interface_list = []
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if "via" in line:
                        next_hop = line.split("via")[-1].strip()
                        if "Bundle-Ether" in next_hop:
                            physical_interfaces = self.get_all_interfaces_in_pc(next_hop)
                            interface_list += physical_interfaces
                        elif "TU." in next_hop:
                            physical_interfaces = self.get_egress_interface_for_lsp(next_hop)
                            interface_list += physical_interfaces
                        else:
                            interface_list.append(next_hop)
                if len(interface_list) > 0:
                    return interface_list
            return output
        except Exception as e:
            return "Failed to get next hop physical interface due to {}".format(str(e))

    def check_remote_ldp_sessions(self):
        """
        :param dut: The Device Under Test
        :return: boolean, message
        """
        # get a list of ldp neighbors marked as operational
        result, ldp_neighbor_ips = self.get_ldp_oper_neighbor_ips()
        if result:
            for neighbor_ip in ldp_neighbor_ips:
                ldp_next_hop_interface = self.get_next_hop_physical_interface_list(neighbor_ip)
                result, message = self.verify_core_path(ldp_next_hop_interface)
                if result:
                    return result, message
        return False, "Could not find an operational ldp session on {} traversing an IBR or OWR".format(self.hostname)

    def get_egress_interface_for_lsp(self, lsp_name):
        """
        :param dut: The Device Under Test
        :param ldp_op_list: list of ldp neighbors marked as operational
        :return: boolean, message
        """
        # for each operational ldp session check the route to get the next-hop
        try:
            command = "show mpls traffic-eng tunnels name {} | include Hop0".format(lsp_name)
            output = self.commands(commands=[command], module_ignore_errors=True)
            if not output["failed"]:
                list_of_interface = []
                for line in output["stdout_lines"][0]:
                    if "Hop0" in line:
                        next_hop_ip = line.split()[1]
                        list_of_interface = self.get_next_hop_physical_interface_list(next_hop_ip)
                if list_of_interface:
                    return list_of_interface
            return output
        except Exception as e:
            message = "Failed to get egress interface for lsp due to {}".format(str(e))
            logger.error(message)
            return message

    def verify_core_path(self, ldp_int_list):
        """
        :param dut: The Device Under Test
        :param ldp_int_list: list of next-hop interfaces for operational ldp sessions
        :return: boolean, message
        """
        # check each next-hop address and see if the neighbor is an IBR-cisco device
        lldp_details = self.get_lldp_neighbors()
        for interface in ldp_int_list:
            if interface in lldp_details:
                if (
                    "ibr" in lldp_details[interface]["neighbor"].lower()
                    or "owr" in lldp_details[interface]["neighbor"].lower()
                ):
                    return True, "The LDP has remote session traversing core path via {}".format(interface)
        message = "No interface traversing core path according to lldp details {}".format(lldp_details)
        return False, message

    """
    MACSEC
    """

    def get_macsec_connection_status_details(self, interface):
        """
        :param interface: interface of macsec adjacency
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        command = "show macsec mka session interface {} detail".format(interface)
        output = self.commands(commands=[command])["stdout"][0]
        split_out = output.split("MKA Detailed Status for MKA Session")
        if len(split_out) == 1:
            return False, "No session found on {}".format(interface)
        split_out = split_out[1:]

        dict_out = {"pre-shared-key": {}, "fallback-key": {}}

        if len(split_out) == 1:
            primary_out = split_out[0].splitlines()
            for line in primary_out:
                if "MKA Cipher Suite" in line:
                    dict_out["cipher-suite"] = line.split(":")[1].strip()
                elif "CAK Name (CKN)" in line:
                    dict_out["pre-shared-key"]["ckn"] = line.split(":")[1].strip()
                elif "Fallback Data:" in line:
                    dict_out["fallback-key"]["ckn"] = primary_out[primary_out.index(line) + 2].split(":")[1].strip()
                elif "MKA Policy Name" in line:
                    dict_out["name"] = line.split(":")[1].strip()
            return True, dict_out

        elif len(split_out) == 2:
            primary_out = split_out[0].splitlines()
            for line in primary_out:
                if "MKA Cipher Suite" in line:
                    dict_out["cipher-suite"] = line.split(":")[1].strip()
                elif "CAK Name (CKN)" in line:
                    dict_out["pre-shared-key"]["ckn"] = line.split(":")[1].strip()
                elif "MKA Policy Name" in line:
                    dict_out["name"] = line.split(":")[1].strip()

            fallback_out = split_out[1].splitlines()
            for line in fallback_out:
                if "CAK Name (CKN)" in line:
                    dict_out["fallback-key"]["ckn"] = line.split(":")[1].strip()
            return True, dict_out
        else:
            return False, dict_out

    def set_rekey_period(self, profile_name, rekey_period_value):
        """
        :param profile_name: policy to change rekey value on
        :param rekey_period_value: value to set rekey in seconds, value range between 60 and 2592000
        :return: boolean, output from rekey implementation
        """
        try:
            command = "macsec-policy {} sak-rekey-interval seconds {}".format(profile_name, rekey_period_value)
            output = self.config(lines=[command])
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to set rekey period due to {}".format(str(e))

    def get_macsec_profile(self, interface):
        """
        :param interface: interface of device to capture profile name
        :return: profile name
        """
        try:
            command = "show run int {} macsec psk-keychain".format(interface)
            output = self.commands(commands=[command])
            """example of output:

            Thu Feb  6 16:32:34.297 UTC
            interface HundredGigE0/2/0/11
            macsec psk-keychain ptx10k-64hexCAK fallback-psk-keychain ptx10k-64hexCAK-fallback policy macsec-xpn-256
            !
            """
            if not output["failed"]:
                return True, output['stdout_lines'][0][1].split()[-1].strip()
            return False, output
        except Exception as e:
            return False, "Failed to get_macsec_profile due to {}".format(str(e))

    def get_macsec_status_logs(self, interface, last_count="30", log_type="ESTABLISHED"):
        """
        :param interface: interface of macsec adjacency
        :param log_type: ESTABLISHED, FAILURE, ROLLOVER
        :param last_count: optional field to capture number of logs
        :return: boolean, output from logs
        """
        try:
            interface = self.convert_interface_prefix([interface])
            if log_type == "ESTABLISHED":
                log_type = "established"
            elif log_type == "FAILURE":
                log_type = "MACSEC_CIPHER_MISMATCH"
            elif log_type == "ROLLOVER":
                return True, "log {} not supported on device {}".format(log_type, self.hostname)
            command = "show logging last {} | include {} | include {}".format(last_count, log_type, interface)
            output = self.commands(commands=[command])["stdout"][0]
            if not output["failed"]:
                return len(output["stdout_lines"][0]) > 0, output["stdout"][0]
            return False, str(output)
        except Exception as e:
            return False, str(e)

    def get_key_name(self, interface, key_type):
        """
        :param interface:
        :param key_type:
        :return: string of key name
        """
        if key_type == "primary":
            command = "show run int {} macsec psk-keychain".format(interface)
            output = self.commands(commands=[command])["stdout_lines"][0]
            """example of output:

            Thu Feb  6 16:32:34.297 UTC
            interface HundredGigE0/2/0/11
            macsec psk-keychain ptx10k-64hexCAK fallback-psk-keychain ptx10k-64hexCAK-fallback policy macsec-xpn-256
            !
            """
            return output[1].split()[2]
        if key_type == "fallback":
            command = "show run int {} macsec psk-keychain".format(interface)
            output = self.commands(commands=[command])["stdout_lines"][0]
            """example of output:

            Thu Feb  6 16:32:34.297 UTC
            interface HundredGigE0/2/0/11
            macsec psk-keychain ptx10k-64hexCAK fallback-psk-keychain ptx10k-64hexCAK-fallback policy macsec-xpn-256
            !
            """
            return output[1].split()[4]
        else:
            return "unsupported key_type"

    def get_macsec_key_lifetime(self, key_name):
        """
        :param string of key chain name:
        :return: string of CKN from the key chain name
        """
        command = "show running-config forma key chain {} macsec".format(key_name)
        output = self.commands(commands=[command])["stdout_lines"][0]
        for line in output:
            if "lifetime" in line:
                return line.split(" ", 7)[-1]
        else:
            return "macsec key lifetime not find"

    def set_macsec_key(self, profile_name, key, key_type, interface):
        """
        :param profile_name: macsec profile name used for key
        :param key: string key to apply
        :param key_type: fallback or primary
        :param interface: interface of macsec session
        :return: boolean and test_msg string
        """
        key_name = self.get_key_name(interface, key_type)
        lifetime = self.get_macsec_key_lifetime(key_name)
        if lifetime != "macsec key lifetime not find":
            commands = [
                "no key chain {}".format(key_name),
                "key chain {} macsec key {} key-string {} cryptographic-algorithm aes-256-cmac".format(
                    key_name, key, key
                ),
                "key chain {} macsec key {} lifetime {}".format(key_name, key, lifetime),
            ]
        else:
            commands = [
                "no key chain {}".format(key_name),
                "key chain {} macsec key {} key-string {} cryptographic-algorithm aes-256-cmac".format(
                    key_name, key, key
                ),
            ]
        if key_name != "unsupported key_type":
            output = self.config(lines=commands)
            test_msg = "Output: {}".format(output)
            return True, test_msg
        else:
            test_msg = "Key type {} not supported".format(key_type)
            return False, test_msg

    def get_macsec_config(self, interface):
        """
        :param interface: interface of device to capture profile name
        :return: interface config
        """
        try:
            command = "show running-config formal interface {} macsec psk-keychain".format(interface)
            output = self.commands(commands=[command])
            # Returning only MACSEC config.
            if not output["failed"]:
                for config in output["stdout_lines"][0]:
                    if "psk" in config:
                        return True, config
            # if psk is not found return false
            return False, output
        except Exception as e:
            return False, "Failed to get macsec config due to {}".format(str(e))

    def apply_macsec_interface_config(self, commands):
        """
        :param commands: List command which need to execute on DTU.
        :return: boolean
        """
        try:
            output = self.config(lines=commands)
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to apply macsec interface config due to {}".format(str(e))

    def delete_macsec_interface_config(self, interface):
        """
        :param interface: remove MACSEC from physical interface
        :return: bool
        """
        try:
            command = "no interface {} macsec ".format(interface)
            output = self.config(lines=command)
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to delete macsec interface config due to {}".format(str(e))

    """
    RSVP
    """

    def check_rsvp_nbr(self, neighbor):
        """
        :param neighbor: neighbor of rsvp
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        try:
            command = "show rsvp neighbors | include Global"
            output = self.commands(commands=[command])["stdout_lines"][0]
            """
            Sample output
            RP/0/RP0/CPU0:IBR02.STR01#show rsvp neighbors | include Global
            Wed Jul 15 14:50:28.721 UTC
            Global Neighbor: 10.3.151.95
            Global Neighbor: 10.3.151.163
            """
            for line in output:
                if neighbor in line:
                    return True, "RSVP neighbor {} is up".format(neighbor)
            else:
                return False, "RSVP neighbor {} is down".format(neighbor)
        except Exception as e:
            return False, "Failed to get RSVP neighbor status due to {}".format(str(e))

    def get_loopback_ipv4_addr(self):
        """
        :return: boolean, failure message or str
        """
        loopback_ip = "0.0.0.0"
        command = "sho running-config formal interface Loopback 99"
        output_list = self.commands(commands=[command])["stdout_lines"][0]
        for line in output_list:
            if "ipv4" in line:
                loopback_ip = line.split()[4]
                break
        return loopback_ip

    def remove_int_from_portchan(self, interface, pcnum):
        """
        remove interface from interface ether-bundle
        :param interface: The interface name
        :param pcnum: portchannel number
        :return: boolean, message
        """
        try:
            command = ["no bundle id"]
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
        remove interface from ether-bundle
        :param interface: The interface name
        :param pcnum: portchannel number
        :return:  boolean, message
        """
        try:
            command = ["interface {} bundle id {} mode active".format(interface, pcnum)]
            output = self.config(lines=command)
            if not output["failed"]:
                return True, "Added interface {} from ether-bundle {}".format(interface, pcnum)
            else:
                return False, "Failed to add interface {} from ether-bundle {}".format(interface, pcnum)
        except Exception as e:
            return False, "Failed to add interface {} from ether-bundle {} due to {}".format(interface, pcnum, str(e))

    """
    TACACS
    """

    def run_configure_command_test(self):
        """
        This function is intend to test current account can get into config mode and do harmless config
        and confirm the account has priviliage to configure the router.
        """
        try:
            command = ["alias testversion show version"]
            output = self.config(lines=command)
            if not output["failed"]:
                rollback_command = ["no alias testversion"]
                self.config(lines=rollback_command)
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
        At the end it executes a "commit confirmed 120" command on the router.
        then, start another ssh session to run "show version" command on the router to test the prod tacacs server.
        After 120 seconds the router will automatically restore the original configurations.
        """
        try:
            prod_configs = ["configure exclusive"]
            prod_configs.append("no aaa group server tacacs+ TACACS-DEFAULT ")
            prod_configs.append("aaa group server tacacs+ TACACS-DEFAULT ")
            prod_configs.append("aaa group server tacacs+ TACACS-DEFAULT vrf MANAGEMENT")
            prod_configs.append(
                "aaa group server tacacs+ TACACS-DEFAULT server-private {} port 49 key 7 {}".format(
                    prod_tacacsserver, tacacs_secret
                )
            )
            prod_configs.append("commit confirmed 120")
            config_ssh_session = SSHClient()
            config_ssh_session.set_missing_host_key_policy(AutoAddPolicy())
            config_ssh_session.load_system_host_keys()
            config_ssh_session.connect(self.hostname, username=self.ansible_user, password=self.ansible_passwd)
            cli_shell = config_ssh_session.invoke_shell()
            for line in prod_configs:
                cli_shell.send(line + "\n")
            output = cli_shell.recv(1024).decode("utf-8")
            if "Failed to commit" not in output:
                time.sleep(20)
                test_ssh_session = SSHClient()
                test_ssh_session.set_missing_host_key_policy(AutoAddPolicy())
                test_ssh_session.load_system_host_keys()
                test_ssh_session.connect(self.hostname, username=user, password=pwd)
                stdin, stdout, stderr = test_ssh_session.exec_command("show version")
                if not stderr.readlines():
                    cli_shell.close()
                    test_ssh_session.close()
                    return True, stdout.readlines()
            else:
                return False, output
        except Exception as e:
            msg = "Failed to apply/check tacacs configuration due to {}".format(str(e))
            return False, msg

    def check_for_aggregate_route_generation(self, agg_prefix):
        """
        :param agg_prefix: aggregate prefix
        :return: Boolean status of Aggregate prefix
        """
        try:
            command = "show route | include {}".format(agg_prefix)
            agg_route_gen_status = False
            output = self.commands(commands=[command])
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if agg_prefix in line:
                        agg_route_gen_status = True
                        break
            return agg_route_gen_status, output["stdout_lines"][0]
        except Exception as e:
            return False, "Failed to verify the aggregate route due to {}".format(str(e))

    def get_list_of_location(self):
        command = "show platform | include NSHUT | include CPU | exclude RP"
        output = self.commands(commands=[command])
        location_list = []
        if not output["failed"]:
            for line in output["stdout_lines"][0]:
                if "CPU" in line:
                    location_list.append(line.split()[0])
        return location_list

    def get_ipfix_export_data_count(self, location):
        try:
            packets_exported = 0
            command = 'show flow exporter IPFIX_MSAZ location {} | include "Packets exported:"'.format(location)
            output = self.commands(commands=[command])
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if "Packets exported:" in line:
                        packets_exported += int(line.split()[2])
            return packets_exported
        except Exception as e:
            return {"error": str(e)}

    def is_ipfix_exporting_data(self):
        try:
            location_list = self.get_list_of_location()
            first_time_packets_exported = 0
            second_time_packets_exported = 0
            for location in location_list:
                location_counter = self.get_ipfix_export_data_count(location)
                first_time_packets_exported += location_counter
            # wait for 30 seconds
            time.sleep(30)
            for location in location_list:
                location_counter = self.get_ipfix_export_data_count(location)
                second_time_packets_exported += location_counter
            if first_time_packets_exported == second_time_packets_exported:
                return False, "The total packets exported ipfix data are NOT increasing"
            else:
                return True, "The total packets exported ipfix data are increasing"
        except Exception as e:
            return False, "Failed to check is ipfix exporting data due to {}".format(str(e))

    def apply_sample_filter_to_interface(self, filter_name, interface):
        try:
            command = "interface {} flow ipv4 monitor {}_IPV4 sampler {}_SM ingress".format(
                interface, filter_name, filter_name
            )
            output = self.config(lines=[command])
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to apply sample filter to interface due to {}".format(str(e))

    def reboot_chassis(self):
        try:
            command = "admin hw-module location all reload noprompt"
            output = self.commands(commands=[command])
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to reboot the device {}. due to {}".format(self.hostname, str(e))
