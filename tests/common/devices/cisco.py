import re
import time
import logging
from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)

SAMPLE_COMMAND_DATA = '''
RP/0/RP0/CPU0:vlab-01#show operational LLDP NodeTable Node/NodeName/Rack=0;Slot=0;Instance=CPU0 Neighbors DeviceTable Device/DeviceID=vlab-02/Interf$
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
                        "PeerMACAddress": "5254.0012.3456", 
                        "PortDescription": "vlab-01:fortyGigE0/4", 
                        "SystemName": "vlab-02", 
                        "SystemDescription": "SONiC Software Version: SONiC.HEAD.361-dirty-20220105.010103 - HwSku: soda-crystalnet - Distribution: Debian 10.11 - Kernel: 4.19.0-12-2-amd64", 
                        "TimeRemaining": "98", 
                        "SystemCapabilities": "B,W,R,S", 
                        "EnabledCapabilities": "B,R", 
                        "NetworkAddresses": {
                          "Entry": {
                            "Address": {
                              "AddressType": "IPv4", 
                              "IPv4Address": "10.250.0.113"
......
'''

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
                'ansible_connection':'network_cli',
                'ansible_network_os':module_name.split('_', 1)[0],
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

    def get_lldp_neighbor(self, local_iface=None, remote_device=None):
        try:
            if (local_iface is not None and remote_device is not None):
                command = 'show operational LLDP NodeTable ' \
                    'Node/NodeName/Rack=0;Slot=0;Instance=CPU0 Neighbors DeviceTable ' \
                    'Device/DeviceID={}/InterfaceName={} json'.format(local_iface, remote_device)
            else:
                command = 'show operational LLDP json'
            output = self.commands(commands=[command], module_ignore_errors=True)
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
            return re.search('!!!!!', output['stdout'][0]) != None if output['failed'] is False else False
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
                for k, v in data.items():
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

    def cisco_xr_commit_config(self):
        #commit cisco config
        self.config(lines=['commit confirm 60'])
        time.sleep(40)
        self.config(lines=['commit'])

    def config_command(self, command):
        """
        This function try to load and commit command/s into the device from config mode, only support IOS XR only. 
        """
        try:
            if isinstance(command, str):
                self.config(lines=[command])
            #list of one line string commands
            elif isinstance(command, list):
                self.config(lines=command)
            self.cisco_xr_commit_config()
            return (True, "The command {} loaded into device {}".format(command, self.hostname))
        except Exception as e:
            return (False, e)