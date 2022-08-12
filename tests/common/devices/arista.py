import re
import logging
from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)

SAMPLE_COMMAND_DATA = ''' vlab-04#show lldp neighbors | json 
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
} '''


class AristaHost(AnsibleHostBase):
    """
    @summary: Class for Arista host
    """
    def __init__(self, ansible_adhoc, hostname, ansible_user, ansible_passwd):
        '''Initialize an object for interacting with arista device using ansible modules
        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the arista device
            ansible_user (string): Username for accessing the arista CLI interface
            ansible_passwd (string): Password for the ansible_user
        '''
        self.ansible_user = ansible_user
        self.ansible_passwd = ansible_passwd
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        # Reserved for execute ansible commands in local device
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

    def __getattr__(self, module_name):
        if module_name.startswith('eos_'):
            evars = {
                'ansible_connection':'network_cli',
                'ansible_network_os':module_name.split('_', 1)[0],
                'ansible_ssh_user': self.ansible_user,
                'ansible_ssh_pass': self.ansible_passwd,
                'ansible_become_method': 'enable'
            }
        else:
            raise Exception("Does not have module: {}".format(module_name))
        self.host.options['variable_manager'].extra_vars.update(evars)
        return super(AristaHost, self).__getattr__(module_name)

    def __str__(self):
        return '<AristaHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()

    def commands(self, *args, **kwargs):
        return self.eos_command(*args, **kwargs)

    def config(self, *args, **kwargs):
        return self.eos_config(*args, **kwargs)

    def get_lldp_neighbor(self, local_iface=None):
        try:
            if local_iface is not None:
                match = re.match('Ethernet(\d+)', local_iface)
            if match:
                command = 'show lldp neighbors Ethernet {} | json'.format(match.group(1))
            else:
                command = 'show lldp neighbors | json'
            output = self.commands(commands=[command])
            return output['stdout_lines'][0] if output['failed'] is False else False
        except Exception as e:
            logger.error('command {} failed. exception: {}'.format(command, repr(e)))
        return False

    def isis_config_auth(self, key):
        # configure lsp authentication key
        output = self.config(
                lines=['authentication mode md5',
                        'authentication key {} level-2'.format(key)],
                parents=['router isis test1'])
        logger.debug('configure lsp authentication key: %s' % (output))

        # configure hello authentication key
        output = self.config(
                lines=['isis authentication mode md5',
                        'isis authentication key {} level-2'.format(key)],
                parents=['interface Port-Channel2'])
        logger.debug('configure hello authentication key: %s' % (output))

    def isis_remove_auth(self, key):
        # remove lsp authentication key
        output = self.config(
                lines=['no authentication mode md5',
                        'no authentication key {} level-2'.format(key)],
                parents=['router isis test1'])
        logger.debug('remove lsp authentication key: %s' % (output))

        # remove hello authentication key
        output = self.config(
                lines=['no isis authentication mode md5',
                        'no isis authentication key {} level-2'.format(key)],
                parents=['interface Port-Channel2'])
        logger.debug('remove hello authentication key: %s' % (output))

    def show_command_to_json(self, command, lookup_key=None, lookup_val=None):
        try:
            json_command = command + " | json"
            output = self.commands(commands=[json_command])
            if all([lookup_key, lookup_val]):
                return self.extract_key_val_pair_from_json(output['stdout_lines'], lookup_key, lookup_val)
            elif lookup_key is not None and lookup_val is None:
                return self.extract_val_from_json(output['stdout_lines'], lookup_key)
            else:
                return output['stdout_lines']
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
        Function to recursivly match provided key in all levels and put the matched key and value pair into a list for return
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

    def config_command(self, command):
        """
        This function try to load command/s into the device from config mode
        """
        try:
            #one line string command
            if isinstance(command, str):
                self.config(lines=[command])
            #list of one line string commands
            elif isinstance(command, list):
                self.config(lines=command)
            return (True, "The command {} loaded into device {}".format(command, self.hostname))
        except Exception as e:
            return (False, e)