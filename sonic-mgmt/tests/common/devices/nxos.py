import ipaddress
import json
import logging

from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)


class NxosHost(AnsibleHostBase):
    """
    #added by achekuri
    """
    def __init__(self, ansible_adhoc, hostname, nxos_user, nxos_passwd, shell_user=None, shell_passwd=None, gather_facts=False):

        '''Initialize an object for interacting with NxoS type device using ansible modules

        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the NXOS device
            nxos_user (string): Username for accessing the EOS CLI interface
            nxos_passwd (string): Password for the nxos_user
            shell_user (string, optional): Username for accessing the Linux shell CLI interface. Defaults to None.
            shell_passwd (string, optional): Password for the shell_user. Defaults to None.
            gather_facts (bool, optional): Whether to gather some basic facts. Defaults to False.
        '''
        self.nxos_user = nxos_user
        self.nxos_passwd = nxos_passwd
        self.shell_user = shell_user
        self.shell_passwd = shell_passwd
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

    def __getattr__(self, module_name):
        if module_name.startswith('nxos_'):
            evars = {
                'ansible_connection':'network_cli',
                'ansible_network_os':'nxos',
                'ansible_user': self.nxos_user,
                'ansible_password': self.nxos_passwd,
                'ansible_ssh_user': self.nxos_user,
                'ansible_ssh_pass': self.nxos_passwd,
                'ansible_become_method': 'enable'
            }
        else:
            if not self.shell_user or not self.shell_passwd:
                raise Exception("Please specify shell_user and shell_passwd for {}".format(self.hostname))
            evars = {
                'ansible_connection':'ssh',
                'ansible_network_os':'linux',
                'ansible_user': self.shell_user,
                'ansible_password': self.shell_passwd,
                'ansible_ssh_user': self.shell_user,
                'ansible_ssh_pass': self.shell_passwd,
                'ansible_become_method': 'sudo',
                'ansible_become_user': 'admin'
            }
        self.host.options['variable_manager'].extra_vars.update(evars)
        return super(NxosHost, self).__getattr__(module_name)

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} -l {fanout_host} --extra-vars \'{extra_vars}\' -vvvvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
            fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["stdout"]))

    def get_auto_negotiation_mode(self, interface_name):
        output = self.nxos_command(commands=[{
            'command': 'show interfaces %s status' % interface_name,
            'output': 'json'
        }])
        if self._has_cli_cmd_failed(output):
            _raise_err('Failed to get auto neg state for {}: {}'.format(interface_name, output['msg']))
        autoneg_enabled = output['stdout'][0]['TABLE_interface']['ROW_interface'].get('autonegotiation', False)
        return autoneg_enabled

    def shutdown(self, interface_name):
        out = self.nxos_config(
            lines=['shutdown'],
            parents='interface %s' % interface_name)
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def no_shutdown(self, interface_name):
        out = self.nxos_config(
            lines=['no shutdown'],
            parents='interface %s' % interface_name)
        logging.info('No shut interface [%s]' % interface_name)
        return out
    
    def shutdown_multiple(self, interfaces):
        ret_list = []
        for intf in interfaces:
            ret_list.append(self.shutdown(intf))
        return ret_list
    
    def no_shutdown_multiple(self, interfaces):
        ret_list = []
        for intf in interfaces:
            ret_list.append(self.no_shutdown(intf))
        return ret_list
