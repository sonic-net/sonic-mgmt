import json
import logging

from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)


class OnyxHost(AnsibleHostBase):
    """
    @summary: Class for ONYX switch

    For running ansible module on the ONYX switch
    """

    def __init__(self, ansible_adhoc, hostname, user, passwd, gather_facts=False):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname, connection="network_cli")
        evars = {'ansible_connection':'network_cli',
                'ansible_network_os':'onyx',
                'ansible_user': user,
                'ansible_password': passwd,
                'ansible_ssh_user': user,
                'ansible_ssh_pass': passwd,
                'ansible_become_method': 'enable'
                }

        self.host.options['variable_manager'].extra_vars.update(evars)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

    def shutdown(self, interface_name):
        out = self.host.onyx_config(
            lines=['shutdown'],
            parents='interface %s' % interface_name)
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def no_shutdown(self, interface_name):
        out = self.host.onyx_config(
            lines=['no shutdown'],
            parents='interface %s' % interface_name)
        logging.info('No shut interface [%s]' % interface_name)
        return out

    def check_intf_link_state(self, interface_name):
        show_int_result = self.host.onyx_command(
            commands=['show interfaces ethernet {} | include "Operational state"'.format(interface_name)])[self.hostname]
        return 'Up' in show_int_result['stdout'][0]

    def command(self, cmd):
        out = self.host.onyx_command(commands=[cmd])
        return out

    def set_interface_lacp_rate_mode(self, interface_name, mode):
        out = self.host.onyx_config(
            lines=['lacp rate %s' % mode],
            parents='interface ethernet %s' % interface_name)
        logging.info("Set interface [%s] lacp rate to [%s]" % (interface_name, mode))
        return out

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        """
        Execute ansible playbook with specified parameters
        """
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} -l {fanout_host} --extra-vars \'{extra_vars}\' -vvvvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
            fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["localhost"]["stdout"]))
