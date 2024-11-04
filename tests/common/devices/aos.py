import json
import logging
import os

from tests.common.devices.base import AnsibleHostBase
import re


def _raise_err(msg):
    raise Exception(msg)


class AosHost(AnsibleHostBase):
    """
    @summary: Class for Accton switch
    For running ansible module on the Accton switch
    """

    def __init__(self, ansible_adhoc, hostname, user, passwd, gather_facts=False):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        self.hostname = hostname
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

        self.admin_conn_props = {
            'ansible_connection': 'network_cli',
            'ansible_network_os': 'aos',
            'ansible_become_method': 'enable',
            'ansible_user': user,
            'ansible_password': passwd
        }

    def _exec_jinja_template(self, task_name, jinja_template):
        inventory = 'lab'
        ansible_root = '../ansible/'
        playbook_name = 'accton_os_cmd_exec.yml'
        jinja_name = 'accton_os_cmd_exec.j2'
        playbook_text = '- hosts: {}\n'.format(self.hostname) + \
                        '  gather_facts: no\n\n' + \
                        '  tasks:\n' + \
                        '  - conn_graph_facts: host={{ inventory_hostname }}\n' + \
                        '    delegate_to: localhost\n' + \
                        '    tags: always\n\n' + \
                        '  - set_fact:\n' + \
                        '      peer_host: \"{{device_info[inventory_hostname][\'mgmtip\']}}\"\n' + \
                        '      peer_hwsku: \"{{device_info[inventory_hostname][\'HwSku\']}}\"\n\n' + \
                        '  - name: {}\n'.format(task_name) + \
                        '    action: apswitch template={}\n'.format(jinja_name) + \
                        '    args:\n' + \
                        '      host: \"{{peer_host}}\"\n' + \
                        '      login: \"{{switch_login[hwsku_map[peer_hwsku]]}}\"\n' + \
                        '      os_name: {}\n'.format('aos') + \
                        '    connection: switch\n'

        with open(ansible_root + jinja_name, 'w') as f:
            f.write(jinja_template)

        with open(ansible_root + playbook_name, 'w') as f:
            f.write(playbook_text)

        res = self.exec_template(ansible_root, playbook_name, inventory)

        os.system("rm {}".format(ansible_root + jinja_name))
        os.system("rm {}".format(ansible_root + playbook_name))

        return res

    def __str__(self):
        return '<AosHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()

    def shutdown(self, interface_name):
        out = self.aos_config(lines=['shutdown'], parents=['interface {}'.format(interface_name)])
        logging.info('Shut interface {}'.format(interface_name))
        return {self.hostname: out}

    def no_shutdown(self, interface_name):
        out = self.aos_config(lines=['no shutdown'], parents=['interface {}'.format(interface_name)])
        logging.info('No shut interface {}'.format(interface_name))
        return {self.hostname: out}

    def command(self, cmd):
        task_name = 'Execute command \'{}\''.format(cmd)
        out = self._exec_jinja_template(task_name, cmd)
        logging.info('Exec command: \'{}\''.format(cmd))
        return {self.hostname: out}

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        """
        Execute ansible playbook with specified parameters
        """
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} -l {fanout_host} \
                            --extra-vars \'{extra_vars}\' -vvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
                                           fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["localhost"]["stdout"]))

    # delegate AOS related commands to Ansible
    def __getattr__(self, module_name):
        if not module_name.startswith('aos_'):
            return None
        self.host.options['variable_manager'].extra_vars.update(self.admin_conn_props)
        return super(AosHost, self).__getattr__(module_name)

    def _has_cli_cmd_failed(self, cmd_output_obj):
        return 'failed' in cmd_output_obj and cmd_output_obj['failed']

    def cli_command(self, cmd):
        return self.aos_command(commands=[cmd])['stdout'][0]

    def get_auto_negotiation_mode(self, port):
        return self.get_speed(port) == 'Auto'

    def set_auto_negotiation_mode(self, port, enabled):
        if self.get_auto_negotiation_mode(port) == enabled:
            return True
        if enabled:
            out = self.aos_config(
                lines=['negotiation'],
                parents=['interface {}'.format(port)])
        else:
            out = self.aos_config(
                lines=['no negotiation'],
                parents=['interface {}'.format(port)])
        return not self._has_cli_cmd_failed(out)

    def get_speed(self, port):
        output = self.cli_command('show interfaces status {}'.format(port))

        found_txt = extract_val('Speed-duplex', output)
        if found_txt is None:
            _raise_err('Not able to extract interface %s speed from output: %s' % (port, output))

        return speed_gb_to_mb(found_txt)

    def get_supported_speeds(self, port):
        """Get supported speeds for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            list: A list of supported speed strings or None
        """
        output = self.cli_command('show interfaces status {}'.format(port))
        found_txt = extract_val('Capabilities', output)

        if found_txt is None:
            _raise_err('Failed to find port speeds list in output: %s' % output)

        speed_list = found_txt.split(',')
        return list(map(speed_gb_to_mb, speed_list))

    def set_speed(self, interface_name, speed):

        if not speed:
            # other set_speed implementations advertise port speeds when speed=None
            # but in AOS autoneg activation and speeds advertisement is done via a single CLI cmd
            # so this branch left nop intentionally
            return True
        speed = speed_mb_to_gb(speed)
        out = self.aos_config(
                lines=['speed {}'.format(speed)],
                parents='interface %s' % interface_name)
        return not self._has_cli_cmd_failed(out)

    def is_lldp_disabled(self):
        """
        TODO: Add support for AOS device when access to
        AOS fanout becomes available.

        Return False always. If AOS device is found as a
        fanout the pretest will fail until this check is implemented.
        """
        return False


def speed_gb_to_mb(speed):
    res = re.search(r'(\d+)(\w)', speed)
    if not res:
        return speed
    speed = res.groups()[0]
    return speed + '000'


def speed_mb_to_gb(val):
    return '{}Gfull'.format(int(val) // 1000)


def extract_val(prop_name, output):
    found_txt = re.search(r'{}\s+:\s+(.+)'.format(prop_name), output)
    return found_txt.groups()[0] if found_txt else None
