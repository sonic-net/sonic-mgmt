import json
import logging


class AosHost():
    """
    @summary: Class for Accton switch
    For running ansible module on the Accton switch
    """

    def __init__(self, ansible_adhoc, hostname, user, passwd, gather_facts=False):
        self.hostname = hostname
        self.user = user
        self.passwd = passwd
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

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

    def shutdown(self, interface_name):
        task_name = 'Shutdown interface {}'.format(interface_name)
        template = 'configure\n' + \
                   '    interface {}\n'.format(interface_name) + \
                   '    shutdown\n' + \
                   '    exit\n' + \
                   'exit\n' + \
                   'exit\n'
        out = self._exec_jinja_template(task_name, template)
        logging.info('Shut interface {}'.format(interface_name))
        return {self.hostname : out }

    def no_shutdown(self, interface_name):
        task_name = 'No shutdown interface {}'.format(interface_name)
        template = 'configure\n' + \
                   '    interface {}\n'.format(interface_name) + \
                   '    no shutdown\n' + \
                   '    exit\n' + \
                   'exit\n' + \
                   'exit\n'
        out = self._exec_jinja_template(task_name, template)
        logging.info('No shut interface {}'.format(interface_name))
        return {self.hostname : out }

    def command(self, cmd):
        task_name = 'Execute command \'{}\''.format(cmd)
        out = self._exec_jinja_template(task_name, cmd)
        logging.info('Exec command: \'{}\''.format(cmd))
        return {self.hostname : out }

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        """
        Execute ansible playbook with specified parameters
        """
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} -l {fanout_host} --extra-vars \'{extra_vars}\' -vvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
            fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["localhost"]["stdout"]))
