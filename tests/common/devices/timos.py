import paramiko
import warnings
import time
import logging
from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)


class TimosHost(AnsibleHostBase):
    """
    @summary: Class for Nokia timos switch

    For running ansible module on the timos switch
    """
    warnings.filterwarnings(action='ignore', module='.*paramiko.*')
    warnings.filterwarnings(action='ignore', module='.*cryptography.*')

    def __init__(self, ansible_adhoc, hostname, user, passwd, gather_facts=False):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname, connection="network_cli")
        evars = {'ansible_connection': 'network_cli',
                 'ansible_network_os': 'timos',
                 'ansible_user': user,
                 'ansible_password': passwd
                 }

        self.host.options['variable_manager'].extra_vars.update(evars)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

        timos_host = self.host.options["inventory_manager"].get_host(hostname)
        timos_host_vars = timos_host.vars
        if 'ansible_host' in timos_host_vars:
            self.timos_mgmt_ip = timos_host_vars['ansible_host']
        self.timos_name = timos_host_vars['ansible_ssh_user']
        self.timos_passwd = timos_host_vars['ansible_ssh_pass']

    def shutdown(self, interface_name):
        timos_ssh = paramiko.SSHClient()
        timos_ssh.load_system_host_keys()
        timos_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        timos_ssh.connect(self.timos_mgmt_ip, port=22,
                          username=self.timos_name,
                          password=self.timos_passwd)
        timos_connection = timos_ssh.invoke_shell()
        time.sleep(2)
        cmd1 = ("configure port {} shutdown \n".format(interface_name))
        timos_connection.send(cmd1)
        time.sleep(2)
        timos_op = timos_connection.recv(5000)
        logging.info(' {}'.format(timos_op))
        timos_ssh.close()
        time.sleep(2)

    def no_shutdown(self, interface_name):
        timos_ssh = paramiko.SSHClient()
        timos_ssh.load_system_host_keys()
        timos_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        timos_ssh.connect(self.timos_mgmt_ip, port=22,
                          username=self.timos_name,
                          password=self.timos_passwd)
        timos_connection = timos_ssh.invoke_shell()
        time.sleep(2)
        cmd1 = ("configure port {} no shutdown \n".format(interface_name))
        timos_connection.send(cmd1)
        time.sleep(2)
        timos_op = timos_connection.recv(5000)
        logging.info(' {}'.format(timos_op))
        timos_ssh.close()
        time.sleep(2)

