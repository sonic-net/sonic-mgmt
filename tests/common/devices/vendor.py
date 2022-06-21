
import paramiko
import time
import re

class Cli(object):
    # unit: second
    SSH_CMD_TIMEOUT = 10

    def __init__(self, hostaddr, shell_user, shell_passwd, timeout=None):
        self.hostaddr = hostaddr
        self.shell_user = shell_user
        self.shell_passwd = shell_passwd
        self.timeout = Cli.SSH_CMD_TIMEOUT if timeout is None else timeout

    def __del__(self):
        self.disconnect()

    def connect(self):
        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.conn.connect(hostname=self.hostaddr, username=self.shell_user, password=self.shell_passwd, allow_agent=False, look_for_keys=False)
        self.shell = self.conn.invoke_shell()
        # avoid paramiko Channel.recv() stuck forever
        self.shell.settimeout(self.timeout)
        # add a reference to avoid garbage collecting destructs the ssh connection
        #self.shell.keep_this = self.conn

    def disconnect(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        return

    def command(self, cmd, prompt):
        if cmd is not None:
            self.shell.send(cmd + '\n')
            time.sleep(0.2)

        result = self.receive(prompt)
        return result

    def receive(self, prompt):
        input_buffer = ''
        start_time = time.time()
        received_all_data = False

        while not received_all_data:
            recv_ready_timeout = (time.time() - start_time) >= self.timeout
            # if pipe is empty and not timeout yet, keep waiting
            should_wait = (not recv_ready_timeout) and (not self.shell.recv_ready())
            if should_wait:
                time.sleep(0.5)
                continue

            try:
                input_buffer += self.shell.recv(16384)
            except Exception as err:
                msg = 'Receive ssh command result error: msg={} type={}'.format(err, type(err))
                return msg

            # Received a prompt or a single 'exit' is considered as received all data
            received_all_data = (re.search(prompt, input_buffer) is not None) \
                                or \
                                (input_buffer.replace('\n', '').replace('\r', '').strip().lower() == 'exit')

        return input_buffer


class VendorHost(object):
    """
    @summary: Class for Vendor host
    """
    def __init__(self, hostname, hostaddr, shell_user, shell_passwd):
        '''Initialize an object for interacting with EoS type device using ansible modules

        Args:
            hostname (string): hostname of the Vendor device
            hostaddr (string): ip address of Vendor device
            shell_user (string): Username for accessing the Vendor Linux shell CLI interface
            shell_passwd (string): Password for the shell_user.
        '''
        self.hostname = hostname
        self.hostaddr = hostaddr
        self.shell_user = shell_user
        self.shell_passwd = shell_passwd
        self._connected = False

    def __del__(self):
        self.disconnect()

    @property
    def connected(self):
        return self._connected

    def get_prompt(self, first_prompt, init_prompt):
        lines = first_prompt.split('\n')
        prompt = lines[-1]
        # match all modes - A#, A(config)#, A(config-if)#
        return prompt.strip().replace(init_prompt, '.*#')

    def disconnect(self):
        if self.connected:
            self.cli.disconnect()
            self._connected = False
    
    def command(self, cmd):
        if not self.connected:
            self.connect()
        return self.cli.command(cmd, self.prompt)

    def __str__(self):
        return '<VendorHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()
    
    def connect(self, prompt):
        self.cli = Cli(self.hostaddr, self.shell_user, self.shell_passwd)
        self.cli.connect()
        self._connected = True

        first_prompt = self.cli.command(None, prompt)
        self.prompt = self.get_prompt(first_prompt, prompt)

    def enter_config_mode(self):
        self.command("""
                    end
                    configure
                    """)

    def exit_config_mode(self):
        self.command("end")
