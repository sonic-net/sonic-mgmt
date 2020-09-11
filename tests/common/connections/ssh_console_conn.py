import time
import re
from base_console_conn import BaseConsoleConn
from netmiko.ssh_exception import NetMikoAuthenticationException

class SSHConsoleConn(BaseConsoleConn):
    def __init__(self, **kwargs):
        if not kwargs.has_key("console_server_username") \
                or not kwargs.has_key("console_server_password"):
            raise ValueError("Either console_server__username or console_server_password is not set")

        # Console via SSH connection need two groups of user/passwd
        self.sonic_username = kwargs['username']
        self.sonic_password = kwargs['password']
        console_username = kwargs['console_server_username'] + r':p=' + str(kwargs['port'])
        # Restore the default port for SSH
        del kwargs['port']
        kwargs['username'] = console_username
        kwargs['password'] = kwargs['console_server_password']
        kwargs['device_type'] = "_ssh"
        super(SSHConsoleConn, self).__init__(**kwargs)

    def session_preparation(self):
        self._test_channel_read()
        self.login_stage_2()
        self.set_base_prompt()
        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def login_stage_2(self,
                      pri_prompt_terminator=r".*# ",
                      alt_prompt_terminator=r".*\$ ",
                      username_pattern=r"(?:user:|username|login|user name)",
                      pwd_pattern=r"assword",
                      delay_factor=1,
                      max_loops=20,
                      ):
        """
        Perform a further login
        :return: None
        """
        """Telnet login. Can be username/password or just password."""
        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        i = 1
        while i <= max_loops:
            try:
                output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if re.search(username_pattern, output, flags=re.I):
                    self.write_channel(self.sonic_username + self.TELNET_RETURN)
                    time.sleep(1 * delay_factor)
                    output = self.read_channel()
                    return_msg += output

                # Search for password pattern / send password
                if re.search(pwd_pattern, output, flags=re.I):
                    self.write_channel(self.sonic_password + self.TELNET_RETURN)
                    time.sleep(0.5 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    if re.search(
                            pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                        alt_prompt_terminator, output, flags=re.M
                ):
                    return return_msg

                self.write_channel(self.TELNET_RETURN)
                time.sleep(0.5 * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise NetMikoAuthenticationException(msg)

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        self.remote_conn.close()
        msg = "Login failed: {}".format(self.host)
        raise NetMikoAuthenticationException(msg)

    def cleanup(self):
        # Send an exit to logout from SONiC
        self.send_command(command_string="exit",
                          expect_string="login:")
        # remote_conn must be closed, or the SSH session will be kept on Digi,
        # and any other login is prevented
        self.remote_conn.close()
        del self.remote_conn

