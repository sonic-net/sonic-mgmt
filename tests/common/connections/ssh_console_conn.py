import time
import re
from base_console_conn import BaseConsoleConn, CONSOLE_SSH
from netmiko.ssh_exception import NetMikoAuthenticationException

class SSHConsoleConn(BaseConsoleConn):
    def __init__(self, **kwargs):
        if not kwargs.has_key("console_username") \
                or not kwargs.has_key("console_password"):
            raise ValueError("Either console_username or console_password is not set")

        # Console via SSH connection need two groups of user/passwd
        self.sonic_username = kwargs['sonic_username']
        self.sonic_password = kwargs['sonic_password']

        if kwargs['console_type'] == CONSOLE_SSH:
            kwargs['username'] = kwargs['console_username'] + r':' + str(kwargs['console_port'])
            self.menu_port = None
        else:
            kwargs['username'] = kwargs['console_username']
            self.menu_port = kwargs['console_port']
        kwargs['password'] = kwargs['console_password']
        kwargs['host'] = kwargs['console_host']
        kwargs['device_type'] = "_ssh"
        super(SSHConsoleConn, self).__init__(**kwargs)

    def session_preparation(self):
        self._test_channel_read()
        if (self.menu_port):
            # For devices logining via menu port, 2 additional login are needed
            # Since we have attempted all passwords in __init__ of base class until successful login
            # So self.username and self.password must be the correct ones
            self.login_stage_2(username=self.username,
                                password=self.password,
                                menu_port=self.menu_port,
                                pri_prompt_terminator=r".*login")
        # Attempt all sonic password
        for i in range(0, len(self.sonic_password)):
            password = self.sonic_password[i]
            try:
                self.login_stage_2(username=self.sonic_username,
                                password=password)
            except NetMikoAuthenticationException as e:
                if i == len(self.sonic_password) - 1:
                    raise e
            else:
                break

        self.set_base_prompt()
        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def login_stage_2(self,
                      username,
                      password,
                      menu_port=None,
                      pri_prompt_terminator=r".*# ",
                      alt_prompt_terminator=r".*\$ ",
                      username_pattern=r"(?:user:|username|login|user name)",
                      pwd_pattern=r"assword",
                      delay_factor=1,
                      max_loops=20
                      ):
        """
        Perform a stage_2 login
        """
        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        i = 1
        menu_port_sent = False
        user_sent = False
        password_sent = False
        # The following prompt is only for SONiC
        # Need to add more login failure prompt for other system
        login_failure_prompt = r".*incorrect"
        while i <= max_loops:
            try:
                if menu_port and not menu_port_sent:
                    self.write_and_poll("menu ports", "Selection:")
                    self.write_channel(str(self.menu_port) + self.RETURN)
                    menu_port_sent = True

                output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if not user_sent and re.search(username_pattern, output, flags=re.I):
                    self.write_channel(username + self.RETURN)
                    time.sleep(1 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    user_sent = True

                # Search for password pattern / send password
                if user_sent and not password_sent and re.search(pwd_pattern, output, flags=re.I):
                    self.write_channel(password + self.RETURN)
                    time.sleep(0.5 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    password_sent = True
                    if re.search(
                            pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                        alt_prompt_terminator, output, flags=re.M
                ):
                    return return_msg

                # Check if login failed
                if re.search(login_failure_prompt, output, flags=re.M):
                    # Wait a short time or the next login will be refused
                    time.sleep(1 * delay_factor)
                    msg = "Login failed: {}".format(self.host)
                    raise NetMikoAuthenticationException(msg)

                self.write_channel(self.RETURN)
                time.sleep(0.5 * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise NetMikoAuthenticationException(msg)

        # Last try to see if we already logged in
        self.write_channel(self.RETURN)
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

