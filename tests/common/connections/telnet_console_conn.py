import time
import re
from base_console_conn import BaseConsoleConn
from netmiko.ssh_exception import NetMikoAuthenticationException

class TelnetConsoleConn(BaseConsoleConn):
    def __init__(self, **kwargs):
        # For telnet console, neither console username or password is needed
        # so we assign sonic_username/sonic_password to username/password
        kwargs['host'] = kwargs['console_host']
        kwargs['port'] = kwargs['console_port']
        # Don't set the value of password here because we will loop
        # among all passwords in __init__ 
        kwargs['username'] = kwargs['sonic_username']
        kwargs['console_username'] = kwargs['sonic_username']
        kwargs['console_password'] = kwargs['sonic_password']
        kwargs['device_type'] = "_telnet"
        super(TelnetConsoleConn, self).__init__(**kwargs)

    def session_preparation(self):
        super(TelnetConsoleConn, self).session_preparation()

    def telnet_login(
        self,
        pri_prompt_terminator=r".*# ",
        alt_prompt_terminator=r".*\$ ",
        username_pattern=r"(?:user:|username|login|user name)",
        pwd_pattern=r"assword",
        delay_factor=1,
        max_loops=20,
    ):
        """Telnet login. Can be username/password or just password."""
        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        login_failure_prompt = r".*incorrect"
        username_sent = False
        password_sent = False
        i = 1
        while i <= max_loops:
            try:
                output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if not username_sent and re.search(username_pattern, output, flags=re.I):
                    self.write_channel(self.username + self.TELNET_RETURN)
                    username_sent = True
                    time.sleep(1 * delay_factor)
                    output = self.read_channel()
                    return_msg = output

                # Search for password pattern / send password
                if username_sent and not password_sent and re.search(pwd_pattern, output, flags=re.I):
                    self.write_channel(self.password + self.TELNET_RETURN)
                    time.sleep(0.5 * delay_factor)
                    password_sent = True
                    output = self.read_channel()
                    return_msg += output
                    if re.search(
                        pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Support direct telnet through terminal server
                if re.search(r"initial configuration dialog\? \[yes/no\]: ", output):
                    self.write_channel("no" + self.TELNET_RETURN)
                    time.sleep(0.5 * delay_factor)
                    count = 0
                    while count < 15:
                        output = self.read_channel()
                        return_msg += output
                        if re.search(r"ress RETURN to get started", output):
                            output = ""
                            break
                        time.sleep(2 * delay_factor)
                        count += 1

                # Check for device with no password configured
                if re.search(r"assword required, but none set", output):
                    self.remote_conn.close()
                    msg = "Login failed - Password required, but none set: {}".format(
                        self.host
                    )
                    raise NetMikoAuthenticationException(msg)
                
                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                    alt_prompt_terminator, return_msg, flags=re.M
                ):
                    return return_msg
                
                #  Check if login failed
                if re.search(login_failure_prompt, output, flags=re.M):
                    self.remote_conn.close()
                    # Wait a short time or the next login will be refused
                    time.sleep(1 * delay_factor)
                    msg = "Login failed: {} password: {}".format(self.host, self.password)
                    raise NetMikoAuthenticationException(msg)

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

