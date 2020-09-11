from base_console_conn import BaseConsoleConn

class TelnetConsoleConn(BaseConsoleConn):
    def __init__(self, **kwargs):
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
        return super(TelnetConsoleConn, self).telnet_login(pri_prompt_terminator,
                                                           alt_prompt_terminator,
                                                           username_pattern,
                                                           pwd_pattern,
                                                           delay_factor,
                                                           max_loops)

