"""
Base class for console connection of SONiC devices
"""

import logging
from netmiko.cisco_base_connection import CiscoBaseConnection

class BaseConsoleConn(CiscoBaseConnection):

    def __init__(self, **kwargs):
        self.logger = logging.getLogger(__name__)
        if kwargs.has_key('console_server_username'):
            del kwargs['console_server_username']
        if kwargs.has_key('console_server_password'):
            del kwargs['console_server_password']
        if kwargs.has_key('console_server_port'):
            del kwargs['console_server_port']
        super(BaseConsoleConn, self).__init__(**kwargs)

    def set_base_prompt(self, pri_prompt_terminator='#',
                        alt_prompt_terminator='$', delay_factor=1):
        return super(BaseConsoleConn, self).set_base_prompt(
            pri_prompt_terminator=pri_prompt_terminator,
            alt_prompt_terminator=alt_prompt_terminator,
            delay_factor=delay_factor)

    def disable_paging(self, command="", delay_factor=1):
        # not supported
        pass

    def find_prompt(self, delay_factor=1):
        return super(BaseConsoleConn, self).find_prompt(delay_factor)

    def clear_buffer(self):
        # todo
        super(BaseConsoleConn, self).clear_buffer()

    def enable(self):
        # not support config mode for now
        pass

    def config_mode(self):
        # not support config mode for now
        pass

    def exit_config_mode(self, exit_config, pattern):
        # not support config mode for now
        pass

    def cleanup(self):
        super(BaseConsoleConn, self).cleanup()

    def disconnect(self):
        super(BaseConsoleConn, self).disconnect()

