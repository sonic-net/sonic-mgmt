from telnet_console_conn import TelnetConsoleConn
from ssh_console_conn import SSHConsoleConn

__all__ = ["TelnetConsoleConn", "SSHConsoleConn"]

ConsoleTypeMapper = {
    "mad_console": TelnetConsoleConn,
    "digi_console": SSHConsoleConn
}

def ConsoleHost(console_type,
                console_host,
                console_port,
                sonic_username,
                sonic_password,
                console_server_username=None,
                console_server_password=None,
                timeout_s=100):
    if not ConsoleTypeMapper.has_key(console_type):
        raise ValueError("console type {} is not supported yet".format(console_type))
    params = {
        "host": console_host,
        "port": console_port,
        "username": sonic_username,
        "password": sonic_password,
        "console_server_username": console_server_username,
        "console_server_password": console_server_password,
        "timeout": timeout_s
    }
    return ConsoleTypeMapper[console_type](**params)

