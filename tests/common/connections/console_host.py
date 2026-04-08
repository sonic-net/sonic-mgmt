from .base_console_conn import (
    CONSOLE_SSH,
    CONSOLE_SSH_CISCO_CONFIG,
    CONSOLE_SSH_MENU_PORTS,
    CONSOLE_TELNET,
    CONSOLE_SSH_DIGI_CONFIG,
    CONSOLE_SSH_SONIC_CONFIG,
    CONSOLE_CONSERVER
)
from .telnet_console_conn import TelnetConsoleConn
from .ssh_console_conn import SSHConsoleConn
from .conserver_console_conn import ConserverConsoleConn
from .linecard_console_conn import LinecardConsoleConn

CONSOLE_LINECARD = "console_linecard"

ConsoleTypeMapper = {
    CONSOLE_TELNET: TelnetConsoleConn,
    CONSOLE_SSH: SSHConsoleConn,
    CONSOLE_SSH_MENU_PORTS: SSHConsoleConn,
    CONSOLE_SSH_DIGI_CONFIG: SSHConsoleConn,
    CONSOLE_SSH_SONIC_CONFIG: SSHConsoleConn,
    CONSOLE_SSH_CISCO_CONFIG: SSHConsoleConn,
    CONSOLE_CONSERVER: ConserverConsoleConn,
    CONSOLE_LINECARD: LinecardConsoleConn
}


def ConsoleHost(console_type,
                console_host,
                console_port,
                sonic_username,
                sonic_password,
                console_username=None,
                console_password=None,
                console_device=None,
                timeout_s=100,
                supervisor_ip=None,
                linecard_number=None,
                slot_num=None,
                hwsku=None):
    if console_type not in ConsoleTypeMapper:
        raise ValueError("console type {} is not supported yet".format(console_type))
    params = {
        "console_host": console_host,
        "console_port": console_port,
        "console_type": console_type,
        "sonic_username": sonic_username,
        "sonic_password": sonic_password,
        "console_username": console_username,
        "console_password": console_password,
        "console_device": console_device,
        "timeout": timeout_s
    }

    # Add linecard-specific parameters if provided
    if supervisor_ip is not None:
        params["supervisor_ip"] = supervisor_ip
    if linecard_number is not None:
        params["linecard_number"] = linecard_number
    if slot_num is not None:
        params["slot_num"] = slot_num
    if hwsku is not None:
        params["hwsku"] = hwsku

    return ConsoleTypeMapper[console_type](**params)
