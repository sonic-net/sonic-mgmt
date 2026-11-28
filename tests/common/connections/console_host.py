import logging

from .base_console_conn import (
    CONSOLE_SSH,
    CONSOLE_SSH_CISCO_CONFIG,
    CONSOLE_SSH_MENU_PORTS,
    CONSOLE_SSH_TO_PORT,
    CONSOLE_TELNET,
    CONSOLE_SSH_DIGI_CONFIG,
    CONSOLE_SSH_SONIC_CONFIG,
    CONSOLE_CONSERVER,
    CONSOLE_SSH_RARITAN_CONFIG,
)
from .telnet_console_conn import TelnetConsoleConn
from .ssh_console_conn import SSHConsoleConn
from .conserver_console_conn import ConserverConsoleConn
from .linecard_console_conn import LinecardConsoleConn

CONSOLE_LINECARD = "console_linecard"

logger = logging.getLogger(__name__)

ConsoleTypeMapper = {
    CONSOLE_TELNET: TelnetConsoleConn,
    CONSOLE_SSH: SSHConsoleConn,
    CONSOLE_SSH_MENU_PORTS: SSHConsoleConn,
    CONSOLE_SSH_TO_PORT: SSHConsoleConn,
    CONSOLE_SSH_DIGI_CONFIG: SSHConsoleConn,
    CONSOLE_SSH_SONIC_CONFIG: SSHConsoleConn,
    CONSOLE_SSH_CISCO_CONFIG: SSHConsoleConn,
    CONSOLE_CONSERVER: ConserverConsoleConn,
    CONSOLE_LINECARD: LinecardConsoleConn,
    CONSOLE_SSH_RARITAN_CONFIG: SSHConsoleConn,
}


def ConsoleHost(console_type,
                sonic_username,
                sonic_password,
                timeout_s=None,
                console_host=None,
                console_port=None,
                console_username=None,
                console_password=None,
                console_direct_ssh_port=None,
                console_device=None,
                supervisor_ip=None,
                slot_num=None,
                hwsku=None,
                attach_only=False):
    """Connect to a device console.

    Args:
        console_type: how the console is reached, a key of ConsoleTypeMapper.
        sonic_username: DUT login user; None when not logging in (attach_only, console-server config types).
        sonic_password: list of DUT passwords, tried in order (conserver and linecard use the first).
        timeout_s: seconds allowed to connect; a connect still running then is cut without writing to the
            line. None for no limit.
        console_host: the console server's address (SSH and telnet types).
        console_port: the DUT's port on the console server; how it is used depends on console_type.
        console_username: console server login user (SSH types).
        console_password: list of console server passwords, tried in order (SSH types).
        console_direct_ssh_port: the SSH port that reaches the DUT's line directly (console_ssh_to_port only).
        console_device: the conserver "host:name" of the DUT console (conserver only).
        supervisor_ip: address of the supervisor whose serial port reaches the linecard (linecard only).
        slot_num: the linecard's slot, e.g. "slot3" (linecard only).
        hwsku: the chassis HwSKU; only Arista is supported (linecard only).
        attach_only: attach to the DUT's line without logging in or writing to it (SSH and telnet only).

    Returns:
        The connection, or None if timeout_s is given and the connect times out. Other failures raise.

    Raises:
        ValueError: console_type is not supported, or attach_only is given for a type without it.
    """
    if console_type not in ConsoleTypeMapper:
        raise ValueError("console type {} is not supported yet".format(console_type))
    if attach_only and not issubclass(ConsoleTypeMapper[console_type], (SSHConsoleConn, TelnetConsoleConn)):
        raise ValueError("attach_only is not supported for console type {}".format(console_type))
    params = {
        "console_host": console_host,
        "console_port": console_port,
        "console_type": console_type,
        "sonic_username": sonic_username,
        "sonic_password": sonic_password,
        "console_username": console_username,
        "console_password": console_password,
        "console_device": console_device,
        "timeout_s": timeout_s,
    }

    if attach_only:
        params["attach_only"] = True

    # Add linecard-specific parameters if provided
    if supervisor_ip is not None:
        params["supervisor_ip"] = supervisor_ip
    if slot_num is not None:
        params["slot_num"] = slot_num
    if hwsku is not None:
        params["hwsku"] = hwsku
    if console_direct_ssh_port is not None:
        params["direct_ssh_port"] = console_direct_ssh_port

    try:
        return ConsoleTypeMapper[console_type](**params)
    except TimeoutError:
        # Every console class's connect timeout is a TimeoutError. Without timeout_s, raise as before.
        if timeout_s is None:
            raise
        logger.warning("%s console did not connect within %s s", console_type, timeout_s)
        return None
