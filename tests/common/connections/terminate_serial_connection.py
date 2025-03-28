import telnetlib
from tests.common.cisco_data import is_cisco_device


def terminate_occupied_serial_connection(duthost, creds: dict, console_host: str, console_port: int) -> bool:
    """
    Terminates a occupied serial connection on a device.

    This function serves as a placeholder for other SONiC vendors to add their own
    implementations. Different vendors may use different methods for terminating
    serial connections, such as Telnet, Minicom, etc.

    Args:
        duthost: The device under test instance.
        creds (dict): A dictionary containing credentials.
        console_host (str): The hostname or IP address of the console server.
        console_port (int): The Telnet port number on the console server.

    Returns:
        bool: True if the serial connection was terminated successfully, False otherwise.
    """
    if is_cisco_device(duthost):
        return cisco_telnet_kill_session(console_host, console_port, creds)
    else:
        return False


def cisco_telnet_kill_session(host: str, port: int, creds: dict) -> bool:
    """
    Terminates a Telnet session on a Cisco device.

    This function connects to a Cisco device using Telnet, enters enable mode, and
    terminates the specified Telnet session by sending the appropriate command.

    Args:
        host (str): The Telnet server IP address.
        port (int): The Telnet port number.
        creds (dict): A dictionary containing credentials.

    Returns:
        bool: True if the Telnet session was terminated successfully, False otherwise.
    """
    password = creds.get("console_login", {}).get("console_telnet", {}).get("server_password", [None])[0]

    if password is None or port is None or host is None:
        return False

    # Assuming the line number is derived from the last digit of the telnet port
    line_number = port % 100

    try:
        with telnetlib.Telnet(host) as tn:
            # Wait for the initial prompt and send the password
            tn.read_until(b"Password: ")
            tn.write(password.encode("ascii") + b"\n")

            # Enter enable mode
            tn.read_until(b">")
            tn.write(b"enable\n")
            tn.read_until(b"Password: ")
            tn.write(password.encode("ascii") + b"\n")

            # Clear the specified line
            tn.read_until(b"#")
            command = f"clear line {line_number}\n"
            tn.write(command.encode("ascii"))

            # Handle the confirmation prompt
            tn.read_until(b"[confirm]")
            tn.write(b"\n")

            # Wait for the OK message
            tn.read_until(b"[OK]")

            # Close the connection
            tn.write(b"exit\n")
        return True
    except (EOFError, OSError):
        return False
