import logging
import paramiko
import time
import re


logger = logging.getLogger(__name__)


class L1SwitchHost(object):
    """
    @summary: Class for L1 Switch

    For running commands on the L1 switch via ansible. Each port on the L1 switch consists of two uni-directional ports,
    one representing a Tx Port with E, and one representing a Rx Port with W. There are also two sections: namely A
    and B. As an example, port 1 on the L1 switch in section A will have two uni-directional ports, 1AE and 1AW.
    The 1AE port is the Tx port, and the 1AW port is the Rx port.
    """

    def __init__(self, hostname, user, passwd, device_type="W2W ROME"):
        self.hostname = hostname
        self.type = device_type
        self.user = user
        self.passwd = passwd
        self.connections = {}
        self.client = None

    def __getattr__(self, module_name):
        return getattr(self.host, module_name)

    def get_l1_switch_type(self):
        return self.type

    def shutdown(self, port_name, direction="bi-directional"):
        """
        Shuts down the given port, both directions or tx or rx based on direction.

        Args:
            port_name (str): Name of the port to shutdown ex. "14"
            direction (str): Direction of the port to shutdown, either "bi-directional", "tx" or "rx"
        Returns:
            None
        """
        if direction == "bi-directional":
            commands = ["port set 1AE{} oper_status disable".format(port_name),
                        "port set 1AW{} oper_status disable".format(port_name)]
        elif direction == "tx":
            commands = ["port set 1AE{} oper_status disable".format(port_name)]
        elif direction == "rx":
            commands = ["port set 1AW{} oper_status disable".format(port_name)]

        for command in commands:
            self.execute_command(command)
            time.sleep(2)

    def startup(self, port_name, direction="bi-directional"):
        """
        Starts up the given port, oth directions or tx or rx based on direction.

        Args:
            port_name (str): Name of the port to startup ex. "14"
            direction (str): Direction of the port to startup, either "bi-directional", "tx" or "rx"
        Returns:
            None
        """
        if direction == "bi-directional":
            commands = ["port set 1AE{} oper_status enable".format(port_name),
                        "port set 1AW{} oper_status enable".format(port_name)]
        elif direction == "tx":
            commands = ["port set 1AE{} oper_status enable".format(port_name)]
        elif direction == "rx":
            commands = ["port set 1AW{} oper_status enable".format(port_name)]

        for command in commands:
            self.execute_command(command)
            time.sleep(2)

    def get_connected_ports(self):
        """
        Gets all the connected ports in dict form on the switch.

        Args:
            None
        Returns:
            connected_ports (dict): key value pair of connected ports
        """
        _, stdout, stderr = self.execute_command("connection show connected")
        if stderr:
            return None
        else:
            out = stdout.read().decode().splitlines()
            for i in range(8, len(out) - 1):
                result = re.search(r"\((\w+,\w+)\)-\((\w+,\w+)\)", out[i])
                if result:
                    port1, port2 = self.extract_port_pair(result.group(0))
                    if port1 is None or port2 is None:
                        continue
                    self.connections[port1] = port2
                    self.connections[port2] = port1

        return self.connections

    def create_connection(self, ports):
        """
        Creates a bi-directional connection between the two given ports.

        Args:
            ports (list): List of tuple of ports to connect ex. [(1, 2), (3, 4)]
        Returns:
            None
        """
        for port in ports:
            commands = ["connection create 1AE{} to 1AW{}".format(port[0], port[1]),
                        "connection create 1AE{} to 1AW{}".format(port[1], port[0])]

            port1_E = "1AE{}".format(port[0])
            port1_W = "1AW{}".format(port[0])
            port2_E = "1AE{}".format(port[1])
            port2_W = "1AW{}".format(port[1])

            for command in commands:
                self.execute_command(command)
                time.sleep(20)

            self.connections[port1_E] = port2_W
            self.connections[port1_W] = port2_E
            self.connections[port2_E] = port1_W
            self.connections[port2_W] = port1_E

    def remove_connection(self, ports):
        """
        Removes the bi-directional connection between the two given ports.

        Args:
            ports (list): List of tuple of ports to remove ex. [(1, 2), (3, 4)]
        Returns:
            None
        """
        for port in ports:
            commands = ["connection disconnect 1AE{} from 1AW{}".format(port[0], port[1]),
                        "connection disconnect 1AE{} from 1AW{}".format(port[1], port[0])]

            port1_E = "1AE{}".format(port[0])
            port1_W = "1AW{}".format(port[0])
            port2_E = "1AE{}".format(port[1])
            port2_W = "1AW{}".format(port[1])

            port_mappings = [port1_E, port1_W, port2_E, port2_W]

            for command in commands:
                self.execute_command(command)
                time.sleep(20)

            for port_mapping in port_mappings:
                try:
                    self.connections.pop(port_mapping)
                except KeyError:
                    pass

    def __str__(self):
        return "{ L1 Switch - hostname: '%s', device_type: '%s' }" % (self.hostname, self.type)

    def __repr__(self):
        return self.__str__()

    def setup_SSH_connection(self):
        """
        Set up the SSH client with the L1 switch credentials

        Args:
            None
        Returns:
            client (paramiko.SSHClient): SSH client object
        """
        if self.hostname is None or self.user is None and self.passwd is None:
            raise Exception("Hostname, user and password must be set before connecting to the device")

        client = paramiko.SSHClient()

        # add to known hosts - but show warning if not found
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            client.connect(hostname=self.hostname, username=self.user, password=self.passwd,
                           disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]), look_for_keys=False)
        except paramiko.ssh_exception.IncompatiblePeer:
            logging.info("[!] Incompatible SSH peer")
            return None
        except paramiko.ssh_exception.ChannelException as e:
            logging.info("[!] Channel Exception")
            print(e)
            return None
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            logging.info("[!] No valid connection")
            logging.info(e)
            return None
        except:  # noqa: E722
            logging.info("[!] Cannot connect to the SSH Server")
            return None

        return client

    def execute_command(self, command, timeout=3):
        """
        Execute the given command on the L1 switch

        Args:
            command (str): Command to execute on the L1 switch
        Returns:
            stdin (paramiko.channel.ChannelStdinFile): stdin object
            stdout (paramiko.channel.ChannelFile): stdout object
            stderr (paramiko.channel.ChannelFile): stderr object
        """
        attempts = 0
        connected_session = False
        stdin, stdout, stderr = None, None, None
        self.client = self.setup_SSH_connection()

        while attempts < timeout and connected_session is False:
            try:
                stdin, stdout, stderr = self.client.exec_command(command)
                connected_session = True
            except paramiko.ssh_exception.SSHException:
                logging.info("Retrying connecting to L1 switch")
                connected_session = False
                self.client = self.setup_SSH_connection()
            attempts += 1

        if connected_session:
            self.client.close()
            return stdin, stdout, stderr

    def extract_port_pair(self, port_pair):
        """
        Extracts a tuple of port names from a port pair string ex. "(E7,A7)-(W8,A8)" -> "1AE7", "1AW8"

        Args:
            port_pair (str): Port pair string to convert
        Returns:
            port1 (str): Name of the first port
            port2 (str): Name of the second port
        """
        result = re.search(r"\((\w+,\w+)\)-\((\w+,\w+)\)", port_pair)
        res = []
        if result:
            out = [(result.group(1), result.group(2)), (result.group(3), result.group(4))]
        else:
            return None, None

        for port_bay in out:
            port_dir_split = port_bay[0].rstrip("0123456789")
            port_num_split = port_bay[0][len(port_dir_split):]
            port_bay_split = port_bay[1].rstrip("0123456789")
            port_num_bay_split = port_bay[1][len(port_bay_split):]
            if port_num_split == port_num_bay_split:
                res.append("1{}{}{}".format(port_bay_split, port_dir_split, port_num_split))
            else:
                return None, None

        return res[0], res[1]
