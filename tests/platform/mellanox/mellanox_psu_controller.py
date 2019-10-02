"""
Mellanox specific PSU controller

This script contains illustrative functions and class for creating PSU controller based on Mellanox lab configuration.

Some actual configurations were or replaced with dummy configurations.
"""
import logging
import subprocess

import paramiko

from psu_controller import PsuControllerBase


def run_local_cmd(cmd):
    """
    @summary: Helper function for run command on localhost -- the sonic-mgmt container
    @param cmd: Command to be executed
    @return: Returns whatever output to stdout by the command
    @raise: Raise an exception if the command return code is not 0.
    """
    process = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    ret_code = process.returncode

    if ret_code != 0:
        raise Exception("ret_code=%d, error message=%s. cmd=%s" % (ret_code, stderr, ' '.join(cmd)))

    return stdout


def connect_mellanox_server():
    """
    @summary: Connect to a server on Mellanox lab network via SSH
    @return: Returns a paramiko.client.SSHClient object which can be used for running commands
    """
    mellanox_server = None
    try:
        mellanox_server = paramiko.client.SSHClient()
        mellanox_server.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        mellanox_server.connect("a_mellanox_server", username="username", password="password")
    except Exception as e:
        logging.debug("Failed to connect to mellanox server, exception: " + repr(e))
    return mellanox_server


def find_psu_controller_conf_file(server):
    """
    @summary: Find the exact location of the configuration file which contains mapping between PSU controllers and DUT
              switches.
    @param server: The paramiko.client.SSHClient object connected to a Mellanox server
    @return: Returns the exact path of the configuration file
    """
    result = None
    try:
        locations = ("/path1", "/path2")
        config_file_name = "psu_controller_configuration_file.txt"
        for location in locations:
            _, stdout, stderr = server.exec_command("find %s -name %s" % (location, config_file_name))

            lines = stdout.readlines()
            if len(lines) > 0:
                result = lines[0].strip()
                break
    except paramiko.SSHException as e:
        logging.debug("Failed to find psu controller configuration file location, exception: " + repr(e))
    return result


def get_psu_controller_host(hostname, server, conf_file_location):
    """
    @summary: Check the configuration file to find out IP address of the PDU controlling power to PSUs of DUT.
    @param hostname: Hostname of the SONiC DUT
    @param server: The paramiko.client.SSHClient object connected to a Mellanox server
    @param conf_file_location: Exact path of the configuration file on the Mellanox server
    @return: Returns IP address of the PDU controlling power to PSUs of DUT
    """
    result = None
    try:
        _, stdout, stderr = server.exec_command("grep %s %s" % (hostname, conf_file_location))
        for line in stdout.readlines():
            fields = line.strip().split()
            if len(fields) == 2:
                result = fields[1]
                break
    except paramiko.SSHException as e:
        logging.debug("Failed to get psu controller host, exception: " + repr(e))
    return result


def get_psu_controller_type(psu_controller_host):
    """
    @summary: Use SNMP to get the type of PSU controller host
    @param psu_controller_host: IP address of PSU controller host
    @return: Returns type string of the specified PSU controller host
    """
    result = None
    cmd = "snmpget -v 1 -c public -Ofenqv %s .1.3.6.1.2.1.1.1.0" % psu_controller_host
    try:
        stdout = run_local_cmd(cmd)

        lines = stdout.splitlines()
        if len(lines) > 0:
            result = lines[0].strip()
            result = result.replace('"', '')
    except Exception as e:
        logging.debug("Failed to get psu controller type, exception: " + repr(e))

    return result


class SentrySwitchedCDU(PsuControllerBase):
    """
    PSU Controller class for 'Sentry Switched CDU'

    This class implements the interface defined in PsuControllerBase class for PDU type 'Sentry Switched CDU'
    """
    PORT_NAME_BASE_OID = ".1.3.6.1.4.1.1718.3.2.3.1.3.1"
    PORT_STATUS_BASE_OID = ".1.3.6.1.4.1.1718.3.2.3.1.5.1"
    PORT_CONTROL_BASE_OID = ".1.3.6.1.4.1.1718.3.2.3.1.11.1"
    STATUS_ON = "1"
    STATUS_OFF = "0"
    CONTROL_ON = "1"
    CONTROL_OFF = "2"

    def _get_psu_ports(self):
        """
        @summary: Helper method for getting PDU ports connected to PSUs of DUT
        """
        try:
            cmd = "snmpwalk -v 1 -c public -Ofenq %s %s " % (self.controller, self.PORT_NAME_BASE_OID)
            stdout = run_local_cmd(cmd)
            for line in stdout.splitlines():
                if self.hostname in line:
                    fields = line.split()
                    if len(fields) == 2:
                        # Remove the preceeding PORT_NAME_BASE_OID, remaining string is the PDU port ID
                        self.pdu_ports.append(fields[0].replace(self.PORT_NAME_BASE_OID, ''))
        except Exception as e:
            logging.debug("Failed to get ports controlling PSUs of DUT, exception: " + repr(e))

    def __init__(self, hostname, controller):
        PsuControllerBase.__init__(self)
        self.hostname = hostname
        self.controller = controller
        self.pdu_ports = []
        self._get_psu_ports()
        logging.info("Initialized " + self.__class__.__name__)

    def turn_on_psu(self, psu_id):
        """
        @summary: Use SNMP to turn on power to PSU of DUT specified by psu_id

        There is a limitation in the Mellanox configuration. Currently we can just find out which PDU ports are
        connected to PSUs of which DUT. But we cannot find out the exact mapping between PDU ports and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified psu_id to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU ports ID stored in
        self.pdu_ports.

        @param psu_id: ID of the PSU on SONiC DUT
        @return: Return true if successfully execute the command for turning on power. Otherwise return False.
        """
        try:
            idx = int(psu_id) % len(self.pdu_ports)
            port_oid = self.PORT_CONTROL_BASE_OID + self.pdu_ports[idx]
            cmd = "snmpset -v1 -C q -c private %s %s i %s" % (self.controller, port_oid, self.CONTROL_ON)
            run_local_cmd(cmd)
            logging.info("Turned on PSU %s" % str(psu_id))
            return True
        except Exception as e:
            logging.debug("Failed to turn on PSU %s, exception: %s" % (str(psu_id), repr(e)))
            return False

    def turn_off_psu(self, psu_id):
        """
        @summary: Use SNMP to turn off power to PSU of DUT specified by psu_id

        There is a limitation in the Mellanox configuration. Currently we can just find out which PDU ports are
        connected to PSUs of which DUT. But we cannot find out the exact mapping between PDU ports and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified psu_id to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU ports ID stored in
        self.pdu_ports.

        @param psu_id: ID of the PSU on SONiC DUT
        @return: Return true if successfully execute the command for turning off power. Otherwise return False.
        """
        try:
            idx = int(psu_id) % len(self.pdu_ports)
            port_oid = self.PORT_CONTROL_BASE_OID + self.pdu_ports[idx]
            cmd = "snmpset -v1 -C q -c private %s %s i %s" % (self.controller, port_oid, self.CONTROL_OFF)
            run_local_cmd(cmd)
            logging.info("Turned off PSU %s" % str(psu_id))
            return True
        except Exception as e:
            logging.debug("Failed to turn off PSU %s, exception: %s" % (str(psu_id), repr(e)))
            return False

    def get_psu_status(self, psu_id=None):
        """
        @summary: Use SNMP to get status of PDU ports supplying power to PSUs of DUT

        There is a limitation in the Mellanox configuration. Currently we can just find out which PDU ports are
        connected to PSUs of which DUT. But we cannot find out the exact mapping between PDU ports and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified psu_id to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU ports ID stored in
        self.pdu_ports.

        @param psu_id: Optional. If specified, only return status of PDU port connected to specified PSU of DUT. If
                       omitted, return status of all PDU ports connected to PSUs of DUT.
        @return: Return status of PDU ports connected to PSUs of DUT in a list of dictionary. Example result:
                     [{"psu_id": 0, "psu_on": True}, {"psu_id": 1, "psu_on": True}]
                 The psu_id in returned result is integer starts from 0.
        """
        results = []
        try:
            cmd = "snmpwalk -v 1 -c public -Ofenq %s %s " % (self.controller, self.PORT_STATUS_BASE_OID)
            stdout = run_local_cmd(cmd)
            for line in stdout.splitlines():
                for idx, port in enumerate(self.pdu_ports):
                    port_oid = self.PORT_STATUS_BASE_OID + port
                    if port_oid in line:
                        fields = line.strip().split()
                        if len(fields) == 2:
                            status = {"psu_id": idx, "psu_on": True if fields[1] == self.STATUS_ON else False}
                            results.append(status)
            if psu_id is not None:
                idx = int(psu_id) % len(self.pdu_ports)
                results = results[idx:idx+1]
            logging.info("Got PSU status: %s" % str(results))
        except Exception as e:
            logging.debug("Failed to get psu status, exception: " + repr(e))
        return results

    def close(self):
        pass


def make_mellanox_psu_controller(hostname):
    """
    @summary: For creating different type of PSU controller based on Mellanox lab configuration.
    @param hostname: Hostname of the SONiC DUT
    @return: Returns an instance of PSU controller
    """
    mellanox_server = connect_mellanox_server()
    if not mellanox_server:
        return None

    conf_file_location = find_psu_controller_conf_file(mellanox_server)
    logging.info("conf_file_location: %s" % conf_file_location)
    if not conf_file_location:
        return None

    psu_controller_host = get_psu_controller_host(hostname, mellanox_server, conf_file_location)
    logging.info("psu_controller_host: %s" % psu_controller_host)
    if not psu_controller_host:
        return None

    psu_controller_type = get_psu_controller_type(psu_controller_host)
    logging.info("psu_controller_type: %s" % psu_controller_type)
    if not psu_controller_type:
        return None

    if "Sentry Switched CDU" in psu_controller_type:
        logging.info("Initializing PSU controller instance")
        return SentrySwitchedCDU(hostname, psu_controller_host)
