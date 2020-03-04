"""
This module contains classes for PSU controllers that supports the SNMP management protocol.

The classes must implement the PsuControllerBase interface defined in controller_base.py.
"""
import logging

from controller_base import PsuControllerBase
from controller_base import run_local_cmd


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

    def _get_pdu_ports(self):
        """
        @summary: Helper method for getting PDU ports connected to PSUs of DUT

        The PDU ports connected to DUT must have hostname of DUT configured in port name/description.
        This method depends on this configuration to find out the PDU ports connected to PSUs of specific DUT.
        """
        try:
            cmd = "snmpwalk -v 1 -c public -Ofenq %s %s " % (self.controller, self.PORT_NAME_BASE_OID)
            stdout = run_local_cmd(cmd)
            for line in stdout.splitlines():
                if self.hostname in line:  # PDU port name/description should have DUT hostname
                    fields = line.split()
                    if len(fields) == 2:
                        # Remove the preceding PORT_NAME_BASE_OID, remaining string is the PDU port ID
                        self.pdu_ports.append(fields[0].replace(self.PORT_NAME_BASE_OID, ''))
        except Exception as e:
            logging.debug("Failed to get ports controlling PSUs of DUT, exception: " + repr(e))

    def __init__(self, hostname, controller):
        logging.info("Initializing " + self.__class__.__name__)
        PsuControllerBase.__init__(self)
        self.hostname = hostname
        self.controller = controller
        self.pdu_ports = []
        self._get_pdu_ports()
        logging.info("Initialized " + self.__class__.__name__)

    def turn_on_psu(self, psu_id):
        """
        @summary: Use SNMP to turn on power to PSU of DUT specified by psu_id

        DUT hostname must be configured in PDU port name/description. But it is hard to specify which PDU port is
        connected to the first PSU of DUT and which port is connected to the second PSU.

        Because of this, currently we just find out which PDU ports are connected to PSUs of which DUT. We cannot
        find out the exact mapping between PDU ports and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified psu_id to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU ports ID stored in
        self.pdu_ports. But still, we cannot gurante that psu_id 0 is first PSU of DUT, and so on.

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

        DUT hostname must be configured in PDU port name/description. But it is hard to specify which PDU port is
        connected to the first PSU of DUT and which port is connected to the second PSU.

        Because of this, currently we just find out which PDU ports are connected to PSUs of which DUT. We cannot
        find out the exact mapping between PDU ports and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified psu_id to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU ports ID stored in
        self.pdu_ports. But still, we cannot gurante that psu_id 0 is first PSU of DUT, and so on.

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

        DUT hostname must be configured in PDU port name/description. But it is hard to specify which PDU port is
        connected to the first PSU of DUT and which port is connected to the second PSU.

        Because of this, currently we just find out which PDU ports are connected to PSUs of which DUT. We cannot
        find out the exact mapping between PDU ports and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified psu_id to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU ports ID stored in
        self.pdu_ports. But still, we cannot gurante that psu_id 0 is first PSU of DUT, and so on.

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
                    fields = line.strip().split()
                    if len(fields) == 2 and fields[0] == port_oid:
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


def get_psu_controller(controller_ip, dut_hostname):
    """
    @summary: Factory function to create the actual PSU controller object.
    @return: The actual PSU controller object. Returns None if something went wrong.
    """

    psu_controller_type = get_psu_controller_type(controller_ip)
    if not psu_controller_type:
        return None

    if "Sentry Switched CDU" in psu_controller_type:
        logging.info("Initializing PSU controller")
        return SentrySwitchedCDU(dut_hostname, controller_ip)

    return None
