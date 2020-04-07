"""
This module contains classes for PSU controllers that supports the SNMP management protocol.

The classes must implement the PsuControllerBase interface defined in controller_base.py.
"""
import logging

from controller_base import PsuControllerBase

from pysnmp.proto import rfc1902
from pysnmp.entity.rfc3413.oneliner import cmdgen

class snmpPsuController(PsuControllerBase):
    """
    PSU Controller class for SNMP conrolled PSUs - 'Sentry Switched CDU' and 'APC Web/SNMP Management Card'

    This class implements the interface defined in PsuControllerBase class for SNMP conrtolled PDU type 
    'Sentry Switched CDU' and 'APC Web/SNMP Management Card'
    """

    def get_psu_controller_type(self):
        """
        @summary: Use SNMP to get the type of PSU controller host
        @param psu_controller_host: IP address of PSU controller host
        @return: Returns type string of the specified PSU controller host
        """
        pSYSDESCR = ".1.3.6.1.2.1.1.1.0"
        SYSDESCR = "1.3.6.1.2.1.1.1.0"
        psu = None
        cmdGen = cmdgen.CommandGenerator()
        snmp_auth = cmdgen.CommunityData('public')
        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((self.controller, 161), timeout=5.0),
            cmdgen.MibVariable(pSYSDESCR,),
            )
        if errorIndication:
            logging.info("Failed to get psu controller type, exception: " + str(errorIndication))
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if current_oid == SYSDESCR:
                psu = current_val
        if psu is None:
            self.psuType = None
            return
        if 'Sentry Switched CDU' in psu:
            self.psuType = "SENTRY"
        if 'APC Web/SNMP Management Card' in psu:
            self.psuType = "APC"
        return

    def psuCntrlOid(self):
        """
        Define Oids based on the PSU Type
        """
        # MIB OIDs for 'APC Web/SNMP Management PSU'
        APC_PORT_NAME_BASE_OID = "1.3.6.1.4.1.318.1.1.4.4.2.1.4"
        APC_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.318.1.1.12.3.5.1.1.4"
        APC_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.318.1.1.12.3.3.1.1.4"
        # MIB OID for 'Sentry Switched CDU'
        SENTRY_PORT_NAME_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.3.1"
        SENTRY_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.5.1"
        SENTRY_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.11.1"
        self.STATUS_ON = "1"
        self.STATUS_OFF = "0"
        self.CONTROL_ON = "1"
        self.CONTROL_OFF = "2"
        if self.psuType == "APC":
            self.pPORT_NAME_BASE_OID     = '.'+APC_PORT_NAME_BASE_OID
            self.pPORT_STATUS_BASE_OID   = '.'+APC_PORT_STATUS_BASE_OID
            self.pPORT_CONTROL_BASE_OID  = '.'+APC_PORT_CONTROL_BASE_OID
            self.PORT_NAME_BASE_OID      = APC_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = APC_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = APC_PORT_CONTROL_BASE_OID
        elif self.psuType == "SENTRY":
            self.pPORT_NAME_BASE_OID     = '.'+SENTRY_PORT_NAME_BASE_OID
            self.pPORT_STATUS_BASE_OID   = '.'+SENTRY_PORT_STATUS_BASE_OID
            self.pPORT_CONTROL_BASE_OID  = '.'+SENTRY_PORT_CONTROL_BASE_OID
            self.PORT_NAME_BASE_OID      = SENTRY_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = SENTRY_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = SENTRY_PORT_CONTROL_BASE_OID
        else:
            pass


    def _get_pdu_ports(self):
        """
        @summary: Helper method for getting PDU ports connected to PSUs of DUT

        The PDU ports connected to DUT must have hostname of DUT configured in port name/description.
        This method depends on this configuration to find out the PDU ports connected to PSUs of specific DUT.
        """
        cmdGen = cmdgen.CommandGenerator()
        snmp_auth = cmdgen.CommunityData('public')
        errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((self.controller, 161)),
            cmdgen.MibVariable(self.pPORT_NAME_BASE_OID,),
            )
        if errorIndication:
            logging.debug("Failed to get ports controlling PSUs of DUT, exception: " + str(errorIndication))
        for varBinds in varTable:
            for oid, val in varBinds:
                current_oid = oid.prettyPrint()
                current_val = val.prettyPrint()
                if self.hostname.lower()  in current_val.lower():
                    # Remove the preceding PORT_NAME_BASE_OID, remaining string is the PDU port ID
                    self.pdu_ports.append(current_oid.replace(self.PORT_NAME_BASE_OID, ''))

    def __init__(self, hostname, controller):
        logging.info("Initializing " + self.__class__.__name__)
        PsuControllerBase.__init__(self)
        self.hostname = hostname
        self.controller = controller
        self.pdu_ports = []
        self.psuType = None
        self.get_psu_controller_type()
        self.psuCntrlOid()
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
        port_oid = self.pPORT_CONTROL_BASE_OID + self.pdu_ports[rfc1902.Integer(psu_id)]
        errorIndication, errorStatus, _, _ = \
        cmdgen.CommandGenerator().setCmd(
            cmdgen.CommunityData('private'),
            cmdgen.UdpTransportTarget((self.controller, 161)),
            (port_oid, rfc1902.Integer(self.CONTROL_ON)),
        )
        if errorIndication or errorStatus != 0:
            logging.debug("Failed to turn on PSU %s, exception: %s" % (str(psu_id), str(errorStatus)))
            return False
        return True

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
        port_oid = self.pPORT_CONTROL_BASE_OID + self.pdu_ports[rfc1902.Integer(psu_id)]
        errorIndication, errorStatus, _, _ = \
        cmdgen.CommandGenerator().setCmd(
            cmdgen.CommunityData('private'),
            cmdgen.UdpTransportTarget((self.controller, 161)),
            (port_oid, rfc1902.Integer(self.CONTROL_OFF)),
        )
        if errorIndication or errorStatus != 0:
            logging.debug("Failed to turn on PSU %s, exception: %s" % (str(psu_id), str(errorStatus)))
            return False
        return True

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
        cmdGen = cmdgen.CommandGenerator()
        snmp_auth = cmdgen.CommunityData('public')
        errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((self.controller, 161)),
            cmdgen.MibVariable(self.pPORT_STATUS_BASE_OID,),
            )
        if errorIndication:
            logging.debug("Failed to get ports controlling PSUs of DUT, exception: " + str(errorIndication))
        for varBinds in varTable:
            for oid, val in varBinds:
                current_oid = oid.prettyPrint()
                current_val = val.prettyPrint()
                for idx, port in enumerate(self.pdu_ports):
                    port_oid = self.PORT_STATUS_BASE_OID + port
                    if current_oid == port_oid:
                        status = {"psu_id": idx, "psu_on": True if current_val == self.STATUS_ON else False}
                        results.append(status)
        if psu_id is not None:
            idx = int(psu_id) % len(self.pdu_ports)
            results = results[idx:idx+1]
        logging.info("Got PSU status: %s" % str(results))
        return results

    def close(self):
        pass


def get_psu_controller(controller_ip, dut_hostname):
    """
    @summary: Factory function to create the actual PSU controller object.
    @return: The actual PSU controller object. Returns None if something went wrong.
    """
    return snmpPsuController(dut_hostname, controller_ip)
