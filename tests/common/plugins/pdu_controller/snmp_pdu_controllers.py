"""
This module contains classes for PDU controllers that supports the SNMP management protocol.

The classes must implement the PduControllerBase interface defined in controller_base.py.
"""
import logging

from controller_base import PduControllerBase

from pysnmp.proto import rfc1902
from pysnmp.entity.rfc3413.oneliner import cmdgen

class snmpPduController(PduControllerBase):
    """
    PDU Controller class for SNMP conrolled PDUs - 'Sentry Switched CDU' and 'APC Web/SNMP Management Card'

    This class implements the interface defined in PduControllerBase class for SNMP conrtolled PDU type 
    'Sentry Switched CDU' and 'APC Web/SNMP Management Card'
    """

    def get_pdu_controller_type(self):
        """
        @summary: Use SNMP to get the type of PDU controller host
        @param pdu_controller_host: IP address of PDU controller host
        @return: Returns type string of the specified PDU controller host
        """
        pSYSDESCR = ".1.3.6.1.2.1.1.1.0"
        SYSDESCR = "1.3.6.1.2.1.1.1.0"
        pdu = None
        cmdGen = cmdgen.CommandGenerator()
        snmp_auth = cmdgen.CommunityData(self.snmp_rocommunity)
        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((self.controller, 161), timeout=5.0),
            cmdgen.MibVariable(pSYSDESCR,),
            )
        if errorIndication:
            logging.info("Failed to get pdu controller type, exception: " + str(errorIndication))
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if current_oid == SYSDESCR:
                pdu = current_val
        if pdu is None:
            self.pduType = None
            return
        if 'Sentry Switched PDU' in pdu:
            self.pduType = "SENTRY4"
        if 'Sentry Switched CDU' in pdu:
            self.pduType = "SENTRY"
        if 'APC Web/SNMP Management Card' in pdu:
            self.pduType = "APC"
        if 'Emerson' in pdu:
            self.pduType = 'Emerson'
        return

    def pduCntrlOid(self):
        """
        Define Oids based on the PDU Type
        """
        # MIB OIDs for 'APC Web/SNMP Management PDU'
        APC_PORT_NAME_BASE_OID = "1.3.6.1.4.1.318.1.1.4.4.2.1.4"
        APC_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.318.1.1.12.3.5.1.1.4"
        APC_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.318.1.1.12.3.3.1.1.4"
        # MIB OID for 'Sentry Switched CDU'
        SENTRY_PORT_NAME_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.3.1"
        SENTRY_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.5.1"
        SENTRY_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.11.1"
        # MIB OID for 'Emerson'
        EMERSON_PORT_NAME_BASE_OID = "1.3.6.1.4.1.476.1.42.3.8.50.20.1.10.1.1"
        EMERSON_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.476.1.42.3.8.50.20.1.100.1.1"
        EMERSON_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.476.1.42.3.8.50.20.1.100.1.1"
        # MIB OID for 'Sentry Switched PDU'
        SENTRY4_PORT_NAME_BASE_OID = "1.3.6.1.4.1.1718.4.1.8.2.1.3"
        SENTRY4_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.1718.4.1.8.3.1.1"
        SENTRY4_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.1718.4.1.8.5.1.2"
        self.STATUS_ON = "1"
        self.STATUS_OFF = "0"
        self.CONTROL_ON = "1"
        self.CONTROL_OFF = "2"
        if self.pduType == "APC":
            self.pPORT_NAME_BASE_OID     = '.'+APC_PORT_NAME_BASE_OID
            self.pPORT_STATUS_BASE_OID   = '.'+APC_PORT_STATUS_BASE_OID
            self.pPORT_CONTROL_BASE_OID  = '.'+APC_PORT_CONTROL_BASE_OID
            self.PORT_NAME_BASE_OID      = APC_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = APC_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = APC_PORT_CONTROL_BASE_OID
        elif self.pduType == "SENTRY":
            self.pPORT_NAME_BASE_OID     = '.'+SENTRY_PORT_NAME_BASE_OID
            self.pPORT_STATUS_BASE_OID   = '.'+SENTRY_PORT_STATUS_BASE_OID
            self.pPORT_CONTROL_BASE_OID  = '.'+SENTRY_PORT_CONTROL_BASE_OID
            self.PORT_NAME_BASE_OID      = SENTRY_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = SENTRY_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = SENTRY_PORT_CONTROL_BASE_OID
        elif self.pduType == "Emerson":
            self.pPORT_NAME_BASE_OID     = '.'+EMERSON_PORT_NAME_BASE_OID
            self.pPORT_STATUS_BASE_OID   = '.'+EMERSON_PORT_STATUS_BASE_OID
            self.pPORT_CONTROL_BASE_OID  = '.'+EMERSON_PORT_CONTROL_BASE_OID
            self.PORT_NAME_BASE_OID      = EMERSON_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = EMERSON_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = EMERSON_PORT_CONTROL_BASE_OID
        elif self.pduType == "SENTRY4":
            self.pPORT_NAME_BASE_OID     = '.'+SENTRY4_PORT_NAME_BASE_OID
            self.pPORT_STATUS_BASE_OID   = '.'+SENTRY4_PORT_STATUS_BASE_OID
            self.pPORT_CONTROL_BASE_OID  = '.'+SENTRY4_PORT_CONTROL_BASE_OID
            self.PORT_NAME_BASE_OID      = SENTRY4_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = SENTRY4_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = SENTRY4_PORT_CONTROL_BASE_OID
        else:
            pass


    def _get_pdu_ports(self):
        """
        @summary: Helper method for getting PDU ports connected to PSUs of DUT

        The PDU ports connected to DUT must have hostname of DUT configured in port name/description.
        This method depends on this configuration to find out the PDU ports connected to PSUs of specific DUT.
        """
        if not self.pduType:
            logging.info('PDU type is unknown')
            return

        max_lane = 5
        host_matched = False
        cmdGen = cmdgen.CommandGenerator()
        snmp_auth = cmdgen.CommunityData(self.snmp_rocommunity)

        for lane_id in range(1, max_lane + 1):
            pdu_port_base = self.PORT_NAME_BASE_OID[0: -1] + str(lane_id)

            errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
                snmp_auth,
                cmdgen.UdpTransportTarget((self.controller, 161)),
                cmdgen.MibVariable("." + pdu_port_base,),
                )
            if errorIndication:
                logging.debug("Failed to get ports controlling PSUs of DUT, exception: " + str(errorIndication))
            else:
                for varBinds in varTable:
                    for oid, val in varBinds:
                        current_oid = oid.prettyPrint()
                        current_val = val.prettyPrint()
                        if self.hostname.lower()  in current_val.lower():
                            host_matched = True
                            # Remove the preceding PORT_NAME_BASE_OID, remaining string is the PDU port ID
                            self.pdu_ports.append(current_oid.replace(pdu_port_base, ''))
                if host_matched:
                    self.map_host_to_lane(lane_id)
                    break
        else:
            logging.error("{} device is not attached to any of PDU port".format(self.hostname.lower()))

    def map_host_to_lane(self, lane_id):
        """
        Dynamically update Oids based on the PDU lane ID
        """
        if self.pduType == "SENTRY4":
            # No need to update lane for SENTRY4
            return

        self.pPORT_NAME_BASE_OID     = self.pPORT_NAME_BASE_OID[0: -1] + str(lane_id)
        self.pPORT_STATUS_BASE_OID   = self.pPORT_STATUS_BASE_OID[0: -1] + str(lane_id)
        self.pPORT_CONTROL_BASE_OID  = self.pPORT_CONTROL_BASE_OID[0: -1] + str(lane_id)
        self.PORT_NAME_BASE_OID      = self.PORT_NAME_BASE_OID[0: -1] + str(lane_id)
        self.PORT_STATUS_BASE_OID    = self.PORT_STATUS_BASE_OID[0: -1] + str(lane_id)
        self.PORT_CONTROL_BASE_OID   = self.PORT_CONTROL_BASE_OID[0: -1] + str(lane_id)

    def __init__(self, hostname, controller, pdu):
        logging.info("Initializing " + self.__class__.__name__)
        PduControllerBase.__init__(self)
        self.hostname = hostname
        self.controller = controller
        self.snmp_rocommunity = pdu['snmp_rocommunity']
        self.snmp_rwcommunity = pdu['snmp_rwcommunity']
        self.pdu_ports = []
        self.pduType = None
        self.get_pdu_controller_type()
        self.pduCntrlOid()
        self._get_pdu_ports()
        logging.info("Initialized " + self.__class__.__name__)

    def turn_on_outlet(self, outlet):
        """
        @summary: Use SNMP to turn on power to PDU of DUT specified by outlet

        DUT hostname must be configured in PDU port name/description. But it is hard to specify which PDU port is
        connected to the first PDU of DUT and which port is connected to the second PDU.

        Because of this, currently we just find out which PDU ports are connected to PSUs of which DUT. We cannot
        find out the exact mapping between PDU ports and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified outlet to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU ports ID stored in
        self.pdu_ports. But still, we cannot gurante that outlet 0 is first PDU of DUT, and so on.

        @param outlet: ID of the PDU on SONiC DUT
        @return: Return true if successfully execute the command for turning on power. Otherwise return False.
        """
        if not self.pduType:
            logging.error('Unable to turn on: PDU type is unknown')
            return False

        port_oid = self.pPORT_CONTROL_BASE_OID + self.pdu_ports[rfc1902.Integer(outlet)]
        errorIndication, errorStatus, _, _ = \
        cmdgen.CommandGenerator().setCmd(
            cmdgen.CommunityData(self.snmp_rwcommunity),
            cmdgen.UdpTransportTarget((self.controller, 161)),
            (port_oid, rfc1902.Integer(self.CONTROL_ON)),
        )
        if errorIndication or errorStatus != 0:
            logging.debug("Failed to turn on outlet %s, exception: %s" % (str(outlet), str(errorStatus)))
            return False
        return True

    def turn_off_outlet(self, outlet):
        """
        @summary: Use SNMP to turn off power to PDU outlet of DUT specified by outlet

        DUT hostname must be configured in PDU port name/description. But it is hard to specify which PDU port is
        connected to the first PSU of DUT and which port is connected to the second PSU.

        Because of this, currently we just find out which PDU outlets are connected to PSUs of which DUT. We cannot
        find out the exact mapping between PDU outlets and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified outlet to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU ports ID stored in
        self.pdu_ports. But still, we cannot guarantee that outlet 0 is first PSU of DUT, and so on.

        @param outlet: ID of the outlet on PDU
        @return: Return true if successfully execute the command for turning off power. Otherwise return False.
        """
        if not self.pduType:
            logging.error('Unable to turn off: PDU type is unknown')
            return False

        port_oid = self.pPORT_CONTROL_BASE_OID + self.pdu_ports[rfc1902.Integer(outlet)]
        errorIndication, errorStatus, _, _ = \
        cmdgen.CommandGenerator().setCmd(
            cmdgen.CommunityData(self.snmp_rwcommunity),
            cmdgen.UdpTransportTarget((self.controller, 161)),
            (port_oid, rfc1902.Integer(self.CONTROL_OFF)),
        )
        if errorIndication or errorStatus != 0:
            logging.debug("Failed to turn on outlet %s, exception: %s" % (str(outlet), str(errorStatus)))
            return False
        return True

    def get_outlet_status(self, outlet=None):
        """
        @summary: Use SNMP to get status of PDU ports supplying power to PSUs of DUT

        DUT hostname must be configured in PDU port name/description. But it is hard to specify which PDU port is
        connected to the first PSU of DUT and which port is connected to the second PSU.

        Because of this, currently we just find out which PDU ports are connected to PSUs of which DUT. We cannot
        find out the exact mapping between PDU outlets and PSUs of DUT.

        To overcome this limitation, the trick is to convert the specified outlet to integer, then calculate the mode
        upon the number of PSUs on DUT. The calculated mode is used as an index to get PDU outlet ID stored in
        self.pdu_ports. But still, we cannot guarantee that outlet 0 is first PSU of DUT, and so on.

        @param outlet: Optional. If specified, only return status of PDU outlet connected to specified PSU of DUT. If
                       omitted, return status of all PDU outlets connected to PSUs of DUT.
        @return: Return status of PDU outlets connected to PSUs of DUT in a list of dictionary. Example result:
                     [{"outlet_id": 0, "outlet_on": True}, {"outlet_id": 1, "outlet_on": True}]
                 The outlet in returned result is integer starts from 0.
        """
        results = []
        if not self.pduType:
            logging.error('Unable to retrieve status: PDU type is unknown')
            return results

        cmdGen = cmdgen.CommandGenerator()
        snmp_auth = cmdgen.CommunityData(self.snmp_rocommunity)
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
                        status = {"outlet_id": idx, "outlet_on": True if current_val == self.STATUS_ON else False}
                        results.append(status)
        if outlet is not None:
            idx = int(outlet) % len(self.pdu_ports)
            results = results[idx:idx+1]
        logging.info("Got outlet status: %s" % str(results))
        return results

    def close(self):
        pass


def get_pdu_controller(controller_ip, dut_hostname, pdu):
    """
    @summary: Factory function to create the actual PDU controller object.
    @return: The actual PDU controller object. Returns None if something went wrong.
    """
    return snmpPduController(dut_hostname, controller_ip, pdu)
