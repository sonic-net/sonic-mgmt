"""
This module contains classes for PDU controllers that supports the SNMP management protocol.

The classes must implement the PduControllerBase interface defined in controller_base.py.
"""
import logging

from .controller_base import PduControllerBase

from pysnmp.proto import rfc1902
from pysnmp.entity.rfc3413.oneliner import cmdgen

logger = logging.getLogger(__name__)


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
            cmdgen.MibVariable(pSYSDESCR)
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
        if 'Vertiv Geist Upgradeable PDU' in pdu:
            self.pduType = 'Vertiv'
        return

    def pduCntrlOid(self):
        """
        Define Oids based on the PDU Type
        """
        # MIB OIDs for 'APC Web/SNMP Management PDU'
        APC_PORT_NAME_BASE_OID = "1.3.6.1.4.1.318.1.1.4.4.2.1"
        APC_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.318.1.1.12.3.5.1.1"
        APC_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.318.1.1.12.3.3.1.1"
        # MIB OID for 'Sentry Switched CDU'
        SENTRY_PORT_NAME_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.3"
        SENTRY_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.5"
        SENTRY_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.1718.3.2.3.1.11"
        # MIB OID for 'Emerson'
        EMERSON_PORT_NAME_BASE_OID = "1.3.6.1.4.1.476.1.42.3.8.50.20.1.10.1"
        EMERSON_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.476.1.42.3.8.50.20.1.100.1"
        EMERSON_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.476.1.42.3.8.50.20.1.100.1"
        # MIB OID for 'Sentry Switched PDU'
        SENTRY4_PORT_NAME_BASE_OID = "1.3.6.1.4.1.1718.4.1.8.2.1.3"
        SENTRY4_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.1718.4.1.8.3.1.1"
        SENTRY4_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.1718.4.1.8.5.1.2"
        SENTRY4_PORT_POWER_BASE_OID = "1.3.6.1.4.1.1718.4.1.8.3.1.9"
        # MIB OID for 'Vertiv Geist Upgradeable PDU'
        VERTIV_PORT_NAME_BASE_OID = "1.3.6.1.4.1.21239.5.2.3.5.1.3"
        VERTIV_PORT_STATUS_BASE_OID = "1.3.6.1.4.1.21239.5.2.3.5.1.4"
        VERTIV_PORT_CONTROL_BASE_OID = "1.3.6.1.4.1.21239.5.2.3.5.1.6"
        VERTIV_PORT_POWER_BASE_OID = "1.3.6.1.4.1.21239.5.2.3.6.1.12"
        self.STATUS_ON = "1"
        self.STATUS_OFF = "0"
        self.CONTROL_ON = "1"
        self.CONTROL_OFF = "2"
        self.has_lanes = True
        self.max_lanes = 5
        self.PORT_POWER_BASE_OID = None
        if self.pduType == "APC":
            self.PORT_NAME_BASE_OID      = APC_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = APC_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = APC_PORT_CONTROL_BASE_OID
        elif self.pduType == "SENTRY":
            self.PORT_NAME_BASE_OID      = SENTRY_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = SENTRY_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = SENTRY_PORT_CONTROL_BASE_OID
        elif self.pduType == "Emerson":
            self.PORT_NAME_BASE_OID      = EMERSON_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = EMERSON_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = EMERSON_PORT_CONTROL_BASE_OID
            self.CONTROL_OFF             = "0"
        elif self.pduType == "SENTRY4":
            self.PORT_NAME_BASE_OID      = SENTRY4_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID    = SENTRY4_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID   = SENTRY4_PORT_CONTROL_BASE_OID
            self.PORT_POWER_BASE_OID     = SENTRY4_PORT_POWER_BASE_OID
            self.has_lanes = False
            self.max_lanes = 1
        elif self.pduType == "Vertiv":
            self.PORT_NAME_BASE_OID = VERTIV_PORT_NAME_BASE_OID
            self.PORT_STATUS_BASE_OID = VERTIV_PORT_STATUS_BASE_OID
            self.PORT_CONTROL_BASE_OID = VERTIV_PORT_CONTROL_BASE_OID
            self.PORT_POWER_BASE_OID = VERTIV_PORT_POWER_BASE_OID
            self.STATUS_OFF = "2"
            self.CONTROL_ON = "2"
            self.CONTROL_OFF = "4"
            self.has_lanes = False
            self.max_lanes = 1
        else:
            pass

    def _build_outlet_maps(self, port_oid, label):
        self.port_oid_dict[port_oid] = { 'label' : label }
        self.port_label_dict[label] = { 'port_oid' : port_oid }

    def _probe_lane(self, lane_id, cmdGen, snmp_auth):
        pdu_port_base = self.PORT_NAME_BASE_OID
        query_oid = '.' + pdu_port_base
        if self.has_lanes:
            query_oid = query_oid + '.' + str(lane_id)

        errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((self.controller, 161)),
            cmdgen.MibVariable(query_oid)
            )
        if errorIndication:
            logging.debug("Failed to get ports controlling PSUs of DUT, exception: " + str(errorIndication))
        else:
            for varBinds in varTable:
                for oid, val in varBinds:
                    current_oid = oid.prettyPrint()
                    port_oid = current_oid.replace(pdu_port_base, '')
                    label = val.prettyPrint().lower()
                    self._build_outlet_maps(port_oid, label)

    def _get_pdu_ports(self):
        """
        @summary: Helper method for getting PDU ports connected to PSUs of DUT

        The PDU ports connected to DUT must have hostname of DUT configured in port name/description.
        This method depends on this configuration to find out the PDU ports connected to PSUs of specific DUT.
        """
        if not self.pduType:
            logging.info('PDU type is unknown: pdu_ip {}'.format(self.controller))
            return

        cmdGen = cmdgen.CommandGenerator()
        snmp_auth = cmdgen.CommunityData(self.snmp_rocommunity)

        for lane_id in range(1, self.max_lanes + 1):
            self._probe_lane(lane_id, cmdGen, snmp_auth)

    def __init__(self, controller, pdu):
        logging.info("Initializing " + self.__class__.__name__)
        PduControllerBase.__init__(self)
        self.controller = controller
        self.snmp_rocommunity = pdu['snmp_rocommunity']
        self.snmp_rwcommunity = pdu['snmp_rwcommunity']
        self.pduType = None
        self.port_oid_dict = {}
        self.port_label_dict = {}
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

        @param outlet: ID of the PDU on SONiC DUT
        @return: Return true if successfully execute the command for turning on power. Otherwise return False.
        """
        if not self.pduType:
            logging.error('Unable to turn on: PDU type is unknown: pdu_ip {}'.format(self.controller))
            return False

        port_oid = '.' + self.PORT_CONTROL_BASE_OID + outlet
        errorIndication, errorStatus, _, _ = \
        cmdgen.CommandGenerator().setCmd(
            cmdgen.CommunityData(self.snmp_rwcommunity),
            cmdgen.UdpTransportTarget((self.controller, 161)),
            (port_oid, rfc1902.Integer(self.CONTROL_ON))
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

        @param outlet: ID of the outlet on PDU
        @return: Return true if successfully execute the command for turning off power. Otherwise return False.
        """
        if not self.pduType:
            logging.error('Unable to turn off: PDU type is unknown: pdu_ip {}'.format(self.controller))
            return False

        port_oid = '.' + self.PORT_CONTROL_BASE_OID + outlet
        errorIndication, errorStatus, _, _ = \
        cmdgen.CommandGenerator().setCmd(
            cmdgen.CommunityData(self.snmp_rwcommunity),
            cmdgen.UdpTransportTarget((self.controller, 161)),
            (port_oid, rfc1902.Integer(self.CONTROL_OFF))
        )
        if errorIndication or errorStatus != 0:
            logging.debug("Failed to turn off outlet %s, exception: %s" % (str(outlet), str(errorStatus)))
            return False
        return True

    def _get_one_outlet_power(self, cmdGen, snmp_auth, port_id, status):
        if not self.PORT_POWER_BASE_OID:
            return

        query_id = '.' + self.PORT_POWER_BASE_OID + port_id
        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((self.controller, 161)),
            cmdgen.MibVariable(query_id)
            )
        if errorIndication:
            logging.debug("Failed to get outlet power level of DUT outlet, exception: " + str(errorIndication))

        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            port_oid = current_oid.replace(self.PORT_POWER_BASE_OID, '')
            if port_oid == port_id:
                status['output_watts'] = current_val
                return

    def _get_one_outlet_status(self, cmdGen, snmp_auth, port_id):
        query_id = '.' + self.PORT_STATUS_BASE_OID + port_id
        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            snmp_auth,
            cmdgen.UdpTransportTarget((self.controller, 161)),
            cmdgen.MibVariable(query_id)
            )
        if errorIndication:
            logging.debug("Failed to outlet status of PDU, exception: " + str(errorIndication))

        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            port_oid = current_oid.replace(self.PORT_STATUS_BASE_OID, '')
            if port_oid == port_id:
                status = {"outlet_id": port_oid, "outlet_on": True if current_val == self.STATUS_ON else False}
                self._get_one_outlet_power(cmdGen, snmp_auth, port_id, status)
                return status

        return None

    def get_outlet_status(self, outlet=None, hostname=None):
        """
        @summary: Use SNMP to get status of PDU ports supplying power to PSUs of DUT

        DUT hostname must be configured in PDU port name/description. But it is hard to specify which PDU port is
        connected to the first PSU of DUT and which port is connected to the second PSU.

        Because of this, currently we just find out which PDU ports are connected to PSUs of which DUT. We cannot
        find out the exact mapping between PDU outlets and PSUs of DUT.

        @param outlet: Optional. If specified, only return status of PDU outlet connected to specified PSU of DUT. If
                       omitted, return status of all PDU outlets connected to PSUs of DUT.
        @return: Return status of PDU outlets connected to PSUs of DUT in a list of dictionary. Example result:
                     [{"outlet_id": "0.0.1", "outlet_on": True}, {"outlet_id": "0.0.2", "outlet_on": True}]
                 The outlet in returned result is integer starts from 0.
        """
        results = []
        if not self.pduType:
            logging.error('Unable to retrieve status: PDU type is unknown: pdu_ip {}'.format(self.controller))
            return results

        if not outlet and not hostname:
            # Return status of all outlets
            ports = self.port_oid_dict.keys()
        elif outlet:
            ports = [ oid for oid in self.port_oid_dict.keys() if oid.endswith(outlet) ]
            if not ports:
                logging.error("Outlet ID {} doesn't belong to PDU {}".format(outlet, self.controller))
        elif hostname:
            hn = hostname.lower()
            ports = [ self.port_label_dict[label]['port_oid'] for label in self.port_label_dict.keys() if hn in label ]
            if not ports:
                logging.error("{} device is not attached to any outlet of PDU {}".format(hn, self.controller))

        cmdGen = cmdgen.CommandGenerator()
        snmp_auth = cmdgen.CommunityData(self.snmp_rocommunity)

        for port in ports:
            status = self._get_one_outlet_status(cmdGen, snmp_auth, port)
            if status:
                results.append(status)

        logging.info("Got outlet status: %s" % str(results))
        return results

    def close(self):
        pass


def get_pdu_controller(controller_ip, pdu):
    """
    @summary: Factory function to create the actual PDU controller object.
    @return: The actual PDU controller object. Returns None if something went wrong.
    """
    return snmpPduController(controller_ip, pdu)
