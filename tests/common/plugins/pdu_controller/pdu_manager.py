"""
    PduManager is intended to solve the issue where DUT connects to
    multiple PDU controllers.

    It also intended to hide the dependency on the fake outlet_id,
    and reference outlet buy outlet dictionary directly. With this,
    we could enable different way to identify outlet, e.g. with the
    outlet number from graph.

    It also intended to create a smooth transition from defining
    PDU in inventory to defining PDU in connection graph. Data in
    graph is preferred, but if graph data is missing, existing
    inventory data will be used.

    PDU manager implements the same base PDU controller APIs and
    collect status from and distribute operations to individual PDU
    controllers.
"""

import logging
import pysnmp
if pysnmp.version[0] >= 5:
    # Use pysnmp 5.x+ compatible implementation (includes 7.x)
    from .snmp_pdu_controllers import get_pdu_controller
else:
    # Use pysnmp 4.x compatible implementation
    from .snmp_pdu_controllers_legacy import get_pdu_controller

logger = logging.getLogger(__name__)


class PSU():

    def __init__(self, psu_name, dut_name):
        self.psu_name = psu_name
        self.dut_name = dut_name

    def build_psu(self, psu_peer, pdu_info, pdu_vars):
        self.feeds = {}
        for feed_name, psu_peer_of_feed in psu_peer.items():
            feed = Feed(self, feed_name)
            if feed.build_feed(psu_peer_of_feed, pdu_info, pdu_vars):
                self.feeds[feed_name] = feed
        return len(self.feeds) > 0


class Feed():

    controllers = {}

    def __init__(self, psu, feed_name):
        self.psu = psu
        self.feed_name = feed_name

    def build_feed(self, psu_peer_of_feed, pdu_info, pdu_vars):
        if "peerdevice" not in psu_peer_of_feed:
            logger.warning('PSU {} feed {} is missing peer device'.format(self.psu.psu_name, self.feed_name))
            return False
        pdu_device = psu_peer_of_feed["peerdevice"]
        if pdu_device not in pdu_info or pdu_device not in pdu_vars:
            logger.warning("pdu device {} is missing in pdu_info or pdu_vars".format(pdu_device))
            return False
        pdu_info_of_peer = pdu_info[pdu_device]
        pdu_vars_of_peer = pdu_vars[pdu_device]
        if 'ManagementIp' not in pdu_info_of_peer or 'Protocol' not in pdu_info_of_peer:
            logger.warning('PSU {} feed {} is missing critical information ManagementIp or Protocol'.format(
                self.psu.psu_name, self.feed_name))
            return False
        if pdu_info_of_peer['Protocol'] != 'snmp':
            logger.warning('Protocol {} is currently not supported'.format(pdu_info_of_peer['Protocol']))
            return False
        self.pdu_info = pdu_info_of_peer
        self.pdu_vars = pdu_vars_of_peer
        if not self._build_controller():
            return False
        outlet = None
        # if peerport is probing/not given, return status of all ports on the pdu
        peerport = psu_peer_of_feed.get('peerport', 'probing')
        if peerport != 'probing':
            outlet = peerport if peerport.startswith('.') else '.' + peerport
        outlets = self.controller.get_outlet_status(hostname=self.psu.dut_name, outlet=outlet)
        for outlet in outlets:
            outlet['pdu_name'] = pdu_device
            outlet['psu_name'] = self.psu.psu_name
            outlet['feed_name'] = self.feed_name
        self.outlets = outlets
        return len(self.outlets) > 0

    def _build_controller(self):
        ip = self.pdu_info["ManagementIp"]
        if ip in Feed.controllers:
            self.controller = Feed.controllers[ip]
        else:
            self.controller = get_pdu_controller(ip, self.pdu_vars, self.pdu_info["HwSku"], self.pdu_info["Type"])
            if not self.controller:
                logger.warning('Failed creating pdu controller: {}'.format(self.pdu_info))
                return False
            Feed.controllers[ip] = self.controller
        return True


class PduManager():

    def __init__(self, dut_hostname):
        """
            dut_hostname is the target DUT host name. The dut
            defines which PDU(s) and outlet(s) it connected to.

            It is NOT the PDU host name. PDU host name is defined
            either in graph or in inventory and associated with
            the DUT.
        """
        self.dut_hostname = dut_hostname
        """
        A PSU instance represents a PSU. A PSU can have multiple feeds,
        where all of them contributes to the status of one PSU.
        """
        self.PSUs = {}

    def add_controller(self, psu_name, psu_peer, pdu_info, pdu_vars):
        """
            Add a controller to be managed.
            Sample psu_peer:
            {
                "A": {
                    "peerdevice": "pdu-107",
                    "peerport": "39",
                }
            }
        """
        psu = PSU(psu_name, self.dut_hostname)
        if not psu.build_psu(psu_peer, pdu_info, pdu_vars):
            return
        self.PSUs[psu_name] = psu

    def _get_controller(self, outlet):
        return self.PSUs[outlet['psu_name']].feeds[outlet['feed_name']].controller

    def turn_on_outlet(self, outlet=None):
        """
            Turnning on an outlet. The outlet contains enough information
            to identify the pdu controller + outlet ID.
            when outlet is None, all outlets will be turned off.
        """
        if outlet is not None:
            return self._get_controller(outlet).turn_on_outlet(outlet['outlet_id'])
        else:
            # turn on all outlets
            ret = True
            for psu_name, psu in self.PSUs.items():
                for feed_name, feed in psu.feeds.items():
                    for outlet in feed.outlets:
                        rc = self._get_controller(outlet).turn_on_outlet(outlet['outlet_id'])
                        ret = ret and rc
            return ret

    def turn_off_outlet(self, outlet=None):
        """
            Turnning off an outlet. The outlet contains enough information
            to identify the pdu controller + outlet ID.
            when outlet is None, all outlets will be turned off.
        """
        if outlet is not None:
            return self._get_controller(outlet).turn_off_outlet(outlet['outlet_id'])
        else:
            # turn on all outlets
            ret = True
            for psu_name, psu in self.PSUs.items():
                for feed_name, feed in psu.feeds.items():
                    for outlet in feed.outlets:
                        rc = self._get_controller(outlet).turn_off_outlet(outlet['outlet_id'])
                        ret = ret and rc
            return ret

    def get_outlet_status(self, outlet=None):
        """
            Getting outlet status. The outlet contains enough information
            to identify the pdu controller + outlet ID.
            when outlet is None, status of all outlets will be returned.
        """
        status = []
        if outlet is not None:
            outlets = self._get_controller(outlet).get_outlet_status(outlet=outlet['outlet_id'])
            pdu_name = outlet['pdu_name']
            psu_name = outlet['psu_name']
            feed_name = outlet['feed_name']
            for outlet in outlets:
                outlet['pdu_name'] = pdu_name
                outlet['psu_name'] = psu_name
                outlet['feed_name'] = feed_name
            status = status + outlets
        else:
            # collect all status
            for psu_name, psu in self.PSUs.items():
                for feed_name, feed in psu.feeds.items():
                    for outlet in feed.outlets:
                        pdu_name = outlet['pdu_name']
                        outlets = feed.controller.get_outlet_status(outlet=outlet['outlet_id'])
                        for outlet in outlets:
                            outlet['pdu_name'] = pdu_name
                            outlet['psu_name'] = psu_name
                            outlet['feed_name'] = feed_name
                        status = status + outlets
        return status

    def close(self):
        for controller in Feed.controllers.values():
            controller.close()


def _build_pdu_manager(pduman, pdu_links, pdu_info, pdu_vars):
    logger.info('Creating pdu manager')

    for psu_name, psu_peer in list(pdu_links.items()):
        pduman.add_controller(psu_name, psu_peer, pdu_info, pdu_vars)

    return len(pduman.PSUs) > 0


def pdu_manager_factory(dut_hostname, pdu_links, pdu_info, pdu_vars):
    """
    factory method had 3 major inputs, pdu_hosts and pdu_vars are used for
    building from inventory, and conn_graph_facts and pdu_vars are used for building
    from graph. Building from graph takes structured data of psu, feed, and its peer
    info from conn_graph_facts, while the old building from inventory takes flat data
    of pdu name and its info. To accomodate this, 3 input will be reformatted to 3,
    the first one being pdu_links, structured as psu, feed, peer pdu info. Second
    one being pdu_info, which contains management ip, type, etc.. Third pdu_vars, which
    is a mapping of pdu_names and inventory variables. Data processing should be done
    before factory method is called.
    @summary: Factory function for creating PDU manager instance.
    @param dut_hostname: DUT host name.
    @param pdu_links: structured data of psu, feed, peer pdu info.
    @param pdu_info: a ductionary of pdu hostname and its info
    @param pdu_vars: a dictionary of pdu hostname and its inv variables
    """
    logger.info('Creating pdu manager object')
    pduman = PduManager(dut_hostname)
    if _build_pdu_manager(pduman, pdu_links, pdu_info, pdu_vars):
        return pduman

    return None
