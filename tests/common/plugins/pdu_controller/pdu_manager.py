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
import copy
from snmp_pdu_controllers import get_pdu_controller

logger = logging.getLogger(__name__)


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
            controlers is an array of controller dictionaries with
            following information:
            {
                'psu_name'   : name of the PSU on DUT,
                'host'       : controller_IP_address,
                'controller' : controller instance,
                'outlets'    : cached outlet status,
                'psu_peer'   : psu peer information,
            }
        """
        self.controllers = []

    def _update_outlets(self, outlets, pdu_index, controller_index=None):
        for outlet_idx, outlet in enumerate(outlets):
            outlet['pdu_index'] = pdu_index + outlet_idx
            if controller_index is None:
                controller_index = pdu_index
            outlet['pdu_name'] = self.controllers[controller_index]['psu_peer']['peerdevice']

    def add_controller(self, psu_name, psu_peer, pdu_vars):
        """
            Add a controller to be managed.
            Sampel psu_peer:
            {
                "peerdevice": "pdu-107",
                "HwSku": "Sentry",
                "Protocol": "snmp",
                "ManagementIp": "10.0.0.107",
                "Type": "Pdu",
                "peerport": "39"
            }
        """
        if 'Protocol' not in psu_peer or 'ManagementIp' not in psu_peer:
            logger.info('psu_peer {} missing critical inforamtion'.format(psu_peer))
            return

        if psu_peer['Protocol'] != 'snmp':
            logger.warning('Controller protocol {} is not supported'.format(protocol))
            return

        controller = None
        pdu_ip = psu_peer['ManagementIp']
        shared_pdu = False
        for pdu in self.controllers:
            if psu_name in pdu:
                logger.warning('PSU {} already has a pdu definition'.format(psu_name))
                return
            if pdu_ip == pdu['host']:
                shared_pdu = True  # Sharing controller with another outlet
                controller = pdu['controller']

        outlets = []
        pdu = {
            'psu_name': psu_name,
                'host': pdu_ip,
                'controller': controller,
                'outlets': outlets,
                'psu_peer': psu_peer,
        }
        next_index = len(self.controllers)
        self.controllers.append(pdu)

        outlet = None
        if 'peerport' in psu_peer and psu_peer['peerport'] != 'probing':
            outlet = psu_peer['peerport'] if psu_peer['peerport'].startswith('.') else '.' + psu_peer['peerport']

        if not (shared_pdu and outlet is None):
            if controller is None:
                controller = get_pdu_controller(pdu_ip, pdu_vars)
                if not controller:
                    logger.warning('Failed creating pdu controller: {}'.format(psu_peer))
                    return

            outlets = controller.get_outlet_status(hostname=self.dut_hostname, outlet=outlet)
            self._update_outlets(outlets, next_index)
            pdu['outlets'] = outlets
            pdu['controller'] = controller

    def _get_pdu_controller(self, pdu_index):
        pdu = self.controllers[pdu_index]
        return pdu['controller']

    def turn_on_outlet(self, outlet=None):
        """
            Turnning on an outlet. The outlet contains enough information
            to identify the pdu controller + outlet ID.
            when outlet is None, all outlets will be turned off.
        """
        if outlet is not None:
            controller = self._get_pdu_controller(outlet['pdu_index'])
            return controller.turn_on_outlet(outlet['outlet_id'])
        else:
            # turn on all outlets
            ret = True
            for controller in self.controllers:
                for outlet in controller['outlets']:
                    rc = controller['controller'].turn_on_outlet(outlet['outlet_id'])
                    ret = ret and rc

        return ret

    def turn_off_outlet(self, outlet=None):
        """
            Turnning off an outlet. The outlet contains enough information
            to identify the pdu controller + outlet ID.
            when outlet is None, all outlets will be turned off.
        """
        if outlet is not None:
            controller = self._get_pdu_controller(outlet['pdu_index'])
            return controller.turn_off_outlet(outlet['outlet_id'])
        else:
            # turn on all outlets
            ret = True
            for controller in self.controllers:
                for outlet in controller['outlets']:
                    rc = controller['controller'].turn_off_outlet(outlet['outlet_id'])
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
            pdu_index = outlet['pdu_index']
            controller = self._get_pdu_controller(pdu_index)
            outlets = controller.get_outlet_status(outlet=outlet['outlet_id'])
            self._update_outlets(outlets, pdu_index)
            status = status + outlets
        else:
            # collect all status
            for controller_index, controller in enumerate(self.controllers):
                for outlet in controller['outlets']:
                    outlets = controller['controller'].get_outlet_status(outlet=outlet['outlet_id'])
                    self._update_outlets(outlets, outlet['pdu_index'], controller_index)
                    status = status + outlets

        return status

    def close(self):
        for controller in self.controllers:
            if len(controller['outlets']) > 0:
                controller['controller'].close()


def _merge_dev_link(devs, links):
    ret = copy.deepcopy(devs)
    for host, info in links.items():
        if host not in ret:
            ret[host] = {}

        for key, val in info.items():
            if key not in ret[host]:
                ret[host][key] = {}
            ret[host][key]=dict(ret[host][key], **val)

    return ret


def _build_pdu_manager_from_graph(pduman, dut_hostname, conn_graph_facts, pdu_vars):
    logger.info('Creating pdu manager from graph information')
    pdu_devs = conn_graph_facts['device_pdu_info']
    pdu_links = conn_graph_facts['device_pdu_links']
    pdu_info = _merge_dev_link(pdu_devs, pdu_links)
    if dut_hostname not in pdu_info or not pdu_info[dut_hostname]:
        # No PDU information in graph
        logger.info('PDU informatin for {} is not found in graph'.format(dut_hostname))
        return False

    for psu_name, psu_peer in pdu_info[dut_hostname].items():
        pduman.add_controller(psu_name, psu_peer, pdu_vars)

    return len(pduman.controllers) > 0


def _build_pdu_manager_from_inventory(pduman, dut_hostname, pdu_hosts, pdu_vars):
    logger.info('Creating pdu manager from inventory information')
    if not pdu_hosts:
        logger.info('Do not have sufficient PDU information to create PDU manager for host {}'.format(dut_hostname))
        return False

    for ph, var_list in pdu_hosts.items():
        controller_ip = var_list.get("ansible_host")
        if not controller_ip:
            logger.info('No "ansible_host" is defined in inventory file for "{}"'.format(pdu_hosts))
            logger.info('Unable to create pdu_controller for {}'.format(dut_hostname))
            continue

        controller_protocol = var_list.get("protocol")
        if not controller_protocol:
            logger.info(
                'No protocol is defined in inventory file for "{}". Try to use default "snmp"'.format(pdu_hosts))
            controller_protocol = 'snmp'

        psu_peer = {
            'peerdevice': ph,
                        'HwSku': 'unknown',
                        'Protocol': controller_protocol,
                        'ManagementIp': controller_ip,
                        'Type': 'Pdu',
                        'peerport': 'probing',
        }
        pduman.add_controller(ph, psu_peer, pdu_vars)

    return len(pduman.controllers) > 0


def pdu_manager_factory(dut_hostname, pdu_hosts, conn_graph_facts, pdu_vars):
    """
    @summary: Factory function for creating PDU manager instance.
    @param dut_hostname: DUT host name.
    @param pdu_hosts: comma separated PDU host names.
    @param conn_graph_facts: connection graph facts.
    @param pdu_vars: pdu community strings
    """
    logger.info('Creating pdu manager object')
    pduman = PduManager(dut_hostname)
    if _build_pdu_manager_from_graph(pduman, dut_hostname, conn_graph_facts, pdu_vars):
        return pduman

    if _build_pdu_manager_from_inventory(pduman, dut_hostname, pdu_hosts, pdu_vars):
        return pduman

    return None
