#
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic vxlans fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.vxlans.vxlans import VxlansArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class VxlansFacts(object):
    """ The sonic vxlans fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = VxlansArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for vxlans
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section ^interface')
            # using mock data instead
            data = self.get_all_vxlans()

        objs = []
        for conf in data:
            if conf:
                objs.append(conf)

        ansible_facts['ansible_network_resources'].pop('vxlans', None)
        facts = {}
        if objs:
            facts['vxlans'] = []
            params = utils.validate_config(self.argument_spec, {'config': objs})
            if params:
                facts['vxlans'].extend(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)

        return ansible_facts

    def get_all_vxlans(self):
        vxlans = []
        vxlan_tunnels = []
        vxlan_vlan_map = []
        suppress_vlans = []

        vxlans_tunnels_vlan_map = self.get_all_vxlans_tunnels_vlan_map()
        vxlans_evpn_nvo_list = self.get_all_vxlans_evpn_nvo_list()

        if vxlans_tunnels_vlan_map.get('VXLAN_TUNNEL'):
            if vxlans_tunnels_vlan_map['VXLAN_TUNNEL'].get('VXLAN_TUNNEL_LIST'):
                vxlan_tunnels.extend(vxlans_tunnels_vlan_map['VXLAN_TUNNEL']['VXLAN_TUNNEL_LIST'])

        if vxlans_tunnels_vlan_map.get('VXLAN_TUNNEL_MAP'):
            if vxlans_tunnels_vlan_map['VXLAN_TUNNEL_MAP'].get('VXLAN_TUNNEL_MAP_LIST'):
                vxlan_vlan_map.extend(vxlans_tunnels_vlan_map['VXLAN_TUNNEL_MAP']['VXLAN_TUNNEL_MAP_LIST'])

        if vxlans_tunnels_vlan_map.get('SUPPRESS_VLAN_NEIGH'):
            if vxlans_tunnels_vlan_map['SUPPRESS_VLAN_NEIGH'].get('SUPPRESS_VLAN_NEIGH_LIST'):
                suppress_vlans.extend(vxlans_tunnels_vlan_map['SUPPRESS_VLAN_NEIGH']['SUPPRESS_VLAN_NEIGH_LIST'])

        self.fill_tunnel_source_ip(vxlans, vxlan_tunnels, vxlans_evpn_nvo_list)
        self.fill_vlan_map(vxlans, vxlan_vlan_map)

        vxlan_vrf_list = self.get_all_vxlans_vrf_list()
        self.fill_vrf_map(vxlans, vxlan_vrf_list)

        self.fill_suppress_vlan_neigh(vxlans, suppress_vlans)

        return vxlans

    def get_all_vxlans_vrf_list(self):
        """Get all the vxlan tunnels and vlan map available """
        request = [{"path": "data/sonic-vrf:sonic-vrf/VRF/VRF_LIST", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        vxlan_vrf_list = {}
        if "sonic-vrf:VRF_LIST" in response[0][1]:
            vxlan_vrf_list = response[0][1].get("sonic-vrf:VRF_LIST", {})

        return vxlan_vrf_list

    def get_all_vxlans_evpn_nvo_list(self):
        """Get all the evpn nvo list available """
        request = [{"path": "data/sonic-vxlan:sonic-vxlan/EVPN_NVO/EVPN_NVO_LIST", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        vxlans_evpn_nvo_list = []
        if "sonic-vxlan:EVPN_NVO_LIST" in response[0][1]:
            vxlans_evpn_nvo_list = response[0][1].get("sonic-vxlan:EVPN_NVO_LIST", [])

        return vxlans_evpn_nvo_list

    def get_all_vxlans_tunnels_vlan_map(self):
        """Get all the vxlan tunnels and vlan map available """
        request = [{"path": "data/sonic-vxlan:sonic-vxlan", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        vxlans_tunnels_vlan_map = {}
        if "sonic-vxlan:sonic-vxlan" in response[0][1]:
            vxlans_tunnels_vlan_map = response[0][1].get("sonic-vxlan:sonic-vxlan", {})

        return vxlans_tunnels_vlan_map

    def fill_tunnel_source_ip(self, vxlans, vxlan_tunnels, vxlans_evpn_nvo_list):
        for each_tunnel in vxlan_tunnels:
            vxlan = {}
            vxlan['name'] = each_tunnel['name']
            vxlan['source_ip'] = each_tunnel.get('src_ip', None)
            vxlan['primary_ip'] = each_tunnel.get('primary_ip', None)
            vxlan["external_ip"] = each_tunnel.get('external_ip', None)
            vxlan['evpn_nvo'] = None
            evpn_nvo = next((nvo_map['name'] for nvo_map in vxlans_evpn_nvo_list if nvo_map['source_vtep'] == vxlan['name']), None)
            if evpn_nvo:
                vxlan['evpn_nvo'] = evpn_nvo
            vxlans.append(vxlan)

    def fill_vlan_map(self, vxlans, vxlan_vlan_map):
        for each_vlan_map in vxlan_vlan_map:
            name = each_vlan_map['name']
            matched_vtep = next((each_vxlan for each_vxlan in vxlans if each_vxlan['name'] == name), None)
            if matched_vtep:
                vni = int(each_vlan_map['vni'])
                vlan = int(each_vlan_map['vlan'][4:])
                vlan_map = matched_vtep.get('vlan_map')
                if vlan_map:
                    vlan_map.append({'vni': vni, 'vlan': vlan})
                else:
                    matched_vtep['vlan_map'] = [{'vni': vni, 'vlan': vlan}]

    def fill_vrf_map(self, vxlans, vxlan_vrf_list):
        for each_vrf in vxlan_vrf_list:
            vni = each_vrf.get('vni', None)
            if vni is None:
                continue

            matched_vtep = None
            if vxlans:
                # SONIC supports only one VxLan interface.
                matched_vtep = vxlans[0]

            if matched_vtep:
                vni = int(each_vrf['vni'])
                vrf = each_vrf['vrf_name']
                vrf_map = matched_vtep.get('vrf_map')
                if vrf_map:
                    vrf_map.append({'vni': vni, 'vrf': vrf})
                else:
                    matched_vtep['vrf_map'] = [{'vni': vni, 'vrf': vrf}]

    def fill_suppress_vlan_neigh(self, vxlans, suppress_vlans):
        suppress_vlan_neigh = {}
        suppress_vlan_neigh_list = []
        for each_suppress_vlan_neigh in suppress_vlans:
            name = each_suppress_vlan_neigh.get('name', None)
            if name is None:
                continue
            matched_suppress_vn = None
            if vxlans:
                matched_suppress_vn = vxlans[0]

            if matched_suppress_vn:
                suppress_vlan_neigh = matched_suppress_vn.get('suppress_vlan_neigh')
                if suppress_vlan_neigh:
                    suppress_vlan_neigh.append({'vlan_name': name})
                else:
                    matched_suppress_vn['suppress_vlan_neigh'] = [{'vlan_name': name}]
