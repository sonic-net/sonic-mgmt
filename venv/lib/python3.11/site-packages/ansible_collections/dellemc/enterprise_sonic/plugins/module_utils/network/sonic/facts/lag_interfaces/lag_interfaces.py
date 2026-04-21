#
# -*- coding: utf-8 -*-
# Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic lag_interfaces fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.lag_interfaces.lag_interfaces import Lag_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"
ESI_TYPE_PAYLOAD_TO_VALUE = {
    'TYPE_0_OPERATOR_CONFIGURED': 'ethernet_segment_id',
    'TYPE_1_LACP_BASED': 'auto_lacp',
    'TYPE_3_MAC_BASED': 'auto_system_mac'
}


class Lag_interfacesFacts(object):
    """ The sonic lag_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Lag_interfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_all_portchannels(self):
        """Get all the interfaces available in chassis"""
        request = [{"path": "data/sonic-portchannel:sonic-portchannel", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if response[0][1]:
            data = response[0][1]['sonic-portchannel:sonic-portchannel']
        else:
            data = []

        return data

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for lag_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []
        if not data:
            data = self.get_all_portchannels()
            data = self.transform_config(data)

        for conf in data:
            if conf:
                objs.append(conf)

        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['lag_interfaces'] = utils.remove_empties({'config': params['config']})['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def transform_config(self, conf):
        po_data = {}
        if 'PORTCHANNEL' in conf and conf['PORTCHANNEL'].get('PORTCHANNEL_LIST'):
            for po in conf['PORTCHANNEL']['PORTCHANNEL_LIST']:
                po_data[po['name']] = {
                    'name': po['name'],
                    'members': {'interfaces': []}
                }

                if po.get('static'):
                    po_data[po['name']]['mode'] = 'static'
                else:
                    po_data[po['name']]['mode'] = 'lacp'
                    if po.get('lacp_individual'):
                        po_data[po['name']]['lacp_individual'] = {'enable': True if po['lacp_individual'] == 'enable' else False}
                    if po.get('lacp_individual_timeout'):
                        po_data[po['name']].setdefault('lacp_individual', {})
                        po_data[po['name']]['lacp_individual']['timeout'] = po['lacp_individual_timeout']

                if po.get('graceful_shutdown_mode'):
                    po_data[po['name']]['graceful_shutdown'] = True if po['graceful_shutdown_mode'] == 'ENABLE' else False
                for option in ('fallback', 'fast_rate', 'min_links', 'system_mac'):
                    if po.get(option) is not None:
                        po_data[po['name']][option] = po[option]

        if 'PORTCHANNEL_MEMBER' in conf and conf['PORTCHANNEL_MEMBER'].get('PORTCHANNEL_MEMBER_LIST'):
            for po_member in conf['PORTCHANNEL_MEMBER']['PORTCHANNEL_MEMBER_LIST']:
                if po_member['name'] in po_data:
                    po_data[po_member['name']]['members']['interfaces'].append({'member': po_member['ifname']})

        if 'EVPN_ETHERNET_SEGMENT' in conf and conf['EVPN_ETHERNET_SEGMENT'].get('EVPN_ETHERNET_SEGMENT_LIST'):
            for eth_segment in conf['EVPN_ETHERNET_SEGMENT']['EVPN_ETHERNET_SEGMENT_LIST']:
                if eth_segment['ifname'] in po_data:
                    po_data[eth_segment['ifname']]['ethernet_segment'] = {}
                    if eth_segment.get('esi_type'):
                        po_data[eth_segment['ifname']]['ethernet_segment']['esi_type'] = ESI_TYPE_PAYLOAD_TO_VALUE.get(eth_segment['esi_type'])
                    po_data[eth_segment['ifname']]['ethernet_segment']['esi'] = eth_segment.get('esi')
                    po_data[eth_segment['ifname']]['ethernet_segment']['df_preference'] = eth_segment.get('df_pref')

        return list(po_data.values())
