#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic dhcp_snooping fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.dhcp_snooping.dhcp_snooping import Dhcp_snoopingArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError


class Dhcp_snoopingFacts(object):
    """ The sonic dhcp_snooping fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Dhcp_snoopingArgs.argument_spec
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
        """ Populate the facts for dhcp_snooping
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            data = self.get_dhcp_snooping()

        obj = self.render_config(self.generated_spec, data)

        ansible_facts['ansible_network_resources'].pop('dhcp_snooping', None)
        facts = {}
        if obj:
            params = utils.validate_config(self.argument_spec, {'config': obj})
            params_cleaned = {'config': utils.remove_empties(params['config'])}
            facts['dhcp_snooping'] = params_cleaned['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_dhcp_snooping(self):
        config = {}

        config['top_level'] = self.get_dhcp_snooping_top_level()
        config['binding'] = self.get_dhcp_snooping_binding()

        return config

    def get_dhcp_snooping_top_level(self):
        """Get all DHCP snooping configurations available in chassis"""
        dhcp_snooping_path = 'data/openconfig-dhcp-snooping:dhcp-snooping'
        method = 'GET'
        request = [{'path': dhcp_snooping_path, 'method': method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        config = {}
        if (response[0][1].get('openconfig-dhcp-snooping:dhcp-snooping')):
            config = response[0][1].get('openconfig-dhcp-snooping:dhcp-snooping')

        return config

    def get_dhcp_snooping_binding(self):
        dhcp_binding_snooping_path = 'data/openconfig-dhcp-snooping:dhcp-snooping-binding'
        method = 'GET'
        request = [{'path': dhcp_binding_snooping_path, 'method': method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        config = {}
        if (response[0][1].get('openconfig-dhcp-snooping:dhcp-snooping-binding')):
            config = response[0][1].get('openconfig-dhcp-snooping:dhcp-snooping-binding')

        return config

    def render_config(self, spec, conf):
        """
        Render config as dictionary structure and delete keys
          from spec for null values

        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        config = deepcopy(spec)

        v4 = {'afi': 'ipv4'}
        v6 = {'afi': 'ipv6'}
        config['afis'] = [v4, v6]

        # Start with the top-level config from the device.
        top_level = conf.get('top_level', {})

        # Transform the "config" dict from the top-level device config.
        deviceConfig = top_level.get('config', {})

        v4_enabled = deviceConfig.get('dhcpv4-admin-enable', None)
        if v4_enabled:
            v4['enabled'] = True
        else:
            v4['enabled'] = False
        v6_enabled = deviceConfig.get('dhcpv6-admin-enable', None)
        if v6_enabled:
            v6['enabled'] = True
        else:
            v6['enabled'] = False

        v4_verify_mac = deviceConfig.get('dhcpv4-verify-mac-address', None)
        if v4_verify_mac is False:
            v4['verify_mac'] = False
        else:
            v4['verify_mac'] = True
        v6_verify_mac = deviceConfig.get('dhcpv6-verify-mac-address', None)
        if v6_verify_mac is False:
            v6['verify_mac'] = False
        else:
            v6['verify_mac'] = True

        # Transform the "state" dict from the top-level device config.
        state = top_level.get('state', {})

        v4_vlans = state.get('dhcpv4-snooping-vlan', [])
        if len(v4_vlans) > 0:
            v4['vlans'] = v4_vlans
        v6_vlans = state.get('dhcpv6-snooping-vlan', [])
        if len(v6_vlans) > 0:
            v6['vlans'] = v6_vlans

        STANDARD_ETH = "Eth"
        PC = 'PortChannel'
        v4_trusted_intf = state.get('dhcpv4-trusted-intf', [])
        if len(v4_trusted_intf) > 0:
            v4['trusted'] = []
            for intfName in v4_trusted_intf:
                intf = {}
                if intfName.startswith(STANDARD_ETH) or intfName.startswith(PC):
                    intf['intf_name'] = intfName
                else:
                    continue
                v4['trusted'].append(intf)
        v6_trusted_intf = state.get('dhcpv6-trusted-intf', [])
        if len(v6_trusted_intf) > 0:
            v6['trusted'] = []
            for intfName in v6_trusted_intf:
                intf = {}
                if intfName.startswith(STANDARD_ETH) or intfName.startswith(PC):
                    intf['intf_name'] = intfName
                else:
                    continue
                v6['trusted'].append(intf)

        # Transform the binding config from the device.
        binding = conf.get('binding', {})
        binding_list_container = binding.get('dhcp-snooping-binding-entry-list', {})
        binding_list = binding_list_container.get('dhcp-snooping-binding-list', [])
        if len(binding_list) > 0:
            v4_entries = []
            v6_entries = []
            for entry in binding_list:
                binding = {}
                binding['mac_addr'] = entry['mac']
                binding['ip_addr'] = entry['state']['ipaddress']
                binding['intf_name'] = entry['state']['intf']
                binding['vlan_id'] = entry['state']['vlan']
                if entry['iptype'] == 'ipv4':
                    v4_entries.append(binding)
                elif entry['iptype'] == 'ipv6':
                    v6_entries.append(binding)
            if len(v4_entries) > 0:
                v4['source_bindings'] = v4_entries
            if len(v6_entries) > 0:
                v6['source_bindings'] = v6_entries

        return config
