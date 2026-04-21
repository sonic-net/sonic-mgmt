#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic dhcp_relay fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.dhcp_relay.dhcp_relay import Dhcp_relayArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

SELECT_VALUE_TO_BOOL = {
    'ENABLE': True,
    'DISABLE': False
}


class Dhcp_relayFacts(object):
    """ The sonic dhcp_relay fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Dhcp_relayArgs.argument_spec
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
        """ Populate the facts for dhcp_relay
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            dhcp_relay_configs = self.get_dhcp_relay()
            dhcpv6_relay_configs = self.get_dhcpv6_relay()

            all_relay_configs = {}
            for intf_name, dhcp_relay_config in dhcp_relay_configs.items():
                all_relay_configs[intf_name] = {}
                all_relay_configs[intf_name]['ipv4'] = dhcp_relay_config

            for intf_name, dhcpv6_relay_config in dhcpv6_relay_configs.items():
                if all_relay_configs.get(intf_name):
                    all_relay_configs[intf_name]['ipv6'] = dhcpv6_relay_config
                else:
                    all_relay_configs[intf_name] = {}
                    all_relay_configs[intf_name]['ipv6'] = dhcpv6_relay_config

        objs = []
        for relay_config in all_relay_configs.items():
            obj = self.render_config(self.generated_spec, relay_config)
            if obj:
                objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('dhcp_relay', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['dhcp_relay'] = utils.remove_empties({'config': params['config']})['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

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
        config['name'] = conf[0]

        if conf[1].get('ipv4'):
            ipv4_dict = conf[1]['ipv4']
            if ipv4_dict.get('policy_action'):
                ipv4_dict['policy_action'] = ipv4_dict['policy_action'].lower()

            ipv4_dict['link_select'] = SELECT_VALUE_TO_BOOL.get(ipv4_dict['link_select'])
            ipv4_dict['vrf_select'] = SELECT_VALUE_TO_BOOL.get(ipv4_dict['vrf_select'])

            config['ipv4'] = ipv4_dict
        else:
            config.pop('ipv4')

        if conf[1].get('ipv6'):
            ipv6_dict = conf[1]['ipv6']
            ipv6_dict['vrf_select'] = SELECT_VALUE_TO_BOOL.get(ipv6_dict['vrf_select'])

            config['ipv6'] = ipv6_dict
        else:
            config.pop('ipv6')

        return config

    def get_dhcp_relay(self):
        """Get all DHCP relay configurations available in chassis"""
        dhcp_relay_interfaces_path = 'data/openconfig-relay-agent:relay-agent/dhcp'
        method = 'GET'
        request = [{'path': dhcp_relay_interfaces_path, 'method': method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        dhcp_relay_interfaces = []
        if (response[0][1].get('openconfig-relay-agent:dhcp')
                and response[0][1]['openconfig-relay-agent:dhcp'].get('interfaces')):
            dhcp_relay_interfaces = response[0][1]['openconfig-relay-agent:dhcp']['interfaces'].get('interface', [])

        dhcp_relay_configs = {}
        for interface in dhcp_relay_interfaces:
            ipv4_dict = {}
            server_addresses = []

            config = interface.get('config', {})
            for address in config.get('helper-address', []):
                temp = {}
                temp['address'] = address
                server_addresses.append(temp)
            ipv4_dict['server_addresses'] = server_addresses

            ipv4_dict['max_hop_count'] = config.get('openconfig-relay-agent-ext:max-hop-count')
            ipv4_dict['policy_action'] = config.get('openconfig-relay-agent-ext:policy-action')
            ipv4_dict['source_interface'] = config.get('openconfig-relay-agent-ext:src-intf')
            ipv4_dict['vrf_name'] = config.get('openconfig-relay-agent-ext:vrf')

            opt_config = interface.get('agent-information-option', {}).get('config', {})
            ipv4_dict['circuit_id'] = opt_config.get('circuit-id')
            ipv4_dict['link_select'] = opt_config.get('openconfig-relay-agent-ext:link-select')
            ipv4_dict['vrf_select'] = opt_config.get('openconfig-relay-agent-ext:vrf-select')

            dhcp_relay_configs[interface['id']] = ipv4_dict

        return dhcp_relay_configs

    def get_dhcpv6_relay(self):
        """Get all DHCPv6 relay configurations available in chassis"""
        dhcpv6_relay_interfaces_path = 'data/openconfig-relay-agent:relay-agent/dhcpv6'
        method = 'GET'
        request = [{'path': dhcpv6_relay_interfaces_path, 'method': method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        dhcpv6_relay_interfaces = []
        if (response[0][1].get('openconfig-relay-agent:dhcpv6')
                and response[0][1]['openconfig-relay-agent:dhcpv6'].get('interfaces')):
            dhcpv6_relay_interfaces = response[0][1]['openconfig-relay-agent:dhcpv6']['interfaces'].get('interface', [])

        dhcpv6_relay_configs = {}
        for interface in dhcpv6_relay_interfaces:
            ipv6_dict = {}
            server_addresses = []

            config = interface.get('config', {})
            for address in config.get('helper-address', []):
                temp = {}
                temp['address'] = address
                server_addresses.append(temp)
            ipv6_dict['server_addresses'] = server_addresses

            ipv6_dict['max_hop_count'] = config.get('openconfig-relay-agent-ext:max-hop-count')
            ipv6_dict['source_interface'] = config.get('openconfig-relay-agent-ext:src-intf')
            ipv6_dict['vrf_name'] = config.get('openconfig-relay-agent-ext:vrf')

            opt_config = interface.get('options', {}).get('config', {})
            ipv6_dict['vrf_select'] = opt_config.get('openconfig-relay-agent-ext:vrf-select')

            dhcpv6_relay_configs[interface['id']] = ipv6_dict

        return dhcpv6_relay_configs
