#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_dhcp_relay class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    normalize_interface_name,
    get_normalize_interface_name,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'

DEFAULT_CIRCUIT_ID = '%p'
DEFAULT_MAX_HOP_COUNT = 10
DEFAULT_POLICY_ACTION = 'discard'

BOOL_TO_SELECT_VALUE = {
    True: 'ENABLE',
    False: 'DISABLE'
}


def __derive_dhcp_relay_address_delete_op(key_set, command, exist_conf):
    new_conf = exist_conf
    if command and command.get('address', None):
        return __DELETE_CONFIG_IF_NO_SUBCONFIG(key_set, command, exist_conf)
    else:
        return True, new_conf


TEST_KEYS_generate_config = [
    {'config': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'server_addresses': {'address': '', '__delete_op': __derive_dhcp_relay_address_delete_op}}
]


class Dhcp_relay(ConfigBase):
    """
    The sonic_dhcp_relay class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'dhcp_relay',
    ]

    dhcp_relay_intf_path = 'data/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface={intf_name}'
    dhcp_relay_intf_config_path = {
        'circuit_id': dhcp_relay_intf_path + '/agent-information-option/config/circuit-id',
        'link_select': dhcp_relay_intf_path + '/agent-information-option/config/openconfig-relay-agent-ext:link-select',
        'max_hop_count': dhcp_relay_intf_path + '/config/openconfig-relay-agent-ext:max-hop-count',
        'policy_action': dhcp_relay_intf_path + '/config/openconfig-relay-agent-ext:policy-action',
        'server_address': dhcp_relay_intf_path + '/config/helper-address={server_address}',
        'server_addresses_all': dhcp_relay_intf_path + '/config/helper-address',
        'source_interface': dhcp_relay_intf_path + '/config/openconfig-relay-agent-ext:src-intf',
        'vrf_name': dhcp_relay_intf_path + '/config/openconfig-relay-agent-ext:vrf',
        'vrf_select': dhcp_relay_intf_path + '/agent-information-option/config/openconfig-relay-agent-ext:vrf-select'
    }

    dhcpv6_relay_intf_path = 'data/openconfig-relay-agent:relay-agent/dhcpv6/interfaces/interface={intf_name}'
    dhcpv6_relay_intf_config_path = {
        'max_hop_count': dhcpv6_relay_intf_path + '/config/openconfig-relay-agent-ext:max-hop-count',
        'server_address': dhcpv6_relay_intf_path + '/config/helper-address={server_address}',
        'server_addresses_all': dhcpv6_relay_intf_path + '/config/helper-address',
        'source_interface': dhcpv6_relay_intf_path + '/config/openconfig-relay-agent-ext:src-intf',
        'vrf_name': dhcpv6_relay_intf_path + '/config/openconfig-relay-agent-ext:vrf',
        'vrf_select': dhcpv6_relay_intf_path + '/options/config/openconfig-relay-agent-ext:vrf-select'
    }

    def __init__(self, module):
        super(Dhcp_relay, self).__init__(module)

    def get_dhcp_relay_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        dhcp_relay_facts = facts['ansible_network_resources'].get('dhcp_relay')
        if not dhcp_relay_facts:
            return []
        return dhcp_relay_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []

        existing_dhcp_relay_facts = self.get_dhcp_relay_facts()
        commands, requests = self.set_config(existing_dhcp_relay_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        changed_dhcp_relay_facts = self.get_dhcp_relay_facts()

        result['before'] = existing_dhcp_relay_facts
        if result['changed']:
            result['after'] = changed_dhcp_relay_facts

        result['commands'] = commands

        new_config = changed_dhcp_relay_facts
        old_config = existing_dhcp_relay_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_dhcp_relay_facts,
                                        TEST_KEYS_generate_config)
            new_config = self.post_process_generated_config(new_config)
            result['after(generated)'] = new_config

        if self._module._diff:
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_dhcp_relay_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        want = self._module.params['config']
        if want:
            # In state deleted, specific empty parameters are supported
            if state != 'deleted':
                want = remove_empties_from_list(want)

            normalize_interface_name(want, self._module)
            for config in want:
                if config.get('ipv4') and config['ipv4'].get('source_interface'):
                    config['ipv4']['source_interface'] = get_normalize_interface_name(config['ipv4']['source_interface'], self._module)
                if config.get('ipv6') and config['ipv6'].get('source_interface'):
                    config['ipv6']['source_interface'] = get_normalize_interface_name(config['ipv6']['source_interface'], self._module)
        else:
            want = []

        have = existing_dhcp_relay_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        state = self._module.params['state']
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have)
        requests = self.get_modify_dhcp_dhcpv6_relay_requests(commands)
        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []
        if not want:
            commands = have
            requests.extend(self.get_delete_dhcp_dhcpv6_relay_completely_requests(commands))
        else:
            commands = want
            requests.extend(self.get_delete_dhcp_dhcpv6_relay_requests(commands, have))

        if len(requests) == 0:
            commands = []

        if commands:
            commands = update_states(commands, "deleted")

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        del_commands, del_requests = self.get_delete_commands_requests_for_replaced_overridden(want, have, 'replaced')
        if del_commands:
            new_have = get_diff(have, del_commands)
            commands = update_states(del_commands, 'deleted')
            requests = del_requests
        else:
            new_have = have

        add_commands = get_diff(want, new_have)
        if add_commands:
            commands.extend(update_states(add_commands, 'replaced'))
            requests.extend(self.get_modify_dhcp_dhcpv6_relay_requests(add_commands))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        del_commands, del_requests = self.get_delete_commands_requests_for_replaced_overridden(want, have, 'overridden')
        if del_commands:
            new_have = get_diff(have, del_commands)
            commands = update_states(del_commands, 'deleted')
            requests = del_requests
        else:
            new_have = have

        add_commands = get_diff(want, new_have)
        if add_commands:
            commands.extend(update_states(add_commands, 'overridden'))
            requests.extend(self.get_modify_dhcp_dhcpv6_relay_requests(add_commands))

        return commands, requests

    def get_modify_dhcp_dhcpv6_relay_requests(self, commands):
        """Get requests to modify DHCP and DHCPv6 relay configurations
        for all interfaces specified by the commands
        """
        requests = []

        for command in commands:
            if command.get('ipv4'):
                requests.extend(self.get_modify_specific_dhcp_relay_param_requests(command))
            if command.get('ipv6'):
                requests.extend(self.get_modify_specific_dhcpv6_relay_param_requests(command))

        return requests

    def get_modify_specific_dhcp_relay_param_requests(self, command):
        """Get requests to modify specific DHCP relay configurations
        based on the command specified for the interface
        """
        requests = []

        name = command['name']
        ipv4 = command.get('ipv4')
        if not ipv4:
            return requests

        # Specifying appropriate order for merge to succeed
        server_addresses = self.get_server_addresses(ipv4.get('server_addresses'))
        if server_addresses:
            payload = {'openconfig-relay-agent:helper-address': list(server_addresses)}
            url = self.dhcp_relay_intf_config_path['server_addresses_all'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv4.get('vrf_name'):
            payload = {'openconfig-relay-agent-ext:vrf': ipv4['vrf_name']}
            url = self.dhcp_relay_intf_config_path['vrf_name'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv4.get('source_interface'):
            payload = {'openconfig-relay-agent-ext:src-intf': ipv4['source_interface']}
            url = self.dhcp_relay_intf_config_path['source_interface'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv4.get('link_select') is not None:
            link_select = BOOL_TO_SELECT_VALUE[ipv4['link_select']]
            payload = {'openconfig-relay-agent-ext:link-select': link_select}
            url = self.dhcp_relay_intf_config_path['link_select'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv4.get('max_hop_count'):
            payload = {'openconfig-relay-agent-ext:max-hop-count': ipv4['max_hop_count']}
            url = self.dhcp_relay_intf_config_path['max_hop_count'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv4.get('vrf_select') is not None:
            vrf_select = BOOL_TO_SELECT_VALUE[ipv4['vrf_select']]
            payload = {'openconfig-relay-agent-ext:vrf-select': vrf_select}
            url = self.dhcp_relay_intf_config_path['vrf_select'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv4.get('policy_action'):
            payload = {'openconfig-relay-agent-ext:policy-action': ipv4['policy_action'].upper()}
            url = self.dhcp_relay_intf_config_path['policy_action'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv4.get('circuit_id'):
            payload = {'openconfig-relay-agent:circuit-id': ipv4['circuit_id']}
            url = self.dhcp_relay_intf_config_path['circuit_id'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_modify_specific_dhcpv6_relay_param_requests(self, command):
        """Get requests to modify specific DHCPv6 relay configurations
        based on the command specified for the interface
        """
        requests = []

        name = command['name']
        ipv6 = command.get('ipv6')
        if not ipv6:
            return requests

        # Specifying appropriate order for merge to succeed
        server_addresses = self.get_server_addresses(ipv6.get('server_addresses'))
        if server_addresses:
            payload = {'openconfig-relay-agent:helper-address': list(server_addresses)}
            url = self.dhcpv6_relay_intf_config_path['server_addresses_all'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv6.get('vrf_name'):
            payload = {'openconfig-relay-agent-ext:vrf': ipv6['vrf_name']}
            url = self.dhcpv6_relay_intf_config_path['vrf_name'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv6.get('source_interface'):
            payload = {'openconfig-relay-agent-ext:src-intf': ipv6['source_interface']}
            url = self.dhcpv6_relay_intf_config_path['source_interface'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv6.get('max_hop_count'):
            payload = {'openconfig-relay-agent-ext:max-hop-count': ipv6['max_hop_count']}
            url = self.dhcpv6_relay_intf_config_path['max_hop_count'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        if ipv6.get('vrf_select') is not None:
            vrf_select = BOOL_TO_SELECT_VALUE[ipv6['vrf_select']]
            payload = {'openconfig-relay-agent-ext:vrf-select': vrf_select}
            url = self.dhcpv6_relay_intf_config_path['vrf_select'].format(intf_name=name)
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_dhcp_dhcpv6_relay_completely_requests(self, have):
        """Get requests to delete all existing DHCP and DHCPv6 relay
        configurations in the chassis
        """
        requests = []
        for cfg in have:
            if cfg.get('ipv4'):
                requests.append(self.get_delete_all_dhcp_relay_intf_request(cfg['name']))
            if cfg.get('ipv6'):
                requests.append(self.get_delete_all_dhcpv6_relay_intf_request(cfg['name']))

        return requests

    def get_delete_dhcp_dhcpv6_relay_requests(self, commands, have):
        """Get requests to delete DHCP and DHCPv6 relay configurations
        based on the commands specified
        """
        requests = []

        for command in commands:
            intf_name = command['name']
            have_obj = next((cfg for cfg in have if cfg['name'] == intf_name), None)
            if not have_obj:
                continue

            have_ipv4 = have_obj.get('ipv4')
            have_ipv6 = have_obj.get('ipv6')

            ipv4 = command.get('ipv4')
            ipv6 = command.get('ipv6')
            if not ipv4 and not ipv6:
                if have_ipv4:
                    requests.append(self.get_delete_all_dhcp_relay_intf_request(intf_name))
                if have_ipv6:
                    requests.append(self.get_delete_all_dhcpv6_relay_intf_request(intf_name))
            else:
                if ipv4 and have_ipv4:
                    requests.extend(self.get_delete_specific_dhcp_relay_param_requests(command, have_obj))
                if ipv6 and have_ipv6:
                    requests.extend(self.get_delete_specific_dhcpv6_relay_param_requests(command, have_obj))

        return requests

    def get_delete_specific_dhcp_relay_param_requests(self, command, config, is_state_deleted=True):
        """Get requests to delete specific DHCP relay configurations
        based on the command specified for the interface
        """
        requests = []

        name = command['name']
        ipv4 = command.get('ipv4')
        have_ipv4 = config.get('ipv4')
        if not ipv4 or not have_ipv4:
            return requests

        server_addresses = self.get_server_addresses(ipv4.get('server_addresses'))
        have_server_addresses = self.get_server_addresses(have_ipv4.get('server_addresses'))

        # Delete all DHCP relay config for an interface, if only
        # a single server address with no value is specified.
        #
        # This "special" YAML sequence is supported to provide
        # "delete all AF parameters" functionality despite the Ansible
        # infrastructure limitations that prevent use of a simpler
        # syntax for deleting an entire AF parameter dictionary.
        if (ipv4.get('server_addresses') and len(ipv4.get('server_addresses'))
                and not server_addresses):
            requests.append(self.get_delete_all_dhcp_relay_intf_request(name))
            return requests

        del_server_addresses = have_server_addresses.intersection(server_addresses)
        if del_server_addresses:
            # Deleting all DHCP server addresses configured on an
            # interface automatically removes all DHCP relay config in
            # that interface. Therefore, seperate requests to delete
            # other DHCP relay configs are not required.
            if is_state_deleted and len(del_server_addresses) == len(have_server_addresses):
                requests.append(self.get_delete_all_dhcp_relay_intf_request(name))
                return requests

            for addr in del_server_addresses:
                url = self.dhcp_relay_intf_config_path['server_address'].format(intf_name=name, server_address=addr)
                requests.append({'path': url, 'method': DELETE})

        # Specifying appropriate order for deletion to succeed
        if ipv4.get('link_select') is not None and have_ipv4.get('link_select'):
            url = self.dhcp_relay_intf_config_path['link_select'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        if (ipv4.get('source_interface') and have_ipv4.get('source_interface')
                and ipv4['source_interface'] == have_ipv4['source_interface']):
            url = self.dhcp_relay_intf_config_path['source_interface'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        if (ipv4.get('max_hop_count') and have_ipv4.get('max_hop_count')
                and ipv4['max_hop_count'] == have_ipv4['max_hop_count']
                and have_ipv4['max_hop_count'] != DEFAULT_MAX_HOP_COUNT):
            url = self.dhcp_relay_intf_config_path['max_hop_count'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        if ipv4.get('vrf_select') is not None and have_ipv4.get('vrf_select'):
            url = self.dhcp_relay_intf_config_path['vrf_select'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        if (ipv4.get('policy_action') and have_ipv4.get('policy_action')
                and ipv4['policy_action'] == have_ipv4['policy_action']
                and have_ipv4['policy_action'] != DEFAULT_POLICY_ACTION):
            url = self.dhcp_relay_intf_config_path['policy_action'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        if (ipv4.get('circuit_id') and have_ipv4.get('circuit_id')
                and ipv4['circuit_id'] == have_ipv4['circuit_id']
                and have_ipv4['circuit_id'] != DEFAULT_CIRCUIT_ID):
            url = self.dhcp_relay_intf_config_path['circuit_id'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        return requests

    def get_delete_specific_dhcpv6_relay_param_requests(self, command, have, is_state_deleted=True):
        """Get requests to delete specific DHCPv6 relay configurations
        based on the command specified for the interface
        """
        requests = []

        name = command['name']
        ipv6 = command.get('ipv6')
        have_ipv6 = have.get('ipv6')
        if not ipv6 or not have_ipv6:
            return requests

        server_addresses = self.get_server_addresses(ipv6.get('server_addresses'))
        have_server_addresses = self.get_server_addresses(have_ipv6.get('server_addresses'))

        # Delete all DHCPv6 relay config for an interface, if only
        # a single server address with no value is specified.
        #
        # This "special" YAML sequence is supported to provide
        # "delete all AF parameters" functionality despite the Ansible
        # infrastructure limitations that prevent use of a simpler
        # syntax for deleting an entire AF parameter dictionary.
        if (ipv6.get('server_addresses') and len(ipv6.get('server_addresses'))
                and not server_addresses):
            requests.append(self.get_delete_all_dhcpv6_relay_intf_request(name))
            return requests

        del_server_addresses = have_server_addresses.intersection(server_addresses)
        if del_server_addresses:
            # Deleting all DHCPv6 server addresses configured on an
            # interface automatically removes all DHCPv6 relay config
            # in that interface. Therefore, seperate requests to delete
            # other DHCPv6 relay configs are not required.
            if is_state_deleted and len(del_server_addresses) == len(have_server_addresses):
                requests.append(self.get_delete_all_dhcpv6_relay_intf_request(name))
                return requests

            for addr in del_server_addresses:
                url = self.dhcpv6_relay_intf_config_path['server_address'].format(intf_name=name, server_address=addr)
                requests.append({'path': url, 'method': DELETE})

        # Specifying appropriate order for deletion to succeed
        if (ipv6.get('source_interface') and have_ipv6.get('source_interface')
                and ipv6['source_interface'] == have_ipv6['source_interface']):
            url = self.dhcpv6_relay_intf_config_path['source_interface'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        if (ipv6.get('max_hop_count') and have_ipv6.get('max_hop_count')
                and ipv6['max_hop_count'] == have_ipv6['max_hop_count']
                and have_ipv6['max_hop_count'] != DEFAULT_MAX_HOP_COUNT):
            url = self.dhcpv6_relay_intf_config_path['max_hop_count'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        if ipv6.get('vrf_select') is not None and have_ipv6.get('vrf_select'):
            url = self.dhcpv6_relay_intf_config_path['vrf_select'].format(intf_name=name)
            requests.append({'path': url, 'method': DELETE})

        return requests

    def get_delete_all_dhcp_relay_intf_request(self, intf_name):
        """Get request to delete all DHCP relay configurations in the
        specified interface
        """
        return {'path': self.dhcp_relay_intf_config_path['server_addresses_all'].format(intf_name=intf_name), 'method': DELETE}

    def get_delete_all_dhcpv6_relay_intf_request(self, intf_name):
        """Get request to delete all DHCPv6 relay configurations in the
        specified interface
        """
        return {'path': self.dhcpv6_relay_intf_config_path['server_addresses_all'].format(intf_name=intf_name), 'method': DELETE}

    def get_delete_commands_requests_for_replaced_overridden(self, want, have, state):
        """Returns the commands and requests necessary to remove applicable
        current configurations when state is replaced or overridden
        """
        default_value = {
            'circuit_id': DEFAULT_CIRCUIT_ID,
            'max_hop_count': DEFAULT_MAX_HOP_COUNT,
            'policy_action': DEFAULT_POLICY_ACTION
        }
        commands = []
        requests = []
        if not have:
            return commands, requests

        for conf in have:
            intf_name = conf['name']
            ipv4_conf = conf.get('ipv4')
            ipv6_conf = conf.get('ipv6')

            match_obj = next((cmd for cmd in want if cmd['name'] == intf_name), None)
            if not match_obj:
                # Delete all DHCP and DHCPv6 relay config for interfaces,
                # that are not specified in overridden.
                if state == 'overridden':
                    commands.append(conf)
                    if ipv4_conf:
                        requests.append(self.get_delete_all_dhcp_relay_intf_request(intf_name))
                    if ipv6_conf:
                        requests.append(self.get_delete_all_dhcpv6_relay_intf_request(intf_name))
                continue

            command = {'name': intf_name}
            if ipv4_conf:
                match_ipv4 = match_obj.get('ipv4')
                # Delete all DHCP relay config for an interface if not specified
                if not match_ipv4:
                    command['ipv4'] = ipv4_conf
                    requests.append(self.get_delete_all_dhcp_relay_intf_request(intf_name))
                else:
                    have_server_addresses = self.get_server_addresses(ipv4_conf.get('server_addresses'))
                    server_addresses = self.get_server_addresses(match_ipv4.get('server_addresses'))

                    # Delete all DHCP relay config for an interface, if
                    # all existing server addresses are to be replaced
                    # or if the VRF is to be removed.
                    if (not have_server_addresses.intersection(server_addresses)
                            or (ipv4_conf.get('vrf_name') and match_ipv4.get('vrf_name') is None)):
                        command['ipv4'] = ipv4_conf
                        requests.append(self.get_delete_all_dhcp_relay_intf_request(intf_name))
                    else:
                        ipv4_command = {}
                        del_server_addresses = have_server_addresses.difference(server_addresses)
                        if del_server_addresses:
                            ipv4_command['server_addresses'] = []
                            for address in del_server_addresses:
                                ipv4_command['server_addresses'].append({'address': address})

                        for option in ('source_interface', 'link_select', 'vrf_select'):
                            if ipv4_conf.get(option) and match_ipv4.get(option) is None:
                                ipv4_command[option] = ipv4_conf[option]

                        for option in ('circuit_id', 'max_hop_count', 'policy_action'):
                            if (ipv4_conf.get(option) and match_ipv4.get(option) is None
                                    and ipv4_conf[option] != default_value[option]):
                                ipv4_command[option] = ipv4_conf[option]

                        if ipv4_command:
                            command['ipv4'] = ipv4_command
                            requests.extend(self.get_delete_specific_dhcp_relay_param_requests(command, command, False))

            if ipv6_conf:
                match_ipv6 = match_obj.get('ipv6')
                # Delete all DHCPv6 relay config for an interface if not specified
                if not match_ipv6:
                    command['ipv6'] = ipv6_conf
                    requests.append(self.get_delete_all_dhcpv6_relay_intf_request(intf_name))
                else:
                    have_server_addresses = self.get_server_addresses(ipv6_conf.get('server_addresses'))
                    server_addresses = self.get_server_addresses(match_ipv6.get('server_addresses'))

                    # Delete all DHCPv6 relay config for an interface, if
                    # all existing server addresses are to be replaced
                    # or if the VRF is to be removed.
                    if (not have_server_addresses.intersection(server_addresses)
                            or (ipv6_conf.get('vrf_name') and match_ipv6.get('vrf_name') is None)):
                        command['ipv6'] = ipv6_conf
                        requests.append(self.get_delete_all_dhcpv6_relay_intf_request(intf_name))
                    else:
                        ipv6_command = {}
                        del_server_addresses = have_server_addresses.difference(server_addresses)
                        if del_server_addresses:
                            ipv6_command['server_addresses'] = []
                            for address in del_server_addresses:
                                ipv6_command['server_addresses'].append({'address': address})

                        for option in ('source_interface', 'vrf_select'):
                            if ipv6_conf.get(option) and match_ipv6.get(option) is None:
                                ipv6_command[option] = ipv6_conf[option]

                        if (ipv6_conf.get('max_hop_count') and match_ipv6.get('max_hop_count') is None
                                and ipv6_conf['max_hop_count'] != default_value['max_hop_count']):
                            ipv6_command['max_hop_count'] = ipv6_conf['max_hop_count']

                        if ipv6_command:
                            command['ipv6'] = ipv6_command
                            requests.extend(self.get_delete_specific_dhcpv6_relay_param_requests(command, command, False))

            if command.get('ipv4') or command.get('ipv6'):
                commands.append(command)

        return commands, requests

    @staticmethod
    def get_server_addresses(server_addresses_dict):
        """Get a set of server addresses available in the given
        server_addresses dict
        """
        server_addresses = set()
        if not server_addresses_dict:
            return server_addresses

        for addr in server_addresses_dict:
            if addr.get('address'):
                server_addresses.add(addr['address'])

        return server_addresses

    def post_process_generated_config(self, configs):
        confs = remove_empties_from_list(configs)
        if confs:
            for conf in confs[:]:
                keys = conf.keys()
                if len(keys) <= 1:
                    confs.remove(conf)
        return confs

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['name'])
            for cfg in config:
                ipv4 = cfg.get('ipv4', {})
                if ipv4 and ipv4.get('server_addresses', []):
                    ipv4['server_addresses'].sort(key=lambda x: x['address'])
                ipv6 = cfg.get('ipv6', {})
                if ipv6 and ipv6.get('server_addresses', []):
                    ipv6['server_addresses'].sort(key=lambda x: x['address'])
