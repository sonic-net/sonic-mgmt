#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_l3_interfaces class
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
    remove_empties,
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    normalize_interface_name
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

try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote

TEST_KEYS = [
    {"addresses": {"address": ""}}
]
TEST_KEYS_formatted_diff = [
    {"config": {"name": "", '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {"addresses": {"address": "", '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]

DELETE = "DELETE"
PATCH = "PATCH"

DEFAULT_VALUES = {
    'ipv6': {
        'autoconf': False,
        'dad': 'DISABLE',
        'enabled': False
    }
}


class L3_interfaces(ConfigBase):
    """
    The sonic_l3_interfaces class
    """

    gather_subset = [
        '!all',
        '!min'
    ]

    gather_network_resources = [
        'l3_interfaces',
    ]

    l3_non_vlan_path = 'data/openconfig-interfaces:interfaces/interface={intf_name}/subinterfaces/subinterface={sub_intf}'
    l3_vlan_path = 'data/openconfig-interfaces:interfaces/interface={vlan_name}/openconfig-vlan:routed-vlan'

    ipv4_path = '{l3_intf_path}/openconfig-if-ip:ipv4'
    ipv4_addresses_path = ipv4_path + '/addresses'
    ipv4_addr_del_path = ipv4_addresses_path + '/address={address}'
    ipv4_sag_path = ipv4_path + '/openconfig-interfaces-ext:sag-ipv4/config/static-anycast-gateway'
    ipv4_sag_del_path = ipv4_sag_path + '={address}'
    ipv4_proxy_arp_path = ipv4_path + '/proxy-arp'
    ipv4_proxy_arp_config_path = ipv4_proxy_arp_path + '/config'
    ipv4_proxy_arp_mode_path = ipv4_proxy_arp_config_path + '/mode'

    ipv6_path = '{l3_intf_path}/openconfig-if-ip:ipv6'
    ipv6_addresses_path = ipv6_path + '/addresses'
    ipv6_addr_del_path = ipv6_addresses_path + '/address={address}'
    ipv6_sag_path = ipv6_path + '/openconfig-interfaces-ext:sag-ipv6/config/static-anycast-gateway'
    ipv6_sag_del_path = ipv6_sag_path + '={address}'
    ipv6_config_root_path = ipv6_path + '/config'
    ipv6_config_path = {
        'enabled': ipv6_config_root_path + '/enabled',
        'dad': ipv6_config_root_path + '/ipv6_dad',
        'autoconf': ipv6_config_root_path + '/ipv6_autoconfig'
    }
    ipv6_nd_proxy_path = ipv6_path + '/nd-proxy'
    ipv6_nd_proxy_config_path = ipv6_nd_proxy_path + '/config'
    ipv6_nd_proxy_mode_path = ipv6_nd_proxy_config_path + '/mode'
    ipv6_nd_proxy_rules_path = ipv6_nd_proxy_config_path + '/nd-proxy-rules'
    ipv6_nd_proxy_rules_del_path = ipv6_nd_proxy_rules_path + '={rule}'

    def __init__(self, module):
        super(L3_interfaces, self).__init__(module)

    def get_l3_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        l3_interfaces_facts = facts['ansible_network_resources'].get('l3_interfaces')
        if not l3_interfaces_facts:
            return []
        return l3_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_l3_interfaces_facts = self.get_l3_interfaces_facts()
        commands, requests = self.set_config(existing_l3_interfaces_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['before'] = existing_l3_interfaces_facts
        old_config = existing_l3_interfaces_facts
        if self._module.check_mode:
            new_config = self.get_new_config(commands, old_config)
            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_l3_interfaces_facts()
            if result['changed']:
                result['after'] = new_config

        if self._module._diff:
            self.sort_lists_in_config(old_config)
            if not self._module.check_mode:
                self.sort_lists_in_config(new_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['commands'] = commands
        result['warnings'] = warnings
        return result

    def set_config(self, existing_l3_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self.validate_and_normalize_want(self._module.params['config'])
        have = existing_l3_interfaces_facts
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
        if state in ('replaced', 'overridden'):
            commands, requests = self._state_replaced_overridden(want, have, state)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        return commands, requests

    def _state_replaced_overridden(self, want, have, state):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, del_commands = [], []
        requests, del_requests = [], []

        if have:
            want_dict = {item['name']: item for item in want} if want else {}
            for have_conf in have:
                intf_name = have_conf['name']
                have_conf = self.remove_defaults(have_conf)
                conf = want_dict.get(intf_name)
                if not conf:
                    # Delete all L3 interfaces that are not specified in 'overridden'
                    if state == 'overridden':
                        del_commands.append({'name': intf_name})
                        del_requests.extend(self.get_delete_l3_interface_requests(have_conf, have_conf))
                    continue

                command = {}
                conf_addrs = self.get_addresses(conf)
                have_addrs = self.get_addresses(have_conf)
                del_addrs = {
                    'ipv4': {'primary': set(), 'secondary': set()},
                    'ipv6': {'address': set(), 'eui64': set()}
                }
                for option in ('ipv4', 'ipv6'):
                    is_ipv6 = (option == 'ipv6')
                    if not have_conf.get(option):
                        continue

                    if not conf.get(option):
                        command[option] = have_conf[option]
                        continue

                    if have_conf[option].get('anycast_addresses'):
                        if conf[option].get('anycast_addresses'):
                            del_anycast_addrs = set(have_conf[option]['anycast_addresses']).difference(conf[option]['anycast_addresses'])
                            if del_anycast_addrs:
                                command.setdefault(option, {})['anycast_addresses'] = list(del_anycast_addrs)
                        else:
                            command.setdefault(option, {})['anycast_addresses'] = have_conf[option]['anycast_addresses']

                    if is_ipv6:
                        del_addrs['ipv6']['address'] = have_addrs['ipv6']['address'].difference(conf_addrs['ipv6']['address'])
                        del_addrs['ipv6']['eui64'] = have_addrs['ipv6']['eui64'].difference(conf_addrs['ipv6']['eui64'])

                        del_ipv6_subopt_command = {}
                        for suboption in ('enabled', 'dad', 'autoconf'):
                            if suboption in have_conf['ipv6'] and suboption not in conf['ipv6']:
                                del_ipv6_subopt_command[suboption] = have_conf['ipv6'][suboption]
                        if del_ipv6_subopt_command:
                            command.setdefault('ipv6', {})
                            command['ipv6'].update(del_ipv6_subopt_command)
                    else:
                        del_addrs['ipv4']['primary'] = have_addrs['ipv4']['primary'].difference(conf_addrs['ipv4']['primary'])
                        del_addrs['ipv4']['secondary'] = have_addrs['ipv4']['secondary'].difference(conf_addrs['ipv4']['secondary'])

                        # If primary address is deleted without deleting all secondary address, then
                        # delete all existing addresses and reconfigure specifed primary and secondary addresses
                        if len(del_addrs['ipv4']['primary']) and len(del_addrs['ipv4']['secondary']) < len(have_addrs['ipv4']['secondary']):
                            del_addrs['ipv4']['secondary'] = have_addrs['ipv4']['secondary']

                    if is_ipv6:
                        have_nd_proxy = have_conf[option].get('nd_proxy')
                        want_nd_proxy = conf[option].get('nd_proxy')
                        # If ipv6 addresses are present in the delete list, then delete the nd_proxy config since
                        # deleting of ipv6 addresses is not allowed if nd_proxy is present.
                        if have_nd_proxy and (not want_nd_proxy or del_addrs['ipv6']['address'] or del_addrs['ipv6']['eui64']):
                            command.setdefault('ipv6', {})['nd_proxy'] = have_nd_proxy
                        elif have_nd_proxy and want_nd_proxy:
                            nd_proxy_cmd = {}
                            # If mode is different, then delete the existing nd_proxy config since
                            # deleting of mode is not allowed if nd_proxy_rules are present.
                            if have_nd_proxy.get('mode') != want_nd_proxy.get('mode'):
                                command.setdefault('ipv6', {})['nd_proxy'] = have_nd_proxy
                            else:
                                have_nd_proxy_rules = set(have_nd_proxy.get('nd_proxy_rules', []))
                                want_nd_proxy_rules = set(want_nd_proxy.get('nd_proxy_rules', []))
                                del_nd_proxy_rules = have_nd_proxy_rules - want_nd_proxy_rules
                                if del_nd_proxy_rules:
                                    nd_proxy_cmd['nd_proxy_rules'] = list(del_nd_proxy_rules)
                                if nd_proxy_cmd:
                                    command.setdefault('ipv6', {})['nd_proxy'] = nd_proxy_cmd
                    else:
                        have_proxy_arp = have_conf[option].get('proxy_arp')
                        want_proxy_arp = conf[option].get('proxy_arp')
                        # If ipv4 addresses are present in the delete list, then delete the proxy_arp config
                        # since deleting of ipv4 addresses is not allowed if proxy_arp is present.
                        if have_proxy_arp and (not want_proxy_arp or del_addrs['ipv4']['primary'] or del_addrs['ipv4']['secondary']):
                            command.setdefault('ipv4', {})['proxy_arp'] = have_proxy_arp

                ipv4_addrs_list, ipv6_addrs_list = self.get_addresses_list(del_addrs)
                if ipv4_addrs_list:
                    command.setdefault('ipv4', {})
                    command['ipv4']['addresses'] = ipv4_addrs_list
                if ipv6_addrs_list:
                    command.setdefault('ipv6', {})
                    command['ipv6']['addresses'] = ipv6_addrs_list

                if command:
                    command['name'] = intf_name
                    del_commands.append(command)
                    del_requests.extend(self.get_delete_l3_interface_requests(command, have_conf))

        if del_commands:
            commands = update_states(del_commands, 'deleted')
            new_have = self.get_new_config(commands, have)
            requests = del_requests
        else:
            new_have = have

        add_commands = self.get_diff(want, new_have)
        if add_commands:
            commands.extend(update_states(add_commands, state))
            requests.extend(self.get_create_l3_interfaces_requests(add_commands))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = self.get_diff(want, have)
        requests = self.get_create_l3_interfaces_requests(commands)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands, requests = [], []
        if not have:
            return commands, requests
        elif not want:
            for have_conf in have:
                commands.append({'name': have_conf['name']})
                requests.extend(self.get_delete_l3_interface_requests(have_conf, have_conf))
        else:
            have_dict = {item['name']: item for item in have}
            for conf in want:
                intf_name = conf['name']
                have_conf = have_dict.get(intf_name)
                if not have_conf:
                    continue

                have_conf = self.remove_defaults(have_conf)
                # Delete all L3 config if only interface name is specified
                if len(conf.keys()) == 1:
                    commands.append(conf)
                    requests.extend(self.get_delete_l3_interface_requests(have_conf, have_conf))
                    continue

                command = {}
                have_addrs = self.get_addresses(have_conf)
                del_addrs = {
                    'ipv4': {'primary': set(), 'secondary': set()},
                    'ipv6': {'address': set(), 'eui64': set()}
                }
                for option in ('ipv4', 'ipv6'):
                    is_ipv6 = (option == 'ipv6')
                    if not (option in conf and have_conf.get(option)):
                        continue

                    # If ipv4/ipv6 is specified as empty, then delete all ipv4/ipv6 config
                    if conf[option] == {}:
                        command[option] = have_conf[option]
                        continue

                    if conf[option].get('anycast_addresses') and have_conf[option].get('anycast_addresses'):
                        del_anycast_addrs = set(conf[option]['anycast_addresses']).intersection(have_conf[option]['anycast_addresses'])
                        if del_anycast_addrs:
                            command[option] = {'anycast_addresses': list(del_anycast_addrs)}

                    # In deletion, only the address is considered
                    conf_addrs = set()
                    if conf[option].get('addresses'):
                        conf_addrs = {addr['address'] for addr in conf[option]['addresses']}

                    if is_ipv6:
                        del_addrs['ipv6']['address'] = have_addrs['ipv6']['address'].intersection(conf_addrs)
                        del_addrs['ipv6']['eui64'] = have_addrs['ipv6']['eui64'].intersection(conf_addrs)

                        del_ipv6_subopt_command = {}
                        for suboption in ('enabled', 'dad', 'autoconf'):
                            if suboption in have_conf['ipv6'] and have_conf['ipv6'][suboption] == conf['ipv6'].get(suboption):
                                del_ipv6_subopt_command[suboption] = have_conf['ipv6'][suboption]
                        if del_ipv6_subopt_command:
                            command.setdefault('ipv6', {})
                            command['ipv6'].update(del_ipv6_subopt_command)

                        # Handle nd proxy
                        have_nd_proxy = have_conf[option].get('nd_proxy')
                        conf_nd_proxy = conf[option].get('nd_proxy')
                        if have_nd_proxy and conf_nd_proxy:
                            nd_proxy_cmd = {}
                            if have_nd_proxy.get('mode') == conf_nd_proxy.get('mode'):
                                nd_proxy_cmd['mode'] = have_nd_proxy.get('mode')

                            have_nd_proxy_rules = set(have_nd_proxy.get('nd_proxy_rules', []))
                            conf_nd_proxy_rules = set(conf_nd_proxy.get('nd_proxy_rules', []))
                            del_nd_proxy_rules = have_nd_proxy_rules.intersection(conf_nd_proxy_rules)

                            if del_nd_proxy_rules:
                                nd_proxy_cmd['nd_proxy_rules'] = list(del_nd_proxy_rules)

                            if nd_proxy_cmd:
                                command.setdefault('ipv6', {})['nd_proxy'] = nd_proxy_cmd

                    else:
                        del_addrs['ipv4']['primary'] = have_addrs['ipv4']['primary'].intersection(conf_addrs)
                        del_addrs['ipv4']['secondary'] = have_addrs['ipv4']['secondary'].intersection(conf_addrs)

                        # Handle proxy arp
                        have_proxy_arp = have_conf[option].get('proxy_arp')
                        conf_proxy_arp = conf[option].get('proxy_arp')
                        if have_proxy_arp and conf_proxy_arp and have_proxy_arp['mode'] == conf_proxy_arp['mode']:
                            command.setdefault('ipv4', {})['proxy_arp'] = have_proxy_arp

                ipv4_addrs_list, ipv6_addrs_list = self.get_addresses_list(del_addrs)
                if ipv4_addrs_list:
                    command.setdefault('ipv4', {})
                    command['ipv4']['addresses'] = ipv4_addrs_list
                if ipv6_addrs_list:
                    command.setdefault('ipv6', {})
                    command['ipv6']['addresses'] = ipv6_addrs_list

                if command:
                    command['name'] = intf_name
                    commands.append(command)
                    requests.extend(self.get_delete_l3_interface_requests(command, have_conf))

        if commands:
            commands = update_states(commands, "deleted")
        return commands, requests

    def get_delete_addresses_requests(self, l3_intf_path, addresses, ipv6=False, delete_all=False):
        """Get requests to delete IP/IPv6 addresses based on the command specified"""
        requests = []
        if addresses:
            if delete_all:
                if ipv6:
                    requests.append({'path': self.ipv6_addresses_path.format(l3_intf_path=l3_intf_path), 'method': DELETE})
                else:
                    requests.append({'path': self.ipv4_addresses_path.format(l3_intf_path=l3_intf_path), 'method': DELETE})
            else:
                if ipv6:
                    for item in addresses:
                        address = item['address'].split('/')[0]
                        url = self.ipv6_addr_del_path.format(l3_intf_path=l3_intf_path, address=address)
                        requests.append({'path': url, 'method': DELETE})
                else:
                    # For IPv4, delete secondary IP(s) followed by primary IP
                    primary_addr_del_request = None
                    for item in addresses:
                        address = item['address'].split('/')[0]
                        url = self.ipv4_addr_del_path.format(l3_intf_path=l3_intf_path, address=address)
                        if item.get('secondary'):
                            requests.append({'path': url + '/config/secondary', 'method': DELETE})
                        else:
                            primary_addr_del_request = {'path': url, 'method': DELETE}

                    if primary_addr_del_request:
                        requests.append(primary_addr_del_request)

        return requests

    def get_delete_anycast_addresses_requests(self, l3_intf_path, addresses, ipv6=False):
        """Get requests to delete IP/IPv6 anycast addresses
        based on the command specified
        """
        requests = []
        if addresses:
            if ipv6:
                for addr in addresses:
                    url = self.ipv6_sag_del_path.format(l3_intf_path=l3_intf_path, address=addr.replace('/', '%2f'))
                    requests.append({'path': url, 'method': DELETE})
            else:
                for addr in addresses:
                    url = self.ipv4_sag_del_path.format(l3_intf_path=l3_intf_path, address=addr.replace('/', '%2f'))
                    requests.append({'path': url, 'method': DELETE})

        return requests

    def get_delete_proxy_arp_requests(self, l3_intf_path, proxy_arp):
        """
        Get requests to delete the proxy arp related configs
        """
        requests = []
        if proxy_arp and 'mode' in proxy_arp:
            requests.append({'path': self.ipv4_proxy_arp_mode_path.format(l3_intf_path=l3_intf_path), 'method': DELETE})

        return requests

    def get_delete_nd_proxy_requests(self, l3_intf_path, nd_proxy):
        """
        Get requests to delete nd_proxy configuration for IPv6.
        If nd_proxy is provided and contains 'nd_proxy_rules', delete only those rules.
        Otherwise, delete the entire nd_proxy config.
        """
        requests = []
        if nd_proxy and isinstance(nd_proxy, dict):
            if nd_proxy.get('nd_proxy_rules'):
                for r in nd_proxy['nd_proxy_rules']:
                    encoded_rule = quote(r, safe='')
                    url = self.ipv6_nd_proxy_rules_del_path.format(l3_intf_path=l3_intf_path, rule=encoded_rule)
                    requests.append({'path': url, 'method': DELETE})

            if 'mode' in nd_proxy:
                url = self.ipv6_nd_proxy_mode_path.format(l3_intf_path=l3_intf_path)
                requests.append({'path': url, 'method': DELETE})

        return requests

    def get_delete_ipv6_param_requests(self, command):
        """Get requests to delete specific IPv6 configurations
        based on the command specified
        """
        requests = []
        if not (command and command.get('ipv6')):
            return requests

        l3_intf_path = self.get_l3_interface_path(command['name'])
        for option in ('enabled', 'autoconf', 'dad'):
            if option in command['ipv6']:
                requests.append({'path': self.ipv6_config_path[option].format(l3_intf_path=l3_intf_path), 'method': DELETE})

        return requests

    def get_delete_l3_interface_requests(self, command, have_conf):
        """Get requests to delete L3 configurations of an interface
        based on the command specified
        """
        requests = []
        l3_intf_path = self.get_l3_interface_path(command['name'])
        if command.get('ipv4'):
            if command['ipv4'].get('proxy_arp'):
                requests.extend(self.get_delete_proxy_arp_requests(l3_intf_path, command['ipv4']['proxy_arp']))
            if command['ipv4'].get('addresses'):
                delete_all_addrs = (len(command['ipv4']['addresses']) == len(have_conf['ipv4']['addresses']))
                requests.extend(self.get_delete_addresses_requests(l3_intf_path, command['ipv4']['addresses'], delete_all=delete_all_addrs))
            if command['ipv4'].get('anycast_addresses'):
                requests.extend(self.get_delete_anycast_addresses_requests(l3_intf_path, command['ipv4']['anycast_addresses']))
        if command.get('ipv6'):
            if command['ipv6'].get('nd_proxy'):
                requests.extend(self.get_delete_nd_proxy_requests(l3_intf_path, command['ipv6']['nd_proxy']))
            if command['ipv6'].get('addresses'):
                delete_all_addrs = (len(command['ipv6']['addresses']) == len(have_conf['ipv6']['addresses']))
                requests.extend(self.get_delete_addresses_requests(l3_intf_path, command['ipv6']['addresses'], ipv6=True, delete_all=delete_all_addrs))
            if command['ipv6'].get('anycast_addresses'):
                requests.extend(self.get_delete_anycast_addresses_requests(l3_intf_path, command['ipv6']['anycast_addresses'], ipv6=True))
            requests.extend(self.get_delete_ipv6_param_requests(command))

        return requests

    def get_create_l3_interfaces_requests(self, configs):
        """Get requests to configure L3 configurations for the interfaces
        specified in commands
        """
        requests = []
        if not configs:
            return requests

        for l3 in configs:
            intf_name = l3.get('name')
            l3_intf_path = self.get_l3_interface_path(intf_name)

            if l3.get('ipv4'):
                if l3['ipv4'].get('addresses'):
                    ipv4_addrs = l3['ipv4']['addresses']
                    ipv4_addrs_pri_payload = []
                    ipv4_addrs_sec_payload = []
                    for item in ipv4_addrs:
                        is_secondary = item.get('secondary', False)
                        if is_secondary:
                            ipv4_addrs_sec_payload.append(self.get_ipv4_addr_payload(item['address'], is_secondary))
                        else:
                            ipv4_addrs_pri_payload.append(self.get_ipv4_addr_payload(item['address'], is_secondary))

                    # Configure primary IP, followed by secondary IP(s)
                    if ipv4_addrs_pri_payload:
                        payload = {'openconfig-if-ip:addresses': {'address': ipv4_addrs_pri_payload}}
                        requests.append({'path': self.ipv4_addresses_path.format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})
                    if ipv4_addrs_sec_payload:
                        payload = {'openconfig-if-ip:addresses': {'address': ipv4_addrs_sec_payload}}
                        requests.append({'path': self.ipv4_addresses_path.format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

                if l3['ipv4'].get('anycast_addresses'):
                    payload = {'openconfig-interfaces-ext:static-anycast-gateway': l3['ipv4']['anycast_addresses']}
                    requests.append({'path': self.ipv4_sag_path.format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

                if l3['ipv4'].get('proxy_arp'):
                    if 'mode' in l3['ipv4']['proxy_arp'] and l3['ipv4']['proxy_arp']['mode'] is not None:
                        payload = {'openconfig-if-ip:mode': l3['ipv4']['proxy_arp']['mode']}
                        requests.append({'path': self.ipv4_proxy_arp_mode_path.format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

            if l3.get('ipv6'):
                if l3['ipv6'].get('addresses'):
                    ipv6_addrs = l3['ipv6']['addresses']
                    ipv6_addrs_payload = []
                    for item in ipv6_addrs:
                        ipv6_addrs_payload.append(self.get_ipv6_addr_payload(item['address'], item.get('eui64', False)))

                    if ipv6_addrs_payload:
                        payload = {'openconfig-if-ip:addresses': {'address': ipv6_addrs_payload}}
                        requests.append({'path': self.ipv6_addresses_path.format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

                if l3['ipv6'].get('anycast_addresses'):
                    payload = {'openconfig-interfaces-ext:static-anycast-gateway': l3['ipv6']['anycast_addresses']}
                    requests.append({'path': self.ipv6_sag_path.format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

                if l3['ipv6'].get('enabled') is not None:
                    payload = {'openconfig-if-ip:enabled': l3['ipv6']['enabled']}
                    requests.append({'path': self.ipv6_config_path['enabled'].format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

                if l3['ipv6'].get('dad'):
                    payload = {'openconfig-if-ip:ipv6_dad': l3['ipv6']['dad']}
                    requests.append({'path': self.ipv6_config_path['dad'].format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

                if l3['ipv6'].get('autoconf') is not None:
                    payload = {'openconfig-if-ip:ipv6_autoconfig': l3['ipv6']['autoconf']}
                    requests.append({'path': self.ipv6_config_path['autoconf'].format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

                if l3['ipv6'].get('nd_proxy'):
                    nd_proxy = l3['ipv6']['nd_proxy']
                    if isinstance(nd_proxy, dict):
                        if 'mode' in nd_proxy and nd_proxy['mode'] is not None:
                            payload = {"openconfig-if-ip:mode": nd_proxy['mode']}
                            requests.append({'path': self.ipv6_nd_proxy_mode_path. format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})
                        if 'nd_proxy_rules' in nd_proxy and nd_proxy['nd_proxy_rules'] is not None:
                            payload = {"openconfig-if-ip:nd-proxy-rules": nd_proxy['nd_proxy_rules']}
                            requests.append({'path': self.ipv6_nd_proxy_rules_path. format(l3_intf_path=l3_intf_path), 'method': PATCH, 'data': payload})

        return requests

    def validate_and_normalize_want(self, want):
        updated_want = []
        state = self._module.params['state']
        if not want:
            if state != 'deleted':
                self._module.fail_json(msg='value of config parameter must not be empty for state {0}'.format(state))
            return updated_want

        if state != 'deleted':
            for conf in want:
                intf_name = conf['name']
                if self.is_mgmt_interface(intf_name):
                    continue
                conf = remove_empties(conf)
                primary_ips = 0
                if conf.get('ipv4') and conf['ipv4'].get('addresses'):
                    for addr in conf['ipv4']['addresses']:
                        if not addr.setdefault('secondary', False):
                            primary_ips += 1
                            if primary_ips > 1:
                                self._module.fail_json(msg='Multiple ipv4 primary ips found! {0}'.format(conf))
                updated_want.append(remove_empties(conf))
        else:
            # In state deleted, empty ipv4 and ipv6 are supported
            for conf in want:
                intf_name = conf['name']
                if self.is_mgmt_interface(intf_name):
                    continue

                conf_ipv4 = conf.get('ipv4')
                conf_ipv6 = conf.get('ipv6')

                if not conf_ipv4 and not conf_ipv6:
                    delete_ipv4 = delete_ipv6 = True
                else:
                    delete_ipv4 = delete_ipv6 = False
                    if conf_ipv4:
                        delete_ipv4 = True
                        for option in ('addresses', 'anycast_addresses', 'proxy_arp'):
                            # For proxy_arp, treat empty dict as not present
                            if option == 'proxy_arp' and conf_ipv4.get(option) in [None, {}, []]:
                                continue
                            if conf_ipv4.get(option) not in [None, []]:
                                delete_ipv4 = False
                                break
                    if conf_ipv6:
                        delete_ipv6 = True
                        for option in ('addresses', 'anycast_addresses', 'dad', 'autoconf', 'enabled', 'nd_proxy'):
                            val = conf_ipv6.get(option)
                            # For nd_proxy, treat empty dict or all-empty dict as not present
                            # check if nd_proxy is a dictionary and all of its values are empty
                            # For ex. nd_proxy = {'mode': None, 'nd_proxy_rules' : []}
                            if option == 'nd_proxy' and val in [None, {}, []] or (isinstance(val, dict) and all(v in [None, {}, []] for v in val.values())):
                                continue
                            if val not in [None, []]:
                                delete_ipv6 = False
                                break

                if delete_ipv4 and delete_ipv6:
                    updated_want.append({'name': intf_name})
                else:
                    updated_conf = remove_empties(conf)
                    if delete_ipv4:
                        updated_conf['ipv4'] = {}
                    if delete_ipv6:
                        updated_conf['ipv6'] = {}
                    updated_want.append(updated_conf)

        normalize_interface_name(updated_want, self._module)
        return updated_want

    def get_l3_interface_path(self, intf_name):
        if intf_name.startswith('Vlan'):
            return self.l3_vlan_path.format(vlan_name=intf_name)
        else:
            sub_intf = 0
            if '.' in intf_name:
                intf_name, sub_intf = intf_name.split('.')
            return self.l3_non_vlan_path.format(intf_name=intf_name, sub_intf=sub_intf)

    @staticmethod
    def get_ipv4_addr_payload(ip_prefix, secondary=False):
        ip, mask = ip_prefix.split('/')
        addr_payload = {
            'ip': ip,
            'openconfig-if-ip:config': {
                'ip': ip,
                'prefix-length': int(mask)
            }
        }
        if secondary:
            addr_payload['openconfig-if-ip:config']['secondary'] = secondary
        return addr_payload

    @staticmethod
    def get_ipv6_addr_payload(ipv6_prefix, eui64=False):
        ipv6, mask = ipv6_prefix.split('/')
        addr_payload = {
            'ip': ipv6,
            'openconfig-if-ip:config': {
                'ip': ipv6,
                'prefix-length': int(mask)
            }
        }
        if eui64:
            addr_payload['openconfig-if-ip:config']['openconfig-interfaces-private:eui64'] = eui64
        return addr_payload

    @staticmethod
    def remove_defaults(have_conf, conf=None, delete_op=True):
        if delete_op:
            # For delete operation, the default values in have_conf are removed
            updated_conf = have_conf.copy()
            if have_conf and have_conf.get('ipv6'):
                updated_conf['ipv6'] = have_conf['ipv6'].copy()
                for option in ('enabled', 'autoconf', 'dad'):
                    if updated_conf['ipv6'].get(option) == DEFAULT_VALUES['ipv6'][option]:
                        del updated_conf['ipv6'][option]

                if not updated_conf['ipv6']:
                    del updated_conf['ipv6']
        else:
            # For merge operation, the default values in conf are removed
            # if that option is not present in have_conf
            updated_conf = conf.copy()
            if conf and conf.get('ipv6'):
                have_ipv6 = have_conf.get('ipv6', {}) if have_conf else {}
                updated_conf['ipv6'] = conf['ipv6'].copy()
                for option in ('enabled', 'autoconf', 'dad'):
                    if option not in have_ipv6 and conf['ipv6'].get(option) == DEFAULT_VALUES['ipv6'][option]:
                        del updated_conf['ipv6'][option]

                if not conf['ipv6']:
                    del conf['ipv6']

        return updated_conf

    def get_diff(self, want, have):
        updated_want = []
        have_dict = {item['name']: item for item in have} if have else {}
        for conf in want:
            if conf.get('ipv6'):
                have_conf = have_dict.get(conf['name'], {})
                conf = self.remove_defaults(have_conf, conf, False)
            if conf.get('ipv4') or conf.get('ipv6'):
                updated_want.append(conf)

        return get_diff(updated_want, have, TEST_KEYS)

    def get_new_config(self, commands, have):
        """Returns generated configuration based on commands and
        existing configuration"""
        state = self._module.params['state']
        new_conf = get_new_config(commands, have, TEST_KEYS_formatted_diff)
        new_conf_dict = {item['name']: item for item in new_conf} if new_conf else {}
        if state != 'deleted':
            for command in commands:
                if command['state'] == 'deleted' or not command.get('ipv4', {}).get('addresses'):
                    continue

                conf = new_conf_dict.get(command['name'], {})
                if not conf.get('ipv4', {}).get('addresses'):
                    continue

                pri_ip_indices = []
                for i in range(len(conf['ipv4']['addresses'])):
                    if not conf['ipv4']['addresses'][i].get('secondary'):
                        pri_ip_indices.append(i)

                # If new primary IP is configured, delete the old primary IP
                if len(pri_ip_indices) > 1:
                    new_pri_ip = None
                    for addr in command['ipv4']['addresses']:
                        if not addr.get('secondary'):
                            new_pri_ip = addr['address']
                            break

                    for i in pri_ip_indices:
                        if conf['ipv4']['addresses'][i]['address'] != new_pri_ip:
                            del conf['ipv4']['addresses'][i]
                            break

        generated_conf = []
        for conf in new_conf:
            # Set to default values if deleted
            conf.setdefault('ipv6', {})
            for suboption in ('enabled', 'autoconf', 'dad'):
                conf['ipv6'].setdefault(suboption, DEFAULT_VALUES['ipv6'][suboption])

            # Remove empty lists
            for option in ('ipv4', 'ipv6'):
                if option in conf:
                    for suboption in ('addresses', 'anycast_addresses'):
                        if suboption in conf[option] and len(conf[option][suboption]) == 0:
                            del conf[option][suboption]
                    # --- Remove empty nd_proxy_rules ---
                    if option == 'ipv6' and conf[option].get('nd_proxy'):
                        nd_proxy = conf[option]['nd_proxy']
                        if isinstance(nd_proxy, dict) and 'nd_proxy_rules' in nd_proxy and len(nd_proxy['nd_proxy_rules']) == 0:
                            del nd_proxy['nd_proxy_rules']

                    if not conf[option]:
                        del conf[option]

            # Return config if non-default values are present
            if conf.get('ipv4') or conf.get('ipv6') != DEFAULT_VALUES['ipv6']:
                generated_conf.append(conf)

        return generated_conf

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: x['name'])
            for cfg in config:
                for option in ('ipv4', 'ipv6'):
                    if cfg.get(option):
                        if cfg[option].get('addresses'):
                            cfg[option]['addresses'].sort(key=lambda x: x['address'])
                        if cfg[option].get('anycast_addresses'):
                            cfg[option]['anycast_addresses'].sort()
                        if option == 'ipv6' and cfg[option].get('nd_proxy'):
                            nd_proxy = cfg[option]['nd_proxy']
                            if isinstance(nd_proxy, dict) and nd_proxy.get('nd_proxy_rules'):
                                nd_proxy['nd_proxy_rules'].sort()

    @staticmethod
    def is_mgmt_interface(intf_name):
        if intf_name == 'eth0' or intf_name.startswith('Management'):
            return True
        return False

    @staticmethod
    def get_addresses(conf):
        """Get set of the ip and ipv6 addresses available in the given
        L3 interface config dict
        """
        addresses = {
            'ipv4': {'primary': set(), 'secondary': set()},
            'ipv6': {'address': set(), 'eui64': set()}
        }
        if not conf:
            return addresses

        if conf.get('ipv4') and conf['ipv4'].get('addresses'):
            for addr in conf['ipv4']['addresses']:
                if addr.get('address'):
                    if addr.get('secondary'):
                        addresses['ipv4']['secondary'].add(addr['address'])
                    else:
                        addresses['ipv4']['primary'].add(addr['address'])

        if conf.get('ipv6') and conf['ipv6'].get('addresses'):
            for addr in conf['ipv6']['addresses']:
                if addr.get('address'):
                    if addr.get('eui64'):
                        addresses['ipv6']['eui64'].add(addr['address'])
                    else:
                        addresses['ipv6']['address'].add(addr['address'])

        return addresses

    @staticmethod
    def get_addresses_list(addresses):
        """Get list of the ip and ipv6 addresses available in the given
        addresses dict
        """
        ipv4_addresses, ipv6_addresses = [], []
        if addresses:
            for addr in addresses['ipv4']['primary']:
                ipv4_addresses.append({'address': addr, 'secondary': False})
            for addr in addresses['ipv4']['secondary']:
                ipv4_addresses.append({'address': addr, 'secondary': True})

            for addr in addresses['ipv6']['address']:
                ipv6_addresses.append({'address': addr})
            for addr in addresses['ipv6']['eui64']:
                ipv6_addresses.append({'address': addr, 'eui64': True})

        return ipv4_addresses, ipv6_addresses
