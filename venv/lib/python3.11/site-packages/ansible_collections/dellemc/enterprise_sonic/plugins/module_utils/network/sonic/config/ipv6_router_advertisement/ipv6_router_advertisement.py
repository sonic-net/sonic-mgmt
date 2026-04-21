#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ipv6_router_advertisement class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    remove_empties_from_list,
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

DELETE = 'DELETE'
PATCH = 'PATCH'

TEST_KEYS = [
    {'dnssl': {'dnssl_name': ''}},
    {'ra_prefixes': {'prefix': ''}},
    {'rdnss': {'address': ''}}
]
TEST_KEYS_formatted_diff = [
    {'config': {'name': ''}},
    {'dnssl': {'dnssl_name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'ra_prefixes': {'prefix': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'rdnss': {'address': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]

DEFAULT_RTADV_VALUES = {
    'suppress': True,
    'ra_fast_retrans': True,
    'adv_interval_option': False,
    'home_agent_config': False,
    'managed_config': False,
    'other_config': False
}
DEFAULT_PREFIX_VALUES = {
    'off_link': False,
    'no_autoconfig': False,
    'router_address': False
}

OPTION_TO_PAYLOAD_MAP = {
    'adv_interval_option': 'openconfig-interfaces-ext:adv-interval-option',
    'dnssl': 'openconfig-interfaces-ext:dns-search-names',
    'home_agent_config': 'openconfig-interfaces-ext:home-agent-config',
    'home_agent_lifetime': 'openconfig-interfaces-ext:home-agent-lifetime',
    'home_agent_preference': 'openconfig-interfaces-ext:home-agent-preference',
    'managed_config': 'openconfig-interfaces-ext:managed-config',
    'min_ra_interval': 'openconfig-interfaces-ext:min-ra-interval',
    'min_ra_interval_msec': 'openconfig-interfaces-ext:min-ra-interval-msec',
    'mtu': 'openconfig-interfaces-ext:mtu',
    'other_config': 'openconfig-interfaces-ext:other-config',
    'ra_fast_retrans': 'openconfig-interfaces-ext:ra-fast-retrans',
    'ra_hop_limit': 'openconfig-interfaces-ext:ra-hop-limit',
    'ra_interval': 'interval',
    'ra_interval_msec': 'openconfig-interfaces-ext:ra-interval-msec',
    'ra_lifetime': 'lifetime',
    'ra_prefixes': 'openconfig-interfaces-ext:ra-prefixes',
    'ra_retrans_interval': 'openconfig-interfaces-ext:ra-retrans-interval',
    'rdnss': 'openconfig-interfaces-ext:rdnss-addresses',
    'reachable_time': 'openconfig-interfaces-ext:reachable-time',
    'router_preference': 'openconfig-interfaces-ext:router-preference',
    'suppress': 'suppress'
}


class Ipv6_router_advertisement(ConfigBase):
    """
    The sonic_ipv6_router_advertisement class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ipv6_router_advertisement',
    ]

    non_vlan_rtadv_path = ('data/openconfig-interfaces:interfaces/interface={intf_name}'
                           '/subinterfaces/subinterface={sub_intf}/openconfig-if-ip:ipv6/router-advertisement')
    vlan_rtadv_path = 'data/openconfig-interfaces:interfaces/interface={vlan_name}/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/router-advertisement'
    rtadv_config_path = '{rtadv_path}/config'

    option_to_key_map = {
        'dnssl': 'dnssl_name',
        'ra_prefixes': 'prefix',
        'rdnss': 'address'
    }
    option_to_table_map = {
        'dnssl': 'dns-search-name',
        'ra_prefixes': 'ra-prefix',
        'rdnss': 'rdnss-address'
    }

    def __init__(self, module):
        super(Ipv6_router_advertisement, self).__init__(module)

    def get_ipv6_router_advertisement_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ipv6_router_advertisement_facts = facts['ansible_network_resources'].get('ipv6_router_advertisement')
        if not ipv6_router_advertisement_facts:
            return []
        return ipv6_router_advertisement_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []

        existing_ipv6_router_advertisement_facts = self.get_ipv6_router_advertisement_facts()
        commands, requests = self.set_config(existing_ipv6_router_advertisement_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        result['before'] = existing_ipv6_router_advertisement_facts
        old_config = existing_ipv6_router_advertisement_facts
        if self._module.check_mode:
            new_config = self.get_new_config(commands, old_config)
            self.sort_lists_in_config(new_config)
            result['after(generated)'] = new_config
        else:
            new_config = self.get_ipv6_router_advertisement_facts()
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

    def set_config(self, existing_ipv6_router_advertisement_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self.validate_and_normalize_want(self._module.params['config'])
        have = existing_ipv6_router_advertisement_facts
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
        """ The command generator when state is replaced/overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, del_commands = [], []
        requests, del_requests = [], []

        want_dict = {item['name']: item for item in want}
        if have:
            for have_conf in have:
                intf_name = have_conf['name']
                have_conf = self.remove_defaults(have_conf)
                if len(have_conf.keys()) == 1:
                    continue

                conf = want_dict.get(intf_name)
                # Delete all interface router advertisement config if not specified in 'overridden',
                # or if only interface name is specified
                if not conf:
                    if state == 'overridden':
                        del_commands.append({'name': have_conf['name']})
                        del_requests.extend(self.get_delete_ipv6_rtadv_requests(have_conf, have_conf, True))
                elif len(conf.keys()) == 1:
                    del_commands.append({'name': have_conf['name']})
                    del_requests.extend(self.get_delete_ipv6_rtadv_requests(have_conf, have_conf, True))
                else:
                    del_command = {}
                    for option, value in have_conf.items():
                        if option == 'name':
                            continue

                        if option not in conf:
                            del_command[option] = value
                        elif option in ('dnssl', 'ra_prefixes', 'rdnss'):
                            del_opt_command = []
                            opt_key = self.option_to_key_map[option]
                            for have_item in value:
                                item = next((ele for ele in conf[option] if ele[opt_key] == have_item[opt_key]), {})
                                if not item or item != have_item:
                                    del_opt_command.append({opt_key: have_item[opt_key]})

                            if del_opt_command:
                                del_command[option] = del_opt_command

                    if del_command:
                        del_command['name'] = conf['name']
                        del_commands.append(del_command)
                        del_requests.extend(self.get_delete_ipv6_rtadv_requests(del_command, have_conf))

        if del_commands:
            commands = update_states(del_commands, 'deleted')
            new_have = self.get_new_config(commands, have)
            requests = del_requests
        else:
            new_have = have

        add_commands = self.get_diff(want, new_have)
        if add_commands:
            commands.extend(update_states(add_commands, state))
            requests.extend(self.get_modify_ipv6_rtadv_requests(add_commands))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = self.get_diff(want, have)
        requests = self.get_modify_ipv6_rtadv_requests(commands)
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
        commands, requests = [], []
        if not have:
            return commands, requests
        elif not want:
            for have_conf in have:
                commands.append({'name': have_conf['name']})
                requests.extend(self.get_delete_ipv6_rtadv_requests(have_conf, have_conf, True))
        else:
            have_dict = {item['name']: item for item in have}
            for conf in want:
                intf_name = conf['name']
                have_conf = have_dict.get(intf_name)
                if not have_conf:
                    continue

                have_conf = self.remove_defaults(have_conf)
                # If only default config is present, nothing to delete
                if len(have_conf.keys()) == 1:
                    continue

                # Delete all interface router advertisement config if only interface name is specified
                if len(conf.keys()) == 1:
                    commands.append(conf)
                    requests.extend(self.get_delete_ipv6_rtadv_requests(conf, have_conf, True))
                    continue

                command = {}
                for option, value in conf.items():
                    if option == 'name':
                        continue

                    if option in ('dnssl', 'ra_prefixes', 'rdnss'):
                        if have_conf.get(option):
                            opt_command = []
                            opt_key = self.option_to_key_map[option]
                            for item in value:
                                have_item = next((ele for ele in have_conf[option] if ele[opt_key] == item[opt_key]), None)
                                if have_item:
                                    opt_command.append({opt_key: item[opt_key]})
                            if opt_command:
                                command[option] = opt_command
                    else:
                        if value == have_conf.get(option):
                            command[option] = value

                if command:
                    command['name'] = conf['name']
                    commands.append(command)
                    requests.extend(self.get_delete_ipv6_rtadv_requests(command, have_conf))

        if commands:
            commands = update_states(commands, 'deleted')
        return commands, requests

    def get_delete_ipv6_rtadv_requests(self, command, have_conf, delete_all=False):
        requests = []
        rtadv_path = self.get_rtadv_path(command['name'])
        if delete_all or len(command.keys()) == 1:
            requests.append({'path': rtadv_path, 'method': DELETE})
        else:
            rtadv_config_path = self.rtadv_config_path.format(rtadv_path=rtadv_path)

            # Delete in the order of: ra-lifetime -> ra-interval -> min-ra-interval
            for option in ('ra_lifetime', 'ra_interval_msec', 'ra_interval', 'min_ra_interval_msec', 'min_ra_interval'):
                if option in command:
                    requests.append({'path': rtadv_config_path + '/' + OPTION_TO_PAYLOAD_MAP[option], 'method': DELETE})

            for option in command:
                if option in ('name', 'min_ra_interval', 'min_ra_interval_msec', 'ra_interval', 'ra_interval_msec', 'ra_lifetime'):
                    continue

                if option in ('dnssl', 'ra_prefixes', 'rdnss'):
                    if len(command[option]) == len(have_conf[option]):
                        requests.append({'path': rtadv_path + '/' + OPTION_TO_PAYLOAD_MAP[option], 'method': DELETE})
                    else:
                        opt_key = self.option_to_key_map[option]
                        url = '{0}/{1}/{2}='.format(rtadv_path, OPTION_TO_PAYLOAD_MAP[option], self.option_to_table_map[option])
                        for item in command[option]:
                            requests.append({'path': url + item[opt_key].replace('/', '%2f'), 'method': DELETE})
                else:
                    requests.append({'path': rtadv_config_path + '/' + OPTION_TO_PAYLOAD_MAP[option], 'method': DELETE})

        return requests

    def get_modify_ipv6_rtadv_requests(self, commands):
        requests = []

        for command in commands:
            name = command['name']
            rtadv_path = self.get_rtadv_path(name)
            rtadv_config_path = self.rtadv_config_path.format(rtadv_path=rtadv_path)

            # Configure in the order of: min-ra-interval -> ra-interval -> ra-lifetime
            for option in ('min_ra_interval', 'min_ra_interval_msec', 'ra_interval', 'ra_interval_msec', 'ra_lifetime'):
                if option in command:
                    requests.append({
                        'path': rtadv_config_path + '/' + OPTION_TO_PAYLOAD_MAP[option],
                        'method': PATCH,
                        'data': {OPTION_TO_PAYLOAD_MAP[option]: command[option]}
                    })

            rtadv_payload = {}
            rtadv_config_payload = {}
            for option, value in command.items():
                if option in ('name', 'min_ra_interval', 'min_ra_interval_msec', 'ra_interval', 'ra_interval_msec', 'ra_lifetime'):
                    continue

                # For default value, send DELETE request
                if option in DEFAULT_RTADV_VALUES and value == DEFAULT_RTADV_VALUES[option]:
                    url = rtadv_config_path + '/' + OPTION_TO_PAYLOAD_MAP[option]
                    requests.append({'path': url, 'method': DELETE})
                else:
                    if option == 'dnssl':
                        dnssl_payload = self.get_ipv6_rtadv_dnssl_payload(value)
                        if dnssl_payload:
                            rtadv_payload[OPTION_TO_PAYLOAD_MAP[option]] = dnssl_payload
                    elif option == 'ra_prefixes':
                        ra_prefixes_payload = self.get_ipv6_rtadv_ra_prefixes_payload(value)
                        if ra_prefixes_payload:
                            rtadv_payload[OPTION_TO_PAYLOAD_MAP[option]] = ra_prefixes_payload
                    elif option == 'rdnss':
                        rdnss_payload = self.get_ipv6_rtadv_rdnss_payload(value)
                        if rdnss_payload:
                            rtadv_payload[OPTION_TO_PAYLOAD_MAP[option]] = rdnss_payload
                    elif option == 'router_preference':
                        rtadv_config_payload[OPTION_TO_PAYLOAD_MAP[option]] = 'openconfig-interfaces-ext:' + value.upper()
                    else:
                        rtadv_config_payload[OPTION_TO_PAYLOAD_MAP[option]] = value

            if rtadv_config_payload:
                rtadv_payload['config'] = rtadv_config_payload
            if rtadv_payload:
                requests.append({'path': rtadv_path, 'method': PATCH, 'data': {'openconfig-if-ip:router-advertisement': rtadv_payload}})

        return requests

    @staticmethod
    def get_ipv6_rtadv_dnssl_payload(dnssl_list):
        payload = []
        for dnssl in dnssl_list:
            config_payload = {'dnssl-name': dnssl['dnssl_name']}
            if 'valid_lifetime' in dnssl:
                config_payload['valid-lifetime'] = dnssl['valid_lifetime']
            payload.append({'dnssl-name': dnssl['dnssl_name'], 'config': config_payload})

        if payload:
            return {'dns-search-name': payload}

        return None

    @staticmethod
    def get_ipv6_rtadv_ra_prefixes_payload(prefix_list):
        payload = []
        for prefix in prefix_list:
            config_payload = {'prefix': prefix['prefix']}
            for option in ('no_autoconfig', 'off_link', 'preferred_lifetime', 'router_address', 'valid_lifetime'):
                if option in prefix:
                    config_payload[option.replace('_', '-')] = prefix[option]
            payload.append({'prefix': prefix['prefix'], 'config': config_payload})

        if payload:
            return {'ra-prefix': payload}

        return None

    @staticmethod
    def get_ipv6_rtadv_rdnss_payload(rdnss_list):
        payload = []
        for rdnss in rdnss_list:
            config_payload = {'address': rdnss['address']}
            if 'valid_lifetime' in rdnss:
                config_payload['valid-lifetime'] = rdnss['valid_lifetime']
            payload.append({'address': rdnss['address'], 'config': config_payload})

        if payload:
            return {'rdnss-address': payload}

        return None

    def get_rtadv_path(self, intf_name):
        if intf_name.startswith('Vlan'):
            return self.vlan_rtadv_path.format(vlan_name=intf_name)
        else:
            sub_intf = 0
            if '.' in intf_name:
                intf_name, sub_intf = intf_name.split('.')
            return self.non_vlan_rtadv_path.format(intf_name=intf_name, sub_intf=sub_intf)

    def get_diff(self, want, have):
        updated_want = []
        have_dict = {item['name']: item for item in have}
        for conf in want:
            have_conf = have_dict.get(conf['name'], {})
            conf = self.remove_defaults(have_conf, conf, False)
            if len(conf.keys()) > 1:
                updated_want.append(conf)

        return get_diff(updated_want, have, TEST_KEYS)

    def get_new_config(self, commands, have):
        """Returns generated configuration based on commands and
        existing configuration"""
        state = self._module.params['state']
        new_conf = get_new_config(commands, have, TEST_KEYS_formatted_diff)
        generated_conf = []
        default_conf = DEFAULT_RTADV_VALUES.copy()
        for conf in new_conf:
            # Remove empty lists
            for option in ('dnssl', 'ra_prefixes', 'rdnss'):
                if option in conf and not conf[option]:
                    del conf[option]

            # Set default values
            for option, def_value in DEFAULT_RTADV_VALUES.items():
                conf.setdefault(option, def_value)

            if conf.get('ra_prefixes'):
                for prefix in conf['ra_prefixes']:
                    for option, def_value in DEFAULT_PREFIX_VALUES.items():
                        prefix.setdefault(option, def_value)

            # Return config if non-default values are present
            default_conf['name'] = conf['name']
            if conf != default_conf:
                generated_conf.append(conf)

        return generated_conf

    @staticmethod
    def remove_defaults(have_conf, conf=None, delete_op=True):
        if delete_op:
            # For delete operation, the default values in have_conf are removed
            updated_conf = have_conf.copy()
            for option, def_value in DEFAULT_RTADV_VALUES.items():
                if updated_conf.get(option) == def_value:
                    del updated_conf[option]

            if have_conf.get('ra_prefixes'):
                updated_conf['ra_prefixes'] = deepcopy(have_conf['ra_prefixes'])
                for updated_prefix in updated_conf['ra_prefixes']:
                    for option, def_value in DEFAULT_PREFIX_VALUES.items():
                        if updated_prefix.get(option) == def_value:
                            del updated_prefix[option]
        else:
            # For merge operation, the default values in conf are removed
            # if that option is not present in have_conf
            updated_conf = conf
            if conf:
                updated_conf = conf.copy()
                have_conf = have_conf if have_conf else {}
                for option, def_value in DEFAULT_RTADV_VALUES.items():
                    if option not in have_conf and conf.get(option) == def_value:
                        del updated_conf[option]

                if conf.get('ra_prefixes'):
                    updated_conf['ra_prefixes'] = deepcopy(conf['ra_prefixes'])
                    have_prefixes = {item['prefix']: item for item in have_conf['ra_prefixes']} if have_conf.get('ra_prefixes') else {}
                    for updated_prefix in updated_conf['ra_prefixes']:
                        have_prefix = have_prefixes.get(updated_prefix['prefix'], {})
                        for option, def_value in DEFAULT_PREFIX_VALUES.items():
                            if option not in have_prefix and updated_prefix.get(option) == def_value:
                                del updated_prefix[option]

        return updated_conf

    def validate_and_normalize_want(self, want):
        state = self._module.params['state']
        if not want:
            if state != 'deleted':
                self._module.fail_json(msg='value of config parameter must not be empty for state {0}'.format(state))
            return []
        else:
            updated_want = remove_empties_from_list(want)
            normalize_interface_name(updated_want, self._module)
            return updated_want

    @staticmethod
    def sort_lists_in_config(config):
        if config:
            config.sort(key=lambda x: x['name'])
            for cfg in config:
                if cfg.get('dnssl'):
                    cfg['dnssl'].sort(key=lambda x: x['dnssl_name'])
                if cfg.get('ra_prefixes'):
                    cfg['ra_prefixes'].sort(key=lambda x: x['prefix'])
                if cfg.get('rdnss'):
                    cfg['rdnss'].sort(key=lambda x: x['address'])
