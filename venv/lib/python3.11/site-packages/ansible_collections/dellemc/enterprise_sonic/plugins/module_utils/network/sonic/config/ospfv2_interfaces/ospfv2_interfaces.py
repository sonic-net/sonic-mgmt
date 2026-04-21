#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ospfv2_interfaces class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
import ipaddress
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    normalize_interface_name,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff,
    __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'
DEFAULT_ADDRESS = '0.0.0.0'

TEST_KEYS = [
    {'config': {'name': ''}},
    {'ospf_attributes': {'address': ''}},
    {'md_authentication': {'key_id': ''}}
]

TEST_KEYS_overridden_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'ospf_attributes': {'address': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'md_authentication': {'key_id': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}}
]

OSPF_INT_ATTRIBUTES = {
    'bfd': {
        'enable': '/if-addresses={}/enable-bfd',
        'bfd_profile': '/if-addresses={}/enable-bfd/config/bfd-profile'
    },
    'network': '/if-addresses={}/config/network-type',
    'ospf_attributes': {
        'address': '/if-addresses={}',
        'area_id': '/if-addresses={}/config/area-id',
        'authentication': '/if-addresses={}/config/authentication-key',
        'authentication_type': '/if-addresses={}/config/authentication-type',
        'cost': '/if-addresses={}/config/metric',
        'dead_interval': '/if-addresses={}/config/dead-interval',
        'hello_interval': '/if-addresses={}/config/hello-interval',
        'hello_multiplier': '/if-addresses={}/config/dead-interval-minimal',
        'md_authentication': '/if-addresses={}/md-authentications/md-authentication={}',
        'mtu_ignore': '/if-addresses={}/config/mtu-ignore',
        'priority': '/if-addresses={}/config/priority',
        'retransmit_interval': '/if-addresses={}/config/retransmission-interval',
        'transmit_delay': '/if-addresses={}/config/transmit-delay'
    }

}


class Ospfv2_interfaces(ConfigBase):
    """
    The sonic_ospfv2_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ospfv2_interfaces',
    ]

    def __init__(self, module):
        super(Ospfv2_interfaces, self).__init__(module)

    def get_ospfv2_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ospfv2_interfaces_facts = facts['ansible_network_resources'].get('ospfv2_interfaces')
        if not ospfv2_interfaces_facts:
            return []
        return ospfv2_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_ospfv2_interfaces_facts = self.get_ospfv2_interfaces_facts()
        commands, requests = self.set_config(existing_ospfv2_interfaces_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_ospfv2_interfaces_facts = self.get_ospfv2_interfaces_facts()

        result['before'] = existing_ospfv2_interfaces_facts
        if result['changed']:
            result['after'] = changed_ospfv2_interfaces_facts

        new_config = changed_ospfv2_interfaces_facts
        old_config = existing_ospfv2_interfaces_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_commands = deepcopy(commands)
            self._add_default_address(new_commands)
            self._add_default_address(new_config)
            self._add_default_address(old_config)

            if self._module.params['state'] == 'overridden':
                new_config = get_new_config(new_commands, old_config, TEST_KEYS_overridden_diff)
            else:
                new_config = get_new_config(new_commands, old_config, TEST_KEYS)
            self._add_default_address(new_config)
            self.sort_lists_in_config(new_config)
            new_config = self._get_generated_config(new_commands, new_config, self._module.params['state'])
            self._strip_default_address(new_config)
            self._strip_default_address(old_config)
            result['after(generated)'] = remove_empties_from_list(new_config)

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_ospfv2_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_ospfv2_interfaces_facts
        new_want = deepcopy(want)
        new_have = deepcopy(have)
        new_want = remove_empties_from_list(want)
        new_have = remove_empties_from_list(have)
        self._add_default_address(new_want)
        self._add_default_address(new_have)
        self.sort_lists_in_config(new_want)
        self.sort_lists_in_config(new_have)
        new_want = self._normalize_interface_name(new_want)
        resp = self.set_state(new_want, new_have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        state = self._module.params['state']

        if state == 'overridden' or state == 'replaced':
            commands, requests = self._state_replaced_or_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)

        return commands, requests

    def _state_replaced_or_overridden(self, want, have):
        """ The command generator when state is replaced or overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        add_config, del_config = self._get_replaced_overridden_config(want, have)
        if del_config:
            del_commands, del_requests = self.get_delete_ospf_interfaces_commands_requests(del_config, have, False)
            if len(del_requests) > 0:
                self._strip_default_address(del_commands)
                commands.extend(update_states(del_commands, 'deleted'))
                requests.extend(del_requests)

        if add_config:
            mod_requests = self.get_create_ospf_interfaces_requests(add_config, [])
            if len(mod_requests) > 0:
                self._strip_default_address(add_config)
                commands.extend(update_states(add_config, self._module.params['state']))
                requests.extend(mod_requests)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have)
        requests = self.get_create_ospf_interfaces_requests(commands, have)

        if commands and len(requests) > 0:
            self._strip_default_address(commands)
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
        is_delete_all = False

        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        del_commands, requests = self.get_delete_ospf_interfaces_commands_requests(commands, have, is_delete_all)

        if del_commands and len(requests) > 0:
            self._strip_default_address(del_commands)
            commands = update_states(del_commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def _get_replaced_overridden_config(self, want, have):
        add_config, del_config = [], []
        state = self._module.params['state']
        for conf in want:
            intf_name = conf.get('name')
            have_conf = next((cfg for cfg in have if cfg['name'] == intf_name), None)
            if not have_conf:
                add_config.append(conf)
            else:
                add_cfg, del_cfg = {}, {}
                for attr in OSPF_INT_ATTRIBUTES:
                    if attr in conf:
                        if attr not in have_conf:
                            add_cfg[attr] = conf[attr]
                        else:
                            if attr == 'bfd':
                                for bfd_attr in ['enable', 'bfd_profile']:
                                    if bfd_attr in conf[attr]:
                                        if bfd_attr not in have_conf[attr]:
                                            add_cfg.setdefault(attr, {})[bfd_attr] = conf[attr][bfd_attr]
                                        elif conf[attr][bfd_attr] != have_conf[attr][bfd_attr]:
                                            add_cfg.setdefault(attr, {})[bfd_attr] = conf[attr][bfd_attr]
                                    elif bfd_attr in have_conf[attr]:
                                        del_cfg.setdefault(attr, {})[bfd_attr] = have_conf[attr][bfd_attr]
                            elif attr == 'network':
                                if conf[attr] != have_conf[attr]:
                                    add_cfg[attr] = conf[attr]
                            else:
                                # attr = 'ospf_attributes'
                                ospf_attr = conf[attr]
                                match_ospf_attr = have_conf.get(attr, [])
                                for ospf_list in ospf_attr:
                                    address = ospf_list.get('address')
                                    match_ospf_list = next((o_list for o_list in match_ospf_attr if o_list.get('address') == address), None)
                                    if not match_ospf_list:
                                        add_cfg.setdefault(attr, []).append(ospf_list)
                                    else:
                                        add_ospf_attr, del_ospf_attr = self._get_replaced_config_for_ospf_attributes(ospf_list, match_ospf_list)
                                        if add_ospf_attr:
                                            add_ospf_attr['address'] = address
                                            add_cfg.setdefault(attr, []).append(add_ospf_attr)
                                        if del_ospf_attr:
                                            del_ospf_attr['address'] = address
                                            del_cfg.setdefault(attr, []).append(del_ospf_attr)
                                for match_ospf_list in match_ospf_attr:
                                    address = match_ospf_list.get('address')
                                    ospf_list = next((o_list for o_list in ospf_attr if o_list.get('address') == address), None)
                                    if not ospf_list:
                                        del_cfg.setdefault(attr, []).append({'address': address})
                    elif attr in have_conf:
                        del_cfg[attr] = have_conf[attr]
                if add_cfg:
                    add_cfg['name'] = intf_name
                    add_config.append(add_cfg)
                if del_cfg:
                    del_cfg['name'] = intf_name
                    del_config.append(del_cfg)

        if state == 'overridden':
            for conf in have:
                intf_name = conf.get('name')
                want_conf = next((cfg for cfg in want if cfg['name'] == intf_name), None)
                if not want_conf:
                    del_config.append({'name': intf_name})
        return add_config, del_config

    def _get_replaced_config_for_ospf_attributes(self, want, have):
        add_config, del_config = {}, {}
        for ospf_attr in OSPF_INT_ATTRIBUTES['ospf_attributes']:
            if ospf_attr == 'hello_multiplier':
                if ospf_attr in want:
                    if ospf_attr not in have:
                        add_config[ospf_attr] = want[ospf_attr]
                        if 'dead_interval' in have:
                            del_config['dead_interval'] = have['dead_interval']
                    elif want[ospf_attr] != have[ospf_attr]:
                        add_config[ospf_attr] = want[ospf_attr]
                elif ospf_attr in have:
                    del_config[ospf_attr] = have[ospf_attr]
            elif ospf_attr == 'dead_interval':
                if ospf_attr in want:
                    if ospf_attr not in have:
                        add_config[ospf_attr] = want[ospf_attr]
                        if 'hello_interval' in have:
                            del_config['hello_interval'] = have['hello_interval']
                    elif want[ospf_attr] != have[ospf_attr]:
                        add_config[ospf_attr] = want[ospf_attr]
                elif ospf_attr in have:
                    del_config[ospf_attr] = have[ospf_attr]
            elif ospf_attr in want:
                if ospf_attr not in have:
                    add_config[ospf_attr] = want[ospf_attr]
                elif want[ospf_attr] != have[ospf_attr]:
                    if ospf_attr != 'md_authentication':
                        add_config[ospf_attr] = want[ospf_attr]
                        if ospf_attr == 'area_id':
                            del_config['area_id'] = have['area_id']
                    else:
                        have_mdkeys = have[ospf_attr]
                        conf_mdkeys = want[ospf_attr]
                        add_mdkeys, del_mdkeys = [], []
                        for conf_key in conf_mdkeys:
                            match_key = next((key for key in have_mdkeys if key['key_id'] == conf_key['key_id']), None)
                            if match_key:
                                if match_key['pwd'] != conf_key['pwd']:
                                    add_mdkeys.append(conf_key)
                                    del_mdkeys.append(match_key)
                            else:
                                add_mdkeys.append(conf_key)
                        for match_key in have_mdkeys:
                            conf_key = next((key for key in conf_mdkeys if key['key_id'] == match_key['key_id']), None)
                            if not conf_key:
                                del_mdkeys.append(match_key)
                        if add_mdkeys:
                            add_config[ospf_attr] = add_mdkeys
                        if del_mdkeys:
                            del_config[ospf_attr] = del_mdkeys
            elif ospf_attr in have:
                del_config[ospf_attr] = have[ospf_attr]

        return add_config, del_config

    def get_create_ospf_interfaces_requests(self, commands, have):
        requests = []
        bfd_dict = {}
        if not commands:
            return requests

        for cmd in commands:
            payload = {}
            bfd_dict = {}
            name = cmd.get('name')
            match = next((item for item in have if item['name'] == cmd['name']), None)
            intf_name, sub_intf = self.get_ospf_if_and_subif(name)
            ospf_path = self.get_ospf_uri(intf_name, sub_intf)
            ospf_attr_configs = []
            default_address_attr_dict = {}
            network_type = ""
            for attr in cmd:
                if attr == 'name':
                    continue
                if attr == 'ospf_attributes':
                    for ospf_list in cmd.get(attr, []):
                        ospf_attr_dict = {}
                        ospf_md_configs_list = []
                        address = ospf_list.get('address')
                        area_id = ospf_list.get('area_id')
                        if address and area_id and match:
                            for match_attr in match.get('ospf_attributes', []):
                                match_address = match_attr.get('address')
                                match_area_id = match_attr.get('area_id')
                                if match_address and match_area_id and match_address == address and match_area_id != area_id:
                                    path = ospf_path + OSPF_INT_ATTRIBUTES['ospf_attributes']['area_id'].format(address)
                                    requests.append({'path': path, 'method': DELETE})
                                    break

                        self.update_dict(ospf_list, ospf_attr_dict, 'area_id', 'area-id')
                        self.update_dict(ospf_list, ospf_attr_dict, 'authentication_type', 'authentication-type')
                        self.update_dict(ospf_list, ospf_attr_dict, 'cost', 'metric')
                        self.update_dict(ospf_list, ospf_attr_dict, 'dead_interval', 'dead-interval')
                        self.update_dict(ospf_list, ospf_attr_dict, 'hello_interval', 'hello-interval')
                        self.update_dict(ospf_list, ospf_attr_dict, 'hello_multiplier', 'hello-multiplier')
                        if 'hello-multiplier' in ospf_attr_dict:
                            ospf_attr_dict['dead-interval-minimal'] = True
                        self.update_dict(ospf_list, ospf_attr_dict, 'mtu_ignore', 'mtu-ignore')
                        self.update_dict(ospf_list, ospf_attr_dict, 'priority', 'priority')
                        self.update_dict(ospf_list, ospf_attr_dict, 'retransmit_interval', 'retransmission-interval')
                        self.update_dict(ospf_list, ospf_attr_dict, 'transmit_delay', 'transmit-delay')

                        if 'authentication' in ospf_list:
                            self.update_dict(ospf_list['authentication'], ospf_attr_dict, 'password', 'authentication-key')
                            self.update_dict(ospf_list['authentication'], ospf_attr_dict, 'encrypted', 'authentication-key-encrypted')

                        if 'md_authentication' in ospf_list:
                            for mdkeys in ospf_list['md_authentication']:
                                md_config = {}
                                self.update_dict(mdkeys, md_config, 'key_id', 'authentication-key-id')
                                if md_config:
                                    md_config.setdefault('config', {})
                                self.update_dict(mdkeys, md_config['config'], 'key_id', 'authentication-key-id')
                                self.update_dict(mdkeys, md_config['config'], 'encrypted', 'authentication-key-encrypted')
                                self.update_dict(mdkeys, md_config['config'], 'md5key', 'authentication-md5-key')
                                if md_config:
                                    ospf_md_configs_list.append(md_config)

                        if ospf_attr_dict:
                            ospf_attr_dict = {'config': ospf_attr_dict}
                        if ospf_md_configs_list:
                            ospf_attr_dict['md-authentications'] = {'md-authentication': ospf_md_configs_list}

                        if ospf_attr_dict:
                            if address == DEFAULT_ADDRESS:
                                default_address_attr_dict = ospf_attr_dict
                            else:
                                ospf_attr_dict.setdefault('config', {})['address'] = address
                                ospf_attr_dict['address'] = address
                                ospf_attr_configs.append(ospf_attr_dict)
                elif attr == 'bfd':
                    self.update_dict(cmd[attr], bfd_dict, 'enable', 'enabled')
                    self.update_dict(cmd[attr], bfd_dict, 'bfd_profile', 'bfd-profile')
                elif attr == 'network':
                    network_type = cmd.get('network')
                    if network_type:
                        network_type = 'openconfig-ospf-types:' + network_type.upper() + '_NETWORK'

            if default_address_attr_dict:
                default_address_attr_dict.setdefault('config', {})['address'] = DEFAULT_ADDRESS
                if network_type:
                    default_address_attr_dict['config']['network-type'] = network_type
                default_address_attr_dict['address'] = DEFAULT_ADDRESS
                ospf_attr_configs.append(default_address_attr_dict)
            elif network_type:
                ospf_attr_configs.append({
                    'address': DEFAULT_ADDRESS,
                    'config': {'network-type': network_type, 'address': DEFAULT_ADDRESS}
                })

            if ospf_attr_configs:
                payload = {
                    'openconfig-ospfv2-ext:ospfv2': {
                        'if-addresses': ospf_attr_configs
                    }
                }
                requests.append({'path': ospf_path, 'method': PATCH, 'data': payload})
            if bfd_dict:
                payload = {
                    'openconfig-ospfv2-ext:ospfv2': {
                        'if-addresses': [{
                            'address': DEFAULT_ADDRESS,
                            'enable-bfd': {'config': bfd_dict}
                        }]
                    }
                }
                requests.append({'path': ospf_path, 'method': PATCH, 'data': payload})
        return requests

    def get_delete_ospf_interfaces_commands_requests(self, commands, have, is_delete_all):
        commands_del, requests = [], []
        if not commands:
            return commands_del, requests

        for cmd in commands:
            del_cmd = {}
            name = cmd.get('name')
            intf_name, sub_intf = self.get_ospf_if_and_subif(name)
            ospf_path = self.get_ospf_uri(intf_name, sub_intf)
            match_have = next((cfg for cfg in have if cfg['name'] == name), None)
            if match_have:
                if is_delete_all or len(cmd) == 1:
                    commands_del.append(match_have)
                    requests.append({'path': ospf_path, 'method': DELETE})
                    continue
                for attr in cmd:
                    if attr == 'name':
                        continue
                    if attr == 'bfd':
                        if 'enable' in cmd.get(attr, {}) and 'enable' in match_have.get(attr, {}):
                            path = ospf_path + OSPF_INT_ATTRIBUTES['bfd']['enable'].format(DEFAULT_ADDRESS)
                            requests.append({'path': path, 'method': DELETE})
                            del_cmd.setdefault(attr, {})['enable'] = match_have[attr]['enable']
                            if 'bfd_profile' in match_have.get(attr, {}):
                                del_cmd[attr]['bfd_profile'] = match_have[attr]['bfd_profile']
                        elif 'bfd_profile' in cmd.get(attr, {}) and 'bfd_profile' in match_have.get(attr, {}):
                            path = ospf_path + OSPF_INT_ATTRIBUTES['bfd']['bfd_profile'].format(DEFAULT_ADDRESS)
                            requests.append({'path': path, 'method': DELETE})
                            del_cmd.setdefault(attr, {})['bfd_profile'] = match_have[attr]['bfd_profile']
                    elif attr == 'network' and match_have.get(attr, {}):
                        path = ospf_path + OSPF_INT_ATTRIBUTES['network'].format(DEFAULT_ADDRESS)
                        requests.append({'path': path, 'method': DELETE})
                        del_cmd[attr] = match_have[attr]
                    elif attr == 'ospf_attributes':
                        match_ospf_attrs = match_have.get('ospf_attributes', [])
                        if match_ospf_attrs:
                            ospf_attrs = cmd.get('ospf_attributes')
                            if ospf_attrs is not None:
                                if not ospf_attrs:
                                    # Delete all attributes in have
                                    del_ospf_attrs, del_requests = self.get_delete_ospf_attributes_commands_requests(match_ospf_attrs, None, ospf_path)
                                    requests.extend(del_requests)
                                    if del_ospf_attrs:
                                        del_cmd[attr] = del_ospf_attrs
                                else:
                                    # Delete specific attributes in have
                                    del_ospf_attrs, del_requests = self.get_delete_ospf_attributes_commands_requests(match_ospf_attrs, ospf_attrs, ospf_path)
                                    requests.extend(del_requests)
                                    if del_ospf_attrs:
                                        del_cmd[attr] = del_ospf_attrs
            if del_cmd:
                del_cmd['name'] = name
                commands_del.append(del_cmd)
        return commands_del, requests

    def get_delete_ospf_attributes_commands_requests(self, match_ospf_attrs, ospf_attrs, ospf_path=''):
        commands, requests = [], []
        if ospf_attrs:
            for o_attr in ospf_attrs:
                del_ospf_attr = {}
                address = o_attr.get('address')
                if address:
                    m_attr = next((cfg for cfg in match_ospf_attrs if cfg['address'] == address), None)
                    if m_attr:
                        if len(o_attr) == 1:
                            cmd, requests_to_delete = self.get_delete_all_ospf_attributes_per_address_commands_requests(m_attr, ospf_path)
                            requests.extend(requests_to_delete)
                            if cmd:
                                cmd['address'] = address
                                del_ospf_attr = cmd
                                commands.append(del_ospf_attr)
                            continue
                        for attr in o_attr:
                            if attr not in ('md_authentication', 'address'):
                                if attr in m_attr and o_attr[attr] is not None and m_attr[attr] is not None:
                                    requests.append({
                                        'path': ospf_path + OSPF_INT_ATTRIBUTES['ospf_attributes'][attr].format(address),
                                        'method': DELETE
                                    })
                                    del_ospf_attr[attr] = m_attr[attr]
                            elif attr == 'md_authentication':
                                if o_attr.get(attr) is None:
                                    del_mkeys = []
                                    for key in m_attr.get(attr, []):
                                        requests.append({
                                            'path': ospf_path + OSPF_INT_ATTRIBUTES['ospf_attributes'][attr].format(m_attr['address'], key['key_id']),
                                            'method': DELETE
                                        })
                                        del_mkeys.append(key)
                                    if del_mkeys:
                                        del_ospf_attr[attr] = del_mkeys

                                else:
                                    del_mkeys = []
                                    for key in o_attr[attr]:
                                        match_key = next((cfg for cfg in m_attr.get(attr, []) if cfg['key_id'] == key['key_id']), None)
                                        if match_key:
                                            requests.append({
                                                'path': ospf_path + OSPF_INT_ATTRIBUTES['ospf_attributes'][attr].format(address, key['key_id']),
                                                'method': DELETE
                                            })
                                            del_mkeys.append(match_key)
                                    if del_mkeys:
                                        del_ospf_attr[attr] = del_mkeys
                if del_ospf_attr:
                    del_ospf_attr['address'] = address
                    commands.append(del_ospf_attr)
        else:
            for m_attr in match_ospf_attrs:
                cmd, requests_to_delete = self.get_delete_all_ospf_attributes_per_address_commands_requests(m_attr, ospf_path)
                requests.extend(requests_to_delete)
                if cmd:
                    cmd['address'] = m_attr['address']
                    commands.append(cmd)

        return commands, requests

    def get_delete_all_ospf_attributes_per_address_commands_requests(self, m_attr, ospf_path):
        commands, requests = {}, []
        for attr in m_attr:
            if attr not in ('md_authentication', 'address'):
                requests.append({
                    'path': ospf_path + OSPF_INT_ATTRIBUTES['ospf_attributes'][attr].format(m_attr['address']),
                    'method': DELETE
                })
                commands[attr] = m_attr[attr]
            elif attr == 'md_authentication':
                del_mkeys = []
                for key in m_attr.get(attr, []):
                    requests.append({
                        'path': ospf_path + OSPF_INT_ATTRIBUTES['ospf_attributes'][attr].format(m_attr['address'], key['key_id']),
                        'method': DELETE
                    })
                    del_mkeys.append(key)
                if del_mkeys:
                    commands[attr] = del_mkeys
        return commands, requests

    def sort_lists_in_config(self, config):
        """ Sort the lists in the config """
        if config:
            config.sort(key=lambda x: x['name'])
            for cfg in config:
                if cfg.get('ospf_attributes', []):
                    cfg['ospf_attributes'].sort(key=lambda x: x['address'])
                    for ospf_attr in cfg.get('ospf_attributes', []):
                        if ospf_attr.get('md_authentication', []):
                            ospf_attr['md_authentication'].sort(key=lambda x: x['key_id'])

    def _strip_default_address(self, conf):
        if conf:
            for cfg in conf:
                for ospf_attr in cfg.get('ospf_attributes', []):
                    if ospf_attr.get('address') == DEFAULT_ADDRESS:
                        del ospf_attr['address']

    def _add_default_address(self, conf):
        if conf:
            for cfg in conf:
                for ospf_attr in cfg.get('ospf_attributes', []):
                    if not ospf_attr.get('address'):
                        ospf_attr['address'] = DEFAULT_ADDRESS

    def _getIpv4Address(self, ip):
        if ip.isdigit():
            ip = int(ip)
        try:
            return ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            self._module.fail_json(msg="Invalid IPv4 address: {}".format(ip))

    def get_ospf_intf_uri(self, intf_name, sub_intf=0):
        intf_name = intf_name.replace('/', '%2f')
        ospf_intf_uri = '/data/openconfig-interfaces:interfaces/interface={}'.format(intf_name)
        if intf_name.startswith('Vlan'):
            ospf_intf_uri += '/openconfig-vlan:routed-vlan'
        else:
            ospf_intf_uri += '/subinterfaces/subinterface={}'.format(sub_intf)
        return ospf_intf_uri

    def get_ospf_uri(self, intf_name, sub_intf=0):
        ospf_uri = self.get_ospf_intf_uri(intf_name, sub_intf)
        ospf_uri += '/openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2'
        return ospf_uri

    def get_ospf_if_and_subif(self, intf_name):
        return intf_name.split('.') if '.' in intf_name else (intf_name, 0)

    def update_dict(self, src, dest, src_key, dest_key, value=False):
        if not value:
            if src.get(src_key) is not None:
                dest[dest_key] = src[src_key]
        elif src:
            dest.update(value)

    def _normalize_interface_name(self, want):
        normalize_interface_name(want, self._module)
        for conf in want:
            ospf_attr = conf.get('ospf_attributes', [])
            for o_attr in ospf_attr:
                if 'area_id' in o_attr:
                    o_attr['area_id'] = str(self._getIpv4Address(o_attr['area_id']))
        return want

    def _get_generated_config(self, want, new_config, state):
        if state == 'merged':
            for cmd in want:
                name = cmd.get('name')
                match = next((cfg for cfg in new_config if cfg['name'] == name), None)
                if match:
                    match_ospf_attr = match.get('ospf_attributes', [])
                    cmd_ospf_attr = cmd.get('ospf_attributes', [])
                    for o_attr in cmd_ospf_attr:
                        m_attr = next((a for a in match_ospf_attr if a.get('address') == o_attr.get('address')), None)
                        if m_attr:
                            if 'dead_interval' in o_attr:
                                m_attr.pop('hello_multiplier', None)
                            if 'hello_multiplier' in o_attr:
                                m_attr.pop('dead_interval', None)
            return new_config
        else:
            new_generated_config = []
            for cmd in new_config:
                cmd_ospf_attr = cmd.get('ospf_attributes', [])
                ospf_attr = []
                for o_attr in cmd_ospf_attr:
                    if len(o_attr) > 1:
                        md_keys = []
                        o_md_keys = o_attr.get('md_authentication', [])
                        if o_md_keys:
                            for key in o_md_keys:
                                if len(key) > 1:
                                    md_keys.append(key)
                        if not md_keys:
                            o_attr.pop('md_authentication', None)
                        else:
                            o_attr['md_authentication'] = md_keys
                    if len(o_attr) > 1:
                        ospf_attr.append(o_attr)
                if ospf_attr:
                    cmd['ospf_attributes'] = ospf_attr
                else:
                    cmd.pop('ospf_attributes', None)
                if len(cmd) > 1:
                    new_generated_config.append(cmd)
            return new_generated_config
