#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_acl_interfaces class
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
    remove_empties,
    validate_config
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

DELETE = 'delete'
POST = 'post'

TEST_KEYS = [
    {'config': {'name': ''}},
    {'access_groups': {'type': ''}},
    {'acls': {'name': ''}}
]

TEST_KEYS_formatted_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'access_groups': {'type': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'acls': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
]

acl_type_to_payload_map = {
    'mac': 'ACL_L2',
    'ipv4': 'ACL_IPV4',
    'ipv6': 'ACL_IPV6'
}


class Acl_interfaces(ConfigBase):
    """
    The sonic_acl_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'acl_interfaces',
    ]

    acl_interfaces_path = 'data/openconfig-acl:acl/interfaces/interface={intf_name}'
    ingress_acl_set_path = acl_interfaces_path + '/ingress-acl-sets/ingress-acl-set={acl_name},{acl_type}'
    egress_acl_set_path = acl_interfaces_path + '/egress-acl-sets/egress-acl-set={acl_name},{acl_type}'

    def __init__(self, module):
        super(Acl_interfaces, self).__init__(module)

    def get_acl_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        acl_interfaces_facts = facts['ansible_network_resources'].get('acl_interfaces')
        if not acl_interfaces_facts:
            return []
        return acl_interfaces_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = []

        existing_acl_interfaces_facts = self.get_acl_interfaces_facts()
        commands, requests = self.set_config(existing_acl_interfaces_facts)
        if commands:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        changed_acl_interfaces_facts = self.get_acl_interfaces_facts()

        result['before'] = existing_acl_interfaces_facts
        if result['changed']:
            result['after'] = changed_acl_interfaces_facts

        result['commands'] = commands

        new_config = changed_acl_interfaces_facts
        old_config = existing_acl_interfaces_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_acl_interfaces_facts,
                                        TEST_KEYS_formatted_diff)
            self.post_process_generated_config(new_config)
            result['after(generated)'] = new_config
        if self._module._diff:
            self.sort_config(new_config)
            self.sort_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_acl_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want:
            want = self.validate_and_normalize_config(want)
        else:
            want = []

        have = existing_acl_interfaces_facts
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
        if state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)

        return commands, requests

    def _state_replaced(self, want, have):
        """ The command generator when state is replaced

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        del_commands = []
        add_commands = []

        have_interfaces = self.get_interface_names(have)
        want_interfaces = self.get_interface_names(want)
        interfaces_to_replace = have_interfaces.intersection(want_interfaces)

        del_diff = get_diff(have, want, TEST_KEYS)
        for cmd in del_diff:
            if cmd['name'] in interfaces_to_replace:
                del_commands.append(cmd)

        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests.extend(self.get_interfaces_acl_unbind_requests(del_commands))

        add_diff = get_diff(want, have, TEST_KEYS)
        # Handle scenarios in replaced state, when only the interface
        # name is specified for deleting all ACL bindings in it.
        for cmd in add_diff:
            if cmd.get('access_groups'):
                add_commands.append(cmd)

        if add_commands:
            commands.extend(update_states(add_commands, 'replaced'))
            requests.extend(self.get_interfaces_acl_bind_requests(add_commands))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        del_commands = []

        have_interfaces = self.get_interface_names(have)
        want_interfaces = self.get_interface_names(want)
        interfaces_to_delete = have_interfaces.difference(want_interfaces)
        interfaces_to_override = have_interfaces.intersection(want_interfaces)

        del_diff = get_diff(have, want, TEST_KEYS)
        for cmd in del_diff:
            if cmd['name'] in interfaces_to_delete:
                del_commands.append({'name': cmd['name']})
            elif cmd['name'] in interfaces_to_override:
                del_commands.append(cmd)

        if del_commands:
            commands = update_states(del_commands, 'deleted')
            requests.extend(self.get_interfaces_acl_unbind_requests(del_commands))

        diff = get_diff(want, have, TEST_KEYS)
        if diff:
            commands.extend(update_states(diff, 'overridden'))
            requests.extend(self.get_interfaces_acl_bind_requests(diff))

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []
        requests = []

        diff = get_diff(want, have, TEST_KEYS)
        if diff:
            requests = self.get_interfaces_acl_bind_requests(diff)
            commands = update_states(diff, 'merged')

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
            # Delete all interface ACL bindings in the chassis
            for cfg in have:
                commands.append({'name': cfg['name']})
        else:
            want_dict = self._convert_config_list_to_dict(want)
            have_dict = self._convert_config_list_to_dict(have)

            for intf_name, access_groups in want_dict.items():
                have_obj = have_dict.get(intf_name)
                if not have_obj:
                    continue

                if not access_groups:
                    commands.append({'name': intf_name})
                else:
                    access_groups_to_del = []
                    for acl_type, acls in access_groups.items():
                        acls_to_delete = []
                        if not have_obj.get(acl_type):
                            continue

                        # Delete all bindings of ACLs belonging to a type in an
                        # interface, if only the ACL type is provided
                        if not acls:
                            for acl_name, direction in have_obj[acl_type].items():
                                acls_to_delete.append({'name': acl_name, 'direction': direction})
                        else:
                            for acl_name, direction in acls.items():
                                if have_obj[acl_type].get(acl_name) and direction == have_obj[acl_type][acl_name]:
                                    acls_to_delete.append({'name': acl_name, 'direction': direction})

                        if acls_to_delete:
                            access_groups_to_del.append({'type': acl_type, 'acls': acls_to_delete})

                    if access_groups_to_del:
                        commands.append({'name': intf_name, 'access_groups': access_groups_to_del})

        if commands:
            requests = self.get_interfaces_acl_unbind_requests(commands)
            commands = update_states(commands, 'deleted')

        return commands, requests

    def get_interfaces_acl_bind_requests(self, commands):
        """Get requests to bind specified ACLs for all interfaces
        specified the commands
        """
        requests = []

        for command in commands:
            intf_name = command['name']
            url = self.acl_interfaces_path.format(intf_name=intf_name)
            for access_group in command['access_groups']:
                for acl in access_group['acls']:
                    if acl['direction'] == 'in':
                        payload = {
                            'openconfig-acl:config': {
                                'id': intf_name
                            },
                            'openconfig-acl:interface-ref': {
                                'config': {
                                    'interface': intf_name.split('.')[0]
                                }
                            },
                            'openconfig-acl:ingress-acl-sets': {
                                'ingress-acl-set': [
                                    {
                                        'set-name': acl['name'],
                                        'type': acl_type_to_payload_map[access_group['type']],
                                        'config': {
                                            'set-name': acl['name'],
                                            'type': acl_type_to_payload_map[access_group['type']]
                                        }
                                    }
                                ]
                            }
                        }
                    else:
                        payload = {
                            'openconfig-acl:config': {
                                'id': intf_name
                            },
                            'openconfig-acl:interface-ref': {
                                'config': {
                                    'interface': intf_name.split('.')[0]
                                }
                            },
                            'openconfig-acl:egress-acl-sets': {
                                'egress-acl-set': [
                                    {
                                        'set-name': acl['name'],
                                        'type': acl_type_to_payload_map[access_group['type']],
                                        'config': {
                                            'set-name': acl['name'],
                                            'type': acl_type_to_payload_map[access_group['type']]
                                        }
                                    }
                                ]
                            }
                        }

                    # Update the payload for subinterfaces
                    if '.' in intf_name:
                        payload['openconfig-acl:interface-ref']['config']['subinterface'] = int(intf_name.split('.')[1])

                    requests.append({'path': url, 'method': POST, 'data': payload})

        return requests

    def get_interfaces_acl_unbind_requests(self, commands):
        """Get requests to unbind specified ACLs for all interfaces
        specified in the commands
        """
        requests = []

        for command in commands:
            intf_name = command['name']
            # Delete all acl bindings in an interface, if only the
            # interface name is provided
            if not command.get('access_groups'):
                url = self.acl_interfaces_path.format(intf_name=intf_name)
                requests.append({'path': url, 'method': DELETE})
            else:
                for access_group in command['access_groups']:
                    for acl in access_group['acls']:
                        if acl['direction'] == 'in':
                            url = self.ingress_acl_set_path.format(intf_name=intf_name, acl_name=acl['name'],
                                                                   acl_type=acl_type_to_payload_map[access_group['type']])
                            requests.append({'path': url, 'method': DELETE})
                        else:
                            url = self.egress_acl_set_path.format(intf_name=intf_name, acl_name=acl['name'],
                                                                  acl_type=acl_type_to_payload_map[access_group['type']])
                            requests.append({'path': url, 'method': DELETE})

        return requests

    def validate_and_normalize_config(self, config_list):
        """Validate and normalize the given config"""
        # Remove empties and validate the config with argument spec
        config_list = [remove_empties(config) for config in config_list]
        validate_config(self._module.argument_spec, {'config': config_list})
        normalize_interface_name(config_list, self._module)

        state = self._module.params['state']
        # When state is deleted, empty access_groups and acls are
        # supported and therefore no futher changes are required.
        if state == 'deleted':
            return config_list

        updated_config_list = []
        for config in config_list:
            if not config.get('access_groups'):
                # When state is replaced, if only the interface name is
                # specified for deleting all ACL bindings in it do not
                # remove that config.
                if state == 'replaced':
                    updated_config_list.append(config)
            else:
                access_group_list = []
                for access_group in config['access_groups']:
                    if access_group.get('acls'):
                        access_group_list.append(access_group)

                if access_group_list:
                    updated_config_list.append({'name': config['name'], 'access_groups': access_group_list})

        return updated_config_list

    @staticmethod
    def get_interface_names(config_list):
        """Get a set of interface names available in the given
        config_list dict
        """
        interface_names = set()
        for config in config_list:
            interface_names.add(config['name'])

        return interface_names

    @staticmethod
    def _convert_config_list_to_dict(config_list):
        config_dict = {}

        for config in config_list:
            config_dict[config['name']] = {}
            if config.get('access_groups'):
                for access_group in config['access_groups']:
                    config_dict[config['name']][access_group['type']] = {}
                    if access_group.get('acls'):
                        for acl in access_group['acls']:
                            config_dict[config['name']][access_group['type']][acl['name']] = acl['direction']

        return config_dict

    def sort_config(self, configs):
        # natsort provides better result.
        # The use of natsort causes sanity error due to it is not available in
        # python version currently used.
        # new_config = natsorted(new_config, key=lambda x: x['name'])
        # For time-being, use simple "sort"
        configs.sort(key=lambda x: x['name'])

        for conf in configs:
            ags = conf.get('access_groups', [])
            if ags:
                ags.sort(key=lambda x: x['type'])
                for ag in ags:
                    if ag.get('acls', []):
                        ag['acls'].sort(key=lambda x: x['name'])

    def post_process_generated_config(self, configs):
        for conf in configs[:]:
            ags = conf.get('access_groups', [])
            if ags:
                for ag in ags[:]:
                    if not ag.get('acls', []):
                        ags.remove(ag)

            if not conf.get('access_groups', []):
                configs.remove(conf)
