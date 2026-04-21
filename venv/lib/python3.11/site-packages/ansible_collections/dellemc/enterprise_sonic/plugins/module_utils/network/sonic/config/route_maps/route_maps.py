#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_route_maps class
The code in this file compares the current configuration (as a dict)
to the configuration provided (as a dict) based on the contents of the
currently executing playbook. The result of the comparison and the end state
requested by the executing playbook are used to to determine the command set
necessary to bring the current configuration to it's desired end-state.
The resulting commands are then transmitted to the target device.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
    validate_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts \
    import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils \
    import (
        get_diff,
        update_states,
        remove_empties_from_list,
        get_normalize_interface_name,
        check_required
    )
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    convert_routemap_bgp_asn,
    to_extcom_str_list
)

TEST_KEYS = [
    {"config": {"map_name": "", "sequence_num": ""}}
]

TEST_KEYS_generate_config = [
    {"config": {"map_name": "", "sequence_num": "", '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}}
]

DELETE = "delete"
PATCH = "patch"


class Route_maps(ConfigBase):
    """
    The sonic_route_maps class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'route_maps',
    ]

    route_maps_uri = 'data/openconfig-routing-policy:routing-policy/policy-definitions'
    route_map_uri = route_maps_uri + '/policy-definition={0}'
    route_map_stmt_uri = route_map_uri + '/statements/statement={1}'
    route_map_stmt_base_uri = route_map_uri + '/statements/statement={1}/'
    route_maps_data_path = 'openconfig-routing-policy:policy-definitions'

    set_community_rest_names = {
        'additive': 'openconfig-routing-policy-ext:ADDITIVE',
        'local_as': 'openconfig-bgp-types:NO_EXPORT_SUBCONFED',
        'no_advertise': 'openconfig-bgp-types:NO_ADVERTISE',
        'no_export': 'openconfig-bgp-types:NO_EXPORT',
        'no_peer': 'openconfig-bgp-types:NOPEER',
        'none': 'openconfig-bgp-types:NONE'
    }

    set_extcomm_rest_names = {
        'rt': 'route-target:',
        'bandwidth': 'link-bandwidth:',
        'soo': 'route-origin:'
    }

    def __init__(self, module):
        super(Route_maps, self).__init__(module)

    def get_route_maps_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset,
                                                         self.gather_network_resources)
        route_maps_facts = facts['ansible_network_resources'].get('route_maps')
        if not route_maps_facts:
            return []
        return route_maps_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()

        existing_route_maps_facts = self.get_route_maps_facts()
        commands, requests = self.set_config(existing_route_maps_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_route_maps_facts = self.get_route_maps_facts()

        result['before'] = existing_route_maps_facts
        if result['changed']:
            result['after'] = changed_route_maps_facts

        new_config = changed_route_maps_facts
        old_config = existing_route_maps_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_route_maps_facts,
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

    def set_config(self, existing_route_maps_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want:
            want = self.validate_and_normalize_config(want)
            convert_routemap_bgp_asn(want)
        else:
            want = []

        have = existing_route_maps_facts
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
        commands = []
        requests = []
        state = self._module.params['state']
        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
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

        # Delete replaced groupings
        commands = deepcopy(want)
        requests = self.get_delete_replaced_groupings(commands, have)
        if not requests:
            commands = []
        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")

        if requests:
            modify_have = []
        else:
            modify_have = have

        # Apply the commands from the playbook
        diff = get_diff(want, modify_have, TEST_KEYS)
        merged_commands = diff
        replaced_requests = self.get_modify_route_maps_requests(merged_commands, want, have)
        requests.extend(replaced_requests)
        if merged_commands and len(replaced_requests) > 0:
            merged_commands = update_states(merged_commands, "replaced")
            commands.extend(merged_commands)

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        if not want:
            return commands, requests

        # Determine if there is any configuration specified in the playbook
        # that is not contained in the current configuration.
        diff_requested = get_diff(want, have, TEST_KEYS)

        # Determine if there is anything already configured that is not
        # specified in the playbook.
        diff_unwanted = get_diff(have, want, TEST_KEYS)

        # Idempotency check: If the configuration already matches the
        # requested configuration with no extra attributes, no
        # commands should be executed on the device.
        if not diff_requested and not diff_unwanted:
            return commands, requests

        # Delete all current route map configuration
        commands = have
        requests = self.get_delete_all_route_map_cfg_request()
        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")

        # Apply the commands from the playbook
        merged_commands = want
        overridden_requests = self.get_modify_route_maps_requests(merged_commands, want, [])
        requests.extend(overridden_requests)
        if merged_commands and len(overridden_requests) > 0:
            merged_commands = update_states(merged_commands, "overridden")
            commands.extend(merged_commands)
        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        diff = get_diff(want, have, TEST_KEYS)
        commands = diff
        requests = self.get_modify_route_maps_requests(commands, want, have)
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
        requests = []
        if not have or have == []:
            commands = []
        elif not want or want == []:
            commands = have
            requests = self.get_delete_all_route_map_cfg_request()
        else:
            commands = want
            requests = self.get_delete_route_maps_requests(have, commands)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_modify_route_maps_requests(self, commands, want, have):
        '''Traverse the input list of configuration "modify" commands
        obtained from parsing the input playbook parameters. For each
        command, create a route map configuration REST API to modify the route
        map specified by the current command.'''

        requests = []
        if not commands:
            return requests

        # Create URL and payload
        route_maps_payload_list = []
        route_maps_payload_dict = {'policy-definition': route_maps_payload_list}
        for command in commands:
            if command.get('action') is None:
                self.insert_route_map_cmd_action(command, want)
            route_map_payload = self.get_modify_single_route_map_request(command, have, requests)
            if route_map_payload:
                route_maps_payload_list.append(route_map_payload)

                # Note: This is consistent with current CLI behavior, but should be
                # revisited if and when the SONiC REST implementation is enhanced
                # for the "match peer" attribute.
                self.route_map_remove_configured_match_peer(route_map_payload, have, requests)

        route_maps_data = {self.route_maps_data_path: route_maps_payload_dict}
        request = {'path': self.route_maps_uri, 'method': PATCH, 'data': route_maps_data}
        requests.append(request)
        return requests

    def insert_route_map_cmd_action(self, command, want):
        '''Insert the "action" value into the specified "command" if it is not
        already present. This dictionary member will not be present in the
        command obtained from the "diff" utility if it is unchanged from its
        currently configured value because it is not a "difference" in the
        configuration requested by the playbook versus the current
        configuration. It is, however, needed in order to create the
        appropriate REST API for modifying other attributes in the route map.'''

        conf_map_name = command.get('map_name', None)
        conf_seq_num = command.get('sequence_num', None)
        if not conf_map_name or not conf_seq_num:
            return

        conf_action = command.get('action', None)
        if conf_action:
            return

        # Find the corresponding route map statement in the "want" dict
        # list and insert it into the current "command" dict.
        matching_map_in_want = self.get_matching_map(conf_map_name, conf_seq_num, want)
        if matching_map_in_want:
            conf_action = matching_map_in_want.get('action')
            if conf_action is not None:
                command['action'] = conf_action

    def get_modify_single_route_map_request(self, command, have, requests):
        '''Create and return the appropriate set of route map REST API attributes
        to modify the route map configuration specified by the current "command".'''

        route_map_request = self.get_route_map_request_skeleton(command)
        if route_map_request == {}:
            return route_map_request

        route_map_statement = route_map_request['statements']['statement'][0]

        self.get_route_map_modify_match_attr(command, route_map_statement)
        self.get_route_map_modify_set_attr(command, route_map_statement, have, requests)
        self.get_route_map_modify_call_attr(command, route_map_statement)

        return route_map_request

    def get_route_map_modify_match_attr(self, command, route_map_statement):
        '''In the dict specified by the input route_map_statement paramenter,
        provide REST API definitions of all "match" attributes contained in the
        user input command dict specified by the "command" input parameter
        to this function.'''

        match_top = command.get('match')
        if not match_top:
            return

        route_map_statement['conditions'] = {}

        #
        # Handle configuration for BGP policy "match" conditions
        # ------------------------------------------------------
        route_map_statement['conditions']['openconfig-bgp-policy:bgp-conditions'] = {}
        route_map_match_bgp_policy = \
            route_map_statement['conditions']['openconfig-bgp-policy:bgp-conditions']

        # Handle match as_path
        if match_top.get('as_path'):
            route_map_match_bgp_policy['match-as-path-set'] = {
                'config': {
                    'as-path-set': match_top['as_path'],
                    'match-set-options': 'ANY'
                }
            }
        # Handle match evpn
        if match_top.get('evpn'):
            route_map_match_bgp_policy['openconfig-policy-ext:match-evpn-set'] = \
                {'config': {}}
            route_map_match_bgp_evpn = \
                route_map_match_bgp_policy[
                    'openconfig-policy-ext:match-evpn-set']['config']
            if match_top['evpn'].get('default_route') is not None:
                boolval = self.yaml_bool_to_python_bool(match_top['evpn']['default_route'])
                route_map_match_bgp_evpn['default-type5-route'] = boolval
            if match_top['evpn'].get('route_type'):
                route_type_rest_name = ('openconfig-bgp-policy-ext:' +
                                        match_top['evpn']['route_type'].upper())
                route_map_match_bgp_evpn['route-type'] = route_type_rest_name
            if match_top['evpn'].get('vni'):
                route_map_match_bgp_evpn['vni-number'] = match_top['evpn']['vni']
            if not route_map_match_bgp_evpn:
                route_map_match_bgp_policy.pop('openconfig-policy-ext:match-evpn-set')

        # Handle BGP policy match  configuration under the "config" dictionary
        route_map_match_bgp_policy['config'] = {}
        if match_top.get('local_preference'):
            route_map_match_bgp_policy['config']['local-pref-eq'] = \
                match_top['local_preference']
        if match_top.get('metric'):
            route_map_match_bgp_policy['config']['med-eq'] = match_top['metric']
        if match_top.get('origin'):
            route_map_match_bgp_policy['config']['origin-eq'] = match_top['origin'].upper()
        if match_top.get('community'):
            route_map_match_bgp_policy['config']['community-set'] = match_top['community']
        if match_top.get('ext_comm'):
            route_map_match_bgp_policy['config']['ext-community-set'] = match_top['ext_comm']
        if match_top.get('ip') and match_top['ip'].get('next_hop'):
            route_map_match_bgp_policy[
                'config']['openconfig-bgp-policy-ext:next-hop-set'] = match_top['ip']['next_hop']
        if not route_map_match_bgp_policy['config']:
            route_map_match_bgp_policy.pop('config')

        if not route_map_match_bgp_policy:
            route_map_statement['conditions'].pop('openconfig-bgp-policy:bgp-conditions')

        # Handle match interface
        if match_top.get('interface'):
            route_map_statement['conditions']['match-interface'] = {
                'config': {'interface': match_top['interface']}
            }

        # Handle match IP address/prefix
        if match_top.get('ip') and match_top['ip'].get('address'):
            route_map_statement['conditions']['match-prefix-set'] = {
                'config': {
                    'prefix-set': match_top['ip']['address'],
                    'match-set-options': 'ANY'
                }
            }

        # Handle match IPv6 address/prefix
        if match_top.get('ipv6') and match_top['ipv6'].get('address'):
            if not route_map_statement['conditions'].get('match-prefix-set'):
                route_map_statement['conditions']['match-prefix-set'] = {
                    'config': {
                        'openconfig-routing-policy-ext:ipv6-prefix-set': match_top[
                            'ipv6']['address'], 'match-set-options': 'ANY'
                    }
                }
            else:
                route_map_statement[
                    'conditions']['match-prefix-set']['config'][
                        'openconfig-routing-policy-ext:ipv6-prefix-set'] = \
                    match_top['ipv6']['address']

        # Handle match peer
        if match_top.get('peer'):
            peer_list = list(match_top['peer'].values())
            route_map_statement['conditions']['match-neighbor-set'] = {
                'config': {
                    'openconfig-routing-policy-ext:address': peer_list
                }
            }

        # Handle match source protocol
        if match_top.get('source_protocol'):
            rest_protocol_name = ''
            if match_top['source_protocol'] in ('bgp', 'ospf', 'static'):
                rest_protocol_name = ('openconfig-policy-types:' +
                                      match_top['source_protocol'].upper())
            elif match_top['source_protocol'] == 'connected':
                rest_protocol_name = 'openconfig-policy-types:DIRECTLY_CONNECTED'

            route_map_statement['conditions']['config'] = \
                {'install-protocol-eq': rest_protocol_name}

        # Handle match source VRF
        if match_top.get('source_vrf'):
            route_map_statement[
                'conditions'][
                    'openconfig-routing-policy-ext:match-src-network-instance'
            ] = {'config': {'name': match_top['source_vrf']}}

        # Handle match tag
        if match_top.get('tag'):
            route_map_statement['conditions']['match-tag-set'] = {
                'config': {
                    'openconfig-routing-policy-ext:tag-value': [match_top['tag']]
                }
            }

    def get_route_map_modify_set_attr(self, command, route_map_statement, have, requests):
        '''In the dict specified by the input route_map_statement paramenter,
        provide REST API definitions of all "set" attributes contained in the
        user input command dict specified by the "command" input parameter
        to this function.'''

        cmd_set_top = command.get('set')
        if not cmd_set_top:
            return

        # Get the current configuration (if any) for this route map statement
        cfg_set_top = {}
        conf_map_name = command.get('map_name')
        conf_seq_num = command.get('sequence_num')
        cmd_rmap_have = self.get_matching_map(conf_map_name, conf_seq_num, have)
        if cmd_rmap_have:
            cfg_set_top = cmd_rmap_have.get('set', {})

        route_map_actions = route_map_statement['actions']

        # Handle configuration for BGP policy "set" conditions
        # ----------------------------------------------------
        route_map_actions['openconfig-bgp-policy:bgp-actions'] = {}
        route_map_bgp_actions = \
            route_map_actions['openconfig-bgp-policy:bgp-actions'] = {}
        # Handle 'set' ARS object
        if cmd_set_top.get('ars_object'):
            route_map_bgp_actions['openconfig-routing-policy-ext:ars-object'] = {
                'config': {
                    'set-ars-object': cmd_set_top['ars_object']
                }
            }

        # Handle 'set' AS path prepend
        if cmd_set_top.get('as_path_prepend'):
            route_map_bgp_actions['set-as-path-prepend'] = {
                'config': {
                    'openconfig-routing-policy-ext:asn-list': cmd_set_top['as_path_prepend'].to_request_attr_fmt()
                }
            }

        # Handle'set' community list delete
        if cmd_set_top.get('comm_list_delete'):
            route_map_bgp_actions['set-community-delete'] = {
                'config': {
                    'community-set-delete': cmd_set_top['comm_list_delete']
                }
            }

        # Handle 'set' community
        if cmd_set_top.get('community'):
            route_map_bgp_actions['set-community'] = {
                'config': {
                    'method': 'INLINE',
                    'options': 'ADD'
                },
                'inline': {
                    'config': {
                        'communities': []
                    }
                }
            }

            rmap_set_communities_cfg = \
                route_map_bgp_actions['set-community']['inline']['config']['communities']

            if cmd_set_top['community'].get('community_number'):

                # Abort the playbook if the Community "none' attribute is configured.
                if cfg_set_top:
                    if (cfg_set_top.get('community') and
                            cfg_set_top['community'].get('community_attributes') and
                            'none' in cfg_set_top['community']['community_attributes']):
                        self._module.fail_json(
                            msg='\nPlaybook aborted: The route map "set" community '
                                '"none" attribute is configured.\n\nPlease remove '
                                'the conflicting configuration to configure other '
                                'community "set" attributes.\n')

                comm_num_list = cmd_set_top['community']['community_number']

                for comm_num in comm_num_list:
                    rmap_set_communities_cfg.append(comm_num)

            if cmd_set_top['community'].get('community_attributes'):
                comm_attr_list = []
                comm_attr_list = cmd_set_top['community']['community_attributes']
                if 'none' in comm_attr_list:
                    # Verify that no other community attributes are being requested
                    # at the same time as the "none" attribute and that no
                    # community attributes are currently configured. Abort the
                    # playbook execution if these conditions are not met.
                    if len(comm_attr_list) > 1 or rmap_set_communities_cfg:
                        self._module.fail_json(
                            msg='\nPlaybook aborted: The route map "set" community "none"'
                                'attribute cannot be configured when other "set" community '
                                'attributes are requested or configured.\n\n'
                                'Please revise the playbook to configure the "none"'
                                'attribute.\n')

                    # Abort the playbook if other Community "set" attributes are
                    # currently configured.
                    if cfg_set_top:
                        if (cfg_set_top.get('community') and
                                (cfg_set_top['community'].get('community_number') or
                                 (cfg_set_top['community'].get('community_attributes') and
                                  'none' not in cfg_set_top['community']['community_attributes']))):
                            self._module.fail_json(
                                msg='\nPlaybook aborted: The route map "set" community "none" '
                                    ' attribute cannot be configured when other"set" community '
                                    'attributes are requested or configured.\n\n'
                                    'Please remove the conflicting configuration to '
                                    'configure the "none" attribue.\n')

                    # Proceed with configuring 'none' if the validity checks passed.
                    rmap_set_communities_cfg.append('openconfig-bgp-types:NONE')
                else:

                    # Abort the playbook if the Community "none' attribute is configured.
                    if cfg_set_top:
                        if (cfg_set_top.get('community') and
                                cfg_set_top['community'].get('community_attributes') and
                                'none' in cfg_set_top['community']['community_attributes']):
                            self._module.fail_json(
                                msg='\nPlaybook aborted: The route map "set"community "none" attribute is '
                                    'configured.\n\n'
                                    'Please remove the conflicting configuration to configure '
                                    'other community "set" attributes.\n')

                    comm_attr_rest_name = {
                        'local_as': 'openconfig-bgp-types:NO_EXPORT_SUBCONFED',
                        'no_advertise': 'openconfig-bgp-types:NO_ADVERTISE',
                        'no_export': 'openconfig-bgp-types:NO_EXPORT',
                        'no_peer': 'openconfig-bgp-types:NOPEER',
                        'additive': 'openconfig-routing-policy-ext:ADDITIVE'
                    }

                    for comm_attr in comm_attr_list:
                        rmap_set_communities_cfg.append(comm_attr_rest_name[comm_attr])

        # Handle set extcommunity
        if cmd_set_top.get('extcommunity'):
            route_map_bgp_actions['set-ext-community'] = {
                'config': {
                    'method': 'INLINE',
                    'options': 'ADD'
                },
                'inline': {
                    'config': {
                        'communities': []
                    }
                }
            }

            rmap_set_extcommunities_cfg = \
                route_map_bgp_actions['set-ext-community']['inline']['config']['communities']

            if cmd_set_top['extcommunity'].get('rt'):
                rt_list = to_extcom_str_list(cmd_set_top['extcommunity']['rt'])

                for rt_val in rt_list:
                    rmap_set_extcommunities_cfg.append("route-target:" + rt_val)

            if cmd_set_top['extcommunity'].get('soo'):
                soo_list = to_extcom_str_list(cmd_set_top['extcommunity']['soo'])

                for soo in soo_list:
                    rmap_set_extcommunities_cfg.append("route-origin:" + soo)

            if cmd_set_top['extcommunity'].get('bandwidth'):

                # If the bandwidth extcommunity is already configured for an existing route map
                # with the same name and sequence number, remove the existing configuration.
                if cfg_set_top.get('extcommunity', {}) and cfg_set_top['extcommunity'].get('bandwidth'):
                    bandwidth_val = cfg_set_top['extcommunity']['bandwidth']['bandwidth_value']
                    if cfg_set_top['extcommunity']['bandwidth']['transitive_value']:
                        transitive_val = "transitive"
                    else:
                        transitive_val = "non-transitive"
                    bw_community_str = ":".join(["link-bandwidth", bandwidth_val, transitive_val])
                    remove_command = {}
                    remove_command["map_name"] = command.get('map_name')
                    remove_command["sequence_num"] = command.get('sequence_num')
                    remove_command["action"] = command.get("action")
                    remove_request = self.get_route_map_request_skeleton(remove_command)
                    route_map_remove_statement = remove_request['statements']['statement'][0]
                    route_map_remove_statement['actions']['openconfig-bgp-policy:bgp-actions'] = {
                        'set-ext-community': {
                            'config': {
                                'method': 'INLINE',
                                'options': 'REMOVE'
                            },
                            'inline': {
                                'config': {
                                    'communities': [bw_community_str]
                                }
                            }
                        }
                    }
                    remove_route_maps_data = {self.route_maps_data_path: {'policy-definition': [remove_request]}}
                    final_remove_request = {'path': self.route_maps_uri, 'method': PATCH, 'data': remove_route_maps_data}
                    requests.append(final_remove_request)

                # Proceed with creation of the new request.
                bandwidth_val = cmd_set_top['extcommunity'].get('bandwidth').get("bandwidth_value")
                if cmd_set_top['extcommunity'].get('bandwidth').get("transitive_value"):
                    transitive_val = "transitive"
                else:
                    transitive_val = "non-transitive"
                rmap_set_extcommunities_cfg.append(":".join(["link-bandwidth", bandwidth_val, transitive_val]))

        #
        # Handle configuration for BGP policy "set" conditions
        # to be located within the "config" sub-dictionary
        # ----------------------------------------------------
        route_map_bgp_actions['config'] = {}
        route_map_bgp_actions_cfg = \
            route_map_actions['openconfig-bgp-policy:bgp-actions']['config']

        # Handle set IP next hop.
        if cmd_set_top.get('ip_next_hop'):
            if cmd_set_top['ip_next_hop'].get('address'):
                route_map_bgp_actions_cfg['set-next-hop'] = \
                    cmd_set_top['ip_next_hop']['address']
            if cmd_set_top['ip_next_hop'].get('native') is not None:
                boolval = \
                    self.yaml_bool_to_python_bool(cmd_set_top['ip_next_hop']['native'])
                route_map_bgp_actions_cfg['openconfig-bgp-policy-ext:set-next-hop-native'] = boolval

        # Handle set IPv6 next hop.
        if cmd_set_top.get('ipv6_next_hop'):
            if cmd_set_top['ipv6_next_hop'].get('global_addr'):
                route_map_bgp_actions_cfg['set-ipv6-next-hop-global'] = \
                    cmd_set_top['ipv6_next_hop']['global_addr']
            if cmd_set_top['ipv6_next_hop'].get('prefer_global') is not None:
                boolval = \
                    self.yaml_bool_to_python_bool(cmd_set_top['ipv6_next_hop']['prefer_global'])
                route_map_bgp_actions_cfg['set-ipv6-next-hop-prefer-global'] = boolval
            if cmd_set_top['ipv6_next_hop'].get('native') is not None:
                boolval = \
                    self.yaml_bool_to_python_bool(cmd_set_top['ipv6_next_hop']['native'])
                route_map_bgp_actions_cfg['openconfig-bgp-policy-ext:set-ipv6-next-hop-native'] = boolval

        # Handle set local preference.
        if cmd_set_top.get('local_preference'):
            route_map_bgp_actions_cfg['set-local-pref'] = cmd_set_top['local_preference']

        # Handle set metric
        if cmd_set_top.get('metric'):
            route_map_actions['metric-action'] = {'config': {}}
            route_map_metric_actions = route_map_actions['metric-action']['config']

            if cmd_set_top['metric'].get('value'):
                route_map_metric_actions['metric'] = cmd_set_top['metric']['value']
                route_map_metric_actions['action'] = \
                    'openconfig-routing-policy:METRIC_SET_VALUE'
                route_map_bgp_actions_cfg['set-med'] = cmd_set_top['metric']['value']
            elif cmd_set_top['metric'].get('rtt_action'):
                if cmd_set_top['metric']['rtt_action'] == 'set':
                    route_map_metric_actions['action'] = \
                        'openconfig-routing-policy:METRIC_SET_RTT'
                elif cmd_set_top['metric']['rtt_action'] == 'add':
                    route_map_metric_actions['action'] = \
                        'openconfig-routing-policy:METRIC_ADD_RTT'
                elif cmd_set_top['metric']['rtt_action'] == 'subtract':
                    route_map_metric_actions['action'] = \
                        'openconfig-routing-policy:METRIC_SUBTRACT_RTT'

            if not route_map_metric_actions:
                route_map_actions.pop('metric-action')

        # Handle set origin
        if cmd_set_top.get('origin'):
            route_map_bgp_actions_cfg['set-route-origin'] = cmd_set_top['origin'].upper()

        # Handle set weight
        if cmd_set_top.get('weight'):
            route_map_bgp_actions_cfg['set-weight'] = cmd_set_top['weight']

        # Handle set tag
        if cmd_set_top.get('tag'):
            route_map_bgp_actions_cfg['set-tag'] = cmd_set_top['tag']

    @staticmethod
    def get_route_map_request_skeleton(command):
        '''Create and return the appropriate set of route map REST API attributes
        to create the route map configuration specified by the current "command".'''

        route_map_request = {}
        if not command:
            return route_map_request

        conf_map_name = command.get('map_name', None)
        conf_action = command.get('action', None)
        conf_seq_num = command.get('sequence_num', None)
        if not conf_map_name or not conf_action or not conf_seq_num:
            return route_map_request

        req_seq_num = str(conf_seq_num)

        if conf_action == 'permit':
            req_action = 'ACCEPT_ROUTE'
        elif conf_action == 'deny':
            req_action = 'REJECT_ROUTE'
        else:
            return route_map_request

        # Create a "blank" template for the request
        route_map_request = {
            'name': conf_map_name,
            'config': {'name': conf_map_name},
            'statements': {
                'statement': [
                    {
                        'name': req_seq_num,
                        'config': {
                            'name': req_seq_num
                        },
                        'actions': {
                            'config': {
                                'policy-result': req_action
                            }
                        }
                    }
                ]
            }
        }
        return route_map_request

    @staticmethod
    def get_route_map_modify_call_attr(command, route_map_statement):
        '''In the dict specified by the input route_map_statement paramenter,
        provide REST API definitions of the "call" attribute (if present)
        contained in the user input command dict specified by the "command"
        input parameter to this function.'''

        call_val = command.get('call')
        if not call_val:
            return

        if not route_map_statement.get('conditions'):
            route_map_statement['conditions'] = {'config': {}}
        elif not route_map_statement['conditions'].get('config'):
            route_map_statement['conditions']['config'] = {}
        route_map_statement['conditions']['config']['call-policy'] = call_val

    def get_delete_all_route_map_cfg_request(self):
        '''Append to the input list of REST API requests the REST API to
        Delete all route map configuration'''
        requests = [{'path': self.route_maps_uri, 'method': DELETE}]
        return requests

    def get_delete_one_route_map_cfg(self, conf_map_name, requests):
        '''Append to the input list of REST API requests the REST API to
        delete all configuration for the specified route map.'''

        delete_rmap_path = self.route_map_uri.format(conf_map_name)
        request = {'path': delete_rmap_path, 'method': DELETE}
        requests.append(request)

    def get_delete_route_map_stmt_cfg(self, command, requests):
        '''Append to the input list of REST API requests the REST API to
        delete all configuration for the route map "statement" (route
        map sub-section) specified by the combination of the route
        map name and "statement" sequence number in the input
        "command" dict.'''
        conf_map_name = command.get('map_name')
        conf_seq_num = command.get('sequence_num')
        req_seq_num = str(conf_seq_num)

        delete_rmap_stmt_path = self.route_map_stmt_uri.format(conf_map_name, req_seq_num)
        request = {'path': delete_rmap_stmt_path, 'method': DELETE}
        requests.append(request)

    def get_delete_route_maps_requests(self, have, commands):
        '''Traverse the input list of configuration "delete" commands obtained
        from parsing the input playbook parameters. For each command,
        create and return the appropriate set of REST API requests to delete
        the appropriate elements from the route map specified by the current command.'''

        requests = []
        if commands:
            for command in commands:
                # Create requests for "eligible" attributes within the current route
                # map statement. The content of the "command" object, on return from
                # execution has only the subset of currently configured attributes
                # within the full group of requested attributes for deletion from
                # this route map statement.
                self.get_delete_single_route_map_requests(have, command, requests)
        return requests

    def get_delete_single_route_map_requests(self, have, command, requests):
        '''Create and return the appropriate set of route map REST APIs
        to delete the eligible requestd attributes from the  route map
        configuration specified by the current "command".'''

        if not command:
            return

        # Validate the current command.
        conf_map_name = command.get('map_name', None)
        if not conf_map_name:
            command = {}
            return
        conf_seq_num = command.get('sequence_num', None)
        if not conf_seq_num:
            if self.any_rmap_inst_in_have(conf_map_name, have):
                self.get_delete_one_route_map_cfg(conf_map_name, requests)
            return

        # Get the current configuration (if any) for this route map statement
        cmd_rmap_have = self.get_matching_map(conf_map_name, conf_seq_num, have)
        if not cmd_rmap_have:
            command = {}
            return

        # Check for route map statement deletion before proceeding further.
        cmd_match_top = command.get('match')
        if cmd_match_top:
            cmd_match_top = command['match']

        cmd_set_top = command.get('set')
        if cmd_set_top:
            cmd_set_top = command['set']

        if not cmd_match_top and not cmd_set_top:
            self.get_delete_route_map_stmt_cfg(command, requests)
            return

        # Proceed with validity checking and execution
        conf_action = command.get('action', None)
        if not conf_action:
            self._module.fail_json(
                msg="\nThe 'action' attribute is required, but is absent"
                    "for route map {0} sequence number {1}\n".format(
                        conf_map_name, conf_seq_num))

        if conf_action not in ('permit', 'deny'):
            self._module.fail_json(
                msg="\nInvalid 'action' attribute value {0} for"
                    "route map {1} sequence number {2}\n".format(
                        conf_action, conf_map_name, conf_seq_num))
            command = {}
            return

        if cmd_match_top:
            self.get_route_map_delete_match_attr(command, cmd_rmap_have, requests)
        if cmd_set_top:
            self.get_route_map_delete_set_attr(command, cmd_rmap_have, requests)
        if command:
            self.get_route_map_delete_call_attr(command, cmd_rmap_have, requests)

        return

    @staticmethod
    def get_matching_map(conf_map_name, conf_seq_num, input_list):
        '''In the input list of command or configuration dicts, find the route map
        configuration "statement" (if it exists) for the specified map name
        and sequence number.'''
        for cfg_route_map in input_list:
            if cfg_route_map.get('map_name') and cfg_route_map.get('sequence_num'):
                if (cfg_route_map['map_name'] == conf_map_name and
                        cfg_route_map.get('sequence_num') == conf_seq_num):
                    return cfg_route_map

        return {}

    @staticmethod
    def any_rmap_inst_in_have(conf_map_name, have):
        '''In the current configuration on the target device, determine if there
        is at least one configuration "statement" for the specified route map name
        from the input playbook request.'''
        for cfg_route_map in have:
            if cfg_route_map.get('map_name'):
                if cfg_route_map['map_name'] == conf_map_name:
                    return True

        return False

    def get_route_map_delete_match_attr(self, command, cmd_rmap_have, requests):
        '''Append to the input list of REST API requests the REST APIs needed
        for deletion of all eligible "match" attributes contained in the
        user input command dict specified by the "command" input parameter
        to this function. Modify the contents of the "command" object to
        remove any attributes that are not currently configured. These
        attributes are not "eligible" for deletion and no REST API "request"
        is generated for them.'''

        conf_map_name = command['map_name']
        conf_seq_num = command['sequence_num']
        req_seq_num = str(conf_seq_num)

        match_top = command.get('match')
        if not match_top:
            return
        match_keys = match_top.keys()

        cfg_match_top = cmd_rmap_have.get('match')
        if not cfg_match_top:
            command.pop('match')
            return
        cfg_match_keys = cfg_match_top.keys()

        match_both_keys = set(match_keys).intersection(cfg_match_keys)

        # Remove any requested deletion items that aren't configured
        match_pop_keys = set(match_keys).difference(match_both_keys)
        for key in match_pop_keys:
            match_top.pop(key)
        if not match_top or not match_both_keys:
            command.pop('match')
            return

        # Handle configuration for BGP policy "match" conditions
        self.get_route_map_delete_match_bgp(command, match_both_keys, cmd_rmap_have, requests)
        if not command.get('match'):
            if 'match' in command:
                command.pop('match')
            return

        # Handle generic top level match attributes.
        generic_match_rest_attr = {
            'interface': 'match-interface',
            'source_vrf': 'openconfig-routing-policy-ext:match-src-network-instance',
            'tag': 'match-tag-set/config/openconfig-routing-policy-ext:tag-value',
            'source_protocol': 'config/install-protocol-eq'
        }

        match_delete_req_base = (self.route_map_stmt_base_uri.format(conf_map_name, req_seq_num) +
                                 'conditions/')

        for key in generic_match_rest_attr:
            if key in match_both_keys and match_top[key] == cfg_match_top[key]:
                request_uri = match_delete_req_base + generic_match_rest_attr[key]
                request = {'path': request_uri, 'method': DELETE}
                requests.append(request)
            elif key in match_top:
                match_top.pop(key)
                if not match_top:
                    command.pop('match')
                    return

        # Handle match peer
        peer_str = ''
        if 'peer' in match_both_keys:
            if (match_top['peer'].get('interface') and cfg_match_top['peer'].get('interface') and
                    match_top['peer']['interface'] == cfg_match_top['peer']['interface']):
                peer_str = match_top['peer']['interface']
            elif (match_top['peer'].get('ip') and cfg_match_top['peer'].get('ip') and
                  match_top['peer']['ip'] == cfg_match_top['peer']['ip']):
                peer_str = match_top['peer']['ip']
            elif (match_top['peer'].get('ipv6') and cfg_match_top['peer'].get('ipv6') and
                  match_top['peer']['ipv6'] == cfg_match_top['peer']['ipv6']):
                peer_str = match_top['peer']['ipv6']
            else:
                match_top.pop('peer')
                if not match_top:
                    command.pop('match')
                    return

            if peer_str:
                request_uri = (match_delete_req_base +
                               'match-neighbor-set/config/'
                               'openconfig-routing-policy-ext:address={0}'.format(peer_str))
                request = {'path': request_uri, 'method': DELETE}
                requests.append(request)

        elif 'peer' in match_top:
            match_top.pop('peer')
            if not match_top:
                command.pop('match')
                return

        # Handle match IP address/prefix
        if ('ip' in match_both_keys and match_top['ip'].get('address') and
                match_top['ip']['address'] == cfg_match_top['ip'].get('address')):
            request_uri = match_delete_req_base + 'match-prefix-set/config/prefix-set'
            request = {'path': request_uri, 'method': DELETE}
            requests.append(request)
        elif 'ip' in match_top:
            match_top.pop('ip')
            if not match_top:
                command.pop('match')
                return

        # Handle match IPv6 address/prefix
        if ('ipv6' in match_both_keys and match_top['ipv6'].get('address') and
                match_top['ipv6']['address'] == cfg_match_top['ipv6'].get('address')):
            ipv6_attr_name = \
                'match-prefix-set/config/openconfig-routing-policy-ext:ipv6-prefix-set'
            request_uri = (match_delete_req_base + ipv6_attr_name)
            request = {'path': request_uri, 'method': DELETE}
            requests.append(request)
        elif 'ipv6' in match_top:
            match_top.pop('ipv6')
            if not match_top:
                command.pop('match')
                return

    def get_route_map_delete_match_bgp(self, command, match_both_keys, cmd_rmap_have, requests):
        '''Append to the input list of REST API requests the REST APIs needed
        for deletion of all eligible "match" attributes defined within the
        BGP match conditions section of the openconfig routing-policy
        definitions for "policy-definitions" (route maps).'''

        conf_map_name = command.get('map_name', None)
        conf_seq_num = command.get('sequence_num', None)
        req_seq_num = str(conf_seq_num)
        match_top = command['match']
        cfg_match_top = cmd_rmap_have.get('match')
        route_map_stmt_base_uri_fmt = self.route_map_stmt_base_uri.format(conf_map_name,
                                                                          req_seq_num)
        bgp_match_delete_req_base = (route_map_stmt_base_uri_fmt +
                                     'conditions/openconfig-bgp-policy:bgp-conditions/')

        # Handle BGP match items within the "config" sub-tree in the openconfig REST API definitons.
        self.get_route_map_delete_match_bgp_cfg(command, match_both_keys, cmd_rmap_have, requests)

        # Handle as_path
        if 'as_path' in match_both_keys and match_top['as_path'] == cfg_match_top['as_path']:
            request_uri = bgp_match_delete_req_base + 'match-as-path-set'
            request = {'path': request_uri, 'method': DELETE}
            requests.append(request)
        elif match_top.get('as_path'):
            match_top.pop('as_path')

        # Handle match evpn
        if 'evpn' in match_both_keys:
            evpn_cfg_delete_base = \
                bgp_match_delete_req_base + 'openconfig-bgp-policy-ext:match-evpn-set/config/'
            evpn_attrs = match_top['evpn']
            evpn_match_keys = evpn_attrs.keys()
            evpn_rest_attr = {
                'default_route': 'default-type5-route',
                'route_type': 'route-type',
                'vni': 'vni-number'
            }
            pop_list = []
            for key in evpn_match_keys:
                if (key not in cfg_match_top['evpn'] or
                        evpn_attrs[key] != cfg_match_top['evpn'][key]):
                    pop_list.append(key)
                else:
                    request_uri = evpn_cfg_delete_base + evpn_rest_attr[key]
                    request = {'path': request_uri, 'method': DELETE}
                    requests.append(request)
            for key in pop_list:
                match_top['evpn'].pop(key)
            if not match_top['evpn']:
                match_top.pop('evpn')

    def get_route_map_delete_match_bgp_cfg(self, command, match_both_keys, cmd_rmap_have, requests):
        '''Append to the input list of REST API requests the REST APIs needed
        for deletion of all eligible "match" attributes defined within the
        BGP match conditions 'config' section of the openconfig routing-policy
        definitions for "policy-definitions" (route maps).'''

        match_top = command['match']
        cfg_match_top = cmd_rmap_have.get('match')
        conf_map_name = command['map_name']
        conf_seq_num = command['sequence_num']
        req_seq_num = str(conf_seq_num)
        bgp_keys = {'metric', 'origin', 'local_preference', 'community', 'ext_comm', 'ip'}
        delete_bgp_keys = bgp_keys.intersection(match_both_keys)
        if not delete_bgp_keys:
            return
        delete_bgp_attrs = []
        bgp_match_delete_req_base = (self.route_map_stmt_base_uri.format(conf_map_name,
                                                                         req_seq_num) +
                                     'conditions/openconfig-bgp-policy:bgp-conditions/config/')

        # Check for IP next hop deletion. This is a special case because "next_hop" is
        # a level below "ip" in the argspec hierarchy. If 'ip' is the only key in
        # delete_bgp_keys, and IP next hop deletion is not required, there is no
        # BGP condition match attribute deletion required.
        if 'ip' in delete_bgp_keys:
            if not match_top['ip'].get('next_hop') or not cfg_match_top['ip'].get('next_hop'):
                delete_bgp_keys.remove('ip')
                if 'next_hop' in match_top['ip']:
                    match_top['ip'].pop('next_hop')
                    if not match_top['ip']:
                        match_top.pop('ip')
                        if not match_top:
                            command.pop('match')
                            return

                if not delete_bgp_keys:
                    return
            else:
                if match_top['ip']['next_hop'] == cfg_match_top['ip']['next_hop']:
                    request_uri = (bgp_match_delete_req_base +
                                   'openconfig-bgp-policy-ext:next-hop-set')
                    request = {'path': request_uri, 'method': DELETE}
                    requests.append(request)
                else:
                    match_top['ip'].pop('next_hop')
                    if not match_top['ip']:
                        match_top.pop('ip')
                        if not match_top:
                            command.pop('match')
                            return

                delete_bgp_keys.remove('ip')
                if not delete_bgp_keys:
                    return

        # Check for deletion of other BGP match attributes.
        bgp_rest_attr = {
            'community': 'community-set',
            'ext_comm': 'ext-community-set',
            'local_preference': 'local-pref-eq',
            'metric': 'med-eq',
            'origin': 'origin-eq'
        }
        for key in delete_bgp_keys:
            if match_top[key] == cfg_match_top[key]:
                bgp_rest_attr_key = bgp_rest_attr[key]
                delete_bgp_attrs.append(bgp_rest_attr_key)
            else:
                match_top.pop(key)
                if not match_top:
                    command.pop('match')
                    return

        if not delete_bgp_attrs:
            return

        # Create requests for deletion of the eligible BGP match attributes.
        for attr in delete_bgp_attrs:
            request_uri = bgp_match_delete_req_base + attr
            request = {'path': request_uri, 'method': DELETE}
            requests.append(request)

    def get_route_map_delete_set_attr(self, command, cmd_rmap_have, requests):
        '''Append to the input list of REST API requests the REST APIs needed
        for deletion of all eligible "set" attributes contained in the
        user input command dict specified by the "command" input parameter
        to this function. Modify the contents of the "command" object to
        remove any attributes that are not currently configured. These
        attributes are not "eligible" for deletion and no REST API "request"
        is generated for them.'''

        cmd_set_top = command.get('set')
        if not cmd_set_top:
            return
        set_keys = cmd_set_top.keys()

        cfg_set_top = cmd_rmap_have.get('set')
        if not cfg_set_top:
            command.pop('set')
            return
        cfg_set_keys = cfg_set_top.keys()

        set_both_keys = set(set_keys).intersection(cfg_set_keys)
        if not set_both_keys:
            command.pop('set')
            return

        conf_map_name = command['map_name']
        conf_seq_num = command['sequence_num']
        req_seq_num = str(conf_seq_num)
        set_delete_base = (self.route_map_stmt_base_uri.format(conf_map_name,
                                                               req_seq_num) + 'actions/')

        # Handle configuration for BGP policy "set" conditions
        self.get_route_map_delete_set_bgp(command, set_both_keys, cmd_rmap_have, requests)
        cmd_set_top = command.get('set')
        if not cmd_set_top:
            command.pop('set')
            return

        # Handle metric "set" attributes.
        if 'metric' in set_both_keys:
            set_delete_metric_base = set_delete_base + 'metric-action/config'
            if cmd_set_top['metric'].get('rtt_action'):
                if cmd_set_top['metric']['rtt_action'] == cfg_set_top['metric'].get('rtt_action'):
                    request_uri = set_delete_metric_base
                    request = {'path': request_uri, 'method': DELETE}
                    requests.append(request)
                else:
                    cmd_set_top.pop('metric')
                    if not cmd_set_top:
                        command.pop('set')
            elif cmd_set_top['metric'].get('value'):
                set_delete_bgp_base = set_delete_base + 'openconfig-bgp-policy:bgp-actions/'
                if cmd_set_top['metric']['value'] == cfg_set_top['metric'].get('value'):
                    request = {'path': set_delete_metric_base, 'method': DELETE}
                    requests.append(request)
                    request = {
                        'path': set_delete_bgp_base + 'config/set-med',
                        'method': DELETE
                    }
                    requests.append(request)

                else:
                    cmd_set_top.pop('metric')
                    if not cmd_set_top:
                        command.pop('set')
        else:
            # 'metric' is not in set_both_keys
            if cmd_set_top.get('metric'):
                cmd_set_top.pop('metric')
                if not cmd_set_top:
                    command.pop('set')
                    return

    def get_route_map_delete_set_bgp(self, command, set_both_keys, cmd_rmap_have, requests):
        '''Append to the input list of REST API requests the REST APIs needed
        for deletion of all eligible "set" attributes defined within the
        BGP "set" conditions section of the openconfig routing-policy
        definitions for "policy-definitions" (route maps).'''

        cmd_set_top = command['set']
        cfg_set_top = cmd_rmap_have.get('set')
        conf_map_name = command['map_name']
        conf_seq_num = command['sequence_num']
        req_seq_num = str(conf_seq_num)
        bgp_set_delete_req_base = (self.route_map_stmt_base_uri.format(conf_map_name, req_seq_num) +
                                   'actions/openconfig-bgp-policy:bgp-actions/')

        # Handle BGP "set" items within the "config" sub-tree in the openconfig REST API definitons.
        self.get_route_map_delete_set_bgp_cfg(command, set_both_keys, cmd_rmap_have, requests)

        # Handle ars_object
        if ('ars_object' in set_both_keys and
                cmd_set_top['ars_object'] == cfg_set_top['ars_object']):
            request_uri = bgp_set_delete_req_base + 'openconfig-routing-policy-ext:ars-object'
            request = {'path': request_uri, 'method': DELETE}
            requests.append(request)
        else:
            if cmd_set_top.get('ars_object'):
                cmd_set_top.pop('ars_object')
                if not cmd_set_top:
                    return

        # Handle as_path_prepend
        if ('as_path_prepend' in set_both_keys and
                cmd_set_top['as_path_prepend'] == cfg_set_top['as_path_prepend']):
            request_uri = bgp_set_delete_req_base + 'set-as-path-prepend'
            request = {'path': request_uri, 'method': DELETE}
            requests.append(request)
        else:
            if cmd_set_top.get('as_path_prepend'):
                cmd_set_top.pop('as_path_prepend')
                if not cmd_set_top:
                    return

        # Handle the "community list delete" (comm_list_delete) attribute
        if ('comm_list_delete' in set_both_keys and
                cmd_set_top['comm_list_delete'] == cfg_set_top['comm_list_delete']):
            request_uri = bgp_set_delete_req_base + 'set-community-delete'
            request = {'path': request_uri, 'method': DELETE}
            requests.append(request)
        else:
            if cmd_set_top.get('comm_list_delete'):
                cmd_set_top.pop('comm_list_delete')
                if not cmd_set_top:
                    return

        # Handle "set community": Handle named attributes first, then handle community numbers
        if 'community' not in set_both_keys:
            if cmd_set_top.get('community'):
                cmd_set_top.pop('community')
                if not cmd_set_top:
                    return
        else:
            community_attr_remove_list = []
            set_community_delete_attrs = []
            if cmd_set_top['community'].get('community_attributes'):
                if cfg_set_top['community'].get('community_attributes'):
                    # Append eligible entries to the delete list. Remember which entries
                    # are ineligible.
                    for community_attr in cmd_set_top['community']['community_attributes']:
                        if community_attr in cfg_set_top['community']['community_attributes']:
                            community_rest_name = self.set_community_rest_names[community_attr]
                            set_community_delete_attrs.append(community_rest_name)
                        else:
                            community_attr_remove_list.append(community_attr)

                    # Delete ineligible entries from the command list.
                    for community_attr in community_attr_remove_list:
                        cmd_set_top['community']['community_attributes'].remove(community_attr)
                    if not cmd_set_top['community']['community_attributes']:
                        cmd_set_top['community'].pop('community_attributes')
                else:
                    # No community attribute entries are configured. Pop the corresponding
                    # commands from the command list.
                    cmd_set_top['community'].pop('community_attributes')

                if not cmd_set_top['community']:
                    cmd_set_top.pop('community')
                    if not cmd_set_top:
                        return

            # Handle deletion of "set" community numbers.
            if cmd_set_top.get('community') and cmd_set_top['community'].get('community_number'):
                community_number_remove_list = []
                if cfg_set_top['community'].get('community_number'):
                    # Append eligible entries to the delete list. Remember which entries
                    # are ineligible.
                    for community_number in cmd_set_top['community']['community_number']:
                        if community_number in cfg_set_top['community']['community_number']:
                            set_community_delete_attrs.append(community_number)
                        else:
                            community_number_remove_list.append(community_number)

                    # Delete ineligible entries from the command list.
                    for community_number in community_number_remove_list:
                        cmd_set_top['community']['community_number'].remove(community_number)
                    if not cmd_set_top['community']['community_number']:
                        cmd_set_top['community'].pop('community_number')
                else:
                    # If no community number entries are configured, pop the entire
                    # community number command dict.
                    cmd_set_top['community'].pop('community_number')

                if not cmd_set_top['community']:
                    cmd_set_top.pop('community')
                    if not cmd_set_top:
                        return

            # Format and enqueue a request to delete eligible community attributes
            if set_community_delete_attrs:
                bgp_set_delete_community_uri = bgp_set_delete_req_base + 'set-community'
                bgp_set_delete_comm_payload = \
                    {'openconfig-bgp-policy:set-community': {}}
                bgp_set_delete_comm_payload_contents = \
                    bgp_set_delete_comm_payload['openconfig-bgp-policy:set-community']
                bgp_set_delete_comm_payload_contents['config'] = \
                    {'method': 'INLINE', 'options': 'REMOVE'}
                bgp_set_delete_comm_payload_contents['inline'] = \
                    {'config': {'communities': set_community_delete_attrs}}

                request = {
                    'path': bgp_set_delete_community_uri,
                    'method': PATCH,
                    'data': bgp_set_delete_comm_payload
                }
                requests.append(request)

        # Handle set "extended community" deletion
        if 'extcommunity' not in set_both_keys:
            if cmd_set_top.get('extcommunity'):
                cmd_set_top.pop('extcommunity')
                if not cmd_set_top:
                    return
        else:
            set_extcommunity_delete_attrs = []

            for extcomm_type in self.set_extcomm_rest_names:
                ext_comm_number_remove_list = []
                if cmd_set_top['extcommunity'].get(extcomm_type):
                    if cfg_set_top['extcommunity'].get(extcomm_type):
                        # Append eligible entries to the delete list. Remember which entries
                        # are ineligible.
                        if extcomm_type == "bandwidth":
                            bandwidth_value = cfg_set_top['extcommunity'][extcomm_type]["bandwidth_value"]
                            transitive_value = cfg_set_top['extcommunity'][extcomm_type]["transitive_value"]
                            if transitive_value:
                                transitive_string = "transitive"
                            else:
                                transitive_string = "non-transitive"
                            if (bandwidth_value == cmd_set_top['extcommunity'][extcomm_type].get("bandwidth_value") and
                               transitive_value == cmd_set_top['extcommunity'][extcomm_type].get("transitive_value")):
                                set_extcommunity_delete_attrs.append(self.set_extcomm_rest_names[extcomm_type] + bandwidth_value + ":" + transitive_string)
                            else:
                                cmd_set_top['extcommunity'].pop('bandwidth')
                        else:
                            for extcomm_number in cmd_set_top['extcommunity'][extcomm_type]:
                                if extcomm_number in cfg_set_top['extcommunity'][extcomm_type]:
                                    set_extcommunity_delete_attrs.append(
                                        self.set_extcomm_rest_names[extcomm_type] + extcomm_number)
                                else:
                                    ext_comm_number_remove_list.append(extcomm_number)

                            # Delete ineligible entries from the command list.
                            for extcomm_number in ext_comm_number_remove_list:
                                cmd_set_top['extcommunity'][extcomm_type].remove(extcomm_number)
                            if not cmd_set_top['extcommunity'][extcomm_type]:
                                cmd_set_top['extcommunity'].pop(extcomm_type)
                    else:
                        # If no extcommunity entries of this type are configured,
                        # pop the entire extcommunity command sub-dict for this type.
                        cmd_set_top['extcommunity'].pop(extcomm_type)

                    if not cmd_set_top['extcommunity']:
                        cmd_set_top.pop('extcommunity')
                        if not cmd_set_top:
                            return

            # Format and enqueue a request to delete eligible extcommunity attributes
            if set_extcommunity_delete_attrs:
                bgp_set_delete_extcomm_uri = bgp_set_delete_req_base + 'set-ext-community'
                bgp_set_delete_extcomm_payload = \
                    {'openconfig-bgp-policy:set-ext-community': {}}
                bgp_set_delete_comm_payload_contents = \
                    bgp_set_delete_extcomm_payload['openconfig-bgp-policy:set-ext-community']
                bgp_set_delete_comm_payload_contents['config'] = \
                    {'method': 'INLINE', 'options': 'REMOVE'}
                bgp_set_delete_comm_payload_contents['inline'] = \
                    {'config': {'communities': set_extcommunity_delete_attrs}}

                request = {
                    'path': bgp_set_delete_extcomm_uri,
                    'method': PATCH,
                    'data': bgp_set_delete_extcomm_payload
                }
                requests.append(request)

    def get_route_map_delete_set_bgp_cfg(self, command, set_both_keys, cmd_rmap_have, requests):
        '''Append to the input list of REST API requests the REST APIs needed
        for deletion of all eligible "set" attributes defined within the
        BGP set conditions 'config' section of the openconfig routing-policy
        definitions for "policy-definitions" (route maps).'''

        cmd_set_top = command['set']

        cfg_set_top = cmd_rmap_have.get('set')
        conf_map_name = command['map_name']
        conf_seq_num = command['sequence_num']
        req_seq_num = str(conf_seq_num)
        bgp_set_delete_req_base = (self.route_map_stmt_base_uri.format(conf_map_name, req_seq_num) +
                                   'actions/openconfig-bgp-policy:bgp-actions/config/')
        # Note: Although 'metric' (REST API 'set-med') is in this REST API configuration
        # group, it is handled separately as part of deleting the top level, functionally
        # related 'metric-action' attribute.
        bgp_cfg_keys = {'ip_next_hop', 'origin', 'local_preference', 'ipv6_next_hop', 'weight', 'tag'}
        delete_bgp_keys = bgp_cfg_keys.intersection(set_both_keys)
        if not delete_bgp_keys:
            for bgp_key in bgp_cfg_keys:
                if bgp_key in cmd_set_top:
                    cmd_set_top.pop(bgp_key)
            return

        delete_bgp_attrs = []

        # Handle the special case of ip_next_hop
        if 'ip_next_hop' in delete_bgp_keys:
            delete_bgp_keys.remove('ip_next_hop')
            ip_next_hop_rest_names = {
                'address': 'set-next-hop',
                'native': 'openconfig-bgp-policy-ext:set-next-hop-native',
            }
            for ip_next_hop_key in ip_next_hop_rest_names:
                if cmd_set_top['ip_next_hop'].get(ip_next_hop_key) is not None:
                    if (cmd_set_top['ip_next_hop'][ip_next_hop_key] ==
                            cfg_set_top['ip_next_hop'].get(ip_next_hop_key)):
                        delete_bgp_attrs.append(ip_next_hop_rest_names[ip_next_hop_key])
                    else:
                        cmd_set_top['ip_next_hop'].pop(ip_next_hop_key)
                        if not cmd_set_top['ip_next_hop']:
                            cmd_set_top.pop('ip_next_hop')
                            if not cmd_set_top:
                                return

            if not delete_bgp_keys and not delete_bgp_attrs:
                return

        # Handle the special case of ipv6_next_hop
        if 'ipv6_next_hop' in delete_bgp_keys:
            delete_bgp_keys.remove('ipv6_next_hop')
            ipv6_next_hop_rest_names = {
                'global_addr': 'set-ipv6-next-hop-global',
                'native': 'openconfig-bgp-policy-ext:set-ipv6-next-hop-native',
                'prefer_global': 'set-ipv6-next-hop-prefer-global',
            }
            for ipv6_next_hop_key in ipv6_next_hop_rest_names:
                if cmd_set_top['ipv6_next_hop'].get(ipv6_next_hop_key) is not None:
                    if (cmd_set_top['ipv6_next_hop'][ipv6_next_hop_key] ==
                            cfg_set_top['ipv6_next_hop'].get(ipv6_next_hop_key)):
                        delete_bgp_attrs.append(ipv6_next_hop_rest_names[ipv6_next_hop_key])
                    else:
                        cmd_set_top['ipv6_next_hop'].pop(ipv6_next_hop_key)
                        if not cmd_set_top['ipv6_next_hop']:
                            cmd_set_top.pop('ipv6_next_hop')
                            if not cmd_set_top:
                                return

            if not delete_bgp_keys and not delete_bgp_attrs:
                return

        # Handle other BGP "config" attributes
        bgp_cfg_rest_names = {
            'local_preference': 'set-local-pref',
            'origin': 'set-route-origin',
            'weight': 'set-weight',
            'tag': 'set-tag',
        }

        for bgp_cfg_key in bgp_cfg_rest_names:
            if bgp_cfg_key in delete_bgp_keys:
                if cmd_set_top[bgp_cfg_key] == cfg_set_top[bgp_cfg_key]:
                    delete_bgp_attrs.append(bgp_cfg_rest_names[bgp_cfg_key])
                else:
                    cmd_set_top.pop(bgp_cfg_key)

        if not cmd_set_top:
            command.pop('set')
            return

        for delete_bgp_attr in delete_bgp_attrs:
            del_set_bgp_cfg_uri = bgp_set_delete_req_base + delete_bgp_attr
            request = {'path': del_set_bgp_cfg_uri, 'method': DELETE}
            requests.append(request)

    def get_route_map_delete_call_attr(self, command, cmd_rmap_have, requests):
        '''Append to the input list of REST API requests the REST API needed
        for deletion of the "call" attribute if this attribute it contained in the
        user input command dict specified by the "command" input parameter
        to this function and it is currently configured. Modify the contents of
        the "command" object to remove the "call" attribute if it is not currently
        configured.'''

        if not command.get('call'):
            return

        if not command['call'] == cmd_rmap_have.get('call'):
            command.pop('call')
            return

        conf_map_name = command['map_name']
        req_seq_num = str(command['sequence_num'])

        call_delete_req_uri = \
            (self.route_map_stmt_base_uri.format(
                conf_map_name, req_seq_num) + 'conditions/config/call-policy')
        request = {'path': call_delete_req_uri, 'method': DELETE}
        requests.append(request)

    @staticmethod
    def yaml_bool_to_python_bool(yaml_bool):
        '''Convert the input YAML bool value to a Python bool value'''
        boolval = False
        if yaml_bool is None:
            boolval = False
        elif yaml_bool:
            boolval = True

        return boolval

    def route_map_remove_configured_match_peer(self, route_map_payload, have, requests):
        '''If a route map "match peer" condition is configured in the route map
        statement corresponding to the incoming route map update request
        specified by the "route_map_payload" input parameter, equeue a REST API request
        to delete it.'''

        if (route_map_payload['statements']['statement'][0].get('conditions') and
                route_map_payload['statements']['statement'][0]
                ['conditions'].get('match-neighbor-set')):
            peer = self.match_peer_configured(route_map_payload, have)
            if peer:
                request = self.create_match_peer_delete_request(route_map_payload, peer)
                if request:
                    requests.append(request)

    def match_peer_configured(self, route_map_payload, have):
        '''Determine if the "match peer ..." condition is already configured for the
        route map statement corresponding to the incoming route map update request
        specified by the "route_map_payload" input parameter. Return the peer string
       if a "match peer" condition is already configured. Otherwise, return an empty
       string'''

        if not route_map_payload or not have:
            return ''

        conf_map_name = route_map_payload.get('name')
        conf_seq_num = (route_map_payload['statements']['statement'][0]['name'])
        if not conf_map_name or not conf_seq_num:
            return ''

        # Get the current configuration (if any) for this route map statement
        cmd_rmap_have = self.get_matching_map(conf_map_name, int(conf_seq_num), have)
        if (not cmd_rmap_have or not cmd_rmap_have.get('match') or
                not cmd_rmap_have['match'].get('peer')):
            return ''

        peer_dict = cmd_rmap_have['match']['peer']
        if peer_dict.get('interface'):
            peer_str = peer_dict['interface']
        elif peer_dict.get('ip'):
            peer_str = peer_dict['ip']
        elif peer_dict.get('ipv6'):
            peer_str = peer_dict['ipv6']
        else:
            return ''

        return peer_str

    def create_match_peer_delete_request(self, route_map_payload, peer_str):
        '''Create a request to delete the current "match peer" configuration for the
        route map statement corresponding to the incoming route map update request
        specified by the "route_map_payload," input parameter. Return the created request.'''

        if not route_map_payload:
            return {}

        conf_map_name = route_map_payload.get('name')
        conf_seq_num = route_map_payload['statements']['statement'][0]['name']
        if not conf_map_name or not conf_seq_num:
            return {}
        match_delete_req_base = (self.route_map_stmt_base_uri.format(conf_map_name, conf_seq_num) +
                                 'conditions/')

        request_uri = (match_delete_req_base +
                       'match-neighbor-set/config/'
                       'openconfig-routing-policy-ext:address={0}'.format(peer_str))
        request = {'path': request_uri, 'method': DELETE}
        return request

    def get_delete_replaced_groupings(self, commands, have):
        '''For each of the route maps specified in the "commands" input list,
        create requests to delete any existing route map configuration
        groupings for which modified attribute requests are specified.'''

        requests = []
        for command in commands:
            self.get_delete_one_map_replaced_groupings(command, have, requests)
        return requests

    def get_delete_one_map_replaced_groupings(self, command, have, requests):
        '''For the route map specified by the input "command", create requests
        to delete any existing route map configuration groupings for which
        modified attribute requests are specified'''

        if not command:
            return {}

        conf_map_name = command.get('map_name', None)
        conf_seq_num = command.get('sequence_num', None)
        if not conf_map_name or not conf_seq_num:
            return {}

        # Get the current configuration (if any) for this route map
        cmd_rmap_have = self.get_matching_map(conf_map_name, conf_seq_num, have)

        # If there's nothing configured for this route map, there's nothing
        # to delete.
        if not cmd_rmap_have:
            command = {}
            return command

        self.get_delete_route_map_replaced_match_groupings(command, cmd_rmap_have, requests)
        replaced_set_group_requests = []
        self.get_delete_route_map_replaced_set_groupings(command, cmd_rmap_have,
                                                         replaced_set_group_requests)
        if replaced_set_group_requests:
            requests.extend(replaced_set_group_requests)

        # Note: Because the "call" route map attribute is a "flat" attribute, not
        # a dictionary, no "pre-delete" is required for this branch of the route map
        # argspec for handling of "replaced" state

        return command

    def get_delete_route_map_replaced_match_groupings(self, command, cmd_rmap_have, requests):
        '''For the route map specified by the input "command", create requests
        to delete any existing route map "match" configuration groupings for which
        modified attribute requests are specified'''

        if not command.get('match'):
            return

        conf_map_name = command.get('map_name', None)
        conf_seq_num = command.get('sequence_num', None)
        req_seq_num = str(conf_seq_num)

        cmd_match_top = command['match']
        cfg_match_top = cmd_rmap_have.get('match')

        # If there are no 'match' attributes configured for this route map,
        # there's nothing to delete.
        if not cfg_match_top:
            command.pop('match')
            return

        match_delete_req_base = (self.route_map_stmt_base_uri.format(conf_map_name, req_seq_num) +
                                 'conditions/')

        # Obtain the set of "match" keys for which changes have been requested and
        # the subset of those keys for which configuration currently exists.
        cmd_match_keys = cmd_match_top.keys()
        cfg_match_keys = cfg_match_top.keys()

        peer_str = ''
        if 'peer' in cfg_match_keys:
            peer_dict = cfg_match_top['peer']
            # Only one peer key at a time can be configured.
            peer_key = list(peer_dict.keys())[0]
            peer_str = peer_dict[peer_key]

        bgp_match_delete_req_base = match_delete_req_base + 'openconfig-bgp-policy:bgp-conditions/'
        match_top_level_keys = [
            'as_path',
            'community',
            'ext_comm',
            'interface',
            'ipv6',
            'local_preference',
            'metric',
            'origin',
            'peer',
            'source_protocol',
            'source_vrf',
            'tag'
        ]

        match_multi_level_keys = [
            'evpn',
            'ip',
        ]

        match_uri_attr = {
            'as_path': bgp_match_delete_req_base + 'match-as-path-set',
            'community': bgp_match_delete_req_base + 'config/community-set',
            'evpn': bgp_match_delete_req_base + 'openconfig-bgp-policy-ext:match-evpn-set/config/',
            'ext_comm': bgp_match_delete_req_base + 'config/ext-community-set',
            'interface': match_delete_req_base + 'match-interface',
            'ip': {
                'address': match_delete_req_base + 'match-prefix-set/config/prefix-set',
                'next_hop': (bgp_match_delete_req_base +
                             'config/openconfig-bgp-policy-ext:next-hop-set')
            },
            'ipv6': (match_delete_req_base +
                     'match-prefix-set/config/openconfig-routing-policy-ext:ipv6-prefix-set'),
            'local_preference': bgp_match_delete_req_base + 'config/local-pref-eq',
            'metric': bgp_match_delete_req_base + 'config/med-eq',
            'origin': bgp_match_delete_req_base + 'config/origin-eq',
            'peer': (match_delete_req_base +
                     'match-neighbor-set/config/'
                     'openconfig-routing-policy-ext:address={0}'.format(peer_str)),
            'source_protocol': match_delete_req_base + 'config/install-protocol-eq',
            'source_vrf': (match_delete_req_base +
                           'openconfig-routing-policy-ext:match-src-network-instance'),
            'tag': (match_delete_req_base +
                    'match-tag-set/config/openconfig-routing-policy-ext:tag-value')
        }

        # Remove all appropriate "match" configuration for this route map if any of the
        # following criteria are met:  (See the note below regarding what configuration
        # is "appropriate" for deletion.)
        #
        # 1) Any top level attribute is specified with a value different from its current
        #    configured value.
        # 2) Any top level attribute is specified that is not currently configured.
        # 3) The set of top level attributes specified does not include all currently
        #    configured attributes (regardless of whether the specified values for
        #    these attributes are the same as the ones courrently configured).
        # (Note: Although the IPv6 attribute is defined as a nested dictionary
        # to allow for future expansion, it is handled here as a top level
        # attribute because it currently has only one member.)
        #
        # When deletion has been triggered, an attribute is deleted only if it is
        # not present at all in the requested configuration. (If it is present in
        # the requested configuration, the "merge" phase of the "replaced" state
        # operation will modify it as needed, so it doesn't need to be explicitly
        # deleted during the "deletion" phase.)
        #
        cfg_top_level_key_set = set(cfg_match_keys).intersection(set(match_top_level_keys))
        cmd_top_level_key_set = set(cmd_match_keys).intersection(set(match_top_level_keys))
        symmetric_diff_set = cmd_top_level_key_set.symmetric_difference(cfg_top_level_key_set)
        intersection_diff_set = cmd_top_level_key_set.intersection(cfg_top_level_key_set)
        cmd_delete_dict = {}
        if (cmd_top_level_key_set and symmetric_diff_set or
                (any(keyname for keyname in intersection_diff_set if
                     cmd_match_top[keyname] != cfg_match_top[keyname]))):

            # Deletion has been triggered. First, delete all approriate top level
            # attributes
            self.delete_replaced_dict_config(
                cfg_key_set=cfg_top_level_key_set,
                cmd_key_set=cmd_top_level_key_set,
                cfg_parent_dict=cfg_match_top,
                uri_attr=match_uri_attr,
                uri_dict_key='cfg_dict_member_key',
                deletion_dict=cmd_delete_dict,
                requests=requests)

            # Next, delete all appropriate sub dictionary attributes.
            match_dict_deletions = {}
            for match_key in match_multi_level_keys:
                cfg_key_set = {}
                cmd_key_set = {}
                if match_key in cfg_match_top:
                    cfg_key_set = set(cfg_match_top[match_key].keys())
                    if match_key in cfg_match_top:
                        cmd_key_set = ([])
                        if cmd_match_top.get(match_key):
                            cmd_key_set = set(cmd_match_top[match_key].keys())
                    match_dict_deletions[match_key] = {}
                    match_dict_deletions_subdict = match_dict_deletions[match_key]
                    self.delete_replaced_dict_config(
                        cfg_key_set=cfg_key_set,
                        cmd_key_set=cmd_key_set,
                        cfg_parent_dict=cfg_match_top[match_key],
                        uri_attr=match_uri_attr,
                        uri_dict_key=match_key,
                        deletion_dict=match_dict_deletions_subdict,
                        requests=requests)

            # Update the dict specifying deleted commands
            command.pop('match')
            if cmd_delete_dict:
                command['match'] = cmd_delete_dict
                command['match'].update(match_dict_deletions)
            return

        # If no top level attribute changes were requested, check for changes in
        # dictionaries nested below the top level.
        # -----------------------------------------------------------------------
        match_key_deletions = {}
        for match_key in match_multi_level_keys:
            if match_key in cmd_match_top:
                if match_key in cfg_match_top:
                    cmd_key_set = set((cmd_match_top[match_key].keys()))
                    cfg_key_set = set(cfg_match_top[match_key].keys())
                    symmetric_diff_set = cmd_key_set.symmetric_difference(cfg_key_set)
                    intersection_diff_set = cmd_key_set.intersection(cfg_key_set)
                    if (symmetric_diff_set or
                            (any(keyname for keyname in intersection_diff_set if
                                 cmd_match_top[match_key][keyname] !=
                                 cfg_match_top[match_key][keyname]))):

                        match_key_deletions[match_key] = {}
                        match_key_deletions_subdict = match_key_deletions[match_key]
                        self.delete_replaced_dict_config(
                            cfg_key_set=cfg_key_set,
                            cmd_key_set=cmd_key_set,
                            cfg_parent_dict=cfg_match_top[match_key],
                            uri_attr=match_uri_attr,
                            uri_dict_key=match_key,
                            deletion_dict=match_key_deletions_subdict,
                            requests=requests)

        command.pop('match')
        if match_key_deletions:
            command['match'] = match_key_deletions

    @staticmethod
    def delete_replaced_dict_config(**in_args):
        ''' Create and enqueue deletion requests for the appropriate attributes in the dictionary
        specified by "dict_key". Update the input deletion_dict with the deleted attributes.
        The input 'in_args' is assumed to contain the following keyword arguments:

        cfg_key_set: The set of currently configured keys for the target dict

        cmd_key_set: The set of currently requested update keys for the target dict

        cfg_parent_dict: The configured dictionary containing the input key set

        uri_attr: a dictionary specifying REST URIs keyed by argspec keys

        uri_dict_key: The key for top level attribue to be used for uri lookup. If set
        to the string value 'cfg_dict_member_key', the current value of 'cfg_dict_member_key'
        is used. Otherwise, the specified value is used directly.

        deletion_dict: a dictionary containing attributes deleted from the parent dict

        requests: The list of REST API requests for the executing playbook section
        '''

        # Set the default uri_key value.
        uri_key = in_args['uri_dict_key']

        # Iterate through members of the parent dict.
        for cfg_dict_member_key in in_args['cfg_key_set'].difference(in_args['cmd_key_set']):
            cfg_dict_member_val = in_args['cfg_parent_dict'][cfg_dict_member_key]
            if in_args['uri_dict_key'] == 'cfg_dict_member_key':
                uri_key = cfg_dict_member_key
            uri = in_args['uri_attr'][uri_key]
            in_args['deletion_dict'].update(
                {cfg_dict_member_key: cfg_dict_member_val})
            if isinstance(uri, dict):
                for member_key in uri:
                    if in_args['cfg_parent_dict'].get(member_key) is not None:
                        request = {'path': uri[member_key],
                                   'method': DELETE}
                        in_args['requests'].append(request)
            elif isinstance(uri, list):
                for set_uri_item in uri:
                    request = {'path': set_uri_item, 'method': DELETE}
            else:
                request = {'path': uri, 'method': DELETE}
                in_args['requests'].append(request)

    def get_delete_route_map_replaced_set_groupings(self, command, cmd_rmap_have,
                                                    requests):
        '''For the route map specified by the input "command", create requests
        to delete any existing route map "set" configuration groupings for which
        modified attribute requests are specified'''

        if not command.get('set'):
            return

        conf_map_name = command.get('map_name', None)
        conf_seq_num = command.get('sequence_num', None)
        req_seq_num = str(conf_seq_num)

        cmd_set_top = command['set']
        cfg_set_top = cmd_rmap_have.get('set')

        # If there are no 'set' attributes configured for this route map,
        # there's nothing to delete.
        if not cfg_set_top:
            command.pop('set')
            return

        set_delete_req_base = (self.route_map_stmt_base_uri.format(conf_map_name, req_seq_num) +
                               'actions/')
        bgp_set_delete_req_base = set_delete_req_base + 'openconfig-bgp-policy:bgp-actions/'

        # Obtain the set of "set" keys for which changes have been requested and the set
        # of keys currently configured.
        cmd_set_keys = cmd_set_top.keys()
        cfg_set_keys = cfg_set_top.keys()

        metric_uri = ''
        if 'metric' in cfg_set_top:
            if cfg_set_top['metric'].get('rtt_action'):
                metric_uri = set_delete_req_base + 'metric-action/config'
            elif cfg_set_top['metric'].get('value'):
                metric_uri = [set_delete_req_base + 'metric-action/config',
                              bgp_set_delete_req_base + 'config/set-med']
        # Top level keys: Note: Although "metric" is defined as a dictionary, it
        # is handled as a "top level" attribute because it can contain
        # only one configured member (either an rtt_action or a "value").
        set_top_level_keys = [
            'ars_object',
            'as_path_prepend',
            'comm_list_delete',
            'local_preference',
            'metric',
            'origin',
            'weight',
            'tag',
        ]

        set_uri_attr = {
            'ars_object': bgp_set_delete_req_base + 'openconfig-routing-policy-ext:ars-object',
            'as_path_prepend': bgp_set_delete_req_base + 'set-as-path-prepend',
            'comm_list_delete': bgp_set_delete_req_base + 'set-community-delete',
            'community': bgp_set_delete_req_base + 'set-community',
            'extcommunity': bgp_set_delete_req_base + 'set-ext-community',
            'ip_next_hop': {
                'address': bgp_set_delete_req_base + 'config/set-next-hop',
                'native': bgp_set_delete_req_base + 'config/openconfig-bgp-policy-ext:set-next-hop-native'
            },
            'ipv6_next_hop': {
                'global_addr': bgp_set_delete_req_base + 'config/set-ipv6-next-hop-global',
                'prefer_global': bgp_set_delete_req_base + 'config/set-ipv6-next-hop-prefer-global',
                'native': bgp_set_delete_req_base + 'config/openconfig-bgp-policy-ext:set-ipv6-next-hop-native'
            },
            'local_preference': bgp_set_delete_req_base + 'config/set-local-pref',
            'metric': metric_uri,
            'origin': bgp_set_delete_req_base + 'config/set-route-origin',
            'weight': bgp_set_delete_req_base + 'config/set-weight',
            'tag': bgp_set_delete_req_base + 'config/set-tag'
        }

        # Remove all appropriate "set" configuration for this route map if any of the
        # following criteria are met:  (See the note below regarding what configuration
        # is "appropriate" for deletion.)
        #
        # 1) Any top level attribute is specified with a value different from its current
        #    configured value.
        # 2) Any top level attribute is specified that is not currently configured.
        # 3) The set of top level attributes specified does not include all currently
        #    configured attributes (regardless of whether the specified values for
        #    these attributes are the same as the ones courrently configured).
        # (Note: Although the IPv6 attribute is defined as a nested dictionary
        # to allow for future expansion, it is handled here as a top level
        # attribute because it currently has only one member.)
        #
        # When deletion has been triggered, an attribute is deleted only if it is
        # not present at all in the requested configuration. (If it is present in
        # the requested configuration, the "merge" phase of the "replaced" state
        # operation will modify it as needed, so it doesn't need to be explicitly
        # deleted during the "deletion" phase.)
        #
        # Handle top level attributes first. If top level attribute deletion is
        # triggered, proceed with deletion of dictionaries and lists below the
        # top level.
        cfg_top_level_key_set = set(cfg_set_keys).intersection(set(set_top_level_keys))
        cmd_top_level_key_set = set(cmd_set_keys).intersection(set(set_top_level_keys))
        cmd_nested_level_key_set = set(cmd_set_keys).difference(set_top_level_keys)
        symmetric_diff_set = cmd_top_level_key_set.symmetric_difference(cfg_top_level_key_set)
        intersection_diff_set = cmd_top_level_key_set.intersection(cfg_top_level_key_set)
        cmd_delete_dict = {}
        if (cmd_top_level_key_set and symmetric_diff_set or
                (any(keyname for keyname in intersection_diff_set if
                     cmd_set_top[keyname] != cfg_set_top[keyname]))):
            # Deletion has been triggered. First, delete all approriate top level
            # attributes
            self.delete_replaced_dict_config(
                cfg_key_set=cfg_top_level_key_set,
                cmd_key_set=cmd_top_level_key_set,
                cfg_parent_dict=cfg_set_top,
                uri_attr=set_uri_attr,
                uri_dict_key='cfg_dict_member_key',
                deletion_dict=cmd_delete_dict,
                requests=requests)

            # Save nested command "set" items and refresh top level command "set" items.
            cmd_set_nested = {}
            for nested_key in cmd_nested_level_key_set:
                if command['set'].get(nested_key) is not None:
                    cmd_set_nested[nested_key] = command['set'][nested_key]

            command.pop('set')
            if cmd_delete_dict:
                command['set'] = cmd_delete_dict
            if cmd_set_nested:
                if not command.get('set'):
                    command['set'] = {}
                command['set'].update(cmd_set_nested)
            if not command.get('set'):
                command['set'] = {}
            cmd_set_top = command['set']

            # Proceed with deletion of dictionaries and lists below the top level.
            # ---------------------------------------------------------------------

            dict_delete_requests = []

            # Check for deletion of set "community" lists. Delete the items in
            # the currently configured list if it exists. As an optimization,
            # avoid deleting list items that will be replaced by the received
            # command.

            set_community_delete_attrs = []
            if 'community' not in cfg_set_top:
                if command['set'].get('community'):
                    command['set'].pop('community')
                    if command['set'] is None:
                        command.pop('set')
                    return
            else:
                set_community_number_deletions = []
                if 'community_number' in cfg_set_top['community']:

                    # Delete eligible configured community numbers.
                    cfg_community_number_set = set(cfg_set_top['community']['community_number'])
                    cmd_community_number_set = ([])
                    if cmd_set_top.get('community') and 'community_number' in cmd_set_top['community']:
                        cmd_community_number_set = set(cmd_set_top['community']['community_number'])
                        command['set']['community'].pop('community_number')

                    for cfg_community_number in cfg_community_number_set.difference(cmd_community_number_set):
                        set_community_delete_attrs.append(cfg_community_number)
                        set_community_number_deletions.append(cfg_community_number)

                    if set_community_number_deletions:
                        # Update the list of deleted community numbers in the "command" dict.
                        if not cmd_set_top.get('community'):
                            command['set']['community'] = {}
                        command['set']['community']['community_number'] = set_community_number_deletions

                set_community_attributes_deletions = []
                if 'community_attributes' in cfg_set_top['community']:

                    # Delete eligible configured community attributes.
                    cfg_community_attributes_set = set(cfg_set_top['community']['community_attributes'])
                    cmd_community_attributes_set = ([])
                    if cmd_set_top.get('community') and 'community_attributes' in cmd_set_top['community']:
                        cmd_community_attributes_set = set(cmd_set_top['community']['community_attributes'])
                        command['set']['community'].pop('community_attributes')

                    for cfg_community_attribute in cfg_community_attributes_set.difference(cmd_community_attributes_set):
                        set_community_delete_attrs.append(self.set_community_rest_names[cfg_community_attribute])
                        set_community_attributes_deletions.append(cfg_community_attribute)

                    if set_community_attributes_deletions:
                        # Update the list of deleted community attributes in the "command" dict.
                        if not cmd_set_top.get('community'):
                            command['set']['community'] = {}
                        command['set']['community']['community_attributes'] = set_community_attributes_deletions

                if command['set'].get('community') is not None and not command['set']['community']:
                    command['set'].pop('community')

                # Format and enqueue a request to delete eligible community attributes
                if set_community_delete_attrs:
                    bgp_set_delete_community_uri = bgp_set_delete_req_base + 'set-community'
                    bgp_set_delete_comm_payload = \
                        {'openconfig-bgp-policy:set-community': {}}
                    bgp_set_delete_comm_payload_contents = \
                        bgp_set_delete_comm_payload['openconfig-bgp-policy:set-community']
                    bgp_set_delete_comm_payload_contents['config'] = \
                        {'method': 'INLINE', 'options': 'REMOVE'}
                    bgp_set_delete_comm_payload_contents['inline'] = \
                        {'config': {'communities': set_community_delete_attrs}}

                    request = {
                        'path': bgp_set_delete_community_uri,
                        'method': PATCH,
                        'data': bgp_set_delete_comm_payload
                    }
                    dict_delete_requests.append(request)

            # Check for deletion of set "extcommunity" lists. Delete the items in
            # the currently configured list if it exists. As an optimization,
            # avoid deleting list items that will be replaced by the received
            # command.
            set_extcommunity_delete_attrs = []

            if 'extcommunity' not in cfg_set_top:
                if command['set'].get('extcommunity'):
                    command['set'].pop('extcommunity')
                    if command['set'] is None:
                        command.pop('set')
                    return
            else:
                for extcomm_type in self.set_extcomm_rest_names:
                    set_extcommunity_delete_attrs_type = []
                    if extcomm_type in cfg_set_top['extcommunity']:
                        # Delete eligible configured extcommunity list items for this
                        # extcommunity list
                        if extcomm_type == "bandwidth":
                            if "bandwidth_value" in cfg_set_top.get("extcommunity", {}).get("bandwidth"):
                                if 'bandwidth' not in cmd_set_top.get('extcommunity', {}):
                                    bandwidth_value = cfg_set_top['extcommunity']['bandwidth']['bandwidth_value']
                                    transitive_value = "transitive" if cfg_set_top['extcommunity']['bandwidth']['transitive_value'] else "non-transitive"
                                    bandwidth_string = (self.set_extcomm_rest_names['bandwidth'] + bandwidth_value + ":" + transitive_value)
                                    set_extcommunity_delete_attrs.append(bandwidth_string)
                                    set_extcommunity_delete_attrs_type.append(cfg_set_top['extcommunity']['bandwidth'])
                        else:
                            cfg_extcommunity_list_set = set(cfg_set_top['extcommunity'][extcomm_type])
                            cmd_extcommunity_list_set = ([])
                            saved_cmd_set = []
                            if cmd_set_top.get('extcommunity') and extcomm_type in cmd_set_top['extcommunity']:
                                cmd_extcommunity_list_set = set(to_extcom_str_list(cmd_set_top['extcommunity'][extcomm_type]))
                                saved_cmd_set = command['set']['extcommunity'].pop(extcomm_type)

                            for extcomm_number in cfg_extcommunity_list_set.difference(cmd_extcommunity_list_set):
                                if extcomm_number in saved_cmd_set:
                                    # ignore equivalent asn:nn with different as-notation format
                                    continue
                                set_extcommunity_delete_attrs.append(self.set_extcomm_rest_names[extcomm_type] + extcomm_number)
                                set_extcommunity_delete_attrs_type.append(extcomm_number)

                        if set_extcommunity_delete_attrs_type:
                            # Update the list of deleted extcommunity list items of this type
                            # in the "command" dict.
                            if not cmd_set_top.get('extcommunity'):
                                command['set']['extcommunity'] = {}
                            command['set']['extcommunity'][extcomm_type] = set_extcommunity_delete_attrs_type

                if command['set'].get('extcommunity') is not None and not command['set']['extcommunity']:
                    command['set'].pop('extcommunity')

                # Format and enqueue a request to delete eligible extcommunity attributes
                if set_extcommunity_delete_attrs:
                    bgp_set_delete_extcomm_uri = bgp_set_delete_req_base + 'set-ext-community'
                    bgp_set_delete_extcomm_payload = \
                        {'openconfig-bgp-policy:set-ext-community': {}}
                    bgp_set_delete_comm_payload_contents = \
                        bgp_set_delete_extcomm_payload[
                            'openconfig-bgp-policy:set-ext-community']
                    bgp_set_delete_comm_payload_contents['config'] = \
                        {'method': 'INLINE', 'options': 'REMOVE'}
                    bgp_set_delete_comm_payload_contents['inline'] = \
                        {'config': {'communities': set_extcommunity_delete_attrs}}

                    request = {
                        'path': bgp_set_delete_extcomm_uri,
                        'method': PATCH,
                        'data': bgp_set_delete_extcomm_payload
                    }
                    dict_delete_requests.append(request)

            # Check for deletion of ip_next_hop attributes.
            # As an optimization, avoid deleting attributes that will be replaced
            # by the received command.
            ip_next_hop_deleted_members = {}
            if 'ip_next_hop' not in cfg_set_top:
                if command['set'].get('ip_next_hop'):
                    command['set'].pop('ip_next_hop')
                    if command['set'] is None:
                        command.pop('set')
                    return

            else:
                # Delete eligible configured ip_next_hop members.
                cfg_ip_next_hop_key_set = set(cfg_set_top['ip_next_hop'].keys())
                cmd_ip_next_hop_key_set = ([])
                if cmd_set_top.get('ip_next_hop'):
                    cmd_ip_next_hop_key_set = set(cmd_set_top['ip_next_hop'].keys())

                set_uri = set_uri_attr['ip_next_hop']
                for ip_next_hop_key in cfg_ip_next_hop_key_set.difference(cmd_ip_next_hop_key_set):
                    ip_next_hop_deleted_members[ip_next_hop_key] = \
                        cfg_set_top['ip_next_hop'][ip_next_hop_key]
                    request = {'path': set_uri[ip_next_hop_key], 'method': DELETE}
                    dict_delete_requests.append(request)

                if ip_next_hop_deleted_members:
                    # Update the list of deleted ip_next_hop attributes in the "command" dict.
                    if not cmd_set_top.get('ip_next_hop'):
                        command['set']['ip_next_hop'] = {}

                    command['set']['ip_next_hop'] = ip_next_hop_deleted_members

            # Check for deletion of ipv6_next_hop attributes. Delete the attributes
            # in the currently configured ipv6_next_hop dict list if they exist.
            # As an optimization, avoid deleting attributes that will be replaced
            # by the received command.
            ipv6_next_hop_deleted_members = {}
            if 'ipv6_next_hop' not in cfg_set_top:
                if command['set'].get('ipv6_next_hop'):
                    command['set'].pop('ipv6_next_hop')
                    if command['set'] is None:
                        command.pop('set')
                    return
            else:
                # Delete eligible configured ipv6_next_hop members.
                cfg_ipv6_next_hop_key_set = set(cfg_set_top['ipv6_next_hop'].keys())
                cmd_ipv6_next_hop_key_set = ([])
                if cmd_set_top.get('ipv6_next_hop'):
                    cmd_ipv6_next_hop_key_set = set(cmd_set_top['ipv6_next_hop'].keys())
                    command['set'].pop('ipv6_next_hop')

                set_uri = set_uri_attr['ipv6_next_hop']
                for ipv6_next_hop_key in cfg_ipv6_next_hop_key_set.difference(cmd_ipv6_next_hop_key_set):
                    ipv6_next_hop_deleted_members[ipv6_next_hop_key] = \
                        cfg_set_top['ipv6_next_hop'][ipv6_next_hop_key]
                    request = {'path': set_uri[ipv6_next_hop_key], 'method': DELETE}
                    dict_delete_requests.append(request)

                if ipv6_next_hop_deleted_members:
                    # Update the list of deleted ipv6_next_hop attributes in the "command" dict.
                    if not cmd_set_top.get('ipv6_next_hop'):
                        command['set']['ipv6_next_hop'] = {}
                    command['set']['ipv6_next_hop'] = ipv6_next_hop_deleted_members

            if dict_delete_requests:
                requests.extend(dict_delete_requests)

            return

        # If no top level attribute changes were requested, check for changes in
        # dictionaries nested below the top level.
        # -----------------------------------------------------------------------

        # Check for replacement of set "community" lists. Delete the items in
        # the currently configured list if it exists and any items for that
        # list are specified in the received command.
        dict_delete_requests = []
        set_community_delete_attrs = []
        if 'community' in cmd_set_top:
            if 'community' not in cfg_set_top:
                command['set'].pop('community')
                if command['set'] is None:
                    command.pop('set')
                    return
            else:
                if 'community_number' in cmd_set_top['community']:
                    set_community_number_deletions = []
                    if 'community_number' in cfg_set_top['community']:
                        symmetric_diff_set = \
                            (set(cmd_set_top['community']['community_number']).symmetric_difference(
                             set(cfg_set_top['community']['community_number'])))
                        if symmetric_diff_set:
                            for community_number in cfg_set_top['community']['community_number']:
                                if (community_number not in cmd_set_top['community']
                                        ['community_number']):
                                    set_community_delete_attrs.append(community_number)
                                    set_community_number_deletions.append(community_number)
                    command['set']['community'].pop('community_number')
                    if set_community_delete_attrs:
                        command['set']['community']['community_number'] = \
                            set_community_number_deletions

                if 'community_attributes' in cmd_set_top['community']:
                    set_community_named_attr_deletions = []
                    if 'community_attributes' in cfg_set_top['community']:
                        symmetric_diff_set = \
                            (set(cmd_set_top[
                                'community']['community_attributes']).symmetric_difference(
                             set(cfg_set_top['community']['community_attributes'])))
                        if symmetric_diff_set:
                            cfg_set_top_comm_attr = cfg_set_top['community']['community_attributes']
                            for community_attr in cfg_set_top_comm_attr:
                                if (community_attr not in cmd_set_top['community']
                                        ['community_attributes']):
                                    set_community_delete_attrs.append(
                                        self.set_community_rest_names[community_attr])
                                    set_community_named_attr_deletions.append(community_attr)
                    command['set']['community'].pop('community_attributes')
                    if set_community_named_attr_deletions:
                        command['set']['community']['community_attributes'] = \
                            set_community_named_attr_deletions
                if command['set']['community'] is None:
                    command['set'].pop('community')

                # Format and enqueue a request to delete eligible community attributes
                if set_community_delete_attrs:
                    bgp_set_delete_community_uri = bgp_set_delete_req_base + 'set-community'
                    bgp_set_delete_comm_payload = \
                        {'openconfig-bgp-policy:set-community': {}}
                    bgp_set_delete_comm_payload_contents = \
                        bgp_set_delete_comm_payload['openconfig-bgp-policy:set-community']
                    bgp_set_delete_comm_payload_contents['config'] = \
                        {'method': 'INLINE', 'options': 'REMOVE'}
                    bgp_set_delete_comm_payload_contents['inline'] = \
                        {'config': {'communities': set_community_delete_attrs}}

                    request = {
                        'path': bgp_set_delete_community_uri,
                        'method': PATCH,
                        'data': bgp_set_delete_comm_payload
                    }
                    dict_delete_requests.append(request)

        # Check for replacement of set "extcommunity" lists. Delete any items in
        # the currently configured list if the corresponding item is not
        # specified in the received command.
        set_extcommunity_delete_attrs = []
        if 'extcommunity' in cmd_set_top:
            if 'extcommunity' not in cfg_set_top:
                command['set'].pop('extcommunity')
            else:
                for extcomm_type in self.set_extcomm_rest_names:
                    set_extcommunity_delete_attrs_type = []
                    if cmd_set_top['extcommunity'].get(extcomm_type):
                        if extcomm_type in cfg_set_top['extcommunity']:
                            symmetric_diff_set = \
                                (set(
                                    to_extcom_str_list(cmd_set_top['extcommunity'][extcomm_type])).symmetric_difference(
                                        set(cfg_set_top['extcommunity'][extcomm_type])))
                            if symmetric_diff_set:
                                # Append eligible entries to the delete list.
                                for extcomm_number in cfg_set_top['extcommunity'][extcomm_type]:
                                    if (extcomm_number not in
                                            cmd_set_top['extcommunity'][extcomm_type]):
                                        set_extcommunity_delete_attrs.append(
                                            self.set_extcomm_rest_names[extcomm_type] +
                                            extcomm_number)
                                        set_extcommunity_delete_attrs_type.append(extcomm_number)
                        # Replace the requested extcommunity numbers for this type with the list of
                        # deleted extcommunity numbers (if any) for this type.
                        command['set']['extcommunity'].pop(extcomm_type)
                        if set_extcommunity_delete_attrs_type:
                            command['set']['extcommunity'][extcomm_type] = \
                                set_extcommunity_delete_attrs_type

                if command['set']['extcommunity'] is None:
                    command['set'].pop('extcommunity')

                # Format and enqueue a request to delete eligible extcommunity attributes
                if set_extcommunity_delete_attrs:
                    bgp_set_delete_extcomm_uri = bgp_set_delete_req_base + 'set-ext-community'
                    bgp_set_delete_extcomm_payload = \
                        {'openconfig-bgp-policy:set-ext-community': {}}
                    bgp_set_delete_comm_payload_contents = \
                        bgp_set_delete_extcomm_payload[
                            'openconfig-bgp-policy:set-ext-community']
                    bgp_set_delete_comm_payload_contents['config'] = \
                        {'method': 'INLINE', 'options': 'REMOVE'}
                    bgp_set_delete_comm_payload_contents['inline'] = \
                        {'config': {'communities': set_extcommunity_delete_attrs}}

                    request = {
                        'path': bgp_set_delete_extcomm_uri,
                        'method': PATCH,
                        'data': bgp_set_delete_extcomm_payload
                    }
                    dict_delete_requests.append(request)

        # If the "replaced" command set includes ip_next_hop attributes that
        # differ from the currently configured attributes, delete
        # ip_next_hop configuration, if it exists, for any ip_next_hop
        # attributes that are not specified in the received command.
        if 'ip_next_hop' in cmd_set_top:
            ip_next_hop_deleted_members = {}
            if 'ip_next_hop' in cfg_set_top:
                symmetric_diff_set = \
                    (set(cmd_set_top['ip_next_hop'].keys()).symmetric_difference(
                     set(cfg_set_top['ip_next_hop'].keys())))
                intersection_diff_set = \
                    (set(cmd_set_top['ip_next_hop'].keys()).intersection(
                     set(cfg_set_top['ip_next_hop'].keys())))
                if (symmetric_diff_set or
                    (any(keyname for keyname in intersection_diff_set if
                         cmd_set_top['ip_next_hop'][keyname] !=
                         cfg_set_top['ip_next_hop'][keyname]))):
                    set_uri = set_uri_attr['ip_next_hop']
                    for member_key in set_uri:
                        if (cfg_set_top['ip_next_hop'].get(member_key) is not None and
                                cmd_set_top['ip_next_hop'].get(member_key) is None):
                            ip_next_hop_deleted_members[member_key] = \
                                cfg_set_top['ip_next_hop'][member_key]
                            request = {'path': set_uri[member_key], 'method': DELETE}
                            dict_delete_requests.append(request)
            command['set'].pop('ip_next_hop')
            if ip_next_hop_deleted_members:
                command['set']['ip_next_hop'] = ip_next_hop_deleted_members

        # If the "replaced" command set includes ipv6_next_hop attributes that
        # differ from the currently configured attributes, delete
        # ipv6_next_hop configuration, if it exists, for any ipv6_next_hop
        # attributes that are not specified in the received command.
        if 'ipv6_next_hop' in cmd_set_top:
            ipv6_next_hop_deleted_members = {}
            if 'ipv6_next_hop' in cfg_set_top:
                symmetric_diff_set = \
                    (set(cmd_set_top['ipv6_next_hop'].keys()).symmetric_difference(
                     set(cfg_set_top['ipv6_next_hop'].keys())))
                intersection_diff_set = \
                    (set(cmd_set_top['ipv6_next_hop'].keys()).intersection(
                     set(cfg_set_top['ipv6_next_hop'].keys())))
                if (symmetric_diff_set or
                    (any(keyname for keyname in intersection_diff_set if
                         cmd_set_top['ipv6_next_hop'][keyname] !=
                         cfg_set_top['ipv6_next_hop'][keyname]))):
                    set_uri = set_uri_attr['ipv6_next_hop']
                    for member_key in set_uri:
                        if (cfg_set_top['ipv6_next_hop'].get(member_key) is not None and
                                cmd_set_top['ipv6_next_hop'].get(member_key) is None):
                            ipv6_next_hop_deleted_members[member_key] = \
                                cfg_set_top['ipv6_next_hop'][member_key]
                            request = {'path': set_uri[member_key], 'method': DELETE}
                            dict_delete_requests.append(request)
            command['set'].pop('ipv6_next_hop')
            if ipv6_next_hop_deleted_members:
                command['set']['ipv6_next_hop'] = ipv6_next_hop_deleted_members

        if dict_delete_requests:
            requests.extend(dict_delete_requests)

    def validate_and_normalize_config(self, input_config_list):
        '''For each input route map dict in the input_config_list list,
        remove empty entries, validate the contents of the dict against the
        argspec constraints for route maps, and convert input interface names to
        the format required for the currently configured interface naming
        mode.'''
        updated_config_list = remove_empties_from_list(input_config_list)
        validate_config(self._module.argument_spec, {'config': updated_config_list})

        # - Verify that parameters required for most "states" are present in
        # each dict in the input list.
        # - Check for interface names in the input configuration and
        # perform any needed reformatting of the names.
        for route_map in updated_config_list:

            # Verify the presence of a "sequence number" and "action" value
            # for all states other than "deleted"
            if self._module.params['state'] != 'deleted':
                check_required(self._module, ['action', 'sequence_num'], route_map, ['config'])

            # Check for interface names requiring re-formatting.
            if not route_map.get('match'):
                continue

            if route_map['match'].get('interface'):
                intf_name = route_map['match']['interface']
                updated_intf_name = get_normalize_interface_name(intf_name, self._module)
                route_map['match']['interface'] = updated_intf_name

            if route_map['match'].get('peer') and route_map['match']['peer'].get('interface'):
                intf_name = route_map['match']['peer']['interface']
                updated_intf_name = get_normalize_interface_name(intf_name, self._module)
                route_map['match']['peer']['interface'] = updated_intf_name

        return updated_config_list

    def sort_lists_in_config(self, config):
        if config:
            config.sort(key=lambda x: (x['map_name'],
                                       x.get('sequence_num') if x.get('sequence_num') is not None else 0))

    def post_process_generated_config(self, configs):
        confs = remove_empties_from_list(configs)
        if confs:
            for conf in confs[:]:
                rm_match = conf.get('match', None)
                rm_set = conf.get('set', None)
                rm_call = conf.get('call', None)
                if not rm_match and not rm_set and not rm_call:
                    confs.remove(conf)
        return confs
