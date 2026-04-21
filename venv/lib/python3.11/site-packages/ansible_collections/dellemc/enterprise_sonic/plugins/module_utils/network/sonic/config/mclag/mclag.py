#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_mclag class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import re
from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_empties,
    to_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    get_ranges_in_list,
    get_normalize_interface_name,
    normalize_interface_name
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __MERGE_OP_DEFAULT,
    __DELETE_OP_DEFAULT,
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
PUT = 'put'
DELETE = 'delete'

TEST_KEYS = [
    {'config': {'domain_id': ''}},
    {'vlans': {'vlan': ''}},
    {'portchannels': {'lag': ''}},
]


def __derive_mclag_config_merge_op(key_set, command, exist_conf):
    c_did = command.get('domain_id', None)
    e_did = exist_conf.get('domain_id', None)
    if not c_did and not e_did:
        return True, exist_conf
    elif not c_did:
        command['domain_id'] = e_did
    elif not e_did:
        exist_conf['domain_id'] = c_did

    if command['domain_id'] != exist_conf['domain_id']:
        return True, exist_conf
    else:
        return __MERGE_OP_DEFAULT(key_set, command, exist_conf)


def __derive_mclag_config_delete_op(key_set, command, exist_conf):
    if command:
        command['domain_id'] = exist_conf['domain_id']
    done, new_conf = __DELETE_OP_DEFAULT(key_set, command, exist_conf)
    return done, new_conf


TEST_KEYS_generate_config = [
    {'config': {'__merge_op': __derive_mclag_config_merge_op,
                '__delete_op': __derive_mclag_config_delete_op}},
    {'vlans': {'vlan': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
    {'portchannels': {'lag': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
]


class Mclag(ConfigBase):
    """
    The sonic_mclag class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'mclag',
    ]

    mclag_simple_attrs = set({
        'peer_address',
        'source_address',
        'peer_link',
        'session_vrf',
        'system_mac',
        'keepalive',
        'session_timeout',
        'delay_restore',
        'gateway_mac',
        'backup_keepalive_source_address',
        'backup_keepalive_peer_address',
        'backup_keepalive_session_vrf',
        'backup_keepalive_interval'
    })

    def __init__(self, module):
        super(Mclag, self).__init__(module)

    def get_mclag_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        mclag_facts = facts['ansible_network_resources'].get('mclag')
        if not mclag_facts:
            return {}
        return mclag_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_mclag_facts = self.get_mclag_facts()
        commands, requests = self.set_config(existing_mclag_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                self.edit_config(requests)
            result['changed'] = True
        result['commands'] = commands

        changed_mclag_facts = self.get_mclag_facts()

        result['before'] = existing_mclag_facts
        if result['changed']:
            result['after'] = changed_mclag_facts

        new_config = changed_mclag_facts
        old_config = existing_mclag_facts
        if self._module.check_mode:
            result.pop('after', None)
            for command in commands:
                self.transform_config_for_diff_check(command)
            self.transform_config_for_diff_check(existing_mclag_facts)
            new_config = get_new_config(commands, existing_mclag_facts,
                                        TEST_KEYS_generate_config)
            d_id = existing_mclag_facts.get('domain_id', None)
            new_config = self.post_process_generated_config(new_config, d_id)
            result['after(generated)'] = new_config

        if self._module._diff:
            self.transform_config_for_diff_check(new_config)
            self.transform_config_for_diff_check(old_config)
            self.sort_lists_in_config(new_config)
            self.sort_lists_in_config(old_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def edit_config(self, requests):
        try:
            response = edit_config(self._module, to_request(self._module, requests))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

    def set_config(self, existing_mclag_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want:
            peer_link = want.get("peer_link", None)
            if peer_link:
                want['peer_link'] = get_normalize_interface_name(want['peer_link'], self._module)
            unique_ip = want.get('unique_ip', None)
            if unique_ip:
                vlans_list = unique_ip['vlans']
                if vlans_list:
                    normalize_interface_name(vlans_list, self._module, 'vlan')
            peer_gateway = want.get('peer_gateway', None)
            if peer_gateway:
                vlans_list = peer_gateway['vlans']
                if vlans_list:
                    normalize_interface_name(vlans_list, self._module, 'vlan')
            members = want.get('members', None)
            if members:
                portchannels_list = members['portchannels']
                if portchannels_list:
                    normalize_interface_name(portchannels_list, self._module, 'lag')
        have = existing_mclag_facts
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
            diff = get_diff(want, have, TEST_KEYS)
            commands, requests = self._state_merged(want, have, diff)
        elif state in ('replaced', 'overridden'):
            commands, requests = self._state_replaced_overridden(want, have, state)
        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        requests = []
        commands = []
        if diff:
            # Obtain diff for VLAN ranges in unique_ip
            if 'unique_ip' in diff and diff['unique_ip'] is not None and diff['unique_ip'].get('vlans'):
                if 'unique_ip' in have and have['unique_ip'] is not None and have['unique_ip'].get('vlans'):
                    diff['unique_ip']['vlans'] = self.get_vlan_range_diff(diff['unique_ip']['vlans'], have['unique_ip']['vlans'])
                    if not diff['unique_ip']['vlans']:
                        diff.pop('unique_ip')
                        if len(diff) == 1:
                            diff.pop('domain_id')

            # Obtain diff for VLAN ranges in peer_gateway
            if 'peer_gateway' in diff and diff['peer_gateway'] is not None and diff['peer_gateway'].get('vlans'):
                if 'peer_gateway' in have and have['peer_gateway'] is not None and have['peer_gateway'].get('vlans'):
                    diff['peer_gateway']['vlans'] = self.get_vlan_range_diff(diff['peer_gateway']['vlans'], have['peer_gateway']['vlans'])
                    if not diff['peer_gateway']['vlans']:
                        diff.pop('peer_gateway')
                        if len(diff) == 1:
                            diff.pop('domain_id')

            requests = self.get_create_mclag_requests(want, diff, have)
            if len(requests) > 0:
                commands = update_states(diff, "merged")
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
            if have:
                requests = self.get_delete_all_mclag_domain_requests(have)
                if len(requests) > 0:
                    commands = update_states(have, "deleted")
        else:
            del_unique_ip_vlans = []
            del_peer_gateway_vlans = []
            # Create list of VLANs to be deleted based on VLAN ranges in unique_ip
            if 'unique_ip' in want and want['unique_ip'] is not None and want['unique_ip'].get('vlans'):
                want_unique_ip = want.pop('unique_ip')
                if 'unique_ip' in have and have['unique_ip'] is not None and have['unique_ip'].get('vlans'):
                    del_unique_ip_vlans = self.get_vlan_range_common(want_unique_ip['vlans'], have['unique_ip']['vlans'])

            # Create list of VLANs to be deleted based on VLAN ranges in peer_gateway
            if 'peer_gateway' in want and want['peer_gateway'] is not None and want['peer_gateway'].get('vlans'):
                want_peer_gateway = want.pop('peer_gateway')
                if 'peer_gateway' in have and have['peer_gateway'] is not None and have['peer_gateway'].get('vlans'):
                    del_peer_gateway_vlans = self.get_vlan_range_common(want_peer_gateway['vlans'], have['peer_gateway']['vlans'])

            new_have = self.remove_default_entries(have)
            d_diff = get_diff(want, new_have, TEST_KEYS, is_skeleton=True)
            diff_want = get_diff(want, d_diff, TEST_KEYS, is_skeleton=True)

            if del_unique_ip_vlans:
                diff_want['unique_ip'] = {'vlans': del_unique_ip_vlans}
            if del_peer_gateway_vlans:
                diff_want['peer_gateway'] = {'vlans': del_peer_gateway_vlans}

            if diff_want:
                requests = self.get_delete_mclag_attribute_requests(have['domain_id'], diff_want)
                if len(requests) > 0:
                    commands = update_states(diff_want, "deleted")
        return commands, requests

    def _state_replaced_overridden(self, want, have, state):
        """ The command generator when state is replaced/overridden

        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands = []
        requests = []
        if want and not have:
            commands = [update_states(want, state)]
            requests = self.get_create_mclag_requests(want, want, have)
        elif not want and have:
            commands = [update_states(have, 'deleted')]
            requests = self.get_delete_all_mclag_domain_requests(have)
        elif want and have:
            add_command = {}
            del_command = {}
            delete_all = False

            # If 'domain_id' is modified, delete all mclag configuration.
            if want['domain_id'] != have['domain_id']:
                del_command = have
                add_command = want
                delete_all = True
            else:
                have = have.copy()
                want = want.copy()
                delete_all_vlans = {
                    'unique_ip': False,
                    'peer_gateway': False
                }

                # Delete unspecified configurations when:
                # 1) state is overridden.
                # 2) state is replaced and configuration other than
                #    unique_ip, peer_gateway or members is specified.
                delete_unspecified = True
                if state == 'replaced' and not self.mclag_simple_attrs.intersection(remove_empties(want).keys()):
                    delete_unspecified = False

                # Create lists of VLANs to be deleted and added based on VLAN ranges
                for option in ('unique_ip', 'peer_gateway'):
                    have_cfg = {}
                    want_cfg = {}
                    # The options are removed from the dict to avoid
                    # comparing the VLAN ranges two more times using get_diff
                    if have.get(option) and have[option].get('vlans'):
                        have_cfg = have.pop(option)
                    if want.get(option) and 'vlans' in want[option]:
                        want_cfg = want.pop(option)

                    if want_cfg:
                        if have_cfg:
                            # Delete all VLANs if empty 'vlans' list is provided
                            if not want_cfg['vlans']:
                                delete_all_vlans[option] = True
                                del_command[option] = have_cfg
                            else:
                                have_vlans = set(self.get_vlan_id_list(have_cfg['vlans']))
                                want_vlans = set(self.get_vlan_id_list(want_cfg['vlans']))
                                if have_vlans.intersection(want_vlans):
                                    del_command[option] = {'vlans': self.get_vlan_range_list(list(have_vlans - want_vlans))}
                                    if not del_command[option]['vlans']:
                                        del_command.pop(option)
                                    add_command[option] = {'vlans': self.get_vlan_range_list(list(want_vlans - have_vlans))}
                                    if not add_command[option]['vlans']:
                                        add_command.pop(option)
                                else:
                                    delete_all_vlans[option] = True
                                    del_command[option] = have_cfg
                                    add_command[option] = want_cfg
                        else:
                            if want_cfg['vlans']:
                                add_command[option] = want_cfg
                    else:
                        if have_cfg and delete_unspecified:
                            delete_all_vlans[option] = True
                            del_command[option] = have_cfg

                del_diff = get_diff(self.remove_default_entries(have), want, TEST_KEYS)
                for option in del_diff:
                    if not want.get(option):
                        if delete_unspecified:
                            del_command[option] = del_diff[option]
                    else:
                        # Delete portchannels that are not specified
                        if option == 'members' and want.get(option):
                            del_command[option] = del_diff[option]

                        # To update 'gateway_mac' configuration in the device,
                        # delete already configured value.
                        if option == 'gateway_mac' and want.get(option):
                            del_command[option] = del_diff[option]

                diff = get_diff(want, have, TEST_KEYS)
                add_command.update(diff)

            if del_command:
                del_command['domain_id'] = have['domain_id']
                commands.extend(update_states(del_command, 'deleted'))
                if delete_all:
                    requests = self.get_delete_all_mclag_domain_requests(del_command)
                    have = {}
                else:
                    if any(delete_all_vlans.values()):
                        del_command = deepcopy(del_command)

                    # Set 'vlans' to None to delete all VLANs
                    for option in delete_all_vlans:
                        if delete_all_vlans[option]:
                            del_command[option]['vlans'] = None
                    requests = self.get_delete_mclag_attribute_requests(del_command['domain_id'], del_command)

            if add_command:
                add_command['domain_id'] = want['domain_id']
                commands.extend(update_states(add_command, state))
                requests.extend(self.get_create_mclag_requests(add_command, add_command, have))

        return commands, requests

    def remove_default_entries(self, data):
        new_data = {}
        if not data:
            return new_data
        else:
            default_val_dict = {
                'keepalive': 1,
                'session_timeout': 30,
                'delay_restore': 300,
                'backup_keepalive_interval': 30
            }
            for key, val in data.items():
                if not (val is None or (key in default_val_dict and val == default_val_dict[key])):
                    new_data[key] = val

            return new_data

    def get_delete_mclag_attribute_requests(self, domain_id, command):
        requests = []
        url_common = 'data/openconfig-mclag:mclag/mclag-domains/mclag-domain=%s/config' % (domain_id)
        method = DELETE
        if 'source_address' in command and command["source_address"] is not None:
            url = url_common + '/source-address'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'peer_address' in command and command["peer_address"] is not None:
            url = url_common + '/peer-address'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'peer_link' in command and command["peer_link"] is not None:
            url = url_common + '/peer-link'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'keepalive' in command and command["keepalive"] is not None:
            url = url_common + '/keepalive-interval'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'session_timeout' in command and command["session_timeout"] is not None:
            url = url_common + '/session-timeout'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'session_vrf' in command and command["session_vrf"] is not None:
            url = url_common + '/session-vrf'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'system_mac' in command and command["system_mac"] is not None:
            url = url_common + '/mclag-system-mac'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'delay_restore' in command and command['delay_restore'] is not None:
            url = url_common + '/delay-restore'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'peer_gateway' in command and command['peer_gateway'] is not None:
            if command['peer_gateway']['vlans'] is None:
                request = {'path': 'data/openconfig-mclag:mclag/vlan-ifs/vlan-if', 'method': method}
                requests.append(request)
            elif command['peer_gateway']['vlans'] is not None:
                vlan_id_list = self.get_vlan_id_list(command['peer_gateway']['vlans'])
                for vlan in vlan_id_list:
                    peer_gateway_url = 'data/openconfig-mclag:mclag/vlan-ifs/vlan-if=Vlan{0}'.format(vlan)
                    request = {'path': peer_gateway_url, 'method': method}
                    requests.append(request)
        if 'unique_ip' in command and command['unique_ip'] is not None:
            if command['unique_ip']['vlans'] is None:
                request = {'path': 'data/openconfig-mclag:mclag/vlan-interfaces/vlan-interface', 'method': method}
                requests.append(request)
            elif command['unique_ip']['vlans'] is not None:
                vlan_id_list = self.get_vlan_id_list(command['unique_ip']['vlans'])
                for vlan in vlan_id_list:
                    unique_ip_url = 'data/openconfig-mclag:mclag/vlan-interfaces/vlan-interface=Vlan{0}'.format(vlan)
                    request = {'path': unique_ip_url, 'method': method}
                    requests.append(request)
        if 'members' in command and command['members'] is not None:
            if command['members']['portchannels'] is None:
                request = {'path': 'data/openconfig-mclag:mclag/interfaces/interface', 'method': method}
                requests.append(request)
            elif command['members']['portchannels'] is not None:
                for each in command['members']['portchannels']:
                    if each:
                        portchannel_url = 'data/openconfig-mclag:mclag/interfaces/interface=%s' % (each['lag'])
                        request = {'path': portchannel_url, 'method': method}
                        requests.append(request)
        if 'gateway_mac' in command and command['gateway_mac'] is not None:
            request = {'path': 'data/openconfig-mclag:mclag/mclag-gateway-macs/mclag-gateway-mac', 'method': method}
            requests.append(request)
        if 'backup_keepalive_source_address' in command and command['backup_keepalive_source_address'] is not None:
            url = url_common + '/backup-keepalive-source-address'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'backup_keepalive_peer_address' in command and command['backup_keepalive_peer_address'] is not None:
            url = url_common + '/backup-keepalive-peer-address'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'backup_keepalive_session_vrf' in command and command['backup_keepalive_session_vrf'] is not None:
            url = url_common + '/backup-keepalive-session-vrf'
            request = {'path': url, 'method': method}
            requests.append(request)
        if 'backup_keepalive_interval' in command and command['backup_keepalive_interval'] is not None:
            url = url_common + '/backup-keepalive-interval'
            request = {'path': url, 'method': method}
            requests.append(request)
        return requests

    def get_delete_all_mclag_domain_requests(self, have):
        requests = []
        path = 'data/openconfig-mclag:mclag/mclag-domains'
        method = DELETE
        if have.get('peer_gateway'):
            request = {'path': 'data/openconfig-mclag:mclag/vlan-ifs/vlan-if', 'method': method}
            requests.append(request)
        if have.get('unique_ip'):
            request = {'path': 'data/openconfig-mclag:mclag/vlan-interfaces/vlan-interface', 'method': method}
            requests.append(request)
        if have.get('gateway_mac'):
            request = {'path': 'data/openconfig-mclag:mclag/mclag-gateway-macs/mclag-gateway-mac', 'method': method}
            requests.append(request)
        if have.get('members'):
            request = {'path': 'data/openconfig-mclag:mclag/interfaces/interface', 'method': method}
            requests.append(request)
        request = {'path': path, 'method': method}
        requests.append(request)
        return requests

    def get_create_mclag_requests(self, want, commands, have):
        requests = []
        path = 'data/openconfig-mclag:mclag/mclag-domains/mclag-domain'
        method = PATCH
        payload = self.build_create_payload(want, commands, have)
        if payload:
            # With current SONiC behavior, it is necessary to use REST put method to ensure
            # the initial configuration of a domain id is configured on the device in all cases.
            if commands['domain_id'] != have.get('domain_id'):
                method = PUT
            request = {'path': path, 'method': method, 'data': payload}
            requests.append(request)
        if 'gateway_mac' in commands and commands['gateway_mac'] is not None:
            gateway_mac_path = 'data/openconfig-mclag:mclag/mclag-gateway-macs/mclag-gateway-mac'
            gateway_mac_method = PATCH
            gateway_mac_payload = {
                'openconfig-mclag:mclag-gateway-mac': [{
                    'gateway-mac': commands['gateway_mac'],
                    'config': {'gateway-mac': commands['gateway_mac']}
                }]
            }
            request = {'path': gateway_mac_path, 'method': gateway_mac_method, 'data': gateway_mac_payload}
            requests.append(request)
        if 'unique_ip' in commands and commands['unique_ip'] is not None:
            if commands['unique_ip']['vlans'] and commands['unique_ip']['vlans'] is not None:
                unique_ip_path = 'data/openconfig-mclag:mclag/vlan-interfaces/vlan-interface'
                unique_ip_method = PATCH
                unique_ip_payload = self.build_create_unique_ip_payload(commands['unique_ip']['vlans'])
                request = {'path': unique_ip_path, 'method': unique_ip_method, 'data': unique_ip_payload}
                requests.append(request)
        if 'peer_gateway' in commands and commands['peer_gateway'] is not None:
            if commands['peer_gateway']['vlans'] and commands['peer_gateway']['vlans'] is not None:
                peer_gateway_path = 'data/openconfig-mclag:mclag/vlan-ifs/vlan-if'
                peer_gateway_method = PATCH
                peer_gateway_payload = self.build_create_peer_gateway_payload(commands['peer_gateway']['vlans'])
                request = {'path': peer_gateway_path, 'method': peer_gateway_method, 'data': peer_gateway_payload}
                requests.append(request)
        if 'members' in commands and commands['members'] is not None:
            if commands['members']['portchannels'] and commands['members']['portchannels'] is not None:
                portchannel_path = 'data/openconfig-mclag:mclag/interfaces/interface'
                portchannel_method = PATCH
                portchannel_payload = self.build_create_portchannel_payload(want, commands['members']['portchannels'])
                request = {'path': portchannel_path, 'method': portchannel_method, 'data': portchannel_payload}
                requests.append(request)
        return requests

    def build_create_payload(self, want, commands, have):
        temp = {}
        if 'session_timeout' in commands and commands['session_timeout'] is not None:
            temp['session-timeout'] = commands['session_timeout']
        if 'keepalive' in commands and commands['keepalive'] is not None:
            temp['keepalive-interval'] = commands['keepalive']
        if 'source_address' in commands and commands['source_address'] is not None:
            temp['source-address'] = commands['source_address']
        if 'peer_address' in commands and commands['peer_address'] is not None:
            temp['peer-address'] = commands['peer_address']
        if 'session_vrf' in commands and commands['session_vrf'] is not None:
            temp['session-vrf'] = commands['session_vrf']
        if 'peer_link' in commands and commands['peer_link'] is not None:
            temp['peer-link'] = str(commands['peer_link'])
        if 'system_mac' in commands and commands['system_mac'] is not None:
            temp['openconfig-mclag:mclag-system-mac'] = str(commands['system_mac'])
        if 'delay_restore' in commands and commands['delay_restore'] is not None:
            temp['delay-restore'] = commands['delay_restore']
        if 'backup_keepalive_source_address' in commands and commands['backup_keepalive_source_address'] is not None:
            temp['backup-keepalive-source-address'] = commands['backup_keepalive_source_address']
        if 'backup_keepalive_peer_address' in commands and commands['backup_keepalive_peer_address'] is not None:
            temp['backup-keepalive-peer-address'] = commands['backup_keepalive_peer_address']
        if 'backup_keepalive_interval' in commands and commands['backup_keepalive_interval'] is not None:
            temp['backup-keepalive-interval'] = commands['backup_keepalive_interval']
        if 'backup_keepalive_session_vrf' in commands and commands['backup_keepalive_session_vrf'] is not None:
            temp['backup-keepalive-session-vrf'] = commands['backup_keepalive_session_vrf']
        mclag_dict = {}
        # Create payload if the above attributes are present in commands or
        # if domain ID doesn't exist
        if temp or (commands.get('domain_id') is not None and commands['domain_id'] != have.get('domain_id')):
            temp['domain-id'] = commands['domain_id']
            domain_id = {"domain-id": want["domain_id"]}
            mclag_dict.update(domain_id)
            config = {"config": temp}
            mclag_dict.update(config)
            payload = {"openconfig-mclag:mclag-domain": [mclag_dict]}
        else:
            payload = {}

        return payload

    def build_create_unique_ip_payload(self, commands):
        payload = {"openconfig-mclag:vlan-interface": []}
        vlan_id_list = self.get_vlan_id_list(commands)
        for vlan in vlan_id_list:
            vlan_name = 'Vlan{0}'.format(vlan)
            payload['openconfig-mclag:vlan-interface'].append({"name": vlan_name, "config": {"name": vlan_name, "unique-ip-enable": "ENABLE"}})
        return payload

    def build_create_peer_gateway_payload(self, commands):
        payload = {"openconfig-mclag:vlan-if": []}
        vlan_id_list = self.get_vlan_id_list(commands)
        for vlan in vlan_id_list:
            vlan_name = 'Vlan{0}'.format(vlan)
            payload['openconfig-mclag:vlan-if'].append({"name": vlan_name, "config": {"name": vlan_name, "peer-gateway-enable": "ENABLE"}})
        return payload

    def build_create_portchannel_payload(self, want, commands):
        payload = {"openconfig-mclag:interface": []}
        for each in commands:
            payload['openconfig-mclag:interface'].append({"name": each['lag'], "config": {"name": each['lag'], "mclag-domain-id": want['domain_id']}})
        return payload

    def get_vlan_range_common(self, config_vlans, match_vlans):
        """Returns the vlan ranges present in both 'config_vlans'
        and 'match_vlans' in vlans spec format
        """
        if not config_vlans:
            return []

        if not match_vlans:
            return []

        config_vlans = self.get_vlan_id_list(config_vlans)
        match_vlans = self.get_vlan_id_list(match_vlans)
        return self.get_vlan_range_list(list(set(config_vlans).intersection(set(match_vlans))))

    def get_vlan_range_diff(self, config_vlans, match_vlans):
        """Returns the vlan ranges present only in 'config_vlans'
        and not in 'match_vlans' in vlans spec format
        """
        if not config_vlans:
            return []

        if not match_vlans:
            return config_vlans

        config_vlans = self.get_vlan_id_list(config_vlans)
        match_vlans = self.get_vlan_id_list(match_vlans)
        return self.get_vlan_range_list(list(set(config_vlans) - set(match_vlans)))

    @staticmethod
    def get_vlan_id_list(vlan_range_list):
        """Returns a list of all VLAN IDs specified in VLAN range list"""
        vlan_id_list = []
        if vlan_range_list:
            for vlan_range in vlan_range_list:
                vlan_val = vlan_range['vlan']
                if '-' in vlan_val:
                    match = re.match(r'Vlan(\d+)-(\d+)', vlan_val)
                    if match:
                        vlan_id_list.extend(range(int(match.group(1)), int(match.group(2)) + 1))
                else:
                    # Single VLAN ID
                    match = re.match(r'Vlan(\d+)', vlan_val)
                    if match:
                        vlan_id_list.append(int(match.group(1)))

        return vlan_id_list

    @staticmethod
    def get_vlan_range_list(vlan_id_list):
        """Returns a list of VLAN ranges for given list of VLAN IDs
        in vlans spec format"""
        vlan_range_list = []

        if vlan_id_list:
            vlan_id_list.sort()
            for vlan_range in get_ranges_in_list(vlan_id_list):
                vlan_range_list.append({'vlan': 'Vlan{0}'.format('-'.join(map(str, (vlan_range[0], vlan_range[-1])[:len(vlan_range)])))})

        return vlan_range_list

    def sort_lists_in_config(self, config):
        if config:
            unique_ip = config.get('unique_ip', None)
            if unique_ip and unique_ip.get('vlans', None):
                unique_ip['vlans'].sort(key=lambda x: x['vlan'])

            peer_gateway = config.get('peer_gateway', None)
            if peer_gateway and peer_gateway.get('vlans', None):
                peer_gateway['vlans'].sort(key=lambda x: x['vlan'])

            members = config.get('members', None)
            if members and members.get('portchannels', None):
                members['portchannels'].sort(key=lambda x: x['lag'])

    def post_process_generated_config(self, configs, domain_id):
        confs = remove_empties(configs)
        if confs:
            if confs.get('domain_id', None):
                keys = confs.keys()
                if len(keys) <= 1:
                    confs = dict()
            else:
                confs['domain_id'] = domain_id
        return confs

    def expand_vlan_id_range(self, vlan_list):
        new_vlan_list = []
        for vlan in vlan_list:
            vids = vlan['vlan']
            if "-" in vids:
                vids = vids.replace('Vlan', '')
                vid_list = vids.split('-')
                vid_lower = int(vid_list[0])
                vid_upper = int(vid_list[1])
                for vid in range(vid_lower, vid_upper + 1):
                    new_vlan_list.append({'vlan': 'Vlan' + str(vid)})
            else:
                new_vlan_list.append(vlan)
        return new_vlan_list

    def transform_config_for_diff_check(self, configs):
        if configs:
            unique_ip = configs.get('unique_ip', None)
            if unique_ip and unique_ip.get('vlans', None):
                unique_ip['vlans'] = self.expand_vlan_id_range(unique_ip['vlans'])

            peer_gateway = configs.get('peer_gateway', None)
            if peer_gateway and peer_gateway.get('vlans', None):
                peer_gateway['vlans'] = self.expand_vlan_id_range(peer_gateway['vlans'])
