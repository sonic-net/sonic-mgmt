#
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_bgp_neighbors class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    remove_matching_defaults,
    remove_empties,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.sort_config_util import (
    sort_config,
    remove_void_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    convert_bgp_asn,
    validate_bgps,
    normalize_neighbors_interface_name,
    get_ip_afi_cfg_payload,
    get_prefix_limit_payload
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'

TEST_KEYS = [
    {'config': {'vrf_name': '', 'bgp_as': ''}},
    {'neighbors': {'neighbor': ''}},
    {'peer_group': {'name': ''}},
    {'afis': {'afi': '', 'safi': ''}}
]

DEFAULT_ENTRIES = [
    [
        {'name': 'peer_group'},
        {'name': 'timers'},
        {'name': 'keepalive', 'default': 60}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'timers'},
        {'name': 'holdtime', 'default': 180}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'timers'},
        {'name': 'connect_retry', 'default': 30}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'advertisement_interval', 'default': 0}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'auth_pwd'},
        {'name': 'encrypted', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'ebgp_multihop'},
        {'name': 'enabled', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'passive', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'local_as'},
        {'name': 'no_prepend', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'local_as'},
        {'name': 'replace_as', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'address_family'},
        {'name': 'afis'},
        {'name': 'ip_afi'},
        {'name': 'send_default_route', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'address_family'},
        {'name': 'afis'},
        {'name': 'activate', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'address_family'},
        {'name': 'afis'},
        {'name': 'prefix_limit'},
        {'name': 'prevent_teardown', 'default': False}
    ],
    [
        {'name': 'peer_group'},
        {'name': 'address_family'},
        {'name': 'afis'},
        {'name': 'prefix_limit'},
        {'name': 'discard_extra', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'timers'},
        {'name': 'keepalive', 'default': 60}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'timers'},
        {'name': 'holdtime', 'default': 180}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'timers'},
        {'name': 'connect_retry', 'default': 30}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'advertisement_interval', 'default': 0}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'ebgp_multihop'},
        {'name': 'enabled', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'passive', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'local_as'},
        {'name': 'no_prepend', 'default': False}
    ],
    [
        {'name': 'neighbors'},
        {'name': 'local_as'},
        {'name': 'replace_as', 'default': False}
    ]
]

is_delete_all = False
TEST_KEYS_sort_config = [
    {'config': {'__test_keys': ('vrf_name', 'bgp_as')}},
    {'neighbors': {'__test_keys': ('neighbor',)}},
    {'peer_group': {'__test_keys': ('name',)}},
    {'afis': {'__test_keys': ('afi', 'safi')}},
]


def __derive_bgp_nbrs_delete_op(key_set, command, exist_conf):

    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    if done:
        return done, new_conf
    else:
        return __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, new_conf)


def __derive_bgp_neighbors_delete_op(key_set, command, exist_conf):

    if is_delete_all:
        new_conf = {'bgp_as': exist_conf['bgp_as'], 'vrf_name': exist_conf['vrf_name']}
        return True, new_conf

    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    if not new_conf:
        new_conf = {'bgp_as': command['bgp_as'], 'vrf_name': command['vrf_name']}

    return done, new_conf


TEST_KEYS_generate_config = [
    {'__default_ops': {'__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'config': {'vrf_name': '', 'bgp_as': '', '__delete_op': __derive_bgp_neighbors_delete_op}},
    {'neighbors': {'neighbor': '', '__delete_op': __derive_bgp_nbrs_delete_op}},
    {'peer_group': {'name': '', '__delete_op': __derive_bgp_nbrs_delete_op}},
    {'afis': {'afi': '', 'safi': '', '__delete_op': __derive_bgp_nbrs_delete_op}},
]


class Bgp_neighbors(ConfigBase):
    """
    The sonic_bgp_neighbors class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'bgp_neighbors',
    ]

    network_instance_path = '/data/openconfig-network-instance:network-instances/network-instance'
    protocol_bgp_path = 'protocols/protocol=BGP,bgp/bgp'
    neighbor_path = 'neighbors/neighbor'

    def __init__(self, module):
        super(Bgp_neighbors, self).__init__(module)

    def get_bgp_neighbors_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        bgp_facts = facts['ansible_network_resources'].get('bgp_neighbors')
        if not bgp_facts:
            bgp_facts = []
        return bgp_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        existing_bgp_facts = self.get_bgp_neighbors_facts()
        commands, requests = self.set_config(existing_bgp_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True

        existing_bgp_facts = sort_config(existing_bgp_facts, TEST_KEYS_sort_config)

        result['before'] = existing_bgp_facts
        old_config = existing_bgp_facts

        if self._module.check_mode:
            result.pop('after', None)
            old_config = self.pre_process_generated_config(commands, deepcopy(existing_bgp_facts))
            new_config = get_new_config(commands, old_config,
                                        TEST_KEYS_generate_config)
            new_config = self.post_process_generated_config(new_config)
            new_config = remove_empties_from_list(new_config)
            new_config = sort_config(new_config, TEST_KEYS_sort_config)
            result['after(generated)'] = new_config
        else:
            changed_bgp_facts = self.get_bgp_neighbors_facts()
            new_config = changed_bgp_facts
            new_config = sort_config(new_config, TEST_KEYS_sort_config)
            if result['changed']:
                result['after'] = new_config

        if self._module._diff:
            new_config = sort_config(new_config, TEST_KEYS_sort_config)
            result['diff'] = get_formatted_config_diff(old_config,
                                                       new_config,
                                                       self._module._verbosity)
        result['commands'] = commands
        return result

    def set_config(self, existing_bgp_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        convert_bgp_asn(want)
        normalize_neighbors_interface_name(want, self._module)
        have = existing_bgp_facts
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

        if state == 'replaced' or state == 'overridden':
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
        new_have = deepcopy(have)
        new_want = deepcopy(want)
        for cmd in new_want:
            neighbors = cmd.get('neighbors', [])
            peergroup = cmd.get('peer_group', [])
            # Set passive to false if not specified for a new neighbor/peer-group
            if neighbors:
                for nbr in neighbors:
                    if nbr.get('passive') is None:
                        nbr['passive'] = False
            if peergroup:
                for pg in peergroup:
                    if pg.get('passive') is None:
                        pg['passive'] = False
        new_want = remove_empties_from_list(new_want)
        want_skeleton = self._get_skeleton_keys(new_want)
        add_config, del_config = self._get_replaced_overridden_config(new_want, new_have, want_skeleton)
        if del_config:
            del_cmd, del_requests = self.get_delete_commands_requests_for_deleted(del_config, new_have)
            if del_requests:
                requests.extend(del_requests)
                commands.extend(update_states(del_cmd, "deleted"))
        if add_config:
            mod_requests = self.get_modify_bgp_requests(add_config, have, new_want)
            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(add_config, self._module.params['state']))
        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        requests = []
        commands = self.get_diff_bgp_nbr(want, have)
        validate_bgps(self._module, commands, have)
        for cmd in commands:
            neighbors = cmd.get('neighbors', [])
            peergroup = cmd.get('peer_group', [])
            match = next((item for item in have if (item['vrf_name'] == cmd['vrf_name'] and item['bgp_as'] == cmd['bgp_as'])), None)
            if match:
                match_neighbors = match.get('neighbors', [])
                match_peergroup = match.get('peer_group', [])
                if neighbors:
                    for nbr in neighbors:
                        match_nbr = next((item for item in match_neighbors if item['neighbor'] == nbr['neighbor']), None)
                        if nbr.get('passive') is None:
                            if not match_nbr:
                                nbr['passive'] = False
                if peergroup:
                    for pg in peergroup:
                        match_pg = next((item for item in match_peergroup if item['name'] == pg['name']), None)
                        if pg.get('passive') is None:
                            if not match_pg:
                                pg['passive'] = False
            else:
                # Set passive to false if not specified for a new neighbor/peer-group
                for nbr in neighbors:
                    if nbr.get('passive') is None:
                        nbr['passive'] = False
                for pg in peergroup:
                    if pg.get('passive') is None:
                        pg['passive'] = False
        requests = self.get_modify_bgp_requests(commands, have, want)
        if commands and len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """

        global is_delete_all
        is_delete_all = False

        if not want:
            new_have = have
            new_want = want
        else:
            new_have = deepcopy(have)
            new_want = deepcopy(want)
            for default_entry in DEFAULT_ENTRIES:
                remove_matching_defaults(new_have, default_entry)
                remove_matching_defaults(new_want, default_entry)
        commands, requests = self.get_delete_commands_requests_for_deleted(new_want, new_have)

        if commands and len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def get_diff_bgp_nbr(self, base_data, compare_data):
        """Special diff method is needed to handle the case of pwd and encrypted needing to be configured together for auth_pwd"""
        diff = get_diff(base_data, compare_data, TEST_KEYS)

        for cfg in diff:
            neighbors = cfg.get('neighbors')
            peer_group = cfg.get('peer_group')

            if neighbors:
                for nbr in neighbors:
                    auth_pwd = nbr.get('auth_pwd')
                    if auth_pwd:
                        match_nbr = self.find_nei(base_data, cfg['bgp_as'], cfg['vrf_name'], nbr)
                        if auth_pwd.get('pwd') and auth_pwd.get('encrypted') is None:
                            auth_pwd['encrypted'] = match_nbr['auth_pwd']['encrypted']
                        if auth_pwd.get('encrypted') and not auth_pwd.get('pwd'):
                            auth_pwd['pwd'] = match_nbr['auth_pwd']['pwd']

            if peer_group:
                for pg in peer_group:
                    auth_pwd = pg.get('auth_pwd')
                    if auth_pwd:
                        match_pg = self.find_pg(base_data, cfg['bgp_as'], cfg['vrf_name'], pg)
                        if auth_pwd.get('pwd') and auth_pwd.get('encrypted') is None:
                            auth_pwd['encrypted'] = match_pg['auth_pwd']['encrypted']
                        if auth_pwd.get('encrypted') and not auth_pwd.get('pwd'):
                            auth_pwd['pwd'] = match_pg['auth_pwd']['pwd']
        return diff

    def _get_replaced_overridden_config(self, want, have, want_skeleton):
        add_config, del_config = [], []

        diff1 = self.get_diff_bgp_nbr(want, have)
        for default_entry in DEFAULT_ENTRIES:
            remove_matching_defaults(have, default_entry)
            remove_matching_defaults(want, default_entry)
        want = remove_empties_from_list(want)
        have = remove_empties_from_list(have)
        diff2 = self.get_diff_bgp_nbr(have, want)
        state = self._module.params['state']

        add_config = diff1
        for cmd in diff2:
            del_cfg = {}
            vrf_name = cmd.get('vrf_name')
            bgp_as = cmd.get('bgp_as')
            match_neighbors = []
            match_peergroup = []
            if bgp_as in want_skeleton and vrf_name in want_skeleton[bgp_as]:
                match_neighbors = want_skeleton[bgp_as][vrf_name].get('neighbors', [])
                match_peergroup = want_skeleton[bgp_as][vrf_name].get('peer_group', [])

            neighbors = cmd.get('neighbors', [])
            for nbr in neighbors:
                neighbor_name = nbr.get('neighbor')
                match_nbr = True if neighbor_name in match_neighbors else False
                if match_nbr:
                    del_cfg.setdefault('neighbors', []).append(nbr)
                elif state == 'overridden':
                    del_cfg.setdefault('neighbors', []).append({'neighbor': neighbor_name})
            peergroup = cmd.get('peer_group', [])
            for pg in peergroup:
                name = pg.get('name')
                match_pg = True if name in match_peergroup else False
                if match_pg:
                    del_cfg.setdefault('peer_group', []).append(self._get_delete_pg_commands(pg, match_peergroup[name]))
                elif state == 'overridden':
                    del_cfg.setdefault('peer_group', []).append({'name': name})

            if del_cfg:
                del_cfg['bgp_as'] = bgp_as
                del_cfg['vrf_name'] = vrf_name
                del_config.append(del_cfg)
        return add_config, del_config

    def get_delete_commands_requests_for_deleted(self, want, have):
        commands, requests = [], []
        if not have:
            return commands, requests

        if not want:
            commands = remove_empties_from_list(have)
            requests = self.get_delete_all_bgp_neighbor_peergroup_requests(commands)
            return commands, requests

        for conf in want:
            vrf_name = conf.get('vrf_name')
            bgp_as = conf.get('bgp_as')
            cmd, requests_nbr_del, requests_pg_del = {}, [], []
            neighbors = conf.get('neighbors')
            peer_group = conf.get('peer_group')
            have_conf = next((cfg for cfg in have if vrf_name == cfg['vrf_name'] and bgp_as == cfg['bgp_as']), None)

            if have_conf:
                have_conf = remove_empties(have_conf)
                if have_conf.get('neighbors') and neighbors:
                    commands_del = []
                    commands_del, requests_nbr_del = self.get_delete_bgp_neighbor_commands_requests(vrf_name, neighbors, have_conf['neighbors'])
                    if commands_del and len(requests_nbr_del) > 0:
                        cmd['neighbors'] = commands_del

                if have_conf.get('peer_group') and peer_group:
                    commands_del = []
                    commands_del, requests_pg_del = self.get_delete_bgp_peergroup_commands_requests(vrf_name, peer_group, have_conf['peer_group'])
                    if commands_del and len(requests_pg_del) > 0:
                        cmd['peer_group'] = commands_del

                if cmd:
                    cmd['bgp_as'] = bgp_as
                    cmd['vrf_name'] = vrf_name
                    commands.append(cmd)
                    requests.extend(requests_nbr_del)
                    requests.extend(requests_pg_del)

        return commands, requests

    def build_bgp_peer_groups_payload(self, cmd, have, want, bgp_as, vrf_name):
        requests = []
        bgp_peer_group_list = []
        for peer_group in cmd:
            if peer_group:
                bgp_peer_group, peer_group_cfg = {}, {}
                tmp_bfd, tmp_auth, tmp_ebgp, tmp_capability = {}, {}, {}, {}
                tmp_transport, tmp_timers, tmp_remote = {}, {}, {}
                afi = []

                self.update_dict(peer_group, peer_group_cfg, 'name', 'peer-group-name')
                self.update_dict(peer_group, bgp_peer_group, 'name', 'peer-group-name')

                if peer_group.get('bfd') is not None:
                    self.update_dict(peer_group['bfd'], tmp_bfd, 'enabled', 'enabled')
                    self.update_dict(peer_group['bfd'], tmp_bfd, 'check_failure', 'check-control-plane-failure')
                    self.update_dict(peer_group['bfd'], tmp_bfd, 'profile', 'bfd-profile')

                if peer_group.get('auth_pwd') is not None:
                    self.update_dict(peer_group['auth_pwd'], tmp_auth, 'pwd', 'password')
                    self.update_dict(peer_group['auth_pwd'], tmp_auth, 'encrypted', 'encrypted')

                if peer_group.get('ebgp_multihop') is not None:
                    self.update_dict(peer_group['ebgp_multihop'], tmp_ebgp, 'enabled', 'enabled')
                    self.update_dict(peer_group['ebgp_multihop'], tmp_ebgp, 'multihop_ttl', 'multihop-ttl')

                if peer_group.get('timers') is not None:
                    self.update_dict(peer_group['timers'], tmp_timers, 'holdtime', 'hold-time')
                    self.update_dict(peer_group['timers'], tmp_timers, 'keepalive', 'keepalive-interval')
                    self.update_dict(peer_group['timers'], tmp_timers, 'connect_retry', 'connect-retry')

                if peer_group.get('capability') is not None:
                    self.update_dict(peer_group['capability'], tmp_capability, 'dynamic', 'capability-dynamic')
                    self.update_dict(peer_group['capability'], tmp_capability, 'extended_nexthop', 'capability-extended-nexthop')

                self.update_dict(peer_group, peer_group_cfg, 'pg_description', 'description')
                self.update_dict(peer_group, peer_group_cfg, 'disable_connected_check', 'disable-ebgp-connected-route-check')
                self.update_dict(peer_group, peer_group_cfg, 'dont_negotiate_capability', 'dont-negotiate-capability')
                self.update_dict(peer_group, peer_group_cfg, 'enforce_first_as', 'enforce-first-as')
                self.update_dict(peer_group, peer_group_cfg, 'enforce_multihop', 'enforce-multihop')
                self.update_dict(peer_group, peer_group_cfg, 'extended_link_bandwidth', 'extended-link-bandwidth')
                self.update_dict(peer_group, peer_group_cfg, 'override_capability', 'override-capability')
                self.update_dict(peer_group, peer_group_cfg, 'shutdown_msg', 'shutdown-message')
                self.update_dict(peer_group, peer_group_cfg, 'solo', 'solo-peer')
                self.update_dict(peer_group, peer_group_cfg, 'strict_capability_match', 'strict-capability-match')
                self.update_dict(peer_group, peer_group_cfg, 'ttl_security', 'ttl-security-hops')

                if peer_group.get('local_as') is not None:
                    self.update_dict(peer_group['local_as'], peer_group_cfg, 'as', 'local-as')
                    self.update_dict(peer_group['local_as'], peer_group_cfg, 'no_prepend', 'local-as-no-prepend')
                    self.update_dict(peer_group['local_as'], peer_group_cfg, 'replace_as', 'local-as-replace-as')

                self.update_dict(peer_group, tmp_transport, 'local_address', 'local-address')
                self.update_dict(peer_group, tmp_transport, 'passive', 'passive-mode')
                self.update_dict(peer_group, tmp_timers, 'advertisement_interval', 'minimum-advertisement-interval')

                if peer_group.get('remote_as') is not None:
                    have_nei = self.find_pg(have, bgp_as, vrf_name, peer_group)
                    if peer_group['remote_as'].get('peer_as') is not None:
                        if have_nei:
                            if have_nei.get("remote_as") is not None:
                                if have_nei["remote_as"].get("peer_type") is not None:
                                    del_nei = {'name': have_nei['name'], 'remote_as': have_nei['remote_as']}
                                    requests.extend(self.get_delete_specific_peergroup_param_requests(vrf_name, del_nei))
                        tmp_remote.update({'peer-as': peer_group['remote_as']['peer_as'].to_request_attr_fmt()})
                    if peer_group['remote_as'].get('peer_type') is not None:
                        if have_nei:
                            if have_nei.get("remote_as") is not None:
                                if have_nei["remote_as"].get("peer_as") is not None:
                                    del_nei = {'name': have_nei['name'], 'remote_as': have_nei['remote_as']}
                                    requests.extend(self.get_delete_specific_peergroup_param_requests(vrf_name, del_nei))
                        tmp_remote.update({'peer-type': peer_group['remote_as']['peer_type'].upper()})

                if peer_group.get('address_family') is not None:
                    if peer_group['address_family'].get('afis') is not None:
                        for each in peer_group['address_family'].get('afis', []):
                            samp, pfx_lmt_cfg, pfx_lst_cfg, ip_dict = {}, {}, {}, {}
                            afi_safi = each.get('afi', '').upper() + "_" + each.get('safi', '').upper()
                            afi_safi_name = 'openconfig-bgp-types:' + afi_safi
                            samp.update({'afi-safi-name': afi_safi_name, 'config': {'afi-safi-name': afi_safi_name}})
                            if each.get('prefix_limit'):
                                pfx_lmt_cfg = get_prefix_limit_payload(each['prefix_limit'])
                                if pfx_lmt_cfg and afi_safi == 'L2VPN_EVPN':
                                    self._module.fail_json('Prefix limit configuration not supported for l2vpn evpn')
                            if each.get('ip_afi'):
                                afi_safi_cfg = get_ip_afi_cfg_payload(each['ip_afi'])
                                if afi_safi_cfg:
                                    ip_dict.update({'config': afi_safi_cfg})
                            if pfx_lmt_cfg:
                                ip_dict.update({'prefix-limit': {'config': pfx_lmt_cfg}})
                            if ip_dict and afi_safi == 'IPV4_UNICAST':
                                samp.update({'ipv4-unicast': ip_dict})
                            if ip_dict and afi_safi == 'IPV6_UNICAST':
                                samp['ipv6-unicast'] = ip_dict
                            if each.get('activate') is not None:
                                samp['config'] = {'enabled': each['activate']}
                            if each.get('allowas_in'):
                                origin = each['allowas_in'].get('origin')
                                value = each['allowas_in'].get('value')

                                # Check for a conflict between input allowas_in 'origin' configuration and input allowas_in 'value' configuration.
                                want_pg_af = self.find_af(want, bgp_as, vrf_name, peer_group, each['afi'], each['safi'])
                                want_origin = want_pg_af['allowas_in'].get('origin')
                                want_value = want_pg_af['allowas_in'].get('value')
                                if want_origin is True and want_value is not None:
                                    self._module.fail_json(msg="No allowas_in 'value' can be configured when setting allowas_in 'origin' to 'true'.")

                                # Remove any existing configuration that conflicts with the input 'allowas_in' configuration before applying
                                # the new requested 'allowas_in' configuration.
                                have_pg_af = self.find_af(have, bgp_as, vrf_name, peer_group, each['afi'], each['safi'])

                                if origin is not None:
                                    if have_pg_af is not None:
                                        if origin is True and have_pg_af.get('allowas_in') is not None and have_pg_af['allowas_in'].get('value') is not None:
                                            del_nei = {
                                                'name': peer_group['name'],
                                                'address_family': {
                                                    'afis': [{
                                                        'afi': each['afi'],
                                                        'safi': each['safi'],
                                                        'allowas_in': {'value': have_pg_af['allowas_in']['value']}
                                                    }]
                                                }
                                            }
                                            requests.extend(self.get_delete_specific_peergroup_param_requests(vrf_name, del_nei))
                                    samp.update({'allow-own-as': {'config': {'origin': origin, "enabled": bool("true")}}})

                                if value is not None:
                                    if have_pg_af is not None:
                                        if have_pg_af.get('allowas_in') is not None and have_pg_af['allowas_in'].get('origin') is True:
                                            del_nei = {
                                                'name': peer_group['name'],
                                                'address_family': {
                                                    'afis': [{
                                                        'afi': each['afi'],
                                                        'safi': each['safi'],
                                                        'allowas_in': {'origin': have_pg_af['allowas_in']['origin']}
                                                    }]
                                                }
                                            }
                                            requests.extend(self.get_delete_specific_peergroup_param_requests(vrf_name, del_nei))
                                    if samp.get('allow-own-as'):
                                        samp['allow-own-as']['config'].update({'as-count': value})
                                    else:
                                        samp.update({'allow-own-as': {'config': {'as-count': value, "enabled": bool("true")}}})
                            if each.get('prefix_list_in'):
                                pfx_lst_cfg['import-policy'] = each['prefix_list_in']
                            if each.get('prefix_list_out'):
                                pfx_lst_cfg['export-policy'] = each['prefix_list_out']
                            if pfx_lst_cfg:
                                samp['prefix-list'] = {'config': pfx_lst_cfg}
                            if samp:
                                afi.append(samp)

                self.update_dict(tmp_timers, bgp_peer_group, '', '', {'timers': {'config': tmp_timers}})
                self.update_dict(tmp_bfd, bgp_peer_group, '', '', {'enable-bfd': {'config': tmp_bfd}})
                self.update_dict(tmp_auth, bgp_peer_group, '', '', {'auth-password': {'config': tmp_auth}})
                self.update_dict(tmp_ebgp, bgp_peer_group, '', '', {'ebgp-multihop': {'config': tmp_ebgp}})
                self.update_dict(tmp_capability, peer_group_cfg, '', '', tmp_capability)
                self.update_dict(tmp_transport, bgp_peer_group, '', '', {'transport': {'config': tmp_transport}})
                self.update_dict(tmp_remote, peer_group_cfg, '', '', tmp_remote)
                self.update_dict(peer_group_cfg, bgp_peer_group, '', '', {'config': peer_group_cfg})
                if afi and len(afi) > 0:
                    bgp_peer_group['afi-safis'] = {'afi-safi': afi}
                if bgp_peer_group:
                    bgp_peer_group_list.append(bgp_peer_group)
        payload = {'openconfig-network-instance:peer-groups': {'peer-group': bgp_peer_group_list}}
        return payload, requests

    def build_bgp_neighbors_payload(self, cmd, have, bgp_as, vrf_name):
        bgp_neighbor_list = []
        requests = []
        for neighbor in cmd:
            if neighbor:
                bgp_neighbor, neighbor_cfg = {}, {}
                tmp_bfd, tmp_auth, tmp_ebgp, tmp_capability = {}, {}, {}, {}
                tmp_transport, tmp_timers, tmp_remote = {}, {}, {}

                self.update_dict(neighbor, bgp_neighbor, 'neighbor', 'neighbor-address')
                self.update_dict(neighbor, neighbor_cfg, 'neighbor', 'neighbor-address')

                if neighbor.get('bfd') is not None:
                    self.update_dict(neighbor['bfd'], tmp_bfd, 'enabled', 'enabled')
                    self.update_dict(neighbor['bfd'], tmp_bfd, 'check_failure', 'check-control-plane-failure')
                    self.update_dict(neighbor['bfd'], tmp_bfd, 'profile', 'bfd-profile')

                if neighbor.get('auth_pwd') is not None:
                    self.update_dict(neighbor['auth_pwd'], tmp_auth, 'pwd', 'password')
                    self.update_dict(neighbor['auth_pwd'], tmp_auth, 'encrypted', 'encrypted')

                if neighbor.get('ebgp_multihop') is not None:
                    self.update_dict(neighbor['ebgp_multihop'], tmp_ebgp, 'enabled', 'enabled')
                    self.update_dict(neighbor['ebgp_multihop'], tmp_ebgp, 'multihop_ttl', 'multihop-ttl')

                if neighbor.get('timers') is not None:
                    self.update_dict(neighbor['timers'], tmp_timers, 'holdtime', 'hold-time')
                    self.update_dict(neighbor['timers'], tmp_timers, 'keepalive', 'keepalive-interval')
                    self.update_dict(neighbor['timers'], tmp_timers, 'connect_retry', 'connect-retry')

                if neighbor.get('capability') is not None:
                    self.update_dict(neighbor['capability'], tmp_capability, 'dynamic', 'capability-dynamic')
                    self.update_dict(neighbor['capability'], tmp_capability, 'extended_nexthop', 'capability-extended-nexthop')

                self.update_dict(neighbor, neighbor_cfg, 'peer_group', 'peer-group')
                self.update_dict(neighbor, neighbor_cfg, 'nbr_description', 'description')
                self.update_dict(neighbor, neighbor_cfg, 'disable_connected_check', 'disable-ebgp-connected-route-check')
                self.update_dict(neighbor, neighbor_cfg, 'dont_negotiate_capability', 'dont-negotiate-capability')
                self.update_dict(neighbor, neighbor_cfg, 'enforce_first_as', 'enforce-first-as')
                self.update_dict(neighbor, neighbor_cfg, 'enforce_multihop', 'enforce-multihop')
                self.update_dict(neighbor, neighbor_cfg, 'extended_link_bandwidth', 'extended-link-bandwidth')
                self.update_dict(neighbor, neighbor_cfg, 'override_capability', 'override-capability')
                self.update_dict(neighbor, neighbor_cfg, 'shutdown_msg', 'shutdown-message')
                self.update_dict(neighbor, neighbor_cfg, 'solo', 'solo-peer')
                self.update_dict(neighbor, neighbor_cfg, 'port', 'peer-port')
                self.update_dict(neighbor, neighbor_cfg, 'v6only', 'openconfig-bgp-ext:v6only')
                self.update_dict(neighbor, neighbor_cfg, 'strict_capability_match', 'strict-capability-match')
                self.update_dict(neighbor, neighbor_cfg, 'ttl_security', 'ttl-security-hops')

                if neighbor.get('local_as') is not None:
                    self.update_dict(neighbor['local_as'], neighbor_cfg, 'as', 'local-as')
                    self.update_dict(neighbor['local_as'], neighbor_cfg, 'no_prepend', 'local-as-no-prepend')
                    self.update_dict(neighbor['local_as'], neighbor_cfg, 'replace_as', 'local-as-replace-as')

                self.update_dict(neighbor, tmp_transport, 'local_address', 'local-address')
                self.update_dict(neighbor, tmp_transport, 'passive', 'passive-mode')
                self.update_dict(neighbor, tmp_timers, 'advertisement_interval', 'minimum-advertisement-interval')

                if neighbor.get('remote_as', None) is not None:
                    have_nei = self.find_nei(have, bgp_as, vrf_name, neighbor)
                    if neighbor['remote_as'].get('peer_as', None) is not None:
                        if have_nei:
                            if have_nei.get("remote_as", None) is not None:
                                if have_nei["remote_as"].get("peer_type", None) is not None:
                                    del_nei = {
                                        'neighbor': have_nei['neighbor'],
                                        'remote_as': have_nei['remote_as']
                                    }
                                    requests.extend(self.get_delete_specific_neighbor_param_requests(vrf_name, del_nei))
                        tmp_remote['peer-as'] = neighbor['remote_as']['peer_as'].to_request_attr_fmt()
                    if neighbor['remote_as'].get('peer_type', None) is not None:
                        if have_nei:
                            if have_nei.get("remote_as", None) is not None:
                                if have_nei["remote_as"].get("peer_as", None) is not None:
                                    del_nei = {
                                        'neighbor': have_nei['neighbor'],
                                        'remote_as': have_nei['remote_as']
                                    }
                                    requests.extend(self.get_delete_specific_neighbor_param_requests(vrf_name, del_nei))
                        tmp_remote['peer-type'] = neighbor['remote_as']['peer_type'].upper()

                self.update_dict(tmp_timers, bgp_neighbor, '', '', {'timers': {'config': tmp_timers}})
                self.update_dict(tmp_bfd, bgp_neighbor, '', '', {'enable-bfd': {'config': tmp_bfd}})
                self.update_dict(tmp_auth, bgp_neighbor, '', '', {'auth-password': {'config': tmp_auth}})
                self.update_dict(tmp_ebgp, bgp_neighbor, '', '', {'ebgp-multihop': {'config': tmp_ebgp}})
                self.update_dict(tmp_capability, neighbor_cfg, '', '', tmp_capability)
                self.update_dict(tmp_transport, bgp_neighbor, '', '', {'transport': {'config': tmp_transport}})
                self.update_dict(tmp_remote, neighbor_cfg, '', '', tmp_remote)
                self.update_dict(neighbor_cfg, bgp_neighbor, '', '', {'config': neighbor_cfg})

                if bgp_neighbor:
                    bgp_neighbor_list.append(bgp_neighbor)
        payload = {'openconfig-network-instance:neighbors': {'neighbor': bgp_neighbor_list}}
        return payload, requests

    def get_modify_bgp_requests(self, commands, have, want):
        requests = []
        if not commands:
            return requests

        for cmd in commands:
            edit_path = '{0}={1}/{2}'.format(self.network_instance_path, cmd['vrf_name'], self.protocol_bgp_path)
            if 'peer_group' in cmd and cmd['peer_group']:
                edit_peer_groups_payload, edit_requests = self.build_bgp_peer_groups_payload(cmd['peer_group'], have, want, cmd['bgp_as'], cmd['vrf_name'])
                edit_peer_groups_path = edit_path + '/peer-groups'
                requests.extend(edit_requests)
                requests.append({'path': edit_peer_groups_path, 'method': PATCH, 'data': edit_peer_groups_payload})
            if 'neighbors' in cmd and cmd['neighbors']:
                edit_neighbors_payload, edit_requests = self.build_bgp_neighbors_payload(cmd['neighbors'], have, cmd['bgp_as'], cmd['vrf_name'])
                edit_neighbors_path = edit_path + '/neighbors'
                requests.extend(edit_requests)
                requests.append({'path': edit_neighbors_path, 'method': PATCH, 'data': edit_neighbors_payload})
        return requests

    def get_delete_bgp_peergroup_commands_requests(self, vrf_name, want_peergroup, have_peergroup):
        commands, requests = [], []
        for pg in want_peergroup:
            have_pg = next((cfg for cfg in have_peergroup if cfg['name'] == pg['name']), None)
            if have_pg:
                pg = remove_empties(pg)
                if len(pg) == 1 and pg.get('name'):
                    commands.append({'name': pg['name']})
                    requests.append(self.delete_peergroup_whole_request(vrf_name, pg['name']))
                else:
                    cmd = {}
                    for attr in pg:
                        if attr != 'name':
                            return_object = self._get_common_in_dict(pg[attr], have_pg.get(attr))
                            if return_object is not None:
                                cmd[attr] = return_object
                    if cmd:
                        cmd['name'] = pg['name']
                        commands.append(cmd)
                        requests.extend(self.get_delete_specific_peergroup_param_requests(vrf_name, cmd))
        return commands, requests

    def get_delete_bgp_neighbor_commands_requests(self, vrf_name, want_neighbors, have_neighbors):
        commands, requests = [], []
        for nbr in want_neighbors:
            have_nbr = next((cfg for cfg in have_neighbors if cfg['neighbor'] == nbr['neighbor']), None)
            if have_nbr:
                nbr = remove_empties(nbr)
                if len(nbr) == 1 and nbr.get('neighbor'):
                    commands.append({'neighbor': nbr['neighbor']})
                    requests.append(self.delete_neighbor_whole_request(vrf_name, nbr['neighbor']))
                else:
                    cmd = {}
                    for attr in nbr:
                        if attr != 'neighbor':
                            return_object = self._get_common_in_dict(nbr[attr], have_nbr.get(attr))
                            if return_object is not None:
                                cmd[attr] = return_object
                    if cmd:
                        cmd['neighbor'] = nbr['neighbor']
                        commands.append(cmd)
                        requests.extend(self.get_delete_specific_neighbor_param_requests(vrf_name, cmd))
        return commands, requests

    def get_delete_specific_peergroup_param_requests(self, vrf_name, cmd):
        requests = []
        delete_static_path = '{0}={1}/{2}/peer-groups/peer-group={3}'.format(self.network_instance_path, vrf_name, self.protocol_bgp_path, cmd['name'])
        peergroup_request_path = {
            'remote_as': {
                'peer_as': '/config/peer-as',
                'peer_type': '/config/peer-type'
            },
            'advertisement_interval': '/timers/config/minimum-advertisement-interval',
            'timers': {
                'holdtime': '/timers/config/hold-time',
                'keepalive': '/timers/config/keepalive-interval',
                'connect_retry': '/timers/config/connect-retry'
            },
            'capability': {
                'dynamic': '/config/capability-dynamic',
                'extended_nexthop': '/config/capability-extended-nexthop'
            },
            'pg_description': '/config/description',
            'disable_connected_check': '/config/disable-ebgp-connected-route-check',
            'dont_negotiate_capability': '/config/dont-negotiate-capability',
            'enforce_first_as': '/config/enforce-first-as',
            'enforce_multihop': '/config/enforce-multihop',
            'extended_link_bandwidth': '/config/extended-link-bandwidth',
            'override_capability': '/config/override-capability',
            'shutdown_msg': '/config/shutdown-message',
            'solo': '/config/solo-peer',
            'strict_capability_match': '/config/strict-capability-match',
            'ttl_security': '/config/ttl-security-hops',
            'local_as': {
                'as': '/config/local-as',
                'no_prepend': '/config/local-as-no-prepend',
                'replace_as': '/config/local-as-replace-as'
            },
            'local_address': '/transport/config/local-address',
            'passive': '/transport/config/passive-mode',
            'bfd': {
                'enabled': '/enable-bfd/config/enabled',
                'check_failure': '/enable-bfd/config/check-control-plane-failure',
                'profile': '/enable-bfd/config/bfd-profile'
            },
            'auth_pwd': {
                'pwd': '/auth-password/config/password',
                'encrypted': '/auth-password/config/encrypted'
            },
            'ebgp_multihop': {
                'enabled': '/ebgp-multihop/config/enabled',
                'multihop_ttl': '/ebgp-multihop/config/multihop-ttl'
            }
        }

        for attr, value in peergroup_request_path.items():
            if cmd.get(attr) is not None:
                if attr == 'local_as':
                    for local_as_attr in value:
                        delete_path = delete_static_path + value[local_as_attr]
                        requests.append({'path': delete_path, 'method': DELETE})
                elif isinstance(value, dict):
                    for dict_attr in value:
                        if cmd[attr].get(dict_attr) is not None:
                            delete_path = delete_static_path + value[dict_attr]
                            requests.append({'path': delete_path, 'method': DELETE})
                else:
                    delete_path = delete_static_path + value
                    requests.append({'path': delete_path, 'method': DELETE})

        if cmd.get('address_family') is not None:
            if cmd['address_family'].get('afis') is None:
                delete_path = delete_static_path + '/afi-safis/afi-safi'
                requests.append({'path': delete_path, 'method': DELETE})
            else:
                for each in cmd['address_family']['afis']:
                    afi = each.get('afi')
                    safi = each.get('safi')
                    activate = each.get('activate')
                    allowas_in = each.get('allowas_in')
                    ip_afi = each.get('ip_afi')
                    prefix_limit = each.get('prefix_limit')
                    prefix_list_in = each.get('prefix_list_in')
                    prefix_list_out = each.get('prefix_list_out')
                    afi_safi = afi.upper() + '_' + safi.upper()
                    afi_safi_name = 'openconfig-bgp-types:' + afi_safi
                    if afi and safi and not any([activate, allowas_in, ip_afi, prefix_limit, prefix_list_in, prefix_list_out]):
                        delete_path = delete_static_path + '/afi-safis/afi-safi=%s' % (afi_safi_name)
                        requests.append({'path': delete_path, 'method': DELETE})
                    else:
                        if activate:
                            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/config/enabled' % (afi_safi_name)
                            requests.append({'path': delete_path, 'method': DELETE})
                        if allowas_in:
                            if allowas_in.get('origin') is not None:
                                delete_path = delete_static_path + '/afi-safis/afi-safi=%s/allow-own-as/config/origin' % (afi_safi_name)
                                requests.append({'path': delete_path, 'method': DELETE})
                            if allowas_in.get('value'):
                                delete_path = delete_static_path + '/afi-safis/afi-safi=%s/allow-own-as/config/as-count' % (afi_safi_name)
                                requests.append({'path': delete_path, 'method': DELETE})
                        if prefix_list_in:
                            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/prefix-list/config/import-policy' % (afi_safi_name)
                            requests.append({'path': delete_path, 'method': DELETE})
                        if prefix_list_out:
                            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/prefix-list/config/export-policy' % (afi_safi_name)
                            requests.append({'path': delete_path, 'method': DELETE})
                        if afi_safi == 'IPV4_UNICAST':
                            if ip_afi:
                                requests.extend(self.delete_ip_afi_requests(ip_afi, afi_safi_name, 'ipv4-unicast', delete_static_path))
                            if prefix_limit:
                                requests.extend(self.delete_prefix_limit_requests(prefix_limit, afi_safi_name, 'ipv4-unicast', delete_static_path))
                        elif afi_safi == 'IPV6_UNICAST':
                            if ip_afi:
                                requests.extend(self.delete_ip_afi_requests(ip_afi, afi_safi_name, 'ipv6-unicast', delete_static_path))
                            if prefix_limit:
                                requests.extend(self.delete_prefix_limit_requests(prefix_limit, afi_safi_name, 'ipv6-unicast', delete_static_path))

        return requests

    def get_delete_specific_neighbor_param_requests(self, vrf_name, cmd):
        requests = []
        neighbor = cmd['neighbor'].replace('/', '%2f')
        delete_static_path = '{0}={1}/{2}/neighbors/neighbor={3}'.format(self.network_instance_path, vrf_name, self.protocol_bgp_path, neighbor)
        nbr_request_path = {
            'remote_as': {
                'peer_as': '/config/peer-as',
                'peer_type': '/config/peer-type'
            },
            'peer_group': '/config/peer-group',
            'advertisement_interval': '/timers/config/minimum-advertisement-interval',
            'timers': {
                'holdtime': '/timers/config/hold-time',
                'keepalive': '/timers/config/keepalive-interval',
                'connect_retry': '/timers/config/connect-retry'
            },
            'capability': {
                'dynamic': '/config/capability-dynamic',
                'extended_nexthop': '/config/capability-extended-nexthop'
            },
            'nbr_description': '/config/description',
            'disable_connected_check': '/config/disable-ebgp-connected-route-check',
            'dont_negotiate_capability': '/config/dont-negotiate-capability',
            'enforce_first_as': '/config/enforce-first-as',
            'enforce_multihop': '/config/enforce-multihop',
            'extended_link_bandwidth': '/config/extended-link-bandwidth',
            'override_capability': '/config/override-capability',
            'shutdown_msg': '/config/shutdown-message',
            'solo': '/config/solo-peer',
            'port': '/config/peer-port',
            'strict_capability_match': '/config/strict-capability-match',
            'ttl_security': '/config/ttl-security-hops',
            'v6only': '/config/openconfig-bgp-ext:v6only',
            'local_as': {
                'as': '/config/local-as',
                'no_prepend': '/config/local-as-no-prepend',
                'replace_as': '/config/local-as-replace-as'
            },
            'local_address': '/transport/config/local-address',
            'passive': '/transport/config/passive-mode',
            'bfd': {
                'enabled': '/enable-bfd/config/enabled',
                'check_failure': '/enable-bfd/config/check-control-plane-failure',
                'profile': '/enable-bfd/config/bfd-profile'
            },
            'auth_pwd': {
                'pwd': '/auth-password/config/password',
                'encrypted': '/auth-password/config/encrypted'
            },
            'ebgp_multihop': {
                'enabled': '/ebgp-multihop/config/enabled',
                'multihop_ttl': '/ebgp-multihop/config/multihop-ttl'
            }
        }

        for attr, value in nbr_request_path.items():
            if cmd.get(attr) is not None:
                if attr == 'local_as':
                    for local_as_attr in value:
                        delete_path = delete_static_path + value[local_as_attr]
                        requests.append({'path': delete_path, 'method': DELETE})
                elif isinstance(value, dict):
                    for dict_attr in value:
                        if cmd[attr].get(dict_attr) is not None:
                            delete_path = delete_static_path + value[dict_attr]
                            requests.append({'path': delete_path, 'method': DELETE})
                else:
                    delete_path = delete_static_path + value
                    requests.append({'path': delete_path, 'method': DELETE})

        return requests

    def delete_ip_afi_requests(self, ip_afi, afi_safi_name, afi_safi, delete_static_path):
        requests = []
        default_policy_name = ip_afi.get('default_policy_name')
        send_default_route = ip_afi.get('send_default_route')
        if default_policy_name:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/config/default-policy-name' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if send_default_route:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/config/send-default-route' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})

        return requests

    def delete_prefix_limit_requests(self, prefix_limit, afi_safi_name, afi_safi, delete_static_path):
        requests = []
        max_prefixes = prefix_limit.get('max_prefixes')
        prevent_teardown = prefix_limit.get('prevent_teardown')
        warning_threshold = prefix_limit.get('warning_threshold')
        restart_timer = prefix_limit.get('restart_timer')
        discard_extra = prefix_limit.get('discard_extra')
        if max_prefixes:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/max-prefixes' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if prevent_teardown:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/prevent-teardown' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if warning_threshold:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/warning-threshold-pct' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if restart_timer:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/restart-timer' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})
        if discard_extra:
            delete_path = delete_static_path + '/afi-safis/afi-safi=%s/%s/prefix-limit/config/openconfig-bgp-ext:discard-extra' % (afi_safi_name, afi_safi)
            requests.append({'path': delete_path, 'method': DELETE})

        return requests

    def delete_neighbor_whole_request(self, vrf_name, neighbor):
        url = '{0}={1}/{2}/{3}={4}/'.format(self.network_instance_path, vrf_name, self.protocol_bgp_path, self.neighbor_path, neighbor.replace('/', '%2f'))
        return ({'path': url, 'method': DELETE})

    def get_delete_vrf_specific_neighbor_request(self, vrf_name, neighbors):
        requests = []
        for each in neighbors:
            if each.get('neighbor'):
                requests.append(self.delete_neighbor_whole_request(vrf_name, each['neighbor']))
        return requests

    def delete_peergroup_whole_request(self, vrf_name, peergroup_name):
        delete_neighbor_path = '{0}={1}/{2}/peer-groups/peer-group={3}'.format(self.network_instance_path, vrf_name, self.protocol_bgp_path, peergroup_name)
        return ({'path': delete_neighbor_path, 'method': DELETE})

    def get_delete_all_bgp_neighbor_peergroup_requests(self, commands):
        requests = []
        for cmd in commands:
            if cmd.get('neighbors'):
                requests.extend(self.get_delete_vrf_specific_neighbor_request(cmd['vrf_name'], cmd['neighbors']))
            if 'peer_group' in cmd and cmd['peer_group']:
                for each in cmd['peer_group']:
                    requests.append(self.delete_peergroup_whole_request(cmd['vrf_name'], each['name']))
        return requests

    def find_pg(self, have, bgp_as, vrf_name, peergroup):
        mat_dict = next((m_peer for m_peer in have if m_peer['bgp_as'] == bgp_as and m_peer['vrf_name'] == vrf_name), None)
        if mat_dict and mat_dict.get("peer_group", None) is not None:
            mat_pg = next((m for m in mat_dict['peer_group'] if m["name"] == peergroup['name']), None)
            return mat_pg

    def find_af(self, have, bgp_as, vrf_name, peergroup, afi, safi):
        mat_pg = self.find_pg(have, bgp_as, vrf_name, peergroup)
        if mat_pg and mat_pg['address_family'].get('afis', None) is not None and mat_pg['address_family'].get('afis', None) is not None:
            mat_af = next((af for af in mat_pg['address_family']['afis'] if af['afi'] == afi and af['safi'] == safi), None)
            return mat_af

    def find_nei(self, have, bgp_as, vrf_name, neighbor):
        mat_dict = next((m_neighbor for m_neighbor in have if m_neighbor['bgp_as'] == bgp_as and m_neighbor['vrf_name'] == vrf_name), None)
        if mat_dict and mat_dict.get("neighbors", None) is not None:
            mat_neighbor = next((m for m in mat_dict['neighbors'] if m["neighbor"] == neighbor['neighbor']), None)
            return mat_neighbor

    def _get_common_in_dict(self, obj, have_obj):
        if have_obj is not None:
            if not isinstance(obj, dict) and not isinstance(obj, list):
                if have_obj == obj:
                    return obj
            elif isinstance(obj, list):
                traverse_list = []
                for item in obj:
                    afi = item.get('afi')
                    safi = item.get('safi')
                    if afi and safi:
                        have_item = next((cfg for cfg in have_obj if cfg['afi'] == afi and cfg['safi'] == safi), None)
                        if have_item is not None:
                            if self._has_more_than_afi(have_item):
                                return_object = self._get_common_in_dict(item, have_item)
                                if return_object is not None:
                                    traverse_list.append(return_object)
                            elif not self._has_more_than_afi(item):
                                return_object = self._get_common_in_dict(have_item, item)
                                if return_object is not None:
                                    traverse_list.append(return_object)
                return (traverse_list or None)
            else:
                traverse_dict = {}
                for key in obj:
                    return_object = self._get_common_in_dict(obj[key], have_obj.get(key))
                    if return_object is not None:
                        traverse_dict[key] = return_object
                return (traverse_dict or None)
        return None

    def pre_process_generated_config(self, commands, have):
        for conf in commands:
            bgp_as = conf.get('bgp_as')
            vrf_name = conf.get('vrf_name')
            match = next((m for m in have if m['bgp_as'] == bgp_as and m['vrf_name'] == vrf_name), None)
            if match:
                for attr in ('neighbors', 'peer_group'):
                    conf_attr = conf.get(attr, [])
                    match_attr = match.get(attr, [])
                    if conf_attr and match_attr:
                        for item in conf_attr:
                            key = 'neighbor' if attr == 'neighbors' else 'name'
                            match_item = next((nei for nei in match_attr if nei[key] == item[key]), None)
                            if match_item:
                                if 'remote_as' in item and 'remote_as' in match_item:
                                    if 'peer_type' in item.get('remote_as', {}) and 'peer_as' in match_item.get('remote_as', {}):
                                        match_item['remote_as'].pop('peer_as', None)
                                    if 'peer_as' in item.get('remote_as', {}) and 'peer_type' in match_item.get('remote_as', {}):
                                        match_item['remote_as'].pop('peer_type', None)
        return have

    def post_process_generated_config(self, configs):
        TEST_KEYS_remove_void_config = [
            {'neighbors': {'__test_keys': ('neighbor',)}},
            {'peer_group': {'__test_keys': ('name',)}},
            {'afis': {'__test_keys': ('afi', 'safi')}},
        ]
        confs = remove_void_config(configs, TEST_KEYS_remove_void_config)
        # Add default entries
        for conf in confs:
            for peer_group in conf.get('peer_group', []):
                peer_group.setdefault('ebgp_multihop', {'enabled': False})
                if 'multihop_ttl' in peer_group['ebgp_multihop'] and 'enabled' not in peer_group['ebgp_multihop']:
                    peer_group['ebgp_multihop']['enabled'] = True

                peer_group.setdefault('timers', {'connect_retry': 30})
                peer_group['timers'].setdefault('connect_retry', 30)
                peer_group.setdefault('passive', False)
                peer_group.setdefault('advertisement_interval', 0)
                if 'local_as' in peer_group:
                    if 'as' in peer_group['local_as'] and peer_group['local_as']['as']:
                        peer_group['local_as'].setdefault('no_prepend', False)
                        peer_group['local_as'].setdefault('replace_as', False)
                    elif 'no_prepend' in peer_group['local_as'] or 'replace_as' in peer_group['local_as']:
                        peer_group.pop('local_as', None)
                if 'address_family' in peer_group:
                    address_family = peer_group.get('address_family', {})
                    if address_family:
                        for afis in address_family.get('afis', []):
                            afis.setdefault('activate', False)
                            if len(afis.get('ip_afi', {})) > 1:
                                afis['ip_afi'].setdefault('send_default_route', False)
                            elif 'send_default_route' in afis.get('ip_afi', {}):
                                afis.pop('ip_afi', None)
                            if len(afis.get('prefix_limit', {})) > 1:
                                afis['prefix_limit'].setdefault('prevent_teardown', False)
                                afis['prefix_limit'].setdefault('discard_extra', False)
                            elif 'prevent_teardown' in afis.get('prefix_limit', {}):
                                afis.pop('prefix_limit', None)
                            elif 'discard_extra' in afis.get('prefix_limit', {}):
                                afis.pop('prefix_limit', None)
            for neighbor in conf.get('neighbors', []):
                neighbor.setdefault('passive', False)
                if 'ebgp_multihop' in neighbor and 'multihop_ttl' in neighbor['ebgp_multihop'] and 'enabled' not in neighbor['ebgp_multihop']:
                    neighbor['ebgp_multihop']['enabled'] = True
                if 'local_as' in neighbor:
                    if 'as' in neighbor['local_as'] and neighbor['local_as']['as']:
                        neighbor['local_as'].setdefault('no_prepend', False)
                        neighbor['local_as'].setdefault('replace_as', False)
                    elif 'no_prepend' in neighbor['local_as'] or 'replace_as' in neighbor['local_as']:
                        neighbor.pop('local_as', None)
                if 'passive' in neighbor and 'neighbor' in neighbor and len(neighbor) > 2:
                    if 'peer_group' in neighbor or 'remote_as' in neighbor:
                        if 'advertisement_interval' not in neighbor and 'timers' not in neighbor:
                            neighbor['advertisement_interval'] = 0
                            neighbor['timers'] = {'connect_retry': 30, 'keepalive': 60}
        return confs

    def _get_skeleton_keys(self, want):
        skeleton = {}
        for cmd in want:
            bgp_as = cmd['bgp_as'].__str__() if cmd.get('bgp_as') else None
            vrf_name = cmd.get('vrf_name')
            neighbors = []
            peer_group = {}
            for neighbor in cmd.get('neighbors', []):
                neighbors.append(neighbor.get('neighbor'))
            for pg in cmd.get('peer_group', []):
                afi = []
                if 'address_family' in pg and pg.get('address_family'):
                    if 'afis' in pg['address_family'] and pg['address_family'].get('afis'):
                        for afi_conf in pg['address_family']['afis']:
                            afi.append(afi_conf.get('afi'))
                peer_group[pg.get('name')] = afi
            if neighbors or peer_group:
                skeleton.setdefault(bgp_as, {})
                skeleton[bgp_as][vrf_name] = {
                    'neighbors': neighbors,
                    'peer_group': peer_group
                }
        return skeleton

    def _get_delete_pg_commands(self, have, want_skeleton):
        cmd = {}
        for attr in have:
            if attr == 'address_family' and have.get(attr):
                if 'afis' in have.get(attr):
                    af_cmd = []
                    for af in have[attr].get('afis', []):
                        if af.get('afi') in want_skeleton:
                            af_cmd.append(af)
                        else:
                            af_cmd.append({'afi': af.get('afi'), 'safi': af.get('safi')})
                    if af_cmd:
                        cmd[attr] = {'afis': af_cmd}
            else:
                cmd[attr] = have[attr]
        return cmd

    def update_dict(self, src, dest, src_key, dest_key, value=False):
        if not value:
            if src.get(src_key) is not None:
                if src_key == 'as':
                    dest[dest_key] = src[src_key].to_request_attr_fmt()
                else:
                    dest[dest_key] = src[src_key]
        elif src:
            dest.update(value)

    def _has_more_than_afi(self, obj):
        return len(obj) > 2
