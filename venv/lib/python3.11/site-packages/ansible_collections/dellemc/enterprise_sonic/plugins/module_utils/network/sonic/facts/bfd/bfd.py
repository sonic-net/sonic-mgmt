#
# -*- coding: utf-8 -*-
# Copyright 2024444 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic bfd fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bfd.bfd import BfdArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


class BfdFacts(object):
    """ The sonic bfd fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = BfdArgs.argument_spec
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
        """ Populate the facts for bfd
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            bfd_cfg = self.get_bfd_config(self._module)
            data = self.update_bfd(bfd_cfg)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['bfd'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def update_bfd(self, data):
        bfd_dict = {}
        if data:
            bfd_dict['profiles'] = self.update_profiles(data)
            bfd_dict['single_hops'] = self.update_single_hops(data)
            bfd_dict['multi_hops'] = self.update_multi_hops(data)

        return bfd_dict

    def update_profiles(self, data):
        all_profiles = []
        bfd_profile = data.get('openconfig-bfd-ext:bfd-profile', None)
        if bfd_profile:
            profile_list = bfd_profile.get('profile', None)
            if profile_list:
                for profile in profile_list:
                    profile_dict = {}
                    profile_name = profile['profile-name']
                    config = profile['config']
                    enabled = config.get('enabled', None)
                    transmit_interval = config.get('desired-minimum-tx-interval', None)
                    receive_interval = config.get('required-minimum-receive', None)
                    detect_multiplier = config.get('detection-multiplier', None)
                    passive_mode = config.get('passive-mode', None)
                    min_ttl = config.get('minimum-ttl', None)
                    echo_interval = config.get('desired-minimum-echo-receive', None)
                    echo_mode = config.get('echo-active', None)

                    if profile_name:
                        profile_dict['profile_name'] = profile_name
                    if enabled is not None:
                        profile_dict['enabled'] = enabled
                    if transmit_interval:
                        profile_dict['transmit_interval'] = transmit_interval
                    if receive_interval:
                        profile_dict['receive_interval'] = receive_interval
                    if detect_multiplier:
                        profile_dict['detect_multiplier'] = detect_multiplier
                    if passive_mode is not None:
                        profile_dict['passive_mode'] = passive_mode
                    if min_ttl:
                        profile_dict['min_ttl'] = min_ttl
                    if echo_interval:
                        profile_dict['echo_interval'] = echo_interval
                    if echo_mode is not None:
                        profile_dict['echo_mode'] = echo_mode
                    if profile_dict:
                        all_profiles.append(profile_dict)

        return all_profiles

    def update_single_hops(self, data):
        all_single_hops = []
        bfd_single_hop = data.get('openconfig-bfd-ext:bfd-shop-sessions', None)
        if bfd_single_hop:
            single_hop_list = bfd_single_hop.get('single-hop', None)
            if single_hop_list:
                for hop in single_hop_list:
                    single_hop_dict = {}
                    remote_address = hop['remote-address']
                    vrf = hop['vrf']
                    interface = hop['interface']
                    local_address = hop['local-address']
                    config = hop['config']
                    enabled = config.get('enabled', None)
                    transmit_interval = config.get('desired-minimum-tx-interval', None)
                    receive_interval = config.get('required-minimum-receive', None)
                    detect_multiplier = config.get('detection-multiplier', None)
                    passive_mode = config.get('passive-mode', None)
                    echo_interval = config.get('desired-minimum-echo-receive', None)
                    echo_mode = config.get('echo-active', None)
                    profile_name = config.get('profile-name', None)

                    if remote_address:
                        single_hop_dict['remote_address'] = remote_address
                    if vrf:
                        single_hop_dict['vrf'] = vrf
                    if interface:
                        single_hop_dict['interface'] = interface
                    if local_address:
                        single_hop_dict['local_address'] = local_address
                    if enabled is not None:
                        single_hop_dict['enabled'] = enabled
                    if transmit_interval:
                        single_hop_dict['transmit_interval'] = transmit_interval
                    if receive_interval:
                        single_hop_dict['receive_interval'] = receive_interval
                    if detect_multiplier:
                        single_hop_dict['detect_multiplier'] = detect_multiplier
                    if passive_mode is not None:
                        single_hop_dict['passive_mode'] = passive_mode
                    if echo_interval:
                        single_hop_dict['echo_interval'] = echo_interval
                    if echo_mode is not None:
                        single_hop_dict['echo_mode'] = echo_mode
                    if profile_name:
                        single_hop_dict['profile_name'] = profile_name
                    if single_hop_dict:
                        all_single_hops.append(single_hop_dict)

        return all_single_hops

    def update_multi_hops(self, data):
        all_multi_hops = []
        bfd_multi_hop = data.get('openconfig-bfd-ext:bfd-mhop-sessions', None)
        if bfd_multi_hop:
            multi_hop_list = bfd_multi_hop.get('multi-hop', None)
            if multi_hop_list:
                for hop in multi_hop_list:
                    multi_hop_dict = {}
                    remote_address = hop['remote-address']
                    vrf = hop['vrf']
                    local_address = hop['local-address']
                    config = hop['config']
                    enabled = config.get('enabled', None)
                    transmit_interval = config.get('desired-minimum-tx-interval', None)
                    receive_interval = config.get('required-minimum-receive', None)
                    detect_multiplier = config.get('detection-multiplier', None)
                    passive_mode = config.get('passive-mode', None)
                    min_ttl = config.get('minimum-ttl', None)
                    profile_name = config.get('profile-name', None)

                    if remote_address:
                        multi_hop_dict['remote_address'] = remote_address
                    if vrf:
                        multi_hop_dict['vrf'] = vrf
                    if local_address:
                        multi_hop_dict['local_address'] = local_address
                    if enabled is not None:
                        multi_hop_dict['enabled'] = enabled
                    if transmit_interval:
                        multi_hop_dict['transmit_interval'] = transmit_interval
                    if receive_interval:
                        multi_hop_dict['receive_interval'] = receive_interval
                    if detect_multiplier:
                        multi_hop_dict['detect_multiplier'] = detect_multiplier
                    if passive_mode is not None:
                        multi_hop_dict['passive_mode'] = passive_mode
                    if min_ttl:
                        multi_hop_dict['min_ttl'] = min_ttl
                    if profile_name:
                        multi_hop_dict['profile_name'] = profile_name
                    if multi_hop_dict:
                        all_multi_hops.append(multi_hop_dict)

        return all_multi_hops

    def get_bfd_config(self, module):
        bfd_cfg = None
        get_bfd_path = '/data/openconfig-bfd:bfd'
        request = {'path': get_bfd_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-bfd:bfd' in response[0][1]:
                bfd_cfg = response[0][1].get('openconfig-bfd:bfd', None)
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)
        return bfd_cfg
