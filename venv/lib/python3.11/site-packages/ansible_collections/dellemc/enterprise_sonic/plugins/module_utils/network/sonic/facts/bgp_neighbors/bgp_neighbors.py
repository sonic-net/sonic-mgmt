#
# -*- coding: utf-8 -*-
# © Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic bgp_neighbors fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.bgp_neighbors.bgp_neighbors import Bgp_neighborsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.bgp_utils import (
    get_all_bgp_neighbors,
    get_from_params_map,
    get_peergroups,
)


class Bgp_neighborsFacts(object):
    """ The sonic bgp_neighbors fact class
    """

    neighbor_params_map = {
        'neighbor': 'neighbor-address',
        'peer_as': 'peer-as',
        'peer_type': 'peer-type',
        'peer_group': 'peer-group',
        'keepalive': 'keepalive-interval',
        'holdtime': 'hold-time',
        'connect_retry': 'connect-retry',
        'advertisement_interval': 'minimum-advertisement-interval',
        'bfd_enabled': ['enable-bfd', 'enabled'],
        'check_failure': ['enable-bfd', 'check-control-plane-failure'],
        'profile': ['enable-bfd', 'bfd-profile'],
        'dynamic': 'capability-dynamic',
        'extended_nexthop': 'capability-extended-nexthop',
        'pwd': ['auth-password', 'password'],
        'encrypted': ['auth-password', 'encrypted'],
        'nbr_description': 'description',
        'disable_connected_check': 'disable-ebgp-connected-route-check',
        'dont_negotiate_capability': 'dont-negotiate-capability',
        'enforce_first_as': 'enforce-first-as',
        'enforce_multihop': 'enforce-multihop',
        'extended_link_bandwidth': 'extended-link-bandwidth',
        'local_address': ['transport', 'config', 'local-address'],
        'as': 'local-as',
        'no_prepend': 'local-as-no-prepend',
        'replace_as': 'local-as-replace-as',
        'override_capability': 'override-capability',
        'port': 'peer-port',
        'shutdown_msg': 'shutdown-message',
        'solo': 'solo-peer',
        'strict_capability_match': 'strict-capability-match',
        'ttl_security': 'ttl-security-hops',
        'enabled': ['ebgp-multihop', 'enabled'],
        'multihop_ttl': ['ebgp-multihop', 'multihop-ttl'],
        'v6only': 'openconfig-bgp-ext:v6only',
        'discard-extra': 'openconfig-bgp-ext:discard-extra',
        'passive': ['transport', 'config', 'passive-mode']
    }

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Bgp_neighborsArgs.argument_spec
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
        """ Populate the facts for BGP
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = list()

        if not data:
            data = get_all_bgp_neighbors(self._module)
            filtered_data = self.filter_neighbors_data(data)
            if filtered_data:
                data = filtered_data

        for conf in data:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('bgp_neighbors', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['bgp_neighbors'] = remove_empties_from_list(params['config'])
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

        return conf

    def filter_neighbors_data(self, data):
        filtered_data = []
        for conf in data:
            vrf_name = conf['vrf_name']
            tmp = {}
            bgp_as = conf['bgp_as']
            val = None
            if 'neighbors' in conf and 'neighbor' in conf['neighbors']:
                val = conf['neighbors']['neighbor']

            tmp['vrf_name'] = vrf_name
            tmp['bgp_as'] = bgp_as
            peergroup = get_peergroups(self._module, vrf_name)
            if peergroup:
                tmp['peer_group'] = peergroup
            fil_neighbors = []
            if val:
                for neighbor in val:
                    fil_neighbor = get_from_params_map(self.neighbor_params_map, neighbor)
                    capability = {}
                    capability_dynamic = fil_neighbor.get('dynamic', None)
                    if capability_dynamic is not None:
                        capability['dynamic'] = capability_dynamic
                        fil_neighbor.pop('dynamic')
                    capability_extended_nexthop = fil_neighbor.get('extended_nexthop', None)
                    if capability_extended_nexthop is not None:
                        capability['extended_nexthop'] = capability_extended_nexthop
                        fil_neighbor.pop('extended_nexthop')
                    if capability:
                        fil_neighbor['capability'] = capability
                    remote = {}
                    peer_as = fil_neighbor.get('peer_as', None)
                    if peer_as is not None:
                        remote['peer_as'] = peer_as
                        fil_neighbor.pop('peer_as')
                    peer_type = fil_neighbor.get('peer_type', None)
                    if peer_type is not None:
                        remote['peer_type'] = peer_type.lower()
                        fil_neighbor.pop('peer_type')
                    if remote:
                        fil_neighbor['remote_as'] = remote
                    auth_pwd = {}
                    pwd = fil_neighbor.get('pwd', None)
                    if pwd is not None:
                        auth_pwd['pwd'] = pwd
                        fil_neighbor.pop('pwd')
                    encrypted = fil_neighbor.get('encrypted', None)
                    if encrypted is not None:
                        auth_pwd['encrypted'] = encrypted
                        fil_neighbor.pop('encrypted')
                    ebgp_multihop = {}
                    enabled = fil_neighbor.get('enabled', None)
                    if enabled is not None:
                        ebgp_multihop['enabled'] = enabled
                        fil_neighbor.pop('enabled')
                    multihop_ttl = fil_neighbor.get('multihop_ttl', None)
                    if multihop_ttl is not None:
                        ebgp_multihop['multihop_ttl'] = multihop_ttl
                        fil_neighbor.pop('multihop_ttl')
                    local_as = {}
                    asn = fil_neighbor.get('as', None)
                    if asn is not None:
                        local_as['as'] = asn
                        fil_neighbor.pop('as')
                    no_prepend = fil_neighbor.get('no_prepend', None)
                    if no_prepend is not None:
                        local_as['no_prepend'] = no_prepend
                        fil_neighbor.pop('no_prepend')
                    replace_as = fil_neighbor.get('replace_as', None)
                    if replace_as is not None:
                        local_as['replace_as'] = replace_as
                        fil_neighbor.pop('replace_as')
                    bfd = {}
                    bfd_enabled = fil_neighbor.get('bfd_enabled', None)
                    if bfd_enabled is not None:
                        bfd['enabled'] = bfd_enabled
                        fil_neighbor.pop('bfd_enabled')
                    check_failure = fil_neighbor.get('check_failure', None)
                    if check_failure is not None:
                        bfd['check_failure'] = check_failure
                        fil_neighbor.pop('check_failure')
                    profile = fil_neighbor.get('profile', None)
                    if profile is not None:
                        bfd['profile'] = profile
                        fil_neighbor.pop('profile')
                    if auth_pwd:
                        fil_neighbor['auth_pwd'] = auth_pwd
                    if ebgp_multihop:
                        fil_neighbor['ebgp_multihop'] = ebgp_multihop
                    if local_as:
                        fil_neighbor['local_as'] = local_as
                    if bfd:
                        fil_neighbor['bfd'] = bfd
                    if fil_neighbor:
                        fil_neighbors.append(fil_neighbor)
            if fil_neighbors:
                tmp['neighbors'] = fil_neighbors
            filtered_data.append(tmp)
        return filtered_data
