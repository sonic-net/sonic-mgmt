#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The sonic prefix_lists fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible.module_utils.connection import ConnectionError

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils \
    import (
        remove_empties_from_list
    )
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.prefix_lists.prefix_lists import Prefix_listsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


def prefix_set_cfg_parse(unparsed_prefix_set):
    '''Parse the raw input configuration JSON representation for the prefix set specified
    by the input "unparsed_prefix_set" input parameter. Parse the information to
    convert it to a dictionary matching the "argspec" for the "prefix_lists" resource
    module.'''

    parsed_prefix_set = dict()
    if not unparsed_prefix_set.get("config"):
        return parsed_prefix_set
    parsed_prefix_set['name'] = unparsed_prefix_set['name']
    pfx_cfg = unparsed_prefix_set['config']
    if pfx_cfg.get('mode') and isinstance((pfx_cfg['mode']), str):
        parsed_prefix_set['afi'] = pfx_cfg['mode'].lower()
    if unparsed_prefix_set.get('openconfig-routing-policy-ext:extended-prefixes'):
        prefix_lists_container = \
            unparsed_prefix_set['openconfig-routing-policy-ext:extended-prefixes']
        if not prefix_lists_container.get("extended-prefix"):
            return parsed_prefix_set
        prefix_lists_unparsed = prefix_lists_container['extended-prefix']

        prefix_lists_parsed = []
        for prefix_entry_unparsed in prefix_lists_unparsed:
            if not prefix_entry_unparsed.get('config'):
                continue
            if not prefix_entry_unparsed['config'].get('action'):
                continue
            prefix_entry_cfg = prefix_entry_unparsed['config']
            prefix_parsed = dict()
            prefix_parsed['action'] = prefix_entry_cfg['action'].lower()
            if not prefix_entry_unparsed.get('ip-prefix'):
                continue
            if not prefix_entry_unparsed.get('sequence-number'):
                continue

            prefix_parsed['prefix'] = prefix_entry_unparsed['ip-prefix']
            prefix_parsed['sequence'] = prefix_entry_unparsed['sequence-number']
            if (prefix_entry_unparsed.get('masklength-range') and
                    (not prefix_entry_unparsed['masklength-range'] == 'exact')):
                mask = int(prefix_parsed['prefix'].split('/')[1])
                pfx_len = 32 if parsed_prefix_set['afi'] == 'ipv4' else 128
                ge_le = [int(i) for i in prefix_entry_unparsed['masklength-range'].split('..')]
                if ge_le[0] == mask:
                    prefix_parsed['le'] = ge_le[1]
                elif ge_le[1] == pfx_len:
                    prefix_parsed['ge'] = ge_le[0]
                else:
                    prefix_parsed['ge'] = ge_le[0]
                    prefix_parsed['le'] = ge_le[1]
            prefix_lists_parsed.append(prefix_parsed)
        parsed_prefix_set['prefixes'] = prefix_lists_parsed
    return parsed_prefix_set


class Prefix_listsFacts:
    """ The sonic prefix_lists fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Prefix_listsArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_all_prefix_sets(self):
        '''Execute a REST "GET" API to fetch all of the current prefix list configuration
        from the target device.'''

        pfx_fetch_spec = "openconfig-routing-policy:routing-policy/defined-sets/prefix-sets"
        pfx_resp_key = "openconfig-routing-policy:prefix-sets"
        pfx_set_key = "prefix-set"
        # pfx_short_spec = "openconfig-routing-policy:prefix-set"
        url = "data/%s" % pfx_fetch_spec
        method = "GET"
        request = [{"path": url, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc))

        prefix_lists_unparsed = []
        resp_prefix_set = response[0][1].get(pfx_resp_key, None)
        if resp_prefix_set:
            prefix_lists_unparsed = resp_prefix_set.get(pfx_set_key, None)
        return prefix_lists_unparsed

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for prefix_lists
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # (comment by Ansible): just for linting purposes, remove
            pass

        if not data:
            # Fetch data from the current device configuration
            # (Skip if operating on previously fetched configuration.)
            data = self.get_all_prefix_sets()

        # split the unparsed prefix configuration list into a list
        # of parsed prefix set "instances" (dictonary "objects").
        prefix_sets = list()
        for prefix_set_cfg in data:
            prefix_set = prefix_set_cfg_parse(prefix_set_cfg)
            if prefix_set:
                prefix_sets.append(prefix_set)

        ansible_facts['ansible_network_resources'].pop('prefix_lists', None)
        facts = {}
        if prefix_sets:
            params = utils.validate_config(self.argument_spec, {'config': prefix_sets})
            facts['prefix_lists'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts
