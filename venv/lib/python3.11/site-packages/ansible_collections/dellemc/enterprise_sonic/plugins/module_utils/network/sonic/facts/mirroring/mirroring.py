#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic mirroring fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.mirroring.mirroring import MirroringArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

GET = "get"


class MirroringFacts(object):
    """ The sonic mirroring fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = MirroringArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_mirror_session_config(self):
        """Get all mirroring sessions available in chassis"""
        request = [{"path": "data/openconfig-mirror-ext:mirror/sessions", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if response[0][1]:
            data = response[0][1]['openconfig-mirror-ext:sessions']
        else:
            data = {}

        return data

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for mirroring
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            data = self.get_mirror_session_config()

        if data and data.get('session'):
            mirror_session_config = data['session']
        else:
            mirror_session_config = []

        mirror_session_facts = self.get_mirror_session_facts(mirror_session_config)

        ansible_facts['ansible_network_resources'].pop('mirroring', None)
        facts = {}
        if mirror_session_facts:
            params = utils.validate_config(self.argument_spec, {'config': mirror_session_facts})
            facts['mirroring'] = remove_empties(params['config'])

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_mirror_session_facts(self, config):
        mirror_session_facts = dict()
        span = list()
        erspan = list()

        for conf in config:
            ms_info = conf.get('config')
            if not ms_info:
                continue

            name = ms_info.get('name')
            dst_port = ms_info.get('dst-port')
            source = ms_info.get('src-port')
            dst_ip = ms_info.get('dst-ip')
            src_ip = ms_info.get('src-ip')
            direction = ms_info.get('direction')
            if direction:
                direction = direction.lower()
            dscp = ms_info.get('dscp')
            ttl = ms_info.get('ttl')
            gre = ms_info.get('gre-type')
            queue = ms_info.get('queue')

            is_erspan = False
            for attr in [dst_ip, src_ip, dscp, ttl, gre, queue]:
                if attr is not None:
                    is_erspan = True
                    break
            if is_erspan:
                erspan.append({'name': name, 'dst_ip': dst_ip,
                               'src_ip': src_ip, 'source': source,
                               'direction': direction, 'dscp': dscp,
                               'ttl': ttl, 'gre': gre, 'queue': queue})
            else:
                span.append({'name': name, 'dst_port': dst_port,
                             'source': source, 'direction': direction})
        if span:
            mirror_session_facts['span'] = remove_empties_from_list(span)
        if erspan:
            mirror_session_facts['erspan'] = remove_empties_from_list(erspan)

        return mirror_session_facts
