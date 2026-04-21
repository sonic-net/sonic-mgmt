#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ptp_port_ds fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ptp_port_ds.ptp_port_ds import Ptp_port_dsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = 'GET'


class Ptp_port_dsFacts(object):
    """ The sonic ptp_port_ds fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ptp_port_dsArgs.argument_spec
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
        """ Populate the facts for ptp_port_ds
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass
        obj = self.get_all_ptp_port()
        ansible_facts['ansible_network_resources'].pop('ptp_port_ds', None)
        facts = {}
        if obj:
            params = utils.validate_config(self.argument_spec, {'config': obj})
            facts['ptp_port_ds'] = utils.remove_empties({'config': params['config']})['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_all_ptp_port(self):
        """Get all PTP port configurations available in chassis"""
        ptp_port_path = 'data/ietf-ptp:ptp/instance-list=0/port-ds-list'
        request = [{'path': ptp_port_path, 'method': GET}]

        ptp_port_configs = []
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            if re.search("code.*404", str(exc)):
                return ptp_port_configs
            else:
                self._module.fail_json(msg=str(exc), code=exc.code)

        if response[0][1].get('ietf-ptp:port-ds-list'):
            raw_ptp_port_data = response[0][1]['ietf-ptp:port-ds-list']
            for port in raw_ptp_port_data:
                ptp_port_data = {}
                ptp_port_data['interface'] = port['underlying-interface']
                if 'ietf-ptp-ext:role' in port:
                    ptp_port_data['role'] = port['ietf-ptp-ext:role'].lower()
                if 'ietf-ptp-ext:local-priority' in port:
                    ptp_port_data['local_priority'] = port['ietf-ptp-ext:local-priority']
                if 'ietf-ptp-ext:unicast-table' in port:
                    ptp_port_data['unicast_table'] = port['ietf-ptp-ext:unicast-table']
                ptp_port_configs.append(ptp_port_data)
        return ptp_port_configs
