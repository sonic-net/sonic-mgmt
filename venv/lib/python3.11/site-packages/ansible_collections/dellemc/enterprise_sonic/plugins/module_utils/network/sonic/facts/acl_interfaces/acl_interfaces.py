#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic acl_interfaces fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.acl_interfaces.acl_interfaces import Acl_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


class Acl_interfacesFacts(object):
    """ The sonic acl_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Acl_interfacesArgs.argument_spec
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
        """ Populate the facts for acl_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            acl_interfaces_configs = self.get_acl_interfaces()

        objs = []
        for interface_config in acl_interfaces_configs.items():
            obj = self.render_config(self.generated_spec, interface_config)
            if obj:
                objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('acl_interfaces', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['acl_interfaces'] = params['config']

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
        config = deepcopy(spec)
        config['name'] = conf[0]
        config['access_groups'] = []

        acls = {'mac': [], 'ipv4': [], 'ipv6': []}
        for acl in conf[1]:
            acl_type = acl.pop('type')
            if acl_type in ('ACL_L2', 'openconfig-acl:ACL_L2'):
                acls['mac'].append(acl)
            elif acl_type in ('ACL_IPV4', 'openconfig-acl:ACL_IPV4'):
                acls['ipv4'].append(acl)
            elif acl_type in ('ACL_IPV6', 'openconfig-acl:ACL_IPV6'):
                acls['ipv6'].append(acl)

        for acl_type, acl_list in acls.items():
            if acl_list:
                config['access_groups'].append({
                    'type': acl_type,
                    'acls': acl_list
                })

        return config

    def get_acl_interfaces(self):
        """Get all interface access-group configurations available in chassis"""
        acl_interfaces_path = 'data/openconfig-acl:acl/interfaces'
        method = 'GET'
        request = [{'path': acl_interfaces_path, 'method': method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        acl_interfaces = []
        if response[0][1].get('openconfig-acl:interfaces'):
            acl_interfaces = response[0][1]['openconfig-acl:interfaces'].get('interface', [])

        acl_interfaces_configs = {}
        for interface in acl_interfaces:
            acls_list = []

            ingress_acls = interface.get('ingress-acl-sets', {}).get('ingress-acl-set', [])
            for acl in ingress_acls:
                if acl.get('config'):
                    acls_list.append({
                        'name': acl['config']['set-name'],
                        'type': acl['config']['type'],
                        'direction': 'in'
                    })

            egress_acls = interface.get('egress-acl-sets', {}).get('egress-acl-set', [])
            for acl in egress_acls:
                if acl.get('config'):
                    acls_list.append({
                        'name': acl['config']['set-name'],
                        'type': acl['config']['type'],
                        'direction': 'out'
                    })

            acl_interfaces_configs[interface['id']] = acls_list

        return acl_interfaces_configs
