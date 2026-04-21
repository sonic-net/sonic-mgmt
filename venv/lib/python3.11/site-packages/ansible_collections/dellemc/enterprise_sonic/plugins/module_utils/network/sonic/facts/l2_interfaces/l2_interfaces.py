#
# -*- coding: utf-8 -*-
# © Copyright 2020 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic l2_interfaces fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l2_interfaces.l2_interfaces import L2_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class L2_interfacesFacts(object):
    """ The sonic l2_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = L2_interfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def vlan_range_to_list(self, in_range, range_str):
        range_bounds = in_range.split(range_str)
        range_bottom = int(range_bounds[0])
        range_top = int(range_bounds[1]) + 1
        vlan_list = list(range(range_bottom, range_top))
        vlan_dict_list = []
        for vlan in vlan_list:
            vlan_dict_list.append({'vlan': vlan})
        return vlan_dict_list

    def get_l2_interfaces_from_interfaces(self, interfaces):
        l2_interfaces = []

        for intf in interfaces:
            name = intf.get('name')
            if not name:
                continue
            key = 'openconfig-if-ethernet:ethernet'
            if name.startswith('PortChannel'):
                key = 'openconfig-if-aggregate:aggregation'
            eth_det = intf.get(key)
            if eth_det:
                open_cfg_vlan = eth_det.get('openconfig-vlan:switched-vlan')
                if open_cfg_vlan and 'config' in open_cfg_vlan:
                    new_det = dict()
                    new_det['name'] = name
                    if name == "eth0":
                        continue
                    if (open_cfg_vlan['config'].get('access-vlan')):
                        new_det['access'] = dict({'vlan': open_cfg_vlan['config'].get('access-vlan')})
                    if (open_cfg_vlan['config'].get('trunk-vlans')):
                        new_det['trunk'] = {}
                        new_det['trunk']['allowed_vlans'] = []

                        # Save trunk vlans and vlan ranges as a list of single vlan dicts:
                        # Convert single vlan values to strings and convert any ranges
                        # to the argspec range format. (This block assumes that any string
                        # value received is a range, using either ".." or "-" as a
                        # separator between the boundaries of the range. It also assumes
                        # that any non-string value received is an integer specifying a
                        # single vlan.)
                        for vlan in open_cfg_vlan['config'].get('trunk-vlans'):
                            vlan_argspec = ''
                            if isinstance(vlan, str):
                                vlan_argspec = vlan.replace('"', '')
                                if '..' in vlan_argspec:
                                    vlan_argspec = vlan_argspec.replace('..', '-')
                            else:
                                vlan_argspec = str(vlan)
                            new_det['trunk']['allowed_vlans'].append({'vlan': vlan_argspec})
                    l2_interfaces.append(new_det)

        return l2_interfaces

    def get_all_l2_interfaces(self):
        """Get all the l2_interfaces available in chassis"""
        l2_interfaces = {}
        request = [{"path": "data/openconfig-interfaces:interfaces", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        if "openconfig-interfaces:interfaces" in response[0][1]:
            interfaces = response[0][1].get("openconfig-interfaces:interfaces", {})
            if interfaces.get("interface"):
                interfaces = interfaces['interface']
                l2_interfaces = self.get_l2_interfaces_from_interfaces(interfaces)
            else:
                l2_interfaces = {}

        return l2_interfaces

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for l2_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section ^interface')
            # using mock data instead
            data = self.get_all_l2_interfaces()

        objs = list()
        for conf in data:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
        # split the config into instances of the resource
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('l2_interfaces', None)
        facts = {}
        if objs:
            facts['l2_interfaces'] = []
            params = utils.validate_config(self.argument_spec, {'config': objs})
            for cfg in params['config']:
                facts['l2_interfaces'].append(utils.remove_empties(cfg))
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
