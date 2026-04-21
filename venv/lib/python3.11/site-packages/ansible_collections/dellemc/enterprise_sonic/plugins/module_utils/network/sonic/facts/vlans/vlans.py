#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic vlans fact class
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
    remove_empties_from_list,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.vlans.vlans import VlansArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError

GET = "get"


class VlansFacts(object):
    """ The sonic vlans fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = VlansArgs.argument_spec
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
        """ Populate the facts for vlans
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            vlans = self.get_vlans()
        else:
            vlans = data

        facts = {}
        if vlans:
            params = utils.validate_config(self.argument_spec, {'config': vlans})
            facts['vlans'] = remove_empties_from_list(params.get("config"))
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_vlans(self):
        """
        Gather all the vlan configuration from the device

        Returns: List of dictionaries with each item being a vlan config
        """
        request = [{"path": "data/sonic-vlan:sonic-vlan", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        vlans_list = []
        if len(response[0]) >= 1:
            if "sonic-vlan:sonic-vlan" in response[0][1]:
                vlans = response[0][1].get("sonic-vlan:sonic-vlan", {})
                if vlans:
                    if vlans.get("VLAN"):
                        if vlans.get("VLAN").get("VLAN_LIST"):
                            vlans_list = vlans['VLAN']["VLAN_LIST"]

        ret_vlan_configs = []
        for vlan_config_dict in vlans_list:
            autostate = vlan_config_dict.get("autostate") == "enable"
            description = vlan_config_dict.get("description", "")
            vlan_id = vlan_config_dict.get("vlanid")
            vlan_configs = {"vlan_id": vlan_id,
                            "autostate": autostate,
                            "description": description
                            }
            ret_vlan_configs.append(vlan_configs)
        return ret_vlan_configs
