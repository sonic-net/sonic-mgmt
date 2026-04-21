# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The nxos l2_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.l2_interfaces.l2_interfaces import (
    L2_interfacesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.l2_interfaces import (
    L2_interfacesTemplate,
)


class L2_interfacesFacts(object):
    """The nxos l2_interfaces facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = L2_interfacesArgs.argument_spec

    def _get_interface_config(self, connection):
        return connection.get("show running-config | section ^interface")

    def _fix_allowed_vlans(self, parsed_config):
        """Fix the allowed vlans from tuple to a string and remove interfaces with only name key"""

        # Process allowed_vlans
        for interface in parsed_config:
            trunk = interface.get("trunk", {})
            allowed_vlans = trunk.get("allowed_vlans")
            if allowed_vlans and isinstance(allowed_vlans, tuple):
                trunk["allowed_vlans"] = ",".join(map(str, allowed_vlans))

        return parsed_config

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for L2_interfaces network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []

        if not data:
            data = self._get_interface_config(connection)

        # parse native config using the L2_interfaces template
        l2_interfaces_parser = L2_interfacesTemplate(lines=data.splitlines(), module=self._module)
        objs = list(l2_interfaces_parser.parse().values())
        final_objs = self._fix_allowed_vlans(objs)

        ansible_facts["ansible_network_resources"].pop("l2_interfaces", None)

        params = utils.remove_empties(
            l2_interfaces_parser.validate_config(
                self.argument_spec,
                {"config": final_objs},
                redact=True,
            ),
        )

        facts["l2_interfaces"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
