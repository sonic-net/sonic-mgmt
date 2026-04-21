# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr vrf_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.vrf_global.vrf_global import (
    Vrf_globalArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.vrf_global import (
    Vrf_globalTemplate,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.utils.utils import (
    flatten_config,
)


class Vrf_globalFacts(object):
    """The iosxr vrf facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Vrf_globalArgs.argument_spec

    def get_config(self, connection):
        """Get the configuration from the device"""

        return connection.get("show running-config vrf")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Vrf network resource
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """

        facts = {}
        objs = []
        obj = {}

        if not data:
            data = self.get_config(connection)

        data = flatten_config(data, "vrf")

        # parse native config using the Vrf_global template
        vrf_global_parser = Vrf_globalTemplate(lines=data.splitlines(), module=self._module)
        obj = vrf_global_parser.parse()
        objs = list(obj.values())

        ansible_facts["ansible_network_resources"].pop("vrf_global", None)
        params = utils.remove_empties(
            vrf_global_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["vrf_global"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
