# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import operator
import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.fc_interfaces.fc_interfaces import (
    Fc_interfacesArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.rm_templates.fc_interfaces import (
    Fc_interfacesTemplate,
)


__metaclass__ = type

"""
The nxos fc_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""


class Fc_interfacesFacts(object):
    """The nxos fc_interfaces facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Fc_interfacesArgs.argument_spec

    def get_interfaces_data(self, connection):
        return connection.get("show running-config interface all")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Fc_interfaces network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []

        if not data:
            data = self.get_interfaces_data(connection)

        # parse native config using the Fc_interfaces template
        fc_interfaces_parser = Fc_interfacesTemplate(lines=data.splitlines(), module=self._module)

        objs = list(fc_interfaces_parser.parse().values())

        # - populate only fc interfaces
        # - populate "analytics" value based on the presence or absense of "analytics_nvme" or "analytics_scsi" keys
        # - dummy key "m" and "p" is added for sorting, which is removed after sorting
        modified_objs = []
        # match only fc interface
        regex = re.compile(r"^fc\d+\S+")
        for parsed_data in objs:
            if not re.match(regex, parsed_data["name"]):
                continue
            m, p = parsed_data["name"].strip("fc").split("/")
            parsed_data["m"] = int(m)
            parsed_data["p"] = int(p)

            if "analytics_scsi" in parsed_data:
                parsed_data.pop("analytics_scsi")
                if "analytics_nvme" in parsed_data:
                    parsed_data.pop("analytics_nvme")
                    parsed_data["analytics"] = "fc-all"
                else:
                    parsed_data["analytics"] = "fc-scsi"
            else:
                if "analytics_nvme" in parsed_data:
                    parsed_data.pop("analytics_nvme")
                    parsed_data["analytics"] = "fc-nvme"
            modified_objs.append(parsed_data)

        sorted_dict = sorted(modified_objs, key=operator.itemgetter("m", "p"))
        objs = [
            {key: value for key, value in eachdict.items() if key not in ["m", "p"]}
            for eachdict in sorted_dict
        ]

        ansible_facts["ansible_network_resources"].pop("fc_interfaces", None)

        params = utils.remove_empties(
            fc_interfaces_parser.validate_config(self.argument_spec, {"config": objs}, redact=True),
        )

        facts["fc_interfaces"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
