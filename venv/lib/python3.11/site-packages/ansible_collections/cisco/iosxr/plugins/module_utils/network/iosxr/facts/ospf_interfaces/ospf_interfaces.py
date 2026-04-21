# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The iosxr ospf_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

import re

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.ospf_interfaces.ospf_interfaces import (
    Ospf_interfacesArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.ospf_interfaces import (
    Ospf_interfacesTemplate,
)


class Ospf_interfacesFacts(object):
    """The iosxr ospf_interfaces facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Ospf_interfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_ospf_interfaces(self, connection, flag):
        cmd = "show running-config router " + flag
        return connection.get(cmd)

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Ospf_interfaces network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []
        if not data:
            data = self.get_ospf_interfaces(connection, flag="ospf")
            data += "\n" + self.get_ospf_interfaces(connection, flag="ospfv3")
        end_flag, end_mark, count, v_read = 0, 0, 0, False
        areas, config_commands = [], []
        area_str, process, curr_process = "", "", ""
        data = data.splitlines()

        for line in data:
            if line.startswith("router") and curr_process != "" and curr_process != line:
                end_mark, count, end_flag, area_str = 0, 0, 0, ""
            if end_mark == 0 and count == 0 and line.startswith("router ospf"):
                curr_process = line
                process = re.sub("\n", "", line)
                count += 1
                config_commands.append(process)
            else:
                if line.startswith(" area") or line.startswith(" vrf"):
                    area_str = process + re.sub("\n", "", line)
                    config_commands.append(area_str.replace("  ", " "))
                    end_flag += 1
                elif line.startswith("  interface"):
                    ospf_int = area_str + re.sub("\n", "", line)
                    # default output format has more spaces with default identation
                    # reset the spaces with replace
                    config_commands.append(ospf_int.replace("  ", " "))
                    v_read = True
                elif v_read:
                    if "!" not in line:
                        command = ospf_int.replace("  ", " ") + re.sub(
                            "\n",
                            "",
                            line,
                        )
                        config_commands.append(command.replace("   ", " "))
                    else:
                        v_read = False
                elif end_flag > 0 and "!" not in line:
                    command = area_str + re.sub("\n", "", line)
                    config_commands.append(command.replace("  ", " "))
                elif "!" in line:
                    end_flag = 0
                    end_mark += 1
                    if end_mark == 3:
                        end_mark, count = 0, 0
                    area_str = ""
                else:
                    command = process + line
                    command.replace("  ", " ")
                    config_commands.append(re.sub("\n", "", command))
                    areas.append(re.sub("\n", "", command))
        data = config_commands

        ospf_interfaces_parser = Ospf_interfacesTemplate(
            lines=data,
            module=self._module,
        )
        objs = list(ospf_interfaces_parser.parse().values())
        if objs:
            for item in objs:
                item["address_family"] = list(item["address_family"].values())
                for af in item["address_family"]:
                    if af.get("processes"):
                        af["processes"] = list(af["processes"].values())

        ansible_facts["ansible_network_resources"].pop("ospf_interfaces", None)

        params = utils.remove_empties(
            ospf_interfaces_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["ospf_interfaces"] = params.get("config", [])
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
