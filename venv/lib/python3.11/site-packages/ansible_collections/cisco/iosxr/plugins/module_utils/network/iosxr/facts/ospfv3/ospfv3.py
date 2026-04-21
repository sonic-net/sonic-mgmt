# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.ospfv3.ospfv3 import (
    Ospfv3Args,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.rm_templates.ospfv3 import (
    Ospfv3Template,
)


class Ospfv3Facts(object):
    """The iosxr snmp fact class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Ospfv3Args.argument_spec

        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_ospfv3_data(self, connection):
        return connection.get("show running-config router ospfv3")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """

        if not data:
            data = self.get_ospfv3_data(connection)
        end_flag, end_mark, count, v_read = 0, 0, 0, False
        areas, config_commands = [], []
        area_str, process, curr_process = "", "", ""
        data = data.splitlines()
        for line in data:
            if line.startswith("router ospfv3") and curr_process != "" and curr_process != line:
                end_mark, count, end_flag, area_str = 0, 0, 0, ""
            if end_mark == 0 and count == 0 and line.startswith("router ospfv3"):
                curr_process = line
                process = re.sub("\n", "", line)
                count += 1
                config_commands.append(process)
            else:
                if line.startswith(" area") or line.startswith(" vrf"):
                    area_str = process + re.sub("\n", "", line)
                    config_commands.append(area_str.replace("  ", " "))
                    end_flag += 1
                elif line.startswith("  virtual-link"):
                    virtual_str = area_str + re.sub("\n", "", line)
                    config_commands.append(virtual_str.replace("  ", " "))
                    v_read = True
                elif v_read:
                    if "!" not in line:
                        command = virtual_str.replace("  ", " ") + re.sub(
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
        ipv4 = {"processes": []}
        rmmod = NetworkTemplate(
            lines=data,
            tmplt=Ospfv3Template(),
            module=self._module,
        )
        current = rmmod.parse()

        # convert some of the dicts to lists
        for key, sortv in [("processes", "process_id")]:
            if key in current and current[key]:
                current[key] = current[key].values()
                current[key] = sorted(
                    current[key],
                    key=lambda k, sk=sortv: k[sk],
                )

        for process in current.get("processes", []):
            if "areas" in process:
                process["areas"] = list(process["areas"].values())
                process["areas"] = sorted(
                    process["areas"],
                    key=lambda k, sk="area_id": k[sk],
                )
                for area in process["areas"]:
                    if "ranges" in area:
                        area["ranges"] = sorted(
                            area["ranges"],
                            key=lambda k, s="ranges": k[s],
                        )
                    if "virtual_link" in area:
                        area["virtual_link"] = list(
                            area["virtual_link"].values(),
                        )
                        area["virtual_link"] = sorted(
                            area["virtual_link"],
                            key=lambda k, sk="id": k[sk],
                        )
            ipv4["processes"].append(process)

        ansible_facts["ansible_network_resources"].pop("ospfv3", None)
        facts = {}
        if current:
            params = rmmod.validate_config(
                self.argument_spec,
                {"config": ipv4},
                redact=True,
            )
            params = utils.remove_empties(params)

            facts["ospfv3"] = params["config"]

            ansible_facts["ansible_network_resources"].update(facts)
        return ansible_facts
