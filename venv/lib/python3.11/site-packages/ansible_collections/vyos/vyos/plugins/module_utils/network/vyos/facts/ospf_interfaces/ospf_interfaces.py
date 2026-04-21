# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos ospf_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

import re

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.ospf_interfaces.ospf_interfaces import (
    Ospf_interfacesArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.ospf_interfaces import (
    Ospf_interfacesTemplate,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.ospf_interfaces_14 import (
    Ospf_interfacesTemplate14,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.utils.version import (
    LooseVersion,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import get_os_version


class Ospf_interfacesFacts(object):
    """The vyos ospf_interfaces facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Ospf_interfacesArgs.argument_spec

    def get_device_data(self, connection):
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            # use set protocols ospf in order to get both ospf and ospfv3
            return connection.get("show configuration commands |  match 'set protocols ospf'")
        return connection.get('show configuration commands |  match "set interfaces"')

    def get_config_set_1_4(self, data):
        """To classify the configurations beased on interface"""
        config_dict = {}
        for config_line in data.splitlines():
            ospf_int = re.search(r"set protocols (?:ospf|ospfv3) interface (\S+).*", config_line)
            if ospf_int:
                config_dict[ospf_int.group(1)] = (
                    config_dict.get(ospf_int.group(1), "") + config_line + "\n"
                )
        return list(config_dict.values())

    def get_config_set_1_2(self, data):
        """To classify the configurations beased on interface"""
        interface_list = []
        config_set = []
        int_string = ""
        for config_line in data.splitlines():
            ospf_int_raw = re.findall(r"^set interfaces \S+ (\S+)", config_line, re.M)
            ospf_int_vif = re.findall(r"^set interfaces \S+ (\S+) vif (\d+)", config_line, re.M)

            ospf_int = ospf_int_raw + ospf_int_vif
            if ospf_int:
                if ospf_int not in interface_list:
                    if int_string:
                        config_set.append(int_string)
                    interface_list.append(ospf_int)
                    int_string = ""
                int_string = int_string + config_line + "\n"
        if int_string:
            config_set.append(int_string)
        return config_set

    def get_config_set(self, data, connection):
        """To classify the configurations beased on interface"""
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            return self.get_config_set_1_4(data)
        return self.get_config_set_1_2(data)

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
        if LooseVersion(get_os_version(self._module)) >= LooseVersion("1.4"):
            ospf_interface_class = Ospf_interfacesTemplate14
        else:
            ospf_interface_class = Ospf_interfacesTemplate
        ospf_interfaces_parser = ospf_interface_class(lines=[], module=self._module)

        if not data:
            data = self.get_device_data(connection)

        # parse native config using the Ospf_interfaces template
        ospf_interfaces_facts = []
        resources = self.get_config_set(data, connection)
        for resource in resources:
            ospf_interfaces_parser = ospf_interface_class(
                lines=resource.split("\n"),
                module=self._module,
            )
            objs = ospf_interfaces_parser.parse()
            for key, sortv in [("address_family", "afi")]:
                if key in objs and objs[key]:
                    objs[key] = list(objs[key].values())
            ospf_interfaces_facts.append(objs)
        ansible_facts["ansible_network_resources"].pop("ospf_interfaces", None)
        facts = {"ospf_interfaces": []}
        params = utils.remove_empties(
            ospf_interfaces_parser.validate_config(
                self.argument_spec,
                {"config": ospf_interfaces_facts},
                redact=True,
            ),
        )
        if params.get("config"):
            for cfg in params["config"]:
                facts["ospf_interfaces"].append(utils.remove_empties(cfg))
        ansible_facts["ansible_network_resources"].update(facts)
        return ansible_facts
