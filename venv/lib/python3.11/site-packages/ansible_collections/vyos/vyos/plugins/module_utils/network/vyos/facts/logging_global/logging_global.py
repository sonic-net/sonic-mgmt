# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

"""
The vyos logging_global fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.logging_global.logging_global import (
    Logging_globalArgs,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.rm_templates.logging_global import (
    Logging_globalTemplate,
)


class Logging_globalFacts(object):
    """The vyos logging_global facts class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Logging_globalArgs.argument_spec

    def get_logging_data(self, connection):
        return connection.get("show configuration commands | grep syslog")

    def process_facts(self, objFinal):
        if objFinal:
            for ke, vl in iteritems(objFinal):
                if ke == "files":
                    _files = []
                    for k, v in vl.items():
                        _files.append(v)
                    objFinal[ke] = _files
                    objFinal[ke] = sorted(objFinal[ke], key=lambda item: item["path"])
                elif ke == "hosts":
                    _hosts = []
                    for k, v in vl.items():
                        _hosts.append(v)
                    objFinal[ke] = _hosts
                    objFinal[ke] = sorted(objFinal[ke], key=lambda item: item["hostname"])
                elif ke == "users":
                    _users = []
                    for k, v in vl.items():
                        _users.append(v)
                    objFinal[ke] = _users
                    objFinal[ke] = sorted(objFinal[ke], key=lambda item: item["username"])
                elif ke == "console" or ke == "global_params":
                    if objFinal[ke].get("facilities"):
                        objFinal[ke]["facilities"] = sorted(
                            objFinal[ke]["facilities"],
                            key=lambda item: item["facility"],
                        )
        return objFinal

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for Logging_global network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []

        if not data:
            data = self.get_logging_data(connection)

        # parse native config using the Logging_global template
        logging_global_parser = Logging_globalTemplate(lines=data.splitlines(), module=self._module)
        objs = logging_global_parser.parse()
        ansible_facts["ansible_network_resources"].pop("logging_global", None)
        objs = self.process_facts(objs)

        params = utils.remove_empties(
            logging_global_parser.validate_config(
                self.argument_spec,
                {"config": objs},
                redact=True,
            ),
        )

        facts["logging_global"] = params.get("config", {})
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
