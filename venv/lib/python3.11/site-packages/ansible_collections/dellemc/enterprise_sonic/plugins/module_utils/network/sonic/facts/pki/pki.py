#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell EMC
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic pki fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.pki.pki import (
    PkiArgs,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config,
)

pki_path = "data/openconfig-pki:pki/"
security_profiles_path = "data/openconfig-pki:pki/security-profiles"


class PkiFacts(object):
    """The sonic pki fact class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = PkiArgs.argument_spec
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
        """Populate the facts for pki
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass
        resources = {}
        if not data:
            result = self.get_pki()
            if len(result) > 0 and result[0]:
                code, resources = result[0]

        objs = {}
        if (
            resources.get("openconfig-pki:pki")
            and resources.get("openconfig-pki:pki").get("security-profiles")
            and resources.get("openconfig-pki:pki")
            .get("security-profiles")
            .get("security-profile")
        ):
            sps = (
                resources.get("openconfig-pki:pki")
                .get("security-profiles")
                .get("security-profile")
            )
            sps_conf = [r.get("config") for r in sps]
            rep_conf = []
            for c in sps_conf:
                conf = {}
                for k, v in c.items():
                    conf[k.replace("-", "_")] = v
                rep_conf.append(conf)
            objs["security_profiles"] = rep_conf
        if (
            resources.get("openconfig-pki:pki")
            and resources.get("openconfig-pki:pki").get("trust-stores")
            and resources.get("openconfig-pki:pki")
            .get("trust-stores")
            .get("trust-store")
        ):
            tsts = (
                resources.get("openconfig-pki:pki")
                .get("trust-stores")
                .get("trust-store")
            )
            tsts_conf = [r.get("config") for r in tsts]
            rep_conf = []
            for c in tsts_conf:
                conf = {}
                for k, v in c.items():
                    conf[k.replace("-", "_")] = v
                rep_conf.append(conf)

            objs["trust_stores"] = rep_conf

        ansible_facts["ansible_network_resources"].pop("pki", None)
        facts = {}
        if objs:
            params = utils.validate_config(
                self.argument_spec, {"config": objs}
            )
            facts["pki"] = params["config"]

        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts

    def get_pki(self):
        request = {"path": pki_path, "method": "get"}
        try:
            response = edit_config(
                self._module, to_request(self._module, request)
            )
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        return response

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
        return utils.remove_empties(config)
