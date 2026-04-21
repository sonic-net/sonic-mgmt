#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The iosxr_l3_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import re

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.l3_interfaces.l3_interfaces import (
    L3_InterfacesArgs,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.utils.utils import (
    get_interface_type,
    netmask_to_cidr,
)


class L3_InterfacesFacts(object):
    """The iosxr_l3_interfaces fact class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = L3_InterfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_config(self, connection):
        return connection.get_config(flags="interface")

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            data = self.get_config(connection)
        # operate on a collection of resource x
        config = ("\n" + data).split("\ninterface ")
        for conf in config:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
                if obj:
                    objs.append(obj)
        facts = {}

        if objs:
            facts["l3_interfaces"] = []
            params = utils.validate_config(
                self.argument_spec,
                {"config": objs},
            )
            for cfg in params["config"]:
                facts["l3_interfaces"].append(utils.remove_empties(cfg))
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts

    def render_config(self, spec, conf):
        """
        Render config as dictionary structure and delete keys from spec for null values
        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        config = deepcopy(spec)
        match = re.search(r"^(\S+)", conf)
        if match:
            intf = match.group(1)
            if match.group(1).lower() == "preconfigure":
                match = re.search(r"^(\S+) (.*)", conf)
                if match:
                    intf = match.group(2)

            if get_interface_type(intf) == "unknown":
                return {}

            # populate the facts from the configuration
            config["name"] = intf

            # Get the configured IPV4 details
            ipv4 = []
            ipv4_all = re.findall(r"ipv4 address (\S+.*)", conf)
            for each in ipv4_all:
                each_ipv4 = dict()
                if "secondary" in each:
                    each_ipv4["address"] = self.format_ipv4(each.split(" secondary")[0])
                    each_ipv4["secondary"] = True
                elif "secondary" not in each and "dhcp" not in each:
                    each_ipv4["address"] = self.format_ipv4(each)
                elif "dhcp" in each:
                    each_ipv4["address"] = "dhcp"
                ipv4.append(each_ipv4)
                config["ipv4"] = ipv4

            # Get the configured IPV6 details
            ipv6 = []
            ipv6_all = re.findall(r"ipv6 address (\S+)", conf)
            for each in ipv6_all:
                each_ipv6 = dict()
                each_ipv6["address"] = each
                ipv6.append(each_ipv6)
                config["ipv6"] = ipv6

            carrier_delay_match = re.search(r"^\s*carrier-delay (.*)$", conf, re.M)
            if carrier_delay_match:
                args = carrier_delay_match.group(1).strip()
                up_match = re.search(r"up (\d+)", args)
                if up_match:
                    config["carrier_delay"]["up"] = int(up_match.group(1))

                down_match = re.search(r"down (\d+)", args)
                if down_match:
                    config["carrier_delay"]["down"] = int(down_match.group(1))

            dampening_line = re.search(r"^\s*dampening(.*)$", conf, re.M)
            if dampening_line:
                config["dampening"]["enabled"] = True

                params = dampening_line.group(1).strip().split()

                param_keys = [
                    "half_life",
                    "reuse_threshold",
                    "suppress_threshold",
                    "max_suppress_time",
                    "restart_penalty",
                ]
                for i, value in enumerate(params):
                    if i < len(param_keys):
                        key_name = param_keys[i]
                        config["dampening"][key_name] = int(value)

            load_interval = re.search(r"load-interval (\d+)", conf)
            if load_interval:
                config["load_interval"] = int(load_interval.group(1))

            flow_control = re.search(r"flow(?:-control)? (ingress|egress|bidirectional)", conf)
            if flow_control:
                config["flow_control"] = flow_control.group(1)

            flow_monitor_lines = re.findall(
                r"^\s*flow (ipv4|ipv6) monitor (\S+) sampler (\S+) (ingress|egress)",
                conf,
                re.M,
            )
            if flow_monitor_lines:
                if "flow" not in config or not config["flow"]:
                    config["flow"] = {}

                for line in flow_monitor_lines:
                    protocol, monitor, sampler, direction = line
                    if protocol not in config["flow"]:
                        config["flow"][protocol] = {}

                    config["flow"][protocol]["monitor"] = monitor
                    config["flow"][protocol]["sampler"] = sampler
                    config["flow"][protocol]["direction"] = direction

            return utils.remove_empties(config)

    def format_ipv4(self, address):
        parts = address.split(" ")
        if len(parts) > 1 and parts[1]:
            cidr_val = netmask_to_cidr(parts[1])
            return "{0}/{1}".format(parts[0], cidr_val)
        return parts[0]
