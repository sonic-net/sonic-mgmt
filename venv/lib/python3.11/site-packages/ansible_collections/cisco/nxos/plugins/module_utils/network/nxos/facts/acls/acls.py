#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The nxos acls fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.acls.acls import (
    AclsArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.utils.utils import (
    validate_ipv4_addr,
    validate_ipv6_addr,
)


class AclsFacts(object):
    """The nxos acls fact class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = AclsArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec
        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_device_data(self, connection):
        data = connection.get("show running-config | section '^ip(v6)* access-list'")
        if data == "{}":
            return ""
        return data

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for acls
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            data = self.get_device_data(connection)
        data = re.split("\nip", data)
        v6 = []
        v4 = []

        for i in range(len(data)):
            if str(data[i]):
                if "v6" in str(data[i]).split()[0]:
                    v6.append(data[i])
                else:
                    v4.append(data[i])

        resources = []
        resources.append(v6)
        resources.append(v4)
        objs = []
        for resource in resources:
            if resource:
                obj = self.render_config(self.generated_spec, resource)
                if obj:
                    objs.append(obj)

        ansible_facts["ansible_network_resources"].pop("acls", None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {"config": objs})
            params = utils.remove_empties(params)
            facts["acls"] = params["config"]

        ansible_facts["ansible_network_resources"].update(facts)
        return ansible_facts

    def get_endpoint(self, ace, pro):
        ret_dict = {}
        option = ace.split()[0]
        if option == "any":
            ret_dict.update({"any": True})
        else:
            # it could be a.b.c.d or a.b.c.d/x or a.b.c.d/32
            if "/" in option:  # or 'host' in option:
                prefix = re.search(r"(.*)/(\d+)", option)
                ip = prefix.group(1)
                cidr = prefix.group(2)
                if (validate_ipv4_addr(option) and int(cidr) == 32) or (
                    validate_ipv6_addr(option) and int(cidr) == 128
                ):
                    ret_dict.update({"host": ip})
                else:
                    ret_dict.update({"prefix": option})
            else:
                ret_dict.update({"address": option})
                wb = ace.split()[1]
                ret_dict.update({"wildcard_bits": wb})
                ace = re.sub("{0}".format(wb), "", ace, 1)
        ace = re.sub(option, "", ace, 1)
        if pro in ["tcp", "udp"]:
            keywords = ["eq", "lt", "gt", "neq", "range"]
            if len(ace.split()) and ace.split()[0] in keywords:
                port_protocol = {}
                if "range" not in ace.split()[0]:
                    port_pro = re.search(r"(eq|lt|gt|neq) (\S+)", ace)
                    if port_pro:
                        port_protocol.update({port_pro.group(1): port_pro.group(2)})
                        ace = re.sub(port_pro.group(1), "", ace, 1)
                        ace = re.sub(port_pro.group(2), "", ace, 1)
                else:
                    limit = re.search(r"range\s(?P<rstart>\S+)\s(?P<rend>\S+)", ace)
                    if limit:
                        rstart = limit.groupdict()["rstart"]
                        rend = limit.groupdict()["rend"]
                        port_protocol.update(
                            {
                                "range": {
                                    "start": rstart,
                                    "end": rend,
                                },
                            },
                        )
                        range_substring = "range %s %s" % (rstart, rend)
                        ace = re.sub(range_substring, "", ace, 1)
                if port_protocol:
                    ret_dict.update({"port_protocol": port_protocol})
        return ace, ret_dict

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
        protocol_options = {
            "tcp": ["fin", "established", "psh", "rst", "syn", "urg", "ack"],
            "icmp": [
                "administratively_prohibited",
                "alternate_address",
                "conversion_error",
                "dod_host_prohibited",
                "dod_net_prohibited",
                "echo_request",
                "echo_reply",
                "echo",
                "general_parameter_problem",
                "host_isolated",
                "host_precedence_unreachable",
                "host_redirect",
                "host_tos_redirect",
                "host_tos_unreachable",
                "host_unknown",
                "host_unreachable",
                "information_reply",
                "information_request",
                "mask_reply",
                "mask_request",
                "mobile_redirect",
                "net_redirect",
                "net_tos_redirect",
                "net_tos_unreachable",
                "net_unreachable",
                "network_unknown",
                "no_room_for_option",
                "option_missing",
                "packet_too_big",
                "parameter_problem",
                "port_unreachable",
                "precedence_unreachable",
                "protocol_unreachable",
                "unreachable",
                "reassembly_timeout",
                "redirect",
                "router_advertisement",
                "router_solicitation",
                "source_quench",
                "source_route_failed",
                "time_exceeded",
                "timestamp_reply",
                "timestamp_request",
                "traceroute",
                "ttl_exceeded",
            ],
            "icmpv6": [
                "beyond_scope",
                "destination_unreachable",
                "echo_reply",
                "echo_request",
                "fragments",
                "header",
                "hop_limit",
                "mld_query",
                "mld_reduction",
                "mld_report",
                "mldv2",
                "nd_na",
                "nd_ns",
                "next_header",
                "no_admin",
                "no_route",
                "packet_too_big",
                "parameter_option",
                "parameter_problem",
                "port_unreachable",
                "reassembly_timeout",
                "renum_command",
                "renum_result",
                "renum_seq_number",
                "router_advertisement",
                "router_renumbering",
                "router_solicitation",
                "time_exceeded",
                "unreachable",
                "telemetry_path",
                "telemetry_queue",
            ],
            "igmp": ["dvmrp", "host_query", "host_report"],
        }
        if conf:
            if "v6" in conf[0].split()[0]:
                config["afi"] = "ipv6"
            else:
                config["afi"] = "ipv4"
            config["acls"] = []
            for acl in conf:
                acls = {}
                if "match-local-traffic" in acl:
                    config["match_local_traffic"] = True
                    continue
                acl = acl.split("\n")
                acl = [a.strip() for a in acl]
                acl = list(filter(None, acl))
                acls["name"] = re.match(r"(ip)?(v6)?\s?access-list (.*)", acl[0]).group(
                    3,
                )
                acls["aces"] = []
                for ace in list(filter(None, acl[1:])):
                    if re.search(r"^ip(.*)access-list.*", ace):
                        break
                    ace = ace.strip()
                    seq = re.match(r"(\d+)", ace)
                    rem = ""
                    entry = {}
                    if seq:
                        seq = seq.group(0)
                        entry.update({"sequence": seq})
                        ace = re.sub(seq, "", ace, 1)
                        grant = ace.split()[0]
                        if grant != "remark":
                            entry.update({"grant": grant})
                        else:
                            rem = re.match(".*remark (.*)", ace).group(1)
                            entry.update({"remark": rem})

                    if not rem and seq:
                        ace = re.sub(grant, "", ace, 1)

                        pro = ace.split()[0]
                        if pro == "icmp" and config["afi"] == "ipv6":
                            entry.update({"protocol": "icmpv6"})
                        else:
                            entry.update({"protocol": pro})

                        ace = re.sub(pro, "", ace, 1)
                        ace, source = self.get_endpoint(ace, pro)
                        entry.update({"source": source})
                        ace, dest = self.get_endpoint(ace, pro)
                        entry.update({"destination": dest})

                        dscp = re.search(r"dscp (\w*)", ace)
                        if dscp:
                            entry.update({"dscp": dscp.group(1)})

                        frag = re.search(r"fragments", ace)
                        if frag:
                            entry.update({"fragments": True})

                        prec = re.search(r"precedence (\w*)", ace)
                        if prec:
                            entry.update({"precedence": prec.group(1)})

                        log = re.search("log", ace)
                        if log:
                            entry.update({"log": True})

                        pro = entry.get("protocol", "")
                        if pro in ["tcp", "icmp", "icmpv6", "igmp"]:
                            pro_options = {}
                            options = {}
                            for option in protocol_options[pro]:
                                if option not in ["telemetry_path", "telemetry_queue"]:
                                    option = re.sub("_", "-", option)
                                if option in ace:
                                    if option == "echo" and (
                                        "echo_request" in options or "echo_reply" in options
                                    ):
                                        continue
                                    elif option == "unreachable" and "port_unreachable" in options:
                                        continue
                                    option = re.sub("-", "_", option)
                                    options.update({option: True})
                            if options:
                                pro_options.update({pro: options})
                            if pro_options:
                                entry.update({"protocol_options": pro_options})
                    if entry:
                        acls["aces"].append(entry)
                config["acls"].append(acls)
        return utils.remove_empties(config)
