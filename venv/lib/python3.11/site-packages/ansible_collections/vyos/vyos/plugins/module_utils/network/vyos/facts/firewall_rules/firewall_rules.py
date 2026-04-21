#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The vyos firewall_rules fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from copy import deepcopy
from re import M, findall, search

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.argspec.firewall_rules.firewall_rules import (
    Firewall_rulesArgs,
)


class Firewall_rulesFacts(object):
    """The vyos firewall_rules fact class"""

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Firewall_rulesArgs.argument_spec
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
        return connection.get_config()

    def populate_facts(self, connection, ansible_facts, data=None):
        """Populate the facts for firewall_rules
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section ^interface')
            # using mock data instead
            data = self.get_device_data(connection)
        # split the config into instances of the resource
        objs = []
        # check 1.4+ first
        new_rules = True
        v6_rules = findall(r"^set firewall ipv6 (name|forward|input|output) (?:\'*)(\S+)(?:\'*)", data, M)
        if not v6_rules:
            v6_rules = findall(r"^set firewall ipv6-name (?:\'*)(\S+)(?:\'*)", data, M)
            if v6_rules:
                new_rules = False
        v4_rules = findall(r"^set firewall ipv4 (name|forward|input|output) (?:\'*)(\S+)(?:\'*)", data, M)
        if not v4_rules:
            v4_rules = findall(r"^set firewall name (?:\'*)(\S+)(?:\'*)", data, M)
            if v4_rules:
                new_rules = False
        if v6_rules:
            if new_rules:
                config = self.get_rules_post_1_4(data, v6_rules, type="ipv6")
            else:
                config = self.get_rules(data, v6_rules, type="ipv6")
            if config:
                config = utils.remove_empties(config)
                objs.append(config)
        if v4_rules:
            if new_rules:
                config = self.get_rules_post_1_4(data, v4_rules, type="ipv4")
            else:
                config = self.get_rules(data, v4_rules, type="ipv4")
            if config:
                config = utils.remove_empties(config)
                objs.append(config)

        ansible_facts["ansible_network_resources"].pop("firewall_rules", None)
        facts = {}
        if objs:
            facts["firewall_rules"] = []
            params = utils.validate_config(self.argument_spec, {"config": objs})
            for cfg in params["config"]:
                facts["firewall_rules"].append(utils.remove_empties(cfg))

        ansible_facts["ansible_network_resources"].update(facts)
        return ansible_facts

    def get_rules(self, data, rules, type):
        """
        This function performs following:
        - Form regex to fetch 'rule-sets' specific config from data.
        - Form the rule-set list based on ip address.
        :param data: configuration.
        :param rules: list of rule-sets.
        :param type: ip address type.
        :return: generated rule-sets configuration.
        """
        r_v4 = []
        r_v6 = []
        for r in set(rules):
            name_key = "ipv6-name" if type == "ipv6" else "name"
            rule_regex = r" %s %s .+$" % (name_key, r.strip("'"))
            cfg = findall(rule_regex, data, M)
            fr = self.render_config(cfg, r.strip("'"))
            fr["name"] = r.strip("'")
            if type == "ipv6":
                r_v6.append(fr)
            else:
                r_v4.append(fr)
        if r_v4:
            config = {"afi": "ipv4", "rule_sets": r_v4}
        if r_v6:
            config = {"afi": "ipv6", "rule_sets": r_v6}
        return config

    def get_rules_post_1_4(self, data, rules, type):
        """
        This function performs following:
        - Form regex to fetch 'rule-sets' specific config from data.
        - Form the rule-set list based on ip address.
        Specifically for v1.4+ version.
        :param data: configuration.
        :param rules: list of rule-sets.
        :param type: ip address type.
        :return: generated rule-sets configuration.
        """
        r_v4 = []
        r_v6 = []
        for kind, name in set(rules):
            rule_regex = r" %s %s %s .+$" % (type, kind, name.strip("'"))
            cfg = findall(rule_regex, data, M)
            fr = self.render_config(cfg, name.strip("'"))
            if kind == "name":
                fr["name"] = name.strip("'")
            elif kind in ("forward", "input", "output"):
                fr["filter"] = kind
            else:
                raise ValueError("Unknown rule kind: %s %s" % kind, name)
            if type == "ipv6":
                r_v6.append(fr)
            else:
                r_v4.append(fr)
        if r_v4:
            config = {"afi": "ipv4", "rule_sets": r_v4}
        if r_v6:
            config = {"afi": "ipv6", "rule_sets": r_v6}
        return config

    def render_config(self, conf, match):
        """
        Render config as dictionary structure and delete keys
          from spec for null values

        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        conf = "\n".join(filter(lambda x: x, conf))
        a_lst = ["description", "default_action", "default_jump_target", "enable_default_log", "default_log"]
        config = self.parse_attr(conf, a_lst, match)
        if not config:
            config = {}
        if 'default_log' in config:
            config['enable_default_log'] = config.pop('default_log')
        config["rules"] = self.parse_rules_lst(conf)
        return config

    def parse_rules_lst(self, conf):
        """
        This function forms the regex to fetch the 'rules' with in
        'rule-sets'
        :param conf: configuration data.
        :return: generated rule list configuration.
        """
        r_lst = []
        rules = findall(r"rule (?:\'*)(\d+)(?:\'*)", conf, M)
        if rules:
            rules_lst = []
            for r in set(rules):
                r_regex = r" %s .+$" % r
                cfg = "\n".join(findall(r_regex, conf, M))
                obj = self.parse_rules(cfg)
                obj["number"] = int(r)
                if obj:
                    rules_lst.append(obj)
            r_lst = sorted(rules_lst, key=lambda i: i["number"])
        return r_lst

    def parse_rules(self, conf):
        """
        This function triggers the parsing of 'rule' attributes.
        a_lst is a list having rule attributes which doesn't
        have further sub attributes.
        :param conf: configuration
        :return: generated rule configuration dictionary.
        """
        a_lst = [
            "ipsec",
            "log",
            "action",
            "protocol",
            "fragment",
            "disable",
            "description",
            "icmp",
            "jump_target",
            "queue",
            "queue_options",
        ]
        rule = self.parse_attr(conf, a_lst)
        r_sub = {
            "tcp": self.parse_tcp(conf),
            "icmp": self.parse_icmp(conf, "icmp"),
            "time": self.parse_time(conf, "time"),
            "limit": self.parse_limit(conf, "limit"),
            "state": self.parse_state(conf, "state"),
            "recent": self.parse_recent(conf, "recent"),
            "source": self.parse_src_or_dest(conf, "source"),
            "destination": self.parse_src_or_dest(conf, "destination"),
            "inbound_interface": self.parse_interface(conf, "inbound-interface"),
            "outbound_interface": self.parse_interface(conf, "outbound-interface"),
            "packet_length": self.parse_packet_length(conf, "packet-length"),
            "packet_length_exclude": self.parse_packet_length(conf, "packet-length-exclude"),
        }
        rule.update(r_sub)
        return rule

    def parse_interface(self, conf, attrib):
        """
        This function triggers the parsing of 'interface' attributes.
        :param conf: configuration.
        :param attrib: 'interface'.
        :return: generated config dictionary.
        """
        a_lst = ["name", "group"]
        cfg_dict = self.parse_attr(conf, a_lst, match=attrib)
        return cfg_dict

    def parse_packet_length(self, conf, attrib=None):
        """
        This function triggers the parsing of 'packet-length' attributes.
        :param conf: configuration.
        :param attrib: 'packet-length'.
        :return: generated config dictionary.
        """
        lengths = []
        rule_regex = r"%s (.+)$" % attrib
        found_lengths = findall(rule_regex, conf, M)
        if found_lengths:
            lengths = []
            for l in set(found_lengths):
                obj = {"length": l.strip("'")}
                lengths.append(obj)
        return lengths

    def parse_src_or_dest(self, conf, attrib=None):
        """
        This function triggers the parsing of 'source or
        destination' attributes.
        :param conf: configuration.
        :param attrib:'source/destination'.
        :return:generated source/destination configuration dictionary.
        """
        a_lst = ["port", "address", "mac_address"]
        cfg_dict = self.parse_attr(conf, a_lst, match=attrib)
        cfg_dict["group"] = self.parse_group(conf, attrib + " group")
        return cfg_dict

    def parse_recent(self, conf, attrib=None):
        """
        This function triggers the parsing of 'recent' attributes
        :param conf: configuration.
        :param attrib: 'recent'.
        :return: generated config dictionary.
        """
        a_lst = ["time", "count"]
        cfg_dict = self.parse_attr(conf, a_lst, match=attrib)
        return cfg_dict

    def parse_tcp(self, conf):
        """
        This function triggers the parsing of 'tcp' attributes.
        :param conf: configuration.
        :param attrib: 'tcp'.
        :return: generated config dictionary.
        """
        f_lst = []
        flags = findall(r"tcp flags (not )?(?:\'*)([\w!,]+)(?:\'*)", conf, M)
        # for pre 1.4, this is a string including possible commas
        # and ! as an inverter. For 1.4+ this is a single flag per
        # command and 'not' as the inverter
        if flags:
            flag_lst = []
            for n, f in set(flags):
                f = f.strip("'").lower()
                if "," in f:
                    # pre 1.4 version with multiple flags
                    fs = f.split(",")
                    for f in fs:
                        if "!" in f:
                            obj = {"flag": f.strip("'!"), "invert": True}
                        else:
                            obj = {"flag": f.strip("'")}
                        flag_lst.append(obj)
                elif "!" in f:
                    obj = {"flag": f.strip("'!"), "invert": True}
                    flag_lst.append(obj)
                else:
                    obj = {"flag": f.strip("'")}
                    if n:
                        obj["invert"] = True
                    flag_lst.append(obj)
            f_lst = sorted(flag_lst, key=lambda i: i["flag"])
        return {"flags": f_lst}

    def parse_time(self, conf, attrib=None):
        """
        This function triggers the parsing of 'time' attributes.
        :param conf: configuration.
        :param attrib: 'time'.
        :return: generated config dictionary.
        """
        a_lst = [
            "stopdate",
            "stoptime",
            "weekdays",
            "monthdays",
            "startdate",
            "starttime",
        ]
        cfg_dict = self.parse_attr(conf, a_lst, match=attrib)
        return cfg_dict

    def parse_state(self, conf, attrib=None):
        """
        This function triggers the parsing of 'state' attributes.
        :param conf: configuration
        :param attrib: 'state'.
        :return: generated config dictionary.
        """
        a_lst = ["new", "invalid", "related", "established"]
        cfg_dict = self.parse_attr(conf, a_lst, match=attrib)
        return cfg_dict

    def parse_group(self, conf, attrib=None):
        """
        This function triggers the parsing of 'group' attributes.
        :param conf: configuration.
        :param attrib: 'group'.
        :return: generated config dictionary.
        """
        a_lst = ["port_group", "address_group", "network_group"]
        cfg_dict = self.parse_attr(conf, a_lst, match=attrib)
        return cfg_dict

    def parse_icmp_attr(self, conf, match):
        """
        This function peforms the following:
        - parse ICMP arguemnts for firewall rules
        - consider that older versions may need numbers or letters
          in type, newer ones are more specific
        :param conf: configuration.
        :param match: parent node/attribute name.
        :return: generated config dictionary.
        """
        config = {}
        if not conf:
            return config

        for attrib in ("code", "type", "type-name"):
            regex = self.map_regex(attrib)
            if match:
                regex = match + " " + regex
            out = search(r"^.*" + regex + " (.+)", conf, M)
            if out:
                val = out.group(1).strip("'")
                if attrib == 'type-name':
                    config['type_name'] = val
                if attrib == 'code':
                    config['code'] = int(val)
                if attrib == 'type':
                    # <1.3 could be # (type), #/# (type/code) or 'type' (type_name)
                    # recent this is only for strings
                    if "/" in val:  # type/code
                        (type_no, code) = val.split(".")
                        config['type'] = type_no
                        config['code'] = code
                    elif val.isnumeric():
                        config['type'] = type_no
                    else:
                        config['type_name'] = val
        return config

    def parse_icmp(self, conf, attrib=None):
        """
        This function triggers the parsing of 'icmp' attributes.
        :param conf: configuration to be parsed.
        :param attrib: 'icmp'.
        :return: generated config dictionary.
        """
        cfg_dict = self.parse_icmp_attr(conf, "icmp")
        if (len(cfg_dict) == 0):
            cfg_dict = self.parse_icmp_attr(conf, "icmpv6")
        return cfg_dict

    def parse_limit(self, conf, attrib=None):
        """
        This function triggers the parsing of 'limit' attributes.
        :param conf: configuration to be parsed.
        :param attrib: 'limit'
        :return: generated config dictionary.
        """
        cfg_dict = self.parse_attr(conf, ["burst"], match=attrib)
        cfg_dict["rate"] = self.parse_rate(conf, "rate")
        return cfg_dict

    def parse_attr(self, conf, attr_list, match=None):
        """
        This function peforms the following:
        - Form the regex to fetch the required attribute config.
        - Type cast the output in desired format.
        :param conf: configuration.
        :param attr_list: list of attributes.
        :param match: parent node/attribute name.
        :return: generated config dictionary.
        """
        config = {}
        for attrib in attr_list:
            regex = self.map_regex(attrib)
            if match:
                regex = match + " " + regex
            if conf:
                if self.is_bool(attrib):
                    out = conf.find(attrib.replace("_", "-"))
                    dis = conf.find(attrib.replace("_", "-") + " 'disable'")
                    if out >= 1:
                        if dis >= 1:
                            config[attrib] = False
                        else:
                            config[attrib] = True
                else:
                    out = search(r"^.*" + regex + " (.+)", conf, M)
                    if not out:
                        if attrib == "disable":
                            out = search(r"^.*\d+" + " (disable$)", conf, M)
                        if attrib == 'log':
                            out = search(r"^.*\d+" + " (log$)", conf, M)
                    if out:

                        val = out.group(1).strip("'")
                        if self.is_num(attrib):
                            val = int(val)
                        if attrib == "disable":
                            val = True
                        if attrib == "log":
                            val = "enable"
                        config[attrib] = val
        return config

    def map_regex(self, attrib):
        """
        - This function construct the regex string.
        - replace the underscore with hyphen.
        :param attrib: attribute
        :return: regex string
        """
        regex = attrib.replace("_", "-")
        if attrib == "disabled":
            regex = "disable"
        return regex

    def is_bool(self, attrib):
        """
        This function looks for the attribute in predefined bool type set.
        :param attrib: attribute.
        :return: True/False
        """
        bool_set = (
            "new",
            "invalid",
            "related",
            "disabled",
            "established",
            "enable_default_log",
            "default_log",
        )
        return True if attrib in bool_set else False

    def is_num(self, attrib):
        """
        This function looks for the attribute in predefined integer type set.
        :param attrib: attribute.
        :return: True/false.
        """
        num_set = ("time", "code", "type", "count", "burst", "number")
        return True if attrib in num_set else False

    def parse_rate(self, conf, match):
        """
        This function triggers the parsing of 'rate' attributes.
        :param conf: configuration.
        :param attrib: 'rate'
        :return: generated config dictionary.
        """
        config = {}

        out = search(r"^.*" + match + " (.+)", conf, M)
        if out:
            val = out.group(1).strip("'")
            if "/" in val:  # number/unit
                (number, unit) = val.split("/")
                config['number'] = number
                config['unit'] = unit
        return config
