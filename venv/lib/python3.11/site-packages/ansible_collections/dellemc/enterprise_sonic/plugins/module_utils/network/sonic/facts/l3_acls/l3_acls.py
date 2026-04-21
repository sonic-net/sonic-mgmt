#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic l3_acls fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l3_acls.l3_acls import L3_aclsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

IPV4_HOST_MASK = '/32'
IPV6_HOST_MASK = '/128'
L4_PORT_START = 0
L4_PORT_END = 65535

action_payload_to_value_map = {
    'ACCEPT': 'permit',
    'DISCARD': 'discard',
    'DO_NOT_NAT': 'do-not-nat',
    'DROP': 'deny',
    'TRANSIT': 'transit',
}
protocol_payload_to_value_map = {
    'IP_ICMP': 'icmp',
    'IP_IGMP': 2,
    'IP_TCP': 'tcp',
    'IP_UDP': 'udp',
    'IP_RSVP': 46,
    'IP_GRE': 47,
    'IP_AUTH': 51,
    'IP_PIM': 103,
    'IP_L2TP': 115
}
protocol_number_to_name_map = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
    58: 'icmpv6'
}
dscp_value_to_name_map = {
    0: 'default',
    8: 'cs1',
    16: 'cs2',
    24: 'cs3',
    32: 'cs4',
    40: 'cs5',
    48: 'cs6',
    56: 'cs7',
    10: 'af11',
    12: 'af12',
    14: 'af13',
    18: 'af21',
    20: 'af22',
    22: 'af23',
    26: 'af31',
    28: 'af32',
    30: 'af33',
    34: 'af41',
    36: 'af42',
    38: 'af43',
    46: 'ef',
    44: 'voice_admit'
}


class L3_aclsFacts(object):
    """ The sonic l3_acls fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = L3_aclsArgs.argument_spec
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
        """ Populate the facts for l3_acls
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            l3_acls_configs = self.get_l3_acls()

        objs = []
        for l3_acl_config in l3_acls_configs:
            obj = self.render_config(self.generated_spec, l3_acl_config)
            if obj:
                objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('l3_acls', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['l3_acls'] = utils.remove_empties({'config': params['config']})['config']

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

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
        config['address_family'] = conf['address_family']
        config['acls'] = conf['acls']
        is_ipv4 = bool(config['address_family'] == 'ipv4')

        for acl in config['acls']:
            for rule in acl['rules']:
                rule['source'] = {}
                rule['destination'] = {}
                rule['protocol'] = {}
                rule['protocol_options'] = {}

                if ":" in rule['action']:
                    rule['action'] = rule['action'].split(":")[-1]
                rule['action'] = action_payload_to_value_map[rule['action']]

                l2_config = rule.pop('l2', None)
                l3_config = rule.pop('l3', None)
                l4_config = rule.pop('l4', None)
                if l3_config is None:
                    if is_ipv4:
                        rule['protocol']['name'] = 'ip'
                    else:
                        rule['protocol']['name'] = 'ipv6'

                    rule['source']['any'] = True
                    rule['destination']['any'] = True
                    continue

                protocol = l3_config.get('protocol')
                if protocol is not None:
                    if isinstance(protocol, str):
                        protocol = protocol.replace('openconfig-packet-match-types:', '')
                        protocol = protocol_payload_to_value_map[protocol]
                        if isinstance(protocol, str):
                            rule['protocol']['name'] = protocol
                        else:
                            rule['protocol']['number'] = protocol
                    else:
                        protocol = protocol_number_to_name_map.get(protocol, protocol)
                        if isinstance(protocol, str):
                            rule['protocol']['name'] = protocol
                        else:
                            rule['protocol']['number'] = protocol
                else:
                    if is_ipv4:
                        rule['protocol']['name'] = 'ip'
                    else:
                        rule['protocol']['name'] = 'ipv6'

                rule['source'] = self._convert_ip_addr_to_spec_fmt(l3_config.get('source-address'), is_ipv4)
                rule['destination'] = self._convert_ip_addr_to_spec_fmt(l3_config.get('destination-address'), is_ipv4)
                if protocol in ('tcp', 'udp'):
                    rule['source']['port_number'] = self._convert_l4_port_to_spec_fmt(l4_config.get('source-port'))
                    rule['destination']['port_number'] = self._convert_l4_port_to_spec_fmt(l4_config.get('destination-port'))

                if protocol in ('icmp', 'icmpv6'):
                    rule['protocol_options'][protocol] = {
                        'code': l4_config.get('openconfig-acl-ext:icmp-code'),
                        'type': l4_config.get('openconfig-acl-ext:icmp-type')
                    }
                elif protocol == 'tcp':
                    rule['protocol_options']['tcp'] = {}
                    if l4_config.get('openconfig-acl-ext:tcp-session-established'):
                        rule['protocol_options']['tcp']['established'] = True
                    else:
                        for flag in l4_config.get('tcp-flags', []):
                            flag = flag.split(':')[-1].replace('TCP_', '').lower()
                            rule['protocol_options']['tcp'][flag] = True

                dscp = l3_config.get('dscp')
                if dscp in dscp_value_to_name_map:
                    rule['dscp'] = {dscp_value_to_name_map[dscp]: True}
                else:
                    rule['dscp'] = {'value': dscp}

                rule['vlan_id'] = l2_config.get('openconfig-acl-ext:vlanid')

        return config

    def get_l3_acls(self):
        """Get all l3 acl configurations available in chassis"""
        acls_path = 'data/openconfig-acl:acl/acl-sets'
        method = 'GET'
        request = [{'path': acls_path, 'method': method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        acls = []
        if response[0][1].get('openconfig-acl:acl-sets'):
            acls = response[0][1]['openconfig-acl:acl-sets'].get('acl-set', [])

        ipv4_acls_configs = []
        ipv6_acls_configs = []
        for acl in acls:
            is_ipv4 = False
            acl_config = {}
            acl_rules = []

            config = acl['config']
            if config.get('type') in ('ACL_IPV4', 'openconfig-acl:ACL_IPV4'):
                is_ipv4 = True
            elif config.get('type') in ('ACL_IPV6', 'openconfig-acl:ACL_IPV6'):
                is_ipv4 = False
            else:
                continue

            acl_config['name'] = config['name']
            acl_config['remark'] = config.get('description')
            acl_config['rules'] = acl_rules

            acl_entries = acl.get('acl-entries', {}).get('acl-entry', [])
            for acl_entry in acl_entries:
                acl_rule = {}

                acl_entry_config = acl_entry['config']
                acl_rule['sequence_num'] = acl_entry_config['sequence-id']
                acl_rule['remark'] = acl_entry_config.get('description')

                acl_rule['action'] = acl_entry['actions']['config']['forwarding-action']
                acl_rule['l2'] = acl_entry.get('l2', {}).get('config', {})
                if is_ipv4:
                    acl_rule['l3'] = acl_entry.get('ipv4', {}).get('config', {})
                else:
                    acl_rule['l3'] = acl_entry.get('ipv6', {}).get('config', {})
                acl_rule['l4'] = acl_entry.get('transport', {}).get('config', {})

                acl_rules.append(acl_rule)

            if is_ipv4:
                ipv4_acls_configs.append(acl_config)
            else:
                ipv6_acls_configs.append(acl_config)

        l3_acls_configs = []
        if ipv4_acls_configs:
            l3_acls_configs.append({'address_family': 'ipv4', 'acls': ipv4_acls_configs})
        if ipv6_acls_configs:
            l3_acls_configs.append({'address_family': 'ipv6', 'acls': ipv6_acls_configs})

        return l3_acls_configs

    @staticmethod
    def _convert_ip_addr_to_spec_fmt(ip_addr, is_ipv4=False):
        spec_fmt = {}
        if ip_addr is not None:
            ip_addr = ip_addr.lower()
            if is_ipv4:
                host_mask = IPV4_HOST_MASK
            else:
                host_mask = IPV6_HOST_MASK

            if ip_addr.endswith(host_mask):
                spec_fmt['host'] = ip_addr.replace(host_mask, '')
            else:
                spec_fmt['prefix'] = ip_addr
        else:
            spec_fmt['any'] = True

        return spec_fmt

    @staticmethod
    def _convert_l4_port_to_spec_fmt(l4_port):
        spec_fmt = {}
        if l4_port is not None:
            if isinstance(l4_port, str) and '..' in l4_port:
                l4_port = [int(i) for i in l4_port.split('..')]
                if l4_port[0] == L4_PORT_START:
                    spec_fmt['lt'] = l4_port[1]
                elif l4_port[1] == L4_PORT_END:
                    spec_fmt['gt'] = l4_port[0]
                else:
                    spec_fmt['range'] = {
                        'begin': l4_port[0],
                        'end': l4_port[1]
                    }
            else:
                spec_fmt['eq'] = int(l4_port)

        return spec_fmt
