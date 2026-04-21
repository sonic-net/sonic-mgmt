#
# -*- coding: utf-8 -*-
# Copyright 2022 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic l2_acls fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.l2_acls.l2_acls import L2_aclsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

ETHERTYPE_FORMAT = '0x{:04x}'

action_payload_to_value_map = {
    'ACCEPT': 'permit',
    'DISCARD': 'discard',
    'DO_NOT_NAT': 'do-not-nat',
    'DROP': 'deny',
    'TRANSIT': 'transit',
}
ethertype_payload_to_protocol_map = {
    '0x0800': 'ipv4',
    '0x0806': 'arp',
    '0x86dd': 'ipv6',
    'ETHERTYPE_ARP': 'arp',
    'ETHERTYPE_IPV4': 'ipv4',
    'ETHERTYPE_IPV6': 'ipv6'
}
ethertype_payload_to_value_map = {
    'ETHERTYPE_LLDP': '0x88cc',
    'ETHERTYPE_MPLS': '0x8847',
    'ETHERTYPE_ROCE': '0x8915'
}
pcp_value_to_traffic_map = {
    0: 'be',
    1: 'bk',
    2: 'ee',
    3: 'ca',
    4: 'vi',
    5: 'vo',
    6: 'ic',
    7: 'nc'
}


class L2_aclsFacts(object):
    """ The sonic l2_acls fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = L2_aclsArgs.argument_spec
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
        """ Populate the facts for l2_acls
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            l2_acls_configs = self.get_l2_acls()

        objs = []
        for l2_acl_config in l2_acls_configs:
            obj = self.render_config(self.generated_spec, l2_acl_config)
            if obj:
                objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('l2_acls', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['l2_acls'] = utils.remove_empties({'config': params['config']})['config']

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
        config['name'] = conf['name']
        config['remark'] = conf['remark']
        config['rules'] = conf['rules']

        for rule in config['rules']:
            if ":" in rule['action']:
                rule['action'] = rule['action'].split(":")[-1]
            rule['action'] = action_payload_to_value_map[rule['action']]

            rule['source'] = {}
            rule['destination'] = {}
            if rule.get('l2') is None:
                rule['source']['any'] = True
                rule['destination']['any'] = True
                continue

            l2_config = rule.pop('l2')
            if l2_config.get('source-mac') and l2_config.get('source-mac-mask'):
                if l2_config['source-mac-mask'].lower() == 'ff:ff:ff:ff:ff:ff':
                    rule['source']['host'] = l2_config['source-mac'].lower()
                else:
                    rule['source']['address'] = l2_config['source-mac'].lower()
                    rule['source']['address_mask'] = l2_config['source-mac-mask'].lower()
            elif l2_config.get('source-mac'):
                rule['source']['host'] = l2_config['source-mac'].lower()
            else:
                rule['source']['any'] = True

            if l2_config.get('destination-mac') and l2_config.get('destination-mac-mask'):
                if l2_config['destination-mac-mask'].lower() == 'ff:ff:ff:ff:ff:ff':
                    rule['destination']['host'] = l2_config['destination-mac'].lower()
                else:
                    rule['destination']['address'] = l2_config['destination-mac'].lower()
                    rule['destination']['address_mask'] = l2_config['destination-mac-mask'].lower()
            elif l2_config.get('destination-mac'):
                rule['destination']['host'] = l2_config['destination-mac'].lower()
            else:
                rule['destination']['any'] = True

            if l2_config.get('ethertype'):
                ethertype = l2_config['ethertype']
                rule['ethertype'] = {}
                if isinstance(ethertype, str):
                    ethertype = ethertype.split(':')[-1]
                    if ethertype in ethertype_payload_to_protocol_map:
                        rule['ethertype'][ethertype_payload_to_protocol_map[ethertype]] = True
                    else:
                        rule['ethertype']['value'] = ethertype_payload_to_value_map[ethertype]
                else:
                    ethertype = ETHERTYPE_FORMAT.format(ethertype)
                    if ethertype in ethertype_payload_to_protocol_map:
                        rule['ethertype'][ethertype_payload_to_protocol_map[ethertype]] = True
                    else:
                        rule['ethertype']['value'] = ethertype

            if l2_config.get('openconfig-acl-ext:vlanid'):
                rule['vlan_id'] = l2_config['openconfig-acl-ext:vlanid']
            if l2_config.get('openconfig-acl-ext:vlan-tag-format') == 'openconfig-acl-ext:MULTI_TAGGED':
                rule['vlan_tag_format'] = {'multi_tagged': True}

            if l2_config.get('openconfig-acl-ext:dei') is not None:
                rule['dei'] = l2_config['openconfig-acl-ext:dei']

            if l2_config.get('openconfig-acl-ext:pcp') is not None:
                rule['pcp'] = {}
                if l2_config.get('openconfig-acl-ext:pcp-mask') is not None:
                    rule['pcp']['value'] = l2_config['openconfig-acl-ext:pcp']
                    rule['pcp']['mask'] = l2_config['openconfig-acl-ext:pcp-mask']
                else:
                    rule['pcp']['traffic_type'] = pcp_value_to_traffic_map[l2_config['openconfig-acl-ext:pcp']]

        return config

    def get_l2_acls(self):
        """Get all l2 acl configurations available in chassis"""
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

        l2_acls_configs = []
        for acl in acls:
            acl_config = {}
            acl_rules = []

            config = acl['config']
            if config.get('type') not in ('ACL_L2', 'openconfig-acl:ACL_L2'):
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

                acl_rules.append(acl_rule)

            l2_acls_configs.append(acl_config)

        return l2_acls_configs
