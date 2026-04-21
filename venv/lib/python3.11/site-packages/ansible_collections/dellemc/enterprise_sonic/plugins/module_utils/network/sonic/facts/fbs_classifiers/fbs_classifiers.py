#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic fbs_classifiers fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.fbs_classifiers.fbs_classifiers import Fbs_classifiersArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


enum_dict = {
    'openconfig-acl:ACL_IPV4': 'ip',
    'openconfig-acl:ACL_IPV6': 'ipv6',
    'openconfig-acl:ACL_L2': 'mac',
    'openconfig-fbs-ext:MATCH_ACL': 'acl',
    'openconfig-fbs-ext:MATCH_FIELDS': 'fields',
    'openconfig-packet-match-types:ETHERTYPE_ARP': 'arp',
    'openconfig-packet-match-types:ETHERTYPE_IPV4': 'ipv4',
    'openconfig-packet-match-types:ETHERTYPE_IPV6': 'ipv6',
    'openconfig-packet-match-types:ETHERTYPE_LLDP': 'lldp',
    'openconfig-packet-match-types:ETHERTYPE_MPLS': 'mpls',
    'openconfig-packet-match-types:ETHERTYPE_ROCE': 'roce',
    'openconfig-packet-match-types:ETHERTYPE_VLAN': 'vlan',
    'openconfig-packet-match-types:IP_AUTH': 'auth',
    'openconfig-packet-match-types:IP_GRE': 'gre',
    'openconfig-packet-match-types:IP_ICMP': 'icmp',
    'openconfig-packet-match-types:IP_IGMP': 'igmp',
    'openconfig-packet-match-types:IP_L2TP': 'l2tp',
    'openconfig-packet-match-types:IP_PIM': 'pim',
    'openconfig-packet-match-types:IP_RSVP': 'rsvp',
    'openconfig-packet-match-types:IP_TCP': 'tcp',
    'openconfig-packet-match-types:IP_UDP': 'udp',
    'openconfig-packet-match-types:TCP_ACK': 'ack',
    'openconfig-packet-match-types:TCP_FIN': 'fin',
    'openconfig-packet-match-types:TCP_PSH': 'psh',
    'openconfig-packet-match-types:TCP_RST': 'rst',
    'openconfig-packet-match-types:TCP_SYN': 'syn',
    'openconfig-packet-match-types:TCP_URG': 'urg',
    58: 'icmpv6'
}


class Fbs_classifiersFacts(object):
    """ The sonic fbs_classifiers fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Fbs_classifiersArgs.argument_spec
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
        """ Populate the facts for fbs_classifiers
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            cfg = self.get_config(self._module)
            data = self.get_parsed_fbs_classifiers(cfg)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['fbs_classifiers'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_config(self, module):
        cfg = None
        get_path = 'data/openconfig-fbs-ext:fbs/classifiers'
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-fbs-ext:classifiers' in response[0][1]:
                cfg = response[0][1].get('openconfig-fbs-ext:classifiers')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def get_parsed_fbs_classifiers(self, cfg):
        """This method parses the OC FBS classifiers data and returns the parsed data in argspec format"""
        config_list = []

        if cfg and cfg.get('classifier'):
            for classifier in cfg['classifier']:
                classifier_dict = {}
                match_hdr_fields_dict = {}

                if classifier.get('class-name'):
                    classifier_dict['class_name'] = classifier['class-name']
                if classifier.get('config'):
                    config = classifier['config']
                    if config.get('description'):
                        classifier_dict['class_description'] = config['description']
                    if config.get('match-type'):
                        classifier_dict['match_type'] = enum_dict[config['match-type']]

                # Parse match-acl container
                if classifier.get('match-acl') and classifier['match-acl'].get('config'):
                    config = classifier['match-acl']['config']
                    match_acl_dict = {}
                    if config.get('acl-name'):
                        match_acl_dict['acl_name'] = config['acl-name']
                    if config.get('acl-type'):
                        match_acl_dict['acl_type'] = enum_dict[config['acl-type']]
                    if match_acl_dict:
                        classifier_dict['match_acl'] = match_acl_dict

                # Parse ip container
                if (classifier.get('match-hdr-fields') and classifier['match-hdr-fields'].get('ip') and
                        classifier['match-hdr-fields']['ip'].get('config')):
                    config = classifier['match-hdr-fields']['ip']['config']
                    ip_dict = {}

                    if config.get('dscp') is not None:
                        ip_dict['dscp'] = config['dscp']
                    if config.get('protocol'):
                        ip_dict['protocol'] = enum_dict[config['protocol']]
                    if ip_dict:
                        match_hdr_fields_dict['ip'] = ip_dict

                # Parse ipv4 and ipv6 containers
                ip_types = ['ipv4', 'ipv6']
                for ip in ip_types:
                    if (classifier.get('match-hdr-fields') and classifier['match-hdr-fields'].get(ip) and
                            classifier['match-hdr-fields'][ip].get('config')):
                        config = classifier['match-hdr-fields'][ip]['config']
                        ip_dict = {}

                        if config.get('destination-address'):
                            ip_dict['destination_address'] = config['destination-address']
                        if config.get('source-address'):
                            ip_dict['source_address'] = config['source-address']
                        if ip_dict:
                            match_hdr_fields_dict[ip] = ip_dict

                # Parse l2 container
                if (classifier.get('match-hdr-fields') and classifier['match-hdr-fields'].get('l2') and
                        classifier['match-hdr-fields']['l2'].get('config')):
                    config = classifier['match-hdr-fields']['l2']['config']
                    l2_dict = {}

                    if config.get('dei') is not None:
                        l2_dict['dei'] = config['dei']
                    if config.get('destination-mac'):
                        l2_dict['destination_mac'] = config['destination-mac']
                    if config.get('destination-mac-mask'):
                        l2_dict['destination_mac_mask'] = config['destination-mac-mask']
                    if config.get('ethertype'):
                        l2_dict['ethertype'] = enum_dict[config['ethertype']]
                    if config.get('source-mac'):
                        l2_dict['source_mac'] = config['source-mac']
                    if config.get('source-mac-mask'):
                        l2_dict['source_mac_mask'] = config['source-mac-mask']
                    if config.get('pcp') is not None:
                        l2_dict['pcp'] = config['pcp']
                    if config.get('vlanid'):
                        l2_dict['vlanid'] = config['vlanid']
                    if l2_dict:
                        match_hdr_fields_dict['l2'] = l2_dict

                # Parse transport container
                if (classifier.get('match-hdr-fields') and classifier['match-hdr-fields'].get('transport') and
                        classifier['match-hdr-fields']['transport'].get('config')):
                    config = classifier['match-hdr-fields']['transport']['config']
                    transport_dict = {}

                    if config.get('destination-port'):
                        transport_dict['destination_port'] = config['destination-port']
                    if config.get('icmp-code'):
                        transport_dict['icmp_code'] = config['icmp-code']
                    if config.get('icmp-type'):
                        transport_dict['icmp_type'] = config['icmp-type']
                    if config.get('source-port'):
                        transport_dict['source_port'] = config['source-port']
                    if config.get('tcp-flags'):
                        converted_flags = []
                        for flag in config['tcp-flags']:
                            converted_flags.append(enum_dict[flag])
                        transport_dict['tcp_flags'] = converted_flags
                    if transport_dict:
                        match_hdr_fields_dict['transport'] = transport_dict

                if match_hdr_fields_dict:
                    classifier_dict['match_hdr_fields'] = match_hdr_fields_dict
                if classifier_dict:
                    config_list.append(classifier_dict)

        return config_list
