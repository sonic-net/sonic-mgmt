#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic fbs_policies fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.fbs_policies.fbs_policies import Fbs_policiesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

enum_dict = {
    'openconfig-fbs-ext:NEXT_HOP_GROUP_TYPE_IPV4': 'ipv4',
    'openconfig-fbs-ext:NEXT_HOP_GROUP_TYPE_IPV6': 'ipv6',
    'openconfig-fbs-ext:REPLICATION_GROUP_TYPE_IPV4': 'ipv4',
    'openconfig-fbs-ext:REPLICATION_GROUP_TYPE_IPV6': 'ipv6',
    'openconfig-fbs-ext:POLICY_COPP': 'copp',
    'openconfig-fbs-ext:POLICY_FORWARDING': 'forwarding',
    'openconfig-fbs-ext:POLICY_MONITORING': 'monitoring',
    'openconfig-fbs-ext:POLICY_QOS': 'qos',
}


class Fbs_policiesFacts(object):
    """
    The sonic fbs_policies fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Fbs_policiesArgs.argument_spec
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
        """
        Populate the facts for fbs_policies
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            cfg = self.get_config(self._module)
            data = self.get_parsed_fbs_policies(cfg)
        facts = {}
        if data:
            params = utils.validate_config(self.argument_spec, {'config': data})
            facts['fbs_policies'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_config(self, module):
        cfg = None
        get_path = 'data/openconfig-fbs-ext:fbs/policies'
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-fbs-ext:policies' in response[0][1]:
                cfg = response[0][1].get('openconfig-fbs-ext:policies')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def get_parsed_fbs_policies(self, cfg):
        """This method parses the OC FBS policies data and returns the parsed data in argspec format"""
        config_list = []

        if cfg and cfg.get('policy'):
            for policy in cfg['policy']:
                policy_dict = {}
                if policy.get('policy-name'):
                    policy_dict['policy_name'] = policy['policy-name']
                if policy.get('config'):
                    config = policy['config']
                    if config.get('description'):
                        policy_dict['policy_description'] = config['description']
                    if config.get('type'):
                        policy_dict['policy_type'] = enum_dict[config['type']]
                        if policy_dict['policy_type'] == 'copp' and policy_dict['policy_name'] != 'copp-system-policy':
                            policy_dict['policy_type'] = 'acl-' + policy_dict['policy_type']

                # Parse sections container
                if policy.get('sections') and policy['sections'].get('section'):
                    sections = policy['sections']['section']
                    sections_list = []
                    for section in sections:
                        section_dict = {}
                        if section.get('class'):
                            section_dict['class'] = section['class']
                        if section.get('config'):
                            config = section['config']
                            if config.get('description'):
                                section_dict['section_description'] = config['description']
                            if config.get('priority') is not None:
                                section_dict['priority'] = config['priority']

                        # Parse qos container
                        if section.get('qos'):
                            qos = section['qos']
                            qos_dict = {}
                            if qos.get('remark') and qos['remark'].get('config'):
                                config = qos['remark']['config']
                                remark_dict = {}

                                if config.get('set-dot1p') is not None:
                                    remark_dict['set_dot1p'] = config['set-dot1p']
                                if config.get('set-dscp') is not None:
                                    remark_dict['set_dscp'] = config['set-dscp']
                                if remark_dict:
                                    qos_dict['remark'] = remark_dict
                            if qos.get('queuing') and qos['queuing'].get('config') and qos['queuing']['config'].get('output-queue-index') is not None:
                                qos_dict['output_queue_index'] = qos['queuing']['config']['output-queue-index']
                            if qos.get('policer') and qos['policer'].get('config'):
                                qos_dict['policer'] = qos['policer']['config']
                            if qos_dict:
                                section_dict['qos'] = qos_dict

                        # Parse copp container
                        if section.get('copp'):
                            copp = section['copp']
                            copp_dict = {}
                            if copp.get('config') and copp['config'].get('cpu-queue-index') is not None:
                                copp_dict['cpu_queue_index'] = copp['config']['cpu-queue-index']
                            if copp.get('policer') and copp['policer'].get('config'):
                                copp_dict['policer'] = copp['policer']['config']
                            if copp_dict:
                                section_dict['acl_copp'] = copp_dict

                        # Parse mirror-sessions container
                        if (section.get('monitoring') and section['monitoring'].get('mirror-sessions') and
                                section['monitoring']['mirror-sessions'].get('mirror-session') is not None):
                            mirror_session = section['monitoring']['mirror-sessions']['mirror-session']
                            mirror_sessions_list = []
                            for session in mirror_session:
                                if session.get('session-name'):
                                    mirror_sessions_list.append({'session_name': session['session-name']})
                            if mirror_sessions_list:
                                section_dict['mirror_sessions'] = mirror_sessions_list

                        # Parse forwarding container
                        if section.get('forwarding'):
                            forwarding = section['forwarding']
                            forwarding_dict = {}

                            # Parse egress-interfaces container
                            if forwarding.get('egress-interfaces') and forwarding['egress-interfaces'].get('egress-interface') is not None:
                                egress_interface = forwarding['egress-interfaces']['egress-interface']
                                egress_interfaces_list = []
                                for intf in egress_interface:
                                    intf_dict = {}
                                    if intf.get('intf-name'):
                                        intf_dict['intf_name'] = intf['intf-name']
                                    if intf.get('config') and intf['config'].get('priority'):
                                        intf_dict['priority'] = intf['config']['priority']
                                    if intf_dict:
                                        egress_interfaces_list.append(intf_dict)
                                if egress_interfaces_list:
                                    forwarding_dict['egress_interfaces'] = egress_interfaces_list

                            # Parse next-hops container
                            if forwarding.get('next-hops') and forwarding['next-hops'].get('next-hop') is not None:
                                next_hop = forwarding['next-hops']['next-hop']
                                next_hops_list = []
                                for hop in next_hop:
                                    hop_dict = {}
                                    if hop.get('ip-address'):
                                        hop_dict['address'] = hop['ip-address']
                                    if hop.get('network-instance') and hop['network-instance'] != 'openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE':
                                        hop_dict['vrf'] = hop['network-instance']
                                    if hop.get('config') and hop['config'].get('priority'):
                                        hop_dict['priority'] = hop['config']['priority']
                                    if hop_dict:
                                        next_hops_list.append(hop_dict)
                                if next_hops_list:
                                    forwarding_dict['next_hops'] = next_hops_list

                            # Parse next-hop-groups and replication-groups containers
                            group_items = ['next-hop-group', 'replication-group']
                            for item in group_items:
                                if forwarding.get(item + 's') and forwarding[item + 's'].get(item) is not None:
                                    groups = forwarding[item + 's'][item]
                                    groups_list = []
                                    for group in groups:
                                        group_dict = {}
                                        if group.get('group-name'):
                                            group_dict['group_name'] = group['group-name']
                                        if group.get('config'):
                                            config = group['config']
                                            if config.get('group-type'):
                                                group_dict['group_type'] = enum_dict[config['group-type']]
                                            if config.get('priority'):
                                                group_dict['priority'] = config['priority']
                                        if group_dict:
                                            groups_list.append(group_dict)
                                    if groups_list:
                                        groups_list_name = item.replace('-', '_') + 's'
                                        forwarding_dict[groups_list_name] = groups_list

                            # Parse ars container
                            if forwarding.get('ars') and forwarding['ars'].get('config') and forwarding['ars']['config'].get('disable'):
                                forwarding_dict['ars_disable'] = forwarding['ars']['config']['disable']
                            else:
                                # Functional default
                                forwarding_dict['ars_disable'] = False

                            if forwarding_dict:
                                section_dict['forwarding'] = forwarding_dict
                        else:
                            # Functional default
                            section_dict['forwarding'] = {'ars_disable': False}
                        if section_dict:
                            sections_list.append(section_dict)
                    if sections_list:
                        policy_dict['sections'] = sections_list
                if policy_dict:
                    config_list.append(policy_dict)

        return config_list
