#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic qos_interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible.module_utils.connection import ConnectionError
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.qos_interfaces.qos_interfaces import Qos_interfacesArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)

QOS_PATH = '/data/openconfig-qos:qos'


class Qos_interfacesFacts(object):
    """ The sonic qos_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Qos_interfacesArgs.argument_spec
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
        """ Populate the facts for qos_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []
        facts = {}

        if not data:
            data = self.update_qos_interfaces(self._module)
        objs = data
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['qos_interfaces'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def update_qos_interfaces(self, module):
        config_list = []
        interfaces = self.get_config(module, 'interfaces/interface', 'openconfig-qos:interface')
        queues = self.get_config(module, 'queues/queue', 'openconfig-qos:queue')

        if interfaces:
            for intf in interfaces:
                config_dict = {}
                if 'interface-id' in intf:
                    name = intf['interface-id']
                    config_dict['name'] = name

                if ('output' in intf and 'scheduler-policy' in intf['output'] and 'config' in intf['output']['scheduler-policy'] and 'name' in
                        intf['output']['scheduler-policy']['config']):
                    scheduler_policy = intf['output']['scheduler-policy']['config']['name']
                    config_dict['scheduler_policy'] = scheduler_policy

                if ('openconfig-qos-buffer:cable-length' in intf and
                        'config' in intf['openconfig-qos-buffer:cable-length'] and
                        'length' in intf['openconfig-qos-buffer:cable-length']['config']):
                    cable_length = intf['openconfig-qos-buffer:cable-length']['config']['length']
                    config_dict['cable_length'] = cable_length

                if 'openconfig-qos-maps-ext:interface-maps' in intf and 'config' in intf['openconfig-qos-maps-ext:interface-maps']:
                    maps_dict = {}
                    maps = intf['openconfig-qos-maps-ext:interface-maps']['config']
                    if 'dscp-to-forwarding-group' in maps:
                        dscp_fwd_group = maps['dscp-to-forwarding-group']
                        maps_dict['dscp_fwd_group'] = dscp_fwd_group
                    if 'dot1p-to-forwarding-group' in maps:
                        dot1p_fwd_group = maps['dot1p-to-forwarding-group']
                        maps_dict['dot1p_fwd_group'] = dot1p_fwd_group
                    if 'forwarding-group-to-dscp' in maps:
                        fwd_group_dscp = maps['forwarding-group-to-dscp']
                        maps_dict['fwd_group_dscp'] = fwd_group_dscp
                    if 'forwarding-group-to-dot1p' in maps:
                        fwd_group_dot1p = maps['forwarding-group-to-dot1p']
                        maps_dict['fwd_group_dot1p'] = fwd_group_dot1p
                    if 'forwarding-group-to-queue' in maps:
                        fwd_group_queue = maps['forwarding-group-to-queue']
                        maps_dict['fwd_group_queue'] = fwd_group_queue
                    if 'forwarding-group-to-priority-group' in maps:
                        fwd_group_pg = maps['forwarding-group-to-priority-group']
                        maps_dict['fwd_group_pg'] = fwd_group_pg
                    if 'pfc-priority-to-queue' in maps:
                        pfc_priority_queue = maps['pfc-priority-to-queue']
                        maps_dict['pfc_priority_queue'] = pfc_priority_queue
                    if 'pfc-priority-to-priority-group' in maps:
                        pfc_priority_pg = maps['pfc-priority-to-priority-group']
                        maps_dict['pfc_priority_pg'] = pfc_priority_pg
                    if maps_dict:
                        config_dict['qos_maps'] = maps_dict

                if 'pfc' in intf:
                    pfc_dict = {}
                    if 'config' in intf['pfc'] and 'asymmetric' in intf['pfc']['config']:
                        asymmetric = intf['pfc']['config']['asymmetric']
                        pfc_dict['asymmetric'] = asymmetric

                    if 'pfc-priorities' in intf['pfc'] and 'pfc-priority' in intf['pfc']['pfc-priorities']:
                        priorities = intf['pfc']['pfc-priorities']['pfc-priority']
                        priorities_list = []
                        for priority in priorities:
                            priority_dict = {}
                            if 'dot1p' in priority:
                                dot1p = priority['dot1p']
                                priority_dict['dot1p'] = dot1p
                            if 'config' in priority and 'enable' in priority['config']:
                                enable = priority['config']['enable']
                                priority_dict['enable'] = enable
                            if priority_dict:
                                priorities_list.append(priority_dict)
                        if priorities_list:
                            pfc_dict['priorities'] = priorities_list

                    if 'watchdog' in intf['pfc'] and 'config' in intf['pfc']['watchdog']:
                        if 'action' in intf['pfc']['watchdog']['config']:
                            watchdog_action = intf['pfc']['watchdog']['config']['action']
                            pfc_dict['watchdog_action'] = watchdog_action.lower()
                        if 'detection-time' in intf['pfc']['watchdog']['config']:
                            watchdog_detect_time = intf['pfc']['watchdog']['config']['detection-time']
                            pfc_dict['watchdog_detect_time'] = watchdog_detect_time
                        if 'restoration-time' in intf['pfc']['watchdog']['config']:
                            watchdog_restore_time = intf['pfc']['watchdog']['config']['restoration-time']
                            pfc_dict['watchdog_restore_time'] = watchdog_restore_time

                    if pfc_dict:
                        config_dict['pfc'] = pfc_dict

                if queues:
                    queues_list = []
                    for queue in queues:
                        if 'name' in queue:
                            queue_name = queue['name'].split(':')[0]
                            if name == queue_name:
                                queue_dict = {}
                                queue_id = queue['name'].split(':')[1]
                                queue_dict['id'] = int(queue_id)
                                if 'wred' in queue and 'config' in queue['wred'] and 'wred-profile' in queue['wred']['config']:
                                    wred_profile = queue['wred']['config']['wred-profile']
                                    queue_dict['wred_profile'] = wred_profile
                                if queue_dict:
                                    queues_list.append(queue_dict)
                    if queues_list:
                        config_dict['queues'] = queues_list

                if config_dict:
                    config_list.append(config_dict)

        return config_list

    def get_config(self, module, path, list_name):
        cfg = None
        get_path = '%s/%s' % (QOS_PATH, path)
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if list_name in response[0][1]:
                cfg = response[0][1].get(list_name)
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg
