#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic stp fact class
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
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.stp.stp import StpArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


stp_map = {
    'openconfig-spanning-tree-types:EDGE_ENABLE': True,
    'openconfig-spanning-tree-types:EDGE_DISABLE': False,
    'openconfig-spanning-tree-types:MSTP': 'mst',
    'openconfig-spanning-tree-ext:PVST': 'pvst',
    'openconfig-spanning-tree-types:RAPID_PVST': 'rapid_pvst',
    'P2P': 'point-to-point',
    'SHARED': 'shared',
    'LOOP': 'loop',
    'ROOT': 'root',
    'NONE': 'none'
}


class StpFacts(object):
    """ The sonic stp fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = StpArgs.argument_spec
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
        """ Populate the facts for stp
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            stp_cfg = self.get_stp_config(self._module)
            data = self.update_stp(stp_cfg)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['stp'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def update_stp(self, data):
        config_dict = {}
        if data:
            global_ = self.update_global(data)
            interfaces = self.update_interfaces(data)
            mstp = self.update_mstp(data)
            pvst = self.update_pvst(data)
            rapid_pvst = self.update_rapid_pvst(data)

            if global_:
                config_dict['global'] = global_
            if interfaces:
                config_dict['interfaces'] = interfaces
            if mstp:
                config_dict['mstp'] = mstp
            if pvst:
                config_dict['pvst'] = pvst
            if rapid_pvst:
                config_dict['rapid_pvst'] = rapid_pvst

        return config_dict

    def update_global(self, data):
        global_dict = {}
        stp_global = data.get('global')

        if stp_global:
            config = stp_global.get('config')
            if config:
                enabled_protocol = config.get('enabled-protocol')
                loop_guard = config.get('loop-guard')
                bpdu_filter = config.get('bpdu-filter')
                disabled_vlans = config.get('openconfig-spanning-tree-ext:disabled-vlans')
                root_guard_timeout = config.get('openconfig-spanning-tree-ext:rootguard-timeout')
                portfast = config.get('openconfig-spanning-tree-ext:portfast')
                hello_time = config.get('openconfig-spanning-tree-ext:hello-time')
                max_age = config.get('openconfig-spanning-tree-ext:max-age')
                fwd_delay = config.get('openconfig-spanning-tree-ext:forwarding-delay')
                bridge_priority = config.get('openconfig-spanning-tree-ext:bridge-priority')

            if enabled_protocol:
                global_dict['enabled_protocol'] = stp_map[enabled_protocol[0]]
            if loop_guard is not None:
                global_dict['loop_guard'] = loop_guard
            if bpdu_filter is not None:
                global_dict['bpdu_filter'] = bpdu_filter
            if disabled_vlans:
                global_dict['disabled_vlans'] = self.convert_vlans_list(disabled_vlans)
            if root_guard_timeout:
                global_dict['root_guard_timeout'] = root_guard_timeout
            if portfast is not None:
                global_dict['portfast'] = portfast
            if hello_time:
                global_dict['hello_time'] = hello_time
            if max_age:
                global_dict['max_age'] = max_age
            if fwd_delay:
                global_dict['fwd_delay'] = fwd_delay
            if bridge_priority is not None:
                global_dict['bridge_priority'] = bridge_priority

        return global_dict

    def update_interfaces(self, data):
        interfaces_list = []
        interfaces = data.get('interfaces')

        if interfaces:
            intf_list = interfaces.get('interface')
            if intf_list:
                for intf in intf_list:
                    intf_dict = {}
                    config = intf.get('config')
                    intf_name = config.get('name')
                    edge_port = config.get('edge-port')
                    link_type = config.get('link-type')
                    guard = config.get('guard')
                    bpdu_guard = config.get('bpdu-guard')
                    bpdu_filter = config.get('bpdu-filter')
                    portfast = config.get('openconfig-spanning-tree-ext:portfast')
                    uplink_fast = config.get('openconfig-spanning-tree-ext:uplink-fast')
                    shutdown = config.get('openconfig-spanning-tree-ext:bpdu-guard-port-shutdown')
                    cost = config.get('openconfig-spanning-tree-ext:cost')
                    port_priority = config.get('openconfig-spanning-tree-ext:port-priority')
                    stp_enable = config.get('openconfig-spanning-tree-ext:spanning-tree-enable')

                    if intf_name:
                        intf_dict['intf_name'] = intf_name
                    if edge_port is not None:
                        intf_dict['edge_port'] = stp_map[edge_port]
                    if link_type:
                        intf_dict['link_type'] = stp_map[link_type]
                    if guard:
                        intf_dict['guard'] = stp_map[guard]
                    if bpdu_guard is not None:
                        intf_dict['bpdu_guard'] = bpdu_guard
                    if bpdu_filter is not None:
                        intf_dict['bpdu_filter'] = bpdu_filter
                    if portfast is not None:
                        intf_dict['portfast'] = portfast
                    if uplink_fast is not None:
                        intf_dict['uplink_fast'] = uplink_fast
                    if shutdown is not None:
                        intf_dict['shutdown'] = shutdown
                    if cost:
                        intf_dict['cost'] = cost
                    if port_priority is not None:
                        intf_dict['port_priority'] = port_priority
                    if stp_enable is not None:
                        intf_dict['stp_enable'] = stp_enable
                    if intf_dict:
                        interfaces_list.append(intf_dict)

        return interfaces_list

    def update_mstp(self, data):
        mstp_dict = {}
        mstp = data.get('mstp')

        if mstp:
            config = mstp.get('config')
            mst_instances = mstp.get('mst-instances')
            interfaces = mstp.get('interfaces')
            if config:
                mst_name = config.get('name')
                revision = config.get('revision')
                max_hop = config.get('max-hop')
                hello_time = config.get('hello-time')
                max_age = config.get('max-age')
                fwd_delay = config.get('forwarding-delay')

                if mst_name:
                    mstp_dict['mst_name'] = mst_name
                if revision:
                    mstp_dict['revision'] = revision
                if max_hop:
                    mstp_dict['max_hop'] = max_hop
                if hello_time:
                    mstp_dict['hello_time'] = hello_time
                if max_age:
                    mstp_dict['max_age'] = max_age
                if fwd_delay:
                    mstp_dict['fwd_delay'] = fwd_delay

            if mst_instances:
                mst_instance = mst_instances.get('mst-instance')
                if mst_instance:
                    mst_instances_list = []
                    for inst in mst_instance:
                        inst_dict = {}
                        mst_id = inst.get('mst-id')
                        config = inst.get('config')
                        interfaces = inst.get('interfaces')
                        if mst_id is not None:
                            inst_dict['mst_id'] = mst_id
                        if interfaces:
                            intf_list = self.get_interfaces_list(interfaces)
                            if intf_list:
                                inst_dict['interfaces'] = intf_list
                        if config:
                            vlans = config.get('vlan')
                            bridge_priority = config.get('bridge-priority')
                            if vlans:
                                inst_dict['vlans'] = self.convert_vlans_list(vlans)
                            if bridge_priority is not None:
                                inst_dict['bridge_priority'] = bridge_priority
                        if inst_dict:
                            mst_instances_list.append(inst_dict)
                    if mst_instances_list:
                        mstp_dict['mst_instances'] = mst_instances_list

        return mstp_dict

    def update_pvst(self, data):
        pvst_list = []
        pvst = data.get('openconfig-spanning-tree-ext:pvst')

        if pvst:
            vlans = pvst.get('vlans')
            if vlans:
                vlans_list = self.get_vlans_list(vlans)
                if vlans_list:
                    pvst_list = vlans_list

        return pvst_list

    def update_rapid_pvst(self, data):
        rapid_pvst_list = []
        rapid_pvst = data.get('rapid-pvst')

        if rapid_pvst:
            vlans = rapid_pvst.get('vlan')
            if vlans:
                vlans_list = self.get_vlans_list(vlans)
                if vlans_list:
                    rapid_pvst_list = vlans_list

        return rapid_pvst_list

    def get_stp_config(self, module):
        stp_cfg = None
        get_stp_path = '/data/openconfig-spanning-tree:stp'
        request = {'path': get_stp_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            stp_cfg = response[0][1].get('openconfig-spanning-tree:stp')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return stp_cfg

    def get_interfaces_list(self, data):
        intf_list = []
        interface_list = data.get('interface')

        if interface_list:
            for intf in interface_list:
                intf_dict = {}
                config = intf.get('config')
                if config:
                    intf_name = config.get('name')
                    cost = config.get('cost')
                    port_priority = config.get('port-priority')

                    if intf_name:
                        intf_dict['intf_name'] = intf_name
                    if cost:
                        intf_dict['cost'] = cost
                    if port_priority is not None:
                        intf_dict['port_priority'] = port_priority
                    if intf_dict:
                        intf_list.append(intf_dict)

        return intf_list

    def get_vlans_list(self, data):
        vlan_list = []

        for vlan in data:
            vlan_dict = {}
            vlan_id = vlan.get('vlan-id')
            config = vlan.get('config')
            interfaces = vlan.get('interfaces')

            if vlan_id:
                vlan_dict['vlan_id'] = vlan_id
            if interfaces:
                intf_list = self.get_interfaces_list(interfaces)
                if intf_list:
                    vlan_dict['interfaces'] = intf_list
            if config:
                hello_time = config.get('hello-time')
                max_age = config.get('max-age')
                fwd_delay = config.get('forwarding-delay')
                bridge_priority = config.get('bridge-priority')

                if hello_time:
                    vlan_dict['hello_time'] = hello_time
                if max_age:
                    vlan_dict['max_age'] = max_age
                if fwd_delay:
                    vlan_dict['fwd_delay'] = fwd_delay
                if bridge_priority is not None:
                    vlan_dict['bridge_priority'] = bridge_priority
            if vlan_dict:
                vlan_list.append(vlan_dict)

        return vlan_list

    def convert_vlans_list(self, vlans):
        converted_vlans = []

        for vlan in vlans:
            if isinstance(vlan, int):
                converted_vlans.append(str(vlan))

            else:
                converted_vlans.append(vlan.replace('..', '-'))

        return converted_vlans
