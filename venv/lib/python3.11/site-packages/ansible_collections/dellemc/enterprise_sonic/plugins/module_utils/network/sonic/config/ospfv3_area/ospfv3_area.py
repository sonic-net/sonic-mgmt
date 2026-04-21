#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_ospfv3_area class
It is in this file where the current configuration (as list)
is compared to the provided configuration (as list) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
    validate_config,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils \
    import (
        get_diff,
        update_states,
        to_request,
        edit_config,
        remove_empties,
        remove_empties_from_list
    )
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_none
)


OSPF_URI = "data/openconfig-network-instance:network-instances/network-instance={vrf_name}/protocols/protocol=OSPF3,ospfv3/ospfv3"
OSPF_KEY_EXT = "openconfig-ospfv3-ext:"
OSPF_AREA_GLOBAL_URI = "/global/openconfig-ospfv3-ext:inter-area-propagation-policies/inter-area-policy={area_id}"
OSPF_AREA_ATTRIBUTES = {
    'area_id': "/areas/area={area_id}",
    'filter_list_in': OSPF_AREA_GLOBAL_URI + "/filter-list-in/config/name",
    'filter_list_out': OSPF_AREA_GLOBAL_URI + "/filter-list-out/config/name",
    'nssa': {
        'enabled': "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/config/enable",
        'no_summary': "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/config/no-summary",
        'default_originate': {
            'enabled': "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/config/default-route-originate",
            'metric': "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/config/default-route-metric",
            'metric_type': "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/config/default-route-metric-type"
        },
        'ranges': {
            'advertise': "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/ranges/range={address_prefix}/config/advertise",
            'prefix': "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/ranges/range={address_prefix}/config/address-prefix",
            'cost': "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/ranges/range={address_prefix}/config/cost"
        }
    },
    'stub': {
        'enabled': "/areas/area={area_id}/openconfig-ospfv3-ext:stub/config/enable",
        'no_summary': "/areas/area={area_id}/openconfig-ospfv3-ext:stub/config/no-summary",
    },
    'ranges': {
        'advertise': OSPF_AREA_GLOBAL_URI + "/ranges/range={address_prefix}/config/advertise",
        'prefix': OSPF_AREA_GLOBAL_URI + "/ranges/range={address_prefix}/config/address-prefix",
        'cost': OSPF_AREA_GLOBAL_URI + "/ranges/range={address_prefix}/config/metric"
    }
}


class Ospfv3_area(ConfigBase):
    """
    The sonic_ospfv3_area class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ospfv3_area',
    ]

    TEST_KEYS = [
        {"config": {"area_id": "", "vrf_name": ""}},
        {"ranges": {"prefix": ""}}
    ]

    def __init__(self, module):
        super(Ospfv3_area, self).__init__(module)

    def get_ospfv3_area_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A list
        :returns: The current configuration as a list of areas' config
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ospfv3_area_facts = facts['ansible_network_resources'].get('ospfv3_area')
        return ospfv3_area_facts["config"] if ospfv3_area_facts else []

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        commands = []
        existing_ospfv3_area_facts = self.get_ospfv3_area_facts()
        commands, requests = self.set_config(existing_ospfv3_area_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        result['before'] = existing_ospfv3_area_facts
        new_config = deepcopy(existing_ospfv3_area_facts)

        if self._module.check_mode:
            new_config = self.get_new_config(commands, existing_ospfv3_area_facts)
            new_config.sort(key=lambda x: (x['vrf_name'], x['area_id']))
            result['after(generated)'] = new_config
        elif result['changed']:
            new_config = self.get_ospfv3_area_facts()
            new_config.sort(key=lambda x: (x['vrf_name'], x['area_id']))
            result['after'] = new_config
        if self._module._diff:
            existing_ospfv3_area_facts.sort(key=lambda x: (x['vrf_name'], x['area_id']))
            result['config_diff'] = get_formatted_config_diff(existing_ospfv3_area_facts,
                                                              new_config,
                                                              self._module._verbosity)
        return result

    def set_config(self, existing_ospfv3_area_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        have = existing_ospfv3_area_facts

        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a list
        :param have: the current configuration as a list
        :rtype: A tuple
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration, and REST requests that do it
        """
        commands, requests = [], []
        state = self._module.params['state']
        want = self.validate_normalize_config(want, have, state)
        if state in ('overridden', 'replaced'):
            commands, requests = self._state_replaced_or_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :rtype: A tuple of lists
        :returns: A list of the commands and state needed to merge the user-specified
                  new and modified configuration commands into the current
                  configuration, and a list of the corresponding requests that
                  need to be sent to the device to make the specified changes
        """
        commands = remove_empties_from_list(get_diff(want, have, self.TEST_KEYS))
        requests = self.create_ospfv3_area_requests_from_commands(commands)

        commands = update_states(commands, 'merged') if commands and len(requests) > 0 else []
        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :rtype: A tuple of lists
        :returns: A list of the commands and state needed to delete the user-specified
                  configuration commands from the current
                  configuration, and a list of the corresponding requests that
                  need to be sent to the device to make the specified changes
        """
        commands, requests = [], []
        is_delete_all = False
        if not want:
            new_want = have
            is_delete_all = True
        else:
            new_want = want

        commands, requests = self.get_delete_ospfv3_area_requests_commands(new_want, have, is_delete_all)

        commands = update_states(commands, 'deleted') if commands and len(requests) > 0 else []
        return commands, requests

    def _state_replaced_or_overridden(self, want, have):
        """ The command generator when state is replaced or overridden

        :rtype: A tuple of lists
        :returns: A list of what commands and state necessary to migrate the current configuration
                  to the desired configuration, and a list of requests needed to make changes
        """
        commands, requests = [], []
        state = self._module.params['state']
        new_want = self._add_default_values(want)
        add_config, del_config = self._get_replaced_overridden_config(new_want, have, state)
        if del_config and len(del_config) > 0:
            del_requests = self.delete_ospfv3_area_requests_from_commands(del_config, have)
            if len(del_requests) > 0:
                requests.extend(del_requests)
                commands.extend(update_states(del_config, 'deleted'))

        if add_config:
            mod_requests = self.create_ospfv3_area_requests_from_commands(add_config)
            if len(mod_requests) > 0:
                requests.extend(mod_requests)
                commands.extend(update_states(add_config, state))
        return commands, requests

    def _add_default_values(self, conf):
        for config in conf:
            if 'ranges' in config:
                for range_item in config['ranges']:
                    if 'advertise' not in range_item:
                        range_item['advertise'] = True
            if 'nssa' in config and 'ranges' in config['nssa']:
                for range_item in config['nssa']['ranges']:
                    if 'advertise' not in range_item:
                        range_item['advertise'] = True
        return conf

    def validate_normalize_config(self, config, have, state):
        '''validates config and and normalizes format of data. Normalization includes formatting area id, checking setting default cost,
        and filling in auth key information.
        :returns: config object that has been validated and normalized'''
        if not config:
            return []
        config = {"config": config}
        config = remove_none(config)
        # validate_config returns validated user input config. The returned data is based on the
        # argspec definition. At each nested level of the argspec for which the user has specified
        # one or more attributes, the returned data contains added nulls for any attributes that
        # were not specified by the user input.
        config = validate_config(self._module.argument_spec, config)
        # not really using the none values in this module so getting thrown out. Use empty lists for clear
        config = remove_none(config)["config"]
        for area in config:
            try:
                area['area_id'] = self.format_area_name(area['area_id'])
            except Exception as exc:
                self._module.fail_json(msg=str(exc))

            if state != "deleted":
                match_have = next((cfg for cfg in have if cfg['vrf_name'] == area['vrf_name'] and cfg['area_id'] == area['area_id']), None)

                for range_item in area.get('ranges', []):
                    prefix = range_item.get('prefix')
                    if match_have:
                        match_range = next((cfg for cfg in match_have.get('ranges', []) if cfg['prefix'] == prefix), None)
                        if 'advertise' not in range_item:
                            range_item['advertise'] = True if 'cost' in range_item or not match_range else match_range.get('advertise', True)
                    elif 'advertise' not in range_item or 'cost' in range_item:
                        range_item['advertise'] = True
                if area.get('nssa', {}):
                    for range_item in area['nssa'].get('ranges', []):
                        prefix = range_item.get('prefix')
                        if match_have:
                            match_range = next((cfg for cfg in match_have.get('nssa', {}).get('ranges', []) if cfg['prefix'] == prefix), None)
                            if 'advertise' not in range_item:
                                range_item['advertise'] = True if 'cost' in range_item or not match_range else match_range.get('advertise', True)
                        elif 'advertise' not in range_item or 'cost' in range_item:
                            range_item['advertise'] = True
        return config

    def format_area_name(self, area_id):
        """area names in playbook can be single numbers or as four octet numbers, switch works with area names as the latter.
        make sure things are in octect format by applying formatting where needed"""
        if area_id.count(".") < 3:
            area_int = int(area_id)
            return ".".join([str(area_int >> 24 & 0xff), str(area_int >> 16 & 0xff), str(area_int >> 8 & 0xff), str(area_int & 0xff)])
        return area_id

    def get_delete_ospfv3_area_requests_commands(self, want, have, is_delete_all):
        commands, requests = [], []

        for cmd in want:
            vrf_name = cmd.get('vrf_name')
            area_id = cmd.get('area_id')
            match_have = next((cfg for cfg in have if cfg['vrf_name'] == vrf_name and cfg['area_id'] == area_id), None)

            if not match_have:
                continue

            if is_delete_all or len(cmd) == 2:
                commands.append({'vrf_name': vrf_name, 'area_id': area_id})
                continue

            del_cmd = {}
            raw_delete_diff = get_diff(cmd, match_have)
            if not raw_delete_diff:
                del_cmd = get_diff(cmd, raw_delete_diff)
            else:
                for attr, value in cmd.items():
                    if attr in ['vrf_name', 'area_id']:
                        continue
                    if attr not in match_have:
                        continue
                    match_value = match_have[attr]

                    if attr in ['filter_list_in', 'filter_list_out']:
                        if value == match_value:
                            del_cmd[attr] = match_value
                    elif attr in ['nssa', 'stub']:
                        if len(value) == 1:
                            del_cmd[attr] = {'enabled': True}
                        elif 'no_summary' in value and 'no_summary' in match_value:
                            if value['no_summary'] == match_value['no_summary']:
                                del_cmd.setdefault(attr, {}).setdefault('no_summary', match_value['no_summary'])
                        elif 'default_originate' in value and 'default_originate' in match_value:
                            raw_delete_diff = get_diff(value['default_originate'], match_value['default_originate'])
                            if not raw_delete_diff:
                                del_cmd.setdefault(attr, {})['default_originate'] = {'enabled': True}
                            else:
                                filtered_delete_diff = get_diff(value['default_originate'], raw_delete_diff)
                                if filtered_delete_diff:
                                    del_cmd.setdefault(attr, {})['default_originate'] = filtered_delete_diff
                                    del_cmd[attr]['default_originate']['enabled'] = True
                        elif 'ranges' in value and 'ranges' in match_value:
                            range_cmd = self.get_delete_ospfv3_area_ranges_commands(value['ranges'], match_value['ranges'])
                            if range_cmd:
                                del_cmd.setdefault(attr, {})['ranges'] = range_cmd
                        if del_cmd.get(attr):
                            del_cmd.setdefault(attr, {})['enabled'] = True
                    elif attr == 'ranges':
                        range_cmd = self.get_delete_ospfv3_area_ranges_commands(value, match_value)
                        if range_cmd:
                            del_cmd[attr] = range_cmd
            if del_cmd:
                del_cmd['vrf_name'] = vrf_name
                del_cmd['area_id'] = area_id
                commands.append(del_cmd)

        if commands:
            requests = self.delete_ospfv3_area_requests_from_commands(commands, have, is_delete_all)

        return commands, requests

    def get_delete_ospfv3_area_ranges_commands(self, want_ranges, have_ranges):
        commands = []
        if len(want_ranges) == 0:
            for range_item in have_ranges:
                commands.append({'prefix': range_item.get('prefix')})
            return commands

        for range_item in want_ranges:
            prefix = range_item.get('prefix')
            match_have_range = next((cfg for cfg in have_ranges if cfg['prefix'] == prefix), None)
            if match_have_range:
                raw_delete_diff = get_diff(range_item, match_have_range)
                reverse_delete_diff = get_diff(match_have_range, range_item)
                if not raw_delete_diff and not reverse_delete_diff or (len(range_item) == 1):
                    commands.append({'prefix': prefix})
                else:
                    del_cmd = {}
                    if 'cost' in range_item and 'cost' in match_have_range and range_item['cost'] == match_have_range['cost']:
                        del_cmd['cost'] = match_have_range.get('cost')
                    elif ('advertise' in range_item and not range_item['advertise']):
                        if ('advertise' in match_have_range and range_item['advertise'] == match_have_range['advertise']):
                            del_cmd['advertise'] = match_have_range.get('advertise')
                    if del_cmd:
                        del_cmd['prefix'] = prefix
                        commands.append(del_cmd)
        return commands

    def _get_replaced_overridden_config(self, want, have, state):
        add_config, del_config = [], []

        for conf in want:
            vrf_name = conf.get('vrf_name')
            area_id = conf.get('area_id')
            match_have = next((cfg for cfg in have if cfg['vrf_name'] == vrf_name and cfg['area_id'] == area_id), None)

            if not match_have:
                add_config.append(conf)
                continue

            add_cfg, del_cfg = {}, {}
            for attr, value in conf.items():
                if attr in ['vrf_name', 'area_id']:
                    continue

                match_value = match_have.get(attr)

                if attr in ['filter_list_in', 'filter_list_out']:
                    if value != match_value:
                        add_cfg[attr] = value
                elif attr == 'ranges':
                    if match_value is None:
                        add_cfg[attr] = value
                    else:
                        add_range, del_range = self._get_diff_in_ranges(value, match_value)
                        if add_range:
                            add_cfg[attr] = add_range
                        if del_range:
                            del_cfg[attr] = del_range
                elif attr == 'nssa':
                    if 'stub' in match_have:
                        del_cfg['stub'] = {'enabled': True}
                        add_cfg[attr] = value
                        continue
                    elif attr not in match_have:
                        add_cfg[attr] = value
                        continue
                    match_value = match_have[attr]
                    if 'no_summary' in value:
                        if 'no_summary' in match_value and value['no_summary'] != match_value['no_summary']:
                            add_cfg.setdefault(attr, {})['no_summary'] = value['no_summary']
                        elif 'default_originate' in match_value:
                            del_cfg.setdefault(attr, {})['default_originate'] = {'enabled': True}
                            add_cfg.setdefault(attr, {})['no_summary'] = value['no_summary']
                    elif 'default_originate' in value:
                        if 'no_summary' in match_value:
                            del_cfg.setdefault(attr, {})['no_summary'] = match_value
                            add_cfg.setdefault(attr, {})['default_originate'] = value['default_originate']
                        elif 'default_originate' in match_value:
                            add_key, del_key = {}, {}
                            want_key = value.get('default_originate', {})
                            have_key = match_value.get('default_originate', {})
                            diff_keys = set(want_key.items()) ^ set(have_key.items())
                            for key in dict(diff_keys):
                                if key in want_key and key in have_key:
                                    add_key[key] = want_key[key]
                                    del_key[key] = have_key[key]
                                elif key in want_key:
                                    add_key[key] = want_key[key]
                                elif key in have_key:
                                    del_key[key] = have_key[key]

                            if add_key:
                                add_key.setdefault('enabled', value['default_originate']['enabled'])
                                add_cfg.setdefault(attr, {})['default_originate'] = add_key
                            if del_key:
                                del_key.setdefault('enabled', match_value['default_originate']['enabled'])
                                del_cfg.setdefault(attr, {})['default_originate'] = del_key
                    elif 'ranges' in value:
                        add_range, del_range = self._get_diff_in_ranges(value['ranges'], match_value['ranges'])
                        if add_range:
                            add_cfg.setdefault(attr, {})['ranges'] = add_range
                        if del_range:
                            del_cfg.setdefault(attr, {})['ranges'] = add_range
                    if 'nssa' in add_cfg:
                        add_cfg['nssa']['enabled'] = value['enabled']
                    if 'nssa' in del_cfg:
                        del_cfg['nssa']['enabled'] = match_value['enabled']
                elif attr == 'stub':
                    if 'nssa' in match_have:
                        del_cfg['nssa'] = {'enabled': True}
                        add_cfg[attr] = value
                        continue
                    elif 'stub' not in match_have:
                        add_cfg[attr] = value
                        continue

                    match_value = match_have[attr]
                    if 'no_summary' in value:
                        if 'no_summary' in match_value and value['no_summary'] != match_value['no_summary']:
                            add_cfg.setdefault(attr, {})['no_summary'] = value['no_summary']
                            add_cfg[attr]['enabled'] = value['enabled']
                        elif 'no_summary' not in match_value:
                            add_cfg.setdefault(attr, {})['no_summary'] = value['no_summary']
                            add_cfg[attr]['enabled'] = value['enabled']

            for attr in match_have:
                if attr not in conf:
                    if attr not in ['nssa', 'stub']:
                        if attr == 'ranges':
                            for range_item in match_have[attr]:
                                del_cfg.setdefault(attr, []).append({'prefix': range_item['prefix']})
                        else:
                            del_cfg[attr] = match_have[attr]
                    else:
                        del_cfg[attr] = {'enabled': True}

            if add_cfg:
                add_cfg.update({'vrf_name': vrf_name, 'area_id': area_id})
                add_config.append(add_cfg)

            if del_cfg:
                del_cfg.update({'vrf_name': vrf_name, 'area_id': area_id})
                del_config.append(del_cfg)

            if del_cfg and not add_cfg:
                add_config.append({'vrf_name': vrf_name, 'area_id': area_id})

        if state == 'overridden':
            for conf in have:
                vrf_name = conf['vrf_name']
                area_id = conf['area_id']
                if not any(cmd for cmd in want if cmd['vrf_name'] == vrf_name and cmd['area_id'] == area_id):
                    del_config.append({'vrf_name': conf['vrf_name'], 'area_id': conf['area_id']})

        return add_config, del_config

    def create_ospfv3_area_requests_from_commands(self, conf):
        requests = []
        payload = {}
        for area in conf:
            area_payload = {}
            inter_area_payload = {}
            vrf_name = area['vrf_name']
            area_id = area['area_id']
            for attr in area:
                if attr in ['vrf_name', 'area_id']:
                    continue
                if attr == 'nssa':
                    nssa_payload = {
                        'enable': area[attr].get('enabled', True),
                        'no-summary': area[attr].get('no_summary'),
                        'default-route-metric': area[attr].get('default_originate', {}).get('metric'),
                        'default-route-metric-type': area[attr].get('default_originate', {}).get('metric_type'),
                        'default-route-originate': area[attr].get('default_originate', {}).get('enabled')
                    }
                    nssa_payload = remove_empties(nssa_payload)
                    if 'default-route-metric-type' in nssa_payload and nssa_payload['default-route-metric-type']:
                        nssa_payload['default-route-metric-type'] = "TYPE_" + str(nssa_payload['default-route-metric-type'])
                    nssa_ranges = self.update_ranges(area[attr].get('ranges', []))

                    if nssa_payload:
                        area_payload.setdefault(OSPF_KEY_EXT + attr, {})['config'] = nssa_payload

                    if nssa_ranges:
                        area_payload.setdefault(OSPF_KEY_EXT + attr, {})['ranges'] = nssa_ranges

                elif attr == 'stub':
                    stub_payload = {
                        'enable': area[attr].get('enabled', True),
                        'no-summary': area[attr].get('no_summary')
                    }
                    stub_payload = remove_empties(stub_payload)
                    if stub_payload:
                        area_payload.setdefault(OSPF_KEY_EXT + attr, {})['config'] = stub_payload

                elif attr == 'ranges':
                    ranges = self.update_ranges(area[attr], 'metric')
                    if ranges:
                        inter_area_payload[attr] = ranges

                elif attr in ['filter_list_in', 'filter_list_out']:
                    if area[attr]:
                        inter_area_payload[attr.replace('_', '-')] = {
                            'config': {'name': area[attr]}
                        }

            if area_payload:
                area_payload['identifier'] = area_id
                area_payload['config'] = {
                    'identifier': area_id
                }
                payload.setdefault(vrf_name, {}).setdefault('areas', []).append(area_payload)
            elif len(area) == 2:
                area_payload['identifier'] = area_id
                area_payload['config'] = {
                    'identifier': area_id
                }
                payload.setdefault(vrf_name, {}).setdefault('areas', []).append(area_payload)

            if inter_area_payload:
                inter_area_payload['src-area'] = area_id
                inter_area_payload['config'] = {
                    'src-area': area_id
                }
                payload.setdefault(vrf_name, {}).setdefault('inter-area-policy', []).append(inter_area_payload)

        for vrf_name in payload:
            url = OSPF_URI.format(vrf_name=vrf_name)
            request_payload = {}
            if payload[vrf_name].get('areas'):
                request_payload['areas'] = {'area': payload[vrf_name]['areas']}
            if payload[vrf_name].get('inter-area-policy'):
                request_payload['global'] = {
                    'openconfig-ospfv3-ext:inter-area-propagation-policies': {
                        'inter-area-policy': payload[vrf_name]['inter-area-policy']
                    }
                }
            if request_payload:
                request_payload = {'openconfig-network-instance:ospfv3': request_payload}
                requests.append({'path': url, 'method': 'PATCH', 'data': request_payload})

        return requests

    def delete_ospfv3_area_requests_from_commands(self, conf, have, is_delete_all=False):
        requests = []
        if is_delete_all:
            for area in conf:
                vrf_name = area['vrf_name']
                area_id = area['area_id']
                url = OSPF_URI.format(vrf_name=vrf_name) + OSPF_AREA_GLOBAL_URI.format(area_id=area_id)
                requests.append({'path': url, 'method': 'DELETE'})
            return requests

        for area in conf:
            vrf_name = area['vrf_name']
            area_id = area['area_id']
            if len(area) == 2:
                match_have = next((cfg for cfg in have if cfg['vrf_name'] == vrf_name and cfg['area_id'] == area_id), None)
                if match_have:
                    url = OSPF_URI.format(vrf_name=vrf_name) + OSPF_AREA_GLOBAL_URI.format(area_id=area_id)
                    requests.append({'path': url, 'method': 'DELETE'})
                continue

            for attr in area:
                if attr in ['vrf_name', 'area_id']:
                    continue
                if attr == 'nssa' or attr == 'stub':
                    requests.extend(self.get_delete_nssa_or_stub_requests(vrf_name, area_id, area, attr))

                elif attr == 'ranges':
                    requests.extend(self.get_delete_ranges_requests(vrf_name, area_id, area[attr]))

                elif attr in ['filter_list_in', 'filter_list_out']:
                    url = OSPF_URI.format(vrf_name=vrf_name) + OSPF_AREA_ATTRIBUTES[attr].format(area_id=area_id)
                    requests.append({'path': url, 'method': 'DELETE'})

        return requests

    def get_delete_nssa_or_stub_requests(self, vrf_name, area_id, area, attr):
        requests = []
        if len(area[attr]) == 1 or ('enabled' in area[attr] and area[attr]['enabled']):
            url = OSPF_URI.format(vrf_name=vrf_name) + OSPF_AREA_ATTRIBUTES['area_id'].format(area_id=area_id)
            requests.append({'path': url + "/openconfig-ospfv3-ext:" + attr, 'method': 'DELETE'})
            return requests

        for sub_attr in area[attr]:
            if sub_attr == 'ranges':
                requests.extend(self.get_delete_ranges_requests(vrf_name, area_id, area[attr][sub_attr], attr))
            elif sub_attr == 'default_originate':
                if len(area[attr][sub_attr]) == 1 or ('enabled' in area[attr][sub_attr] and area[attr][sub_attr]['enabled']):
                    for sub_url in OSPF_AREA_ATTRIBUTES[attr][sub_attr]:
                        url = OSPF_URI.format(vrf_name=vrf_name) + OSPF_AREA_ATTRIBUTES[attr][sub_attr][sub_url].format(area_id=area_id)
                        requests.append({'path': url, 'method': 'DELETE'})
                    continue

                for default_originate_attr in area[attr][sub_attr]:
                    url = OSPF_URI.format(vrf_name=vrf_name)
                    url += OSPF_AREA_ATTRIBUTES[attr][sub_attr][default_originate_attr].format(area_id=area_id)
                    requests.append({'path': url, 'method': 'DELETE'})
            else:
                url = OSPF_URI.format(vrf_name=vrf_name)
                url += OSPF_AREA_ATTRIBUTES[attr][sub_attr].format(area_id=area_id)
                requests.append({'path': url, 'method': 'DELETE'})
        return requests

    def get_delete_ranges_requests(self, vrf_name, area_id, ranges, type=None):
        requests = []
        base_uri = OSPF_AREA_ATTRIBUTES[type]['ranges'] if type else OSPF_AREA_ATTRIBUTES['ranges']
        for range_item in ranges:
            prefix = range_item['prefix'].replace('/', '%2F')
            if len(range_item) == 1:
                url = OSPF_AREA_GLOBAL_URI + "/ranges/range={address_prefix}"
                if type:
                    url = "/areas/area={area_id}/openconfig-ospfv3-ext:nssa/ranges/range={address_prefix}"
                url = OSPF_URI.format(vrf_name=vrf_name) + url.format(area_id=area_id, address_prefix=prefix)
                requests.append({'path': url, 'method': 'DELETE'})
            else:
                if 'cost' in range_item:
                    url = OSPF_URI.format(vrf_name=vrf_name)
                    url += base_uri['cost'].format(area_id=area_id, address_prefix=prefix)
                    requests.append({'path': url, 'method': 'DELETE'})
                if 'advertise' in range_item:
                    url = OSPF_URI.format(vrf_name=vrf_name)
                    url += base_uri['advertise'].format(area_id=area_id, address_prefix=prefix)
                    requests.append({'path': url, 'method': 'DELETE'})
        return requests

    def update_ranges(self, ranges, cost_key='cost'):
        all_ranges_payload = {}
        for range_item in ranges:
            advertise = range_item.get('advertise', True)
            if range_item.get('cost') is not None:
                advertise = True
            range_payload = {
                'address-prefix': range_item.get('prefix'),
                cost_key : range_item.get('cost'),
                'advertise': advertise
            }
            range_payload = remove_empties(range_payload)
            if range_payload:
                range_payload = {
                    'address-prefix': range_item.get('prefix'),
                    'config': range_payload
                }
                all_ranges_payload.setdefault('range', []).append(range_payload)
        return all_ranges_payload

    def _get_diff_in_ranges(self, want_range, have_range):
        add_range, del_range = [], []
        if not want_range:
            return add_range, want_range

        if not have_range:
            return want_range, del_range

        for item in want_range:
            want_prefix = item.get('prefix')
            match_prefix = next((x for x in have_range if x.get('prefix') == want_prefix), None)
            if not match_prefix:
                add_range.append(item)
            else:
                add_cfg, del_cfg = {}, {}
                diff_keys = set(item.items()) ^ set(match_prefix.items())
                for key in dict(diff_keys):
                    if key in item and key in match_prefix and item[key] != match_prefix[key]:
                        add_cfg[key] = item[key]
                    elif key in item:
                        add_cfg[key] = item[key]
                    elif key in match_prefix:
                        if key == 'advertise' and not match_prefix['advertise']:
                            del_cfg['advertise'] = True
                        else:
                            del_cfg[key] = match_prefix[key]

                if add_cfg:
                    add_cfg['prefix'] = want_prefix
                    add_range.append(add_cfg)

                if del_cfg:
                    del_cfg['prefix'] = want_prefix
                    del_range.append(del_cfg)

        for item in have_range:
            have_prefix = item.get('prefix')
            match_prefix = next((x for x in want_range if x.get('prefix') == have_prefix), None)
            if not match_prefix:
                del_range.append({'prefix': have_prefix})

        return add_range, del_range

    def __get_updated_ranges_after_delete(self, want, have):
        if not want:
            return have
        ranges = []

        for range_item in want.get('ranges', []):
            prefix = range_item.get('prefix')
            match_have_range = next((cfg for cfg in have.get('ranges', []) if cfg['prefix'] == prefix), None)
            if match_have_range:
                if len(range_item) != 1:
                    if 'cost' in range_item and 'cost' in match_have_range:
                        del match_have_range['cost']
                    ranges.append(match_have_range)

        for range_item in have.get('ranges', []):
            prefix = range_item.get('prefix')
            match_want_range = next((cfg for cfg in want.get('ranges', []) if cfg['prefix'] == prefix), None)
            if not match_want_range:
                ranges.append(range_item)

        return ranges if ranges else None

    def __derive_ospfv3_area_delete_op(self, key_set, command, exist_conf):
        new_conf = exist_conf
        if command:
            if len(command.keys()) == 2:
                return True, {}
            for attr in command:
                if attr in ['vrf_name', 'area_id']:
                    continue
                if attr in ['filter_list_in', 'filter_list_out']:
                    new_conf[attr] = None
                if attr == 'ranges' and new_conf.get(attr, []):
                    new_conf['ranges'] = self.__get_updated_ranges_after_delete(command, new_conf)
                if attr == 'nssa' and new_conf.get(attr):
                    if 'enabled' in command[attr]:
                        del new_conf[attr]
                        if len(new_conf.keys()) == 2:
                            return True, {}
                    else:
                        for sub_attr in command[attr]:
                            if sub_attr == 'ranges' and new_conf[attr].get(sub_attr, []):
                                new_conf[attr][sub_attr] = self.__get_updated_ranges_after_delete(command[attr], new_conf[attr])
                            if sub_attr == 'default_originate' and new_conf[attr].get(sub_attr):
                                for in_attr in ['enabled', 'metric', 'metric_type']:
                                    if in_attr in new_conf[attr][sub_attr]:
                                        del new_conf[attr][sub_attr][in_attr]
                                if len(new_conf[attr][sub_attr]) == 0:
                                    del new_conf[attr][sub_attr]
                            if sub_attr == 'no_summary' and new_conf[attr].get(sub_attr):
                                del new_conf[attr][sub_attr]
                if attr == 'stub' and new_conf.get(attr):
                    if 'enabled' in command[attr]:
                        del new_conf[attr]
                        if len(new_conf.keys()) == 2:
                            return True, {}
                    elif 'no_summary' in command[attr] and 'no_summary' in new_conf[attr]:
                        del new_conf[attr]['no_summary']
        return True, new_conf

    def __derive_ospfv3_area_ranges_merge_op(self, key_set, command, exist_conf):
        new_conf = exist_conf
        if command:
            if 'cost' in command:
                new_conf['advertise'] = True
                new_conf['cost'] = command['cost']
            if 'advertise' in command:
                new_conf['advertise'] = command['advertise']

        return True, new_conf

    def get_new_config(self, commands, have):
        """Returns generated configuration based on commands and
        existing configuration"""
        key_set = [
            {'config': {'vrf_name': '', 'area_id': '', '__delete_op': self.__derive_ospfv3_area_delete_op}, },
            {'ranges': {'prefix': '', '__merge_op': self.__derive_ospfv3_area_ranges_merge_op}, }
        ]

        return remove_empties_from_list(get_new_config(commands, have, key_set))
