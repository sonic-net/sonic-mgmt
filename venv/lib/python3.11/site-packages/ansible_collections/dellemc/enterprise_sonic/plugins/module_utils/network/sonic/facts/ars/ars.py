#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ars fact class
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
    remove_empties
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ars.ars import ArsArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


enum_dict = {
    'ARS_MODE_FIXED': 'fixed',
    'ARS_MODE_FLOWLET_QUALITY': 'flowlet-quality',
    'ARS_MODE_FLOWLET_RANDOM': 'flowlet-random',
    'ARS_MODE_PER_PACKET_QUALITY': 'packet-quality',
    'ARS_MODE_PER_PACKET_RANDOM': 'packet-random'
}


class ArsFacts(object):
    """ The sonic ars fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = ArsArgs.argument_spec
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
        """ Populate the facts for ars
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            cfg = self.get_config(self._module)
            data = self.update_ars(cfg)
        objs = data
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ars'] = remove_empties(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_config(self, module):
        cfg = None
        get_path = 'data/openconfig-system:system/openconfig-system-ext:adaptive-routing-switching'
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-system-ext:adaptive-routing-switching' in response[0][1]:
                cfg = response[0][1].get('openconfig-system-ext:adaptive-routing-switching')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def update_ars(self, cfg):
        """This method parses the OC ARS data and returns the parsed data in argspec format"""
        config_dict = {}

        if cfg:
            if cfg.get('ars-profile') and cfg['ars-profile'].get('profile'):
                profiles_list = []
                for profile in cfg['ars-profile']['profile']:
                    if profile.get('config'):
                        if 'algo' in profile['config']:
                            profile['config']['algorithm'] = profile['config'].pop('algo')
                        profiles_list.append(self.get_renamed_dict(profile['config']))
                if profiles_list:
                    config_dict['profiles'] = profiles_list

            if cfg.get('ars-port-profile') and cfg['ars-port-profile'].get('portprofile'):
                port_profiles_list = []
                for profile in cfg['ars-port-profile']['portprofile']:
                    if profile.get('config'):
                        port_profiles_list.append(self.get_renamed_dict(profile['config']))
                if port_profiles_list:
                    config_dict['port_profiles'] = port_profiles_list

            if cfg.get('ars-object') and cfg['ars-object'].get('arsobject'):
                ars_objects_list = []
                for obj in cfg['ars-object']['arsobject']:
                    if obj.get('config'):
                        obj_dict = self.get_renamed_dict(obj['config'])
                        if obj_dict.get('mode'):
                            obj_dict['mode'] = enum_dict[obj_dict['mode']]
                        ars_objects_list.append(obj_dict)

                if ars_objects_list:
                    config_dict['ars_objects'] = ars_objects_list

            if cfg.get('ars-switch-bind') and cfg['ars-switch-bind'].get('switchbind'):
                for bind in cfg['ars-switch-bind']['switchbind']:
                    if bind.get('name') == 'SWITCH' and bind.get('config') and bind['config'].get('profile'):
                        config_dict['switch_binding'] = {'profile': bind['config']['profile']}
                        break

            if cfg.get('ars-port-bind') and cfg['ars-port-bind'].get('portbind'):
                port_bindings_list = []
                for bind in cfg['ars-port-bind']['portbind']:
                    if bind.get('config'):
                        port_bindings_list.append(bind['config'])
                if port_bindings_list:
                    config_dict['port_bindings'] = port_bindings_list

        return config_dict

    def get_renamed_dict(self, cfg_dict):
        """This method renames the keys in a dictionary by replacing hyphens with underscores"""
        renamed_dict = {}
        for key in cfg_dict:
            new_key = key.replace('-', '_')
            renamed_dict[new_key] = cfg_dict[key]

        return renamed_dict
