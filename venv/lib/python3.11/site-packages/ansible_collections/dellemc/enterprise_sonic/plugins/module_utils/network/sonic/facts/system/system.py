#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic system fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type
from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)

from ansible.module_utils.connection import ConnectionError

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.system.system import SystemArgs

GET = "get"


class SystemFacts(object):
    """
    The sonic system fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = SystemArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_system(self):
        """
        Get system hostname available in chassis
        """
        request = [{"path": "data/openconfig-system:system/config", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if ('openconfig-system:config' in response[0][1]):
            data = response[0][1]['openconfig-system:config']
        else:
            data = {}
        return data

    def get_intf_naming_auto_breakout(self):
        """
        Get interface_naming_mode and auto-breakout status available in chassis
        """
        request = [{"path": "data/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST=localhost", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        data = {}
        if ('sonic-device-metadata:DEVICE_METADATA_LIST' in response[0][1]):
            intf_data = response[0][1]['sonic-device-metadata:DEVICE_METADATA_LIST']
            if 'intf_naming_mode' in intf_data[0]:
                if intf_data[0]['intf_naming_mode'] == 'standard-ext':
                    intf_data[0]['intf_naming_mode'] = 'standard_extended'
                data['intf_naming_mode'] = intf_data[0]['intf_naming_mode']
            if 'auto-breakout' in intf_data[0]:
                data['auto-breakout'] = intf_data[0]['auto-breakout']
        return data

    def get_anycast_addr(self):
        """
        Get system anycast address available in chassis
        """
        request = [{"path": "data/sonic-sag:sonic-sag/SAG_GLOBAL/SAG_GLOBAL_LIST/", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if ('sonic-sag:SAG_GLOBAL_LIST' in response[0][1]):
            data = response[0][1]['sonic-sag:SAG_GLOBAL_LIST'][0]
        else:
            data = {}
        return data

    def get_load_share_hash_algo(self):
        """
        Get load share hash algorithm
        """
        request = [{"path": "data/openconfig-loadshare-mode-ext:loadshare/hash-algorithm/config", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        if ('openconfig-loadshare-mode-ext:config' in response[0][1]):
            data = response[0][1]['openconfig-loadshare-mode-ext:config']
        else:
            data = {}
        return data

    def get_auditd_rules(self):
        """
        Get auditd rules configuration available in chassis
        """
        request = [{"path": "data/openconfig-system:system/openconfig-system-ext:auditd-system", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        data = {}
        if response and response[0]:
            if len(response[0]) > 1:
                if ('openconfig-system-ext:auditd-system' in response[0][1]):
                    auditd_system_data = response[0][1]['openconfig-system-ext:auditd-system']
                    if 'config' in auditd_system_data:
                        audit_rules_config = auditd_system_data['config']
                        if 'audit-rules' in audit_rules_config:
                            audit_rules = audit_rules_config['audit-rules']
                            data['audit-rules'] = audit_rules
        return data

    def get_concurrent_session_limit(self):
        """Get concurrent session limit configured on chassis"""
        request = [{"path": "data/openconfig-system:system/openconfig-system-ext:login/concurrent-session/config", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        data = {}
        if response and response[0]:
            if len(response[0]) > 1:
                if ('openconfig-system-ext:config' in response[0][1]):
                    session_limit = response[0][1]['openconfig-system-ext:config']
                    if 'limit' in session_limit:
                        data['concurrent_session_limit'] = session_limit['limit']
        return data

    def get_switching_mode(self):
        """
        Get switching-mode configuration if available in chassis
        Switching-mode is not available as a resource to query until it has been configured to CUT_THROUGH mode at least once.
        In that scenario it is assumed the value is STORE_AND_FORWARD.
        """
        request = [{"path": "data/openconfig-system:system/config/switching-mode", "method": GET}]
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        data = {}
        if response and response[0]:
            if len(response[0]) > 1:
                if ('openconfig-system:switching-mode' in response[0][1]):
                    data["switching-mode"] = response[0][1]['openconfig-system:switching-mode']
                else:
                    data["switching-mode"] = "STORE_AND_FORWARD"
        return data

    def get_adjust_txrx_clock_freq(self):
        """
        Get adjust-txrx-clock-freq configuration if available in chassis
        """
        request = [{"path": "data/openconfig-system:system/config/adjust-txrx-clock-freq", "method": GET}]
        data = {}

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            if 'Resource not found' in str(exc):
                return data

            self._module.fail_json(msg=str(exc), code=exc.code)
        if response and response[0]:
            if len(response[0]) > 1:
                if ('openconfig-system:adjust-txrx-clock-freq' in response[0][1]):
                    data["adjust-txrx-clock-freq"] = response[0][1]['openconfig-system:adjust-txrx-clock-freq']
                else:
                    data["adjust-txrx-clock-freq"] = False
        return data

    def get_password_attributes(self):
        """Get all the password attribute configured in the device"""
        request = [{"path": "data/openconfig-system:system/openconfig-system-ext:login/password-attributes/config", "method": GET}]
        data = {}
        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        if response and response[0]:
            if len(response[0]) > 1:
                if 'openconfig-system-ext:config' in response[0][1]:
                    data = response[0][1]['openconfig-system-ext:config']
        return data

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for system
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if not data:
            data = self.get_system()
        intf_naming_auto_breakout = self.get_intf_naming_auto_breakout()
        if intf_naming_auto_breakout:
            data.update(intf_naming_auto_breakout)
        anycast_addr = self.get_anycast_addr()
        if anycast_addr:
            data.update(anycast_addr)
        pwd_configs = self.get_password_attributes()
        if pwd_configs:
            data.update(pwd_configs)
        load_share_hash_algo = self.get_load_share_hash_algo()
        if load_share_hash_algo:
            data.update(load_share_hash_algo)
        auditd_rules = self.get_auditd_rules()
        if auditd_rules:
            data.update(auditd_rules)
        session_limit = self.get_concurrent_session_limit()
        if session_limit:
            data.update(session_limit)
        switching_mode = self.get_switching_mode()
        if switching_mode:
            data.update(switching_mode)
        adjust_txrx_clock_freq = self.get_adjust_txrx_clock_freq()
        if adjust_txrx_clock_freq:
            data.update(adjust_txrx_clock_freq)
        objs = []
        objs = self.render_config(self.generated_spec, data)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['system'] = utils.remove_empties(params['config'])
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
        config = self.parse_sonic_system(spec, conf)
        return config

    def parse_sonic_system(self, spec, conf):
        config = deepcopy(spec)
        if conf:
            if ('hostname' in conf) and (conf['hostname']):
                config['hostname'] = conf['hostname']
            if ('intf_naming_mode' in conf) and (conf['intf_naming_mode']):
                config['interface_naming'] = conf['intf_naming_mode']
            if ('IPv4' in conf) and (conf['IPv4'] == "enable"):
                config['anycast_address']['ipv4'] = True
            if ('IPv4' in conf) and (conf['IPv4'] == "disable"):
                config['anycast_address']['ipv4'] = False
            if ('IPv6' in conf) and (conf['IPv6'] == "enable"):
                config['anycast_address']['ipv6'] = True
            if ('IPv6' in conf) and (conf['IPv6'] == "disable"):
                config['anycast_address']['ipv6'] = False
            if ('gwmac' in conf) and (conf['gwmac']):
                config['anycast_address']['mac_address'] = conf['gwmac']
            if ('auto-breakout' in conf) and (conf['auto-breakout']):
                config['auto_breakout'] = conf['auto-breakout']
            if ('switching-mode' in conf) and (conf['switching-mode']):
                config['switching_mode'] = conf['switching-mode']
            if ('algorithm' in conf) and (conf['algorithm']):
                config['load_share_hash_algo'] = conf['algorithm']
            if ('audit-rules' in conf) and (conf['audit-rules']):
                config['audit_rules'] = conf['audit-rules']
            if ('concurrent_session_limit' in conf) and (conf['concurrent_session_limit']):
                config['concurrent_session_limit'] = conf['concurrent_session_limit']
            if ('adjust-txrx-clock-freq' in conf):
                config['adjust_txrx_clock_freq'] = conf['adjust-txrx-clock-freq']
            if ('min-lower-case' in conf) and (conf['min-lower-case']):
                config['password_complexity']['min_lower_case'] = conf['min-lower-case']
            if ('min-upper-case' in conf) and (conf['min-upper-case']):
                config['password_complexity']['min_upper_case'] = conf['min-upper-case']
            if ('min-numerals' in conf) and (conf['min-numerals']):
                config['password_complexity']['min_numerals'] = conf['min-numerals']
            if ('min-special-char' in conf) and (conf['min-special-char']):
                config['password_complexity']['min_spl_char'] = conf['min-special-char']
            if ('min-len' in conf) and (conf['min-len']):
                config['password_complexity']['min_length'] = conf['min-len']

        return utils.remove_empties(config)
