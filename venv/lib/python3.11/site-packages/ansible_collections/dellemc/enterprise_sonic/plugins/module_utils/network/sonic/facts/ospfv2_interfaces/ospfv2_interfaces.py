#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic ospfv2_interfaces fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv2_interfaces.ospfv2_interfaces import Ospfv2_interfacesArgs

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible.module_utils.connection import ConnectionError

DEFAULT_ADDRESS = '0.0.0.0'


class Ospfv2_interfacesFacts(object):
    """ The sonic ospfv2_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ospfv2_interfacesArgs.argument_spec
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
        """ Populate the facts for ospfv2_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        all_ospfv2_interface_configs = {}
        if not data:
            all_ospfv2_interface_configs = self.get_ospfv2_interfaces()

        for ospfv2_interface_config in all_ospfv2_interface_configs:
            if ospfv2_interface_config:
                obj = self.render_config(self.generated_spec, ospfv2_interface_config)
                if obj:
                    objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('ospfv2_interfaces', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ospfv2_interfaces'] = remove_empties_from_list(params['config'])

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
        return conf

    def get_ospfv2_interfaces(self):
        """Get all OSPFv2 interfaces available in chassis"""
        request = [{"path": "data/openconfig-interfaces:interfaces", "method": "GET"}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        ospf_configs = []

        if "openconfig-interfaces:interfaces" in response[0][1]:
            interfaces = response[0][1].get("openconfig-interfaces:interfaces", {})
            if interfaces.get('interface'):
                interfaces = interfaces['interface']
            for interface in interfaces:
                intf_name = interface.get('name')
                if intf_name == "eth0":
                    continue

                ospf = None
                ospf_config = {}

                if interface.get('openconfig-vlan:routed-vlan'):
                    ospf = interface.get('openconfig-vlan:routed-vlan', {})
                else:
                    ospf = interface.get('subinterfaces', {}).get('subinterface', [{}])[0]

                if ospf:
                    ipv4 = ospf.get('openconfig-if-ip:ipv4', {})
                    if ipv4:
                        ospf_int = ipv4.get('openconfig-ospfv2-ext:ospfv2', {})
                        if ospf_int:
                            ospf_attributes = []
                            for address in ospf_int.get('if-addresses', []):
                                attr = {}
                                addr = address.get('address')
                                bfd = address.get('enable-bfd')
                                if bfd:
                                    cfg = bfd.get('config')
                                    if cfg:
                                        bfd_cfg = {}
                                        self.update_dict(bfd_cfg, 'enable', cfg.get('enabled'))
                                        self.update_dict(bfd_cfg, 'bfd_profile', cfg.get('bfd-profile'))
                                        self.update_dict(ospf_config, 'bfd', bfd_cfg)
                                config = address.get('config')
                                md_authentications = address.get('md-authentications')
                                if config:
                                    self.update_dict(attr, 'area_id', config.get('area-id'))
                                    self.update_dict(attr, 'authentication_type', config.get('authentication-type'))
                                    self.update_dict(attr, 'cost', config.get('metric'))
                                    self.update_dict(attr, 'hello_interval', config.get('hello-interval'))
                                    self.update_dict(attr, 'mtu_ignore', config.get('mtu-ignore'))
                                    self.update_dict(attr, 'priority', config.get('priority'))
                                    self.update_dict(attr, 'retransmit_interval', config.get('retransmission-interval'))
                                    self.update_dict(attr, 'transmit_delay', config.get('transmit-delay'))

                                    if 'authentication-key' in config:
                                        attr['authentication'] = {}
                                        self.update_dict(attr['authentication'], 'password', config.get('authentication-key'))
                                        self.update_dict(attr['authentication'], 'encrypted', config.get('authentication-key-encrypted'))

                                    if config.get('dead-interval-minimal'):
                                        self.update_dict(attr, 'hello_multiplier', config.get('hello-multiplier'))
                                    else:
                                        self.update_dict(attr, 'dead_interval', config.get('dead-interval'))

                                    if 'network-type' in config:
                                        network = "broadcast" if 'BROADCAST' in config['network-type'] else "point_to_point"
                                        ospf_config['network'] = network

                                if md_authentications:
                                    md_keys = []
                                    for md_auth in md_authentications.get('md-authentication', []):
                                        md_config = md_auth.get('config', {})
                                        if md_config:
                                            md_key = {}
                                            self.update_dict(md_key, 'key_id', md_config.get('authentication-key-id'))
                                            self.update_dict(md_key, 'md5key', md_config.get('authentication-md5-key'))
                                            self.update_dict(md_key, 'encrypted', md_config.get('authentication-key-encrypted'))
                                            if md_key:
                                                md_keys.append(md_key)

                                    self.update_dict(attr, 'md_authentication', md_keys)
                                if attr:
                                    if addr != DEFAULT_ADDRESS:
                                        attr['address'] = addr
                                    ospf_attributes.append(attr)

                            self.update_dict(ospf_config, 'ospf_attributes', ospf_attributes)
                if ospf_config:
                    ospf_config['name'] = intf_name
                    ospf_configs.append(ospf_config)

        return ospf_configs

    def update_dict(self, dict, key, value, parent_key=None):
        if value not in [None, {}, []]:
            if parent_key:
                dict.setdefault(parent_key, {})[key] = value
            else:
                dict[key] = value
