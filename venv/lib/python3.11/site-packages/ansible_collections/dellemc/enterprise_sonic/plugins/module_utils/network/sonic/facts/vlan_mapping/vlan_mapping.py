#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic vlan_mapping fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.vlan_mapping.vlan_mapping import Vlan_mappingArgs

from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible.module_utils.connection import ConnectionError


class Vlan_mappingFacts(object):
    """ The sonic vlan_mapping fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Vlan_mappingArgs.argument_spec
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
        """ Populate the facts for vlan_mapping
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        all_vlan_mapping_configs = {}
        if not data:
            vlan_mapping_configs = self.get_vlan_mappings()
            for interface, vlan_config in vlan_mapping_configs.items():
                vlan_mapping_configs_dict = {}
                vlan_mapping_configs_dict['name'] = interface
                vlan_mapping_configs_dict['mapping'] = vlan_config
                all_vlan_mapping_configs[interface] = vlan_mapping_configs_dict

        objs = []
        for vlan_mapping_config in all_vlan_mapping_configs.items():
            obj = self.render_config(self.generated_spec, vlan_mapping_config)
            if obj:
                objs.append(obj)

        ansible_facts['ansible_network_resources'].pop('vlan_mapping', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['vlan_mapping'] = params['config']

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
        config['name'] = conf[1]['name']
        config['mapping'] = conf[1]['mapping']

        return utils.remove_empties(config)

    def get_vlan_mappings(self):
        """Get all vlan mappings on device"""
        interfaces = self.get_ports() + self.get_portchannels()

        vlan_mapping_configs = {}
        for interface in interfaces:
            response = self.get_port_mappings(interface)

            if "openconfig-interfaces-ext:mapped-vlans" in response:
                vlan_list = response["openconfig-interfaces-ext:mapped-vlans"].get("mapped-vlan", {})
                for vlan_mapping in vlan_list:
                    vlan_mapping_dict = {}

                    vlan_mapping_dict["service_vlan"] = vlan_mapping.get("vlan-id", None)

                    vs_action = (vlan_mapping
                                 .get("egress-mapping", {})
                                 .get("config", {})
                                 .get("vlan-stack-action", "SWAP"))

                    if vs_action == "SWAP":
                        vlan_trans_dict = dict()
                        m_tag = (vlan_mapping
                                 .get("config", {})
                                 .get("multi-tag", False))
                        if m_tag:
                            vlan_trans_dict["multi_tag"] = True
                        match = vlan_mapping.get("match", {})

                        if "match-single-tags" in match:
                            match_single_tags = (vlan_mapping
                                                 .get("match", {})
                                                 .get("match-single-tags", {})
                                                 .get("match-single-tag", []))
                            ms_tags_list = []
                            for ms_tag in match_single_tags:
                                ms_tag_dict = dict()
                                ms_tag_dict["outer_vlan"] = ms_tag["outer-vlan"]
                                ms_tag_dict["priority"] = (ms_tag
                                                           .get("config", {})
                                                           .get("priority", None))

                                ms_tags_list.append(ms_tag_dict)
                            vlan_trans_dict["match_single_tags"] = ms_tags_list

                        if 'match-double-tags' in match:
                            match_double_tags = (vlan_mapping
                                                 .get("match", {})
                                                 .get("match-double-tags", {})
                                                 .get("match-double-tag", []))
                            md_tags_list = []
                            for md_tag in match_double_tags:
                                md_tag_dict = dict()
                                md_tag_dict["inner_vlan"] = md_tag["inner-vlan"]
                                md_tag_dict["outer_vlan"] = md_tag["outer-vlan"]
                                md_tag_dict["priority"] = (md_tag
                                                           .get("config", {})
                                                           .get("priority", None))

                                md_tags_list.append(md_tag_dict)
                            vlan_trans_dict["match_double_tags"] = md_tags_list

                        if vlan_trans_dict:
                            vlan_mapping_dict["vlan_translation"] = vlan_trans_dict
                    else:
                        match = vlan_mapping.get("match", {})

                        if "single-tagged" in match:
                            st_vlan_ids = (vlan_mapping
                                           .get("match", {})
                                           .get("single-tagged", {})
                                           .get("config", {})
                                           .get("vlan-ids", None))
                            st_tagged_dict = dict()
                            if st_vlan_ids:
                                if isinstance(st_vlan_ids[0], str):
                                    st_tagged_dict["vlan_ids"] = st_vlan_ids[0].replace('..', '-').split(',')
                                elif isinstance(st_vlan_ids[0], int):
                                    st_tagged_dict["vlan_ids"] = [str(st_vlan_ids[0])]
                                st_tagged_dict["priority"] = (vlan_mapping
                                                              .get("egress-mapping", {})
                                                              .get("config", {})
                                                              .get("mapped-vlan-priority", None))
                            vlan_mapping_dict["dot1q_tunnel"] = st_tagged_dict

                    if interface["ifname"] in vlan_mapping_configs:
                        vlan_mapping_configs[interface["ifname"]].append(vlan_mapping_dict)
                    else:
                        vlan_mapping_configs[interface["ifname"]] = []
                        vlan_mapping_configs[interface["ifname"]].append(vlan_mapping_dict)

        return vlan_mapping_configs

    def get_port_mappings(self, interface):
        """Get a ports vlan mappings from device"""
        ifname = interface["ifname"]
        if '/' in ifname:
            ifname = ifname.replace('/', '%2F')

        port_mappings = "data/openconfig-interfaces:interfaces/interface=%s/openconfig-interfaces-ext:mapped-vlans" % ifname
        method = "GET"
        request = [{"path": port_mappings, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        return response[0][1]

    def get_ports(self):
        """Get all port names on device"""
        all_ports_path = "data/sonic-port:sonic-port/PORT_TABLE"
        method = "GET"
        request = [{"path": all_ports_path, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        response = response[0][1]

        port_list = []

        if "sonic-port:PORT_TABLE" in response:
            component = response["sonic-port:PORT_TABLE"]
            if "PORT_TABLE_LIST" in component:
                for port in component["PORT_TABLE_LIST"]:
                    if "Eth" in port["ifname"]:
                        port_list.append({"ifname": port["ifname"]})

        return port_list

    def get_portchannels(self):
        """Get all portchannel names on device"""
        all_portchannels_path = "data/sonic-portchannel:sonic-portchannel"
        method = "GET"
        request = [{"path": all_portchannels_path, "method": method}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)

        response = response[0][1]

        portchannel_list = []

        if "sonic-portchannel:sonic-portchannel" in response:
            component = response["sonic-portchannel:sonic-portchannel"]
            if "PORTCHANNEL" in component:
                component = component["PORTCHANNEL"]
                if "PORTCHANNEL_LIST" in component:
                    component = component["PORTCHANNEL_LIST"]
                    for portchannel in component:
                        portchannel_list.append({"ifname": portchannel["name"]})

        return portchannel_list
