#
# -*- coding: utf-8 -*-
# Copyright 2023 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https: //www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic poe fact class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.poe.poe import PoeArgs

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic \
    import to_request, edit_config

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.poe_utils import (
    poe_enum2str,
)


class PoeFacts(object):
    """ The sonic poe fact class
    """
    poe_setting_prefix = "openconfig-if-poe-ext:"

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = PoeArgs.argument_spec
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
        """ Populate the facts for poe
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        if connection:  # just for linting purposes, remove
            pass

        if not data:
            # typically data is populated from the current device configuration
            # data = connection.get('show running-config | section ^interface')
            # using mock data instead
            data = self.get_poe_info()

        cleaned_data = utils.remove_empties(utils.validate_config(self.argument_spec, {"config": data})["config"])

        ansible_facts['ansible_network_resources'].pop('poe', None)
        facts = {}
        if cleaned_data:
            facts['poe'] = cleaned_data

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def format_to_argspec(self, poe_rest_config, interfaces_poe_rest_config):
        formatted_data = {}
        if "global" in poe_rest_config and "config" in poe_rest_config["global"]:
            global_settings = {}
            if "power-management-model" in poe_rest_config["global"]["config"]:
                global_settings["power_mgmt_model"] = poe_enum2str(poe_rest_config["global"]["config"]["power-management-model"])
            if "power-usage-threshold" in poe_rest_config["global"]["config"]:
                global_settings["usage_threshold"] = poe_rest_config["global"]["config"]["power-usage-threshold"]
            if "auto-reset-mode" in poe_rest_config["global"]["config"]:
                global_settings["auto_reset"] = poe_rest_config["global"]["config"]["auto-reset-mode"]
            if len(global_settings) > 0:
                formatted_data["global"] = global_settings

        if "cards" in poe_rest_config:
            formatted_cards_config = []
            for card_rest_config in poe_rest_config["cards"]["card"]:
                if "config" in card_rest_config:
                    formatted_card_config = {}
                    if "power-management-model" in card_rest_config["config"]:
                        formatted_card_config["power_mgmt_model"] = poe_enum2str(card_rest_config["config"]["power-management-model"])
                    if "power-usage-threshold" in card_rest_config["config"]:
                        formatted_card_config["usage_threshold"] = card_rest_config["config"]["power-usage-threshold"]
                    if "auto-reset-mode" in card_rest_config["config"]:
                        formatted_card_config["auto_reset"] = card_rest_config["config"]["auto-reset-mode"]
                    if len(formatted_card_config) > 0:
                        formatted_card_config["card_id"] = card_rest_config["card-id"]
                        formatted_cards_config.append(formatted_card_config)
            if len(formatted_cards_config) > 0:
                formatted_data["cards"] = formatted_cards_config

        if len(interfaces_poe_rest_config) > 0:
            formatted_interfaces_config = self.format_interfaces(interfaces_poe_rest_config=interfaces_poe_rest_config)
            if len(formatted_interfaces_config) > 0:
                formatted_data["interfaces"] = formatted_interfaces_config

        return formatted_data

    def format_interfaces(self, interfaces_poe_rest_config):
        formatted_interfaces_config = []
        for interface_rest_settings in interfaces_poe_rest_config:
            if "config" in interface_rest_settings:
                formated_interface_config = {}
                if self.poe_setting_prefix + "detection-mode" in interface_rest_settings["config"]:
                    formated_interface_config["detection"] = poe_enum2str(interface_rest_settings["config"][self.poe_setting_prefix + "detection-mode"])
                if self.poe_setting_prefix + "disconnect-type" in interface_rest_settings["config"]:
                    formated_interface_config["disconnect_type"] = poe_enum2str(interface_rest_settings["config"][self.poe_setting_prefix + "disconnect-type"])
                if "enabled" in interface_rest_settings["config"]:
                    formated_interface_config["enabled"] = interface_rest_settings["config"]["enabled"]
                if self.poe_setting_prefix + "four-pair-mode" in interface_rest_settings["config"]:
                    formated_interface_config["four_pair"] = interface_rest_settings["config"][self.poe_setting_prefix + "four-pair-mode"]
                if self.poe_setting_prefix + "high-power-mode" in interface_rest_settings["config"]:
                    formated_interface_config["high_power"] = interface_rest_settings["config"][self.poe_setting_prefix + "high-power-mode"]
                if self.poe_setting_prefix + "classification-mode" in interface_rest_settings["config"]:
                    formated_interface_config["power_classification"] = \
                        poe_enum2str(interface_rest_settings["config"][self.poe_setting_prefix + "classification-mode"])
                if self.poe_setting_prefix + "power-limit" in interface_rest_settings["config"]:
                    formated_interface_config["power_limit"] = interface_rest_settings["config"][self.poe_setting_prefix + "power-limit"]
                if self.poe_setting_prefix + "power-limit-type" in interface_rest_settings["config"]:
                    formated_interface_config["power_limit_type"] = \
                        poe_enum2str(interface_rest_settings["config"][self.poe_setting_prefix + "power-limit-type"])
                if self.poe_setting_prefix + "power-pairs" in interface_rest_settings["config"]:
                    formated_interface_config["power_pairs"] = poe_enum2str(interface_rest_settings["config"][self.poe_setting_prefix + "power-pairs"])
                if self.poe_setting_prefix + "powerup-mode" in interface_rest_settings["config"]:
                    formated_interface_config["power_up_mode"] = poe_enum2str(interface_rest_settings["config"][self.poe_setting_prefix + "powerup-mode"])
                if self.poe_setting_prefix + "priority" in interface_rest_settings["config"]:
                    formated_interface_config["priority"] = interface_rest_settings["config"][self.poe_setting_prefix + "priority"].lower()
                if self.poe_setting_prefix + "use-spare-pair" in interface_rest_settings["config"]:
                    formated_interface_config["use_spare_pair"] = interface_rest_settings["config"][self.poe_setting_prefix + "use-spare-pair"]
                if len(formated_interface_config) > 0:
                    if "enabled" not in formated_interface_config:
                        formated_interface_config["enabled"] = False
                    formated_interface_config["name"] = interface_rest_settings["name"]
                    formatted_interfaces_config.append(formated_interface_config)
        return formatted_interfaces_config

    def get_poe_info(self):
        # get poe settings
        try:
            request = [{"path": "data/openconfig-poe:poe", "method": "GET"}]
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc))

        poe_config = {}
        poe_config = response[0][1].get("openconfig-poe:poe", {})

        # get poe interface settings
        try:
            request = [{"path": "data/openconfig-interfaces:interfaces", "method": "GET"}]
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc))

        interface_poe_settings = []
        poe_interfaces = response[0][1].get("openconfig-interfaces:interfaces", {}).get("interface", [])
        for interface in poe_interfaces:
            interface_settings = interface.get("openconfig-if-ethernet:ethernet", {}).get("openconfig-if-poe:poe", {})
            if len(interface_settings) > 0:
                interface_settings.update({"name": interface["name"]})
                interface_poe_settings.append(interface_settings)
        formatted_specs = self.format_to_argspec(poe_config, interface_poe_settings)
        return formatted_specs
