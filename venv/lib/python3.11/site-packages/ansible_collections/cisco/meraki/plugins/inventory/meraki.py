# -*- coding: utf-8 -*-

# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
name: meraki
author:
  - Nilashish Chakraborty (@NilashishC)
short_description: Ansible dynamic inventory plugin for Cisco Meraki devices.
requirements:
  - meraki
extends_documentation_fragment:
  - constructed
description:
  - Build inventories using the Cisco Meraki API.
  - Uses a YAML configuration file cisco_meraki.[yml|yaml].
options:
  meraki_org_id:
    description:
      - The organization ID to fetch the networks and devices from.
    type: str
    required: true
  meraki_api_key:
    description:
      - meraki_api_key (string), API key generated in dashboard; can also be set as an environment variable MERAKI_DASHBOARD_API_KEY
    type: str
  meraki_base_url:
    description:
        - meraki_base_url (string), preceding all endpoint resources
    type: str
    default: https://api.meraki.com/api/v1
  meraki_single_request_timeout:
    description:
      - meraki_single_request_timeout (integer), maximum number of seconds for each API call
    type: int
    default: 60
  meraki_certificate_path:
    description:
      - meraki_certificate_path (string), path for TLS/SSL certificate verification if behind local proxy
    type: str
    default: ''
  meraki_requests_proxy:
    description:
      - meraki_requests_proxy (string), proxy server and port, if needed, for HTTPS
    type: str
    default: ''
  meraki_wait_on_rate_limit:
    description:
      - meraki_wait_on_rate_limit (boolean), retry if 429 rate limit error encountered?
    type: bool
    default: true
  meraki_nginx_429_retry_wait_time:
    description:
      - meraki_nginx_429_retry_wait_time (integer), Nginx 429 retry wait time
    type: int
    default: 60
  meraki_action_batch_retry_wait_time:
    description:
      - meraki_action_batch_retry_wait_time (integer), action batch concurrency error retry wait time
    type: int
    default: 60
  meraki_retry_4xx_error:
    description:
      - meraki_retry_4xx_error (boolean), retry if encountering other 4XX error (besides 429)?
    type: bool
    default: false
  meraki_retry_4xx_error_wait_time:
    description:
      - meraki_retry_4xx_error_wait_time (integer), other 4XX error retry wait time
    type: int
    default: 60
  meraki_maximum_retries:
    description:
      - meraki_maximum_retries (integer), retry up to this many times when encountering 429s or other server-side errors
    type: int
    default: 2
  meraki_output_log:
    description:
      - meraki_output_log (boolean), create an output log file?
    type: bool
    default: true
  meraki_log_file_prefix:
    description:
      - meraki_log_file_prefix (string), log file name appended with date and timestamp
    type: str
    default: meraki_api_
  meraki_log_path:
    description:
      - log_path (string), path to output log; by default, working directory of script if not specified
    type: str
    default: ''
  meraki_print_console:
    description:
      - meraki_print_console (boolean), print logging output to console?
    type: bool
    default: true
  meraki_suppress_logging:
    description:
      - meraki_suppress_logging (boolean), disable all logging? you're on your own then!
    type: bool
    default: false
  meraki_simulate:
    description:
      - meraki_simulate (boolean), simulate POST/PUT/DELETE calls to prevent changes?
    type: bool
    default: false
  meraki_be_geo_id:
    description:
      - meraki_be_geo_id (string), optional partner identifier for API usage tracking; can also be set as an environment variable BE_GEO_ID
    type: str
    default: ''
  meraki_use_iterator_for_get_pages:
    description:
      - meraki_use_iterator_for_get_pages (boolean), list* methods will return an iterator with each object instead of a complete list with all items
    type: bool
    default: false
  meraki_inherit_logging_config:
    description:
      - meraki_inherit_logging_config (boolean), Inherits your own logger instance
    type: bool
    default: false
"""

EXAMPLES = r"""
# cisco_meraki.yml
---
plugin: cisco.meraki.meraki
meraki_api_key: "<enter Meraki API key or set the MERAKI_DASHBOARD_API_KEY env var>"
meraki_org_id: "<enter Meraki Org ID>"
keyed_groups:
  # group devices based on network ID
  - prefix: meraki_network_id
    key: network_id
  # group devices based on network name
  - prefix: meraki_network
    key: network
  # group devices based on device type
  - prefix: meraki_device_type
    key: device_type
  # group devices based on meraki device tag
  - prefix: meraki_tag
    key: tags
"""

from ansible_collections.cisco.meraki.plugins.plugin_utils.meraki import (
    MERAKI,
    meraki_argument_spec,
)
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.errors import AnsibleError


meraki_argument_spec = meraki_argument_spec()
meraki_argument_spec.update(
    dict(meraki_org_id=dict(type="str", required=True)))


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "cisco.meraki.meraki"

    def verify_file(self, path):
        """return true/false if this is possibly a valid file for this plugin to consume"""
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(("cisco_meraki.yaml", "cisco_meraki.yml")):
                valid = True
        return valid

    def _build_network_map(self, dashboard, org_id):
        """Build a dictionary mapping network ID to network names."""
        network_map = {}
        networks = dashboard.exec_meraki(
            family="organizations",
            function="getOrganizationNetworks",
            params={"organizationId": org_id, "total_pages": "all"}
        )
        for network in networks:
            network_map[network["id"]] = to_text(network.get("name", ""))

        return network_map

    def _validate_argspec(self, parameters):
        "Validate the inventory plugin argspec."
        argspec_validator = ArgumentSpecValidator(meraki_argument_spec)
        result = argspec_validator.validate(parameters)

        if result.error_messages:
            raise AnsibleError(
                f"Validation failed: {', '.join(result.error_messages)}")

        return result.validated_parameters

    def parse(self, inventory, loader, path, cache=True):
        """Talk to the Meraki API and build the inventory."""

        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        config = self._read_config_data(path)
        meraki_connect_config = {
            k: config[k] for k in config if k in meraki_argument_spec
        }

        validated_config = self._validate_argspec(
            parameters=meraki_connect_config)

        meraki_org_id = validated_config.pop("meraki_org_id")

        strict = self.get_option("strict")

        dashboard = MERAKI(params=validated_config)

        try:
            devices = dashboard.exec_meraki(
                family="organizations",
                function="getOrganizationDevices",
                params={"organizationId": meraki_org_id, "total_pages": "all"},
            )
            if devices:
                network_map = self._build_network_map(dashboard, meraki_org_id)

                for device in devices:
                    hostname = device.get("name")
                    if not hostname:
                        self.display.warning(
                            f"No name set for device with MAC {device['mac']}"
                        )
                        hostname = device["mac"]
                    self.inventory.add_host(hostname, group="all")

                    if device.get("networkId"):
                        self.inventory.set_variable(
                            hostname, "network_id", device["networkId"]
                        )
                        self.inventory.set_variable(
                            hostname, "network", network_map[device["networkId"]]
                        )
                    else:
                        self.display.vvvv(
                            f"Device {hostname} is not associated with a network."
                        )

                    if device.get("lanIp"):
                        self.inventory.set_variable(
                            hostname, "ansible_host", device["lanIp"]
                        )
                    else:
                        self.display.warning(
                            f"No lanIp found for device with {hostname}."
                            " The `ansible_host` variable will not be set for this host."
                        )

                    self.inventory.set_variable(
                        hostname, "device_type", device["model"]
                    )

                    self.inventory.set_variable(
                        hostname, "ansible_product_serial", device["serial"]
                    )
                    self.inventory.set_variable(
                        hostname, "macaddress", device["mac"])

                    # Add variables created by the user's Jinja2 expressions to the host
                    self._set_composite_vars(self.get_option(
                        "compose"), device, hostname, strict=True)

                    # Create user-defined groups using variables and Jinja2 conditionals
                    self._add_host_to_composed_groups(self.get_option(
                        "groups"), device, hostname, strict=strict)
                    # Add the host to the keyed groups
                    self._add_host_to_keyed_groups(
                        keys=self.get_option("keyed_groups"),
                        variables=device,
                        host=hostname,
                        strict=strict,
                    )
        except Exception as e:
            raise AnsibleError(
                f"Failed to get devices from Meraki API: {to_native(e)}")
