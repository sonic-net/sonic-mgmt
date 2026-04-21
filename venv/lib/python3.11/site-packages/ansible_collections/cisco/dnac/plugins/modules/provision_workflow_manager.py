#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = (
    "Abinash Mishra, Madhan Sankaranarayanan, Syed Khadeer Ahmed, Ajith Andrew J"
)
DOCUMENTATION = r"""
---
module: provision_workflow_manager
short_description: Resource module for provision related
  functions
description:
  - Manage operations related to wired and wireless
    provisioning
  - API to re-provision provisioned devices
  - API to un-provision provisioned devices
  - Un-provisioning refers to removing a device from the inventory list
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Abinash Mishra (@abimishr) Madhan Sankaranarayanan
  (@madhansansel) Syed Khadeer Ahmed(@syed-khadeerahmed)
  Ajith Andrew J (@ajithandrewj)
options:
  config_verify:
    description: Set to true to verify the Cisco Catalyst
      Center config after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center
      after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description:
      - List of details of device being managed.
    type: list
    elements: dict
    required: true
    suboptions:
      management_ip_address:
        description: Management Ip Address of the device.
        type: str
        required: true
      provisioning:
        description: |
          - Specifies whether the user intends to perform
            site assignment only or full provisioning
            for a wired device.
          - Set to 'false' to carry out site assignment
            only.
          - Set to 'true' to proceed with provisioning
            to a site.
          - only applicable for wired devices.
        type: bool
        required: false
        default: true
      force_provisioning:
        description: |
          - Determines whether to force reprovisioning
            of a device.
          - A device cannot be re-provisioned to a different
            site.
          - The 'provisioning' option should not be
            set to 'false' for 'force_provisioning'
            to take effect.
          - Set to 'true' to enforce reprovisioning,
            even if the device is already provisioned.
          - Set to 'false' to skip provisioning for
            devices that are already provisioned.
        type: bool
        required: false
        default: false
      site_name_hierarchy:
        description: Name of the site where the device
          will be added. This parameter is required
          for provisioning the device and assigning
          it to a site.
        type: str
        required: true
      managed_ap_locations:
        description: |
          - Specifies the site locations allocated for
            Access Points (APs).
          - Renamed to 'primary_managed_ap_locations'
            starting from Cisco Catalyst version 2.3.7.6
            to differentiate between primary and secondary
            managed AP locations.
          - Backward compatibility is maintained; either
            'managed_ap_locations' or 'primary_managed_ap_locations'
            can be specified, with no changes required
            after upgrades.
          - Either 'managed_ap_locations' or 'primary_managed_ap_locations'
            can be used interchangeably, but only one
            of them is mandatory and must be provided.
        type: list
        elements: str
      primary_managed_ap_locations:
        description: |
          - Specifies the site locations assigned to
            primary managed Access Points (APs).
          - Introduced as the updated name for 'managed_ap_locations'
            starting from Cisco Catalyst version 2.3.7.6.
          - Backward compatible with 'managed_ap_locations';
            either parameter can be specified without
            requiring changes after upgrades.
          - Mandatory for provisioning wireless devices
            if 'managed_ap_locations' is not used.
          - Supported in Cisco Catalyst version 2.3.7.6
            and later.
        type: list
        elements: str
      secondary_managed_ap_locations:
        description: |
          - Specifies the site locations assigned to
            secondary managed Access Points (APs).
          - Introduced in Cisco Catalyst version 2.3.7.6
            to allow differentiation between primary
            and secondary managed AP locations.
          - Mandatory for provisioning wireless devices
            in scenarios where secondary AP locations
            are required.
        type: list
        elements: str
      dynamic_interfaces:
        description: |
          - A list of dynamic interfaces on the wireless
            controller.
          - Each entry represents an interface with
            associated configuration details.
        type: list
        elements: dict
        suboptions:
          interface_name:
            description: The name of the interface.
            type: str
          vlan_id:
            description: The VLAN ID associated with
              the interface.
            type: str
          interface_ip_address:
            description: The IP address assigned to
              the interface.
            type: str
          interface_netmask_in_c_i_d_r:
            description: The netmask of the interface
              in CIDR format (e.g., 24 for 255.255.255.0).
            type: str
          interface_gateway:
            description: The gateway IP address for
              the interface.
            type: str
          lag_or_port_number:
            description: The port number or LAG (Link
              Aggregation Group) identifier.
            type: str
      skip_ap_provision:
        description: |
          - If set to 'true', Access Point (AP) provisioning
            will be skipped during the workflow.
          - Use this option when AP provisioning is
            not required as part of the current operation.
          - Supported in Cisco Catalyst version 2.3.7.6
            and later.
        type: bool
        default: false
      rolling_ap_upgrade:
        description: |
          - Configuration options for performing a rolling
            upgrade of Access Points (APs) in phases.
          - Allows control over the gradual rebooting
            of APs during the upgrade process.
          - Supported in Cisco Catalyst version 2.3.7.6
            and later.
        type: dict
        suboptions:
          enable_rolling_ap_upgrade:
            description: |
              - Enable or disable the rolling AP upgrade
                feature.
              - If set to 'true', APs will be upgraded
                in batches based on the specified reboot
                percentage.
              - Supported in Cisco Catalyst version
                2.3.7.6 and later.
            type: bool
            default: false
          ap_reboot_percentage:
            description: |
              - The percentage of APs to reboot simultaneously
                during an upgrade.
              - Supported in Cisco Catalyst version
                2.3.7.6 and later.
              - Must be either 5, 15 or 25 representing
                the proportion of APs to reboot at once.
            type: int
      ap_authorization_list_name:
        description: |
          - The name of the Access Point (AP) authorization list to be used during WLC provisioning.
          - This authorization list defines the security policies and access control rules that govern which APs can join the wireless network.
          - The authorization list must exist in Cisco Catalyst Center before provisioning
            and should contain the MAC addresses or certificate-based authentication rules
            for APs.
          - Used in conjunction with 'authorize_mesh_and_non_mesh_aps' for comprehensive AP management during wireless controller provisioning.
          - If not specified, the default authorization behavior of the WLC will be applied.
        type: str
        required: false
      authorize_mesh_and_non_mesh_aps:
        description: |
          - A flag that indicates whether to authorize both mesh and non-mesh Access Points (APs) during the WLC provisioning process.
          - When set to true, all AP types (mesh and non-mesh) will be automatically authorized to join the wireless network.
          - When set to false, only specifically configured APs matching the authorization criteria will be authorized.
          - Mesh APs create wireless backhaul connections to extend network coverage, while non-mesh APs connect directly to the wired infrastructure.
          - This setting works in conjunction with 'ap_authorization_list_name' for complete AP authorization workflow.
          - Supported from Cisco Catalyst Center release version 2.3.7.6 onwards.
          type: bool
      feature_template:
        description: |
          - A dictionary containing feature template configuration for advanced wireless device provisioning.
          - Feature templates provide standardized, reusable configuration patterns that ensure consistent deployment across multiple wireless controllers.
          - Templates enable centralized configuration management, reduce manual errors, and enforce organizational policies.
          - The specified template must exist in Cisco Catalyst Center before it can be applied during provisioning.
          - Feature templates can include WLAN configurations, security policies, QoS settings, and other wireless controller parameters.
          - Supported from Cisco Catalyst Center release version 3.1.3.0 onwards for wireless controller provisioning.
        type: dict
        required: false
        suboptions:
          design_name:
            description: |
              - The name of the feature template design to be applied during wireless controller provisioning.
              - This template name must match exactly with the template name defined in Cisco Catalyst Center.
              - The template defines standardized configuration parameters, policies, and settings to be applied to the wireless controller.
              - Template names are case-sensitive and should follow organizational naming conventions.
            type: str
            required: true
          additional_identifiers:
            description: |
              - A list of additional context-specific identifiers that provide customization parameters for the feature template.
              - These identifiers enable site-specific and WLAN-specific customization of the template during deployment.
              - Each identifier contains key-value pairs that help adapt the template for specific deployment scenarios and locations.
              - Multiple identifiers can be specified to support complex deployment requirements with different WLAN profiles and site contexts.
            type: list
            elements: dict
            required: false
            suboptions:
              wlan_profile_name:
                description: |
                  - The WLAN profile name to be associated with the feature template during wireless controller provisioning.
                  - This profile defines wireless network parameters including SSID, security settings, VLAN assignments, and QoS policies.
                  - The WLAN profile must exist in Cisco Catalyst Center and be properly configured before template application.
                  - Multiple WLAN profiles can be referenced by specifying multiple additional identifier entries.
                type: str
                required: false
              site_name_hierarchy:
                description: |
                  - The site name hierarchy where the feature template should be applied during wireless controller provisioning.
                  - Defines the specific site context for template deployment within the organizational hierarchy.
                  - Must follow the format 'Global/Area/Building/Floor' as configured in Cisco Catalyst Center site topology.
                  - The site hierarchy must exist in Cisco Catalyst Center before template application.
                  - Used to apply site-specific configurations and policies defined in the feature template.
                type: str
                required: false
          excluded_attributes:
            description: |
              - A list of specific template attributes to be excluded from the feature template application during wireless controller provisioning.
              - Use this to selectively apply only certain parts of a template while excluding others that may not be applicable to the specific deployment.
              - Attribute names must match the exact attribute names defined in the feature template configuration.
              - This provides fine-grained control over which template configurations are applied, allowing for customized deployments.
              - Useful for scenarios where most of the template is applicable but specific settings need to be omitted or handled separately.
            type: list
            elements: str
            required: false
            choices: ['["guest_ssid_settings", "bandwidth_limits"]',
              '["dhcp_pool_configuration"]',
              '["radius_server_config", "certificate_settings"]',
              '["qos_policies", "traffic_shaping"]',
              '["mesh_configuration", "ap_group_settings"]']
      application_telemetry:
        description: |
          - A list of settings for enabling or disabling application telemetry on a group of network devices.
          - Supported in Cisco Catalyst version 2.3.7.9 and later.
        type: list
        elements: dict
        suboptions:
          device_ips:
            description: A list of IP addresses representing
              the network devices on which application
              telemetry should be enabled or disabled.
            type: list
            elements: str
          telemetry:
            description: |
              - Specifies whether to enable or disable application telemetry on the devices.
            type: str
            choices: ["enable", "disable"]
          wlan_mode:
            description: |
              - Defines the WLAN mode for the device.
              - Applicable when enabling telemetry on wireless devices
            type: str
            choices: ["LOCAL", "NON_LOCAL"]
          include_guest_ssid:
            description: A flag that indicates whether
              to include guest SSID information when
              enabling telemetry for wireless devices.
            type: bool
            default: false
requirements:
  - dnacentersdk == 2.4.5
  - python >= 3.9
notes:
  - SDK Methods used are sites.Sites.get_site,
    devices.Devices.get_network_device_by_ip,
    task.Task.get_task_by_id,
    sda.Sda.get_provisioned_wired_device,
    sda.Sda.re_provision_wired_device,
    sda.Sda.provision_wired_device,
    wireless.Wireless.provision devices.Device.delete_network_device_with_configuration_cleanup,
    devices.Device.delete_a_network_device_without_configuration_cleanup,
    application_policy.ApplicationPolicy.enable_application_telemetry_feature_on_multiple_network_devices_v1,
    application_policy.ApplicationPolicy.disable_application_telemetry_feature_on_multiple_network_devices_v1
  - Paths used are
    get /dna/intent/api/v1/site get /dna/intent/api/v1/network-device/ip-address/{ipAddress}
    get /dna/intent/api/v1/task/{taskId} get /dna/intent/api/v1/business/sda/provision-device
    put /dna/intent/api/v1/business/sda/provision-device
    post /dna/intent/api/v1/business/sda/provision-device
    post /dna/intent/api/v1/wireless/provision delete
    /dna/intent/api/v1/networkDevices/deleteWithCleanup
    delete /dna/intent/api/v1/networkDevices/deleteWithoutCleanup
    post /dna/intent/api/v1/applicationVisibility/networkDevices/enableAppTelemetry
    post /dna/intent/api/v1/applicationVisibility/networkDevices/disableAppTelemetry
  - Added 'provisioning' option in v6.16.0
  - Added provisioning and reprovisioning of wireless
    devices in v6.16.0
"""
EXAMPLES = r"""
---
- name: Provision a wireless device to a site
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: merged
    config:
      - site_name_hierarchy: Global/USA/San Francisco/BGL_18
        management_ip_address: 204.192.3.40
        managed_ap_locations:
          - Global/USA/San Francisco/BGL_18/Test_Floor2
        dynamic_interfaces:
          - vlan_id: 1866
            interface_name: Vlan1866
            interface_ip_address: 204.192.6.200
            interface_gateway: 204.192.6.1
- name: Provision a wireless device to a site for version
    - 2.3.7.6
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: merged
    config:
      - site_name_hierarchy: Global/USA/San Francisco/BGL_18
        management_ip_address: 204.192.3.40
        primary_managed_ap_locations:
          - Global/USA/San Francisco/BGL_18/Test_Floor2
        secondary_managed_ap_locations:
          - Global/USA/San Francisco/BGL_18/Test_Floor1
        dynamic_interfaces:
          - interface_name: Vlan1866
            vlan_id: 1866
            interface_ip_address: 204.192.6.200
            interface_gateway: 204.192.6.1
        skip_ap_provision: false
        rolling_ap_upgrade:
          enable_rolling_ap_upgrade: false
          ap_reboot_percentage: 5
        ap_authorization_list_name: "AP-Auth-List"
        authorize_mesh_and_non_mesh_aps: true

- name: Provision a wired device to a site
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: merged
    config:
      - site_name_hierarchy: Global/USA/San Francisco/BGL_18
        management_ip_address: 204.192.3.40
- name: Re-Provision a wired device to a site forcefully
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: merged
    config:
      - site_name_hierarchy: Global/USA/San Francisco/BGL_18
        management_ip_address: 204.192.3.40
        force_provisioning: true
- name: Assign a wired device to a site
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: merged
    config:
      - site_name_hierarchy: Global/USA/San Francisco/BGL_18
        management_ip_address: 204.192.3.40
        provisioning: false
- name: Provision a wireless device to a site
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: merged
    config_verify: true
    config:
      - site_name_hierarchy: Global/USA/RTP/BLD11
        management_ip_address: 204.192.12.201
        managed_ap_locations:
          - Global/USA/RTP/BLD11/BLD11_FLOOR1
- name: Unprovision a device from a site
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: deleted
    config_verify: true
    config:
      - management_ip_address: 204.1.2.2
- name: Unprovision a device from a site
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    state: deleted
    config_verify: true
    config:
      - management_ip_address: 204.1.2.2
        clean_config: true
- name: Configure application telemetry for network
    devices on Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Enable application telemetry on specified
        network devices
      cisco.dnac.provision_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_telemetry:
              - device_ips: ["204.1.1.2", "204.192.6.200"]
                telemetry: enable
                wlan_mode: LOCAL
                include_guest_ssid: true
- name: Configure application telemetry for network
    devices on Cisco Catalyst Center
  hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Disable application telemetry on specified
        network devices
      cisco.dnac.provision_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        config_verify: false
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: merged
        config:
          - application_telemetry:
              - device_ips: ["204.1.1.2", "204.192.6.200"]
                telemetry: disable

- name: Provision a wireless device to a site with feature template
  cisco.dnac.provision_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: false
    dnac_api_task_timeout: 1000
    dnac_task_poll_interval: 1
    state: merged
    config:
      - site_name_hierarchy: Global/USA/SAN JOSE/BLD23
        management_ip_address: 204.192.4.2
        primary_managed_ap_locations:
          - Global/USA/SAN JOSE/BLD23/FLOOR1_LEVEL2
        feature_template:
          - design_name: newtest
            additional_identifiers:
              wlan_profile_name: ARUBA_SSID_profile
              site_name_hierarchy: Global/USA/SAN JOSE/BLD23
            excluded_attributes: ["guest_ssid_settings", "bandwidth_limits"]
"""
RETURN = r"""
# Case_1: Successful creation/updation/deletion of provision
response_1:
  description: A dictionary with details of provision is returned
  returned: always
  type: dict
  sample: >
    {
      "response":
      {
        "response": String,
        "version": String
        },
      "msg": String
    }
# Case_2: Error while creating a provision
response_2:
  description: A list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }
# Case_3: Already exists and requires no update
response_3:
  description: A dictionary with the exisiting details as returned by the Cisco Cisco Catalyst Center  Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": String,
      "msg": String
    }
"""
import time
import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class Provision(DnacBase):
    """
    Class containing member attributes for provision workflow module
    """

    def __init__(self, module):
        super().__init__(module)
        self.device_type = None
        self.device_deleted = []
        self.already_provisioned_wired_device = []
        self.already_provisioned_wireless_device = []
        self.provisioned_wired_device = []
        self.provisioned_wireless_device = []
        self.re_provision_wired_device = []
        self.re_provision_wireless_device = []
        self.enable_application_telemetry = []
        self.disable_application_telemetry = []
        self.assigned_device_to_site = []

    def validate_input(self, state=None):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Args:
            self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
                - self.validated_config: If successful, a validated version of the
                  'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
            If the validation succeeds, 'self.status' will be 'success' and
            'self.validated_config' will contain the validated configuration. If it fails,
            'self.status' will be 'failed', and 'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.msg = "config not available in playbook for validation"
            self.status = "success"
            return self

        provision_spec = {
            "management_ip_address": {"type": "str", "required": False},
            "managed_ap_locations": {
                "type": "list",
                "required": False,
                "elements": "str",
            },
            "site_name_hierarchy": {"type": "str", "required": False},
            "primary_managed_ap_locations": {
                "type": "list",
                "required": False,
                "elements": "str",
            },
            "secondary_managed_ap_locations": {
                "type": "list",
                "required": False,
                "elements": "str",
            },
            "dynamic_interfaces": {
                "type": "list",
                "required": False,
                "elements": "dict",
            },
            "skip_ap_provision": {"type": "bool", "required": False},
            "rolling_ap_upgrade": {"type": "dict", "required": False},
            "ap_authorization_list_name": {"type": "str", "required": False},
            "authorize_mesh_and_non_mesh_aps": {"type": "bool", "required": False, "default": False},
            "provisioning": {"type": "bool", "required": False, "default": True},
            "force_provisioning": {"type": "bool", "required": False, "default": False},
            "clean_config": {"type": "bool", "required": False, "default": False},
            "application_telemetry": {
                "type": "list",
                "elements": "dict",
                "options": {
                    "device_ips": {"type": "list", "elements": "str", "required": True},
                    "telemetry": {"type": "str", "required": True},
                    "wlan_mode": {"type": "str", "required": False},
                    "include_guest_ssid": {
                        "type": "bool",
                        "required": False,
                        "default": False,
                    },
                },
            },
            "feature_template": {
                "type": "list",
                "elements": "dict",
                "options": {
                    "design_name": {"type": "str", "required": True},
                    "attributes": {"type": "dict", "required": True},
                    "additional_identifiers": {"type": "dict", "required": False},
                    "excluded_attributes": {
                        "type": "list",
                        "elements": "str",
                        "required": False,
                    },
                },
            }
        }

        if state == "merged":
            application_telemetry_present = any(
                "application_telemetry" in config_item for config_item in self.config
            )
            missing_params = []

            if application_telemetry_present:
                self.log("Detected 'application_telemetry' in the configuration")

                for config_item in self.config:
                    telemetry_list = config_item.get("application_telemetry", [])
                    for index, config_item in enumerate(self.config):
                        telemetry_list = config_item.get("application_telemetry", [])

                        # Validate each telemetry entry
                        for entry_index, telemetry_entry in enumerate(telemetry_list):

                            if (
                                "device_ips" not in telemetry_entry
                                or not telemetry_entry["device_ips"]
                            ):
                                missing_params.append("device_ips")
                                self.log(
                                    "Missing or empty 'device_ips' in 'application_telemetry' at config item {}, telemetry entry {}.".format(
                                        index, entry_index
                                    ),
                                    "DEBUG",
                                )

                            if (
                                "telemetry" not in telemetry_entry
                                or telemetry_entry["telemetry"] is None
                            ):
                                missing_params.append("telemetry")
                                self.log(
                                    "Missing or empty 'telemetry' in 'application_telemetry' at config item {}, telemetry entry {}.".format(
                                        index, entry_index
                                    ),
                                    "DEBUG",
                                )

                if missing_params:
                    self.msg = "Missing or invalid required parameter(s) in application_telemetry: {0}".format(
                        ", ".join(set(missing_params))
                    )
                    self.log(self.msg, "ERROR")
                    self.status = "failed"
                    return self

            else:
                self.log(
                    "'application_telemetry' not found. Validating other required parameters.",
                    "INFO",
                )
                provision_spec["site_name_hierarchy"] = {
                    "type": "str",
                    "required": True,
                }
                for index, config_item in enumerate(self.config):
                    if (
                        "site_name_hierarchy" not in config_item
                        or not config_item["site_name_hierarchy"]
                        or not isinstance(config_item["site_name_hierarchy"], str)
                    ):
                        missing_params.append("site_name_hierarchy")
                        self.log(
                            "Missing or empty 'site_name_hierarchy' in config item at index {0}.".format(
                                index
                            ),
                            "ERROR",
                        )

                    if (
                        "management_ip_address" not in config_item
                        or not config_item["management_ip_address"]
                    ):
                        missing_params.append("management_ip_address")
                        self.log(
                            "Missing or empty 'management_ip_address' in config item at index {0}.".format(
                                index
                            ),
                            "ERROR",
                        )

                    if "provisioning" in config_item:
                        valid_bools = [True, False]
                        provisioning_value = config_item["provisioning"]
                        if provisioning_value not in valid_bools:
                            self.msg = (
                                "Invalid value '{0}' for 'provisioning' in config. "
                                "Expected a boolean-compatible value.".format(provisioning_value)
                            )
                            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                if missing_params:
                    self.msg = "Missing or invalid required parameter(s): {0}".format(
                        ", ".join(set(missing_params))
                    )
                    self.status = "failed"
                    return self

        valid_provision, invalid_params = validate_list_of_dicts(
            self.config, provision_spec
        )
        if invalid_params:
            self.log(
                "Invalid parameters found in the playbook configuration: {0}".format(
                    "\n".join(invalid_params)), "ERROR"
            )
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.log(str(self.msg), "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_provision
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_provision)
        )
        self.log(str(self.msg), "INFO")
        self.status = "success"
        return self

    def get_dev_type(self):
        """
        Fetches the type of device (wired/wireless)

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          str: The type of the device ('wired' or 'wireless'), or None if the device is
              unrecognized, not present, or an error occurs.
        Example:
          Post creation of the validated input, we use this method to get the
          type of the device.
        """
        try:
            dev_response = self.dnac_apply["exec"](
                family="devices",
                function="get_network_device_by_ip",
                params={"ip_address": self.validated_config["management_ip_address"]},
            )

            self.log(
                "The device response from 'get_network_device_by_ip' API is {0}".format(
                    str(dev_response)
                ),
                "DEBUG",
            )

            dev_dict = dev_response.get("response", {})
            if not dev_dict:
                self.log(
                    "Invalid response received from the API 'get_network_device_by_ip'. 'response' is empty or missing.",
                    "WARNING",
                )
                return None

            device_family = dev_dict.get("family")
            if not device_family:
                self.log("Device family is missing in the response.", "WARNING")
                return None

            if device_family == "Wireless Controller":
                device_type = "wireless"
            elif device_family in ["Switches and Hubs", "Routers"]:
                device_type = "wired"
            else:
                device_type = None

            self.log("The device type is {0}".format(device_type), "INFO")

            return device_type

        except Exception as e:
            msg = "The Device - {0} not present in the Cisco Catalyst Center.".format(
                self.validated_config.get("management_ip_address")
            )
            self.log(msg, "INFO")

            return None

    def get_device_id(self):
        """
        Fetches the UUID of the device added in the inventory

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns the serial number of the device as a string. If it fails, it returns None.
        Example:
          After creating the validated input, this method retrieves the
          UUID of the device.
        """
        try:
            dev_response = self.dnac_apply["exec"](
                family="devices",
                function="get_network_device_by_ip",
                params={"ip_address": self.validated_config["management_ip_address"]},
            )

            self.log(
                "The device response from 'get_network_device_by_ip' API is {0}".format(
                    str(dev_response)
                ),
                "DEBUG",
            )
            dev_dict = dev_response.get("response")
            device_id = dev_dict.get("id")

            self.log(
                "Device ID of the device with IP address {0} is {1}".format(
                    self.validated_config["management_ip_address"], device_id
                ),
                "INFO",
            )

        except Exception as e:
            self.msg = (
                "The Device - {0} not present in the Cisco Catalyst Center.".format(
                    self.validated_config.get("management_ip_address")
                )
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return device_id

    def get_device_id_for_app_telemetry(self):
        """
        Fetches the UUID of the device added in the inventory for application telemetry
        using its management IP address.

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
            str: The UUID of the device as a string if found successfully.
            None: If the device is not found in Cisco Catalyst Center or an error occurs.
        Example:
          After creating the validated input, this method retrieves the
          UUID of the device.
        """
        self.log(
            "Fetching device UUID for application telemetry for IP: {}".format(
                self.validated_config.get("management_ip_address", "N/A")
            ),
            "DEBUG"
        )
        try:
            dev_response = self.dnac_apply["exec"](
                family="devices",
                function="get_network_device_by_ip",
                params={"ip_address": self.validated_config["management_ip_address"]},
            )

            self.log(
                "The device response from 'get_network_device_by_ip' API is {0}".format(
                    str(dev_response)
                ),
                "DEBUG",
            )
            dev_dict = dev_response.get("response")
            if not dev_dict:
                self.msg = (
                    "No device response found for IP address {0} from Cisco Catalyst Center.".format(
                        self.validated_config.get("management_ip_address")
                    )
                )
                self.log(self.msg, "ERROR")
                return None

            device_id = dev_dict.get("id")

            if not device_id:
                self.msg = (
                    "Device ID not found in the response for IP address {0}.".format(
                        self.validated_config.get("management_ip_address")
                    )
                )
                self.log(self.msg, "ERROR")
                return None

            self.log(
                "Device ID of the device with IP address {0} is {1}".format(
                    self.validated_config["management_ip_address"], device_id
                ),
                "INFO",
            )
            return device_id

        except Exception as e:
            self.msg = "Failed to retrieve device ID for {0}. Error: {1}".format(
                self.validated_config.get("management_ip_address"), str(e)
            )
            self.log(self.msg, "ERROR")

            return None

    def get_task_status(self, task_id=None):
        """
        Fetches the status of the task once any provision API is called

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
          - task_id: Task_id of the provisioning task.
        Returns:
          The method returns the status of the task_id used to track provisioning.
          Returns True if task is not failed otheriwse returns False.
        Example:
          Post creation of the provision task, this method fetheches the task
          status.

        """
        result = False
        params = {"task_id": task_id}
        while True:
            response = self.dnac_apply["exec"](
                family="task", function="get_task_by_id", params=params
            )
            self.log(
                "Response collected from 'get_task_by_id' API is {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.response
            self.log(
                "Task status for the task id {0} is {1}".format(
                    str(task_id), str(response.get("progress"))
                ),
                "INFO",
            )
            if response.get("isError") or re.search(
                "failed", response.get("progress"), flags=re.IGNORECASE
            ):
                msg = (
                    "Provision task with id {0} has not completed - Reason: {1}".format(
                        task_id, response.get("failureReason")
                    )
                )
                self.module.fail_json(msg=msg)
                return False

            if (
                response.get("progress") in ["TASK_PROVISION", "TASK_MODIFY_PUT"]
                and response.get("isError") is False
            ) or "deleted successfully" in response.get("progress"):

                result = True
                break

            time.sleep(3)
        self.result.update(dict(provision_task=response))
        return result

    def get_execution_status_wireless(self, execution_id=None):
        """
        Fetches the status of the BAPI once site wireless provision API is called

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
          - execution_id: execution_id of the BAPI API.
        Returns:
          The method returns the status of the BAPI used to track wireless provisioning.
          Returns True if the status is not failed, otheriwse returns False.
        Example:
          Post creation of the provision task, this method fetheches the task
          status.

        """
        result = False
        params = {"execution_id": execution_id}
        while True:
            response = self.dnac_apply["exec"](
                family="task",
                function="get_business_api_execution_details",
                params=params,
            )
            self.log(
                "Response collected from 'get_business_api_execution_details' API is {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            self.log(
                "Execution status for the execution id {0} is {1}".format(
                    str(execution_id), str(response.get("status"))
                ),
                "INFO",
            )
            if response.get("bapiError") or response.get("status") == "FAILURE":
                if (
                    response.get("bapiError")
                    == "Device was already provisioned , please use provision update API to reprovision the device"
                ):
                    msg = "Performing reprovisioning of wireless device"
                    result = True
                    self.perform_wireless_reprovision()
                    break
                msg = "Wireless provisioning execution with id {0} has not completed - Reason: {1}".format(
                    execution_id, response.get("bapiError")
                )
                self.module.fail_json(msg=msg)
                return False

            if response.get("status") == "SUCCESS":
                result = True
                break

            time.sleep(3)
        self.result.update(dict(assignment_task=response))
        return result

    def get_site_type(self, site_name_hierarchy=None):
        """
        Fetches the type of site

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
          - site_name_hierarchy: Name of the site collected from the input.
        Returns:
          - site_type: A string indicating the type of the site (area/building/floor).
        Example:
          Post creation of the validated input, this method gets the
          type of the site.
        """

        try:
            response = self.dnac_apply["exec"](
                family="sites",
                function="get_site",
                params={"name": site_name_hierarchy},
            )
        except Exception:
            self.log(
                "Exception occurred as \
                site '{0}' was not found".format(
                    site_name_hierarchy
                ),
                "CRITICAL",
            )
            self.module.fail_json(msg="Site not found", response=[])

        if response:
            self.log(
                "Received site details\
                for '{0}': {1}".format(
                    site_name_hierarchy, str(response)
                ),
                "DEBUG",
            )
            site = response.get("response")
            site_additional_info = site[0].get("additionalInfo")
            for item in site_additional_info:
                if item["nameSpace"] == "Location":
                    site_type = item.get("attributes").get("type")
                    self.log(
                        "Site type for site name '{1}' : {0}".format(
                            site_type, site_name_hierarchy
                        ),
                        "INFO",
                    )

        return site_type

    def is_device_assigned_to_site(self, uuid):
        """
        Checks if a device, specified by its UUID, is assigned to any site.

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
          - uuid (str): The UUID of the device to check for site assignment.
        Returns:
          - boolean:  True if the device is assigned to a site, False otherwise.

        """

        self.log(
            "Checking site assignment for device with UUID: {0}".format(uuid), "INFO"
        )
        try:
            site_response = self.dnac_apply["exec"](
                family="devices",
                function="get_device_detail",
                params={"search_by": uuid, "identifier": "uuid"},
            )
            self.log(
                "Response collected from the API 'get_device_detail' {0}".format(
                    site_response
                )
            )
            site_response = site_response.get("response")
            if site_response.get("location"):
                return True
            else:
                return False
        except Exception as e:
            msg = "Failed to find device with UUID {0} due to: {1}".format(uuid, e)
            self.log(msg, "CRITICAL")
            self.module.fail_json(msg=msg)

    def is_device_assigned_to_site_v1(self, uuid):
        """
        Checks if a device, specified by its UUID, is assigned to any site.

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
          - uuid (str): The UUID of the device to check for site assignment.
        Returns:
          - tuple: (bool, Optional[str])
            - True and the site name if the device is assigned to a site.
            - False and None if not assigned or in case of an error..

        """

        self.log(
            "Checking site assignment for device with UUID: {0}".format(uuid), "INFO"
        )
        try:
            site_api_response = self.dnac_apply["exec"](
                family="site_design",
                function="get_site_assigned_network_device",
                params={"id": uuid},
            )

            self.log(
                "Response collected from the API 'get_site_assigned_network_device' {0}".format(
                    site_api_response
                )
            )
            site_response = site_api_response.get("response")

            if site_response:
                site_name = site_response.get("siteNameHierarchy")
                if site_name:
                    self.log(
                        "Device with UUID {0} is assigned to site: {1}".format(
                            uuid, site_name
                        ),
                        "INFO",
                    )
                    return True, site_name

            self.log(
                "Device with UUID {0} is not assigned to any site.".format(uuid), "INFO"
            )
            return False, None

        except Exception as e:
            msg = "Failed to find device with UUID {0} due to: {1}".format(uuid, e)
            self.log(msg, "CRITICAL")
            self.module.fail_json(msg=msg)

    def get_device_site_by_uuid(self, uuid):
        """
        Checks if a device is assigned to any site.

        Parameters:
        - self: The instance of the class containing the 'config' attribute
                to be validated.
        - uuid (str): The UUID of the device to check for site assignment.
        Returns:
        - location (str): The location of the site if the device is assigned,
                            None otherwise.
        """

        self.log(
            "Checking site assignment for device with UUID: {0}".format(uuid), "INFO"
        )

        try:
            site_response = self.dnac_apply["exec"](
                family="devices",
                function="get_device_detail",
                params={"search_by": uuid, "identifier": "uuid"},
            )
            self.log(
                "Response collected from the API 'get_device_detail': {0}".format(
                    site_response
                )
            )

            site_response = site_response.get("response")
            if site_response and site_response.get("location"):
                location = site_response.get("location")
                return location
            else:
                self.log(
                    "No site assignment found for device with UUID: {0}".format(uuid),
                    "INFO",
                )
                return None

        except Exception as e:
            msg = "Failed to find device with location for UUID {0} due to: {1}".format(
                uuid, e
            )
            self.log(msg, "CRITICAL")
            self.module.fail_json(msg=msg)

    def get_wired_params(self):
        """
        Prepares the payload for provisioning of the wired devices

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - wired_params: A dictionary containing all the values indicating
                          management IP address of the device and the hierarchy
                          of the site.
        Example:
          Post creation of the validated input, it fetches the required
          paramters and stores it for further processing and calling the
          parameters in other APIs.
        """

        site_name = self.validated_config.get("site_name_hierarchy")

        (site_exits, site_id) = self.get_site_id(site_name)

        if site_exits is False:
            msg = "Site {0} doesn't exist".format(site_name)
            self.log(msg, "CRITICAL")
            self.module.fail_json(msg=msg)

        if self.validated_config.get("provisioning") is True:
            wired_params = {
                "deviceManagementIpAddress": self.validated_config[
                    "management_ip_address"
                ],
                "siteNameHierarchy": site_name,
            }
        else:
            wired_params = {
                "device": [{"ip": self.validated_config["management_ip_address"]}],
                "site_id": site_id,
            }

        self.log(
            "Parameters collected for the provisioning of wired device:{0}".format(
                wired_params
            ),
            "INFO",
        )
        return wired_params

    def get_wireless_params(self):
        """
        Prepares the payload for provisioning of the wireless devices

        Parameters:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - wireless_params: A list of dictionary containing all the values indicating
                          management IP address of the device, hierarchy
                          of the site, AP Location of the wireless controller and details
                          of the interface
        Example:
          Post creation of the validated input, it fetches the required
          paramters and stores it for further processing and calling the
          parameters in other APIs.
        """
        ip_address = self.validated_config.get("management_ip_address")
        ap_locations = self.validated_config.get(
            "primary_managed_ap_locations"
        ) or self.validated_config.get("managed_ap_locations")
        wireless_params = [
            {
                "site": self.validated_config.get("site_name_hierarchy"),
                "managedAPLocations": ap_locations,
            }
        ]

        if not ap_locations:
            self.log("Validating AP locations: {0}".format(ap_locations), "DEBUG")
            self.msg = (
                "Missing Managed AP Locations or Primary Managed AP Locations: "
                "Please specify the intended location(s) for the wireless device {0} "
                "within the site hierarchy".format(ip_address)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        ap_locations = self.validated_config.get(
            "primary_managed_ap_locations"
        ) or self.validated_config.get("managed_ap_locations")

        self.floor_names = []

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
            for ap_loc in ap_locations:
                self.log("Processing AP location: {0}".format(ap_loc), "DEBUG")
                site_type = self.get_site_type(site_name_hierarchy=ap_loc)
                self.log(
                    "Resolved site type for AP location '{0}': '{1}'".format(
                        ap_loc, site_type
                    ),
                    "DEBUG",
                )

                if site_type == "floor":
                    self.log(
                        "Site type is 'floor'. Adding '{0}' to the floor names list.".format(
                            ap_loc
                        ),
                        "DEBUG",
                    )
                    self.floor_names.append(ap_loc)
                elif site_type == "building":
                    self.log(
                        "Site type is 'building'. Retrieving floor details for building '{0}'.".format(
                            ap_loc
                        ),
                        "DEBUG",
                    )
                    building_name = ap_loc + ".*"
                    floors = self.get_site(building_name)

                    if "response" in floors and isinstance(floors["response"], list):
                        for item in floors["response"]:
                            if item.get("type") == "floor":
                                self.log(
                                    "Floor found: '{0}' for building '{1}'.".format(
                                        item["nameHierarchy"], ap_loc
                                    ),
                                    "DEBUG",
                                )
                                self.floor_names.append(item["nameHierarchy"])
                            elif "additionalInfo" in item:
                                for additional_info in item["additionalInfo"]:
                                    if (
                                        "attributes" in additional_info
                                        and additional_info["attributes"].get("type")
                                        == "floor"
                                    ):
                                        self.log(
                                            "Floor found in additionalInfo: '{0}' for building '{1}'.".format(
                                                additional_info["siteNameHierarchy"],
                                                ap_loc,
                                            ),
                                            "DEBUG",
                                        )
                                        self.floor_names.append(
                                            additional_info["siteNameHierarchy"]
                                        )
                    else:
                        self.log(
                            "No floors found for building '{0}' or 'response' is invalid.".format(
                                ap_loc
                            ),
                            "DEBUG",
                        )
                else:
                    self.log(
                        "Invalid site type '{0}' for location '{1}'. Managed AP Location must be building or floor.".format(
                            site_type, ap_loc
                        ),
                        "CRITICAL",
                    )
                    self.module.fail_json(
                        msg=(
                            "Invalid site type '{0}' for location '{1}'. Managed AP Location must be building or floor.".format(
                                site_type, ap_loc
                            )
                        ),
                        response=[],
                    )

        self.log("Final list of floor names: {0}".format(self.floor_names), "DEBUG")

        wireless_params[0]["dynamicInterfaces"] = []
        if self.validated_config.get("dynamic_interfaces"):
            for interface in self.validated_config.get("dynamic_interfaces"):
                interface_dict = {
                    "interfaceIPAddress": interface.get("interface_ip_address"),
                    "interfaceNetmaskInCIDR": interface.get(
                        "interface_netmask_in_c_i_d_r"
                    ),
                    "interfaceGateway": interface.get("interface_gateway"),
                    "lagOrPortNumber": interface.get("lag_or_port_number"),
                    "vlanId": interface.get("vlan_id"),
                    "interfaceName": interface.get("interface_name"),
                }
                wireless_params[0]["dynamicInterfaces"].append(interface_dict)

        wireless_params[0]["skip_ap_provision"] = self.validated_config.get(
            "skip_ap_provision"
        )
        wireless_params[0]["primaryManagedAPLocationsSiteIds"] = ap_locations
        wireless_params[0]["secondaryManagedAPLocationsSiteIds"] = (
            self.validated_config.get("secondary_managed_ap_locations")
        )

        if self.validated_config.get("rolling_ap_upgrade"):
            rolling_ap_upgrade = self.validated_config["rolling_ap_upgrade"]
            wireless_params[0]["rolling_ap_upgrade"] = rolling_ap_upgrade
        if self.validated_config.get("ap_authorization_list_name"):
            wireless_params[0]["ap_authorization_list_name"] = self.validated_config.get("ap_authorization_list_name")
        if self.validated_config.get("authorize_mesh_and_non_mesh_aps") is not None:
            wireless_params[0]["authorize_mesh_and_non_mesh_aps"] = self.validated_config.get("authorize_mesh_and_non_mesh_aps")

        response = self.dnac_apply["exec"](
            family="devices",
            function="get_network_device_by_ip",
            params={"ip_address": self.validated_config["management_ip_address"]},
        )

        self.log(
            "Response collected from 'get_network_device_by_ip' is:{0}".format(
                str(response)
            ),
            "DEBUG",
        )
        wireless_params[0]["deviceName"] = response.get("response").get("hostname")
        wireless_params[0]["device_id"] = response.get("response").get("id")
        self.log(
            "Parameters collected for the provisioning of wireless device:{0}".format(
                wireless_params
            ),
            "INFO",
        )

        if self.validated_config.get("feature_template"):
            self.log("Processing feature template configuration for wireless device provisioning", "DEBUG")
            feature_templates = self.validated_config.get("feature_template")
            if not isinstance(feature_templates, list):
                self.msg = "Feature template configuration must be a list. Received: {0}".format(type(feature_templates).__name__)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if not feature_templates:
                self.log("Empty feature template list provided", "WARNING")
                return self

            wireless_params[0]["feature_template"] = []
            self.log("Processing feature template(s)", "INFO")

            for template_index, template in enumerate(feature_templates):
                self.log("Processing feature template {0}".format(template_index + 1), "DEBUG")
                design_name = template.get("design_name")

                if not design_name:
                    self.msg = "Feature template 'design_name' is required but not provided for template at index {0}".format(template_index)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                self.log("Processing feature template with design name: '{0}' at index {1}".format(design_name, template_index), "DEBUG")

                attributes = template.get("attributes", [])
                cleaned_attributes = []

                if attributes:
                    self.log("Processing template attributes for template '{0}'".format(design_name), "DEBUG")

                    if isinstance(attributes, dict):
                        for key, value in attributes.items():
                            if value is not None:
                                cleaned_attributes.append({
                                    "name": key,
                                    "value": value
                                })
                                self.log("Added template attribute for '{0}': '{1}' = '{2}'".format(design_name, key, value), "DEBUG")
                    elif isinstance(attributes, list):
                        self.log("Attributes provided as list for template '{0}', using directly".format(design_name), "DEBUG")
                        cleaned_attributes = attributes
                    else:
                        self.log("Invalid 'attributes' format for template '{0}'. Expected dict or list, got: {1}".format(
                            design_name, type(attributes).__name__), "WARNING")
                else:
                    self.log("No attributes provided for feature template '{0}'".format(design_name), "DEBUG")

                excluded_attributes = template.get("excluded_attributes", [])
                if excluded_attributes:
                    self.log("Processing {0} excluded attributes for template '{1}': {2}".format(
                        len(excluded_attributes), design_name, excluded_attributes), "DEBUG")
                    if not isinstance(excluded_attributes, list):
                        self.log("Invalid 'excluded_attributes' format for template '{0}'. Expected list, got: {1}".format(
                            design_name, type(excluded_attributes).__name__), "WARNING")
                        excluded_attributes = []
                else:
                    self.log("No excluded attributes specified for feature template '{0}'".format(design_name), "DEBUG")

                additional_identifiers = template.get("additional_identifiers", {})

                if additional_identifiers:
                    self.log("Processing additional identifiers for template '{0}'".format(
                        design_name), "DEBUG")
                    for idx, identifier in enumerate(additional_identifiers):
                        if isinstance(identifier, dict):
                            wlan_profile = identifier.get("wlan_profile_name")
                            site_hierarchy = identifier.get("site_name_hierarchy")
                            if wlan_profile:
                                self.log("Template '{0}' - Additional identifier {1}: WLAN profile = '{2}'".format(
                                    design_name, idx + 1, wlan_profile), "DEBUG")
                            if site_hierarchy:
                                self.log("Template '{0}' - Additional identifier {1}: Site hierarchy = '{2}'".format(
                                    design_name, idx + 1, site_hierarchy), "DEBUG")
                        else:
                            self.log("Invalid additional identifier format for template '{0}' at index {1}. Expected dict, got: {2}".format(
                                design_name, idx, type(identifier).__name__), "WARNING")

                else:
                    self.log("No additional identifiers provided for feature template '{0}'".format(design_name), "DEBUG")

                    if excluded_attributes:
                        self.log("Processing excluded attributes for template '{0}': {1}".format(
                            design_name, excluded_attributes), "DEBUG")
                        if not isinstance(excluded_attributes, list):
                            self.log("Invalid 'excluded_attributes' format for template '{0}'. Expected list, got: {1}".format(
                                design_name, type(excluded_attributes).__name__), "WARNING")
                            excluded_attributes = []
                    else:
                        self.log("No excluded attributes specified for feature template '{0}'".format(design_name), "DEBUG")

                ft_entry = {
                    "design_name": design_name,
                }
                if cleaned_attributes:
                    ft_entry["attributes"] = cleaned_attributes
                    self.log("Added cleaned attributes to feature template '{0}' entry".format(
                        design_name), "DEBUG")

                if additional_identifiers:
                    ft_entry["additional_identifiers"] = additional_identifiers
                    self.log("Added additional identifiers to feature template '{0}' entry".format(design_name), "DEBUG")

                if excluded_attributes:
                    ft_entry["excluded_attributes"] = excluded_attributes
                    self.log("Added excluded attributes to feature template '{0}' entry".format(
                        design_name), "DEBUG")

                wireless_params[0]["feature_template"].append(ft_entry)
                self.log("Successfully configured feature template '{0}' for wireless device provisioning".format(design_name), "INFO")

        self.log(
            "Parameters collected for the provisioning of wireless device: {0}".format(wireless_params),
            "INFO",
        )
        return wireless_params

    def resolve_template_id(self, design_name):
        """
        Retrieves the feature template ID for a given design name.

        Args:
            design_name (str): Name of the feature template design to match.

        Description:
            This function queries Cisco Catalyst Center to resolve a feature template design name
            to its corresponding template ID. It searches through template groups and instances,
            filtering out system templates to find user-defined templates.

        Returns:
            str or None: The featureTemplateId if found, else None.
        """
        self.log("Initiating feature template ID resolution for design name: '{0}'".format(design_name), "DEBUG")

        if not design_name:
            self.log("Design name is empty or None - cannot resolve template ID", "ERROR")
            return None

        if not isinstance(design_name, str):
            self.log("Design name must be a string, received: {0}".format(type(design_name).__name__), "ERROR")
            return None

        self.log("Querying Cisco Catalyst Center for feature template with design name: '{0}'".format(design_name), "INFO")

        try:
            ft_response = self.dnac_apply["exec"](
                family="wireless",
                function="get_feature_template_summary",
                params={'designName': design_name}
            )

            self.log("Received feature template API response from 'get_feature_template_summary': {0}".format(str(ft_response)), "DEBUG")

            template_groups = ft_response.get("response", [])
            if not template_groups:
                self.log("No template groups found in API response", "WARNING")
                return None

            self.log("Processing {0} template group(s) for design name: '{1}'".format(len(template_groups), design_name), "DEBUG")

            for group_index, template_group in enumerate(template_groups):
                self.log("Processing template group {0} of {1}".format(group_index + 1, len(template_groups)), "DEBUG")

                instances = template_group.get("instances", [])
                if not instances:
                    self.log("No instances found in template group {0}".format(group_index + 1), "DEBUG")
                    continue

                self.log("Found {0} template instance(s) in group {1}".format(len(instances), group_index + 1), "DEBUG")

                for instance_index, instance in enumerate(instances):
                    instance_design_name = instance.get("designName")
                    instance_id = instance.get("id")
                    is_system_template = instance.get("systemTemplate", False)

                    self.log("Evaluating template instance {0}: design_name='{1}', id='{2}', system_template={3}".format(
                        instance_index + 1, instance_design_name, instance_id, is_system_template), "DEBUG")

                    if instance_design_name == design_name and not is_system_template:
                        self.log("Successfully resolved feature template ID: '{0}' for design name: '{1}'".format(instance_id, design_name), "INFO")
                        return instance_id

                    if instance_design_name == design_name and is_system_template:
                        self.log("Found matching design name '{0}' but it's a system template - skipping".format(design_name), "DEBUG")

                    if instance_design_name != design_name:
                        self.log("Design name mismatch: expected '{0}', found '{1}' - skipping".format(design_name, instance_design_name), "DEBUG")

            self.log("Feature template with design name '{0}' not found after searching all template groups and instances".format(design_name), "WARNING")
            return None

        except Exception as e:
            msg = "Exception occurred while resolving feature template ID for design name '{0}': {1}".format(design_name, str(e))
            self.log(msg, "ERROR")
            return None

    def get_want(self, config):
        """
        Get all provision related informantion from the playbook
        Args:
            self: The instance of the class containing the 'config' attribute to be validated.
            config: validated config passed from the playbook
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.want: A dictionary of paramters obtained from the playbook
                - self.msg: A message indicating all the paramters from the playbook are
                collected
                - self.status: Success
        Example:
            It stores all the paramters passed from the playbook for further processing
            before calling the APIs
        """

        self.validated_config = config
        self.want = {}
        self.device_ip = self.validated_config["management_ip_address"]
        state = self.params.get("state")

        application_telemetry = self.validated_config.get("application_telemetry", [])

        MIN_SUPPORTED_VERSION = "2.3.7.9"
        current_version = self.get_ccc_version()
        self.log(
            "Current Catalyst Center version is {0}".format(current_version), "DEBUG"
        )
        if application_telemetry:
            if self.compare_dnac_versions(current_version, MIN_SUPPORTED_VERSION) >= 0:
                self.log(
                    "Current Catalyst Center version ({0}) supports application telemetry.".format(
                        current_version
                    ),
                    "DEBUG",
                )
                self.log(
                    "Application telemetry configuration detected: {0}".format(
                        application_telemetry
                    ),
                    "DEBUG",
                )
                self.want["application_telemetry"] = application_telemetry

            else:
                self.msg = "Application telemetry is available only in version {0} or higher. Current version: {1}".format(
                    MIN_SUPPORTED_VERSION, current_version
                )
                self.log(self.msg, "ERROR")
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
        else:
            self.log(
                "No application telemetry configuration found in the validated config.",
                "DEBUG",
            )

        self.want["device_type"] = self.get_dev_type()

        if self.want["device_type"] == "wired":
            self.want["prov_params"] = self.get_wired_params()
        elif self.want["device_type"] == "wireless":
            if state.lower() == "merged":
                self.want["prov_params"] = self.get_wireless_params()
        else:
            self.log("Passed devices are neither wired or wireless devices", "WARNING")

        self.msg = (
            "Successfully collected all parameters from playbook " + "for comparison"
        )
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def perform_wireless_reprovision(self):
        """
        This method performs the reprovisioning of a wireless device. Since, we don't have any
        APIs to get provisioned wireless devices, so we are reprovisioning based on the failure
        condition of the device
        Parameters:
            - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
            object: An instance of the class with updated results and status
            based on the processing of differences.
        Example:
            If wireless device is already provisioned, this method calls the provision update
            API and handles it accordingly
        """
        device_id = self.get_device_id()
        self.log("Retrieved device ID: {0}".format(device_id), "DEBUG")
        prov_params = self.want.get("prov_params")[0]
        already_provisioned_site = self.get_device_site_by_uuid(device_id)

        if already_provisioned_site != self.site_name:
            self.log("Device re-provisioning logic triggered.", "INFO")
            self.msg = (
                "Error in re-provisioning a wireless device '{0}' - the device is already associated "
                "with Site: {1} and cannot be re-provisioned to Site {2}.".format(
                    self.device_ip, already_provisioned_site, self.site_name
                )
            )
            self.log(self.msg, "ERROR")
            self.result["response"] = self.msg
            self.status = "failed"
            self.check_return_status()

        param = [
            {
                "deviceName": prov_params.get("deviceName"),
                "site": prov_params.get("site"),
                "managedAPLocations": self.floor_names,
                "dynamicInterfaces": prov_params.get("dynamicInterfaces"),
            }
        ]

        try:
            headers_payload = {"__persistbapioutput": "true"}
            response = self.dnac_apply["exec"](
                family="wireless",
                function="provision_update",
                op_modifies=True,
                params={"payload": param, "headers": headers_payload},
            )
            self.log(
                "Wireless provisioning response collected from 'provision_update' API is: {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            execution_id = response.get("executionId")
            self.get_execution_status_wireless(execution_id=execution_id)
            self.result["changed"] = True
            self.result["msg"] = (
                "Wireless device with IP address {0} got re-provisioned successfully".format(
                    self.validated_config["management_ip_address"]
                )
            )
            self.result["diff"] = self.validated_config
            self.result["response"] = execution_id
            self.log(self.result["msg"], "INFO")
            return self
        except Exception as e:
            self.log("Parameters are {0}".format(self.want))
            self.msg = "Error in wireless re-provisioning of {0} due to {1}".format(
                self.validated_config["management_ip_address"], e
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

    def get_device_provision_status_for_wlc(self):
        """
        Retrieves the provisioning status of a device based on its management IP address.

        Returns:
            str: The provisioning status of the device, either 'success' or 'failed'.
        Description:
            Depending on the Cisco Catalyst Center (CCC) version, this function calls different APIs to
            check if a device is provisioned. It handles both wired and wireless device provisioning
            checks and logs relevant status and errors.
        """

        status = "failed"
        device_management_ip = self.validated_config.get("management_ip_address")
        self.log(
            "Checking provisioning status for device with management IP '{0}' '".format(
                device_management_ip
            ),
            "DEBUG",
        )
        try:
            status_response = self.dnac_apply["exec"](
                family="sda",
                function="get_provisioned_wired_device",
                params={"device_management_ip_address": device_management_ip},
            )

            if isinstance(status_response, dict):
                self.log(
                    "Received API response for device '{0}': {1}".format(
                        device_management_ip, status_response
                    ),
                    "DEBUG",
                )
                status = status_response.get("status", "failed")
            else:
                self.log(
                    "Invalid or empty response received for device with management IP '{}'".format(
                        device_management_ip
                    ),
                    "DEBUG",
                )

        except Exception as e:
            self.log(
                "Device '{0}' is not provisioned due to error: {1}".format(
                    device_management_ip, str(e)
                ),
                "ERROR",
            )
            status = "failed"

        self.log(
            "Final provisioning status for device '{}': '{}'".format(
                device_management_ip, status
            ),
            "DEBUG",
        )
        return status

    def get_diff_merged(self):
        """
        Process and merge device provisioning differences.

        Args:
            self: An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self: An instance of the class with updated results and status based on
            the processing of device provisioning differences.

        Description:
            - Processes device provisioning differences by checking device types and provisioning statuses.
            - Handles both wired and wireless devices:
                1. Wired Devices:
                    - Provisions the device if required.
                    - Uses the `provision_wired_device()` function to perform provisioning.
                2. Wireless Devices:
                    - Checks the current provisioning status.
                    - If already provisioned and `force_provisioning` is not enabled, logs a message and exits.
                    - Otherwise, it proceeds with provisioning using `provision_wireless_device()`.
            - Applies version-based checks using `compare_dnac_versions()`:
                - Devices running ≤ 2.3.5.3 always follow this provisioning logic.
                - Wireless devices running ≥ 2.3.7.6 also follow this logic.
            - If these conditions are not met, bulk provisioning for wired devices is handled via `provision_bulk_wired_device()`.
            - Any errors encountered are logged appropriately.
        """

        # Retrieve the current Cisco Catalyst Center version for comparison
        ccc_version = self.get_ccc_version()
        self.log("Fetched CCC version: {0}".format(ccc_version), "DEBUG")

        # Check if provisioning should be handled based on DNAC version:
        # - If DNAC version is ≤ 2.3.5.3, always proceed with provisioning logic.
        # - If DNAC version is ≥ 2.3.7.6 AND the device is wireless, follow wireless provisioning logic.

        if self.compare_dnac_versions(ccc_version, "2.3.5.3") <= 0 or (
            self.compare_dnac_versions(ccc_version, "2.3.7.6") >= 0
            and self.device_type == "wireless"
        ):
            # Fetch device details from validated config
            self.log(
                "Proceeding with provisioning logic based on CCC version and device type",
                "DEBUG",
            )
            device_type = self.want.get("device_type")
            to_force_provisioning = self.validated_config.get("force_provisioning")
            to_provisioning = self.validated_config.get("provisioning")
            self.device_ip = self.validated_config["management_ip_address"]
            self.site_name = self.validated_config["site_name_hierarchy"]
            self.log(
                "Device Type: {0}, Device IP: {1}, Site: {2}".format(
                    device_type, self.device_ip, self.site_name
                ),
                "DEBUG",
            )

            if device_type == "wired":
                self.log(
                    "Initiating provisioning for wired device: {0}".format(
                        self.device_ip
                    ),
                    "INFO",
                )
                self.provision_wired_device(to_provisioning, to_force_provisioning)

            elif device_type == "wireless":
                self.log(
                    "Checking provisioning status for wireless device: {0}".format(
                        self.device_ip
                    ),
                    "DEBUG",
                )
                status = self.get_device_provision_status_for_wlc()
                if status == "success":

                    if not to_force_provisioning:
                        self.msg = (
                            "Wireless Device '{0}' is already provisioned.".format(
                                self.device_ip
                            )
                        )
                        self.already_provisioned_wireless_device.append(self.device_ip)
                        return self

                self.log("Starting wireless device provisioning...", "INFO")
                self.provision_wireless_device()

            else:
                self.msg = "Exception occurred while getting the device type, device '{0}' is not present in the cisco catalyst center".format(
                    self.device_ip
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        elif self.want.get("application_telemetry"):
            telemetry_config = self.want
            self.log(
                "Application telemetry config found. Proceeding with telemetry logic...",
                "DEBUG",
            )
            self.application_telemetry(telemetry_config)

        else:
            self.log(
                "Skipping individual provisioning. Initiating bulk provisioning for wired devices.",
                "INFO",
            )
            self.provision_bulk_wired_device()

        return self

    def application_telemetry(self, telemetry_config):
        """
        Enables or disables application telemetry on network devices based on the given telemetry configuration.

        Args:
            telemetry_config (dict): A dictionary containing the application telemetry configuration,
                                    including device IPs, telemetry action (enable/disable), WLAN mode,
                                    and guest SSID inclusion.

        Returns:
            self: The updated instance with telemetry enable/disable operation results.

        Description:
            - Iterates over a list of device IPs and determines whether telemetry should be enabled or disabled.
            - Validates the device type and retrieves the corresponding device ID from the network.
            - For enabling telemetry:
                - Builds a payload including WLAN mode and guest SSID details for non-wired devices.
                - Sends the payload using the appropriate API to enable telemetry.
                - Logs and tracks the success or failure of the operation.
            - For disabling telemetry:
                - Gathers device IDs to be disabled.
                - Sends the payload using the appropriate API to disable telemetry.
                - Logs and tracks the success or failure of the operation.
            - Handles and logs any exceptions that may occur during the API execution.
        """

        application_telemetry_details = telemetry_config.get("application_telemetry", [])

        if not application_telemetry_details:
            self.msg = "No application telemetry configuration entries found in telemetry config."
            self.log(self.msg, "WARNING")
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self

        enable_payload = []
        disable_ids = []

        telemetry_api_map = {
            "enable": "enable_application_telemetry_feature_on_multiple_network_devices",
            "disable": "disable_application_telemetry_feature_on_multiple_network_devices"
        }

        self.log("Starting application telemetry configuration process", "DEBUG")
        self.log("Received telemetry configuration: {0}".format(telemetry_config), "DEBUG")

        application_telemetry_details = telemetry_config.get("application_telemetry", [])
        if not application_telemetry_details:
            self.msg = "No application telemetry configuration entries found in telemetry config."
            self.log(self.msg, "WARNING")
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return self

        self.log("Processing {0} telemetry configuration entries".format(len(application_telemetry_details)), "INFO")

        for detail in application_telemetry_details:
            device_ips = detail.get("device_ips", [])
            self.log("Processing device IPs: {0}".format(device_ips), "DEBUG")
            if device_ips is None or len(device_ips) == 0:
                self.msg = "No valid device IPs provided for application telemetry."
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return self

            all_empty = True
            for ip in device_ips:
                if ip.strip() != "":
                    all_empty = False
                    self.log("Valid device IP found: {0}".format(ip), "DEBUG")
                    break

            if all_empty:
                self.msg = "No valid device IPs provided for application telemetry."
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return self

            telemetry = detail.get("telemetry")  # "enable" or "disable"
            if telemetry not in ["enable", "disable"]:
                self.msg = "Invalid telemetry action '{0}'. Expected 'enable' or 'disable'.".format(telemetry)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            wlan_mode = detail.get("wlan_mode")
            include_guest_ssid = detail.get("include_guest_ssid", False)
            self.log("Telemetry action: {0}, WLAN mode: {1}, Include guest SSID: {2}".format(
                telemetry, wlan_mode, include_guest_ssid
            ), "DEBUG")
            for ip in device_ips:
                self.validated_config["management_ip_address"] = ip
                device_type, device_family = self.get_device_type_and_family(ip)
                self.log("Device type: {0}, Device family: {1} for IP: {2}".format(
                    device_type, device_family, ip
                ), "DEBUG")

                unsupported_devices = [
                    "Cisco Catalyst 9500 Switch",
                    "Cisco Catalyst 9600 Switch"
                ]

                if (device_type and device_type in unsupported_devices) or \
                   (device_family and device_family.lower() not in ["routers", "wireless lan controllers", "switches and hubs", "wireless controller"]):
                    self.msg = ("No telemetry-applicable interfaces/WLANs found. "
                                "device : {0} Telemetry not supported for device type: {1}, family: {2}".format(ip, device_type, device_family))
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    return self

                device_type = self.get_dev_type()

                device_id = self.get_device_id_for_app_telemetry()

                if not device_id:
                    self.log("Skipping IP {0} due to missing device_id".format(ip), "WARNING")
                    continue

                is_device_assigned_to_site = self.is_device_assigned_to_site(device_id)
                self.log("Device with IP {0} is assigned to site: {1}".format(ip, is_device_assigned_to_site), "DEBUG")
                if not is_device_assigned_to_site:
                    self.msg = "Device with IP {0} is not assigned to any site. Telemetry cannot be enabled/disabled.".format(ip)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                if telemetry == "enable":
                    device_data = {"id": device_id}
                    if device_type != "wired":
                        if not wlan_mode:
                            self.msg = "wlan_mode is mandatory when the device type is wireless"
                            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                        if wlan_mode:
                            device_data["includeWlanModes"] = [wlan_mode]
                        if include_guest_ssid:
                            device_data["includeGuestSsids"] = include_guest_ssid
                    enable_payload.append(device_data)
                else:
                    disable_ids.append(device_id)

        # Enable telemetry
        if enable_payload:
            api_function = telemetry_api_map["enable"]
            payload = {"networkDevices": enable_payload}
            self.log("Sending enable payload: {0}".format(payload))

            try:
                response = self.dnac._exec(
                    family="application_policy",
                    function=api_function,
                    op_modifies=True,
                    params={"payload": payload}
                )
                self.log("Received API response for enable: {0}".format(response), "DEBUG")
                self.enable_application_telemetry.append(ip)
                self.check_tasks_response_status(response, api_function)

                if self.status not in ["failed", "exited"]:
                    self.msg = "Application telemetry enabled successfully for all devices."
                    self.set_operation_result("success", True, self.msg, "INFO")
                else:
                    self.msg = "Enabling telemetry failed: {0}".format(self.msg)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            except Exception as e:
                self.msg = "Exception while enabling telemetry: {0}".format(e)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        # Disable telemetry
        if disable_ids:
            api_function = telemetry_api_map["disable"]
            disable_ids = list(set(disable_ids))  # Remove duplicates
            payload = {"networkDeviceIds": disable_ids}
            self.log("Sending disable payload: {0}".format(payload))

            try:
                response = self.dnac._exec(
                    family="application_policy",
                    function=api_function,
                    op_modifies=True,
                    params={"payload": payload}
                )
                self.log("Received API response for Disable: {0}".format(response), "DEBUG")
                self.disable_application_telemetry.append(ip)
                self.check_tasks_response_status(response, api_function)

                if self.status not in ["failed", "exited"]:
                    self.msg = "Application telemetry disabled successfully for all devices."
                    self.set_operation_result("success", True, self.msg, "INFO")
                else:
                    self.msg = "Disabling telemetry failed: {0}".format(self.msg)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            except Exception as e:
                self.msg = "Exception while disabling telemetry: {0}".format(e)
                self.result['response'] = self.msg
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        return self

    def get_device_type_and_family(self, device_ip):
        """
        Retrieves the type and family of a network device based on its IP address.

        This method interacts with the Cisco Catalyst Center to fetch metadata about a device
        using its IP address, specifically retrieving its 'type' and 'family' attributes.

        Args:
            device_ip (str): The IP address of the network device to query.

        Returns:
            Tuple[str, str]: A tuple containing the device's type and family.
                            Returns (None, None) if the device is not found or an error occurs.

        Description:
            This method:
            - Initiates an API call to retrieve device details from Catalyst Center using the given IP address.
            - Parses the response to extract the device's 'type' and 'family'.
            - Logs the retrieval process at various stages including request initiation, API response, and the final result.
            - Handles scenarios where the device response is empty or an exception occurs during the API call.
            - Ensures that all operations are logged with appropriate context for easier debugging and traceability.
        """
        self.log("Starting device type/family retrieval for IP: {0}".format(device_ip), "INFO")

        try:
            dev_response = self.dnac_apply['exec'](
                family="devices",
                function='get_network_device_by_ip',
                params={"ip_address": device_ip}
            )

            self.log("API response for device IP {0}: {1}".format(device_ip, str(dev_response)), "DEBUG")

            device = dev_response.get("response", {})
            if not device:
                self.log("Device response empty or missing for IP: {0}".format(device_ip), "WARNING")
                return None, None

            device_type = device.get("type", "")
            device_family = device.get("family", "")

            self.log("Device type: '{0}', family: '{1}' for IP: {2}".format(device_type, device_family, device_ip), "INFO")

            return device_type, device_family

        except Exception as e:
            msg = "Failed to get device details for IP {0}: {1}".format(device_ip, str(e))
            self.log(msg, "ERROR")
            return None, None

    def execute_api(self, api_function, payload, action):
        """
        Executes an API call to configure application telemetry on network devices.

        This method sends a request to the specified Cisco Catalyst Center API with the provided
        payload to either enable or disable telemetry.

        Args:
            api_function: The name of the Catalyst Center API function to be called.
            payload: The request payload containing device-specific data used to enable or disable application telemetry on network devices.
            action: Descriptive label of the action being performed (e.g., "enabling", "disabling").

        Returns:
            self: The instance with updated execution status and messages.

        Description:
            This method:
            - Sends an API request to Catalyst Center to enable or disable application telemetry.
            - Executes the API using the provided function name and payload.
            - Validates the response by checking the task execution status.
            - Updates the operation result and logs appropriate success or failure messages.
            - Handles any exceptions gracefully and logs errors with detailed context.
        """
        try:
            self.log("Sending {0} payload: {1}".format(action, payload), "DEBUG")
            response = self.dnac._exec(
                family="application_policy",
                function=api_function,
                op_modifies=True,
                params={"payload": payload},
            )
            self.log(
                "Received API response for {0}: {1}".format(action, response), "DEBUG"
            )
            self.check_tasks_response_status(response, api_function)

            if self.status not in ["failed", "exited"]:
                self.msg = (
                    "Application telemetry {0} successfully for all devices.".format(
                        action
                    )
                )
                self.set_operation_result("success", True, self.msg, "INFO")
            else:
                self.msg = "Application telemetry {0} failed: {1}".format(
                    action, self.msg
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
        except Exception as e:
            self.msg = "Exception while {0} telemetry: {1}".format(action, e)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return self

    def provision_bulk_wired_device(self):
        """
        Provisions or reprovisions wired network devices in bulk based on the given validated configuration.

        Args:
            self: An instance of a class used for interacting with network devices.

        Returns:
            self: The updated instance with provisioning results.

        Description:
            This method:
            - Identifies devices that need provisioning or reprovisioning.
            - Checks their current provision status.
            - Logs and updates provisioning status accordingly.
            - Ensures already provisioned devices are not unnecessarily reprovisioned unless forced.
            - Updates the instance with provisioning results and logs messages accordingly.
        """

        provision_params, reprovision_params, self.device_ips = [], [], []
        already_provisioned_devices = []

        (
            self.reprovisioned_device,
            self.provisioned_device,
            self.already_provisioned_devices,
        ) = ([], [], [])

        success_msg, provision_needed, reprovision_needed = [], [], []
        self.log("Starting bulk wired device provisioning process.", "INFO")

        for config in self.validated_config:
            device_ip = config.get("management_ip_address")

            if device_ip not in self.device_dict["wired"]:
                self.log(
                    "Skipping device '{0}': Not a wired device.".format(device_ip),
                    "DEBUG",
                )
                continue

            site_name = config.get("site_name_hierarchy")
            site_id_tuple = self.get_site_id(site_name)
            site_id = site_id_tuple[1]
            self.device_ips.append(device_ip)
            site_type = self.get_sites_type(site_name)
            self.log(
                "Site type for site '{0}': {1}".format(site_name, site_type), "DEBUG"
            )
            if site_type in ["area", "global"]:
                self.msg = (
                    "Site type '{0}' is not supported for provisioning. "
                    "Please use a site type of 'building' or 'floor'.".format(site_type)
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            network_device_id = self.get_device_ids_from_device_ips([device_ip]).get(
                device_ip
            )
            if not network_device_id:
                self.log(
                    "Skipping device '{0}': Device ID not found.".format(device_ip),
                    "ERROR",
                )
                continue

            provision_id, status = self.get_device_provision_status(
                network_device_id, device_ip
            )
            self.log(
                "Device '{0}': provision_id='{1}', status='{2}'".format(
                    device_ip, provision_id, status
                ),
                "DEBUG",
            )

            to_force_provisioning = config.get("force_provisioning", False)
            to_provisioning = config.get("provisioning", False)

            if not to_provisioning and status != "success":
                self.log(
                    "Provisioning not required; assigning device '{0}' to site '{1}' (site_id: {2}).".format(
                        device_ip, site_name, site_id
                    ),
                    "INFO",
                )
                if self.assign_device_to_site([network_device_id], site_name, site_id):
                    success_msg.append(
                        "Wired Device '{0}' is assigned to site {1}.".format(
                            device_ip, site_name
                        )
                    )
                    self.assigned_device_to_site.append(device_ip)

                continue

            if status == "success":
                if not to_force_provisioning:
                    self.already_provisioned_wired_device.append(device_ip)
                    success_msg.append(
                        "Wired Device '{0}' is already provisioned.".format(device_ip)
                    )
                    self.log(success_msg[-1], "INFO")

                    if not to_provisioning:
                        self.msg = (
                            "Cannot assign a provisioned device to the site. "
                            "The device is already provisioned. "
                            "To re-provision the device, set both 'provisioning' and 'force_provisioning' to 'true', "
                            "or unprovision the device and try again."
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR")
                    continue

                self.log(
                    "Device '{0}' requires reprovisioning.".format(device_ip), "INFO"
                )
                reprovision_needed.append(device_ip)
                reprovision_params.append(
                    {
                        "id": provision_id,
                        "siteId": site_id,
                        "networkDeviceId": network_device_id,
                    }
                )

            else:
                if to_provisioning:
                    self.log(
                        "Device '{0}' requires provisioning.".format(device_ip), "INFO"
                    )
                    provision_needed.append(device_ip)
                    provision_params.append(
                        {"siteId": site_id, "networkDeviceId": network_device_id}
                    )

        self.log("Provisioning/Reprovisioning evaluation:", "INFO")
        self.log("Provision Needed: {0}".format(provision_needed), "INFO")
        self.log("Reprovision Needed: {0}".format(reprovision_needed), "INFO")

        if set(already_provisioned_devices) == set(self.device_ips):
            self.msg = "All devices are already provisioned: {0}".format(
                already_provisioned_devices
            )
            self.set_operation_result("success", False, self.msg, "INFO")
            return self

        if reprovision_params:
            self.reprovision_wired_device(
                reprovision_params, device_ips=reprovision_needed
            )
            re_prov_success_msg = (
                "re-provisioning of the device(s) '{0}' completed successfully.".format(
                    reprovision_needed
                )
            )
            success_msg.append(re_prov_success_msg)
            self.re_provision_wired_device.append(reprovision_needed)

        if provision_params:
            for i in range(0, len(provision_params), 100):
                batch_params = provision_params[i : i + 100]
                batch_devices = provision_needed[i : i + 100]
                self.log(
                    "Provisioning of the device(s) - {0} with the param - {1}".format(
                        batch_devices, batch_params
                    ),
                    "INFO",
                )
                self.initialize_wired_provisioning(
                    batch_params, device_ips=batch_devices
                )
                success_msg.append(
                    "Provisioning of the device(s) '{0}' completed successfully.".format(
                        batch_devices
                    )
                )

        if success_msg:
            self.msg = success_msg
            self.set_operation_result("success", True, self.msg, "INFO")

        self.log("Bulk wired device provisioning process completed.", "INFO")
        return self

    def get_device_type(self):
        """
        Classifies devices as 'wired' or 'wireless' based on their family type from the Cisco DNA Center API.

        This function queries each device in `validated_config` to determine whether it is a wired or wireless device.
        The classification is stored in `self.device_dict`.

        Returns:
            dict: A dictionary with classified devices: {'wired': [list of wired device IPs], 'wireless': [list of wireless device IPs]}.
        """

        device_dict = {"wired": [], "wireless": []}

        for device in self.validated_config:
            ip_address = device.get("management_ip_address")
            if not ip_address:
                self.log(
                    "Skipping device with missing management IP address.", "WARNING"
                )
                continue

            self.log("Fetching device details for IP: {0}".format(ip_address), "INFO")

            try:
                dev_response = self.dnac_apply["exec"](
                    family="devices",
                    function="get_network_device_by_ip",
                    params={"ip_address": ip_address},
                )

            except Exception as e:
                error_message = "The Device - {0} is already deleted from the Inventory or not present in the Cisco Catalyst Center.".format(
                    device["management_ip_address"]
                )
                self.log(error_message, "WARNING")
                continue

            if not dev_response or "response" not in dev_response:
                self.log(
                    "Invalid or empty response received for device '{0}': {1}".format(
                        ip_address, str(dev_response)
                    ),
                    "ERROR",
                )
                continue

            self.log(
                "Device response for '{0}': {1}".format(ip_address, str(dev_response)),
                "DEBUG",
            )

            self.log(
                "The device response from 'get_network_device_by_ip' API is {0}".format(
                    str(dev_response)
                ),
                "DEBUG",
            )
            dev_dict = dev_response.get("response")
            device_family = dev_dict.get("family", None)

            if device_family == "Wireless Controller":
                device_type = "wireless"
            elif device_family in ["Switches and Hubs", "Routers"]:
                device_type = "wired"
            else:
                device_type = None

            self.log(
                "The device type for IP {0} is {1}".format(
                    device["management_ip_address"], device_type
                ),
                "INFO",
            )

            if device_type:
                device_dict[device_type].append(device["management_ip_address"])

        self.device_dict = device_dict
        self.log("Final device classification: {0}".format(device_dict), "INFO")

        return device_dict

    def get_device_provision_status(self, device_id, device_ip=None):
        """
        Retrieves the provisioning status and provision ID of a device based on its device ID.

        Args:
            device_id (str): The ID of the device for which provisioning status is to be retrieved.

        Returns:
            tuple: A tuple containing:
                - provision_id (str or None): The provision ID of the device if provisioned, None otherwise.
                - status (str): The status of the provisioning process, either 'success' or 'failed'.
        Description:
            Depending on the Cisco Catalyst Center (CCC) version, this function calls different APIs to
            check if a device is provisioned. It handles both wired and wireless device provisioning
            checks and logs relevant status and errors.

        """
        provision_id = None
        status = "failed"

        if isinstance(self.validated_config, list):
            device_management_ip = device_ip
        else:
            device_management_ip = self.validated_config.get("management_ip_address")

        self.log(
            "Checking provisioning status for device with management IP '{0}' and ID '{1}'".format(
                device_management_ip, device_id
            ),
            "DEBUG",
        )
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
            self.log(
                "Using 'get_provisioned_wired_device' API for Catalyst Center version <= 2.3.5.3",
                "DEBUG",
            )
            try:
                status_response = self.dnac_apply["exec"](
                    family="sda",
                    function="get_provisioned_wired_device",
                    params={"device_management_ip_address": device_management_ip},
                )
                if status_response:
                    self.log(
                        "Received API response for device '{0}' from 'get_provisioned_wired_device' "
                        ": {1}".format(device_management_ip, status_response),
                        "DEBUG",
                    )
                    status = status_response.get("status")
                else:
                    self.log(
                        "No status response received for wired device with management IP '{0}'".format(
                            device_management_ip
                        ),
                        "DEBUG",
                    )
            except Exception as e:
                self.log(
                    "Device '{0}' is not provisioned due to error: {1}".format(
                        device_management_ip, str(e)
                    ),
                    "ERROR",
                )
                status = "failed"

        else:
            self.log(
                "Using 'get_provisioned_devices' API for Catalyst Center version > 2.3.5.3",
                "DEBUG",
            )
            try:
                api_response = self.dnac._exec(
                    family="sda",
                    function="get_provisioned_devices",
                    params={"networkDeviceId": device_id},
                )
                if api_response:
                    self.log(
                        "API response for device '{0}' from 'get_provisioned_devices': {1}".format(
                            device_management_ip, api_response
                        ),
                        "DEBUG",
                    )
                    provisioned_devices = api_response.get("response")
                    provision_id = (
                        provisioned_devices[0].get("id")
                        if provisioned_devices
                        else None
                    )

                    if provisioned_devices:
                        status = "success"
                    else:
                        status = "failed"

                    self.log(
                        "Provisioned devices found for '{0}': {1}".format(
                            device_management_ip, bool(provisioned_devices)
                        ),
                        "DEBUG",
                    )
                else:
                    self.log(
                        "No API response received for device '{0}' provisioning check".format(
                            device_management_ip
                        ),
                        "DEBUG",
                    )

            except Exception as e:
                self.msg = (
                    "Error in 'get_provisioned_devices' for device '{0}': {1}".format(
                        device_management_ip, str(e)
                    )
                )
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg

        self.log(
            "Provision status for device with management IP '{0}': status='{1}', "
            "provision_id='{2}'".format(device_management_ip, status, provision_id),
            "DEBUG",
        )
        return provision_id, status

    def provision_wired_device(self, to_provisioning, to_force_provisioning):
        """
        Handle wired device provisioning.

        Args:
            self: An instance of a class used for interacting with Cisco Catalyst Center.
            to_provisioning (bool): Indicates if the device should be provisioned.
            to_force_provisioning (bool): Indicates if the device should be forcefully reprovisioned.

        Returns:
            self: An instance of the class with updated results and status based on
            the provisioning operation.

        Description:
            This function manages the provisioning of a wired device in Cisco Catalyst Center.
            It checks the current provisioning status of the device and, based on the flags
            `to_provisioning` and `to_force_provisioning`, decides whether to provision, reprovision,
            or skip the process. The function sends appropriate API requests, logs the outcomes,
            and updates the instance with provisioning status, task details, and any changes made.
            In case of errors, it logs them and sets the status to 'failed'.
        """
        device_id = self.get_device_id()
        self.log("Device ID retrieved: {0}".format(device_id), "DEBUG")

        provision_id, status = self.get_device_provision_status(device_id)
        self.log(
            "Provision ID and status for device ID '{0}': provision_id='{1}', status='{2}'".format(
                device_id, provision_id, status
            ),
            "DEBUG",
        )

        site_exist, site_id = self.get_site_id(self.site_name)
        self.log(
            "Site ID retrieval for site '{0}': site_exist={1}, site_id='{2}'".format(
                self.site_name, site_exist, site_id
            ),
            "DEBUG",
        )

        reprovision_param = [
            {"id": provision_id, "siteId": site_id, "networkDeviceId": device_id}
        ]
        provision_params = [{"siteId": site_id, "networkDeviceId": device_id}]

        self.log(
            "Reprovision parameters prepared: {0}".format(reprovision_param), "DEBUG"
        )
        self.log("Provision parameters prepared: {0}".format(provision_params), "DEBUG")

        if status == "success":
            if not to_force_provisioning:
                self.result["changed"] = False
                msg = "Wired Device '{0}' is already provisioned.".format(
                    self.validated_config.get("management_ip_address")
                )
                self.result["msg"] = msg
                self.result["response"] = msg
                self.log(msg, "INFO")
                return self

            if not to_provisioning:
                self.msg = (
                    "Cannot assign a provisioned device to the site. "
                    "The device is already provisioned. "
                    "To re-provision the device, ensure that both 'provisioning' and 'force_provisioning' are set to 'true'. "
                    "Alternatively, unprovision the device and try again."
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            self.reprovision_wired_device(reprovision_param)
            return self

        self.log("Checking if provisioning is required based on status.", "INFO")
        if not to_provisioning:
            self.log(
                "Provisioning not required; assigning device '{0}' to site '{1}' with site "
                "ID '{2}'.".format(device_id, self.site_name, site_id),
                "INFO",
            )
            self.assign_device_to_site([device_id], self.site_name, site_id)
        else:
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
                self.log(
                    "Catalyst Center Version is 2.3.5.3 or earlier; directly initializing provisioning with parameters.",
                    "INFO",
                )
                self.initialize_wired_provisioning(provision_params)
            else:
                self.log(
                    "Catalyst Center Version is later than 2.3.5.3; checking if device '{0}' is assigned to site.".format(
                        device_id
                    ),
                    "INFO",
                )

                is_device_assigned_to_a_site, device_site_name = (
                    self.is_device_assigned_to_site_v1(device_id)
                )
                if is_device_assigned_to_a_site:
                    if device_site_name != self.site_name:
                        self.msg = (
                            "Error in provisioning a wired device '{0}' - the device is already associated "
                            "with a Site {1} and cannot be provisioned to Site {2}."
                        ).format(self.device_ip, device_site_name, self.site_name)
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()
                    else:
                        self.log(
                            "Device '{0}' is already assigned to site. Proceeding with provisioning.".format(
                                device_id
                            ),
                            "DEBUG",
                        )
                        self.initialize_wired_provisioning(provision_params)
                else:
                    self.log(
                        "Device '{0}' is not assigned to site '{1}'. Assigning device and "
                        "initializing provisioning.".format(device_id, self.site_name),
                        "DEBUG",
                    )
                    self.assign_device_to_site([device_id], self.site_name, site_id)
                    self.initialize_wired_provisioning(provision_params)

        return self

    def reprovision_wired_device(self, reprovision_param, device_ips=None):
        """
        Reprovision a wired device.

        Args:
            self: An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self: An instance of the class with updated results and status after the
            wired device has been reprovisioned.

        Description:
            This function handles the reprovisioning of a wired device in Cisco Catalyst Center.
            It sends an API request to the 're_provision_wired_device' endpoint using the device's
            provisioning parameters. The function tracks the task status and updates the class instance
            with the reprovisioning status, task ID, and other relevant details. If an error occurs during
            the reprovisioning process, it logs the error and adjusts the status accordingly.
        """
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
            self.log(
                "Starting reprovisioning of wired device using 're_provision_wired_device' API.",
                "DEBUG",
            )
            try:
                response = self.dnac_apply["exec"](
                    family="sda",
                    function="re_provision_wired_device",
                    op_modifies=True,
                    params=self.want["prov_params"],
                )
                taskid = response.get("taskId")
                self.log(
                    "Received task ID '{0}' for wired device reprovisioning.".format(
                        taskid
                    ),
                    "DEBUG",
                )
                while True:
                    result = self.get_task_details(taskid)
                    self.log(
                        "Checking task status for ID '{0}': {1}".format(taskid, result),
                        "DEBUG",
                    )
                    if "processcfs_complete=true" in result.get("data"):
                        self.msg = "Wired Device '{0}' re-provisioning completed successfully.".format(
                            self.device_ip
                        )
                        self.log(self.msg, "INFO")
                        self.result["changed"] = True
                        self.result["msg"] = (
                            "Wired Device '{0}' re-provisioning completed successfully.".format(
                                self.device_ip
                            )
                        )
                        self.result["response"] = self.msg
                        self.log(self.result["msg"], "INFO")
                        return self

                    elif result.get("isError") is True:
                        self.log(
                            "Error in task status for wired device reprovisioning. Task ID: '{0}'".format(
                                taskid
                            ),
                            "ERROR",
                        )
                        raise Exception

            except Exception as e:
                self.msg = "Error in re-provisioning device '{0}' due to {1}".format(
                    self.device_ip, str(e)
                )
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                self.status = "failed"
                self.check_return_status()
        else:
            try:
                self.log(
                    "Starting reprovisioning of wired device using 're_provision_devices' API.",
                    "DEBUG",
                )
                response = self.dnac_apply["exec"](
                    family="sda",
                    function="re_provision_devices",
                    op_modifies=True,
                    params={"payload": reprovision_param},
                )
                self.log(
                    "Received response for 're_provision_devices': {0}".format(
                        response
                    ),
                    "DEBUG",
                )
                self.check_tasks_response_status(
                    response, api_name="re_provision_devices"
                )
                self.log(
                    "Task status after 're_provision_devices' execution: {0}".format(
                        self.status
                    ),
                    "DEBUG",
                )

                if self.status not in ["failed", "exited"]:
                    self.msg = "Wired Device '{0}' re-provisioning completed successfully.".format(
                        device_ips
                    )

                    self.set_operation_result("success", True, self.msg, "INFO")

                if self.status in ["failed", "exited"]:
                    self.msg = (
                        "Wired Device '{0}' re-provisioning failed due to {1}.".format(
                            device_ips, self.msg
                        )
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

            except Exception as e:
                self.msg = "Error in re-provisioning device '{0}' due to {1}".format(
                    device_ips, str(e)
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

    def initialize_wired_provisioning(self, provision_params, device_ips=None):
        """
        Provision a wired device.

        Args:
            self: An instance of a class used for interacting with Cisco Catalyst Center.

        Returns:
            self: An instance of the class with updated results and status after the wired
            device has been provisioned.

        Description:
            This function handles the provisioning of a wired device in Cisco Catalyst Center.
            It sends an API request to the 'provision_wired_device' endpoint with the required
            parameters. If provisioning is successful, the class instance is updated with the
            provisioning status, task ID, and execution details. In case of any errors during
            provisioning, it logs the error and updates the status accordingly.
        """

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
            try:
                self.log(
                    "Starting wired device provisioning with 'provision_wired_device' API.",
                    "DEBUG",
                )
                response = self.dnac_apply["exec"](
                    family="sda",
                    function="provision_wired_device",
                    op_modifies=True,
                    params=self.want["prov_params"],
                )
                if response:
                    self.log(
                        "Received API response from 'provision_wired_device': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    if self.status not in ["failed", "exited"]:
                        success_msg = "Provisioning of the device '{0}' completed successfully.".format(
                            self.device_ip
                        )
                        self.provisioned_wired_device.append(
                            self.validated_config["management_ip_address"]
                        )
                        self.log(success_msg, "INFO")
                        self.result["changed"] = True
                        self.result["msg"] = success_msg
                        self.result["response"] = success_msg
                        return self

            except Exception as e:
                self.msg = "Error in provisioning device '{0}' due to {1}".format(
                    self.device_ip, str(e)
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                self.result["response"] = self.msg
                self.check_return_status()
        else:
            try:
                self.log(
                    "Starting wired device provisioning with 'provision_devices' API.",
                    "DEBUG",
                )
                response = self.dnac._exec(
                    family="sda",
                    function="provision_devices",
                    op_modifies=True,
                    params={"payload": provision_params},
                )
                if response:
                    self.log(
                        "Received API response from 'provision_devices': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, api_name="provision_device"
                    )

                    if self.status not in ["failed", "exited"]:
                        success_msg = "Provisioning of the device(s) '{0}' completed successfully.".format(
                            device_ips
                        )
                        self.provisioned_wired_device.append(
                            device_ips
                        )
                        self.set_operation_result("success", True, self.msg, "INFO")

                    if self.status in ["failed", "exited"]:
                        fail_reason = self.msg
                        self.log(
                            "Exception occurred during 'provisioned_devices': {0}".format(
                                str(fail_reason)
                            ),
                            "ERROR",
                        )
                        self.msg = (
                            "Error in provisioned device '{0}' due to {1}".format(
                                device_ips, str(fail_reason)
                            )
                        )
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

            except Exception as e:
                self.msg = "Error in provisioning device '{0}' due to {1}".format(
                    device_ips, str(e)
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

    def provision_wireless_device(self):
        """
        Provision a wireless device.

        Args:
            self: An instance of a class used for interacting with Cisco Catalyst Center.
            want (dict): A dictionary containing the provisioning parameters for the wireless device.

        Returns:
            self: An instance of the class with updated results and status based on
            the provisioning operation.

        Description:
            This function is responsible for provisioning a wireless device in Cisco Catalyst Center.
            It sends a request using the 'provision' API and handles the execution status.
            If an error occurs during the provisioning process, it logs the error and updates
            the instance status accordingly.
        """

        self.log("Starting provisioning process for wireless device", "INFO")

        prov_params = self.want.get("prov_params")
        if not prov_params or not isinstance(prov_params, list) or not prov_params[0]:
            self.log(
                "Error: 'prov_params' is missing or improperly formatted. Expected a non-empty list.",
                "ERROR",
            )
            self.status = "failed"
            self.result["response"] = (
                "Provisioning aborted due to missing or invalid 'prov_params'."
            )
            return self

        prov_params_data = prov_params[0]
        device_uid = prov_params_data.get("device_id")
        site_name = self.validated_config.get("site_name_hierarchy")
        primary_ap_location = prov_params_data.get("primaryManagedAPLocationsSiteIds")
        secondary_ap_location = prov_params_data.get(
            "secondaryManagedAPLocationsSiteIds"
        )
        site_exist, site_id = self.get_site_id(site_name)

        self.log(
            "Provisioning wireless device with device_id: {0}".format(device_uid),
            "DEBUG",
        )
        self.log("Site name: {0}".format(site_name), "DEBUG")
        self.log("Primary AP location: {0}".format(primary_ap_location), "DEBUG")
        self.log("Secondary AP location: {0}".format(secondary_ap_location), "DEBUG")

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            primary_ap_location_site_id_list = []
            secondary_ap_location_site_id_list = []

            if primary_ap_location:
                self.log("Processing primary access point locations", "INFO")
                for primary_sites in primary_ap_location:
                    self.log(
                        "Retrieving site ID for primary location: {0}".format(
                            primary_sites
                        ),
                        "DEBUG",
                    )
                    site_exist, primary_ap_location_site_id = self.get_site_id(
                        primary_sites
                    )
                    primary_ap_location_site_id_list.append(primary_ap_location_site_id)

            if secondary_ap_location:
                self.log("Processing secondary access point locations", "INFO")
                for secondary_sites in secondary_ap_location:
                    self.log(
                        "Retrieving site ID for secondary location: {0}".format(
                            secondary_sites
                        ),
                        "DEBUG",
                    )
                    site_exist, secondary_ap_location_site_id = self.get_site_id(
                        secondary_sites
                    )
                    secondary_ap_location_site_id_list.append(
                        secondary_ap_location_site_id
                    )

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:

            param = [
                {
                    "deviceName": prov_params[0].get("deviceName"),
                    "site": prov_params[0].get("site"),
                    "managedAPLocations": self.floor_names,
                    "dynamicInterfaces": prov_params[0].get("dynamicInterfaces"),
                }
            ]

            self.log(
                "Detected Catalyst Center version <= 2.3.5.3; using old provisioning method",
                "INFO",
            )
            try:
                response = self.dnac_apply["exec"](
                    family="wireless",
                    function="provision",
                    op_modifies=True,
                    params={"payload": param},
                )
                execution_id = response.get("executionId")
                self.log(
                    "Received execution ID for provisioning: {0}".format(execution_id),
                    "DEBUG",
                )
                self.get_execution_status_wireless(execution_id=execution_id)
                self.result["changed"] = True
                self.result["msg"] = "Wireless device provisioned successfully"
                self.provisioned_wireless_device.append(
                    self.validated_config["management_ip_address"]
                )
                self.result["diff"] = self.validated_config
                self.result["response"] = execution_id
                self.log(self.result["msg"], "INFO")
                return self

            except Exception as e:
                self.msg = "Error in wireless provisioning: {0}".format(str(e))
                self.log(self.msg, "ERROR")
                self.status = "failed"
                self.result["response"] = self.msg
                self.check_return_status()

        else:
            self.log(
                "Detected Catalyst Center version > 2.3.5.3; using new provisioning method",
                "INFO",
            )
            self.log("Checking if device is assigned to the site", "INFO")
            is_device_assigned_to_a_site, device_site_name = (
                self.is_device_assigned_to_site_v1(device_uid)
            )

            if is_device_assigned_to_a_site is False:
                self.log(
                    "Device {0} is not assigned to site {1}; assigning now.".format(
                        device_uid, site_name
                    ),
                    "INFO",
                )
                self.assign_device_to_site([device_uid], site_name, site_id)

            device_id = self.get_device_id()
            self.log("Retrieved device ID: {0}".format(device_id), "DEBUG")

            is_device_assigned_to_a_site, device_site_name = (
                self.is_device_assigned_to_site_v1(device_uid)
            )

            if is_device_assigned_to_a_site is True:
                if device_site_name != self.site_name:
                    self.msg = (
                        "Error in re-provisioning a wireless device '{0}' - the device is already associated "
                        "with a Site {1} and cannot be re-provisioned to Site {2}.".format(
                            self.device_ip, device_site_name, self.site_name
                        )
                    )
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    self.status = "failed"
                    self.check_return_status()

            if primary_ap_location or secondary_ap_location:
                self.log(
                    "Assigning managed AP locations to device ID: {0}".format(
                        device_uid
                    ),
                    "INFO",
                )
                try:
                    self.log("Assigning managed AP locations for the WLC", "INFO")
                    response = self.dnac_apply["exec"](
                        family="wireless",
                        function="assign_managed_ap_locations_for_w_l_c",
                        op_modifies=True,
                        params={
                            "device_id": device_uid,
                            "primaryManagedAPLocationsSiteIds": primary_ap_location_site_id_list,
                            "secondaryManagedAPLocationsSiteIds": secondary_ap_location_site_id_list,
                        },
                    )
                    self.log(
                        "API response from 'assign_managed_ap_locations_for_w_l_c': {}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    if response:
                        self.log(
                            "Received API response from 'assign_managed_ap_locations_for_w_l_c': {0}".format(
                                str(response)
                            ),
                            "DEBUG",
                        )
                        self.check_tasks_response_status(
                            response, api_name="assign_managed_ap_locations_for_w_l_c"
                        )
                        if self.status not in ["failed", "exited"]:
                            self.log(
                                "wireless Device '{0}' assign_managed_ap_locations_for_w_l_c completed successfully.".format(
                                    self.device_ip
                                ),
                                "INFO",
                            )

                        if self.status == "failed":
                            fail_reason = self.msg
                            self.log(
                                "Exception occurred during 'assign_managed_ap_locations_for_w_l_c': {0}".format(
                                    str(fail_reason)
                                ),
                                "ERROR",
                            )
                            self.msg = "Error in 'assign_managed_ap_locations_for_w_l_c' '{0}' due to {1}".format(
                                self.device_ip, str(fail_reason)
                            )
                            self.log(self.msg, "ERROR")
                            self.status = "failed"
                            self.result["response"] = self.msg
                            self.check_return_status()

                except Exception as e:
                    self.log(
                        "Exception occurred during 'assign_managed_ap_locations_for_w_l_c': {0}".format(
                            str(e)
                        ),
                        "ERROR",
                    )
                    self.msg = "Error in 'assign_managed_ap_locations_for_w_l_c' '{0}' due to {1}".format(
                        self.device_ip, str(e)
                    )
                    self.log(self.msg, "ERROR")
                    self.status = "failed"
                    self.result["response"] = self.msg
                    self.check_return_status()

            self.log(
                "Starting wireless controller provisioning for device ID: {0}".format(
                    device_uid
                ),
                "INFO",
            )
            prov_params = self.want.get("prov_params")[0]
            self.log("Provisioning parameters: {0}".format(prov_params), "DEBUG")
            payload = {"device_id": prov_params.get("device_id"), "interfaces": []}

            self.log("Processing interfaces if they exist", "INFO")
            self.log("Building payload for wireless provisioning", "INFO")
            if "dynamicInterfaces" in prov_params:
                self.log("Processing dynamic interfaces", "INFO")
                for interface in prov_params["dynamicInterfaces"]:
                    cleaned_interface = {}
                    for k, v in interface.items():
                        if v is not None:
                            cleaned_interface[k] = v
                        else:
                            self.log(
                                "No dynamic interfaces found in provisioning parameters",
                                "DEBUG",
                            )
                    payload["interfaces"].append(cleaned_interface)
                    self.log(
                        "Processed dynamic interface: {0}".format(cleaned_interface),
                        "DEBUG",
                    )

            skip_ap_provision = prov_params.get("skip_ap_provision")
            self.log("Processing 'rolling_ap_upgrade' if it exists", "INFO")

            if skip_ap_provision is not None:
                payload["skipApProvision"] = skip_ap_provision
                self.log(
                    "Set 'skip_ap_provision'  to: {0}".format(skip_ap_provision),
                    "DEBUG",
                )
            else:
                self.log("'skip_ap_provision'  is not specified", "DEBUG")

            self.log("Processing rolling AP upgrade settings", "INFO")
            allowed_ap_reboot_percentages = {5, 10, 25}

            if "rolling_ap_upgrade" in prov_params:
                self.log("Found 'rolling_ap_upgrade' in provisioning parameters", "DEBUG")

                rolling_upgrade_config = {}
                rolling_upgrade_data = prov_params["rolling_ap_upgrade"]

                if "ap_reboot_percentage" in rolling_upgrade_data:
                    reboot_percentage_value = rolling_upgrade_data["ap_reboot_percentage"]

                    if reboot_percentage_value is None or not str(reboot_percentage_value).isdigit():
                        self.msg = (
                            "Error: Invalid percentage value '{0}'. Must be an integer. "
                            "Supported values are 5, 10, and 25.".format(reboot_percentage_value)
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                    reboot_percentage_value = int(reboot_percentage_value)
                    if reboot_percentage_value not in allowed_ap_reboot_percentages:
                        self.msg = (
                            "Error: Invalid percentage value '{0}'. "
                            "Supported values are 5, 10, and 25.".format(reboot_percentage_value)
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                    rolling_upgrade_config["ap_reboot_percentage"] = reboot_percentage_value
                    self.log(
                        "Processed 'ap_reboot_percentage': {0}".format(reboot_percentage_value),
                        "DEBUG",
                    )

                # Process remaining keys in 'rolling_ap¿_upgrade'
                for key, value in rolling_upgrade_data.items():
                    if key == "ap_reboot_percentage":
                        self.log("Skipping already processed key 'ap_reboot_percentage'", "DEBUG")
                        continue

                    if value is not None:
                        rolling_upgrade_config[key] = value
                        self.log(
                            "Processed 'rolling_ap_upgrade' key '{0}': {1}".format(key, value),
                            "DEBUG",
                        )
                    else:
                        self.log(
                            "No '{0}' found in rolling_ap_upgrade, skipping".format(key),
                            "DEBUG",
                        )

                payload["rollingApUpgrade"] = rolling_upgrade_config

            # Process AP authorization list configuration if provided
            if "ap_authorization_list_name" in prov_params:
                ap_auth_list = prov_params.get("ap_authorization_list_name")
                self.log("Adding AP authorization list name to payload: '{0}'".format(ap_auth_list), "DEBUG")
                payload["apAuthorizationListName"] = ap_auth_list
            else:
                self.log("No AP authorization list name provided in provisioning parameters", "DEBUG")

            # Process mesh and non-mesh AP authorization configuration if provided
            if "authorize_mesh_and_non_mesh_aps" in prov_params:
                authorize_aps = prov_params.get("authorize_mesh_and_non_mesh_aps")
                self.log("Adding mesh and non-mesh AP authorization flag to payload: '{0}'".format(authorize_aps), "DEBUG")
                payload["authorizeMeshAndNonMeshAPs"] = authorize_aps
            else:
                self.log("No mesh and non-mesh AP authorization flag provided in provisioning parameters", "DEBUG")

            current_version = self.get_ccc_version()
            if self.compare_dnac_versions(current_version, "3.1.3.0") >= 0:
                self.log("Cisco Catalyst Center version '{0}' supports feature template functionality (>= 3.1.3.0)".format(current_version), "INFO")
                self.log(prov_params)
                if "feature_template" in prov_params:
                    self.log("Processing feature template configuration from provisioning parameters", "INFO")

                    feature_templates = prov_params.get("feature_template", [])
                    self.log(feature_templates)
                    if not feature_templates:
                        self.log("Empty feature template list found in provisioning parameters", "WARNING")
                    else:
                        self.log("Found {0} feature template(s) to process".format(len(feature_templates)), "DEBUG")
                        payload = self.process_feature_template_configuration(feature_templates, payload)

                else:
                    self.log("No feature template configuration found in provisioning parameters", "DEBUG")

            import json

            self.log(
                "Final constructed payload:\n{0}".format(json.dumps(payload, indent=2)),
                "INFO",
            )

            try:
                response = self.dnac_apply["exec"](
                    family="wireless",
                    function="wireless_controller_provision",
                    op_modifies=True,
                    params=payload,
                )

                if response:
                    self.log(
                        "Received API response from 'wireless_controller_provision': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, api_name="wireless_controller_provision"
                    )
                    if self.status not in ["failed", "exited"]:
                        self.log(
                            "wireless Device '{0}' provisioning completed successfully.".format(
                                self.device_ip
                            ),
                            "INFO",
                        )
                        self.provisioned_wireless_device.append(
                            self.validated_config["management_ip_address"]
                        )
                        self.result["changed"] = True
                        self.result["msg"] = (
                            "Provisioning of the wireless device '{0}' completed successfully.".format(
                                self.device_ip
                            )
                        )
                        self.result["response"] = (
                            "Provisioning of the wireless device '{0}' completed successfully.".format(
                                self.device_ip
                            )
                        )
                        self.log(self.result["msg"], "INFO")
                        return self
            except Exception as e:
                self.log(
                    "Exception occurred during provisioning: {0}".format(str(e)),
                    "ERROR",
                )
                self.msg = (
                    "Error in provisioning wireless device '{0}' due to {1}".format(
                        self.device_ip, str(e)
                    )
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                self.result["response"] = self.msg
                self.check_return_status()

    def process_feature_template_configuration(self, feature_templates, payload):
        """
        Processes feature template configuration for wireless device provisioning payload construction.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            feature_templates (list): List of feature template configurations to process.
            payload (dict): The wireless provisioning payload to be updated with feature template data.
        Returns:
            dict: Updated payload containing feature template configuration.
        Description:
            This function validates and processes feature template configurations for wireless device
            provisioning. It performs comprehensive validation of required fields including design name,
            additional identifiers (WLAN profile and site hierarchy), and excluded attributes. The function
            resolves template and site identifiers using Cisco Catalyst Center APIs, constructs the
            appropriate payload structure for the provisioning API, and ensures all mandatory fields
            are present and properly formatted before adding the template configuration to the payload.
        """
        self.log("Processing feature template configuration with {0} templates".format(
            len(feature_templates) if feature_templates else 0), "DEBUG")
        self.log("Input feature_templates: {0}".format(self.pprint(feature_templates)), "DEBUG")
        self.log("Input payload structure: {0}".format(self.pprint(payload)), "DEBUG")

        if not feature_templates:
            self.log("No feature templates provided; returning original payload unchanged", "DEBUG")
            return payload

        self.initialize_feature_template_payload_structure(payload)

        processing_stats = {"processed": 0, "skipped": 0, "errors": 0}

        for template_index, feature_template in enumerate(feature_templates):
            self.log("Processing feature template #{0}: {1}".format(
                template_index + 1, self.pprint(feature_template)), "DEBUG")

            if not isinstance(feature_template, dict):
                message = "Feature template entry #{0} must be a dictionary. Skipping invalid entry.".format(
                    template_index + 1)
                self.log(message, "WARNING")
                processing_stats["skipped"] += 1
                continue

            try:
                template_entry = self.process_individual_feature_template(
                    template_index, feature_template)

                if template_entry:
                    payload["featureTemplatesOverridenAttributes"]["editFeatureTemplates"].append(
                        template_entry)
                    processing_stats["processed"] += 1
                    self.log("Successfully added feature template entry for templateId '{0}'".format(
                        template_entry.get("featureTemplateId")), "INFO")
                else:
                    processing_stats["skipped"] += 1

            except Exception as exception:
                processing_stats["errors"] += 1
                error_message = "Failed to process feature template #{0}: {1}".format(
                    template_index + 1, str(exception))
                self.log(error_message, "ERROR")

                if hasattr(self, "set_operation_result"):
                    self.set_operation_result("failed", False, error_message, "ERROR").check_return_status()
                    return payload

        self.log("Feature template processing completed - Processed: {0}, Skipped: {1}, Errors: {2}".format(
            processing_stats["processed"], processing_stats["skipped"], processing_stats["errors"]), "INFO")

        self.log("Final payload with feature templates: {0}".format(
            self.pprint(payload["featureTemplatesOverridenAttributes"])), "DEBUG")

        return payload

    def initialize_feature_template_payload_structure(self, payload):
        """
        Initializes the feature template payload structure if not already present.
        Args:
            payload (dict): The wireless provisioning payload to be updated.
        Returns:
            None: The function modifies the payload in place.
        """
        self.log("Initializing feature template payload structure", "DEBUG")

        if "featureTemplatesOverridenAttributes" not in payload:
            payload["featureTemplatesOverridenAttributes"] = {"editFeatureTemplates": []}
            self.log("Created new featureTemplatesOverridenAttributes structure", "DEBUG")
            return

        feature_template_attributes = payload["featureTemplatesOverridenAttributes"]
        if (
            "editFeatureTemplates" not in feature_template_attributes
            or not isinstance(feature_template_attributes["editFeatureTemplates"], list)
        ):
            feature_template_attributes["editFeatureTemplates"] = []
            self.log("Initialized editFeatureTemplates as empty list", "DEBUG")

        return

    def process_individual_feature_template(self, template_index, feature_template):
        """
        Processes a single feature template entry and returns the formatted template entry.
        Args:
            template_index (int): Index of the template being processed
            feature_template (dict): Individual feature template configuration
        Returns:
            dict or None: Formatted template entry for API payload, or None if skipped
        """
        self.log("Processing individual feature template at index {0}".format(template_index), "DEBUG")

        normalized_params = self.normalize_feature_template_input(feature_template)
        feature_template_id = normalized_params["feature_template_id"]
        design_name = normalized_params["design_name"]

        if not feature_template_id and not design_name:
            message = "Feature template #{0} missing both 'featureTemplateId' and 'design_name'. Skipping entry.".format(
                template_index + 1)
            self.log(message, "WARNING")
            return None

        # Resolve template ID if only design name provided
        if not feature_template_id and design_name:
            self.log("Resolving feature template ID for design name '{0}'".format(design_name), "DEBUG")
            try:
                feature_template_id = self.resolve_template_id(design_name)
                if not feature_template_id:
                    message = "Failed to resolve template ID for design '{0}'. Skipping entry.".format(design_name)
                    self.log(message, "WARNING")
                    return None

                self.log("Resolved template ID '{0}' for design '{1}'".format(
                    feature_template_id, design_name), "DEBUG")

            except Exception as exception:
                error_message = "Exception resolving template ID for design '{0}': {1}".format(
                    design_name, str(exception))
                self.log(error_message, "ERROR")
                raise

        template_entry = {
            "featureTemplateId": feature_template_id,
            "attributes": normalized_params["attributes"] if normalized_params["attributes"] else {}
        }

        # Only include additionalIdentifiers if user actually provided something
        if normalized_params["additional_identifiers"]:
            template_entry["additionalIdentifiers"] = normalized_params["additional_identifiers"]

        # Include excludedAttributes if provided
        if normalized_params["excluded_attributes"]:
            template_entry["excludedAttributes"] = normalized_params["excluded_attributes"]

        self.log("Built template entry: {0}".format(self.pprint(template_entry)), "DEBUG")
        return template_entry

    def normalize_feature_template_input(self, feature_template):
        """
        Normalizes feature template input to handle both camelCase and snake_case formats.
        Args:
            feature_template (dict): Raw feature template input
        Returns:
            dict: Normalized parameter dictionary
        """
        self.log("Normalizing feature template input parameters", "DEBUG")

        # Extract template identifiers with fallbacks
        feature_template_id = (
            feature_template.get("featureTemplateId")
            or feature_template.get("feature_template_id")
        )

        design_name = (
            feature_template.get("design_name")
            or feature_template.get("designName")
            or feature_template.get("designname")
        )

        # Extract configuration parameters
        attributes = feature_template.get("attributes") or feature_template.get("attrs") or {}
        if attributes is None:
            attributes = {}

        excluded_attributes = (
            feature_template.get("excludedAttributes")
            or feature_template.get("excluded_attributes")
            or []
        )
        if excluded_attributes is None:
            excluded_attributes = []

        # Process additional identifiers
        additional_identifiers_input = (
            feature_template.get("additionalIdentifiers")
            or feature_template.get("additional_identifiers")
            or {}
        )

        # Collect top-level identifier keys if not in nested structure
        if not additional_identifiers_input:
            additional_identifiers_input = {}
            identifier_keys = [
                "wlan_profile_name", "wlanProfileName",
                "site_name_hierarchy", "siteHierarchy",
                "siteUuid", "site_uuid"
            ]
            for key in identifier_keys:
                if key in feature_template:
                    additional_identifiers_input[key] = feature_template[key]

        normalized_result = {
            "feature_template_id": feature_template_id,
            "design_name": design_name,
            "attributes": attributes,
            "excluded_attributes": excluded_attributes,
            "additional_identifiers": additional_identifiers_input
        }

        self.log("Normalized parameters: {0}".format(self.pprint(normalized_result)), "DEBUG")
        return normalized_result

    def get_diff_deleted(self):
        """
        Delete from provision database
        Args:
            self: An instance of a class used for interacting with Cisco Catalyst Center
        Returns:
            self: An instance of the class with updated results and status based on
            the deletion operation.
        Description:
            This function is responsible for removing devices from the Cisco Catalyst Center PnP GUI and
            raise Exception if any error occured.
        """
        device_ip = self.validated_config["management_ip_address"]
        device_type = self.want.get("device_type")
        if device_type is None:
            self.msg = "The Device - {0} is already deleted from the Inventory or not present in the Cisco Catalyst Center.".format(
                self.validated_config.get("management_ip_address")
            )
            self.set_operation_result("success", False, self.msg, "INFO")
            return self

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") <= 0:
            if device_type != "wired":
                self.result["msg"] = "APIs are not supported for the device"
                self.log(self.result["msg"], "CRITICAL")
                return self

        device_id = self.get_device_id()
        provision_id, status = self.get_device_provision_status(device_id)

        if status != "success":
            self.result["msg"] = (
                "Device associated with the passed IP address is not provisioned"
            )
            self.log(self.result["msg"], "CRITICAL")
            self.result["response"] = self.result["msg"]
            return self

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:

            try:
                response = self.dnac_apply["exec"](
                    family="sda",
                    function="delete_provisioned_wired_device",
                    op_modifies=True,
                    params={
                        "device_management_ip_address": self.validated_config[
                            "management_ip_address"
                        ]
                    },
                )
                self.log(
                    "Response collected from the 'delete_provisioned_wired_device' API is : {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                task_id = response.get("taskId")
                deletion_info = self.get_task_status(task_id=task_id)
                self.result["changed"] = True
                self.result["msg"] = "Deletion done Successfully"
                self.result["diff"] = self.validated_config
                self.result["response"] = task_id
                self.log(self.result["msg"], "INFO")
                return self

            except Exception as e:
                self.msg = "Error in delete provisioned device '{0}' due to {1}".format(
                    self.device_ip, str(e)
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        elif self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") <= 0:
            self.log(
                "Detected Catalyst Center version <= 2.3.7.6"
            )
            try:
                response = self.dnac._exec(
                    family="sda",
                    function="delete_provisioned_devices",
                    op_modifies=True,
                    params={"networkDeviceId": device_id},
                )
                self.log(
                    "Received API response from 'delete_provisioned_devices': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                self.check_tasks_response_status(
                    response, api_name="delete_provisioned_devices"
                )

                if self.status not in ["failed", "exited"]:
                    self.msg = (
                        "Deletion completed successfully for the device '{0}'.".format(
                            self.validated_config["management_ip_address"]
                        )
                    )
                    self.set_operation_result("success", True, self.msg, "INFO")
                    return self

                if self.status in ["failed", "exited"]:
                    fail_reason = self.msg
                    self.log(
                        "Exception occurred during 'delete_provisioned_devices': {0}".format(
                            str(fail_reason)
                        ),
                        "ERROR",
                    )
                    self.msg = (
                        "Error in deleting provisioned device '{0}' due to: {1}".format(
                            self.validated_config["management_ip_address"], fail_reason
                        )
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

            except Exception as e:
                self.msg = "Error in delete provisioned device '{0}' due to {1}".format(
                    self.device_ip, str(e)
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        else:
            try:
                clean_up = self.config[0].get("clean_config", False)

                if clean_up:
                    api_function = "delete_network_device_with_configuration_cleanup"
                else:
                    api_function = (
                        "delete_a_network_device_without_configuration_cleanup"
                    )

                delete_param = {"id": device_id}

                self.log(
                    "Initiating API call '{0}' for device ID: {1}".format(
                        api_function, device_id
                    ),
                    "INFO",
                )

                response = self.dnac._exec(
                    family="devices",
                    function=api_function,
                    op_modifies=True,
                    params=delete_param,
                )
                self.log(
                    "Received API response from '{0}': {1}".format(
                        api_function, str(response)
                    ),
                    "DEBUG",
                )
                self.check_tasks_response_status(response, api_name=device_id)

                if self.status not in ["failed", "exited"]:
                    self.device_deleted.append(self.validated_config["management_ip_address"])
                    self.msg = (
                        "Deletion done Successfully for the device '{0}' ".format(
                            self.validated_config["management_ip_address"]
                        )
                    )
                    self.set_operation_result("success", True, self.msg, "INFO")
                    return self

                if self.status in ["failed", "exited"]:
                    fail_reason = self.msg
                    self.log(
                        "Exception occurred during 'delete_provisioned_devices': {0}".format(
                            str(fail_reason)
                        ),
                        "ERROR",
                    )
                    self.msg = (
                        "Error in delete provisioned device '{0}' due to {1}".format(
                            self.device_ip, str(fail_reason)
                        )
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

            except Exception as e:
                self.msg = "Failed to delete the device - ({0}) from Cisco Catalyst Center due to - {1}".format(
                    device_ip, str(e)
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

    def verify_diff_merged(self):
        """
        Verify the merged status(Creation/Updation) of Discovery in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by
            retrieving the current state (have) and desired state (want) of the configuration,
            logs the states, and validates whether the specified device(s) exists in the DNA
            Center configuration's Inventory Database in the provisioned state.
        """
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0 or (
            self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0
            and self.device_type == "wireless"
        ):
            self.log("validate Cisco Catalyst Center config for merged state", "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            device_type = self.want.get("device_type")
            provisioning = self.validated_config.get("provisioning")
            site_name_hierarchy = self.validated_config.get("site_name_hierarchy")
            uuid = self.get_device_id()
            if provisioning is False:
                if self.is_device_assigned_to_site(uuid) is True:
                    self.log(
                        "Requested device is already added to the site {0}".format(
                            site_name_hierarchy
                        ),
                        "INFO",
                    )
                else:
                    self.log(
                        "Requested device is not added to the site {0}".format(
                            site_name_hierarchy
                        ),
                        "INFO",
                    )
                return self

            if device_type == "wired":
                try:
                    status_response = self.dnac_apply["exec"](
                        family="sda",
                        function="get_provisioned_wired_device",
                        params={
                            "device_management_ip_address": self.validated_config[
                                "management_ip_address"
                            ]
                        },
                    )
                except Exception:
                    status_response = {}
                self.log(
                    "Wired device's status Response collected from 'get_provisioned_wired_device' API is:{0}".format(
                        str(status_response)
                    ),
                    "DEBUG",
                )
                status = status_response.get("status")
                self.log(
                    "The provisioned status of the wired device is {0}".format(status),
                    "INFO",
                )

                if status == "success":
                    self.log("Requested wired device is alread provisioned", "INFO")

                else:
                    self.log("Requested wired device is not provisioned", "INFO")

            else:
                self.log(
                    "Currently we don't have any API in the Cisco Catalyst Center to fetch the provisioning details of wireless devices",
                    "INFO",
                )

        else:
            for config in self.config:
                app_telemetry = config.get("application_telemetry")
                if app_telemetry:
                    self.log(
                        "Since the application telemetry lacks a GET API, verification is not possible.",
                        "INFO",
                    )
                device_ip = config.get("management_ip_address")
                device_id = self.get_device_ids_from_device_ips([device_ip])

                # Ensure device_id exists before proceeding
                network_device_id = device_id.get(device_ip)
                if not network_device_id:
                    self.log("Device ID not found for IP {}".format(device_ip), "ERROR")
                    continue

                provision_id, status = self.get_device_provision_status(
                    network_device_id, device_ip
                )
                self.log(
                    "Provision ID and status for device '{0}': provision_id='{1}', status='{2}'".format(
                        device_ip, provision_id, status
                    ),
                    "DEBUG",
                )

                if status == "success":
                    self.log("Requested wired device is alread provisioned", "INFO")

                else:
                    self.log("Requested wired device is not provisioned", "INFO")

        return self

    def verify_diff_deleted(self):
        """
        Verify the deletion status of Discovery in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified discovery(s) exists in the Cisco Catalyst Center configuration's
            Inventory Database in the provisioned state.
        """
        self.log("validate Cisco Catalyst Center config for deleted state", "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        device_type = self.want.get("device_type")
        if device_type == "wired":
            try:
                status_response = self.dnac_apply["exec"](
                    family="sda",
                    function="get_provisioned_wired_device",
                    params={
                        "device_management_ip_address": self.validated_config[
                            "management_ip_address"
                        ]
                    },
                )
            except Exception:
                status_response = {}
            self.log(
                "Wired device's status Response collected from 'get_provisioned_wired_device' API is:{0}".format(
                    str(status_response)
                ),
                "DEBUG",
            )
            status = status_response.get("status")
            self.log(
                "The provisioned status of the wired device is {0}".format(status),
                "INFO",
            )

            if status == "success":
                self.log(
                    "Requested wired device is in provisioned state and is not unprovisioned",
                    "INFO",
                )

            else:
                self.log("Requested wired device is unprovisioned", "INFO")

        else:
            self.log(
                "Currently we don't have any API in the Cisco Catalyst Center to fetch the provisioning details of wireless devices"
            )
        self.status = "success"

        return self

    def update_device_provisioning_messages(self):
        """
        Aggregates and logs status messages related to device provisioning activities.
        Description:
            This method synthesizes a comprehensive summary message by checking the outcomes of various operations
            (provision, re-provision, deletion, telemetry changes). It categorizes outcomes into those that changed the
            system state and those that did not (e.g., device already provisioned). The final message and the 'changed'
            status are set in the module's result.
        Returns:
            self: The instance of the class with updated `msg` and `result`.
        """

        self.log("Aggregating all final status messages for the module run.", "DEBUG")
        self.result = self.result if hasattr(self, 'result') else {}
        self.result["changed"] = False
        result_msg_list_changed = []
        result_msg_list_not_changed = []

        if self.provisioned_wired_device:
            msg = "Wired device(s) '{0}' provisioned successfully.".format(
                "', '".join(map(str, self.provisioned_wired_device))
            )
            result_msg_list_changed.append(msg)

        if self.provisioned_wireless_device:
            msg = "Wireless device(s) '{0}' provisioned successfully.".format(
                "', '".join(self.provisioned_wireless_device)
            )
            result_msg_list_changed.append(msg)

        if self.already_provisioned_wired_device:
            msg = "Wired device(s) '{0}' already provisioned.".format(
                "', '".join(self.already_provisioned_wired_device)
            )
            result_msg_list_not_changed.append(msg)

        if self.already_provisioned_wireless_device:
            msg = "Wireless device(s) '{0}' already provisioned.".format(
                "', '".join(self.already_provisioned_wireless_device)
            )
            result_msg_list_not_changed.append(msg)

        if self.re_provision_wired_device:
            msg = "Wired device(s) '{0}' re-provisioned successfully.".format(
                "', '".join(map(str, self.re_provision_wired_device))
            )
            result_msg_list_changed.append(msg)

        if self.re_provision_wireless_device:
            msg = "Wireless device(s) '{0}' re-provisioned successfully.".format(
                "', '".join(self.re_provision_wireless_device)
            )
            result_msg_list_changed.append(msg)

        if self.assigned_device_to_site:
            msg = "Device(s) '{0}' assigned to site successfully.".format(
                "', '".join(self.assigned_device_to_site)
            )
            result_msg_list_changed.append(msg)

        if self.device_deleted:
            msg = "Device(s) '{0}' deleted successfully.".format(
                "', '".join(self.device_deleted)
            )
            result_msg_list_changed.append(msg)

        if self.enable_application_telemetry:
            msg = "Application telemetry enabled successfully for {0}".format(
                "', '".join(self.enable_application_telemetry)
            )
            result_msg_list_changed.append(msg)

        if self.disable_application_telemetry:
            msg = "Application telemetry disabled successfully for {0}".format(
                "', '".join(self.disable_application_telemetry)
            )
            result_msg_list_changed.append(msg)

        # Combine messages and set result flags
        if result_msg_list_not_changed and result_msg_list_changed:
            self.result["changed"] = True
            self.msg = "{0} {1}".format(
                " ".join(result_msg_list_not_changed), " ".join(result_msg_list_changed)
            )
        elif result_msg_list_not_changed:
            self.msg = " ".join(result_msg_list_not_changed)
        elif result_msg_list_changed:
            self.result["changed"] = True
            self.msg = " ".join(result_msg_list_changed)
        else:
            input = self.validated_config
            ips = [item["management_ip_address"] for item in input]
            ip_list_str = ", ".join(ips)

            self.msg = "No provisioning operations were executed for these IPs: {0}".format(ip_list_str)
            self.set_operation_result(
                "success", False, self.msg, "INFO"
            )

        self.result["msg"] = self.msg
        self.result["response"] = self.msg

        self.log("Final aggregated message: '{0}'".format(self.msg), "INFO")
        self.log("Final changed status: {0}".format(self.result["changed"]), "DEBUG")

        return self


def main():
    """
    main entry point for module execution
    """

    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "validate_response_schema": {"type": "bool", "default": True},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_provision = Provision(module)
    config_verify = ccc_provision.params.get("config_verify")
    provision_performed = False

    if (
        ccc_provision.compare_dnac_versions(ccc_provision.get_ccc_version(), "2.3.5.3")
        < 0
    ):
        ccc_provision.msg = """The specified version '{0}' does not support the 'provision_workflow_manager' feature.
        Supported versions start from '2.3.5.3' onwards. """.format(
            ccc_provision.get_ccc_version()
        )
        ccc_provision.status = "failed"
        ccc_provision.check_return_status()

    state = ccc_provision.params.get("state")
    if state not in ccc_provision.supported_states:
        ccc_provision.status = "invalid"
        ccc_provision.msg = "State {0} is invalid".format(state)
        ccc_provision.check_return_status()

    ccc_provision.validate_input(state=state).check_return_status()

    is_version_valid = (
        ccc_provision.compare_dnac_versions(ccc_provision.get_ccc_version(), "2.3.7.6")
        >= 0
    )

    if is_version_valid:
        ccc_provision.log("Fetching device types from Cisco Catalyst Center.", "INFO")
        device_dict = ccc_provision.get_device_type()
        ccc_provision.log(
            "Device classification result: {0}".format(device_dict), "DEBUG"
        )

    if is_version_valid and state == "merged":
        for device_type, devices in device_dict.items():
            if not devices:
                ccc_provision.log(
                    "No devices found for type '{0}', skipping.".format(device_type),
                    "INFO",
                )
                continue

            ccc_provision.log(
                "Processing {0} devices: {1}".format(device_type, devices), "INFO"
            )
            ccc_provision.reset_values()

            if device_type == "wired":
                ccc_provision.device_type = "wired"
                ccc_provision.log("Applying configuration for wired devices.", "INFO")
                ccc_provision.get_diff_state_apply[state]().check_return_status()
                provision_performed = True
                if config_verify:
                    ccc_provision.log(
                        "Verifying configuration for wired devices.", "INFO"
                    )
                    ccc_provision.verify_diff_state_apply[state]().check_return_status()

            elif device_type == "wireless":
                ccc_provision.device_type = "wireless"
                for config in ccc_provision.validated_config:
                    device_ip = config.get("management_ip_address")
                    if device_ip in ccc_provision.device_dict["wireless"]:
                        ccc_provision.log(
                            "Applying configuration for wireless device: {0}".format(
                                device_ip
                            ),
                            "INFO",
                        )
                        ccc_provision.reset_values()
                        ccc_provision.get_want(config).check_return_status()
                        ccc_provision.get_diff_state_apply[
                            state
                        ]().check_return_status()
                        provision_performed = True
                        if config_verify:
                            ccc_provision.log(
                                "Verifying configuration for wireless device: {0}".format(
                                    device_ip
                                ),
                                "INFO",
                            )
                            ccc_provision.verify_diff_state_apply[
                                state
                            ]().check_return_status()

        ccc_provision.device_type = None
        ccc_provision.validate_input(state=state).check_return_status()
        ccc_provision.log(
            "Checking for telemetry configurations in the validated configuration.",
            "DEBUG",
        )

        for config in ccc_provision.validated_config:
            ccc_provision.log("Inspecting configuration: {0}".format(config), "DEBUG")

            application_telemetry = config.get("application_telemetry", None)

            if application_telemetry:
                ccc_provision.log(
                    "Telemetry configuration found. Applying telemetry settings for device.",
                    "INFO",
                )
                ccc_provision.reset_values()
                ccc_provision.get_want(config).check_return_status()
                ccc_provision.get_diff_state_apply[state]().check_return_status()
                provision_performed = True
                if config_verify:
                    ccc_provision.log("Verifying telemetry configuration", "INFO")
                    ccc_provision.verify_diff_state_apply[state]().check_return_status()

    else:
        for config in ccc_provision.validated_config:
            ccc_provision.log(
                "Processing device with management IP: {0}".format(
                    config.get("management_ip_address")
                ),
                "INFO",
            )
            ccc_provision.reset_values()
            ccc_provision.get_want(config).check_return_status()
            ccc_provision.get_diff_state_apply[state]().check_return_status()
            provision_performed = True
            if config_verify:
                ccc_provision.log(
                    "Verifying configuration for device with management IP: {0}".format(
                        config.get("management_ip_address")
                    ),
                    "INFO",
                )
                ccc_provision.verify_diff_state_apply[state]().check_return_status()

    ccc_provision.update_device_provisioning_messages().check_return_status()

    module.exit_json(**ccc_provision.result)


if __name__ == "__main__":
    main()
