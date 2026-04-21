#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Abhishek Maheshwari, Madhan Sankaranarayanan"
DOCUMENTATION = r"""
---
module: sda_fabric_sites_zones_workflow_manager
short_description: Manage fabric site(s)/zone(s) and
  update the authentication profile template in Cisco
  Catalyst Center.
description:
  - Creating fabric site(s) for the SDA operation in
    Cisco Catalyst Center.
  - Updating fabric site(s) for the SDA operation in
    Cisco Catalyst Center.
  - Creating fabric zone(s) for the SDA operation in
    Cisco Catalyst Center.
  - Updating fabric zone(s) for the SDA operation in
    Cisco Catalyst Center.
  - Deletes fabric site(s) from Cisco Catalyst Center.
  - Deletes fabric zone(s) from Cisco Catalyst Center.
  - Configure the authentication profile template for
    fabric site/zone in Cisco Catalyst Center.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Abhishek Maheshwari (@abmahesh) Madhan Sankaranarayanan
  (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center configuration after applying the playbook
      configuration.
    type: bool
    default: false
  state:
    description: The desired state of Cisco Catalyst
      Center after the module execution.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description: A list containing detailed configurations
      for creating, updating, or deleting fabric sites
      or zones in a Software-Defined Access (SDA) environment.
      It also includes specifications for updating the
      authentication profile template for these sites.
      Each element in the list represents a specific
      operation to be performed on the SDA infrastructure,
      such as the addition, modification, or removal
      of fabric sites/zones, and modifications to authentication
      profiles.
    type: list
    elements: dict
    required: true
    suboptions:
      fabric_sites:
        description: A dictionary containing detailed
          configurations for managing REST Endpoints
          that will receive Audit log and Events from
          the Cisco Catalyst Center Platform. This dictionary
          is essential for specifying attributes and
          parameters required for the lifecycle management
          of fabric sites, zones, and associated authentication
          profiles.
        type: dict
        suboptions:
          site_name_hierarchy:
            description: This name uniquely identifies
              the site for operations such as creating,
              updating, or deleting fabric sites or
              zones, as well as for updating the authentication
              profile template. This parameter is mandatory
              for any fabric site/zone management operation.
            type: str
            required: true
          fabric_type:
            description: Specifies the type of site
              to be managed within the SDA environment.
              The acceptable values are 'fabric_site'
              and 'fabric_zone'. The default value is
              'fabric_site', indicating the configuration
              of a broader network area, whereas 'fabric_zone'
              typically refers to a more specific segment
              within the site.
            type: str
            required: true
          authentication_profile:
            description: The authentication profile
              applied to the specified fabric. This
              profile determines the security posture
              and controls for network access within
              the site. Possible values include 'Closed
              Authentication', 'Low Impact', 'No Authentication',
              and 'Open Authentication'. This setting
              is critical when creating or updating
              a fabric site or updating the authentication
              profile template.
            type: str
          is_pub_sub_enabled:
            description: A boolean flag that indicates
              whether the pub/sub mechanism is enabled
              for control nodes in the fabric site.
              This feature is relevant only when creating
              or updating fabric sites, not fabric zones.
              When set to 'true', pub/sub is enabled for
              more efficient control plane communication
              within the fabric site. The default is True
              for fabric sites, and this setting is not
              applicable for fabric zones.
              When set to 'false', the fabric site is
              configured to use LISP/BGP for control plane
              communication, which provides traditional
              routing mechanisms.
            type: bool
            default: true
          apply_pending_events:
            description: Modifying an IP address pool
              used in a fabric causes the fabric to
              become outdated. An update is required
              to apply the IP address pool changes to
              the devices in the fabric site. The reconfiguration
              time depends on the number of devices.
              During an upgrade, any pending fabric
              updates are captured as pending fabric
              events and applied to the respective site.  By
              default, this is set to False.
            type: bool
          update_authentication_profile:
            description: A dictionary containing the
              specific details required to update the
              authentication profile template associated
              with the fabric site. This includes advanced
              settings that fine-tune the authentication
              process and security controls within the
              site.
            type: dict
            suboptions:
              authentication_order:
                description: Specifies the primary method
                  of authentication for the site. The
                  available methods are 'dot1x' (IEEE
                  802.1X) and 'mac' (MAC-based authentication).
                  This setting determines the order
                  in which authentication mechanisms
                  are attempted.
                type: str
              dot1x_fallback_timeout:
                description: The timeout duration, in
                  seconds, for falling back from 802.1X
                  authentication. This value must be
                  within the range of 3 to 120 seconds.
                  It defines the period a device waits
                  before attempting an alternative authentication
                  method if 802.1X fails.
                type: int
              wake_on_lan:
                description: A boolean value indicating
                  whether the Wake-on-LAN feature is
                  enabled. Wake-on-LAN allows the network
                  to remotely wake up devices that are
                  in a low-power state.
                type: bool
              number_of_hosts:
                description: Specifies the number of
                  hosts allowed per port. The available
                  options are 'Single' for one device
                  per port or 'Unlimited' for multiple
                  devices. This setting helps in controlling
                  the network access and maintaining
                  security.
                type: str
              enable_bpu_guard:
                description: A boolean setting that
                  enables or disables BPDU Guard. BPDU
                  Guard provides a security mechanism
                  by disabling a port when a BPDU (Bridge
                  Protocol Data Unit) is received, protecting
                  against potential network loops. This
                  setting defaults to true and is applicable
                  only when the authentication profile
                  is set to "Closed Authentication".
                type: bool
              pre_auth_acl:
                description: Defines the Pre-Authentication
                  Access Control List (ACL), which is
                  applicable only when the 'authentication_profile'
                  is set to "Low Impact." This profile
                  allows limited network access before
                  authentication, and the ACL controls
                  which traffic is allowed or blocked
                  during this phase. It is not used
                  with other profiles, as they typically
                  block all traffic until authentication
                  is complete.
                type: dict
                suboptions:
                  enabled:
                    description: A boolean value indicating
                      whether the Pre-Authentication
                      ACL is enabled. When set to 'true',
                      the ACL rules are enforced to
                      control traffic before authentication.
                    type: bool
                  implicit_action:
                    description: Specifies the default
                      action for traffic that does not
                      match any explicit ACL rules.
                      Common actions include 'PERMIT'
                      to allow unmatched traffic or
                      'DENY' to block it.  Implicit
                      behaviour unless overridden (defaults
                      to "DENY").
                    type: str
                    default: "DENY"
                  description:
                    description: A brief text description
                      of the Pre-Authentication ACL,
                      outlining its purpose or providing
                      relevant notes for administrators.
                    type: str
                  access_contracts:
                    description: A list of rules that
                      specify how traffic is handled
                      based on defined conditions. Each
                      rule determines whether traffic
                      is permitted or denied based on
                      the contract parameters. If the
                      'access_contracts' is not provided
                      or is set to null, the system
                      will fall back on its default
                      traffic handling settings. Additionally,
                      up to 3 access control rules can
                      be defined at a time.
                    type: list
                    elements: dict
                    suboptions:
                      action:
                        description: The action to apply
                          when traffic matches the rule.
                          The allowed actions are 'PERMIT'
                          (allow the traffic) and 'DENY'
                          (block the traffic).
                        type: str
                      protocol:
                        description: The protocol that
                          defines the type of traffic
                          to be filtered by the access
                          contract rule. The allowed
                          protocols are 'UDP', 'TCP',
                          and 'TCP_UDP'. However, 'TCP'
                          and 'TCP_UDP' are only allowed
                          when the contract port is
                          set to 'domain'.
                        type: str
                      port:
                        description: Specifies the symbolic
                          port name to which the ACL
                          rule applies. The allowed
                          values are 'domain' (DNS),
                          'bootpc' (Bootstrap Protocol
                          Client), and 'bootps' (Bootstrap
                          Protocol Server). Each port
                          name can only be used once
                          in the Access Contract list.
                        type: str
requirements:
  - dnacentersdk >= 2.9.2
  - python >= 3.9
notes:
  - To ensure the module operates correctly for scaled
    sets,
    which involve creating or updating fabric
    sites/zones and handling the updation of authentication
    profile template,
    please provide valid input in
    the playbook. If any failure is encountered,
    the
    module will and halt execution without proceeding
    to further operations.
  - When deleting fabric sites,
    make sure to provide
    the input to remove the fabric zones associated
    with them in the playbook. Fabric sites cannot be
    deleted until all underlying fabric zones have been
    removed and it can be any order as per the module
    design fabric zones will be deleted first followed
    by fabric sites.
  - Reconfiguration of fabric pending events is supported
    starting from version 2.3.7.9 onwards. Additionally,
    the authentication profile for the 'Low Impact'
    profile now allows more customization of its parameters
  - Parameter 'site_name' is updated to 'site_name_hierarchy'.
  - SDK Method used are
    ccc_fabric_sites.FabricSitesZones.get_site
    ccc_fabric_sites.FabricSitesZones.get_fabric_sites
    ccc_fabric_sites.FabricSitesZones.get_fabric_zones
    ccc_fabric_sites.FabricSitesZones.add_fabric_site
    ccc_fabric_sites.FabricSitesZones.update_fabric_site
    ccc_fabric_sites.FabricSitesZones.add_fabric_zone
    ccc_fabric_sites.FabricSitesZones.update_fabric_zone
    ccc_fabric_sites.FabricSitesZones.get_authentication_profiles
    ccc_fabric_sites.FabricSitesZones.update_authentication_profile
    ccc_fabric_sites.FabricSitesZones.delete_fabric_site_by_id
    ccc_fabric_sites.FabricSitesZones.delete_fabric_zone_by_id
"""
EXAMPLES = r"""
---
- name: Create a fabric site for SDA with the specified
    name.
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1"
            authentication_profile: "Closed Authentication"
            is_pub_sub_enabled: false
- name: Update a fabric site for SDA with the specified
    name.
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1"
            authentication_profile: "Open Authentication"
- name: Update a fabric zone for SDA with the specified
    name.
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1/Floor1"
            fabric_type: "fabric_zone"
            authentication_profile: "Closed Authentication"
- name: Update fabric zone for sda with given name.
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1/Floor1"
            fabric_type: "fabric_zone"
            authentication_profile: "Open Authentication"
- name: Apply all the pending sda fabric events to the
    given site.
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1"
            authentication_profile: "Open Authentication"
            apply_pending_events: true
- name: Set up Pre-Authentication ACL for Low Impact
    Profile
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1"
            fabric_type: "fabric_zone"
            authentication_profile: "Low Impact"
            is_pub_sub_enabled: false
            update_authentication_profile:
              authentication_order: "dot1x"
              dot1x_fallback_timeout: 28
              wake_on_lan: false
              number_of_hosts: "Single"
              pre_auth_acl:
                enabled: true
                implicit_action: "PERMIT"
                description: "low auth profile description"
                access_contracts:
                  - action: "PERMIT"
                    protocol: "UDP"
                    port: "bootps"
                  - action: "PERMIT"
                    protocol: "UDP"
                    port: "bootpc"
                  - action: "PERMIT"
                    protocol: "UDP"
                    port: "domain"
- name: Update/customise authentication profile template
    for fabric site/zone.
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1"
            fabric_type: "fabric_zone"
            authentication_profile: "Open Authentication"
            is_pub_sub_enabled: false
            update_authentication_profile:
              authentication_order: "dot1x"
              dot1x_fallback_timeout: 28
              wake_on_lan: false
              number_of_hosts: "Single"
- name: Deleting/removing fabric site from sda from
    Cisco Catalyst Center
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1"
- name: Deleting/removing fabric zone from sda from
    Cisco Catalyst Center
  cisco.dnac.sda_fabric_sites_zones_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - fabric_sites:
          - site_name_hierarchy: "Global/Test_SDA/Bld1/Floor1"
            fabric_type: "fabric_zone"
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class FabricSitesZones(DnacBase):
    """Class containing member attributes for sda fabric sites and zones workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.create_site, self.update_site, self.no_update_site = [], [], []
        self.create_zone, self.update_zone, self.no_update_zone = [], [], []
        self.update_auth_profile, self.no_update_profile, self.pending_fabric_event = (
            [],
            [],
            [],
        )
        self.delete_site, self.delete_zone, self.absent_site, self.absent_zone = (
            [],
            [],
            [],
            [],
        )

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
            If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
            will contain the validated configuration. If it fails, 'self.status' will be 'failed', and
            'self.msg' will describe the validation issues.
        """

        temp_spec = {
            "fabric_sites": {
                "type": "list",
                "elements": "dict",
                "site_name_hierarchy": {"type": "str"},
                "fabric_type": {"type": "str", "default": "fabric_site"},
                "authentication_profile": {"type": "str"},
                "is_pub_sub_enabled": {"type": "bool", "default": True},
                "apply_pending_events": {"type": "bool", "default": False},
                "update_authentication_profile": {
                    "type": "dict",
                    "site_name_hierarchy": {"type": "str"},
                    "authentication_profile": {"type": "str"},
                    "authentication_order": {"type": "str"},
                    "dot1x_fallback_timeout": {"type": "int"},
                    "wake_on_lan": {"type": "bool"},
                    "number_of_hosts": {"type": "str"},
                    "enable_bpu_guard": {"type": "bool"},
                    "pre_auth_acl": {
                        "type": "dict",
                        "enabled": {"type": "bool"},
                        "implicit_action": {"type": "str"},
                        "description": {"type": "str"},
                        "access_contracts": {
                            "type": "list",
                            "elements": "dict",
                            "action": {"type": "str"},
                            "protocol": {"type": "str"},
                            "port": {"type": "str"},
                        },
                    },
                },
            },
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(
                invalid_params
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")

        return self

    def get_fabric_site_detail(self, site_name, site_id):
        """
        Retrieves the detailed information of a fabric site from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The complete name of the site for which the details need to be retrieved.
            site_id (str): The unique identifier of the site in the Cisco Catalyst Center.
        Returns:
            dict or None: A dictionary containing the details of the fabric site if found.
                        Returns None if the site is not a fabric site or if an error occurs.
        Description:
            This function fetches the fabric site details from Cisco Catalyst Center using the provided site ID.
            It logs the API response and returns the site details if the site is a fabric site. If the site is not
            found or is not a fabric site, it returns None. In case of an error, it logs the issue, sets the status
            to "failed", and handles the failure.
        """

        try:
            response = self.dnac._exec(
                family="sda",
                function="get_fabric_sites",
                op_modifies=True,
                params={"site_id": site_id},
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_fabric_sites' for the site '{0}': {1}".format(
                    site_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "Given site '{0}' is not a fabric site in Cisco Catalyst Center.".format(
                        site_name
                    ),
                    "INFO",
                )
                return None

            return response[0]
        except Exception as e:
            self.msg = """Error while getting the details of Site with given name '{0}' present in
                    Cisco Catalyst Center: {1}""".format(
                site_name, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return None

    def get_fabric_zone_detail(self, site_name, site_id):
        """
        Retrieves the detailed information of a fabric zone from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The complete name of the site for which the fabric zone details need to be retrieved.
            site_id (str): The unique identifier of the site in the Cisco Catalyst Center.
        Returns:
            dict or None: A dictionary containing the details of the fabric zone if found,
                        or None if the site is not a fabric zone or an error occurs.
        Description:
            This function fetches the fabric zone details from Cisco Catalyst Center using the provided site ID.
            It logs the API response and returns the details if the site is a fabric zone. If the site is not
            recognized as a fabric zone, it returns None. In case of an error, it logs the issue, sets the status
            to "failed", and handles the failure appropriately.
        """

        try:
            response = self.dnac._exec(
                family="sda",
                function="get_fabric_zones",
                op_modifies=True,
                params={"site_id": site_id},
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_fabric_zones' for the site '{0}': {1}".format(
                    site_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "Given site '{0}' is not a fabric zone in Cisco Catalyst Center.".format(
                        site_name
                    ),
                    "INFO",
                )
                return None

            return response[0]

        except Exception as e:
            self.msg = """Error while getting the details of fabric zone '{0}' present in
                    Cisco Catalyst Center: {1}""".format(
                site_name, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return None

    def get_have(self, config):
        """
        Retrieves the current state of fabric sites and zones from the Cisco Catalyst Center based on the given configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A configuration dictionary containing details about the fabric sites and zones.
                        The key "fabric_sites" should contain a list of dictionaries.
        Returns:
            self (object): The instance of the class with the updated `have` attribute containing the current state
                of fabric sites and zones.
        Description:
            This function processes the provided configuration to determine the current state of fabric sites
            and zones in the Cisco Catalyst Center. It iterates over the "fabric_sites" list in the configuration,
            extracting the site name and type. For each site, it retrieves the corresponding site or zone ID
            and details using the `get_site_id`, `get_fabric_site_detail`, and `get_fabric_zone_detail` methods.
            The `have` attribute of the instance is updated with this dictionary, representing the current state
            of the system. The function logs the final state and returns the instance for further use.
        """

        have = {"fabric_sites_ids": [], "fabric_zone_ids": []}
        fabric_sites = config.get("fabric_sites", [])

        for site in fabric_sites:
            site_name = site.get("site_name_hierarchy")
            fabric_type = site.get("fabric_type", "fabric_site")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    f"The site '{site_name}' does not exist in the Catalyst Center. "
                    "A site must be created first before it can be converted into a Fabric Site."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            if fabric_type == "fabric_site":
                site_detail = self.get_fabric_site_detail(site_name, site_id)
                if site_detail:
                    self.log(
                        "Site detail for fabric site {0} collected successfully.".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    have["fabric_sites_ids"].append(site_detail.get("siteId"))
            else:
                zone_detail = self.get_fabric_zone_detail(site_name, site_id)
                if zone_detail:
                    self.log(
                        "Site detail for fabric zone {0} collected successfully.".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    have["fabric_zone_ids"].append(zone_detail.get("siteId"))

        self.have = have
        self.log("Current State (have): {0}".format(str(have)), "INFO")

        return self

    def get_want(self, config):
        """
        Collects and validates the desired state configuration for fabric sites and zones from the given playbook configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the configuration for the desired state of fabric sites and zones.
                        It should include a key "fabric_sites" with a list of dictionaries.
        Returns:
            self (object): The instance of the class with the updated `want` attribute containing the validated desired state
                of fabric sites and zones and updating authentication profile template.
        Description:
            This function processes the provided playbook configuration to determine the desired state of fabric sites
            and zones in the Cisco Catalyst Center.
            The validated site information is stored in the `want` dictionary under the key "fabric_sites".
            The `want` attribute of the instance is updated with this dictionary, representing the desired state
            of the system. The function returns the instance for further processing or method chaining.
        """

        want = {}
        fabric_sites = config.get("fabric_sites")

        if not fabric_sites:
            self.msg = (
                "No input provided in the playbook for fabric site/zone operation or updating the "
                "authentication profile template in Cisco Catalysyt Center."
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        if fabric_sites:
            fabric_site_info = []

            for site in fabric_sites:
                site_name = site.get("site_name_hierarchy")
                fabric_type = site.get("fabric_type", "fabric_site")

                if not site_name:
                    self.msg = (
                        "Required parameter 'site_name_hierarchy' is missing. It must be provided in the playbook for fabric site/zone "
                        "operations in Cisco Catalyst Center."
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if site_name.title() == "Global":
                    self.msg = (
                        "Unable to create/update the given site 'Global' to {0} as it is not allowed operation "
                        "in the Cisco Catalyst Center."
                    ).format(fabric_type)
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if fabric_type not in ["fabric_site", "fabric_zone"]:
                    self.msg = (
                        "Invalid fabric_type '{0}' provided. Please use 'fabric_site' or 'fabric_zone' for fabric site/zone operations"
                        " in Cisco Catalyst Center."
                    ).format(fabric_type)
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                fabric_site_info.append(site)

            want["fabric_sites"] = fabric_site_info

        self.want = want
        self.msg = "Successfully collected all parameters from the playbook for creating/updating the fabric sites/zones."
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def create_fabric_site(self, site):
        """
        Creates a fabric site in the Cisco Catalyst Center using the provided site configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site (dict): A dictionary containing the details of the fabric site to be created.
        Returns:
            self (object): The instance of the class with updated status and result attributes reflecting the outcome
                of the fabric site creation operation.
        Description:
            This function creates a fabric site in the Cisco Catalyst Center based on the configuration provided
            in the `site` dictionary.
            The function constructs the payload for the API request, which includes the site ID, authentication profile,
            and an optional flag for PubSub enablement. The payload is then sent to the `add_fabric_site` API endpoint.
            After the API call, the function monitors the status of the task using the `get_task_details` method.
            If the task encounters an error, the function logs the error and sets the status to "failed". If the task completes
            successfully and contains the necessary data, the status is set to "success", and the site is marked as created.
        """

        try:
            fabric_site_payload = []
            site_name = site.get("site_name_hierarchy")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    f"The site '{site_name}' does not exist in the Catalyst Center. "
                    "A site must be created first before it can be converted into a Fabric Site."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            auth_profile = site.get("authentication_profile")
            if not auth_profile:
                self.msg = (
                    "Required parameter 'authentication_profile'is missing needed for creation of fabric sites in Cisco Catalyst Center. "
                    "Please provide one of the following authentication_profile ['Closed Authentication', 'Low Impact'"
                    ", 'No Authentication', 'Open Authentication'] in the playbook."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            site_payload = {
                "siteId": site_id,
                "authenticationProfileName": site.get("authentication_profile"),
                "isPubSubEnabled": site.get("is_pub_sub_enabled", False),
            }
            fabric_site_payload.append(site_payload)
            task_name = "add_fabric_site"
            payload = {"payload": fabric_site_payload}
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Fabric site '{0}' created successfully in the Cisco Catalyst Center".format(
                site_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.create_site.append(site_name)

        except Exception as e:
            self.msg = "An exception occured while creating the fabric site '{0}' in Cisco Catalyst Center: {1}".format(
                site_name, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def fabric_site_needs_update(self, site, site_in_ccc):
        """
        Determines if a fabric site in Cisco Catalyst Center needs to be updated based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site (dict): A dictionary containing the desired configuration of the fabric site.
            site_in_ccc (dict): A dictionary containing the current configuration of the fabric site as
                                present in the Cisco Catalyst Center.
        Returns:
            bool: True if the fabric site requires an update, False otherwise.
        Description:
            This function compares the desired configuration (`site`) of a fabric site with its current
            configuration (`site_in_ccc`) in the Cisco Catalyst Center.
            The function returns True, indicating that the fabric site needs to be updated. Otherwise, it returns False,
            indicating no update is needed.
        """

        auth_profile = site.get("authentication_profile")
        if auth_profile and auth_profile != site_in_ccc.get(
            "authenticationProfileName"
        ):
            return True

        is_pub_sub_enabled = site.get("is_pub_sub_enabled")
        if is_pub_sub_enabled is not None and is_pub_sub_enabled != site_in_ccc.get(
            "isPubSubEnabled"
        ):
            return True

        return False

    def update_fabric_site(self, site, site_in_ccc):
        """
        Updates a fabric site in the Cisco Catalyst Center based on the provided configuration and current state.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site (dict): A dictionary containing the desired configuration for the fabric site.
            site_in_ccc (dict): A dictionary containing the current configuration of the fabric site
                                in the Cisco Catalyst Center.
        Returns:
            self (object): The instance of the class with updated status and result attributes reflecting the outcome
                of the fabric site update operation.
        Description:
            This method updates a fabric site in the Cisco Catalyst Center. The constructed payload includes the site ID,
            authentication profile name, and PubSub enablement status and payload is sent to the `update_fabric_site`
            API endpoint.
            After initiating the update, the method tracks the status of the update task using `get_task_details`.
            It checks for task errors or successful completion, updating the status and logging messages accordingly.
            If the task fails, an appropriate error message is logged, and the status is set to "failed".
        """

        try:
            update_site_params = []
            site_name = site.get("site_name_hierarchy")

            if site.get("is_pub_sub_enabled") is None:
                pub_sub_enable = site_in_ccc.get("isPubSubEnabled")
            else:
                pub_sub_enable = site.get("is_pub_sub_enabled")

            if not site.get("authentication_profile"):
                auth_profile = site_in_ccc.get("authenticationProfileName")
            else:
                auth_profile = site.get("authentication_profile")

            site_payload = {
                "id": site_in_ccc.get("id"),
                "siteId": site_in_ccc.get("siteId"),
                "authenticationProfileName": auth_profile,
                "isPubSubEnabled": pub_sub_enable,
            }
            update_site_params.append(site_payload)
            payload = {"payload": update_site_params}
            task_name = "update_fabric_site"
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Fabric site '{0}' updated successfully in the Cisco Catalyst Center".format(
                site_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.update_site.append(site_name)

        except Exception as e:
            self.msg = "An exception occured while updating the fabric site '{0}' in Cisco Catalyst Center: {1}".format(
                site_name, str(e)
            )
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def create_fabric_zone(self, zone):
        """
        Creates a fabric zone in the Cisco Catalyst Center based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            zone (dict): A dictionary containing the desired configuration for the fabric zone.
        Returns:
            self (object): The instance of the class with updated status and result attributes reflecting the outcome
                of the fabric zone creation operation.
        Description:
            This method creates a fabric zone in the Cisco Catalyst Center and  sends the payload to the add_fabric_zone
            API endpoint. The method logs the requested payload and the API response.
            After initiating the creation, the method monitors the task's status using `get_task_details`.
            It checks for task errors or successful completion. If the task fails, an appropriate error message
            is logged, and the status is set to "failed". If the task succeeds, the status is set to "success",
            and the site name is added to the list of successfully created zones.
            The function returns the class instance (`self`) with the updated attributes.
        """

        try:
            fabric_zone_payload = []
            site_name = zone.get("site_name_hierarchy")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    f"The site '{site_name}' does not exist in the Catalyst Center. "
                    "A site must be created first before it can be converted into a Fabric Site."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            zone_payload = {
                "siteId": site_id,
                "authenticationProfileName": zone.get("authentication_profile"),
            }
            fabric_zone_payload.append(zone_payload)
            self.log(
                "Requested payload for creating fabric zone '{0}' is:  {1}".format(
                    site_name, zone_payload
                ),
                "INFO",
            )
            task_name = "add_fabric_zone"
            payload = {"payload": fabric_zone_payload}
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Fabric zone '{0}' created successfully in the Cisco Catalyst Center.".format(
                site_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.create_zone.append(site_name)

        except Exception as e:
            self.msg = "An exception occured while creating the fabric zone '{0}' in Cisco Catalyst Center: {1}".format(
                site_name, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def update_fabric_zone(self, zone, zone_in_ccc):
        """
        Updates an existing fabric zone in the Cisco Catalyst Center with the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            zone (dict): A dictionary containing the desired updates for the fabric zone.
            zone_in_ccc (dict): A dictionary containing the current configuration of the fabric zone
                                in the Cisco Catalyst Center.
        Returns:
            self (object): The instance of the class with updated status and result attributes reflecting the outcome
                of the fabric zone update operation.
        Description:
            This method updates the configuration of a fabric zone in the Cisco Catalyst Center.
            The constructed payload is sent to the `update_fabric_zone` API endpoint. The method logs the
            requested payload and the API response.
            After initiating the update, the method monitors the task's status using `get_task_details`. It checks
            for task errors or successful completion.
            The function returns the class instance (`self`) with the updated attributes.
        """

        try:
            update_zone_params = []
            site_name = zone.get("site_name_hierarchy")

            zone_payload = {
                "id": zone_in_ccc.get("id"),
                "siteId": zone_in_ccc.get("siteId"),
                "authenticationProfileName": zone.get("authentication_profile")
                or zone_in_ccc.get("authenticationProfileName"),
            }
            update_zone_params.append(zone_payload)
            self.log(
                "Requested payload for updating fabric zone '{0}' is:  {1}".format(
                    site_name, zone_payload
                ),
                "INFO",
            )

            payload = {"payload": update_zone_params}
            task_name = "update_fabric_zone"
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Fabric zone '{0}' updated successfully in the Cisco Catalyst Center".format(
                site_name
            )
            self.log(success_msg, "DEBUG")
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.update_zone.append(site_name)

        except Exception as e:
            self.msg = "An exception occured while updating the fabric zone '{0}' in Cisco Catalyst Center: {1}".format(
                site_name, str(e)
            )
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def validate_auth_profile_parameters(self, auth_profile_dict, auth_profile):
        """
        Validates the parameters provided for updating the authentication profile template.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            auth_profile_dict (dict): A dictionary containing the parameters for the authentication profile.
        Returns:
            self (objetc): The instance of the class with updated status and result attributes if invalid parameters are found.
        Description:
            This method checks the validity of the provided parameters for the authentication profile template. It validates
            the "authentication_order" to ensure it is either "dot1x" or "mac". For "dot1x_fallback_timeout", it ensures the
            value is an integer within the range of 3 to 120. The "number_of_hosts" must be either "Single" or "Unlimited".
            If any invalid parameters are found, they are added to the `invalid_auth_profile_list`. Corresponding error messages
            are logged, and the status is set to "failed". The method also logs warnings for any exceptions encountered during
            the validation process.
        """

        invalid_auth_profile_list = []
        auth_order = auth_profile_dict.get("authentication_order")
        if auth_order and auth_order not in ["dot1x", "mac"]:
            invalid_auth_profile_list.append("authentication_order")
            msg = (
                "Invalid authentication_order '{0}'given in the playbook for the update of authentication profile template. "
                "Please provide one of the following authentication_order ['dot1x', 'mac'] in the playbook."
            ).format(auth_order)
            self.log(msg, "ERROR")

        fall_timeout = auth_profile_dict.get("dot1x_fallback_timeout")
        if fall_timeout:
            try:
                timeout = int(fall_timeout)
                if timeout not in range(3, 121):
                    invalid_auth_profile_list.append("dot1x_fallback_timeout")
                    msg = (
                        "Invalid 'dot1x_fallback_timeout' '{0}' given in the playbook. "
                        "Please provide a value in the range [3, 120]."
                    ).format(timeout)
                    self.log(msg, "ERROR")
            except Exception as e:
                invalid_auth_profile_list.append("dot1x_fallback_timeout")
                msg = (
                    "Invalid 'dot1x_fallback_timeout' string '{0}' given in the playbook, unable to convert it into the integer. "
                    "Please provide a value in the range [3, 120]."
                ).format(fall_timeout)
                self.log(msg, "WARNING")

        number_of_hosts = auth_profile_dict.get("number_of_hosts")
        if number_of_hosts and number_of_hosts.title() not in ["Single", "Unlimited"]:
            invalid_auth_profile_list.append("number_of_hosts")
            msg = (
                "Invalid number_of_hosts '{0}'given in the playbook for the update of authentication profile template. "
                "Please provide one of the following: ['Single', 'Unlimited']."
            ).format(auth_order)
            self.log(msg, "ERROR")

        if (
            self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0
            and auth_profile == "Low Impact"
        ):
            pre_auth_acl = auth_profile_dict.get("pre_auth_acl")
            if pre_auth_acl:
                enabled = pre_auth_acl.get("enabled")

                if enabled is None:
                    invalid_auth_profile_list.append("enabled")
                    self.log(
                        "Parameter 'enable' should be given either true/false for the Pre-Auth ACL.",
                        "ERROR",
                    )

                access_contracts_list = auth_profile_dict.get("access_contracts")
                if access_contracts_list:
                    if len(access_contracts_list) > 3:
                        invalid_auth_profile_list.append("access_contracts")
                        msg = (
                            "Access Control schema should be of length less than or equal to 3. And in the input "
                            "playbook schema it's given of length {0}."
                        ).format(len(access_contracts_list))
                        self.log(msg, "ERROR")

                    for access_contract in access_contracts_list:
                        action = access_contract.get("action")
                        protocol = access_contract.get("protocol")
                        port = access_contract.get("port")

                        if not action:
                            self.log(
                                "Given parameter 'action' is not provided in the input playbook",
                                "INFO",
                            )
                            invalid_auth_profile_list.append("action")

                        if not protocol:
                            self.log(
                                "Given parameter 'protocol' is not provided in the input playbook",
                                "INFO",
                            )
                            invalid_auth_profile_list.append("protocol")

                        if not port:
                            self.log(
                                "Given parameter 'port' is not provided in the input playbook",
                                "INFO",
                            )
                            invalid_auth_profile_list.append("port")

                        if action and action.upper() not in ["PERMIT", "DENY"]:
                            invalid_auth_profile_list.append("action")
                            msg = (
                                "Invalid action '{0}' given in the playbook for updating the authentication profile template. "
                                "Please provide one of the following action ['PERMIT', 'DENY'] in the playbook."
                            ).format(action)
                            self.log(msg, "ERROR")

                        if port and port not in ["domain", "bootpc", "bootps"]:
                            invalid_auth_profile_list.append("port")
                            msg = (
                                "Invalid port '{0}' given in the playbook for updating the authentication profile template. "
                                "Please provide one of the following port ['domain', 'bootpc', 'bootps'] in the playbook."
                            ).format(port)
                            self.log(msg, "ERROR")

                        if protocol and protocol.upper() not in [
                            "UDP",
                            "TCP",
                            "TCP_UDP",
                        ]:
                            invalid_auth_profile_list.append("protocol")
                            msg = (
                                "Invalid protocol '{0}' given in the playbook for updating the authentication profile template. "
                                "Please provide one of the following protocol ['UDP', 'TCP', 'TCP_UDP'] in the playbook."
                            ).format(protocol)
                            self.log(msg, "ERROR")

                        if (
                            port
                            and port == "domain"
                            and protocol
                            and protocol.upper() == "UDP"
                        ):
                            invalid_auth_profile_list.append("protocol")
                            msg = (
                                "Invalid protocol 'UDP' given in the playbook for updating the authentication profile template. "
                                "'TCP' and 'TCP_UDP' are only allowed when the contract port is 'domain'."
                            )
                            self.log(msg, "ERROR")

        if invalid_auth_profile_list:
            self.msg = (
                "Invalid parameters found: {0}. "
                "Unable to update the authentication profile template."
            ).format(invalid_auth_profile_list)
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def get_authentication_profile(self, fabric_id, auth_profile, site_name):
        """
        Retrieves the details of an authentication profile for a given fabric and site from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_id (str): The ID of the fabric to which the authentication profile belongs.
            auth_profile (str): The name of the authentication profile to retrieve.
            site_name (str): The name of the site associated with the authentication profile.
        Returns:
            dict or None: A dictionary containing the details of the authentication profile if found, or None if no profile is associated
                        with the site or if an error occurs.
        Description:
            This method sends a request to the Cisco Catalyst Center to fetch the authentication profile details based on the provided
            `fabric_id` and `auth_profile` name. The `site_name` is used for logging purposes to provide context in the logs.
            If the response contains authentication profile details, these details are returned. If no profile is found or if an error
            occurs during the request, the method logs an appropriate message and returns `None`.
        """

        try:
            profile_details = None
            response = self.dnac._exec(
                family="sda",
                function="get_authentication_profiles",
                op_modifies=True,
                params={
                    "fabric_id": fabric_id,
                    "authentication_profile_name": auth_profile,
                },
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_authentication_profiles' for the site '{0}': {1}".format(
                    site_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "No Authentication profile associated to this site '{0}' in Cisco Catalyst Center.".format(
                        site_name
                    ),
                    "INFO",
                )
                return profile_details

            profile_details = response[0]

        except Exception as e:
            self.msg = (
                "Error while getting the details of authentication profiles for the site '{0}' present in "
                "Cisco Catalyst Center: {1}"
            ).format(site_name, str(e))
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return profile_details

    def auth_profile_needs_update(self, auth_profile_dict, auth_profile_in_ccc):
        """
        Determines if the authentication profile requires an update by comparing it with the existing profile in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            auth_profile_dict (dict): A dictionary containing the desired authentication profile settings to compare.
            auth_profile_in_ccc (dict): A dictionary containing the current authentication profile settings from Cisco Catalyst Center.
        Returns:
            bool: Returns `True` if any of the settings in `auth_profile_dict` differ from those in `auth_profile_in_ccc` and an update
                is needed. Returns `False` if the settings match and no update is required.
        Description:
            This method compares the provided authentication profile settings (`auth_profile_dict`) with the current settings retrieved from
            the Cisco Catalyst Center (`auth_profile_in_ccc`). It considers the possibility of an additional setting "enable_bpu_guard" if
            the current profile is "Closed Authentication".
            It iterates through a mapping of profile settings and checks if any of the settings require an update. If any discrepancies are
            found, the method returns `True`. If all settings match, it returns `False`.
        """

        profile_key_mapping = {
            "authentication_order": "authenticationOrder",
            "dot1x_fallback_timeout": "dot1xToMabFallbackTimeout",
            "wake_on_lan": "wakeOnLan",
            "number_of_hosts": "numberOfHosts",
        }
        profile_name = auth_profile_in_ccc.get("authenticationProfileName")
        if profile_name == "Closed Authentication":
            profile_key_mapping["enable_bpu_guard"] = "isBpduGuardEnabled"

        for key, ccc_key in profile_key_mapping.items():
            desired_value = auth_profile_dict.get(key)

            if desired_value is None:
                continue

            current_value = auth_profile_in_ccc.get(ccc_key)

            if key == "dot1x_fallback_timeout":
                desired_value = int(desired_value)
                current_value = int(current_value)

            if desired_value != current_value:
                return True

        if (
            profile_name == "Low Impact"
            and self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0
        ):
            pre_auth_acl = auth_profile_dict.get("pre_auth_acl")
            acl_in_ccc = auth_profile_in_ccc.get("preAuthAcl")
            if pre_auth_acl:
                self.log("Pre-Auth ACL settings found in the input profile.", "INFO")
                if pre_auth_acl.get("enabled") and pre_auth_acl.get(
                    "enabled"
                ) != acl_in_ccc.get("enabled"):
                    self.log(
                        "Mismatch found in 'enabled' flag between input profile and CCC configuration.",
                        "INFO",
                    )
                    return True

                if pre_auth_acl.get("implicit_action") and pre_auth_acl.get(
                    "implicit_action"
                ) != acl_in_ccc.get("implicitAction"):
                    self.log(
                        "Mismatch found in 'implicit_action' between input profile and CCC configuration.",
                        "INFO",
                    )
                    return True

                if pre_auth_acl.get("description") and pre_auth_acl.get(
                    "description"
                ) != acl_in_ccc.get("description"):
                    self.log(
                        "Mismatch found in 'description' between input profile and CCC configuration.",
                        "INFO",
                    )
                    return True

                access_contracts = pre_auth_acl.get("access_contracts")
                access_contracts_in_ccc = acl_in_ccc.get("accessContracts")

                if access_contracts:
                    self.log(
                        "Access Contracts found in the input profile. Comparing with CCC configuration.",
                        "DEBUG",
                    )
                    input_access_contracts = {
                        frozenset(contracts.items()) for contracts in access_contracts
                    }
                    ccc_access_contracts = {
                        frozenset(contracts.items())
                        for contracts in access_contracts_in_ccc
                    }

                    if input_access_contracts != ccc_access_contracts:
                        self.log(
                            "Mismatch found in Access Contracts between input profile and CCC configuration.",
                            "INFO",
                        )
                        return True

        return False

    def collect_authentication_params(self, auth_profile_dict, auth_profile_in_ccc):
        """
        Collects and prepares the updated authentication profile parameters based on the provided dictionary and the current profile in
        Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            auth_profile_dict (dict): A dictionary containing the desired authentication profile settings.
            auth_profile_in_ccc (dict): A dictionary containing the current authentication profile settings from Cisco Catalyst Center.
        Returns:
            list: A list containing a single dictionary with the updated authentication profile parameters.
        Description:
            This method prepares the updated parameters for an authentication profile by combining desired settings from `auth_profile_dict` with
            the current settings from `auth_profile_in_ccc`.
            It creates a dictionary with the ID, fabric ID, profile name, and updated settings for authentication order, dot1x fallback timeout,
            number of hosts, and Wake-on-LAN. If the profile is "Closed Authentication," it also includes the BPDU guard setting.
            The method returns a list containing the updated parameters in a dictionary, which can be used for further processing or API requests.
        """

        updated_params = []
        profile_name = auth_profile_in_ccc.get("authenticationProfileName")
        authentications_params_dict = {
            "id": auth_profile_in_ccc.get("id"),
            "fabricId": auth_profile_in_ccc.get("fabricId"),
            "authenticationProfileName": profile_name,
            "authenticationOrder": auth_profile_dict.get("authentication_order")
            or auth_profile_in_ccc.get("authenticationOrder"),
            "dot1xToMabFallbackTimeout": int(
                auth_profile_dict.get("dot1x_fallback_timeout")
            )
            or auth_profile_in_ccc.get("dot1xToMabFallbackTimeout"),
            "numberOfHosts": auth_profile_dict.get("number_of_hosts")
            or auth_profile_in_ccc.get("numberOfHosts"),
        }

        if auth_profile_dict.get("wake_on_lan") is None:
            authentications_params_dict["wakeOnLan"] = auth_profile_in_ccc.get(
                "wakeOnLan"
            )
        else:
            authentications_params_dict["wakeOnLan"] = auth_profile_dict.get(
                "wake_on_lan"
            )

        if profile_name == "Closed Authentication":
            if auth_profile_dict.get("enable_bpu_guard") is None:
                authentications_params_dict["isBpduGuardEnabled"] = (
                    auth_profile_in_ccc.get("isBpduGuardEnabled", True)
                )
            else:
                authentications_params_dict["isBpduGuardEnabled"] = (
                    auth_profile_dict.get("enable_bpu_guard")
                )

        if (
            profile_name == "Low Impact"
            and self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0
        ):
            pre_auth_acl = auth_profile_dict.get("pre_auth_acl")
            acl_in_ccc = auth_profile_in_ccc.get("preAuthAcl")

            if pre_auth_acl:
                self.log(
                    "Low Impact profile detected. Pre-Auth ACL settings will be updated.",
                    "DEBUG",
                )
                authentications_params_dict["preAuthAcl"] = {}
                enabled_flag = pre_auth_acl.get("enabled")
                if enabled_flag is not None:
                    authentications_params_dict["preAuthAcl"]["enabled"] = enabled_flag
                    self.log(
                        "Pre-Auth ACL 'enabled' flag set to: {0}".format(enabled_flag),
                        "INFO",
                    )
                else:
                    enabled_flag_in_ccc = acl_in_ccc.get("enabled")
                    authentications_params_dict["preAuthAcl"][
                        "enabled"
                    ] = enabled_flag_in_ccc
                    self.log(
                        "Pre-Auth ACL 'enabled' flag not provided. Falling back to existing configuration: {0}".format(
                            enabled_flag_in_ccc
                        ),
                        "INFO",
                    )

                authentications_params_dict["preAuthAcl"]["implicitAction"] = (
                    pre_auth_acl.get("implicit_action")
                    or acl_in_ccc.get("implicitAction", "DENY")
                )
                self.log(
                    "Pre-Auth ACL 'implicitAction' set to: {0}".format(
                        authentications_params_dict["preAuthAcl"]["implicitAction"]
                    ),
                    "DEBUG",
                )
                authentications_params_dict["preAuthAcl"]["description"] = (
                    pre_auth_acl.get("description") or acl_in_ccc.get("description")
                )
                self.log(
                    "Pre-Auth ACL 'description' set to: {0}".format(
                        authentications_params_dict["preAuthAcl"]["description"]
                    ),
                    "DEBUG",
                )

                if pre_auth_acl.get("access_contracts") is not None:
                    self.log(
                        "Pre-Auth ACL 'accessContracts' set from input profile.",
                        "DEBUG",
                    )
                    authentications_params_dict["preAuthAcl"]["accessContracts"] = (
                        pre_auth_acl.get("access_contracts")
                    )
                else:
                    self.log(
                        "Pre-Auth ACL 'accessContracts' not provided. Falling back to existing configuration.",
                        "DEBUG",
                    )
                    authentications_params_dict["preAuthAcl"]["accessContracts"] = (
                        acl_in_ccc.get("accessContracts")
                    )

        updated_params.append(authentications_params_dict)
        self.log(
            "Payload for updating authentication profile collected successfully: {0}".format(
                updated_params
            ),
            "INFO",
        )

        return updated_params

    def update_authentication_profile_template(self, profile_update_params, site_name):
        """
        Updates the authentication profile template for a specified site in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            profile_update_params (dict): A dictionary containing the parameters to update the authentication profile.
            site_name (str): The name of the site where the authentication profile is being updated.
        Returns:
            self (object): Returns the current instance of the class with updated status and message attributes.
        Description:
            This method sends a request to update the authentication profile template for the specified site using the
            provided parameters. It first logs the requested payload and sends it to the API for processing.
            It then monitors the task status by polling until the update is complete. If the update is successful,
            it logs a success message and appends the site name to the list of updated profiles. If an error occurs or
            the task fails, it logs an error message and updates the status to "failed".
        """

        try:
            self.log(
                "Requested payload for updating authentication profile for site {0}: {1}".format(
                    site_name, profile_update_params
                ),
                "DEBUG",
            )
            payload = {"payload": profile_update_params}
            task_name = "update_authentication_profile"
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Authentication profile for the site '{0}' updated successfully in the Cisco Catalyst Center".format(
                site_name
            )
            self.log(success_msg, "DEBUG")
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            auth_profile_name = profile_update_params[0].get(
                "authenticationProfileName"
            )
            if auth_profile_name == "Low Impact":
                self.log(
                    "Site '{0}' uses 'Low Impact' authentication profile (with with pre-authentication access control list configuration).".format(
                        site_name
                    ),
                    "DEBUG",
                )
                site_name += (
                    " (with pre-authentication access control list configuration)"
                )

            self.update_auth_profile.append(site_name)
            self.log(
                "Site '{0}' added to the list of updated authentication profiles.".format(
                    site_name
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "An exception occured while updating the authentication profile for site '{0}' in Cisco Catalyst Center: {1}".format(
                site_name, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def delete_fabric_site_zone(self, fabric_id, site_name, fabric_type):
        """
        Deletes a fabric site or fabric zone from Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_id (str): The ID of the fabric site or fabric zone to be deleted.
            site_name (str): The name of the fabric site or fabric zone to be deleted.
            fabric_type (str): The type of the entity to be deleted. Should be either "fabric_site" or "fabric_zone".
        Returns:
            self (object): Returns the current instance of the class with updated status and message attributes.
        Description:
            This method sends a request to delete a fabric site or fabric zone based on the provided `fabric_id` and `fabric_type`.
            It determines the appropriate API function to call based on the `fabric_type`, either "delete_fabric_site_by_id" or
            "delete_fabric_zone_by_id". It returns the class instance for further processing or chaining.
        """

        try:
            if fabric_type == "fabric_site":
                task_name = "delete_fabric_site_by_id"
                type_name = "fabric site"
            else:
                task_name = "delete_fabric_zone_by_id"
                type_name = "fabric zone"

            payload = {"id": fabric_id}
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "{0} '{1}' deleted successfully from the Cisco Catalyst Center".format(
                    type_name.title(), site_name
                ),
                "INFO",
            )

            success_msg = (
                "{0} '{1}' deleted successfully from the Cisco Catalyst Center".format(
                    type_name.title(), site_name
                )
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

            if fabric_type == "fabric_site":
                self.delete_site.append(site_name)
            else:
                self.delete_zone.append(site_name)

        except Exception as e:
            self.msg = "Exception occurred while deleting {0} '{1}' due to: {2}".format(
                type_name, site_name, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def update_site_zones_profile_messages(self):
        """
        Updates and logs messages based on the status of fabric sites, fabric zones, and authentication profile templates.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): Returns the current instance of the class with updated `result` and `msg` attributes.
        Description:
            This method aggregates status messages related to the creation, update, or deletion of fabric sites, fabric zones,
            and authentication profile templates.
            It checks various instance variables (`create_site`, `update_site`, `no_update_site`, `create_zone`, `update_zone`,
            `no_update_zone`, `update_auth_profile`, `no_update_profile`, `delete_site`, `absent_site`, `delete_zone`, `absent_zone`)
            to determine the status and generates corresponding messages.
            The method also updates the `result["response"]` attribute with the concatenated status messages.
        """

        self.result["changed"] = False
        result_msg_list = []

        if self.create_site:
            create_site_msg = "Fabric site(s) '{0}' created successfully in Cisco Catalyst Center.".format(
                self.create_site
            )
            result_msg_list.append(create_site_msg)

        if self.update_site:
            update_site_msg = "Fabric site(s) '{0}' updated successfully in Cisco Catalyst Center.".format(
                self.update_site
            )
            result_msg_list.append(update_site_msg)

        if self.no_update_site:
            no_update_site_msg = (
                "Fabric site(s) '{0}' need no update in Cisco Catalyst Center.".format(
                    self.no_update_site
                )
            )
            result_msg_list.append(no_update_site_msg)

        if self.create_zone:
            create_zone_msg = "Fabric zone(s) '{0}' created successfully in Cisco Catalyst Center.".format(
                self.create_zone
            )
            result_msg_list.append(create_zone_msg)

        if self.update_zone:
            update_zone_msg = "Fabric zone(s) '{0}' updated successfully in Cisco Catalyst Center.".format(
                self.update_zone
            )
            result_msg_list.append(update_zone_msg)

        if self.no_update_zone:
            no_update_zone_msg = (
                "Fabric zone(s) '{0}' need no update in Cisco Catalyst Center.".format(
                    self.no_update_zone
                )
            )
            result_msg_list.append(no_update_zone_msg)

        if self.pending_fabric_event:
            pending_event_msg = "Following pending fabric event(s) '{0}' applied successfully in Cisco Catalyst Center.".format(
                self.pending_fabric_event
            )
            result_msg_list.append(pending_event_msg)

        if self.update_auth_profile:
            update_auth_msg = "Authentication profile template for site(s) '{0}' updated successfully in Catalyst Center.".format(
                self.update_auth_profile
            )
            result_msg_list.append(update_auth_msg)

        if self.no_update_profile:
            no_update_auth_msg = "Authentication profile template for site(s) '{0}' need no update in Cisco Catalyst Center.".format(
                self.no_update_profile
            )
            result_msg_list.append(no_update_auth_msg)

        if self.delete_site:
            delete_site_msg = "Fabric site(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                self.delete_site
            )
            result_msg_list.append(delete_site_msg)

        if self.absent_site:
            absent_site_msg = "Unable to delete fabric site(s) '{0}' as they are not present in Cisco Catalyst Center.".format(
                self.absent_site
            )
            result_msg_list.append(absent_site_msg)

        if self.delete_zone:
            delete_zone_msg = "Fabric zone(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                self.delete_zone
            )
            result_msg_list.append(delete_zone_msg)

        if self.absent_zone:
            absent_zone_msg = "Unable to delete fabric zone(s) '{0}' as they are not present in Cisco Catalyst Center.".format(
                self.absent_zone
            )
            result_msg_list.append(absent_zone_msg)

        if (
            self.create_site
            or self.update_site
            or self.create_zone
            or self.update_zone
            or self.delete_zone
            or self.delete_site
            or self.update_auth_profile
            or self.pending_fabric_event
        ):
            self.result["changed"] = True

        self.msg = " ".join(result_msg_list)
        self.log(self.msg, "INFO")
        self.set_operation_result("success", self.result["changed"], self.msg, "INFO")

        return self

    def is_wired_data_collection_enable(self, site_name, site_id):
        """
        Checks if wired data collection is enabled for a specified site.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site to check.
            site_id (str): The unique identifier of the site.
        Returns:
            bool: True if wired data collection is enabled for the site, False otherwise.
        Description:
            This function logs the status of wired data collection for a given site and checks if it is enabled.
            It retrieves telemetry settings for the specified site using the `retrieve_telemetry_settings_for_a_site`
            API function. If telemetry settings or wired data collection details are missing or disabled,
            function logs relevant messages and returns False. If wired data collection is enabled, it returns True.
        """

        self.log(
            "Checking whether wired data collection is enabled for the site: {0}".format(
                site_name
            ),
            "INFO",
        )

        try:
            telemetry_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_telemetry_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id},
            )
            telemetry_details = telemetry_response.get("response", {})
            if not telemetry_details:
                self.log(
                    "No telemetry settings found for site '{0}' (ID: {1})".format(
                        site_name, site_id
                    ),
                    "WARNING",
                )
                return False

            self.log(
                "Successfully retrieved telemetry settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, telemetry_details
                ),
                "DEBUG",
            )
            wired_data_collection = telemetry_details.get("wiredDataCollection")

            if not wired_data_collection:
                self.log(
                    "Wired Data Collection is not enabled at this site '{0}'.".format(
                        site_name
                    ),
                    "DEBUG",
                )
                return False

            is_enabled = wired_data_collection.get("enableWiredDataCollection")
            if not is_enabled:
                self.log(
                    "Wired Data Collection is not enabled at this site '{0}'.".format(
                        site_name
                    ),
                    "DEBUG",
                )
                return False
            self.log(
                "Wired Data Collection is enabled at this site '{0}'.".format(
                    site_name
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = "Exception occurred while getting telemetry settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "CRITICAL"
            ).check_return_status()

        return True

    def get_telemetry_details(self, site_name, site_id):
        """
        Retrieves telemetry settings for a specified site.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site for which telemetry settings are being retrieved.
            site_id (str): The unique identifier of the site.
        Returns:
            dict: A dictionary containing telemetry details for the site. If telemetry settings are not found
                or an exception occurs, it logs an error and returns an empty dictionary.
        Description:
            This function logs the process of checking and retrieving telemetry settings for a specified site.
            It sends a request to the `retrieve_telemetry_settings_for_a_site` API function using the provided
            site ID. If no telemetry settings are found, it logs an error message and sets the operation result
            to "failed."
        """

        self.log("Fetching telemetry settings for site: {0}".format(site_name), "INFO")
        try:
            telemetry_response = self.dnac._exec(
                family="network_settings",
                function="retrieve_telemetry_settings_for_a_site",
                op_modifies=False,
                params={"id": site_id},
            )
            telemetry_details = telemetry_response.get("response", {})
            if not telemetry_details:
                self.msg = (
                    "No telemetry settings found for site '{0}' (ID: {1})".format(
                        site_name, site_id
                    )
                )
                self.set_operation_result(
                    "failed", False, self.msg, "CRITICAL"
                ).check_return_status()

            self.log(
                "Successfully retrieved telemetry settings for site '{0}' (ID: {1}): {2}".format(
                    site_name, site_id, telemetry_details
                ),
                "DEBUG",
            )

        except Exception as e:
            self.msg = "Exception occurred while getting telemetry settings for site '{0}' (ID: {1}): {2}".format(
                site_name, site_id, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "CRITICAL"
            ).check_return_status()

        return telemetry_details

    def enable_wired_data_collection(self, site_name, site_id):
        """
        Enables wired data collection for a specified site.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site for which wired data collection should be enabled.
            site_id (str): The unique identifier of the site.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function enables wired data collection for a specified site in Cisco Catalyst Center. It first retrieves
            the current telemetry settings for the site using `get_telemetry_details`. If the `wiredDataCollection` field
            is missing, it initializes it as an empty dictionary. It then sets `enableWiredDataCollection` to `True`.
            The function creates a payload with the updated telemetry settings and initiates an API call to set
            telemetry settings for the site. It retrieves the task ID for the API call and checks the status of task.
            If any part of the process fails, it logs an error message and sets the operation result to "failed."
            If successful, it logs an informational message indicating that wired data collection was enabled.
        """

        self.log(
            "Started the process of enabling wired data collection for site {0}...".format(
                site_name
            ),
            "DEBUG",
        )

        try:
            telemetry_settings = self.get_telemetry_details(site_name, site_id)
            if telemetry_settings.get("wiredDataCollection") is None:
                telemetry_settings["wiredDataCollection"] = {}
            telemetry_settings["wiredDataCollection"][
                "enableWiredDataCollection"
            ] = True

            payload = {
                "id": site_id,
                "wiredDataCollection": telemetry_settings.get("wiredDataCollection"),
                "wirelessTelemetry": telemetry_settings.get("wirelessTelemetry"),
                "snmpTraps": telemetry_settings.get("snmpTraps"),
                "syslogs": telemetry_settings.get("syslogs"),
                "applicationVisibility": telemetry_settings.get(
                    "applicationVisibility"
                ),
            }
            task_name = "set_telemetry_settings_for_a_site"
            task_id = self.get_taskid_post_api_call(
                "network_settings", task_name, payload
            )

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = (
                "Successfully enabled wired data collection for site '{0}'.".format(
                    site_name
                )
            )
            self.log(success_msg, "INFO")
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        except Exception as e:
            self.msg = (
                "An exception occured while enabling the Wired Data Collection for the site '{0}' "
                "in Cisco Catalyst Center: {1}"
            ).format(site_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def get_all_pending_events_ids(self, site_name, fabric_id):
        """
        Fetches all pending fabric events for a specified site in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site for which pending fabric events need to be retrieved.
            fabric_id (str): The unique identifier of the fabric associated with the site.
        Returns:
            dict: A dictionary where keys are event details (names) and values are their corresponding event IDs.
        Description:
            This function iteratively retrieves all pending fabric events for a given site using the `get_pending_fabric_events`
            API in Cisco Catalyst Center. It uses pagination, incrementing the offset by 500 for each subsequent API call until no
            more events are found. Each event's name (`detail`) and ID (`id`) are extracted and stored in a dictionary.

            This method helps in monitoring or troubleshooting fabric events that haven't been addressed yet within the network.
        """

        self.log(
            "Fetching all the pending fabric events for site: {0}".format(site_name),
            "INFO",
        )
        pending_fabric_events = {}
        offset = 1
        while True:
            try:
                self.log("Fetching events with offset: {0}".format(offset), "INFO")
                response = self.dnac._exec(
                    family="sda",
                    function="get_pending_fabric_events",
                    op_modifies=True,
                    params={"fabric_id": fabric_id, "offset": offset},
                )
                response = response.get("response")
                if not response:
                    self.log(
                        "There is no more pending fabric event for the site: {0}".format(
                            site_name
                        ),
                        "INFO",
                    )
                    break

                self.log(
                    "Received API response from 'get_pending_fabric_events' for the site '{0}': {1}".format(
                        site_name, str(response)
                    ),
                    "DEBUG",
                )

                for event in response:
                    event_id = event.get("id")
                    event_name = event.get("detail")
                    pending_fabric_events[event_name] = event_id

                if len(response) < 500:
                    self.log(
                        "response from 'get_pending_fabric_events' for the site is less than 500 so coming out of the loop",
                        "DEBUG",
                    )
                    break

                offset += 500
            except Exception as e:
                self.msg = "Exception occurred while fetching the pending fabric events for site '{0}': {1}".format(
                    site_name, str(e)
                )
                self.set_operation_result(
                    "failed", False, self.msg, "CRITICAL"
                ).check_return_status()

        return pending_fabric_events

    def apply_pending_fabric_events(self, event_name, event_id, fabric_id, site_name):
        """
        Applies a pending fabric event to a specified site in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            event_name (str): The name of the fabric event to be applied.
            event_id (str): The unique identifier of the pending fabric event.
            fabric_id (str): The unique identifier of the fabric where the event should be applied.
            site_name (str): The name of the site associated with the fabric event.
        Returns:
            self (object): Returns the instance of the class to allow method chaining.
        Description:
            This function applies a pending fabric event to a specific site within Cisco DNA Center. It constructs a payload
            containing the `fabricId` and `eventId`, then initiates the API call to apply the event.
            The function logs the payload details and checks for the task ID to confirm the event application process
            initiation. If the task ID retrieval fails, it logs an error and marks the operation as failed. Upon successfully
            retrieving the task ID, the function monitors the task status to ensure the event is applied correctly.
            If any exception occurs during this process, it logs an error message and updates the operation result to "failed."
        """

        try:
            event_payload = {"fabricId": fabric_id, "id": event_id}
            self.log(
                "Requested payload for applying fabric event '{0}' is:  {1}".format(
                    event_name, event_payload
                ),
                "INFO",
            )
            task_name = "apply_pending_fabric_events"
            payload = {"payload": [event_payload]}
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Pending fabric event '{0}' applied successfully to the fabric site {1}".format(
                event_name, site_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = "An exception occured while applying the pending fabric event '{0}' for site {1}: {2}".format(
                event_name, site_name, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def make_hashable(self, obj):
        """
        Recursively converts a dictionary (or nested data structure) into a hashable format.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            obj (dict | list | any): The dictionary, list, or other data structure to be converted
                                        into a hashable form. Nested dictionaries and lists are also supported.
        Returns:
            frozenset | tuple | any:
                - If `obj` is a dictionary, it returns a `frozenset` of key-value pairs where values are recursively processed.
                - If `obj` is a list, it returns a `tuple` of elements processed recursively.
                - If `obj` is neither a dictionary nor a list, it returns the object as is.
        Description:
            This function allows dictionaries, lists, and other nested data structures to be converted
            into hashable types, enabling them to be used as keys in other dictionaries or stored in sets.
            Dictionaries are converted into `frozensets` of key-value pairs, and lists are converted into
            `tuples`. Non-iterable values are returned without modification. This is useful when needing
            to cache or compare complex data structures.
        """

        if isinstance(obj, dict):
            return frozenset((k, self.make_hashable(v)) for k, v in obj.items())
        elif isinstance(obj, list):
            return tuple(self.make_hashable(v) for v in obj)

        self.log("The object '{0}' converted into hashable format.".format(obj), "INFO")

        return obj

    def reconfigure_the_fabric_site(self, site_name, fabric_id):
        """
        Reconfigures the fabric site by applying any pending fabric events for the given site in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site for which to reconfigure the fabric.
            fabric_id (str): The unique identifier of the fabric associated with the site.

        Returns:
            self (object): Returns the current instance of the class (self), updated with the result of the operation.

        Description:
            This method checks if the Cisco Catalyst Center (CCC) version supports pending fabric event reconfiguration
            (only versions >= 2.3.7.9). If supported, it retrieves and applies all pending fabric events for the specified site
            and fabric ID. It logs each step of the process and handles exceptions gracefully.
        """

        try:
            current_version = self.get_ccc_version()
            if not self.compare_dnac_versions(current_version, "2.3.7.9") >= 0:
                self.log(
                    "Reconfiguring fabric pending events is supported only from Cisco Catalyst Center version 2.3.7.9 onwards."
                    " Current version: {0}".format(current_version),
                    "WARNING",
                )
                return self

            self.log(
                "Checking for pending fabric events on site '{0}' with fabric ID '{1} in Catalyst Center.".format(
                    site_name, fabric_id
                ),
                "DEBUG",
            )
            pending_events_map = self.get_all_pending_events_ids(site_name, fabric_id)
            if not pending_events_map:
                self.log(
                    "No pending fabric events found for site '{0}'.".format(site_name),
                    "INFO",
                )
                return self

            for event_detail, event_id in pending_events_map.items():
                self.log(
                    "Applying pending fabric event '{0}' (event ID: {1}) for site '{2}'.".format(
                        event_detail, event_id, site_name
                    ),
                    "DEBUG",
                )
                self.apply_pending_fabric_events(
                    event_detail, event_id, fabric_id, site_name
                ).check_return_status()
                self.pending_fabric_event.append(
                    event_detail + " for site " + site_name
                )
                self.log(
                    "Successfully applied fabric event '{0}' for site '{1}'.".format(
                        event_detail, site_name
                    ),
                    "INFO",
                )

        except Exception as e:
            self.msg = "An exception occurred while applying the reconfiguring the fabric site {0}: {1}".format(
                site_name, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def get_diff_merged(self, config):
        """
        Creates, updates, or deletes fabric sites and zones based on the provided configuration, and manages
        authentication profile updates.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the configuration for fabric sites and zones and updating
                    authentication profile template.
        Returns:
            self (object): Returns the current instance of the class with updated attributes based on the operations performed.
        Description:
            This method processes the provided configuration to manage fabric sites and zones in Cisco Catalyst Center.
            1. Fabric Sites
                - If 'fabric_sites' is present in the configuration, it iterates over the list of sites.
                - Checks if the site needs to be created or updated based on its type ("fabric_site" or "fabric_zone").
                - Creates or updates the site as necessary. If the site does not need any updates, it logs this information.
            2. Authentication Profile
                - If an `update_authentication_profile` parameter is provided, it validates and updates the authentication
                    profile template associated with the site.
                - Ensures that the authentication profile is valid and performs updates if needed.
                - If no update is necessary or if the profile is not present, it logs the appropriate messages.
        """

        # Create/Update Fabric sites/zones in Cisco Catalyst Center
        raw_fabric_sites = self.want.get("fabric_sites")
        self.log("Preserve the order of input while deduplicating", "DEBUG")
        self.log("Starting deduplication of raw_fabric_sites.", "DEBUG")
        unique_fabric_site_set = set()
        fabric_sites = []
        for fabric_site_dict in raw_fabric_sites:
            # Convert dictionary to a frozenset - immutable set
            site_zone = frozenset(self.make_hashable(fabric_site_dict))
            if site_zone not in unique_fabric_site_set:
                self.log("New unique site found: '{0}'".format(site_zone), "DEBUG")
                unique_fabric_site_set.add(site_zone)
                fabric_sites.append(fabric_site_dict)

        self.log(
            "Deduplication complete. Total unique sites: {0}".format(len(fabric_sites)),
            "DEBUG",
        )

        for site in fabric_sites:
            site_name = site.get("site_name_hierarchy")
            fabric_type = site.get("fabric_type", "fabric_site")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    f"The site '{site_name}' does not exist in the Catalyst Center. "
                    "A site must be created first before it can be converted into a Fabric Site."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            auth_profile = site.get("authentication_profile")

            if auth_profile and auth_profile not in [
                "Closed Authentication",
                "Low Impact",
                "No Authentication",
                "Open Authentication",
            ]:
                self.msg = (
                    "Invalid authentication_profile '{0}'given in the playbook for the creation of fabric site. "
                    "Please provide one of the following authentication_profile ['Closed Authentication', 'Low Impact'"
                    ", 'No Authentication', 'Open Authentication'] in the playbook."
                ).format(auth_profile)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            self.log(
                "Checking whether Wired Endpoint Data Collection is enabled at this site '{0}'or not".format(
                    site_name
                ),
                "INFO",
            )
            is_wired_data_enable = self.is_wired_data_collection_enable(
                site_name, site_id
            )

            if not is_wired_data_enable:
                self.log(
                    "Wired Data Collection is not enabled at this site '{0}'.".format(
                        site_name
                    ),
                    "INFO",
                )
                self.enable_wired_data_collection(
                    site_name, site_id
                ).check_return_status()
                self.log(
                    "Wired Data Collection has been successfully enabled for site '{0}'.".format(
                        site_name
                    ),
                    "INFO",
                )
            else:
                self.log(
                    "Wired Data Collection is already enabled at this site '{0}'.".format(
                        site_name
                    ),
                    "INFO",
                )

            if fabric_type == "fabric_site":
                self.log(
                    "Checking whether the given site {0} is already fabric site or not.".format(
                        site_name
                    ),
                    "DEBUG",
                )

                if site_id not in self.have.get("fabric_sites_ids"):
                    self.log(
                        "Starting the process of making site {0} as fabric site...".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    self.create_fabric_site(site).check_return_status()
                else:
                    self.log(
                        "Checking whether the given fabric site '{0}' needs to be reconfigured.".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    pending_events = site.get("apply_pending_events")
                    site_in_ccc = self.get_fabric_site_detail(site_name, site_id)
                    if pending_events:
                        self.log(
                            "Pending events detected for fabric site '{0}'".format(
                                site_name
                            ),
                            "DEBUG",
                        )
                        fabric_id = site_in_ccc.get("id")
                        self.log(
                            "Reconfiguring fabric site '{0}' with fabric ID '{1}'.".format(
                                site_name, fabric_id
                            ),
                            "DEBUG",
                        )
                        self.reconfigure_the_fabric_site(
                            site_name, fabric_id
                        ).check_return_status()

                    self.log(
                        "Checking whether the given fabric site '{0}' needs to be updated.".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    require_update = self.fabric_site_needs_update(site, site_in_ccc)
                    if require_update:
                        self.update_fabric_site(site, site_in_ccc).check_return_status()
                    else:
                        self.no_update_site.append(site_name)
                        self.log(
                            "Fabric site '{0}' already present and does not need any update in the Cisco Catalyst Center.".format(
                                site_name
                            ),
                            "INFO",
                        )
            else:
                self.log(
                    "Checking whether the given site {0} is already fabric zone or not.".format(
                        site_name
                    ),
                    "DEBUG",
                )

                if site_id not in self.have.get("fabric_zone_ids"):
                    self.log(
                        "Starting the process of making site {0} as fabric zone...".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    self.create_fabric_zone(site).check_return_status()
                else:
                    self.log(
                        "Checking whether the given fabric zone {0} needs to be reconfigured or not.".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    pending_events = site.get("apply_pending_events")
                    zone_in_ccc = self.get_fabric_zone_detail(site_name, site_id)
                    if pending_events:
                        self.log(
                            "Pending events detected for fabric zone '{0}'. Retrieving zone details.".format(
                                site_name
                            ),
                            "DEBUG",
                        )
                        fabric_id = zone_in_ccc.get("id")
                        self.log(
                            "Reconfiguring fabric zone '{0}' with fabric ID '{1}'.".format(
                                site_name, fabric_id
                            ),
                            "DEBUG",
                        )
                        self.reconfigure_the_fabric_site(
                            site_name, fabric_id
                        ).check_return_status()

                    self.log(
                        "Checking whether the given fabric zone '{0}' needs an update.".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    if auth_profile and auth_profile != zone_in_ccc.get(
                        "authenticationProfileName"
                    ):
                        self.log(
                            "Authentication profile '{0}' does not match the profile '{1}' in Cisco Catalyst Center "
                            "for the fabric zone '{2}'.".format(
                                auth_profile,
                                zone_in_ccc.get("authenticationProfileName"),
                                site_name,
                            ),
                            "INFO",
                        )
                        self.update_fabric_zone(site, zone_in_ccc).check_return_status()
                    else:
                        self.no_update_zone.append(site_name)
                        self.log(
                            "Fabric zone '{0}' already present and does not need any update in the Cisco Catalyst Center.".format(
                                site_name
                            ),
                            "INFO",
                        )

            # Updating/customising the default parameters for authentication profile template
            if site.get("update_authentication_profile"):
                if not auth_profile:
                    self.msg = (
                        "Required parameter 'authentication_profile' is missing needed for updating the authentication profile template. "
                        "Please provide one of the following authentication_profile ['Closed Authentication', 'Low Impact'"
                        ", 'Open Authentication'] in the playbook."
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if auth_profile == "No Authentication":
                    self.msg = (
                        "Unable to update 'authentication_profile' for the site '{0}' as for the profile template 'No Authentication' updating "
                        "authentication_profile is not supported. Please provide one of the following authentication_profile ['Closed Authentication'"
                        ", 'Low Impact', 'Open Authentication'] in the playbook."
                    ).format(site_name)
                    self.no_update_profile.append(site_name)
                    self.set_operation_result("success", False, self.msg, "INFO")
                    return self

                # With the given site id collect the fabric site/zone id
                if fabric_type == "fabric_site":
                    site_detail = self.get_fabric_site_detail(site_name, site_id)
                    fabric_id = site_detail.get("id")
                else:
                    zone_detail = self.get_fabric_zone_detail(site_name, site_id)
                    fabric_id = zone_detail.get("id")

                # Validate the playbook input parameter for updating the authentication profile
                auth_profile_dict = site.get("update_authentication_profile")
                self.validate_auth_profile_parameters(
                    auth_profile_dict, auth_profile
                ).check_return_status()
                validate_msg = (
                    "All the given parameter(s) '{0}' in the playbook for updating the authentication"
                    " profile in SDA fabric site/zone are validated successfully."
                ).format(auth_profile_dict)
                self.log(validate_msg, "INFO")
                auth_profile_in_ccc = self.get_authentication_profile(
                    fabric_id, auth_profile, site_name
                )

                if not auth_profile_in_ccc:
                    self.msg = (
                        "There is no authentication template profile associated to the site '{0}' "
                        "in the Cisco Catalyst Center so unable to update the profile parameters."
                    ).format(site_name)
                    self.set_operation_result("success", False, self.msg, "INFO")
                    self.no_update_profile.append(site_name)
                    return self

                profile_needs_update = self.auth_profile_needs_update(
                    auth_profile_dict, auth_profile_in_ccc
                )
                if not profile_needs_update:
                    self.msg = (
                        "Authentication profile for the site '{0}' does not need any update in the "
                        "Cisco Catalyst Center."
                    ).format(site_name)
                    self.set_operation_result("success", False, self.msg, "INFO")
                    self.no_update_profile.append(site_name)
                    return self

                # Collect the authentication profile parameters for the update operation
                profile_update_params = self.collect_authentication_params(
                    auth_profile_dict, auth_profile_in_ccc
                )
                self.update_authentication_profile_template(
                    profile_update_params, site_name
                ).check_return_status()

        return self

    def get_diff_deleted(self, config):
        """
        Deletes fabric sites and zones from the Cisco Catalyst Center based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the configuration for fabric sites and zones. It may include:
                - 'fabric_sites' - List of dictionaries, where each dictionary represents a fabric site or zone.
                    - 'site_name' - The name of the site or zone to be deleted.
                    - 'fabric_type'- Type of the site or zone, either "fabric_site" or "fabric_zone". Defaults to "fabric_site".
        Returns:
            self (object): Returns the current instance of the class with updated attributes based on the deletion operations performed.
        Description:
            This method processes the provided configuration to manage the deletion of fabric sites and zones in Cisco Catalyst Center.
            - For Fabric Sites
                - Verifies if the site exists in Cisco Catalyst Center.
                - Deletes the site if it exists; otherwise, logs a message indicating the site is not present.
            - For Fabric Zones
                - Verifies if the zone exists in Cisco Catalyst Center.
                - Deletes the zone if it exists; otherwise, logs a message indicating the zone is not present.
        """

        # Delete Fabric sites/zones from the Cisco Catalyst Center
        if not config.get("fabric_sites"):
            self.msg = "Unable to delete any fabric site/zone or authentication profile template as input is not given in the playbook."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        raw_fabric_sites = self.want.get("fabric_sites")
        # Preserve the order of input while deduplicating
        self.log("Starting deduplication of raw_fabric_sites.", "DEBUG")
        unique_fabric_site_set = set()
        fabric_sites = []
        for fabric_site_dict in raw_fabric_sites:
            # Convert dictionary to a frozenset - immutable set
            site_zone = frozenset(self.make_hashable(fabric_site_dict))
            if site_zone not in unique_fabric_site_set:
                self.log("New unique site found: '{0}'".format(site_zone), "DEBUG")
                unique_fabric_site_set.add(site_zone)
                fabric_sites.append(fabric_site_dict)

        self.log(
            "Deduplication complete. Total unique sites: {0}".format(len(fabric_sites)),
            "DEBUG",
        )
        fabric_site_dict = {}

        for site in fabric_sites:
            site_name = site.get("site_name_hierarchy")
            fabric_type = site.get("fabric_type", "fabric_site")

            if not site_name:
                self.msg = "Unable to delete fabric site/zone as required parameter 'site_name_hierarchy' is not given in the playbook."
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    f"The site '{site_name}' does not exist in the Catalyst Center. "
                    "A site must be created first before it can be converted into a Fabric Site."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            self.log(
                "Getting the site id: {0} for the site {1}".format(site_id, site_name),
                "INFO",
            )

            if fabric_type == "fabric_site":
                # Check whether fabric site is present in Cisco Catalyst Center.
                if site_id in self.have.get("fabric_sites_ids"):
                    site_detail = self.get_fabric_site_detail(site_name, site_id)
                    fabric_id = site_detail.get("id")
                    fabric_site_dict[site_name] = fabric_id
                    continue
                else:
                    self.absent_site.append(site_name)
                    self.log(
                        "Unable to delete fabric site '{0}' as it is not present in the Cisco Catalyst Center.".format(
                            site_name
                        ),
                        "INFO",
                    )
            else:
                # Check whether fabric zone is present in Cisco Catalyst Center.
                if site_id in self.have.get("fabric_zone_ids"):
                    site_detail = self.get_fabric_zone_detail(site_name, site_id)
                    fabric_id = site_detail.get("id")
                    # Delete the fabric zone from the Cisco Catalyst Center
                    self.delete_fabric_site_zone(
                        fabric_id, site_name, fabric_type
                    ).check_return_status()
                else:
                    self.absent_zone.append(site_name)
                    self.log(
                        "Unable to delete fabric zone '{0}' as it is not present in the Cisco Catalyst Center.".format(
                            site_name
                        ),
                        "INFO",
                    )

        for site_name, fabric_id in fabric_site_dict.items():
            self.log("Deleting the fabric site {0}...".format(site_name), "INFO")
            self.delete_fabric_site_zone(
                fabric_id, site_name, "fabric_site"
            ).check_return_status()

        return self

    def verify_diff_merged(self, config):
        """
        Verify the addition/update status of fabric site/zones in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration details to be verified.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies whether the specified configurations have been successfully added/updated
            in Cisco Catalyst Center as desired.
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        if config.get("fabric_sites"):
            raw_fabric_sites = self.want.get("fabric_sites")
            unique_fabric_sites = {self.make_hashable(d) for d in raw_fabric_sites}
            fabric_sites = [dict(t) for t in unique_fabric_sites]
            verify_site_list, verify_auth_list = [], []
            site_name_list, auth_name_list = [], []
            auth_flag = False

            for site in fabric_sites:
                site_name = site.get("site_name_hierarchy")
                fabric_type = site.get("fabric_type", "fabric_site")
                site_exists, site_id = self.get_site_id(site_name)
                if not site_exists:
                    self.msg = (
                        f"The site '{site_name}' does not exist in the Catalyst Center. "
                        "A site must be created first before it can be converted into a Fabric Site."
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if fabric_type == "fabric_site":
                    if site_id not in self.have.get("fabric_sites_ids"):
                        verify_site_list.append(site_name)
                    else:
                        site_name_list.append(site_name)
                else:
                    if site_id not in self.have.get("fabric_zone_ids"):
                        verify_site_list.append(site_name)
                    else:
                        site_name_list.append(site_name)

                #  Verifying updating/customising the default parameters for authentication profile template
                if site.get("update_authentication_profile"):
                    auth_flag = True
                    self.log(
                        "Fetching the fabric site/zone id with the given site id...",
                        "DEBUG",
                    )
                    if fabric_type == "fabric_site":
                        site_detail = self.get_fabric_site_detail(site_name, site_id)
                        fabric_id = site_detail.get("id")
                        auth_name_list.append(site_name)
                    else:
                        zone_detail = self.get_fabric_zone_detail(site_name, site_id)
                        fabric_id = zone_detail.get("id")
                        auth_name_list.append(site_name)

                    if not fabric_id:
                        verify_auth_list.append(site_name)

            if not verify_site_list:
                msg = (
                    "Requested fabric site(s)/zone(s) '{0}' have been successfully added/updated to the Cisco Catalyst Center "
                    "and their addition/update has been verified."
                ).format(site_name_list)
            else:
                msg = (
                    "Playbook's input does not match with Cisco Catalyst Center, indicating that the fabric site(s) '{0}' "
                    " addition/update task may not have executed successfully."
                ).format(verify_site_list)

            self.log(msg, "INFO")
            if not auth_flag:
                return self

            if not verify_auth_list:
                msg = (
                    "Authentication template profile for the site(s) '{0}' have been successfully updated to the Cisco Catalyst Center "
                    "and their update has been verified."
                ).format(auth_name_list)
            else:
                msg = (
                    "Playbook's input does not match with Cisco Catalyst Center, indicating that the Authentication template "
                    "profile for the site(s) '{0}' update task may not have executed successfully."
                ).format(verify_auth_list)

            self.log(msg, "INFO")

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of fabric sites/zones from the Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration details to be verified.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified fabric site/zone deleted from Cisco Catalyst Center.
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        fabric_sites = self.want.get("fabric_sites")
        verify_site_list, site_name_list = [], []

        for site in fabric_sites:
            site_name = site.get("site_name_hierarchy")
            fabric_type = site.get("fabric_type", "fabric_site")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    f"The site '{site_name}' does not exist in the Catalyst Center. "
                    "A site must be created first before it can be converted into a Fabric Site."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            if fabric_type == "fabric_site":
                # Check whether fabric site is present in Cisco Catalyst Center.
                if site_id in self.have.get("fabric_sites_ids"):
                    verify_site_list.append(site_name)
                else:
                    site_name_list.append(site_name)
            else:
                # Check whether fabric zone is present in Cisco Catalyst Center.
                if site_id in self.have.get("fabric_zone_ids"):
                    verify_site_list.append(site_name)
                else:
                    site_name_list.append(site_name)

        if not verify_site_list:
            msg = (
                "Requested fabric site(s)/zones(s) '{0}' have been successfully deleted from the Cisco Catalyst "
                "Center and their deletion has been verified."
            ).format(site_name_list)
        else:
            msg = (
                "Playbook's input does not match with Cisco Catalyst Center, indicating that fabric site(s)/zones(s)"
                " '{0}' deletion task may not have executed successfully."
            ).format(verify_site_list)
        self.log(msg, "INFO")

        return self


def main():
    """main entry point for module execution"""

    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": True},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_log": {"type": "bool", "default": False},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    ccc_fabric_sites = FabricSitesZones(module)
    if (
        ccc_fabric_sites.compare_dnac_versions(
            ccc_fabric_sites.get_ccc_version(), "2.3.7.6"
        )
        < 0
    ):
        ccc_fabric_sites.msg = (
            "The specified version '{0}' does not support the SDA fabric devices feature. Supported versions start "
            "  from '2.3.7.6' onwards. Version '2.3.7.6' introduces APIs for creating, updating and deleting the "
            "Fabric Sites/Zones and updating the Authentication profiles.".format(
                ccc_fabric_sites.get_ccc_version()
            )
        )
        ccc_fabric_sites.set_operation_result(
            "failed", False, ccc_fabric_sites.msg, "ERROR"
        ).check_return_status()

    state = ccc_fabric_sites.params.get("state")

    if state not in ccc_fabric_sites.supported_states:
        ccc_fabric_sites.status = "invalid"
        ccc_fabric_sites.msg = "State {0} is invalid".format(state)
        ccc_fabric_sites.check_return_status()

    ccc_fabric_sites.validate_input().check_return_status()
    config_verify = ccc_fabric_sites.params.get("config_verify")

    for config in ccc_fabric_sites.validated_config:
        ccc_fabric_sites.reset_values()
        ccc_fabric_sites.get_want(config).check_return_status()
        ccc_fabric_sites.get_have(config).check_return_status()
        ccc_fabric_sites.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_fabric_sites.verify_diff_state_apply[state](
                config
            ).check_return_status()

    # Invoke the API to check the status and log the output of each site/zone and authentication profile update on console.
    ccc_fabric_sites.update_site_zones_profile_messages().check_return_status()

    module.exit_json(**ccc_fabric_sites.result)


if __name__ == "__main__":
    main()
