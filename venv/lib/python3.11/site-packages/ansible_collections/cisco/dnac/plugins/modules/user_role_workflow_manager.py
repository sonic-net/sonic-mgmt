# !/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Ajith Andrew J, Syed khadeer Ahmed, Rangaprabhu Deenadayalu, Madhan Sankaranarayanan"
DOCUMENTATION = r"""
---
module: user_role_workflow_manager
short_description: Resource module for managing users
  and roles in Cisco Catalyst Center.
description:
  - Manages operations to create, update, and delete
    users and roles in Cisco Catalyst Center.
  - Provides APIs to create, update, and delete users
    and roles.
version_added: "6.17.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Ajith Andrew J (@ajithandrewj)
  - Syed Khadeer Ahmed (@syed-khadeerahmed)
  - Rangaprabhu Deenadayalu (@rangaprabha-d)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center
      after module completion.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description: A dictionary containing the configuration
      details for users or roles.
    type: dict
    required: true
    suboptions:
      user_details:
        description: Manages the configuration details
          for user accounts.
        type: list
        elements: dict
        suboptions:
          username:
            description:
              - The 'username' associated with the user
                account.
              - Required for user create, update and
                delete operations.
            type: str
          first_name:
            description: The first name of the user.
            type: str
          last_name:
            description: The last name of the user.
            type: str
          email:
            description:
              - The email address of the user (e.g.,
                syedkhadeerahmed@example.com).
              - Used to retrieve user data if the 'username'
                is forgotten.
              - Required for user deletion if the 'username'
                is forgotten.
            type: str
          password:
            description:
              - The password for the user account, which
                must adhere to specified complexity
                requirements.
              - Must contain at least one special character,
                one capital letter, one lowercase letter,
                and a minimum length of 8 characters.
              - Required for creating a new user account.
            type: str
          password_update:
            description:
              - Indicates whether the password should
                be updated.
              - Set to `true` to trigger a password
                update.
              - Required if a password change is necessary;
                must be explicitly set to `true` to
                initiate the update process.
              - If no update is needed, omit this parameter
                or set it to `false`.
              - Ensure this parameter is correctly set
                to avoid unnecessary updates or errors.
            type: str
          role_list:
            description:
              - A list of role names to be assigned
                to the user. If no role is specified,
                the default role will be "OBSERVER-ROLE".
              - The role names must match with those
                defined in the Cisco Catalyst Center.
              - The default roles present in the Cisco
                Catalyst Center are "SUPER-ADMIN-ROLE",
                "NETWORK-ADMIN-ROLE", "OBSERVER-ROLE".
              - SUPER-ADMIN-ROLE grants Full access,
                including user management.
              - NETWORK-ADMIN-ROLE grants Full network
                access, no system functions.
              - OBSERVER-ROLE grants view-only access,
                no configuration or control functions.
            type: list
            elements: str
      role_details:
        description: Manages the configuration details
          for roles.
        type: list
        elements: dict
        suboptions:
          role_name:
            description: The name of the role to be
              managed.
            type: str
          description:
            description: A brief description of the
              role's purpose and scope.
            type: str
          assurance:
            description: Ensure consistent service levels
              with complete visibility across all aspects
              of the network.
            choices: ["deny", "read", "write"]
            default: "read"
            suboptions:
              overall:
                description: Set the same access level
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                default: "read"
              monitoring_and_troubleshooting:
                description:
                  - Monitor and manage network health,
                    troubleshoot issues, and perform
                    remediation.
                  - Includes proactive network monitoring
                    and AI-driven insights.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              monitoring_settings:
                description:
                  - Configure and manage health thresholds
                    for the network, clients, and applications.
                  - Requires at least 'read' permission
                    for Monitoring and Troubleshooting.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              troubleshooting_tools:
                description:
                  - Create and manage sensor tests.
                  - Schedule on-demand forensic packet
                    captures (Intelligent Capture) for
                    troubleshooting clients.
                  - Requires at least 'read' permission
                    for Monitoring and Troubleshooting.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
          network_analytics:
            description: Manage components related to
              network analytics.
            suboptions:
              overall:
                description: Set the same access level
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                default: "read"
              data_access:
                description:
                  - Enable access to query engine APIs.
                  - Manage functions such as global
                    search, rogue management, and aWIPS.
                  - Setting this to 'deny' affects Search
                    and Assurance functionality.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
          network_design:
            description: Set up the network hierarchy,
              update the software image repository,
              and configure network profiles and settings
              for managing sites and network devices.
            suboptions:
              overall:
                description: Set the same access level
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                default: "read"
              advanced_network_settings:
                description:
                  - Update network settings, including
                    global device credentials, authentication
                    and policy servers, certificates,
                    trustpool, cloud access keys, stealthwatch,
                    umbrella, and data anonymization.
                  - Export the device inventory and
                    its credentials.
                  - Requires at least 'read' permission
                    on Network Settings.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              image_repository:
                description: Manage software images
                  and facilitate upgrades and updates
                  on physical and virtual network entities
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              network_hierarchy:
                description: Define and create a network
                  hierarchy of sites, buildings, floors,
                  and areas based on geographic location.
              network_profiles:
                description:
                  - Create network profiles for routing,
                    switching, and wireless. Assign
                    profiles to sites.
                  - Includes roles such as template
                    editor, tagging, model config editor,
                    and authentication template.
                  - To create SSIDs, 'write' permission
                    on network settings is required.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              network_settings:
                description:
                  - Manage common site-wide network
                    settings such as AAA, NTP, DHCP,
                    DNS, Syslog, SNMP, and Telemetry.
                  - Users in this role can add an SFTP
                    server and adjust the Network Resync
                    Interval found under Systems > Settings.
                  - To create wireless profiles, 'write'
                    permission on Network Profiles is
                    required.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              virtual_network:
                description: Manage virtual networks
                  (VNs). Segment physical networks into
                  multiple logical networks for traffic
                  isolation and controlled inter-VN
                  communication.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
          network_provision:
            description: Configure, upgrade, provision,
              and manage network devices.
            suboptions:
              overall:
                description: Provides the same choice
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              compliance:
                description: Manage compliance provisioning.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              exo:
                description: Scan the network for End
                  of Life, End of Sales, or End of Support
                  information for hardware and software.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              image_update:
                description: Upgrade software images
                  on devices that do not match the Golden
                  Image settings after a complete upgrade
                  lifecycle.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              inventory_management:
                description:
                  - Discover, add, replace, or delete
                    devices while managing device attributes
                    and configuration properties.
                  - To replace a device, 'write' permission
                    is required for pnp under network
                    provision.
                type: list
                elements: dict
                suboptions:
                  overall:
                    description: Provides the same choice
                      for all sub-parameters.
                    choices: ["deny", "read", "write"]
                    default: "read"
                    type: str
                  device_configuration:
                    description: Display the running
                      configuration of a device.
                    choices: ["deny", "read", "write"]
                    default: "read"
                    type: str
                  discovery:
                    description: Discover new devices
                      on the network.
                    choices: ["deny", "read", "write"]
                    default: "read"
                    type: str
                  network_device:
                    description: Add devices from inventory,
                      view device details, and perform
                      device-level actions.
                    choices: ["deny", "read", "write"]
                    default: "read"
                    type: str
                  port_management:
                    description: Allow port actions
                      on a device.
                    choices: ["deny", "read", "write"]
                    default: "read"
                    type: str
                  topology:
                    description:
                      - Display the network device and
                        link connectivity.
                      - Manage device roles, tag devices,
                        customize the display, and save
                        custom topology layouts.
                      - To view the SD-Access Fabric
                        window, at least 'read' permission
                        on "Network Provision > Inventory
                        Management > Topology" is required.
                    choices: ["deny", "read", "write"]
                    default: "read"
                    type: str
              license:
                description:
                  - Unified view of software and network
                    assets related to license usage
                    and compliance.
                  - Also controls permissions for cisco.com
                    and Smart accounts.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              network_telemetry:
                description:
                  - Enable or disable the collection
                    of application telemetry from devices.
                  - Configure telemetry settings for
                    the assigned site.
                  - Configure additional settings such
                    as wireless service assurance and
                    controller certificates.
                  - To enable or disable network telemetry,
                    'write' permission on Provision
                    is required.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              pnp:
                description: Automatically onboard new
                  devices, assign them to sites, and
                  configure them with site-specific
                  settings.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              provision:
                description:
                  - Provision devices with site-specific
                    settings and network policies.
                  - Includes roles such as Fabric, Application
                    Policy, Application Visibility,
                    Cloud, Site-to-Site VPN, Network/Application
                    Telemetry, Stealthwatch, Sync Start
                    vs Run Configuration, and Umbrella
                    provisioning.
                  - On the main dashboards for rogue
                    and aWIPS, certain actions, including
                    rogue containment, can be enabled
                    or disabled.
                  - To provision devices, 'write' permission
                    on Network Design and Network Provision
                    is required.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
          network_services:
            description: Configure additional capabilities
              on the network beyond basic network connectivity
              and access.
            default: "read"
            suboptions:
              overall:
                description: Provides the same choice
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              app_hosting:
                description: Deploy, manage, and monitor
                  virtualized and container-based applications
                  running on network devices.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              bonjour:
                description: Enable the Wide Area Bonjour
                  service to facilitate policy-based
                  service discovery across the network.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              stealthwatch:
                description:
                  - Configure network elements to send
                    data to Cisco Stealthwatch for threat
                    detection and mitigation, including
                    encrypted traffic.
                  - To provision Stealthwatch, 'write'
                    permission is required for the following
                    components.
                  - Network Design > Network Settings.
                  - Network Provision > Provision.
                  - Network Services > Stealthwatch.
                  - Network Design > Advanced Settings.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              umbrella:
                description:
                  - Configure network elements to use
                    Cisco Umbrella as a first line of
                    defense against cybersecurity threats.
                  - To provision Umbrella, 'write' permission
                    is required for the following components.
                  - Network Design > Network Settings.
                  - Network Provision > Provision.
                  - Network Provision > Scheduler.
                  - Network Services > Umbrella.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
          platform:
            description: Open platform for accessible,
              intent-based workflows, data exchange,
              notifications, and third-party app integrations.
            default: "deny"
            suboptions:
              overall:
                description: Provides the same choice
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                default: "deny"
                type: str
              apis:
                description: Access Cisco Catalyst Center
                  through REST APIs to drive value.
                choices: ["deny", "read", "write"]
                default: "deny"
                type: str
              bundles:
                description: Enhance productivity by
                  configuring and activating preconfigured
                  bundles for ITSM integration.
                choices: ["deny", "read", "write"]
                default: "deny"
                type: str
              events:
                description:
                  - Subscribe to near real-time notifications
                    for network and system events of
                    interest.
                  - Configure email and syslog logs
                    in System > Settings > Destinations.
                choices: ["deny", "read", "write"]
                default: "deny"
                type: str
              reports:
                description:
                  - Generate reports using predefined
                    templates for all aspects of the
                    network.
                  - Generate reports for rogue devices
                    and aWIPS.
                  - Configure webhooks in System > Settings
                    > Destinations.
                choices: ["deny", "read", "write"]
                default: "deny"
                type: str
          security:
            description: Manage and control secure access
              to the network.
            default: "read"
            suboptions:
              overall:
                description: Provides the same choice
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              group_based_policy:
                description:
                  - Manage group-based policies for
                    networks that enforce segmentation
                    and access control based on Cisco
                    security group tags.
                  - This role includes Endpoint Analytics.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              ip_based_access_control:
                description: Manage IP-based access
                  control lists that enforce network
                  segmentation based on IP addresses.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              security_advisories:
                description: Scan the network for security
                  advisories. Review and understand
                  the impact of published Cisco security
                  advisories.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
          system:
            description: Centralized administration
              of Cisco Catalyst Center, including configuration
              management, network connectivity, software
              upgrades, and more.
            default: "read"
            suboptions:
              overall:
                description: Provides the same choice
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              machine_reasoning:
                description: Configure automatic updates
                  to the machine reasoning knowledge
                  base to rapidly identify security
                  vulnerabilities and improve automated
                  issue analysis.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              system_management:
                description:
                  - Manage core system functionality
                    and connectivity settings, user
                    roles, and external authentication.
                  - This role includes Cisco Credentials,
                    Integrity Verification, Device EULA,
                    HA, Integration Settings, Disaster
                    Recovery, Debugging Logs, Telemetry
                    Collection, System EULA, IPAM, vManage
                    Servers, Cisco AI Analytics, Backup
                    & Restore, and Data Platform.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
          utilities:
            description: One-stop-shop productivity
              resource for the most commonly used troubleshooting
              tools and services.
            suboptions:
              overall:
                description: Provides the same choice
                  for all sub-parameters.
                choices: ["deny", "read", "write"]
                type: str
              audit_log:
                description: Detailed log of changes
                  made via UI or API interface to network
                  devices or Cisco Catalyst Center.
                choices: ["deny", "read", "write"]
                default: "deny"
                type: str
              event_viewer:
                description: View network device and
                  client events for troubleshooting.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              network_reasoner:
                description:
                  - Allow the Cisco support team to
                    remotely troubleshoot the network
                    devices managed by Cisco Catalyst
                    Center.
                  - Enables an engineer from the Cisco
                    Technical Assistance Center (TAC)
                    to connect remotely to a customer's
                    Cisco Catalyst Center setup for
                    troubleshooting.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
              remote_device_support:
                description: Allow Cisco support team
                  to remotely troubleshoot any network
                  devices managed by Cisco Catalyst
                  Center.
                choices: ["deny", "read", "write"]
                default: "deny"
                type: str
              scheduler:
                description: Run, schedule, and monitor
                  network tasks and activities such
                  as deploying policies, provisioning,
                  or upgrading the network, integrated
                  with other back-end services.
                choices: ["deny", "read", "write"]
                default: "write"
                type: str
              search:
                description: Search for various objects
                  in Cisco Catalyst Center, including
                  sites, network devices, clients, applications,
                  policies, settings, tags, menu items,
                  and more.
                choices: ["deny", "read", "write"]
                default: "read"
                type: str
requirements:
  - dnacentersdk >= 2.7.2
  - python >= 3.9.19
notes:
  - SDK Methods used - user_and_roles.UserandRoles.get_user_api
    - user_and_roles.UserandRoles.add_user_api - user_and_roles.UserandRoles.update_user_api
    - user_and_roles.UserandRoles.delete_user_api
  - Paths used - get /dna/system/api/v1/user - post
    /dna/system/api/v1/user - put /dna/system/api/v1/user
    - delete /dna/system/api/v1/user/{userId}
"""
EXAMPLES = r"""
---
- name: Create a user
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    dnac_api_task_timeout: 1000
    dnac_task_poll_interval: 1
    state: merged
    config:
      user_details:
        - username: "ajithandrewj"
          first_name: "ajith"
          last_name: "andrew"
          email: "ajith.andrew@example.com"
          password: "Example@0101"
          role_list: ["SUPER-ADMIN-ROLE"]
- name: Update a user for first name, last name, email,
    and role list
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    dnac_api_task_timeout: 1000
    dnac_task_poll_interval: 1
    state: merged
    config:
      user_details:
        - username: "ajithandrewj"
          first_name: "ajith"
          last_name: "andrew"
          email: "ajith.andrew@example.com"
          role_list: ["SUPER-ADMIN-ROLE"]
- name: Update a user for role list
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    dnac_api_task_timeout: 1000
    dnac_task_poll_interval: 1
    state: merged
    config:
      user_details:
        - username: "ajithandrewj"
          role_list: ["NETWORK-ADMIN-ROLE"]
- name: Update the user password
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    dnac_api_task_timeout: 1000
    dnac_task_poll_interval: 1
    state: merged
    config:
      user_details:
        - username: "ajithandrewj"
          password: "Example@010101"
          password_update: true
- name: Delete a user using username or email address
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    dnac_api_task_timeout: 1000
    dnac_task_poll_interval: 1
    state: deleted
    config:
      user_details:
        username: "ajithandrewj"
- name: Create a Comprehensive Role
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    config:
      role_details:
        - role_name: "Full-Access-Admin"
          description: "Admin role with access to most
            operational domains."
          assurance:
            - monitoring_and_troubleshooting: "write"
              monitoring_settings: "read"
              troubleshooting_tools: "deny"
          network_analytics:
            - data_access: "write"
          network_design:
            - advanced_network_settings: "deny"
              image_repository: "deny"
              network_hierarchy: "deny"
              network_profiles: "write"
              network_settings: "write"
              virtual_network: "read"
          network_provision:
            - compliance: "deny"
              eox: "read"
              image_update: "write"
              inventory_management:
                - device_configuration: "write"
                  discovery: "deny"
                  network_device: "read"
                  port_management: "write"
                  topology: "write"
              license: "write"
              network_telemetry: "write"
              pnp: "deny"
              provision: "read"
          network_services:
            - app_hosting: "deny"
              bonjour: "write"
              stealthwatch: "read"
              umbrella: "deny"
          platform:
            - apis: "write"
              bundles: "write"
              events: "write"
              reports: "read"
          security:
            - group_based_policy: "read"
              ip_based_access_control: "write"
              security_advisories: "write"
          system:
            - machine_reasoning: "read"
              system_management: "write"
          utilities:
            - audit_log: "read"
              event_viewer: "deny"
              network_reasoner: "write"
              remote_device_support: "read"
              scheduler: "read"
              search: "write"
- name: Create Assurance Role
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    config:
      role_details:
        - role_name: "Assurance-Manager"
          description: "User with assurance write access
            and read-only monitoring."
          assurance:
            - overall: "write"
              monitoring_and_troubleshooting: "read"
- name: Create a Network Provision Role
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    config:
      role_details:
        - role_name: "Network-Provision-Manager"
          description: "User with access to most network
            provision operations."
          network_provision:
            - compliance: "write"
              image_update: "write"
              inventory_management:
                - overall: "read"
                  device_configuration: "write"
              license: "write"
              network_telemetry: "write"
              pnp: "deny"
              provision: "read"
- name: Update a Role for Assurance and Platform
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    config:
      role_details:
        - role_name: "Full-Access-Admin"
          assurance:
            - overall: "read"
          platform:
            - apis: "write"
              bundles: "write"
              events: "write"
              reports: "read"
- name: Delete a role
  cisco.dnac.user_role_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: true
    dnac_log_level: DEBUG
    config_verify: true
    dnac_api_task_timeout: 1000
    dnac_task_poll_interval: 1
    state: deleted
    config:
      role_details:
        - role_name: "Assurance-Manager"
"""
RETURN = r"""
# Case 1: Successful creation of user
response_1:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "message": "string",
            "userId": "string"
        }
    }
# Case 2: Successful updation of user
response_2:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "message": "string"
        }
    }
# Case 3: Successful deletion of user
response_3:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "message": "string"
        }
    }
# Case 4: User exists and no action needed (for update)
response_4:
  description: A dictionary with existing user details indicating no update needed.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "user": {
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "username": "johndoe",
                "role_list": ["NETWORK-ADMIN-ROLE"]
            },
            "userId": "string",  # User ID from Cisco Catalyst Center
            "type": "string"
        },
        "msg": "User already exists and no update needed."
    }
# Case 5: Error during user operation (create/update/delete)
response_5:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "msg": "Error during creating, updating or deleting the user."
        }
    }
# Case 6: User not found (during delete operation)
response_6:
  description: A dictionary indicating user not found during delete operation.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "msg": "User not found."
        }
    }
# Case 7: Successful creation of role
response_7:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "roleid": "string",
            "message": "string"
        }
    }
# Case 8: Successful updation of role
response_8:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "roleId": "string",
            "message": "string"
        }
    }
# Case 9: Successful deletion of role
response_9:
  description: A dictionary with details of the API execution from Cisco Catalyst Center.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "message": "string"
        }
    }
# Case 10: Error during role operation (create/update/delete)
response_10:
  description: A dictionary with details of the API execution and error information.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "msg": "Error during creating, updating or deleting the role."
        }
    }
# Case 11: Role not found (during delete operation)
response_11:
  description: A dictionary indicating role not found during delete operation.
  returned: always
  type: dict
  sample:
    {
        "response": {
            "msg": "Role not found."
        }
    }
"""

import re
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_list,
)
from ansible.module_utils.basic import AnsibleModule


class UserandRole(DnacBase):
    """Class containing member attributes for user workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged", "deleted"]
        self.keymap = {}
        self.created_user, self.updated_user, self.no_update_user = [], [], []
        self.created_role, self.updated_role, self.no_update_role = [], [], []
        self.deleted_user, self.deleted_role = [], []
        self.no_deleted_user, self.no_deleted_role = [], []

    def validate_input_yml(self, user_role_details):
        """
        Validate the fields provided in the yml files.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types based on input.
        Parameters:
          - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
          - user_role_details (list): Contains user details or role details according to the yml file.
        Returns:
          The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either "success" or "failed").
                - self.validated_config: If successful, a validated version of the "config" parameter.
        Description:
          - To use this method, create an instance of the class and call "validate_input_yml" on it.
          - If the validation succeeds, "self.status" will be "success" and "self.validated_config" will contain the validated
            configuration. If it fails, "self.status" will be "failed", and "self.msg" will describe the validation issues.
          - If the validation succeeds, this will allow to go next step, unless this will stop execution based on the fields.
        """
        self.log("Validating the Playbook Yaml File..", "INFO")
        config = self.payload.get("config")
        self.key = self.generate_key()

        if self.key and "error_message" in self.key:
            self.msg = self.key.get("error_message")
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        if user_role_details is None or not isinstance(user_role_details, list):
            self.msg = "Configuration is not available in the playbook for validation or user/role details are not type list"
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        if (
            "role_details" in config
            and "role_name" in user_role_details[0]
            and user_role_details[0].get("role_name") is not None
        ):
            role_details = {
                "role_name": {"required": True, "type": "str"},
                "description": {"required": False, "type": "str"},
                "assurance": {"required": False, "type": "list", "elements": "dict"},
                "network_analytics": {
                    "required": False,
                    "type": "list",
                    "elements": "dict",
                },
                "network_design": {
                    "required": False,
                    "type": "list",
                    "elements": "dict",
                },
                "network_provision": {
                    "required": False,
                    "type": "list",
                    "elements": "dict",
                },
                "network_services": {
                    "required": False,
                    "type": "list",
                    "elements": "dict",
                },
                "platform": {"required": False, "type": "list", "elements": "dict"},
                "security": {"required": False, "type": "list", "elements": "dict"},
                "system": {"required": False, "type": "list", "elements": "dict"},
                "utilities": {"required": False, "type": "list", "elements": "dict"},
            }
            valid_param, invalid_param = validate_list_of_dicts(
                user_role_details, role_details
            )

            if invalid_param:
                self.msg = "Invalid parameter(s) found in playbook: {0}".format(
                    ", ".join(invalid_param)
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            self.validated_config = valid_param
            self.msg = "Successfully validated playbook config params: {0}".format(
                str(valid_param[0])
            )
            self.log(self.msg, "INFO")
            self.status = "success"
            return self

        if (
            "user_details" in config
            and "username" in user_role_details[0]
            or "email" in user_role_details[0]
        ):
            for user in user_role_details:
                if "password" in user:
                    encrypt_password_response = self.encrypt_password(
                        user["password"], self.key.get("generate_key")
                    )

                    if (
                        encrypt_password_response
                        and "error_message" in encrypt_password_response
                    ):
                        self.msg = encrypt_password_response.get("error_message")
                        self.log(self.msg, "ERROR")
                        self.status = "failed"
                        return self

                    user["password"] = encrypt_password_response.get("encrypt_password")

            if (
                user_role_details[0].get("username") is not None
                or user_role_details[0].get("email") is not None
            ):
                user_details = {
                    "first_name": {"required": False, "type": "str"},
                    "last_name": {"required": False, "type": "str"},
                    "email": {"required": False, "type": "str"},
                    "password": {"required": False, "type": "str"},
                    "password_update": {"required": False, "type": "bool"},
                    "username": {"required": False, "type": "str"},
                    "role_list": {"required": False, "type": "list", "elements": "str"},
                }

                try:
                    valid_param, invalid_param = validate_list_of_dicts(
                        user_role_details, user_details
                    )
                except Exception as e:
                    self.log("Unexpected error occurred: {0}".format(str(e)), "ERROR")
                    self.msg = "{0}.".format(str(e).split(".", maxsplit=1)[0])
                    self.log(self.msg, "ERROR")
                    self.status = "failed"
                    return self

                if invalid_param:
                    self.msg = "Invalid parameter(s) found in playbook: {0}".format(
                        ", ".join(invalid_param)
                    )
                    self.log(self.msg, "ERROR")
                    self.status = "failed"
                    return self

                self.validated_config = valid_param
                self.msg = "Successfully validated playbook config params:{0}".format(
                    str(valid_param[0])
                )
                self.log(self.msg, "INFO")
                self.status = "success"
                return self

        self.msg = (
            "'Configuration parameters such as 'username', 'email', or 'role_name' are missing from the playbook' or "
            "'The 'user_details' key is invalid for role creation, updation, or deletion' or "
            "'The 'role_details' key is invalid for user creation, updation, or deletion'"
        )
        self.log(self.msg, "ERROR")
        self.status = "failed"
        return self

    def validate_string_parameter(self, param_name, param_value, error_messages):
        """
        Helper function to validate string parameters.
        """
        # Check if the parameter value is a string
        if not isinstance(param_value, str):
            error_messages.append(
                "Parameter '{0}' must be a string.".format(param_name)
            )

    def validate_string_field(self, field_value, regex, error_message, error_messages):
        """
        Helper function to validate string fields against a regex pattern.
        """
        if field_value and not regex.match(field_value):
            error_messages.append(error_message)

    def validate_password(self, password, error_messages):
        """
        Validate the provided password and append an error message if it does not meet the criteria.
        Args:
            - password (str): The password to be validated. Must be a string.
            - error_messages (list): A list where error messages are appended if the password does not meet the criteria.
        Returns:
            None: This function does not return a value, but it may append an error message to `error_messages` if the password is invalid.
        Criteria:
            - The password must be 9 to 20 characters long.
            - The password must include characters from at least three of the following classes:
              lowercase letters, uppercase letters, digits, and special characters.
        """
        meets_character_requirements = False
        password_criteria_message = (
            "The password must be 9 to 20 characters long and include at least three of the following "
            "character types: lowercase letters, uppercase letters, digits, and special characters. "
            "Additionally, the password must not contain repetitive or sequential characters."
        )

        self.log(password_criteria_message, "DEBUG")
        password_regexs = [
            re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?!.*[\W_]).{9,20}$"),
            re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_])(?!.*\d).{9,20}$"),
            re.compile(r"^(?=.*[a-z])(?=.*\d)(?=.*[\W_])(?!.*[A-Z]).{9,20}$"),
            re.compile(r"^(?=.*[A-Z])(?=.*\d)(?=.*[\W_])(?!.*[a-z]).{9,20}$"),
            re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{9,20}$"),
        ]

        self.log("Password meets character type and length requirements.", "INFO")
        for password_regex in password_regexs:
            if password_regex.match(password):
                meets_character_requirements = True
                break

        if not meets_character_requirements:
            self.log("Password failed character type and length validation.", "ERROR")
            error_messages.append(password_criteria_message)

    def validate_role_parameters(
        self, role_key, params_list, role_config, role_param_map, error_messages
    ):
        """
        Helper function to validate role parameters.
        """
        role_list = role_config.get(role_key, [])
        if role_list is not None:
            for role in role_list:
                self.log("Validating role: {0}".format(role), "DEBUG")
                for param in params_list:
                    if role.get(param):
                        self.log(
                            "Validating parameter '{0}' with value '{1}'".format(
                                param, role[param]
                            ),
                            "DEBUG",
                        )
                        self.validate_string_parameter(
                            param, role[param], error_messages
                        )

                if role == "network_provision":
                    inventory_management_list = role.get("inventory_management", [])
                    if inventory_management_list is not None:
                        for inventory_management in inventory_management_list:
                            self.log(
                                "Validating inventory management: {0}".format(
                                    inventory_management
                                ),
                                "DEBUG",
                            )
                            for param in role_param_map["inventory_management"]:
                                if inventory_management.get(param):
                                    self.log(
                                        "Validating inventory management parameter '{0}' with value '{1}'".format(
                                            param, inventory_management[param]
                                        ),
                                        "DEBUG",
                                    )
                                    self.validate_string_parameter(
                                        param,
                                        inventory_management[param],
                                        error_messages,
                                    )

    def identify_invalid_params(self, params, mismatches):
        """
        Identify and collect invalid parameters from a dictionary or list based on allowed parameters.
        Args:
            - params (dict | list): The dictionary or list of parameters to be checked. Nested dictionaries or lists are supported.
            - mismatches (list): A list where invalid parameter names are appended. This list is used to collect all
              parameters that are not in 'allowed_params'.
        Returns:
            - mismatches (list): This function returns the 'mismatches' list containing the names of any parameters that are not in the 'allowed_params' set.
        Criteria:
            - Parameters in 'params' must be checked recursively if they are dictionaries or lists.
            - Only parameters that are not in the 'allowed_params' set are appended to the 'mismatches' list.
        """
        allowed_params = [
            "monitoring_and_troubleshooting",
            "monitoring_settings",
            "troubleshooting_tools",
            "data_access",
            "advanced_network_settings",
            "image_repository",
            "network_hierarchy",
            "network_profiles",
            "network_settings",
            "virtual_network",
            "compliance",
            "eox",
            "image_update",
            "inventory_management",
            "license",
            "network_telemetry",
            "pnp",
            "provision",
            "device_configuration",
            "discovery",
            "network_device",
            "port_management",
            "topology",
            "app_hosting",
            "bonjour",
            "stealthwatch",
            "umbrella",
            "apis",
            "bundles",
            "events",
            "reports",
            "group_based_policy",
            "ip_based_access_control",
            "security_advisories",
            "machine_reasoning",
            "system_management",
            "audit_log",
            "event_viewer",
            "network_reasoner",
            "remote_device_support",
            "scheduler",
            "search",
            "role_name",
            "description",
            "assurance",
            "network_analytics",
            "network_design",
            "network_provision",
            "network_services",
            "platform",
            "security",
            "system",
            "utilities",
            "overall",
        ]
        self.log(
            "Starting to iterate through params to identify unknown parameters.",
            "DEBUG",
        )

        if isinstance(params, dict):
            for key, value in params.items():
                if key not in allowed_params:
                    self.log("Invalid parameter detected: {0}".format(key), "ERROR")
                    mismatches.append(key)

                if isinstance(value, dict) or isinstance(value, list):
                    self.identify_invalid_params(value, mismatches)
        elif isinstance(params, list):
            for item in params:
                self.identify_invalid_params(item, mismatches)

        if not mismatches:
            self.log("No invalid parameters found.", "INFO")

        return mismatches

    def valid_role_config_parameters(self, role_config):
        """
        Additional validation for the create role configuration payload.
        Parameters:
        - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        - role_config (dict): A dictionary containing the input configuration details.
        Returns:
        The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either "success" or "failed").
        Description:
            - To use this method, create an instance of the class and call "valid_role_config_parameters" on it.
            - If the validation succeeds it returns "success".
            - If it fails, "self.status" will be "failed", and "self.msg" will describe the validation issues.
        """
        self.log("Validating role configuration parameters...", "INFO")

        invalid_params = []
        self.identify_invalid_params(role_config, invalid_params)

        if invalid_params:
            self.msg = "Invalid parameters in playbook config: Mismatched parameter(s) '{0}' in role '{1}'".format(
                "', '".join(invalid_params), role_config.get("role_name")
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        error_messages = []
        role_name = role_config.get("role_name")
        role_name_regex = re.compile(r"^[a-zA-Z0-9._-]{1,25}$")
        role_name_regex_msg = "Role names must be 1 to 25 characters long and should contain only letters, numbers, periods, underscores, and hyphens."

        if role_name:
            self.validate_string_field(
                role_name,
                role_name_regex,
                "role_name: '{0}' {1}".format(role_name, role_name_regex_msg),
                error_messages,
            )
        else:
            error_messages.append(role_name_regex_msg)

        description = role_config["description"]
        if description:
            if len(description) > 1000:
                error_messages.append(
                    "Role description exceeds the maximum length of 1000 characters."
                )
            else:
                self.validate_string_parameter(
                    "description", description, error_messages
                )

        role_param_map = {
            "assurance": [
                "overall",
                "monitoring_and_troubleshooting",
                "monitoring_settings",
                "troubleshooting_tools",
            ],
            "network_analytics": ["overall", "data_access"],
            "network_design": [
                "overall",
                "advanced_network_settings",
                "image_repository",
                "network_hierarchy",
                "network_profiles",
                "network_settings",
                "virtual_network",
            ],
            "network_provision": [
                "overall",
                "compliance",
                "eox",
                "image_update",
                "license",
                "network_telemetry",
                "pnp",
                "provision",
            ],
            "inventory_management": [
                "overall",
                "device_configuration",
                "discovery",
                "network_device",
                "port_management",
                "topology",
            ],
            "network_services": [
                "overall",
                "app_hosting",
                "bonjour",
                "stealthwatch",
                "umbrella",
            ],
            "platform": ["overall", "apis", "bundles", "events", "reports"],
            "security": [
                "overall",
                "group_based_policy",
                "ip_based_access_control",
                "security_advisories",
            ],
            "system": ["overall", "machine_reasoning", "system_management"],
            "utilities": [
                "overall",
                "audit_log",
                "event_viewer",
                "network_reasoner",
                "remote_device_support",
                "scheduler",
                "search",
            ],
        }

        for role_key, params_list in role_param_map.items():
            self.validate_role_parameters(
                role_key, params_list, role_config, role_param_map, error_messages
            )

        if error_messages:
            self.msg = "Invalid parameters in playbook config: {0}".format(
                ", ".join(error_messages)
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.msg = "Successfully validated config params: {0}".format(str(role_config))
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def valid_user_config_parameters(self, user_config):
        """
        Additional validation for the create user configuration payload.
        Parameters:
          - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
          - user_config (dict): A dictionary containing the input configuration details.
        Returns:
          The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either "success" or "failed").
        Description:
            - To use this method, create an instance of the class and call "valid_user_config_parameters" on it.
            - If the validation succeeds it returns "success".
            - If it fails, "self.status" will be "failed", and "self.msg" will describe the validation issues.
        """
        self.log("Validating user configuration parameters...", "INFO")
        error_messages = []
        name_regex = re.compile(r"^[A-Za-z0-9@._-]{2,50}$")
        name_regex_msg = (
            "can have alphanumeric characters only and must be 2 to 50 characters long."
        )

        first_name = user_config.get("first_name")
        self.validate_string_field(
            first_name,
            name_regex,
            "first_name: First name '{0}' {1}".format(first_name, name_regex_msg),
            error_messages,
        )

        last_name = user_config.get("last_name")
        self.validate_string_field(
            last_name,
            name_regex,
            "last_name: Last name '{0}' {1}".format(last_name, name_regex_msg),
            error_messages,
        )

        password = user_config.get("password")

        if password:
            decrypt_password_response = self.decrypt_password(
                password, self.key.get("generate_key")
            )

            if (
                decrypt_password_response
                and "error_message" in decrypt_password_response
            ):
                self.msg = decrypt_password_response.get("error_message")
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            user_config["password"] = decrypt_password_response.get("decrypt_password")
            plain_password = user_config.get("password")
            self.validate_password(plain_password, error_messages)
            encrypt_password_response = self.encrypt_password(
                plain_password, self.key.get("generate_key")
            )

            if (
                encrypt_password_response
                and "error_message" in encrypt_password_response
            ):
                self.msg = encrypt_password_response.get("error_message")
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            user_config["password"] = encrypt_password_response.get(
                "encrypt_password"
            ).decode()
            self.log(
                "Password decrypted, validated, and re-encrypted successfully.", "DEBUG"
            )

        username_regex = re.compile(r"^[A-Za-z0-9@._-]{3,50}$")
        username_regex_msg = "The username must not contain any special characters and must be 3 to 50 characters long."
        username = user_config.get("username")
        self.validate_string_field(
            username,
            username_regex,
            "username: '{0}' {1}".format(username, username_regex_msg),
            error_messages,
        )

        if user_config.get("role_list"):
            param_spec = dict(type="list", elements="str")
            validate_list(
                user_config["role_list"], param_spec, "role_list", error_messages
            )

        if error_messages:
            self.msg = "Invalid parameters in playbook config: {0}".format(
                str(", ".join(error_messages))
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.msg = "Successfully validated config params:{0}".format(str(user_config))
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def get_want(self, config):
        """
        Retrieve all user or role-related information from the playbook needed for creation/updation in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): A dictionary containing user or role information.
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            - Retrieves all user or role-related information from the playbook required for creating or updating in Cisco Catalyst Center.
            - Includes parameters such as "username", "email", "role_list" and "role_name" as applicable.
            - Stores the gathered information in the "want" attribute for later reference.
            - Logs the desired state configuration for debugging and informational purposes.
        """
        want = {}
        for key, value in config.items():
            want[key] = value

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")
        return self

    def update_have_with_role(self, have, role_exists, current_role_config):
        """
        Helper function to update the 'have' dictionary with role details.
        """
        if role_exists:
            have["role_name"] = current_role_config.get("name")
            have["current_role_config"] = current_role_config
        have["role_exists"] = role_exists

    def update_have_with_user(
        self, have, user_exists, current_user_config, current_role_id_config
    ):
        """
        Helper function to update the 'have' dictionary with user details.
        """
        if user_exists:
            have["username"] = current_user_config.get("username")
            have["current_user_config"] = current_user_config
        have["user_exists"] = user_exists
        have["current_role_id_config"] = current_role_id_config

    def get_have(self, input_config):
        """
        Retrieve and store current user or role details from Cisco Catalyst Center based on input configuration.
        Parameters:
            - self (object): An instance for interacting with Cisco Catalyst Center.
            - input_config (dict): Configuration details specifying user or role.
        Returns:
            - self (object): An instance for interacting with Cisco Catalyst Center.
        Description:
            - Queries Cisco Catalyst Center to check if specified user or role exists.
            - If the input specifies a role name, checks and retrieves current role configuration.
            - If the input specifies a 'username' or 'email', checks and retrieves current user configuration.
            - Stores retrieved user or role details in the "have" attribute for later reference.
        """
        self.log("Starting retrieval of user or role details...", "INFO")
        have = {}

        if "role_name" in input_config and input_config["role_name"] is not None:
            role_exists, current_role_config = self.get_current_config(input_config)
            self.log(
                "Current role config details (have): {0}".format(
                    str(current_role_config)
                ),
                "DEBUG",
            )
            self.update_have_with_role(have, role_exists, current_role_config)

        if "username" in input_config or "email" in input_config:
            user_exists, current_user_config, current_role_id_config = (
                self.get_current_config(input_config)
            )
            self.log(
                "Current user config details (have): {0}".format(
                    str(current_user_config)
                ),
                "DEBUG",
            )
            self.update_have_with_user(
                have, user_exists, current_user_config, current_role_id_config
            )

        self.have = have
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        return self

    def get_diff_merged(self, config):
        """
        Update or create users and roles in Cisco Catalyst Center based on playbook configurations.
        Parameters:
            - self (object): Instance for interacting with Cisco Catalyst Center.
            - config (dict): Configuration data for user or role updates.
        Returns:
            - self (object): Instance for interacting with Cisco Catalyst Center.
        Description:
            - Determines whether to update or create a user or role in Cisco Catalyst Center based on the provided configuration.
            - Determines update or creation needs based on "role_name", "username", or "email" in config.
            - Updates roles if "role_name" exists, creates if absent using "create_role" or "update_role".
            - Updates users if "username" or "email" exists, creates if absent using "create_user" or "update_user".
            - Returns the instance of the class used for interacting with Cisco Catalyst Center after updating or
              creating the user or role.
        """
        self.log("Starting the users and roles create/update process...", "INFO")
        task_response = None
        responses = {}

        if "role_name" in config:
            # update the role if role exists
            if self.have.get("role_exists"):
                self.valid_role_config_parameters(config).check_return_status()
                desired_role = self.generate_role_payload(self.want, "update")
                self.log(
                    "desired role with config {0}".format(str(desired_role)), "DEBUG"
                )

                if "error_message" not in desired_role:
                    consolidated_data, update_required_param = (
                        self.role_requires_update(
                            self.have["current_role_config"], desired_role
                        )
                    )

                    if not consolidated_data:
                        self.msg = "Role with role_name '{0}' already exists and does not require an update.".format(
                            self.have.get("role_name")
                        )
                        self.no_update_role.append(self.have.get("role_name"))
                        self.log(self.msg, "INFO")
                        responses["role_operation"] = {"response": config}
                        self.result["response"] = self.msg
                        self.status = "success"
                        return self

                    task_response = self.update_role(update_required_param)
                else:
                    task_response = desired_role
            else:
                # Create the role
                self.valid_role_config_parameters(config).check_return_status()
                self.log("Creating role with config {0}".format(str(config)), "DEBUG")
                role_info_params = self.generate_role_payload(self.want, "create")

                if "error_message" not in role_info_params:
                    filtered_data, overall_update_required = self.get_permissions(
                        self.want, role_info_params, "create"
                    )
                    denied_permissions = self.find_denied_permissions(self.want)
                    denied_required, create_role_params = self.remove_denied_operations(
                        filtered_data, denied_permissions
                    )

                    if denied_required or overall_update_required:
                        task_response = self.create_role(create_role_params)
                    else:
                        task_response = self.create_role(role_info_params)
                else:
                    task_response = role_info_params

        if "username" in config or "email" in config:
            # update the user if role exists
            if self.have.get("user_exists"):
                self.valid_user_config_parameters(config).check_return_status()
                (consolidated_data, update_required_param) = self.user_requires_update(
                    self.have["current_user_config"],
                    self.have["current_role_id_config"],
                )

                if self.want.get("password_update"):
                    if update_required_param.get("role_list"):
                        if self.want["username"].lower() not in self.have["current_user_config"]["username"]:
                            task_response = {"error_message": "Username for an existing user cannot be updated."}
                        else:
                            self.get_diff_deleted(self.want)
                            update_required_param["password"] = self.want.get(
                                "password"
                            )
                            user_info_params = self.snake_to_camel_case(
                                update_required_param
                            )
                            task_response = self.create_user(user_info_params)
                    else:
                        task_response = {
                            "error_message": "The role name in the 'role_list' of user details is not present in the Cisco Catalyst Center. "
                            "Please provide a valid role name."
                        }
                else:
                    if not consolidated_data:
                        username = self.have.get("username")
                        self.msg = "User with username '{0}' already exists and does not require an update.".format(
                            username
                        )
                        self.no_update_user.append(username)
                        self.log(self.msg, "INFO")
                        responses["role_operation"] = {"response": config}
                        self.result["response"] = self.msg
                        self.status = "success"
                        return self

                    if update_required_param.get("role_list"):

                        if self.want["username"].lower() not in self.have["current_user_config"]["username"]:
                            task_response = {"error_message": "Username for an existing user cannot be updated."}
                        else:
                            user_in_have = self.have["current_user_config"]
                            update_param = update_required_param
                            update_param["user_id"] = user_in_have.get("user_id")
                            user_info_params = self.snake_to_camel_case(update_param)
                            task_response = self.update_user(user_info_params)
                    else:
                        task_response = {
                            "error_message": "The role name in the user details 'role_list' is not present in the Cisco Catalyst Center. "
                            "Please provide a valid role name."
                        }
            else:
                # Create the user
                self.valid_user_config_parameters(config).check_return_status()
                self.log("Creating user with config {0}".format(str(config)), "DEBUG")
                user_params = self.want

                user_details = {}
                for key, value in user_params.items():
                    if value is not None:
                        if key != "role_list":
                            user_details[key] = value
                        else:
                            current_role = self.have.get("current_role_id_config")
                            user_details[key] = []
                            for role_name in user_params["role_list"]:
                                role_id = current_role.get(role_name.lower())
                                if role_id:
                                    user_details[key].append(role_id)
                                else:
                                    self.log(
                                        "Role ID for {0} not found in current_role_id_config".format(
                                            str(role_name)
                                        ),
                                        "DEBUG",
                                    )

                if "role_list" not in user_details:
                    default_role = self.have.get("current_role_id_config")
                    if default_role:
                        user_details["role_list"] = [default_role.get("observer-role")]

                if user_details.get("role_list"):
                    user_info_params = self.snake_to_camel_case(user_details)
                    task_response = self.create_user(user_info_params)
                else:
                    task_response = {
                        "error_message": "The role name in the user details role_list is not present in the Cisco Catalyst Center,"
                        " Please provide a valid role name"
                    }

        if task_response and "error_message" not in task_response:
            self.log("Task respoonse {0}".format(str(task_response)), "INFO")
            responses["operation"] = {"response": task_response}
            self.msg = responses
            self.result["response"] = self.msg
            self.result["changed"] = True
            self.status = "success"
            self.log(self.msg, "INFO")
            return self

        self.msg = task_response.get("error_message")
        self.log(self.msg, "ERROR")
        self.status = "failed"
        return self

    def get_current_config(self, input_config):
        """
        Retrieve user and role details from Cisco Catalyst Center based on input parameters.

        Parameters:
            - self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            - input_config (dict): A dictionary containing input parameters for retrieving user or role details.

        Returns:
            - If 'username' is in input_config:
                - user_exists (bool): True if the user exists, False otherwise.
                - current_user_configuration (dict): Dictionary containing current user details.
                - current_role_id (dict): Dictionary containing current role IDs.
            - If 'role_name' is in input_config:
                - role_exists (bool): True if the role exists, False otherwise.
                - current_role_configuration (dict): Dictionary containing current role details.

        Description:
            - Checks the existence of a user and retrieves user details in Cisco Catalyst Center
              by querying the "get_users_api" function in the "user_and_roles" family.
            - Checks the existence of a role and retrieves role details in Cisco Catalyst Center
              by querying the "get_roles_api" function in the "user_and_roles" family.
            - Logs errors if required parameters are missing in the playbook config.
        """
        user_exists = False
        role_exists = False
        current_user_configuration = {}
        current_role_configuration = {}
        current_role_id = {}

        if "role_name" in input_config and input_config["role_name"] is not None:
            self.log(
                "Retrieving role details for role_name: {0}".format(
                    str(input_config["role_name"])
                ),
                "DEBUG",
            )

            response_role = self.get_role()
            response_role = self.camel_to_snake_case(response_role)
            roles = response_role.get("response", {}).get("roles", [])

            for role in roles:
                if role.get("name") == input_config.get("role_name"):
                    current_role_configuration = role
                    role_exists = True

            self.log(
                "Role retrieval result - role_exists: {0}, current_role_configuration: {1}".format(
                    str(role_exists), str(current_role_configuration)
                ),
                "DEBUG",
            )
            return role_exists, current_role_configuration

        if "username" in input_config or "email" in input_config:
            self.log(
                "Retrieving user details for username: {0}, email: {1}".format(
                    str(input_config.get("username")), str(input_config.get("email"))
                ),
                "DEBUG",
            )
            response_user = self.get_user()
            response_role = self.get_role()
            response_user = self.camel_to_snake_case(response_user)
            response_role = self.camel_to_snake_case(response_role)
            users = response_user.get("response", {}).get("users", [])
            roles = response_role.get("response", {}).get("roles", [])

            for user in users:
                if input_config.get("username") is not None:
                    if user.get("username") == input_config.get("username").lower():
                        current_user_configuration = user
                        user_exists = True
                elif input_config.get("email") is not None:
                    if user.get("email") == input_config.get("email"):
                        current_user_configuration = user
                        user_exists = True

            self.log(
                "User retrieval result - user_exists: {0}, current_user_configuration: {1}".format(
                    str(user_exists), str(current_user_configuration)
                ),
                "DEBUG",
            )

            if input_config.get("role_list"):
                for role_name in input_config["role_list"]:
                    for role in roles:
                        if role.get("name").lower() == role_name.lower():
                            current_role_id[role.get("name").lower()] = role.get(
                                "role_id"
                            )
            else:
                for role in roles:
                    if role.get("name").lower() == "observer-role":
                        current_role_id[role.get("name").lower()] = role.get("role_id")

            self.log(
                "Role ID retrieval result - current_role_id: {0}".format(
                    str(current_role_id)
                ),
                "DEBUG",
            )
            return user_exists, current_user_configuration, current_role_id

    def create_user(self, user_params):
        """
        Create a new user in Cisco Catalyst Center with the provided parameters.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - user_params (dict): A dictionary containing user information.
        Returns:
            - response (dict): The API response from the "create_user" function.
        Description:
            - Sends a request to create a new user in Cisco Catalyst Center using the provided user parameters.
            - Uses the "user_and_roles" family and "add_user_api" function for the API call.
            - Logs the provided user parameters and the received API response.
            - Returns the API response from the "create_user" function.
        """
        self.log("Create user with 'user_params' argument...", "DEBUG")

        if user_params.get("password"):
            decrypt_password_response = self.decrypt_password(
                user_params["password"], self.key.get("generate_key")
            )

            if "error_message" in decrypt_password_response:
                self.msg = decrypt_password_response.get("error_message")
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            user_params["password"] = decrypt_password_response.get("decrypt_password")

        required_keys = ["username", "password"]
        missing_keys = []

        self.log(
            "Check if each required key is present in the user_params dictionary...",
            "DEBUG",
        )
        for key in required_keys:
            if key not in user_params:
                missing_keys.append(key)

        if missing_keys:
            error_message = (
                "Mandatory parameter(s) '{0}' not present in the user details.".format(
                    ", ".join(missing_keys)
                )
            )
            return {"error_message": error_message}

        try:
            response = self.dnac._exec(
                family="user_and_roles",
                function="add_user_api",
                op_modifies=True,
                params=user_params,
            )
            self.log(
                "Received API response from create_user: {0}".format(str(response)),
                "DEBUG",
            )
            self.created_user.append(user_params.get("username"))
            return response

        except Exception as e:
            self.log("Unexpected error occurred: {0}".format(str(e)), "ERROR")
            if "[403]" in str(e):
                error_message = "The Catalyst Center user '{0}' does not have the necessary permissions to 'create or update' a user via the API.".format(
                    self.payload.get("dnac_username")
                )
            else:
                error_message = error_message = str(e).split('"')[9]

            return {"error_message": error_message}

    def create_role(self, role_params):
        """
        Create a new role in Cisco Catalyst Center with the provided parameters.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - role_params (dict): A dictionary containing role information.
        Returns:
            - response (dict): The API response from the "create_role" function.
        Description:
            - Sends a request to create a new role in Cisco Catalyst Center using the provided role parameters.
            - Utilizes the "user_and_roles" family and "add_role_api" function for the API request.
            - Logs the provided role parameters and the received API response.
            - Returns the API response from the "create_role" function.
        """

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            try:
                self.log(
                    "Create role with role_info_params: {0}".format(str(role_params)),
                    "DEBUG",
                )
                response = self.dnac._exec(
                    family="user_and_roles",
                    function="add_role_api",
                    op_modifies=True,
                    params=role_params,
                )
                self.log(
                    "Received API response from create_role: {0}".format(str(response)),
                    "DEBUG",
                )
                self.created_role.append(role_params.get("role"))
                return response

            except Exception as e:
                self.log("Unexpected error occurred: {0}".format(str(e)), "ERROR")
                error_message = "The Catalyst Center user '{0}' does not have the necessary permissions to 'create a role' through the API.".format(
                    self.payload.get("dnac_username")
                )
                return {"error_message": error_message}

        error_message = "The specified version '{0}' does not have the 'add_role_api' functionality. Supported version(s) from '2.3.7.6' onwards.".format(
            self.payload.get("dnac_version")
        )
        return {"error_message": error_message}

    def get_user(self):
        """
        Retrieve users from Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - response (dict): The API response from the "get_users_api" function.
        Description:
            - Sends a request to retrieve users from Cisco Catalyst Center using the "user_and_roles" family
              and "get_users_api" function.
            - Logs the received API response and returns it.
        """
        response = self.dnac._exec(
            family="user_and_roles",
            function="get_users_api",
            op_modifies=True,
            params={"invoke_source": "external"},
        )
        self.log(
            "Received API response from get_users_api: {0}".format(str(response)),
            "DEBUG",
        )
        return response

    def get_role(self):
        """
        Retrieve roles from Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            - response (dict): The API response from the "get_roles" function.
        Description:
            - Sends a request to retrieve roles from Cisco Catalyst Center using the "user_and_roles" family
              and "get_roles_api" function.
            - Logs the received API response and returns it.
        """
        response = self.dnac._exec(
            family="user_and_roles",
            function="get_roles_api",
            op_modifies=True,
        )
        self.log(
            "Received API response from get_roles_api: {0}".format(str(response)),
            "DEBUG",
        )
        return response

    def add_entries(self, entry_types, operations, unique_types):
        """Add multiple entries with specified operations to the unique_types dictionary."""
        for entry_type in entry_types:
            new_entry = {"type": entry_type, "operations": operations}
            unique_types[new_entry["type"]] = new_entry
            self.log("Added entry: {0}".format(new_entry), "DEBUG")

    def process_assurance_rules(self, role_config, role_operation, unique_types):
        """
        Process the assurance rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing assurance rules.
            - role_operation (str): The operation type (e.g., "update").
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """
        entry_types = [
            "Assurance.Monitoring and Troubleshooting",
            "Assurance.Monitoring Settings",
            "Assurance.Troubleshooting Tools",
        ]

        # Determine if default entries should be added based on role_operation
        if role_operation == "create":
            self.log(
                "Role operation is 'create'. Adding default assurance entries.", "DEBUG"
            )
            self.add_entries(entry_types, ["gRead"], unique_types)
        else:
            self.log(
                "Role operation is not 'create'. Skipping default assurance entries.",
                "DEBUG",
            )

        if role_config["assurance"] is None:
            return {}

        self.log("Processing assurance rules.", "INFO")

        # Process each assurance rule
        for assurance_rule in role_config["assurance"]:
            for resource_name, permission in assurance_rule.items():
                if permission is None:
                    self.log(
                        "Skipping resource {0} because permission is None".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                permission = permission.lower()

                if permission not in ["read", "write", "deny"]:
                    error_message = "Invalid permission '{0}' for assurance resource '{1}' under the role '{2}'".format(
                        permission, resource_name, self.have.get("role_name")
                    )
                    self.log(error_message, "DEBUG")
                    return {"error_message": error_message}

                if permission == "deny":
                    self.log(
                        "Skipping resource {0} because permission is 'deny'".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                operations = self.convert_permission_to_operations(permission)
                self.log(
                    "Converted permission {0} to operations {1}".format(
                        permission, operations
                    ),
                    "DEBUG",
                )

                if resource_name == "overall":
                    self.add_entries(entry_types, operations, unique_types)
                elif resource_name == "monitoring_and_troubleshooting":
                    new_entry = {
                        "type": "Assurance.Monitoring and Troubleshooting",
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for 'monitoring_and_troubleshooting': {0}".format(
                            new_entry
                        ),
                        "DEBUG",
                    )
                else:
                    new_entry = {
                        "type": "Assurance.{0}".format(
                            resource_name.replace("_", " ").title()
                        ),
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for resource {0}: {1}".format(
                            resource_name, new_entry
                        ),
                        "DEBUG",
                    )
        return {}

    def process_network_analytics_rules(
        self, role_config, role_operation, unique_types
    ):
        """
        Process the network analytics rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing network analytics rules.
            - role_operation (str): The operation type (e.g., "update").
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """
        entry_types = {"type": "Network Analytics.Data Access", "operations": ["gRead"]}

        # Determine if default entries should be added based on role_operation
        if role_operation == "create":
            self.log(
                "Role operation is 'create'. Adding default network analytics entries.",
                "DEBUG",
            )
            unique_types[entry_types["type"]] = entry_types
        else:
            self.log(
                "Role operation is not 'create'. Skipping default network analytics entries.",
                "DEBUG",
            )

        if role_config["network_analytics"] is None:
            return {}

        self.log("Processing network analytics rules.", "INFO")

        # Process each network analytics rule
        for network_analytics_rule in role_config["network_analytics"]:
            for resource_name, permission in network_analytics_rule.items():
                if permission is None:
                    self.log(
                        "Skipping resource {0} because permission is None".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                permission = permission.lower()

                if permission not in ["read", "write", "deny"]:
                    error_message = "Invalid permission '{0}' for network analytics resource '{1}' under the role '{2}'".format(
                        permission, resource_name, self.have.get("role_name")
                    )
                    self.log(error_message, "DEBUG")
                    return {"error_message": error_message}

                if permission == "deny":
                    self.log(
                        "Skipping resource {0} because permission is 'deny'".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                operations = self.convert_permission_to_operations(permission)
                self.log(
                    "Converted permission {0} to operations {1}".format(
                        permission, operations
                    ),
                    "DEBUG",
                )

                if resource_name == "overall" or resource_name == "data_access":
                    new_entry = {

                        "type": "Network Analytics.Data Access",
                        "operations": operations
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for resource {0}: {1}".format(
                            resource_name, new_entry
                        ),
                        "DEBUG",
                    )
        return {}

    def process_network_design_rules(self, role_config, role_operation, unique_types):
        """
        Process the network design rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing network design rules.
            - role_operation (str): The operation type (e.g., "update").
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """
        entry_types = [
            "Network Design.Advanced Network Settings",
            "Network Design.Image Repository",
            "Network Design.Network Hierarchy",
            "Network Design.Network Profiles",
            "Network Design.Network Settings",
            "Network Design.Virtual Network",
        ]

        # Determine if default entries should be added based on role_operation
        if role_operation == "create":
            self.log(
                "Role operation is 'create'. Adding default network design entries.",
                "DEBUG",
            )
            self.add_entries(entry_types, ["gRead"], unique_types)
        else:
            self.log(
                "Role operation is not 'create'. Skipping default network design entries.",
                "DEBUG",
            )

        if role_config["network_design"] is None:
            return {}

        self.log("Processing network design rules.", "INFO")

        # Process each network design rule
        for network_design_rule in role_config["network_design"]:
            for resource_name, permission in network_design_rule.items():
                if permission is None:
                    self.log(
                        "Skipping resource {0} because permission is None".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                permission = permission.lower()

                if permission not in ["read", "write", "deny"]:
                    error_message = "Invalid permission '{0}' for network design resource '{1}' under the role '{2}'".format(
                        permission, resource_name, self.have.get("role_name")
                    )
                    self.log(error_message, "DEBUG")
                    return {"error_message": error_message}

                if permission == "deny":
                    self.log(
                        "Skipping resource {0} because permission is 'deny'".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                operations = self.convert_permission_to_operations(permission)
                self.log(
                    "Converted permission {0} to operations {1}".format(
                        permission, operations
                    ),
                    "DEBUG",
                )

                if resource_name == "overall":
                    self.add_entries(entry_types, operations, unique_types)
                else:
                    new_entry = {
                        "type": "Network Design.{0}".format(
                            resource_name.replace("_", " ").title()
                        ),
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for resource {0}: {1}".format(
                            resource_name, new_entry
                        ),
                        "DEBUG",
                    )
        return {}

    def process_network_provision_rules(
        self, role_config, role_operation, unique_types
    ):
        """
        Process the network provision rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing network provision rules.
            - role_operation (str): The operation type (e.g., "update").
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """
        entry_types = [
            "Network Provision.Compliance",
            "Network Provision.EoX",
            "Network Provision.Image Update",
            "Network Provision.Inventory Management.Device Configuration",
            "Network Provision.Inventory Management.Discovery",
            "Network Provision.Inventory Management.Network Device",
            "Network Provision.Inventory Management.Port Management",
            "Network Provision.Inventory Management.Topology",
            "Network Provision.License",
            "Network Provision.Network Telemetry",
            "Network Provision.PnP",
            "Network Provision.Provision",
        ]

        # Determine if default entries should be added based on role_operation
        if role_operation == "create":
            self.log(
                "Role operation is 'create'. Adding default network provision entries.",
                "DEBUG",
            )
            self.add_entries(entry_types, ["gRead"], unique_types)
        else:
            self.log(
                "Role operation is not 'create'. Skipping default network provision entries.",
                "DEBUG",
            )

        if role_config["network_provision"] is None:
            return {}

        self.log("Processing network provision rules.", "INFO")

        # Process each network provision rule
        if not isinstance(role_config["network_provision"], list):
            error_message = "The given network_provision is not in type: list"
            self.log(error_message, "DEBUG")
            return {"error_message": error_message}

        for provision in role_config["network_provision"]:
            for resource_name, permission in provision.items():
                if isinstance(permission, list):
                    # Handle nested inventory_management
                    for sub_resource_name, sub_permission in permission[0].items():
                        if sub_permission is None:
                            self.log(
                                "Skipping sub-resource {0} because permission is None".format(
                                    sub_resource_name
                                ),
                                "DEBUG",
                            )
                            continue

                        sub_permission = sub_permission.lower()

                        if sub_permission not in ["read", "write", "deny"]:
                            error_message = "Invalid permission '{0}' for network provision for sub-resource '{1}' under the role '{2}'".format(
                                sub_permission,
                                sub_resource_name,
                                self.have.get("role_name"),
                            )
                            self.log(error_message, "DEBUG")
                            return {"error_message": error_message}

                        if sub_permission == "deny":
                            self.log(
                                "Skipping sub-resource {0} because permission is 'deny'".format(
                                    sub_resource_name
                                ),
                                "DEBUG",
                            )
                            continue

                        operations = self.convert_permission_to_operations(
                            sub_permission
                        )
                        self.log(
                            "Converted sub-permission {0} to operations {1}".format(
                                sub_permission, operations
                            ),
                            "DEBUG",
                        )

                        if sub_resource_name == "overall":
                            overall_entry_types = [
                                "Network Provision.Inventory Management.Device Configuration",
                                "Network Provision.Inventory Management.Discovery",
                                "Network Provision.Inventory Management.Network Device",
                                "Network Provision.Inventory Management.Port Management",
                                "Network Provision.Inventory Management.Topology",
                            ]
                            self.add_entries(
                                overall_entry_types, operations, unique_types
                            )
                        else:
                            new_entry = {
                                "type": "Network Provision.{0}.{1}".format(
                                    resource_name.replace("_", " ").title(),
                                    sub_resource_name.replace("_", " ").title(),
                                ),
                                "operations": operations,
                            }
                            unique_types[new_entry["type"]] = new_entry
                            self.log(
                                "Added entry for resource {0}: {1}".format(
                                    sub_resource_name, new_entry
                                ),
                                "DEBUG",
                            )
                else:
                    if permission is None:
                        self.log(
                            "Skipping resource {0} because permission is None".format(
                                resource_name
                            ),
                            "DEBUG",
                        )
                        continue

                    permission = permission.lower()

                    if permission not in ["read", "write", "deny"]:
                        error_message = "Invalid permission '{0}' for network provision resource '{1}' under the role '{2}'".format(
                            permission, resource_name, self.have.get("role_name")
                        )
                        self.log(error_message, "DEBUG")
                        return {"error_message": error_message}

                    if permission == "deny":
                        self.log(
                            "Skipping resource {0} because permission is 'deny'".format(
                                resource_name
                            ),
                            "DEBUG",
                        )
                        continue

                    operations = self.convert_permission_to_operations(permission)
                    self.log(
                        "Converted permission {0} to operations {1}".format(
                            permission, operations
                        ),
                        "DEBUG",
                    )

                    if resource_name == "overall":
                        self.add_entries(entry_types, operations, unique_types)
                    elif resource_name == "eox":
                        new_entry = {
                            "type": "Network Provision.EoX",
                            "operations": operations,
                        }
                        unique_types[new_entry["type"]] = new_entry
                        self.log(
                            "Added entry for 'eox': {0}".format(new_entry), "DEBUG"
                        )
                    elif resource_name == "pnp":
                        new_entry = {
                            "type": "Network Provision.PnP",
                            "operations": operations,
                        }
                        unique_types[new_entry["type"]] = new_entry
                        self.log(
                            "Added entry for 'pnp': {0}".format(new_entry), "DEBUG"
                        )
                    else:
                        new_entry = {
                            "type": "Network Provision.{0}".format(
                                resource_name.replace("_", " ").title()
                            ),
                            "operations": operations,
                        }
                        unique_types[new_entry["type"]] = new_entry
                        self.log(
                            "Added entry for resource {0}: {1}".format(
                                resource_name, new_entry
                            ),
                            "DEBUG",
                        )
        return {}

    def process_network_services_rules(self, role_config, role_operation, unique_types):
        """
        Process the network services rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing network services rules.
            - role_operation (str): The operation type (e.g., "update").
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """
        entry_types = [
            "Network Services.App Hosting",
            "Network Services.Bonjour",
            "Network Services.Stealthwatch",
            "Network Services.Umbrella",
        ]

        # Determine if default entries should be added based on role_operation
        if role_operation == "create":
            self.log(
                "Role operation is 'create'. Adding default network services entries.",
                "DEBUG",
            )
            self.add_entries(entry_types, ["gRead"], unique_types)
        else:
            self.log(
                "Role operation is not 'create'. Skipping default network services entries.",
                "DEBUG",
            )

        if role_config["network_services"] is None:
            return {}

        self.log("Processing network services rules.", "INFO")

        # Process each network service rule
        for services_rule in role_config["network_services"]:
            for resource_name, permission in services_rule.items():
                if permission is None:
                    self.log(
                        "Skipping resource {0} because permission is None".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                permission = permission.lower()

                if permission not in ["read", "write", "deny"]:
                    error_message = "Invalid permission '{0}' for network services resource '{1}' under the role '{2}'".format(
                        permission, resource_name, self.have.get("role_name")
                    )
                    self.log(error_message, "DEBUG")
                    return {"error_message": error_message}

                if permission == "deny":
                    self.log(
                        "Skipping resource {0} because permission is 'deny'".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                operations = self.convert_permission_to_operations(permission)
                self.log(
                    "Converted permission {0} to operations {1}".format(
                        permission, operations
                    ),
                    "DEBUG",
                )

                if resource_name == "overall":
                    self.add_entries(entry_types, operations, unique_types)
                else:
                    new_entry = {
                        "type": "Network Services.{0}".format(
                            resource_name.replace("_", " ").title()
                        ),
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for resource {0}: {1}".format(
                            resource_name, new_entry
                        ),
                        "DEBUG",
                    )
        return {}

    def process_platform_rules(self, role_config, unique_types):
        """
        Process the platform rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing platform rules.
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """

        if role_config["platform"] is None:
            return {}

        self.log("Processing platform rules.", "INFO")

        # Process each platform rule
        for platform_rule in role_config["platform"]:
            for resource_name, permission in platform_rule.items():
                if permission is None:
                    self.log(
                        "Skipping resource {0} because permission is None".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                permission = permission.lower()

                if permission not in ["read", "write", "deny"]:
                    error_message = "Invalid permission '{0}' for platform resource '{1}' under the role '{2}'".format(
                        permission, resource_name, self.have.get("role_name")
                    )
                    self.log(error_message, "DEBUG")
                    return {"error_message": error_message}

                if permission == "deny":
                    self.log(
                        "Skipping resource {0} because permission is 'deny'".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                operations = self.convert_permission_to_operations(permission)
                self.log(
                    "Converted permission {0} to operations {1}".format(
                        permission, operations
                    ),
                    "DEBUG",
                )

                if resource_name == "overall":
                    overall_entry_types = [
                        "Platform.APIs",
                        "Platform.Bundles",
                        "Platform.Events",
                        "Platform.Reports",
                    ]
                    self.add_entries(overall_entry_types, operations, unique_types)
                elif resource_name == "apis":
                    new_entry = {"type": "Platform.APIs", "operations": operations}
                    unique_types[new_entry["type"]] = new_entry
                    self.log("Added entry for 'apis': {0}".format(new_entry), "DEBUG")
                else:
                    new_entry = {
                        "type": "Platform.{0}".format(
                            resource_name.replace("_", " ").title()
                        ),
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for resource {0}: {1}".format(
                            resource_name, new_entry
                        ),
                        "DEBUG",
                    )
        return {}

    def process_security_rules(self, role_config, role_operation, unique_types):
        """
        Process the security rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing security rules.
            - role_operation (str): The operation type (e.g., "update").
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """
        entry_types = [
            "Security.Group-Based Policy",
            "Security.IP Based Access Control",
            "Security.Security Advisories",
        ]

        # Determine if default entries should be added based on role_operation
        if role_operation == "create":
            self.log(
                "Role operation is 'create'. Adding default security entries.", "DEBUG"
            )
            self.add_entries(entry_types, ["gRead"], unique_types)
        else:
            self.log(
                "Role operation is not 'create'. Skipping default security entries.",
                "DEBUG",
            )

        if role_config["security"] is None:
            return {}

        self.log("Processing security rules.", "INFO")

        # Process each security rule
        for security_rule in role_config["security"]:
            for resource_name, permission in security_rule.items():
                if permission is None:
                    self.log(
                        "Skipping resource {0} because permission is None".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                permission = permission.lower()

                if permission not in ["read", "write", "deny"]:
                    error_message = "Invalid permission '{0}' for security resource '{1}' under the role '{2}'".format(
                        permission, resource_name, self.have.get("role_name")
                    )
                    self.log(error_message, "DEBUG")
                    return {"error_message": error_message}

                if permission == "deny":
                    self.log(
                        "Skipping resource {0} because permission is 'deny'".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                operations = self.convert_permission_to_operations(permission)
                self.log(
                    "Converted permission {0} to operations {1}".format(
                        permission, operations
                    ),
                    "DEBUG",
                )

                if resource_name == "overall":
                    self.add_entries(entry_types, operations, unique_types)
                elif resource_name == "ip_based_access_control":
                    new_entry = {
                        "type": "Security.IP Based Access Control",
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for 'ip_based_access_control': {0}".format(
                            new_entry
                        ),
                        "DEBUG",
                    )
                elif resource_name == "group_based_policy":
                    new_entry = {
                        "type": "Security.Group-Based Policy",
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for 'group_based_policy': {0}".format(new_entry),
                        "DEBUG",
                    )
                else:
                    new_entry = {
                        "type": "Security.{0}".format(
                            resource_name.replace("_", " ").title()
                        ),
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for resource {0}: {1}".format(
                            resource_name, new_entry
                        ),
                        "DEBUG",
                    )
        return {}

    def process_system_rules(self, role_config, role_operation, unique_types):
        """
        Process the system rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing system rules.
            - role_operation (str): The operation type (e.g., "update").
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """
        entry_types = ["System.Machine Reasoning", "System.System Management"]

        # Determine if default entries should be added based on role_operation
        if role_operation == "create":
            self.log(
                "Role operation is 'create'. Adding default system entries.", "DEBUG"
            )
            self.add_entries(entry_types, ["gRead"], unique_types)
            new_entry = {
                "type": "System.Basic",
                "operations": ["gRead", "gUpdate", "gCreate", "gRemove"]
            }
            unique_types[new_entry["type"]] = new_entry
            self.log("Added entry for resource basic: {0}".format(new_entry), "DEBUG")
        else:
            self.log(
                "Role operation is not 'create'. Skipping default system entries.",
                "DEBUG",
            )

        if role_config["system"] is None:
            return {}

        self.log("Processing system rules.", "INFO")

        # Process each system rule
        for system_rule in role_config["system"]:
            for resource_name, permission in system_rule.items():
                if permission is None:
                    self.log(
                        "Skipping resource {0} because permission is None".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                permission = permission.lower()

                if permission not in ["read", "write", "deny"]:
                    error_message = "Invalid permission '{0}' for system resource '{1}' under the role '{2}'".format(
                        permission, resource_name, self.have.get("role_name")
                    )
                    self.log(error_message, "DEBUG")
                    return {"error_message": error_message}

                if permission == "deny":
                    self.log(
                        "Skipping resource {0} because permission is 'deny'".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                operations = self.convert_permission_to_operations(permission)
                self.log(
                    "Converted permission {0} to operations {1}".format(
                        permission, operations
                    ),
                    "DEBUG",
                )

                if resource_name == "overall":
                    self.add_entries(entry_types, operations, unique_types)
                else:
                    new_entry = {
                        "type": "System.{0}".format(
                            resource_name.replace("_", " ").title()
                        ),
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for resource {0}: {1}".format(
                            resource_name, new_entry
                        ),
                        "DEBUG",
                    )
        return {}

    def process_utilities_rules(self, role_config, role_operation, unique_types):
        """
        Process the utilities rules and update the unique_types dictionary with the corresponding operations.
        Parameters:
            - role_config (dict): The role configuration containing utilities rules.
            - role_operation (str): The operation type (e.g., "update").
            - unique_types (dict): A dictionary to store the unique resource types and their operations.
        """
        # Determine if default entries should be added based on role_operation
        if role_operation == "create":
            self.log(
                "Role operation is 'create'. Adding default utilities entries.", "DEBUG"
            )
            default_entry_types = [
                "Utilities.Event Viewer",
                "Utilities.Network Reasoner",
                "Utilities.Search",
            ]
            self.add_entries(default_entry_types, ["gRead"], unique_types)
            new_entry1 = {
                "type": "Utilities.Scheduler",
                "operations": ["gRead", "gUpdate", "gCreate", "gRemove"],
            }
            unique_types[new_entry1["type"]] = new_entry1

        else:
            self.log(
                "Role operation is not 'create'. Skipping default utilities entries.",
                "DEBUG",
            )

        if role_config["utilities"] is None:
            return {}

        self.log("Processing utilities rules.", "INFO")

        # Process each utilities rule
        for utilities_rule in role_config["utilities"]:
            for resource_name, permission in utilities_rule.items():
                if permission is None:
                    self.log(
                        "Skipping resource {0} because permission is None".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                permission = permission.lower()

                if permission not in ["read", "write", "deny"]:
                    error_message = "Invalid permission '{0}' for utilities resource '{1}' under the role '{2}'".format(
                        permission, resource_name, self.have.get("role_name")
                    )
                    self.log(error_message, "DEBUG")
                    return {"error_message": error_message}

                if permission == "deny":
                    self.log(
                        "Skipping resource {0} because permission is 'deny'".format(
                            resource_name
                        ),
                        "DEBUG",
                    )
                    continue

                operations = self.convert_permission_to_operations(permission)
                self.log(
                    "Converted permission {0} to operations {1}".format(
                        permission, operations
                    ),
                    "DEBUG",
                )

                if resource_name == "overall":
                    overall_entry_types = [
                        "Utilities.Event Viewer",
                        "Utilities.Network Reasoner",
                        "Utilities.Search",
                        "Utilities.Audit Log",
                        "Utilities.Remote Device Support",
                        "Utilities.Scheduler",
                    ]
                    self.add_entries(overall_entry_types, operations, unique_types)
                else:
                    new_entry = {
                        "type": "Utilities.{0}".format(
                            resource_name.replace("_", " ").title()
                        ),
                        "operations": operations,
                    }
                    unique_types[new_entry["type"]] = new_entry
                    self.log(
                        "Added entry for resource {0}: {1}".format(
                            resource_name, new_entry
                        ),
                        "DEBUG",
                    )
        return {}

    def generate_role_payload(self, role_config, role_operation):
        """
        Generate a role payload for Cisco Catalyst Center.

        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - role_config (dict): A dictionary containing the configuration for the role.

        Returns:
            - payload (dict): A dictionary containing the payload for the role with processed resource types and operations.

        Description:
            - Generates a payload for a role based on the given role configuration.
            - Processes various sections of the role configuration, such as assurance, network analytics,
            network design, network provision, network services, platform, security, system, and utilities.
            - Validates permissions and converts them to corresponding operations using the convert_permission_to_operations method.
            - If the permission is valid and not set to "deny", constructs a resource type entry with operations and appends it to resource_types.
            - The final payload includes the role name, description, and the list of resource types with operations.
        """
        self.log("Starting payload generation for role...", "INFO")

        # Extract role name and description from the configuration
        role_name = role_config.get("role_name", "")
        description = role_config.get("description", "")
        unique_types = {}

        # List of functions to process each section of role configuration
        processing_functions = [
            self.process_assurance_rules,
            self.process_network_analytics_rules,
            self.process_network_design_rules,
            self.process_network_provision_rules,
            self.process_network_services_rules,
            self.process_platform_rules,
            self.process_security_rules,
            self.process_system_rules,
            self.process_utilities_rules,
        ]

        # Process each section and check for errors
        for process_func in processing_functions:
            func_name = process_func.__name__
            self.log("Processing with {0}...".format(func_name), "DEBUG")
            if func_name in "process_platform_rules":
                function_response = process_func(role_config, unique_types)
            else:
                function_response = process_func(
                    role_config, role_operation, unique_types
                )
            if function_response:
                self.log(
                    "Error occurred in {0}: {1}".format(func_name, function_response),
                    "DEBUG",
                )
                return function_response

        # Construct the final payload
        resource_types_list = list(unique_types.values())
        self.log("Generated resource types: {0}".format(resource_types_list), "DEBUG")
        payload = {
            "role": role_name,
            "description": description,
            "resourceTypes": resource_types_list,
        }
        self.log("Generated payload: {0}".format(payload), "DEBUG")

        return payload

    def convert_permission_to_operations(self, permission):
        """
        Convert a permission string to a list of operations.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - permission (str): A string representing the permission level (e.g., "read" or "write").
        Returns:
            - list: A list of strings representing operations associated with the given permission level.
                    Returns None if the permission level is not recognized.
        Description:
            - This method converts a permission string to a corresponding list of operations.
            - For "read" or "Read" permissions, it returns a list containing "gRead".
            - For "write" or "Write" permissions, it returns a list containing "gRead", "gUpdate", "gCreate", and "gRemove".
            - If the permission level is not recognized, it returns None.
        """
        if permission == "read":
            return ["gRead"]
        elif permission == "write":
            return ["gRead", "gUpdate", "gCreate", "gRemove"]

    def role_requires_update(self, current_role, desired_role):
        """
        Check if the role requires updates and save parameters to update.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - current_role (dict): Dictionary containing current role information.
            - desired_role (dict): Dictionary containing desired role information.
        Returns:
            - bool: True if the role requires updates, False otherwise.
            - updated_get_have (dict): Updated dictionary with parameters that need to be updated.
        Description:
            - This method checks if the current role information needs to be updated based on the desired role information.
            - It compares the resource types and operations between current_role and desired_role.
            - If any resource type is not found in current_role but exists in desired_role, it adds it to current_role.
            - Removes denied operations based on denied permissions found in self.want.
            - Returns values indicating whether updates are required and the updated role information.
        """
        self.log("Starting role comparison for updates...", "INFO")
        update_required = False
        update_role_params = {}

        for want_resource in desired_role["resourceTypes"]:
            resource_found = False
            for have_resource in current_role["resource_types"]:
                if have_resource["type"] == want_resource["type"]:
                    resource_found = True
                    if have_resource["operations"] != want_resource["operations"]:
                        self.log(
                            "Updating operations for resource type {0}.".format(
                                want_resource["type"]
                            ),
                            "DEBUG",
                        )
                        have_resource["operations"] = want_resource["operations"]
                        update_required = True
                    break
            if not resource_found:
                self.log(
                    "Adding new resource type {0} to current role.".format(
                        want_resource["type"]
                    ),
                    "DEBUG",
                )
                current_role["resource_types"].append(want_resource)
                update_required = True

        # Compare and update first name
        desired_description = desired_role.get("description")
        current_description = current_role.get("description")
        if desired_description is not None:
            if current_description != desired_description:
                self.log(
                    "Updating description from {0} to {1}.".format(
                        current_description, desired_description
                    ),
                    "DEBUG",
                )
                update_role_params["description"] = desired_description
                update_required = True
            elif "description" not in update_role_params:
                update_role_params["description"] = current_description
        else:
            update_role_params["description"] = current_description

        # Create the updated dictionary
        updated_get_have = {
            "roleId": current_role["role_id"],
            "description": update_role_params["description"],
            "resourceTypes": current_role["resource_types"],
        }

        self.log("Calling get_permissions to filter permissions...", "DEBUG")
        filtered_data, overall_update_required = self.get_permissions(
            self.want, updated_get_have, "update"
        )

        self.log("Finding denied permissions...", "DEBUG")
        denied_permissions = self.find_denied_permissions(self.want)
        denied_update_required, updated_get_have = self.remove_denied_operations(
            filtered_data, denied_permissions
        )

        if update_required or denied_update_required or overall_update_required:
            self.log("Role update required. Changes detected.", "DEBUG")
            return True, updated_get_have

        self.log("No updates required for the role.", "DEBUG")
        return False, updated_get_have

    def user_requires_update(self, current_user, current_role):
        """
        Check if the user requires updates and save parameters to update.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - current_user (dict): Dictionary containing current user information.
            - current_role (dict): Dictionary containing role mappings.
        Returns:
            - bool: True if the user requires updates, False otherwise.
            - update_user_params (dict): Dictionary containing parameters that need to be updated.
        Description:
            - This method checks if the current user information needs to be updated based on the desired user information.
            - It compares specific fields such as "first_name", "last_name", "email", "username", and "role_list".
            - If any of these fields differ between current_user and self.want, update_user_params is populated with the desired values.
            - Returns values indicating whether updates are required and the parameters to update if so.
        """
        update_needed = False
        update_user_params = {}

        # Compare and update first name
        desired_first_name = self.want.get("first_name")
        current_first_name = current_user.get("first_name")
        if desired_first_name is not None:
            if current_first_name != desired_first_name:
                self.log(
                    "Updating first name from {0} to {1}.".format(
                        current_first_name, desired_first_name
                    ),
                    "DEBUG",
                )
                update_user_params["first_name"] = desired_first_name
                update_needed = True
            elif "first_name" not in update_user_params:
                update_user_params["first_name"] = current_first_name
        else:
            update_user_params["first_name"] = current_first_name

        # Compare and update last name
        desired_last_name = self.want.get("last_name")
        current_last_name = current_user.get("last_name")
        if desired_last_name is not None:
            if current_last_name != desired_last_name:
                self.log(
                    "Updating last name from {0} to {1}.".format(
                        current_last_name, desired_last_name
                    ),
                    "DEBUG",
                )
                update_user_params["last_name"] = desired_last_name
                update_needed = True
            elif "last_name" not in update_user_params:
                update_user_params["last_name"] = current_last_name
        else:
            update_user_params["last_name"] = current_last_name

        # Compare and update username
        desired_username = self.want.get("username").lower()
        current_username = current_user.get("username").lower()
        if desired_username is not None:
            if current_username != desired_username:
                self.log(
                    "Username for an existing User cannot be updated from {0} to {1}.".format(
                        current_username, desired_username
                    ),
                    "DEBUG",
                )
                update_user_params["username"] = desired_username
                update_needed = True
            elif "username" not in update_user_params:
                update_user_params["username"] = current_username
        else:
            update_user_params["username"] = current_username

        # Compare and update email
        desired_email = self.want.get("email")
        current_email = current_user.get("email")
        if desired_email is not None:
            if current_email != desired_email:
                self.log(
                    "Updating email from {0} to {1}.".format(
                        current_email, desired_email
                    ),
                    "DEBUG",
                )
                update_user_params["email"] = desired_email
                update_needed = True
            elif "email" not in update_user_params:
                update_user_params["email"] = current_email
        else:
            update_user_params["email"] = current_email

        # Compare and update role list
        desired_role_list = self.want.get("role_list")
        current_role_list = current_user.get("role_list", [])
        if desired_role_list is not None:
            desired_role_name = desired_role_list[0].lower()
            if desired_role_name in current_role:
                role_id = current_role[desired_role_name]
                if current_role_list[0] != role_id:
                    self.log(
                        "Updating role list with new role ID {0}.".format(role_id),
                        "DEBUG",
                    )
                    update_user_params["role_list"] = [role_id]
                    update_needed = True
                else:
                    update_user_params["role_list"] = current_role_list
            else:
                self.log(
                    "Role {0} not found in current_role. Setting role list to empty.".format(
                        desired_role_name
                    ),
                    "DEBUG",
                )
                update_user_params["role_list"] = []
                update_needed = True
        else:
            update_user_params["role_list"] = current_role_list

        self.log("User update parameters: {0}".format(update_user_params), "DEBUG")

        return update_needed, update_user_params

    def update_user(self, user_params):
        """
        Update a user in Cisco Catalyst Center with the provided parameters.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - user_params (dict): A dictionary containing user information.
        Returns:
            - response (dict): The API response from the "update_user" function.
        Description:
            - This method sends a request to update a user in Cisco Catalyst Center using the provided
            - user parameters. It logs the response and returns it.
        """
        try:
            self.log("Updating user with parameters: {0}".format(user_params), "DEBUG")
            response = self.dnac._exec(
                family="user_and_roles",
                function="update_user_api",
                op_modifies=True,
                params=user_params,
            )
            self.log(
                "Received API response from update_user: {0}".format(str(response)),
                "DEBUG",
            )
            self.updated_user.append(user_params.get("username"))
            return response

        except Exception as e:
            self.log("Unexpected error occurred: {0}".format(str(e)), "ERROR")
            error_message = (
                "Invalid email format for email '{0}' under username '{1}'".format(
                    user_params.get("email"), user_params.get("username")
                )
            )
            return {"error_message": error_message}

    def update_role(self, role_params):
        """
        Update a role in Cisco Catalyst Center with the provided parameters.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - role_params (dict): A dictionary containing role information.
        Returns:
            - response (dict): The API response from the "update_role" function.
        Description:
            - This method sends a request to update a role in Cisco Catalyst Center using the provided
              role parameters. It first logs the role parameters at the "DEBUG" level. Then it calls the"_exec" method
              of the "dnac" object to perform the API request. The API request is specified with the "user_and_roles" family
              and the "update_role_api" function. The method logs the received API response at the "DEBUG" level and
              finally returns the response.
        """

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            try:
                self.log(
                    "Updating role with role_info_params: {0}".format(str(role_params)),
                    "DEBUG",
                )
                response = self.dnac._exec(
                    family="user_and_roles",
                    function="update_role_api",
                    op_modifies=True,
                    params=role_params,
                )
                self.log(
                    "Received API response from update_role: {0}".format(str(response)),
                    "DEBUG",
                )
                self.updated_role.append(self.have.get("role_name"))
                return response

            except Exception as e:
                self.log("Unexpected error occurred: {0}".format(str(e)), "ERROR")
                error_message = "The catalyst center user '{0}' does not have the necessary permissions to update role through the API.".format(
                    self.payload.get("dnac_username")
                )
                return {"error_message": error_message}

        error_message = "The specified version '{0}' does not have the 'update_role_api' functionality. Supported version(s) from '2.3.7.6' onwards.".format(
            self.payload.get("dnac_version")
        )
        return {"error_message": error_message}

    def find_denied_permissions(self, config, parent_key=""):
        """
        Find all permissions set to "deny" in a configuration structure.
        Parameters:
            - config (dict or list): The configuration structure to search, which can be a nested dictionary or list.
            - parent_key (str): The key path leading to the current position in the configuration (used for nested structures).
        Returns:
            - denied_permissions (list): A list of keys representing paths in the configuration that have "deny" as their value.
        Description:
            - This function recursively searches through a given configuration structure, which can be a dictionary or a list,
              to find all occurrences of the string "deny". It constructs and returns a list of key paths where "deny" is found.
              The key paths are formed by combining parent keys with the current keys or indices, providing a clear path
              to the denied permissions within the nested structure.
        """
        denied_permissions = []

        if isinstance(config, dict):
            self.log(
                "Processing dictionary with parent_key: {0}".format(parent_key), "DEBUG"
            )

            for key, value in config.items():
                if parent_key:
                    full_key = "{0}.{1}".format(parent_key, key)
                else:
                    full_key = key
                self.log("Checking key: {0}".format(full_key), "DEBUG")

                if isinstance(value, dict) or isinstance(value, list):
                    denied_permissions.extend(
                        self.find_denied_permissions(value, full_key)
                    )
                elif isinstance(value, str) and value.lower() == "deny":
                    denied_permissions.append(full_key)
                self.log("Found 'deny' at key: {0}".format(full_key), "DEBUG")

        elif isinstance(config, list):
            for index, item in enumerate(config):
                full_key = "{0}[{1}]".format(parent_key, index)
                self.log(
                    "Processing list with parent_key: {0}".format(parent_key), "DEBUG"
                )

                if isinstance(item, dict):
                    denied_permissions.extend(
                        self.find_denied_permissions(item, full_key)
                    )
                self.log("Found 'deny' at index: {0}".format(full_key), "DEBUG")

        self.log("Denied permissions are {0}".format(str(denied_permissions)), "DEBUG")
        return denied_permissions

    def remove_denied_operations(self, input_data, denied_permissions):
        """
        Remove denied operations from the input data based on the provided denied permissions.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - input_data (dict): Input data containing resource types that may include denied operations.
            - denied_permissions (list): A list of denied permissions to be removed from input_data.
        Returns:
            - update_required (bool): True if any denied operations were removed, otherwise False.
            - updated_input_data (dict): Input data with denied operations removed.
        Description:
            - This method filters out denied operations from the resource types in the input_data based on the provided denied_permissions.
            - It checks each resource type against the denied permissions to determine if it should be kept or removed.
            - If a resource type matches any of the denied permissions, it is excluded from the updated input_data.
            - The method returns values indicating whether any updates were made (update_required) and the updated input_data.
        """
        self.log("Starting removal of denied operations.", "INFO")
        resource_types = input_data["resourceTypes"]
        remaining_resource_types = []
        update_required = False

        for resource in resource_types:
            keep_resource = True
            resource_type_lower = resource["type"].lower()
            for denied in denied_permissions:
                denied_type_lower = (
                    denied.split(".")[-1].replace("_", " ").replace("[0]", "").lower()
                )

                if denied_type_lower == "network settings":
                    denied_type_lower = "network design.network settings"
                    if denied_type_lower in resource_type_lower:
                        keep_resource = False
                        self.log(
                            "Removing resource due to denied type: {0}".format(
                                denied_type_lower
                            ),
                            "DEBUG",
                        )
                        update_required = True
                        break

                elif denied_type_lower == "provision":
                    denied_type_lower = "network provision.provision"
                    if denied_type_lower in resource_type_lower:
                        keep_resource = False
                        self.log(
                            "Removing resource due to denied type: {0}".format(
                                denied_type_lower
                            ),
                            "DEBUG",
                        )
                        update_required = True
                        break

                elif denied_type_lower == "group based policy":
                    denied_type_lower = "security.group-based policy"
                    if denied_type_lower in resource_type_lower:
                        keep_resource = False
                        self.log(
                            "Removing resource due to denied type: {0}".format(
                                denied_type_lower
                            ),
                            "DEBUG",
                        )
                        update_required = True
                        break

                else:
                    if denied_type_lower in resource_type_lower:
                        keep_resource = False
                        self.log(
                            "Removing resource due to denied type: {0}".format(
                                denied_type_lower
                            ),
                            "DEBUG",
                        )
                        update_required = True
                        break

            if keep_resource:
                remaining_resource_types.append(resource)

        input_data["resourceTypes"] = remaining_resource_types
        self.log(
            "Removal complete. Update required: {0}".format(update_required), "DEBUG"
        )

        return update_required, input_data

    def parse_config(self, config_section):
        """
        Parse the given configuration section into a structured dictionary.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config_section (dict): A dictionary containing a section of the configuration to be parsed.
        Returns:
            - parsed_config (dict): A dictionary containing the parsed configuration details.
        Description:
            - This method iterates through the provided configuration section and processes each key-value pair.
            - If the value is None, it assigns an empty dictionary to the corresponding key in the parsed configuration.
            - If the value is a non-empty list, it recursively parses the first element of the list.
            - Otherwise, it directly assigns the value to the corresponding key in the parsed configuration.
            - The resulting dictionary represents the structured configuration details.
        """
        parsed_config = {}
        for key, value in config_section.items():
            if value is None:
                parsed_config[key] = {}
            elif isinstance(value, list) and value:
                parsed_config[key] = self.parse_config(value[0])
            else:
                parsed_config[key] = value
        return parsed_config

    def check_permission(self, permissions, resource_type):
        """
        Check if a given resource type has permissions denied or allowed based on the provided permissions.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - permissions (dict): A dictionary containing permission details for various resource types.
            - resource_type (str): A string specifying the resource type for which permissions are being checked.
        Returns:
            - check_deny_update (bool): A boolean indicating if the overall permission is denied.
            - check_permission (bool): A boolean indicating if the permission is allowed.
        Description:
            - This method processes the resource type string to generate a list of keys for navigating through the permissions dictionary.
            - It traverses the permissions dictionary based on the generated keys to find the relevant permission level.
            - If an "overall" permission of "deny" is found at any level, it returns (True, False).
            - If the keys do not match any entry in the permissions dictionary, it returns (False, True).
            - If the keys match and there is no "overall" permission of "deny", it returns (False, True).
        """
        keys = resource_type.lower().replace(" ", "_").split(".")
        current_level = permissions
        for key in keys:
            if key in current_level:
                current_level = current_level[key]
                self.log("Navigated to level: {0}".format(key), "DEBUG")
            elif (
                "overall" in current_level
                and current_level["overall"].lower() == "deny"
            ):
                self.log("Permission denied at level: {0}".format(key), "DEBUG")
                return True, False
            else:
                self.log("Permission allowed at level: {0}".format(key), "DEBUG")
                return False, True

        overall_permission = (
            "overall" in current_level and current_level["overall"].lower() == "deny"
        )
        self.log(
            "Final permission check: Denied: {0}, Allowed: {1}".format(
                overall_permission, not overall_permission
            ),
            "DEBUG",
        )
        return False, not overall_permission

    def get_operations(self, permissions, resource_type):
        """
        Retrieve specific operations allowed for a given resource type based on the provided permissions.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - permissions (dict): A dictionary containing permission details for various resource types.
            - resource_type (str): A string specifying the resource type for which operations are being retrieved.
        Returns:
            - list: A list of specific operations allowed for the given resource type. If no specific operations are found, an empty list is returned.
        Description:
            - This method processes the resource type string to generate a list of keys for navigating through the permissions dictionary.
            - It traverses the permissions dictionary based on the generated keys to find the relevant permission level.
            - If an "overall" permission of "deny" is found, it collects and returns specific permissions that are not denied.
            - If no specific operations are found or if the "overall" permission is not "deny", it returns an empty list.
        """
        self.log(
            "Retrieving operations for resource type: {0}".format(resource_type), "INFO"
        )
        keys = resource_type.lower().replace(" ", "_").split(".")
        current_level = permissions

        for key in keys:
            if key in current_level:
                current_level = current_level[key]
                self.log("Navigated to level: {0}".format(key), "DEBUG")

        if "overall" in current_level and current_level["overall"].lower() == "deny":
            specific_permissions = {}
            self.log(
                "Overall permission denied for resource type: {0}".format(
                    resource_type
                ),
                "DEBUG",
            )

            for k, v in current_level.items():
                if k != "overall" and v.lower() != "deny":
                    specific_permissions[k] = v
                    self.log(
                        "No specific operations found or overall permission not denied.",
                        "DEBUG",
                    )

            return list(specific_permissions.values())

        return []

    def get_permissions(self, config, input_data, role_operation):
        """
        Retrieve and configure permissions for a role based on the provided configuration and input data.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): A dictionary containing configuration details.
            - input_data (dict): A dictionary containing the role details, including "role", "description", and "resourceTypes".
            - role_operation (str): A string indicating the operation type (e.g., "update").
        Returns:
            - result (dict): A dictionary containing the configured role permissions.
            - is_denied (bool): A boolean indicating if any operation is denied.
        Description:
            - This method parses the provided configuration to retrieve permissions for the specified resources in the input data.
              It checks permissions for each resource type and determines the allowed operations.
            - If the role_operation is not "update", it includes the role name in the result. Otherwise, it includes the role ID.
            - It logs the final permissions configuration and returns the result along with a boolean indicating if any operations
            are denied.
        """
        self.log(
            "Starting permission retrieval for role operation: {0}".format(
                role_operation
            ),
            "INFO",
        )
        permissions = self.parse_config(config)
        allowed_operations = []
        check_deny = []

        for resource in input_data["resourceTypes"]:
            res_type = resource["type"]
            operations = resource["operations"]
            check_deny_update, check_permission = self.check_permission(
                permissions, res_type
            )
            check_deny.append(str(check_deny_update))

            if check_permission:
                specific_operations = self.get_operations(permissions, res_type)
                allowed_operations.append(
                    {
                        "type": res_type,
                        "operations": (
                            operations
                            if not specific_operations
                            else specific_operations
                        ),
                    }
                )

        if role_operation == "create":
            result = {
                "role": input_data["role"],
                "description": input_data["description"],
                "resourceTypes": allowed_operations,
            }
        else:
            result = {
                "roleId": input_data["roleId"],
                "description": input_data["description"],
                "resourceTypes": allowed_operations,
            }

        self.log("Final permissions configuration: {0}".format(result), "DEBUG")

        if "True" in check_deny:
            self.log("Permission check complete. Any denied operations: True", "DEBUG")
            return result, True

        self.log("Permission check complete. Any denied operations: False", "DEBUG")
        return result, False

    def get_diff_deleted(self, config):
        """
        Delete a user or role from Cisco Catalyst Center based on the provided parameters.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): A dictionary containing configuration details, such as "role_name", "username", and "email".
        Returns:
            - self (object): An instance of the class after the deletion operation is performed.
        Description:
            - This method checks the provided configuration to determine whether a role or user needs to be deleted from
              Cisco Catalyst Center. It verifies if the role or user exists, logs the current state, and then proceeds to delete
              the specified role or user. It logs the response from the deletion operation and updates the status and result
              accordingly.
        """
        self.log("Starting the users and roles delete process...", "INFO")

        if "role_name" in config:
            if self.have.get("role_exists"):
                self.valid_role_config_parameters(config).check_return_status()
                self.log("Deleting role with config {0}".format(str(config)), "DEBUG")

                current_role = self.have.get("current_role_config")
                role_id_to_delete = {}
                role_id_to_delete["role_id"] = current_role.get("role_id")
                task_response = self.delete_role(role_id_to_delete)
                self.log("Task response {0}".format(str(task_response)), "INFO")

                if task_response and "error_message" not in task_response:
                    responses = {"role_operation": {"response": task_response}}
                    self.msg = responses
                    self.result["response"] = self.msg
                    self.result["changed"] = True
                    self.status = "success"
                    self.log(self.msg, "INFO")
                    return self

                self.msg = task_response
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            self.no_deleted_role.append(self.want.get("role_name"))
            return self

        if "username" in config or "email" in config:
            if self.have.get("user_exists"):
                self.valid_user_config_parameters(config).check_return_status()
                self.log("Deleting user with config {0}".format(str(config)), "DEBUG")

                current_user = self.have.get("current_user_config")
                user_id_to_delete = {}
                user_id_to_delete["user_id"] = current_user.get("user_id")
                task_response = self.delete_user(user_id_to_delete)
                self.log("Task response {0}".format(str(task_response)), "INFO")

                if task_response and "error_message" not in task_response:
                    responses = {"users_operation": {"response": task_response}}
                    self.msg = responses
                    self.result["response"] = self.msg
                    self.result["changed"] = True
                    self.status = "success"
                    self.log(self.msg, "INFO")
                    return self

                self.msg = task_response
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            if config.get("username") is not None:
                user_identifier = self.want.get("username")
            else:
                user_identifier = self.want.get("email")

            self.no_deleted_user.append(self.want.get("username"))
            return self

    def delete_user(self, user_params):
        """
        Delete a user in Cisco Catalyst Center with the provided parameters.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - user_params (dict): A dictionary containing user information.
        Returns:
            - response (dict): The API response from the "delete_user" function, or an error message if the operation fails.
        Description:
            - This method sends a request to delete a user in Cisco Catalyst Center using the provided user parameters.
            - It logs the response and returns it.
            - The function uses the "user_and_roles" family and the "delete_user_api" function from the Cisco Catalyst Center API.
        """

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            username = self.have.get("username")
            self.log(
                "Attempting to delete user with user_params: {0}".format(
                    str(user_params)
                ),
                "DEBUG",
            )
            try:
                response = self.dnac._exec(
                    family="user_and_roles",
                    function="delete_user_api",
                    op_modifies=True,
                    params=user_params,
                )

                if response and isinstance(response, dict):
                    self.log(
                        "Received API response from delete_user '{0}': {1}".format(
                            username, str(response)
                        ),
                        "DEBUG",
                    )
                    self.deleted_user.append(username)
                    return response

                error_msg = response.get(
                    "error_message",
                    "Unknown error occurred while deleting user '{0}'".format(username),
                )
                self.log("User deletion failed. Error: {0}".format(error_msg), "ERROR")
                return {"error_message": error_msg}

            except Exception as e:
                if "[404]" in str(e):
                    error_message = (
                        "User '{0}' was not found in Cisco Catalyst Center".format(
                            username
                        )
                    )
                elif "[412]" in str(e):
                    error_message = "User '{0}' tried to delete themselves or does not have right permission to delete a user in Cisco Catalyst Center".format(
                        username
                    )
                else:
                    error_message = (
                        "Exception occurred while deleting user {0}: {1}".format(
                            username, str(e)
                        )
                    )

                return {"error_message": error_message}

        self.status = "failed"
        self.msg = "The specified version '{0}' does not have the 'delete_user_api' functionality. Supported version(s) from '2.3.7.6' onwards.".format(
            self.payload.get("dnac_version")
        )
        self.log(self.msg, "ERROR")
        self.check_return_status()

    def delete_role(self, role_params):
        """
        Delete a role in Cisco Catalyst Center with the provided parameters
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - role_params (dict): A dictionary containing role information.
        Returns:
            - response (dict): The API response from the "delete_role" function.
        Description:
            - This method sends a request to delete a role in Cisco Catalyst Center using the provided role parameters.
            - It logs the response and returns it.
            - The function uses the "user_and_roles" family and the "delete_role_api" function from the Cisco Catalyst Center API.
        """

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            try:
                self.log(
                    "delete role with role_params: {0}".format(str(role_params)),
                    "DEBUG",
                )
                response = self.dnac._exec(
                    family="user_and_roles",
                    function="delete_role_api",
                    op_modifies=True,
                    params=role_params,
                )
                self.log(
                    "Received API response from delete_role: {0}".format(str(response)),
                    "DEBUG",
                )
                self.deleted_role.append(self.have.get("role_name"))
                return response

            except Exception as e:
                self.log("Unexpected error occurred: {0}".format(str(e)), "ERROR")
                if "[403]" in str(e):
                    error_message = "The Catalyst Center user '{0}' does not have the necessary permissions to delete the role through the API.".format(
                        self.payload.get("dnac_username")
                    )
                else:
                    error_message = "An error occurred while deleting the role. Check whether user(s) are assigned to the role '{0}'.".format(
                        self.have.get("role_name")
                    )

                return {"error_message": error_message}

        self.status = "failed"
        self.msg = "The specified version '{0}' does not have the 'delete_role_api' functionality. Supported version(s) from '2.3.7.6' onwards.".format(
            self.payload.get("dnac_version")
        )
        self.log(self.msg, "ERROR")
        self.check_return_status()

    def verify_diff_merged(self, config):
        """
        Verify the merged status (Creation/Updation) of user or role details in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified, containing keys like "role_name", "username", and "email".
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            - This method checks the merged status of a user or role configuration in Cisco Catalyst Center by retrieving the current state
              (have) and desired state (want) of the configuration. It logs the current and desired states, and validates whether the specified
              user or role exists in the Catalyst Center configuration.
            - The method verifies if the role or user creation or update has been executed successfully by comparing the current state with
              the desired state and checking if any updates are required.
            - If the specified role or user exists, it logs a success message. If the role or user needs to be updated, it checks if the update
              has been successfully verified. In case of any mismatch between the playbook input and the Catalyst Center configuration, it logs
              an appropriate message indicating that the merge task may not have executed successfully.
        """
        self.log("Verify the users and roles create/update process...", "INFO")

        if "role_name" in config:
            self.get_have(config)
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            # Code to validate ccc config for merged state
            role_exist = self.have.get("role_exists")
            role_name = self.want.get("role_name")

            if role_exist:
                self.status = "success"
                self.msg = "The requested role {0} is present in the Cisco Catalyst Center and its creation has been verified.".format(
                    role_name
                )
                self.log(self.msg, "INFO")
            else:
                self.log(
                    "The playbook input for role {0} does not align with the Cisco Catalyst Center, indicating that the \
                         merge task may not have executed successfully.".format(
                        role_name
                    ),
                    "INFO",
                )

            desired_role = self.generate_role_payload(self.want, "update")
            (require_update, updated_role_info) = self.role_requires_update(
                self.have["current_role_config"], desired_role
            )
            if not require_update:
                self.log(
                    "The update for role {0} has been successfully verified. The updated info - {1}".format(
                        role_name, updated_role_info
                    ),
                    "INFO",
                )
                self.status = "success"

        if "username" in config or "email" in config:
            self.get_have(config)
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            # Code to validate ccc config for merged state
            user_exist = self.have.get("user_exists")
            user_name = self.have.get("username")

            if user_exist:
                self.status = "success"
                self.msg = "The requested user {0} is present in the Cisco Catalyst Center and its creation has been verified.".format(
                    user_name
                )
                self.log(self.msg, "INFO")
            else:
                self.log(
                    "The playbook input for user {0} does not align with the Cisco Catalyst Center, indicating that \
                         the merge task may not have executed successfully.".format(
                        user_name
                    ),
                    "INFO",
                )

            (require_update, updated_user_info) = self.user_requires_update(
                self.have["current_user_config"], self.have["current_role_id_config"]
            )
            if not require_update:
                self.log(
                    "The update for user {0} has been successfully verified. The updated info - {1}".format(
                        user_name, updated_user_info
                    ),
                    "INFO",
                )
                self.status = "success"

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of user or role details in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified, containing keys like "role_name", "username", and "email".
        Returns:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            - This method checks the deletion status of a user or role configuration in Cisco Catalyst Center.
            - It validates whether the specified site (user or role) exists in the Catalyst Center configuration.
            - If the specified role or user does not exist, it sets the status to "success" and logs a confirmation message.
            - If the role or user still exists, it logs a mismatch message indicating the deletion was not executed successfully.
        """
        self.log("Verify the users and roles delete process...", "INFO")

        if "role_name" in config:
            self.get_have(config)
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            role_exist = self.have.get("role_exists")

            if not role_exist:
                self.status = "success"
                msg = "The requested role {0} has already been deleted from the Cisco Catalyst Center and this has been \
                    successfully verified.".format(
                    str(self.want.get("role_name"))
                )
                self.log(msg, "INFO")
                return self

            self.log(
                "Mismatch between the playbook input for role {0} and the Cisco Catalyst Center indicates that the deletion was \
                     not executed successfully.".format(
                    str(self.want.get("role_name"))
                ),
                "INFO",
            )

        if "username" in config or "email" in config:
            self.get_have(config)
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")
            self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

            user_exist = self.have.get("user_exists")

            if not user_exist:
                self.status = "success"
                msg = "The requested user {0} has already been deleted from the Cisco Catalyst Center and this has been \
                    successfully verified.".format(
                    str(self.want.get("username"))
                )
                self.log(msg, "INFO")
                return self

            self.log(
                "Mismatch between the playbook input for user {0} and the Cisco Catalyst Center indicates that the deletion \
                     was not executed successfully.".format(
                    str(self.want.get("username"))
                ),
                "INFO",
            )

        return self

    def update_user_role_profile_messages(self):
        """
        Updates and logs messages based on the status of users and roles.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): Returns the current instance of the class with updated `result` and `msg` attributes.
        Description:
            This method aggregates status messages related to the creation, update, or deletion of users and roles.
            It checks various instance variables (`create_user`, `update_user`, `no_update_user`, `delete_user`,
            `create_role`, `update_role`, `no_update_role`, `delete_role`) to determine the status and generates
            corresponding messages. The method also updates the `result["response"]` attribute with the concatenated status messages.
        """

        self.result["changed"] = False
        result_msg_list = []
        no_update_list = []

        if self.want.get("password_update") is not True:
            update_action = "created"
        else:
            update_action = "updated"

        if self.created_user:
            create_user_msg = (
                "User(s) '{0}' {1} successfully in Cisco Catalyst Center.".format(
                    "', '".join(self.created_user), update_action
                )
            )
            result_msg_list.append(create_user_msg)

        if self.updated_user:
            update_user_msg = (
                "User(s) '{0}' updated successfully in Cisco Catalyst Center.".format(
                    "', '".join(self.updated_user)
                )
            )
            result_msg_list.append(update_user_msg)

        if self.no_update_user:
            no_update_user_msg = (
                "User(s) '{0}' need no update in Cisco Catalyst Center.".format(
                    "', '".join(self.no_update_user)
                )
            )
            no_update_list.append(no_update_user_msg)

        if self.payload.get("state") == "deleted":
            if self.deleted_user:
                delete_user_msg = "User(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                    "', '".join(self.deleted_user)
                )
                result_msg_list.append(delete_user_msg)

        if self.created_role:
            create_role_msg = (
                "Role(s) '{0}' created successfully in Cisco Catalyst Center.".format(
                    "', '".join(self.created_role)
                )
            )
            result_msg_list.append(create_role_msg)

        if self.updated_role:
            update_role_msg = (
                "Role(s) '{0}' updated successfully in Cisco Catalyst Center.".format(
                    "', '".join(self.updated_role)
                )
            )
            result_msg_list.append(update_role_msg)

        if self.no_update_role:
            no_update_role_msg = (
                "Role(s) '{0}' need no update in Cisco Catalyst Center.".format(
                    "', '".join(self.no_update_role)
                )
            )
            no_update_list.append(no_update_role_msg)

        if self.deleted_role:
            delete_role_msg = "Role(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                "', '".join(self.deleted_role)
            )
            result_msg_list.append(delete_role_msg)

        if self.no_deleted_user:
            no_delete_user_msg = (
                "The specified user '{0}' does not exist in Cisco Catalyst Center. "
                "Please provide a valid 'username' or 'email' for user deletion.".format(
                    "', '".join(self.no_deleted_user)
                )
            )
            no_update_list.append(no_delete_user_msg)

        if self.no_deleted_role:
            no_delete_role_msg = (
                "The specified role '{0}' does not exist in Cisco Catalyst Center. "
                "Please provide a valid 'role_name' for user deletion.".format(
                    "', '".join(self.no_deleted_role)
                )
            )
            no_update_list.append(no_delete_role_msg)

        if result_msg_list and no_update_list:
            self.result["changed"] = True
            self.msg = "{0} {1}".format(
                " ".join(result_msg_list), " ".join(no_update_list)
            )
        elif result_msg_list:
            self.result["changed"] = True
            self.msg = " ".join(result_msg_list)
        elif no_update_list:
            self.msg = " ".join(no_update_list)
        else:
            self.msg = "No changes were made. No user or role actions were performed in Cisco Catalyst Center."

        self.log(self.msg, "INFO")
        self.result["response"] = self.msg

        return self

    def snake_to_camel_case(self, data):
        """
        Convert keys from snake_case to camelCase in a given dictionary or list of dictionaries recursively.
        Parameters:
            - data (dict or list): A dictionary with keys in snake_case or a list containing such dictionaries.
        Returns:
            - dict or list: A new dictionary with keys converted to camelCase, or a list of dictionaries
              with keys converted to camelCase.
        Description:
            - This function recursively converts keys from snake_case to camelCase in a given dictionary or list of dictionaries.
            - It handles nested dictionaries and lists, converting all keys in each dictionary found. Lists containing dictionaries
              are recursively processed to ensure all contained dictionaries have their keys converted.
        """

        def to_camel_case(snake_str):
            """
            Helper function to convert snake to camel case.
            """
            components = snake_str.split("_")
            camel_case_str = components[0]
            for component in components[1:]:
                camel_case_str += component.title()
            return camel_case_str

        if isinstance(data, dict):
            camel_case_data = {}
            for key, value in data.items():
                new_key = to_camel_case(key)

                if isinstance(value, list):
                    camel_case_list = []
                    for item in value:
                        camel_case_list.append(item)
                    camel_case_data[new_key] = camel_case_list
                else:
                    camel_case_data[new_key] = value

            return camel_case_data

    def process_config_details(self, config_type, state):
        """
        Process and apply configuration changes based on a given configuration type and desired state.

        Parameters:
            - config_type (str): The configuration type to be processed, found in the "config" section of the payload.
            - state (str): The target state for the configuration (e.g., "present" or "absent").

        Description:
            - This method first checks if the `config_type` exists in the payload and validates its configuration.
            - For each validated configuration, it resets internal values, retrieves the desired (want) and current (have) states,
              and applies the necessary changes based on the `state`.
            - If `config_verify` is enabled, it verifies that the changes have been correctly applied.
        """
        if config_type in self.payload.get("config"):
            self.validate_input_yml(
                self.payload.get("config").get(config_type)
            ).check_return_status()
            config_verify = self.payload.get("config_verify")

            for config in self.validated_config:
                self.reset_values()
                self.get_want(config).check_return_status()
                self.get_have(config).check_return_status()
                self.get_diff_state_apply[state](config).check_return_status()

                if config_verify:
                    self.verify_diff_state_apply[state](config).check_return_status()


def main():
    """main entry point for module execution"""
    # Basic Ansible type check or assign default.
    user_role_details = {
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
        "config_verify": {"type": "bool", "default": False},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "dict"},
        "validate_response_schema": {"type": "bool", "default": True},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    module = AnsibleModule(argument_spec=user_role_details, supports_check_mode=True)

    ccc_user_role = UserandRole(module)
    state = ccc_user_role.params.get("state")

    if (
        ccc_user_role.compare_dnac_versions(ccc_user_role.get_ccc_version(), "2.3.5.3")
        < 0
    ):
        ccc_user_role.msg = (
            "The specified version '{0}' does not support the user and role workflow feature. Supported versions start from '2.3.5.3' onwards. "
            "Version '2.3.5.3' introduces APIs for creating and updating users, as well as retrieving users and roles. "
            "Version '2.3.7.6' expands support to include APIs for creating, updating, retrieving, and deleting both users and roles.".format(
                ccc_user_role.get_ccc_version()
            )
        )
        ccc_user_role.status = "failed"
        ccc_user_role.check_return_status()

    if state == "merged":
        ccc_user_role.process_config_details("role_details", state)
        ccc_user_role.process_config_details("user_details", state)
    else:
        ccc_user_role.process_config_details("user_details", state)
        ccc_user_role.process_config_details("role_details", state)

    ccc_user_role.update_user_role_profile_messages().check_return_status()

    module.exit_json(**ccc_user_role.result)


if __name__ == "__main__":
    main()
