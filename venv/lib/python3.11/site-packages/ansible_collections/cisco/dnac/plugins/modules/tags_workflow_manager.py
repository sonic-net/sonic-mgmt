#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Archit Soni, Madhan Sankaranarayanan"

DOCUMENTATION = r"""
---
module: tags_workflow_manager
short_description: Create/ Update/ Delete Tag(s) and
  Tag Memberships in Cisco Catalyst Center.
description:
  - This module helps users create, update, and delete
    tags, as well as manage tag memberships in Cisco
    Catalyst Center.
  - It provides the ability to define dynamic rules
    for tagging devices and ports, ensuring that devices
    and ports are automatically tagged based various
    matching criteria.
  - Users can assign, update, or delete tags on devices
    and ports based on attributes such as IP Address,
    MAC Address, hostnames, serial numbers, or port
    names.
  - The module also facilitates assigning, updating,
    or deleting tags for devices and ports within specific
    sites, simplifying the management of tags across
    multiple devices and ports under sites.
version_added: '6.30.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Archit Soni (@koderchit) Madhan Sankaranarayanan
  (@madhansansel)
options:
  dnac_version:
    description: The Catalyst Center version required
      for using 'tags_workflow_manager' module.
    type: str
    default: 2.3.7.9
  config_verify:
    description: Set to 'true' to verify the Cisco Catalyst
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
    description: >
      A list of dictionaries defining attributes and
      parameters required for managing tags and tag
      memberships. It is used to configure tag and tag
      membership operations in Cisco Catalyst Center.
    type: list
    elements: dict
    required: true
    suboptions:
      tag:
        description: A dictionary containing detailed
          configurations for creating, updating, or
          deleting tags.
        type: dict
        suboptions:
          name:
            description: >
              The unique name identifying the tag for
              operations such as creation, update, or
              deletion. This parameter is mandatory
              for any tag management operation.
            type: str
            required: true
          description:
            description: >
              A brief description of the tag. This field
              is optional but provides additional context.
            type: str
          force_delete:
            description: >
              When set to 'true', forces tag deletion
              even if it is associated with devices
              and ports. Typically used when the 'state'
              is 'deleted', this option removes all
              associated dynamic rules, detaches the
              tag from all devices and ports, and then
              deletes the tag.
            type: bool
            default: false
          device_rules:
            description: >
              Defines rules for dynamically tagging
              devices based on attributes such as device
              name, device family, device series, IP
              address, location, and version. Devices
              that match the specified criteria are
              automatically tagged. If multiple rules
              are provided - Rules with the same 'rule_name'
              are evaluated using OR logic (i.e., a
              device matching any of them is tagged).
              - Rules with different 'rule_name' values
              are evaluated using AND logic (i.e., a
              device must match all such rules to be
              tagged).
            type: dict
            suboptions:
              rule_descriptions:
                description: List of rules that define
                  how devices will be tagged.
                type: list
                elements: dict
                required: true
                suboptions:
                  rule_name:
                    description: >
                      The name of the rule that determines
                      which device attribute is used
                      for tagging. Available options
                      correspond to different device
                      attributes.
                    type: str
                    choices: [device_name, device_family,
                      device_series, ip_address, location,
                      version]
                    required: true
                  search_pattern:
                    description: >
                      The pattern used to search for
                      the specified device attribute.
                      Determines how the 'value' should
                      be matched.
                    type: str
                    choices: [contains, equals, starts_with,
                      ends_with]
                    required: true
                  value:
                    description: >
                      The specific value that the rule
                      will match against. For example,
                      a device name, an IP address,
                      or a MAC address.
                    type: str
                    required: true
                  operation:
                    description: >
                      Defines how the 'value' is matched
                      against device attributes. - 'ILIKE'
                      -  Performs a case-insensitive
                      match. - 'LIKE' -  Performs a
                      case-sensitive match.
                    type: str
                    choices: [ILIKE, LIKE]
                    default: ILIKE
          port_rules:
            description: >
              Rules for dynamically tagging ports based
              on attributes such as Port Name, Port
              Speed, Admin Status, Operational Status,
              Description. A port that meets the specified
              criteria will be automatically tagged.
              If multiple rules are provided - Rules
              with the same 'rule_name' are evaluated
              using OR logic (i.e., a port matching
              any of them is tagged). - Rules with different
              'rule_name' values are evaluated using
              AND logic (i.e., a port must match all
              such rules to be tagged).
            type: dict
            suboptions:
              scope_description:
                description: >
                  Defines the device scope for the rule,
                  including scope category and scope
                  members. The port rules apply only
                  to ports of devices within the specified
                  scope.
                type: dict
                suboptions:
                  scope_category:
                    description: >
                      Specifies whether the scope is
                      based on tags or site hierarchies.
                      - If `TAG`, the `scope_members`
                      must contain tag names from Cisco
                      Catalyst Center. - If `SITE`,
                      the `scope_members` must contain
                      site hierarchy names from Cisco
                      Catalyst Center.
                    choices: [TAG, SITE]
                    type: str
                    required: true
                  scope_members:
                    description: >
                      A list of scope members to include.
                      - When `scope_category` is `TAG`,
                      this list contains tag names.
                      - When `scope_category` is `SITE`,
                      this list contains site hierarchy
                      names.
                    type: list
                    elements: str
                    required: true
                  inherit:
                    description: >
                      Determines whether the selected
                      site inherits devices from its
                      child sites within the specified
                      scope. This flag is relevant only
                      when 'scope_category' is 'SITE'.
                      - When `scope_category` is `SITE`,
                      the default value is `true`. -
                      When `scope_category` is `TAG`,
                      the default value is `false`.
                    type: bool
              rule_descriptions:
                description: List of rules that define
                  how ports will be tagged.
                type: list
                elements: dict
                suboptions:
                  rule_name:
                    description: >
                      The name of the rule that determines
                      which port attribute is used for
                      tagging. Available options correspond
                      to different port attributes.
                    type: str
                    choices: [speed, admin_status, port_name,
                      operational_status, description]
                    required: true
                  search_pattern:
                    description: >
                      The pattern used to search for
                      the specified port attribute.
                      Determines how the 'value' should
                      be matched.
                    type: str
                    choices: [contains, equals, starts_with,
                      ends_with]
                    required: true
                  value:
                    description: The value that the
                      rule will match against, such
                      as port name or port speed.
                    type: str
                    required: true
                  operation:
                    description: >
                      Defines how the 'value' is matched
                      against port attributes. - 'ILIKE'
                      -  Performs a case-insensitive
                      match. - 'LIKE' -  Performs a
                      case-sensitive match.
                    type: str
                    choices: [ILIKE, LIKE]
                    default: 'ILIKE'
          new_name:
            description: >
              The new name for the tag when updating an existing tag.
            type: str
            required: false
      tag_memberships:
        description: A dictionary containing detailed
          configuration for managing tag memberships
          for devices and interfaces.
        type: dict
        suboptions:
          tags:
            description: >
              List of tag names to assign to devices
              or interfaces. These tags should be present
              in Cisco Catalyst Center.
            type: list
            elements: str
            required: true
          device_details:
            description: Details about the devices and
              interfaces to which tags are to be assigned.
            type: list
            elements: dict
            suboptions:
              ip_addresses:
                description: List of IP addresses for
                  the devices.
                type: list
                elements: str
              hostnames:
                description: List of hostnames for the
                  devices.
                type: list
                elements: str
              mac_addresses:
                description: List of MAC addresses for
                  the devices.
                type: list
                elements: str
              serial_numbers:
                description: List of serial numbers
                  for the devices.
                type: list
                elements: str
              port_names:
                description: >
                  List of port names to which the tags
                  are to be assigned under the devices.
                  It is an optional parameter, used
                  as per requirement. If port_names
                  is not given, the tags will be assigned
                  to devices. If port_names is given,
                  the tags will be assigned to the ports
                  under the respective devices.
                type: list
                elements: str
          site_details:
            description: Details about the sites under
              which devices or interfaces will be tagged.
            type: list
            elements: dict
            suboptions:
              site_names:
                description: List of the site name hierarchies
                  under which devices or interfaces
                  will be tagged.
                type: list
                elements: str
                required: true
              port_names:
                description: >
                  List of port names to which the tags
                  are to be assigned under the devices
                  belonging to the given sites. It is
                  an optional parameter, used as per
                  requirement. If port_names is not
                  given, the tags will be assigned to
                  devices under the given sites. If
                  port_names is given, the tags will
                  be assigned to these ports under devices
                  belonging to the given sites.
                type: list
                elements: str
requirements:
  - dnacentersdk >= 2.10.3
  - python >= 3.9
notes:
  - Ensure that all required parameters are provided
    correctly for successful execution. If any failure
    occurs,
    the module will halt execution without proceeding
    to further operations.
  - If `force_delete` is set to `true` in deleted state,
    the tag will be forcibly removed from all associated
    devices and ports,
    and the tag will be deleted.
  - In device_rules and port_rules,
    rules with the same
    rule_name are ORed together,
    while rules with different
    rule_name values are ANDed together.
  - Each device or interface can have a maximum of 500
    tags assigned.
  - |-
    SDK Methods used are tags.Tag.add_members_to_the_tag tags.Tag.create_tag tags.Tag.delete_tag
    devices.Devices.get_device_list devices.Devices.get_interface_details site_design.SiteDesign.get_sites
    site_design.SiteDesign.get_site_assigned_network_devices tags.Tag.get_tag tags.Tag.get_tag_members_by_id
    tags.Tag.query_the_tags_associated_with_network_devices tags.Tag.query_the_tags_associated_with_interfaces
    tags.Tag.update_tag tags.Tag.update_tags_associated_with_the_interfaces
    tags.Tag.update_tags_associated_with_the_network_devices
    - SDK Paths used are /dna/intent/api/v1/tag/${id}/member /dna/intent/api/v1/tag /dna/intent/api/v1/tag/${id}
    /dna/intent/api/v1/network-device /dna/intent/api/v1/interface/network-device/${deviceId}/interface-name
    /dna/intent/api/v1/sites /dna/intent/api/v1/networkDevices/assignedToSite /dna/intent/api/v1/tag
    /dna/intent/api/v1/tag/${id}/member /dna/intent/api/v1/tags/networkDevices/membersAssociations/query
    /dna/intent/api/v1/tags/interfaces/membersAssociations/query /dna/intent/api/v1/tag
    /dna/intent/api/v1/tags/networkDevices/membersAssociations/bulk
    /dna/intent/api/v1/tags/interfaces/membersAssociations/bulk
"""

EXAMPLES = r"""
---
# For creating/updating a tag
- name: Create a tag with description.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Create a tag with description.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: merged
        config_verify: false
        config:
          - tag:
              name: Server_Connected_Devices_and_Ports
              description: "Tag for devices and interfaces
                connected to servers"
# For creating/updating a tag with device rules.
- name: Create a tag for border devices in the 9300
    series.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Create a tag for border devices in the 9300
        series.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: merged
        config_verify: false
        config:
          - tag:
              name: Border_9300_Tag
              description: Tag for border devices belonging
                to the Cisco Catalyst 9300 family.
              device_rules:
                rule_descriptions:
                  - rule_name: device_name
                    search_pattern: contains
                    value: Border
                    operation: ILIKE
                  - rule_name: device_series
                    search_pattern: ends_with
                    value: 9300
                    operation: ILIKE
# For creating/updating a tag with port rules.
- name: Create a tag for high-speed server-connected
    interfaces.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Create a tag for high-speed server-connected
        interfaces.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: merged
        config_verify: false
        config:
          - tag:
              name: HighSpeed_Server_Interfaces
              description: Tag for 10G interfaces connected
                to servers.
              port_rules:
                scope_description:
                  scope_category: TAG
                  scope_members:
                    - NY_SERVER_TAG
                    - SJC_SERVER_TAG
                rule_descriptions:
                  - rule_name: speed
                    search_pattern: equals
                    value: "10000"
                    operation: ILIKE
                  - rule_name: port_name
                    search_pattern: contains
                    value: TenGigabitEthernet1/0/1
                    operation: ILIKE
# For updating the scope description of a tag with port rules:
- name: Update scope description for tagged server-connected
    interfaces.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Update scope description for tagged server-connected
        interfaces.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: merged
        config_verify: false
        config:
          - tag:
              name: Server_Connected_Interfaces
              description: Tag for interfaces on devices
                connected to servers, scoped to specific
                sites.
              port_rules:
                scope_description:
                  scope_category: SITE
                  scope_members:
                    - Global/USA
                    - Global/INDIA
# For updating rule descriptions of a tag with port rules:
- name: Update port rule descriptions for server-connected
    interfaces.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Update port rule descriptions for server-connected
        interfaces.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: merged
        config_verify: false
        config:
          - tag:
              name: Server_Connected_Interfaces
              description: Tag for interfaces on devices
                connected to servers.
              port_rules:
                rule_descriptions:
                  - rule_name: speed
                    search_pattern: contains
                    value: "100000"
                    operation: ILIKE
                  - rule_name: port_name
                    search_pattern: equals
                    value: TenGigabitEthernet1/0/1
                    operation: ILIKE
# To assign tags to devices/ports (Remove port_names list to assign tags to devices.)
- name: Assign tags to devices or interfaces.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Assign tags to devices or interfaces.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: merged
        config_verify: false
        config:
          - tag_memberships:
              tags:
                - High_Speed_Interfaces
              device_details:
                - ip_addresses:
                    - 10.197.156.97
                    - 10.197.156.98
                    - 10.197.156.99
                  hostnames:
                    - SJC_Border1
                    - SJC_Border2
                    - NY_Border1
                  mac_addresses:
                    - e4:38:7e:42:bc:00
                    - 6c:d6:e3:75:5a:e0
                    - 34:5d:a8:3b:d8:e0
                  serial_numbers:
                    - SAD055006NE
                    - SAD04350EEU
                    - SAD055108C2
                  port_names:
                    - FortyGigabitEthernet1/1/1
                    - FortyGigabitEthernet1/1/2
          - tag_memberships:
              tags:
                - Server_Connected_Devices
              device_details:
                - ip_addresses:
                    - 10.197.156.97
                    - 10.197.156.98
                    - 10.197.156.99
                  hostnames:
                    - SJC_Border1
                    - SJC_Border2
                    - NY_Border1
                  mac_addresses:
                    - e4:38:7e:42:bc:00
                    - 6c:d6:e3:75:5a:e0
                    - 34:5d:a8:3b:d8:e0
                  serial_numbers:
                    - SAD055006NE
                    - SAD04350EEU
                    - SAD055108C2
# To assign tags to devices or ports under specific sites (Remove port_namesto assign tags to devices only.)
- name: Assign tags to devices or interfaces within
    a specific site.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Assign tags to devices or interfaces within
        a specific site.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: merged
        config_verify: false
        config:
          - tag_memberships:
              tags:
                - High_Speed_Interfaces
              site_details:
                - site_names:
                    - Global/INDIA
                  port_names:
                    - FortyGigabitEthernet1/1/1
                    - FortyGigabitEthernet1/1/2
          - tag_memberships:
              tags:
                - Server_Connected_Devices
              site_details:
                - site_names:
                    - Global/INDIA
# Deleting a tag.
- name: Delete a Tag.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Delete a Tag.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: deleted
        config_verify: false
        config:
          - tag:
              name: Server_Connected_Devices
# Force Deleting a tag.
# It will remove all the dynamic and static members from the tag and delete the tag.
- name: Force delete a Tag.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Force delete a Tag.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: deleted
        config_verify: false
        config:
          - tag:
              name: Server_Connected_Devices
              force_delete: true
# For deleting rule descriptions of a tag with device rules.
- name: Delete rule description of a tag with device
    rules
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Delete rule description of a tag with device
        rules
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: deleted
        config_verify: false
        config:
          - tag:
              name: Catalyst_Access_Tag
              device_rules:
                rule_descriptions:
                  - rule_name: device_family
                    search_pattern: ends_with
                    value: 9300
                    operation: ILIKE
# For deleting scope members of a tag with port rules.
- name: Delete scope members of a tag with port rules
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Delete scope members of a tag with port
        rules
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: deleted
        config_verify: false
        config:
          - tag:
              name: Catalyst_Site_Tag
              description: Tag for managing site-based
                configurations
              port_rules:
                scope_description:
                  scope_category: SITE
                  scope_members:
                    - Global/INDIA
# For deleting rule descriptions of a tag with port rules.
- name: Delete rule descriptions of a tag with port
    rules
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Delete rule descriptions of a tag with port
        rules
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: deleted
        config_verify: false
        config:
          - tag:
              name: Catalyst_Port_Tag
              description: Tag for high-speed ports
                and interface rules
              port_rules:
                rule_descriptions:
                  - rule_name: speed
                    search_pattern: equals
                    value: "10000"
                    operation: ILIKE
                  - rule_name: port_name
                    search_pattern: contains
                    value: tengig/1/0/1
                    operation: ILIKE
# For Deleting tags from devices/ports (Remove port_names to delete tags from devices)
- name: Delete tags from members.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Delete tags from members.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: deleted
        config_verify: false
        config:
          - tag_memberships:
              tags:
                - Catalyst_Port_Tag
              device_details:
                - ip_addresses:
                    - 10.197.156.97
                    - 10.197.156.98
                  hostnames:
                    - SJC_Border1
                    - NY_Border1
                  mac_addresses:
                    - e4:38:7e:42:bc:00
                    - 6c:d6:e3:75:5a:e0
                  serial_numbers:
                    - SAD055006NE
                    - SAD04350EEU
                  port_names:
                    - TenGigabitEthernet1/0/1
                    - TenGigabitEthernet1/0/2
          - tag_memberships:
              tags:
                - Catalyst_Device_Tag
              device_details:
                - ip_addresses:
                    - 10.197.156.97
                    - 10.197.156.98
                  hostnames:
                    - SJC_Border1
                    - NY_Border1
                  mac_addresses:
                    - e4:38:7e:42:bc:00
                    - 6c:d6:e3:75:5a:e0
                  serial_numbers:
                    - SAD055006NE
                    - SAD04350EEU
#  For deleting tags from devices/ports under specific sites (Remove port_names to delete tags from devices)
- name: Delete tags from members within a specific sites.
  hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  connection: local
  tasks:
    - name: Delete tags from members within a specific
        sites.
      cisco.dnac.tags_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        dnac_log_file_path: "{{ dnac_log_file_path }}"
        state: deleted
        config_verify: true
        config:
          - tag_memberships:
              tags:
                - Catalyst_Device_Tag
              site_details:
                - site_names:
                    - Global/INDIA
          - tag_memberships:
              tags:
                - Catalyst_Port_Tag
              site_details:
                - site_names:
                    - Global/INDIA
                  port_names:
                    - TenGigabitEthernet1/0/1
                    - TenGigabitEthernet1/0/2
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

from collections import defaultdict
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import DnacBase
from ansible_collections.cisco.dnac.plugins.module_utils.validation import (
    validate_list_of_dicts,
)
import re


class Tags(DnacBase):
    """Class containing member attributes for tags workflow manager module"""

    def __init__(self, module):
        """
        Initializes the Tags class with module-specific configurations.

        Args:
            module: The module instance being initialized.

        Attributes:
            supported_states (list): A list of supported states, including "merged" and "deleted".
            created_tag (list): Stores tag that has been newly created.
            updated_tag (list): Stores tag that has been updated.
            not_updated_tag (list): Stores tag that was expected to be updated but were not.
            deleted_tag (list): Stores tag that has been deleted.
            absent_tag (list): Stores tag that are absent.

            updated_tag_memberships (list): A list of tag memberships that were successfully updated.
            not_updated_tag_memberships (list): A list of tag memberships that failed to update.
            deleted_tag_memberships (list): A list of tag memberships that were successfully deleted.
            not_deleted_tag_memberships (list): A list of tag memberships that failed to be deleted.

        Schema for a member in tag_memberships (Updated/ Not Updated/ Deleted/ Not deleted):
            {
                "id": device_id,
                "device_type": "networkdevice" / "interface",
                "device_identifier": "hostname" / "serial_number" / "ip_address" /  "mac_addresses",
                "device_value": "<actual_value>",  # The actual hostname, serial number, or IP
                "interface_name": "<interface_name>" / None,
                "site_name": "<site_name>" / None,
                "reason": "<Failure reason>",  # Present only in not_updated/not_deleted memberships
                "tags_list": [List of associated tags]  # Present in all membership
            }

        Schema for a member in tag_list:
            {
                "tag_name": "<TAG_NAME>",
                "tag_id": "<TAG_ID>"
            }
        """
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.created_tag, self.updated_tag, self.not_updated_tag = [], [], []
        self.deleted_tag, self.absent_tag = [], []

        self.updated_tag_memberships, self.not_updated_tag_memberships = [], []
        self.deleted_tag_memberships, self.not_deleted_tag_memberships = [], []
        self.result["changed"] = False
        self.MAX_TAGS_LIMIT_PER_MEMBER = 500

    def validate_input(self):
        """
        Validate the playbook configuration.

        Description:
            Checks the configuration provided in the playbook against a predefined specification
            to ensure it adheres to the expected structure and data types.

        Args:
            self (object): The instance of the class that contains the 'config' attribute to be validated.

        Returns:
            self.msg (str): A message describing the validation result.
            self.status (str): The status of the validation (either 'success' or 'failed').
            self.validated_config (dict or None): If successful, a validated version of the 'config' parameter;
                                                otherwise, None.
        """

        validation_schema = {
            "tag": {
                "type": "dict",
                "elements": "dict",
                "name": {"type": "str", "required": True},
                "description": {"type": "str"},
                "force_delete": {"type": "bool", "default": False},
                "device_rules": {
                    "type": "dict",
                    "elements": "dict",
                    "rule_descriptions": {
                        "type": "list",
                        "elements": "dict",
                        "required": True,
                        "rule_name": {"type": "str", "required": True},
                        "search_pattern": {"type": "str", "required": True},
                        "value": {"type": "str", "required": True},
                        "operation": {"type": "str", "default": "ILIKE"},
                    },
                },
                "port_rules": {
                    "type": "dict",
                    "elements": "dict",
                    "scope_description": {
                        "type": "dict",
                        "elements": "dict",
                        "scope_category": {"type": "str", "required": True},
                        "inherit": {"type": "bool"},
                        "scope_members": {
                            "type": "list",
                            "elements": "str",
                            "required": True,
                        },
                    },
                    "rule_descriptions": {
                        "type": "list",
                        "elements": "dict",
                        "rule_name": {"type": "str", "required": True},
                        "search_pattern": {"type": "str", "required": True},
                        "value": {"type": "str", "required": True},
                        "operation": {"type": "str", "default": "ILIKE"},
                    },
                },
                "new_name": {"type": "str"},
                "network_device_tag_retrieval_batch_size": {
                    "type": "int",
                    "range_max": 500,
                    "range_min": 1,
                    "default": 500,
                },
                "interface_tag_retrieval_batch_size": {
                    "type": "int",
                    "range_max": 500,
                    "range_min": 1,
                    "default": 500,
                },
                "network_device_tag_update_batch_size": {
                    "type": "int",
                    "range_max": 500,
                    "range_min": 1,
                    "default": 500,
                },
                "interface_tag_update_batch_size": {
                    "type": "int",
                    "range_max": 500,
                    "range_min": 1,
                    "default": 500,
                },
            },
            "tag_memberships": {
                "type": "dict",
                "tags": {"type": "list", "elements": "str", "required": True},
                "device_details": {
                    "type": "list",
                    "elements": "dict",
                    "ip_addresses": {"type": "list", "elements": "str"},
                    "hostnames": {"type": "list", "elements": "str"},
                    "mac_addresses": {"type": "list", "elements": "str"},
                    "serial_numbers": {"type": "list", "elements": "str"},
                    "port_names": {"type": "list", "elements": "str"},
                },
                "site_details": {
                    "type": "list",
                    "elements": "dict",
                    "site_names": {"type": "list", "elements": "str", "required": True},
                    "port_names": {"type": "list", "elements": "str"},
                },
                "network_device_tag_retrieval_batch_size": {
                    "type": "int",
                    "range_max": 500,
                    "range_min": 1,
                    "default": 500,
                },
                "interface_tag_retrieval_batch_size": {
                    "type": "int",
                    "range_max": 500,
                    "range_min": 1,
                    "default": 500,
                },
                "network_device_tag_update_batch_size": {
                    "type": "int",
                    "range_max": 500,
                    "range_min": 1,
                    "default": 500,
                },
                "interface_tag_update_batch_size": {
                    "type": "int",
                    "range_max": 500,
                    "range_min": 1,
                    "default": 500,
                },
            },
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing. Please check the playbook and try again."
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
            return self

        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, validation_schema
        )

        if invalid_params:
            formatted_errors = '\n'.join(invalid_params)
            self.msg = (
                "The playbook contains invalid parameters: \n"
                f"{formatted_errors}"
                "\nRefer to the documentation for more details on the expected input type."
            )
            self.fail_and_exit(self.msg)
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters. Validated Config: {0}".format(
            self.pprint(valid_temp)
        )
        return self

    def validate_rule_name(self, rule_name, rule_name_choices, errors):
        """
        Validates the provided rule name against allowed choices.

        Args:
            rule_name (str): The name of the rule to be validated.
            rule_name_choices (list): A list of valid rule names.
            errors (list): A list to store validation error messages.

        Returns:
            self: The object instance with updated error messages if validation fails.

        Description:
            - Ensures that `rule_name` is provided.
            - Converts the rule name to lowercase for case-insensitive comparison.
            - Checks if the rule name exists in `rule_name_choices`.
            - Appends error messages if validation fails.
        """

        self.log("Validating rule name: {0}".format(rule_name), "DEBUG")

        if not rule_name:
            errors.append(
                "Rule Name not provided. Required parameter for defining dynamic device rules."
            )

        rule_name = rule_name.lower()
        if rule_name not in rule_name_choices:
            errors.append(
                "Invalid rule name: '{0}'. Valid options are: {1}".format(
                    rule_name, ", ".join(rule_name_choices)
                )
            )

        return self

    def validate_search_pattern(self, search_pattern, search_pattern_choices, errors):
        """
        Validates the given search pattern against a list of allowed search pattern choices.

        Args:
            search_pattern (str): The search pattern to be validated.
            search_pattern_choices (list): A list of valid search patterns.
            errors (list): A list to store validation error messages.

        Returns:
            self: The object instance with updated error messages if validation fails.

        Description:
            - Checks if `search_pattern` is provided. If not, logs an error.
            - Converts `search_pattern` to lowercase for case-insensitive validation.
            - Verifies if `search_pattern` exists in `search_pattern_choices`. If not, logs an error.
        """

        self.log("Validating search pattern: {0}".format(search_pattern), "DEBUG")

        if not search_pattern:
            errors.append(
                "Search Pattern not provided. Required parameter for defining dynamic device rules."
            )

        search_pattern = search_pattern.lower()
        if search_pattern not in search_pattern_choices:
            errors.append(
                "Search pattern provided: {0} is Invalid. Search Pattern should be one of {1}".format(
                    search_pattern, search_pattern_choices
                )
            )

        return self

    def validate_value(self, value, errors):
        """
        Validates whether the given value is provided.

        Args:
            value (str): The value to be validated.
            errors (list): A list to store validation error messages.

        Returns:
            self: The object instance with updated error messages if validation fails.

        Description:
            - Checks if `value` is provided. If not, logs an error.
        """

        self.log("Validating value parameter :{0}".format(value), "DEBUG")

        if not value:
            errors.append(
                "Value not provided. Required parameter for defining dynamic device rules."
            )
        return self

    def validate_operation(self, operation, operation_choices, errors):
        """
        Validates the given operation against a predefined set of valid operations.

        Args:
            operation (str): The operation to be validated.
            operation_choices (list): A list of allowed operations.
            errors (list): A list to store validation error messages.

        Returns:
            self: The object instance with updated error messages if validation fails.

        Description:
            - If `operation` is not provided, it defaults to "ILIKE" and logs a warning.
            - Converts `operation` to uppercase for comparison.
            - Validates whether `operation` exists in `operation_choices`.
        """

        self.log("Validating operation parameter :{0}".format(operation), "DEBUG")

        if not operation:
            operation = "ILIKE"
            errors.append(
                "Operation not provided. Setting it to its default value of {0}".format(
                    operation
                )
            )
            return self

        # Changing to Upper case for comparision
        operation = operation.upper()
        if operation not in operation_choices:
            errors.append(
                "Operation provided: {0} is Invalid. Operation should be one of {1}".format(
                    operation, operation_choices
                )
            )

        return self

    def validate_device_rules(self, tag):
        """
        Validates and processes device rules provided in the tag dictionary.

        Args:
            tag (dict): A dictionary containing a "device_rules" key with
                "rule_descriptions" under it. Each rule should include:
                - "rule_name" (str): Name of the device attribute to match.
                - "search_pattern" (str): Matching pattern type.
                - "value" (str): Value to match.
                - "operation" (str, optional): Matching operation (default is "ILIKE").

        Returns:
            dict or None: A dictionary containing the validated device rules if successful,
                        otherwise None.

        Description:
            - Checks for the presence of device rules.
            - Validates each rule against expected constraints.
            - Logs errors for missing or invalid parameters.
            - Sets default values where necessary.
            - If validation fails, logs the error and stops execution.
        """

        self.log("Starting device rule validation for tag: {0}.".format(tag), "DEBUG")

        device_rules = tag.get("device_rules")

        if not device_rules:
            self.log("Device Rules are not provided", "INFO")
            return None

        rule_descriptions = device_rules.get("rule_descriptions")
        if not rule_descriptions:
            self.msg = (
                "Device Rules does not contain rule descriptions."
                "Required parameter for defining dynamic device rules."
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        validated_rule_descriptions = []
        errors = []
        # Choices
        rule_name_choices = [
            "device_name",
            "device_family",
            "device_series",
            "ip_address",
            "location",
            "version",
        ]
        search_pattern_choices = ["contains", "equals", "starts_with", "ends_with"]
        operation_choices = ["ILIKE", "LIKE"]

        for device_rule in rule_descriptions:
            rule_name = device_rule.get("rule_name")
            self.validate_rule_name(rule_name, rule_name_choices, errors)

            search_pattern = device_rule.get("search_pattern")
            self.validate_search_pattern(search_pattern, search_pattern_choices, errors)

            value = device_rule.get("value")
            self.validate_value(value, errors)

            operation = device_rule.get("operation")
            self.validate_operation(operation, operation_choices, errors)

            if errors:
                self.msg = "Device Rule validation failed: " + ", ".join(errors)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            validated_device_rule = {
                "rule_name": rule_name.lower(),
                "search_pattern": search_pattern.lower(),
                "value": value,
                "operation": operation.upper(),
            }

            validated_rule_descriptions.append(validated_device_rule)

        validated_device_rules = {"rule_descriptions": validated_rule_descriptions}

        self.msg = (
            "Device Rules validation completed. Validated device rules: {0}".format(
                self.pprint(validated_device_rules)
            )
        )
        self.log(self.msg, "INFO")

        return validated_device_rules

    def validate_scope_description(self, scope_description):
        """
        Validates the provided scope description for port rules.

        Args:
            scope_description (dict): A dictionary containing the scope description.

        Returns:
            dict: The validated scope description.

        Description:
            - Ensures that `scope_description` is provided.
            - Validates the `scope_category` against allowed choices ("TAG", "SITE").
            - Defaults `inherit` to True for "SITE" and False for "TAG" if not provided.
            - Ensures `scope_members` are provided.
            - Logs relevant information and errors during validation.
        """

        self.log(
            "Starting validation for scope description: {0}".format(scope_description),
            "INFO",
        )

        if not scope_description:
            self.log("Port Rules do not contain scope description.", "INFO")
            return None

        errors = []
        scope_category = scope_description.get("scope_category")
        scope_category_choices = ["TAG", "SITE"]
        if scope_category and scope_category.upper() not in scope_category_choices:
            errors.append(
                "Scope category provided: {0} is Invalid. Scope category should be one of {1}".format(
                    scope_category, scope_category_choices
                )
            )

        inherit = scope_description.get("inherit")
        if not inherit:
            if scope_category == "SITE":
                inherit = True
                self.log(
                    "Inherit Not provided, Setting it to its default value: {0} for scope_category {1}.".format(
                        inherit, scope_category
                    ),
                    "INFO",
                )
            elif scope_category == "TAG":
                inherit = False
                self.log(
                    "Inherit Not provided, Setting it to its default value: {0} for scope_category {1}.".format(
                        inherit, scope_category
                    ),
                    "INFO",
                )
            else:
                errors.append(
                    "Scope Category : {0} is not available".format(scope_category)
                )

        scope_members = scope_description.get("scope_members")

        if not scope_members:
            errors.append(
                (
                    "No scope members provided for scope category: {0}."
                    "It is required to define/update port rules".format(scope_category)
                )
            )
        if errors:
            self.msg = "Scope Rule validation failed: " + ", ".join(errors)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        validated_scope_description = {
            "scope_category": scope_category.upper(),
            "inherit": inherit,
            "scope_members": scope_members,
        }

        self.log(
            "Scope Description validation completed. Validated Scope description: {0}".format(
                self.pprint(validated_scope_description)
            ),
            "INFO",
        )

        return validated_scope_description

    def validate_port_rule_descriptions(self, rule_descriptions):
        """
        Validates the provided port rule descriptions.

        Args:
            rule_descriptions (list): A list of rule description dictionaries .

        Returns:
            list: A list of validated rule descriptions.

        Description:
            - Ensures that `rule_descriptions` is provided.
            - Validates each rule's `rule_name`, `search_pattern`, `value`, and `operation`.
            - Logs errors if validation fails.
            - Returns a list of validated rule descriptions.
        """

        self.log(
            "Starting validation for port rule descriptions: {0}".format(
                rule_descriptions
            ),
            "INFO",
        )

        if not rule_descriptions:
            self.log("Port Rules do not contain rule descriptions.", "INFO")
            return None

        validated_rule_descriptions = []
        rule_name_choices = [
            "speed",
            "admin_status",
            "port_name",
            "operational_status",
            "description",
        ]
        search_pattern_choices = ["contains", "equals", "starts_with", "ends_with"]
        operation_choices = ["ILIKE", "LIKE"]

        for port_rule in rule_descriptions:
            errors = []
            rule_name = port_rule.get("rule_name")
            self.validate_rule_name(rule_name, rule_name_choices, errors)

            search_pattern = port_rule.get("search_pattern")
            self.validate_search_pattern(search_pattern, search_pattern_choices, errors)

            value = port_rule.get("value")
            self.validate_value(value, errors)

            operation = port_rule.get("operation")
            self.validate_operation(operation, operation_choices, errors)

            if errors:
                self.msg = "Scope Rule validation failed: " + ", ".join(errors)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            validated_port_rule = {
                "rule_name": rule_name,
                "search_pattern": search_pattern,
                "value": value,
                "operation": operation,
            }
            validated_rule_descriptions.append(validated_port_rule)

        self.log(
            "Port Rule Description validation completed. Validated Port rule descriptions: {0}".format(
                self.pprint(validated_rule_descriptions)
            ),
            "INFO",
        )

        return validated_rule_descriptions

    def validate_port_rules(self, tag):
        """
        Validates and processes port rules provided in the configuration dictionary.

        Args:
            tag (dict): A dictionary containing a "port_rules" key with:
                        - "rule_descriptions" (list): List of rule objects defining port attributes.
                        - "scope_description" (dict): Specifies scope details for the port rules.

        Returns:
            dict: A dictionary containing the validated port rules.

        Description:
            This method ensures all provided port rules and scope descriptions are valid.
            It checks for missing or invalid fields and logs errors when necessary. Default
            values are assigned to optional fields if missing. The validation halts with an
            error if critical fields are invalid or missing.
        """

        self.log("Starting port rule validation for tag: {0}.".format(tag), "DEBUG")

        port_rules = tag.get("port_rules")

        if not port_rules:
            self.log("No Port Rules are provided", "INFO")
            return None

        rule_descriptions = port_rules.get("rule_descriptions")
        scope_description = port_rules.get("scope_description")

        if not rule_descriptions and not scope_description:
            self.msg = (
                "Port Rules do not contain the rule descriptions and the scope description. "
                "Both are required for creation of dynamic rules, and at least one is required "
                "for update or delete."
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        validated_port_rules = {}

        validated_scope_description = self.validate_scope_description(scope_description)
        if validated_scope_description:
            validated_port_rules["scope_description"] = validated_scope_description

        validated_rule_descriptions = self.validate_port_rule_descriptions(
            rule_descriptions
        )
        if validated_rule_descriptions:
            validated_port_rules["rule_descriptions"] = validated_rule_descriptions

        self.log(
            "Port Rules validation completed. Validated Port rules: {0}".format(
                self.pprint(validated_port_rules)
            ),
            "INFO",
        )

        return validated_port_rules

    def get_tag_id(self, tag_name):
        """
        Retrieves the tag ID for a given tag name from the Cisco Catalyst Center.

        Args:
            tag_name (str): The name of the tag whose ID needs to be retrieved.

        Returns:
            str or None: The tag ID if found, otherwise None.

        Description:
            This method initiates an API call to retrieve tag details using the provided tag name.
            If the response is empty or an error occurs, it logs the issue and returns None.
        """

        self.log("Retrieving tag ID for tag name: '{0}'.".format(tag_name), "DEBUG")

        try:
            response = self.dnac._exec(
                family="tag", function="get_tag", params={"name": tag_name}
            )

            self.log(
                "Received API response from 'get_tag' for the tag '{0}': {1}".format(
                    tag_name, str(response)
                ),
                "DEBUG",
            )

            tag_data = response.get("response")

            if not isinstance(tag_data, list) or not tag_data:
                self.log(
                    "No tag details found for tag name: '{0}'. Response: {1}".format(
                        tag_name, tag_data
                    ),
                    "DEBUG",
                )
                return None

            tag_id = tag_data[0].get("id")

            return tag_id

        except Exception as e:
            self.msg = "Error retrieving tag ID for '{0}' from Cisco Catalyst Center: {1}".format(
                tag_name, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def process_tag(self, tag):
        """
        Validates and processes the tag configuration.

        Args:
            tag (dict): The input dictionary containing tag details, including name, description, force_delete flag,
                        and associated device and port rules.

        Returns:
            dict: A validated tag configuration dictionary containing:
                - 'name' (str): The tag name.
                - 'description' (str): The tag description (if provided).
                - 'force_delete' (bool): The force delete flag.
                - 'device_rules' (list): Validated device rules.
                - 'port_rules' (list): Validated port rules.

        Description:
            This function extracts the tag configuration from the input dictionary, ensuring that a valid tag name is provided.
            It validates associated device and port rules before constructing a validated tag dictionary. If validation fails,
            an appropriate error message is logged, and execution is halted.

            The validated tag configuration is returned for further processing.
        """

        self.log("Processing tag configuration: {0}".format(self.pprint(tag)), "DEBUG")

        tag_name = tag.get("name")
        if not tag_name:
            self.msg = "No Tag Name provided or Provided Tag Name is empty."
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        new_tag_name = tag.get("new_name")

        if new_tag_name is None:
            new_tag_name = ""
        else:
            if new_tag_name:
                self.log(
                    f"New Tag Name provided: '{new_tag_name}'. It will be used to update the existing tag name: '{tag_name}'.",
                    "DEBUG",
                )
            else:
                self.msg = (
                    f"New Tag Name: '{new_tag_name}' is empty for the tag: '{tag_name}'. Please Input a valid new tag name.",
                )
                self.fail_and_exit(self.msg)

        description = tag.get("description")
        if description == "":
            description = None

        force_delete = tag.get("force_delete", False)
        device_rules = self.validate_device_rules(tag)
        port_rules = self.validate_port_rules(tag)

        validated_tag = {
            "name": tag_name,
            "description": description,
            "force_delete": force_delete,
            "device_rules": device_rules,
            "port_rules": port_rules,
            "new_name": new_tag_name,
            "network_device_tag_retrieval_batch_size": tag.get(
                "network_device_tag_retrieval_batch_size"
            ),
            "interface_tag_retrieval_batch_size": tag.get(
                "interface_tag_retrieval_batch_size"
            ),
            "network_device_tag_update_batch_size": tag.get(
                "network_device_tag_update_batch_size"
            ),
            "interface_tag_update_batch_size": tag.get(
                "interface_tag_update_batch_size"
            ),
        }

        self.log(
            "Tag config validation completed. Validated Tag Config: {0}".format(
                self.pprint(validated_tag)
            ),
            "INFO",
        )
        return validated_tag

    def validate_device_detail(self, device_detail, identifier):
        """
        Validates whether a provided device detail matches a specified identifier type.

        Parameters:
            device_detail (str): The device detail to be validated (e.g., IP address, hostname, MAC address, serial number).
            identifier (str): The type of identifier to validate against (e.g., "ip_addresses", "hostnames", "mac_addresses", "serial_numbers").

        Returns:
            bool: True if the device detail matches the specified identifier type, False otherwise.

        Description:
            This method compiles a regex pattern based on the identifier type and checks if the provided device detail
            matches the pattern. If the identifier is invalid, it logs an error message and exits.
        """
        regex_pattern_map = {
            "ip_addresses": r"^(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$",  # Matches valid IPv4 addresses
            "hostnames": r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$",  # Matches valid hostnames
            "mac_addresses": r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$",  # Matches valid MAC addresses
            "serial_numbers": r"^[A-Za-z0-9]{8,12}$",  # Matches valid serial numbers (8-12 alphanumeric characters)
        }

        regex_pattern_for_identifiers = regex_pattern_map.get(identifier)
        if not regex_pattern_map:
            self.msg = f"Invalid device identifier type provided: '{identifier}'. Valid options are: '{regex_pattern_map.keys()}'"
            self.fail_and_exit(self.msg)

        regex_pattern_compiled = re.compile(regex_pattern_for_identifiers)
        match_result = bool(regex_pattern_compiled.fullmatch(device_detail))

        self.log(
            f"Validating device detail '{device_detail}' with device identifier '{identifier}': Match result: {match_result}",
            "DEBUG",
        )

        return match_result

    def process_tag_memberships(self, tag_memberships):
        """
        Validates and processes tag membership configuration.

        Args:
            tag_memberships (dict): The input dictionary containing tag membership details, including tags, device details,
                                    and site details.

        Returns:
            dict: A validated tag membership configuration dictionary containing:
                - 'tags' (list): List of tags to be assigned to devices and interfaces.
                - 'device_details' (list): Validated device details with at least one identifier (IP, hostname, MAC, serial number).
                - 'site_details' (list): Validated site details with site names.

        Description:
            This function ensures that valid tags are provided and that each device entry contains at least one of the required
            identifiers (IP address, hostname, MAC address, or serial number). It also verifies that site details include
            valid site names. If validation fails at any stage, an appropriate error message is logged, and execution is halted.

            The validated tag membership configuration is returned for further processing.
        """

        self.log(
            "Processing tag memberships configuration: {0}".format(
                self.pprint(tag_memberships)
            ),
            "DEBUG",
        )

        tags = tag_memberships.get("tags")
        device_details = tag_memberships.get("device_details")
        site_details = tag_memberships.get("site_details")

        if not tags:
            self.msg = "No tags provided in tag_memberships. Required Parameter."
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
        else:
            for tag_name in tags:
                tag_id = self.get_tag_id(tag_name)
                if tag_id is None:
                    self.msg = "Tag {0} is not found in Cisco Catalyst Center. Please check the playbook. ".format(
                        tag_name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
                    return self

        if not device_details:
            self.log(
                "Device details are not provided in tag memberships config", "DEBUG"
            )
        else:
            valid_device_identifiers = [
                "ip_addresses",
                "hostnames",
                "mac_addresses",
                "serial_numbers",
            ]
            for device_detail in device_details:
                if not any(device_detail.get(k) for k in valid_device_identifiers):
                    self.msg = "At least one of IP addresses, hostnames, MAC addresses, or serial numbers is required."
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                for identifier in valid_device_identifiers:
                    if device_detail.get(identifier):
                        for detail in device_detail[identifier]:
                            if not self.validate_device_detail(detail, identifier):
                                self.msg = f"Invalid {identifier} provided: {detail}. Please check the playbook."
                                self.fail_and_exit(self.msg)

            port_names = device_detail.get("port_names")
            if port_names:
                self.msg = (
                    "Port names is provided under device details. "
                    "Tag membership operation applies to interfaces"
                )
                self.log(self.msg, "DEBUG")
            else:
                self.msg = (
                    "Port names is not provided under device details. "
                    "Tag membership operation applies to network devices"
                )
                self.log(self.msg, "DEBUG")

        if not site_details:
            self.log("Site details are not provided in tag memberships config", "DEBUG")
        else:
            for site_detail in site_details:
                if not site_detail.get("site_names"):
                    self.msg = "Site Names not provided. Required to assign the tags to its members."
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
            port_names = site_detail.get("port_names")
            if port_names:
                self.msg = (
                    "Port names is provided under site details. "
                    "Tag membership operation applies to interfaces"
                )
                self.log(self.msg, "DEBUG")
            else:
                self.msg = (
                    "Port names is not provided under site details. "
                    "Tag membership operation applies to network devices"
                )
                self.log(self.msg, "DEBUG")

        self.log(
            "Tag memberships validation completed. Validated tag memberships: {0}".format(
                self.pprint(tag_memberships)
            ),
            "INFO",
        )
        return tag_memberships

    def get_want(self, config):
        """
        Extracts, processes, and validates the desired state configuration for tags and tag memberships.

        Args:
            config (dict): The input dictionary containing tag and tag membership details.

        Returns:
            object: The instance of the class with the `want` attribute updated to reflect the validated desired state.

        Description:
            This function acts as a wrapper to process tags and tag memberships separately using `process_tag` and
            `process_tag_memberships`. It first validates the presence of relevant configurations and logs any missing
            parameters.

            The processed results are stored in the `want` dictionary, which includes:
            - 'tag': The validated tag configuration (if provided).
            - 'tag_memberships': The validated tag membership details (if provided).

            The `want` dictionary is assigned to the instance for further processing.
        """

        self.log(
            "Validating desired state configuration for tags and tag memberships. Config: {0}".format(
                self.pprint(config)
            ),
            "DEBUG",
        )

        want = {}

        tag = config.get("tag")
        tag_memberships = config.get("tag_memberships")

        if not tag and not tag_memberships:
            self.msg = "No input provided for tag operations or updating tag memberships in Cisco Catalyst Center."
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        # Process tags
        if tag:
            want["tag"] = self.process_tag(tag)
        else:
            self.log("Tag config not provided.", "DEBUG")

        # Process tag memberships
        if tag_memberships:
            want["tag_memberships"] = self.process_tag_memberships(tag_memberships)
        else:
            self.log("Tag memberships config not provided.", "DEBUG")

        self.want = want
        self.msg = "Successfully collected all parameters from the playbook for tag and tag memberships playbook configuration"
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
        Retrieves the tag ID based on the provided config, and stores it in the 'have' dictionary.

        Args:
            config (dict): Configuration dictionary containing the 'tag' key with 'name' as a subkey.

        Returns:
            self: Returns the instance of the class for method chaining.

        Description:
            This method extracts the tag name from the config, retrieves the tag ID,
            and stores it in the 'have' dictionary. If the tag ID is not found, it logs an debug message.
        """

        self.log(
            "Fetching current state of tags from Cisco Catalyst Center based on provided configuration: {0}".format(
                self.pprint(config)
            ),
            "DEBUG",
        )
        have = {}
        tag = config.get("tag")
        if tag:
            tag_name = tag.get("name")
            tag_info = self.get_tag_info(tag_name)
            if not tag_info:
                self.msg = "Tag Details for {0} are not available in Cisco Catalyst Center".format(
                    tag_name
                )
                self.log(self.msg, "DEBUG")
            else:
                have["tag_info"] = tag_info

        self.have = have
        self.msg = "Successfully retrieved tag details from Cisco Catalyst Center."
        self.log("Present State (have): {0}".format(self.pprint(self.have)), "INFO")
        return self

    def format_rule_representation(self, rule):
        """
        Formats a rule representation by mapping rule names to appropriate selectors and applying
        search pattern transformations to the value.

        Args:
            rule (dict): A dictionary containing rule details with keys:
                        - "search_pattern" (str): The pattern type (equals, contains, starts_with, ends_with).
                        - "operation" (str): The operation to be performed.
                        - "value" (str): The value associated with the rule.
                        - "rule_name" (str): The name of the rule.

        Returns:
            dict: A formatted rule representation with keys:
                - "operation" (str): The operation type.
                - "name" (str): The mapped name for the rule.
                - "value" (str): The transformed value based on the search pattern.
        """

        self.log(
            "Starting rule formatting for rule: {0}".format(self.pprint(rule)), "DEBUG"
        )

        search_pattern = rule.get("search_pattern")
        operation = rule.get("operation")
        value = rule.get("value")
        name = rule.get("rule_name")

        name_selector = {
            # Device rule_names
            "device_name": "hostname",
            "device_family": "family",
            "device_series": "series",
            "ip_address": "managementIpAddress",
            "location": "groupNameHierarchy",
            "version": "softwareVersion",
            # Port rule_names
            "speed": "speed",
            "admin_status": "adminStatus",
            "port_name": "portName",
            "operational_status": "status",
            "description": "description",
        }
        name = name_selector.get(name)

        if name == "speed":
            unit_suffix = (
                "000"  # Convert Mbps to kbps (UI expects Mbps, API expects kbps)
            )
            pattern_map = {
                "equals": "{0}{1}",
                "contains": "%{0}%{1}%",
                "starts_with": "{0}{1}%",
                "ends_with": "%{0}{1}",
            }
        else:
            unit_suffix = ""
            pattern_map = {
                "equals": "{0}",
                "contains": "%{0}%",
                "starts_with": "{0}%",
                "ends_with": "%{0}",
            }
        value = pattern_map.get(search_pattern, "{0}").format(value, unit_suffix)

        formatted_rule = {"operation": operation, "name": name, "value": value}

        self.log(
            "Transformed rule: Input={0} → Output={1}".format(
                self.pprint(rule), self.pprint(formatted_rule)
            ),
            "INFO",
        )
        return formatted_rule

    def sorting_rule_descriptions(self, rule_descriptions):
        """
        Sorts rule descriptions based on predefined priority order of 'name' and then
        lexicographically by 'value' within the same 'name'.

        Args:
            rule_descriptions (list of dict): A list of dictionaries where each dictionary
                contains:
                - "name" (str): The rule category.
                - "value" (str): The corresponding value.

        Returns:
            list of dict: A sorted list of rule descriptions, first by the priority of 'name'
                         and then alphabetically by 'value'.
        """

        self.log(
            "Starting sorting of rule descriptions: {0}".format(
                self.pprint(rule_descriptions)
            ),
            "DEBUG",
        )

        sort_order = {
            "hostname": 0,
            "family": 1,
            "series": 2,
            "managementIpAddress": 3,
            "groupNameHierarchy": 4,
            "softwareVersion": 5,
            "speed": 6,
            "adminStatus": 7,
            "portName": 8,
            "status": 9,
            "description": 10,
        }

        # Sort based on the `name` order and then by `value` within the same `name`
        sorted_rule_descriptions = sorted(
            rule_descriptions,
            key=lambda x: (sort_order.get(x["name"], float("inf")), x["value"]),
        )
        return sorted_rule_descriptions

    def group_rules_into_tree(self, rule_descriptions):
        """
        Groups leaf nodes by 'name' and creates a hierarchical dictionary structure
        according to the specified rules.

        Args:
            rule_descriptions (list): List of leaf nodes (base rules).

        Returns:
            dict: Hierarchical rule description dictionary structure.
        """

        if not rule_descriptions:
            return None

        leaf_nodes = rule_descriptions
        # Group leaf nodes by 'name'
        grouped_nodes = defaultdict(list)
        for node in leaf_nodes:
            grouped_nodes[node["name"]].append(node)

        # Helper function to limit items to two per group and branch
        def branch_conditions(conditions, operation):
            while len(conditions) > 2:
                conditions = [
                    {
                        "operation": operation,
                        "items": [conditions.pop(0), conditions.pop(0)],
                    }
                ] + conditions

            return conditions

        # Build the hierarchical structure for grouped nodes
        grouped_conditions = []
        for name, nodes in grouped_nodes.items():
            if len(nodes) > 1:
                # Create an OR operation for nodes with the same name
                or_group = {"operation": "OR", "items": branch_conditions(nodes, "OR")}
                grouped_conditions.append(or_group)
            else:
                # Single node remains as is
                grouped_conditions.append(nodes[0])

        # Combine all grouped conditions with AND
        while len(grouped_conditions) > 2:
            grouped_conditions = [
                {
                    "operation": "AND",
                    "items": [grouped_conditions.pop(0), grouped_conditions.pop(0)],
                }
            ] + grouped_conditions

        if len(grouped_conditions) > 1:
            return {"operation": "AND", "items": grouped_conditions}
        else:
            return grouped_conditions[0]

    def format_device_rules(self, device_rules):
        """
        Formats device rules by processing rule descriptions, applying formatting,
        sorting, and grouping them into a hierarchical structure.

        Args:
            device_rules (dict): A dictionary containing device rule details.
                Expected keys:
                    - "rule_descriptions" (list of dict): List of device rules.

        Returns:
            dict: A formatted dictionary containing device rules grouped hierarchically.
        """

        self.log(
            "Starting device rule formatting for input: {0}".format(
                self.pprint(device_rules)
            ),
            "INFO",
        )

        if device_rules is None:
            self.log("device_rules is None. Returning None", "DEBUG")
            return None

        rule_descriptions = device_rules.get("rule_descriptions")

        formatted_rule_descriptions = []
        for device_rule in rule_descriptions:
            formatted_rule_description = self.format_rule_representation(device_rule)
            formatted_rule_descriptions.append(formatted_rule_description)

        # Sorting it so that its uniform and easier to compare with future updates.
        formatted_rule_descriptions_list = self.sorting_rule_descriptions(
            formatted_rule_descriptions
        )

        self.log(
            "Formatted Rule Descriptions In List Format:{0}".format(
                self.pprint(formatted_rule_descriptions_list)
            ),
            "INFO",
        )

        formatted_device_rules = {
            "memberType": "networkdevice",
            "rules": formatted_rule_descriptions_list,
        }
        self.log(
            "Formatted Device rules for Input:{0} is Output:{1}".format(
                self.pprint(device_rules), self.pprint(formatted_device_rules)
            ),
            "INFO",
        )
        return formatted_device_rules

    def format_scope_description(self, scope_description):
        """
        Formats scope description by processing scope category and members,
        retrieving corresponding IDs, and returning a structured output.

        Args:
            scope_description (dict): A dictionary containing scope details.
                Expected keys:
                    - "scope_category" (str): Category of the scope (TAG or SITE).
                    - "scope_members" (list): List of scope members.
                    - "inherit" (bool): Inherit flag in case of SITE.

        Returns:
            dict: A formatted dictionary containing scope description.
        """

        self.log(
            "Starting scope description formatting for input: {0}".format(
                self.pprint(scope_description)
            ),
            "DEBUG",
        )
        if not scope_description:
            self.log(
                "scope_description is {0}. Returning None".format(scope_description),
                "INFO",
            )
            return scope_description

        scope_category = scope_description.get("scope_category")
        scope_members = scope_description.get("scope_members")
        scope_members_ids = []

        if scope_category == "TAG":
            for tag in scope_members:
                tag_id = self.get_tag_id(tag)
                if tag_id is None:
                    self.msg = (
                        "Scope Member provided: {0} is Not present in Cisco Catalyst Center. "
                        "Please ensure that the scope_members are present and scope_category is provided are valid"
                    ).format(tag)
                    self.log(self.msg, "INFO")
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
                scope_members_ids.append(tag_id)
        elif scope_category == "SITE":
            for site in scope_members:
                site_exists, site_id = self.get_site_id(site)
                if not site_exists:
                    self.msg = (
                        "Scope Member provided: {0} is Not present in Cisco Catalyst Center. "
                        "Please ensure that the scope_members are present and scope_category provided are valid"
                    ).format(site)
                    self.log(self.msg, "INFO")
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
                scope_members_ids.append(site_id)

        formatted_scope_description = {
            "memberType": "networkdevice",
            "groupType": scope_category,
            "scopeObjectIds": scope_members_ids,
            "inherit": scope_description.get("inherit"),
        }

        self.log(
            "Formatted Scope Description for Input:{0} is Output:{1}".format(
                scope_description, formatted_scope_description
            ),
            "INFO",
        )

        return formatted_scope_description

    def format_port_rules(self, port_rules):
        """
        Formats port rules by processing rule descriptions and scope descriptions,
        applying formatting, sorting, and structuring them into a hierarchical format.

        Args:
            port_rules (dict): A dictionary containing port rule details.
                Expected keys:
                    - "rule_descriptions" (list of dict): List of port rules.
                    - "scope_description" (dict): Scope description details.

        Returns:
            dict: A formatted dictionary containing structured port rules.
        """

        self.log(
            "Starting port rule formatting for input: {0}".format(
                self.pprint(port_rules)
            ),
            "DEBUG",
        )

        if port_rules is None:
            self.log("port_rules is None. Returning None", "DEBUG")
            return None

        formatted_port_rules = {"memberType": "interface"}

        rule_descriptions = port_rules.get("rule_descriptions")
        scope_description = port_rules.get("scope_description")

        formatted_rule_descriptions = []

        # Checking if rule_desctiptions exist because in case of update, only one of scope/rules can be given.
        if rule_descriptions:
            for port_rule in rule_descriptions:
                formatted_rule_description = self.format_rule_representation(port_rule)
                formatted_rule_descriptions.append(formatted_rule_description)

            # Sorting it so that its easier to compare.
            formatted_rule_descriptions = self.sorting_rule_descriptions(
                formatted_rule_descriptions
            )

            formatted_port_rules["rules"] = formatted_rule_descriptions

        formatted_scope_description = []
        if scope_description:
            formatted_scope_description = self.format_scope_description(
                scope_description
            )
            formatted_port_rules["scopeRule"] = formatted_scope_description

        self.log(
            "Formatted Port rules for Input:{0} is Output:{1}".format(
                port_rules, formatted_port_rules
            ),
            "INFO",
        )
        return formatted_port_rules

    def combine_device_port_rules(self, device_rules, port_rules):
        """
        Combines device-specific and port-specific rules into a list.

        Args:
            device_rules (list): A list of rules related to the device.
            port_rules (list): A list of rules related to the port.

        Returns:
            list: A list containing the combined device and port rules. If either list is None, it is treated as an empty list.

        Description:
            This method combines the given device and port rules into a single list and logs the result.
        """

        self.log(
            "Combining device_rules: {0} with port_rules: {1}".format(
                self.pprint(device_rules), self.pprint(port_rules)
            ),
            "DEBUG",
        )

        dynamic_rules = []
        if port_rules:
            dynamic_rules.append(port_rules)

        if device_rules:
            dynamic_rules.append(device_rules)

        self.log(
            "Combined dynamic_rules for device_rules:{0}, port_rules:{1} are: {2}".format(
                self.pprint(device_rules),
                self.pprint(port_rules),
                self.pprint(dynamic_rules),
            ),
            "DEBUG",
        )
        return dynamic_rules

    def create_tag(self, tag):
        """
        Creates a new tag with associated rules and parameters.

        Args:
            tag (dict): A dictionary containing the tag information. Expected keys are:
                - "name": The name of the tag. (required)
                - "description": A description of the tag.
                - "device_rules": A dictionary of device-related rules.
                - "port_rules": A dictionary of port-related rules.

        Returns:
            self: Returns the current instance (self) for chaining.

        Description:
            This method formats the device and port rules, validates the port rule descriptions,
            combines the rules, and creates a new tag by making an API call. If any errors occur
            during the process, appropriate error messages are logged.
        """

        self.log(
            "Starting tag creation process for tag: {0}".format(tag.get("name")), "INFO"
        )

        tag_name = tag.get("name")
        description = tag.get("description")
        device_rules = tag.get("device_rules")
        port_rules = tag.get("port_rules")

        formatted_device_rules = self.format_device_rules(device_rules)
        if formatted_device_rules:
            formatted_device_rules["rules"] = self.group_rules_into_tree(
                formatted_device_rules["rules"]
            )

        formatted_port_rules = self.format_port_rules(port_rules)
        if formatted_port_rules:
            formatted_port_rules["rules"] = self.group_rules_into_tree(
                formatted_port_rules["rules"]
            )

        if formatted_port_rules:
            rule_descriptions = port_rules.get("rule_descriptions")
            scope_description = port_rules.get("scope_description")
            if not rule_descriptions or not scope_description:
                self.msg = """Either of rule_description:{0} or scope_description:{1} is empty in port_rules.
                Both are required for port rule creation""".format(
                    rule_descriptions, scope_description
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                return self

        dynamic_rules = self.combine_device_port_rules(
            formatted_device_rules, formatted_port_rules
        )
        tag_payload = {
            "name": tag_name,
            "description": description,
        }

        if dynamic_rules:
            tag_payload["dynamicRules"] = dynamic_rules

        task_name = "create_tag"
        parameters = {"payload": tag_payload}
        task_id = self.get_taskid_post_api_call("tag", task_name, parameters)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0} for the tag {1}'.".format(
                task_name, tag_name
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
            return self

        success_msg = (
            "Tag: '{0}' created successfully in the Cisco Catalyst Center".format(
                tag_name
            )
        )
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self

    def get_tag_info(self, tag_name):
        """
        Retrieves the details of a tag by its name.

        Args:
            tag_name (str): The name of the tag.

        Returns:
            dict or None: The tag details if found, otherwise None.

        Description:
            Sends an API request to retrieve the details of a tag based on its name.
        """

        self.log(
            "Initiating retrieval of tag details for tag name: '{0}'.".format(tag_name),
            "DEBUG",
        )

        try:
            response = self.dnac._exec(
                family="tag", function="get_tag", params={"name": tag_name}
            )

            # Check if the response is empty
            self.log(
                "Received API response from 'get_tag' for the tag '{0}': {1}".format(
                    tag_name, str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")

            if not response:
                self.msg = "No tag details retrieved for tag name: {0}, Response is empty.".format(
                    tag_name
                )
                self.log(self.msg, "DEBUG")
                return None

            tag_info = response[0]
            self.log(
                "Retrieved tag details for tag name: '{0}': {1}".format(
                    tag_name, self.pprint(tag_info)
                ),
                "DEBUG",
            )
            if tag_info.get("description") == "":
                tag_info["description"] = None

            return tag_info

        except Exception as e:
            self.msg = """Error while getting the details of Tag with given name '{0}' present in
            Cisco Catalyst Center: {1}""".format(
                tag_name, str(e)
            )
            self.fail_and_exit(self.msg)

    def get_device_id_by_param(self, param, param_value):
        """
        Retrieves the device ID based on a given parameter (e.g., IP address, hostname).

        Args:
            param (str): The parameter to search by (e.g., "ip_address", "hostname").
            param_value (str): The value of the parameter to search for.

        Returns:
            str or None: The device ID if found, otherwise None.

        Description:
            Sends an API request to retrieve the device ID based on the provided parameter and value.
        """

        self.log(
            "Initiating retrieval of device id details for device with {0}: '{1}' ".format(
                param, param_value
            ),
            "DEBUG",
        )

        try:
            param_api_name = {
                "ip_address": "managementIpAddress",
                "hostname": "hostname",
                "mac_address": "macAddress",
                "serial_number": "serialNumber",
            }

            payload = {"{0}".format(param_api_name.get(param)): param_value}
            response = self.dnac._exec(
                family="devices", function="get_device_list", params=payload
            )
            # Check if the response is empty
            self.log(
                "Received API response from 'get_device_list' for the Device with {0}: '{1}' : {2}".format(
                    param, param_value, str(response)
                ),
                "DEBUG",
            )
            response_data = response.get("response")

            if not response_data or not isinstance(response_data, list):
                self.log(
                    "No device details retrieved for {0}: '{1}', response: {2}.".format(
                        param, param_value, response_data
                    ),
                    "DEBUG",
                )
                return None

            device_id = response_data[0].get("id")
            return device_id

        except Exception as e:
            self.msg = """Error while getting the details of Device with {0}:'{1}' present in
            Cisco Catalyst Center: {2}""".format(
                param, param_value, str(e)
            )
            self.fail_and_exit(self.msg)

    def get_port_id_by_device_id(
        self, device_id, port_name, device_identifier, device_identifier_value
    ):
        """
        Retrieves the port ID for a given device id and interface/port name.

        Args:
            device_id (str): The ID of the device.
            port_name (str): The name of the interface/port.
            device_identifier (str): The identifier type (e.g., 'hostname', 'serial_number').
            device_identifier_value (str): The value of the device identifier.

        Returns:
            str or None: The port ID if found, otherwise None.

        Description:
            Sends an API request to retrieve the port ID for the specified interface on the given device.
        """

        self.log(
            "Retrieving interface details for '{0}' on device with {1}: '{2}'.".format(
                port_name, device_identifier, device_identifier_value
            ),
            "DEBUG",
        )

        try:
            response = self.dnac._exec(
                family="devices",
                function="get_interface_details",
                params={"device_id": device_id, "name": port_name},
            )

            self.log(
                "Received API response from 'get_interface_details' for the interface name: '{0}' of device with {1}: '{2}' is : {3}".format(
                    port_name, device_identifier, device_identifier_value, str(response)
                ),
                "DEBUG",
            )

            response_data = response.get("response")
            if not response_data:
                self.msg = "No interface details for interface name: '{0}' of device with {1}: '{2}', Response is empty.".format(
                    port_name, device_identifier, device_identifier_value
                )
                self.log(self.msg, "DEBUG")
                return None

            port_id = response_data.get("id")

            return port_id

        except Exception as e:
            error_message = str(e)
            if (
                "status_code: 404" in error_message
                and "No resource found with deviceId: {0} and interfaceName:{1}".format(
                    device_id, port_name
                )
                in error_message
            ):
                self.log(
                    "Skipping: Interface '{0}' not found on device {1}: '{2}'. Error: {3}".format(
                        port_name,
                        device_identifier,
                        device_identifier_value,
                        error_message,
                    ),
                    "INFO",
                )
                return None  # Skips the operation when this specific error occurs

            self.msg = "Failed to retrieve interface details for '{0}' on device {1}: '{2}'. Error: {3}".format(
                port_name, device_identifier, device_identifier_value, str(e)
            )
            self.fail_and_exit(self.msg)

    def deduplicate_list_of_dict(self, list_of_dicts):
        """
        Removes duplicate dictionaries from a list.

        Args:
            list_of_dicts (list): A list of dictionaries to deduplicate.

        Returns:
            list: A list of unique dictionaries (duplicates removed).

        Description:
            Iterates through a list of dictionaries and removes duplicates based on their content.
        """

        self.log(
            "Starting deduplication for list: {0}".format(self.pprint(list_of_dicts)),
            "DEBUG",
        )

        seen = set()
        unique_dicts = []
        for d in list_of_dicts:
            # Convert dictionary to a tuple of sorted items (temporary hashable representation)
            identifier = tuple(sorted(d.items()))

            if identifier not in seen:
                seen.add(identifier)
                # Append the original dict (not modified)
                unique_dicts.append(d)

        self.log("Deduplicated list: {0}".format(self.pprint(unique_dicts)), "DEBUG")

        return unique_dicts

    def format_device_details(self, device_details):
        """
        Formats device details by retrieving device and port IDs.

        Args:
            device_details (list): A list of dictionaries containing device details.

        Returns:
            list: A list of dictionaries with formatted device and port information, including IDs.

        Description:
            This function processes a list of device details, deduplicates port names, retrieves device IDs, and handles missing devices or interfaces.
        """

        self.log(
            "Processing device details to retrieve device/port IDs: {0}".format(
                self.pprint(device_details)
            ),
            "DEBUG",
        )

        device_ids = []
        for device_detail in device_details:
            port_names = device_detail.get("port_names")
            if port_names:
                self.log(
                    "Deduplicating the port_names list for duplicate port names",
                    "DEBUG",
                )
                port_names = list(set(port_names))

            param_map = {
                "ip_addresses": "ip_address",
                "hostnames": "hostname",
                "mac_addresses": "mac_address",
                "serial_numbers": "serial_number",
            }

            for params_name, param_name in param_map.items():
                param_list = device_detail.get(params_name)
                if not param_list:
                    continue
                for param in param_list:
                    device_id = self.get_device_id_by_param(param_name, param)
                    device_detail_dict = {
                        "device_type": "networkdevice",
                        "device_identifier": param_name,
                        "device_value": param,
                    }
                    if device_id is None:
                        self.log(
                            "No device found with {0}: {1}".format(param_name, param),
                            "INFO",
                        )
                        device_detail_dict["reason"] = (
                            "Device doesn't exist in Cisco Catalyst Center"
                        )
                        state = self.params.get("state")

                        if port_names:
                            for port_name in port_names:
                                interface_detail_dict = {
                                    "device_type": "interface",
                                    "device_identifier": param_name,
                                    "device_value": param,
                                    "interface_name": port_name,
                                    "reason": "Device doesn't exist in Cisco Catalyst Center",
                                }
                                # Tag not updated/deleted for interface
                                if state == "merged":
                                    self.not_updated_tag_memberships.append(
                                        interface_detail_dict
                                    )
                                elif state == "deleted":
                                    self.not_deleted_tag_memberships.append(
                                        interface_detail_dict
                                    )
                        else:
                            # Tag not updated/deleted for device
                            if state == "merged":
                                self.not_updated_tag_memberships.append(
                                    device_detail_dict
                                )
                            elif state == "deleted":
                                self.not_deleted_tag_memberships.append(
                                    device_detail_dict
                                )

                        self.log(
                            "No device found in Cisco Catalyst Center with {0}: {1}".format(
                                param_name, param
                            ),
                            "INFO",
                        )
                    else:
                        # If no port names, add only device details and continue
                        if not port_names:
                            self.log(
                                "Device found with {0}: {1}, adding to device_ids".format(
                                    param_name, param
                                ),
                                "DEBUG",
                            )
                            device_detail_dict["id"] = device_id
                            device_ids.append(device_detail_dict)
                            continue

                        # Process port details if device exists
                        for port_name in port_names:
                            port_id = self.get_port_id_by_device_id(
                                device_id, port_name, param_name, param
                            )
                            interface_detail_dict = {
                                "device_type": "interface",
                                "device_identifier": param_name,
                                "device_value": param,
                                "interface_name": port_name,
                            }
                            if port_id is None:
                                self.log(
                                    "Interface: '{0}' is not available for the device with {1}:'{2}'.".format(
                                        port_name, param_name, param
                                    ),
                                    "INFO",
                                )
                                interface_detail_dict["reason"] = (
                                    "Interface Not Available on Device"
                                )
                                state = self.params.get("state")
                                if state == "merged":
                                    self.not_updated_tag_memberships.append(
                                        interface_detail_dict
                                    )
                                elif state == "deleted":
                                    self.not_deleted_tag_memberships.append(
                                        interface_detail_dict
                                    )
                            else:
                                interface_detail_dict["id"] = port_id
                                self.log(
                                    "Found interface '{0}' on device with {1}: '{2}', adding to device_ids".format(
                                        port_name, param_name, param
                                    ),
                                    "DEBUG",
                                )
                                device_ids.append(interface_detail_dict)

        self.log("Deduplicating the device_ids list for duplicate device IDs", "DEBUG")
        device_ids = self.deduplicate_list_of_dict(device_ids)
        self.log(
            "Successfully retrieved device/port IDs from device_details: {0}\nResult: {1}".format(
                self.pprint(device_details), self.pprint(device_ids)
            ),
            "DEBUG",
        )

        return device_ids

    def get_device_id_list_by_site_name(self, site_name, site_id):
        """
        Retrieves a list of device IDs assigned to a specific site.

        Args:
            site_name (str): The name of the site for which to retrieve device IDs.

        Returns:
            list: A list of device IDs if found, else None.

        Description:
            This function fetches the device IDs for all devices assigned to a site identified by its name. If no devices are found, it logs the error.
        """

        self.log(
            "Initiating retrieval of device details under site: '{0}'.".format(
                site_name
            ),
            "DEBUG",
        )

        device_id_list = []

        offset = 1
        limit = 500
        while True:
            batch = offset // limit + 1
            self.log(
                "Fetching device details for site '{0}', Batch {1}, Offset {2}".format(
                    site_name, batch, offset
                ),
                "DEBUG",
            )
            try:
                response = self.dnac._exec(
                    family="site_design",
                    function="get_site_assigned_network_devices",
                    params={"site_id": site_id, "offset": offset, "limit": limit},
                )

                # Check if the response is empty
                self.log(
                    "Received API response from 'get_site_assigned_network_devices' for the site name: '{0}' for batch:{1}: {2}".format(
                        site_name, batch, str(response)
                    ),
                    "DEBUG",
                )
                response = response.get("response")

                if not response:
                    self.msg = "No devices found under the site name: {0} for batch :{1}, Response is empty.".format(
                        site_name, batch
                    )
                    self.log(self.msg, "DEBUG")
                    break

                for response_ele in response:
                    device_id_list.append(response_ele.get("deviceId"))

                if len(response) < limit:
                    self.log(
                        "Retrieved the last batch ({0}) of devices for site '{1}'. No more data to fetch.".format(
                            batch, site_name
                        ),
                        "DEBUG",
                    )
                    break

                offset += limit

            except Exception as e:
                self.msg = """Error while getting the details of the devices under the site name '{0}' for batch {1} present in
                Cisco Catalyst Center: {2}""".format(
                    site_name, batch, str(e)
                )
                self.fail_and_exit(self.msg)

        self.log(
            "Final list of device IDs retrieved for site '{0}': {1}".format(
                site_name, self.pprint(device_id_list)
            ),
            "DEBUG",
        )
        return device_id_list

    def format_site_details(self, site_details):
        """
        Formats site details to retrieve device and interface information for each site.

        Args:
            site_details (list): A list of site details, including site names and associated port names (optional).

        Returns:
            list: A list of device and interface details with IDs, including site names.

        Description:
            This function processes the site details, retrieves the device and interface IDs for each site, and
            formats the data for further processing. It handles deduplication and error logging for missing sites and devices.
        """

        self.log(
            "Starting device and interface retrieval for given site details:\n{0}".format(
                self.pprint(site_details)
            ),
            "DEBUG",
        )

        device_ids = []
        for site_detail in site_details:
            port_names = site_detail.get("port_names")
            if port_names:
                self.log(
                    "Deduplicating the port_names list for duplicate port names",
                    "DEBUG",
                )
                port_names = list(set(port_names))

            site_names = site_detail.get("site_names")
            for site in site_names:
                site_exists, site_id = self.get_site_id(site)
                if not site_exists:
                    self.msg = (
                        "Site provided: {0} is Not present in Cisco Catalyst Center. "
                        "Please ensure that the Site name hierarchy provided is valid"
                    ).format(site)
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
                device_ids_list = self.get_device_id_list_by_site_name(site, site_id)

                if not device_ids_list:
                    self.log(
                        "No device found under the site '{0}' in Cisco Catalyst Center".format(
                            site
                        ),
                        "INFO",
                    )
                    continue

                for device_id in device_ids_list:
                    device_name = self.get_device_name_by_id(device_id)
                    device_detail_dict = {
                        "id": device_id,
                        "device_type": "networkdevice",
                        "device_identifier": "hostname",
                        "device_value": device_name,
                        "site_name": site,
                    }
                    if not port_names:
                        device_ids.append(device_detail_dict)
                        continue

                    for port_name in port_names:
                        interface_detail_dict = {
                            "device_type": "interface",
                            "device_identifier": "hostname",
                            "device_value": device_name,
                            "interface_name": port_name,
                            "site_name": site,
                        }
                        port_id = self.get_port_id_by_device_id(
                            device_id, port_name, "hostname", device_name
                        )
                        if port_id:
                            interface_detail_dict["id"] = port_id
                            device_ids.append(interface_detail_dict)
                            continue

                        interface_detail_dict["reason"] = (
                            " Interface Not Available on Device"
                        )
                        state = self.params.get("state")
                        if state == "merged":
                            self.not_updated_tag_memberships.append(
                                interface_detail_dict
                            )
                        elif state == "deleted":
                            self.not_deleted_tag_memberships.append(
                                interface_detail_dict
                            )

                        self.log(
                            "Interface: '{0}' is not available for the device with {1}:'{2}'.".format(
                                port_name, "hostname", device_name
                            ),
                            "INFO",
                        )

        self.log(
            "Removing duplicate device/interface entries before returning.", "DEBUG"
        )
        device_ids = self.deduplicate_list_of_dict(device_ids)

        self.log(
            "Successfully retrieved device/port IDs from site_details: {0}\nResult: {1}".format(
                self.pprint(site_details), device_ids
            ),
            "DEBUG",
        )

        return device_ids

    def get_device_name_by_id(self, device_id):
        """
        Retrieves the device name (hostname) using the device ID.

        Args:
            device_id (str): The ID of the device to retrieve.

        Returns:
            str: The device name (hostname) if found, else None.

        Description:
            This function retrieves the device details for a given device ID and extracts the hostname. If no details are found, it logs the error.
        """

        self.log(
            "Fetching device details for Device ID: {0}".format(device_id), "DEBUG"
        )

        try:
            payload = {"id": device_id}
            response = self.dnac._exec(
                family="devices", function="get_device_list", params=payload
            )
            # Check if the response is empty
            self.log(
                "Received API response from 'get_device_list' for the Device with ID: '{0}': {1}".format(
                    device_id, str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")

            if not response:
                self.msg = "No Device details retrieved for Device with ID: {0}, Response is empty.".format(
                    device_id
                )
                self.log(self.msg, "DEBUG")
                return None

            device_name = response[0].get("hostname")
            self.log(
                "Device ID: {0} corresponds to Hostname: {1}".format(
                    device_id, device_name
                ),
                "DEBUG",
            )
            return device_name

        except Exception as e:
            self.msg = """Error while getting the details of Device with ID: {0} present in
            Cisco Catalyst Center: {1}""".format(
                device_id, str(e)
            )
            self.fail_and_exit(self.msg)

    def create_tag_membership(self, tag_name, member_details):
        """
        Adds network device and interface members to a specified tag in the Cisco Catalyst Center.

        Args:
            tag_name (str): The name of the tag to which members are to be added.
            member_details (list): A list of dictionaries containing member details. Each dictionary must contain 'id' and 'device_type' keys.

        Returns:
            self: The current instance of the object, allowing for method chaining.

        Description:
            Adds network device and interface members to a specified tag in the Cisco Catalyst Center.
        """

        self.log(
            "Initiating tag membership creation for Tag: '{0}' with members: {1}".format(
                tag_name, self.pprint(member_details)
            ),
            "INFO",
        )

        network_device_list = []
        interface_list = []
        for member_detail in member_details:
            member_id = member_detail.get("id")
            member_type = member_detail.get("device_type")
            if member_type == "interface":
                interface_list.append(member_id)
            elif member_type == "networkdevice":
                network_device_list.append(member_id)
            else:
                self.log(
                    "Unrecognized member type '{0}' for member ID '{1}'. Skipping...".format(
                        member_type, member_id
                    ),
                    "WARNING",
                )

        self.log(
            "Total members categorized - Network Devices: {0}, Interfaces: {1}".format(
                len(network_device_list), len(interface_list)
            ),
            "DEBUG",
        )

        tag_id = self.get_tag_id(tag_name)
        #  Tag id can't be None, checking it in get_want validation functions.

        member_payload = {}

        if network_device_list:
            member_payload["networkdevice"] = network_device_list

        if interface_list:
            member_payload["interface"] = interface_list

        task_name = "add_members_to_the_tag"
        parameters = {"payload": member_payload, "id": tag_id}
        task_id = self.get_taskid_post_api_call("tag", task_name, parameters)

        if not task_id:
            self.msg = "Unable to retrieve the task_id for the task '{0}' for the tag {1}.".format(
                task_name, tag_name
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
            return self

        success_msg = "Added Tag members successfully for the tag {0} in the Cisco Catalyst Center".format(
            tag_name
        )
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self

    def get_tags_associated_with_the_network_devices(self, network_device_details):
        """
        Retrieves tags associated with a list of network devices in batches from the Cisco Catalyst Center.

        Args:
            network_device_details (list): A list of dictionaries, each containing 'id' (device ID) to identify the network devices.

        Returns:
            dict: A dictionary where the keys are device IDs and the values are lists of dictionaries,
            each containing 'tag_name' and 'tag_id' for associated tags.

        Description:
            Retrieves tags associated with a list of network devices in batches from the Cisco Catalyst Center.
        """

        self.log(
            "Initiating retrieval of tags associated with network devices: {0}".format(
                self.pprint(network_device_details)
            ),
            "DEBUG",
        )

        fetched_tags_details = {}
        device_ids = []
        for network_device_detail in network_device_details:
            device_id = network_device_detail.get("id")
            fetched_tags_details["{0}".format(device_id)] = []
            device_ids.append(device_id)

        if not device_ids:
            self.log(
                "No valid device IDs provided. Exiting retrieval process.", "WARNING"
            )
            return {}
        self.log("Retrieved Device IDs: {0}".format(device_ids), "DEBUG")

        BATCH_SIZE = self.NETWORK_DEVICE_TAG_RETRIEVAL_BATCH_SIZE
        total_batches = (
            len(device_ids) + BATCH_SIZE - 1
        ) // BATCH_SIZE  # Calculate total batches

        for batch_index, i in enumerate(range(0, len(device_ids), BATCH_SIZE), start=1):
            batch = device_ids[i : i + BATCH_SIZE]

            self.log(
                "Processing batch {0}/{1}, Device IDs: {2}".format(
                    batch_index, total_batches, batch
                ),
                "DEBUG",
            )

            try:
                payload = {"ids": batch}

                response = self.dnac._exec(
                    family="tag",
                    function="query_the_tags_associated_with_network_devices",
                    op_modifies=True,
                    params=payload,
                )
                # Check if the response is empty
                self.log(
                    "Received API response from 'query_the_tags_associated_with_network_devices' for batch {0} payload: {1}, {2}".format(
                        batch_index, payload, str(response)
                    ),
                    "DEBUG",
                )
                response = response.get("response")

                if not response:
                    self.log(
                        "No tags details retrieved for batch: {0}, Payload: {1}, Response is empty.".format(
                            batch_index, payload
                        ),
                        "DEBUG",
                    )
                    continue

                for device in response:
                    device_id = device.get("id")
                    tags = device.get("tags")
                    if tags is not None:
                        for tag in tags:
                            tag_name = tag.get("name")
                            tag_id = tag.get("id")
                            tag_detail_dict = {"tag_name": tag_name, "tag_id": tag_id}
                            fetched_tags_details[device_id].append(tag_detail_dict)

            except Exception as e:
                self.msg = "Error while retrieving tag details for batch {0}/{1} in Cisco Catalyst Center: {2}".format(
                    batch_index, total_batches, str(e)
                )
                self.fail_and_exit(self.msg)

        self.log(
            "Retrieved tags details from network devices: {0}".format(
                fetched_tags_details
            ),
            "INFO",
        )
        return fetched_tags_details

    def get_tags_associated_with_the_interfaces(self, interface_details):
        """
        Retrieves tags associated with a list of interfaces in batches from the Cisco Catalyst Center.

        Args:
            interface_details (list): A list of dictionaries, each containing 'id' (interface ID) to identify the interfaces.

        Returns:
            dict: A dictionary where the keys are interface IDs and the values are lists of dictionaries,
                each containing 'tag_name' and 'tag_id' for associated tags.

        Description:
            Retrieves tags associated with a list of interfaces in batches from the Cisco Catalyst Center.
        """

        self.log(
            "Initiating retrieval of tags associated with interfaces: {0}".format(
                interface_details
            ),
            "DEBUG",
        )

        fetched_tags_details = {}
        interface_ids = []
        for interface_detail in interface_details:
            interface_id = interface_detail.get("id")
            fetched_tags_details["{0}".format(interface_id)] = []
            interface_ids.append(interface_id)

        if not interface_ids:
            self.log(
                "No valid interface IDs provided. Exiting retrieval process.", "WARNING"
            )
            return {}

        BATCH_SIZE = self.INTERFACE_TAG_RETRIEVAL_BATCH_SIZE
        total_batches = (
            len(interface_ids) + BATCH_SIZE - 1
        ) // BATCH_SIZE  # Calculate total batches

        for batch_index, i in enumerate(
            range(0, len(interface_ids), BATCH_SIZE), start=1
        ):
            batch = interface_ids[i : i + BATCH_SIZE]

            self.log(
                "Processing batch {0}/{1}, Interface IDs: {2}".format(
                    batch_index, total_batches, batch
                ),
                "DEBUG",
            )

            try:
                payload = {"ids": batch}
                response = self.dnac._exec(
                    family="tag",
                    function="query_the_tags_associated_with_interfaces",
                    op_modifies=True,
                    params=payload,
                )
                # Check if the response is empty
                self.log(
                    "Received API response from 'query_the_tags_associated_with_interfaces' for the batch:{0} with payload: {1} is: {2}".format(
                        batch_index, payload, str(response)
                    ),
                    "DEBUG",
                )
                response = response.get("response")
                if not response:
                    self.log(
                        "No tags details retrieved for batch: {0}, Payload: {1}, Response is empty.".format(
                            batch_index, payload
                        ),
                        "DEBUG",
                    )
                for interface in response:
                    interface_id = interface.get("id")
                    tags = interface.get("tags")
                    if tags is not None:
                        for tag in tags:
                            tag_name = tag.get("name")
                            tag_id = tag.get("id")
                            tag_detail_dict = {"tag_name": tag_name, "tag_id": tag_id}
                            fetched_tags_details[interface_id].append(tag_detail_dict)

            except Exception as e:
                self.msg = "Error while retrieving tag details for batch {0}/{1} in Cisco Catalyst Center: {2}".format(
                    batch_index, total_batches, str(e)
                )
                self.fail_and_exit(self.msg)

        self.log(
            "Retrieved tags details from interfaces: {0}".format(fetched_tags_details),
            "INFO",
        )
        return fetched_tags_details

    def compare_and_update_list(self, existing_list, new_list):
        """
        Compares two lists (existing and new) and returns whether they need to be updated,
        based on the specified state ('merged' or 'deleted').

        Args:
            existing_list (list): The list of existing items.
            new_list (list): The list of new items to compare and merge or delete.

        Returns:
            tuple: A tuple containing:
                - bool: `True` if the list has been updated, `False` otherwise.
                - list: The updated list after merging or deleting elements.
        Description:
            Compares two lists (existing and new) and returns whether they need to be updated,
            based on the specified state ('merged' or 'deleted'). It also returns the updated list.
            This function works only in case of primary list elements (str/tuple/int/etc.).
        """

        state = self.params.get("state")
        self.log("Comparing lists for the state: '{0}'".format(state), "DEBUG")
        self.log("Existing List: {0}".format(existing_list), "DEBUG")
        self.log("New List: {0}".format(new_list), "DEBUG")

        existing_set = set(existing_list)
        new_set = set(new_list)

        updated_list = []
        if state == "merged":
            updated_list = list(existing_set | new_set)
        elif state == "deleted":
            updated_list = list(existing_set - new_set)

        # Sorted existing List
        existing_list = sorted(existing_list)
        updated_list = sorted(updated_list)

        needs_update = updated_list != existing_list

        self.log("Updated List: {0}".format(updated_list), "DEBUG")
        self.log("Needs Update: {0}".format(needs_update), "DEBUG")

        return needs_update, updated_list

    def compare_and_update_list_of_dict(self, existing_list, new_list):
        """
        Compares two lists of dictionaries (existing and new) and returns whether they need to be updated,
        based on the specified state ('merged' or 'deleted').

        Args:
            existing_list (list): A list of dictionaries representing the existing items.
            new_list (list): A list of dictionaries representing the new items to compare and merge or delete.

        Returns:
            tuple: A tuple containing:
                - bool: `True` if the list has been updated, `False` otherwise.
                - list: The updated list after merging or deleting elements.
        Description:
            Compares two lists of dictionaries (existing and new) and returns whether they need to be updated,
            based on the specified state ('merged' or 'deleted'). It also returns the updated list while preserving the order.
        """

        updated_list = []
        state = self.params.get("state")
        self.log("Comparing list of dict for the state: '{0}'".format(state), "DEBUG")
        self.log("Existing List: {0}".format(self.pprint(existing_list)), "DEBUG")
        self.log("New List: {0}".format(self.pprint(new_list)), "DEBUG")

        if state == "merged":
            # Merge while preserving order
            updated_list = existing_list.copy()
            for new_dict in new_list:
                if (
                    new_dict not in existing_list
                ):  # Check if new_dict is already in existing_list
                    updated_list.append(new_dict)

        elif state == "deleted":
            # Delete elements in new_list from existing_list while preserving order
            updated_list = [d for d in existing_list if d not in new_list]

        # Check if there's a difference
        needs_update = updated_list != existing_list
        self.log("Needs Update: {0}".format(needs_update), "DEBUG")
        self.log("Updated List: {0}".format(self.pprint(updated_list)), "DEBUG")

        return needs_update, updated_list

    def update_tags_associated_with_the_network_devices(self, payload):
        """
        Updates the tags associated with network devices.

        Args:
            payload (list): A list of data representing the tags to be associated with the network devices. Each entry in the list
                corresponds to a devices with their associated tags as a list.

        Returns:
            self: The instance of the class, allowing for method chaining.

        Description:
            Updates the tags associated with network devices in batches and checks the status of each update task.
            The function breaks down the payload into smaller batches, sends them to the Cisco Catalyst Center API,
            and retrieves the task ID for each batch to track the update progress.
        """

        self.log("Starting to update tags associated with the network devices.", "INFO")

        task_name = "update_tags_associated_with_the_network_devices"

        BATCH_SIZE = self.NETWORK_DEVICE_TAG_UPDATE_BATCH_SIZE
        start_index = 0

        while start_index < len(payload):
            batch = payload[start_index : start_index + BATCH_SIZE]
            parameters = {"payload": batch}
            task_id = self.get_taskid_post_api_call("tag", task_name, parameters)
            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0} for the batch {1} with the payload {2}'.".format(
                    task_name, start_index // BATCH_SIZE + 1, payload
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                break

            self.log(
                "Successfully retrieved task_id for {0}: {1} for batch {2}.".format(
                    task_name, task_id, start_index // BATCH_SIZE + 1
                ),
                "INFO",
            )
            success_msg = "Updated Tags associated with the network devices for the batch {0} successfully in the Cisco Catalyst Center".format(
                start_index // BATCH_SIZE + 1
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

            start_index += BATCH_SIZE

        return self

    def update_tags_associated_with_the_interfaces(self, payload):
        """
        Update the tags associated with interfaces.

        Args:
            payload (list): A list of data representing the tags to be associated with interfaces. Each entry in the list corresponds
                            to a batch of interfaces with their associated tags as a list.

        Returns:
            self: The instance of the class, allowing for method chaining.

        Description:
            Updates the tags associated with interfaces in batches and checks the status of each update task.
            The function splits the provided payload into smaller batches and sends each batch to the Cisco Catalyst Center API.
            It tracks the task status for each batch after it is submitted.
        """

        self.log("Starting to update tags associated with the interfaces.", "INFO")

        task_name = "update_tags_associated_with_the_interfaces"
        BATCH_SIZE = self.INTERFACE_TAG_UPDATE_BATCH_SIZE
        start_index = 0

        while start_index < len(payload):
            batch = payload[start_index : start_index + BATCH_SIZE]
            parameters = {"payload": batch}

            task_id = self.get_taskid_post_api_call("tag", task_name, parameters)
            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0} for the payload {1}'.".format(
                    task_name, payload
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                break

            self.log(
                "Successfully retrieved task_id for {0}: {1} for batch {2}.".format(
                    task_name, task_id, start_index // BATCH_SIZE + 1
                ),
                "INFO",
            )

            success_msg = "Updated Tags associated with the interfaces successfully for the batch: {0} in the Cisco Catalyst Center".format(
                start_index // BATCH_SIZE + 1
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

            start_index += BATCH_SIZE

        return self

    def updating_network_device_tag_memberships(
        self, network_device_details, new_tags_details
    ):
        """
        Updates the tag memberships for network devices.

        Args:
            network_device_details (list): A list of dictionaries containing details about network devices.
            new_tags_details (list): A list of dictionaries containing the new tags to be associated with the devices.

        Returns:
            self (object): The current instance after updating the tag memberships.

        Description:
            This function updates the tag memberships for network devices by comparing the existing tags with the new ones.
            If there is a change in the tags, the function updates the device's tags in batches. If the number of tags exceeds
            the maximum limit (defined by `MAX_TAGS_LIMIT_PER_MEMBER`), an error is raised. It handles both "merged" and "deleted"
            states and updates accordingly.
        """

        state = self.params.get("state")
        self.log(
            "Starting tag membership update process for {0} devices. Operation state: {1}.".format(
                network_device_details, state
            ),
            "INFO",
        )

        fetched_tags_details = self.get_tags_associated_with_the_network_devices(
            network_device_details
        )
        payload = []
        for network_device_detail in network_device_details:

            device_id = network_device_detail.get("id")
            device_identifier = network_device_detail.get("device_identifier")
            device_value = network_device_detail.get("device_value")
            network_device_detail["tags_list"] = new_tags_details

            needs_update, updated_tags = self.compare_and_update_list_of_dict(
                fetched_tags_details.get(device_id), new_tags_details
            )
            if needs_update:
                updated_tags_ids = []
                for tag_detail in updated_tags:
                    tag_id = tag_detail.get("tag_id")
                    tag_id_dict = {"id": tag_id}
                    updated_tags_ids.append(tag_id_dict)
                MAX_TAGS_LIMIT = self.MAX_TAGS_LIMIT_PER_MEMBER
                if len(updated_tags_ids) > MAX_TAGS_LIMIT:
                    self.msg = "The maximum tag limit exceed for the device with {0}:{1}. The maximum number of tags a device can have is {2}. ".format(
                        device_identifier, device_value, MAX_TAGS_LIMIT
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
                current_device_payload = {"id": device_id, "tags": updated_tags_ids}
                if state == "merged":
                    self.updated_tag_memberships.append(network_device_detail)
                elif state == "deleted":
                    self.deleted_tag_memberships.append(network_device_detail)

                payload.append(current_device_payload)
            else:
                if state == "merged":
                    network_device_detail["reason"] = (
                        "Device is already Tagged with the given tags. Nothing to update."
                    )
                    self.not_updated_tag_memberships.append(network_device_detail)
                elif state == "deleted":
                    network_device_detail["reason"] = (
                        "Device is not tagged with given tags. Nothing to delete."
                    )
                    self.not_deleted_tag_memberships.append(network_device_detail)

        if payload:
            self.update_tags_associated_with_the_network_devices(payload)
        else:
            self.log(
                "No need for updating tags associated with the network devices", "DEBUG"
            )

        return self

    def updating_interface_tag_memberships(self, interface_details, new_tags_details):
        """
        Updates the tag memberships for interfaces.

        Args:
            interface_details (list): A list of dictionaries containing details about the interfaces.
            new_tags_details (list): A list of dictionaries containing the new tags to be associated with the interfaces.

        Returns:
            self (object): The current instance after updating the tag memberships.

        Description:
            This function updates the tag memberships for interfaces by comparing the existing tags with the new ones.
            If there is a change in the tags, the function updates the interface's tags in batches. If the number of tags exceeds
            the maximum limit (defined by `MAX_TAGS_LIMIT_PER_MEMBER`), an error is raised. It handles both "merged" and "deleted"
            states and updates accordingly.
        """

        state = self.params.get("state")
        self.log(
            "Starting tag membership update process for {0} interfaces. Operation state: {1}.".format(
                interface_details, state
            ),
            "INFO",
        )

        fetched_tags_details = self.get_tags_associated_with_the_interfaces(
            interface_details
        )
        payload = []
        for interface_detail in interface_details:
            device_id = interface_detail.get("id")
            interface_detail["tags_list"] = new_tags_details
            device_identifier = interface_detail.get("device_identifier")
            device_value = interface_detail.get("device_value")
            interface_name = interface_detail.get("interface_name")

            needs_update, updated_tags = self.compare_and_update_list_of_dict(
                fetched_tags_details.get(device_id), new_tags_details
            )
            if needs_update:
                updated_tags_ids = []
                for tag_detail in updated_tags:
                    tag_id = tag_detail.get("tag_id")
                    tag_id_dict = {"id": tag_id}
                    updated_tags_ids.append(tag_id_dict)

                MAX_TAGS_LIMIT = self.MAX_TAGS_LIMIT_PER_MEMBER
                if len(updated_tags_ids) > MAX_TAGS_LIMIT:
                    self.msg = (
                        "The maximum tag limit exceed for the interface: {0} with {1}:{2}."
                        "The maximum number of tags A device can have is {3}.".format(
                            interface_name,
                            device_identifier,
                            device_value,
                            MAX_TAGS_LIMIT,
                        )
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
                current_interface_payload = {"id": device_id, "tags": updated_tags_ids}

                if state == "merged":
                    self.updated_tag_memberships.append(interface_detail)
                elif state == "deleted":
                    self.deleted_tag_memberships.append(interface_detail)
                payload.append(current_interface_payload)
            else:
                if state == "merged":
                    interface_detail["reason"] = (
                        "Interface is already Tagged to the given tags. Nothing to update."
                    )
                    self.not_updated_tag_memberships.append(interface_detail)
                elif state == "deleted":
                    interface_detail["reason"] = (
                        "Interface is not tagged to given tags. Nothing to delete."
                    )
                    self.not_deleted_tag_memberships.append(interface_detail)
        if payload:
            self.update_tags_associated_with_the_interfaces(payload)
        else:
            self.log(
                "No need for updating tags associated with the interfaces", "DEBUG"
            )

        return self

    def updating_tag_memberships(self, tag_memberships):
        """
        Updates tag memberships for network devices and interfaces based on provided details.

        Args:
            tag_memberships (dict): A dictionary containing 'device_details', 'tags_name_id', and optionally
                                    'site_details' to update the tags.

        Returns:
            self (object): The current instance after updating tags.

        Description:
            This function processes tag memberships for network devices and interfaces. It compares existing and new tags,
            and updates them in batches based on the provided 'merged' or 'deleted' state. It handles devices and interfaces
            separately, and if the number of tags exceeds the maximum limit (defined by `MAX_TAGS_LIMIT_PER_MEMBER`), an error is raised.
        """

        self.log(
            "Starting tag membership update process for {0}".format(tag_memberships),
            "INFO",
        )
        device_details = tag_memberships.get("device_details")
        new_tags_details = tag_memberships.get("tags_name_id")
        member_details = []

        if device_details:
            formatted_device_details = self.format_device_details(device_details)
            member_details = member_details + formatted_device_details

        site_details = tag_memberships.get("site_details")

        if site_details:
            formatted_site_details = self.format_site_details(site_details)
            member_details = member_details + formatted_site_details

        interface_details = []
        network_device_details = []

        for member_detail in member_details:
            member_type = member_detail.get("device_type")
            if member_type == "networkdevice":
                network_device_details.append(member_detail)

            elif member_type == "interface":
                interface_details.append(member_detail)

        tag_memberships["network_device_details"] = network_device_details
        tag_memberships["interface_details"] = interface_details

        if network_device_details:
            self.updating_network_device_tag_memberships(
                network_device_details, new_tags_details
            )

        if interface_details:
            self.updating_interface_tag_memberships(interface_details, new_tags_details)

        return self

    def compare_and_update_scope_description(
        self, scope_description, scope_description_in_ccc
    ):
        """
        Compares and updates the scope description between provided and CCC data.

        Args:
            scope_description (dict): The scope description to compare and update.
            scope_description_in_ccc (dict): The current scope description in CCC.

        Returns:
            tuple: (bool, dict) indicating if update is needed and the updated scope description.

        Description:
            Compares and updates the scope description between provided and CCC data.
        """

        state = self.params.get("state")
        self.log(
            "Checking scope description for updates for state: {0}. Inputs - scope_description: {1}, existing: {2}".format(
                state,
                self.pprint(scope_description),
                self.pprint(scope_description_in_ccc),
            ),
            "DEBUG",
        )
        requires_update = False

        # Scope Description in Cisco Catalyst Center can't be None, else port_rule won't exist in the first place.
        if scope_description is None:
            self.log(
                "Scope description is None. Keeping the existing description unchanged.",
                "DEBUG",
            )
            return requires_update, scope_description_in_ccc

        scope_category = scope_description.get("groupType")
        scope_category_in_ccc = scope_description_in_ccc.get("groupType")

        scope_members = scope_description.get("scopeObjectIds")
        scope_members_in_ccc = scope_description_in_ccc.get("scopeObjectIds")

        inherit = scope_description.get("inherit")
        inherit_in_ccc = scope_description_in_ccc.get("inherit")

        self.log("Validating scope category and inheritance settings.", "DEBUG")
        updated_scope_description = {}

        if scope_category == scope_category_in_ccc:

            if inherit != inherit_in_ccc:
                requires_update = True
                self.log(
                    "Inheritance setting has changed. Marking for update.", "DEBUG"
                )

            tmp_requires_update, updated_scope_members = self.compare_and_update_list(
                scope_members_in_ccc, scope_members
            )
            requires_update = requires_update | tmp_requires_update
            if tmp_requires_update:
                self.log("Scope members have changed. Marking for update.", "DEBUG")

            if not updated_scope_members:
                # In this case user wants to delete all the scope members, so returning empty updated_scope_description
                self.log(
                    "All scope members removed. Returning empty updated scope description.",
                    "DEBUG",
                )
                return requires_update, updated_scope_description

            updated_scope_description.update(
                {
                    "groupType": scope_category,
                    "inherit": inherit,
                    "scopeObjectIds": updated_scope_members,
                }
            )

        else:
            if state == "deleted":
                self.msg = (
                    "For state: {0}, scope_category must match the existing one.\n"
                    "Provided: '{1}', Existing: {2}"
                ).format(state, scope_category, scope_category_in_ccc)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
            elif state == "merged":
                if not scope_members:
                    self.msg = (
                        "For state: {0}, when changing scope_category, scope_members can't be empty.\n"
                        "Provided members: {1}, Scope category: '{2}', Existing category: {3}"
                    ).format(
                        state, scope_members, scope_category, scope_category_in_ccc
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
            requires_update = True

            updated_scope_description.update(
                {
                    "groupType": scope_category,
                    "inherit": inherit,
                    "scopeObjectIds": scope_members,
                }
            )
            self.log("Scope category change detected. Update required.", "DEBUG")

        updated_scope_description["memberType"] = "networkdevice"
        self.log(
            "Update required in scope description: {0}".format(requires_update), "DEBUG"
        )
        self.log(
            "Updated scope description: {0}".format(
                self.pprint(updated_scope_description)
            ),
            "DEBUG",
        )

        return requires_update, updated_scope_description

    def ungroup_rules_tree_into_list(self, rules):
        """
        Recursively extracts all leaf nodes (base rules) from a nested rule structure.

        Args:
            rules (dict or None): The rule structure, which may contain nested dictionaries.

        Returns:
            list: A list of leaf nodes (base rules).

        Description: Recursively extracts all leaf nodes (base rules) from a nested rule structure.
        """

        if rules is None:
            self.log("Rules input is None. Returning None.", "DEBUG")
            return None

        leaf_nodes = []

        # Check if the current dictionary has 'items' (indicating nested conditions)
        if isinstance(rules, dict) and "items" in rules:
            for item in rules["items"]:
                # Recursively process each item
                leaf_nodes.extend(self.ungroup_rules_tree_into_list(item))
        else:
            # If no 'items', it's a leaf node
            leaf_nodes.append(rules)

        return leaf_nodes

    def compare_and_update_rules(self, rules, rules_in_ccc):
        """
        Description: Compares and updates rules based on the current state (merged or deleted).

        Args:
            rules (dict): The new set of rules to compare.
            rules_in_ccc (dict): The existing set of rules from the Cisco Catalyst Center.

        Returns:
            tuple: A tuple containing a boolean indicating if an update is required and the updated rules (or None).
        """

        requires_update = False
        state = self.params.get("state")

        self.log(
            "Comparing and updating rules. State: {0}, New rules: {1}, Existing rules: {2}".format(
                self.params.get("state"), self.pprint(rules), self.pprint(rules_in_ccc)
            ),
            "DEBUG",
        )

        if state == "merged":
            if rules is None and rules_in_ccc is None:
                self.log(
                    "Both new and existing rules are None. No update required.", "DEBUG"
                )
                return requires_update, None

            if rules is None:  # Nothing to update case
                self.log(
                    "New rules are None. Keeping existing rules unchanged.", "DEBUG"
                )
                return requires_update, rules_in_ccc

            if rules_in_ccc is None:  # Updating it with the new rules
                self.log("Existing rules are None. Updating with new rules.", "DEBUG")
                requires_update = True
                return requires_update, rules

        elif state == "deleted":
            if rules is None and rules_in_ccc is None:
                self.log(
                    "Both new and existing rules are None. Nothing to delete. No update required.",
                    "DEBUG",
                )
                return requires_update, None

            if rules is None:  # Nothing to delete case
                self.log(
                    "New rules are None. Nothing to delete. Keeping existing rules unchanged.",
                    "DEBUG",
                )
                return requires_update, rules_in_ccc

            if rules_in_ccc is None:  # Nothing to delete case
                self.log("Existing rules are None. Nothing to delete.", "DEBUG")
                return requires_update, rules_in_ccc

        requires_update, updated_rules = self.compare_and_update_list_of_dict(
            rules_in_ccc, rules
        )
        self.log(
            "Update required: {0}. Updated rules: {1}".format(
                requires_update, self.pprint(updated_rules)
            ),
            "DEBUG",
        )
        return requires_update, updated_rules

    def compare_and_update_port_rules(self, port_rules, port_rules_in_ccc):
        """
        Compares and updates port rules between the provided `port_rules` and `port_rules_in_ccc`.

        Args:
            port_rules (dict): Port rules to be applied.
            port_rules_in_ccc (dict): Current port rules in Cisco Catalyst Center (CCC).

        Returns:
            tuple: A boolean indicating if an update is required and the updated port rules dictionary.

        Description:
            Compares and updates port rules between the provided `port_rules` and `port_rules_in_ccc`.
        """

        requires_update = False
        state = self.params.get("state")

        self.log("Comparing and updating port rules. State: {0}".format(state), "DEBUG")
        self.log(
            "Input port rules: {0}, Existing port rules: {1}".format(
                self.pprint(port_rules), self.pprint(port_rules_in_ccc)
            ),
            "DEBUG",
        )

        if state == "merged":
            # Both are Absent
            if port_rules is None and port_rules_in_ccc is None:
                self.log(
                    "Both new and existing port rules are None. No update required.",
                    "DEBUG",
                )
                return requires_update, None

            # One is Absent, as nothing to merge, So No update required
            if port_rules is None:
                self.log(
                    "New port rules are None. Keeping existing rules unchanged.",
                    "DEBUG",
                )
                return requires_update, port_rules_in_ccc

            if port_rules_in_ccc is None:
                #  Update is required, In existing there are No port_rules, so both scope and rules are required.
                requires_update = True
                scope_description = port_rules.get("scopeRule")
                rules = port_rules.get("rules")

                if not scope_description or not rules:
                    self.msg = (
                        "Either rule_description:{0} or scope_description:{1} is empty in port_rules."
                        " Since no existing port rules are present, both are required for an update.".format(
                            rules, scope_description
                        )
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                self.log(
                    "Existing port rules are None. Updating with new rules.", "DEBUG"
                )
                return requires_update, port_rules

        elif state == "deleted":
            # Both are Absent
            if port_rules is None and port_rules_in_ccc is None:
                self.log(
                    "Both new and existing port rules are None. No update required.",
                    "DEBUG",
                )
                return requires_update, None

            # One is Absent, Existing No port rules so nothing to delete
            if port_rules_in_ccc is None:
                self.log(
                    "Existing device rules are already absent; nothing to delete.",
                    "DEBUG",
                )
                return requires_update, port_rules_in_ccc

            # One is Absent, No new port rules in playbook, so nothing to delete
            if port_rules is None:
                self.log("Port rules are None, no need to delete anything.", "DEBUG")
                return requires_update, port_rules_in_ccc

        #  Both exist case:
        self.log(
            "Both provided and existing port rules are present. Comparing rules for updates...",
            "DEBUG",
        )

        scope_description = port_rules.get("scopeRule")
        scope_description_in_ccc = port_rules_in_ccc.get("scopeRule")

        tmp_required_update, updated_scope_description = (
            self.compare_and_update_scope_description(
                scope_description, scope_description_in_ccc
            )
        )
        requires_update = tmp_required_update | requires_update

        rules = port_rules.get("rules")
        rules_in_ccc = port_rules_in_ccc.get("rules")

        tmp_requires_update, updated_rules = self.compare_and_update_rules(
            rules, rules_in_ccc
        )
        requires_update = tmp_requires_update | requires_update

        updated_port_rules = {}

        if not updated_scope_description and not updated_rules:
            self.log("No changes detected. Returning unchanged rules.", "DEBUG")
            return requires_update, updated_port_rules

        if not updated_scope_description or not updated_rules:
            if not updated_scope_description:
                self.msg = (
                    "On deletion, the scope description for port rules {0} is being cleared entirely. "
                    "At least one scope member must be left after deletion to proceed"
                    "with the deletion in Cisco Catalyst Center"
                ).format(updated_scope_description)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
            else:
                self.msg = (
                    "On deletion, the rule descriptions for port rules {0} is being cleared entirely. "
                    "At least one rule must be left after deletion to proceed with the deletion in Cisco Catalyst Center"
                ).format(updated_rules)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        updated_port_rules = {
            "memberType": "interface",
            "rules": updated_rules,
            "scopeRule": updated_scope_description,
        }

        self.log(
            "Comparison result - Requires update:{0}, Updated port rules:{1}".format(
                requires_update, self.pprint(updated_port_rules)
            ),
            "DEBUG",
        )

        return requires_update, updated_port_rules

    def compare_and_update_device_rules(self, device_rules, device_rules_in_ccc):
        """
        Compares and updates port rules between the provided `port_rules` and `port_rules_in_ccc`.

        Args:
            device_rules (dict): Device rules to be applied.
            device_rules_in_ccc (dict): Current device rules in Cisco Catalyst Center (CCC).

        Returns:
            tuple: A boolean indicating if an update is required and the updated device rules dictionary.

        Description:
            Compares and updates device rules between the provided `device_rules` and `device_rules_in_ccc`.
        """

        requires_update = False
        state = self.params.get("state")
        self.log(
            "Starting device rule comparison for state: '{0}'".format(state), "DEBUG"
        )
        self.log(
            "Provided device rules: {0}".format(self.pprint(device_rules)), "DEBUG"
        )
        self.log(
            "Existing device rules in CCC: {0}".format(
                self.pprint(device_rules_in_ccc)
            ),
            "DEBUG",
        )

        # Handle None cases upfront
        if device_rules_in_ccc is None and device_rules is None:
            self.log(
                "Both provided and existing device rules are None. No update required.",
                "DEBUG",
            )
            return requires_update, None

        if state == "merged":
            # One is Absent
            if device_rules is None:
                #  No merge required
                self.log(
                    "Device rules are None; using existing rules in CCC. No merge required.",
                    "DEBUG",
                )
                return requires_update, device_rules_in_ccc

            #  device_rules is Not None, so update required
            if device_rules_in_ccc is None:
                requires_update = True
                self.log(
                    "Existing device rules in CCC are None; update required with new device rules.",
                    "INFO",
                )
                return requires_update, device_rules

        elif state == "deleted":
            # Any one is absent, device_rules is none so, nothing to delete
            if device_rules is None:
                self.log("Device rules are None, no need to delete anything.", "DEBUG")
                return requires_update, device_rules_in_ccc

            # Any one is absent, device_rules_in_ccc is None, so nothing to delete
            if device_rules_in_ccc is None:
                self.log(
                    "Existing device rules are already absent; nothing to delete.",
                    "DEBUG",
                )
                return requires_update, device_rules_in_ccc

        self.log(
            "Both provided and existing device rules are present. Comparing rules for updates...",
            "DEBUG",
        )
        #  Both are present case
        rules = device_rules.get("rules")
        rules_in_ccc = device_rules_in_ccc.get("rules")

        tmp_requires_update, updated_rules = self.compare_and_update_rules(
            rules, rules_in_ccc
        )
        requires_update = tmp_requires_update | requires_update

        updated_device_rules = {}
        if updated_rules:
            updated_device_rules = {
                "memberType": "networkdevice",
                "rules": updated_rules,
            }

        self.log("Comparing device rules for state: '{0}'".format(state), "DEBUG")
        self.log(
            "new device rules:{0} and existing device rules:{1}".format(
                self.pprint(device_rules), self.pprint(device_rules_in_ccc)
            ),
            "DEBUG",
        )
        self.log(
            "Requires update:{0}, updated device rules:{1}".format(
                requires_update, self.pprint(updated_device_rules)
            ),
            "DEBUG",
        )

        return requires_update, updated_device_rules

    def compare_and_update_tag(self, tag, tag_in_ccc):
        """
        Compares and updates tag details, including device rules and port rules,
        between the provided tag and the one in Cisco Catalyst Center (CCC).

        Args:
            tag (dict): The tag containing the updated information.
            tag_in_ccc (dict): The existing tag information in Cisco Catalyst Center (CCC).

        Returns:
            tuple: A boolean indicating if an update is required and the updated tag details.

        Description:
            Compares and updates tag details, including device rules and port rules, between the provided tag and the one in Cisco Catalyst Center (CCC).
        """

        self.log("Starting tag comparison...", "DEBUG")
        self.log("Provided tag details: {0}".format(self.pprint(tag)), "DEBUG")
        self.log(
            "Existing tag details in CCC: {0}".format(self.pprint(tag_in_ccc)), "DEBUG"
        )
        requires_update = False

        tag_name = tag.get("name")
        new_tag_name = tag.get("new_name", "")
        description = tag.get("description")
        device_rules = tag.get("device_rules")
        port_rules = tag.get("port_rules")

        formatted_device_rules = self.format_device_rules(device_rules)
        formatted_port_rules = self.format_port_rules(port_rules)

        tag_name_in_ccc = tag_in_ccc.get("name")
        description_in_ccc = tag_in_ccc.get("description")
        dynamic_rules_in_ccc = tag_in_ccc.get("dynamicRules", [])
        dynamic_rule_dict_in_ccc = {}

        for dynamic_rule_in_ccc in dynamic_rules_in_ccc:
            member_type_in_ccc = dynamic_rule_in_ccc.get("memberType")
            rules_in_ccc = dynamic_rule_in_ccc.get("rules")
            ungrouped_rules_in_ccc = self.ungroup_rules_tree_into_list(rules_in_ccc)
            if member_type_in_ccc == "interface":
                scope_description_in_ccc = dynamic_rule_in_ccc.get("scopeRule")
                dynamic_rule_dict_in_ccc["formatted_port_rules_in_ccc"] = {
                    "memberType": member_type_in_ccc,
                    "rules": ungrouped_rules_in_ccc,
                    "scopeRule": scope_description_in_ccc,
                }
            elif member_type_in_ccc == "networkdevice":
                dynamic_rule_dict_in_ccc["formatted_device_rules_in_ccc"] = {
                    "memberType": member_type_in_ccc,
                    "rules": ungrouped_rules_in_ccc,
                }

        # These are extracted from CCC so they are already formatted.
        formatted_device_rules_in_ccc = dynamic_rule_dict_in_ccc.get(
            "formatted_device_rules_in_ccc"
        )
        formatted_port_rules_in_ccc = dynamic_rule_dict_in_ccc.get(
            "formatted_port_rules_in_ccc"
        )
        updated_tag_info = {"name": tag_name}

        if new_tag_name and tag_name_in_ccc != new_tag_name:
            self.log(
                f"New Tag Name provided: '{new_tag_name}'. Existing tag name: '{tag_name_in_ccc}'. Update required.",
                "INFO",
            )
            updated_tag_info["name"] = new_tag_name
            requires_update = True

        tmp_requires_update, updated_device_rules = (
            self.compare_and_update_device_rules(
                formatted_device_rules, formatted_device_rules_in_ccc
            )
        )
        requires_update = tmp_requires_update | requires_update

        tmp_requires_update, updated_port_rules = self.compare_and_update_port_rules(
            formatted_port_rules, formatted_port_rules_in_ccc
        )
        requires_update = tmp_requires_update | requires_update

        if updated_device_rules:
            updated_device_rules["rules"] = self.group_rules_into_tree(
                updated_device_rules["rules"]
            )

        if updated_port_rules:
            updated_port_rules["rules"] = self.group_rules_into_tree(
                updated_port_rules["rules"]
            )

        updated_dynamic_rules = self.combine_device_port_rules(
            updated_device_rules, updated_port_rules
        )

        if description_in_ccc is not None and description is not None:
            if description != description_in_ccc:
                self.log("Tag description differs. Update required.", "INFO")
                requires_update = True
                updated_tag_info["description"] = description
            else:
                self.log(
                    "The new tag description matches the previous one. No update necessary.",
                    "INFO",
                )
                updated_tag_info["description"] = description_in_ccc
        elif description_in_ccc is not None:
            self.log("New Tag description is None. No Update required.", "INFO")
            updated_tag_info["description"] = description_in_ccc
        elif description is not None:
            self.log("Tag description is new. Update required.", "INFO")
            requires_update = True
            updated_tag_info["description"] = description
        else:
            updated_tag_info["description"] = description_in_ccc

        if updated_dynamic_rules:
            updated_tag_info["dynamic_rules"] = updated_dynamic_rules

        state = self.params.get("state")
        self.log("Comparing tag info for state: '{0}'".format(state), "DEBUG")
        self.log(
            "new tag info: {0} and existing tag info:{1}".format(
                self.pprint(tag), self.pprint(tag_in_ccc)
            ),
            "DEBUG",
        )
        self.log(
            "Requires update:{0}, updated tag info:{1}".format(
                requires_update, self.pprint(updated_tag_info)
            ),
            "DEBUG",
        )

        return requires_update, updated_tag_info

    def update_tag(self, tag, tag_id):
        """
        Updates a tag in the Cisco Catalyst Center (CCC) with the provided tag details.

        Args:
            tag (dict): The tag containing the updated information.
            tag_id (str): The ID of the tag to be updated.

        Returns:
            self: The updated instance with the tag's name appended to the updated_tag list if the update is successful.

        Description:
            Updates a tag in the Cisco Catalyst Center (CCC) with the provided tag details.
        """
        tag_name = tag.get("name")
        self.log(
            "Initiating update for tag: '{0}' with tag_id: '{1}'".format(
                tag_name, tag_id
            ),
            "INFO",
        )
        description = tag.get("description")
        tag_payload = {"name": tag_name, "description": description, "id": tag_id}
        new_tag_name = tag.get("new_tag_name")
        if new_tag_name:
            self.log(
                f"New tag name provided: '{new_tag_name}'. Updating tag name from '{tag_name}' to '{new_tag_name}'.",
                "DEBUG",
            )
            tag_payload.update({"name": new_tag_name})

        dynamic_rules = tag.get("dynamic_rules")
        if dynamic_rules:
            self.log(
                "Dynamic rules detected for tag '{0}', adding to payload.".format(
                    tag_name
                ),
                "DEBUG",
            )
            tag_payload["dynamicRules"] = dynamic_rules

        task_name = "update_tag"
        parameters = {"payload": tag_payload}
        task_id = self.get_taskid_post_api_call("tag", task_name, parameters)

        if not task_id:
            self.msg = (
                "Unable to retrieve the task_id for the updating tag {1}'.".format(
                    tag_name
                )
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
            return self

        success_msg = (
            "Tag: '{0}' updated successfully in the Cisco Catalyst Center".format(
                tag_name
            )
        )
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self

    def delete_tag(self, tag, tag_id):
        """
        Deletes a tag from the Cisco Catalyst Center (CCC) based on the provided tag ID.

        Args:
            tag (dict): The tag containing the name and other details of the tag to be deleted.
            tag_id (str): The ID of the tag to be deleted.

        Returns:
            self: The updated instance with the tag's name appended to the deleted_tag list if the deletion is successful.
        """

        tag_name = tag.get("name")
        self.log(
            "Initiating deletion for tag: '{0}' with tag_id: '{1}'".format(
                tag_name, tag_id
            ),
            "INFO",
        )

        task_name = "delete_tag"
        parameters = {"id": tag_id}
        task_id = self.get_taskid_post_api_call("tag", task_name, parameters)

        if not task_id:
            self.msg = (
                "Unable to retrieve the task_id for the deleting tag {0}'.".format(
                    tag_name
                )
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
            return self

        success_msg = (
            "Tag: '{0}' deleted successfully in the Cisco Catalyst Center".format(
                tag_name
            )
        )
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self

    def get_tag_associated_network_devices(self, tag_name, tag_id):
        """
        Fetches network devices associated with a specific tag from the Cisco Catalyst Center (CCC).

        Args:
            tag_name (str): The name of the tag for which network devices are being fetched.
            tag_id (str): The ID of the tag whose associated network devices are to be retrieved.

        Returns:
            list: A list of dictionaries, each containing details about a network device (ID, device type, identifier, and value).

        Description:
            This method fetches network devices associated with a given tag from the Cisco Catalyst Center,
            handling pagination and retries. It iterates through the responses in batches and logs the progress.
            It raises an error and exits if fetching the network devices fails.
        """
        self.log(
            "Fetching network device members for tag: '{0}'".format(tag_name), "DEBUG"
        )
        network_devices = []
        offset = 1
        limit = 500
        retry_count = 0
        while True:
            retry_count += 1
            self.log(
                "Attempt {0}: Fetching network devices (Offset: {1})".format(
                    retry_count, offset
                ),
                "DEBUG",
            )
            try:
                response = self.dnac._exec(
                    family="tag",
                    function="get_tag_members_by_id",
                    op_modifies=False,
                    params={
                        "id": tag_id,
                        "member_type": "networkdevice",
                        "offset": offset,
                    },
                )
                self.log(
                    "API Response (Network Devices) for tag '{0}' (Offset {1}): {2}".format(
                        tag_name, offset, response
                    ),
                    "DEBUG",
                )

                response = response.get("response")
                if not response:
                    self.log(
                        "No more network devices found for tag '{0}'".format(tag_name),
                        "DEBUG",
                    )
                    break

                for device_detail in response:
                    device_id = device_detail.get("instanceUuid")
                    device_name = self.get_device_name_by_id(device_id)
                    device_detail_dict = {
                        "id": device_id,
                        "device_type": "networkdevice",
                        "device_identifier": "hostname",
                        "device_value": device_name,
                    }
                    network_devices.append(device_detail_dict)
                if len(response) < limit:
                    self.log(
                        "Fetched last batch of network devices for tag '{0}'".format(
                            tag_name
                        ),
                        "DEBUG",
                    )
                    break
                offset += limit
            except Exception as e:
                self.msg = """Error while getting the details of Tag Members with given name '{0}' present in
                Cisco Catalyst Center: {1}""".format(
                    tag_name, str(e)
                )
                self.fail_and_exit(self.msg)
        self.log(
            "Extracted network device details for the tag: '{0}' is :{1}".format(
                tag_name, network_devices
            ),
            "INFO",
        )
        return network_devices

    def get_tag_associated_interfaces(self, tag_name, tag_id):
        """
        Fetches interfaces associated with a specific tag from the Cisco Catalyst Center (CCC).

        Args:
            tag_name (str): The name of the tag for which interfaces are being fetched.
            tag_id (str): The ID of the tag whose associated interfaces are to be retrieved.

        Returns:
            list: A list of dictionaries, each containing details about an interface (ID, device type, identifier, value, and interface name).

        Description:
            This method fetches interfaces associated with a given tag from the Cisco Catalyst Center,
            handling pagination and retries. It iterates through the responses in batches and logs the progress.
            It raises an error and exits if fetching the interfaces fails.
        """

        self.log("Fetching interface members for tag: '{0}'".format(tag_name), "DEBUG")
        offset = 1
        limit = 500
        retry_count = 0
        interfaces = []
        while True:
            try:
                retry_count += 1
                self.log(
                    "Attempt {0}: Fetching Interfaces (Offset: {1})".format(
                        retry_count, offset
                    ),
                    "DEBUG",
                )
                response = self.dnac._exec(
                    family="tag",
                    function="get_tag_members_by_id",
                    op_modifies=False,
                    params={
                        "id": tag_id,
                        "member_type": "interface",
                        "offset": offset,
                    },
                )
                self.log(
                    "API Response (Interfaces) for tag '{0}' (Offset {1}): {2}".format(
                        tag_name, offset, response
                    ),
                    "DEBUG",
                )

                response = response.get("response")
                if not response:
                    self.log(
                        "No more Interfaces found for tag '{0}'".format(tag_name),
                        "DEBUG",
                    )
                    break

                for interface_detail in response:
                    interface_id = interface_detail.get("instanceUuid")
                    device_id = interface_detail.get("deviceId")
                    interface_name = interface_detail.get("portName")
                    device_name = self.get_device_name_by_id(device_id)
                    interface_detail_dict = {
                        "id": interface_id,
                        "device_type": "interface",
                        "device_identifier": "hostname",
                        "device_value": device_name,
                        "interface_name": interface_name,
                    }
                    interfaces.append(interface_detail_dict)
                if len(response) < limit:
                    self.log(
                        "Fetched last batch of network devices for tag '{0}'".format(
                            tag_name
                        ),
                        "DEBUG",
                    )
                    break
            except Exception as e:
                self.msg = """Error while getting the details of Tag Members with given name '{0}' present in
                Cisco Catalyst Center: {1}""".format(
                    tag_name, str(e)
                )
                self.fail_and_exit(self.msg)
            offset += limit
        self.log(
            "Extracted interface details for the tag: '{0}' is :{1}".format(
                tag_name, interfaces
            ),
            "INFO",
        )
        return interfaces

    def get_tag_members(self, tag, tag_id):
        """
        Retrieves the list of members (network devices and interfaces) associated with a tag from the Cisco Catalyst Center (CCC).

        Args:
            tag (dict): The tag containing information about the tag.
            tag_id (str): The ID of the tag whose members are to be retrieved.

        Returns:
            list: A list of dictionaries containing details of the tag members (network devices and interfaces).

        Description:
            This method retrieves the list of members (network devices and interfaces) associated with a tag
            from the Cisco Catalyst Center. It fetches network devices and interfaces separately, combines them,
            and returns the complete list. The function also handles errors and logs the progress of retrieval.
        """

        tag_name = tag.get("name")
        self.log(
            "Starting retrieval of members for tag: '{0}' (ID: {1})".format(
                tag_name, tag_id
            ),
            "INFO",
        )

        member_details = []

        # Fetch Network Devices and Interfaces Separately
        network_devices = self.get_tag_associated_network_devices(tag_name, tag_id)
        interfaces = self.get_tag_associated_interfaces(tag_name, tag_id)

        # Combine both lists
        member_details = network_devices + interfaces

        self.log(
            "Completed member retrieval for tag: '{0}'. Total members found: {1}".format(
                tag_name, len(member_details)
            ),
            "INFO",
        )
        return member_details

    def force_delete_tag_memberships(self, tag, tag_id):
        """
        Removes the given tag from all associated network devices and interfaces in Cisco Catalyst Center.

        Args:
            tag (dict): The tag metadata, including the tag name.
            tag_id (str): The unique identifier of the tag.

        Returns:
            self: The instance after processing tag removal.

        Description:
            Fetches all members linked to the tag, categorizes them as network devices or interfaces,
            and updates their tag memberships to remove the specified tag.
        """

        tag_name = tag.get("name")
        self.log(
            "Starting force delete operation for tag: '{0}' (ID: {1})".format(
                tag_name, tag_id
            ),
            "INFO",
        )
        member_details = self.get_tag_members(tag, tag_id)
        interface_details = []
        network_device_details = []

        new_tags_details = [{"tag_name": tag_name, "tag_id": tag_id}]
        for member_detail in member_details:
            member_type = member_detail.get("device_type")
            if member_type == "networkdevice":
                network_device_details.append(member_detail)
            elif member_type == "interface":
                interface_details.append(member_detail)

        if not network_device_details and not interface_details:
            self.log(
                "No devices or interfaces found for tag: '{0}'. Exiting operation.".format(
                    tag_name
                ),
                "INFO",
            )
            return self

        # Process Network Devices
        if network_device_details:
            self.updating_network_device_tag_memberships(
                network_device_details, new_tags_details
            )

        # Process Interfaces
        if interface_details:
            self.updating_interface_tag_memberships(interface_details, new_tags_details)

        self.log(
            "Successfully completed tag removal for tag: '{0}'".format(tag_name), "INFO"
        )
        return self

    def initialize_batch_size_values(self, tag_data_config):
        """
        Initializes batch size values for retrieving and updating network device
        and interface tags from the given tag or tag_membership_config.

        Args:
            tag (dict): The tag or tag_membership config containing batch size configurations.

        Returns:
            self: The instance with updated batch size attributes.

        Description:
            Initializes batch size values for retrieving and updating network device
            and interface tags from the given tag or tag_membership_config.
        """
        self.log("Initializing BATCH_SIZE values", "INFO")

        self.NETWORK_DEVICE_TAG_RETRIEVAL_BATCH_SIZE = tag_data_config.get(
            "network_device_tag_retrieval_batch_size"
        )
        self.INTERFACE_TAG_RETRIEVAL_BATCH_SIZE = tag_data_config.get(
            "interface_tag_retrieval_batch_size"
        )
        self.NETWORK_DEVICE_TAG_UPDATE_BATCH_SIZE = tag_data_config.get(
            "network_device_tag_update_batch_size"
        )
        self.INTERFACE_TAG_UPDATE_BATCH_SIZE = tag_data_config.get(
            "interface_tag_update_batch_size"
        )

        self.log(
            "NETWORK_DEVICE_TAG_RETRIEVAL_BATCH_SIZE: {0}".format(
                self.NETWORK_DEVICE_TAG_RETRIEVAL_BATCH_SIZE
            ),
            "INFO",
        )
        self.log(
            "INTERFACE_TAG_RETRIEVAL_BATCH_SIZE: {0}".format(
                self.INTERFACE_TAG_RETRIEVAL_BATCH_SIZE
            ),
            "INFO",
        )
        self.log(
            "NETWORK_DEVICE_TAG_UPDATE_BATCH_SIZE: {0}".format(
                self.NETWORK_DEVICE_TAG_UPDATE_BATCH_SIZE
            ),
            "INFO",
        )
        self.log(
            "INTERFACE_TAG_UPDATE_BATCH_SIZE: {0}".format(
                self.INTERFACE_TAG_UPDATE_BATCH_SIZE
            ),
            "INFO",
        )
        return self

    def process_tag_merged(self, tag):
        """
        Creates or updates a tag in Cisco Catalyst Center.

        Args:
            tag (dict): The tag details including its name and attributes.

        Returns:
            self: The updated instance after processing the tag.

        Description:
            This function checks if the given tag exists in Cisco Catalyst Center.
            If the tag is not present, it creates a new one; otherwise, it updates
            the existing tag if necessary. If no update is required, it logs that
            the tag remains unchanged.
        """

        tag_name = tag.get("name")
        self.log(
            "Starting Tag Create/Update Operation for the Tag: {0}".format(tag_name),
            "DEBUG",
        )
        self.initialize_batch_size_values(tag)

        tag_in_ccc = self.have.get("tag_info")
        if not tag_in_ccc:
            self.log(
                "Creating Tag: {0} with config: {1}".format(tag_name, self.pprint(tag)),
                "DEBUG",
            )
            self.create_tag(tag).check_return_status()
            self.created_tag.append(tag_name)
            return self

        self.log(
            "Tag: {0} is already present in Cisco Catalyst Center with details: {1}".format(
                tag_name, self.pprint(tag_in_ccc)
            ),
            "DEBUG",
        )
        requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)

        if not requires_update:
            self.not_updated_tag.append(tag_name)
            self.log("No update required in the tag: {0}".format(tag_name), "DEBUG")
            return self

        self.log(
            "Updating the tag: {0} with config: {1}".format(
                tag_name, self.pprint(updated_tag_info)
            ),
            "DEBUG",
        )
        self.update_tag(tag=updated_tag_info, tag_id=tag_in_ccc.get("id"))
        self.updated_tag.append(tag_name)

        return self

    def process_tag_memberships_merged(self, tag_memberships):
        """
        Creates or updates tag memberships for devices and interfaces.

        Args:
            tag_memberships (dict): Details of the tag memberships to be updated.

        Returns:
            self: The updated instance after processing tag memberships.

        Description:
            This function ensures that all specified tags have valid IDs. If a tag does not
            exist in Cisco Catalyst Center, an error is logged. Otherwise, the function
            updates the tag memberships for devices and interfaces as needed.
        """

        self.log("Starting Tag Membership Create/Update Operation", "DEBUG")
        self.initialize_batch_size_values(tag_memberships)

        tag_names = tag_memberships.get("tags")
        tags_details_list = []

        for tag_name in tag_names:
            tag_id = self.get_tag_id(tag_name)
            if tag_id is None:
                self.msg = "Tag: {0} is not present in Cisco Catalyst Center. Please create the tag before modifying tag memberships".format(
                    tag_name
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                return self

            tags_details_list.append({"tag_id": tag_id, "tag_name": tag_name})

        tag_memberships["tags_name_id"] = tags_details_list
        self.updating_tag_memberships(tag_memberships)
        return self

    def get_diff_merged(self, config):
        """
        Compares and updates tags and tag memberships to match the desired configuration.

        Args:
            config (dict): The configuration containing tag and tag membership details.

        Returns:
            self: The updated instance after synchronization.

        Description:
            This function analyzes the current (`have`) and desired (`want`) configurations
            for tags and tag memberships. It triggers the creation or update of tags
            and their memberships, ensuring that the final configuration aligns with
            the intended state.
        """

        self.log(
            "Starting the get diff merged for tag and tag memberships operations",
            "INFO",
        )

        tag = self.want.get("tag")
        tag_memberships = self.want.get("tag_memberships")

        if tag:
            self.process_tag_merged(tag)
        if tag_memberships:
            self.process_tag_memberships_merged(tag_memberships)

        self.msg = "Get Diff Merged Completed Successfully"
        return self

    def process_force_delete_tag(self, tag, tag_id, tag_name):
        """
        Force deletes a tag in Cisco Catalyst Center by removing its dynamic rules,
        deleting all associated memberships, and then deleting the tag itself.

        Args:
            tag (dict): The tag details.
            tag_id (str): The unique identifier of the tag.
            tag_name (str): The name of the tag.

        Returns:
            self (object): The current instance after performing the force delete operation.

        Description:
            This function ensures that a tag is completely removed by:
            1. Removing any dynamic rules associated with the tag.
            2. Deleting all network device and interface memberships linked to the tag.
            3. Deleting the tag itself.
            The tag name is then appended to `self.deleted_tag` for tracking purposes.
        """
        self.log("Performing Force Delete for the Tag: {0}".format(tag_name), "DEBUG")

        # Remove dynamic rules
        self.update_tag({"name": tag_name}, tag_id)
        self.log("Removed dynamic rules for Tag: {0}".format(tag_name), "DEBUG")

        # Remove tag memberships
        self.force_delete_tag_memberships(tag, tag_id)
        self.log("Deleted all memberships for Tag: {0}".format(tag_name), "DEBUG")

        # Delete tag
        self.delete_tag(tag, tag_id)
        self.log("Successfully deleted Tag: {0}".format(tag_name), "DEBUG")
        self.deleted_tag.append(tag_name)

        return self

    def delete_or_update_tag(self, tag, tag_in_ccc, tag_name, tag_id):
        """
        Deletes or updates a tag in Cisco Catalyst Center based on its parameters.

        Args:
            tag (dict): The tag details, including description, device rules, or port rules.
            tag_in_ccc (dict): The existing tag details in Cisco Catalyst Center.
            tag_name (str): The name of the tag.
            tag_id (str): The unique identifier of the tag.

        Returns:
            self (object): The current instance after performing the delete or update operation.

        Description:
            - If the tag lacks `description`, `device_rules`, and `port_rules`, it is entirely deleted.
            - If any of these parameters exist, a comparison is made with the existing tag.
            - If updates are needed, specific parameters are deleted or modified.
            - If no changes are required, the tag remains unchanged, and a log message is recorded.
        """

        self.log("Processing delete or update for Tag: {0}".format(tag_name), "DEBUG")

        if not any(
            tag.get(param) for param in ["description", "device_rules", "port_rules"]
        ):
            self.log("Deleting entire Tag: {0}".format(tag_name), "DEBUG")
            self.delete_tag(tag, tag_id).check_return_status()
            self.deleted_tag.append(tag_name)
            return self

        requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)
        if requires_update:
            self.log(
                "Deleting specific parameters of Tag: {0}".format(tag_name), "DEBUG"
            )
            self.update_tag(tag=updated_tag_info, tag_id=tag_in_ccc.get("id"))
            self.updated_tag.append(tag_name)
            return self

        self.not_updated_tag.append(tag_name)
        self.log(
            "No changes required for Tag: {0}, skipping deletion of parameters.".format(
                tag_name
            ),
            "INFO",
        )

        return self

    def process_tag_deleted(self, tag):
        """
        Processes the deletion of a tag in Cisco Catalyst Center.

        Args:
            tag (dict): The tag details containing its name and optional force_delete flag.

        Returns:
            self (object): The current instance after performing the delete operation.

        Description:
            - Initializes batch size values for processing.
            - Checks if the tag exists in Cisco Catalyst Center.
            - If the tag is absent, logs the event and adds it to `absent_tag`.
            - If `force_delete` is enabled, performs a complete deletion of the tag.
            - Otherwise, selectively deletes or updates tag parameters as needed.
        """

        tag_name = tag.get("name")

        self.log("Starting Tag Deletion for the Tag '{0}'".format(tag_name), "DEBUG")
        self.initialize_batch_size_values(tag)

        tag_in_ccc = self.have.get("tag_info")
        if not tag_in_ccc:
            self.log(
                "Not able to perform delete operations. Tag '{0}' as it is not present in Cisco Catalyst Center.".format(
                    tag_name
                ),
                "DEBUG",
            )
            self.absent_tag.append(tag_name)
            return self

        tag_id = tag_in_ccc.get("id")
        force_delete = tag.get("force_delete")

        if force_delete:
            self.process_force_delete_tag(tag, tag_id, tag_name)
        else:
            self.delete_or_update_tag(tag, tag_in_ccc, tag_name, tag_id)

        return self

    def process_tag_membership_deleted(self, tag_memberships):
        """
        Processes the deletion of tag memberships in Cisco Catalyst Center.

        Args:
            tag_memberships (dict): A dictionary containing details about the tag memberships to be modified.

        Returns:
            self (object): The current instance after processing the tag membership deletion.

        Description:
            - Logs the initiation of tag membership processing.
            - Initializes batch size values for efficient processing.
            - Retrieves tag IDs for the provided tag names.
            - If a tag does not exist, logs an error and stops execution.
            - Associates tag IDs with their respective names and updates the `tag_memberships` dictionary.
            - Calls `updating_tag_memberships` to handle the membership modification.
        """

        self.log("Starting Tag Membership Create/Update Operation", "DEBUG")
        self.initialize_batch_size_values(tag_memberships)

        tag_names = tag_memberships.get("tags")
        tags_details_list = []

        for tag_name in tag_names:
            tag_id = self.get_tag_id(tag_name)
            if tag_id is None:
                self.msg = "Tag: {0} is not present in Cisco Catalyst Center. Please create the tag before modifying tag memberships".format(
                    tag_name
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                return self
            else:
                tag_detail_dict = {"tag_id": tag_id, "tag_name": tag_name}
                tags_details_list.append(tag_detail_dict)

        tag_memberships["tags_name_id"] = tags_details_list
        self.updating_tag_memberships(tag_memberships)

        return self

    def get_diff_deleted(self, config):
        """
        Args:
            config (dict): The configuration that contains details about the tags and tag memberships.

        Returns:
            self: The instance of the class, enabling method chaining.

        Description:
            Compares the desired configuration (`want`) with the current configuration (`have`) for tags and tag memberships.
            This function handles the deletion of tags and their associated memberships in Cisco Catalyst Center.
        """

        self.log(
            "Starting the get diff deleted for tag and tag memberships operations",
            "INFO",
        )

        tag = self.want.get("tag")
        tag_memberships = self.want.get("tag_memberships")

        if tag:
            self.process_tag_deleted(tag)

        if tag_memberships:
            self.process_tag_membership_deleted(tag_memberships)

        self.msg = "Get Diff Deleted Completed Successfully"

        return self

    def verify_network_device_tag_membership_diff(
        self, network_device_details, new_tags_details
    ):
        """
        Verifies whether the tag memberships of network devices match the expected configuration.

        Args:
            network_device_details (list of dict): A list of dictionaries, each containing details of a network device.
                - "id" (str): Unique identifier of the network device.
                - "device_identifier" (str): Device type identifier (e.g., hostname or MAC address).
                - "device_value" (str): The actual value of the device identifier.
            new_tags_details (list of dict): List of expected tag details for comparison.

        Returns:
            bool: True if all network devices have correct tag memberships, False if there are mismatches.

        Description:
            This function fetches the current tag memberships for each network device and compares them
            against the expected tag details. If a mismatch is found, a warning is logged.
        """

        self.log("Starting verification of network device tag memberships.", "INFO")

        if not network_device_details:
            self.log(
                "No network devices provided for tag membership verification.", "DEBUG"
            )
            return True

        self.log("Verifying tag memberships for network devices...", "DEBUG")
        verify_success = True
        fetched_tags_details = self.get_tags_associated_with_the_network_devices(
            network_device_details
        )

        for network_device_detail in network_device_details:
            device_id = network_device_detail.get("id")
            needs_update, updated_tags = self.compare_and_update_list_of_dict(
                fetched_tags_details.get(device_id), new_tags_details
            )
            device_identifier = network_device_detail.get("device_identifier")
            device_value = network_device_detail.get("device_value")

            if not needs_update:
                self.log(
                    "Tag membership for device {0}:{1} is up to date.".format(
                        device_identifier, device_value
                    ),
                    "DEBUG",
                )
                continue

            verify_success = False

            self.msg = (
                "Tag membership mismatch for device {0}:{1} in Cisco Catalyst Center. "
                "Playbook operation might not be successful."
            ).format(device_identifier, device_value)
            self.log(self.msg, "WARNING")

        return verify_success

    def verify_interface_tag_membership_diff(self, interface_details, new_tags_details):
        """
        Verifies whether the tag memberships of interfaces match the expected configuration.

        Args:
            interface_details (list of dict): A list of dictionaries, each containing details of an interface.
                - "id" (str): Unique identifier of the device.
                - "device_identifier" (str): Device type identifier (e.g., hostname or MAC address).
                - "device_value" (str): The actual value of the device identifier.
                - "interface_name" (str): The name of the interface.
            new_tags_details (list of dict): List of expected tag details for comparison.

        Returns:
            bool: True if all interfaces have correct tag memberships, False if there are mismatches.

        Description:
            This function fetches the current tag memberships for each interface and compares them
            against the expected tag details. If a mismatch is found, a warning is logged.
        """

        self.log("Starting verification of interface tag memberships.", "INFO")

        if not interface_details:
            self.log("No interfaces provided for tag membership verification.", "DEBUG")
            return True

        self.log("Verifying tag memberships for interfaces...", "DEBUG")
        verify_success = True
        fetched_tags_details = self.get_tags_associated_with_the_interfaces(
            interface_details
        )
        for interface_detail in interface_details:
            device_id = interface_detail.get("id")
            device_identifier = interface_detail.get("device_identifier")
            device_value = interface_detail.get("device_value")
            interface_name = interface_detail.get("interface_name")
            interface_detail["tags_list"] = new_tags_details

            needs_update, updated_tags = self.compare_and_update_list_of_dict(
                fetched_tags_details.get(device_id), new_tags_details
            )
            if not needs_update:
                self.log(
                    "Tag membership for interface {0} on device {1}:{2} is up to date.".format(
                        interface_name, device_identifier, device_value
                    ),
                    "DEBUG",
                )
                continue

            verify_success = False
            self.msg = (
                "Tag membership mismatch for interface {0} on device {1}:{2} in Cisco Catalyst Center. "
                "Playbook operation might not be successful.".format(
                    interface_name, device_identifier, device_value
                )
            )
            self.log(self.msg, "WARNING")

        return verify_success

    def verify_tag_membership_diff(self, tag_memberships):
        """
        Verifies whether the tag memberships for network devices and interfaces match the expected configuration.

        Args:
            tag_memberships (dict): A dictionary containing tag membership details for devices and interfaces.
                - "interface_details" (list of dict): List of interfaces with associated tags.
                - "network_device_details" (list of dict): List of network devices with associated tags.
                - "tags_name_id" (list of dict): List of expected tags to verify against current memberships.

        Returns:
            bool: True if all tag memberships are verified without differences, False if mismatches exist.

        Description:
            This function verifies that the tag memberships of network devices and interfaces align with
            the expected configuration. It logs warnings if discrepancies are detected.
        """

        self.log(
            "Starting tag membership verification for network devices and interfaces.",
            "INFO",
        )

        new_tags_details = tag_memberships.get("tags_name_id")
        network_result = self.verify_network_device_tag_membership_diff(
            tag_memberships.get("network_device_details"), new_tags_details
        )
        interface_result = self.verify_interface_tag_membership_diff(
            tag_memberships.get("interface_details"), new_tags_details
        )

        if network_result and interface_result:
            self.log(
                "Tag membership verification completed successfully with no mismatches.",
                "INFO",
            )
        else:
            self.log(
                "Tag membership verification found mismatches. Review the warnings for details.",
                "WARNING",
            )

        return network_result and interface_result

    def verify_tag_diff_merged(self, tag):
        """
        Verifies whether the tag details in the playbook match the current details in the Cisco Catalyst Center.

        Args:
            tag (dict): A dictionary containing the tag details.
                - "name" (str): The name of the tag to verify.

        Returns:
            bool: True if the tag details match, False if there's a mismatch.

        Description:
            This function checks whether the tag details in the playbook and Cisco Catalyst Center are the same.
            If there's a mismatch, a warning is logged, and the playbook operation may be unsuccessful.
        """

        self.log("Verifying the tag details for the playbook operation", "INFO")

        tag_name = tag.get("name")

        verify_diff = True
        tag_in_ccc = self.have.get("tag_info")
        if not tag_in_ccc:
            verify_diff = False
            self.log(
                "Tag {0} not found in Cisco Catalyst Center. Merged playbook operation might be unsuccessful".format(
                    tag_name
                ),
                "WARNING",
            )
            return verify_diff

        self.log(
            "Checking for Tag {0} if the details are same in playbook and Cisco Catalyst Center".format(
                tag_name
            ),
            "DEBUG",
        )
        requires_update, updated_tag_info = self.compare_and_update_tag(tag, tag_in_ccc)

        if requires_update:
            verify_diff = False
            self.msg = (
                "Tag Details present in playbook and Cisco Catalyst Center does not match"
                " for the tag {0}. Playbook operation might be unsuccessful".format(
                    tag_name
                )
            )
            self.log(self.msg, "WARNING")
            return verify_diff

        self.log(
            "Tag Details present in playbook and Cisco Catalyst Center are same for the tag {0}.".format(
                tag_name
            ),
            "DEBUG",
        )
        return verify_diff

    def verify_diff_merged(self, config):
        """
        Verifies if the tag and tag membership details in the playbook match the current state in the Cisco Catalyst Center.

        Args:
            config (dict): Configuration details required to fetch current state and verify tags and memberships.
                This typically includes the current state and playbook-defined configurations.

        Returns:
            self: The object instance with the updated status and logs regarding the success or failure of the verification process.

        Description:
            Verifies if the tag and tag membership details in the playbook match the current state in the Cisco Catalyst Center.
            Logs warnings if there are discrepancies and returns the status of the operation.
        """

        self.log(
            "Verifying tag and tag membership details for the playbook operation.",
            "DEBUG",
        )

        tag_config_data = config.get("tag", {})
        if tag_config_data:
            new_tag_name = tag_config_data.get("new_name")

            if new_tag_name:
                current_name = self.want.get("tag", {}).get("name", "Unknown")
                self.log(
                    f"Updating tag name: current name='{current_name}', new name='{new_tag_name}'.",
                    "DEBUG",
                )
                # Update the tag name in the config
                config["tag"]["name"] = config["tag"].get("new_name")

        self.get_have(config).check_return_status()
        tag = self.want.get("tag")
        tag_memberships = self.want.get("tag_memberships")
        verify_diff = True
        if tag:
            verify_diff &= self.verify_tag_diff_merged(tag)

        if tag_memberships:
            membership_verify_diff = self.verify_tag_membership_diff(tag_memberships)
            if membership_verify_diff:
                self.log(
                    "tag memberships Details present in playbook and Cisco Catalyst Center are same.",
                    "DEBUG",
                )
            else:
                verify_diff = False
                self.log(
                    "tag memberships Details present in playbook and Cisco Catalyst Center does not match. Playbook operation might be unsuccessful",
                    "WARNING",
                )

        if verify_diff:
            self.msg = "Playbook operation is successful. Verification Completed"
            self.log(self.msg, "INFO")
        else:
            self.msg = "Playbook operation is unsuccessful."
            self.fail_and_exit(self.msg)
        return self

    def verify_tag_diff_deleted(self, tag):
        """
        Verifies whether the tag details in the playbook align with the current state in Cisco Catalyst Center when performing a delete operation.

        Args:
            tag (dict): A dictionary containing tag details.

        Returns:
            bool: True if the tag details match or can be safely deleted, False if there's a mismatch.

        Description:
            This function verifies if the tag and its details in the playbook match the current state in the Cisco Catalyst Center,
            considering whether the tag should be forcibly deleted or updated. If discrepancies are found, warnings are logged.
        """

        tag_name = tag.get("name")
        self.log(
            "Checking if Tag {0} details in the playbook align with the current state for deletion.".format(
                tag_name
            ),
            "DEBUG",
        )

        tag_in_ccc = self.have.get("tag_info")
        force_delete = tag.get("force_delete")
        verify_diff = True
        if force_delete:
            if not tag_in_ccc:
                self.log(
                    "Tag {0} is not present in Cisco Catalyst Center. No Mismatch Found".format(
                        tag_name
                    ),
                    "DEBUG",
                )
                return verify_diff
            verify_diff = False
            self.log(
                "Tag {0} is found in Cisco Catalyst Center. Playbook operation might be unsuccessful.".format(
                    tag_name
                ),
                "WARNING",
            )
            return verify_diff

        description = tag.get("description")
        device_rules = tag.get("device_rules")
        port_rules = tag.get("port_rules")

        if description or device_rules or port_rules:
            #  Update Case
            if not tag_in_ccc:
                verify_diff = False
                self.log(
                    "Tag {0} is not found in Cisco Catalyst Center. It should have been present. Playbook operation might be unsuccessful".format(
                        tag_name
                    ),
                    "WARNING",
                )

                return verify_diff

            requires_update, updated_tag_info = self.compare_and_update_tag(
                tag, tag_in_ccc
            )

            if not requires_update:
                self.log(
                    "Tag details for Tag:{0} are same in Cisco Catalyst Center and Playbook.".format(
                        tag_name
                    ),
                    "DEBUG",
                )

                return verify_diff

            verify_diff = False
            self.msg = (
                "Tag details for Tag:{0} are different in Cisco Catalyst Center and Playbook."
                "Playbook operation might be unsuccessful".format(tag_name)
            )
            self.log(self.msg, "WARNING")

            return verify_diff

        # Simple Tag Deletion Case
        if not tag_in_ccc:
            self.log(
                "Tag {0} is not present in Cisco Catalyst Center".format(tag_name),
                "DEBUG",
            )
            return verify_diff

        verify_diff = False
        self.log(
            "Tag {0} is still present in Cisco Catalyst Center. Playbook operation might be unsuccessful".format(
                tag_name
            ),
            "WARNING",
        )

        return verify_diff

    def verify_diff_deleted(self, config):
        """
        Verifies whether the tag and tag membership details in the playbook align with the current state in Cisco Catalyst Center
        when performing a delete operation.

        Args:
            config (dict): Configuration details required to fetch the current state and verify tags and memberships.
                This includes the current state and playbook-defined configurations.

        Returns:
            self: The object instance with the updated status and logs indicating the success or failure of the verification process.

        Description:
            Verifies whether the tag and tag membership details in the playbook align with the current state in Cisco Catalyst Center
            when performing a delete operation. Logs warnings if there are discrepancies.
        """

        self.log(
            "Verifying tag and tag membership details for the deletion operation.",
            "DEBUG",
        )

        self.get_have(config).check_return_status()
        tag = self.want.get("tag")
        tag_memberships = self.want.get("tag_memberships")

        verify_diff = True
        if tag:
            verify_diff &= self.verify_tag_diff_deleted(tag)

        if tag_memberships:
            membership_verify_diff = self.verify_tag_membership_diff(tag_memberships)
            if membership_verify_diff:
                self.log(
                    "tag memberships Details present in playbook and Cisco Catalyst Center are same.",
                    "DEBUG",
                )
            else:
                verify_diff = False
                self.log(
                    "tag memberships Details present in playbook and Cisco Catalyst Center does not match. Playbook operation might be unsuccessful",
                    "WARNING",
                )

        if verify_diff:
            self.msg = "Playbook operation is successful. Verification Completed"
            self.log(self.msg, "INFO")
        else:
            self.msg = "Playbook operation is unsuccessful"
            self.fail_and_exit(self.msg)

        return self

    def int_fail(self, msg="Intentional Fail :)"):
        """
        Triggers an intentional failure by setting an error message and updating the operation status.

        Args:
            msg (str, optional): Custom error message to indicate the failure. Defaults to "Intentional Fail :)".

        Returns:
            None

        Description:
            - Updates `self.msg` with the provided error message.
            - Sets the operation result to "failed" with an error status.
            - Calls `check_return_status()` to handle further failure processing.
        """

        self.msg = msg
        self.set_operation_result("failed", False, self.msg, "ERROR")
        self.check_return_status()

    def generate_tagging_message(self, action, membership):
        """
        Generates a dynamic tagging or un-tagging message based on device type, action, and tags.

        Args:
            action (str): The action performed, which can be "updated", "not_updated", "deleted", or "not_deleted".
            membership (dict): A dictionary containing device and tag details, including:
                - device_type (str): Type of device ("networkdevice" or "interface").
                - device_identifier (str): Identifier type (e.g., "Serial Number", "MAC Address").
                - device_value (str): Actual identifier value.
                - site_name (str, optional): The site under which the device/interface resides.
                - tags_list (list, optional): List of dictionaries containing tag details.
                - reason (str, optional): Reason for failure (if applicable).
                - interface_name (str, optional): Interface name (for interface-based tagging).

        Returns:
            str: A formatted message describing the tagging or un-tagging action.

        Description:
            - Constructs a base message depending on whether the entity is a network device or an interface.
            - Appends site information if available.
            - Extracts tag names from the provided tag list.
            - Constructs a meaningful message based on the provided `action`.
        """
        self.log(
            "Starting dynamic tagging message generation for action: {0}, membership: {1}".format(
                action, membership
            ),
            "INFO",
        )

        device_type = membership.get("device_type")
        device_identifier = membership.get("device_identifier")
        device_value = membership.get("device_value")
        site_name = membership.get("site_name", "")
        tags_list = membership.get("tags_list")
        reason = membership.get("reason", "")
        interface_name = membership.get("interface_name", "")

        if device_type == "networkdevice":
            base_msg = "The Device with {0}: {1}".format(
                device_identifier, device_value
            )
        elif device_type == "interface":
            base_msg = "The Interface {0} of device with {1}: {2}".format(
                interface_name, device_identifier, device_value
            )
        else:
            return ""

        if site_name:
            base_msg += " under site:{0}".format(site_name)
        tag_names = (
            ", ".join(tag.get("tag_name", "Unknown") for tag in tags_list)
            if tags_list
            else "any tags"
        )

        if action == "updated":
            return "{0} has been tagged to {1}".format(base_msg, tag_names)
        elif action == "not_updated":
            return "{0} has not been tagged to {1} because: {2}".format(
                base_msg, tag_names, reason
            )
        elif action == "deleted":
            return "{0} has been untagged from {1}".format(base_msg, tag_names)
        elif action == "not_deleted":
            return "{0} has not been untagged from {1} because: {2}".format(
                base_msg, tag_names, reason
            )

        return ""

    def update_tags_profile_messages(self):
        """
        Updates messages related to tag operations and membership updates in the Cisco Catalyst Center.

        Args:
            None

        Returns:
            self: The current object with updated operation results and messages.

        Description:
            This method generates status messages for:
            - Tag creation, update, deletion, and absence.
            - Tag membership updates, deletions, and non-updates with reasons.
            - The overall operation result, setting 'changed' to True if any modifications were made.
        """

        self.result["changed"] = False
        result_msg_list = []

        tag_messages = {
            "created_tag": "Tag '{0}' has been created successfully in the Cisco Catalyst Center.",
            "updated_tag": "Tag '{0}' has been updated successfully in the Cisco Catalyst Center.",
            "not_updated_tag": "Tag '{0}' needs no update in the Cisco Catalyst Center.",
            "deleted_tag": "Tag '{0}' has been deleted successfully in the Cisco Catalyst Center.",
            "absent_tag": "Not able to perform delete operations for Tag '{0}' because it is not present in the Cisco Catalyst Center.",
        }

        for tag_attr, msg_template in tag_messages.items():
            tag_list = getattr(self, tag_attr, [])
            if tag_list:
                if len(tag_list) == 1:
                    tag_msg = msg_template.format(tag_list[0])
                else:
                    tag_msg = msg_template.format(", ".join(tag_list))
                    tag_msg = (
                        tag_msg.replace("Tag", "Tags")
                        .replace("it is", "they are")
                        .replace("has", "have")
                    )
                result_msg_list.append(tag_msg)

        for action, memberships in [
            ("updated", self.updated_tag_memberships),
            ("not_updated", self.not_updated_tag_memberships),
            ("deleted", self.deleted_tag_memberships),
            ("not_deleted", self.not_deleted_tag_memberships),
        ]:
            if memberships:
                for membership in memberships:
                    message = self.generate_tagging_message(action, membership)
                    if message:
                        result_msg_list.append(message)
        if any(
            [
                self.created_tag,
                self.updated_tag,
                self.deleted_tag,
                self.updated_tag_memberships,
                self.deleted_tag_memberships,
            ]
        ):
            self.result["changed"] = True

        self.msg = ("\n").join(result_msg_list)
        self.set_operation_result("success", self.result["changed"], self.msg, "INFO")

        return self


def main():
    """
    main entry point for tags workflow manager module execution
    """

    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": True},
        "dnac_version": {"type": "str", "default": "2.3.7.9"},
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

    ccc_tags = Tags(module)
    ccc_version = ccc_tags.get_ccc_version()
    if ccc_tags.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
        ccc_tags.msg = (
            "Tagging feature is not supported in Cisco Catalyst Center version '{0}'. Supported versions start "
            "from '2.3.7.9' onwards. Version '2.3.7.9' introduces APIs for creating, updating and deleting the "
            "tag and tag memberships.".format(ccc_version)
        )
        ccc_tags.set_operation_result(
            "failed", False, ccc_tags.msg, "ERROR"
        ).check_return_status()

    state = ccc_tags.params.get("state")

    if state not in ccc_tags.supported_states:
        ccc_tags.msg = "State '{0}' is invalid. Supported states:{1}. Please check the playbook and try again.".format(
            state, ccc_tags.supported_states
        )
        ccc_tags.set_operation_result(
            "failed", False, ccc_tags.msg, "ERROR"
        ).check_return_status()

    ccc_tags.validate_input().check_return_status()
    config_verify = ccc_tags.params.get("config_verify")

    for config in ccc_tags.validated_config:
        ccc_tags.reset_values()
        ccc_tags.get_want(config).check_return_status()
        ccc_tags.get_have(config).check_return_status()

        ccc_tags.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_tags.verify_diff_state_apply[state](config).check_return_status()

    ccc_tags.update_tags_profile_messages().check_return_status()

    module.exit_json(**ccc_tags.result)


if __name__ == "__main__":
    main()
