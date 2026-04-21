#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Luna Aliaj, Madhan Sankaranarayanan, Archit Soni"
DOCUMENTATION = r"""
---
module: lan_automation_workflow_manager
short_description: Automate network discovery, deployment,
  and device configuration with LAN Automation in Cisco
  Catalyst Center.
description:
  - Configuring LAN Automation sessions in Cisco Catalyst
    Center for automated discovery of devices and their
    integration into the network.
  - Updating LAN Automation device configurations, including
    loopback addresses, hostnames, and link configurations.
  - Automatically stopping an ongoing LAN Automation
    session based on conditions like timeout or discovery
    device list completion, without explicitly calling
    the stop API.
  - Additionally, it provides functionalities to stop
    ongoing LAN Automation sessions and to handle PnP
    device authorization.
version_added: '6.20.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Luna Aliaj (@majlona)
  - Madhan Sankaranarayanan (@madhansansel)
  - Archit Soni (@koderchit)
options:
  dnac_api_task_timeout:
    description: The maximum time to wait for a task
      to complete on Cisco DNA Center for LAN Automation.
    type: int
    default: 604800
  dnac_task_poll_interval:
    description: The interval, in seconds, to poll for
      task completion.
    type: int
    default: 30
  config_verify:
    description: Set to true to verify the LAN Automation
      config after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center
      after module completion.
    type: str
    choices: ['merged', 'deleted']
    default: merged
  config:
    description: A list containing detailed configurations
      for creating and stopping a LAN Automation session,
      and also for updating loopback addresses, hostnames,
      and link configurations for LAN automated devices.
      Each element in the list represents a specific
      operation to be performed on the LAN automation
      infrastructure.
    type: list
    elements: dict
    required: true
    suboptions:
      lan_automation:
        description: Configuration for starting or stopping
          LAN Automation sessions.
        type: dict
        suboptions:
          discovered_device_site_name_hierarchy:
            description: Site hierarchy where the discovered
              devices will be placed.
            type: str
            required: true
          primary_device_management_ip_address:
            description: Management IP address of the
              primary or seed device in the LAN Automation
              session.
            type: str
            required: true
          peer_device_management_ip_address:
            description: Management IP address of the
              peer device in the LAN Automation session.
            type: str
            required: false
          primary_device_interface_names:
            description: A list of interface names on
              the primary device to be used for LAN
              automation.
            type: list
            elements: str
            required: true
          ip_pools:
            description: A list of IP pools used during
              the LAN Automation session.
            type: list
            elements: dict
            required: true
            suboptions:
              ip_pool_name:
                description: Name of the IP pool.
                type: str
                required: true
              ip_pool_role:
                description: Role of the IP pool in
                  the automation session, either MAIN_POOL
                  or PHYSICAL_LINK_POOL.
                type: str
                required: true
                choices: [MAIN_POOL, PHYSICAL_LINK_POOL]
          multicast_enabled:
            description: Flag to enable multicast routing
              in the LAN Automation session.
            type: bool
            default: false
          host_name_prefix:
            description: Prefix used for auto-generating
              hostnames during the LAN Automation session.
            type: str
            required: false
          redistribute_isis_to_bgp:
            description: Flag to enable the redistribution
              of IS-IS routes to BGP.
            type: bool
            default: false
          isis_domain_pwd:
            description: Password for IS-IS domain configuration.
            type: str
            required: false
          discovery_level:
            description: Depth of the discovery during
              LAN automation (e.g., Level 1-5 below
              the primary seed device).
            type: int
            default: 2
          discovery_timeout:
            description: Timeout for device discovery
              during LAN Automation, in minutes. Until
              this time, stop processing will not be
              triggered. Any device contacting after
              the provided discovery timeout will not
              be processed, and a device reset and reload
              will be attempted to bring it back to
              the PnP agent state before process completion.
              The supported timeout range is in minutes
              [20-10080]. If both 'discovery_timeout'
              and 'discovery_devices' are provided,
              processing will stop based on whichever
              occurs earlier. Users can always use the
              LAN Automation deleted state to force
              stop processing.
            type: int
            required: false
          discovery_devices:
            description: A list of devices to be discovered
              during the LAN Automation session. If
              only a device list is provided without
              a timeout, stop processing will occur
              once all devices from the list are discovered.
              The maximum number of devices that can
              be provided for a session is 50. If both
              the discovery devices list and timeout
              are provided, the stop processing will
              be attempted whichever happens earlier.
              Users may choose to use the LAN Automation
              'deleted' state to stop processing at
              any time.
            type: list
            elements: dict
            required: false
            suboptions:
              device_serial_number:
                description: Serial number of the device
                  to be discovered.
                type: str
                required: true
              device_host_name:
                description: Hostname of the device
                  to be discovered.
                type: str
                required: false
              device_site_name_hierarchy:
                description: Site hierarchy where the
                  device will be placed after discovery.
                type: str
                required: false
              device_management_ip_address:
                description: Management IP address of
                  the device.
                type: str
                required: false
          launch_and_wait:
            description: Flag indicating whether the
              task should pause until the LAN Automation
              session completes before continuing to
              subsequent tasks. If set to false, the
              process will move to the next task immediately.
            type: bool
            default: false
          pnp_authorization:
            description: Flag to enable Plug and Play
              (PnP) authorization for devices discovered
              during the session.
            type: bool
            default: false
          device_serial_number_authorization:
            description: A list of serial numbers of
              devices to be authorized during the session.
            type: list
            elements: str
            required: false
      lan_automated_device_update:
        description: Configuration for updating device
          settings discovered through LAN Automation.
        type: dict
        suboptions:
          loopback_update_device_list:
            description: List of devices to update with
              new loopback IP addresses.
            type: list
            elements: dict
            suboptions:
              device_management_ip_address:
                description: Management IP address of
                  the device.
                type: str
                required: true
              new_loopback0_ip_address:
                description: New Loopback0 IP Address
                  for the device, sourced from the LAN
                  pool associated with the device discovery
                  site.
                type: str
                required: true
          hostname_update_devices:
            description: List of devices to update with
              new hostnames.
            type: list
            elements: dict
            suboptions:
              device_management_ip_address:
                description: Management IP address of
                  the device.
                type: str
                required: true
              new_host_name:
                description: New hostname for the device.
                type: str
                required: true
          link_add:
            description: Add a new link between two
              devices.
            type: dict
            suboptions:
              source_device_management_ip_address:
                description: Management IP address of
                  the source device.
                type: str
                required: true
              source_device_interface_name:
                description: Interface name on the source
                  device.
                type: str
                required: true
              destination_device_management_ip_address:
                description: Management IP address of
                  the destination device.
                type: str
                required: true
              destination_device_interface_name:
                description: Interface name on the destination
                  device.
                type: str
                required: true
              ip_pool_name:
                description: Name of the IP pool configured
                  within LAN Automation, from which
                  IP addresses will be allocated for
                  the new link.
                type: str
                required: true
          link_delete:
            description: Remove an existing link between
              two devices.
            type: dict
            suboptions:
              source_device_management_ip_address:
                description: Management IP address of
                  the source device.
                type: str
                required: true
              source_device_interface_name:
                description: Interface name on the source
                  device.
                type: str
                required: true
              destination_device_management_ip_address:
                description: Management IP address of
                  the destination device.
                type: str
                required: true
              destination_device_interface_name:
                description: Interface name on the destination
                  device.
                type: str
                required: true
      port_channel:
        description: >
          Configuration to create, update, or delete Port Channels between two LAN
          Automated devices in Cisco Catalyst Center. Port Channels aggregate
          multiple physical links between devices to provide increased bandwidth
          and redundancy.
        type: list
        elements: dict
        suboptions:
          source_device_management_ip_address:
            description: >
              Management IP address of the source device. At least one device
              identifier (IP address, MAC address, or serial number) must be
              provided for the source device. The device must be LAN Automated
              and in Reachable and Managed state in Cisco Catalyst Center inventory.
            type: str
            required: false
          source_device_mac_address:
            description: >
              MAC address of the source device. Alternative to management IP
              address or serial number for device identification. The device
              must be LAN Automated and in Reachable and Managed state in
              Cisco Catalyst Center inventory.
            type: str
            required: false
          source_device_serial_number:
            description: >
              Serial number of the source device. Alternative to management IP
              address or MAC address for device identification. The device must
              be LAN Automated and in Reachable and Managed state in Cisco
              Catalyst Center inventory.
            type: str
            required: false
          destination_device_management_ip_address:
            description: >
              Management IP address of the destination device. At least one device
              identifier (IP address, MAC address, or serial number) must be
              provided for the destination device. The device must be LAN Automated
              and in Reachable and Managed state in Cisco Catalyst Center inventory.
            type: str
            required: false
          destination_device_mac_address:
            description: >
              MAC address of the destination device. Alternative to management IP
              address or serial number for device identification. The device must
              be LAN Automated and in Reachable and Managed state in Cisco
              Catalyst Center inventory.
            type: str
            required: false
          destination_device_serial_number:
            description: >
              Serial number of the destination device. Alternative to management
              IP address or MAC address for device identification. The device must
              be LAN Automated and in Reachable and Managed state in Cisco
              Catalyst Center inventory.
            type: str
            required: false
          port_channel_number:
            description: >
              - This value is system-assigned during creation and user provided value will be ignored.
                Catalyst Center will automatically provide a unique number upon creation.
              - Can be used for update operations to target a specific existing
                Port Channel for modification (adding/removing interfaces).
              - Can be used for delete operations to identify the specific
                Port Channel to remove from the device pair.
              - When used for update/delete operations, eliminates the need to
                specify existing interface links for Port Channel identification.
            type: int
            required: false
          links:
            description: >
              - List of physical interface links to include in the Port Channel.
              - Required for create operations - at least one link must be specified.
              - Optional for update operations - adds/removes links from existing
                Port Channel.
              - All links must be between the same source and destination devices.
              - Interface names must match exact device interface nomenclature.
            type: list
            elements: dict
            suboptions:
              source_port:
                description: >
                  Interface name on the source device (e.g., 'GigabitEthernet1/0/1',
                  'TenGigabitEthernet1/0/1'). Must be a valid, available interface
                  on the source device that is not already part of another Port Channel.
                type: str
                required: true
              destination_port:
                description:
                  Interface name on the destination device (e.g., 'GigabitEthernet1/0/1',
                  'TenGigabitEthernet1/0/1'). Must be a valid, available interface
                  on the destination device that is not already part of another
                  Port Channel.
                type: str
                required: true
requirements:
  - dnacentersdk >= 2.9.2
  - python >= 3.9
notes:
  - When waiting for the LAN automation session to complete,
    the timeout and the list of devices to be discovered
    will initially be considered. If neither a timeout
    nor a device list is provided,
    LAN automation will
    continue running until stopped.
  - To stop a LAN automation session,
    execute the same
    details in the 'deleted' state. Only the seed device
    IP is required to terminate the session.
  - PnP authorization will be performed if device authorization
    has been selected in Catalyst Center. LAN automation
    will continue running until the provided serial
    numbers are authorized,
    continuously checking the
    status of the devices. If PnP authorization is enabled
    without a list of devices for either authorization
    or discovery,
    the module will not wait for the LAN
    automation task to complete. However,
    if a device
    is in an Error state or authorization is not checked
    on Catalyst Center,
    the playbook will keep running
    until the state of the device is active or reached
    the timeout value.
  - Port Channel operations require both source and destination devices
    to be LAN Automated devices in Reachable and Managed state within
    Cisco Catalyst Center inventory.
  - For the source device, at least one of identifier must be provided from management
    IP address, MAC address, or serial number.
  - For the destination device, at least one of identifier must be provided from management
    IP address, MAC address, or serial number when performing
    create or update operations, and is recommended when targeting a
    specific Port Channel for deletion.
  - When multiple device identifiers are provided for the same device,
    precedence order is serial_number > management_ip_address > mac_address.
  - Port Channel link constraints - each Port Channel must maintain
    between 2 and 8 physical links. Operations creating Port Channels
    with fewer than 2 or more than 8 links will fail validation.
  - Port Channel identification for updates can use either existing
    link specifications or port_channel_number parameter. When both
    are provided, port_channel_number takes precedence for identification.
  - Link isolation requirement - physical links cannot be shared between
    multiple Port Channels. Each link belongs exclusively to one
    Port Channel configuration.
  - Source and destination terminology is used for configuration
    consistency only. Both devices function as equal peers in the
    resulting Port Channel aggregation.
  - Port Channel deletion behavior varies based on provided parameters.
    When deleting Port Channels without specifying individual links,
    if port_channel_number is provided, only that specific Port Channel
    will be deleted. If both endpoints are provided without
    port_channel_number, all Port Channels between those devices will
    be deleted. If only source endpoint is provided, all Port Channels
    from that source device will be deleted.
  - Port Channel deletion behavior when deleting individual links -
    removing links that would result in fewer than 2 remaining links
    will automatically delete the entire Port Channel. Operations that
    would leave exactly 1 link will fail validation as Port Channels
    require minimum 2 links for proper operation.
  - Port Channel operations integrate with existing LAN Automation
    device lifecycle management and appear in standard Catalyst Center
    interface topology views.
  - When updating Port Channels, at least one existing link must be
    provided to identify the Port Channel between the same endpoints
    unless port_channel_number is specified for direct identification.
  - Links from different Port Channels cannot be mixed during update
    operations. Each physical link can belong to only one Port Channel
    at any given time.

  - SDK Method used are
    lan_automation.LanAutomation.lan_automation_start_v2
    lan_automation.LanAutomation.lan_automation_stop
    lan_automation.LanAutomation.lan_automation_device_update
    lan_automation.LanAutomation.lan_automation_active_sessions
    lan_automation.LanAutomation.lan_automation_status
    lan_automation.LanAutomation.lan_automation_log
    lan_automation.LanAutomation.get_port_channels
    lan_automation.LanAutomation.create_a_new_port_channel_between_devices
    lan_automation.LanAutomation.add_a_lan_automated_link_to_a_port_channel
    lan_automation.LanAutomation.delete_port_channel
    lan_automation.LanAutomation.remove_a_link_from_port_channel
    devices.Devices.get_interface_details
    devices.Devices.get_device_list
    device_onboarding_pnp.DeviceOnboardingPnp.authorize_device
    device_onboarding_pnp.DeviceOnboardingPnp.get_device_list
"""

EXAMPLES = r"""
---
- name: Start a LAN Automation session without waiting
    for it to finish
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - lan_automation:
          discovered_device_site_name_hierarchy: "Global/USA/SAN
            JOSE"
          peer_device_management_ip_address: "204.1.1.2"
          primary_device_management_ip_address: "204.1.1.1"
          primary_device_interface_names:
            - "HundredGigE1/0/2"
            - "HundredGigE1/0/29"
          ip_pools:
            - ip_pool_name: "underlay_sub"
              ip_pool_role: "MAIN_POOL"
            - ip_pool_name: "underlay_sub_sj"
              ip_pool_role: "PHYSICAL_LINK_POOL"
          multicast_enabled: true
          redistribute_isis_to_bgp: true
          host_name_prefix: "San-Jose"
          isis_domain_pwd: "cisco"
          discovery_level: 5
          discovery_timeout: 40
          discovery_devices:
            - device_serial_number: "FJC27172JDW"
              device_host_name: "SR-LAN-9300-IM1"
              device_site_name_hierarchy: "Global/USA/SAN
                JOSE/BLD23"
              device_management_ip_address: "204.1.1.10"
            - device_serial_number: "FJC2721261A"
              device_host_name: "SR-LAN-9300-IM2"
              device_site_name_hierarchy: "Global/USA/SAN
                JOSE/BLD20"
              device_management_ip_address: "204.1.1.11"
          launch_and_wait: false
          pnp_authorization: false

- name: Start a LAN Automation session with device authorization
    and waiting for the task to complete
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - lan_automation:
          discovered_device_site_name_hierarchy: "Global/USA/SAN
            JOSE"
          peer_device_management_ip_address: "204.1.1.2"
          primary_device_management_ip_address: "204.1.1.1"
          primary_device_interface_names:
            - "HundredGigE1/0/2"
            - "HundredGigE1/0/29"
          ip_pools:
            - ip_pool_name: "underlay_sub"
              ip_pool_role: "MAIN_POOL"
            - ip_pool_name: "underlay_sub_sj"
              ip_pool_role: "PHYSICAL_LINK_POOL"
          multicast_enabled: true
          redistribute_isis_to_bgp: true
          host_name_prefix: "San-Jose"
          isis_domain_pwd: "cisco"
          discovery_level: 5
          discovery_timeout: 40
          discovery_devices:
            - device_serial_number: "FJC27172JDW"
              device_host_name: "SR-LAN-9300-IM1"
              device_site_name_hierarchy: "Global/USA/SAN
                JOSE/BLD23"
              device_management_ip_address: "204.1.1.10"
            - device_serial_number: "FJC2721261A"
              device_host_name: "SR-LAN-9300-IM2"
              device_site_name_hierarchy: "Global/USA/SAN
                JOSE/BLD20"
              device_management_ip_address: "204.1.1.11"
          launch_and_wait: true
          pnp_authorization: true
          device_serial_number_authorization:
            - "FJC27172JDW"
            - "FJC2721261A"

- name: Stop a LAN Automation session
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: deleted
    config:
      - lan_automation:
          discovered_device_site_name_hierarchy: "Global/USA/SAN
            JOSE"
          primary_device_management_ip_address: "204.1.1.1"

- name: Update loopback for LAN Automated devices
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - lan_automated_device_update:
          loopback_update_device_list:
            - device_management_ip_address: "204.1.3.160"
              new_loopback0_ip_address: "91.1.2.6"
            - device_management_ip_address: "204.1.2.163"
              new_loopback0_ip_address: "91.1.2.5"

- name: Update hostname for LAN Automated devices
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - lan_automated_device_update:
          hostname_update_devices:
            - device_management_ip_address: "204.1.1.1"
              new_host_name: "SR-LAN-9300-im1"
            - device_management_ip_address: "91.1.1.6"
              new_host_name: "Test"

- name: Add link for LAN Automated devices
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - lan_automated_device_update:
          link_add:
            source_device_management_ip_address: "204.1.1.1"
            source_device_interface_name: "HundredGigE1/0/2"
            destination_device_management_ip_address: "204.1.1.4"
            destination_device_interface_name: "HundredGigE1/0/5"
            ip_pool_name: "underlay_sj"

- name: Delete link between LAN Automated devices
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - lan_automated_device_update:
          link_delete:
            source_device_management_ip_address: "204.1.1.1"
            source_device_interface_name: "HundredGigE1/0/2"
            destination_device_management_ip_address: "204.1.1.4"
            destination_device_interface_name: "HundredGigE1/0/5"

- name: Apply loopback and hostname updates for LAN
    Automated devices
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - lan_automated_device_update:
          loopback_update_device_list:
            - device_management_ip_address: "204.1.1.160"
              new_loopback0_ip_address: "10.4.18.101"
          hostname_update_devices:
            - device_management_ip_address: "91.1.3.2"
              new_host_name: "SR-LAN-9300-SJ"
            - device_management_ip_address: "204.1.1.5"
              new_host_name: "SR-LAN-9500-SJ"

- name: Create a new Port Channel using Management IP address device identification
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - port_channel:
          - source_device_management_ip_address: 10.1.1.1
            destination_device_management_ip_address: 20.1.1.1
            links:
              - source_port: GigabitEthernet1/0/1
                destination_port: GigabitEthernet2/0/1
              - source_port: GigabitEthernet1/0/2
                destination_port: GigabitEthernet2/0/2

- name: Create Port Channel using MAC address device identification
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - port_channel:
          - source_device_mac_address: aa:bb:cc:dd:ee:01
            destination_device_mac_address: aa:bb:cc:dd:ee:02
            links:
              - source_port: TenGigabitEthernet1/0/1
                destination_port: TenGigabitEthernet1/0/1
              - source_port: TenGigabitEthernet1/0/2
                destination_port: TenGigabitEthernet1/0/2

- name: Create Port Channel using serial number device identification
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - port_channel:
          - source_device_serial_number: FCW2140L056
            destination_device_serial_number: FCW2140L057
            links:
              - source_port: FortyGigabitEthernet1/0/1
                destination_port: FortyGigabitEthernet1/0/1

# Provide at least one existing link to identify the Port Channel.
- name: Update existing Port Channel by providing at least one existing link
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - port_channel:
          - source_device_management_ip_address: 10.1.1.1
            destination_device_management_ip_address: 20.1.1.1
            links:
              # Existing link already part of the Port Channel
              - source_port: GigabitEthernet1/0/1
                destination_port: GigabitEthernet2/0/1
              # New link to be added
              - source_port: GigabitEthernet1/0/10
                destination_port: GigabitEthernet2/0/10

- name: Update a Port Channel using port_channel_number
  # No need to specify existing links when port_channel_number is provided.
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - port_channel:
          - source_device_management_ip_address: 10.1.1.1
            destination_device_management_ip_address: 20.1.1.1
            port_channel_number: 1
            links:
              - source_port: GigabitEthernet1/0/10
                destination_port: GigabitEthernet2/0/10

- name: Delete all Port Channels between two devices
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: deleted
    config:
      - port_channel:
          - source_device_management_ip_address: 10.1.1.1
            destination_device_management_ip_address: 20.1.1.1

- name: Delete a specific link from a Port Channel
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: deleted
    config:
      - port_channel:
          - source_device_management_ip_address: 10.1.1.1
            destination_device_management_ip_address: 20.1.1.1
            links:
              - source_port: GigabitEthernet1/0/1
                destination_port: GigabitEthernet2/0/1            # This link will be removed from its associated Port Channel.

- name: Delete an entire Port Channel between two devices by specifying all the links
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: deleted
    config:
      - port_channel:
          - source_device_management_ip_address: 10.1.1.1
            destination_device_management_ip_address: 20.1.1.1
            links:
              - source_port: GigabitEthernet1/0/1
                destination_port: GigabitEthernet2/0/1
              - source_port: GigabitEthernet1/0/2
                destination_port: GigabitEthernet2/0/2
              - source_port: GigabitEthernet1/0/3
                destination_port: GigabitEthernet2/0/3

- name: Delete an entire Port Channel between two devices by specifying the port_channel_number
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: deleted
    config:
      - port_channel:
          - source_device_management_ip_address: 10.1.1.1
            destination_device_management_ip_address: 20.1.1.1
            port_channel_number: 1

- name: Delete all Port Channels originating from a source device
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: deleted
    config:
      - port_channel:
          - source_device_management_ip_address: 10.1.1.1
          # Deletes every Port Channel from source device 10.1.1.1, regardless of destination.

- name: Complex Port Channel operations with multiple configurations
  cisco.dnac.lan_automation_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    config_verify: false
    state: merged
    config:
      - port_channel:
          # First Port Channel between devices A and B
          - source_device_management_ip_address: "10.1.1.1"
            destination_device_management_ip_address: "20.1.1.1"
            links:
              - source_port: "GigabitEthernet1/0/1"
                destination_port: "GigabitEthernet2/0/1"
              - source_port: "GigabitEthernet1/0/2"
                destination_port: "GigabitEthernet2/0/2"
          # Second Port Channel between devices A and C
          - source_device_management_ip_address: "10.1.1.1"
            destination_device_management_ip_address: "30.1.1.1"
            links:
              - source_port: "GigabitEthernet1/0/3"
                destination_port: "GigabitEthernet3/0/1"
              - source_port: "GigabitEthernet1/0/4"
                destination_port: "GigabitEthernet3/0/2"
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
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import DnacBase
from ansible_collections.cisco.dnac.plugins.module_utils.validation import (
    validate_list_of_dicts,
)

import time


class LanAutomation(DnacBase):
    """Class containing member attributes for lan automation workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        (
            self.started_lan_automation,
            self.completed_lan_automation,
            self.stopped_lan_automation,
        ) = ([], [], [])
        self.no_lan_auto_start, self.no_lan_auto_stop = [], []
        self.updated_loopback, self.no_loopback_updated = [], []
        self.updated_hostname, self.no_hostname_updated = [], []
        self.added_link, self.no_link_added = [], []
        self.deleted_link, self.no_link_deleted = [], []
        self.port_channel_created = []
        self.port_channel_deleted, self.no_port_channel_deleted = [], []
        self.link_added_to_port_channel, self.link_not_added_to_port_channel = [], []
        self.link_removed_from_port_channel, self.link_not_removed_from_port_channel = (
            [],
            [],
        )
        self.supported_states = ["merged", "deleted"]

    def validate_input(self):
        """
        Validate the fields provided in the playbook.  Checks the
        configuration provided in the playbook against a predefined
        specification to ensure it adheres to the expected structure
        and data types.

        Args:
          - self: The instance of the class containing the 'config' attribute
                  to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - self.msg: A message describing the validation result.
          - self.status: The status of the validation (either 'success' or 'failed').
          - self.validated_config: If successful, a validated version of the
                                   'config' parameter.
        Example:
          To use this method, create an instance of the class and call
          'validate_input' on it.If the validation succeeds, 'self.status'
          will be 'success' and 'self.validated_config' will contain the
          validated configuration. If it fails, 'self.status' will be
          'failed', and 'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation."
            self.log(self.msg, "ERROR")
            return self

        lan_automation_spec = {
            "lan_automation": {
                "type": "dict",
                "required": False,
                "elements": "dict",
                "discovered_device_site_name_hierarchy": {
                    "type": "str",
                    "required": True,
                },
                "primary_device_management_ip_address": {
                    "type": "str",
                    "required": True,
                },
                "primary_device_interface_names": {
                    "type": "list",
                    "required": True,
                    "elements": "str",
                },
                "peer_device_management_ip_address": {
                    "type": "str",
                    "required": False,
                },
                "ip_pools": {
                    "type": "list",
                    "required": True,
                    "elements": "dict",
                    "ip_pool_name": {"type": "str", "required": True},
                    "ip_pool_role": {
                        "type": "str",
                        "required": True,
                        "choices": ["MAIN_POOL", "PHYSICAL_LINK_POOL"],
                    },
                },
                "multicast_enabled": {
                    "type": "bool",
                    "required": False,
                    "default": False,
                },
                "host_name_prefix": {"type": "str", "required": False},
                "redistribute_isis_to_bgp": {
                    "type": "bool",
                    "required": False,
                    "default": False,
                },
                "isis_domain_pwd": {"type": "str", "required": False},
                "discovery_level": {
                    "type": "int",
                    "required": False,
                    "default": 2,
                },
                "discovery_timeout": {"type": "int", "required": False},
                "discovery_devices": {
                    "type": "list",
                    "required": False,
                    "elements": "dict",
                    "device_serial_number": {"type": "str", "required": True},
                    "device_host_name": {"type": "str", "required": False},
                    "device_site_name_hierarchy": {
                        "type": "str",
                        "required": False,
                    },
                    "device_management_ip_address": {
                        "type": "str",
                        "required": False,
                    },
                },
                "launch_and_wait": {
                    "type": "bool",
                    "required": False,
                    "default": False,
                },
                "pnp_authorization": {
                    "type": "bool",
                    "required": False,
                    "default": False,
                },
                "device_serial_number_authorization": {
                    "type": "list",
                    "required": False,
                    "elements": "str",
                },
            },
            "lan_automated_device_update": {
                "type": "dict",
                "required": False,
                "elements": "dict",
                "loopback_update_device_list": {
                    "type": "list",
                    "required": False,
                    "elements": "dict",
                    "device_management_ip_address": {
                        "type": "str",
                        "required": True,
                    },
                    "new_loopback0_ip_address": {
                        "type": "str",
                        "required": True,
                    },
                },
                "hostname_update_devices": {
                    "type": "list",
                    "required": False,
                    "elements": "dict",
                    "device_management_ip_address": {
                        "type": "str",
                        "required": True,
                    },
                    "new_host_name": {"type": "str", "required": True},
                },
                "link_add": {
                    "type": "dict",
                    "required": False,
                    "source_device_management_ip_address": {
                        "type": "str",
                        "required": True,
                    },
                    "source_device_interface_name": {
                        "type": "str",
                        "required": True,
                    },
                    "destination_device_management_ip_address": {
                        "type": "str",
                        "required": True,
                    },
                    "destination_device_interface_name": {
                        "type": "str",
                        "required": True,
                    },
                    "ip_pool_name": {"type": "str", "required": True},
                },
                "link_delete": {
                    "type": "dict",
                    "required": False,
                    "source_device_management_ip_address": {
                        "type": "str",
                        "required": True,
                    },
                    "source_device_interface_name": {
                        "type": "str",
                        "required": True,
                    },
                    "destination_device_management_ip_address": {
                        "type": "str",
                        "required": True,
                    },
                    "destination_device_interface_name": {
                        "type": "str",
                        "required": True,
                    },
                },
            },
            "port_channel": {
                "type": "list",
                "elements": "dict",
                "source_device_management_ip_address": {
                    "type": "str",
                    "required": False,
                },
                "source_device_mac_address": {
                    "type": "str",
                    "required": False,
                },
                "source_device_serial_number": {
                    "type": "str",
                    "required": False,
                },
                "destination_device_management_ip_address": {
                    "type": "str",
                    "required": False,
                },
                "destination_device_mac_address": {
                    "type": "str",
                    "required": False,
                },
                "destination_device_serial_number": {
                    "type": "str",
                    "required": False,
                },
                "port_channel_number": {
                    "type": "int",
                    "required": False,
                },
                "links": {
                    "type": "list",
                    "elements": "dict",
                    "required": False,
                    "source_port": {
                        "type": "str",
                        "required": True,
                    },
                    "destination_port": {
                        "type": "str",
                        "required": True,
                    },
                },
            },
        }

        valid_lan_automation, invalid_params = validate_list_of_dicts(
            self.config, lan_automation_spec
        )

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.log(str(self.msg), "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_lan_automation
        self.msg = f"Successfully validated playbook configuration parameters using 'validate_input': {self.pprint(valid_lan_automation)}."
        self.log(self.msg, "INFO")
        self.status = "success"
        return self

    def get_have(self, config):
        """
        Retrieve the current LAN Automation session details and port channel configurations from Cisco Catalyst Center.
        This method checks for active LAN Automation sessions, retrieves their details,
        maps session IDs to the primary IP addresses of seed devices, and stores the
        information in the class instance.
        Args:
            - config (dict): Configuration settings used for retrieving the LAN Automation session details.
        Returns:
            - object: The current instance of the class (`self`) with updated attributes:
                - `self.have` (dict): A dictionary containing:
                    - activeSessions (bool): Indicates if active LAN Automation sessions are present.
                    - activeSessionIds (list): List of IDs for the active LAN Automation sessions.
                    - session_to_ip_map (dict): Maps session IDs to their corresponding primary IP addresses.
                    - port_channel (list[list[dict] | None]): Extracted port channel configurations for each
                      playbook-defined port channel config.
                        - Each element corresponds to one config from the playbook.
                        - Each element is either:
                            • list[dict] → one or more matching port channel configs
                            • None → if no match was found for that config
                        - If the playbook does not define any port channel configs, this is [].
        """

        have = {
            "activeSessions": False,
            "activeSessionIds": [],
            "session_to_ip_map": {},
        }
        active_lan_automation = False
        lan_automation_session_ids = []

        (active_lan_automation, lan_automation_session_ids) = (
            self.active_lan_automation_sessions()
        )

        self.log(
            "Current active LAN Automation sessions (have): {} and their ids are: {}".format(
                str(active_lan_automation), str(lan_automation_session_ids)
            ),
            "DEBUG",
        )

        if active_lan_automation:
            have["activeSessions"] = active_lan_automation
            have["activeSessionIds"] = lan_automation_session_ids

        lan_automation_sessions = self.get_lan_automation_status()
        session_to_ip_map = self.map_active_sessions_to_primary_ip(
            lan_automation_sessions, lan_automation_session_ids
        )

        if session_to_ip_map:
            have["session_to_ip_map"] = session_to_ip_map

        self.log(
            "Mapped active session IDs to primary IPs: {}".format(
                str(session_to_ip_map)
            ),
            "INFO",
        )

        have["port_channel"] = self.extract_port_channel_config_from_catalyst_center()

        self.have = have
        self.log("Current State (self.have): {}".format(str(self.have)), "INFO")
        self.msg = "Successfully retrieved the details from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_port_channels(
        self,
        source_device_management_ip_address,
        destination_device_management_ip_address,
        port_channel_number,
    ):
        """
        Retrieve Port Channel configurations between two devices from Cisco Catalyst Center.

        Parameters:
            source_device_management_ip_address (str): Management IP address of the source device.
            destination_device_management_ip_address (str): Management IP address of the destination device. If None,
                        retrieves Port Channels from the source device to all connected devices.
            port_channel_number (int): Specific Port Channel number to filter results. If None, returns all Port Channels between the devices.

        Returns:
            list or None: List of Port Channel configuration dictionaries if found, None if no configurations exist.
                        Each dictionary contains Port Channel details including device information,
                        Port Channel numbers, and link configurations.

        Description:
            Calls the Cisco Catalyst Center API to retrieve Port Channel configurations between two specified devices.
            The method constructs a payload with source and destination device IP addresses and makes an API call
            to 'get_port_channels'. If a specific port_channel_number is provided, it filters the results to return
            only configurations matching that Port Channel number. The method handles API response validation,
            logs detailed information about the retrieval process, and returns None if no configurations are found
            or if an error occurs during the API call.
        """

        self.log(
            f"Initiating Port Channel retrieval - Source IP: '{source_device_management_ip_address}', "
            f"Destination IP: '{destination_device_management_ip_address}', Port Channel Number: '{port_channel_number}'",
            "INFO",
        )

        if not source_device_management_ip_address:
            self.log(
                "Source device management IP address is required to fetch Port Channel configurations.",
                "ERROR",
            )
            return []

        if not self.is_valid_ipv4(source_device_management_ip_address):
            self.msg = (
                f"Invalid source device IP address format: {source_device_management_ip_address}",
                "ERROR",
            )
            self.fail_and_exit(self.msg)

        payload = {
            "device1_management_ipaddress": source_device_management_ip_address,
            "device2_management_ipaddress": destination_device_management_ip_address,
            #  port_channel_number is not passed in payload, as fetching with port_channel_number is not available yet. To be added here later.
        }

        if destination_device_management_ip_address:
            self.log(
                f"Processing Port Channel configuration: Source device '{source_device_management_ip_address}' -> "
                f"Destination device '{destination_device_management_ip_address}'",
                "DEBUG",
            )
            if not self.is_valid_ipv4(destination_device_management_ip_address):
                self.msg = (
                    f"Invalid destination device IP address format: {destination_device_management_ip_address}".format(
                        destination_device_management_ip_address
                    ),
                    "ERROR",
                )
                self.fail_and_exit(self.msg)
        else:
            self.log(
                f"Processing Port Channel configuration: All Port Channels from source device '{source_device_management_ip_address}'",
                "DEBUG",
            )

        if port_channel_number:
            self.log(
                f"Applying Port Channel number filter: '{port_channel_number}'", "DEBUG"
            )
        else:
            self.log(
                "No Port Channel number filter applied - retrieving all Port Channels",
                "DEBUG",
            )

        # Note about API limitation
        self.log(
            "Note: port_channel_number filtering is done client-side as API doesn't support server-side filtering yet",
            "DEBUG",
        )

        try:
            self.log(
                f"Calling 'get_port_channels' API with payload: {self.pprint(payload)}",
                "DEBUG",
            )
            response = self.dnac_apply["exec"](
                family="lan_automation", function="get_port_channels", params=payload
            )

            # Check if the response is empty
            self.log(
                f"API call completed. Received API response from 'get_port_channels' for for Source IP: '{source_device_management_ip_address}', "
                f"Destination IP: '{destination_device_management_ip_address}': {response}",
                "DEBUG",
            )

            if not response:
                self.msg = (
                    f"No port channel configurations retrieved for Source IP: '{source_device_management_ip_address}', "
                    f"Destination IP: '{destination_device_management_ip_address}', Response is empty."
                )
                self.log(self.msg, "DEBUG")
                return []

            port_channel_info = response.get("response")

            self.log(
                f"Retrieved Port Channel configurations for Source IP: {source_device_management_ip_address}, "
                f"Destination IP: {destination_device_management_ip_address}: {self.pprint(port_channel_info)}",
                "INFO",
            )
            if not port_channel_number:
                self.log(
                    "port_channel_number is not provided, returning all Port Channel configurations.",
                    "INFO",
                )
                return port_channel_info

            self.log(
                f"Successfully retrieved {len(port_channel_info)} Port Channel configuration(s) for "
                f"source device: {source_device_management_ip_address}",
                "INFO",
            )
            filtered_info = [
                info
                for info in port_channel_info
                if info.get("device1PortChannelNumber") == port_channel_number
            ]

            if not filtered_info:
                self.msg = (
                    f"No Port Channel configurations found for Source IP: '{source_device_management_ip_address}', "
                    f"Destination IP: '{destination_device_management_ip_address}', Port Channel Number: '{port_channel_number}'."
                )
                self.log(self.msg, "DEBUG")
                return []

            self.log(
                f"Filtered Port Channel configurations: {self.pprint(filtered_info)}",
                "DEBUG",
            )
            return filtered_info

        except Exception as e:
            self.msg = (
                f"Exception occurred while retrieving Port Channel details - "
                f"Source IP: '{source_device_management_ip_address}', "
                f"Destination IP: '{destination_device_management_ip_address}', "
                f"Port Channel Number: '{port_channel_number}', "
                f"Error: '{str(e)}'"
            )
            self.fail_and_exit(self.msg)

    def format_port_channels_have_configs(self, port_channel_configs):
        """
        Format port channel configurations into a standardized structure.

        Parameters:
            port_channel_configs (list[dict]):
                List of dictionaries containing raw port channel configurations.
                Each configuration may include device IPs, port channel numbers, IDs,
                and associated port channel member links.

        Returns:
            list[dict]:
                List of formatted port channel configuration dictionaries.
                Each dictionary contains source/destination device IPs,
                port channel number, ID, and associated links.

        Description:
            This method processes a list of raw port channel configurations
            and reformats them into a structured format suitable for further
            workflows. Each port channel entry includes device management IPs,
            port channel metadata, and member link mappings (source/destination ports).
            Logging is performed at multiple stages to aid debugging.
        """
        self.log(
            f"Formatting Port Channel configuration: {self.pprint(port_channel_configs)}",
            "DEBUG",
        )

        if not port_channel_configs:
            self.log("No Port Channel configurations to format.", "INFO")
            return []

        formatted_configs = []
        for idx, port_channel_config in enumerate(port_channel_configs, start=1):
            self.log(
                f"Processing port channel config #{idx}: {self.pprint(port_channel_config)}",
                "DEBUG",
            )

            formatted_config = {
                "sourceDeviceManagementIPAddress": port_channel_config.get(
                    "device1ManagementIPAddress"
                ),
                "destinationDeviceManagementIPAddress": port_channel_config.get(
                    "device2ManagementIPAddress"
                ),
                "portChannelNumber": port_channel_config.get(
                    "device1PortChannelNumber"
                ),
                "id": port_channel_config.get("id"),
            }
            self.log(
                f"Extracted config details: "
                f"Source={formatted_config['sourceDeviceManagementIPAddress']}, "
                f"Destination={formatted_config['destinationDeviceManagementIPAddress']}, "
                f"PortChannel={formatted_config['portChannelNumber']}, "
                f"ID={formatted_config['id']}",
                "DEBUG",
            )

            formatted_config["links"] = [
                {
                    "sourcePort": link.get("device1Interface"),
                    "destinationPort": link.get("device2Interface"),
                }
                for link in port_channel_config.get("portChannelMembers", [])
            ]

            formatted_configs.append(formatted_config)

        self.log(
            f"Formatted {len(formatted_configs)} Port Channel configuration(s): "
            f"{self.pprint(formatted_configs)}",
            "DEBUG",
        )
        return formatted_configs

    def extract_port_channel_config_from_catalyst_center(self):
        """
        Extract port channel configurations from Catalyst Center.

        Parameters:
            None

        Returns:
            list[list[dict] | None]:
                - The outer list corresponds to each port channel config defined
                  in the playbook (`want["port_channel"]`).
                - Each element in the outer list can be:
                    • list[dict] → one or more matching configs from Catalyst Center
                    • None → if no matching config was found for that playbook entry
                - If the playbook does not define any port channel configs,
                  an empty list [] is returned.

        Description:
            This method compares the desired port channel configurations defined
            in the playbook (`want["port_channel"]`) with existing port channel
            configurations fetched from Catalyst Center.

            Behavior:
            - If no port channel configs are defined in the playbook, an empty list [] is returned.
            - If `port_channel_number` is provided, exactly one config is expected and returned
              inside a list (or None if no match).
            - If only `links` are provided, exactly one config is matched and returned
              inside a list (or None if no match).
            - If neither are provided, all existing configs for the given device pair
              are returned inside a list.
            - If multiple configs match the same set of links, the method raises an error.
            - Logs are generated at INFO and DEBUG levels for traceability.
        """

        port_channel_configs = self.want.get("port_channel", [])
        self.log(
            f"Initializing extraction of port channel configurations from Catalyst Center "
            f"for playbook port_channel config: {self.pprint(port_channel_configs)}",
            "DEBUG",
        )

        if not port_channel_configs:
            self.log(
                "No port_channel configuration provided in the playbook. "
                "No extraction needed.",
                "INFO",
            )
            return []

        have_port_channel_configs = []

        for idx, port_channel_config in enumerate(port_channel_configs, start=1):
            self.log(
                f"[Config {idx}] Extracting details from Catalyst Center for playbook config: {self.pprint(port_channel_config)}",
                "INFO",
            )

            source_device_management_ip_address = port_channel_config.get(
                "sourceDeviceManagementIPAddress"
            )
            destination_device_management_ip_address = port_channel_config.get(
                "destinationDeviceManagementIPAddress"
            )
            port_channel_number = port_channel_config.get("portChannelNumber")

            self.log(
                f"[Config {idx}] Fetching configs with Source={source_device_management_ip_address}, "
                f"Destination={destination_device_management_ip_address}, "
                f"PortChannel={port_channel_number}",
                "DEBUG",
            )
            fetched_port_channel_configs = self.get_port_channels(
                source_device_management_ip_address,
                destination_device_management_ip_address,
                port_channel_number,
            )

            want_links = port_channel_config.get("links")
            if not fetched_port_channel_configs:
                self.log(
                    f"No matching port channel configurations found in Catalyst Center for [Config {idx}].",
                    "INFO",
                )
                if want_links and port_channel_number:
                    #  Port channel number and links both are provided, i.e. expecting to update, so fail if existing is not found.
                    self.log(
                        f"[Config {idx}] No existing Port Channel config found with provided port_channel_number.",
                        "DEBUG",
                    )
                    self.msg = (
                        "No existing Port Channel configuration found with the provided "
                        f"port_channel_number: {port_channel_number}. When both port_channel_number and links "
                        "are specified, an existing Port Channel is expected for update. "
                        "If you want to create a new Port Channel, please remove the "
                        "port_channel_number parameter from your playbook configuration "
                        "and try again."
                    )
                    self.fail_and_exit(self.msg)

                have_port_channel_configs.append(None)
                continue

            self.log(
                f"Retrieved {len(fetched_port_channel_configs)} raw port channel configurations from Catalyst Center for [Config {idx}]",
                "DEBUG",
            )
            formatted_port_channel_config_list = self.format_port_channels_have_configs(
                fetched_port_channel_configs
            )

            if want_links:
                self.log(
                    f"[Config {idx}] Links provided in playbook: {self.pprint(want_links)}",
                    "INFO",
                )
                if port_channel_number:
                    self.log(
                        f"[Config {idx}] port_channel_number provided, keeping all fetched configs.",
                        "INFO",
                    )
                    have_port_channel_config = formatted_port_channel_config_list
                    # if formatted_port_channel_config_list is not empty and port_channel_number is provided, there should be only one config in the list.
                    self.log(
                        f"[Config {idx}] Matching configs: {self.pprint(have_port_channel_config)}",
                        "DEBUG",
                    )
                else:
                    self.log(
                        f"[Config {idx}] port_channel_number not provided, attempting to find the relevant port channel with the provided links.",
                        "INFO",
                    )
                    link_matched_port_channel_config_index_set = set()
                    for want_link in want_links:
                        for i, have_port_channel_config in enumerate(
                            formatted_port_channel_config_list
                        ):
                            for have_link in have_port_channel_config.get("links", []):
                                if want_link.get("sourcePort") == have_link.get(
                                    "sourcePort"
                                ) and want_link.get("destinationPort") == have_link.get(
                                    "destinationPort"
                                ):
                                    link_matched_port_channel_config_index_set.add(i)
                                    self.log(
                                        f"[Config {idx}] Link {want_link} matches with existing config index {i}: "
                                        f"{self.pprint(have_port_channel_config)}",
                                        "DEBUG",
                                    )

                    if not link_matched_port_channel_config_index_set:
                        self.log(
                            f"[Config {idx}] No existing Port Channel config found by matching links provided in config.",
                            "DEBUG",
                        )
                        have_port_channel_config = None

                    elif len(link_matched_port_channel_config_index_set) > 1:
                        matched_config_indices = ", ".join(
                            map(
                                str,
                                sorted(link_matched_port_channel_config_index_set),
                            )
                        )
                        self.msg = (
                            f"[Config {idx}] Links provided in playbooks belongs to multiple existing Port "
                            f"Channel configurations: {self.pprint(formatted_port_channel_config_list)}."
                            f"Matching indices: {matched_config_indices}"
                        )
                        self.fail_and_exit(self.msg)
                    else:
                        matched_config_index = (
                            link_matched_port_channel_config_index_set.pop()
                        )
                        self.log(
                            f"[Config {idx}] Link matched Port Channel config at index: '{matched_config_index}' "
                            f"Matched Config: {self.pprint(formatted_port_channel_config_list[matched_config_index])}",
                            "DEBUG",
                        )
                        have_port_channel_config = [
                            formatted_port_channel_config_list[matched_config_index]
                        ]
            else:
                self.log(
                    f"[Config {idx}] No links provided in the playbook configuration, keeping all {len(formatted_port_channel_config_list)} configs.",
                    "INFO",
                )
                have_port_channel_config = formatted_port_channel_config_list

            have_port_channel_configs.append(have_port_channel_config)
            self.log(
                f"[Config {idx}] Final extracted configs: {self.pprint(have_port_channel_config)}",
                "DEBUG",
            )

        self.log(
            f"Retrieved existing Port Channel configurations (Have): {self.pprint(have_port_channel_configs)}",
            "DEBUG",
        )
        return have_port_channel_configs

    def map_active_sessions_to_primary_ip(
        self, lan_automation_sessions, lan_automation_session_ids
    ):
        """
        Map active LAN Automation session IDs to their respective primary seed device IP addresses.
        This method associates each session ID from the active LAN Automation sessions with its
        corresponding primary seed device's management IP address.
        Args:
            - lan_automation_sessions (list): List of dictionaries containing session details for all active LAN
              Automation sessions.
            - lan_automation_session_ids (list): List of active LAN Automation session IDs retrieved from Cisco
              Catalyst Center.
        Returns:
            - dict: A dictionary mapping session IDs to their corresponding primary seed device IP address.
                    If no primary IP address is found for a session ID, its value is set to `None`.
        """

        self.log(
            f"Initiating session ID to primary IP mapping for {len(lan_automation_sessions or [])} sessions and {len(lan_automation_session_ids or [])} IDs",
            "DEBUG",
        )

        session_id_to_primary_ip = {}

        for session_id in lan_automation_session_ids:
            primary_ip = None

            for session in lan_automation_sessions:
                if session.get("id") == session_id:
                    primary_ip = session.get("primaryDeviceManagmentIPAddress")
                    break

            session_id_to_primary_ip[session_id] = primary_ip

        self.log(
            "Mapped active session IDs to primary IPs: {}".format(
                session_id_to_primary_ip
            ),
            "INFO",
        )

        return session_id_to_primary_ip

    def active_lan_automation_sessions(self):
        """
        Retrieve details of active LAN Automation sessions from Cisco Catalyst Center.
        This method queries the Catalyst Center to check for any ongoing LAN Automation sessions
        by calling the `lan_automation_active_sessions` API and retrieves the session IDs.
        Returns:
            - tuple: A tuple containing two elements:
                - active_sessions (bool): Indicates whether active LAN Automation sessions exist (`True`/`False`).
                - active_session_ids (list): List of IDs for any active LAN Automation sessions.
                  If no active sessions are found, the list is empty.
        """
        response = None
        try:
            response = self.dnac._exec(
                family="lan_automation",
                function="lan_automation_active_sessions",
                op_modifies=False,
            )

        except Exception as e:
            self.log(
                "Error occurred while retrieving active LAN automation sessions",
                "WARNING",
            )

        active_sessions = 0
        active_session_ids = []

        if response and response.get("response"):
            active_sessions = int(response["response"].get("activeSessions", 0))
            active_session_ids = response["response"].get("activeSessionIds", [])

            if active_sessions > 0:
                self.log(
                    "Active LAN automation sessions: {}".format(str(active_sessions)),
                    "INFO",
                )
            else:
                self.log("No active LAN automation sessions found.", "INFO")
        else:
            self.log("Failed to retrieve LAN automation session details.", "ERROR")

        return active_sessions, active_session_ids

    def get_lan_automation_status(self):
        """
        Retrieve all LAN Automation sessions from Cisco Catalyst Center by querying 'lan_automation_status' function
        in the 'lan_automation' family. This method fetches details of ongoing and completed LAN Automation sessions
        including associated devices, IP pools, and the discovery status.
        Args:
            - self (object): An instance of the class containing the method.
        Returns:
            - list: A list containing dictionaries for each LAN automation session. Each dictionary includes
                    detailed information about the session (e.g., devices, IP pools, discovery status, etc.).
                    If no sessions are found, an empty list is returned.
        """

        sessions = []
        try:
            response = self.dnac._exec(
                family="lan_automation",
                function="lan_automation_status",
                op_modifies=False,
            )

        except Exception as e:
            self.log("Error occurred while retrieving LAN automation status", "WARNING")
            return []

        if response and response.get("response"):
            sessions = response["response"]
            if sessions:
                self.log(
                    "Retrieved {} LAN automation session(s).".format(
                        str(len(sessions))
                    ),
                    "INFO",
                )
            else:
                self.log("No LAN automation sessions found.", "INFO")
        else:
            self.log("Failed to retrieve LAN automation session details.", "ERROR")

        return sessions

    def get_ip_details(self, management_ip_address, device_type):
        """
        Fetch the existence status of a device using the provided management IP address. This method checks if the
        device with the specified IP exists in Cisco Catalyst Center and is often used for validating seed, peer,
        or source devices.
        Args:
            - management_ip_address (str): The management IP address to be validated.
            - device_type (str): The type of the device (used for logging purposes).
        Returns:
            - bool: A boolean value indicating the existence of the IP.
        """

        ip_exists = False
        try:
            response = self.dnac_apply["exec"](
                family="devices",
                function="get_device_list",
                params={"management_ip_address": management_ip_address},
                op_modifies=False,
            )
        except Exception:
            self.log(
                "Exception occurred as management IP address {0} for device type {1} was not found".format(
                    management_ip_address, device_type
                ),
                "CRITICAL",
            )
            self.module.fail_json(
                msg="IP address: {0} does not exist. Please provide a valid IP address for {1}!".format(
                    management_ip_address, device_type
                ),
                response=[],
            )

        if response:
            self.log(
                "Received IP address details for {0}: {1}".format(
                    device_type, management_ip_address
                ),
                "DEBUG",
            )
            ip = response.get("response")
            if ip and len(ip) > 0:
                ip_exists = True
            else:
                self.log(
                    "Management IP address {0} for device type {1} was not found in Catalyst Center.".format(
                        management_ip_address, device_type
                    ),
                    "CRITICAL",
                )

        return ip_exists

    def get_hostname_details(self, management_ip_address):
        """
        Retrieve the hostname of the device associated with the provided management IP address from Catalyst Center.
        This method queries the device inventory and returns the hostname for the given IP address, if available.
        Args:
            - management_ip_address (str): The management IP address of the device.
        Returns:
            - str or None: The hostname of the device with the provided IP, or None if not found.
        """

        hostname = None
        try:
            response = self.dnac_apply["exec"](
                family="devices",
                function="get_device_list",
                params={"management_ip_address": management_ip_address},
                op_modifies=False,
            )
        except Exception:
            self.log(
                "Exception occurred while retrieving hostname for management IP address {0}.".format(
                    management_ip_address
                ),
                "ERROR",
            )
            return None

        if response:
            self.log(
                "Received device details for IP address {0}.".format(
                    management_ip_address
                ),
                "DEBUG",
            )
            device_details = response.get("response", [])

            if len(device_details) > 0:
                hostname = device_details[0].get("hostname")
                if hostname:
                    self.log(
                        "Hostname for IP {0} is {1}.".format(
                            management_ip_address, hostname
                        ),
                        "INFO",
                    )
            else:
                self.log(
                    "No device found with IP address {0}.".format(
                        management_ip_address
                    ),
                    "WARNING",
                )

        return hostname

    def get_site_details(self, site_name_hierarchy):
        """
        Fetches the existence status of the site where devices will be discovered.
        Args:
            - site_name_hierarchy (str): Name of the site collected from the input.
        Returns:
            - bool: A boolean value indicating the existence of the site.
        Example:
            Prior to starting a LAN Automation session, this method checks whether the site
            where devices will be discovered exists in the Cisco Catalyst Center.
        """

        site_exists = False
        try:
            response = self.dnac_apply["exec"](
                family="sites",
                function="get_site",
                params={"name": site_name_hierarchy},
                op_modifies=True,
            )
        except Exception:
            self.log(
                "Exception occurred as site '{0}' was not found".format(
                    site_name_hierarchy
                ),
                "CRITICAL",
            )
            self.module.fail_json(
                msg="Site {0} does not exist. Please provide a valid discovered device site name!".format(
                    site_name_hierarchy
                ),
                response=[],
            )

        if response:
            self.log(
                "Received site details for '{0}': {1}".format(
                    site_name_hierarchy, str(response)
                ),
                "DEBUG",
            )
            site = response.get("response")
            if len(site) == 1:
                site_exists = True
                self.log(
                    "Site Name: {0} exists in the Cisco Catalyst Center".format(
                        site_name_hierarchy
                    ),
                    "INFO",
                )

        return site_exists

    def get_device_ip_by_device_identifier(
        self, device_identifier, device_identifier_value
    ):
        """
        Retrieve the management IP address of a device given a specific identifier.

        Parameters:
            device_identifier (str):
                The type of identifier used to search for the device. Possible values:
                    - "ip_address"
                    - "mac_address"
                    - "serial_number"
            device_identifier_value (str):
                The value of the identifier to match for the device.

        Returns:
            str | None:
                - The management IP address of the device if found.
                - None if no device matches the given identifier and value.

        Description:
            This method maps the given identifier type to the corresponding API field,
            queries the Cisco Catalyst Center for the device using the 'get_device_list' API,
            and retrieves the management IP address. Detailed DEBUG logs are generated
            for the payload, API response, and any errors encountered. If the API call
            fails or no device is found, the method either logs the issue or exits the
            program with a failure message.
        """

        self.log(
            f"Retrieving device IP for device with {device_identifier}: '{device_identifier_value}'.",
            "DEBUG",
        )
        if not device_identifier:
            self.log(
                "Device identifier type is required for device IP retrieval", "ERROR"
            )
            return None

        if not device_identifier_value:
            self.log(
                "Device identifier value is required for device IP retrieval", "ERROR"
            )
            return None

        valid_identifiers = ["ip_address", "mac_address", "serial_number"]
        if device_identifier not in valid_identifiers:
            self.log(
                "Invalid device identifier type: {0}. Valid types are: {1}".format(
                    device_identifier, ", ".join(valid_identifiers)
                ),
                "ERROR",
            )
            return None

        device_identifier_api_name_dict = {
            "ip_address": "managementIpAddress",
            "mac_address": "macAddress",
            "serial_number": "serialNumber",
        }
        api_field = device_identifier_api_name_dict.get(device_identifier)
        payload = {f"{api_field}": device_identifier_value}
        self.log(
            f"Constructed payload for API request: {self.pprint(payload)}", "DEBUG"
        )
        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                params=payload,
            )

            self.log(
                f"Received API response from 'get_device_list' for the device with {device_identifier}: '{device_identifier_value}' is : {str(response)}",
                "DEBUG",
            )

            if not response:
                self.log(
                    f"No response received from 'get_device_list' API for {device_identifier}: {device_identifier_value}",
                    "WARNING",
                )
                return None

            response_data = response.get("response")
            if not response_data:
                self.msg = f"No device found with {device_identifier}: '{device_identifier_value}'."
                self.log(self.msg, "DEBUG")
                return None

            if not isinstance(response_data, list) or len(response_data) == 0:
                self.log(
                    "Empty or invalid device list returned for {0}: {1}".format(
                        device_identifier, device_identifier_value
                    ),
                    "INFO",
                )
                return None

            device_data = response_data[0]
            device_ip = device_data.get("managementIpAddress")

            self.log(
                f"Device IP for {device_identifier} '{device_identifier_value}' found: {device_ip}",
                "INFO",
            )

            return device_ip

        except Exception as e:
            error_message = str(e)
            self.msg = f"Failed to retrieve device IP for {device_identifier}: '{device_identifier_value}'. Error: {error_message}"
            self.fail_and_exit(self.msg)

    def resolve_device_ip(self, device_type, serial_number, ip_address, mac_address):
        """
        Resolve the management IP address of a device using serial number, IP address, or MAC address.

        Parameters:
            device_type (str):
                The type of device (source or destination).
            serial_number (str | None):
                The serial number of the device. If provided, this is used as the primary method to retrieve the IP.
            ip_address (str | None):
                The IP address of the device. Used if serial number is not provided.
            mac_address (str | None):
                The MAC address of the device. Used if neither serial number nor IP address are provided.

        Returns:
            str:
                The resolved management IP address of the device. If the device cannot be found using the provided
                identifier(s), the method exits with an error.

        Description:
            This method attempts to resolve the management IP address of a device in the following order:
            1. Serial number (highest priority)
            2. Provided IP address
            3. MAC address (lowest priority)

            - Logs are generated at DEBUG level for every step.
            - If a device cannot be found using the provided identifier, the method calls `fail_and_exit`.
            - Internally, it uses `get_device_ip_by_device_identifier` to query Cisco DNA Center.
        """
        self.log(
            f"Starting device IP resolution for {device_type} device using available identifiers",
            "DEBUG",
        )

        self.log(
            "Resolution parameters - Serial: {0}, IP: {1}, MAC: {2}".format(
                serial_number or "None", ip_address or "None", mac_address or "None"
            ),
            "DEBUG",
        )

        if not device_type:
            self.log(
                "Device type parameter is required for device IP resolution", "ERROR"
            )
            self.msg = "Device type cannot be empty for IP resolution"
            self.fail_and_exit(self.msg)

        resolved_ip_address = None

        if serial_number:
            self.log(
                f"{device_type.capitalize()} device management serial number is provided: {serial_number}",
                "DEBUG",
            )
            self.log("Retrieving IP address using serial number...", "DEBUG")
            ip_address = self.get_device_ip_by_device_identifier(
                "serial_number", serial_number
            )
            if not ip_address:
                self.log(
                    f"Failed to resolve IP address using serial number: {serial_number}",
                    "ERROR",
                )
                self.msg = (
                    f"Failed to retrieve device details using serial number: {serial_number}. "
                    "Please check if serial number is correct."
                )
                self.fail_and_exit(self.msg)

            self.log(
                f"Successfully resolved IP address using serial number {serial_number}: {ip_address}",
                "INFO",
            )

        elif ip_address:
            self.log(
                f"{device_type.capitalize()} device management IP address is provided: {ip_address}",
                "DEBUG",
            )
            self.log("Validating provided IP address...", "DEBUG")
            original_ip_address = ip_address
            ip_address = self.get_device_ip_by_device_identifier(
                "ip_address", ip_address
            )
            if not ip_address:
                self.log(
                    f"Failed to resolve IP address using IP address: {original_ip_address}",
                    "ERROR",
                )
                self.msg = (
                    f"Failed to retrieve device details using IP address: {original_ip_address}. "
                    "Please check if IP address is correct."
                )
                self.fail_and_exit(self.msg)
            else:
                self.log(
                    f"Successfully validated the IP address: {ip_address}", "DEBUG"
                )

        elif mac_address:
            self.log(
                f"{device_type.capitalize()} device management MAC address is provided: {mac_address}",
                "DEBUG",
            )
            self.log("Retrieving IP address using MAC address...", "DEBUG")
            ip_address = self.get_device_ip_by_device_identifier(
                "mac_address", mac_address
            )
            if not ip_address:
                self.log(
                    f"Failed to resolve IP address using MAC address: {mac_address}",
                    "ERROR",
                )
                self.msg = (
                    f"Failed to retrieve device details using MAC address: {mac_address}. "
                    "Please check if MAC address is correct."
                )
                self.fail_and_exit(self.msg)

            self.log(
                f"Successfully resolved IP address using MAC address {mac_address}: {ip_address}",
                "INFO",
            )
        else:
            self.msg = (
                f"None of 'management_ip_address', 'mac_address' or 'serial_number' "
                f"are provided for the {device_type} device. Atleast one of them is required."
            )
            self.fail_and_exit(self.msg)

        return ip_address

    def validate_port_channel_number(self, port_channel_config, idx, state):
        """
        Validate port channel number parameter based on state.
        Args:
            port_channel_config (dict): Port channel configuration
            idx (int): Configuration index for logging
            state (str): Current operation state
        Returns:
            int or None: Validated port channel number
        """
        self.log(
            f"Validating port channel number for configuration {idx} in state '{state}'",
            "DEBUG",
        )
        port_channel_number = port_channel_config.get("port_channel_number")

        if state == "merged":
            if not port_channel_number:
                self.log(
                    "Configuration {0}: No port_channel_number provided - new Port Channel will be "
                    "created if none exists between endpoints".format(idx),
                    "INFO",
                )
                return None

            self.log(
                "Configuration {0}: port_channel_number provided: {1} - will be used for "
                "updating existing Port Channel".format(idx, port_channel_number),
                "INFO",
            )
            return port_channel_number

        elif state == "deleted":
            if not port_channel_number:
                self.log(
                    "Configuration {0}: No port_channel_number provided - all Port Channels "
                    "between specified endpoints will be deleted".format(idx),
                    "INFO",
                )
                return None

            self.log(
                "Configuration {0}: port_channel_number provided: {1} - only specified "
                "Port Channel will be deleted".format(idx, port_channel_number),
                "INFO",
            )
            return port_channel_number

        return None

    def validate_port_channel_links(
        self, port_channel_config, idx, state, missing_params
    ):
        """
        Validate port channel links parameter based on state.
        Args:
            port_channel_config (dict): Port channel configuration
            idx (int): Configuration index for logging
            state (str): Current operation state
            missing_params (list): List to collect missing parameters
        Returns:
            list or None: Validated links configuration
        """

        self.log(
            f"Validating port channel links for configuration {idx} in state '{state}'",
            "DEBUG",
        )

        links = port_channel_config.get("links")

        if state == "merged":
            if not links:
                error_msg = (
                    "Configuration {0}: Missing links parameter for merged state - "
                    "at least one link must be specified".format(idx)
                )
                self.log(error_msg, "ERROR")
                missing_params.append(error_msg)
                return None
            else:
                self.log(
                    "Configuration {0}: Links provided for validation: {1}".format(
                        idx, len(links) if isinstance(links, list) else "invalid"
                    ),
                    "INFO",
                )

                # Validate links structure
                self.validate_links(links)
                return links

        elif state == "deleted":
            if not links:
                self.log(
                    "Configuration {0}: No links provided for deleted state - "
                    "all links will be targeted".format(idx),
                    "INFO",
                )
                return None
            else:
                self.log(
                    "Configuration {0}: Links provided for deletion: {1}".format(
                        idx, len(links) if isinstance(links, list) else "invalid"
                    ),
                    "INFO",
                )

                # Validate links structure
                self.validate_links(links)
                return links

        return None

    def _validate_and_resolve_source_device(
        self, port_channel_config, idx, missing_params
    ):
        """
        Validate and resolve source device IP address.
        Args:
            port_channel_config (dict): Port channel configuration
            idx (int): Configuration index for logging
            missing_params (list): List to collect missing parameters
        Returns:
            str or None: Resolved source device IP address
        """
        source_ip = port_channel_config.get("source_device_management_ip_address")
        source_mac = port_channel_config.get("source_device_management_mac_address")
        source_serial = port_channel_config.get(
            "source_device_management_serial_number"
        )

        if any([source_ip, source_mac, source_serial]):
            self.log(
                f"Configuration {idx}: Source device identifiers provided - resolving IP address",
                "DEBUG",
            )

            resolved_ip = self.resolve_device_ip(
                "source", source_serial, source_ip, source_mac
            )

            if resolved_ip:
                self.log(
                    f"Configuration {idx}: Successfully resolved source device IP: {resolved_ip}",
                    "INFO",
                )
                return resolved_ip
            else:
                error_msg = f"Configuration {idx}: Failed to resolve source device IP"
                self.log(error_msg, "ERROR")
                missing_params.append(error_msg)
                return None
        else:
            error_msg = (
                f"Configuration {idx}: Missing source device identifiers - at least one of "
                "'source_device_management_ip_address', 'source_device_management_mac_address' "
                "or 'source_device_management_serial_number' is required"
            )
            self.log(error_msg, "ERROR")
            missing_params.append(error_msg)
            return None

    def _validate_and_resolve_destination_device(
        self, port_channel_config, idx, state, missing_params
    ):
        """
        Validate and resolve destination device IP address based on state.
        Args:
            port_channel_config (dict): Port channel configuration
            idx (int): Configuration index for logging
            state (str): Current operation state
            missing_params (list): List to collect missing parameters
        Returns:
            str or None: Resolved destination device IP address
        """
        dest_ip = port_channel_config.get("destination_device_management_ip_address")
        dest_mac = port_channel_config.get("destination_device_mac_address")
        dest_serial = port_channel_config.get("destination_device_serial_number")

        has_destination_identifiers = any([dest_ip, dest_mac, dest_serial])

        if state == "merged":
            if has_destination_identifiers:
                self.log(
                    f"Configuration {idx}: Destination device identifiers provided - resolving IP address",
                    "DEBUG",
                )

                resolved_ip = self.resolve_device_ip(
                    "destination", dest_serial, dest_ip, dest_mac
                )

                if resolved_ip:
                    self.log(
                        f"Configuration {idx}: Successfully resolved destination device IP: {resolved_ip}",
                        "INFO",
                    )
                    return resolved_ip
                else:
                    error_msg = (
                        f"Configuration {idx}: Failed to resolve destination device IP"
                    )
                    self.log(error_msg, "ERROR")
                    missing_params.append(error_msg)
                    return None
            else:
                error_msg = (
                    f"Configuration {idx}: Missing destination device identifiers for merged state - "
                    f"at least one of 'destination_device_management_ip_address', "
                    f"'destination_device_mac_address' or 'destination_device_serial_number' "
                    f"is required"
                )
                self.log(error_msg, "ERROR")
                missing_params.append(error_msg)
                return None

        elif state == "deleted":
            if not has_destination_identifiers:
                self.log(
                    f"Configuration {idx}: No destination device identifiers provided for deleted state - "
                    f"all port channels from source device will be targeted",
                    "INFO",
                )
                return None
            else:
                self.log(
                    f"Configuration {idx}: Destination device identifiers provided - resolving IP address",
                    "DEBUG",
                )

                resolved_ip = self.resolve_device_ip(
                    "destination", dest_serial, dest_ip, dest_mac
                )

                if resolved_ip:
                    self.log(
                        f"Configuration {idx}: Successfully resolved destination device IP: {resolved_ip}",
                        "INFO",
                    )
                    return resolved_ip
                else:
                    error_msg = (
                        f"Configuration {idx}: Failed to resolve destination device IP"
                    )
                    self.log(error_msg, "ERROR")
                    missing_params.append(error_msg)
                    return None

        return None

    def validate_and_extract_port_channel_config_from_playbook(self, config):
        """
        Validate and extract port channel configurations from the playbook.

        Parameters:
            config (dict):
                The playbook configuration containing port channel information and
                device details.

        Returns:
            tuple[list[dict], list[str]]:
                - want_port_channel_configs (list[dict]):
                    A list of validated and resolved port channel configuration dictionaries.
                    Each dictionary may include:
                        - source_device_management_ip_address (str)
                        - destination_device_management_ip_address (str | None)
                        - port_channel_number (int | None)
                        - links (list[dict] | None)
                - missing_params (list[str]):
                    A list of parameters that were required but missing from the playbook config.
                    Examples:
                        - Missing source device identifiers
                        - Missing destination device identifiers (for merged state)
                        - Missing links (for merged state)

        Description:
            This method performs the following:
            - Iterates through port channel configurations defined in the playbook.
            - Resolves device IP addresses using serial number, IP, or MAC address for both
            source and destination devices.
            - Validates optional parameters such as `port_channel_number` and `links` according
            to the desired state ('merged' or 'deleted').
            - Generates INFO and DEBUG logs for every validation and resolution step.
            - Collects any missing required parameters into `missing_params`.
            - Returns a list of fully prepared port channel configurations along with any
            missing parameter information.
        """

        self.log(
            f"Validating and Extracting port channel configuration for the config: {self.pprint(config)}",
            "DEBUG",
        )
        port_channel_configs = config.get("port_channel")

        if not port_channel_configs:
            self.log("No port channel configuration provided in the playbook.", "INFO")
            return [], []

        if not isinstance(port_channel_configs, list):
            self.log(
                f"Invalid port_channel format - expected list, got: {type(port_channel_configs).__name__}",
                "ERROR",
            )
            return [], ["Invalid port_channel format - expected list"]

        self.log(
            f"Found {len(port_channel_configs)} port channel configurations to process",
            "INFO",
        )

        missing_params = []
        want_port_channel_configs = []
        state = self.params.get("state")

        self.log(f"Processing port channel configurations for state: {state}", "DEBUG")

        # Validate and collect port channel parameters
        for idx, port_channel_config in enumerate(port_channel_configs, start=1):
            self.log(
                f"[PortChannel {idx}] Processing playbook config: {self.pprint(port_channel_config)}",
                "DEBUG",
            )
            if not isinstance(port_channel_config, dict):
                error_msg = (
                    "Invalid port channel config at index {0} - expected dict".format(
                        idx
                    )
                )
                self.log(error_msg, "ERROR")
                missing_params.append(error_msg)
                continue

            want_port_channel_config = {}

            # Source end point validation, one of the device identifiers is required
            want_port_channel_config["source_device_management_ip_address"] = (
                self._validate_and_resolve_source_device(
                    port_channel_config, idx, missing_params
                )
            )

            # Destination end point validation, based on state as destination end points details are conditionally optional
            want_port_channel_config["destination_device_management_ip_address"] = (
                self._validate_and_resolve_destination_device(
                    port_channel_config, idx, state, missing_params
                )
            )

            #  optional parameter, validating according to state
            want_port_channel_config["port_channel_number"] = (
                self.validate_port_channel_number(port_channel_config, idx, state)
            )

            #  optional parameter, validating according to state
            want_port_channel_config["links"] = self.validate_port_channel_links(
                port_channel_config, idx, state, missing_params
            )

            want_port_channel_configs.append(want_port_channel_config)
            self.log(
                f"[PortChannel {idx}] Final extracted config: {self.pprint(want_port_channel_config)}",
                "DEBUG",
            )

        self.log(
            f"All extracted port channel configurations: {self.pprint(want_port_channel_configs)}",
            "INFO",
        )
        if missing_params:
            self.log(f"Missing required parameters: {missing_params}", "ERROR")

        return want_port_channel_configs, missing_params

    def validate_links(self, links):
        """
        Validate provided port channel links to ensure no duplicate source or destination ports.

        Parameters:
            links (list[dict]):
                A list of dictionaries, each containing:
                    - source_port (str): The source port of the link.
                    - destination_port (str): The destination port of the link.

        Returns:
            None:
                Raises an error via `fail_and_exit` if any source port is mapped to multiple
                destination ports, or any destination port is mapped to multiple source ports.

        Description:
            This method performs the following:
            - Iterates through each link in the provided list.
            - Ensures that each source port maps to only one destination port.
            - Ensures that each destination port maps to only one source port.
            - Logs DEBUG messages at the start and end of validation.
            - Raises an error and exits if duplicate mappings are detected.
        """

        self.log(
            f"Validating provided links for duplicate source or destination ports. Links: {self.pprint(links)}",
            "DEBUG",
        )

        source_to_destination_port_mapping = {}
        destination_to_source_port_mapping = {}

        for idx, link in enumerate(links, start=1):
            src = link.get("source_port")
            dst = link.get("destination_port")
            self.log(
                f"[Link {idx}] Checking mapping: source={src}, destination={dst}",
                "DEBUG",
            )

            if src not in source_to_destination_port_mapping:
                source_to_destination_port_mapping[src] = dst
                self.log(
                    f"[Link {idx}] Source port {src} mapped to destination {dst}",
                    "DEBUG",
                )
            else:
                self.msg = (
                    f"Link {idx}] Source port : {src} is mapped to multiple destination ports\n"
                    f"Destination Port 1: {source_to_destination_port_mapping[src]}, Destination Port 2: {dst}\n"
                    "A Source Port can only be mapped to a single Destination Port"
                )
                self.fail_and_exit(self.msg)

            if dst not in destination_to_source_port_mapping:
                destination_to_source_port_mapping[dst] = src
                self.log(
                    f"[Link {idx}] Destination port {dst} mapped to source {src}",
                    "DEBUG",
                )
            else:
                self.msg = (
                    f"Destination port : {dst} is mapped to multiple source ports\n"
                    f"Source Port 1: {destination_to_source_port_mapping[dst]}, Source Port 2: {src}\n"
                    "A Destination Port can only be mapped to a single Source Port"
                )
                self.fail_and_exit(self.msg)

        self.log(
            "No duplicate source or destination ports found in the provided links.",
            "DEBUG",
        )
        return

    def get_want(self, config):
        """
        Collects and validates the desired state of LAN automation, device updates, and port channel configurations
        based on the provided configuration.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A configuration dictionary containing details about LAN automation sessions, device
            updates, and port channel configurations.

        Returns:
            self (object): The instance of the class with the updated `want` attribute containing the validated desired
            state of LAN automation, device update processes, and port channel configurations.

        Description:
            This function processes the given configuration to gather and validate details about:
            - LAN Automation: It collects information on LAN automation sessions, ensuring that all required parameters
                            such as IP pools, management IP addresses, and discovery devices are provided and valid.
            - Device Updates: It checks the configuration for details about devices that require updates, such as
                            hostname updates, loopback interfaces, and link configurations, validating the provided
                            IP addresses and device roles.
            - Port Channels: It validates and extracts port channel configurations from the playbook, resolving source
                            and destination device IP addresses, port channel numbers, and links. Ensures that all
                            required parameters are present according to the desired state ('merged' or 'deleted').
            If any required parameters are missing or invalid, the function logs an error message and updates the
            status accordingly. On successful collection of all parameters, it logs the desired state and sets the
            status to success.
        """

        want = {}
        missing_params = []
        state = self.params.get("state")

        if state == "merged":
            want["lan_automation"], lan_auto_missing_params = (
                self.extract_lan_automation(config)
            )
            missing_params.extend(lan_auto_missing_params)

            want["lan_automated_device_update"], lan_auto_device_missing_params = (
                self.extract_lan_automated_device_update(config)
            )
            missing_params.extend(lan_auto_device_missing_params)

        elif state == "deleted":
            want["lan_automation"], lan_auto_missing_params = (
                self.extract_lan_automation(config)
            )
            missing_params.extend(lan_auto_missing_params)

        want["port_channel"], port_channel_missing_params = (
            self.validate_and_extract_port_channel_config_from_playbook(config)
        )
        missing_params.extend(port_channel_missing_params)

        if missing_params:
            self.msg = (
                "The following required parameters are missing or invalid: "
                + ", ".join(missing_params)
            )
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        want = self.update_dict_keys_to_camel_case(want)
        self.want = want
        self.msg = "Successfully collected all parameters from playbook for comparison"
        self.log(f"Desired State (want): {self.pprint(self.want)}", "INFO")
        self.status = "success"
        return self

    def snake_to_camel(self, snake_str):
        """
        Converts a string from snake_case to camelCase.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            snake_str (str): A string in snake_case format to be converted.
        Returns:
            str: The input string converted to camelCase.
        Description:
            This function processes the input snake_case string by splitting it at underscores ('_')
            and capitalizing each word (except the first one), then concatenates them into camelCase format.
        """
        components = snake_str.split("_")
        return components[0] + "".join(x.title() for x in components[1:])

    def update_dict_keys_to_camel_case(self, input_data):
        """
        Recursively updates dictionary keys from snake_case to camelCase while preserving specific keys.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            input_data (dict or list): A dictionary or list containing keys in snake_case format.
        Returns:
            dict or list: The dictionary or list with updated keys converted to camelCase, except for certain
                          preserved keys ('lan_automation', 'lan_automated_device_update').
        Description:
            This function traverses the input dictionary or list, converting all keys from snake_case to camelCase,
            except for the keys specified in `keys_to_preserve`. It also supports special mappings for certain
            keys where predefined camelCase strings are used instead of the default conversion.
        """

        keys_to_preserve = [
            "lan_automation",
            "lan_automated_device_update",
            "port_channel",
        ]

        specific_key_mappings = {
            "primary_device_management_ip_address": "primaryDeviceManagmentIPAddress",
            "peer_device_management_ip_address": "peerDeviceManagmentIPAddress",
            "device_management_ip_address": "deviceManagementIPAddress",
            "new_loopback0_ip_address": "newLoopback0IPAddress",
            "source_device_management_ip_address": "sourceDeviceManagementIPAddress",
            "destination_device_management_ip_address": "destinationDeviceManagementIPAddress",
        }

        if isinstance(input_data, dict):
            updated_dict = {}
            for key, value in input_data.items():
                if key in keys_to_preserve:
                    updated_key = key
                elif key in specific_key_mappings:
                    updated_key = specific_key_mappings[key]
                else:
                    updated_key = self.snake_to_camel(key)

                updated_dict[updated_key] = self.update_dict_keys_to_camel_case(value)
            return updated_dict

        elif isinstance(input_data, list):
            return [self.update_dict_keys_to_camel_case(item) for item in input_data]

        else:
            return input_data

    def extract_lan_automation(self, config):
        """
        Extracts and validates the 'lan_automation' section from the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A configuration dictionary containing the 'lan_automation' details.
        Returns:
            dict: The extracted 'lan_automation' configuration if valid.
            list: A list of missing parameters, if any are found.
        Description:
            This function extracts the 'lan_automation' section from the provided configuration dictionary. It ensures
            that required parameters such as IP pools, device management IP addresses, and discovery devices are present
            and valid. The function validates both 'merged' and 'deleted' states, checking site hierarchies and IP
            addresses. In case of any missing or invalid parameters, the function logs errors and updates the response
            accordingly.
        """

        lan_automation = config.get("lan_automation")
        missing_params = []

        if not isinstance(lan_automation, dict):
            self.log(
                "lan_automation is not a dict, but a {}".format(type(lan_automation))
            )
            return None, missing_params

        state = self.params.get("state")
        self.log("Processing 'lan_automation' for state: {}".format(state), "DEBUG")

        if state == "deleted":
            self.validate_ipv4_ip(
                lan_automation.get("primary_device_management_ip_address"),
                "lan_automation -> primary_device_management_ip_address",
                missing_params,
            )
            self.log(
                "Validated primary_device_management_ip_address for deletion", "INFO"
            )
            return lan_automation, missing_params

        if state == "merged":
            discovered_site_name = lan_automation.get(
                "discovered_device_site_name_hierarchy"
            )
            if not discovered_site_name:
                missing_params.append(
                    "lan_automation -> discovered_device_site_name_hierarchy"
                )
                self.log(
                    "Missing parameter: lan_automation -> discovered_device_site_name_hierarchy",
                    "ERROR",
                )
            else:
                self.log(
                    "Validating discovered site name: {}".format(discovered_site_name),
                    "INFO",
                )
                if not self.get_site_details(discovered_site_name):
                    self.fail_with_error(
                        'Invalid site "{}". Please provide a valid site!'.format(
                            discovered_site_name
                        )
                    )
                else:
                    self.log(
                        "Discovered site name '{}' exists and is valid.".format(
                            discovered_site_name
                        ),
                        "DEBUG",
                    )

            primary_device_ip = lan_automation.get(
                "primary_device_management_ip_address"
            )
            self.log(
                "Validating primary device management IP address: {}".format(
                    primary_device_ip
                ),
                "INFO",
            )
            self.validate_ipv4_ip(
                primary_device_ip,
                "lan_automation -> primary_device_management_ip_address",
                missing_params,
            )
            if not self.get_ip_details(
                primary_device_ip,
                "lan_automation -> primary_device_management_ip_address",
            ):
                self.module.fail_json(
                    msg="IP address: {} does not exist in Catalyst Center. Please provide a valid IP address for "
                    "'lan_automation -> primary_device_management_ip_address'!".format(
                        primary_device_ip
                    ),
                    response=[],
                )
            self.log(
                "Primary device management IP address '{}' is valid.".format(
                    primary_device_ip
                ),
                "DEBUG",
            )

            peer_device_ip = lan_automation.get("peer_device_management_ip_address")
            if peer_device_ip:
                self.log(
                    "Validating peer device management IP address: {}".format(
                        peer_device_ip
                    ),
                    "INFO",
                )
                self.validate_ipv4_ip(
                    peer_device_ip,
                    "lan_automation -> peer_device_management_ip_address",
                    missing_params,
                )
                if not self.get_ip_details(
                    peer_device_ip,
                    "lan_automation -> peer_device_management_ip_address",
                ):
                    self.module.fail_json(
                        msg="IP address: {} does not exist in Catalyst Center. Please provide a valid IP address for "
                        "'lan_automation -> peer_device_management_ip_address'!".format(
                            peer_device_ip
                        ),
                        response=[],
                    )
                self.log(
                    "Validate peer device management IP address is not the same as primary device IP",
                    "INFO",
                )
                if primary_device_ip == peer_device_ip:
                    self.module.fail_json(
                        msg="The primary device management IP address '{}' cannot be the same as the peer device IP "
                        "address '{}'.".format(primary_device_ip, peer_device_ip),
                        response=[],
                    )
                self.log(
                    "Peer device management IP address '{}' is valid.".format(
                        peer_device_ip
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "Peer device IP not provided. Skipping peer device checks.", "INFO"
                )

            primary_device_interfaces = lan_automation.get(
                "primary_device_interface_names"
            )
            if not primary_device_interfaces:
                missing_params.append(
                    "lan_automation -> primary_device_interface_names"
                )
                self.log(
                    "Missing parameter: lan_automation -> primary_device_interface_names",
                    "ERROR",
                )
            else:
                self.log(
                    "Primary device interface names provided: {}".format(
                        primary_device_interfaces
                    ),
                    "DEBUG",
                )

            self.validate_ip_pools(lan_automation.get("ip_pools"), missing_params)
            self.log("Validating discovery devices.", "INFO")
            self.validate_discovery_devices(
                lan_automation.get("discovery_devices"), missing_params
            )
            self.log("Completed validation of lan_automation parameters.", "INFO")
            self.log(
                "Validate launch_and_wait, pnp_authorization and if not provided set default to False.",
                "INFO",
            )
            launch_and_wait = lan_automation.get("launch_and_wait")
            if not isinstance(launch_and_wait, bool):
                self.log(
                    "Invalid value for 'launch_and_wait': {}. Defaulting to 'false'.".format(
                        launch_and_wait
                    ),
                    "WARNING",
                )
                launch_and_wait = False  # Default to False
            lan_automation["launch_and_wait"] = launch_and_wait

            self.log("'launch_and_wait' set to: {}".format(launch_and_wait), "INFO")

            pnp_authorization = lan_automation.get("pnp_authorization")
            if not isinstance(pnp_authorization, bool):
                self.log(
                    "Invalid value for 'pnp_authorization': {}. Defaulting to 'false'.".format(
                        pnp_authorization
                    ),
                    "WARNING",
                )
                pnp_authorization = False
            lan_automation["pnp_authorization"] = pnp_authorization

            self.log("'pnp_authorization' set to: {}".format(pnp_authorization), "INFO")

        return lan_automation, missing_params

    def extract_lan_automated_device_update(self, config):
        """
        Extracts and validates the 'lan_automated_device_update' section from the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A configuration dictionary containing the 'lan_automated_device_update' details.
        Returns:
            dict: The extracted 'lan_automated_device_update' configuration if valid.
            list: A list of missing parameters, if any are found.
        Description:
            This function extracts the 'lan_automated_device_update' section from the configuration and validates the
            details for various updates such as loopback updates, hostname updates, and link configurations (link_add
            and link_delete). It checks for the presence and validity of device lists and IP addresses, logging any
            errors if parameters are missing or invalid.
        """

        missing_params = []
        update_device = config.get("lan_automated_device_update")

        if not isinstance(update_device, dict):
            self.log(
                "lan_automated_device_update is not a dict, but a {}".format(
                    type(update_device)
                ),
                "ERROR",
            )
            return None, missing_params

        loopback_devices = update_device.get("loopback_update_device_list")
        self.log(
            "Starting validation of loopback update devices: {}".format(
                loopback_devices
            ),
            "DEBUG",
        )
        self.validate_device_list(loopback_devices, missing_params)

        hostname_devices = update_device.get("hostname_update_devices")
        self.log(
            "Starting validation of hostname update devices: {}".format(
                hostname_devices
            ),
            "DEBUG",
        )
        self.validate_hostname_update_devices(hostname_devices, missing_params)

        link_add = update_device.get("link_add")
        self.log(
            "Starting validation of link_add configurations: {}".format(link_add),
            "DEBUG",
        )
        self.validate_link_update(link_add, "link_add", missing_params)

        link_delete = update_device.get("link_delete")
        self.log(
            "Starting validation of link_delete configurations: {}".format(link_delete),
            "DEBUG",
        )
        self.validate_link_update(link_delete, "link_delete", missing_params)

        self.log(
            "Completed validation of lan_automated_device_update parameters.", "DEBUG"
        )
        return update_device, missing_params

    def validate_ip_pools(self, ip_pools, missing_params):
        """
        Validates the 'ip_pools' section within the LAN automation configuration.
        Args:
            self (object): An instance of the class used for LAN automation validation.
            ip_pools (list): A list of dictionaries representing IP pools.
            missing_params (list): A list to accumulate any missing or invalid parameters found during validation.
        Returns:
            None: This method updates the 'missing_params' list in case of missing or invalid entries.
        Description:
            - This function checks whether the 'ip_pools' section contains valid information. It verifies:
                - If the list is empty, it adds an error message for 'ip_pools'.
                - Each IP pool must include 'ip_pool_name', and if missing, an error is logged.
                - The 'ip_pool_role' is validated and converted to uppercase. If the value is not 'MAIN_POOL' or
                  'PHYSICAL_LINK_POOL', an error message is appended to the list.
        """

        if not ip_pools:
            self.log(
                "IP pools list is empty. Adding 'lan_automation -> ip_pools' to missing parameters.",
                "ERROR",
            )
            missing_params.append("lan_automation -> ip_pools")
            return

        self.log("Starting validation of IP pools: {}".format(ip_pools), "DEBUG")

        for index, pool in enumerate(ip_pools):
            if not pool.get("ip_pool_name"):
                self.log(
                    "IP pool at index {} is missing 'ip_pool_name'.".format(index),
                    "ERROR",
                )
                missing_params.append(
                    "lan_automation -> ip_pools[{}] -> ip_pool_name".format(index)
                )

            ip_pool_role = pool.get("ip_pool_role")
            if not ip_pool_role:
                self.log(
                    "IP pool at index {} is missing 'ip_pool_role'.".format(index),
                    "ERROR",
                )
                missing_params.append(
                    "lan_automation -> ip_pools[{}] -> ip_pool_role".format(index)
                )
                continue

            ip_pool_role = ip_pool_role.upper()
            if ip_pool_role not in ["MAIN_POOL", "PHYSICAL_LINK_POOL"]:
                self.log(
                    "Invalid IP pool role '{}' at index {}. Must be 'MAIN_POOL' or 'PHYSICAL_LINK_POOL'.".format(
                        ip_pool_role, index
                    ),
                    "ERROR",
                )
                missing_params.append(
                    "lan_automation -> ip_pools[{}] -> ip_pool_role (must be either 'MAIN_POOL' or 'PHYSICAL_LINK_POOL')".format(
                        index
                    )
                )
                continue

            self.log(
                "IP pool role '{}' at index {} validated and set.".format(
                    ip_pool_role, index
                ),
                "INFO",
            )
            pool["ip_pool_role"] = ip_pool_role

        return

    def validate_discovery_devices(self, discovery_devices, missing_params):
        """
        Validates the 'discovery_devices' section within the LAN automation configuration.
        Args:
            self (object): An instance of the class used for LAN automation validation.
            discovery_devices (list): A list of dictionaries representing discovery devices.
            missing_params (list): A list to accumulate any missing or invalid parameters found during validation.
        Returns:
            None: This method updates the 'missing_params' list in case of missing or invalid entries.
        Description:
            - The function checks the presence of 'device_serial_number' for each device in the discovery devices list.
            - It validates the 'device_site_name_hierarchy' if provided, ensuring the site exists. If the site is
              invalid, it raises an error and halts execution.
        """
        if discovery_devices is None:
            self.log(
                "No discovery devices found. Skipping validation for 'discovery_devices'.",
                "INFO",
            )
            return

        for j, device in enumerate(discovery_devices):
            if device is None:
                self.log(
                    "Invalid device entry at index {}. Device cannot be 'None'.".format(
                        j
                    ),
                    "ERROR",
                )
                self.fail_with_error(
                    "'discovery_devices[{}]' cannot be 'None'. Provide a valid device entry.".format(
                        j
                    )
                )
                return

            self.log("Validating device at index {}: {}".format(j, device), "DEBUG")
            if not device.get("device_serial_number"):
                self.log(
                    "Discovery device at index {} is missing 'device_serial_number'.".format(
                        j
                    ),
                    "ERROR",
                )
                missing_params.append(
                    "lan_automation -> discovery_devices[{}] -> device_serial_number (required if "
                    "discovery_devices is provided)".format(j)
                )

            site_name = device.get("device_site_name_hierarchy")
            if site_name:
                self.log(
                    "Validating site name hierarchy '{}' for device at index {}.".format(
                        site_name, j
                    ),
                    "DEBUG",
                )
                if not self.get_site_details(site_name):
                    self.fail_with_error(
                        'Invalid site "{}" for device at index {}. Please provide a valid site!'.format(
                            site_name, j
                        )
                    )
                else:
                    self.log(
                        "Site name hierarchy '{}' validated successfully for device at index {}.".format(
                            site_name, j
                        ),
                        "DEBUG",
                    )

    def validate_device_list(self, device_list, missing_params):
        """
        Validates device lists such as 'loopback_update_device_list'.
        Args:
            self (object): An instance of the class used for LAN automation validation.
            device_list (list): A list of dictionaries representing devices to validate.
            missing_params (list): A list to accumulate any missing or invalid parameters found during validation.
        Returns:
            None: This method updates the 'missing_params' list in case of missing or invalid entries.
        Description:
            - For each device, the function validates the 'device_management_ip_address' and 'new_loopback0_ip_address'.
            - It checks if the provided IP addresses exist in the system. If not, it raises an error and stops.
            - Missing or invalid parameters are appended to the 'missing_params' list.
        """
        if not device_list:
            self.log(
                "No devices to validate in device_list. Skipping validation.", "ERROR"
            )
            return

        self.log(
            "Starting validation of devices in device list: {}".format(device_list),
            "DEBUG",
        )

        for j, device in enumerate(device_list):
            if not isinstance(device, dict):
                self.log(
                    "Expected a dictionary at index {}, but got: {}".format(
                        j, type(device)
                    ),
                    "ERROR",
                )
                self.fail_with_error(
                    "Invalid data type for loopback_update_device_list at index {}: expected a dictionary, got {}".format(
                        j, type(device)
                    )
                )
            management_ip = device.get("device_management_ip_address")
            if not management_ip:
                self.log(
                    "Device at index {} missing 'device_management_ip_address'.".format(
                        j
                    ),
                    "ERROR",
                )
                missing_params.append(
                    "loopback_update_device_list[{}] -> device_management_ip_address".format(
                        j
                    )
                )
            else:
                self.validate_ipv4_ip(
                    management_ip,
                    "loopback_update_device_list -> device_management_ip_address",
                    missing_params,
                )
                if not self.get_ip_details(
                    management_ip,
                    "loopback_update_devices -> device_management_ip_address",
                ):
                    self.fail_with_error(
                        "IP address '{}' does not exist in Catalyst Center. "
                        "Please provide a valid IP address for 'loopback_update_devices -> "
                        "device_management_ip_address'.".format(management_ip)
                    )

            loopback_ip = device.get("new_loopback0_ip_address")
            if not loopback_ip:
                self.log(
                    "Device at index {} missing 'new_loopback0_ip_address'.".format(j),
                    "ERROR",
                )
                missing_params.append(
                    "lan_automated_device_update -> loopback_update_device_list[{}] -> new_loopback0_ip_address".format(
                        j
                    )
                )
            else:
                self.validate_ipv4_ip(
                    loopback_ip,
                    "loopback_update_device_list -> new_loopback0_ip_address",
                    missing_params,
                )

            self.log(
                "Device at index {} validated with management IP '{}' and loopback IP '{}'.".format(
                    j, management_ip, loopback_ip
                ),
                "INFO",
            )

    def validate_hostname_update_devices(self, hostname_update_devices, missing_params):
        """
        Validates the 'hostname_update_devices' section within the LAN automation configuration.
        Args:
            self (object): An instance of the class used for LAN automation validation.
            hostname_update_devices (list): A list of dictionaries representing devices for hostname updates.
            missing_params (list): A list to accumulate any missing or invalid parameters found during validation.
        Returns:
            None: This method updates the 'missing_params' list in case of missing or invalid entries.
        Description:
            - The function validates the 'device_management_ip_address' and 'new_host_name' for each device.
            - If the provided IP address does not exist in the system, an error is raised.
            - Missing parameters are added to the 'missing_params' list.
        """
        if not hostname_update_devices:
            self.log(
                "No hostname update devices to validate. Skipping validation.", "INFO"
            )
            return

        self.log(
            "Starting validation of hostname update devices: {}".format(
                hostname_update_devices
            ),
            "INFO",
        )
        for j, device in enumerate(hostname_update_devices):
            if not isinstance(device, dict):
                self.log(
                    "Expected a dictionary at index {}, but got: {}".format(
                        j, type(device)
                    ),
                    "ERROR",
                )
                self.fail_with_error(
                    "Invalid data type for hostname_update_devices at index {}: expected a dictionary, got {}".format(
                        j, type(device)
                    )
                )

            management_ip = device.get("device_management_ip_address")
            self.validate_ipv4_ip(
                management_ip,
                "hostname_update_devices -> device_management_ip_address",
                missing_params,
            )

            if not self.get_ip_details(
                management_ip, "hostname_update_devices -> device_management_ip_address"
            ):
                self.log(
                    "Invalid or non-existent IP address: {} in device at index {}.".format(
                        management_ip, j
                    ),
                    "ERROR",
                )
                self.module.fail_json(
                    msg="IP address: {} does not exist in Catalyst Center. Please provide a valid IP address for "
                    "'hostname_update_devices -> device_management_ip_address'.".format(
                        management_ip
                    ),
                    response=[],
                )

            new_host_name = device.get("new_host_name")
            if not new_host_name:
                self.log(
                    "Device at index {} is missing 'new_host_name'.".format(j), "ERROR"
                )
                missing_params.append(
                    "lan_automated_device_update -> hostname_update_devices[{}] -> new_host_name".format(
                        j
                    )
                )
            else:
                self.log(
                    "Device at index {} has management IP '{}' and new hostname '{}'.".format(
                        j, management_ip, new_host_name
                    ),
                    "INFO",
                )

    def validate_link_update(self, link_update_dict, link_name, missing_params):
        """
        Validates 'link_add' and 'link_delete' sections within the LAN automation configuration.
        Args:
            self (object): An instance of the class used for LAN automation validation.
            link_update_dict (dict): A dictionary representing link updates.
            link_name (str): Name of the link update, either 'link_add' or 'link_delete'.
            missing_params (list): A list to accumulate any missing or invalid parameters found during validation.
        Returns:
            None: This method updates the 'missing_params' list in case of missing or invalid entries.
        Description:
            - The function validates IP addresses, interface names, and 'ip_pool_name' for link updates.
            - If any of these parameters are missing, an error is logged.
            - In the case of 'link_add', the 'ip_pool_name' must also be provided.
        """
        if not link_update_dict:
            self.log(
                "{0} dictionary is empty. Skipping validation.".format(link_name),
                "INFO",
            )
            return

        if not isinstance(link_update_dict, dict):
            self.fail_with_error(
                "Expected a dict for {0}, but got {1}".format(
                    link_name, type(link_update_dict).__name__
                )
            )
            return

        self.log(
            "Starting validation for {0}: {1}".format(link_name, link_update_dict),
            "INFO",
        )
        source_ip = link_update_dict.get("source_device_management_ip_address")
        self.validate_ipv4_ip(
            source_ip,
            "{0} -> source_device_management_ip_address".format(link_name),
            missing_params,
        )

        source_interface_name = link_update_dict.get("source_device_interface_name")
        if not source_interface_name:
            self.log(
                "{0} is missing 'source_device_interface_name'.".format(link_name),
                "ERROR",
            )
            missing_params.append(
                "lan_automated_device_update -> {0} -> source_device_interface_name".format(
                    link_name
                )
            )
        # Validate Destination Device Management IP Address
        destination_ip = link_update_dict.get(
            "destination_device_management_ip_address"
        )
        self.validate_ipv4_ip(
            destination_ip,
            "{0} -> destination_device_management_ip_address".format(link_name),
            missing_params,
        )

        if not link_update_dict.get("destination_device_interface_name"):
            self.log(
                "{0} is missing 'destination_device_interface_name'.".format(link_name),
                "ERROR",
            )
            missing_params.append(
                "lan_automated_device_update -> {0} -> destination_device_interface_name".format(
                    link_name
                )
            )
        if link_name == "link_add" and not link_update_dict.get("ip_pool_name"):
            self.log(
                "{0} requires 'ip_pool_name', but it is missing.".format(link_name),
                "ERROR",
            )
            missing_params.append(
                "lan_automated_device_update -> {0} -> ip_pool_name (missing)".format(
                    link_name
                )
            )

    def validate_ipv4_ip(self, ip_address, field_name, missing_params=None):
        """
        Validate a single IP address.
        Args:
            ip_address (str): The IP address to validate.
            field_name (str): The name of the IP field being validated.
            missing_params (list, optional): Accumulator for missing parameters.
        Description:
            This method checks if the provided IP address is valid. If the IP address is not
            provided, it adds a message indicating the field is missing to the `missing_params`
            list if it is not None. If the IP address is invalid, it raises an error with a message
            specifying the field name and the invalid IP address.
        """
        if not ip_address:
            if missing_params is not None:
                missing_params.append("{0} (missing)".format(field_name))
        elif not self.is_valid_ipv4(ip_address):
            self.fail_with_error(
                "Invalid IP address for {0}: {1}. Please provide a valid IP address!".format(
                    field_name, ip_address
                )
            )

    def get_device_id(self, device_ip):
        """
        Fetches the device ID for a given management IP address from the API response.
        Parameters:
            device_ip (str): The management IP address of the device.
        Returns:
            str or None: The device ID if found, otherwise None.
        Description:
            This method retrieves the device ID associated with the provided management IP address
            by making a call to the API. If an error occurs during the API call or if no device
            is found, it logs an appropriate message and returns None. If the device is found,
            it logs the device ID and returns it.
        """

        try:
            response = self.dnac_apply["exec"](
                family="devices",
                function="get_device_list",
                params={"management_ip_address": device_ip},
                op_modifies=False,
            )
        except Exception as e:
            self.log(
                "Error fetching device ID for {0}: {1}".format(device_ip, str(e)),
                "ERROR",
            )
            return None

        if not response or "response" not in response:
            self.log("No device found for {0}".format(device_ip), "INFO")
            return None

        device_list = response.get("response", [])
        if device_list and len(device_list) > 0:
            device_id = device_list[0].get("id")
            self.log("Device ID for {0} is {1}".format(device_ip, device_id), "INFO")
            return device_id
        else:
            self.log("No device ID found for {0}".format(device_ip), "INFO")
            return None

    def check_link_details(self, source_device_ip, interface_name):
        """
        Check if the link details are valid by verifying the IPv4, IS-IS Support, and address fields
        from the API response.
        Args:
            source_device_ip (str): IP address of the source device.
            interface_name (str): Interface name of the source device.
        Returns:
            bool: True if the link details are valid, False otherwise.
        Description:
            This method checks the validity of the link details for a specified source device and
            interface by fetching the interface details from the API. It validates that the IPv4
            address is present, IS-IS support is enabled, and that the address list is not empty.
            It logs messages indicating the validity of the link details and returns a boolean value
            indicating whether the link details are valid.
        """
        device_id = self.get_device_id(source_device_ip)

        if device_id is None:
            self.log("Device ID not found for {0}.".format(source_device_ip), "WARNING")
            return False

        try:
            response = self.dnac_apply["exec"](
                family="devices",
                function="get_interface_details",
                params={"device_id": device_id, "name": interface_name},
                op_modifies=False,
            )
        except Exception as e:
            self.log(
                "Error fetching link details for {0} on {1}: {2}".format(
                    source_device_ip, interface_name, str(e)
                ),
                "ERROR",
            )
            return False

        if not response or "response" not in response:
            self.log(
                "No response received for {0} on {1}".format(
                    source_device_ip, interface_name
                ),
                "INFO",
            )
            return False

        self.log("Received response from 'get_interface_details'{}".format(response))
        interface_details = response.get("response", {})
        ipv4_address = interface_details.get("ipv4Address")
        isis_support = interface_details.get("isisSupport", "false")
        address_list = interface_details.get("addresses", [])

        self.log("Interface Details: {0}".format(interface_details), "DEBUG")
        self.log("IPv4 Address: {0}".format(ipv4_address), "DEBUG")
        self.log("IS-IS Support: {0}".format(isis_support), "DEBUG")
        self.log("Address List: {0}".format(address_list), "DEBUG")

        if ipv4_address and isis_support != "false" and address_list:
            self.log(
                "Valid link details for {0} on {1}".format(
                    source_device_ip, interface_name
                ),
                "INFO",
            )
            return True
        else:
            self.log(
                "Invalid link details for {0} on {1}".format(
                    source_device_ip, interface_name
                ),
                "INFO",
            )
            return False

    def fail_with_error(self, error_message):
        """
        Log an error and raise a failure.
        Args:
            error_message (str): The error message to log and raise.
        Description:
            This method logs the provided error message and raises a failure in the module,
            stopping further execution with the error message returned in the response.
        """
        self.log(error_message, "ERROR")
        self.module.fail_json(msg=error_message, response=[])

    def _build_port_channel_messages(self, items, template, result_msg_list):
        """
        Helper function to format port channel messages and append them to the result list.

        Parameters:
            items (list): List of port channel dictionaries containing source, destination, and links.
            template (str): Message template to format the result string.
            result_msg_list (list): The list to which formatted messages will be appended.

        Returns:
            None

        Description:
            Iterates over the provided list of port channels, extracts the source IP,
            destination IP, and associated links, and formats them into a message using
            the given template. The formatted message is appended to the result list.
        """

        for port_channel in items:
            source_device_ip = port_channel.get("sourceDeviceManagementIPAddress")
            destination_device_ip = port_channel.get(
                "destinationDeviceManagementIPAddress"
            )
            links = port_channel.get("links", [])
            msg = template.format(
                source=source_device_ip,
                destination=destination_device_ip,
                links=self.pprint(links),
            )
            result_msg_list.append(msg)
            self.log(f"Appended message: {msg}", "DEBUG")

    def build_port_channel_result_messages(self):
        """
        Build and return result messages for all port channel operations.

        Parameters:
            None

        Returns:
            list: A list of formatted messages summarizing port channel operations.

        Description:
            This method consolidates messages for port channel creation, deletion,
            link addition, and link removal operations. It uses a mapping of
            instance attributes to predefined message templates. For each attribute
            that contains results, it delegates message construction to the helper
            function `_build_port_channel_messages`.
        """
        message_map = {
            "port_channel_created": (
                "Port channel created successfully between source device '{source}' "
                "and destination device '{destination}' with links: {links}."
            ),
            "port_channel_deleted": (
                "Port channel deleted successfully between source device '{source}' "
                "and destination device '{destination}' with links: {links}."
            ),
            "no_port_channel_deleted": (
                "No port channel found to delete between source device '{source}' "
                "and destination device '{destination}' with links: {links}. No update needed."
            ),
            "link_added_to_port_channel": (
                "Links added successfully to the port channel between source device '{source}' "
                "and destination device '{destination}'. Added links: {links}."
            ),
            "link_not_added_to_port_channel": (
                "Links were not added to the port channel between source device '{source}' "
                "and destination device '{destination}' as they already exist. Links: {links}."
            ),
            "link_removed_from_port_channel": (
                "Links removed successfully from the port channel between source device '{source}' "
                "and destination device '{destination}'. Removed links: {links}."
            ),
            "link_not_removed_from_port_channel": (
                "Links were not removed from the port channel between source device '{source}' "
                "and destination device '{destination}' as they do not exist. Links: {links}."
            ),
        }

        result_msg_list = []
        self.log("Building result messages for port channel operations", "INFO")

        for attr, template in message_map.items():
            items = getattr(self, attr, [])
            if items:
                self.log(
                    f"Processing attribute: {attr} with {len(items)} items", "DEBUG"
                )
                self._build_port_channel_messages(items, template, result_msg_list)

        self.log(
            f"Completed building result messages for port channel operations. Total messages: {len(result_msg_list)}",
            "INFO",
        )
        return result_msg_list

    def update_lan_auto_messages(self):
        """
        Updates and logs messages based on the status of LAN automation start, completion, stop,
        and loopbacks, hostnames, links updates, and port channel operations.

        Returns:
            self (object): Returns the current instance of the class with updated `result` and `msg` attributes.

        Description:
            This method compiles status messages related to various aspects of LAN automation, including:
            - LAN Automation Sessions: start, completion, and stop statuses.
            - Loopbacks and Hostnames: updates applied or not needed.
            - Links: added, deleted, or no action needed for device links.
            - Port Channels: creation, deletion, link addition or removal, and no-action-needed scenarios.

            For each of these categories, the method checks the corresponding status flags, constructs messages,
            logs them, and appends them to a result message list. The `result` attribute is updated to indicate
            whether any changes occurred during the automation process. Finally, the messages are compiled
            into `self.msg` and logged with the operation result.
        """

        self.result["changed"] = False
        result_msg_list = []
        if self.started_lan_automation:
            result_msg_list.append(
                "LAN automation session started successfully for the following: {0}".format(
                    self.started_lan_automation
                )
            )

        if self.no_lan_auto_start:
            result_msg_list.append(
                "A LAN Automation session is already running with the following seed IP: {0}. Hence, no update needed".format(
                    self.no_lan_auto_start
                )
            )

        if self.completed_lan_automation:
            result_msg_list.append(
                "LAN automation session completed successfully for the following: {0}".format(
                    self.completed_lan_automation
                )
            )

        if self.stopped_lan_automation:
            result_msg_list.append(
                "LAN automation session stopped successfully for the following: {0}".format(
                    self.stopped_lan_automation
                )
            )

        if self.no_lan_auto_stop:
            result_msg_list.append(
                "No active LAN automation session with following seed IP found: {0}".format(
                    self.no_lan_auto_stop
                )
            )

        if self.updated_loopback:
            update_loopback_msg = "Provided loopback IP Addresses were updated successfully in Cisco Catalyst Center."
            result_msg_list.append(update_loopback_msg)

        if self.no_loopback_updated:
            no_loopback_update_msg = (
                "Provided loopback IP Addresses {} do not need any update in Cisco Catalyst "
                "Center.".format(self.no_loopback_updated)
            )
            result_msg_list.append(no_loopback_update_msg)

        if self.updated_hostname:
            update_hostname_msg = "Provided hostname(s) were updated successfully in Cisco Catalyst Center."
            result_msg_list.append(update_hostname_msg)

        if self.no_hostname_updated:
            no_hostname_update_msg = "Provided hostname(s) {} did not need an update in Cisco Catalyst Center.".format(
                self.no_hostname_updated
            )
            result_msg_list.append(no_hostname_update_msg)

        if self.added_link:
            added_link_msg = (
                "Provided links were added successfully in Cisco Catalyst Center."
            )
            result_msg_list.append(added_link_msg)

        if self.no_link_added:
            no_link_added_msg = (
                "Provided links {} were not added in Cisco Catalyst Center as links for the devices "
                "already exist.".format(self.no_link_added)
            )
            result_msg_list.append(no_link_added_msg)

        if self.deleted_link:
            delete_link_msg = (
                "Provided links were deleted successfully from Cisco Catalyst Center."
            )
            result_msg_list.append(delete_link_msg)

        if self.no_link_deleted:
            no_link_deleted_msg = "Provided links {} did not need any deletion from Cisco Catalyst Center."
            result_msg_list.append(no_link_deleted_msg)

        port_channel_msgs = self.build_port_channel_result_messages()
        result_msg_list.extend(port_channel_msgs)

        if (
            self.updated_loopback
            or self.updated_hostname
            or self.added_link
            or self.deleted_link
            or self.started_lan_automation
            or self.completed_lan_automation
            or self.stopped_lan_automation
            or self.port_channel_created
            or self.port_channel_deleted
            or self.link_added_to_port_channel
            or self.link_removed_from_port_channel
        ):
            self.result["changed"] = True

        self.msg = "\n".join(result_msg_list)
        self.set_operation_result("success", self.result["changed"], self.msg, "INFO")

        return self

    def verify_diff_merged(self, config):
        """
        Manages LAN Automation tasks and Port Channel operations in Cisco Catalyst Center based on the provided configuration.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the configuration details for LAN automation and port channels. The structure includes:
                - 'lan_automation': Dictionary with details for starting a LAN automation session, including:
                    - 'primaryDeviceManagmentIPAddress': The IP address of the primary device.
                    - 'launchAndWait': Boolean indicating if the session should be launched and waited upon.
                - 'lan_automated_device_update': Dictionary containing updates for LAN automated devices, including:
                    - 'loopbackUpdateDeviceList': List of dictionaries for loopback IP updates.
                    - 'hostnameUpdateDevices': List of dictionaries for hostname updates.
                    - 'linkAdd': Dictionary for link addition details.
                    - 'linkDelete': Dictionary for link deletion details.
                - 'port_channel': List of port channel configurations to be verified or updated, including:
                    - 'source_device_management_ip_address' and 'destination_device_management_ip_address'
                    - 'links': List of links associated with the port channel.
                    - 'port_channel_number': Optional port channel number.

        Returns:
            self (object): Returns the current instance of the class with updated attributes for created,
                        updated, and no-update status of LAN automation tasks and port channel operations.

        Description:
            This method orchestrates LAN Automation operations and port channel verification by:
            - Initiating a LAN automation session if specified in the configuration, checking for existing
            sessions, and logging the result.
            - Filtering device updates to determine which changes are necessary before performing updates.
            - Performing updates to devices based on the filtered details for loopback IP addresses,
            hostnames, links to be added, and links to be deleted.
            - Verifying port channel configurations and ensuring the correct port channels exist, links are added or removed,
            and logging successes and warnings as appropriate.
            - Ensuring all required tasks are executed and their statuses are checked to facilitate smooth
            playbook execution.
        """
        lan_automation = self.want.get("lan_automation", {})
        if lan_automation:
            seed_ip_address = lan_automation.get("primaryDeviceManagmentIPAddress")
            launch_and_wait = lan_automation.get("launchAndWait", False)

            self.log(
                "Verifying LAN automation session for seed IP: {}".format(
                    seed_ip_address
                ),
                "DEBUG",
            )
            if seed_ip_address and not launch_and_wait:
                self.get_have(config)
                self.log("Current State (have): {0}".format(str(self.have)), "INFO")
                session_to_ip_mapping = self.have.get("session_to_ip_map", {})

                session_id = None
                for sid, ip in session_to_ip_mapping.items():
                    if ip == seed_ip_address:
                        session_id = sid
                        break

                if session_id:
                    self.status = "success"
                    self.msg = "The LAN automation session for seed IP '{0}' has successfully started. Session ID: {1}".format(
                        seed_ip_address, session_id
                    )
                    self.log(self.msg, "INFO")
                    return self

                self.msg = (
                    "Failed to verify that the LAN automation session for seed IP '{0}' has started. "
                    "No session found immediately after starting.".format(
                        seed_ip_address
                    )
                )
                self.log(self.msg, "INFO")

        lan_devices = self.want.get("lan_automated_device_update", {})
        if lan_devices:
            self.process_loopback_updates(
                lan_devices.get("loopbackUpdateDeviceList", [])
            )
            self.process_hostname_updates(lan_devices.get("hostnameUpdateDevices", []))
            self.process_link_addition(lan_devices.get("linkAdd", {}))
            self.process_link_deletion(lan_devices.get("linkDelete", {}))

        port_channel = self.want.get("port_channel", {})
        if port_channel:
            self.get_have(config)
            self.log(f"Current State (have): {self.pprint(self.have)}", "INFO")

            self.log("Verifying Port Channel configurations in merged state.", "INFO")
            self.verify_diff_merged_port_channel(port_channel)
        return self

    def verify_diff_merged_port_channel(self, port_channel):
        """
        Verifies port channel configurations in the merged state.

        Parameters:
            port_channel (list[dict]): List of desired port channel configurations from the playbook. Each dictionary may include:
                - 'source_device_management_ip_address'
                - 'destination_device_management_ip_address'
                - 'links': List of links in the port channel.
                - 'port_channel_number': Optional port channel number.

        Returns:
            self (object): Returns the current instance of the class after verifying port channel configurations.

        Description:
            This method iterates through the desired port channel configurations and performs the following:
            - Logs the start of verification for each port channel configuration.
            - Retrieves the corresponding existing port channel configuration from `self.have`.
            - Checks if the port channel configuration exists; if not, raises an error.
            - Compares the existing configuration with the desired configuration using `port_channel_config_needs_update`.
            - If an update is needed but the configuration is expected to be already applied, raises an error.
            - Logs debug messages for each verification step and indicates if the configuration is up to date.
        """

        self.log(
            f"Verifying port channel configurations in merged state: {self.pprint(port_channel)}",
            "INFO",
        )

        for i, want_port_channel_config in enumerate(port_channel):
            self.log(
                f"Verifying port channel configuration at '{i}' index: {self.pprint(want_port_channel_config)}",
                "DEBUG",
            )

            have_port_channel_configs = self.have.get("port_channel")[i]
            self.log(
                f"Corresponding existing port channel configurations at '{i}' index: {self.pprint(have_port_channel_configs)}",
                "DEBUG",
            )

            if not have_port_channel_configs:
                self.msg = (
                    f"Port channel configuration verification failed at index '{i}'. "
                    "No existing port channel configuration found. Expected port channel to be created but it doesn't exist."
                )
                self.fail_and_exit(self.msg)
            else:
                self.log(
                    "Existing port channel configuration found. Verifying if updates were applied.",
                    "DEBUG",
                )
                #  In case of merged, there'll only one config if it exists.
                have_port_channel_config = have_port_channel_configs[0]
                needs_update, updated_port_channel_config = (
                    self.port_channel_config_needs_update(
                        want_port_channel_config, have_port_channel_config
                    )
                )
                if needs_update:
                    self.msg = (
                        f"Port channel configuration verification failed at index '{i}'. "
                        f"Configuration needs update but expected it to be already updated. "
                        f"Config that needs update: {self.pprint(updated_port_channel_config)}"
                    )
                    self.fail_and_exit(self.msg)
                else:
                    self.log(
                        "Port channel configuration verification passed. Configuration is up to date as expected.",
                        "DEBUG",
                    )

        return self

    def process_loopback_updates(self, loopback_updates):
        """
        Processes loopback IP updates and logs the results.
        Args:
            loopback_updates (list): A list of dictionaries containing loopback
                                     update details. Each dictionary should contain
                                     a key "newLoopback0IPAddress".
        Returns:
            None
        Description:
            This method iterates through a list of loopback update dictionaries,
            verifies the existence of the new loopback IP address in the system,
            and logs the outcome of each verification.
        """
        if not loopback_updates:
            self.log(
                "No loopback update data provided. Skipping loopback update processing.",
                "INFO",
            )
            return

        self.log("Processing loopback updates.", "INFO")
        for loopback in loopback_updates:
            new_ip = loopback.get("newLoopback0IPAddress")
            if self.get_ip_details(new_ip, "new loopback IP update"):
                self.log(
                    "Verified loopback IP address {0} was updated on Catalyst Center.".format(
                        new_ip
                    ),
                    "INFO",
                )
            else:
                self.log(
                    "Loopback IP address {0} was not updated on Catalyst Center.".format(
                        new_ip
                    ),
                    "WARNING",
                )

    def process_hostname_updates(self, hostname_updates):
        """
        Processes hostname updates and logs the results.
        Args:
            hostname_updates (list): A list of dictionaries containing hostname
                                     update details. Each dictionary should include
                                     "deviceManagementIPAddress" and "newHostName".
        Returns:
            None
        Description:
            This method processes a list of hostname update dictionaries and
            checks whether the hostname of each device IP is updated. It logs
            whether the update was successful or if it was already up to date.
        """
        if not hostname_updates:
            self.log(
                "No hostname updates data provided. Skipping hostname updates processing.",
                "INFO",
            )
            return

        self.log("Processing hostname updates.", "INFO")
        for hostname in hostname_updates:
            device_ip = hostname.get("deviceManagementIPAddress")
            new_hostname = hostname.get("newHostName")
            current_hostname = self.get_hostname_details(device_ip)

            if current_hostname == new_hostname:
                self.log(
                    "Hostname for device IP {0} is already updated to {1}.".format(
                        device_ip, new_hostname
                    ),
                    "INFO",
                )
            else:
                self.log(
                    "Hostname for device IP {0} was not updated to {1}.".format(
                        device_ip, new_hostname
                    ),
                    "WARNING",
                )

    def process_link_addition(self, link_add):
        """
        Processes link addition and logs the results.
        Args:
            link_add (dict): A dictionary containing details for adding a link,
                             including "sourceDeviceManagementIPAddress",
                             "sourceDeviceInterfaceName", "destinationDeviceManagementIPAddress",
                             and "destinationDeviceInterfaceName".
        Returns:
            None
        Description:
            This method checks the details of the link to be added and verifies
            whether both source and destination links exist in the system. It
            logs the result of the link addition attempt.
        """
        if not link_add:
            self.log(
                "No link addition data provided. Skipping link addition processing.",
                "INFO",
            )
            return

        self.log("Processing link addition.", "INFO")

        source_ip_address = link_add.get("sourceDeviceManagementIPAddress")
        source_interface_name = link_add.get("sourceDeviceInterfaceName")
        destination_ip_address = link_add.get("destinationDeviceManagementIPAddress")
        destination_interface_name = link_add.get("destinationDeviceInterfaceName")

        if self.check_link_details(
            source_ip_address, source_interface_name
        ) and self.check_link_details(
            destination_ip_address, destination_interface_name
        ):
            self.log(
                "Link between {0}/{1} and {2}/{3} was added successfully in Catalyst Center.".format(
                    source_ip_address,
                    source_interface_name,
                    destination_ip_address,
                    destination_interface_name,
                ),
                "INFO",
            )
        else:
            self.log(
                "Link between {0}/{1} and {2}/{3} was not added in Catalyst Center.".format(
                    source_ip_address,
                    source_interface_name,
                    destination_ip_address,
                    destination_interface_name,
                ),
                "WARNING",
            )

    def process_link_deletion(self, link_delete):
        """
        Processes link deletion and logs the results.
        Args:
            link_delete (dict): A dictionary containing details for deleting a link,
                                including "sourceDeviceManagementIPAddress",
                                "sourceDeviceInterfaceName", "destinationDeviceManagementIPAddress",
                                and "destinationDeviceInterfaceName".
        Returns:
            None
        Description:
            This method checks whether the specified link is already removed or
            still exists in the system. It logs the outcome of the link deletion attempt.
        """
        if not link_delete:
            self.log(
                "No link deletion data provided. Skipping link deletion processing.",
                "INFO",
            )
            return

        self.log("Processing link deletion.", "INFO")

        source_ip_address = link_delete.get("sourceDeviceManagementIPAddress")
        source_interface_name = link_delete.get("sourceDeviceInterfaceName")
        destination_ip_address = link_delete.get("destinationDeviceManagementIPAddress")
        destination_interface_name = link_delete.get("destinationDeviceInterfaceName")

        if not self.check_link_details(
            source_ip_address, source_interface_name
        ) and not self.check_link_details(
            destination_ip_address, destination_interface_name
        ):
            self.log(
                "Link between {0}/{1} and {2}/{3} has already been removed.".format(
                    source_ip_address,
                    source_interface_name,
                    destination_ip_address,
                    destination_interface_name,
                ),
                "INFO",
            )
        else:
            self.log(
                "Link between {0}/{1} and {2}/{3} still exists and needs to be removed.".format(
                    source_ip_address,
                    source_interface_name,
                    destination_ip_address,
                    destination_interface_name,
                ),
                "WARNING",
            )

    def get_diff_merged(self):
        """
        Orchestrates LAN Automation operations in Cisco Catalyst Center based on user input from the playbook.
        This method manages the following tasks:
        - Starting a LAN Automation session.
        - Stopping the session if needed.
        - Updating LAN Automated devices based on the filtered configuration received.
        - Managing Port Channel configurations by creating, updating, or deleting port channels
          according to the desired state in the playbook.
        It ensures all required tasks are present, executes them, and checks their status to facilitate smooth
        playbook execution.
        Returns:
            self (object): Returns the current instance of the class used for interacting with Cisco Catalyst Center.
        Args:
             self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            - The method first checks if there are any LAN automation settings in `self.want`. If found,
              it initiates the LAN automation session and logs the task ID.
            - If device updates are specified, it validates that the LAN automation session has been completed
              before proceeding.
            - Device updates are filtered to determine which changes are necessary.
            - Each type of update (loopback, hostname, links) is processed, and the method logs the results
              of the operations and any issues encountered.
            - The filtered updates are passed to the corresponding API calls to update the LAN automated devices
              as necessary.
            - Port channel configurations specified in `self.want["port_channel"]` are processed for creation,
              update, or deletion, and the status of these operations is verified.
        """
        action_plan = {
            "start_lan_automation": (
                self.start_lan_auto,
                self.get_lan_auto_task_status,
            ),
            "update_lan_automated_devices": (
                self.update_lan_auto_devices,
                self.get_update_lan_task_status,
            ),
        }

        lan_automation = self.want.get("lan_automation", {})
        update_device = self.want.get("lan_automated_device_update", {})
        port_channel = self.want.get("port_channel", {})

        self.log("LAN Automation settings: {}".format(lan_automation), "DEBUG")
        self.log("Device update settings: {}".format(update_device), "DEBUG")

        if lan_automation:
            launch_and_wait = lan_automation.get("launchAndWait", False)
            self.log("Launch and wait setting: {}".format(launch_and_wait), "DEBUG")

            session_to_ip_mapping = self.have.get("session_to_ip_map", {})
            seed_ip_address = lan_automation.get("primaryDeviceManagmentIPAddress")
            self.log(
                "Current session to IP mapping: {}".format(session_to_ip_mapping),
                "DEBUG",
            )
            self.log(
                "Seed IP address being checked: {}".format(seed_ip_address), "DEBUG"
            )

            if (
                session_to_ip_mapping
                and seed_ip_address in session_to_ip_mapping.values()
            ):
                self.no_lan_auto_start.append(seed_ip_address)
                self.msg = (
                    "A LAN automation session is already running for the same seed IP address: {}. "
                    "Hence, no update needed. ".format(seed_ip_address)
                )
                self.set_operation_result("success", False, self.msg, "INFO")
                self.check_return_status()
                return self

            action_func, status_func = action_plan["start_lan_automation"]
            self.log(
                "Performing '{}' operation...".format(action_func.__name__), "DEBUG"
            )

            result_task_id = action_func(lan_automation)
            self.log(
                "Result task ID from '{}': {}".format(
                    action_func.__name__, result_task_id
                ),
                "DEBUG",
            )
            self.log("Result task ID is: {}".format(result_task_id))

            if not result_task_id:
                self.msg = "An error occurred while retrieving the task_id of the '{}' operation.".format(
                    action_func.__name__
                )
                self.set_operation_result("failed", False, self.msg, "CRITICAL")
                self.log(self.msg, "ERROR")

            self.log("Checking status for task ID: {}".format(result_task_id), "DEBUG")
            status_func(result_task_id).check_return_status()
            self.log("LAN Automation session completed successfully.", "DEBUG")

        if update_device:
            if lan_automation and not launch_and_wait:
                self.msg = (
                    "Error: You need to first run LAN automation and wait for it to complete before running "
                    "'update_lan_automated_devices'. "
                )
                self.set_operation_result("failed", False, self.msg, "CRITICAL")
                self.log(self.msg, "ERROR")
                self.module.fail_json(msg=self.msg, response=[])

            filtered_updates = self.filter_updates(update_device)
            self.log(
                "Filtered updates for devices: {}".format(filtered_updates), "DEBUG"
            )

            if filtered_updates:
                action_func, status_func = action_plan["update_lan_automated_devices"]
                self.log(
                    "Performing '{}' operation with filtered updates.".format(
                        action_func.__name__
                    ),
                    "DEBUG",
                )
                result_task_ids = action_func(filtered_updates)

                if not result_task_ids:
                    self.msg = "An error occurred while retrieving task_ids for '{}' operation.".format(
                        action_func.__name__
                    )
                    self.set_operation_result("failed", False, self.msg, "CRITICAL")
                else:
                    self.log("Changes Merged: Task IDs: {}".format(result_task_ids))
                    status_func(result_task_ids).check_return_status()
                    self.log("Device updates completed successfully.", "INFO")
            else:
                self.log("No updates required after filtering.", "INFO")

        if port_channel:
            self.log(
                f"Processing port channel configuration: {self.pprint(port_channel)}",
                "DEBUG",
            )
            self.get_diff_merged_port_channel(port_channel).check_return_status()

        return self

    def port_channel_config_needs_update(
        self, want_port_channel_config, have_port_channel_config
    ):
        """
        Determines if a given port channel configuration requires an update based on the desired state
        in the playbook and the existing configuration in Cisco Catalyst Center.

        Parameters:
            want_port_channel_config (dict): The desired port channel configuration from the playbook.
                Expected keys:
                    - sourceDeviceManagementIPAddress (str): Source device IP.
                    - destinationDeviceManagementIPAddress (str | None): Destination device IP.
                    - links (list[dict] | None): List of link mappings for the port channel.
            have_port_channel_config (dict | None): The existing port channel configuration retrieved
                from Catalyst Center. Same structure as `want_port_channel_config`.

        Returns:
            tuple:
                - bool: True if an update is required, False otherwise.
                - dict | None: The updated port channel configuration containing only the links that
                  need to be added or removed. None if no update is needed.

        Description:
            - Compares the desired port channel configuration (`want_port_channel_config`) with the
              existing configuration (`have_port_channel_config`).
            - Validates source-to-destination port mappings to ensure no duplicates exist.
            - Determines which links need to be added (for 'merged' state) or removed (for 'deleted' state).
            - Validates that the resulting number of links does not exceed 8 or fall below 2.
            - Logs DEBUG messages at key points: starting comparison, desired vs existing configs,
              links requiring update, and validation results.
            - Exits with an error if any constraints are violated or invalid state is provided.
        """

        state = self.params.get("state")
        self.log(
            f"Comparing if port channel configuration needs update in '{state}' state.",
            "DEBUG",
        )
        self.log(
            f"Desired port channel config: {self.pprint(want_port_channel_config)}",
            "DEBUG",
        )
        self.log(
            f"Existing port channel config: {self.pprint(have_port_channel_config)}",
            "DEBUG",
        )

        if not have_port_channel_config:
            self.log(
                "No existing port channel configuration found. Update needed.", "DEBUG"
            )
            return True, want_port_channel_config

        # prechecks before comparision
        want_links = want_port_channel_config.get("links")
        want_source_to_destination_port_mapping = {}
        want_destination_to_source_port_mapping = {}
        for link_idx, want_link in enumerate(want_links, start=1):
            for want_source_port, want_destination_port in want_link.items():
                want_source_to_destination_port_mapping[want_source_port] = (
                    want_destination_port
                )
                want_destination_to_source_port_mapping[want_destination_port] = (
                    want_source_port
                )
                self.log(
                    f"Mapped desired link {link_idx}: {want_source_port} -> {want_destination_port}",
                    "DEBUG",
                )

        self.log(
            "Starting duplicate port validation against existing port channel configuration.",
            "DEBUG",
        )
        have_links = have_port_channel_config.get("links", [])
        for have_link in have_links:
            have_src = have_link.get("sourcePort")
            have_dst = have_link.get("destinationPort")
            if (
                have_src in want_source_to_destination_port_mapping
                and have_dst != want_source_to_destination_port_mapping[have_src]
            ):
                self.msg = (
                    f"Duplicate source port '{have_src}' found in existing port channel configuration.\n"
                    f"Existing Link - Source: {have_src}, Destination: {have_dst}\n"
                    f"Desired Link - Source: {have_src}, Destination: {want_source_to_destination_port_mapping[have_src]}\n"
                    "One source port can only map to one destination port."
                )
                self.fail_and_exit(self.msg)

        updated_required_links = []

        self.log("Determining links that require update.", "DEBUG")
        if state == "merged":
            for want_link in want_links:
                if want_link not in have_links:
                    updated_required_links.append(want_link)
        elif state == "deleted":
            for have_link in have_links:
                if have_link in want_links:
                    updated_required_links.append(have_link)
        else:
            self.msg = f"Invalid state '{state}' provided. Supported states are 'merged' and 'deleted'."
            self.fail_and_exit(self.msg)
        #  The update API is not available, instead 2 seperate APIs for Add and delete are available, so only storing the new links to be added/removed.

        if not updated_required_links:
            self.log(
                "Port channel configuration is up to date. No update needed.", "DEBUG"
            )
            return False, None

        self.log(
            f"Port channel configuration needs update. Links that requires update: {self.pprint(updated_required_links)}",
            "DEBUG",
        )

        self.log(
            "Checking if updated links exceed 8 (max) or fall below 2 (min) allowed links per port channel.",
            "DEBUG",
        )

        if state == "merged":
            total_links_after_merge = len(updated_required_links) + len(have_links)
            if total_links_after_merge > 8:
                self.log(
                    "Link count validation failed - would exceed maximum of 8 links",
                    "ERROR",
                )
                self.msg = (
                    f"Port channel configuration update would result in more than 8 links. "
                    f"Maximum allowed links per port channel is 8. Current links: {len(have_links)}, "
                    f"Links to be added: {len(updated_required_links)}, Total would be: {total_links_after_merge}"
                )
                self.fail_and_exit(self.msg)

        elif state == "deleted":
            remaining_links_after_deletion = len(have_links) - len(
                updated_required_links
            )
            if remaining_links_after_deletion == 1:
                self.log(
                    "Link count validation failed - would result in less than 2 links",
                    "ERROR",
                )
                self.msg = (
                    f"Port channel configuration update would result in less than 2 links. "
                    f"Minimum required links per port channel is 2. Current links: {len(have_links)}, "
                    f"Links to be removed: {len(updated_required_links)}, Total would be: {remaining_links_after_deletion}"
                )
                self.fail_and_exit(self.msg)

        self.log("Port channel link count validation passed.", "DEBUG")

        updated_port_channel_config = {
            "sourceDeviceManagementIPAddress": want_port_channel_config.get(
                "sourceDeviceManagementIPAddress"
            ),
            "destinationDeviceManagementIPAddress": want_port_channel_config.get(
                "destinationDeviceManagementIPAddress"
            ),
            "links": updated_required_links,
            "id": have_port_channel_config.get("id"),
        }
        self.log(
            f"Port channel configuration comparison completed - update required with {len(updated_required_links)} links",
            "DEBUG",
        )
        self.log(
            f"Updated port channel configuration: {self.pprint(updated_port_channel_config)}",
            "DEBUG",
        )

        return True, updated_port_channel_config

    def create_port_channel(self, port_channel_config):
        """
        Creates a new port channel between two devices using the provided configuration.

        Parameters:
            port_channel_config (dict): Configuration dictionary containing:
                - sourceDeviceManagementIPAddress (str): IP of the source device.
                - destinationDeviceManagementIPAddress (str): IP of the destination device.
                - links (list[dict]): List of link mappings with 'sourcePort' and 'destinationPort'.

        Returns:
            self: Returns the current instance with updated `port_channel_created` list.

        Description:
            - Logs the initiation of the port channel creation process.
            - Constructs the payload for the API call based on source/destination IPs and links.
            - Calls the API to create the port channel and retrieves the task ID.
            - Logs the API call payload at DEBUG level.
            - Checks if the task ID is returned; if not, exits with an error.
            - Monitors the task status and logs success upon completion.
            - Appends the created port channel configuration to `self.port_channel_created`.
        """

        self.log(
            f"Initiating port channel creation with configuration: {self.pprint(port_channel_config)}",
            "INFO",
        )
        source_device_management_ip = port_channel_config.get(
            "sourceDeviceManagementIPAddress"
        )
        destination_device_management_ip = port_channel_config.get(
            "destinationDeviceManagementIPAddress"
        )

        create_port_channel_payload = {
            "device1ManagementIPAddress": source_device_management_ip,
            "device2ManagementIPAddress": destination_device_management_ip,
            "portChannelMembers": [
                {
                    "device1Interface": link.get("sourcePort"),
                    "device2Interface": link.get("destinationPort"),
                }
                for link in port_channel_config.get("links", [])
            ],
        }

        task_name = "create_a_new_port_channel_between_devices"

        self.log(
            f"Calling '{task_name}' API with payload: {self.pprint(create_port_channel_payload)}",
            "DEBUG",
        )
        task_id = self.get_taskid_post_api_call(
            "lan_automation", task_name, create_port_channel_payload
        )

        if not task_id:
            self.msg = f"Unable to retrieve the task_id for the task '{task_name}' for the port channel'."
            self.fail_and_exit(self.msg)

        success_msg = (
            f"Port channel between the source device '{source_device_management_ip}' and "
            f"destination device '{destination_device_management_ip}' created successfully."
        )
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.log(
            f"Port channel creation process completed for devices: {source_device_management_ip} -> {destination_device_management_ip}",
            "INFO",
        )

        self.port_channel_created.append(port_channel_config)
        return self

    def add_lan_automated_link_to_a_port_channel(self, port_channel_config):
        """
        Adds new links to an existing port channel between two devices.

        Parameters:
            port_channel_config (dict): Configuration dictionary containing:
                - id (str): ID of the existing port channel.
                - sourceDeviceManagementIPAddress (str): IP of the source device.
                - destinationDeviceManagementIPAddress (str): IP of the destination device.
                - links (list[dict]): List of link mappings to be added with 'sourcePort' and 'destinationPort'.

        Returns:
            self: Returns the current instance with updated `link_added_to_port_channel` list.

        Description:
            - Logs the initiation of the port channel update process.
            - Constructs the payload for adding links to the port channel.
            - Calls the API and retrieves the task ID for adding links.
            - Logs DEBUG information about the API payload and task ID retrieval.
            - Monitors the task status and logs a success message upon completion.
            - Appends the updated port channel configuration to `self.link_added_to_port_channel`.
        """

        source_device_management_ip = port_channel_config.get(
            "sourceDeviceManagementIPAddress"
        )
        destination_device_management_ip = port_channel_config.get(
            "destinationDeviceManagementIPAddress"
        )
        self.log(
            f"Initiating update of port channel between source device: '{source_device_management_ip}' and "
            f"destination device: '{destination_device_management_ip}' with config: {self.pprint(port_channel_config)}",
            "INFO",
        )

        if not source_device_management_ip:
            self.log(
                "Source device management IP address is required for link addition",
                "ERROR",
            )
            self.msg = (
                "Source device management IP address is missing from configuration"
            )
            self.fail_and_exit(self.msg)

        if not destination_device_management_ip:
            self.log(
                "Destination device management IP address is required for link addition",
                "ERROR",
            )
            self.msg = (
                "Destination device management IP address is missing from configuration"
            )
            self.fail_and_exit(self.msg)

        links = port_channel_config.get("links", [])
        if not links or not isinstance(links, list):
            self.log(
                "Valid links list is required for port channel link addition", "ERROR"
            )
            self.msg = "Links configuration is missing or invalid"
            self.fail_and_exit(self.msg)

        update_port_channel_payload = {
            "id": port_channel_config.get("id"),
            "portChannelMembers": [
                {
                    "device1Interface": link.get("sourcePort"),
                    "device2Interface": link.get("destinationPort"),
                }
                for link in port_channel_config.get("links", [])
            ],
        }

        self.log(
            f"Initial update link payload before device order check: {self.pprint(update_port_channel_payload)}",
            "DEBUG",
        )

        if self.check_if_device_order_needs_swapping(port_channel_config):
            self.log(
                "Device order swapping is required. Swapping device1Interface and device2Interface in all port channel members.",
                "INFO",
            )
            for member in update_port_channel_payload["portChannelMembers"]:
                original_device1 = member["device1Interface"]
                original_device2 = member["device2Interface"]
                member["device1Interface"], member["device2Interface"] = (
                    member["device2Interface"],
                    member["device1Interface"],
                )
                self.log(
                    f"Swapped interfaces - Original: device1Interface='{original_device1}', device2Interface='{original_device2}' "
                    f"-> Swapped: device1Interface='{member['device1Interface']}', device2Interface='{member['device2Interface']}'",
                    "DEBUG",
                )
            self.log(
                f"Device order swapping completed. Updated payload: {self.pprint(update_port_channel_payload)}",
                "DEBUG",
            )
        else:
            self.log(
                "Device order matches Catalyst Center configuration. No swapping required.",
                "DEBUG",
            )

        task_name = "add_a_lan_automated_link_to_a_port_channel"

        self.log(
            f"Calling '{task_name}' API with payload: {self.pprint(update_port_channel_payload)}",
            "DEBUG",
        )
        task_id = self.get_taskid_post_api_call(
            "lan_automation", task_name, update_port_channel_payload
        )
        if not task_id:
            self.msg = (
                f"Unable to retrieve the task_id for the task '{task_name}' for the port channel "
                f"between the source device '{source_device_management_ip}' and destination device '{destination_device_management_ip}''."
            )
            self.fail_and_exit(self.msg)

        success_msg = (
            f"Port channel between the source device '{source_device_management_ip}' and "
            f"destination device '{destination_device_management_ip}' updated successfully with links: {self.pprint(port_channel_config.get('links'))}."
        )

        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.log(
            f"Port channel links added successfully to port channel ID '{port_channel_config.get('id')}'.",
            "INFO",
        )

        self.link_added_to_port_channel.append(port_channel_config)
        return self

    def get_diff_merged_port_channel(self, port_channel):
        """
        Processes port channel configurations in the 'merged' state and ensures they are created or updated as needed.

        Parameters:
            port_channel (list[dict]): List of desired port channel configurations to be processed.

        Returns:
            self: Returns the current instance with updated port channel status lists.

        Description:
            - Iterates through each desired port channel configuration.
            - Logs the desired configuration at each index.
            - Compares with existing configurations in `self.have`.
            - Creates new port channels if none exist.
            - Updates existing port channels if links need to be added.
            - Logs the status of each configuration, including updates or no-change scenarios.
        """

        self.log(
            f"Processing port channel configurations in merged state: {self.pprint(port_channel)}",
            "INFO",
        )

        for i, want_port_channel_config in enumerate(port_channel):
            self.log(
                f"Processing port channel configuration at '{i}' index: {self.pprint(want_port_channel_config)}",
                "DEBUG",
            )

            have_port_channel_configs = self.have.get("port_channel")[i]
            self.log(
                f"Existing port channel configurations at index '{i}': {self.pprint(have_port_channel_configs)}",
                "DEBUG",
            )

            if not have_port_channel_configs:
                self.log(
                    "No existing port channel configuration found. Creating new port channel.",
                    "DEBUG",
                )
                self.create_port_channel(want_port_channel_config)
            else:
                self.log(
                    "Existing port channel configuration found. Checking for updates.",
                    "DEBUG",
                )
                have_port_channel_config = have_port_channel_configs[0]
                #  In case of merged, there'll only one config if it exists.
                needs_update, updated_port_channel_config = (
                    self.port_channel_config_needs_update(
                        want_port_channel_config, have_port_channel_config
                    )
                )
                if needs_update:
                    self.log(
                        "Port channel configuration needs update. Creating updated port channel.",
                        "DEBUG",
                    )
                    self.add_lan_automated_link_to_a_port_channel(
                        updated_port_channel_config
                    )
                else:
                    self.log(
                        "Port channel configuration is up to date. No update needed.",
                        "DEBUG",
                    )
                    self.link_not_added_to_port_channel.append(want_port_channel_config)

        self.log(
            "Completed processing all port channel configurations in merged state.",
            "INFO",
        )
        return self

    def filter_updates(self, update_device):
        """
        Filters out updates that don't need to be performed on LAN automated devices.
        Args:
            update_device (dict): The dictionary containing LAN automated device updates. This should include:
                - 'loopbackUpdateDeviceList': List of devices requiring loopback IP address updates.
                - 'hostnameUpdateDevices': List of devices requiring hostname changes.
                - 'linkAdd': Dictionary of links to be added, containing source and destination device details.
                - 'linkDelete': Dictionary of links to be deleted, containing source and destination device details.
        Returns:
            dict: A filtered dictionary of updates that actually require changes.
        Description:
             This method checks each type of update (loopback, hostname, link add, link delete) and filters out
             updates that are not necessary. It evaluates the current state of each device against the desired
             state as defined in the update_device input.
        """

        update_types = {
            "loopbackUpdateDeviceList": "loopback_update",
            "hostnameUpdateDevices": "hostname_update",
            "linkAdd": "link_add",
            "linkDelete": "link_delete",
        }

        filtered_updates = {}

        for update_key, update_type in update_types.items():
            updates = update_device.get(
                update_key, {} if update_key in ["linkAdd", "linkDelete"] else []
            )

            if updates:
                self.log(
                    "Filtering updates for {}: {}".format(update_key, updates), "DEBUG"
                )

                if update_type == "loopback_update":
                    filtered_updates[update_key] = []
                    for device in updates:
                        current_ip = device.get("deviceManagementIPAddress")
                        new_ip = device.get("newLoopback0IPAddress")

                        if current_ip != new_ip:
                            filtered_updates[update_key].append(device)
                            self.log(
                                "Loopback IP needs update for device: {}. Current: {}, New: {}".format(
                                    device, current_ip, new_ip
                                ),
                                "INFO",
                            )
                        else:
                            self.no_loopback_updated.append(device)
                            self.log(
                                "No update needed for loopback IP on device: {}".format(
                                    device
                                ),
                                "INFO",
                            )
                    if not filtered_updates[update_key]:
                        self.log("No loopback updates needed after filtering.", "INFO")

                elif update_type == "hostname_update":
                    filtered_updates[update_key] = []
                    for device in updates:
                        current_hostname = self.get_hostname_details(
                            device.get("deviceManagementIPAddress")
                        )
                        if current_hostname != device.get("newHostName"):
                            self.log(
                                "Hostname needs update for device: {}. Current: {}, New: {}".format(
                                    device, current_hostname, device.get("newHostName")
                                ),
                                "INFO",
                            )
                            filtered_updates[update_key].append(device)
                        else:
                            self.no_hostname_updated.append(device)
                            self.log(
                                "No update needed for hostname on device: {}".format(
                                    device
                                ),
                                "INFO",
                            )
                    if not filtered_updates[update_key]:
                        self.log("No hostname updates needed after filtering.", "INFO")

                elif update_type == "link_add":
                    self.log(
                        "Link add updates ready for processing: {}".format(updates),
                        "DEBUG",
                    )

                    source_ip_address = updates.get("sourceDeviceManagementIPAddress")
                    source_interface_name = updates.get("sourceDeviceInterfaceName")
                    destination_ip_address = updates.get(
                        "destinationDeviceManagementIPAddress"
                    )
                    destination_interface_name = updates.get(
                        "destinationDeviceInterfaceName"
                    )

                    if self.check_link_details(
                        source_ip_address, source_interface_name
                    ) and self.check_link_details(
                        destination_ip_address, destination_interface_name
                    ):
                        self.log(
                            "Link already exists between {}/{} and {}/{}. No update needed.".format(
                                source_ip_address,
                                source_interface_name,
                                destination_ip_address,
                                destination_interface_name,
                            ),
                            "INFO",
                        )

                        self.no_link_added.append(updates)
                    else:
                        filtered_updates[update_key] = updates

                    if not filtered_updates[update_key]:
                        self.log("No link add updates needed after filtering.", "INFO")

                elif update_type == "link_delete":
                    if not self.check_link_details(
                        updates.get("sourceDeviceManagementIPAddress"),
                        updates.get("sourceDeviceInterfaceName"),
                    ) and not self.check_link_details(
                        updates.get("destinationDeviceManagementIPAddress"),
                        updates.get("destinationDeviceInterfaceName"),
                    ):
                        filtered_updates[update_key] = updates
                        self.log(
                            "Link delete updates ready for processing: {}".format(
                                updates
                            ),
                            "DEBUG",
                        )
                    else:
                        self.no_link_deleted.append(updates)
                        self.log(
                            "No link delete needed for updates: {}".format(updates),
                            "INFO",
                        )

                    if not filtered_updates.get(update_key):
                        self.log(
                            "No link delete updates needed after filtering.", "INFO"
                        )

        self.log("Filtered updates: {}".format(filtered_updates), "DEBUG")

        return filtered_updates

    def update_lan_auto_devices(self, filtered_updates):
        """
        Update LAN automated devices based on the filtered configuration from the input file.
        Args:
            filtered_updates (dict): Dictionary containing only the devices that require updates in camelCase.
        Returns:
            dict: A dictionary containing task IDs for each type of update process.
        Description:
            This method iterates through the provided filtered updates and initiates API calls for each update type.
            It logs the processing steps and captures task IDs returned by the API. If no updates are found for a type,
            it logs that the update is being skipped. In case of an error during API calls, the method logs the failure.
        """

        task_ids = {
            "loopback_update": None,
            "hostname_update": None,
            "link_add": None,
            "link_delete": None,
        }

        update_types = {
            "loopbackUpdateDeviceList": "loopback_update",
            "hostnameUpdateDevices": "hostname_update",
            "linkAdd": "link_add",
            "linkDelete": "link_delete",
        }

        for update_key, update_type in update_types.items():
            updates = filtered_updates.get(update_key, [])

            if updates:
                self.log(
                    "Processing updates for {}: {}".format(update_key, updates), "DEBUG"
                )

                task_id = self.call_lan_auto_update_api(update_type, updates)

                if task_id:
                    task_ids[update_type] = task_id
                    self.log(
                        "Successfully initiated {} update. Task ID: {}".format(
                            update_type, task_id
                        ),
                        "INFO",
                    )
                else:
                    self.log(
                        "Failed to get task ID for {} update: {}".format(
                            update_type, updates
                        ),
                        "ERROR",
                    )
            else:
                self.log(
                    "No updates found for {}, skipping.".format(update_key), "INFO"
                )

        self.log("Generated task_ids: {}".format(task_ids))

        return task_ids

    def get_lan_auto_task_status(self, task_id):
        """
        Monitors the progress of a LAN Automation task based on the 'launch_and_wait' setting.
        Parameters:
            task_id (str): The ID of the LAN automation task to monitor.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            The method handles both scenarios of waiting for task completion and logging progress.
            If 'launch_and_wait' is False, it retrieves task details once and logs the outcome.
            If True, it continuously polls the task status and checks for errors or completion.
            It also handles PnP device authorizations if enabled, logging necessary information throughout the process.
            The method ensures to set the operation result based on the final status of the task.
        """

        lan_automation = self.want.get("lan_automation", {})
        launch_and_wait = lan_automation.get("launchAndWait", False)  # Default is False
        pnp_authorization = lan_automation.get("pnpAuthorization", False)
        device_serials = [
            serial.upper()
            for serial in lan_automation.get("deviceSerialNumberAuthorization", [])
        ] or [
            device.get("deviceSerialNumber", "").upper()
            for device in lan_automation.get("discoveryDevices", [])
        ]

        self.log("LAN Automation Config: {}".format(lan_automation), "DEBUG")
        self.log("Launch and Wait: {}".format(launch_and_wait), "DEBUG")
        self.log("PnP Authorization: {}".format(pnp_authorization), "DEBUG")
        self.log("Device Serial Numbers: {}".format(device_serials), "DEBUG")

        start_time = time.time()
        remaining_auth_devices = device_serials.copy()
        pending_authorization = True

        task_id = task_id.get("response", {}).get("taskId")
        self.log(
            "Starting to monitor LAN automation task with task ID: {}".format(task_id),
            "DEBUG",
        )

        if not launch_and_wait:
            task_details = self.get_task_details(task_id)
            if not task_details:
                self.msg = "Error retrieving task status for starting LAN Automation with task_id '{}'.".format(
                    task_id
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Task details for task ID {}: {}".format(task_id, task_details), "DEBUG"
            )

            if task_details.get("isError") is True:
                error_msg = task_details.get("failureReason") or task_details.get(
                    "progress"
                )
                self.msg = "Error encountered: {}".format(error_msg)
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            if pnp_authorization:
                self.msg = (
                    "The LAN automation session has been initiated successfully! You can monitor its progress through "
                    "the Catalyst Center UI. However, please note that since PnP authorization is enabled, you will "
                    "need to manually authorize the devices on the PnP page, as the 'launch_and_wait' option is set "
                    "to False."
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("success", True, self.msg, "INFO")
                self.started_lan_automation.append(
                    lan_automation.get("primaryDeviceManagmentIPAddress")
                )
            else:
                self.msg = (
                    "LAN automation session has started successfully. Please check Catalyst Center UI "
                    "to track progress."
                )
                self.log(self.msg, "INFO")
                self.set_operation_result("success", True, self.msg, "INFO")
                self.started_lan_automation.append(
                    lan_automation.get("primaryDeviceManagmentIPAddress")
                )

            return self

        self.log("Entering polling loop for LAN automation task completion...", "DEBUG")

        while True:
            task_details = self.get_task_details(task_id)
            if not task_details:
                self.msg = "Error retrieving task status for starting LAN Automation with task_id '{}'.".format(
                    task_id
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                break

            self.log(
                "Current task details for task ID {}: {}".format(task_id, task_details),
                "DEBUG",
            )

            if task_details.get("isError") is True:
                error_msg = task_details.get("failureReason") or task_details.get(
                    "progress"
                )
                self.msg = "Error encountered: {}".format(error_msg)
                self.status = "failed"
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", True, self.msg, "INFO")
                break

            if "complete" in task_details.get("progress", "").lower():
                self.msg = "LAN automation has completed successfully: {}".format(
                    task_details.get("progress")
                )
                self.log(self.msg, "INFO")
                self.completed_lan_automation.append(
                    lan_automation.get("primaryDeviceManagmentIPAddress")
                )
                self.status = "success"
                self.set_operation_result("success", True, self.msg, "INFO")
                break

            self.log(
                "Current progress for task ID {}: {}".format(
                    task_id, task_details.get("progress")
                ),
                "DEBUG",
            )
            elapsed_time = time.time() - start_time
            if int(elapsed_time) % 300 == 0:
                logs = self.collect_logs()
                if logs:
                    self.log("Collected logs: {}".format(logs), "INFO")
                    self.msg = "LAN Automation Session Logs: {}".format(logs)

            if pnp_authorization and pending_authorization:
                if remaining_auth_devices:
                    self.log(
                        "Authorizing devices in PnP with serial numbers provided: {}".format(
                            remaining_auth_devices
                        ),
                        "DEBUG",
                    )
                    authorized_devices = self.authorize_devices(remaining_auth_devices)
                    self.log(
                        "Authorized devices: {}".format(", ".join(authorized_devices)),
                        "INFO",
                    )
                    remaining_auth_devices = [
                        device
                        for device in remaining_auth_devices
                        if device not in authorized_devices
                    ]

                    if not authorized_devices:
                        self.log(
                            "Some devices from {} were not authorized as their state is not Pending Authorization. "
                            "Please check the logs for details regarding the state of the devices and ensure the "
                            "serial numbers are correct. We will keep checking the state and attempt authorizing the "
                            "devices again. If device authorization is done manually or the checkbox to enable "
                            "authorization on the device is not checked on Catalyst Center, consider stopping "
                            "LAN Automation session.".format(remaining_auth_devices),
                            "DEBUG",
                        )

                    if remaining_auth_devices:
                        self.log(
                            "Devices still pending authorization: {}".format(
                                ", ".join(remaining_auth_devices)
                            ),
                            "INFO",
                        )
                    else:
                        pending_authorization = False
                        self.log(
                            "All devices have been successfully authorized.", "INFO"
                        )
                else:
                    pending_authorization = False
                    self.msg = (
                        "PnP authorization is set to True, but no devices were given for authorization or "
                        "discovery. Please authorize devices manually in the PnP page in Catalyst Center."
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")

            self.log("Waiting for 30 seconds before the next status check...", "DEBUG")
            time.sleep(self.params.get("dnac_task_poll_interval", 30))

        if self.status != "success":
            elapsed_time = time.time() - start_time
            self.msg = (
                "LAN automation did not complete within the expected time {:.2f} seconds. "
                "Consider stopping the LAN Automation by running the playbook in Deleted state.".format(
                    elapsed_time
                )
            )
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", True, self.msg, "INFO")

        return self

    def call_lan_auto_update_api(self, update_type, payload):
        """
        Call the LAN automation API based on the update type and payload.
        Args:
            update_type (str): The type of update (loopback_update, hostname_update, link_add, link_delete).
            payload (list): The payload containing the update details from the input file. The structure
                            depends on the update type and is derived from filtered updates.
        Returns:
            str: The task ID from the API response if successful, otherwise None.
        Description:
            The method prepares the request parameters according to the type of update and makes the API call.
            It logs the parameters and response received from the API. If the API returns a task ID,
            it logs and returns that ID. In case of an error during the API call, it logs the error
            and returns None.
        """
        feature_map = {
            "loopback_update": "LOOPBACK0_IPADDRESS_UPDATE",
            "hostname_update": "HOSTNAME_UPDATE",
            "link_add": "LINK_ADD",
            "link_delete": "LINK_DELETE",
        }

        payload_map = {
            "loopback_update": "loopbackUpdateDeviceList",
            "hostname_update": "hostnameUpdateDevices",
            "link_add": "linkUpdate",
            "link_delete": "linkUpdate",
        }

        feature = feature_map.get(update_type)
        payload_key = payload_map.get(update_type)
        self.log(
            "Preparing to call LAN automation API for update type '{}': {}".format(
                update_type, payload
            ),
            "DEBUG",
        )

        try:
            params = {"feature": feature, payload_key: payload}

            self.log("Ready for API call with params: {}".format(params))
            response = self.dnac_apply["exec"](
                family="lan_automation",
                function="lan_automation_device_update",
                params=params,
                op_modifies=True,
            )

            self.log(
                "Response received for {} API call: {}".format(update_type, response),
                "DEBUG",
            )

            if response:
                task_id = response["response"].get("taskId")
                self.log(
                    "Task ID for {} update is {}".format(update_type, task_id), "DEBUG"
                )
                return task_id
            else:
                self.log(
                    "No response received from {} API call".format(update_type), "ERROR"
                )
                return None

        except Exception as e:
            self.log(
                "Error occurred during {} update: {}".format(update_type, str(e)),
                "CRITICAL",
            )
            self.set_operation_result(
                "failed",
                False,
                "Error occurred during {} update: {}".format(update_type, str(e)),
                "CRITICAL",
            )
        return None

    def get_update_lan_task_status(self, task_ids):
        """
        Monitors the progress of the LAN automation device update tasks and logs the results.
        Parameters:
            task_ids (dict): A dictionary containing task IDs for each type of update process.
        Returns:
            self: An instance of the class used for interacting with Cisco Catalyst Center.
        Description:
            This method iterates through each task ID associated with different update types, such as
            loopback updates, hostname updates, and link management. For each task ID, it retrieves the
            status, checks for errors, and logs the relevant information. If an update is completed
            successfully, it appends the task ID to the corresponding list of completed tasks. In case of
            errors, appropriate messages are logged, and the operation result is marked as failed.
        """
        self.log("Task Ids is: {}".format(task_ids))

        for update_type, task_id in task_ids.items():
            if task_id is not None:
                self.log(
                    "Monitoring task ID: {} for update type: {}".format(
                        task_id, update_type
                    ),
                    "INFO",
                )

                while True:
                    task_details = self.get_task_details(task_id)
                    if not task_details:
                        self.msg = (
                            "Error retrieving task status for task_id '{}'.".format(
                                task_id
                            )
                        )
                        self.log(self.msg, "ERROR")
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()
                        break

                    self.log(
                        "Task details for task ID {}: {}".format(task_id, task_details),
                        "DEBUG",
                    )

                    if task_details.get("isError") is True:
                        error_msg = task_details.get(
                            "failureReason"
                        ) or task_details.get("progress")
                        self.msg = (
                            "Error encountered for update type {} with Task ID: '{}': {} Check the logs "
                            "for more details.".format(update_type, task_id, error_msg)
                        )

                        self.log(self.msg, "ERROR")
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()
                        break

                    if (
                        "deleted" in task_details.get("progress", "").lower()
                        or "config push success"
                        in task_details.get("progress", "").lower()
                        or "update performed successfully"
                        in task_details.get("progress", "").lower()
                    ):
                        self.msg = (
                            "Update {} for task ID '{}' completed successfully".format(
                                update_type, task_id
                            )
                        )
                        self.log(self.msg, "INFO")

                        if update_type == "loopback_update":
                            self.updated_loopback.append(task_id)
                        elif update_type == "hostname_update":
                            self.updated_hostname.append(task_id)
                        elif update_type == "link_add":
                            self.added_link.append(task_id)
                        elif update_type == "link_delete":
                            self.deleted_link.append(task_id)
                        break

                    self.log(
                        "Current progress for task ID {}: {}".format(
                            task_id, task_details.get("progress")
                        ),
                        "DEBUG",
                    )

                    time.sleep(self.params.get("dnac_task_poll_interval", 30))

        return self

    def collect_logs(self):
        """
        Collects logs by calling the log-status API from device_onboarding_pnp.
        Returns:
            dict: Log entry if successful, otherwise an empty dict.
        Description:
            This method retrieves the log entries from the LAN automation process by invoking the
            corresponding API. If successful, it returns the log data; otherwise, it returns an
            empty dictionary. The logs can be useful for debugging and monitoring the state of
            the automation tasks.
        """
        try:
            response = self.dnac._exec(
                family="lan_automation",
                function="lan_automation_log",
                op_modifies=False,
            )
            if response:
                response_data = response.get("response", [])
                self.log(
                    "Received API response from 'lan_automation_log': {}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                if response_data:
                    return response_data[0]

            self.log("No response received for log status request.", "WARNING")
            return {}
        except Exception as e:
            self.log("Error retrieving log status: {}".format(str(e)), "WARNING")
            return {}

    def authorize_devices(self, device_serials):
        """
        Authorizes devices based on serial numbers either from device_serial_numbers or discovery_devices.
        Returns:
            list: A list of successfully authorized device serial numbers.
        Description:
            This method checks the state of devices corresponding to the provided serial numbers.
            If devices are in 'Pending Authorization' state, it attempts to authorize them. The method
            returns a list of successfully authorized devices or an empty list if some devices were not found.
        """

        self.log(
            "Retrieving device IDs for serial numbers: {}".format(device_serials),
            "DEBUG",
        )
        device_list_response = self.get_device_list(device_serials)

        if not device_list_response:
            self.log(
                "Failed to retrieve device list and information for authorization. Devices might have not onboarded "
                "on PnP yet.",
                "ERROR",
            )
            self.msg = "Error retrieving the device list for the given serial numbers."
            return []

        serial_to_id_map = {}
        device_ids = []

        for device in device_list_response:
            device_info = device.get("deviceInfo")
            if device_info:
                serial_number = device_info.get("serialNumber")
                device_id = device.get("id")
                state = device_info.get("state")

                self.log(
                    "Checking device: Serial Number: {}, State: {}".format(
                        serial_number, state
                    ),
                    "DEBUG",
                )

                if serial_number in device_serials:
                    if state == "Pending Authorization":
                        serial_to_id_map[serial_number] = device_id
                        device_ids.append(device_id)
                    else:
                        self.log(
                            "Device {} is NOT in Pending Authorization state; current state: {}".format(
                                serial_number, state
                            ),
                            "INFO",
                        )
                else:
                    self.log(
                        "Serial number {} is not in the provided device_serials list".format(
                            serial_number
                        ),
                        "INFO",
                    )

        self.log(
            "Serial to ID mapping for devices in 'Pending Authorization': {}".format(
                serial_to_id_map
            ),
            "DEBUG",
        )
        self.log(
            "Device IDs list for devices in 'Pending Authorization': {}".format(
                device_ids
            ),
            "DEBUG",
        )

        missing_serials = [
            serial for serial in device_serials if serial not in serial_to_id_map
        ]
        self.log(
            "This is missing serials for devices not found in PnP and/or are not in 'Pending Authorization': {}".format(
                missing_serials
            )
        )

        if missing_serials:
            self.log(
                "The following device serial numbers were not found in PnP onboarding page: {}".format(
                    missing_serials
                ),
                "WARNING",
            )

        if not device_ids:
            self.log(
                "No matching device IDs found for the provided serial numbers {}.".format(
                    device_serials
                ),
                "ERROR",
            )
            return []

        self.log(
            "Attempting to authorize devices with IDs: {}".format(device_ids), "DEBUG"
        )
        authorized_devices = self.authorize_pnp_devices(device_ids, serial_to_id_map)
        if not authorized_devices:
            self.log("Authorization failed for one or more devices", "ERROR")
            return []

        authorized_serials = [
            serial
            for serial, id in serial_to_id_map.items()
            if id in authorized_devices
        ]

        self.log(
            "The following devices were successfully authorized: {}".format(
                ", ".join(authorized_serials)
            ),
            "INFO",
        )
        return authorized_serials

    def authorize_pnp_devices(self, device_ids, serial_to_id_map):
        """
        Authorizes devices in PnP based on their device IDs.
        Args:
            device_ids (list): A list of device IDs to be authorized.
            serial_to_id_map (dict): A mapping of device serial numbers to their corresponding device IDs.
        Returns:
            list: A list of authorized device serial numbers.
        Description:
            This method sends a request to authorize devices in the Plug and Play (PnP) service using the provided
            device IDs. If the API call is successful and the status code indicates success, it returns the list
            of device IDs that were authorized. If there is an error during the authorization process, the method
            logs the error and returns an empty list. In case of an unsuccessful status code, the failure is logged,
            and an empty list is also returned.
        """

        self.log("Devices to be authorized: {}".format(device_ids))

        payload = {"deviceIdList": device_ids}
        try:
            response = self.dnac._exec(
                family="device_onboarding_pnp",
                function="authorize_device",
                op_modifies=True,
                params=payload,
            )
        except Exception as e:
            self.log(
                "Error occurred while authorizing devices: {}".format(str(e)), "ERROR"
            )
            return None

        if response:
            status_code = response.get("statusCode")
            if status_code is not None:
                if status_code == 200:
                    self.log(
                        "Authorization API call was successful as following: {}".format(
                            response
                        ),
                        "INFO",
                    )
                    return device_ids
                else:
                    self.log(
                        "Authorization API call failed with status code: {}".format(
                            status_code
                        ),
                        "ERROR",
                    )
                    return []
        else:
            self.log("No response received from the authorize_device API.", "ERROR")
            self.msg = "No response was received from device Authorization API."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return []

    def get_device_list(self, device_serial_numbers):
        """
        Retrieves device information based on a list of device serial numbers.
        Args:
            device_serial_numbers (list): A list of device serial numbers to retrieve information for.
        Returns:
            list: A list of device information if found; an empty list if not found or if an error occurs.
        Description:
            This method calls the device onboarding API to fetch information about devices using the provided
            serial numbers. If the API call is successful and returns valid data, it returns the list of device
            information. If there is an error or the response is invalid, the method logs the issue and returns
            an empty list.
        """

        self.log(
            "Initiating API call for device list: {}".format(device_serial_numbers)
        )
        try:
            response = self.dnac._exec(
                family="device_onboarding_pnp",
                function="get_device_list",
                params={"serial_number": device_serial_numbers},
                op_modifies=False,
            )
        except Exception as e:
            self.log(
                "Error retrieving device list for serial numbers '{}': {}".format(
                    device_serial_numbers, str(e)
                ),
                "WARNING",
            )
            return []

        self.log("Device List Response: {}".format(response))

        if isinstance(response, list) and response:
            return response

        self.log("Received empty or invalid response: {}".format(response), "WARNING")
        return []

    def start_lan_auto(self, lan_automation_params):
        """
        Initiates a LAN Automation session in Cisco Catalyst Center. It checks for pre-existing LAN automation sessions
        with the same primary device management IP address and starts a new session if no conflicts are found.
        Args:
            lan_automation_params (dict): A dictionary containing parameters for starting LAN automation.
        Returns:
            result (dict): A dictionary containing the result of the LAN automation initiation.
        Description:
            This method starts a new LAN automation session, ensuring that no other session is currently running
            for the same primary device management IP address. It prepares the necessary parameters for the
            LAN automation request and sends the initiation call to the appropriate API. If successful, it returns
            a result dictionary containing the task ID. In case of errors, it logs the errors, sets the operation
            result to failed, and returns an empty dictionary.
        """
        session_to_ip_mapping = self.have.get("session_to_ip_map", {})
        seed_ip_address = lan_automation_params.get("primaryDeviceManagmentIPAddress")
        self.log(
            "Current session to IP mapping: {}".format(session_to_ip_mapping), "DEBUG"
        )
        self.log("Seed IP address being checked: {}".format(seed_ip_address), "DEBUG")

        if session_to_ip_mapping and seed_ip_address in session_to_ip_mapping.values():
            self.no_lan_auto_start.append(seed_ip_address)
            self.msg = (
                "A LAN automation session is already running for the same seed IP address: {}. Hence, "
                "no update needed. ".format(seed_ip_address)
            )
            self.set_operation_result("success", False, self.msg, "INFO")
            self.check_return_status()

        self.log("Input parameters: {}".format(lan_automation_params), "DEBUG")

        included_keys = {
            "discoveredDeviceSiteNameHierarchy",
            "peerDeviceManagmentIPAddress",
            "primaryDeviceManagmentIPAddress",
            "primaryDeviceInterfaceNames",
            "ipPools",
            "multicastEnabled",
            "redistributeIsisToBgp",
            "hostNamePrefix",
            "isisDomainPwd",
            "discoveryLevel",
            "discoveryTimeout",
            "discoveryDevices",
        }

        lan_auto_params = {
            key: lan_automation_params[key]
            for key in included_keys
            if key in lan_automation_params
        }

        if lan_auto_params:
            self.log(
                "Starting LAN automation with the following parameters: {}".format(
                    lan_auto_params
                ),
                "DEBUG",
            )
        else:
            self.log("No valid parameters found for LAN automation.", "WARNING")

        self.log(
            "Starting LAN automation with parameters: {}".format(lan_auto_params),
            "DEBUG",
        )
        lan_auto_params_list = []
        lan_auto_params_list.append(lan_auto_params)

        self.log(
            "Sending request to start LAN Automation with payload: {}".format(
                lan_auto_params_list
            ),
            "DEBUG",
        )
        try:
            response = self.dnac_apply["exec"](
                family="lan_automation",
                function="lan_automation_start_v2",
                params={"payload": lan_auto_params_list},
                op_modifies=True,
            )

            self.log(
                "Response received for starting LAN Automation API call: {}".format(
                    response
                ),
                "DEBUG",
            )

            if response:
                self.result.update(dict(response=response["response"]))
                task_id = response["response"].get("taskId")
                self.log(
                    "Task ID for starting LAN Automation session is {}".format(task_id),
                    "DEBUG",
                )

                if task_id:
                    self.result["task_id"] = task_id

                return self.result

            self.msg = "No response received from the LAN Automation API call."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            self.check_return_status()
        except Exception as e:
            self.msg = "An error occurred while trying to start LAN Automation session. Error: {}".format(
                str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.set_operation_result("failed", False, self.msg, "CRITICAL")
            self.check_return_status()

        return self.result

    def get_diff_deleted(self):
        """
        Stops the LAN automation session in the Cisco Catalyst Center based on the provided configuration.
        Args:
            self (object): An instance of a class for interacting with the Cisco Catalyst Center.
            config (dict): A dictionary containing details for stopping the LAN automation session, including:
                - 'lan_automation': Dictionary with:
                    - 'primaryDeviceManagmentIPAddress': IP address of the primary device management.
        Returns:
            self (object): Returns the current instance of the class after attempting to stop the LAN automation session.
        Description:
            This method checks for an active LAN automation session for the given IP address. If found, it calls the
            Cisco Catalyst Center API to stop the session.
            It logs the outcome, indicating success or failure, and updates the internal state based on the API response.
        """

        port_channel = self.want.get("port_channel", {})
        if port_channel:
            self.log(
                f"Processing port channel configuration: {self.pprint(port_channel)}",
                "DEBUG",
            )
            self.get_diff_deleted_port_channel(port_channel).check_return_status()

        if not self.want.get("lan_automation"):
            self.log(
                "LAN automation configuration not found in 'want'. Exiting the method.",
                "INFO",
            )
            return self

        session_to_ip_mapping = self.have.get("session_to_ip_map", {})
        seed_ip_address = self.want.get("lan_automation").get(
            "primaryDeviceManagmentIPAddress"
        )
        self.log(
            "Current session to IP mapping: {}".format(session_to_ip_mapping), "DEBUG"
        )
        self.log(
            "Seed IP address for stopping LAN automation: {}".format(seed_ip_address),
            "DEBUG",
        )

        if not session_to_ip_mapping:
            self.msg = (
                "No LAN automation session is currently running. Please use state merged to start a "
                "new LAN Automation session."
            )
            self.no_lan_auto_stop.append(seed_ip_address)
            self.set_operation_result("success", False, self.msg, "INFO")
            return self

        session_id = next(
            (
                sid
                for sid, ip_address in session_to_ip_mapping.items()
                if ip_address == seed_ip_address
            ),
            None,
        )

        if not session_id:
            self.msg = "No active LAN automation session found for seed IP address: {0}.".format(
                seed_ip_address
            )
            self.log(self.msg)
            self.set_operation_result("failed", False, self.msg, "INFO")
            return self

        self.log(
            "LAN automation session is running for seed IP address: {0}, session ID: {1}.".format(
                seed_ip_address, session_id
            ),
            "INFO",
        )

        try:
            self.log(
                "Attempting to stop LAN automation session with ID: {}".format(
                    session_id
                ),
                "DEBUG",
            )
            response = self.dnac_apply["exec"](
                family="lan_automation",
                function="lan_automation_stop",
                params={"id": session_id},
                op_modifies=True,
            )

            self.log(
                "Response from 'lan_automation_stop' API: {0}".format(response), "DEBUG"
            )

            response_data = response.get("response", {})
            error_code = response_data.get("errorCode")
            message = response_data.get("message")
            detail = response_data.get("detail")

            if error_code:
                self.msg = "Error stopping LAN automation session: {0}. Details: {1} (Error Code: {2}) ".format(
                    message, detail, error_code
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
            else:
                self.check_stop_session(seed_ip_address, session_id)
                self.msg = "Successfully stopped LAN automation session with session ID: {0}.".format(
                    session_id
                )
                self.stopped_lan_automation.append(seed_ip_address)
                self.set_operation_result("success", True, self.msg, "INFO")

        except Exception as e:
            self.msg = "An error occurred while stopping the LAN automation session: {0}".format(
                str(e)
            )
            self.log(self.msg, "CRITICAL")
            self.set_operation_result("failed", False, self.msg, "CRITICAL")

        return self

    def process_link_deletion_in_port_channel(
        self, want_port_channel_config, have_port_channel_config
    ):
        """
        Processes the deletion of links in a port channel and determines whether the entire port channel
        or specific links need to be removed.

        Parameters:
            want_port_channel_config (dict): Desired port channel configuration specifying links to delete.
            have_port_channel_config (dict): Existing port channel configuration from which links will be removed.

        Returns:
            None: Updates internal state lists to reflect deletions or no-change scenarios.

        Description:
            - Compares desired links to delete against existing port channel links.
            - Determines if updates are required using `port_channel_config_needs_update`.
            - Logs debug and info messages at every step to provide detailed traceability.
            - Deletes the entire port channel if all links are being removed.
            - Deletes specific links if only a subset needs removal.
            - Updates `link_not_removed_from_port_channel` list if no changes are required.
        """

        self.log(
            "Starting port channel link deletion processing for specified configuration",
            "DEBUG",
        )
        self.log(
            f"Desired port channel configuration for link deletion: {self.pprint(want_port_channel_config)}",
            "DEBUG",
        )
        self.log(
            f"Existing port channel configuration for link deletion: {self.pprint(have_port_channel_config)}",
            "DEBUG",
        )
        want_links = want_port_channel_config.get("links", [])
        self.log(
            f"Links are provided in the configuration for deletion. Checking if updates are required. Links to be deleted: {self.pprint(want_links)}",
            "DEBUG",
        )

        needs_update, updated_port_channel_config = (
            self.port_channel_config_needs_update(
                want_port_channel_config, have_port_channel_config
            )
        )

        if needs_update:
            self.log("Port channel links need update.", "DEBUG")
            self.log(
                "Determining whether all links are being removed, which would result in full port channel deletion.",
                "DEBUG",
            )

            have_links_len = len(have_port_channel_config.get("links", []))
            deleted_links_len = len(updated_port_channel_config.get("links", []))

            if have_links_len == deleted_links_len:
                self.log(
                    "All links are being removed. Deleting the entire port channel.",
                    "DEBUG",
                )
                self.delete_lan_automated_port_channel(updated_port_channel_config)
            else:
                self.log(
                    f"Deleting specified links from the port channel. Links to remove: {self.pprint(updated_port_channel_config.get('links', []))}",
                    "INFO",
                )
                self.delete_lan_automated_link_from_a_port_channel(
                    updated_port_channel_config
                )
        else:
            self.log("Port channel links are up to date. No update needed.", "DEBUG")
            self.link_not_removed_from_port_channel.append(want_port_channel_config)

        self.log(
            f"Completed processing link deletion for port channel: {self.pprint(want_port_channel_config)}",
            "DEBUG",
        )
        return

    def process_delete_port_channel(self, have_port_channel_config):
        """
        Triggers the deletion of the port channel via API and logs the operation.

        Parameters:
            have_port_channel_config (dict): A dictionary containing the current port channel configuration details, including:
                - 'id' (str): The unique identifier of the port channel.
                - 'portChannelNumber' (int): The port channel number.
                - 'sourceDeviceManagementIPAddress' (str): IP address of the source device.
                - 'destinationDeviceManagementIPAddress' (str): IP address of the destination device.

        Returns:
            None

        Description:
            - Logs the current port channel configuration that is targeted for deletion.
            - Prepares the payload required for the deletion API call.
            - Calls `delete_lan_automated_port_channel` to delete the port channel.
            - Logs both the initiation and confirmation of the deletion process.
        """
        self.log(
            "Starting complete port channel deletion process for specified configuration",
            "DEBUG",
        )

        destination_device_management_ip = have_port_channel_config.get(
            "destinationDeviceManagementIPAddress"
        )
        source_device_management_ip = have_port_channel_config.get(
            "sourceDeviceManagementIPAddress"
        )
        port_channel_number = have_port_channel_config.get("portChannelNumber")
        self.log(
            f"Deleting port channel configuration: {self.pprint(have_port_channel_config)}",
            "DEBUG",
        )
        updated_port_channel_config = {
            "id": have_port_channel_config.get("id"),
            "portChannelNumber": port_channel_number,
            "destinationDeviceManagementIPAddress": destination_device_management_ip,
            "sourceDeviceManagementIPAddress": source_device_management_ip,
            "links": have_port_channel_config.get("links", []),
        }

        self.log(
            f"Constructed port channel deletion configuration: {self.pprint(updated_port_channel_config)}",
            "DEBUG",
        )
        self.log(
            f"Executing port channel deletion API call for port channel ID: {updated_port_channel_config.get('id')}",
            "DEBUG",
        )
        self.delete_lan_automated_port_channel(updated_port_channel_config)

    def delete_lan_automated_port_channel(self, port_channel_config):
        """
        Deletes a specific port channel from Cisco Catalyst Center using the provided configuration.

        Parameters:
            port_channel_config (dict): A dictionary containing the port channel details to be deleted, including:
                - 'id' (str): Unique identifier of the port channel.
                - 'sourceDeviceManagementIPAddress' (str): IP address of the source device.
                - 'destinationDeviceManagementIPAddress' (str): IP address of the destination device.

        Returns:
            self: Returns the current instance after initiating deletion and logging the result.

        Description:
            - Logs the port channel configuration that is about to be deleted.
            - Constructs the payload required for the deletion API call.
            - Calls the LAN automation API to delete the port channel and retrieves the task ID.
            - Raises an error if the task ID cannot be retrieved.
            - Waits for task completion and logs a success message upon deletion.
            - Updates the internal `port_channel_deleted` list to track deleted configurations.
        """

        self.log(
            f"Initiating deletion of port channel with configuration: {self.pprint(port_channel_config)}",
            "DEBUG",
        )

        source_device_management_ip = port_channel_config.get(
            "sourceDeviceManagementIPAddress"
        )
        destination_device_management_ip = port_channel_config.get(
            "destinationDeviceManagementIPAddress"
        )

        delete_port_channel_payload = {
            "id": port_channel_config.get("id"),
        }

        task_name = "delete_port_channel"
        self.log(
            f"Calling '{task_name}' API with payload: {self.pprint(delete_port_channel_payload)}",
            "DEBUG",
        )

        task_id = self.get_taskid_post_api_call(
            "lan_automation", task_name, delete_port_channel_payload
        )
        if not task_id:
            self.msg = f"Unable to retrieve the task_id for the task '{task_name}' for the port channel'."
            self.fail_and_exit(self.msg)

        success_msg = (
            f"Port channel between the source device '{source_device_management_ip}' and "
            f"destination device '{destination_device_management_ip}' deleted successfully."
        )
        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.port_channel_deleted.append(port_channel_config)
        return self

    def get_port_channel_details_by_id(self, port_channel_id):
        """
        Retrieve Port Channel configuration details by ID from Cisco Catalyst Center.

        Parameters:
            port_channel_id (str): Unique identifier of the port channel to retrieve.

        Returns:
            dict or None: Port Channel configuration dictionary if found, None if not found or error occurs.

        Description:
            Calls the Cisco Catalyst Center API to retrieve Port Channel configuration details
            using the port channel ID. The method handles API response validation, logs detailed
            information about the retrieval process, and returns None if no configuration is found
            or if an error occurs during the API call.
        """

        self.log(
            f"Initiating Port Channel retrieval by ID: '{port_channel_id}'",
            "INFO",
        )

        if not port_channel_id:
            self.log(
                "Port channel ID is required to fetch Port Channel configuration.",
                "ERROR",
            )
            return None

        try:
            self.log(
                f"Calling 'get_port_channel_information_by_id' API with ID: '{port_channel_id}'",
                "DEBUG",
            )
            response = self.dnac_apply["exec"](
                family="lan_automation",
                function="get_port_channel_information_by_id",
                params={"id": port_channel_id},
            )

            self.log(
                f"API call completed. Received API response from 'get_port_channel_information_by_id' "
                f"for Port Channel ID: '{port_channel_id}': {response}",
                "DEBUG",
            )

            if not response:
                self.msg = (
                    f"No port channel configuration retrieved for Port Channel ID: '{port_channel_id}'. "
                    f"Response is empty."
                )
                self.log(self.msg, "DEBUG")
                return None

            port_channel_info = response.get("response")

            if not port_channel_info:
                self.log(
                    f"No Port Channel configuration found for ID: '{port_channel_id}'.",
                    "DEBUG",
                )
                return None

            port_channel_info = port_channel_info[
                0
            ]  # Assuming the response is a list with one item
            self.log(
                f"Successfully retrieved Port Channel configuration for ID: '{port_channel_id}': "
                f"{self.pprint(port_channel_info)}",
                "INFO",
            )
            return port_channel_info

        except Exception as e:
            self.log(
                f"Error retrieving Port Channel configuration by ID '{port_channel_id}': {str(e)}",
                "ERROR",
            )
            return None

    def check_if_device_order_needs_swapping(self, port_channel_config):
        """
        Checks if the device order in the port channel configuration needs swapping by comparing
        with the actual port channel configuration from Cisco Catalyst Center.

        Parameters:
            port_channel_config (dict): Port channel configuration containing:
                - 'id' (str): Unique identifier of the port channel.
                - 'sourceDeviceManagementIPAddress' (str): IP address of the source device.
                - 'destinationDeviceManagementIPAddress' (str): IP address of the destination device.

        Returns:
            bool: True if swapping is required, False if device order matches.

        Description:
            - Extracts the port channel ID from the configuration.
            - Calls `get_port_channel_details_by_id` to fetch the actual configuration from Catalyst Center.
            - Compares the source device IP address from our config with device1 IP from Catalyst Center.
            - If they match, no swapping is required (returns False).
            - If they don't match, swapping is required (returns True).
            - Logs detailed information about the comparison process for traceability.
        """

        self.log(
            f"Checking if device order needs swapping for port channel configuration: {self.pprint(port_channel_config)}",
            "DEBUG",
        )

        port_channel_id = port_channel_config.get("id")
        if not port_channel_id:
            self.log(
                "Port channel ID not found in configuration. Cannot check device order.",
                "ERROR",
            )
            return False

        self.log(
            f"Retrieving port channel details from Catalyst Center using ID: '{port_channel_id}'",
            "DEBUG",
        )

        catc_config = self.get_port_channel_details_by_id(port_channel_id)

        if not catc_config:
            self.log(
                f"Failed to retrieve port channel configuration from Catalyst Center for ID: '{port_channel_id}'. "
                f"Assuming no swapping is required.",
                "WARNING",
            )
            return False

        # Extract source device IP from our configuration
        our_source_ip = port_channel_config.get("sourceDeviceManagementIPAddress")

        # Extract device1 and device2 IPs from Catalyst Center configuration
        catc_device1_ip = catc_config.get("device1ManagementIPAddress")
        catc_device2_ip = catc_config.get("device2ManagementIPAddress")

        self.log(
            f"Comparing device order - Our source IP: '{our_source_ip}', "
            f"Catalyst Center device1 IP: '{catc_device1_ip}', "
            f"Catalyst Center device2 IP: '{catc_device2_ip}'",
            "DEBUG",
        )

        if our_source_ip == catc_device1_ip:
            self.log(
                f"Source device IP {our_source_ip} matches Catalyst Center device1 IP {catc_device1_ip}. No swapping required.",
                "DEBUG",
            )
            return False

        if our_source_ip == catc_device2_ip:
            self.log(
                f"Source device IP {our_source_ip} matches Catalyst Center device2 IP {catc_device2_ip}. Swapping is required.",
                "INFO",
            )
            return True

        self.log(
            f"Source device IP '{our_source_ip}' does not match either device1 IP '{catc_device1_ip}' "
            f"or device2 IP '{catc_device2_ip}' from Catalyst Center configuration.",
            "ERROR",
        )
        self.msg = (
            f"Port channel configuration validation failed. Source device IP '{our_source_ip}' "
            f"does not match the port channel devices in Catalyst Center. "
            f"Port channel ID '{port_channel_id}' has devices: "
            f"device1='{catc_device1_ip}', device2='{catc_device2_ip}'. "
            f"Please verify the port channel configuration."
        )
        self.fail_and_exit(self.msg)

    def delete_lan_automated_link_from_a_port_channel(self, port_channel_config):
        """
        Deletes specific links from an existing port channel in Cisco Catalyst Center.

        Parameters:
            port_channel_config (dict): A dictionary containing the port channel details and links to delete, including:
                - 'id' (str): Unique identifier of the port channel.
                - 'sourceDeviceManagementIPAddress' (str): IP address of the source device.
                - 'destinationDeviceManagementIPAddress' (str): IP address of the destination device.
                - 'links' (list[dict]): List of dictionaries containing links to be removed. Each dictionary should have:
                    - 'sourcePort' (str): Source interface in the port channel.
                    - 'destinationPort' (str): Destination interface in the port channel.

        Returns:
            self: Returns the current instance after initiating link deletion and logging the result.

        Description:
            - Logs the port channel and link configuration that is about to be deleted.
            - Constructs the payload required for the API call to remove links from the port channel.
            - Calls the LAN automation API and retrieves the task ID for the deletion operation.
            - Raises an error if the task ID cannot be retrieved.
            - Waits for task completion and logs a success message upon deletion.
            - Updates the internal `link_removed_from_port_channel` list to track deleted links.
        """

        source_device_management_ip = port_channel_config.get(
            "sourceDeviceManagementIPAddress"
        )
        destination_device_management_ip = port_channel_config.get(
            "destinationDeviceManagementIPAddress"
        )

        self.log(
            f"Initiating deletion of links from port channel between source device: '{source_device_management_ip}' "
            f"and destination device: '{destination_device_management_ip}",
            "DEBUG",
        )

        delete_link_payload = {
            "id": port_channel_config.get("id"),
            "portChannelMembers": [
                {
                    "device1Interface": link.get("sourcePort"),
                    "device2Interface": link.get("destinationPort"),
                }
                for link in port_channel_config.get("links", [])
            ],
        }

        self.log(
            f"Initial delete link payload before device order check: {self.pprint(delete_link_payload)}",
            "DEBUG",
        )
        # This section is required due to the Catalyst Center API design.
        # The get_port_channel API doesn't provide the exact device order
        # as it was originally created. However, the remove and add APIs
        # expect the interface details in the exact order.
        if self.check_if_device_order_needs_swapping(port_channel_config):
            self.log(
                "Device order swapping is required. Swapping device1Interface and device2Interface in all port channel members.",
                "INFO",
            )
            for member in delete_link_payload["portChannelMembers"]:
                original_device1 = member["device1Interface"]
                original_device2 = member["device2Interface"]
                member["device1Interface"], member["device2Interface"] = (
                    member["device2Interface"],
                    member["device1Interface"],
                )
                self.log(
                    f"Swapped interfaces - Original: device1Interface='{original_device1}', device2Interface='{original_device2}' "
                    f"-> Swapped: device1Interface='{member['device1Interface']}', device2Interface='{member['device2Interface']}'",
                    "DEBUG",
                )

            self.log(
                f"Device order swapping completed. Updated payload: {self.pprint(delete_link_payload)}",
                "DEBUG",
            )
        else:
            self.log(
                "Device order matches Catalyst Center configuration. No swapping required.",
                "DEBUG",
            )
        task_name = "remove_a_link_from_port_channel"

        self.log(
            f"Calling '{task_name}' API with payload: {self.pprint(delete_link_payload)}",
            "DEBUG",
        )
        task_id = self.get_taskid_post_api_call(
            "lan_automation", task_name, delete_link_payload
        )
        if not task_id:
            self.msg = f"Unable to retrieve the task_id for the task '{task_name}' for the port channel'."
            self.fail_and_exit(self.msg)

        success_msg = (
            f"Links from port channel between the source device '{source_device_management_ip}' "
            f"and destination device '{destination_device_management_ip}' deleted successfully."
        )

        self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
        self.link_removed_from_port_channel.append(port_channel_config)
        return self

    def get_diff_deleted_port_channel(self, port_channel):
        """
        Processes port channel configurations in the 'deleted' state and deletes port channels or specific links
        from existing port channels in Cisco Catalyst Center as necessary.

        Parameters:
            port_channel (list[dict]): A list of port channel configurations to process for deletion. Each dictionary
            can include:
                - 'sourceDeviceManagementIPAddress' (str): IP address of the source device.
                - 'destinationDeviceManagementIPAddress' (str): IP address of the destination device.
                - 'portChannelNumber' (str/int): Port channel number.
                - 'links' (list[dict]): List of links to delete, where each dictionary contains:
                    - 'sourcePort' (str): Source interface.
                    - 'destinationPort' (str): Destination interface.

        Returns:
            self: Returns the current instance after processing deletions and logging results.

        Description:
            - Iterates through each port channel configuration provided in the 'deleted' state.
            - Checks if an existing port channel configuration is present in `self.have`.
            - If no existing configuration is found, logs the information and marks no deletion required.
            - If links are specified, deletes only the specified links using `process_link_deletion_in_port_channel`.
            - If only a port channel number is provided without specific links, deletes the entire port channel using `process_delete_port_channel`.
            - If only destination device IP is provided, deletes all port channels between the source and destination device.
            - If only source device IP is provided, deletes all port channels associated with the source device.
            - Maintains detailed DEBUG logs for all decisions and actions taken.
            - Updates internal tracking lists like `no_port_channel_deleted` as applicable.
        """

        self.log(
            f"Processing port channel configurations in deleted state: {self.pprint(port_channel)}",
            "INFO",
        )

        for i, want_port_channel_config in enumerate(port_channel):
            self.log(
                f"Processing port channel configuration at '{i}' index: {self.pprint(want_port_channel_config)}",
                "DEBUG",
            )

            have_port_channel_config_list = self.have.get("port_channel")[i]
            self.log(
                f"Corresponding existing port channel configurations at '{i}' index: {self.pprint(have_port_channel_config_list)}",
                "DEBUG",
            )

            if not have_port_channel_config_list:
                self.log(
                    "No existing port channel configuration found. No operations required.",
                    "DEBUG",
                )
                self.no_port_channel_deleted.append(want_port_channel_config)
                continue

            self.log(
                "Existing port channel configuration found. Checking for updates.",
                "DEBUG",
            )
            source_device_management_ip = want_port_channel_config.get(
                "sourceDeviceManagementIPAddress"
            )
            destination_device_management_ip = want_port_channel_config.get(
                "destinationDeviceManagementIPAddress"
            )
            links = want_port_channel_config.get("links")
            port_channel_number = want_port_channel_config.get("portChannelNumber")

            if links:
                self.log(
                    f"Links are provided in the configuration for deletion. "
                    f"Processing link deletion for source device '{source_device_management_ip}' "
                    f"and destination device '{destination_device_management_ip}'. Links: {self.pprint(links)}",
                    "DEBUG",
                )
                have_port_channel_config = have_port_channel_config_list[0]
                self.process_link_deletion_in_port_channel(
                    want_port_channel_config, have_port_channel_config
                )
            elif port_channel_number:
                self.log(
                    f"Port channel number is provided: '{port_channel_number}'. Deleting the entire port channel.",
                    "DEBUG",
                )
                have_port_channel_config = have_port_channel_config_list[0]
                self.process_delete_port_channel(have_port_channel_config)
            elif destination_device_management_ip:
                self.log(
                    "Source and Destination device management IP is provided without specific links or port channel number. "
                    f"Deleting all the port channel between the source device: '{source_device_management_ip}' "
                    f"and destination device: '{destination_device_management_ip}'.",
                    "DEBUG",
                )
                for have_port_channel_config in have_port_channel_config_list:
                    self.process_delete_port_channel(have_port_channel_config)
            else:
                self.log(
                    f"No links, port channel number, or destination device provided. "
                    f"Deleting all port channels associated with source device '{source_device_management_ip}'",
                    "DEBUG",
                )
                for have_port_channel_config in have_port_channel_config_list:
                    self.process_delete_port_channel(have_port_channel_config)

        self.log("Completed processing all port channel deletions.", "INFO")
        return self

    def check_stop_session(self, seed_ip_address, session_id, max_wait_time=1800):
        """
        Periodically checks if the LAN Automation session has been stopped.
        Args:
            seed_ip_address (str): Seed device management IP address.
            session_id (str): ID of the session to check for activity.
            max_wait_time (int): Maximum wait time in seconds (default is 1800).
        Returns:
            self: The current instance of the class, with updated status and messages.
        Description:
            This method polls the Cisco Catalyst Center to verify if the specified LAN automation session is still active.
            If the session is found to be stopped, it logs a success message and updates the operation result.
            If the session remains active beyond the specified wait time, it logs a timeout message and updates the
            operation result accordingly.
        """
        end_time = time.time() + max_wait_time
        self.log(
            "Starting to check if the LAN automation session is stopped for seed IP '{0}' with session ID '{1}'.".format(
                seed_ip_address, session_id
            ),
            "DEBUG",
        )

        while time.time() < end_time:
            self.get_have(self.want)
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")

            active_session_ids = self.have.get("activeSessionIds", [])
            self.log("Active session IDs: {0}".format(active_session_ids), "DEBUG")

            if session_id not in active_session_ids:
                self.status = "success"
                self.msg = "The LAN automation session for seed IP '{0}' has been successfully stopped.".format(
                    seed_ip_address
                )
                self.set_operation_result(
                    "success", True, self.msg, "INFO"
                ).check_return_status()
                return self

            self.log(
                "LAN automation session for seed IP '{0}' is still running. Checking again in "
                "{1} seconds...".format(
                    seed_ip_address, self.params.get("dnac_task_poll_interval")
                ),
                "INFO",
            )

            time.sleep(self.params.get("dnac_task_poll_interval"))

        self.status = "failed"
        self.msg = (
            "Timeout reached (~30 minutes). Unable to verify that the LAN automation session for seed IP '{0}' "
            "has been completely stopped. Please monitor through the Cisco Catalyst Center UI.".format(
                seed_ip_address
            )
        )
        self.set_operation_result("failed", False, self.msg, "CRITICAL")
        return self

    def verify_diff_deleted_port_channel(self, port_channel):
        """
        Verifies that port channel configurations in deleted state have been properly removed.

        Parameters:
            port_channel (list[dict]): List of port channel configurations intended for deletion.
                Each dict may contain:
                    - sourceDeviceManagementIPAddress (str): Source device IP.
                    - destinationDeviceManagementIPAddress (str): Destination device IP.
                    - portChannelNumber (str/int): Port channel number.
                    - links (list[dict]): Links associated with the port channel.

        Returns:
            self: Logs verification results and raises errors if deletions were not applied as expected.

        Description:
            - Logs the verification start and end at INFO level.
            - For each port channel configuration:
                - DEBUG logs the configuration and the existing state.
                - Checks if links, port channel number, or destination IP are provided and verifies deletions accordingly.
                - Raises an error if expected deletions were not applied.
                - Updates internal verification status and ensures traceability.
            - Ensures every branch of verification has logging to trace the decision process and results.
        """
        self.log(
            f"Verifying port channel configurations in deleted state: {self.pprint(port_channel)}",
            "INFO",
        )

        for i, want_port_channel_config in enumerate(port_channel):
            self.log(
                f"Verifying port channel configuration at '{i}' index: {self.pprint(want_port_channel_config)}",
                "DEBUG",
            )

            have_port_channel_config_list = self.have.get("port_channel")[i]
            self.log(
                f"Corresponding existing port channel configurations at '{i}' index: {self.pprint(have_port_channel_config_list)}",
                "DEBUG",
            )

            if not have_port_channel_config_list:
                self.log(
                    "No existing port channel configuration found. Verification passed.",
                    "DEBUG",
                )
                continue

            self.log(
                "Existing port channel configuration found. Verifying if deletions were applied correctly.",
                "DEBUG",
            )
            source_device_management_ip = want_port_channel_config.get(
                "sourceDeviceManagementIPAddress"
            )
            destination_device_management_ip = want_port_channel_config.get(
                "destinationDeviceManagementIPAddress"
            )
            links = want_port_channel_config.get("links")
            port_channel_number = want_port_channel_config.get("portChannelNumber")

            if links:
                self.log(
                    "Links were provided in the configuration for deletion. Verifying if links were properly removed.",
                    "DEBUG",
                )
                have_port_channel_config = have_port_channel_config_list[0]
                needs_update, updated_port_channel_config = (
                    self.port_channel_config_needs_update(
                        want_port_channel_config, have_port_channel_config
                    )
                )
                if needs_update:
                    self.msg = (
                        f"Port channel verification failed at index '{i}'. "
                        f"Links that should have been deleted are still present: {self.pprint(have_port_channel_config.get('links'))}"
                    )
                    self.fail_and_exit(self.msg)
                else:
                    self.log(
                        "Port channel link deletion verification passed. Links were properly removed.",
                        "DEBUG",
                    )
            elif port_channel_number:
                self.log(
                    f"Port channel number provided: '{port_channel_number}'. Verifying deletion.",
                    "DEBUG",
                )
                self.msg = (
                    f"Port channel verification failed at index '{i}'. Port channel with number '{port_channel_number}' should "
                    f"have been deleted but still exists. Source IP: '{source_device_management_ip}', "
                    f"Destination IP: '{destination_device_management_ip}', Existing details: {self.pprint(have_port_channel_config_list)}"
                )
                self.fail_and_exit(self.msg)
                # Since have_port_channel_config_list is not empty, the port channel still exists and deletion failed

            elif destination_device_management_ip:
                self.log(
                    f"Destination device IP provided: '{destination_device_management_ip}'. Verifying deletion of all port channels between "
                    f"source '{source_device_management_ip}' and destination '{destination_device_management_ip}'.",
                    "DEBUG",
                )
                self.msg = (
                    f"Port channel verification failed at index '{i}'. Port channels between source device '{source_device_management_ip}' "
                    f"and destination device '{destination_device_management_ip}' should "
                    f"have been deleted but still exist: {self.pprint(have_port_channel_config_list)}"
                )
                self.fail_and_exit(self.msg)
                # If we reach here, have_port_channel_config_list is not empty, so deletion failed
            else:
                self.log(
                    f"No specific links, port channel number, or destination device provided. "
                    f"Verifying deletion of all port channels from source device '{source_device_management_ip}'.",
                    "DEBUG",
                )
                self.msg = (
                    f"Port channel verification failed at index '{i}'. Port channels from source device '{source_device_management_ip}' "
                    f"should have been deleted but still exist: {self.pprint(have_port_channel_config_list)}"
                )
                self.fail_and_exit(self.msg)
                # If we still have any port channel configs from this source device, deletion failed

        self.log("Completed verification of all port channel deletions.", "INFO")
        return self

    def verify_diff_deleted(self, config):
        """
        Verifies the presence of an active LAN Automation session for the specified seed IP address in Cisco Catalyst
        Center and checks the deletion status of port channels.

        Args:
            config (dict): Configuration details to be verified.

        Returns:
            self: The current instance of the class used for interacting with Cisco Catalyst Center.

        Description:
            - Checks for an active LAN automation session associated with the primary device management IP address.
            Logs the session ID if found, otherwise logs that no session is active for the specified seed IP.
            - Verifies the deletion of port channels if port channel configuration is present in the requested configuration.
            Logs details of verification for traceability and raises errors if deletions were not applied as expected.
        """

        self.get_have(config)
        self.log(f"Current State (have): {self.pprint(self.have)}", "INFO")

        port_channel = self.want.get("port_channel", {})
        if port_channel:
            self.log(
                f"Verifying port channel deletion in deleted state: {self.pprint(port_channel)}",
                "DEBUG",
            )
            self.verify_diff_deleted_port_channel(port_channel).check_return_status()

        if not self.want.get("lan_automated_device_update"):
            self.log(
                "LAN automated device update is not requested. Exiting verification.",
                "DEBUG",
            )
            return self

        seed_ip_address = self.want.get("lan_automation").get(
            "primaryDeviceManagmentIPAddress"
        )
        self.log(
            "Verifying active LAN automation session for seed IP: {}".format(
                seed_ip_address
            ),
            "DEBUG",
        )

        session_to_ip_mapping = self.have.get("session_to_ip_map", {})
        self.log("Session to IP mapping: {}".format(session_to_ip_mapping), "DEBUG")

        session_id = None
        for sid, ip in session_to_ip_mapping.items():
            if ip == seed_ip_address:
                session_id = sid
                break

        if not session_id:
            self.msg = (
                "No active LAN automation session found for seed IP '{}'.".format(
                    seed_ip_address
                )
            )
            self.log(self.msg)
        else:
            self.msg = "Active LAN automation session found for seed IP '{}', session ID: {}.".format(
                seed_ip_address, session_id
            )

            self.log(self.msg)

        return self


def main():
    """
    main entry point for module execution
    """

    # Define the specification for the module's arguments
    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_log": {"type": "bool", "default": False},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 604800},
        "dnac_task_poll_interval": {"type": "int", "default": 30},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_lan_automation = LanAutomation(module)

    state = ccc_lan_automation.params.get("state")

    if (
        ccc_lan_automation.compare_dnac_versions(
            ccc_lan_automation.get_ccc_version(), "2.3.7.6"
        )
        < 0
    ):
        ccc_lan_automation.msg = (
            "The specified version '{}' does not support LAN Automation workflow feature. Supported versions start "
            "from '2.3.7.6' onwards. Version '2.3.7.6' introduces new APIs which support optional auto-stop processing"
            " feature based on the provided timeout or a specific device list, or both.".format(
                ccc_lan_automation.get_ccc_version()
            )
        )
        ccc_lan_automation.status = "failed"
        ccc_lan_automation.check_return_status()

    if state not in ccc_lan_automation.supported_states:
        ccc_lan_automation.status = "invalid"
        ccc_lan_automation.msg = "State {0} is invalid".format(state)
        ccc_lan_automation.check_return_status()

    ccc_lan_automation.validate_input().check_return_status()
    config_verify = ccc_lan_automation.params.get("config_verify")

    for config in ccc_lan_automation.validated_config:
        ccc_lan_automation.reset_values()
        ccc_lan_automation.get_want(config).check_return_status()
        ccc_lan_automation.get_have(config).check_return_status()
        ccc_lan_automation.get_diff_state_apply[state]().check_return_status()
        if config_verify:
            ccc_lan_automation.verify_diff_state_apply[state](
                config
            ).check_return_status()

    ccc_lan_automation.update_lan_auto_messages().check_return_status()

    module.exit_json(**ccc_lan_automation.result)


if __name__ == "__main__":
    main()
