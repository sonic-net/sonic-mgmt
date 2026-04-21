#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to perform operations on SDA fabric devices in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["Muthu Rakesh, Madhan Sankaranarayanan, Archit Soni"]
DOCUMENTATION = r"""
---
module: sda_fabric_devices_workflow_manager
short_description: Manage SDA fabric devices in Cisco
  Catalyst Center.
description:
  - Perform operations on SDA fabric devices, including adding, updating, and deleting
    fabric devices.
  - Manage L2 handoffs for fabric devices, including adding and deleting configurations.
  - Manage L3 handoffs for fabric devices with IP transit, including adding, updating,
    and deleting configurations.
  - Manage L3 handoffs for fabric devices with SDA transit, including adding, updating,
    and deleting configurations.
  - Configure wireless controller settings on fabric devices, including enabling/disabling
    wireless mode, managing AP location scopes, setting rolling AP upgrade behavior,
    and optionally reloading the device for cleanup.
version_added: '6.21.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Muthu Rakesh (@MUTHU-RAKESH-27) Madhan Sankaranarayanan (@madhansansel) Archit Soni (@koderchit)
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
    choices: [merged, deleted]
    default: merged
  config:
    description:
      - A list of SDA fabric device configurations associated
        with fabric sites.
      - Each entry in the list represents the configurations
        for devices within a fabric site.
    type: list
    elements: dict
    required: true
    suboptions:
      fabric_devices:
        description: Configuration details for SDA fabric
          devices associated with a fabric site.
        type: dict
        suboptions:
          fabric_name:
            description:
              - Name of the SDA fabric site.
              - Mandatory parameter for all operations
                under fabric_devices.
              - The fabric site must already be created
                before configuring devices.
              - A Fabric Site is composed of networking
                devices operating in SD-Access Fabric
                roles.
              - A fabric site consists of networking
                devices in SD-Access Fabric roles, including
                Border Nodes, Control Plane Nodes, and
                Edge Nodes.
              - A Fabric sites may also include Fabric
                Wireless LAN Controllers and Fabric
                Wireless Access Points.
            type: str
            required: true
          device_config:
            description: A list of devices with their
              respective border settings, L2 handoff,
              L3 handoff with SDA transit, and L3 handoff
              with IP transit.
            type: list
            elements: dict
            required: true
            suboptions:
              device_ip:
                description:
                  - IP address of the device to be added
                    to the fabric site.
                  - Mandatory parameter for all operations
                    under fabric_devices.
                  - Device must be provisioned to the
                    site prior to configuration.
                  - For deleting a device, the device
                    will be deleted if the user doesnot
                    pass the layer3_handoff_ip_transit,
                    layer3_handoff_sda_transit and layer2_handoff
                    with the state as deleted.
                type: str
                required: true
              device_roles:
                description:
                  - Specifies the role(s) of the device
                    within the fabric site.
                  - This parameter is required when
                    adding the device to the fabric
                    site.
                  - The device roles cannot be updated
                    once assigned.
                  - At least one device must be a CONTROL_PLANE_NODE
                    to assign roles to other devices.
                  - An EDGE_NODE in a fabric cannot
                    be a CONTROL_PLANE_NODE.
                  - The device role [CONTROL_PLANE_NODE,
                    EDGE_NODE] is not allowed.
                  - Available roles, - CONTROL_PLANE_NODE
                    - Manages the mapping of endpoint
                    IP addresses to their location within
                    the network using LISP, enabling
                    mobility. - EDGE_NODE - Connects
                    endpoints to the SDA network, handling
                    policy enforcement, segmentation,
                    and communication with the control
                    plane. - BORDER_NODE - Acts as the
                    gateway between the fabric and external
                    networks, managing traffic entering
                    or exiting the SDA environment.
                    - WIRELESS_CONTROLLER_NODE - Manages
                    and controls wireless access points
                    and devices within the network.
                  - For 'WIRELESS_CONTROLLER_NODE',
                    the check for the provisioning status
                    will be added in 2.3.7.6 SDK.
                choices: [CONTROL_PLANE_NODE, EDGE_NODE,
                  BORDER_NODE, WIRELESS_CONTROLLER_NODE]
                type: list
                elements: str
              wireless_controller_settings:
                description: >
                  Dictionary containing wireless controller configurations to be applied to a network switch
                  in a Cisco Catalyst Center SDA fabric. This includes enabling/disabling wireless mode,
                  configuring primary and secondary managed AP locations, setting rolling AP upgrade behavior, and optionally
                  reloading the device after disabling the wireless capabilities on the controller.
                type: dict
                suboptions:
                  enable:
                    description: >
                      Boolean flag indicating whether wireless controller mode should be enabled (`true`)
                      or disabled (`false`) on the switch.
                    type: bool
                  reload:
                    description: >
                      Boolean flag that triggers a reload of the switch when set to `true` and wireless
                      capabilities are being disabled. The reload ensures cleanup of controller-related configurations.
                    type: bool
                    default: false
                  primary_managed_ap_locations:
                    description: >
                      List of strings representing the site hierarchy paths (e.g., "Global/Area/Site")
                      where the switch is configured as the primary AP controller.
                    type: list
                    elements: str
                  secondary_managed_ap_locations:
                    description: >
                      List of strings representing the site hierarchy paths (e.g., "Global/Area/Site1")
                      where the switch is configured as a secondary AP controller.
                    type: list
                    elements: str
                  rolling_ap_upgrade:
                    description: >
                      Dictionary for configuring rolling AP upgrade settings. These settings define
                      how APs reboot during a firmware upgrade to minimize service disruption.
                    type: dict
                    suboptions:
                      enable:
                        description: >
                          Boolean flag indicating whether rolling AP upgrades should be enabled for the switch.
                          This helps ensure that not all APs reboot simultaneously during upgrades.
                        type: bool
                      ap_reboot_percentage:
                        description: >
                          Integer value specifying the percentage of APs that are allowed to reboot
                          at once during a rolling upgrade. This setting applies only when rolling AP upgrades are enabled.
                        type: int
                        choices: [5, 15, 25]
              borders_settings:
                description:
                  - Effective only when the 'device_roles'
                    contains BORDER_NODE.
                  - This parameter is required when
                    adding the device to a fabric site
                    with the `BORDER_NODE` role.
                  - Updates to `borders_settings` are
                    allowed after the initial configuration.
                  - Border type can be Layer2 or Layer3.
                  - Border type can be Layer2 or Layer3,
                    identified based on the presence
                    of L2 Handoff or L3 Handoff with
                    IP or SDA transit.
                type: dict
                suboptions:
                  layer3_settings:
                    description: Configures a device
                      with a Layer3 border type.
                    type: list
                    elements: dict
                    suboptions:
                      local_autonomous_system_number:
                        description:
                          - Identifies the local autonomous
                            system in BGP routing.
                          - This parameter is required
                            when adding a device with
                            the `BORDER_NODE` role.
                          - The `local_autonomous_system_number`
                            cannot be updated once set.
                          - Acceptable range is from
                            1 to 4,294,967,295.
                          - Dot notation (1.0 to 65535.65535)
                            is also allowed. For example,
                            65534.65535.
                        type: str
                      is_default_exit:
                        description:
                          - Indicates whether this Border
                            Node serves as the default
                            gateway for traffic exiting
                            the virtual network.
                          - The `is_default_exit` cannot
                            be updated.
                        type: bool
                        default: true
                      import_external_routes:
                        description:
                          - Determines whether routes
                            from external networks are
                            imported into the fabric.
                          - Enhances security by limiting
                            route usage to internal
                            routes.
                          - The 'import_external_routes'
                            cannot be updated.
                        type: bool
                        default: true
                      border_priority:
                        description:
                          - Sets the preference level
                            for this Border Node when
                            multiple border nodes are
                            present.
                          - Higher-priority nodes are
                            favored for routing traffic
                            to external networks.
                          - Acceptable range is from
                            1 to 9. If not set, the
                            default value is 10.
                          - This parameter can be updated.
                        type: int
                        default: 10
                      prepend_autonomous_system_count:
                        description:
                          - Increases the AS path length
                            artificially when advertising
                            routes via BGP.
                          - It makes the route less
                            attractive to external peers.
                          - Acceptable range is from
                            1 to 10. If not set, the
                            default value is 0.
                          - This parameter can be updated.
                        type: int
                        default: 0
                  layer3_handoff_ip_transit:
                    description:
                      - Adds layer 3 handoffs with ip
                        transit in fabric devices.
                      - Configured when IP traffic is
                        routed from the SDA fabric to
                        external networks.
                      - If 'layer3_handoff_ip_transit'
                        is set, border type will be
                        considered as Layer3.
                    type: list
                    elements: dict
                    suboptions:
                      transit_network_name:
                        description:
                          - Network that connects multiple
                            SDA fabrics or networks.
                          - Required for all operations
                            in L3 Handoff with IP transit.
                          - It is not possible to update
                            `transit_network_name` after
                            initial configuration.
                        type: str
                      interface_name:
                        description:
                          - Refers to the specific network
                            interface in the border
                            device.
                          - This parameter is required
                            for all operations in L3
                            Handoff with IP transit.
                          - This parameter cannot be
                            updated after being set.
                        type: str
                      external_connectivity_ip_pool_name:
                        description:
                          - Denotes the IP address range
                            allocated for communication
                            between the SDA fabric and
                            external networks.
                          - This parameter is required
                            for adding the L3 Handoff
                            with IP transit.
                          - The IP pool must be reserved
                            in the fabric site.
                          - If `external_connectivity_ip_pool_name`
                            is specified, there is no
                            need to set the local and
                            remote addresses.
                          - Specifying `external_connectivity_ip_pool_name`
                            will automatically configure
                            the local and remote addresses.
                          - If both are set, `external_connectivity_ip_pool_name`
                            takes precedence.
                          - Updating IP addresses is
                            not permitted.
                        type: str
                      virtual_network_name:
                        description:
                          - Refers to the logical segmentation
                            of the network, grouping
                            devices into isolated virtual
                            networks.
                          - Either `virtual_network_name`
                            or `vlan_id` is required
                            for all operations in L3
                            Handoff with IP transit.
                        type: str
                      vlan_id:
                        description:
                          - Unique identifier assigned
                            to a Virtual Local Area
                            Network (VLAN).
                          - Should be unique across
                            the entire fabric site settings.
                          - The 'vlan_id' can range
                            from 1 to 4094, excluding
                            1, 1002-1005, 2046, and
                            4094.
                          - Either `virtual_network_name`
                            or `vlan_id` is required
                            for all operations in L3
                            Handoff with IP transit.
                          - This parameter cannot be
                            updated once set.
                        type: int
                      tcp_mss_adjustment:
                        description:
                          - Allows the modification
                            of the Maximum Segment Size
                            in TCP packets.
                          - The 'tcp_mss_adjustment'
                            can be set from 500 to 1440.
                          - This parameter can be updated
                            after being initially set.
                        type: int
                      local_ip_address:
                        description:
                          - IP address assigned to a
                            device's interface within
                            the fabric.
                          - The 'local_ip_address' is
                            for IPv4.
                          - Both 'local_ip_address'
                            and 'remote_ip_address'
                            must fall within the same
                            subnet.
                          - Either local and remote
                            addresses or `external_connectivity_ip_pool_name`
                            is required.
                          - If local and remote addresses
                            are provided with 'external_connectivity_ip_pool_name',
                            `external_connectivity_ip_pool_name`
                            takes precedence.
                        type: str
                      remote_ip_address:
                        description:
                          - IP address of a device located
                            outside the fabric network,
                            often used for BGP peering.
                          - The 'remote_ip_address'
                            is for IPv4.
                          - Both 'local_ip_address'
                            and 'remote_ip_address'
                            must fall within the same
                            subnet.
                          - Either local and remote
                            addresses or `external_connectivity_ip_pool_name`
                            is required.
                          - If local and remote addresses
                            are provided with 'external_connectivity_ip_pool_name',
                            `external_connectivity_ip_pool_name`
                            takes precedence.
                        type: str
                      local_ipv6_address:
                        description:
                          - IP address assigned to a
                            device's interface within
                            the fabric.
                          - The local_ipv6_address is
                            for IPv6.
                          - Both 'local_ipv6_address'
                            and 'remote_ipv6_address'
                            must fall within the same
                            subnet.
                          - If 'remote_ipv6_address'
                            is provided, then 'local_ipv6_address'
                            is required.
                          - If local and remote addresses
                            are provided with 'external_connectivity_ip_pool_name',
                            `external_connectivity_ip_pool_name`
                            takes precedence.
                        type: str
                      remote_ipv6_address:
                        description:
                          - IP address of a device located
                            outside the fabric network,
                            often used for BGP peering.
                          - The 'remote_ipv6_address'
                            is for IPv6.
                          - Both 'local_ipv6_address'
                            and 'remote_ipv6_address'
                            must fall within the same
                            subnet.
                          - If 'local_ipv6_address'
                            is provided, then 'remote_ipv6_address'
                            is required.
                          - If local and remote addresses
                            are provided with 'external_connectivity_ip_pool_name',
                            `external_connectivity_ip_pool_name`
                            takes precedence.
                        type: str
                  layer3_handoff_sda_transit:
                    description:
                      - Adds layer 3 handoffs with SDA
                        transit in fabric devices.
                      - Configured when routing traffic
                        is routed from the SDA fabric
                        to external networks.
                      - If 'layer3_handoff_sda_transit'
                        is set, border type will be
                        considered as Layer3.
                    type: dict
                    suboptions:
                      transit_network_name:
                        description:
                          - Network that connects multiple
                            SDA fabrics or networks.
                          - This parameter is required
                            for all operations in L3
                            Handoff with SDA transit.
                          - The transit_network_name
                            cannot be updated.
                        type: str
                      affinity_id_prime:
                        description:
                          - It supersedes the border
                            priority to determine border
                            node preference.
                          - The lower the relative value
                            of 'affinity_id_prime',
                            the higher the preference.
                          - Resources with the same
                            affinity ID are treated
                            similarly and affinity_id_decider
                            decides the priority.
                          - The 'affinity_id_prime'
                            ranges from 0 to 2147483647.
                          - The 'affinity_id_prime'
                            can be updated.
                        type: int
                      affinity_id_decider:
                        description:
                          - If the 'affinity_id_prime'
                            value is the same, the 'affinity_id_decider'
                            value is used as a tiebreaker.
                          - The lower the relative value
                            of 'affinity_id_decider',
                            the higher the preference.
                          - The 'affinity_id_decider'
                            ranges from 0 to 2147483647.
                          - The 'affinity_id_decider'
                            can be updated.
                        type: int
                      connected_to_internet:
                        description:
                          - Set this true to allow associated
                            site to provide internet
                            access to other sites through
                            SDA.
                          - Default value is false.
                          - This parameter can be updated.
                        type: bool
                        default: false
                      is_multicast_over_transit_enabled:
                        description:
                          - Set this true to configure
                            native multicast over multiple
                            sites that are connected
                            to an SDA transit.
                          - Default value is false.
                          - This parameter can be updated.
                        type: bool
                        default: false
                  layer2_handoff:
                    description:
                      - Adds layer 2 handoffs in fabric
                        devices.
                      - This parameter cannots be updated.
                      - Configured while transferring
                        a device's data traffic at Layer
                        2 (Data Link layer).
                      - If 'layer2_handoff' is set,
                        the border type will be considered
                        as Layer2.
                    type: list
                    elements: dict
                    suboptions:
                      interface_name:
                        description:
                          - Refers to the specific network
                            interface in the border
                            device.
                          - This parameter is required
                            for all operations in L2
                            Handoff.
                          - The 'interface_name' cannot
                            be updated.
                        type: str
                      internal_vlan_id:
                        description:
                          - Represents the VLAN identifier
                            used within the fabric for
                            traffic segmentation among
                            devices.
                          - Should be unique across
                            the entire fabric site settings.
                          - This parameter is required
                            for all operations in layer2_handoff.
                          - The 'internal_vlan_id' can
                            range from 1 to 4094, excluding
                            1, 1002-1005, 2046, and
                            4094.
                        type: int
                      external_vlan_id:
                        description:
                          - Represents to the VLAN identifier
                            used for traffic that exits
                            the fabric to external networks.
                          - Should be unique across
                            the entire fabric site settings.
                          - This parameter is required
                            for all operations in 'layer2_handoff'.
                          - The 'external_vlan_id' can
                            range from 1 to 4094, excluding
                            1, 1002-1005, 2046, and
                            4094.
                        type: int
requirements:
  - dnacentersdk >= 2.9.2
  - python >= 3.9
notes:
  - Wireless controller settings configured via this module require specific device roles and image states on the switch.
  - A reboot is required to remove wireless configurations from the device after disabling wireless controller capabilities.
  - Ensure the wireless image (e.g., 9800-SW) is installed, committed, and activated on the switch with wired roles enabled prior to configuration.
  - Supported role combinations for enabling wireless controller mode are -
    - Border + Control Plane + Edge + Wireless Controller (B+CP+E+WC)
    - Border + Control Plane + Wireless Controller (B+CP+WC)
    - Edge + Wireless Controller (E+WC)
  - The 9800-SW image is required to enable wireless controller capabilities on the switch.
    Before using the Embedded Wireless LAN Controller settings, ensure the image has been distributed and activated, and the
    device has been resynced.
    The SWIM Workflow Manager module can be used to perform the image distribution and activation.
  - A maximum of two devices can have Embedded Wireless Controller Capabilities in the fabric.
  - SDK Method used are -
    - site_design.SiteDesign.get_sites
    - network_settings.NetworkSettings.get_reserve_ip_subpool
    - devices.Devices.get_device_list
    - sda.Sda.get_transit_networks
    - sda.Sda.get_layer3_virtual_networks
    - sda.Sda.get_fabric_sites
    - sda.Sda.get_fabric_zones
    - sda.Sda.get_provisioned_devices
    - sda.Sda.get_fabric_devices_layer2_handoffs
    - sda.Sda.get_fabric_devices_layer3_handoffs_with_sda_transit
    - sda.Sda.get_fabric_devices_layer3_handoffs_with_ip_transit
    - sda.Sda.get_fabric_devices
    - sda.Sda.add_fabric_devices
    - sda.Sda.add_control_plane_device
    - sda.Sda.add_fabric_devices_layer2_handoffs
    - sda.Sda.add_fabric_devices_layer3_handoffs_with_sda_transit
    - sda.Sda.add_fabric_devices_layer3_handoffs_with_ip_transit
    - sda.Sda.update_fabric_devices
    - sda.Sda.update_fabric_devices_layer3_handoffs_with_sda_transit
    - sda.Sda.update_fabric_devices_layer3_handoffs_with_ip_transit
    - sda.Sda.delete_fabric_device_layer2_handoff_by_id
    - sda.Sda.delete_fabric_device_by_id
    - sda.Sda.delete_fabric_device_layer3_handoffs_with_sda_transit
    - sda.Sda.delete_fabric_device_layer3_handoff_with_ip_transit_by_id
    - task.Task.get_tasks_by_id
    - task.Task.get_task_details_by_id
    - fabric_wireless.FabricWireless.get_sda_wireless_details_from_switches
    - wireless.Wireless.get_primary_managed_ap_locations_for_specific_wireless_controller
    - wireless.Wireless.get_secondary_managed_ap_locations_for_specific_wireless_controller
    - wireless.Wireless.assign_managed_ap_locations_for_w_l_c
    - fabric_wireless.Wireless.reload_switch_for_wireless_controller_cleanup
    - fabric_wireless.Wireless.switch_wireless_setting_and_rolling_ap_upgrade_management

  - Paths used are
    - GET /dna/intent/api/v1/sites
    - GET /dna/intent/api/v1/reserve-ip-subpool
    - GET /dna/intent/api/v1/network-device
    - GET /dna/intent/api/v1/sda/transitNetworks
    - GET /dna/intent/api/v1/sda/layer3VirtualNetworks
    - GET /dna/intent/api/v1/sda/fabricSites
    - GET /dna/intent/api/v1/sda/fabricZones
    - GET /dna/intent/api/v1/sda/provisionDevices
    - GET /dna/intent/api/v1/sda/fabricDevices/layer2Handoffs
    - GET /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits
    - GET /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits
    - GET /dna/intent/api/v1/sda/fabricDevices
    - POST /dna/intent/api/v1/sda/fabricDevices
    - POST /dna/intent/api/v1/business/sda/control-plane-device
    - POST /dna/intent/api/v1/sda/fabricDevices/layer2Handoffs
    - POST /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits
    - POST /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits
    - PUT /dna/intent/api/v1/sda/fabricDevices
    - PUT /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits
    - PUT /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits
    - DELETE /dna/intent/api/v1/sda/fabricDevices/${id}
    - DELETE /dna/intent/api/v1/sda/fabricDevices/layer2Handoffs/${id}
    - DELETE /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits
    - DELETE /dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits/${id}
    - GET /dna/intent/api/v1/tasks/${id}
    - GET /dna/intent/api/v1/tasks/${id}/detail
    - GET /dna/intent/api/v1/sda/fabrics/${fabricId}/switchWirelessSetting
    - GET /dna/intent/api/v1/wirelessControllers/${networkDeviceId}/primaryManagedApLocations
    - GET /dna/intent/api/v1/wirelessControllers/${networkDeviceId}/secondaryManagedApLocations
    - GET /dna/intent/api/v1/sites
    - POST /dna/intent/api/v1/wirelessControllers/${deviceId}/assignManagedApLocations
    - POST /dna/intent/api/v1/sda/fabrics/${fabricId}/switchWirelessSetting/reload
    - PUT /dna/intent/api/v1/sda/fabrics/${fabricId}/switchWirelessSetting

"""
EXAMPLES = r"""
---
- name: Create SDA fabric device with device role as
    CONTROL_PLANE_NODE
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE]
- name: Create SDA fabric device with device role as
    CONTROL_PLANE_NODE, EDGE_NODE
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, EDGE_NODE]

- name: Create SDA fabric device with device role as CONTROL_PLANE_NODE, EDGE_NODE, BORDER_NODE, WIRELESS_CONTROLLER_NODE
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, EDGE_NODE, BORDER_NODE, WIRELESS_CONTROLLER_NODE]
              borders_settings:
                layer3_settings:
                  local_autonomous_system_number: 1234
                  is_default_exit: true
                  import_external_routes: true
                  border_priority: 1
                  prepend_autonomous_system_count: 1
              wireless_controller_settings:
                enable: true
                primary_managed_ap_locations:
                  - Global/USA/SAN-FRANCISCO/BLD_SF
                secondary_managed_ap_locations:
                  - Global/USA/SAN-FRANCISCO/BLD_SF1
                rolling_ap_upgrade:
                  enable: true
                  ap_reboot_percentage: 25

- name: Update SDA fabric device with device role containing WIRELESSS_CONTROLLER_NODE to disable AP rolling upgrade.
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              wireless_controller_settings:
                rolling_ap_upgrade:
                  enable: false

- name: Update SDA fabric device with device role containing WIRELESSS_CONTROLLER_NODE to disable wireless capabilities with reload.
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              wireless_controller_settings:
                enable: false
                reload: true


- name: Create SDA fabric device with device role as CONTROL_PLANE_NODE, EDGE_NODE,
    BORDER_NODE
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, EDGE_NODE, BORDER_NODE]
              borders_settings:
                layer3_settings:
                  local_autonomous_system_number: 1234
                  is_default_exit: true
                  import_external_routes: true
                  border_priority: 1
                  prepend_autonomous_system_count: 1
- name: Update the SDA fabric device with the device
    roles with BORDER_NODE and add L2 Handoff
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, BORDER_NODE]
              borders_settings:
                layer3_settings:
                  local_autonomous_system_number: 1234
                  is_default_exit: true
                  import_external_routes: true
                  border_priority: 2
                  prepend_autonomous_system_count: 2
                layer2_handoff:
                  - interface_name: FortyGigabitEthernet1/1/1
                    internal_vlan_id: 550
                    external_vlan_id: 551
- name: Add the L3 Handoff with SDA Transit to the SDA
    fabric device
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, BORDER_NODE]
              borders_settings:
                layer3_handoff_sda_transit:
                  transit_network_name: SDA_PUB_SUB_TRANSIT
                  affinity_id_prime: 1
                  affinity_id_decider: 1
                  connected_to_internet: true
                  is_multicast_over_transit_enabled: false
- name: Add L3 Handoff with IP Transit to the SDA fabric
    device with external_connectivity_ip_pool_name
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, BORDER_NODE]
              borders_settings:
                layer3_handoff_ip_transit:
                  - transit_network_name: IP_TRANSIT_1
                    interface_name: FortyGigabitEthernet1/1/1
                    external_connectivity_ip_pool_name: Reserved_sda_test_1
                    virtual_network_name: L3VN1
                    vlan_id: 440
                    tcp_mss_adjustment: 501
- name: Add L3 Handoff with IP Transit to the SDA fabric
    device with local and remote network
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, BORDER_NODE]
              borders_settings:
                layer3_handoff_ip_transit:
                  - transit_network_name: IP_TRANSIT_1
                    interface_name: FortyGigabitEthernet1/1/1
                    virtual_network_name: L3VN1
                    vlan_id: 440
                    tcp_mss_adjustment: 510
                    local_ip_address: 10.0.0.1/24
                    remote_ip_address: 10.0.0.2/24
                    local_ipv6_address: 2009:db8::1/64
                    remote_ipv6_address: 2009:db8::2/64
- name: Update the border settings of the SDA Devices
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, BORDER_NODE]
              borders_settings:
                layer3_settings:
                  local_autonomous_system_number: 1234
                  is_default_exit: false
                  import_external_routes: false
                  border_priority: 1
                  prepend_autonomous_system_count: 3
- name: Update the L3 Handoffs with SDA Transit and
    IP Transit.
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: merged
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              device_roles: [CONTROL_PLANE_NODE, BORDER_NODE]
              borders_settings:
                layer3_handoff_sda_transit:
                  transit_network_name: SDA_PUB_SUB_TRANSIT
                  affinity_id_prime: 2
                  affinity_id_decider: 2
                  connected_to_internet: false
                  is_multicast_over_transit_enabled: true
                layer3_handoff_ip_transit:
                  - transit_network_name: IP_TRANSIT_1
                    interface_name: FortyGigabitEthernet1/1/1
                    virtual_network_name: L3VN1
                    vlan_id: 440
                    tcp_mss_adjustment: 511
                    local_ip_address: 10.0.0.1/24
                    remote_ip_address: 10.0.0.2/24
                    local_ipv6_address: 2009:db8::1/64
                    remote_ipv6_address: 2009:db8::2/64
- name: Delete the L2 Handoff
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: deleted
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              borders_settings:
                layer2_handoff:
                  - interface_name: FortyGigabitEthernet1/1/1
                    internal_vlan_id: 550
- name: Delete the L3 Handoff with SDA Transit
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: deleted
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              borders_settings:
                layer3_handoff_sda_transit:
                  transit_network_name: SDA_PUB_SUB_TRANSIT
- name: Delete the L3 Handoff with IP Transit
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: deleted
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
              borders_settings:
                layer3_handoff_ip_transit:
                  - transit_network_name: IP_TRANSIT_1
                    interface_name: FortyGigabitEthernet1/1/1
                    virtual_network_name: L3VN1
- name: Delete the device
  cisco.dnac.sda_fabric_devices_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{ dnac_log_level }}"
    state: deleted
    config_verify: true
    config:
      - fabric_devices:
          fabric_name: Global/USA/SAN-JOSE
          device_config:
            - device_ip: 10.0.0.1
"""
RETURN = r"""
# Case_1: Successful addition of SDA fabric devices
response_1:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_2: Successful update of SDA fabric devices
response_2:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_3: Successful deletion of SDA fabric devices
response_3:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_4: Successful creation L2 Handoff in fabric device
response_4:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_5: Successful deletion L2 Handoff in fabric device
response_5:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_6: Successful creation L3 Handoff with SDA transit in fabric device
response_6:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_7: Successful update L3 Handoff with SDA transit in fabric device
response_7:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_8: Successful update L3 Handoff with SDA transit in fabric device
response_8:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_9: Successful deletion L3 Handoff with SDA transit in fabric device
response_9:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_10: Successful creation L3 Handoff with IP transit in fabric device
response_10:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_11: Successful update L3 Handoff with IP transit in fabric device
response_11:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_12: Successful deletion L3 Handoff with IP transit in fabric device
response_12:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "str",
        "url": "str"
      },
      "version": "str"
    }
# Case_13: Successful addition of Control Node to the fabric.
response_13:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "endTime": "int",
        "lastUpdate": "int",
        "status": "str",
        "startTime": "int",
        "version": "int",
        "resultLocation": "str",
        "id": "str"
      },
      "version": "str"
    }
"""

import time
import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
)


class FabricDevices(DnacBase):
    """Class containing member attributes for sda_fabric_devices_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.response = []
        self.fabric_devices_obj_params = self.get_obj_params("fabricDevices")
        self.fabric_l3_handoff_sda_obj_params = self.get_obj_params(
            "fabricSdaL3Handoff"
        )
        self.fabric_l3_handoff_ip_obj_params = self.get_obj_params("fabricIpL3Handoff")
        self.max_timeout = self.params.get("dnac_api_task_timeout")
        self.fabric_type = None                     # Can be either 'fabric_site' or 'fabric_zone'

    def validate_input(self):
        """
        Checks if the configuration parameters provided in the playbook
        meet the expected structure and data types,
        as defined in the 'temp_spec' dictionary.

        Parameters:
            self (object): The current object details.
        Returns:
            self (object): The current object with updated desired Fabric Devices information.
        Example:
            If the validation succeeds, 'self.status' will be 'success' and
            'self.validated_config' will contain the validated configuration.
            If it fails, 'self.status' will be 'failed', and
            'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.msg = "config not available in playbook for validation."
            self.status = "success"
            return self

        # temp_spec is the specification for the expected structure of configuration parameters
        temp_spec = {
            "fabric_devices": {
                "type": "dict",
                "fabric_name": {"type": "str"},
                "device_config": {
                    "type": "list",
                    "elements": "dict",
                    "device_ip": {"type": "str"},
                    "device_roles": {
                        "type": "list",
                        "elements": "str",
                    },
                    "wireless_controller_settings": {
                        "type": "dict",
                        "enable": {"type": "bool"},
                        "reload": {"type": "bool", "default": False},
                        "primary_managed_ap_locations": {
                            "type": "list",
                            "elements": "str",
                        },
                        "secondary_managed_ap_locations": {
                            "type": "list",
                            "elements": "str",
                        },
                        "rolling_ap_upgrade": {
                            "type": "dict",
                            "enable": {"type": "bool", "default": False},
                            "ap_reboot_percentage": {
                                "type": "int",
                                "choice": ["5", "15", "25"],
                            },
                        },
                    },
                    "borders_settings": {
                        "type": "list",
                        "elements": "dict",
                        "layer3_settings": {
                            "type": "dict",
                            "local_autonomous_system_number": {"type": "str"},
                            "is_default_exit": {"type": "bool"},
                            "import_external_routes": {"type": "bool"},
                            "border_priority": {"type": "int"},
                            "prepend_autonomous_system_count": {"type": "int"},
                        },
                        "layer3_handoff_ip_transit": {
                            "type": "list",
                            "elements": "dict",
                            "transit_network_name": {"type": "str"},
                            "interface_name": {"type": "str"},
                            "external_connectivity_ip_pool_name": {"type": "str"},
                            "virtual_network_name": {"type": "str"},
                            "vlan_id": {"type": "int"},
                            "tcp_mss_adjustment": {"type": "int"},
                            "local_ip_address": {"type": "str"},
                            "remote_ip_address": {"type": "str"},
                            "local_ipv6_address": {"type": "str"},
                            "remote_ipv6_address": {"type": "str"},
                        },
                        "layer3_handoff_sda_transit": {
                            "type": "list",
                            "elements": "dict",
                            "transit_network_name": {"type": "str"},
                            "affinity_id_prime": {"type": "int"},
                            "affinity_id_decider": {"type": "int"},
                            "connected_to_internet": {"type": "bool"},
                            "is_multicast_over_transit_enabled": {"type": "bool"},
                        },
                        "layer2_handoff": {
                            "type": "list",
                            "elements": "dict",
                            "interface_name": {"type": "str"},
                            "internal_vlan_id": {"type": "int"},
                            "external_vlan_id": {"type": "int"},
                        },
                    },
                },
            }
        }

        # Validate playbook params against the specification (temp_spec)
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {invalid_params}".format(
                invalid_params="\n".join(invalid_params)
            )
            self.status = "failed"
            return self

        self.validated_config = valid_temp
        self.log(
            "Successfully validated playbook config params: {valid_temp}".format(
                valid_temp=valid_temp
            ),
            "INFO",
        )
        self.msg = "Successfully validated input from the playbook."
        self.status = "success"
        return self

    def get_obj_params(self, get_object):
        """
        Get the required comparison obj_params value

        Parameters:
            get_object (str): identifier for the required obj_params
        Returns:
            obj_params (list): obj_params value for comparison.
        Description:
            This function gets the object for the requires_update function.
            The obj_params will have the pattern to be compared.
        """

        try:
            if get_object == "fabricDevices":
                obj_params = [
                    ("borderTypes", "borderTypes"),
                    ("borderDeviceSettings", "borderDeviceSettings"),
                ]
            elif get_object == "fabricSdaL3Handoff":
                obj_params = [
                    ("affinityIdPrime", "affinityIdPrime"),
                    ("affinityIdDecider", "affinityIdDecider"),
                    ("connectedToInternet", "connectedToInternet"),
                    ("isMulticastOverTransitEnabled", "isMulticastOverTransitEnabled"),
                ]
            elif get_object == "fabricIpL3Handoff":
                obj_params = [
                    ("tcpMssAdjustment", "tcpMssAdjustment"),
                ]
            else:
                raise ValueError(
                    "Received an unexpected value for 'get_object': {object_name}".format(
                        object_name=get_object
                    )
                )
        except Exception as msg:
            self.log("Received exception: {msg}".format(msg=msg), "CRITICAL")

        return obj_params

    def get_transit_id_from_name(self, transit_name):
        """
        Get the transit ID from the transit name.

        Parameters:
            transit_name (str): The name of the transit network.
        Returns:
            transit_id (str or None): The ID of the transit network. None, if transit does not exist.
        Description:
            Call the API 'get_transit_networks' by setting the 'name' field with the
            given transit name.
            If the response is not empty, fetch the Id and return. Else, return None.
        """

        self.log(
            "Starting to get transit ID for transit name: '{name}'".format(
                name=transit_name
            ),
            "DEBUG",
        )
        transit_id = None
        try:
            transit_details = self.dnac._exec(
                family="sda",
                function="get_transit_networks",
                params={"name": transit_name},
            )

            # If the SDK returns no response, then the transit does not exist
            transit_details = transit_details.get("response")
            if not transit_details:
                self.log(
                    "There is no transit network with the name '{name}'.".format(
                        name=transit_name
                    ),
                    "DEBUG",
                )
                return transit_id

            transit_id = transit_details[0].get("id")
            self.log(
                "Transit ID found: '{id}' for transit name: '{name}'.".format(
                    id=transit_id, name=transit_name
                ),
                "DEBUG",
            )
        except Exception as msg:
            self.msg = "Exception occurred while running the API 'get_transit_networks': {msg}".format(
                msg=msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        self.log("Returning transit ID: '{id}'.".format(id=transit_id), "DEBUG")
        return transit_id

    def get_device_details_from_ip(self, device_ip):
        """
        Get the network device details from the network device IP.

        Parameters:
            device_ip (str): The IP address of the network device.
        Returns:
            device_details (dict or None): The details of the network device. None, if the device does not exist.
        Description:
            Call the API 'get_device_list' by setting the 'management_ip_address' field with the
            given IP address.
            If the response is not empty, return the device details. Else, return None.
        """

        self.log(
            "Starting to get device details for device IP: '{ip}'.".format(
                ip=device_ip
            ),
            "DEBUG",
        )
        device_details = None
        try:
            device_details = self.dnac._exec(
                family="devices",
                function="get_device_list",
                params={"management_ip_address": device_ip},
            )
            self.log(
                "Response received from 'get_device_list': {response}".format(
                    response=device_details
                ),
                "DEBUG",
            )

            # If the SDK returns no response, then the device does not exist
            device_details = device_details.get("response")
            if not device_details:
                self.log(
                    "There is no device with the IP address '{ip_address}'.".format(
                        ip_address=device_ip
                    ),
                    "DEBUG",
                )
                return device_details

        except Exception as msg:
            self.msg = "Exception occurred while running the API 'get_device_list': {msg}".format(
                msg=msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        self.log(
            "Returning device details: '{details}'.".format(details=device_details),
            "DEBUG",
        )
        return device_details

    def check_valid_virtual_network_name(self, virtual_network_name):
        """
        Get the fabric ID from the given site hierarchy name.

        Parameters:
            virtual_network_name (str): The name of the L3 virtual network.
        Returns:
            True or False (bool): True if the L3 virtual network exists. Else, return False.
        Description:
            Call the API 'get_layer3_virtual_networks' by setting the 'virtual_network_name'
            and 'offset' field.
            Call the API till we reach empty response or we find the L3 virtual network with the
            given name.
            If the status is set to failed, return None. Else, return the fabric site ID.
        """

        self.log(
            "Starting to check if virtual network exists: '{name}'.".format(
                name=virtual_network_name
            ),
            "DEBUG",
        )
        try:
            virtual_network_details = self.dnac._exec(
                family="sda",
                function="get_layer3_virtual_networks",
                params={
                    "virtual_network_name": virtual_network_name,
                },
            )
            self.log(
                "Response received from 'get_layer3_virtual_networks': {response}".format(
                    response=virtual_network_details
                ),
                "DEBUG",
            )

            if not isinstance(virtual_network_details, dict):
                self.msg = "Error in getting virtual network details - Response is not a dictionary"
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

            # if the SDK returns no response, then the virtual network does not exist
            virtual_network_details = virtual_network_details.get("response")
            if not virtual_network_details:
                self.log(
                    "There is no L3 virtual network with the name '{name}.".format(
                        name=virtual_network_name
                    ),
                    "DEBUG",
                )
                return False

            self.log(
                "L3 virtual network '{name}' exists.".format(name=virtual_network_name),
                "DEBUG",
            )

        except Exception as msg:
            self.msg = "Exception occurred while running the API 'get_layer3_virtual_networks': {msg}".format(
                msg=msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return True

    def check_valid_reserved_pool(self, reserved_pool_name, fabric_name):
        """
        Get the fabric ID from the given site hierarchy name.

        Parameters:
            reserved_pool_name (str): The name of the reserved pool.
            fabric_name (str): The name of the fabric site to check for existence.
        Returns:
            True or False (bool): True if the reserved pool exists. Else, return False.
        Description:
            Call the API 'get_reserve_ip_subpool' by setting the 'site_id' and 'offset' field.
            Call the API till we reach empty response or we find the reserved subpool with the
            given subpool name.
            If the status is set to failed, return None. Else, return the fabric site ID.
        """

        self.log(
            "Starting to check for reserved pool '{pool_name}' in fabric '{fabric_name}'.".format(
                pool_name=reserved_pool_name, fabric_name=fabric_name
            ),
            "DEBUG",
        )
        try:
            (site_exists, site_id) = self.get_site_id(fabric_name)
            self.log(
                "The site with the name '{site_name} exists in Cisco Catalyst Center is '{site_exists}'".format(
                    site_name=fabric_name, site_exists=site_exists
                ),
                "DEBUG",
            )
            if not site_id:
                self.msg = (
                    "The site with the hierarchy name '{site_name}' is invalid.".format(
                        site_name=fabric_name
                    )
                )
                self.status = "failed"
                return self.check_return_status()

            offset = 1
            start_time = time.time()

            self.log(
                "Calling API 'get_reserve_ip_subpool' with site_id '{site_id}'.".format(
                    site_id=site_id
                ),
                "DEBUG",
            )
            while True:
                all_reserved_pool_details = self.dnac._exec(
                    family="network_settings",
                    function="get_reserve_ip_subpool",
                    params={"site_id": site_id, "offset": offset},
                )
                self.log(
                    "Response received from 'get_reserve_ip_subpool': {response}".format(
                        response=all_reserved_pool_details
                    ),
                    "DEBUG",
                )

                if not isinstance(all_reserved_pool_details, dict):
                    self.msg = (
                        "Error in getting reserve pool - Response is not a dictionary"
                    )
                    self.log(self.msg, "CRITICAL")
                    self.status = "failed"
                    return self.check_return_status()

                offset += 25
                all_reserved_pool_details = all_reserved_pool_details.get("response")
                if not all_reserved_pool_details:
                    self.log(
                        "There is no reserved subpool in the site '{site_name}'.".format(
                            site_name=fabric_name
                        ),
                        "DEBUG",
                    )
                    return False

                # Check for maximum timeout, default value is 1200 seconds
                if (time.time() - start_time) >= self.max_timeout:
                    self.msg = "Max timeout of {0} sec has reached for the API 'get_reserved_ip_subpool' status.".format(
                        self.max_timeout
                    )
                    self.log(self.msg, "CRITICAL")
                    self.status = "failed"
                    break

                # Find the reserved pool with the given name in the list of reserved pools
                reserved_pool_details = get_dict_result(
                    all_reserved_pool_details, "groupName", reserved_pool_name
                )
                if reserved_pool_details:
                    self.log(
                        "The reserved pool found with the name '{reserved_pool}' in the site '{site_name}'.".format(
                            reserved_pool=reserved_pool_name, site_name=fabric_name
                        ),
                        "DEBUG",
                    )
                    return True

                self.log(
                    "No matching reserved pool found for '{pool}' in site '{site_name}'. Continuing to next offset.".format(
                        pool=reserved_pool_name, site_name=fabric_name
                    ),
                    "DEBUG",
                )
        except Exception as msg:
            self.msg = "Exception occurred while running the API 'get_reserve_ip_subpool': {msg}".format(
                msg=msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return True

    def get_fabric_site_id_from_name(self, site_name, site_id):
        """
        Get the fabric ID from the given site hierarchy name.

        Parameters:
            site_name (str): The name of the site.
            site_id (str): The ID of the site.
        Returns:
            fabric_site_id (str): The ID of the fabric site.
        Description:
            Call the API 'get_fabric_sites' by setting the 'site_id' field with the
            given site id.
            If the status is set to failed, return None. Else, return the fabric site ID.
        """

        self.log(
            "Attempting to retrieve fabric site details for site ID '{site_id}' and site name '{site_name}'.".format(
                site_id=site_id, site_name=site_name
            ),
            "DEBUG",
        )
        fabric_site_id = None
        try:
            fabric_site_exists = self.dnac._exec(
                family="sda",
                function="get_fabric_sites",
                params={"site_id": site_id},
            )
            self.log(
                "Response received from 'get_fabric_sites': {response}".format(
                    response=fabric_site_exists
                ),
                "DEBUG",
            )

            # If the status is 'failed', then the site is not a fabric
            if not isinstance(fabric_site_exists, dict):
                self.msg = "Error in getting fabric site details - Response is not a dictionary"
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

            # if the SDK returns no response, then the virtual network does not exist
            fabric_site_exists = fabric_site_exists.get("response")
            if not fabric_site_exists:
                self.log(
                    "The site hierarchy 'fabric_site' {site_name} is not a valid one or it not a 'Fabric' site.".format(
                        site_name=site_name
                    ),
                    "ERROR",
                )
                return fabric_site_id

            self.log(
                "The site hierarchy 'fabric_site' {fabric_name} is a valid fabric site.".format(
                    fabric_name=site_name
                ),
                "DEBUG",
            )
            fabric_site_id = fabric_site_exists[0].get("id")
            self.log(
                "Fabric site ID retrieved successfully: {fabric_site_id}".format(
                    fabric_site_id=fabric_site_id
                ),
                "DEBUG",
            )
        except Exception as msg:
            self.msg = "Exception occurred while running the API 'get_fabric_sites': {msg}".format(
                msg=msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return fabric_site_id

    def get_fabric_zone_id_from_name(self, site_name, site_id):
        """
        Get the fabric zone ID from the given site hierarchy name.

        Parameters:
            site_name (str): The name of the site.
            site_id (str): The ID of the zone.
        Returns:
            fabric_zone_id (str): The ID of the fabric zone.
        Description:
            Call the API 'get_fabric_zones' by setting the 'site_name_hierarchy' field with the
            given site name.
            If the status is set to failed, return None. Else, return the fabric site ID.
        """

        self.log(
            "Attempting to retrieve fabric site details for site ID '{site_id}' and site name '{site_name}'.".format(
                site_id=site_id, site_name=site_name
            ),
            "DEBUG",
        )
        fabric_zone_id = None
        try:
            fabric_zone = self.dnac._exec(
                family="sda",
                function="get_fabric_zones",
                params={"site_id": site_id},
            )
            self.log(
                "Response received from 'get_fabric_zones': {response}".format(
                    response=fabric_zone
                ),
                "DEBUG",
            )

            # If the status is 'failed', then the zone is not a fabric
            if not isinstance(fabric_zone, dict):
                self.msg = "Error in getting fabric zone details - Response is not a dictionary"
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

            # if the SDK returns no response, then the virtual network does not exist
            fabric_zone = fabric_zone.get("response")
            if not fabric_zone:
                self.log(
                    "The site hierarchy 'fabric_zone' {site_name} is not a valid one or it not a 'Fabric' zone.".format(
                        site_name=site_name
                    ),
                    "ERROR",
                )
                return fabric_zone_id

            self.log(
                "The site hierarchy 'fabric_site' {fabric_name} is a valid fabric site.".format(
                    fabric_name=site_name
                ),
                "DEBUG",
            )
            fabric_zone_id = fabric_zone[0].get("id")
            self.log(
                "Fabric zone ID retrieved successfully: {fabric_zone_id}".format(
                    fabric_zone_id=fabric_zone_id
                ),
                "DEBUG",
            )
        except Exception as msg:
            self.msg = "Exception occurred while running the API 'get_fabric_zones': {msg}".format(
                msg=msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return fabric_zone_id

    def check_device_is_provisioned(
        self, fabric_device_ip, device_id, site_id, site_name
    ):
        """
        Check if the device with the given IP is provisioned to the site or not.

        Parameters:
            fabric_device_ip (str): The IP address of the network device.
            device_id (str): The ID of the network device.
            site_id (str): The ID of the fabric site.
            site_name (str): The name of the fabric site.
        Returns:
            self: The current object with updated desired Fabric Devices information.
        Description:
            Call the API 'get_provisioned_devices' by setting the 'network_device_id'
            field with the device ID.
            If the response is empty, return self by setting the self.msg and
            self.status as 'failed'.
        """

        self.log(
            "Checking provision status for device ID '{device_id}' with IP '{device_ip}' at site '{site_name}'.".format(
                device_id=device_id, device_ip=fabric_device_ip, site_name=site_name
            )
        )
        try:
            provisioned_device_details = self.dnac._exec(
                family="sda",
                function="get_provisioned_devices",
                params={"network_device_id": device_id},
            )
            self.log(
                "Response received from 'get_provisioned_devices': {response}".format(
                    response=provisioned_device_details
                ),
                "DEBUG",
            )

            # If the response returned from the SDK is None, then the device is not provisioned to the site.
            provisioned_device_details = provisioned_device_details.get("response")
            if not provisioned_device_details:
                self.msg = "The network device with the IP address '{device_ip}' is not provisioned to the site '{site_name}'.".format(
                    device_ip=fabric_device_ip, site_name=site_name
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

        except Exception as msg:
            self.msg = "Exception occurred while running the API 'get_provisioned_devices': {msg}".format(
                msg=msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"

        if self.status != "failed":
            self.log(
                "The network device with the IP address '{device_ip}' is provisioned to the site '{site_name}'.".format(
                    device_ip=fabric_device_ip, site_name=site_name
                ),
                "DEBUG",
            )

        return self

    def format_fabric_device_params(self, fabric_device_details):
        """
        Process the fabric device parameters retrieved from the Cisco Catalyst Center.

        Parameters:
            fabric_device_details (str): The fabric device details from the Cisco Catalyst Center.
        Returns:
            fabric_device_info (dict): Processed fabric device data in a format
            suitable for Cisco Catalyst Center configuration.
        Description:
            Form a dict with the params which is in accordance with the API payload structure.
        """

        fabric_device_info = {
            "id": fabric_device_details.get("id"),
            "fabricId": fabric_device_details.get("fabricId"),
            "networkDeviceId": fabric_device_details.get("networkDeviceId"),
            "deviceRoles": fabric_device_details.get("deviceRoles"),
            "borderDeviceSettings": fabric_device_details.get("borderDeviceSettings"),
        }

        # Formatted payload for the SDK 'Add fabric devices', 'Update fabric devices'
        self.log(
            "The fabric device details are '{fabric_device_info}'".format(
                fabric_device_info=fabric_device_info
            ),
            "DEBUG",
        )
        return fabric_device_info

    def l2_handoff_exists(self, fabric_id, device_id, internal_vlan_id, interface_name):
        """
        Check the availability of the L2 Handoff for the 'fabric_id', 'network_device_id',
        'internal_vlan_id' and return the ID of the Layer 2 Handoff.

        Parameters:
            fabric_id (str): The Id of the fabric site to check for existence.
            device_id (str): The Id of the provisioned device to check for existence.
            internal_vlan_id (str): The VLAN ID for the internal network.
            interface_name (str): The interface name of the network device.
        Returns:
            l2_handoff_id (dict or None) - L2 Handoff ID from the Cisco Catalyst Center.
        Description:
            Call the API 'get_fabric_devices_layer2_handoffs'. If the response is empty return None.
            Else, return the id of the l2 handoff.
        """

        l2_handoff_id = None
        offset = 1
        start_time = time.time()

        # Call the SDK with incremental offset till we find the L2 Handoff with given
        # interface name and internal vlan id
        while True:
            try:
                all_l2_handoff_details = self.dnac._exec(
                    family="sda",
                    function="get_fabric_devices_layer2_handoffs",
                    params={
                        "fabric_id": fabric_id,
                        "network_device_id": device_id,
                        "offset": offset,
                    },
                )
                self.log(
                    "Response received from 'get_fabric_devices_layer2_handoffs': {response}".format(
                        response=all_l2_handoff_details
                    ),
                    "DEBUG",
                )

                if not isinstance(all_l2_handoff_details, dict):
                    self.msg = "Failed to retrieve the L2 Handoff details - Response is not a dictionary"
                    self.log(str(self.msg), "CRITICAL")
                    self.status = "failed"
                    return self.check_return_status()

                all_l2_handoff_details = all_l2_handoff_details.get("response")
                if not all_l2_handoff_details:
                    self.log(
                        "There is no L2 Handoffs are available associated with the device with ID '{id}' in the Cisco Catalyst Center.".format(
                            id=device_id
                        ),
                        "INFO",
                    )
                    break

                l2_handoff_details = None
                for item in all_l2_handoff_details:
                    if (
                        item.get("internalVlanId") == internal_vlan_id
                        and item.get("interfaceName") == interface_name
                    ):
                        l2_handoff_details = item
                        break

                if l2_handoff_details:
                    self.log(
                        "The L2 handoff details with the internal VLAN Id: {details}".format(
                            details=internal_vlan_id
                        ),
                        "DEBUG",
                    )
                    l2_handoff_id = l2_handoff_details.get("id")
                    break

                offset += 500
                end_time = time.time()
                if (end_time - start_time) >= self.max_timeout:
                    self.msg = "Max timeout of {max_time} sec has reached for the API 'l2_handoff_exists' status.".format(
                        max_time=self.max_timeout
                    )
                    self.status = "failed"
                    return self.check_return_status()
            except Exception as msg:
                self.msg = "Exception occurred while running the API 'get_fabric_devices_layer2_handoffs': {msg}".format(
                    msg=msg
                )
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

        if l2_handoff_id:
            self.log(
                "L2 handoff ID found: {l2_handoff_id}".format(
                    l2_handoff_id=l2_handoff_id
                ),
                "INFO",
            )
        else:
            self.log("No L2 handoff ID found for the specified parameters.", "INFO")

        return l2_handoff_id

    def sda_l3_handoff_exists(self, fabric_id, device_id, transit_name):
        """
        Check the availability of the L2 Handoff for the 'fabric_id', 'network_device_id',
        'internal_vlan_id'.

        Parameters:
            fabric_id (str): The Id of the fabric site to check for existence.
            device_id (str): The Id of the provisioned device to check for existence.
            transit_name (str): The IP address of the the provisioned device.
        Returns:
            sda_l3_handoff_details (dict or None): The details of the L3 Handoff with SDA transit with
            the given transit name. None if the there is no L3 Handoff with SDA transit.
        Description:
            Call the API 'get_fabric_devices_layer3_handoffs_with_sda_transit'. If the response is
            empty return None. Else, return the details of the l3 handoff with SDA transit.
        """

        sda_l3_handoff_details = None
        self.log(
            "Checking L3 Handoff existence for fabric ID '{fabric_id}': device ID: '{device_id}' : transit name '{transit_name}'".format(
                fabric_id=fabric_id, device_id=device_id, transit_name=transit_name
            ),
            "INFO",
        )
        transit_id = self.get_transit_id_from_name(transit_name)
        if not transit_id:
            if self.params.get("state") == "deleted":
                self.log(
                    "The state is 'deleted', so we are returning SDA L3 Handoffs without any further checks "
                    "event hough there is no transit with the name '{transit_name}'.".format(
                        transit_name=transit_name
                    ),
                    "INFO",
                )
                return sda_l3_handoff_details

            self.msg = "The SDA transit with the name '{name}' is not available in the Cisco Catalyst Center.".format(
                name=transit_name
            )
            self.status = "failed"
            return self.check_return_status()

        start_time = time.time()
        offset = 1

        # Call the SDK with incremental offset till to find the SDA L3 Handoff
        while True:
            try:
                all_sda_l3_handoff_details = self.dnac._exec(
                    family="sda",
                    function="get_fabric_devices_layer3_handoffs_with_sda_transit",
                    params={
                        "fabric_id": fabric_id,
                        "network_device_id": device_id,
                        "offset": offset,
                    },
                )

                offset += 500
                if not isinstance(all_sda_l3_handoff_details, dict):
                    self.msg = "Failed to retrieve the L2 Handoff details - Response is not a dictionary"
                    self.log(self.msg, "CRITICAL")
                    self.status = "failed"
                    return self.check_return_status()

                all_sda_l3_handoff_details = all_sda_l3_handoff_details.get("response")
                if not all_sda_l3_handoff_details:
                    self.log(
                        "There is no L3 Handoffs with SDA transit associated with the device with ID '{id}' in the Cisco Catalyst Center.".format(
                            id=device_id
                        ),
                        "INFO",
                    )
                    break

                sda_l3_handoff_details = get_dict_result(
                    all_sda_l3_handoff_details, "transitNetworkId", transit_id
                )
                if sda_l3_handoff_details:
                    self.log(
                        "The L3 Handoff with SDA transit details with the transit name '{name}': '{details}".format(
                            name=transit_name, details=sda_l3_handoff_details
                        ),
                        "DEBUG",
                    )
                    break

                end_time = time.time()
                if (end_time - start_time) >= self.max_timeout:
                    self.msg = "Max timeout of {max_time} sec has reached for the API 'sda_l3_handoff_exists' status.".format(
                        max_time=self.max_timeout
                    )
                    self.status = "failed"
                    return self.check_return_status()
            except Exception as msg:
                self.msg = (
                    "Received API response from 'get_fabric_devices_layer3_handoffs_with_sda_transit' "
                    "with the transit name '{name}': {msg}".format(
                        name=transit_name, msg=msg
                    )
                )
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

        if sda_l3_handoff_details:
            self.log(
                "L3 Handoff details found: {details}".format(
                    details=sda_l3_handoff_details
                ),
                "INFO",
            )
        else:
            self.log(
                "No L3 Handoff details found for transit name '{name}'.".format(
                    name=transit_name
                ),
                "INFO",
            )

        return sda_l3_handoff_details

    def ip_l3_handoff_exists(
        self, fabric_id, device_id, transit_name, virtual_network_name, vlan_id
    ):
        """
        Check if the SDA fabric devices with the given fabric ID and
        the provisioned device ID exists or not.

        Parameters:
            fabric_id (str): The Id of the fabric site to check for existence.
            device_id (str): The Id of the provisioned device to check for existence.
            transit_name (str): The IP address of the the provisioned device.
            virtual_network_name (str): The Layer 3 virtual network name.
            vlan_id (str): The VLAN ID associated with the L3 Handoff IP transit.
        Returns:
            ip_l3_handoff_details (dict or None): The details of the L3 Handoff with IP transit with
            the given transit name, virtual network name or VLAN ID.
            None if the there is no L3 Handoff with Ip transit.
        Description:
            Call the API 'get_fabric_devices_layer3_handoffs_with_ip_transit'. If the response is
            empty return None. Else, return the details of the l3 handoff with SDA transit which matches
            the given transit name and virtual network name or vlan id from the fabric device.
        """

        self.log(
            "Starting the IP L3 Handoff existence check for device ID '{device_id}' with transit '{transit_name}'.".format(
                device_id=device_id, transit_name=transit_name
            ),
            "DEBUG",
        )
        ip_l3_handoff_details = None

        # Check if the transit name is valid or not
        # If yes, return the transit ID. Else, return a failure message.
        transit_id = self.get_transit_id_from_name(transit_name)
        if not transit_id:
            if self.params.get("state") == "deleted":
                self.log(
                    "The state is 'deleted', so we are returning IP L3 Handoffs without any further checks "
                    "even though there is no transit with the name '{transit_name}'.".format(
                        transit_name=transit_name
                    ),
                    "INFO",
                )
                return ip_l3_handoff_details

            self.msg = "The IP transit with the name '{name}' is not available in the Cisco Catalyst Center.".format(
                name=transit_name
            )
            self.status = "failed"
            return self.check_return_status()

        self.log(
            "Transit ID for '{transit_name}' successfully retrieved: {transit_id}".format(
                transit_name=transit_name, transit_id=transit_id
            ),
            "DEBUG",
        )
        start_time = time.time()
        offset = 1

        # Call the SDK with incremental offset till we find the IP L3 Handoff with given virtual network name
        self.log(
            "Fetching IP L3 Handoff details for fabric ID '{fabric_id}' and device ID '{device_id}'.".format(
                fabric_id=fabric_id, device_id=device_id
            ),
            "DEBUG",
        )
        while True:
            try:
                all_ip_l3_handoff_details = self.dnac._exec(
                    family="sda",
                    function="get_fabric_devices_layer3_handoffs_with_ip_transit",
                    params={
                        "fabric_id": fabric_id,
                        "network_device_id": device_id,
                        "offset": offset,
                    },
                )
                self.log(
                    "IP L3 Handoff details fetched successfully for offset {offset}.".format(
                        offset=offset
                    ),
                    "DEBUG",
                )
                self.log(
                    "Received response from 'get_fabric_devices_layer3_handoffs_with_ip_transit': {response}".format(
                        response=all_ip_l3_handoff_details
                    ),
                    "DEBUG",
                )
            except Exception as msg:
                self.msg = (
                    "Exception occurred while getting the details of Layer3 Handoffs with IP transit "
                    "with the transit name '{name}': {msg}".format(
                        name=transit_name, msg=msg
                    )
                )
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

            offset += 500
            if not isinstance(all_ip_l3_handoff_details, dict):
                self.msg = "Failed to retrieve the L2 Handoff details - Response is not a dictionary"
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

            all_ip_l3_handoff_details = all_ip_l3_handoff_details.get("response")
            if not all_ip_l3_handoff_details:
                self.log(
                    "There is no L3 Handoffs with IP transit associated with the device with ID '{id}' in the Cisco Catalyst Center.".format(
                        id=device_id
                    ),
                    "INFO",
                )
                break

            self.log(
                "Scanning IP L3 Handoff details for matching transit ID '{transit_id}' and virtual network '{virtual_network}' or VLAN ID '{vlan_id}'.".format(
                    transit_id=transit_id,
                    virtual_network=virtual_network_name,
                    vlan_id=vlan_id,
                ),
                "DEBUG",
            )
            virtual_network = virtual_network_name
            check_string = "virtualNetworkName"
            if not virtual_network:
                virtual_network = vlan_id
                check_string = "vlanId"

            for item in all_ip_l3_handoff_details:
                if (
                    item.get("transitNetworkId") == transit_id
                    and item.get(check_string) == virtual_network
                ):
                    ip_l3_handoff_details = item
                    self.log(
                        "Matching IP L3 Handoff found for transit '{transit_name}' with details: {details}".format(
                            transit_name=transit_name, details=ip_l3_handoff_details
                        ),
                        "INFO",
                    )
                    break

            if not ip_l3_handoff_details:
                self.log(
                    "No matching IP L3 Handoff found for transit '{transit_name}'.".format(
                        transit_name=transit_name
                    ),
                    "INFO",
                )
            else:
                break

            end_time = time.time()
            if (end_time - start_time) >= self.max_timeout:
                self.msg = "Max timeout of {max_time} sec has reached for the API 'ip_l3_handoff_exists' status.".format(
                    max_time=self.max_timeout
                )
                self.status = "failed"
                return self.check_return_status()

        return ip_l3_handoff_details

    def fabric_device_exists(self, fabric_id, device_id, device_ip):
        """
        Check if the SDA fabric devices with the given fabric ID and
        the provisioned device ID exists or not.

        Parameters:
            fabric_id (str): The Id of the fabric site to check for existence.
            device_id (str): The Id of the provisioned device to check for existence.
            device_ip (str): The IP address of the the provisioned device.
        Returns:
            dict - A dictionary containing information about the
                   SDA fabric device's existence:
                - 'exists' (bool): True if the fabric device exists, False otherwise.
                - 'id' (str or None): The ID of the fabric device if it exists or None if it doesn't.
                - 'device_details' (dict or None): Details of the fabric device if it exists else None.
        Description:
            Sets the existance, details and the id of the fabric device as None.
            Calls the API 'get_fabric_devices' by settings the fields 'fabric_id'
            and 'network_device_id'.
            If the response is empty return the device_info, Else, format the given
            details and return the device_info.
        """

        self.log(
            "Starting check for fabric device existence with ID '{device_id}' in fabric '{fabric_id}'.".format(
                device_id=device_id, fabric_id=fabric_id
            ),
            "DEBUG",
        )
        device_info = {
            "exists": False,
            "device_details": None,
            "id": None,
        }
        fabric_device_details = self.dnac._exec(
            family="sda",
            function="get_fabric_devices",
            params={
                "fabric_id": fabric_id,
                "network_device_id": device_id,
            },
        )
        self.log(
            "Successfully retrieved details for fabric device with ID '{device_id}'.".format(
                device_id=device_id
            ),
            "DEBUG",
        )

        if not isinstance(fabric_device_details, dict):
            self.msg = "Error in getting fabric devices - Response is not a dictionary"
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self.check_return_status()

        # If the SDK return an empty response, then the fabric device is not available
        fabric_device_details = fabric_device_details.get("response")
        if not fabric_device_details:
            self.log(
                "Fabric device with IP {ip} does not exist.".format(ip=device_ip),
                "DEBUG",
            )
            return device_info

        self.log(
            "Fabric device with the IP address '{ip}' is found: {details}".format(
                ip=device_ip, details=fabric_device_details
            ),
            "INFO",
        )

        # Update the existence, details and the id of the fabric device
        device_info.update(
            {
                "exists": True,
                "id": fabric_device_details[0].get("id"),
                "device_details": self.format_fabric_device_params(
                    fabric_device_details[0]
                ),
            }
        )

        self.log(
            "SDA fabric device details successfully formatted for device with IP '{ip}'.".format(
                ip=device_ip
            ),
            "DEBUG",
        )
        self.log(
            "SDA fabric device details: {details}".format(
                details=device_info.get("details")
            ),
            "DEBUG",
        )
        self.log("SDA fabric device id: {id}".format(id=device_info.get("id")), "DEBUG")
        return device_info

    def process_layer2_handoff(
        self,
        fabric_devices_info,
        layer2_handoff,
        fabric_site_id,
        network_device_id,
        fabric_device_ip,
    ):
        """
        Process the L2 Handoff details which is provided in the playbook.

        Parameters:
            fabric_devices_info (dict): Processed information of the device's L2 Handoff.
            layer2_handoff (list of dict): Playbook details of the L2 Handoff.
            fabric_site_id (str): ID of the fabric site.
            network_device_id (str): ID of the network device.
            fabric_device_ip (str): IP address of the network device.
        Returns:
            fabric_devices_info (list of dict): Processed information of the device's L2 Handoff.
        Description:
            Check if the L2 Handoff exists. Validate the internal_vlan_id and interface_name.
            Get the L2 Handoff ID, if exists.
        """

        self.log(
            "Processing the L2 Handoff for the device '{ip}'".format(
                ip=fabric_device_ip
            )
        )
        if not layer2_handoff:
            return fabric_devices_info

        for value in layer2_handoff:
            internal_vlan_id = value.get("internal_vlan_id")
            if not internal_vlan_id:
                self.msg = (
                    "The required parameter 'internal_vlan_id' in 'l2_handoffs' is missing "
                    "for the device ip '{ip}'.".format(ip=fabric_device_ip)
                )
                self.status = "failed"
                return self

            interface_name = value.get("interface_name")
            if not interface_name:
                self.msg = (
                    "The required parameter 'interface_name' in 'l2_handoffs' is missing "
                    "for the device ip '{ip}'.".format(ip=fabric_device_ip)
                )
                self.status = "failed"
                return self

            l2_handoff_id = self.l2_handoff_exists(
                fabric_site_id, network_device_id, internal_vlan_id, interface_name
            )
            fabric_devices_info.get("l2_handoff_details").append(l2_handoff_id)

        self.log("Successfully processed the L2 Handoff information.", "DEBUG")
        return fabric_devices_info

    def process_layer3_sda_handoff(
        self,
        fabric_devices_info,
        layer3_handoff_sda_transit,
        fabric_site_id,
        network_device_id,
        fabric_device_ip,
    ):
        """
        Process the L3 Handoff with SDA Transit details which is provided in the playbook.

        Parameters:
            fabric_devices_info (dict): Processed information of the device's SDA L3 Handoff.
            layer3_handoff_sda_transit (dict): Playbook details of the SDA L3 Handoff.
            fabric_site_id (str): ID of the fabric site.
            network_device_id (str): ID of the network device.
            fabric_device_ip (str): IP address of the network device.
        Returns:
            fabric_devices_info (list of dict): Processed information of the device's SDA L3 Handoff.
        Description:
            Check if the SDA L3 Handoff exists. Validate the transit_network_name.
            Get the SDA L3 Handoff ID and details, if exists.
        """

        self.log(
            "Processing the SDA L3 Handoff for the device '{ip}'".format(
                ip=fabric_device_ip
            )
        )
        if not layer3_handoff_sda_transit:
            return fabric_devices_info

        if layer3_handoff_sda_transit:

            # Transit network name is mandatory
            transit_network_name = layer3_handoff_sda_transit.get(
                "transit_network_name"
            )
            if not transit_network_name:
                self.msg = "The required parameter 'transit_network_name' in 'layer3_handoff_sda_transit' is missing."
                self.status = "failed"
                return self

            sda_l3_handoff_details = self.sda_l3_handoff_exists(
                fabric_site_id, network_device_id, transit_network_name
            )
            fabric_devices_info.update(
                {"sda_l3_handoff_details": sda_l3_handoff_details}
            )

        self.log("Successfully processed the SDA L3 Handoff information.", "DEBUG")
        return fabric_devices_info

    def process_layer3_ip_handoff(
        self,
        fabric_devices_info,
        layer3_handoff_ip_transit,
        fabric_site_id,
        network_device_id,
        fabric_device_ip,
    ):
        """
        Process the L3 Handoff with SDA Transit details which is provided in the playbook.

        Parameters:
            fabric_devices_info (dict): Processed information of the device's IP L3 Handoff.
            layer3_handoff_ip_transit (list of dict): Playbook details of the IP L3 Handoff.
            fabric_site_id (str): ID of the fabric site.
            network_device_id (str): ID of the network device.
            fabric_device_ip (str): IP address of the network device.
        Returns:
            fabric_devices_info (list of dict): Processed information of the device's IP L3 Handoff.
        Description:
            Check if the IP L3 Handoff exists. Validate the transit_network_name, interface_name
            virtual_network_name, vlan_id.
            Get the IP L3 Handoff ID and details, if exists.
        """

        self.log(
            "Processing the IP L3 Handoff for the device '{ip}'".format(
                ip=fabric_device_ip
            )
        )
        if not layer3_handoff_ip_transit:
            return fabric_devices_info

        for value in layer3_handoff_ip_transit:

            # Transit name, interface name and virtual network name are mandatory
            transit_network_name = value.get("transit_network_name")
            if not transit_network_name:
                self.msg = "The required parameter 'transit_network_name' in 'layer3_handoff_ip_transit' is missing."
                self.status = "failed"
                return self

            interface_name = value.get("interface_name")
            if not interface_name:
                self.msg = "The required parameter 'interface_name' in 'layer3_handoff_ip_transit' is missing."
                self.status = "failed"
                return self

            virtual_network_name = value.get("virtual_network_name")
            vlan_id = value.get("vlan_id")
            if not (virtual_network_name and vlan_id):
                self.msg = (
                    "Either the 'virtual_network_name' or 'vlan_id' is mandatory for updating and deleting the "
                    "layer3_handoff_ip_transit or both of them is mandatory for creating a layer3_handoff_ip_transit."
                )
                self.status = "failed"
                return self

            self.log(
                "All required parameters for Layer 3 IP handoff are present. Processing handoff for Transit Network "
                "'{network}', Interface '{interface}', VLAN ID '{vlan_id}'.".format(
                    network=transit_network_name,
                    interface=interface_name,
                    vlan_id=vlan_id,
                ),
                "DEBUG",
            )
            ip_l3_handoff_detail = self.ip_l3_handoff_exists(
                fabric_site_id,
                network_device_id,
                transit_network_name,
                virtual_network_name,
                vlan_id,
            )
            fabric_devices_info.get("ip_l3_handoff_details").append(
                ip_l3_handoff_detail
            )

        self.log("Successfully processed the IP L3 Handoff information.", "DEBUG")
        return fabric_devices_info

    def get_have_fabric_devices(self, fabric_devices):
        """
        Retrieves SDA fabric devices information from Cisco Catalyst Center using the playbook inputs.

        Args:
            fabric_devices (dict): Dictionary containing fabric details such as fabric name and devices.

        Returns:
            self: Returns the instance with updated 'have.fabric_devices' information.

        Description:
            - Validates the presence of required parameters such as 'fabric_name' and 'device_ip'.
            - Retrieves site and fabric IDs, checks device existence, and provisioning state.
            - Fetches detailed information including wireless controller settings and handoff configurations (L2, L3 SDA, L3 IP).
            - Logs critical steps and errors during the process.
        """

        fabric_devices_details = []
        fabric_name = fabric_devices.get("fabric_name")

        # Fabric name is mandatory for this workflow
        if not fabric_name:
            self.msg = (
                "The required parameter 'fabric_name' in 'fabric_devices' is missing."
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.log(
            "Initiating site ID retrieval for fabric '{fabric_name}'.".format(
                fabric_name=fabric_name
            ),
            "INFO",
        )
        (site_exists, site_id) = self.get_site_id(fabric_name)
        self.log(
            "Retrieved site ID: {site_id}. Site exists: {site_exists}.".format(
                site_id=site_id, site_exists=site_exists
            ),
            "DEBUG",
        )
        self.log(
            "The site with the name '{site_name} exists in Cisco Catalyst Center is '{site_exists}'".format(
                site_name=fabric_name, site_exists=site_exists
            ),
            "DEBUG",
        )
        if not site_id:
            self.msg = "Invalid site hierarchy name '{site_name}'.".format(
                site_name=fabric_name
            )
            self.status = "failed"
            return self.check_return_status()

        self.log(
            "Fetching fabric site ID for site '{site_id}'.".format(site_id=site_id),
            "INFO",
        )
        fabric_site_id = self.get_fabric_site_id_from_name(fabric_name, site_id)
        if not fabric_site_id:
            fabric_site_id = self.get_fabric_zone_id_from_name(fabric_name, site_id)
            self.fabric_type = "fabric_zone"
            if not fabric_site_id:
                self.msg = "The provided 'fabric_name' '{fabric_name}' is not a valid fabric site.".format(
                    fabric_name=fabric_name
                )
                if self.params.get("state") == "deleted":
                    self.log(self.msg, "INFO")
                    self.result.get("response").append({"msg": self.msg})
                    self.status = "exited"
                    return self

                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            self.log(
                "Fabric zone ID obtained: {fabric_site_id}.".format(
                    fabric_site_id=fabric_site_id
                ),
                "DEBUG",
            )
        else:
            self.fabric_type = "fabric_site"
            self.log(
                "Fabric site ID obtained: {fabric_site_id}.".format(
                    fabric_site_id=fabric_site_id
                ),
                "DEBUG",
            )

        # device_config contains the list of devices on which the operations should be performed
        device_config = fabric_devices.get("device_config")
        if not device_config:
            self.msg = (
                "The parameter 'device_config' is mandatory under 'fabric_devices'."
            )
            self.status = "failed"
            return self

        for item in device_config:
            fabric_devices_info = {
                "exists": False,
                "device_details": None,
                "l2_handoff_details": [],
                "sda_l3_handoff_details": None,
                "ip_l3_handoff_details": [],
                "id": None,
                "fabric_site_id": None,
                "network_device_id": None,
                "wireless_controller_settings": None,
            }

            # Fabric device IP is mandatory for this workflow
            fabric_device_ip = item.get("device_ip")
            if not fabric_device_ip:
                self.msg = "The required parameter 'device_ip' in 'device_config' is missing under the fabric '{fabric_name}'.".format(
                    fabric_name=fabric_name
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            self.log(
                "Checking if device '{device_ip}' exists in fabric '{fabric_name}'.".format(
                    device_ip=fabric_device_ip, fabric_name=fabric_name
                ),
                "INFO",
            )
            self.log(
                "Fetching network device ID for IP '{device_ip}'.".format(
                    device_ip=fabric_device_ip
                ),
                "INFO",
            )
            network_device_details = self.get_device_details_from_ip(fabric_device_ip)
            if not network_device_details:
                self.msg = "The 'device_ip' '{ip}' in 'device_config' is not a valid IP under the fabric '{fabric_name}'.".format(
                    ip=fabric_device_ip, fabric_name=fabric_name
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            self.log(
                "The device with the IP {ip} is a valid network device IP.".format(
                    ip=fabric_device_ip
                ),
                "DEBUG",
            )
            network_device_id = network_device_details[0].get("id")
            self.log(
                "Obtained network device ID: {network_device_id}.".format(
                    network_device_id=network_device_id
                ),
                "DEBUG",
            )
            family_name = network_device_details[0].get("family")
            if family_name != "Wireless Controller":
                self.log(
                    "The device with the IP '{ip}' is not a Wireless Controller, "
                    "proceeding with provisioning checks.".format(ip=fabric_device_ip),
                    "DEBUG",
                )
                state = self.params.get("state")
                if state == "deleted":
                    self.log(
                        f"The state is 'deleted', so skipping the provisioning checks for the device with the IP '{fabric_device_ip}'.",
                        "DEBUG",
                    )
                else:
                    self.log(
                        f"Checking if the device with the IP '{fabric_device_ip}' is provisioned in the fabric '{fabric_name}'.",
                        "DEBUG",
                    )
                    self.check_device_is_provisioned(
                        fabric_device_ip, network_device_id, site_id, fabric_name
                    ).check_return_status()
            else:
                self.log(
                    "The device with the IP '{ip}' is a Wireless Controller, "
                    "skipping provisioning checks."
                )

            fabric_devices_info.update(
                {
                    "fabric_site_id": fabric_site_id,
                    "network_device_id": network_device_id,
                }
            )
            device_info = self.fabric_device_exists(
                fabric_site_id, network_device_id, fabric_device_ip
            )
            fabric_devices_info.update(
                {
                    "exists": device_info.get("exists"),
                    "id": device_info.get("id"),
                    "device_details": device_info.get("device_details"),
                }
            )
            device_exists = fabric_devices_info.get("exists")
            if not device_exists:
                self.log(
                    "Device '{device_ip}' not found in fabric site '{fabric_name}'. Marking for addition.".format(
                        device_ip=fabric_device_ip, fabric_name=fabric_name
                    ),
                    "DEBUG",
                )
                fabric_devices_details.append(fabric_devices_info)
                continue

            device_roles = device_info.get("device_details").get("deviceRoles")

            self.log(
                f"Fetching wireless controller settings for the fabric '{fabric_name}'.",
                "DEBUG",
            )
            if self.fabric_type == "fabric_site":
                wireless_controller_settings = self.get_have_wireless_controller_settings(
                    fabric_name, fabric_site_id, network_device_id, fabric_device_ip
                )
                fabric_devices_info.update(
                    {"wireless_controller_settings": wireless_controller_settings}
                )
            else:
                self.log(f"Fabric type is '{self.fabric_type}', skipping wireless controller settings retrieval.", "DEBUG")

            is_border_device = False
            if "BORDER_NODE" in device_roles:
                is_border_device = True

            self.log(
                "Device '{device_ip}' roles identified: {roles}. Is Border Device: {is_border_device}".format(
                    device_ip=fabric_device_ip,
                    roles=device_roles,
                    is_border_device=is_border_device,
                ),
                "DEBUG",
            )

            # The border settings is active on when the device has a role of the border node
            borders_settings = item.get("borders_settings")
            if is_border_device and borders_settings:
                self.process_layer2_handoff(
                    fabric_devices_info,
                    borders_settings.get("layer2_handoff"),
                    fabric_site_id,
                    network_device_id,
                    fabric_device_ip,
                )
                self.process_layer3_sda_handoff(
                    fabric_devices_info,
                    borders_settings.get("layer3_handoff_sda_transit"),
                    fabric_site_id,
                    network_device_id,
                    fabric_device_ip,
                )
                self.process_layer3_ip_handoff(
                    fabric_devices_info,
                    borders_settings.get("layer3_handoff_ip_transit"),
                    fabric_site_id,
                    network_device_id,
                    fabric_device_ip,
                )

            self.log(
                "SDA fabric device exists for '{ip}': {exists}".format(
                    ip=fabric_device_ip, exists=fabric_devices_info.get("exists")
                ),
                "DEBUG",
            )
            self.log(
                "SDA fabric device details for '{ip}': {device_details}".format(
                    ip=fabric_device_ip,
                    device_details=fabric_devices_info.get("device_details"),
                ),
                "DEBUG",
            )
            self.log(
                "SDA fabric device ID for '{ip}': {id}".format(
                    ip=fabric_device_ip, id=fabric_devices_info.get("id")
                ),
                "DEBUG",
            )
            self.log(
                "L2 handoff details for '{ip}': '{l2_handoff_details}'".format(
                    ip=fabric_device_ip,
                    l2_handoff_details=fabric_devices_info.get("l2_handoff_details"),
                ),
                "DEBUG",
            )
            self.log(
                "L3 SDA handoff details for '{ip}': '{sda_l3_handoff_details}'".format(
                    ip=fabric_device_ip,
                    sda_l3_handoff_details=fabric_devices_info.get(
                        "sda_l3_handoff_details"
                    ),
                ),
                "DEBUG",
            )
            self.log(
                "L3 IP handoff details for '{ip}': '{ip_l3_handoff_details}'".format(
                    ip=fabric_device_ip,
                    ip_l3_handoff_details=fabric_devices_info.get(
                        "ip_l3_handoff_details"
                    ),
                ),
                "DEBUG",
            )
            fabric_devices_details.append(fabric_devices_info)

        self.log(
            "All fabric devices details collected for fabric '{fabric_name}': {details}".format(
                fabric_name=fabric_name, details=fabric_devices_details
            ),
            "INFO",
        )
        self.have.update({"fabric_devices": fabric_devices_details})
        self.msg = (
            "Collecting the SDA fabric devices details from the Cisco Catalyst Center."
        )
        self.status = "success"
        return self

    def get_sda_wireless_details_for_switches(
        self, fabric_name, fabric_id, network_device_id, fabric_device_ip
    ):
        """
        Retrieves SDA wireless details for a specific switch in a given fabric.

        Args:
            fabric_name (str): Name of the fabric to query.
            fabric_id (str): ID of the fabric in Cisco Catalyst Center.
            network_device_id (str): Network device ID of the target switch.
            fabric_device_ip (str): IP address of the switch.

        Returns:
            dict or None: The wireless details dictionary for the matching switch, or None if not found.

        Description:
            This function invokes the Cisco Catalyst Center SDA API to retrieve wireless configuration data from
            switches belonging to the specified fabric. It filters the response to find and return the details for
            the switch with the provided network_device_id. If the switch is not found or the API response is empty,
            the function returns None. If an exception occurs during the API call, it logs and raises the error.
        """

        self.log(
            f"Retrieving SDA wireless details from fabric '{fabric_name}' (ID: '{fabric_id}') to "
            f"find switch with device ID '{network_device_id}' (IP: '{fabric_device_ip}').",
            "DEBUG",
        )
        try:
            response = self.dnac._exec(
                family="fabric_wireless",
                function="get_sda_wireless_details_from_switches",
                params={"fabric_id": fabric_id},
            )

            self.log(
                f"Received API response from 'get_sda_wireless_details_from_switches' for the fabric '{fabric_name}': {response}",
                "DEBUG",
            )

            wireless_data = response.get("response")

            if not isinstance(wireless_data, list) or not wireless_data:
                self.log(
                    f"No wireless details found or response is not a list for fabric: '{fabric_name}'. Response: {wireless_data}",
                    "DEBUG",
                )
                return None

            self.log(
                f"{len(wireless_data)} wireless-configured switches retrieved for fabric '{fabric_name}'.",
                "DEBUG",
            )

            for switch_data in wireless_data:
                current_id = switch_data.get("id")
                self.log(
                    f"Inspecting device with ID '{current_id}' for match with '{network_device_id}'.",
                    "DEBUG",
                )
                if current_id == network_device_id:
                    self.log(
                        f"Match found. Wireless details for switch (IP: '{fabric_device_ip}') in fabric '{fabric_name}': {self.pprint(switch_data)}",
                        "DEBUG",
                    )
                    return switch_data

            self.log(
                f"No wireless configuration found for switch (Device ID: '{network_device_id}', IP: '{fabric_device_ip}') in fabric '{fabric_name}'.",
                "DEBUG",
            )
            return None

        except Exception as e:
            self.log(
                f"Exception occurred while retrieving wireless details for fabric '{fabric_name}': {e}",
                "ERROR",
            )
            self.msg = f"Error retrieving wireless details for fabric '{fabric_name}' from Cisco Catalyst Center: {e}"
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

    def get_managed_ap_locations_for_network_device(
        self, fabric_device_ip, network_device_id, ap_type="primary"
    ):
        """
        Retrieves managed AP locations (primary or secondary) associated with a specific device.

        Args:
            fabric_device_ip (str): IP address of the network device.
            network_device_id (str): Network device ID of the device in Cisco Catalyst Center.
            ap_type (str): Type of AP locations to retrieve: 'primary' or 'secondary'. Defaults to 'primary'.

        Returns:
            list: A list of managed AP location objects associated with the given device.

        Description:
            This function paginates through the Cisco Catalyst Center API to retrieve all primary or secondary managed
            AP locations managed by the specified device. It uses the Catalyst Center API client to make paginated requests
            and aggregates the responses into a single list. Handles retries and gracefully exits on specific known
            API error messages.
        """
        self.log(
            f"Starting retrieval of {ap_type} managed AP locations for device (IP: '{fabric_device_ip}', ID: '{network_device_id}').",
            "DEBUG",
        )

        allowed_ap_type = ["primary", "secondary"]
        if ap_type not in allowed_ap_type:
            self.log(
                f"Invalid ap_type: '{ap_type}' provided. Allowed types: {', '.join(allowed_ap_type)}",
                "ERROR",
            )
            return []

        api_function = (
            f"get_{ap_type}_managed_ap_locations_for_specific_wireless_controller"
        )

        managed_ap_locations_all = []
        offset = 1
        limit = 500
        batch_count = 0

        while True:
            batch_count += 1
            self.log(
                f"Batch {batch_count}: Requesting {ap_type} managed AP locations (offset={offset}, limit={limit}) for device '{fabric_device_ip}'.",
                "DEBUG",
            )

            try:
                response = self.dnac._exec(
                    family="wireless",
                    function=api_function,
                    op_modifies=False,
                    params={
                        "network_device_id": network_device_id,
                        "limit": limit,
                        "offset": offset,
                    },
                )

                self.log(
                    f"API Response ({ap_type.capitalize()} Managed AP Locations) for device '{fabric_device_ip}' (Offset {offset}): {response}",
                    "DEBUG",
                )

                if not isinstance(response, dict):
                    self.log(
                        f"Invalid API response type: {type(response)} received. Cannot extract AP locations.",
                        "ERROR",
                    )
                    self.fail_and_exit("Unexpected response from Catalyst Center API.")

                managed_ap_response = response.get("response")
                if not managed_ap_response:
                    self.log(
                        f"Batch {batch_count}: No {ap_type} managed AP locations found in response for device '{fabric_device_ip}'. Stopping pagination.",
                        "DEBUG",
                    )
                    break

                managed_ap_locations = managed_ap_response.get("managedApLocations", [])
                count = len(managed_ap_locations)

                self.log(
                    f"Batch {batch_count}: Retrieved {count} {ap_type} managed AP locations.",
                    "DEBUG",
                )

                if not managed_ap_locations:
                    self.log(
                        f"Batch {batch_count}: No AP locations in response. Stopping pagination.",
                        "DEBUG",
                    )
                    break

                managed_ap_locations_all.extend(managed_ap_locations)

                if count < limit:
                    self.log(
                        f"Batch {batch_count}: AP locations in response: {count} less than limit: {limit}. Stopping pagination."
                        "DEBUG",
                    )
                    break

                offset += limit

            except Exception as e:
                if (
                    "no locations were discovered corresponding to the specified wireless controller"
                    in str(e).lower()
                ):
                    self.log(
                        f"No more {ap_type} managed AP locations found in batch '{batch_count}' for device '{fabric_device_ip}'.",
                        "DEBUG",
                    )
                    break

                self.msg = f"Error occurred while retrieving {ap_type} managed AP locations for device '{fabric_device_ip}': {e}"
                self.fail_and_exit(self.msg)

        self.log(
            f"Completed retrieval. Total number of {ap_type} managed AP locations fetched: {len(managed_ap_locations_all)}\n"
            f"{ap_type} managed AP locations are: {self.pprint(managed_ap_locations_all)}",
            "INFO",
        )
        return managed_ap_locations_all

    def get_have_wireless_controller_settings(
        self, fabric_name, fabric_site_id, network_device_id, fabric_device_ip
    ):
        """
        Retrieves wireless controller settings (including primary/secondary scopes and rolling AP upgrade)
        for a given device in a specified SDA fabric.

        Args:
            fabric_name (str): Name of the fabric.
            fabric_site_id (str): ID of the fabric site.
            network_device_id (str): Network device ID.
            fabric_device_ip (str): IP address of the network device.

        Returns:
            dict or None: Dictionary containing wireless controller settings including:
                        - enable (bool)
                        - rolling_ap_upgrade (dict with 'enable' and 'ap_reboot_percentage')
                        - primary_managed_ap_locations (list)
                        - secondary_managed_ap_locations (list)
                        Returns None if the Catalyst Center version does not support wireless controller settings.

        Description:
            This function checks the Cisco Catalyst Center version for compatibility of wireless settings.
            If supported, it retrieves SDA wireless details, primary and secondary managed AP locations,
            and rolling AP upgrade settings for the specified wireless controller.
        """

        self.log(
            f"Initializing retrieval of wireless controller settings for device with IP Address '{fabric_device_ip}' "
            f"in fabric '{fabric_name}'.",
            "DEBUG",
        )
        ccc_version = self.get_ccc_version()
        if self.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
            self.log(
                f"Wireless controller settings are not supported in Catalyst Center version '{ccc_version}'. "
                "Minimum required version is 2.3.7.9. Returning None.",
                "DEBUG",
            )
            return None

        self.log(
            f"Catalyst Center version '{ccc_version}' supports wireless controller settings. "
            f"Proceeding with configuration check for device with IP Address '{fabric_device_ip}' in fabric '{fabric_name}'.",
            "DEBUG",
        )

        wireless_controller_settings = {
            "enable": False,
            "primary_managed_ap_locations": None,
            "secondary_managed_ap_locations": None,
            "rolling_ap_upgrade": None,
        }

        sda_wireless_details = self.get_sda_wireless_details_for_switches(
            fabric_name, fabric_site_id, network_device_id, fabric_device_ip
        )
        self.log(
            f"SDA wireless details retrieved for device with IP address '{fabric_device_ip}': "
            f"{self.pprint(sda_wireless_details)}",
            "DEBUG",
        )
        if sda_wireless_details:
            rolling_ap_upgrade_details = sda_wireless_details.get("rollingApUpgrade")
            self.log(
                f"Rolling AP Upgrade details for device with IP address '{fabric_device_ip}' in fabric '{fabric_name}': "
                f"{self.pprint(rolling_ap_upgrade_details)}",
                "DEBUG",
            )
            wireless_controller_settings.update(
                {
                    "enable": True,
                    "rolling_ap_upgrade": {
                        "enable": rolling_ap_upgrade_details.get(
                            "enableRollingApUpgrade"
                        ),
                        "ap_reboot_percentage": rolling_ap_upgrade_details.get(
                            "apRebootPercentage"
                        ),
                    },
                }
            )
        else:
            self.log(
                f"No SDA wireless details found for device with IP address '{fabric_device_ip}' in fabric '{fabric_name}'.",
                "DEBUG",
            )

        primary_managed_ap_locations_details = (
            self.get_managed_ap_locations_for_network_device(
                fabric_device_ip, network_device_id, ap_type="primary"
            )
        )
        self.log(
            f"Primary scope details retrieved for device with IP Address '{fabric_device_ip}': {self.pprint(primary_managed_ap_locations_details)}",
            "DEBUG",
        )

        secondary_managed_ap_locations_details = (
            self.get_managed_ap_locations_for_network_device(
                fabric_device_ip, network_device_id, ap_type="secondary"
            )
        )
        self.log(
            f"Secondary scope details retrieved for device with IP Address '{fabric_device_ip}': {self.pprint(secondary_managed_ap_locations_details)}",
            "DEBUG",
        )

        wireless_controller_settings.update(
            {
                "primary_managed_ap_locations": primary_managed_ap_locations_details,
                "secondary_managed_ap_locations": secondary_managed_ap_locations_details,
            }
        )

        self.log(
            f"AP Scope Summary for device IP '{fabric_device_ip}' in fabric '{fabric_name}': "
            f"Primary Scope Count = {len(primary_managed_ap_locations_details)}, Secondary Scope Count = {len(secondary_managed_ap_locations_details)}",
            "DEBUG",
        )
        self.log(
            f"Final wireless controller settings for device IP '{fabric_device_ip}' in fabric '{fabric_name}': "
            f"{self.pprint(wireless_controller_settings)}",
            "INFO",
        )
        return wireless_controller_settings

    def get_have(self, config):
        """
        Get the SDA fabric devices related information from Cisco Catalyst Center.

        Parameters:
            config (dict): Playbook details containing fabric devices details.
        Returns:
            self: The current object with updated fabric devices details.
        Description:
            Check the fabric_devices. If it is not available, return with a msg by setting the
            self.status as 'failed' and return self.
            Call the 'get_have_fabric_devices' function to collect the information
            about the fabric devices in the Cisco Catalyst Center.
        """

        self.log("Starting to retrieve SDA fabric devices information.", "INFO")
        fabric_devices = config.get("fabric_devices")
        if not fabric_devices:
            self.msg = "The parameter 'fabric_devices' is missing under the 'config'."
            self.status = "failed"
            return self

        self.log("Fabric devices found in config. Proceeding with retrieval.", "DEBUG")
        self.get_have_fabric_devices(fabric_devices).check_return_status()
        self.log(
            "Fabric devices information retrieval was successful. Details: {details}".format(
                details=self.have
            ),
            "DEBUG",
        )
        self.log(
            "Current State (have): {current_state}".format(current_state=self.have),
            "INFO",
        )
        self.msg = "Successfully retrieved the SDA fabric devices details from the Cisco Catalyst Center."
        self.status = "success"
        return self

    def validate_local_autonomous_system_number(
        self, local_autonomous_system_number, device_ip
    ):
        """
        Validate the local autonomous system number for the border settings.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            local_autonomous_system_number (str): Local Autonomous System number of the border device.
            device_ip (str): The IP address of the network device.
        Description:
            The Local Autonomous System number can of two format. One is from 1 to 4294967295.
            The other one can be of dot format. from 1.0 to 65535.65535.
            Find '.' is in the 'local_autonomous_system_number'. If yes split it into two part
            and check if the left part is between 1 to 65535 and the right part is from
            0 to 65535. If the '.' is not present in the 'local_autonomous_system_number',
            check if the value is between 1 to 4294967295.
        """

        try:
            str_asn = str(local_autonomous_system_number)
            if "." in str_asn:

                # Split the input into two parts
                parts = str_asn.split(".")
                if len(parts) == 2:
                    first_part = int(parts[0])
                    second_part = int(parts[1])

                    # Validate the range for both parts
                    if 1 <= first_part <= 65535 and 0 <= second_part <= 65535:
                        self.log(
                            "Input is valid in the format 1.0 to 65535.65535", "INFO"
                        )
                    else:
                        self.msg = "The 'local_autonomous_system_number' should be in the range '1.0' to '65535.65535' for the device '{ip}'.".format(
                            ip=device_ip
                        )
                        self.status = "failed"
                        return self.check_return_status()
                else:
                    self.msg = "The 'local_autonomous_system_number' should contain one '.' and two numeric parts for the device '{ip}'.".format(
                        ip=device_ip
                    )
                    self.status = "failed"
                    return self.check_return_status()
            else:
                local_autonomous_system_number = int(local_autonomous_system_number)
                if not 1 <= local_autonomous_system_number <= 4294967295:
                    self.msg = "The 'local_autonomous_system_number' should be from 1 to 4294967295 for the device '{ip}'.".format(
                        ip=device_ip
                    )
                    self.status = "failed"
                    return self.check_return_status()

        except ValueError:
            self.msg = "The 'local_autonomous_system_number' should contain only digits 0-9 for the device '{ip}'.".format(
                ip=device_ip
            )
            self.status = "failed"
            return self.check_return_status()

        self.log("The 'local_autonomous_system_number' is successfully validated.")
        return

    def validate_device_roles(self, device_roles, device_ip):
        """
        Validate the device roles against the list of valid roles.

        Parameters:
            device_roles (list): The list of device roles to validate.
            device_ip (str): The IP address of the device.

        Returns:
            None

        Description:
            Validate the device roles against the list of valid roles.
            If any device_role is not correct, The workflow will fail with an error.
        """
        if not device_roles:
            self.msg = f"The 'device_roles' list cannot be empty for the IP '{device_ip}'."
            self.fail_and_exit(self.msg)

        valid_device_roles_list = [
            "CONTROL_PLANE_NODE",
            "EDGE_NODE",
            "BORDER_NODE",
            "WIRELESS_CONTROLLER_NODE",
        ]
        for device_role in device_roles:
            if device_role not in valid_device_roles_list:
                self.msg = f"The value '{device_role}' in 'device_roles' for the IP '{device_ip}' should be in the list '{', '.join(valid_device_roles_list)}'."
                self.fail_and_exit(self.msg)

        return

    def get_device_params(self, fabric_id, network_id, device_details, config_index):
        """
        Get the SDA fabric devices detail along with the border
        settings information from playbook.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            fabric_id (str): The Id of the fabric site.
            network_id (str): The Id of the network device.
            device_details (dict): Playbook details containing fabric devices details along
            with the Border Settings, L2 Handoff, L3 SDA Handoff, L3 IP Handoff information.
            config_index (int): Pointer to the device_config elements in the playbook.
        Returns:
            device_info (dict): The processed device details from the user playbook.
        Description:
            Get the device details from the playbook and do the basic validation and
            do the checks which is done by the GUI.
            Return the device details.
        """

        self.log(
            "Starting get_device_params with fabric_id: {fabric_id}, network_id: {network_id}, config_index: {config_index}".format(
                fabric_id=fabric_id, network_id=network_id, config_index=config_index
            ),
            "DEBUG",
        )
        device_ip = device_details.get("device_ip")
        self.log("Device IP retrieved: {ip}".format(ip=device_ip), "DEBUG")
        device_info = {
            "networkDeviceId": network_id,
            "fabricId": fabric_id,
            "embedded_wireless_controller_capabilities": False
        }

        # If the user didnot provide the mandatory information and if it can be
        # retrieved from the Cisco Catalyst Center, we will use it
        have_device_details = self.have.get("fabric_devices")[config_index].get(
            "device_details"
        )
        self.log(
            "Existing device details found: {device_details}".format(
                device_details=have_device_details
            ),
            "DEBUG",
        )
        have_device_exists = False
        if have_device_details:
            have_device_exists = self.have.get("fabric_devices")[config_index].get(
                "exists"
            )

        self.log(
            "Device exists status: {device_exists}".format(
                device_exists=have_device_exists
            ),
            "DEBUG",
        )

        # Device IP and the Fabric name is mandatory and cannot be fetched from the Cisco Catalyst Center
        device_roles = device_details.get("device_roles")
        if not device_roles:
            self.log("Device roles not provided for device {ip}.".format(ip=device_ip))
            if have_device_exists:
                self.log(
                    "The device details with ip '{ip}' is already present in the Cisco Catalyst Center.".format(
                        ip=device_ip
                    )
                )
                device_roles = have_device_details.get("deviceRoles")

            if not device_roles:
                self.msg = (
                    "The parameter 'device_roles is mandatory under 'device_config' "
                    "for the device with IP '{ip}'.".format(ip=device_ip)
                )
                self.log(str(self.msg), "ERROR")
                self.status = "failed"
                return self.check_return_status()

        self.log("Device roles provided: {roles}".format(roles=device_roles), "DEBUG")
        if sorted(device_roles) == ["CONTROL_PLANE_NODE", "EDGE_NODE"]:
            self.msg = (
                "The current combination of roles {device_roles} is invalid. "
                "An EDGE_NODE in a fabric cannot be a CONTROL_PLANE_NODE.".format(
                    device_roles=device_roles
                )
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            self.check_return_status()
        if device_roles == ["WIRELESS_CONTROLLER_NODE"]:
            self.log("Device is a Wireless Controller.", "DEBUG")
            device_info["embedded_wireless_controller_capabilities"] = False
        else:
            self.log("Device is a switch with Embedded Wireless Controller capabilities.", "DEBUG")
            device_info["embedded_wireless_controller_capabilities"] = True
            if not have_device_exists:
                if not device_roles:
                    self.msg = (
                        "The parameter 'device_roles is mandatory under 'device_config' "
                        "for the device with IP '{ip}'.".format(ip=device_ip)
                    )
                    self.fail_and_exit(self.msg)

                self.validate_device_roles(device_roles, device_ip)

                if "WIRELESS_CONTROLLER_NODE" in device_roles:
                    device_roles.remove("WIRELESS_CONTROLLER_NODE")
                    # WIRELESS_CONTROLLER_NODE is added from backend and can't be passed to the API if not present in the backend.
            else:
                if device_roles is None:
                    device_roles = have_device_details.get("deviceRoles")
                else:
                    self.validate_device_roles(device_roles, device_ip)
                    have_wireless_controller_node = (
                        "WIRELESS_CONTROLLER_NODE" in have_device_details.get("deviceRoles")
                    )
                    want_wireless_controller_node = "WIRELESS_CONTROLLER_NODE" in device_roles

                    if want_wireless_controller_node and not have_wireless_controller_node:
                        device_roles.remove("WIRELESS_CONTROLLER_NODE")
                        # WIRELESS_CONTROLLER_NODE is added from backend and can't be passed to the API if not present in the backend.

                    if sorted(device_roles) != sorted(have_device_details.get("deviceRoles")):
                        self.msg = "The parameter 'device_roles' cannot be updated in the device with IP '{ip}'.".format(
                            ip=device_ip
                        )
                        self.fail_and_exit(self.msg)

        device_info.update({"deviceRoles": device_roles})
        self.log(
            "Device info updated with roles: {device_info}".format(
                device_info=device_info
            ),
            "DEBUG",
        )
        if "BORDER_NODE" not in device_roles:
            self.log(
                "Device does not have 'BORDER_NODE' role, returning device_info",
                "DEBUG",
            )
            return device_info

        self.log("Device has 'BORDER_NODE' role; processing border settings", "DEBUG")
        borders_settings = device_details.get("borders_settings")
        have_border_settings = None

        # Get the border settings details from the Cisco Catalyst Center, if available
        if have_device_details:
            have_border_settings = have_device_details.get("borderDeviceSettings")

        if not borders_settings:
            if not have_border_settings:
                self.msg = (
                    "The parameter 'borders_settings' is mandatory when the 'device_roles' has 'BORDER_NODE' "
                    "for the device {ip}.".format(ip=device_ip)
                )
                self.status = "failed"
                return self.check_return_status()

            device_info.update({"borderDeviceSettings": have_border_settings})
            self.log(
                "Border settings retrieved from existing data: {have_border_settings}".format(
                    have_border_settings=have_border_settings
                ),
                "DEBUG",
            )
            return device_info

        self.log("Processing user-provided border settings", "DEBUG")
        border_device_settings = {}
        border_types = []
        layer3_settings = borders_settings.get("layer3_settings")
        layer3_handoff_ip_transit = borders_settings.get("layer3_handoff_ip_transit")
        layer3_handoff_sda_transit = borders_settings.get("layer3_handoff_sda_transit")
        if layer3_settings:
            border_types.append("LAYER_3")
        elif layer3_handoff_ip_transit:
            border_types.append("LAYER_3")
        elif layer3_handoff_sda_transit:
            border_types.append("LAYER_3")
        elif "BORDER_NODE" in device_roles:
            border_types.append("LAYER_3")

        l2_handoff = borders_settings.get("layer2_handoff")
        if l2_handoff:
            border_types.append("LAYER_2")

        if have_border_settings:
            border_types = have_border_settings.get("borderTypes")

        if not border_types:
            self.msg = (
                "The 'layer3_settings' parameter is required under 'borders_settings' when "
                "'device_roles' includes 'BORDER_NODE' for device {ip}.".format(
                    ip=device_ip
                )
            )
            self.status = "failed"
            return self.check_return_status()

        border_device_settings.update({"borderTypes": border_types})

        # Get the border settings from the Cisco Catalyst Center
        have_layer3_settings = None
        if have_border_settings:
            have_layer3_settings = have_border_settings.get("layer3Settings")

        if "LAYER_3" in border_types:
            if not layer3_settings:
                self.log(
                    "The layer 3 settings is not provided in the playbook for the device '{ip}'.".format(
                        ip=device_ip
                    ),
                    "DEBUG",
                )
                if not have_layer3_settings:
                    self.log(
                        "The layer 3 settings of the device '{ip}' is not available in the Cisco Catalyst Center.".format(
                            ip=device_ip
                        ),
                        "DEBUG",
                    )
                    self.msg = (
                        "The parameter 'layer3_settings' is mandatory under 'borders_settings' when the "
                        "'device_roles' has 'BORDER_NODE' for the device {ip}.".format(
                            ip=device_ip
                        )
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()
                else:
                    self.log(
                        "Copying the layer 3 settings details of the device '{ip}' "
                        "from the Cisco Catalyst Center: {details}".format(
                            ip=device_ip, details=have_layer3_settings
                        ),
                        "DEBUG",
                    )
                    layer3_settings = have_layer3_settings

            local_autonomous_system_number = layer3_settings.get(
                "local_autonomous_system_number"
            )
            self.log(
                "Local AS number: {asn_number}".format(
                    asn_number=local_autonomous_system_number
                ),
                "DEBUG",
            )
            if local_autonomous_system_number is None:
                if have_layer3_settings:
                    local_autonomous_system_number = have_layer3_settings.get(
                        "localAutonomousSystemNumber"
                    )
                else:
                    self.msg = (
                        "The parameter 'local_autonomous_system_number' is mandatory for the 'layer3_settings' "
                        "for the device with IP '{ip}'.".format(ip=device_ip)
                    )
                    self.status = "failed"
                    return self.check_return_status()
            else:
                existing_as_number = (
                    have_layer3_settings.get("localAutonomousSystemNumber")
                    if have_layer3_settings
                    else None
                )
                if existing_as_number and str(local_autonomous_system_number) != str(
                    existing_as_number
                ):
                    self.msg = (
                        "The parameter 'local_autonomous_system_number' in 'layer3_settings' must not be updated "
                        "for the device with IP '{ip}'.".format(ip=device_ip)
                    )
                    self.status = "failed"
                    return self.check_return_status()

            self.validate_local_autonomous_system_number(
                local_autonomous_system_number, device_ip
            )
            self.log(
                "Successfully validated 'local_autonomous_system_number': {asn_number}".format(
                    asn_number=local_autonomous_system_number
                ),
                "DEBUG",
            )
            is_default_exit = layer3_settings.get("is_default_exit")
            if is_default_exit is None:
                if have_layer3_settings:
                    is_default_exit = have_layer3_settings.get("isDefaultExit", True)
                else:
                    is_default_exit = True
            else:
                if have_layer3_settings:
                    if is_default_exit != have_layer3_settings.get("isDefaultExit"):
                        self.msg = (
                            "The parameter 'is_default_exit' under 'layer3_settings' should not be "
                            "updated for the device with IP '{ip}'.".format(
                                ip=device_ip
                            )
                        )
                        self.set_operation_result(
                            "failed", False, self.msg, "ERROR"
                        ).check_return_status()

            import_external_routes = layer3_settings.get("import_external_routes")
            if import_external_routes is None:
                if have_layer3_settings:
                    have_import_external_routes = have_layer3_settings.get(
                        "importExternalRoutes"
                    )
                    import_external_routes = have_import_external_routes
                else:
                    import_external_routes = True
            else:
                if have_layer3_settings:
                    have_import_external_routes = have_layer3_settings.get(
                        "importExternalRoutes"
                    )
                    if import_external_routes != have_import_external_routes:
                        self.msg = (
                            "The parameter 'import_external_routes' under 'layer3_settings' should not be "
                            "updated for the device with IP '{ip}'.".format(
                                ip=device_ip
                            )
                        )
                        self.status = "failed"
                        return self.check_return_status()

            border_priority = layer3_settings.get("border_priority")
            # Default value of border priority is 10
            # we can se the border priority from 0 to 9
            if not border_priority:
                if have_layer3_settings:
                    have_border_priority = have_layer3_settings.get("borderPriority")
                    if have_border_priority and have_border_priority != 10:
                        border_priority = have_border_priority
            else:
                try:
                    border_priority = int(border_priority)
                    if not 1 <= border_priority <= 9:
                        self.msg = "The 'border_priority' should be from 1 to 9 for the device '{ip}'.".format(
                            ip=device_ip
                        )
                        self.status = "failed"
                        return self.check_return_status()

                except ValueError:
                    self.msg = "The 'border_priority' should contain only digits 0-9 for the device '{ip}'.".format(
                        ip=device_ip
                    )
                    self.status = "failed"
                    return self.check_return_status()

            prepend_autonomous_system_count = layer3_settings.get(
                "prepend_autonomous_system_count"
            )
            # Default value of prepend autonomous system count is 0
            # we can se the prepend autonomous system count from 1 to 10
            if not prepend_autonomous_system_count:
                if have_layer3_settings:
                    have_prepend_autonomous_system_count = have_layer3_settings.get(
                        "prependAutonomousSystemCount"
                    )
                    if (
                        have_prepend_autonomous_system_count
                        and have_prepend_autonomous_system_count != 0
                    ):
                        prepend_autonomous_system_count = (
                            have_prepend_autonomous_system_count
                        )
            else:
                try:
                    prepend_autonomous_system_count = int(
                        prepend_autonomous_system_count
                    )
                    if not 1 <= prepend_autonomous_system_count <= 10:
                        self.msg = "The 'prepend_autonomous_system_count' should be from 1 to 10 for the device '{ip}'.".format(
                            ip=device_ip
                        )
                        self.status = "failed"
                        return self.check_return_status()

                except ValueError:
                    self.msg = "The 'prepend_autonomous_system_count' should contain only digits 0-9 for the device '{ip}'.".format(
                        ip=device_ip
                    )
                    self.status = "failed"
                    return self.check_return_status()

            border_device_settings.update(
                {
                    "layer3Settings": {
                        "localAutonomousSystemNumber": str(
                            local_autonomous_system_number
                        ),
                        "isDefaultExit": is_default_exit,
                        "importExternalRoutes": import_external_routes,
                    }
                }
            )
            if border_priority:
                border_device_settings.get("layer3Settings").update(
                    {
                        "borderPriority": border_priority,
                    }
                )

            if prepend_autonomous_system_count:
                border_device_settings.get("layer3Settings").update(
                    {
                        "prependAutonomousSystemCount": prepend_autonomous_system_count,
                    }
                )

            device_info.update({"borderDeviceSettings": border_device_settings})
            self.log(
                "Final device info: {device_info}".format(device_info=device_info),
                "DEBUG",
            )

        return device_info

    def validate_vlan_fields(self, internal_vlan_id, external_vlan_id, device_ip):
        """
        Get the L2 Handoff of the SDA fabric devices information from playbook.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            fabric_id (str): The Id of the fabric site.
            network_id (str): The Id of the network device.
            device_details (dict): Playbook details containing fabric devices details along
            with the Border Settings, L2 Handoff, L3 SDA Handoff, L3 IP Handoff information.
            device_config_index (int): The index of the device details in the device_config.
        Returns:
            l2_handoff_info (list): The processed L2 Handoff details from the user playbook.
        Description:
            Validate the existence of the internal_vlan_id and external_vlan_id.
            Check whether the vlan ID is in reserved vlan id and within the range.
        """

        if not internal_vlan_id:
            return (
                "The 'interface_name' is mandatory under 'layer2_handoff' for device with IP '{ip}'".format(
                    ip=device_ip
                ),
                "failed",
            )

        # Internal vlan id can be from 2 to 4094
        # Except 1002, 1003, 1004, 1005, 2046, 4094
        try:
            internal_vlan_id = int(internal_vlan_id)
            reserved_vlans = [1, 1002, 1003, 1004, 1005, 2046, 4094]
            if not (2 <= internal_vlan_id <= 4094):
                return (
                    "The 'internal_vlan_id' should be from 2 to 4094 for the device '{ip}'.".format(
                        ip=device_ip
                    ),
                    "failed",
                )

            if not (internal_vlan_id not in reserved_vlans):
                return (
                    "The 'internal_vlan_id' should not be a reserved VLAN '{reserved_vlan}' for the device '{ip}'.".format(
                        reserved_vlan=reserved_vlans, ip=device_ip
                    ),
                    "failed",
                )

        except ValueError:
            return (
                "The 'internal_vlan_id' should contain only digits 0-9 for the device '{ip}'.".format(
                    ip=device_ip
                ),
                "failed",
            )

        if not external_vlan_id:
            return (
                "The 'external_vlan_id' is mandatory under 'layer2_handoff' for "
                "the device with IP '{ip}'".format(ip=device_ip),
                "failed",
            )

        # External vlan id can be from 2 to 4094
        # Except 1002, 1003, 1004, 1005, 2046, 4094
        try:
            external_vlan_id = int(external_vlan_id)
            reserved_vlans = [1, 1002, 1003, 1004, 1005, 2046, 4094]
            if not (2 <= external_vlan_id <= 4094):
                return (
                    "The 'external_vlan_id' should be from 2 to 4094 for the device '{ip}'.".format(
                        ip=device_ip
                    ),
                    "failed",
                )

            if not (external_vlan_id not in reserved_vlans):
                return (
                    "The 'external_vlan_id' should not be a reserved VLAN '{reserved_vlan}' for the device '{ip}'.".format(
                        reserved_vlan=reserved_vlans, ip=device_ip
                    ),
                    "failed",
                )

        except ValueError:
            return (
                "The 'external_vlan_id' should contain only digits 0-9 for the device '{ip}'.".format(
                    ip=device_ip
                ),
                "failed",
            )

        return None

    def check_transit_type(self, transit_id):
        """
        Check whether the given transit id is LISP/PUB SUB or LISP/BGP.

        Parameters:
            transit_id (str): The id of the transit network.
        Returns:
            is_transit_pub_sub (bool): Returns True, if the transit type is 'SDA_LISP_PUB_SUB_TRANSIT'. Else, False.
        Description:
            Calls the 'get_transit_networks' API by setting the 'id' and 'type' fields
            with the given transit id and 'SDA_LISP_PUB_SUB_TRANSIT'.
            If the response is valid, fetch the Id and return True, otherwise False.
        """

        self.log(
            "Fetching transit type for transit ID: '{id}'".format(id=transit_id),
            "DEBUG",
        )
        is_transit_pub_sub = False
        try:
            transit_details = self.dnac._exec(
                family="sda",
                function="get_transit_networks",
                params={"id": transit_id, "type": "SDA_LISP_PUB_SUB_TRANSIT"},
            )

            # If the SDK returns no response, then the transit does not exist with type 'SDA_LISP_PUB_SUB_TRANSIT'
            transit_details = transit_details.get("response")
            if not transit_details:
                self.log(
                    "There is no transit network with the id '{id}' with transit type 'SDA_LISP_PUB_SUB_TRANSIT'.".format(
                        id=transit_id
                    ),
                    "DEBUG",
                )
                return is_transit_pub_sub

            self.log(
                "Transit network found with ID: '{id}' and type 'SDA_LISP_PUB_SUB_TRANSIT'.".format(
                    id=transit_id
                ),
                "DEBUG",
            )
            is_transit_pub_sub = True
        except Exception as msg:
            self.msg = "Exception occurred while running the API 'get_transit_networks': {msg}".format(
                msg=msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return is_transit_pub_sub

    def get_l2_handoff_params(
        self, fabric_id, network_id, device_details, device_config_index
    ):
        """
        Get the L2 Handoff of the SDA fabric devices information from playbook.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            fabric_id (str): The Id of the fabric site.
            network_id (str): The Id of the network device.
            device_details (dict): Playbook details containing fabric devices details along
            with the Border Settings, L2 Handoff, L3 SDA Handoff, L3 IP Handoff information.
            device_config_index (int): The index of the device details in the device_config.
        Returns:
            l2_handoff_info (list): The processed L2 Handoff details from the user playbook.
        Description:
            Check the existence of the borders_settings and layer2_handoff in the playbook.
            Get and validate the interface_name, internal_vlan_id and external_vlan_id.
        """

        l2_handoff_info = []
        borders_settings = device_details.get("borders_settings")
        if not borders_settings:
            self.log(
                "No borders settings found in device details for IP: {device_ip}".format(
                    device_ip=device_details.get("device_ip")
                ),
                "DEBUG",
            )
            return l2_handoff_info

        layer2_handoff = borders_settings.get("layer2_handoff")
        if not layer2_handoff:
            self.log(
                "No layer2 handoff settings found in borders settings for device IP: {device_ip}".format(
                    device_ip=device_details.get("device_ip")
                ),
                "DEBUG",
            )
            return l2_handoff_info

        device_ip = device_details.get("device_ip")
        l2_handoff_index = -1
        have_l2_handoff_details = self.have.get("fabric_devices")[
            device_config_index
        ].get("l2_handoff_details")
        for item in layer2_handoff:
            l2_handoff_index += 1
            l2_handoff = {
                "networkDeviceId": network_id,
                "fabricId": fabric_id,
            }
            if have_l2_handoff_details and have_l2_handoff_details[l2_handoff_index]:
                self.log(
                    "Skipping existing L2 handoff details for device IP: {device_ip} at index: {index}".format(
                        device_ip=device_ip, index=l2_handoff_index
                    ),
                    "DEBUG",
                )
                continue

            interface_name = item.get("interface_name")
            if not interface_name:
                self.msg = (
                    "The 'interface_name' is mandatory under 'layer2_handoff' for "
                    "the device with IP '{ip}'".format(ip=device_ip)
                )
                self.status = "failed"
                return self.check_return_status()

            internal_vlan_id = item.get("internal_vlan_id")
            external_vlan_id = item.get("external_vlan_id")
            error = self.validate_vlan_fields(
                internal_vlan_id, external_vlan_id, device_ip
            )
            if error:
                (self.msg, self.status) = error
                self.log(
                    "Validation error for device IP {ip}: {msg}".format(
                        ip=device_ip, msg=self.msg
                    )
                )
                return self.check_return_status()

            l2_handoff.update(
                {
                    "interfaceName": interface_name,
                    "internalVlanId": internal_vlan_id,
                    "externalVlanId": external_vlan_id,
                }
            )

            l2_handoff_info.append(l2_handoff)

        self.log(
            "L2 handoff parameters successfully retrieved for device IP: {device_ip}".format(
                device_ip=device_ip
            ),
            "DEBUG",
        )
        return l2_handoff_info

    def get_sda_l3_handoff_params(
        self, fabric_id, network_id, device_details, device_config_index
    ):
        """
        Get the L3 SDA Handoff of the SDA fabric devices information from playbook.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            fabric_id (str): The Id of the fabric site.
            network_id (str): The Id of the network device.
            device_details (dict): Playbook details containing fabric devices details along
            with the Border Settings, L2 Handoff, L3 SDA Handoff, L3 IP Handoff information.
            device_config_index (int): The index of the device details in the device_config.
        Returns:
            sda_l3_handoff_info (dict): The processed L3 Handoff with SDA transit details from the user playbook.
        Description:
            Check the existence of the borders_settings and layer3_handoff_sda_transit in the playbook.
            Get and validate the transit_name, connected_to_internet, affinity_id_prime,
            affinity_id_decider and is_multicast_over_transit_enabled.
        """

        sda_l3_handoff_info = {}
        device_ip = device_details.get("device_ip")
        borders_settings = device_details.get("borders_settings")
        if not borders_settings:
            self.log(
                "No borders settings found for device IP: {device_ip}".format(
                    device_ip=device_ip
                ),
                "DEBUG",
            )
            return sda_l3_handoff_info

        layer3_handoff_sda_transit = borders_settings.get("layer3_handoff_sda_transit")
        if not layer3_handoff_sda_transit:
            self.log(
                "No layer3 handoff SDA transit settings found for device IP: {device_ip}".format(
                    device_ip=device_ip
                ),
                "DEBUG",
            )
            return sda_l3_handoff_info

        sda_l3_handoff_info = {
            "networkDeviceId": network_id,
            "fabricId": fabric_id,
        }

        is_sda_l3_handoff_exists = False
        have_sda_l3_handoff = self.have.get("fabric_devices")[device_config_index].get(
            "sda_l3_handoff_details"
        )
        if have_sda_l3_handoff:
            self.log(
                "Existing L3 handoff found for device IP: {device_ip}".format(
                    device_ip=device_ip
                ),
                "DEBUG",
            )
            is_sda_l3_handoff_exists = True

        transit_name = layer3_handoff_sda_transit.get("transit_network_name")
        if not transit_name:
            self.msg = "The parameter 'transit_name' is mandatory under 'layer3_handoff_sda_transit'."
            self.status = "failed"
            return self.check_return_status()

        transit_id = self.get_transit_id_from_name(transit_name)
        if not transit_id:
            self.msg = "The SDA transit with the name '{name}' is not available in the Cisco Catalyst Center.".format(
                name=transit_name
            )
            self.status = "failed"
            return self.check_return_status()

        self.log(
            "Transit ID for the transit name {name}: {id}".format(
                name=transit_name, id=transit_id
            )
        )

        is_transit_pub_sub = self.check_transit_type(transit_id)
        self.log(
            "The transit type is 'LISP/PUB SUB': {is_transit_pub_sub}".format(
                is_transit_pub_sub=is_transit_pub_sub
            )
        )
        connected_to_internet = layer3_handoff_sda_transit.get("connected_to_internet")
        if connected_to_internet is None:
            if is_sda_l3_handoff_exists:
                connected_to_internet = have_sda_l3_handoff.get("connectedToInternet")
            else:
                connected_to_internet = False

        self.log(
            "Connected to internet for device IP {device_ip}: {connected_to_internet}".format(
                device_ip=device_ip, connected_to_internet=connected_to_internet
            ),
            "DEBUG",
        )

        is_multicast_over_transit_enabled = layer3_handoff_sda_transit.get(
            "is_multicast_over_transit_enabled"
        )
        if is_multicast_over_transit_enabled is None:
            if is_sda_l3_handoff_exists:
                is_multicast_over_transit_enabled = have_sda_l3_handoff.get(
                    "isMulticastOverTransitEnabled"
                )
            else:
                is_multicast_over_transit_enabled = False

            self.log(
                "Multicast over transit enabled for device IP {device_ip}: {is_multicast_enabled}".format(
                    device_ip=device_ip,
                    is_multicast_enabled=is_multicast_over_transit_enabled,
                )
            )

        affinity_id_prime = layer3_handoff_sda_transit.get("affinity_id_prime")
        if not affinity_id_prime:
            if is_sda_l3_handoff_exists:
                have_affinity_id_prime = have_sda_l3_handoff.get("affinityIdPrime")
                if not have_affinity_id_prime:
                    affinity_id_prime = have_affinity_id_prime
        else:

            # Affinity id prime value should be from 0 to 2147483647
            try:
                affinity_id_prime = int(affinity_id_prime)
                if not (0 <= affinity_id_prime <= 2147483647):
                    self.msg = (
                        "The 'affinity_id_prime' should be from 0 to 2147483647 for the "
                        "device '{device_ip}'".format(device_ip=device_ip)
                    )
                    self.status = "failed"
                    return self.check_return_status()

            except ValueError:
                self.msg = "The 'affinity_id_prime' should contain only digits 0-9 for the device '{ip}'.".format(
                    ip=device_ip
                )
                self.status = "failed"
                return self.check_return_status()

        self.log(
            "Affinity ID Prime is set to: {affinity_id_prime}".format(
                affinity_id_prime=affinity_id_prime
            ),
            "DEBUG",
        )
        affinity_id_decider = layer3_handoff_sda_transit.get("affinity_id_decider")
        if not affinity_id_decider:
            if is_sda_l3_handoff_exists:
                have_affinity_id_decider = have_sda_l3_handoff.get("affinityIdDecider")
                if not have_affinity_id_decider:
                    affinity_id_decider = have_affinity_id_decider
        else:

            # Affinity id decider value should be from 0 to 2147483647
            try:
                affinity_id_decider = int(affinity_id_decider)
                if not (0 <= affinity_id_decider <= 2147483647):
                    self.msg = (
                        "The 'affinity_id_decider' should be from 0 to 2147483647 for the "
                        "device '{device_ip}'".format(device_ip=device_ip)
                    )
                    self.status = "failed"
                    return self.check_return_status()

            except ValueError:
                self.msg = "The 'affinity_id_decider' should contain only digits 0-9 for the device '{ip}'.".format(
                    ip=device_ip
                )
                self.status = "failed"
                return self.check_return_status()

        self.log(
            "Affinity ID Decider is set to: {affinity_id_decider}".format(
                affinity_id_decider=affinity_id_decider
            ),
            "DEBUG",
        )
        if (not affinity_id_prime) ^ (not affinity_id_decider):
            self.msg = (
                "Either 'affinity_id_prime' or 'affinity_id_decider' is not accepted. If you wish "
                "to add the affinity, pass both the 'affinity_id_prime' or 'affinity_id_decider' "
                "for the device with IP '{ip}".format(ip=device_ip)
            )
            self.status = "failed"
            return self.check_return_status()

        sda_l3_handoff_info.update(
            {
                "transitNetworkId": transit_id,
                "connectedToInternet": connected_to_internet,
            }
        )

        if is_transit_pub_sub:
            sda_l3_handoff_info.update(
                {
                    "affinityIdPrime": affinity_id_prime,
                    "affinityIdDecider": affinity_id_decider,
                    "isMulticastOverTransitEnabled": is_multicast_over_transit_enabled,
                }
            )

        self.log(
            "Successfully retrieved L3 handoff parameters for device IP: {device_ip}".format(
                device_ip=device_ip
            )
        )
        return sda_l3_handoff_info

    def validate_layer3_handoff_ip_transit(
        self,
        item,
        device_ip,
        is_ip_l3_handoff_exists,
        have_ip_l3_handoff,
        l3_ip_handoff_index,
    ):
        """
        Validate Layer 3 handoff IP transit parameters.

        Parameters:
            item (dict): The current item from layer3_handoff_ip_transit.
            device_ip (str): The device IP address.
            is_ip_l3_handoff_exists (int): The existence of the L3 handoff item.
            have_ip_l3_handoff (dict): Existing L3 handoff details for the device.
            l3_ip_handoff_index (int): Index for the current item in the 'have_ip_l3_handoff'.

        Returns:
            tuple: A tuple containing transit_id, interface_name, virtual_network_name, vlan_id, tcp_mss_adjustment
                   and a success flag.
        Description:
            Check the existence of the borders_settings and layer3_handoff_ip_transit in the playbook.
            Get and validate the transit_name, interface_name, virtual_network_name,
            vlan_id and tcp_mss_adjustment.
        """

        transit_name = item.get("transit_network_name")
        if not transit_name:
            self.msg = "The parameter 'transit_name' is mandatory under 'layer3_handoff_sda_transit'."
            self.status = "failed"
            self.log(self.msg, "ERROR")
            return (None, None, None, None, None, False)

        self.log(
            "Transit network name found: {transit_name}".format(
                transit_name=transit_name
            ),
            "DEBUG",
        )
        transit_id = self.get_transit_id_from_name(transit_name)
        if not transit_id:
            self.msg = "The IP transit with the name '{name}' is not available in the Cisco Catalyst Center.".format(
                name=transit_name
            )
            self.status = "failed"
            self.log(self.msg, "ERROR")
            return (None, None, None, None, None, False)

        self.log(
            "Transit network ID resolved: {transit_id}".format(transit_id=transit_id),
            "DEBUG",
        )
        interface_name = item.get("interface_name")
        if not interface_name:
            self.msg = (
                "The 'interface_name' is mandatory under 'layer3_handoff_ip_transit' for "
                "the device with IP '{ip}'".format(ip=device_ip)
            )
            self.status = "failed"
            self.log(self.msg, "ERROR")
            return (None, None, None, None, None, False)

        self.log(
            "Interface name found: {interface_name}".format(
                interface_name=interface_name
            ),
            "DEBUG",
        )
        virtual_network_name = item.get("virtual_network_name")
        if virtual_network_name:
            is_valid_virtual_network = self.check_valid_virtual_network_name(
                virtual_network_name
            )
            if not is_valid_virtual_network:
                self.msg = "The virtual network with the name '{virtual_nw_name}' is not valid.".format(
                    virtual_nw_name=virtual_network_name
                )
                self.status = "failed"
                self.log(self.msg, "ERROR")
                return (None, None, None, None, None, False)

        self.log(
            "Valid virtual network name: {vn_name}".format(
                vn_name=virtual_network_name
            ),
            "DEBUG",
        )
        vlan_id = item.get("vlan_id")
        if vlan_id:

            # vlan id can be from 2 to 4094
            # Except 1002, 1003, 1004, 1005, 2046, 4094
            try:
                vlan_id = int(vlan_id)
                reserved_vlans = [1, 1002, 1003, 1004, 1005, 2046, 4094]
                if not (2 <= vlan_id <= 4094):
                    self.msg = "The 'vlan_id' should be from 2 to 4094 for the device '{ip}'.".format(
                        ip=device_ip
                    )
                    self.status = "failed"
                    self.log(self.msg, "ERROR")
                    return (None, None, None, None, None, False)

                if vlan_id in reserved_vlans:
                    self.msg = "The 'vlan_id' should not be a reserved VLAN '{reserved_vlan}' for the device '{ip}'.".format(
                        reserved_vlan=reserved_vlans, ip=device_ip
                    )
                    self.status = "failed"
                    self.log(self.msg, "ERROR")
                    return (None, None, None, None, None, False)

            except ValueError:
                self.msg = "The 'vlan_id' should contain only digits 0-9 for the device '{ip}'.".format(
                    ip=device_ip
                )
                self.status = "failed"
                self.log(self.msg, "ERROR")
                return (None, None, None, None, None, False)

        if is_ip_l3_handoff_exists:
            if not (virtual_network_name and vlan_id):
                self.msg = (
                    "The 'virtual_network_name' or 'vlan_id' is mandatory under 'layer3_handoff_ip_transit' "
                    "for updating the Layer 3 Handoff with IP transit in the device with IP '{ip}'".format(
                        ip=device_ip
                    )
                )
                self.status = "failed"
                self.log(self.msg, "ERROR")
                return (None, None, None, None, None, False)
            elif virtual_network_name and (not vlan_id):
                vlan_id = have_ip_l3_handoff[l3_ip_handoff_index].get("vlanId")
            elif vlan_id and (not virtual_network_name):
                virtual_network_name = have_ip_l3_handoff[l3_ip_handoff_index].get(
                    "virtualNetworkName"
                )
        else:
            if not (virtual_network_name and vlan_id):
                self.msg = (
                    "The 'virtual_network_name' and  'vlan_id' are mandatory under 'layer3_handoff_ip_transit' for "
                    "adding the Layer 3 Handoff with IP transit in the device with IP '{ip}'".format(
                        ip=device_ip
                    )
                )
                self.status = "failed"
                self.log(self.msg, "ERROR")
                return (None, None, None, None, None, False)

        tcp_mss_adjustment = item.get("tcp_mss_adjustment")
        if not tcp_mss_adjustment:
            if is_ip_l3_handoff_exists:
                have_tcp_mss_adjustment = have_ip_l3_handoff[l3_ip_handoff_index].get(
                    "tcpMssAdjustment"
                )
                if have_tcp_mss_adjustment:
                    tcp_mss_adjustment = have_tcp_mss_adjustment
            else:
                tcp_mss_adjustment = 0
        else:

            # TCP mss adjustment should be from 500 to 1440
            try:
                tcp_mss_adjustment = int(tcp_mss_adjustment)
                if not (500 <= tcp_mss_adjustment <= 1440):
                    self.msg = "The 'tcp_mss_adjustment' should be from 500 to 1440 in 'layer3_handoff_ip_transit' for the device '{ip}'.".format(
                        ip=device_ip
                    )
                    self.status = "failed"
                    self.log(self.msg, "ERROR")
                    return (None, None, None, None, None, False)

            except ValueError:
                self.msg = "The 'tcp_mss_adjustment' should contain only digits 0-9 for the device '{ip}'.".format(
                    ip=device_ip
                )
                self.status = "failed"
                self.log(self.msg, "ERROR")
                return (None, None, None, None, None, False)

        return (
            transit_id,
            interface_name,
            virtual_network_name,
            vlan_id,
            tcp_mss_adjustment,
            True,
        )

    def get_ip_l3_handoff_params(
        self, fabric_id, network_id, device_details, device_config_index, fabric_name
    ):
        """
        Get the L3 IP Handoff of the SDA fabric devices information from playbook.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            fabric_id (str): The Id of the fabric site.
            network_id (str): The Id of the network device.
            device_details (dict): Playbook details containing fabric devices details along
            with the Border Settings, L2 Handoff, L3 SDA Handoff, L3 IP Handoff information.
            device_config_index (int): The index of the device details in the device_config.
            fabric_name (str): The name of the fabric site.
        Returns:
            ip_l3_handoff_info (list): The processed L3 Handoff with IP transit details from the user playbook.
        """

        self.log(
            "Fetching the L3 Handoff with the IP Transit under the fabric '{fabric_name}".format(
                fabric_name=fabric_name
            )
        )
        ip_l3_handoff_info = []
        borders_settings = device_details.get("borders_settings")
        if not borders_settings:
            self.log(
                "No border settings found for device with IP: {ip}".format(
                    ip=device_details.get("device_ip")
                )
            )
            return ip_l3_handoff_info

        layer3_handoff_ip_transit = borders_settings.get("layer3_handoff_ip_transit")
        if not layer3_handoff_ip_transit:
            self.log(
                "No Layer 3 Handoff with IP Transit found for device with IP: {ip}".format(
                    ip=device_details.get("device_ip")
                )
            )
            return ip_l3_handoff_info

        device_ip = device_details.get("device_ip")
        l3_ip_handoff_index = -1
        for item in layer3_handoff_ip_transit:
            l3_ip_handoff_index += 1
            l3_ip_handoff = {
                "networkDeviceId": network_id,
                "fabricId": fabric_id,
            }
            is_ip_l3_handoff_exists = False
            have_ip_l3_handoff = self.have.get("fabric_devices")[
                device_config_index
            ].get("ip_l3_handoff_details")
            if have_ip_l3_handoff and have_ip_l3_handoff[l3_ip_handoff_index]:
                is_ip_l3_handoff_exists = True
                self.log(
                    "Existing IP L3 handoff found for index {index}: {details}".format(
                        index=l3_ip_handoff_index,
                        details=have_ip_l3_handoff[l3_ip_handoff_index],
                    ),
                    "DEBUG",
                )

            (
                transit_id,
                interface_name,
                virtual_network_name,
                vlan_id,
                tcp_mss_adjustment,
                is_valid,
            ) = self.validate_layer3_handoff_ip_transit(
                item,
                device_details.get("device_ip"),
                is_ip_l3_handoff_exists,
                have_ip_l3_handoff,
                l3_ip_handoff_index,
            )

            if not is_valid:
                self.check_return_status()

            l3_ip_handoff.update(
                {
                    "transitNetworkId": transit_id,
                    "interfaceName": interface_name,
                    "virtualNetworkName": virtual_network_name,
                    "vlanId": vlan_id,
                }
            )
            if tcp_mss_adjustment:
                l3_ip_handoff.update(
                    {
                        "tcpMssAdjustment": tcp_mss_adjustment,
                    }
                )

            self.log(
                "L3 IP handoff parameters updated: {l3_ip_handoff}".format(
                    l3_ip_handoff=l3_ip_handoff
                ),
                "DEBUG",
            )

            # If the fabric device is available, then fetch the local and remote IP addresses
            if is_ip_l3_handoff_exists:
                local_ip_address = have_ip_l3_handoff[l3_ip_handoff_index].get(
                    "localIpAddress"
                )
                remote_ip_address = have_ip_l3_handoff[l3_ip_handoff_index].get(
                    "remoteIpAddress"
                )
                local_ipv6_address = have_ip_l3_handoff[l3_ip_handoff_index].get(
                    "localIpv6Address"
                )
                remote_ipv6_address = have_ip_l3_handoff[l3_ip_handoff_index].get(
                    "remoteIpv6Address"
                )
                l3_ip_handoff.update(
                    {
                        "localIpAddress": local_ip_address,
                        "remoteIpAddress": remote_ip_address,
                        "localIpv6Address": local_ipv6_address,
                        "remoteIpv6Address": remote_ipv6_address,
                    }
                )
            else:

                # If external_connectivity_ip_pool_name is given local and remote address will be ignored
                # If external_connectivity_ip_pool_name is not given, then local and remote is mandatory
                external_connectivity_ip_pool_name = item.get(
                    "external_connectivity_ip_pool_name"
                )
                if external_connectivity_ip_pool_name:

                    # Check if the reserved pool is available in the Cisco Catalyst Center or not
                    is_valid_reserved_pool = self.check_valid_reserved_pool(
                        external_connectivity_ip_pool_name, fabric_name
                    )
                    if not is_valid_reserved_pool:
                        self.msg = (
                            "The 'external_connectivity_ip_pool_name' is not a valid reserved pool for the "
                            "device with IP '{ip}'.".format(ip=device_ip)
                        )
                        self.status = "failed"
                        return self.check_return_status()

                    l3_ip_handoff.update(
                        {
                            "externalConnectivityIpPoolName": external_connectivity_ip_pool_name
                        }
                    )
                else:
                    local_ip_address = item.get("local_ip_address")
                    remote_ip_address = item.get("remote_ip_address")
                    local_ipv6_address = item.get("local_ipv6_address")
                    remote_ipv6_address = item.get("remote_ipv6_address")
                    if not (local_ip_address and remote_ip_address):
                        self.msg = (
                            "The parameters 'local_ip_address' and 'remote_ip_address' is mandatory for "
                            "creating L3 Handoff with IP Transit."
                        )
                        self.status = "failed"
                        return self.check_return_status()

                    l3_ip_handoff.update(
                        {
                            "localIpAddress": local_ip_address,
                            "remoteIpAddress": remote_ip_address,
                        }
                    )
                    if local_ipv6_address and remote_ipv6_address:
                        l3_ip_handoff.update(
                            {
                                "localIpv6Address": local_ipv6_address,
                                "remoteIpv6Address": remote_ipv6_address,
                            }
                        )
                    elif local_ipv6_address or remote_ipv6_address:
                        self.msg = (
                            "If IPv6 addresses need to added. Please provide both local and remote IPv6 address "
                            "for the device '{ip}".format(ip=device_ip)
                        )
                        self.status = "failed"
                        return self.check_return_status()

            ip_l3_handoff_info.append(l3_ip_handoff)

        return ip_l3_handoff_info

    def process_scope_list(self, scope_list):
        """
        Process a list of site names to retrieve detailed site info including child sites.

        Args:
            scope_list (list): List of site names.

        Returns:
            list: Deduplicated list of dicts with 'siteId' and 'siteNameHierarchy' for sites.

        Description:
            For each site name, this method fetches both the site and its child sites from Catalyst Center
            using `get_site()`. It then extracts relevant site details and deduplicates the final list before returning.
        """
        self.log(
            f"Processing scope list with {len(scope_list)} site(s): {scope_list}",
            "DEBUG",
        )

        if not scope_list:
            self.log("Scope list is empty, returning empty list.", "DEBUG")
            return []

        processed_scope = []
        for site_name in scope_list:
            self.log(f"Processing site: {site_name}", "DEBUG")
            current_site = self.get_site(site_name).get("response", [])

            child_sites_response = self.get_site(site_name + "/.*")
            child_sites = child_sites_response.get("response", [])
            self.log(
                f"Found {len(child_sites)} child site(s) for site '{site_name}'.",
                "DEBUG",
            )

            all_containing_sites = child_sites + current_site
            self.log(
                f"Processing {len(all_containing_sites)} total site(s) for '{site_name}'.",
                "DEBUG",
            )
            for containing_site in all_containing_sites:
                containing_site_info = {
                    "siteId": containing_site.get("id"),
                    "siteNameHierarchy": containing_site.get("nameHierarchy"),
                }
                processed_scope.append(containing_site_info)

        deduped_scope = self.deduplicate_list_of_dict(processed_scope)

        self.log(
            f"Deduplication complete. Original list size: {len(processed_scope)}, "
            f"Deduplicated list size: {len(deduped_scope)}.",
            "INFO",
        )
        self.log(f"Final deduplicated scope list:\n{deduped_scope}", "DEBUG")

        return deduped_scope

    def validate_enable_field_in_wireless_config(self, wireless_controller_config):
        """
        Validate the 'enable' field in wireless_controller_settings.

        Args:
            wireless_controller_config (dict): Wireless controller settings dict from playbook.

        Returns:
            bool: The value of the 'enable' field if validation passes.

        Description:
            - Checks if the 'enable' field is present and is a boolean.
            - Logs relevant messages during validation.
            - Exits the program via `self.fail_and_exit` if validation fail
        """
        self.log(
            "Starting validation of 'enable' field in wireless controller settings...",
            "DEBUG",
        )
        enable = wireless_controller_config.get("enable")
        if enable is None:
            self.msg = "'enable' field is required but missing in wireless controller settings."
            self.fail_and_exit(self.msg)

        if not isinstance(enable, bool):
            self.msg = "'enable' field must be a boolean value in wireless controller settings."
            self.fail_and_exit(self.msg)

        self.log(f"Validated 'enable' field: {enable}", "DEBUG")
        return enable

    def validate_reload_in_wireless_config(self, wireless_controller_config):
        """
        Validate the 'reload' field in wireless_controller_settings.

        Args:
            wireless_controller_config (dict): Wireless controller settings dict from playbook.

        Returns:
            bool: The value of the 'reload' field, defaulting to False if not present.

        Description:
            - Checks if the 'reload' field is a boolean if provided.
            - Defaults to False if the 'reload' field is missing.
            - Logs relevant messages during validation.
            - Exits the program via `self.fail_and_exit` if validation fails.
        """

        self.log(
            "Starting validation of 'reload' field in wireless controller settings...",
            "DEBUG",
        )
        reload_on_disable = wireless_controller_config.get("reload")
        if reload_on_disable is None:
            self.log("'reload' field is missing. Defaulting to False.", "INFO")
            reload_on_disable = False

        if not isinstance(reload_on_disable, bool):
            self.fail_and_exit(
                "'reload' field must be a boolean value in wireless controller settings."
            )

        self.log(f"Validated 'reload' field: {reload_on_disable}", "DEBUG")
        return reload_on_disable

    def validate_primary_managed_ap_locations(self, primary_managed_ap_locations):
        """
        Validate the 'primary_managed_ap_locations' field in wireless_controller_settings.

        Args:
            primary_managed_ap_locations (list or None): The primary managed AP locations list or None.

        Returns:
            list or None: Validated primary managed AP locations list or None if not provided.

        Description:
            - Validates that 'primary_managed_ap_locations' is a list if provided.
            - If not provided, defaults to None.
            - Logs validation progress and exits on failure.
        """
        self.log(
            "Starting validation of 'primary_managed_ap_locations' in wireless controller settings...",
            "DEBUG",
        )

        if primary_managed_ap_locations is None:
            self.log("'primary_managed_ap_locations' not provided.", "DEBUG")
        elif not isinstance(primary_managed_ap_locations, list):
            self.msg = "'primary_managed_ap_locations' must be a list in wireless controller settings."
            self.fail_and_exit(self.msg)
        else:
            primary_managed_ap_locations = self.process_scope_list(
                primary_managed_ap_locations
            )
            self.log(
                f"Validated 'primary_managed_ap_locations': {primary_managed_ap_locations}",
                "DEBUG",
            )

        self.log(
            f"Completed validation of primary_managed_ap_locations = {primary_managed_ap_locations}",
            "DEBUG",
        )
        return primary_managed_ap_locations

    def validate_secondary_managed_ap_locations(self, secondary_managed_ap_locations):
        """
        Validate the 'secondary_managed_ap_locations' field in wireless_controller_settings.

        Args:
            secondary_managed_ap_locations (list or None): The secondary managed AP locations list or None.

        Returns:
            list or None: Validated secondary managed AP locations list or None if not provided.

        Description:
            - Validates that 'secondary_managed_ap_locations' is a list if provided.
            - If not provided, defaults to None.
            - Logs validation progress and exits on failure.
        """
        self.log(
            "Starting validation of 'secondary_managed_ap_locations' in wireless controller settings...",
            "DEBUG",
        )

        if secondary_managed_ap_locations is None:
            self.log("'secondary_managed_ap_locations' not provided.", "DEBUG")
        elif not isinstance(secondary_managed_ap_locations, list):
            self.msg = "'secondary_managed_ap_locations' must be a list in wireless controller settings."
            self.fail_and_exit(self.msg)
        else:
            secondary_managed_ap_locations = self.process_scope_list(
                secondary_managed_ap_locations
            )
            self.log(
                f"Validated 'secondary_managed_ap_locations': {secondary_managed_ap_locations}",
                "DEBUG",
            )

        self.log(
            f"Completed validation of secondary_managed_ap_locations = {secondary_managed_ap_locations}",
            "DEBUG",
        )

        return secondary_managed_ap_locations

    def validate_rolling_ap_upgrade(self, rolling_ap_upgrade):
        """
        Validate the 'rolling_ap_upgrade' section in wireless_controller_settings.

        Args:
            rolling_ap_upgrade (dict or None): The rolling_ap_upgrade dict or None.

        Returns:
            dict or None: Validated rolling_ap_upgrade dict or None if not provided.

        Description:
            - Validates that 'rolling_ap_upgrade' is a dictionary containing 'enable' (bool) and optionally 'ap_reboot_percentage' (int).
            - Ensures 'ap_reboot_percentage', if provided, is one of the allowed values [5, 15, 25].
            - Logs validation progress and exits on failure.
        """
        self.log(
            "Starting validation of 'rolling_ap_upgrade' in wireless controller settings...",
            "DEBUG",
        )

        if rolling_ap_upgrade is None:
            self.log(
                "No 'rolling_ap_upgrade' section provided; returning None.", "DEBUG"
            )
            return None

        if not isinstance(rolling_ap_upgrade, dict):
            self.msg = f"'rolling_ap_upgrade' must be a dictionary in wireless controller settings. Received: {type(rolling_ap_upgrade).__name__}"
            self.fail_and_exit(self.msg)

        enable_rolling_ap_upgrade = rolling_ap_upgrade.get("enable")
        if enable_rolling_ap_upgrade is None:
            self.msg = "'enable' is required inside 'rolling_ap_upgrade' section."
            self.fail_and_exit(self.msg)

        valid_keys = {"enable", "ap_reboot_percentage"}
        unexpected_keys = set(rolling_ap_upgrade.keys()) - valid_keys
        if unexpected_keys:
            self.log(
                f"Unexpected keys in 'rolling_ap_upgrade': {unexpected_keys}. Only 'enable' and 'ap_reboot_percentage' are allowed.",
                "WARNING",
            )

        if not isinstance(enable_rolling_ap_upgrade, bool):
            self.msg = f"'enable' in 'rolling_ap_upgrade' must be a boolean. Received: {type(enable_rolling_ap_upgrade).__name__}"
            self.fail_and_exit(self.msg)

        self.log(
            f"Validated 'rolling_ap_upgrade.enable': {enable_rolling_ap_upgrade}",
            "DEBUG",
        )

        ap_reboot_percentage = rolling_ap_upgrade.get("ap_reboot_percentage")
        allowed_values = [5, 15, 25]
        if ap_reboot_percentage is None:
            self.log(
                "No 'ap_reboot_percentage' provided in rolling_ap_upgrade; skipping validation.",
                "DEBUG",
            )
        elif not isinstance(ap_reboot_percentage, int):
            self.msg = f"'ap_reboot_percentage' in 'rolling_ap_upgrade' must be an integer. Received: {type(ap_reboot_percentage).__name__}"
            self.fail_and_exit(self.msg)
        elif ap_reboot_percentage not in allowed_values:
            self.msg = f"'ap_reboot_percentage': '{ap_reboot_percentage}' in 'rolling_ap_upgrade' must be one of {allowed_values}."
            self.fail_and_exit(self.msg)
        else:
            self.log(
                f"Validated 'ap_reboot_percentage': {ap_reboot_percentage}", "DEBUG"
            )

        self.log(
            f"Completed validation of 'rolling_ap_upgrade': {rolling_ap_upgrade}",
            "DEBUG",
        )
        return rolling_ap_upgrade

    def validate_device_roles_for_wireless_settings(self, device_roles):
        """
        Validate if the device roles are allowed for wireless controller configuration.

        Args:
            device_roles (list): List of roles assigned to the device.

        Returns:
            self: Returns the class instance for chaining or further processing.

        Description:
            This method checks whether the current device roles are part of the predefined allowed combinations
            for enabling wireless controller settings. The supported combinations are:
                - ['BORDER_NODE', 'CONTROL_PLANE_NODE', 'EDGE_NODE', 'WIRELESS_CONTROLLER_NODE']
                - ['BORDER_NODE', 'CONTROL_PLANE_NODE', 'WIRELESS_CONTROLLER_NODE']
                - ['EDGE_NODE', 'WIRELESS_CONTROLLER_NODE']
            If the device's role combination is invalid, the module execution will fail with an error message.
        """
        self.log(
            "Validating device roles for wireless controller configuration...", "INFO"
        )

        temp_device_roles = copy.deepcopy(device_roles)
        if "WIRELESS_CONTROLLER_NODE" not in temp_device_roles:
            # WIRELESS_CONTROLLER_NODE may always not be present in the device roles.
            # In get_device_params we are removing it to not cause issues in the Update API.
            temp_device_roles.append("WIRELESS_CONTROLLER_NODE")

        allowed_device_roles = [
            [
                "BORDER_NODE",
                "CONTROL_PLANE_NODE",
                "EDGE_NODE",
                "WIRELESS_CONTROLLER_NODE",
            ],
            ["BORDER_NODE", "CONTROL_PLANE_NODE", "WIRELESS_CONTROLLER_NODE"],
            ["EDGE_NODE", "WIRELESS_CONTROLLER_NODE"],
        ]
        is_allowed = any(
            sorted(temp_device_roles) == sorted(allowed)
            for allowed in allowed_device_roles
        )

        if is_allowed:
            self.log(
                f"Device roles {temp_device_roles} are valid for wireless controller configuration.",
                "DEBUG",
            )
        else:
            allowed_str = "\n  - ".join([str(comb) for comb in allowed_device_roles])
            self.msg = (
                f"Invalid device role combination for wireless controller settings: {temp_device_roles}\n"
                f"Allowed combinations are:\n  - {allowed_str}"
            )
            self.fail_and_exit(self.msg)

        self.log(
            "Device role validation for wireless controller settings completed successfully.",
            "INFO",
        )

        return self

    def get_want_wireless_controller_settings(
        self, device_details, fabric_name, fabric_device_ip, config_index
    ):
        """
        Retrieve and validate wireless controller settings from the device playbook details.

        Args:
            device_details (dict): Device details dict from the playbook.
            fabric_name (str): Name of the fabric.
            fabric_device_ip (str): IP address of the fabric device.
            config_index (int): Index of the configuration.

        Returns:
            dict or None: Validated wireless controller settings dict or None if not applicable.

        Description:
            - Validates wireless controller settings, ensuring compatibility with Catalyst Center version.
            - Utilizes helper functions to validate individual sections of the configuration.
            - Logs all major steps and exits the program if critical validation fails.
        """

        self.log(
            f"Starting retrieval of wireless controller settings for device '{fabric_device_ip}' in fabric '{fabric_name}'...",
            "DEBUG",
        )

        wireless_controller_config = device_details.get("wireless_controller_settings")
        if not wireless_controller_config:
            self.log(
                f"No wireless controller settings found for device '{fabric_device_ip}' in fabric '{fabric_name}'. Returning None.",
                "DEBUG",
            )
            return None

        ccc_version = self.get_ccc_version()
        if self.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
            self.msg = (
                f"Wireless controller settings are not supported in Catalyst Center version '{ccc_version}'. "
                "Minimum required version is 2.3.7.9."
            )
            self.fail_and_exit(self.msg)

        self.log(
            f"Catalyst Center version '{ccc_version}' supports wireless controller settings. Proceeding with validation.",
            "DEBUG",
        )

        enable = self.validate_enable_field_in_wireless_config(
            wireless_controller_config
        )
        rolling_ap_upgrade = None
        primary_managed_ap_locations = None
        reload_on_disable = None
        secondary_managed_ap_locations = None

        if enable is False:
            reload_on_disable = self.validate_reload_in_wireless_config(
                wireless_controller_config
            )
        else:
            primary_managed_ap_locations = self.validate_primary_managed_ap_locations(
                wireless_controller_config.get("primary_managed_ap_locations")
            )
            secondary_managed_ap_locations = (
                self.validate_secondary_managed_ap_locations(
                    wireless_controller_config.get("secondary_managed_ap_locations")
                )
            )
            # Check if both are empty lists
            if not primary_managed_ap_locations and not secondary_managed_ap_locations:
                self.msg = (
                    f"Both 'primary_managed_ap_locations' and 'secondary_managed_ap_locations' cannot be empty in "
                    f"wireless controller settings for device IP '{fabric_device_ip}' in fabric '{fabric_name}'."
                )
                self.fail_and_exit(self.msg)

            rolling_ap_upgrade = self.validate_rolling_ap_upgrade(
                wireless_controller_config.get("rolling_ap_upgrade")
            )

        want_wireless_controller_settings = {
            "enable": enable,
            "primary_managed_ap_locations": primary_managed_ap_locations,
            "secondary_managed_ap_locations": secondary_managed_ap_locations,
            "rolling_ap_upgrade": rolling_ap_upgrade,
        }
        if not enable:
            want_wireless_controller_settings["reload"] = reload_on_disable

        self.log(
            f"Wireless controller settings after validation: {self.pprint(want_wireless_controller_settings)}",
            "DEBUG",
        )

        updated_settings = self.update_get_want_wireless_controller_settings(
            fabric_name,
            fabric_device_ip,
            config_index,
            want_wireless_controller_settings,
        )

        self.log(
            f"Final wireless controller settings to return: {self.pprint(updated_settings)}",
            "DEBUG",
        )
        return updated_settings

    def update_get_want_wireless_controller_settings(
        self,
        fabric_name,
        fabric_device_ip,
        config_index,
        want_wireless_controller_settings,
    ):
        """
        Update and normalize the wireless controller settings for a fabric device.

        Args:
            fabric_name (str): Name of the fabric where the device resides.
            fabric_device_ip (str): Management IP address of the fabric device.
            config_index (int): Index of the device inside self.have["fabric_devices"] list.
            want_wireless_controller_settings (dict): Desired wireless controller settings from the playbook.

        Returns:
            dict: Final wireless controller settings with missing values filled from Catalyst Center config or defaults.

        Description:
            This method ensures that the desired wireless controller settings are complete by
            supplementing missing values with the existing Catalyst Center configuration or default values.
            It checks for the presence of 'primary_managed_ap_locations', 'secondary_managed_ap_locations', and 'rolling_ap_upgrade'.
            If both scopes are missing or empty, it raises an error, since at least one must be provided.
            The method logs the start and end of the update process as well as intermediate decisions.
        """

        self.log(
            f"Starting update of wireless controller settings for device {fabric_device_ip} in fabric '{fabric_name}'",
            "INFO",
        )

        have_wireless_controller_settings = self.have.get("fabric_devices")[
            config_index
        ].get("wireless_controller_settings")

        self.log(
            f"Current (have) wireless controller settings:\n{self.pprint(have_wireless_controller_settings)}",
            "DEBUG",
        )
        self.log(
            f"Desired (want) wireless controller settings:\n{self.pprint(want_wireless_controller_settings)}",
            "DEBUG",
        )

        # PRIMARY SCOPE
        primary_managed_ap_locations = want_wireless_controller_settings.get(
            "primary_managed_ap_locations"
        )
        if primary_managed_ap_locations is None:
            if have_wireless_controller_settings:
                have_primary_managed_ap_locations = have_wireless_controller_settings.get(
                    "primary_managed_ap_locations"
                )
            else:
                have_primary_managed_ap_locations = None

            if not have_primary_managed_ap_locations:
                self.log(
                    "No 'primary_managed_ap_locations' found in both playbook and existing catalyst center config. Setting to empty list.",
                    "INFO",
                )
                primary_managed_ap_locations = []
            else:
                primary_managed_ap_locations = have_primary_managed_ap_locations
                self.log(
                    f"'primary_managed_ap_locations' not defined in playbook. Using existing Catalyst Center config value: {primary_managed_ap_locations}",
                    "INFO",
                )
        else:
            self.log(
                f"'primary_managed_ap_locations' found in playbook: {primary_managed_ap_locations}",
                "INFO",
            )

        # SECONDARY SCOPE
        secondary_managed_ap_locations = want_wireless_controller_settings.get(
            "secondary_managed_ap_locations"
        )
        if secondary_managed_ap_locations is None:
            if have_wireless_controller_settings:
                have_secondary_managed_ap_locations = have_wireless_controller_settings.get(
                    "secondary_managed_ap_locations"
                )
            else:
                have_secondary_managed_ap_locations = None

            if not have_secondary_managed_ap_locations:
                secondary_managed_ap_locations = []
                self.log(
                    "No 'secondary_managed_ap_locations' found in both playbook and existing Catalyst Center config. Setting to empty list.",
                    "INFO",
                )
            else:
                secondary_managed_ap_locations = have_secondary_managed_ap_locations
                self.log(
                    f"'secondary_managed_ap_locations' not defined in playbook. Using existing Catalyst Center config value: {secondary_managed_ap_locations}",
                    "INFO",
                )
        else:
            self.log(
                f"'secondary_managed_ap_locations' found in playbook: {secondary_managed_ap_locations}",
                "INFO",
            )

        # ROLLING AP UPGRADE
        rolling_ap_upgrade = want_wireless_controller_settings.get("rolling_ap_upgrade")
        if rolling_ap_upgrade is None:
            if have_wireless_controller_settings:
                have_rolling_ap_upgrade = have_wireless_controller_settings.get(
                    "rolling_ap_upgrade"
                )
            else:
                have_rolling_ap_upgrade = None

            if have_rolling_ap_upgrade is None:
                rolling_ap_upgrade = {"enable": True, "ap_reboot_percentage": 25}
                self.log(
                    f"No 'rolling_ap_upgrade' found in both playbook and Catalyst Center config. Setting to default: {rolling_ap_upgrade}",
                    "INFO",
                )
            else:
                rolling_ap_upgrade = have_rolling_ap_upgrade
                self.log(
                    f"'rolling_ap_upgrade' not defined in playbook. Using existing Catalyst Center config: {rolling_ap_upgrade}",
                    "INFO",
                )
        else:
            ap_reboot_percentage = rolling_ap_upgrade.get("ap_reboot_percentage")
            if ap_reboot_percentage is None:
                have_rolling_ap_upgrade = have_wireless_controller_settings.get(
                    "rolling_ap_upgrade"
                )
                if have_rolling_ap_upgrade:
                    ap_reboot_percentage = have_rolling_ap_upgrade.get(
                        "ap_reboot_percentage"
                    )
                    rolling_ap_upgrade["ap_reboot_percentage"] = ap_reboot_percentage
                    self.log(
                        f"'ap_reboot_percentage' missing in playbook. Using existing Catalyst Center config value: {ap_reboot_percentage}",
                        "INFO",
                    )
                else:
                    rolling_ap_upgrade.update({"ap_reboot_percentage": 25})
                    self.log(
                        "No 'ap_reboot_percentage' found in both playbook and Catalyst Center config. Setting to default: 25",
                        "INFO",
                    )
            else:
                self.log(
                    f"'rolling_ap_upgrade' found in playbook with 'ap_reboot_percentage': {ap_reboot_percentage}",
                    "INFO",
                )

        # COMPILE FINAL OUTPUT
        want_wireless_controller_settings.update(
            {
                "primary_managed_ap_locations": primary_managed_ap_locations,
                "secondary_managed_ap_locations": secondary_managed_ap_locations,
                "rolling_ap_upgrade": rolling_ap_upgrade,
            }
        )

        self.log(
            f"Completed update of wireless controller settings for device {fabric_device_ip}. "
            f"Final settings:\n{want_wireless_controller_settings}",
            "INFO",
        )
        return want_wireless_controller_settings

    def get_want_fabric_devices(self, fabric_devices):
        """
        Get all the SDA fabric devices along with the Border settings, L2 Handoff,
        L3 SDA Handoff, L3 IP Handoff, wireless controller settings information from playbook.
        Set the status and the msg before returning from the API
        Check the return value of the API with check_return_status()

        Parameters:
            fabric_devices (dict): Playbook details containing fabric devices details along
            with the Border Settings, L2 Handoff, L3 SDA Handoff, L3 IP Handoff information, Wireless controller information.
        Returns:
            self: The current object with updated desired fabric devices information.
        Description:
            Do all the validation which is done in the GUI and format the payload
            in such a way that we can pass it to the API.
            Call the respective functions for gathering the device details,
            L2 Handoff, L3 IP Handoff, L3 SDA Handoff provided by the user.
            Also gathers and updates wireless controller settings per device.
        """

        fabric_name = fabric_devices.get("fabric_name")
        self.log(
            "Starting to gather fabric device details for fabric: {fabric_name}".format(
                fabric_name=fabric_name
            ),
            "DEBUG",
        )
        fabric_devices_details = []
        device_config = fabric_devices.get("device_config")
        for device_config_index, item in enumerate(device_config):
            self.log(
                f"Processing device configuration at index: {device_config_index}",
                "DEBUG",
            )
            fabric_site_id = self.have.get("fabric_devices")[device_config_index].get(
                "fabric_site_id"
            )
            device_ip = item.get("device_ip")
            self.log(
                "Processing device configuration at index: {index}".format(
                    index=device_config_index
                ),
                "DEBUG",
            )
            network_device_id = self.have.get("fabric_devices")[
                device_config_index
            ].get("network_device_id")
            fabric_devices_info = {
                "device_details": self.get_device_params(
                    fabric_site_id, network_device_id, item, device_config_index
                ),
                "l2_handoff_details": self.get_l2_handoff_params(
                    fabric_site_id, network_device_id, item, device_config_index
                ),
                "sda_l3_handoff_details": self.get_sda_l3_handoff_params(
                    fabric_site_id, network_device_id, item, device_config_index
                ),
                "ip_l3_handoff_details": self.get_ip_l3_handoff_params(
                    fabric_site_id,
                    network_device_id,
                    item,
                    device_config_index,
                    fabric_name,
                ),
            }
            if self.fabric_type == "fabric_site":
                self.log(f"Gathering wireless controller settings for fabric type: {self.fabric_type}", "DEBUG")
                fabric_devices_info["wireless_controller_settings"] = self.get_want_wireless_controller_settings(
                    item, fabric_name, device_ip, device_config_index
                )
            else:
                self.log(f"Skipping wireless controller settings for fabric type: {self.fabric_type}", "DEBUG")
                fabric_devices_info["wireless_controller_settings"] = None

            self.log(
                "The fabric device with IP '{ip}' details under the site '{site}': {details}".format(
                    ip=device_ip, site=fabric_name, details=fabric_devices_info
                )
            )
            self.log(
                "Collected device details for IP '{ip}': {details}".format(
                    ip=device_ip, details=fabric_devices_info
                ),
                "DEBUG",
            )
            fabric_devices_details.append(fabric_devices_info)

        self.log(
            "All fabric devices processed. Compiled details: {requested_state}".format(
                requested_state=fabric_devices_details
            ),
            "DEBUG",
        )
        self.want.update({"fabric_devices": fabric_devices_details})
        self.msg = "Collecting the SDA fabric transits details from the playbook."
        self.status = "success"
        self.log(
            "Fabric devices details successfully gathered. Status: {status}".format(
                status=self.status
            ),
            "DEBUG",
        )
        return self

    def get_want(self, config):
        """
        Get the SDA fabric devices related information from playbook.

        Parameters:
            config (list of dict): Playbook details contains the details of fabric devices.
        Returns:
            self: The current object with updated fabric devices details.
        Description:
            Check the existence of the fabric_devices in the playbook.
            Collect the fabric devices details from the playbook if fabric_devices exists.
        """

        self.log(
            "Starting to retrieve fabric devices information from the provided configuration.",
            "DEBUG",
        )
        fabric_devices = config.get("fabric_devices")
        if not fabric_devices:
            self.msg = "The parameter 'fabric_devices' is missing under the 'config'."
            self.status = "failed"
            return self

        self.get_want_fabric_devices(fabric_devices).check_return_status()

        self.log(
            "Desired State (want): {requested_state}".format(requested_state=self.want),
            "INFO",
        )
        self.msg = "Successfully retrieved details from the playbook."
        self.status = "success"
        return self

    def bulk_add_fabric_devices(self, create_fabric_devices, fabric_name):
        """
        Add the SDA fabric devices with the given payload under the fabric.

        Parameters:
            create_fabric_devices (list): The payload for adding the fabric devices in bulk.
            fabric_name (str): The name of the fabric site or zone.
        Returns:
            self (object): The current object with adding SDA fabric device information.
        Description:
            Find the length of the payload, if it is greater than 40, separate it out into batches of 40.
            Call the add fabric devices API with the bulk payload. Check the task status from the task ID.
        """

        try:
            self.log("Starting to add fabric devices in batches.", "INFO")
            num_devices = len(create_fabric_devices)

            for item in range(0, num_devices, 40):
                payload = {"payload": create_fabric_devices[item : item + 40]}
                task_name = "add_fabric_devices"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrieve the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Successfully added the fabric device with details '{device_details}'.".format(
                    device_details=create_fabric_devices[item : item + 40]
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

            self.msg = "Successfully created the fabric devices with the payload to the fabric site '{fabric_site}': {payload}".format(
                fabric_site=fabric_name, payload=create_fabric_devices
            )
            self.log(self.msg, "INFO")
            self.status = "success"

        except Exception as msg:
            self.msg = "Exception occurred while updating the fabric devices with the payload '{payload}': {msg}".format(
                payload=create_fabric_devices, msg=msg
            )
            self.status = "failed"
            return self

        return self

    def bulk_update_fabric_devices(self, update_fabric_devices, fabric_name):
        """
        Update the SDA fabric devices with the given payload under the fabric.

        Parameters:
            update_fabric_devices (list): The payload for updating the fabric devices in bulk.
            fabric_name (str): The name of the fabric site or zone.
        Returns:
            self (object): The current object with updated SDA fabric device information.
        Description:
            Find the length of the payload, if it is greater than 40, separate it out into batches of 40.
            Call the update fabric devices API with the bulk payload. Check the task status from the task ID.
        """

        try:
            self.log("Starting to update fabric devices in batches.", "INFO")
            num_devices = len(update_fabric_devices)

            for item in range(0, num_devices, 40):
                payload = {"payload": update_fabric_devices[item : item + 40]}
                task_name = "update_fabric_devices"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrieve the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Successfully updated the fabric device with details '{device_details}'.".format(
                    device_details=update_fabric_devices[item : item + 40]
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

            self.msg = (
                "Successfully updated the device with payload '{payload}' to the fabric site '{fabric_site}'.".format(
                    payload=update_fabric_devices, fabric_site=fabric_name
                ),
                "INFO",
            )
            self.log(self.msg, "INFO")
            self.status = "success"

        except Exception as msg:
            self.msg = "Exception occurred while updating the fabric devices for the payload '{payload}': {msg}".format(
                payload=update_fabric_devices, msg=msg
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        return self

    def update_l2_handoff(
        self,
        have_l2_handoff,
        want_l2_handoff,
        device_ip,
        result_fabric_device_response,
        result_fabric_device_msg,
    ):
        """
        Create L2 Handoff in a fabric device with fields provided in playbook.

        Parameters:
            have_l2_handoff (list): L2 Handoff details from the Cisco Catalyst Center.
            want_l2_handoff (dict): L2 Handoff details from the user playbook.
            device_ip (str): The IP of the fabric device.
            result_fabric_device_response (dict): The response status of the fabric device.
            result_fabric_device_msg (dict): The message status of the fabric device.

        Returns:
            self (object): The current object with added L2 Handoff information.
        Description:
            Seperate the L2 Handoffs which need to be created and the rest. Since L2 Handoff can
            only be created not updated. Call the API 'add_fabric_devices_layer2_handoffs' to
            create the L2 Handoff in the provided device.
        """

        self.log(
            "Starting L2 Handoff update process for device IP: {ip}".format(
                ip=device_ip
            ),
            "DEBUG",
        )
        create_l2_handoff = []
        l2_handoff_index = -1

        # The L2 Handoffs does not support update
        # So find which L2 handoffs need to be created and which needs to be ignored
        for item in want_l2_handoff:
            l2_handoff_index += 1
            if not (have_l2_handoff and have_l2_handoff[l2_handoff_index]):
                self.log(
                    "Preparing to create L2 Handoff: {l2_handoff}".format(
                        l2_handoff=item
                    ),
                    "DEBUG",
                )
                create_l2_handoff.append(item)
            else:
                self.log(
                    "Ignoring existing L2 Handoff: {l2_handoff}".format(
                        l2_handoff=item
                    ),
                    "DEBUG",
                )

        if not create_l2_handoff:
            self.log(
                "No new L2 Handoffs to create for device IP: {ip}".format(ip=device_ip),
                "INFO",
            )
            self.msg = "No new L2 Handoffs are available to create."
            self.status = "success"
            return self

        try:
            payload = {"payload": create_l2_handoff}
            task_name = "add_fabric_devices_layer2_handoffs"
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)
            if not task_id:
                self.msg = (
                    "Unable to retrieve the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "L2 Handoff(s) '{l2_handoff}' added successfully in the device with IP '{ip}.".format(
                l2_handoff=create_l2_handoff, ip=device_ip
            )
            self.log(
                "Starting task status check for task ID: {task_id}".format(
                    task_id=task_id
                ),
                "DEBUG",
            )
            self.get_task_status_from_tasks_by_id(
                task_id, task_name, success_msg
            ).check_return_status()
        except Exception as msg:
            self.msg = "Exception occurred while creating the L2 Handoff(s) in the device '{ip}': {msg}".format(
                ip=device_ip, msg=msg
            )
            self.status = "failed"
            return self

        result_fabric_device_response.update({"l2_handoff_details": create_l2_handoff})
        result_fabric_device_msg.update(
            {"l2_handoff_details": "L2 Handoffs added successfully."}
        )

        self.msg = "Successfully added the L2 Handoffs."
        self.status = "success"
        return self

    def update_sda_l3_handoff(
        self,
        have_sda_l3_handoff,
        want_sda_l3_handoff,
        device_ip,
        result_fabric_device_response,
        result_fabric_device_msg,
    ):
        """
        Create SDA L3 Handoff in a fabric device with fields provided in playbook.

        Parameters:
            have_sda_l3_handoff (list): SDA L3 Handoff details from the Cisco Catalyst Center.
            want_sda_l3_handoff (dict): SDA L3 Handoff details from the user playbook.
            device_ip (str): The IP of the fabric device.
            result_fabric_device_response (dict): The response status of the fabric device.
            result_fabric_device_msg (dict): The message status of the fabric device.

        Returns:
            self (object): The current object with added SDA L3 Handoff information.
        Description:
            Identify the SDA L3 Handoffs which need to be created or updated. Since only one
            SDA L3 Handoff can only be created not updated. Call the API
            'add_fabric_devices_layer3_handoffs_with_sda_transit' to
            create the SDA L3 Handoff in the provided device.
        """

        self.log(
            "Starting update process for SDA L3 Handoff on device IP: {ip}".format(
                ip=device_ip
            ),
            "DEBUG",
        )

        # Check is SDA L3 Handoff exists or not
        if not have_sda_l3_handoff:
            self.log(
                "Desired SDA L3 Handoff details for the device '{ip}' (want): {requested_state}".format(
                    ip=device_ip, requested_state=want_sda_l3_handoff
                ),
                "DEBUG",
            )
            try:
                payload = {"payload": [want_sda_l3_handoff]}
                task_name = "add_fabric_devices_layer3_handoffs_with_sda_transit"
                self.log(
                    "Preparing to add new SDA L3 Handoff with payload: {payload}".format(
                        payload=payload
                    ),
                    "DEBUG",
                )
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrieve the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "L3 Handoff(s) with SDA Transit '{sda_l2_handoff}' added successfully in the device with IP '{ip}.".format(
                    sda_l2_handoff=want_sda_l3_handoff, ip=device_ip
                )
                self.log(
                    "Task ID retrieved: {task_id}".format(task_id=task_id), "DEBUG"
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
            except Exception as msg:
                self.msg = "Exception occurred while adding the SDA L3 Handoff for the device '{ip}': {msg}".format(
                    ip=device_ip, msg=msg
                )
                self.status = "failed"
                return self

            result_fabric_device_response.update(
                {"sda_l3_handoff_details": want_sda_l3_handoff}
            )
            result_fabric_device_msg.update(
                {"sda_l3_handoff_details": "SDA L3 handoff added successfully"}
            )
            self.msg = "Successfully added the L3 Handoff with SDA Transit."
            self.status = "success"
            return self

        self.log(
            "Current SDA L3 Handoff details for the device '{ip}' in Catalyst Center: {current_details}".format(
                ip=device_ip, current_details=have_sda_l3_handoff
            ),
            "DEBUG",
        )
        self.log(
            "Desired SDA L3 Handoff details for the device '{ip}' for Catalyst Center: {requested_details}".format(
                ip=device_ip, requested_details=want_sda_l3_handoff
            ),
            "DEBUG",
        )

        # SDA L3 Handoff Exists
        # Check if the SDA L3 Handoff required an update or not
        if not self.requires_update(
            have_sda_l3_handoff,
            want_sda_l3_handoff,
            self.fabric_l3_handoff_sda_obj_params,
        ):
            self.log(
                "SDA L3 Handoff for the device '{ip}' doesn't require an update.".format(
                    ip=device_ip
                ),
                "INFO",
            )
            result_fabric_device_msg.update(
                {"sda_l3_handoff_details": "SDA L3 Handoff doesn't require an update."}
            )
            self.msg = "L3 Handoff with SDA Transit does not require an update."
            self.status = "success"
            return self

        self.log(
            "Updating SDA L3 Handoff for the device '{ip}'.".format(ip=device_ip),
            "DEBUG",
        )

        # SDA L3 Handoff requires an update or not
        try:
            want_sda_l3_handoff.update({"id": have_sda_l3_handoff.get("id")})
            payload = {"payload": [want_sda_l3_handoff]}
            task_name = "update_fabric_devices_layer3_handoffs_with_sda_transit"
            self.log(
                "Preparing to update SDA L3 Handoff with payload: {payload}".format(
                    payload=payload
                ),
                "DEBUG",
            )
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)
            if not task_id:
                self.msg = (
                    "Unable to retrieve the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "L3 Handoff(s) with SDA Transit '{sda_l3_handoff}' updated successfully in the device with IP '{ip}.".format(
                sda_l3_handoff=want_sda_l3_handoff, ip=device_ip
            )
            self.log("Task ID retrieved: {task_id}".format(task_id=task_id), "DEBUG")
            self.get_task_status_from_tasks_by_id(
                task_id, task_name, success_msg
            ).check_return_status()
        except Exception as msg:
            self.msg = "Exception occurred while updating the SDA L3 Handoff for the device '{ip}': {msg}".format(
                ip=device_ip, msg=msg
            )
            self.status = "failed"
            return self

        self.log(
            "Successfully updated the SDA L3 Handoff to the device '{ip}'.".format(
                ip=device_ip
            ),
            "INFO",
        )
        result_fabric_device_response.update(
            {"sda_l3_handoff_details": want_sda_l3_handoff}
        )
        result_fabric_device_msg.update(
            {"sda_l3_handoff_details": "SDA L3 Handoff updated successfully."}
        )

        self.msg = "Successfully updated the L3 Handoff with SDA Transit."
        self.status = "success"
        return self

    def update_ip_l3_handoff(
        self,
        have_ip_l3_handoff,
        want_ip_l3_handoff,
        device_ip,
        result_fabric_device_response,
        result_fabric_device_msg,
    ):
        """
        Create IP L3 Handoff in a fabric device with fields provided in playbook.

        Parameters:
            have_ip_l3_handoff (list): IP L3 Handoff details from the Cisco Catalyst Center.
            want_ip_l3_handoff (dict): IP L3 Handoff details from the user playbook.
            device_ip (str): The IP of the fabric device.
            result_fabric_device_response (dict): The response status of the fabric device.
            result_fabric_device_msg (dict): The message status of the fabric device.

        Returns:
            self (object): The current object with added IP L3 Handoff information.
        Description:
            Identify the IP L3 Handoffs which need to be created or updated. Call the API
            'add_fabric_devices_layer3_handoffs_with_ip_transit' to create the IP L3 Handoff
            in the provided device. Call the API 'update_fabric_devices_layer3_handoffs_with_ip_transit'
            to update the IP L3 Handoff.
        """

        self.log(
            "Entering update_ip_l3_handoff with parameters:\n"
            "Device IP: {device_ip}\n"
            "Current IP L3 Handoff: {have}\n"
            "Desired IP L3 Handoff: {want}\n"
            "Fabric Device Response (Initial): {response}\n"
            "Fabric Device Message (Initial): {msg}".format(
                device_ip=device_ip,
                have=have_ip_l3_handoff,
                want=want_ip_l3_handoff,
                response=result_fabric_device_response,
                msg=result_fabric_device_msg,
            ),
            "DEBUG",
        )
        create_ip_l3_handoff = []
        update_ip_l3_handoff = []
        ip_l3_handoff_index = -1
        for item in want_ip_l3_handoff:
            ip_l3_handoff_index += 1
            self.log(
                "Evaluating desired handoff {index}/{total} for device {ip}.".format(
                    index=ip_l3_handoff_index + 1,
                    total=len(want_ip_l3_handoff),
                    ip=device_ip,
                ),
                "DEBUG",
            )

            # Check for the IP L3 Handoff existence
            if not (have_ip_l3_handoff and have_ip_l3_handoff[ip_l3_handoff_index]):
                create_ip_l3_handoff.append(item)
                self.log(
                    "Handoff {index} requires creation on device {ip}.".format(
                        index=ip_l3_handoff_index + 1, ip=device_ip
                    ),
                    "DEBUG",
                )
            else:
                if self.requires_update(
                    have_ip_l3_handoff[ip_l3_handoff_index],
                    item,
                    self.fabric_l3_handoff_ip_obj_params,
                ):
                    self.log(
                        "Handoff {index} requires updating on device {ip}.".format(
                            index=ip_l3_handoff_index + 1, ip=device_ip
                        ),
                        "DEBUG",
                    )
                    item.update(
                        {"id": have_ip_l3_handoff[ip_l3_handoff_index].get("id")}
                    )
                    update_ip_l3_handoff.append(item)

        # If both the list are empty, then not update is required
        if not (create_ip_l3_handoff or update_ip_l3_handoff):
            self.log(
                "IP L3 Handoff for the device '{ip}' doesn't require an update.".format(
                    ip=device_ip
                ),
                "INFO",
            )
            result_fabric_device_msg.update(
                {"ip_l3_handoff_details": "IP L3 Handoff doesn't require an update."}
            )

            return self

        # L3 IP Handoffs to be created
        result_fabric_device_response.update({"ip_l3_handoff_details": {}})
        result_fabric_device_msg.update({"ip_l3_handoff_details": {}})
        if create_ip_l3_handoff:
            self.log(
                "IP L3 Handoff details to be created for the device '{ip}' (want): {requested_state}".format(
                    ip=device_ip, requested_state=create_ip_l3_handoff
                ),
                "DEBUG",
            )
            try:
                payload = {"payload": create_ip_l3_handoff}
                task_name = "add_fabric_devices_layer3_handoffs_with_ip_transit"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrieve the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "L3 Handoff(s) with IP Transit '{ip_l3_handoff}' added successfully in the device with IP '{ip}.".format(
                    ip_l3_handoff=create_ip_l3_handoff, ip=device_ip
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
            except Exception as msg:
                self.msg = "Exception occurred while adding the L3 Handoff with IP Transit to the device '{ip}': {msg}".format(
                    ip=device_ip, msg=msg
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            result_fabric_device_response.get("ip_l3_handoff_details").update(
                {"creation": create_ip_l3_handoff}
            )
            result_fabric_device_msg.get("ip_l3_handoff_details").update(
                {"creation": "IP L3 Handoffs creation is successful."}
            )

        # L3 IP Handoffs to be updated
        if update_ip_l3_handoff:
            self.log(
                "Desired L3 Handoff details with IP Transit for the device '{ip}' for Catalyst Center: {requested_details}".format(
                    ip=device_ip, requested_details=update_ip_l3_handoff
                ),
                "DEBUG",
            )
            try:
                payload = {"payload": update_ip_l3_handoff}
                task_name = "update_fabric_devices_layer3_handoffs_with_ip_transit"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrieve the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "L3 Handoff(s) with IP Transit '{ip_l3_handoff}' updated successfully in the device with IP '{ip}.".format(
                    ip_l3_handoff=update_ip_l3_handoff, ip=device_ip
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
            except Exception as msg:
                self.msg = "Exception occurred while updating the L3 Handoff with IP Transit to the device '{ip}': {msg}".format(
                    ip=device_ip, msg=msg
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            self.log(
                "Successfully updated the L3 Handoff with IP Transit for the device '{ip}'.".format(
                    ip=device_ip
                ),
                "INFO",
            )
            result_fabric_device_response.get("ip_l3_handoff_details").update(
                {"updation": update_ip_l3_handoff}
            )
            result_fabric_device_msg.get("ip_l3_handoff_details").update(
                {"updation": "IP L3 Handoffs updation is successful."}
            )

        self.msg = "L3 Handoff(s) with IP Transit operations are successful."
        self.log(str(self.msg), "DEBUG")
        self.status = "success"
        return self

    def check_managed_ap_locations_requires_update(
        self,
        have_wireless_controller_details,
        want_wireless_controller_details,
        device_ip,
    ):
        """
        Check if the managed AP locations require updating by comparing current and desired wireless controller scopes.

        Args:
            have_wireless_controller_details (dict): Current wireless controller details, including primary and secondary scopes.
            want_wireless_controller_details (dict): Desired wireless controller details to compare against.
            device_ip (str): IP address of the device being checked.

        Returns:
            tuple:
                bool: True if update is required, False otherwise.
                dict: Updated scope details containing 'primary_managed_ap_locations' and 'secondary_managed_ap_locations' from the desired state.

        Description:
            This method compares the unordered lists of dictionaries for both primary and secondary scopes
            between the current and desired wireless controller settings to determine if an update is necessary.
            It returns a flag indicating whether an update is needed and the updated scope details.
        """

        self.log(
            f"Checking if managed AP locations require update for device IP '{device_ip}'",
            "INFO",
        )

        requires_update = False
        want_primary_managed_ap_locations = want_wireless_controller_details.get(
            "primary_managed_ap_locations"
        )
        want_secondary_managed_ap_locations = want_wireless_controller_details.get(
            "secondary_managed_ap_locations"
        )

        updated_scope_details = {
            "primary_managed_ap_locations": want_primary_managed_ap_locations,
            "secondary_managed_ap_locations": want_secondary_managed_ap_locations,
        }

        if have_wireless_controller_details is None:
            requires_update = True
            self.log(
                f"Have wireless controller settings are not present for device: {device_ip}\n"
                f"Managed AP location update required for device IP '{device_ip}': {requires_update}\n"
                f"Updated scope details: '{self.pprint(updated_scope_details)}'",
                "INFO",
            )
            return requires_update, updated_scope_details

        self.log("Comparing primary and secondary scopes...", "DEBUG")
        have_primary_managed_ap_locations = have_wireless_controller_details.get(
            "primary_managed_ap_locations"
        )
        requires_update = not self.compare_unordered_lists_of_dicts(
            have_primary_managed_ap_locations, want_primary_managed_ap_locations
        )

        have_secondary_managed_ap_locations = have_wireless_controller_details.get(
            "secondary_managed_ap_locations"
        )
        requires_update |= not self.compare_unordered_lists_of_dicts(
            have_secondary_managed_ap_locations, want_secondary_managed_ap_locations
        )

        self.log(
            f"Managed AP location update required for device IP '{device_ip}': {requires_update}",
            "INFO",
        )
        if requires_update:
            self.log(
                f"Updated scope details: {self.pprint(updated_scope_details)}", "DEBUG"
            )

        return requires_update, updated_scope_details

    def update_managed_ap_locations_for_network_device(
        self, managed_ap_locations, fabric_device_ip, device_id
    ):
        """
        Update managed AP locations for a given network device by posting site scope information to Catalyst Center.

        Args:
            managed_ap_locations (dict): Dictionary with 'primary_managed_ap_locations' and 'secondary_managed_ap_locations' containing site IDs.
            fabric_device_ip (str): IP address of the target fabric device.
            device_id (str): Device ID of the fabric device in Cisco Catalyst Center.

        Returns:
            self: The current object after performing the update.

        Description:
            This function extracts primary and secondary site IDs from the given managed AP locations,
            constructs the API payload, makes a POST API call, and tracks task status to ensure
            the AP locations are successfully updated for the device.
        """

        self.log(
            f"Initiating update of managed ap locations for device with IP address: '{fabric_device_ip}'",
            "INFO",
        )

        task_name = "assign_managed_ap_locations_for_w_l_c"
        primary_managed_ap_locations_site_id = [
            scope_details.get("siteId")
            for scope_details in managed_ap_locations.get(
                "primary_managed_ap_locations"
            )
        ]
        secondary_managed_ap_locations_site_id = [
            scope_details.get("siteId")
            for scope_details in managed_ap_locations.get(
                "secondary_managed_ap_locations"
            )
        ]

        self.log(
            f"[{fabric_device_ip}] Updating managed AP scopes:\n  - Primary: {primary_managed_ap_locations_site_id}\n  "
            f"- Secondary: {secondary_managed_ap_locations_site_id}",
            "DEBUG",
        )

        parameters = {
            "device_id": device_id,
            "primaryManagedAPLocationsSiteIds": primary_managed_ap_locations_site_id,
            "secondaryManagedAPLocationsSiteIds": secondary_managed_ap_locations_site_id,
        }

        task_id = self.get_taskid_post_api_call("wireless", task_name, parameters)

        if not task_id:
            self.msg = f"Unable to retrieve the task_id for the updating managed ap locations for device with IP address: {fabric_device_ip}'."
            self.fail_and_exit(self.msg)

        success_msg = f"Managed AP locations for device with IP Address: '{fabric_device_ip}' updated successfully in the Cisco Catalyst Center"
        self.get_task_status_from_tasks_by_id(
            task_id, task_name, success_msg
        ).check_return_status()

        self.log(
            f"Completed update of managed AP locations for device IP: '{fabric_device_ip}'",
            "DEBUG",
        )

        return self

    def check_wireless_controller_settings_requires_update(
        self,
        have_wireless_controller_details,
        want_wireless_controller_details,
        device_ip,
    ):
        """
        Check if wireless controller settings require an update based on 'enable' and 'rolling_ap_upgrade' fields.

        Args:
            have_wireless_controller_details (dict): Current state from the system.
            want_wireless_controller_details (dict): Desired state from the playbook.
            device_ip (str): IP address of the wireless controller device being validated.

        Returns:
            tuple:
                bool: True if an update is required, False otherwise.
                dict: Wireless controller settings from the desired state.

        Description:
            This function compares the current ('have') and desired ('want') wireless controller settings for a specific device.
            It checks two fields: 'enable' (bool) and 'rolling_ap_upgrade' (dict).
            - If both 'enable' values are False, no update is required.
            - If there is any mismatch in 'enable' or 'rolling_ap_upgrade', an update is required.
            The function returns a boolean flag and the desired wireless controller settings to be applied.
        """

        self.log(
            f"Starting wireless controller settings comparison for device: {device_ip}",
            "INFO",
        )

        requires_update = False
        want_enable = want_wireless_controller_details.get("enable")
        want_rolling_ap_upgrade = want_wireless_controller_details.get(
            "rolling_ap_upgrade"
        )
        wireless_controller_settings = {
            "enable": want_enable,
            "rolling_ap_upgrade": want_rolling_ap_upgrade,
        }

        if have_wireless_controller_details is None:
            self.log(
                f"No current wireless controller settings found for device {device_ip}. Update required."
                f"Updated wireless controller settings: {wireless_controller_settings}",
                "INFO",
            )
            requires_update = True
            return requires_update, wireless_controller_settings

        have_enable = have_wireless_controller_details.get("enable")

        if have_enable is False and want_enable is False:
            self.log(
                f"'enable' is False for both current(have) and desired(want) states on device {device_ip}. No update required.",
                "DEBUG",
            )
            return requires_update, wireless_controller_settings

        if have_enable != want_enable:
            self.log(
                f"'enable' mismatch for device {device_ip} → have: {have_enable}, want: {want_enable}",
                "DEBUG",
            )
            requires_update = True

        have_rolling_ap_upgrade = have_wireless_controller_details.get(
            "rolling_ap_upgrade"
        )

        if have_rolling_ap_upgrade != want_rolling_ap_upgrade:
            self.log(
                f"'rolling_ap_upgrade' mismatch for device {device_ip}:\n  have: {have_rolling_ap_upgrade}\n  want: {want_rolling_ap_upgrade}",
                "DEBUG",
            )
            requires_update = True
        else:
            self.log(f"'rolling_ap_upgrade' matches for device {device_ip}.", "DEBUG")

        self.log(
            f"Wireless controller settings requires update : {requires_update} for device {device_ip}."
            f"Updated wireless controller settings: {wireless_controller_settings}",
            "INFO",
        )
        return requires_update, wireless_controller_settings

    def update_wireless_controller_settings(self, fabric_devices):
        """
        Update wireless controller settings and managed AP locations for each device in the fabric.

        Args:
            fabric_devices (dict): Dictionary containing fabric details including 'fabric_name' and
                                a list of 'device_config' with device-specific configurations.

        Returns:
            self: Returns the instance to allow method chaining.

        Description:
            Iterates through each device in the fabric, compares current ('have') and desired ('want')
            wireless controller settings and managed AP locations, and updates them if required.
            It logs each significant step and condition, and handles device reloads when disabling
            wireless controller settings if configured to do so.
        """

        fabric_name = fabric_devices.get("fabric_name")
        self.log(
            f"Starting to update wireless controller settings for fabric: {fabric_name}",
            "DEBUG",
        )
        device_config = fabric_devices.get("device_config")

        for device_config_index, item in enumerate(device_config):
            self.log(f"Processing device at index {device_config_index}.", "DEBUG")

            # Retrieve desired device details to check if embedded wireless controller capabilities are present
            want_device_details = self.want.get("fabric_devices")[device_config_index].get("device_details")

            if not want_device_details.get("embedded_wireless_controller_capabilities"):
                self.log(
                    f"Skipping Device at index {device_config_index} as it does not have embedded wireless controller capabilities.",
                    "DEBUG",
                )
                continue

            if item.get("wireless_controller_settings") is None:
                self.log(
                    f"Skipping device at index {device_config_index} as it has no wireless controller settings to configure.",
                    "DEBUG",
                )
                continue

            device_config_have = self.have.get("fabric_devices")[device_config_index]
            fabric_site_id = device_config_have.get("fabric_site_id")
            device_details = device_config_have.get("device_details", {})
            device_roles = device_details.get("deviceRoles") or item.get("device_roles")
            device_ip = item.get("device_ip")
            network_device_id = device_config_have.get("network_device_id")
            have_wireless_controller_details = device_config_have.get(
                "wireless_controller_settings"
            )

            # Validate device roles for wireless controller settings
            self.validate_device_roles_for_wireless_settings(
                device_roles
            ).check_return_status()

            self.log(
                f"Starting update for device index {device_config_index} with IP Address: {device_ip}",
                "DEBUG",
            )

            # Retrieve desired wireless controller settings
            want_wireless_controller_details = self.want.get("fabric_devices")[
                device_config_index
            ].get("wireless_controller_settings")

            self.log(
                f"Current wireless controller details: {self.pprint(have_wireless_controller_details)}",
                "DEBUG",
            )
            self.log(
                f"Desired wireless controller details: {self.pprint(want_wireless_controller_details)}",
                "DEBUG",
            )

            # Check if managed AP locations require update
            requires_update, updated_scope_details = (
                self.check_managed_ap_locations_requires_update(
                    have_wireless_controller_details,
                    want_wireless_controller_details,
                    device_ip,
                )
            )
            self.log(f"Managed AP locations require update: {requires_update}", "DEBUG")
            if requires_update:
                self.log(
                    f"Updating managed AP locations for device {device_ip}.", "INFO"
                )
                self.update_managed_ap_locations_for_network_device(
                    updated_scope_details, device_ip, network_device_id
                )
            else:
                self.log(
                    f"No update required for managed AP locations on device {device_ip}",
                    "DEBUG",
                )

            # Check if wireless controller settings require update
            requires_update, updated_wireless_settings = (
                self.check_wireless_controller_settings_requires_update(
                    have_wireless_controller_details,
                    want_wireless_controller_details,
                    device_ip,
                )
            )
            self.log(
                f"Wireless controller settings require update: {requires_update}",
                "DEBUG",
            )

            if requires_update:
                self.log(
                    f"Updating wireless controller settings for device {device_ip}.",
                    "INFO",
                )
                self.update_switch_wireless_setting_and_rolling_ap_upgrade_management(
                    updated_wireless_settings,
                    device_ip,
                    network_device_id,
                    fabric_name,
                    fabric_site_id,
                )
            else:
                self.log(
                    f"No update required for wireless controller settings on device {device_ip}",
                    "DEBUG",
                )

            # Handle device reload if wireless controller is disabled
            if not updated_wireless_settings.get("enable"):
                self.log(
                    f"Wireless controller is disabled for device {device_ip}. Checking reload requirements.",
                    "DEBUG",
                )
                if want_wireless_controller_details.get("reload"):
                    self.log(
                        f"Reloading device {device_ip} due to wireless controller disable.",
                        "INFO",
                    )
                    self.reload_switch_for_wireless_controller_cleanup(
                        device_ip, network_device_id, fabric_name, fabric_site_id
                    )
                else:
                    self.log(
                        f"No reload required for device {device_ip} after wireless controller disable.",
                        "DEBUG",
                    )

        self.log(
            f"Completed updating wireless controller settings for fabric: {fabric_name}",
            "INFO",
        )
        return self

    def update_switch_wireless_setting_and_rolling_ap_upgrade_management(
        self,
        wireless_settings,
        device_ip,
        network_device_id,
        fabric_name,
        fabric_site_id,
    ):
        """
        Update switch wireless settings and rolling AP upgrade management for a specific device.

        Args:
            wireless_settings (dict): Desired wireless settings, including:
                                        - 'enable' (bool): Whether wireless is enabled.
                                        - 'rolling_ap_upgrade' (dict): Contains 'enable' (bool) and 'ap_reboot_percentage' (int).
            device_ip (str): IP address of the device to update.
            network_device_id (str): Network device identifier.
            fabric_name (str): Name of the fabric to which the device belongs.
            fabric_site_id (str): Site ID of the fabric.

        Returns:
            self: Returns the instance to allow method chaining.

        Description:
            This method constructs and sends an update request to the Cisco Catalyst Center API
            to modify the wireless settings and rolling AP upgrade configurations for the specified device.
            It logs all major steps, checks for task ID retrieval success, and waits for task completion.
        """

        self.log(
            f"Initiating update of switch wireless settings and rolling AP upgrade management for device '{device_ip}' under fabric '{fabric_name}'",
            "INFO",
        )

        # Construct payload
        enable = wireless_settings.get("enable")
        payload = {
            "fabric_id": fabric_site_id,
            "id": network_device_id,
            "enableWireless": enable,
        }

        if enable:
            rolling_ap_upgrade = wireless_settings.get("rolling_ap_upgrade")
            self.log(
                f"Applying rolling AP upgrade settings: {rolling_ap_upgrade}", "DEBUG"
            )
            payload["rollingApUpgrade"] = {
                "enableRollingApUpgrade": rolling_ap_upgrade.get("enable"),
                "apRebootPercentage": rolling_ap_upgrade.get("ap_reboot_percentage"),
            }
        else:
            self.log(
                f"Wireless settings is to be disabled for device '{device_ip}'. Skipping rolling AP upgrade settings.",
                "DEBUG",
            )

        self.log(
            f"Constructed API payload for device '{device_ip}': {self.pprint(payload)}",
            "DEBUG",
        )
        task_name = "switch_wireless_setting_and_rolling_ap_upgrade_management"
        parameters = payload

        task_id = self.get_taskid_post_api_call(
            "fabric_wireless", task_name, parameters
        )
        if not task_id:
            self.msg = (
                f"Unable to retrieve the task_id for the updating wireless settings "
                f"for the device with IP address: '{device_ip}' under fabric: '{fabric_name}'"
            )
            self.fail_and_exit(self.msg)

        success_msg = (
            f"Wireless Controller Settings for the device with IP address: '{device_ip}' under "
            f"fabric: '{fabric_name}' updated successfully in the Cisco Catalyst Center."
        )
        self.get_task_status_from_tasks_by_id(
            task_id, task_name, success_msg
        ).check_return_status()

        self.log(
            f"Completed update of switch wireless settings and rolling AP upgrade management for device '{device_ip}' under fabric '{fabric_name}'",
            "INFO",
        )
        return self

    def reload_switch_for_wireless_controller_cleanup(
        self, device_ip, network_device_id, fabric_name, fabric_site_id
    ):
        """
        Reload the switch device for wireless controller cleanup after disabling wireless controller capabilities.

        Args:
            device_ip (str): IP address of the device to reload.
            network_device_id (str): Network device identifier.
            fabric_name (str): Name of the fabric to which the device belongs.
            fabric_site_id (str): Site ID of the fabric.

        Returns:
            self: Returns the instance to allow method chaining.

        Description:
            This method triggers a reload of the specified switch device by making a task API call
            to the Cisco Catalyst Center. It logs key steps, ensures task ID retrieval,
            waits for task completion, and handles failures gracefully.
        """

        self.log(
            f"Initiating reload of the device with IP address: '{device_ip}' under fabric: '{fabric_name}' for "
            "controller cleanup after disabling wireless controller capabilities.",
            "INFO",
        )
        payload = {"fabric_id": fabric_site_id, "deviceId": network_device_id}

        self.log(
            f"Constructed API payload for device '{device_ip}': {self.pprint(payload)}",
            "DEBUG",
        )
        task_name = "reload_switch_for_wireless_controller_cleanup"
        parameters = payload
        task_id = self.get_taskid_post_api_call(
            "fabric_wireless", task_name, parameters
        )

        if not task_id:
            self.msg = f"Unable to retrieve the task_id for the reloading the device with IP address: '{device_ip}' under fabric: '{fabric_name}'"
            self.fail_and_exit(self.msg)

        success_msg = f"Reload successful for the device with IP address: '{device_ip}' under fabric: '{fabric_name}' in the Cisco Catalyst Center"
        self.get_task_status_from_tasks_by_id(
            task_id, task_name, success_msg
        ).check_return_status()

        self.log(
            f"Completed API request for reload of the device '{device_ip}' under fabric '{fabric_name}'.",
            "INFO",
        )
        return self

    def update_fabric_devices(self, fabric_devices):
        """
        Create/Update fabric devices, Border Settings, L2 Handoffs, L3 Handoff with SDA Transit,
        L3 Handoff with IP Transit in Cisco Catalyst Center with fields provided in playbook.

        Parameters:
            fabric_devices (dict): SDA fabric devices under a fabric site playbook details.
        Returns:
            self (object): The current object with updated desired Fabric Devices information.
        Description:
            Do the basic validation. Check if the device exists or not.
            If the device needs to added to the fabric call the API 'add_fabric_devices'.
            If the device already exists, check if the device needs any update or not.
            If the device needs update call the API 'update_fabric_devices'.
            Check the response of the task Id.
        """

        self.log(
            "Input values for update_fabric_devices: {input}".format(
                input=fabric_devices
            ),
            "DEBUG",
        )
        fabric_name = fabric_devices.get("fabric_name")
        if not fabric_name:
            self.log("Error: 'fabric_name' is missing from input.", "ERROR")
            self.set_operation_result(
                "failed", False, "Fabric name is required.", "ERROR"
            )
            return self

        self.log("Fabric name: '{fabric_name}'".format(fabric_name=fabric_name))
        fabric_device_index = -1
        device_config = fabric_devices.get("device_config")
        if not device_config:
            self.log("Error: 'device_config' is missing from input.", "ERROR")
            self.set_operation_result(
                "failed", False, "Device configuration is required.", "ERROR"
            )
            return self

        self.log(
            "The device config information for the fabric site '{fabric_name}': {device_config}".format(
                fabric_name=fabric_name, device_config=device_config
            )
        )
        self.response.append({"response": {}, "msg": {}})
        self.response[0].get("response").update({fabric_name: {}})
        self.response[0].get("msg").update({fabric_name: {}})
        to_create = []
        to_update = []
        for item in device_config:
            fabric_device_index += 1
            device_ip = item.get("device_ip")
            if not device_config:
                self.log("Error: 'device_ip' is missing from input.", "ERROR")
                self.set_operation_result(
                    "failed", False, "Device IP is required.", "ERROR"
                )
                return self

            self.log(
                "The device ip under the fabric site '{fabric_name}': {device_ip}".format(
                    fabric_name=fabric_name, device_ip=device_ip
                )
            )
            self.response[0].get("response").get(fabric_name).update(
                {
                    device_ip: {
                        "device_details": None,
                        "l2_handoff": [],
                        "l3_sda_handoff": None,
                        "l3_ip_handoff": [],
                    }
                }
            )
            self.response[0].get("msg").get(fabric_name).update({device_ip: {}})
            result_fabric_device_response = (
                self.response[0].get("response").get(fabric_name).get(device_ip)
            )
            result_fabric_device_msg = (
                self.response[0].get("msg").get(fabric_name).get(device_ip)
            )
            have_fabric_device = self.have.get("fabric_devices")[fabric_device_index]
            want_fabric_device = self.want.get("fabric_devices")[fabric_device_index]
            have_device_details = have_fabric_device.get("device_details")
            want_device_details = want_fabric_device.get("device_details")
            self.log(
                "Existing device details for IP '{ip}': {existing}".format(
                    ip=device_ip, existing=have_device_details
                ),
                "DEBUG",
            )
            self.log(
                "Desired device details for IP '{ip}': {desired}".format(
                    ip=device_ip, desired=want_device_details
                ),
                "DEBUG",
            )

            # Check fabric device exists, if not add it
            if not have_device_details:
                self.log(
                    "Desired fabric device '{ip}' details (want): {requested_state}".format(
                        ip=device_ip, requested_state=want_device_details
                    ),
                    "DEBUG",
                )
                try:
                    device_roles = want_device_details.get("deviceRoles")
                    self.log(
                        "Device roles retrieved: {device_roles}".format(
                            device_roles=device_roles
                        ),
                        "DEBUG",
                    )
                    if "CONTROL_PLANE_NODE" in device_roles:
                        self.log(
                            "Control Plane Node should be added first in the fabric. Hence, adding the Control "
                            "Plane Node '{ip}' in fabric '{fabric_name}' at the beginning of the list.".format(
                                ip=device_ip, fabric_name=fabric_name
                            ),
                            "INFO",
                        )
                        to_create = [want_device_details] + to_create
                    else:
                        self.log(
                            "Adding device with IP '{ip}' to fabric '{fabric_name}' because "
                            "it does not have Control Plane as its role.".format(
                                ip=device_ip, fabric_name=fabric_name
                            ),
                            "INFO",
                        )
                        to_create.append(want_device_details)

                except Exception as msg:
                    self.msg = (
                        "Exception occurred while adding the device '{ip}' "
                        "to the fabric site '{site}: {msg}".format(
                            ip=device_ip, site=fabric_name, msg=msg
                        )
                    )
                    self.status = "failed"
                    return self

                result_fabric_device_response.update(
                    {"device_details": want_device_details}
                )
                result_fabric_device_msg.update(
                    {"device_details": "SDA fabric device details added successfully."}
                )
            else:
                self.log(
                    "Current SDA fabric device '{ip}' details in Catalyst Center: {current_details}".format(
                        ip=device_ip, current_details=have_device_details
                    ),
                    "DEBUG",
                )
                self.log(
                    "Desired SDA fabric transit '{ip}' details for Catalyst Center: {requested_details}".format(
                        ip=device_ip, requested_details=want_device_details
                    ),
                    "DEBUG",
                )

                # Check if the update is required or not
                if not self.requires_update(
                    have_device_details,
                    want_device_details,
                    self.fabric_devices_obj_params,
                ):
                    self.log(
                        "SDA fabric device '{ip}' device doesn't require an update.".format(
                            ip=device_ip
                        ),
                        "INFO",
                    )
                    result_fabric_device_msg.update(
                        {
                            "device_details": "SDA fabric device details doesn't require an update."
                        }
                    )
                else:

                    # Device Details Exists
                    self.log(
                        "Current SDA fabric device '{ip}' details in Catalyst Center: {current_state}".format(
                            ip=device_ip, current_state=have_device_details
                        ),
                        "DEBUG",
                    )
                    self.log(
                        "Desired SDA fabric device '{ip}' details: {requested_state}".format(
                            ip=device_ip, requested_state=want_device_details
                        ),
                        "DEBUG",
                    )
                    want_device_details.update(
                        {
                            "id": self.have.get("fabric_devices")[
                                fabric_device_index
                            ].get("id")
                        }
                    )
                    to_update.append(want_device_details)
                    result_fabric_device_response.update(
                        {"device_details": want_device_details}
                    )
                    result_fabric_device_msg.update(
                        {
                            "device_details": "SDA fabric device details updated successfully."
                        }
                    )

        if to_create:
            self.log(
                "Attempting to add {count} device(s) to fabric '{fabric_name}'.".format(
                    count=len(to_create), fabric_name=fabric_name
                ),
                "INFO",
            )
            self.bulk_add_fabric_devices(to_create, fabric_name).check_return_status()

        if to_update:
            self.log(
                "Attempting to update {count} device(s) to fabric '{fabric_name}'.".format(
                    count=len(to_update), fabric_name=fabric_name
                ),
                "INFO",
            )
            self.bulk_update_fabric_devices(
                to_update, fabric_name
            ).check_return_status()

        fabric_device_index = -1
        for item in device_config:
            fabric_device_index += 1
            device_ip = item.get("device_ip")
            self.log(
                "Started the Handoffs operation for the device with IP '{ip}'.".format(
                    ip=device_ip
                )
            )
            result_fabric_device_response = (
                self.response[0].get("response").get(fabric_name).get(device_ip)
            )
            result_fabric_device_msg = (
                self.response[0].get("msg").get(fabric_name).get(device_ip)
            )
            have_fabric_device = self.have.get("fabric_devices")[fabric_device_index]
            self.log(
                "The details of the device '{ip}' in the Catalyst Center: {have_details}".format(
                    ip=device_ip, have_details=have_device_details
                )
            )
            want_fabric_device = self.want.get("fabric_devices")[fabric_device_index]
            self.log(
                "The details of the device '{ip}' provided in the playbook: {want_details}".format(
                    ip=device_ip, want_details=want_fabric_device
                )
            )
            device_roles = want_fabric_device.get("device_details").get("deviceRoles")
            self.log(
                "The device role of the device '{ip}' is '{device_role}'".format(
                    ip=device_ip, device_role=device_roles
                )
            )
            if "BORDER_NODE" not in device_roles:
                continue

            self.log(
                "Entered handoffs section which includes SDA - IP L3 Handoffs and L2 Handoff"
            )
            have_l2_handoff = have_fabric_device.get("l2_handoff_details")
            self.log(
                "The L2 Handoff details of the device '{ip}' in the Catalyst Center: {have_details}".format(
                    ip=device_ip, have_details=have_l2_handoff
                )
            )
            want_l2_handoff = want_fabric_device.get("l2_handoff_details")
            self.log(
                "The L2 Handoff details of the device '{ip}' provided in the playbook: {want_details}".format(
                    ip=device_ip, want_details=want_l2_handoff
                )
            )
            if want_l2_handoff:
                self.log(
                    "Operating the L2 Handoff details for the device '{device_ip}'.".format(
                        device_ip=device_ip
                    )
                )
                self.update_l2_handoff(
                    have_l2_handoff,
                    want_l2_handoff,
                    device_ip,
                    result_fabric_device_response,
                    result_fabric_device_msg,
                )

            have_sda_l3_handoff = have_fabric_device.get("sda_l3_handoff_details")
            self.log(
                "The L3 SDA Handoff details of the device '{ip}' in the Catalyst Center: {have_details}".format(
                    ip=device_ip, have_details=have_sda_l3_handoff
                )
            )
            want_sda_l3_handoff = want_fabric_device.get("sda_l3_handoff_details")
            self.log(
                "The L3 SDA Handoff details of the device '{ip}' provided in the playbook: {want_details}".format(
                    ip=device_ip, want_details=want_sda_l3_handoff
                )
            )
            if want_sda_l3_handoff:
                self.log(
                    "Operating the L3 Handoff with SDA Transit details for the device '{device_ip}'.".format(
                        device_ip=device_ip
                    )
                )
                self.update_sda_l3_handoff(
                    have_sda_l3_handoff,
                    want_sda_l3_handoff,
                    device_ip,
                    result_fabric_device_response,
                    result_fabric_device_msg,
                )

            have_ip_l3_handoff = have_fabric_device.get("ip_l3_handoff_details")
            self.log(
                "The L3 IP Handoff details of the device '{ip}' in the Catalyst Center: {have_details}".format(
                    ip=device_ip, have_details=have_ip_l3_handoff
                )
            )
            want_ip_l3_handoff = want_fabric_device.get("ip_l3_handoff_details")
            self.log(
                "The L3 IP Handoff details of the device '{ip}' provided in the playbook: {want_details}".format(
                    ip=device_ip, want_details=want_ip_l3_handoff
                )
            )
            if want_ip_l3_handoff:
                self.log(
                    "Operating the L3 Handoff with IP Transit details for the device '{device_ip}'.".format(
                        device_ip=device_ip
                    )
                )
                self.update_ip_l3_handoff(
                    have_ip_l3_handoff,
                    want_ip_l3_handoff,
                    device_ip,
                    result_fabric_device_response,
                    result_fabric_device_msg,
                )

        self.result.update({"response": self.response})
        self.log("Updated the SDA fabric transits successfully", "INFO")
        self.msg = "The operations on fabric device is successful."
        self.status = "success"
        return self

    def get_diff_merged(self, config):
        """
        Add or Update the SDA devices transits, Border Settings, L2 Handoff, L3 SDA Handoff,
        L3 IP Handoff in Cisco Catalyst Center based on the playbook details.

        Parameters:
            config (list of dict): Playbook details containing SDA fabric devices information.
        Returns:
            self (object): The current object with updated desired Fabric Devices information.
        Description:
            If the 'fabric_devices' is available in the playbook, call the function 'update_fabric_devices'.
            Else return self.
        """

        fabric_devices = config.get("fabric_devices")
        if fabric_devices is not None:
            self.log(
                "Updating fabric devices: {devices}".format(devices=fabric_devices),
                "DEBUG",
            )
            try:
                self.update_fabric_devices(fabric_devices).check_return_status()

                if self.fabric_type == "fabric_site":
                    # To Update Wireless Controller Settings, have should be updated with the fabric ID in case of new fabric creation.
                    self.get_have(config)
                    self.log("Updating wireless controller settings for fabric type 'fabric_site'.", "DEBUG")
                    self.update_wireless_controller_settings(
                        fabric_devices
                    ).check_return_status()
                else:
                    self.log(
                        f"Skipping wireless controller settings update for fabric type '{self.fabric_type}'.",
                        "DEBUG",
                    )
                self.log("Successfully updated fabric devices.", "INFO")
            except Exception as e:
                self.log(
                    "Error while updating fabric devices: {error}".format(error=str(e)),
                    "ERROR",
                )
                self.set_operation_result(
                    "failed", False, "Failed to update fabric devices.", "ERROR"
                )
                return self
        else:
            self.log(
                "No 'fabric_devices' found in configuration. Skipping update.",
                "WARNING",
            )

        return self

    def prioritize_device_deletion(self, device_config):
        """
        Prioritize the device config so that the device with the role 'CONTROL_PLANE_NODE'
        is deleted last, and devices that don't exist are handled first.

        Parameters:
            device_config (list): Devices config details provided by the user in the playbook.
        Returns:
            updated_device_config (list): Reordered device config details.
        Description:
            For each device in the config, check whether it exists in the Cisco Catalyst Center.
            If the device doesn't exist, prepend it to the list. If it has a role 'CONTROL_PLANE_NODE',
            append it to ensure it is processed last. Update self.have['fabric_details'] with the new
            order and return the updated config.
        """

        fabric_device_index = -1
        updated_device_config = []
        update_have = []
        self.log(
            "Starting to reorder devices based on their existence and role.", "DEBUG"
        )
        self.log(
            "Input device_config: {device_config}".format(device_config=device_config),
            "DEBUG",
        )
        for item in device_config:
            fabric_device_index += 1
            device_ip = item.get("device_ip")
            self.log("Processing device with IP: {ip}".format(ip=device_ip))
            have_device_details = self.have.get("fabric_devices")[fabric_device_index]
            exists = have_device_details.get("exists")
            if not exists:
                self.log(
                    "The device with IP address '{ip}' is not available in the Cisco Catalyst Center.".format(
                        ip=device_ip
                    )
                )
                updated_device_config = [item] + updated_device_config
                update_have = [have_device_details] + update_have
                continue

            device_roles = have_device_details.get("device_details").get("deviceRoles")
            if "CONTROL_PLANE_NODE" in device_roles:
                self.log(
                    "Device with IP '{ip}' has role 'CONTROL_PLANE_NODE', appending to the end.".format(
                        ip=device_ip
                    )
                )
                updated_device_config.append(item)
                update_have.append(have_device_details)
                continue

            self.log(
                "Device with IP '{ip}' role '{device_roles}', prepending.".format(
                    ip=device_ip, device_roles=device_roles
                )
            )
            updated_device_config.insert(0, item)
            update_have.insert(0, have_device_details)

        self.have.update({"fabric_devices": update_have})
        self.log(
            "Updated device_config for deletion: {updated_config}".format(
                updated_config=updated_device_config
            )
        )

        return updated_device_config

    def delete_l2_handoff(
        self,
        have_l2_handoff,
        device_ip,
        result_fabric_device_response,
        result_fabric_device_msg,
    ):
        """
        Delete L2 Handoffs in Cisco Catalyst Center with fields provided in playbook.

        Parameters:
            have_l2_handoff (list): L2 Handoff details from the Cisco Catalyst Center.
            device_ip (str): The IP of the fabric device.
            result_fabric_device_response (dict): The response status of the fabric device.
            result_fabric_device_msg (dict): The message status of the fabric device.
        Returns:
            self (object): The current object with deleted L2 Handoffs information.
        Description:
            Seperate which L2 Handoff exist and which are not. If there are L2 Handoff,
            which needs to be deleted. Call the API 'delete_fabric_device_layer2_handoff_by_id'.
        """

        self.log(
            "Entering delete_l2_handoff API with parameters: "
            "have_l2_handoff={have_l2_handoff}, device_ip={device_ip}".format(
                have_l2_handoff=have_l2_handoff, device_ip=device_ip
            ),
            "DEBUG",
        )
        result_fabric_device_response.update({"l2_handoff_details": {}})
        delete_l2_handoff = []
        non_existing_l2_handoff = []

        # Check if the L2 Handoff exists or not
        for item in have_l2_handoff:
            if not item:
                non_existing_l2_handoff.append(item)
            else:
                delete_l2_handoff.append(item)

        self.log(
            "Identified L2 Handoffs to delete: {delete_list}".format(
                delete_list=delete_l2_handoff
            ),
            "DEBUG",
        )
        self.log(
            "Non-existing L2 Handoffs: {non_existing_list}".format(
                non_existing_list=non_existing_l2_handoff
            ),
            "DEBUG",
        )
        for id in delete_l2_handoff:
            try:
                payload = {"id": id}
                task_name = "delete_fabric_device_layer2_handoff_by_id"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrive the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    self.log(str(success_msg), "INFO")
                    return self

                success_msg = "Successfully deleted the fabric device L2 Handoff with id '{id}'.".format(
                    id=id
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
            except Exception as msg:
                self.msg = "Exception occurred while deleting the L2 Handoff in the fabric device with IP '{ip}': {msg}".format(
                    ip=device_ip, msg=msg
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

        result_fabric_device_response.get("l2_handoff_details").update(
            {
                "Deleted L2 Handoff": delete_l2_handoff,
                "Non existing L2 Handoff": non_existing_l2_handoff,
            }
        )
        if delete_l2_handoff:
            result_fabric_device_msg.update(
                {"l2_handoff_details": "L2 Handoffs deleted successfully."}
            )
        else:
            result_fabric_device_msg.update(
                {
                    "l2_handoff_details": "L2 Handoffs are not found in the Cisco Catalyst Center."
                }
            )

        self.msg = "Successfully deleted the L2 Handoffs."
        self.log(self.msg, "DEBUG")
        self.status = "success"
        return self

    def delete_sda_l3_handoff(
        self,
        have_sda_l3_handoff,
        device_ip,
        result_fabric_device_response,
        result_fabric_device_msg,
    ):
        """
        Delete L3 Handoff with SDA Transit in Cisco Catalyst Center with fields provided in playbook.

        Parameters:
            have_l2_handoff (list): SDA L3 Handoff details from the Cisco Catalyst Center.
            device_ip (str): The IP of the fabric device.
            result_fabric_device_response (dict): The response status of the fabric device.
            result_fabric_device_msg (dict): The message status of the fabric device.
        Returns:
            self (object): The current object with deleted SDA L3 Handoffs information.
        Description:
            Identify whether the SDA L3 Handoff exist or not. If there are SDA L3 Handoff,
            which needs to be deleted. Call the API 'delete_fabric_device_layer3_handoffs_with_sda_transit'.
        """

        self.log(
            "Entering delete_sda_l3_handoff API with parameters: "
            "have_sda_l3_handoff={have_sda_l3_handoff}, device_ip={device_ip}".format(
                have_sda_l3_handoff=have_sda_l3_handoff, device_ip=device_ip
            ),
            "DEBUG",
        )
        if not have_sda_l3_handoff:
            self.log(
                "No SDA L3 Handoff found for device IP '{device_ip}'.".format(
                    device_ip=device_ip
                ),
                "DEBUG",
            )
            self.log(
                "The SDA L3 Handoff doesnot exist under the device {device_ip}.".format(
                    device_ip=device_ip
                )
            )
            result_fabric_device_msg.update(
                {
                    "sda_l3_handoff_details": "SDA L3 Handoff is not found in the Cisco Catalyst Center."
                }
            )
        else:
            self.log(
                "The SDA L3 Handoff exists under the device {device_ip}.".format(
                    device_ip=device_ip
                )
            )
            fabric_id = have_sda_l3_handoff.get("fabricId")
            network_device_id = have_sda_l3_handoff.get("networkDeviceId")
            self.log(
                "Found SDA L3 Handoff with fabric_id={fabric_id}, network_device_id={network_device_id}.".format(
                    fabric_id=fabric_id, network_device_id=network_device_id
                ),
                "DEBUG",
            )
            try:
                payload = {
                    "fabric_id": fabric_id,
                    "network_device_id": network_device_id,
                }
                task_name = "delete_fabric_device_layer3_handoffs_with_sda_transit"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrive the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Successfully deleted the fabric device SDA Transit L3 Handoff with id '{id}'.".format(
                    id=id
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
            except Exception as msg:
                self.msg = "Exception occurred while deleting the SDA L3 Handoff in the fabric device with IP '{ip}': {msg}".format(
                    ip=device_ip, msg=msg
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

            result_fabric_device_response.update(
                {"sda_l3_handoff_details": have_sda_l3_handoff}
            )
            result_fabric_device_msg.update(
                {"sda_l3_handoff_details": "SDA L3 Handoff is deleted successfully."}
            )

        self.msg = "Successfully deleted the SDA L3 Handoffs."
        self.log(str(self.msg), "DEBUG")
        self.status = "success"
        return self

    def delete_ip_l3_handoff(
        self,
        have_ip_l3_handoff,
        device_ip,
        result_fabric_device_response,
        result_fabric_device_msg,
    ):
        """
        Delete L3 Handoff with IP Transit in Cisco Catalyst Center with fields provided in playbook.

        Parameters:
            have_ip_l3_handoff (list): IP L3 Handoff details from the Cisco Catalyst Center.
            device_ip (str): The IP of the fabric device.
            result_fabric_device_response (dict): The response status of the fabric device.
            result_fabric_device_msg (dict): The message status of the fabric device.
        Returns:
            self (object): The current object with deleted IP L3 Handoffs information.
        Description:
            Seperate which IP L3 Handoff exist and which are not. If there are IP L3 Handoff,
            which needs to be deleted. Call the API 'delete_fabric_device_layer3_handoff_with_ip_transit_by_id'.
        """

        self.log(
            "Entering delete_ip_l3_handoff API with parameters: "
            "have_ip_l3_handoff={have_ip_l3_handoff}, device_ip={device_ip}".format(
                have_ip_l3_handoff=have_ip_l3_handoff, device_ip=device_ip
            ),
            "DEBUG",
        )
        result_fabric_device_response.update({"ip_l3_handoff_details": {}})
        delete_ip_l3_handoff = []
        non_existing_ip_l3_handoff = []

        # Check which IP L3 Handoff exists and which does not
        for item in have_ip_l3_handoff:
            if not item:
                non_existing_ip_l3_handoff.append(item)
            else:
                delete_ip_l3_handoff.append(item)

        self.log(
            "Identified delete_ip_l3_handoff: {delete_ip_l3_handoff}, non_existing_ip_l3_handoff: {non_existing_ip_l3_handoff}".format(
                delete_ip_l3_handoff=delete_ip_l3_handoff,
                non_existing_ip_l3_handoff=non_existing_ip_l3_handoff,
            ),
            "DEBUG",
        )

        for item in delete_ip_l3_handoff:
            id = item.get("id")
            self.log(
                "Attempting to delete IP L3 Handoff with id: {id}".format(id=id),
                "DEBUG",
            )
            try:
                payload = {"id": id}
                task_name = "delete_fabric_device_layer3_handoff_with_ip_transit_by_id"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)
                if not task_id:
                    self.msg = "Unable to retrive the task_id for the task '{task_name}'.".format(
                        task_name=task_name
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Successfully deleted the fabric device IP Transit L3 Handoff with id '{id}'.".format(
                    id=id
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
            except Exception as msg:
                self.msg = "Exception occurred while deleting the IP L3 Handoff in the fabric device with IP '{ip}': {msg}".format(
                    ip=device_ip, msg=msg
                )
                self.log(self.msg, "ERROR")
                self.status = "failed"
                return self

        result_fabric_device_response.get("ip_l3_handoff_details").update(
            {
                "Deleted L3 Handoff": delete_ip_l3_handoff,
                "Non existing L3 Handoff": non_existing_ip_l3_handoff,
            }
        )
        if delete_ip_l3_handoff:
            result_fabric_device_msg.update(
                {"ip_l3_handoff_details": "IP L3 Handoffs deleted successfully."}
            )
        else:
            result_fabric_device_msg.update(
                {
                    "ip_l3_handoff_details": "IP L3 Handoffs are not found in the Cisco Catalyst Center."
                }
            )

        self.msg = "Successfully deleted the IP L3 Handoffs."
        self.status = "success"
        return self

    def delete_fabric_devices(self, fabric_devices):
        """
        Delete fabric devices, Border Settings, L2 Handoffs, L3 Handoff with SDA Transit,
        L3 Handoff with IP Transit in Cisco Catalyst Center with fields provided in playbook.

        Parameters:
            fabric_devices (dict): SDA fabric devices under a fabric site playbook details.
        Returns:
            self (object): The current object with updated desired Fabric Devices information.
        Description:
            Do the basic validation. If L2 Handoff is available, call the API 'delete_l2_handoff'.
            If SDA L3 Handoff is available, call the API 'delete_sda_l3_handoff'. If IP L3 Handoff is availabl, call the API
            'delete_ip_l3_handoff'. If only the device IP is provided, call the API 'delete_fabric_device_by_id'
            to delete the fabric device from the fabric site.
        """

        fabric_name = fabric_devices.get("fabric_name")
        if not fabric_name:
            self.log("Error: 'fabric_name' is missing from input.", "ERROR")
            self.set_operation_result(
                "failed", False, "Fabric name is required.", "ERROR"
            )
            return self

        fabric_device_index = -1
        device_config = fabric_devices.get("device_config")
        if not device_config:
            self.log("Error: 'device_config' is missing from input.", "ERROR")
            self.set_operation_result(
                "failed", False, "Device configuration is required.", "ERROR"
            )
            return self

        self.response.append({"response": {}, "msg": {}})
        self.response[0].get("response").update({fabric_name: {}})
        self.response[0].get("msg").update({fabric_name: {}})
        self.log(
            "Starting deletion of fabric devices under fabric '{fabric_name}'".format(
                fabric_name=fabric_name
            ),
            "DEBUG",
        )
        updated_device_config = self.prioritize_device_deletion(device_config)
        for item in updated_device_config:
            fabric_device_index += 1
            device_ip = item.get("device_ip")
            self.response[0].get("response").get(fabric_name).update(
                {
                    device_ip: {
                        "device_details": None,
                        "l2_handoff": [],
                        "l3_sda_handoff": None,
                        "l3_ip_handoff": [],
                    }
                }
            )
            self.response[0].get("msg").get(fabric_name).update({device_ip: {}})
            self.log(
                "Processing device with IP '{device_ip}'".format(device_ip=device_ip),
                "DEBUG",
            )
            result_fabric_device_response = (
                self.response[0].get("response").get(fabric_name).get(device_ip)
            )
            result_fabric_device_msg = (
                self.response[0].get("msg").get(fabric_name).get(device_ip)
            )
            have_fabric_device = self.have.get("fabric_devices")[fabric_device_index]
            have_l2_handoff = have_fabric_device.get("l2_handoff_details")
            if have_l2_handoff:
                self.log(
                    "Deleting L2 Handoff for device '{device_ip}'".format(
                        device_ip=device_ip
                    ),
                    "DEBUG",
                )
                self.delete_l2_handoff(
                    have_l2_handoff,
                    device_ip,
                    result_fabric_device_response,
                    result_fabric_device_msg,
                ).check_return_status()
            else:
                result_fabric_device_msg.update(
                    {
                        "l3_ip_handoff": "IP L3 Handoff doesnot found in the Cisco Catalyst Center."
                    }
                )
            have_sda_l3_handoff = have_fabric_device.get("sda_l3_handoff_details")
            if have_sda_l3_handoff:
                self.log(
                    "Deleting SDA L3 Handoff for device '{device_ip}'".format(
                        device_ip=device_ip
                    ),
                    "DEBUG",
                )
                self.delete_sda_l3_handoff(
                    have_sda_l3_handoff,
                    device_ip,
                    result_fabric_device_response,
                    result_fabric_device_msg,
                ).check_return_status()
            else:
                result_fabric_device_msg.update(
                    {
                        "l3_sda_handoff": "SDA L3 Handoff doesnot found in the Cisco Catalyst Center."
                    }
                )

            have_ip_l3_handoff = have_fabric_device.get("ip_l3_handoff_details")

            if have_ip_l3_handoff:
                self.log(
                    "Deleting IP L3 Handoff for device '{device_ip}'".format(
                        device_ip=device_ip
                    ),
                    "DEBUG",
                )
                self.delete_ip_l3_handoff(
                    have_ip_l3_handoff,
                    device_ip,
                    result_fabric_device_response,
                    result_fabric_device_msg,
                ).check_return_status()
            else:
                result_fabric_device_msg.update(
                    {
                        "l2_handoff": "L2 Handoff doesnot found in the Cisco Catalyst Center."
                    }
                )

            device_exists = have_fabric_device.get("exists")
            device_roles = None
            if device_exists:
                device_roles = have_fabric_device.get("device_details").get(
                    "deviceRoles"
                )
                self.log(
                    "The role of the fabric device with IP '{ip}' is '{device_roles}'".format(
                        ip=device_ip, device_roles=device_roles
                    ),
                    "DEBUG",
                )

            # If 'sda_l3_handoff_details' and 'l3_sda_handoff' and 'l2_handoff' are not provided
            # We need to delete the device as well along with the settings

            layer3_handoff_ip_transit = None
            layer3_handoff_sda_transit = None
            layer2_handoff = None
            borders_settings = item.get("borders_settings")
            if device_roles and ("BORDER_NODE" in device_roles) and borders_settings:
                layer3_handoff_ip_transit = borders_settings.get(
                    "layer3_handoff_ip_transit"
                )
                layer3_handoff_sda_transit = borders_settings.get(
                    "layer3_handoff_sda_transit"
                )
                layer2_handoff = borders_settings.get("layer2_handoff")

            if not (
                layer3_handoff_ip_transit
                or layer3_handoff_sda_transit
                or layer2_handoff
            ):
                if device_exists:
                    id = have_fabric_device.get("id")
                    self.log(
                        "Deleting fabric device with IP '{device_ip}', ID '{id}'".format(
                            device_ip=device_ip, id=id
                        ),
                        "DEBUG",
                    )
                    try:
                        payload = {"id": id}
                        task_name = "delete_fabric_device_by_id"
                        task_id = self.get_taskid_post_api_call(
                            "sda", task_name, payload
                        )
                        if not task_id:
                            self.msg = "Unable to retrive the task_id for the task '{task_name}'.".format(
                                task_name=task_name
                            )
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            )
                            return self

                        success_msg = "Successfully deleted the SDA fabric device with IP '{ip}'.".format(
                            ip=device_ip
                        )
                        self.get_task_status_from_tasks_by_id(
                            task_id, task_name, success_msg
                        ).check_return_status()
                        result_fabric_device_msg.update(
                            {
                                "device_details": "SDA device successfully removed from fabric."
                            }
                        )
                    except Exception as msg:
                        self.msg = "Exception occurred while deleting the fabric device with IP '{ip}': {msg}".format(
                            ip=device_ip, msg=msg
                        )
                        self.log(self.msg, "ERROR")
                        self.status = "failed"
                        return self
                else:
                    self.log(
                        "Fabric device with IP '{device_ip}' not found in Cisco Catalyst Center.".format(
                            device_ip=device_ip
                        ),
                        "INFO",
                    )
                    result_fabric_device_msg.update(
                        {
                            "device_details": "SDA device not found in the Cisco Catalyst Center."
                        }
                    )

        self.result.update({"response": self.response})
        self.msg = "The deletion of devices L2 Handoff, L3 Handoff with IP and SDA transit is successful."
        self.log(str(self.msg), "DEBUG")
        self.status = "success"
        return self

    def get_diff_deleted(self, config):
        """
        Delete the SDA devices transits, Border Settings, L2 Handoff, L3 SDA Handoff,
        L3 IP Handoff in Cisco Catalyst Center based on the playbook details.

        Parameters:
            config (list of dict): Playbook details containing SDA fabric devices information.
        Returns:
            self (object): The current object with updated desired Fabric Devices information.
        Description:
            If the 'fabric_devices' is available in the playbook, call the function 'delete_fabric_devices'.
            Else return self.
        """

        fabric_devices = config.get("fabric_devices")
        if fabric_devices is not None:
            self.log(
                "Fabric devices found in the configuration. Initiating deletion process.",
                "INFO",
            )
            self.delete_fabric_devices(fabric_devices)
        else:
            self.log(
                "No fabric devices found in the configuration. No deletion actions performed.",
                "INFO",
            )

        return self

    def verify_ip_l3_handoff(self, device_ip, have_l3_ip, want_l3_ip):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            device_ip (str): The IP of the fabric device.
            have_l3_ip (dict): L3 handoff with IP transit details in the Cisco Catalyst Center.
            want_l3_ip (dict): L3 handoff with IP transit details provided in the playbook.
        Returns:
            self (object): The current object with updated verification information of L3 IP Handoff.
        """

        ip_l3_handoff_index = -1
        for item in want_l3_ip:
            ip_l3_handoff_index += 1
            if not self.requires_update(
                have_l3_ip[ip_l3_handoff_index],
                item,
                self.fabric_l3_handoff_ip_obj_params,
            ):
                self.msg = (
                    "The L3 Handoff for IP transit config for the device '{ip}' is still not "
                    "applied to the Cisco Catalyst Center.".format(ip=device_ip)
                )
                self.status = "failed"
                return self

        self.msg = "Successfully validated the L3 Handoff with IP Transit."
        self.status = "success"
        return self

    def verify_l2_handoff(self, device_ip, have_l2, want_l2):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            device_ip (str): The IP of the fabric device.
            have_l2 (dict): L2 handoff details in the Cisco Catalyst Center.
            want_l2 (dict): L2 handoff details provided in the playbook.
        Returns:
            self (object): The current object with updated verification information of L2 Handoff.
        """

        l2_handoff_index = -1
        for item in want_l2:
            l2_handoff_index += 1
            if not have_l2[l2_handoff_index]:
                self.msg = (
                    "The L2 Handoff for config '{config}' for the device '{ip}' is still not "
                    "applied to the Cisco Catalyst Center.".format(
                        config=item, ip=device_ip
                    )
                )
                self.status = "failed"
                return self

        self.msg = "Successfully validated the L2 Handoff."
        self.status = "success"
        return self

    def verify_sda_l3_handoff(self, device_ip, have_l3_sda, want_l3_sda):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            device_ip (str): The IP of the fabric device.
            have_l3_sda (dict): L3 handoff with SDA transit details in the Cisco Catalyst Center.
            want_l3_sda (dict): L3 handoff with SDA transit details provided in the playbook.
        Returns:
            self (object): The current object with updated verification information of L3 SDA Handoff.
        """

        if self.requires_update(
            have_l3_sda, want_l3_sda, self.fabric_l3_handoff_ip_obj_params
        ):
            self.msg = (
                "The L3 Handoff for SDA transit for the device '{ip}' is still not "
                "applied to the Cisco Catalyst Center.".format(ip=device_ip)
            )
            self.status = "failed"
            return self

        self.msg = "Successfully validated the L3 Handoff with SDA Transit."
        self.status = "success"
        return self

    def verify_layer3_settings(
        self, device_ip, have_device_details, want_device_details
    ):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            device_ip (str): The IP of the fabric device.
            have_device_details (dict): SDA fabric device details in the Cisco Catalyst Center.
            want_device_details (dict): SDA fabric device details provided in the playbook.
        Returns:
            self (object): The current object with updated verification information of SDA fabric devices.
        """

        if self.requires_update(
            have_device_details, want_device_details, self.fabric_devices_obj_params
        ):
            self.msg = (
                "The border setting for SDA device with IP '{ip}' is still not "
                "applied to the Cisco Catalyst Center.".format(ip=device_ip)
            )
            self.status = "failed"
            return self

        self.msg = "Successfully validated SDA fabric device details."
        self.status = "success"
        return self

    def verify_enable_wireless_controller_settings(
        self,
        have_wireless_controller_settings,
        want_wireless_controller_settings,
        fabric_name,
        device_ip,
    ):
        """
        Verify that the wireless controller settings and managed AP locations are correctly updated for a device.

        Args:
            have_wireless_controller_settings (dict): Current wireless controller settings of the device.
            want_wireless_controller_settings (dict): Desired wireless controller settings to verify against.
            fabric_name (str): Name of the fabric to which the device belongs.
            device_ip (str): IP address of the device.

        Returns:
            self: Returns the instance to allow method chaining.

        Description:
            This method checks if the managed AP locations and wireless controller settings match the desired state.
            If any setting is not updated as expected, it logs an error message and stops execution.
            On success, it logs and confirms the verification.
        """
        self.log(
            f"Starting verification of wireless controller settings and managed AP locations for device with IP '{device_ip}' under fabric '{fabric_name}'.",
            "INFO",
        )
        requires_update, updated_scope_details = (
            self.check_managed_ap_locations_requires_update(
                have_wireless_controller_settings,
                want_wireless_controller_settings,
                device_ip,
            )
        )
        if requires_update:
            self.msg = f"Managed AP Locations are NOT updated for device with IP '{device_ip}' under fabric '{fabric_name}'. Verification failed."
            self.fail_and_exit(self.msg)
        else:
            self.log(
                f"Managed AP Locations are updated for device with IP '{device_ip}' under fabric '{fabric_name}'.",
                "DEBUG",
            )

        self.log(
            f"Verifying 'rolling_ap_upgrade' settings for device '{device_ip}'...",
            "INFO",
        )
        want_rolling_ap_upgrade = want_wireless_controller_settings.get(
            "rolling_ap_upgrade", {}
        )
        want_rolling_ap_upgrade_enable = want_rolling_ap_upgrade.get("enable", False)

        self.log(
            f"Checking if 'rolling_ap_upgrade' is enabled in the desired settings for device '{device_ip}'.",
            "INFO",
        )

        if want_rolling_ap_upgrade_enable:
            self.log(
                f"'rolling_ap_upgrade' is enabled in the desired configuration for device '{device_ip}'. Checking if an update is required.",
                "INFO",
            )
            requires_update, updated_wireless_settings = (
                self.check_wireless_controller_settings_requires_update(
                    have_wireless_controller_settings,
                    want_wireless_controller_settings,
                    device_ip,
                )
            )
            if requires_update:
                self.msg = f"Wireless Controller Settings are NOT updated for device with IP '{device_ip}' under fabric '{fabric_name}'. Verification failed."
                self.fail_and_exit(self.msg)

            self.log(
                f"Wireless Controller Settings are updated for the device with IP address '{device_ip}' under fabric: '{fabric_name}.'",
                "INFO",
            )
        else:
            self.log(
                f"'rolling_ap_upgrade' is disabled in the desired configuration for device '{device_ip}'. Checking if an update is required.",
                "INFO",
            )
            if have_wireless_controller_settings:
                self.log(
                    f"Current wireless controller settings found for device '{device_ip}'. Verifying 'rolling_ap_upgrade' status.",
                    "INFO",
                )
                have_rolling_ap_upgrade = have_wireless_controller_settings.get(
                    "rolling_ap_upgrade", {}
                )
                have_rolling_ap_upgrade_enable = have_rolling_ap_upgrade.get(
                    "enable", False
                )

                if have_rolling_ap_upgrade_enable != want_rolling_ap_upgrade_enable:
                    self.msg = (
                        f"Mismatch in 'rolling_ap_upgrade' configuration for device '{device_ip}' under fabric '{fabric_name}'. "
                        f"Expected 'disabled', but found 'enabled'. Verification failed."
                    )
                    self.fail_and_exit(self.msg)

                self.log(
                    f"'rolling_ap_upgrade' is correctly disabled on device '{device_ip}'. No update needed.",
                    "INFO",
                )
            else:
                self.msg = (
                    f"Failed to retrieve current wireless controller settings for device '{device_ip}'. "
                    f"Verification failed."
                )
                self.fail_and_exit(self.msg)

        self.msg = (
            f"All Wireless Controller Settings are updated successfully for the device with IP address '{device_ip}' under fabric: '{fabric_name}.'"
            "Verification Successful"
        )
        return self

    def verify_disable_wireless_controller_settings(
        self, have_wireless_controller_settings, fabric_name, device_ip
    ):
        """
        Verify that the wireless controller settings are disabled for a specific device.

        Args:
            have_wireless_controller_settings (dict): Current wireless controller settings of the device.
            fabric_name (str): Name of the fabric to which the device belongs.
            device_ip (str): IP address of the device.

        Returns:
            self: Returns the instance to allow method chaining.

        Description:
            - Checks whether the 'enable' field in the current wireless controller settings is set to False.
            - Logs detailed messages for success and failure scenarios.
            - Stops execution if the wireless controller is still enabled.
        """
        self.log(
            f"Starting verification to ensure wireless controller settings are disabled for device with IP '{device_ip}' under fabric '{fabric_name}'.",
            "INFO",
        )

        have_enable = have_wireless_controller_settings.get("enable")
        if have_enable:
            self.msg = (
                f"Wireless controller settings are NOT disabled for the device with IP address '{device_ip}' under fabric '{fabric_name}'. "
                "Verification Failed."
            )
            self.fail_and_exit(self.msg)

        self.msg = (
            f"Wireless controller settings are successfully disabled for the device with IP address '{device_ip}' under fabric '{fabric_name}'. "
            "Verification Successful."
        )
        return self

    def verify_diff_merged(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (dict): Playbook details containing fabric devices configuration.
        Returns:
            self (object): The current object with updated desired Fabric Devices information.
        Description:
            Call the get_have function to collected the updated information from the Cisco Catalyst Center.
            Check the difference between the information provided by the user and the information collected
            from the Cisco Catalyst Center. If there is any difference, then the config is not applied to
            the Cisco Catalyst Center.
        """

        self.get_have(config)
        self.log(
            "Current State (have): {current_state}".format(current_state=self.have),
            "INFO",
        )
        self.log(
            "Desired State (want): {requested_state}".format(requested_state=self.want),
            "INFO",
        )
        fabric_devices = config.get("fabric_devices")
        if fabric_devices is not None:
            fabric_name = fabric_devices.get("fabric_name")
            device_config = fabric_devices.get("device_config")
            fabric_device_index = -1
            for item in device_config:
                fabric_device_index += 1
                device_ip = item.get("device_ip")
                have_details = self.have.get("fabric_devices")[fabric_device_index]
                want_details = self.want.get("fabric_devices")[fabric_device_index]
                if item.get("wireless_controller_settings"):
                    if self.fabric_type == "fabric_site":
                        self.log(
                            f"Starting verification of wireless controller settings for device with IP '{device_ip}' under fabric '{fabric_name}'.",
                            "INFO",
                        )
                        have_wireless_controller_settings = have_details.get(
                            "wireless_controller_settings", None
                        )
                        want_wireless_controller_settings = want_details.get(
                            "wireless_controller_settings"
                        )
                        enable = want_wireless_controller_settings.get("enable")
                        if enable:
                            self.log(
                                f"Verifying that wireless controller settings are enabled for device with IP '{device_ip}'.",
                                "DEBUG",
                            )
                            self.verify_enable_wireless_controller_settings(
                                have_wireless_controller_settings,
                                want_wireless_controller_settings,
                                fabric_name,
                                device_ip,
                            ).check_return_status()
                        else:
                            self.log(
                                f"Verifying that wireless controller settings are disabled for device with IP '{device_ip}'.",
                                "DEBUG",
                            )
                            self.verify_disable_wireless_controller_settings(
                                have_wireless_controller_settings, fabric_name, device_ip
                            ).check_return_status()
                    else:
                        self.log(
                            f"Skipping wireless controller settings verification for fabric type '{self.fabric_type}'.", "DEBUG"
                        )

                # Verifying whether the IP L3 Handoff is applied to the Cisco Catalyst Center or not
                if item.get("layer3_handoff_ip_transit"):
                    have_l3_ip = have_details.get("ip_l3_handoff_details")
                    want_l3_ip = want_details.get("ip_l3_handoff_details")
                    self.verify_ip_l3_handoff(
                        device_ip, have_l3_ip, want_l3_ip
                    ).check_return_status()
                self.log(
                    "Successfully validated the L3 Handoffs for IP Transit in the device '{ip}'.".format(
                        ip=device_ip
                    ),
                    "INFO",
                )

                # Verifying whether the SDA L3 Handoff is applied to the Cisco Catalyst Center or not
                if item.get("layer3_handoff_sda_transit"):
                    have_l3_sda = have_details.get("sda_l3_handoff_details")
                    want_l3_sda = want_details.get("sda_l3_handoff_details")
                    self.verify_sda_l3_handoff(
                        device_ip, have_l3_sda, want_l3_sda
                    ).check_return_status()

                self.log(
                    "Successfully validated the L3 Handoffs for SDA Transit in the device '{ip}'.".format(
                        ip=device_ip
                    ),
                    "INFO",
                )

                # Verifying whether the L2 Handoff is applied to the Cisco Catalyst Center or not
                if item.get("layer2_handoff"):
                    have_l2 = have_details.get("sda_l3_handoff_details")
                    want_l2 = want_details.get("sda_l3_handoff_details")
                    self.verify_l2_handoff(
                        device_ip, have_l2, want_l2
                    ).check_return_status()

                self.log(
                    "Successfully validated the L2 Handoffs for in the device '{ip}'.".format(
                        ip=device_ip
                    ),
                    "INFO",
                )

                if item.get("layer3_settings"):
                    have_device_details = have_details.get("device_details")
                    want_device_details = want_details.get("device_details")
                    self.verify_layer3_settings(
                        device_ip, have_device_details, want_device_details
                    ).check_return_status()

                self.log(
                    "Successfully validated the border settings for in the device '{ip}'.".format(
                        ip=device_ip
                    ),
                    "INFO",
                )
                self.response[0].get("msg").get(fabric_name).get(device_ip).update(
                    {"Validation": "Success"}
                )

        self.result.update({"response": self.response})
        self.msg = "Successfully validated the SDA fabric devices(s)."
        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is deleted (delete).

        Parameters:
            config (dict): Playbook details containing fabric devices configuration.
        Returns:
            self (object): The current object with updated desired Fabric Devices information.
        Description:
            Call the get_have function to collected the updated information from the Cisco Catalyst Center.
            Check if the config provided by the user is present in the Cisco Catalyst Center or not
            If the config is available in the Cisco Catalyst Center then the config is not applied to
            the Cisco Catalyst Center.
        """

        self.get_have(config)
        self.log(
            "Current State (have): {current_state}".format(current_state=self.have),
            "INFO",
        )
        fabric_devices = config.get("fabric_devices")
        if fabric_devices is not None:
            fabric_name = fabric_devices.get("fabric_name")
            device_config = fabric_devices.get("device_config")
            fabric_device_index = -1
            for item in device_config:
                fabric_device_index += 1
                device_ip = item.get("device_ip")
                fabric_device_details = self.have.get("fabric_devices")[
                    fabric_device_index
                ]
                if item.get("layer3_handoff_ip_transit"):

                    # Verifying the absence of IP L3 Handoff
                    if fabric_device_details.get("ip_l3_handoff_details"):
                        self.msg = (
                            "The L3 Handoff for IP transit for the device '{ip}' is still present in "
                            "the Cisco Catalyst Center.".format(ip=device_ip)
                        )
                        self.status = "failed"
                        return self

                    self.log(
                        "Successfully validated absence of L3 Handoffs for IP Transit in the device '{ip}'.".format(
                            ip=device_ip
                        ),
                        "INFO",
                    )

                if item.get("layer3_handoff_sda_transit"):

                    # Verifying the absence of SDA L3 Handoff
                    if fabric_device_details.get("sda_l3_handoff_details"):
                        self.msg = (
                            "The L3 Handoff for SDA transit for the device '{ip}' is still present in "
                            "the Cisco Catalyst Center.".format(ip=device_ip)
                        )
                        self.status = "failed"
                        return self

                    self.log(
                        "Successfully validated absence of L3 Handoffs for SDA Transit in the device '{ip}'.".format(
                            ip=device_ip
                        ),
                        "INFO",
                    )

                if item.get("layer2_handoff"):

                    # Verifying the absence of L2 Handoff
                    if fabric_device_details.get("l2_handoff_details"):
                        self.msg = (
                            "The L2 Handoff for the device '{ip}' is still present in "
                            "the Cisco Catalyst Center.".format(ip=device_ip)
                        )
                        self.status = "failed"
                        return self

                    self.log(
                        "Successfully validated absence of L2 Handoffs in the device '{ip}'.".format(
                            ip=device_ip
                        ),
                        "INFO",
                    )

                if not (
                    item.get("layer3_handoff_ip_transit")
                    or item.get("layer3_handoff_sda_transit")
                    or item.get("layer2_handoff")
                ):

                    # Verifying the absence of the device
                    if item.get("device_details"):
                        self.msg = (
                            "The SDA device with the IP '{ip}' is still present in "
                            "the Cisco Catalyst Center.".format(ip=device_ip)
                        )
                        self.status = "failed"
                        return self

                    self.log(
                        "Successfully validated absence of SDA device with the IP '{ip}'.".format(
                            ip=device_ip
                        ),
                        "INFO",
                    )

                self.response[0].get("msg").get(fabric_name).get(device_ip).update(
                    {"Validation": "Success"}
                )

        self.result.update({"response": self.response})
        self.msg = "Successfully validated the absence of SDA fabric device(s)."
        self.status = "success"
        return self

    def reset_values(self):
        """
        Reset all necessary attributes to default values

        Parameters:
            self (object): The current object details.
        Returns:
            None
        """
        self.fabric_type = None
        self.have.clear()
        self.want.clear()
        return


def main():
    """main entry point for module execution"""

    # Define the specification for module arguments
    element_spec = {
        "dnac_host": {"type": "str", "required": True},
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
        "config": {"type": "list", "required": True, "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
        "validate_response_schema": {"type": "bool", "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_sda_devices = FabricDevices(module)
    if (
        ccc_sda_devices.compare_dnac_versions(
            ccc_sda_devices.get_ccc_version(), "2.3.7.6"
        )
        < 0
    ):
        ccc_sda_devices.msg = (
            "The specified version '{0}' does not support the SDA fabric devices feature. Supported versions start from '2.3.7.6' onwards. "
            "Version '2.3.7.6' introduces APIs for adding, updating and deleting the devices from the fabric site "
            "along with that manages the L2 handoffs, L3 Handoff with SDA Transit and L3 Handoffs with IP Transit.".format(
                ccc_sda_devices.get_ccc_version()
            )
        )
        ccc_sda_devices.status = "failed"
        ccc_sda_devices.check_return_status()

    state = ccc_sda_devices.params.get("state")
    config_verify = ccc_sda_devices.params.get("config_verify")
    if state not in ccc_sda_devices.supported_states:
        ccc_sda_devices.status = "invalid"
        ccc_sda_devices.msg = "State '{state}' is invalid".format(state=state)
        ccc_sda_devices.check_return_status()

    ccc_sda_devices.validate_input().check_return_status()

    for config in ccc_sda_devices.config:
        ccc_sda_devices.reset_values()
        ccc_sda_devices.get_have(config).check_return_status()
        if state != "deleted":
            ccc_sda_devices.get_want(config).check_return_status()
        ccc_sda_devices.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_sda_devices.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_sda_devices.result)


if __name__ == "__main__":
    main()
