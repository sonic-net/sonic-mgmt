# !/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ("Priyadharshini B", "Madhan Sankaranarayanan")

DOCUMENTATION = r"""
---
module: fabric_devices_info_workflow_manager
short_description: >
  Comprehensive fabric device information gathering module for Cisco Catalyst Center with advanced filtering and output capabilities.

description:
  - Retrieves comprehensive fabric device information from Cisco Catalyst Center using flexible, user-defined filtering criteria.
  - Supports device identification through fabric site hierarchy and optional fabric device role filtering for targeted information retrieval.
  - Enables selective information retrieval across six categories are fabric configuration details, Layer 2/3 handoff configurations, device onboarding status,
    connected neighbor devices, health metrics, and active issues.
  - Implements robust data collection with configurable retry mechanisms, timeout handling, and polling intervals for reliable operation in enterprise
    environments.
  - Provides flexible file output capabilities using the C(output_file_info) parameter with support for JSON and YAML formats, configurable
    file modes (overwrite or append), and optional timestamp inclusion.
  - When C(output_file_info) is specified, results are written to the designated file. otherwise, results are returned
    in the standard Ansible module output.
  - Returns structured data for each requested information category, or an empty result set when no devices match
    the specified filter criteria after exhausting all retry attempts.
  - Operates as a read-only facts/info module ensuring safe execution in check mode without modifying device configurations.

version_added: "6.32.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params

author:
  - Priyadharshini B (@pbalaku2)
  - Madhan Sankaranarayanan (@madhansansel)

options:
  config_verify:
    description: Set to true to verify the Cisco Catalyst Center after applying the playbook config.
    type: bool
    default: false
  state:
    description: The desired state of the configuration after module execution.
    type: str
    choices: ["gathered"]
    default: gathered
  config:
    description: List of dictionaries specifying fabric device query parameters.
    type: list
    elements: dict
    required: true
    suboptions:
      fabric_devices:
        description:
          - Defines fabric device filtering criteria to retrieve information from Software-Defined Access (SDA) fabric sites.
          - Each device entry must include the fabric_site_hierarchy parameter to identify the fabric site.
          - Optional device_identifier parameter provides additional filtering capabilities within the fabric site.
        type: list
        elements: dict
        suboptions:
          fabric_site_hierarchy:
            description:
              - Hierarchical path of the fabric site to query for fabric device information.
              - Must be an existing site configured as a Software-Defined Access (SDA) fabric site in Cisco Catalyst Center.
              - Site path must follow the full hierarchical structure (e.g., "Global/Region/Building/Floor").
              - All fabric devices within this site hierarchy will be included unless further filtered by other parameters.
              - Site hierarchy paths must match exactly as configured in Cisco Catalyst Center's site management structure.
            type: str
            required: true
          fabric_device_role:
            description:
              - Optional filter to restrict fabric device information retrieval to specific fabric roles.
              - When specified, only fabric devices with the matching role will have their information retrieved.
              - If omitted, all fabric devices within the specified fabric site hierarchy are included.
              - Role-based filtering improves performance for large fabric deployments by reducing the scope of devices processed.
            type: str
            required: false
            choices:
              - CONTROL_PLANE_NODE    # SDA control plane devices managing fabric overlay
              - BORDER_NODE          # Fabric border devices connecting to external networks
              - EDGE_NODE           # Fabric edge devices connecting endpoints
              - EXTENDED_NODE       # Fabric extended nodes for specific deployment scenarios
              - WIRELESS_CONTROLLER_NODE  # Wireless controllers in fabric deployments
          device_identifier:
            description:
              - Optional list of device identification criteria to further filter fabric devices within the specified fabric site.
              - Provides granular control over which fabric devices have their information retrieved.
              - If omitted, all fabric devices within the fabric site hierarchy (and optional role filter) are processed.
              - Multiple identification methods can be combined for comprehensive device targeting.
              - Only devices that are both fabric-enabled and match the identifier criteria will be processed.
              - For IP-based identification, specify either ip_address (for individual IPs) OR ip_address_range (for IP ranges),
                not both in the same device_identifier entry.
              - When multiple identification parameters (ip_address, hostname, serial_number) are specified in the same entry,
                they must all refer to the same physical device for proper validation.
              - Use separate device_identifier entries when targeting different devices with different identification methods.
            type: list
            elements: dict
            suboptions:
              ip_address:
                description:
                  - List of management IP addresses to identify specific fabric devices within specified fabric site.
                  - Each IP address must correspond to a managed device in the Cisco Catalyst Center inventory.
                  - Only devices with matching IP addresses that are also fabric-enabled will have their information retrieved.
                  - IP addresses must be valid IPv4 addresses in dotted decimal notation.
                  - Cannot be used together with ip_address_range parameter - choose one identification method per device_identifier entry.
                  - Mutually exclusive with ip_address_range - specify either ip_address OR ip_address_range, not both.
                type: list
                elements: str
                required: false
              ip_address_range:
                description:
                  - IP address range specification for bulk device identification within specified fabric sites.
                  - Format "start_ip-end_ip" (e.g., "192.168.1.1-192.168.1.50") for contiguous IP ranges.
                  - Range is automatically expanded into individual IP addresses for processing.
                  - Only fabric-enabled devices within the specified range will have their information retrieved.
                  - Useful for targeting entire subnets or network segments within fabric deployments.
                  - Cannot be used together with ip_address parameter - choose one identification method per device_identifier entry.
                  - Mutually exclusive with ip_address - specify either ip_address_range OR ip_address, not both.
                type: str
                required: false
              serial_number:
                description:
                  - List of device serial numbers to identify specific fabric devices.
                  - Each serial number must match exactly as recorded in Cisco Catalyst Center device inventory.
                  - Only devices with matching serial numbers that are also fabric-enabled will have their information retrieved.
                  - Serial numbers are case-sensitive and must match the format used by the device manufacturer.
                type: list
                elements: str
                required: false
              hostname:
                description:
                  - List of device hostnames to identify specific fabric devices.
                  - Each hostname must match exactly as configured in Cisco Catalyst Center device inventory.
                  - Only devices with matching hostnames that are also fabric-enabled will have their information retrieved.
                  - Hostnames are case-sensitive and must match the exact device hostname configuration.
                type: list
                elements: str
                required: false
          timeout:
            description:
              - Maximum time in seconds to wait for device information retrieval operations to complete.
              - Applied to each individual device lookup operation during the filtering process.
              - If device information retrieval fails within this timeout period, the operation will retry based on the 'retries' parameter.
              - Longer timeouts may be needed for environments with slower network connectivity or larger device inventories.
              - If timeout is greater than (retries * interval), the operation will continue retrying until the timeout period ends.
              - Total operation time is bounded by the timeout value regardless of retry configuration.
            type: int
            default: 120
          retries:
            description:
              - Number of retry attempts for device information retrieval operations when initial attempts fail.
              - Applied to each individual device lookup and fabric device filtering operation.
              - Higher retry counts improve reliability in environments with intermittent connectivity or high API load.
              - Total operation time is affected by retries combined with timeout and interval settings.
              - Actual retry attempts may be less than specified if timeout period is reached first.
            type: int
            default: 3
          interval:
            description:
              - Time in seconds to wait between retry attempts for device information retrieval operations.
              - Applied as a delay between failed attempts during device lookup and fabric filtering processes.
              - Combined with timeout and retries to determine total operation duration.
              - If (retries * interval) exceeds timeout, retries will continue until timeout is reached.
              - Longer intervals help reduce API load on Cisco Catalyst Center during retry operations.
              - Should be balanced with timeout settings to avoid excessively long operation times.
            type: int
            default: 10
          requested_info:
            description:
              - List of fabric device information types to retrieve for each identified fabric device.
              - If omitted or empty, all available information categories will be retrieved by default.
              - Selective information retrieval improves performance and reduces API load for large fabric deployments.
              - Each information type corresponds to specific Cisco Catalyst Center APIs and data sources.
            type: list
            elements: str
            choices:
              - fabric_info             # Fabric configuration details, device roles, and fabric site associations
              - handoff_info            # Layer 2/3 handoff configurations for border and control plane nodes
              - onboarding_info         # Device provisioning status, port assignments, port channels and SSID details for wireless devices
              - connected_devices_info  # Neighbor device information via CDP/LLDP discovery protocols
              - device_health_info      # Health metrics including CPU, memory, temperature, and performance data
              - device_issues_info      # Active alerts, issues, and problems detected on fabric devices
          output_file_info:
            description:
              - Controls file output generation for fabric device information retrieval results.
              - When provided, saves retrieved device information to the specified file
                along with returning the data in standard Ansible module output.
              - Supports flexible file formatting, writing modes, and optional timestamp inclusion for audit purposes.
              - Enables automated reporting and data archival workflows for fabric device monitoring operations.
            type: dict
            suboptions:
              file_path:
                description:
                  - Absolute path to the output file without file extension.
                  - File extension is automatically appended based on the selected file format (.json or .yaml).
                  - Directory structure will be created automatically if it does not exist.
                  - Path must be writable by the user executing the Ansible playbook.
                type: str
                required: true
              file_format:
                description:
                  - Output data format for the generated file.
                  - Determines file structure and extension applied to the file path.
                  - YAML format provides better human readability while JSON offers programmatic parsing advantages.
                  - Format selection affects file extension and data serialization method.
                type: str
                default: yaml
                choices:
                  - json
                  - yaml
              file_mode:
                description:
                  - File writing mode determining how data is written to the target file.
                  - Use 'w' to overwrite existing file content or 'a' to append new data to existing content.
                  - Append mode enables incremental data collection across multiple playbook runs.
                  - Overwrite mode ensures clean data sets for each execution.
                type: str
                default: w
                choices:
                  - w
                  - a
              timestamp:
                description:
                  - Controls inclusion of data retrieval timestamp in the output file content.
                  - When enabled, adds the data collection timestamp as the first entry for audit trail purposes.
                  - Useful for tracking when fabric device information was collected in automated workflows.
                  - Timestamp format follows "YYYY-MM-DD HH:MM:SS" standard format.
                type: bool
                default: false

requirements:
- dnacentersdk >= 2.9.3
- python >= 3.9.19

notes:
- This is a facts/info module that only retrieves information and does not modify any device configurations or network state.
- Writing to a local file is for reporting, archival, and audit purposes only and does not affect the state of any managed devices.
- Module is safe to use in check mode as it performs read-only operations against Cisco Catalyst Center APIs.
- Fabric device filtering automatically identifies SDA fabric-enabled devices from the specified fabric site hierarchy.
- The fabric_site_hierarchy parameter is required and must reference an existing SDA fabric site in Cisco Catalyst Center.
- Device identification through device_identifier parameters provides granular control over which fabric devices are processed.
- Information retrieval is optimized based on device capabilities -
  SSID details are only retrieved for wireless controllers, handoff information is role-specific.
- Retry mechanisms with configurable timeout, retry count, and polling intervals ensure reliable data collection in enterprise-scale deployments.
- Requires Cisco Catalyst Center version 2.3.7.9 or later for fabric device information retrieval functionality.
- File output supports both JSON and YAML formats with flexible writing modes (overwrite/append) and optional timestamp inclusion for audit trails.
- Module handles mixed wired and wireless fabric environments automatically, applying appropriate API calls based on device type detection.

- SDK Methods used are
  - devices.Devices.get_device_list
  - sda.Sda.get_fabric_devices
  - sda.Sda.get_fabric_sites
  - sda.Sda.get_fabric_devices_layer3_handoffs_with_sda_transit
  - sda.Sda.get_fabric_devices_layer3_handoffs_with_ip_transit
  - sda.Sda.get_fabric_devices_layer2_handoffs
  - devices.Devices.get_interface_info_by_id
  - devices.Devices.get_connected_device_detail
  - devices.Devices.devices
  - issues.Issues.issues
  - sda.Sda.get_provisioned_wired_device
  - sda.Sda.get_port_assignments
  - wireless.Wireless.get_ssid_details_for_specific_wireless_controller

- Paths used are
  - GET/dna/intent/api/v1/network-device
  - GET/dna/intent/api/v1/sda/fabricDevices
  - GET/dna/intent/api/v1/sda/fabricSites
  - GET/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits
  - GET/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits
  - GET/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs
  - GET/dna/intent/api/v1/interface/network-device/{deviceId}
  - GET/dna/intent/api/v1/network-device/{deviceUuid}/interface/{interfaceUuid}/neighbor
  - GET/dna/intent/api/v1/device-health
  - GET/dna/intent/api/v1/issues
  - GET/dna/intent/api/v1/business/sda/provision-device
  - GET/dna/intent/api/v1/sda/portAssignments
  - GET/dna/intent/api/v1/wireless/controller/{networkDeviceId}/ssidDetails
"""

EXAMPLES = r"""

# Case 1: Retrieves all information for devices that are part of the fabric, from Cisco Catalyst Center.
- name: Get Fabric device information from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Gather detailed facts for specific fabric devices
      cisco.dnac.fabric_devices_info_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: gathered
        config:
          - fabric_devices:
              - fabric_site_hierarchy: "Global/rishipat_area/Fabric-area-1"  # Mandatory parameter
                fabric_device_role: "CONTROL_PLANE_NODE"
                device_identifier:
                  - ip_address: ["192.168.200.69"]
                  - serial_number: ["FJC272121AG"]
                  - hostname: ["SJ-BN-9300.cisco.local"]
                timeout: 30
                retries: 3
                interval: 10
                output_file_info:
                  file_path: /Users/priyadharshini/Downloads/fabric_device_info
                  file_format: yaml
                  file_mode: a
                  timestamp: true

# Case 2: Retrieves specific information for devices that are part of the fabric, from Cisco Catalyst Center.
- name: Get Fabric device information from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Gather detailed facts for specific fabric devices
      cisco.dnac.fabric_devices_info_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: gathered
        config:
          - fabric_devices:
              - fabric_site_hierarchy: "Global/rishipat_area/Fabric-area-1"  # Mandatory parameter
                fabric_device_role: "CONTROL_PLANE_NODE"
                device_identifier:
                  - ip_address: ["192.168.200.69"]
                  - serial_number: ["FJC272121AG"]
                  - hostname: ["SJ-BN-9300.cisco.local"]
                timeout: 30
                retries: 3
                interval: 10
                requested_info:
                  - fabric_info
                  - handoff_info
                  - onboarding_info
                  - connected_devices_info
                  - device_health_info
                  - device_issues_info
                output_file_info:
                  file_path: /Users/priyadharshini/Downloads/fabric_device_info
                  file_format: json
                  file_mode: w
                  timestamp: true

# Case 3: Retrieves all information for devices that are part of the fabric, from Cisco Catalyst Center.
- name: Get Fabric device information from Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Gather detailed facts for specific fabric devices
      cisco.dnac.fabric_devices_info_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_port: "{{ dnac_port }}"
        dnac_version: "{{ dnac_version }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_api_task_timeout: 1000
        dnac_task_poll_interval: 1
        state: gathered
        config:
          - fabric_devices:
              - fabric_site_hierarchy: "Global/rishipat_area/Fabric-area-1"  # Mandatory parameter
                fabric_device_role: "CONTROL_PLANE_NODE"
                device_identifier:
                  - ip_address: ["192.168.200.69"]
                  - serial_number: ["FJC272121AG"]
                  - hostname: ["SJ-BN-9300.cisco.local"]
                timeout: 30
                retries: 3
                interval: 10
                requested_info:
                  - all
                output_file_info:
                  file_path: /Users/priyadharshini/Downloads/fabric_device_info
                  file_format: yaml
                  file_mode: a
                  timestamp: true
"""

RETURN = r"""

# Case 1: Successfully retrieved fabric information for devices that are part of the fabric, from Cisco Catalyst Center
response_fabric_info:
  description:
    - Fabric information for filtered fabric devices
    - Returned for each fabric device matching the filters.
  returned: always
  type: list

  sample:
    {
      "response": [
        "The fabric devices filtered from the network devices are: ['204.1.2.2']",
        {
          "fabric_info": [
            {
              "device_ip": "204.1.2.2",
              "fabric_details": [
                {
                  "borderDeviceSettings": {
                    "borderTypes": [
                      "LAYER_3"
                    ],
                    "layer3Settings": {
                      "borderPriority": 10,
                      "importExternalRoutes": false,
                      "isDefaultExit": true,
                      "localAutonomousSystemNumber": "5",
                      "prependAutonomousSystemCount": 0
                    }
                  },
                  "deviceRoles": [
                    "BORDER_NODE",
                    "CONTROL_PLANE_NODE",
                    "EDGE_NODE"
                  ],
                  "fabricId": "c9fda934-a212-4a1b-be5f-f391d2ff8863",
                  "id": "9294625f-52d4-485f-9d36-5abcfa4f863f",
                  "networkDeviceId": "e5cc9398-afbf-40a2-a8b1-e9cf0635c28a"
                }
              ]
            }
          ]
        }
      ],
      "status": "success"
    }

# Case 2: Successfully retrieved handoff info for devices that are part of the fabric, from Cisco Catalyst Center
response_fabric_devices_layer3_handoffs_sda_info:
    description:
      - Handoff information for filtered fabric devices.
      - Returned for each fabric device matching the filters.
    returned: always
    type: list

    "sample": {
      "response": [
        "The fabric devices filtered from the network devices are: ['91.1.1.2']",
        [
          {
            "fabric_devices_layer3_handoffs_sda_info": [
              {
                "device_ip": "91.1.1.2",
                "handoff_layer3_sda_transit_info": [
                  {
                    "connectedToInternet": true,
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "isMulticastOverTransitEnabled": false,
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "transitNetworkId": "02f92f56-e9c8-4534-b7f1-e06635061de9"
                  }
                ]
              }
            ]
          }
        ],
        [
          {
            "fabric_devices_layer3_handoffs_ip_info": [
              {
                "device_ip": "91.1.1.2",
                "handoff_layer3_ip_transit_info": [
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "f10250af-bd72-4175-ad9b-ea2831e74a15",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.69/30",
                    "localIpv6Address": "2004:1:16::1:0:45/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.70/30",
                    "remoteIpv6Address": "2004:1:16::1:0:46/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "DEFAULT_VN",
                    "vlanId": 3000
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "3cd81271-4621-40fd-aac7-8b8499127c0c",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.73/30",
                    "localIpv6Address": "2004:1:16::1:0:49/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.74/30",
                    "remoteIpv6Address": "2004:1:16::1:0:4a/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "Fabric_VN",
                    "vlanId": 3001
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "cdad28e7-8df2-432d-8550-666a9fcfc21c",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.77/30",
                    "localIpv6Address": "2004:1:16::1:0:4d/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.78/30",
                    "remoteIpv6Address": "2004:1:16::1:0:4e/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "INFRA_VN",
                    "vlanId": 3002
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "8711bdb5-7a92-4ab0-a7d7-b4053e1db84c",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.81/30",
                    "localIpv6Address": "2004:1:16::1:0:51/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.82/30",
                    "remoteIpv6Address": "2004:1:16::1:0:52/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "IntraSubnet_VN",
                    "vlanId": 3003
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "66b48881-e72f-44cc-aedb-6819af25bd27",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.85/30",
                    "localIpv6Address": "2004:1:16::1:0:55/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.86/30",
                    "remoteIpv6Address": "2004:1:16::1:0:56/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "SGT_Port_test",
                    "vlanId": 3004
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "6dd7d005-74aa-4762-a59e-1c280a975425",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.89/30",
                    "localIpv6Address": "2004:1:16::1:0:59/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.90/30",
                    "remoteIpv6Address": "2004:1:16::1:0:5a/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "VN1",
                    "vlanId": 3005
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "a13167ae-d900-4048-92a6-0d41bd1bd531",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.93/30",
                    "localIpv6Address": "2004:1:16::1:0:5d/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.94/30",
                    "remoteIpv6Address": "2004:1:16::1:0:5e/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "VN2",
                    "vlanId": 3006
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "932cd9d7-9067-4224-ab1d-922a7cd79b5b",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.97/30",
                    "localIpv6Address": "2004:1:16::1:0:61/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.98/30",
                    "remoteIpv6Address": "2004:1:16::1:0:62/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "VN3",
                    "vlanId": 3007
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "9c09c4a8-5a7f-4b06-ac28-4d895293cfe7",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.101/30",
                    "localIpv6Address": "2004:1:16::1:0:65/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.102/30",
                    "remoteIpv6Address": "2004:1:16::1:0:66/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "VN4",
                    "vlanId": 3008
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "df69abf3-266a-4678-84d2-ca8d9340b4c2",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.105/30",
                    "localIpv6Address": "2004:1:16::1:0:69/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.106/30",
                    "remoteIpv6Address": "2004:1:16::1:0:6a/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "VN5",
                    "vlanId": 3009
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "d95e8a82-7a71-4f4a-a31a-85385c1e1ef8",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.109/30",
                    "localIpv6Address": "2004:1:16::1:0:6d/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.110/30",
                    "remoteIpv6Address": "2004:1:16::1:0:6e/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "VN6",
                    "vlanId": 3010
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "27171568-3f08-4f13-8991-a8904bc7e2a6",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.113/30",
                    "localIpv6Address": "2004:1:16::1:0:71/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.114/30",
                    "remoteIpv6Address": "2004:1:16::1:0:72/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "VN7",
                    "vlanId": 3011
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "bb704a7d-8988-4d8c-80e5-4c02bb9ab042",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.117/30",
                    "localIpv6Address": "2004:1:16::1:0:75/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.118/30",
                    "remoteIpv6Address": "2004:1:16::1:0:76/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "WiredVNFB1",
                    "vlanId": 3012
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "8d814e72-25af-490d-8f69-dec10af9e790",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.121/30",
                    "localIpv6Address": "2004:1:16::1:0:79/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.122/30",
                    "remoteIpv6Address": "2004:1:16::1:0:7a/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "WiredVNFBLayer2",
                    "vlanId": 3013
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "b01aa3a2-61c8-4179-a568-6dcdbafe993f",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.125/30",
                    "localIpv6Address": "2004:1:16::1:0:7d/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.126/30",
                    "remoteIpv6Address": "2004:1:16::1:0:7e/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "WiredVNStatic",
                    "vlanId": 3014
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "a4f61e60-b75c-4bcd-b7c4-e3bd68ec324d",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.129/30",
                    "localIpv6Address": "2004:1:16::1:0:81/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.130/30",
                    "remoteIpv6Address": "2004:1:16::1:0:82/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "WirelessVNFB",
                    "vlanId": 3015
                  },
                  {
                    "externalConnectivityIpPoolName": "BorderHandOff_sub",
                    "fabricId": "6ea62e10-cc4b-4f67-8251-d0939fdd4ad8",
                    "id": "43761af5-509f-4d07-9d2c-8b09f6ba2114",
                    "interfaceName": "TenGigabitEthernet1/0/2",
                    "localIpAddress": "204.1.16.133/30",
                    "localIpv6Address": "2004:1:16::1:0:85/126",
                    "networkDeviceId": "36680b59-39b2-446b-8ceb-5a1e157b5799",
                    "remoteIpAddress": "204.1.16.134/30",
                    "remoteIpv6Address": "2004:1:16::1:0:86/126",
                    "tcpMssAdjustment": 0,
                    "transitNetworkId": "bbf16d41-031b-4061-b9b6-ae75768ae196",
                    "virtualNetworkName": "WirelessVNFGuest",
                    "vlanId": 3016
                  }
                ]
              }
            ]
          }
        ],
        [
          {
            "fabric_devices_layer2_handoffs_info": [
              {
                "device_ip": "91.1.1.2",
                "handoff_layer2_info": []
              }
            ]
          }
        ]
      ],
      "status": "success"
      }

# Case 3: Successfully retrieved issues for devices that are part of the fabric, from Cisco Catalyst Center
response_device_issues_info:
  description:
    - Issue information for filtered fabric devices.
    - Returned for each fabric device matching the filters.
  returned: always
  type: list

  sample: {
    "response": [
      "The fabric devices filtered from the network devices are: ['204.1.2.2']",
      [
        {
          "device_issues_info": [
            {
              "device_ip": "204.1.2.2",
              "issue_details": [
                {
                  "aiDriven": "No",
                  "category": "Connected",
                  "clientMac": null,
                  "deviceId": "e5cc9398-afbf-40a2-a8b1-e9cf0635c28a",
                  "deviceRole": "",
                  "issueId": "4eec8a72-65ff-45ae-89be-f0437eae778e",
                  "issue_occurence_count": 1703,
                  "last_occurence_time": 1750856863468,
                  "name": "AAA Server '172.23.241.245' state on Edge device 'abhitest' is DEAD.",
                  "priority": "P1",
                  "siteId": "",
                  "status": "active"
                },
                {
                  "aiDriven": "No",
                  "category": "User Defined",
                  "clientMac": null,
                  "deviceId": "e5cc9398-afbf-40a2-a8b1-e9cf0635c28a",
                  "deviceRole": "",
                  "issueId": "80ba94eb-15d3-48c2-a3f4-20bf99551217",
                  "issue_occurence_count": 5,
                  "last_occurence_time": 1750789583288,
                  "name": "NON_AUTHORITATIVE_CLOCK",
                  "priority": "P2",
                  "siteId": "",
                  "status": "active"
                }
              ]
            }
          ]
        }
      ]
    ],
    "status": "success"
  }

# Case 4: Successfully retrieved health info for devices that are part of the fabric, from Cisco Catalyst Center
response_device_health_info:
  description:
    - Health information for filtered fabric devices.
    - Returned for each fabric device matching the filters.
  returned: always
  type: list

  sample: {
    "response": [
      "The fabric devices filtered from the network devices are: ['204.1.2.2']",
      [
        {
          "device_health_info": [
            {
              "device_ip": "204.1.2.2",
              "health_details": [
                {
                  "airQualityHealth": {},
                  "avgTemperature": 4350.0,
                  "band": {},
                  "clientCount": {},
                  "cpuHealth": 10,
                  "cpuUlitilization": 2.75,
                  "cpuUtilization": 2.75,
                  "deviceFamily": "SWITCHES_AND_HUBS",
                  "deviceType": "Cisco Catalyst 9300 Switch",
                  "freeMemoryBufferHealth": -1,
                  "freeTimerScore": -1,
                  "interDeviceLinkAvailFabric": 10,
                  "interDeviceLinkAvailHealth": 100,
                  "interfaceLinkErrHealth": 10,
                  "interferenceHealth": {},
                  "ipAddress": "204.1.2.2",
                  "issueCount": 2,
                  "location": "Global/USA/New York/NY_BLD1",
                  "macAddress": "90:88:55:07:59:00",
                  "maxTemperature": 5700.0,
                  "memoryUtilization": 50,
                  "memoryUtilizationHealth": 10.0,
                  "model": "Cisco Catalyst 9300 Switch",
                  "name": "abhitest",
                  "noiseHealth": {},
                  "osVersion": "17.12.4",
                  "overallHealth": 1,
                  "packetPoolHealth": -1,
                  "reachabilityHealth": "REACHABLE",
                  "utilizationHealth": {},
                  "uuid": "e5cc9398-afbf-40a2-a8b1-e9cf0635c28a",
                  "wanLinkUtilization": -1.0,
                  "wqePoolsHealth": -1
                }
              ]
            }
          ]
        }
      ]
    ],
    "status": "success"
  }

# Case 5: Successfully retrieved connected device info for devices that are part of the fabric, from Cisco Catalyst Center
response_connected_device_info:
  description:
    - Connected device information for filtered fabric devices.
    - Returned for each fabric device matching the filters.
  returned: always
  type: list

  sample: {
    "response": [
      "The fabric devices filtered from the network devices are: ['204.1.2.2']",
      [
        {
          "connected_device_info": [
            {
              "connected_device_details": [
                {
                  "capabilities": [
                    "ROUTER",
                    "TB_BRIDGE"
                  ],
                  "neighborDevice": "AP345D.A80E.20B4",
                  "neighborPort": "GigabitEthernet0"
                },
                {
                  "capabilities": [
                    "IGMP_CONDITIONAL_FILTERING",
                    "ROUTER",
                    "SWITCH"
                  ],
                  "neighborDevice": "NY-BN-9300",
                  "neighborPort": "TenGigabitEthernet1/1/2"
                },
                {
                  "capabilities": [
                    "ROUTER",
                    "TB_BRIDGE"
                  ],
                  "neighborDevice": "AP6849.9275.0FD0",
                  "neighborPort": "GigabitEthernet0"
                },
                {
                  "capabilities": [
                    "ROUTER",
                    "TB_BRIDGE"
                  ],
                  "neighborDevice": "AP6CD6.E369.49B4",
                  "neighborPort": "GigabitEthernet0"
                },
                {
                  "capabilities": [
                    "ROUTER",
                    "TB_BRIDGE"
                  ],
                  "neighborDevice": "AP34B8.8315.7C6C",
                  "neighborPort": "GigabitEthernet0"
                },
                {
                  "capabilities": [
                    "HOST"
                  ],
                  "neighborDevice": "IAC-TSIM",
                  "neighborPort": "TenGigabitEthernet0/0/2"
                },
                {
                  "capabilities": [
                    "IGMP_CONDITIONAL_FILTERING",
                    "ROUTER",
                    "SWITCH"
                  ],
                  "neighborDevice": "NY-BN-9300",
                  "neighborPort": "TenGigabitEthernet2/1/2"
                }
              ],
              "device_ip": "204.1.2.2"
            }
          ]
        }
      ]
    ],
    "status": "success"
    }

# Case 6: Successfully retrieved onboarding info for devices that are part of the fabric, from Cisco Catalyst Center
response_onboarding_info:
  description:
    - Onboarding information for filtered fabric devices.
    - Returned for each fabric device matching the filters.
  returned: always
  type: list
  sample: {
    "response": [
      "The fabric devices filtered from the network devices are: ['204.192.5.2']",
      [
        {
          "device_onboarding_info": [
            {
              "device_ip": "204.192.5.2",
              "port_details": []
            }
          ]
        }
      ],
      [
        {
          "ssid_info": [
            {
              "device_ip": "204.192.5.2",
              "ssid_details": [
                {
                  "adminStatus": true,
                  "l2Security": "open",
                  "l3Security": "web_auth",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "ARUBA_SSIDtb17",
                  "wlanId": 28,
                  "wlanProfileName": "ARUBA_SSID_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "wpa2_enterprise",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz + 6GHz",
                  "ssidName": "CiscoSensorProvisioning",
                  "wlanId": 1,
                  "wlanProfileName": "CiscoSensorProvisioning"
                },
                {
                  "adminStatus": true,
                  "l2Security": "open",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "GUEST2tb17",
                  "wlanId": 26,
                  "wlanProfileName": "GUEST2_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "open",
                  "l3Security": "web_auth",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "Guest_passthrough_inttb17",
                  "wlanId": 18,
                  "wlanProfileName": "Guest_passthrough_int_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "open",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz",
                  "ssidName": "GUESTtb17",
                  "wlanId": 20,
                  "wlanProfileName": "GUEST_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "wpa2_enterprise",
                  "l3Security": "web_auth",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "Guest_webauthinternaltb17",
                  "wlanId": 22,
                  "wlanProfileName": "Guest_webauthinternal_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "open",
                  "l3Security": "web_auth",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "Guest_webpassthroughtb17",
                  "wlanId": 19,
                  "wlanProfileName": "Guest_webpassthrough_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "open",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "OPENtb17",
                  "wlanId": 23,
                  "wlanProfileName": "OPEN_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "wpa2_enterprise",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "posturetb17",
                  "wlanId": 21,
                  "wlanProfileName": "posture_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "wpa2_enterprise",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "Radius_ssidtb17",
                  "wlanId": 17,
                  "wlanProfileName": "Radius_ssid_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "wpa2_enterprise",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "Random_mactb17",
                  "wlanId": 29,
                  "wlanProfileName": "Random_mac_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "wpa2_personal",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "Single5KBandtb17",
                  "wlanId": 27,
                  "wlanProfileName": "Single5KBand_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "wpa2_enterprise",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "SSIDDot1XIndiatb17",
                  "wlanId": 30,
                  "wlanProfileName": "SSIDDot1XIndia_profile"
                },
                {
                  "adminStatus": true,
                  "l2Security": "wpa2_enterprise",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "SSIDDUAL BANDtb17",
                  "wlanId": 25,
                  "wlanProfileName": "SSIDDUAL BAND_profile"
                },
                {
                  "adminStatus": false,
                  "l2Security": "wpa2_enterprise",
                  "l3Security": "open",
                  "managed": true,
                  "radioPolicy": "2.4GHz + 5GHz",
                  "ssidName": "SSIDSchedulertb17",
                  "wlanId": 24,
                  "wlanProfileName": "SSIDScheduler_profile"
                }
              ]
            }
          ]
        }
      ],
      [
        {
          "provision_status_info": [
            {
              "device_ip": "204.192.5.2",
              "provision_status": {
                "description": "Wired Provisioned device detail retrieved successfully.",
                "deviceManagementIpAddress": "204.192.5.2",
                "siteNameHierarchy": "Global/USA/SAN JOSE/BLD23",
                "status": "success"
              }
            }
          ]
        }
      ]
    ],
    "status": "success"
    }

# Case 7: Successfully retrieved all info for devices that are part of the fabric, from Cisco Catalyst Center
response_all_info:
  description:
    - All fabric related information for filtered fabric devices.
    - Returned for each fabric device matching the filters.
  returned: always
  type: list
  sample: {
    "response": [
      "The fabric devices filtered from the network devices are: ['204.1.2.2', '204.192.6.200']",
      [
        {
          "fabric_info": [
            {
              "device_ip": "204.1.2.2",
              "fabric_details": [
                {
                  "borderDeviceSettings": {
                    "borderTypes": ["LAYER_3"],
                    "layer3Settings": {
                      "borderPriority": 10,
                      "importExternalRoutes": false,
                      "isDefaultExit": true,
                      "localAutonomousSystemNumber": "5",
                      "prependAutonomousSystemCount": 0
                    }
                  },
                  "deviceRoles": [
                    "BORDER_NODE",
                    "CONTROL_PLANE_NODE",
                    "EDGE_NODE"
                  ],
                  "fabricId": "c9fda934-a212-4a1b-be5f-f391d2ff8863",
                  "id": "9294625f-52d4-485f-9d36-5abcfa4f863f",
                  "networkDeviceId": "e5cc9398-afbf-40a2-a8b1-e9cf0635c28a"
                }
              ]
            }
          ]
        }
      ],
      [
        {
          "device_issues_info": [
            {
              "device_ip": "204.1.2.2",
              "issue_details": [
                {
                  "aiDriven": "No",
                  "category": "Connected",
                  "clientMac": null,
                  "deviceId": "e5cc9398-afbf-40a2-a8b1-e9cf0635c28a",
                  "deviceRole": "",
                  "issueId": "4eec8a72-65ff-45ae-89be-f0437eae778e",
                  "issue_occurence_count": 1703,
                  "last_occurence_time": 1750856863468,
                  "name": "AAA Server '172.23.241.245' state on Edge device 'abhitest' is DEAD.",
                  "priority": "P1",
                  "siteId": "",
                  "status": "active"
                },
                {
                  "aiDriven": "No",
                  "category": "User Defined",
                  "clientMac": null,
                  "deviceId": "e5cc9398-afbf-40a2-a8b1-e9cf0635c28a",
                  "deviceRole": "",
                  "issueId": "80ba94eb-15d3-48c2-a3f4-20bf99551217",
                  "issue_occurence_count": 5,
                  "last_occurence_time": 1750789583288,
                  "name": "NON_AUTHORITATIVE_CLOCK",
                  "priority": "P2",
                  "siteId": "",
                  "status": "active"
                }
              ]
            }
          ]
        }
      ],
      [
        {
          "device_health_info": [
            {
              "device_ip": "204.1.2.2",
              "health_details": [
                {
                  "airQualityHealth": {},
                  "avgTemperature": 4350.0,
                  "band": {},
                  "clientCount": {},
                  "cpuHealth": 10,
                  "cpuUlitilization": 2.75,
                  "cpuUtilization": 2.75,
                  "deviceFamily": "SWITCHES_AND_HUBS",
                  "deviceType": "Cisco Catalyst 9300 Switch",
                  "freeMemoryBufferHealth": -1,
                  "freeTimerScore": -1,
                  "interDeviceLinkAvailFabric": 10,
                  "interDeviceLinkAvailHealth": 100,
                  "interfaceLinkErrHealth": 10,
                  "interferenceHealth": {},
                  "ipAddress": "204.1.2.2",
                  "issueCount": 2,
                  "location": "Global/USA/New York/NY_BLD1",
                  "macAddress": "90:88:55:07:59:00",
                  "maxTemperature": 5700.0,
                  "memoryUtilization": 50,
                  "memoryUtilizationHealth": 10.0,
                  "model": "Cisco Catalyst 9300 Switch",
                  "name": "abhitest",
                  "noiseHealth": {},
                  "osVersion": "17.12.4",
                  "overallHealth": 1,
                  "packetPoolHealth": -1,
                  "reachabilityHealth": "REACHABLE",
                  "utilizationHealth": {},
                  "uuid": "e5cc9398-afbf-40a2-a8b1-e9cf0635c28a",
                  "wanLinkUtilization": -1.0,
                  "wqePoolsHealth": -1
                }
              ]
            }
          ]
        }
      ],
      [
        {
          "fabric_devices_layer3_handoffs_sda_info": [
            {
              "device_ip": "204.1.2.2",
              "handoff_info": []
            }
          ]
        }
      ],
      [
        {
          "fabric_devices_layer3_handoffs_ip_info": [
            {
              "device_ip": "204.1.2.2",
              "handoff_info": []
            }
          ]
        }
      ],
      [
        {
          "fabric_devices_layer2_handoffs_info": [
            {
              "device_ip": "204.1.2.2",
              "handoff_info": []
            }
          ]
        }
      ],
      [
        {
          "connected_device_info": [
            {
              "connected_device_details": [
                {
                  "capabilities": [
                    "IGMP_CONDITIONAL_FILTERING",
                    "ROUTER",
                    "SWITCH"
                  ],
                  "neighborDevice": "NY-BN-9300",
                  "neighborPort": "TenGigabitEthernet2/1/2"
                },
                {
                  "capabilities": [
                    "IGMP_CONDITIONAL_FILTERING",
                    "ROUTER",
                    "SWITCH"
                  ],
                  "neighborDevice": "NY-BN-9300",
                  "neighborPort": "TenGigabitEthernet1/1/2"
                },
                {
                  "capabilities": [
                    "ROUTER",
                    "TB_BRIDGE"
                  ],
                  "neighborDevice": "AP6849.9275.0FD0",
                  "neighborPort": "GigabitEthernet0"
                },
                {
                  "capabilities": [
                    "ROUTER",
                    "TB_BRIDGE"
                  ],
                  "neighborDevice": "AP6CD6.E369.49B4",
                  "neighborPort": "GigabitEthernet0"
                },
                {
                  "capabilities": [
                    "ROUTER",
                    "TB_BRIDGE"
                  ],
                  "neighborDevice": "AP34B8.8315.7C6C",
                  "neighborPort": "GigabitEthernet0"
                },
                {
                  "capabilities": ["HOST"],
                  "neighborDevice": "IAC-TSIM",
                  "neighborPort": "TenGigabitEthernet0/0/2"
                },
                {
                  "capabilities": [
                    "ROUTER",
                    "TB_BRIDGE"
                  ],
                  "neighborDevice": "AP345D.A80E.20B4",
                  "neighborPort": "GigabitEthernet0"
                }
              ],
              "device_ip": "204.1.2.2"
            }
          ]
        }
      ]
    ],
    "status": "success"
    }

# Case 8: If no fabric devices is found
response_info:
  description:
    - Returned when no fabric devices match the provided filters.
  returned: always
  type: list

  sample: {
    "response":[
      "No fabric devices found for the given filters."
    ]
  }
"""

from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
)
from ansible.module_utils.basic import AnsibleModule

try:
    import yaml
except ImportError:
    yaml = None
import time
import os
import json
import ipaddress
from datetime import datetime

from ansible_collections.cisco.dnac.plugins.module_utils.validation import (
    validate_list_of_dicts,)


class FabricDevicesInfo(DnacBase):
    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ['gathered']
        self.total_response = []

    def validate_input(self):
        """
        Validate the playbook configuration for fabric device structure and integrity.

        This method ensures that the provided 'config' attribute adheres to the expected format for fabric device
        processing. It validates the presence and types of required fields, checks for duplicates, and ensures
        consistency in user-provided values such as requested information categories.

        Args:
            self: The instance of the class that contains the 'config' attribute to be validated.

        Returns:
            The method returns the current instance with updated attributes:
            - self.msg: A descriptive message indicating the outcome of the validation process.
            - self.status: The result of the validation ('success' or 'failed').
            - self.validated_config: A cleaned and validated configuration if validation succeeds.

        Validations Performed:
            - 'config' must be a list of dictionaries.
            - Each dictionary must contain the key 'fabric_devices' mapped to a list.
            - Each 'fabric_device' must be a dictionary containing at least one of:
                'ip_address', 'hostname', 'serial_number', 'device_role', or 'site_hierarchy'.
            - All values in those fields (if present) must be lists of strings.
            - 'requested_info', if provided, must be a list of allowed strings.
            - Validates 'timeout', 'retries', and 'interval' as non-negative integers if specified.
            - Ensures 'output_file_path' is a string if provided.
            - Detects and prevents duplicate IP addresses, hostnames, or serial numbers across devices.
        """

        config_spec = {
            "fabric_devices": {
                "type": "list",
                "elements": "dict",
                "fabric_site_hierarchy": {
                    "type": "str",
                    "required": True
                },
                "fabric_device_role": {
                    "type": "str",
                    "required": False,
                    "allowed_values": [
                        "CONTROL_PLANE_NODE",
                        "BORDER_NODE",
                        "EDGE_NODE",
                        "EXTENDED_NODE",
                        "WIRELESS_CONTROLLER_NODE"
                    ]
                },
                "device_identifier": {
                    "type": "list",
                    "elements": "dict",
                    "ip_address": {
                        "type": "list",
                        "elements": "str",
                        "required": False
                    },
                    "ip_address_range": {
                        "type": "str",
                        "required": False
                    },
                    "serial_number": {
                        "type": "list",
                        "elements": "str",
                        "required": False
                    },
                    "hostname": {
                        "type": "list",
                        "elements": "str",
                        "required": False
                    }
                },
                "timeout": {
                    "type": "int",
                    "default": 120,
                },
                "retries": {
                    "type": "int",
                    "default": 3,
                },
                "interval": {
                    "type": "int",
                    "default": 10,
                },
                "requested_info": {
                    "type": "list",
                    "elements": "str",
                    "allowed_values": [
                        "fabric_info",
                        "handoff_info",
                        "onboarding_info",
                        "connected_devices_info",
                        "device_health_info",
                        "device_issues_info"
                    ]
                },
                "output_file_info": {
                    "type": "dict",
                    "file_path": {
                        "type": "str",
                    },
                    "file_format": {
                        "type": "str",
                        "default": "yaml",
                        "allowed_values": ["json", "yaml"]
                    },
                    "file_mode": {
                        "type": "str",
                        "default": "w",
                        "allowed_values": ["w", "a"]
                    },
                    "timestamp": {
                        "type": "bool",
                        "default": False
                    }
                }
            }
        }
        try:
            valid_config, invalid_params = validate_list_of_dicts(self.config, config_spec)

            if invalid_params:
                self.msg = "Fabric devices configuration validation failed with invalid parameters: {0}".format(
                    invalid_params
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            self.validated_config = valid_config

            self.log("Fabric devices configuration validation completed successfully", "INFO")
            self.log(self.config)
            self.log(
                "Validated {0} fabric device configuration section(s) for workflow processing".format(
                    (valid_config)
                ),
                "DEBUG"
            )
            return self

        except Exception as validation_exception:
            self.msg = "Fabric devices configuration validation encountered an error: {0}".format(
                str(validation_exception)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_want(self, config):
        """
        Extract the desired state ('want') from a fabric devices playbook block.

        Args:
            self (object): An instance of a class interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the playbook configuration, expected to include
                    a list of fabric devices under the 'fabric_devices' key.

        Returns:
            self: The current instance of the class with the 'want' attribute populated
                based on the validated fabric device data from the playbook.
        Description:
            This method processes the 'fabric_devices' section of the provided configuration and
            validates its structure and content. Specifically, it performs the following steps:

            - Checks that the 'fabric_devices' key exists and is not empty.
            - Validates that each device entry includes at least one of the following:
                'ip_address', 'hostname', 'serial_number', 'device_role', or 'site_hierarchy'.
            - If 'requested_info' is provided for a device, verifies that all values are among
            the allowed set:
                - all
                - fabric_info
                - handoff_info
                - onboarding_info
                - connected_devices_info
                - device_health_info
                - device_issues_info
            Upon successful validation, the fabric device data is stored in the instance's 'want'
            attribute for use in subsequent processing.
        """
        self.log("Extracting desired fabric devices information workflow state from playbook configuration", "DEBUG")
        self.log("Processing configuration sections for comprehensive workflow validation", "DEBUG")

        want = {}
        fabric_devices = config.get("fabric_devices")

        want["fabric_devices"] = config.get("fabric_devices")

        required_device_keys = [
            "fabric_site_hierarchy"
        ]
        allowed_return_values = {
            "all",
            "fabric_info",
            "handoff_info",
            "onboarding_info",
            "connected_devices_info",
            "device_health_info",
            "device_issues_info",
        }
        allowed_device_identifier_filters = {"ip_address", "hostname", "serial_number", "ip_address_range"}
        allowed_field = {
            "fabric_site_hierarchy", "fabric_device_role", "device_identifier",
            "timeout", "retries", "interval", "requested_info", "output_file_info"
        }
        allowed_fabric_device_roles = {"CONTROL_PLANE_NODE", "EDGE_NODE", "BORDER_NODE", "WIRELESS_CONTROLLER_NODE", "EXTENDED_NODE"}
        allowed_output_file_info_keys = {"file_path", "file_format", "file_mode", "timestamp"}
        allowed_file_formats = {"json", "yaml"}
        allowed_file_modes = {"a", "w"}

        for config in self.config:
            if "fabric_devices" not in config:
                self.msg = "'fabric_devices' key is missing in the config block"
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        for idx, device in enumerate(config["fabric_devices"]):
            self.log("Processing device entry {0}: {1}".format(idx + 1, device), "DEBUG")
            for key in device:
                if key not in allowed_field:
                    self.msg = "'{0}' is not a valid key in fabric device entry. Allowed keys are: {1}".format(
                        key, ", ".join(sorted(allowed_field))
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if not any(device.get(key) for key in required_device_keys):
                self.log("Device index {0} missing required identification keys: {1}".format(idx + 1, required_device_keys), "ERROR")
                self.msg = (
                    "Each fabric device must contain at least one of: {0}."
                    .format(", ".join(required_device_keys))
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if "fabric_device_role" in device:
                if device["fabric_device_role"] not in allowed_fabric_device_roles:
                    self.msg = (
                        "'fabric_device_role' must be one of: {0}"
                        .format(", ".join(sorted(allowed_fabric_device_roles)))
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            for numeric in ("timeout", "retries", "interval"):
                if numeric in device and device[numeric] < 0:
                    self.msg = "'{0}' must be a non-negative integer".format(numeric)
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            valid_keys_found = set()
            identifiers = device.get("device_identifier", [])
            if identifiers:
                all_identifier_keys = set()
                for identifier in identifiers:
                    self.log("Processing device_identifier: {0}".format(identifier), "DEBUG")
                    all_identifier_keys.update(identifier.keys())

                    for key in identifier:
                        self.log(key)
                        if key in allowed_device_identifier_filters:
                            valid_keys_found.add(key)
                            self.log(valid_keys_found)
                        else:
                            self.msg = (
                                "Invalid or unrecognized key '{0}' found in device_identifier. "
                                "Allowed keys are: {1}".format(
                                    key, ", ".join(sorted(allowed_device_identifier_filters))
                                )
                            )
                            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                if "ip_address" in all_identifier_keys and "ip_address_range" in all_identifier_keys:
                    self.msg = (
                        "Both 'ip_address' and 'ip_address_range' are specified across device_identifier entries. "
                        "Please specify only one of them."
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                if not valid_keys_found:
                    self.msg = (
                        "Each 'device_identifier' list must contain at least one valid key among: {0}."
                        .format(", ".join(allowed_device_identifier_filters))
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if "requested_info" in device and device["requested_info"] is not None:
                self.log("Applying requested_info for device index {0}".format(idx + 1), "DEBUG")
                return_value = device["requested_info"]
                for value_name in return_value:
                    if value_name not in allowed_return_values:
                        self.log(
                            "Invalid requested_info '{0}' in device index {1}."
                            "Valid options: {2}".format(value_name, idx, allowed_return_values), "ERROR"
                        )
                        self.msg = (
                            "'{0}' is not a valid return value. Allowed values are: {1}"
                            .format(value_name, sorted(allowed_return_values))
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if "output_file_info" in device:
                output_file_info = device["output_file_info"]
                if output_file_info is None:
                    continue

                file_format = output_file_info.get("file_format", "yaml")
                file_mode = output_file_info.get("file_mode", "w")
                timestamp = output_file_info.get("timestamp", False)

                output_file_info["file_format"] = file_format
                output_file_info["file_mode"] = file_mode
                output_file_info["timestamp"] = timestamp

                for key in output_file_info:
                    if key not in allowed_output_file_info_keys:
                        self.msg = "'{0}' is not a valid key in 'output_file_info'. Allowed keys are: {1}".format(
                            key, sorted(allowed_output_file_info_keys)
                        )
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                    if output_file_info["file_format"] not in allowed_file_formats:
                        self.msg = "'file_format' must be one of: {0}".format(", ".join(sorted(allowed_file_formats)))
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                    if output_file_info["file_mode"] not in allowed_file_modes:
                        self.msg = "'file_mode' must be one of: {0}".format(", ".join(sorted(allowed_file_modes)))
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        self.want = want
        self.log(want, "DEBUG")
        self.log("Fabric devices information workflow desired state extraction completed successfully", "DEBUG")

    def get_diff_gathered(self, config):
        """
        Processes the device configuration and retrieves requested information for each fabric device.

        Args:
            self (object): An instance of the class interacting with Cisco Catalyst Center APIs.
            config (dict): A dictionary containing the playbook configuration, including a list of
                        fabric devices and the specific types of information to be retrieved
                        (via the 'requested_info' key).

        Returns:
            self: The current instance with the 'msg' and 'total_response' attributes populated
                based on the API responses for the requested device information.

        Description:
            This method retrieves fabric-related information of fabric devices
            for a list of network devices provided in the playbook. For each device in the
            input, it performs the following:

            - Determines which categories of information are requested, including:
                - fabric_info
                - handoff_info (Layer 2, Layer 3 SDA, Layer 3 IP)
                - onboarding_info
                - connected_devices_info
                - device_health_info
                - device_issues_info
        """
        self.log("Starting device info retrieval for all device entries", "INFO")

        fabric_devices = config.get("fabric_devices", [])
        combined_fabric_data = {}

        for device_cfg in fabric_devices:
            self.log("Processing device configuration entry with parameters: {0}".format(list(device_cfg.keys())), "DEBUG")
            filtered_config = {}
            for field_name, field_value in device_cfg.items():
                if field_name != "requested_info":
                    filtered_config[field_name] = field_value

            self.log("Filtered config (excluding requested_info): {0}".format(filtered_config), "DEBUG")
            self.log("Extracted device identification parameters: {0}".format(list(filtered_config.keys())), "DEBUG")
            requested_info = device_cfg.get("requested_info", [])

            if not requested_info:
                all_info_requested = True
                self.log("No specific information types requested - retrieving all available information categories", "DEBUG")
            else:
                all_info_requested = "all" in requested_info
                self.log("Specific information types requested: {0}".format(requested_info), "DEBUG")

            fabric_info = all_info_requested or "fabric_info" in requested_info
            handoff_info = all_info_requested or "handoff_info" in requested_info
            onboarding_info = all_info_requested or "onboarding_info" in requested_info
            connected_devices_info = all_info_requested or "connected_devices_info" in requested_info
            device_health_info = all_info_requested or "device_health_info" in requested_info
            device_issues_info = all_info_requested or "device_issues_info" in requested_info

            self.log("""
            Requested:
            fabric_info:            {0}
            handoff_info:           {1}
            onboarding_info:        {2}
            connected_devices_info: {3}
            device_health_info:     {4}
            device_issues_info:     {5}
            """.format(
                fabric_info,
                handoff_info,
                onboarding_info,
                connected_devices_info,
                device_health_info,
                device_issues_info
            ), "DEBUG")
            fabric_site_hierarchy = device_cfg.get("fabric_site_hierarchy")
            fabric_exists, fabric_id = self.is_fabric_site(fabric_site_hierarchy)
            device_ids = self.get_device_id(filtered_config)
            filtered_fabric_devices = self.filter_fabric_devices(filtered_config)
            self.log("Filtered fabric devices after applying given filters: {0}".format(filtered_fabric_devices), "DEBUG")

            if not fabric_exists:
                self.msg = "The specified site hierarchy '{0}' is not a fabric site.".format(
                    device_cfg.get("fabric_site_hierarchy")
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            if not filtered_fabric_devices:
                self.msg = "No fabric devices found for the given filters."
                self.total_response.append(self.msg)
                break
            else:
                self.total_response.append("The fabric devices filtered from the network devices are: {0}".format(list(filtered_fabric_devices.keys())))

            if fabric_info:
                self.log("Retrieving fabric configuration details and device roles for {0} fabric devices".format(len(filtered_fabric_devices)), "DEBUG")
                fabric_info_result = self.get_fabric_info(filtered_fabric_devices)
                self.total_response.append(fabric_info_result)
                combined_fabric_data["fabric_info"] = fabric_info_result

            if device_issues_info:
                self.log("Retrieving active device issues and alerts for {0} fabric devices".format(len(filtered_fabric_devices)), "DEBUG")
                device_issues_result = self.get_device_issues_info(filtered_fabric_devices)
                self.total_response.append(device_issues_result)
                combined_fabric_data["device_issues_info"] = device_issues_result

            if handoff_info:
                self.log("Retrieving Layer 2/3 handoff configurations for fabric border and control plane nodes", "DEBUG")
                self.log("Retrieving Layer 3 SDA handoff configurations for fabric devices", "DEBUG")
                handoff_layer3_sda_result = self.get_handoff_layer3_sda_info(filtered_fabric_devices)
                self.total_response.append(handoff_layer3_sda_result)
                combined_fabric_data["handoff_layer3_sda_info"] = handoff_layer3_sda_result

                self.log("Retrieving Layer 3 IP transit handoff configurations for fabric devices", "DEBUG")
                handoff_layer3_ip_result = self.get_handoff_layer3_ip_info(filtered_fabric_devices)
                self.total_response.append(handoff_layer3_ip_result)
                combined_fabric_data["handoff_layer3_ip_info"] = handoff_layer3_ip_result

                self.log("Retrieving Layer 2 handoff configurations for fabric devices", "DEBUG")
                handoff_layer2_result = self.get_handoff_layer2_info(filtered_fabric_devices)
                self.total_response.append(handoff_layer2_result)
                combined_fabric_data["handoff_layer2_info"] = handoff_layer2_result
            if connected_devices_info:
                self.log("Retrieving connected neighbor device information via interface for {0} fabric devices".format(len(filtered_fabric_devices)), "DEBUG")
                connected_devices_result = self.get_connected_device_details_from_interfaces(filtered_fabric_devices)
                self.total_response.append(connected_devices_result)
                combined_fabric_data["connected_devices_info"] = connected_devices_result

            if device_health_info:
                self.log("Retrieving health metrics and performance data for {0} fabric devices".format(len(filtered_fabric_devices)), "DEBUG")
                device_health_result = self.get_device_health_info(filtered_fabric_devices)
                self.total_response.append(device_health_result)
                combined_fabric_data["device_health_info"] = device_health_result

            if onboarding_info:
                self.log("Retrieving device onboarding status and port assignment details for {0} fabric devices".format(len(fabric_devices)), "DEBUG")
                self.log("Retrieving device onboarding and port assignment information", "DEBUG")
                onboarding_info_result = self.get_port_details(filtered_fabric_devices)
                self.total_response.append(onboarding_info_result)
                combined_fabric_data["onboarding_info"] = onboarding_info_result

                self.log("Retrieving device onboarding status and port channel details for {0} fabric devices".format(len(fabric_devices)), "DEBUG")
                self.log("Retrieving device onboarding and port channel information", "DEBUG")
                port_channel_info_result = self.get_port_channels(filtered_fabric_devices)
                self.total_response.append(port_channel_info_result)
                combined_fabric_data["port_channel_info"] = port_channel_info_result

                self.log("Retrieving SSID configuration details for wireless fabric devices", "DEBUG")
                ssid_info_result = self.get_ssid_details(filtered_fabric_devices)
                self.total_response.append(ssid_info_result)
                combined_fabric_data["ssid_info"] = ssid_info_result

                self.log("Retrieving device provision status and deployment state information", "DEBUG")
                provision_status_result = self.get_provision_status(filtered_fabric_devices)
                self.total_response.append(provision_status_result)
                combined_fabric_data["provision_status_info"] = provision_status_result

        if config.get("fabric_devices"):
            output_file_info = config["fabric_devices"][0].get("output_file_info")

        if output_file_info:
            self.log("Processing file output configuration for fabric device information export: {0}".format(output_file_info), "INFO")
            self.write_device_info_to_file({"output_file_info": output_file_info})
            self.log("Fabric device information successfully written to output file", "INFO")

        if self.total_response:
            self.log("Fabric device information retrieval workflow completed successfully with {0} response entries".format(len(fabric_devices)), "INFO")
            self.msg = self.total_response
            self.set_operation_result("success", False, self.msg, "INFO")

    def is_fabric_site(self, site_hierarchy):
        """
        Determines whether a given site hierarchy is configured as a Software-Defined Access (SDA) fabric site.

        This method validates the existence of a site hierarchy in Cisco Catalyst Center and checks
        if it has been configured as an SDA fabric site.

        Args:
            site_hierarchy (str): The hierarchical path of the site to validate as a fabric site.
                Format: "Global/Area/Building/Floor" or similar hierarchical structure.
                Must be an existing site in Cisco Catalyst Center.

        Returns:
            tuple: A tuple containing two elements:
                - bool: True if the site is configured as a fabric site, False otherwise.
                - str or None: The fabric site ID if the site is a fabric site, None otherwise.

        """
        self.log("Checking if site hierarchy '{0}' is a fabric site".format(site_hierarchy), "DEBUG")
        site_exists, site_id = self.get_site_id(site_hierarchy)

        if not site_exists:
            self.msg = "The specified site hierarchy '{0}' does not exist.".format(site_hierarchy)
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        try:
            limit = 500
            offset = 1
            fabric_site_id = None

            self.log("Checking fabric sites for site_id: {0}".format(site_id), "DEBUG")

            while True:
                response = self.dnac._exec(
                    family="sda",
                    function="get_fabric_sites",
                    params={"site_id": site_id, "offset": offset, "limit": limit}
                )

                self.log("Received API response from 'get_fabric_sites': {0}".format(response), "DEBUG")

                fabric_sites = response.get("response", [])
                self.log("Retrieved {0} fabric site(s) for site_id: {1}".format(len(fabric_sites), site_id), "DEBUG")

                if fabric_sites:
                    fabric_site_id = fabric_sites[0].get("id")
                    self.log(
                        "The site hierarchy '{0}' (siteId: {1}) is a Fabric site with Fabric ID: {2}".format(
                            site_hierarchy, site_id, fabric_site_id
                        ),
                        "INFO"
                    )
                    return True, fabric_site_id

                if len(fabric_sites) < limit:
                    self.log("No more fabric sites returned (less than limit {0}).".format(limit), "DEBUG")
                    break

                offset += limit

            self.log(
                "The site hierarchy '{0}' (siteId: {1}) is NOT a Fabric site.".format(site_hierarchy, site_id),
                "INFO"
            )
            return False, None

        except Exception as e:
            self.msg = "Error occurred while checking fabric site: {0}".format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
            return False, None

    def get_device_id(self, filtered_config):
        """
        Retrieves device UUIDs from Cisco Catalyst Center based on device identifier parameters.

        This method processes device identification criteria from the configuration and maps network
        devices to their corresponding UUIDs. It supports multiple identification methods and only
        considers devices that are managed and reachable in the Catalyst Center inventory.
        Logic Implementation:
        The method implements two distinct logical operations based on the structure of device_identifiers:

        Logic Implementation:
            The method implements two distinct logical operations based on the structure of device_identifiers:

            AND Logic (Single Entry with Multiple Keys):
                - Triggered when: len(device_identifiers) == 1 AND len(device_identifiers[0].keys()) > 1
                - Behavior: Devices must match ALL specified criteria within the single entry
                - Example: [{"ip_address": ["192.168.1.1"], "hostname": ["switch01"]}]
                - Result: Returns only devices that have IP 192.168.1.1 AND hostname switch01
                - Implementation: Uses set intersection to find devices matching all criteria

            OR Logic (Multiple Entries):
                - Triggered when: Multiple device_identifier entries are provided
                - Behavior: Devices matching ANY of the entries are included
                - Example: [{"ip_address": ["192.168.1.1"]}, {"hostname": ["switch02"]}]
                - Result: Returns devices that have IP 192.168.1.1 OR hostname switch02
                - Implementation: Accumulates devices from each entry independently

        Args:
            filtered_config (dict): Configuration dictionary containing device identification parameters.

        Returns:
            dict or None: A dictionary mapping device IP addresses to their UUIDs for managed devices.
                        Returns None if no device_identifier section is found in configuration.
        """

        self.log("Starting device UUID mapping retrieval from 'device_identifier' entries", "INFO")

        device_identifiers = filtered_config.get("device_identifier", [])
        if not device_identifiers:
            self.msg = "No 'device_identifier' section found in configuration. Skipping device ID retrieval."
            self.log(self.msg, "WARNING")
            return None

        param_key_map = {
            "ip_address": "managementIpAddress",
            "serial_number": "serialNumber",
            "hostname": "hostname"
        }

        ip_uuid_map = {}
        timeout = filtered_config.get("timeout", 120)
        retries = filtered_config.get("retries", 3)
        interval = filtered_config.get("interval", 10)

        # Detect logic type: AND or OR
        is_and_logic = len(device_identifiers) == 1 and len(device_identifiers[0].keys()) > 1
        logic_type = "AND" if is_and_logic else "OR"
        self.log("Detected device_identifier logic type: {0}".format(logic_type), "DEBUG")

        if is_and_logic:
            identifier = device_identifiers[0]
            self.log("Processing AND logic for identifiers: {0}".format(identifier), "DEBUG")

            combined_devices = None
            for key, values in identifier.items():
                if not values:
                    continue
                if not isinstance(values, list):
                    values = [values]

                expanded_values = []

                for value in values:
                    if key == "ip_address_range":
                        try:
                            start_ip, end_ip = value.split("-")
                            start = ipaddress.IPv4Address(start_ip.strip())
                            end = ipaddress.IPv4Address(end_ip.strip())
                            expanded_values.extend([
                                str(ipaddress.IPv4Address(i))
                                for i in range(int(start), int(end) + 1)
                            ])
                            self.log(
                                "Expanded IP range '{0}' into {1} IPs".format(value, len(expanded_values)),
                                "DEBUG"
                            )
                        except Exception as e:
                            self.log("Invalid IP range '{0}': {1}".format(value, str(e)), "ERROR")
                    else:
                        expanded_values.append(value)

                param_key = param_key_map.get(key)
                matched_devices = []

                missing_ips = []

                for ip_or_value in expanded_values:
                    params = {param_key_map.get(key, "managementIpAddress"): ip_or_value}
                    attempt = 0
                    start_time = time.time()
                    device_found = False

                    while attempt < retries or (time.time() - start_time) < timeout:
                        self.log("Attempt {0} - Calling API with params: {1}".format(attempt + 1, params), "DEBUG")
                        try:
                            response = self.dnac._exec(
                                family="devices",
                                function="get_device_list",
                                params=params
                            )
                            devices = response.get("response", [])
                            self.log("Received API response for {0}={1}: {2}".format(key, ip_or_value, response), "DEBUG")
                            managed_devices = [
                                device for device in devices
                                if device.get("collectionStatus") == "Managed"
                                or device.get("reachabilityStatus") == "Reachable"
                            ]
                            if managed_devices:
                                matched_devices.extend(managed_devices)
                                device_found = True
                                break
                        except Exception as e:
                            self.log("API call failed for {0}={1}: {2}".format(key, value, str(e)), "WARNING")
                        attempt += 1
                        time.sleep(interval)

                    if not device_found:
                        missing_ips.append(ip_or_value)

                if missing_ips:
                    display_value = "IP(s) not found: {}".format(", ".join(missing_ips))
                    self.msg = (
                        "No managed devices found for the following identifiers: {0}. "
                        "Device(s) may be unreachable, unmanaged, or not present in Catalyst Center inventory."
                    ).format(display_value)
                    self.set_operation_result("success", False, self.msg, "INFO")
                    if self.msg not in self.total_response:
                        self.total_response.append(self.msg)

                if combined_devices is None:
                    combined_devices = matched_devices
                else:
                    combined_devices = [
                        device for device in combined_devices if any(
                            device.get("instanceUuid") == managed_device.get("instanceUuid") for managed_device in matched_devices
                        )
                    ]

            for device in combined_devices or []:
                uuid = device.get("instanceUuid")
                ip = device.get("managementIpAddress")
                if uuid and ip:
                    ip_uuid_map[ip] = uuid

            if not combined_devices:
                self.msg = (
                    "No managed devices found matching all specified identifiers "
                    "({0}).".format(list(identifier.keys()))
                )
                self.set_operation_result("success", False, self.msg, "INFO")
                self.total_response.append(self.msg)

        else:
            for idx, identifier in enumerate(device_identifiers, start=1):
                self.log("Processing OR logic entry #{0}: {1}".format(idx, identifier), "DEBUG")

                for key, values in identifier.items():
                    if not values:
                        continue
                    if not isinstance(values, list):
                        values = [values]

                    expanded_values = []

                    for value in values:
                        if key == "ip_address_range":
                            try:
                                start_ip, end_ip = value.split("-")
                                start = ipaddress.IPv4Address(start_ip.strip())
                                end = ipaddress.IPv4Address(end_ip.strip())
                                expanded_values.extend([
                                    str(ipaddress.IPv4Address(i))
                                    for i in range(int(start), int(end) + 1)
                                ])
                                self.log(
                                    "Expanded IP range '{0}' into {1} IPs".format(value, len(expanded_values)),
                                    "DEBUG"
                                )
                            except Exception as e:
                                self.log("Invalid IP range '{0}': {1}".format(value, str(e)), "ERROR")
                        else:
                            expanded_values.append(value)

                    missing_ips = []

                    for ip_or_value in expanded_values:
                        params = {param_key_map.get(key, "managementIpAddress"): ip_or_value}
                        attempt = 0
                        attempt = 0
                        start_time = time.time()
                        device_found = False

                        while attempt < retries or (time.time() - start_time) < timeout:
                            self.log("Attempt {0} - Calling API with params: {1}".format(attempt + 1, params), "DEBUG")
                            try:
                                response = self.dnac._exec(
                                    family="devices",
                                    function="get_device_list",
                                    params=params
                                )
                                devices = response.get("response", [])
                                self.log("Received API response for {0}={1}: {2}".format(key, ip_or_value, response), "DEBUG")
                                managed_devices = [
                                    device for device in devices
                                    if device.get("collectionStatus") == "Managed"
                                    or device.get("reachabilityStatus") == "Reachable"
                                ]
                                if managed_devices:
                                    for device in managed_devices:
                                        uuid = device.get("instanceUuid")
                                        ip = device.get("managementIpAddress")
                                        if uuid and ip:
                                            ip_uuid_map[ip] = uuid
                                    device_found = True
                                    break
                            except Exception as e:
                                self.log("API call failed for {0}={1}: {2}".format(key, value, str(e)), "WARNING")
                            attempt += 1
                            time.sleep(interval)

                        if not device_found:
                            missing_ips.append(ip_or_value)

                    if missing_ips:
                        display_value = ", ".join(missing_ips)
                        self.msg = (
                            "No managed devices found for the following {0}(s): {1}. "
                            "Device(s) may be unreachable, unmanaged, or not present in Catalyst Center inventory."
                        ).format(key, display_value)
                        self.set_operation_result("success", False, self.msg, "INFO")
                        if self.msg not in self.total_response:
                            self.total_response.append(self.msg)

        total_devices = len(ip_uuid_map)
        self.log("Device UUID mapping completed — mapped {0} managed devices.".format(total_devices), "INFO")

        return ip_uuid_map

    def filter_fabric_devices(self, filtered_config):
        """
        Filters network devices to identify which ones are part of a Software-Defined Access (SDA) fabric site.

        This method retrieves all fabric devices from a specified fabric site and cross-references them
        with the provided device identifiers to determine which devices are actually fabric-enabled.
        It supports optional role-based filtering to narrow results to specific fabric device roles.

        Args:
            filtered_config (dict): Configuration dictionary containing device identification parameters.

        Returns:
            dict: A dictionary mapping device IP addresses to their corresponding UUIDs for devices
                that are both managed and part of the fabric site. Returns None if an error occurs.
        """
        self.log("Starting comprehensive fabric device filtering", "INFO")
        site_hierarchy = self.want["fabric_devices"][0].get("fabric_site_hierarchy")
        fabric_exists, fabric_id = self.is_fabric_site(site_hierarchy)
        device_ids = self.get_device_id(filtered_config)

        if filtered_config.get("device_identifier") and not device_ids:
            self.log(
                "Device identifiers were specified in configuration but no matching device UUIDs were found. "
                "Skipping fabric filtering.", "WARNING"
            )
            return None

        fabric_device_role = self.want["fabric_devices"][0].get("fabric_device_role")

        timeout = filtered_config.get("timeout", 120)
        retries = filtered_config.get("retries", 3)
        interval = filtered_config.get("interval", 10)

        filtered_devices = {}
        start_time = time.time()
        attempt = 0

        if fabric_exists:
            self.log("Retrieving fabric devices for fabric ID: {0}".format(fabric_id), "DEBUG")

            while attempt < retries and (time.time() - start_time) < timeout:
                try:
                    limit = 500
                    offset = 1
                    fabric_devices = []

                    params = {"fabric_id": fabric_id, "offset": offset, "limit": limit}
                    if fabric_device_role:
                        params["device_roles"] = fabric_device_role
                        self.log(
                            "Applying role-based filtering for role: '{0}' in API request".format(fabric_device_role),
                            "DEBUG"
                        )
                    self.log("Initial API params for fabric devices retrieval: {0}".format(params), "DEBUG")

                    while True:
                        response = self.dnac._exec(
                            family="sda",
                            function="get_fabric_devices",
                            params=params
                        )

                        self.log("Received API response from 'get_fabric_devices': {0}".format(response), "DEBUG")

                        devices = response.get("response", [])

                        if devices:
                            fabric_devices.extend(devices)

                        if len(devices) < limit:
                            self.log("No more fabric devices returned (less than limit {0}).".format(limit), "DEBUG")
                            break

                        offset += limit
                        params["offset"] = offset

                    self.log("Total fabric devices retrieved: {0}".format(len(fabric_devices)), "INFO")

                    filtered_devices = {}
                    if device_ids:
                        for ip, uuid in device_ids.items():
                            for device in fabric_devices:
                                fabric_id = device.get("fabricId")
                                if device.get("networkDeviceId") == uuid:
                                    filtered_devices[ip] = fabric_id
                                    self.log(
                                        "Device {0} (UUID: {1}) included as part of fabric site '{2}'.".format(
                                            ip, uuid, site_hierarchy
                                        ),
                                        "DEBUG"
                                    )
                    else:
                        for device in fabric_devices:
                            uuid = device.get("networkDeviceId")
                            if uuid:
                                ip_map = self.get_device_ips_from_device_ids([uuid])
                                if ip_map and isinstance(ip_map, dict):
                                    ip = list(ip_map.values())[0]
                                    if ip:
                                        filtered_devices[ip] = fabric_id
                                        self.log(
                                            "Device {0} (UUID: {1}) included as part of fabric site '{2}'.".format(
                                                ip, uuid, site_hierarchy
                                            ),
                                            "DEBUG"
                                        )
                    if filtered_devices:
                        self.log("Fabric devices successfully filtered on attempt {0}".format(attempt + 1), "INFO")
                        break

                    if attempt < retries and (time.time() - start_time) < timeout:
                        self.log(
                            "No matching fabric devices found in attempt {0}. Retrying in {1} seconds...".format(
                                attempt + 1, interval
                            ),
                            "WARNING"
                        )
                        time.sleep(interval)
                        attempt += 1

                    total_filtered = len(filtered_devices)
                    self.log(
                        "Filtered down to {0} fabric devices after applying site{1} criteria.".format(
                            total_filtered,
                            " and role" if fabric_device_role else ""
                        ),
                        "INFO",
                    )

                    if not filtered_devices:
                        self.msg = "No devices from the provided identifiers are part of the specified fabric site with the given criteria."
                        self.set_operation_result("Success", False, self.msg, "ERROR").check_return_status()

                except Exception as e:
                    self.msg = "Error occurred while retrieving/filtering fabric devices: {0}".format(str(e))
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                    return None
            return filtered_devices

    def get_fabric_info(self, filtered_fabric_devices):
        """
        Retrieve comprehensive fabric configuration details for specified fabric devices from Catalyst Center.

        This method queries the Catalyst Center SDA API to collect detailed fabric-specific information
        for each provided fabric device. It iterates through the filtered fabric devices to retrieve
        complete fabric configuration metadata including device roles, fabric site associations, and
        SDA-specific attributes such as device types, border/edge/control plane roles, and fabric ID mappings.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Returns:
            list: Structured fabric related information results in standardized format:
                [
                    {
                        "fabric_info": [
                            {
                                "device_ip": "192.168.1.1",
                                "fabric_details": [fabric_records] or [] or "Error: <error_message>"
                            }
                        ]
                    }
                ]
        """
        self.log("Retrieving comprehensive fabric configuration details for fabric device inventory", "INFO")
        self.log("Processing fabric information for {0} fabric devices".format(len(filtered_fabric_devices)), "DEBUG")

        fabric_device_role = self.want["fabric_devices"][0].get("fabric_device_role")
        device_identifier = self.want["fabric_devices"][0].get("device_identifier")

        fabric_info_list = []
        devices_with_fabric_info = 0
        devices_with_errors = 0

        self.log("Querying fabric device information for filtered fabric devices from Cisco Catalyst Center", "DEBUG")

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])
            for ip, device_uuid in ip_device_uuid_map.items():
                self.log("Processing fabric device {0}/{1}: IP={2}".format(
                    index + 1, len(filtered_fabric_devices), ip
                ), "DEBUG")
                try:
                    params = {"fabric_id": fabric_id}
                    if fabric_device_role:
                        params["device_roles"] = fabric_device_role
                        self.log(
                            "Applying role-based filtering for role: '{0}' in API request".format(fabric_device_role),
                            "DEBUG"
                        )
                    if device_identifier:
                        params["network_device_id"] = device_uuid
                        self.log(
                            "Added 'network_device_id' to API params for device {0}: {1}".format(ip, device_uuid),
                            "DEBUG"
                        )
                    self.log("Initial API params for fabric devices retrieval: {0}".format(params), "DEBUG")

                    response = self.dnac._exec(
                        family="sda",
                        function="get_fabric_devices",
                        params=params
                    )
                    fabric_data = response.get("response", [])
                    self.log(
                        "Received API response from 'get_fabric_devices' for device {0}: {1}".format(
                            ip, response
                        ),
                        "DEBUG"
                    )

                    filtered_fabric_data = [
                        device for device in fabric_data
                        if device.get("networkDeviceId") == device_uuid
                    ]

                    if filtered_fabric_data:
                        devices_with_fabric_info += 1
                        self.log("Fabric details found for device_ip: {0}.".format(ip), "INFO")
                        fabric_info_list.append({
                            "device_ip": ip,
                            "fabric_details": filtered_fabric_data
                        })
                        self.log("Successfully retrieved fabric configuration for device {0}".format(ip), "DEBUG")
                    else:
                        self.log("No fabric details found for device_ip: {0}".format(ip), "WARNING")

                except Exception as api_err:
                    devices_with_errors += 1
                    error_message = "Failed to retrieve fabric information for device {0}: {1}".format(ip, str(api_err))
                    self.log(error_message, "ERROR")
                    fabric_info_list.append({
                        "device_ip": ip,
                        "fabric_details": "Error: {0}".format(api_err)
                    })
                    continue

        result = [{"fabric_info": fabric_info_list}]

        self.log("Completed fabric info retrieval for filtered fabric devices. Total devices processed: {0}".format(len(fabric_info_list)), "INFO")
        self.log("Fabric info result: {0}".format(result), "DEBUG")

        total_fabric_devices = len(filtered_fabric_devices)
        self.log(
            "Fabric information retrieval completed - processed {0}/{1} fabric devices successfully".format(
                devices_with_fabric_info, total_fabric_devices
            ),
            "INFO"
        )
        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during fabric information retrieval".format(devices_with_errors), "WARNING")

        if devices_with_fabric_info > 0:
            self.log(
                "Fabric information successfully retrieved for devices: {0}".format(
                    [info["device_ip"] for info in fabric_info_list if not isinstance(info["fabric_details"], str)]
                ),
                "DEBUG"
            )
        return result

    def get_device_issues_info(self, filtered_fabric_devices):
        """
        Retrieve current device issues and alerts for fabric devices from Cisco Catalyst Center.

        This method queries the Catalyst Center Issues API to collect active issues, alerts, and
        health problems for each provided fabric device. It provides comprehensive troubleshooting
        information including critical alerts, warnings, and operational issues that may affect
        fabric device performance and SDA functionality.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Return:
            list: Structured device issues information results in standardized format:
                [
                    {
                        "device_issues_info": [
                            {
                                "device_ip": "192.168.1.1",
                                "issue_details": [issue_records] or [] or "Error: <error_message>"
                            },
                            {
                                "device_ip": "192.168.1.2",
                                "issue_details": [issue_records] or [] or "Error: <error_message>"
                            }
                        ]
                    }
                ]
        """
        self.log("Retrieving current device issues and alerts for fabric device troubleshooting", "INFO")
        self.log(
            "Processing device issues information for {0} fabric devices ".format(
                len(filtered_fabric_devices)
            ),
            "DEBUG"
        )

        issue_info_list = []
        devices_processed = 0
        devices_with_issues = 0
        devices_without_issues = 0
        devices_with_errors = 0

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])
            for ip, device_uuid in ip_device_uuid_map.items():
                self.log("Processing fabric device {0}/{1}: IP={2}".format(
                    index + 1, len(filtered_fabric_devices), ip
                ), "DEBUG")
                devices_processed += 1
                self.log("Retrieving issue information for fabric device {0}".format(ip), "DEBUG")
                try:
                    response = self.dnac._exec(
                        family="issues",
                        function="issues",
                        params={"device_id": device_uuid}
                    )
                    issue_data = response.get("response", [])
                    self.log(
                        "Received API response from 'issues' for device {0}: {1}".format(
                            ip, response
                        ),
                        "DEBUG"
                    )

                    if issue_data:
                        devices_with_issues += 1
                        self.log("Active issues found for fabric device {0} - retrieved {1} issue records".format(ip, len(issue_data)), "INFO")
                        issue_info_list.append({
                            "device_ip": ip,
                            "issue_details": issue_data
                        })

                    else:
                        devices_without_issues += 1
                        self.log("No active issues found for fabric device {0} - device status healthy".format(ip), "DEBUG")
                        issue_info_list.append({
                            "device_ip": ip,
                            "issue_details": []
                        })

                except Exception as api_err:
                    devices_with_errors += 1
                    self.msg = "Failed to retrieve device issues for fabric device {0}: {1}".format(ip, str(api_err))
                    issue_info_list.append({
                        "device_ip": ip,
                        "issue_details": "Error: {0}".format(str(api_err))
                    })

            result = [{"device_issues_info": issue_info_list}]

            self.log("Completed device info retrieval. Total devices processed: {0}".format(len(issue_info_list)), "INFO")

            total_fabric_devices = len(filtered_fabric_devices)
            self.log(
                "Device issues retrieval completed - processed {0}/{1} fabric devices successfully".format(
                    devices_processed, total_fabric_devices
                ),
                "INFO",
            )
            if devices_with_issues > 0:
                self.log("Fabric devices with active issues: {0}".format(devices_with_issues), "WARNING")

            if devices_without_issues > 0:
                self.log("Fabric devices with healthy status (no issues): {0}".format(devices_without_issues), "INFO")

            if devices_with_errors > 0:
                self.log("Warning: {0} devices encountered errors during issue information retrieval".format(devices_with_errors), "WARNING")

            self.log("Aggregated device‑issues info: {0}".format(result), "DEBUG")

            return result

    def get_transit_name_by_id(self, transit_id):
        """
        Retrieve the human-readable transit network name for a given transit network identifier.

        This method queries the Cisco Catalyst Center SDA API to resolve transit network IDs
        into their corresponding descriptive names for enhanced readability and reporting.
        Transit networks are used in fabric handoff configurations to enable inter-fabric
        and external connectivity in SDA deployments.

        Args:
            transit_id (str): The unique identifier (UUID) of the transit network.
                Must be a valid transit network ID that exists in the Catalyst Center SDA configuration.

        Returns:
            str or None: The descriptive name of the transit network if found, otherwise None.
                - Success: Returns the transit network name (e.g., "MPLS_WAN_Transit", "Internet_Transit")
                - Not Found: Returns None when the transit ID doesn't exist or has no name configured
                - Error: Returns None when API call fails or encounters exceptions
        """
        self.log("Starting transit network name retrieval for transit_id: {0}".format(transit_id), "DEBUG")

        if not isinstance(transit_id, str) or len(transit_id.strip()) == 0:
            self.log("Invalid transit_id format provided: {0} - returning None".format(transit_id), "WARNING")
            return None

        try:
            self.log("Querying Catalyst Center for transit network details with ID: {0}".format(transit_id), "DEBUG")
            response = self.dnac._exec(
                family="sda",
                function="get_transit_networks",
                params={"id": transit_id}
            )
            transit_info = response.get("response", [])
            self.log("Received API response for 'get_transit_networks' with transit_id {0}: {1}".format(transit_id, response), "DEBUG")

            if not transit_info:
                self.log("No transit network information found for transit_id: {0}".format(transit_id), "DEBUG")
                return None

            transit_name = transit_info[0].get("name", None)

            if not transit_name:
                self.log("Transit network found but no name configured for transit_id: {0}".format(transit_id), "WARNING")
                return None

            self.log("Successfully retrieved transit network name: '{0}' for ID: {1}".format(transit_name, transit_id), "INFO")
            return transit_name

        except Exception as e:
            self.log("Failed to retrieve transit name for transit_id {0}: {1}".format(transit_id, str(e)), "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return None

    def get_handoff_layer3_sda_info(self, filtered_fabric_devices):
        """
        Retrieve Layer 3 SDA (Software-Defined Access) handoff configurations for fabric inter-site connectivity.

        This method queries the Catalyst Center SDA API to collect Layer 3 SDA transit handoff configurations
        for fabric devices that enable inter-fabric site communication and SDA overlay routing. It provides
        detailed information about SDA transit connections, LISP mappings, and fabric-to-fabric routing
        configurations essential for multi-site SDA deployments.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Returns:
            list: Structured Layer 3 SDA handoff information results in standardized format:
                [
                    {
                        "fabric_devices_layer3_handoffs_sda_info": [
                            {
                                "device_ip": "192.168.1.1",
                                "handoff_layer3_sda_transit_info": [handoff_records] or [] or "Error: <error_message>"
                            },
                            {
                                "device_ip": "192.168.1.2",
                                "handoff_layer3_sda_transit_info": [handoff_records] or [] or "Error: <error_message>"
                            }
                        ]
                    }
                ]
        """
        self.log("Retrieving Layer 3 SDA handoff configurations for fabric inter-site connectivity", "INFO")
        self.log("Processing Layer 3 SDA handoff information for {0} devices across fabric sites".format(len(filtered_fabric_devices)), "DEBUG")

        device_identifier = self.want["fabric_devices"][0].get("device_identifier")

        all_handoff_layer3_sda_list = []
        processed_device_ips = set()
        devices_processed = 0
        devices_with_handoffs = 0
        devices_without_handoffs = 0
        devices_with_errors = 0

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])
            for ip, device_uuid in ip_device_uuid_map.items():
                self.log(
                    "Processing layer3 sda handoff info for device {0}/{1}: "
                    "IP: {2}".format(index + 1, len(filtered_fabric_devices), ip),
                    "DEBUG"
                )
                processed_device_ips.add(ip)
                devices_processed += 1

                self.log("Retrieving Layer 3 SDA handoff configuration for fabric device {0} in fabric site {1}".format(ip, fabric_id), "DEBUG")

                try:
                    params = {"fabric_id": fabric_id}
                    if device_identifier or fabric_id:
                        params["network_device_id"] = device_uuid
                        self.log(
                            "Added 'network_device_id' parameter for device {0}: {1}".format(ip, device_uuid),
                            "DEBUG"
                        )
                    response = self.dnac._exec(
                        family="sda",
                        function="get_fabric_devices_layer3_handoffs_with_sda_transit",
                        params=params
                    )
                    layer3_sda_handoff_data = response.get("response", [])
                    self.log(
                        "Received API response for 'get_fabric_devices_layer3_handoffs_with_sda_transit' for IP {0}: {1}".format(
                            ip, response
                        ),
                        "DEBUG"
                    )
                    if layer3_sda_handoff_data:
                        for handoff in layer3_sda_handoff_data:
                            transit_id = handoff.get("transitNetworkId")
                            handoff["transitName"] = self.get_transit_name_by_id(transit_id)
                            devices_with_handoffs += 1
                            self.log(
                                "Layer 3 SDA handoff configuration found for fabric device {0} - "
                                "retrieved {1} handoff records".format(
                                    ip, len(layer3_sda_handoff_data)
                                ),
                                "INFO"
                            )
                            all_handoff_layer3_sda_list.append({
                                "device_ip": ip,
                                "handoff_layer3_sda_transit_info": layer3_sda_handoff_data
                            })

                    else:
                        devices_without_handoffs += 1
                        self.log(
                            "No Layer 3 SDA handoff configuration found for fabric device {0} - "
                            "device may not be configured for inter-fabric routing".format(
                                ip
                            ),
                            "DEBUG"
                        )
                        all_handoff_layer3_sda_list.append({
                            "device_ip": ip,
                            "handoff_layer3_sda_transit_info": []
                        })

                except Exception as api_err:
                    devices_with_errors += 1
                    self.msg = "Exception occurred while getting L3 SDA hand-off info for device {0}: {1}".format(ip, api_err)
                    all_handoff_layer3_sda_list.append({
                        "device_ip": ip,
                        "handoff_layer3_sda_transit_info": "Error: {0}".format(api_err)
                    })

        result = [{"fabric_devices_layer3_handoffs_sda_info": all_handoff_layer3_sda_list}]

        total_fabric_devices = len(filtered_fabric_devices)
        self.log(
            "Layer 3 SDA handoff configuration retrieval completed - "
            "processed {0}/{1} fabric devices successfully".format(
                devices_processed,
                total_fabric_devices
            ),
            "INFO"
        )
        if devices_with_handoffs > 0:
            self.log("Fabric devices with Layer 3 SDA handoff configurations: {0}".format(devices_with_handoffs), "INFO")

        if devices_without_handoffs > 0:
            self.log("Fabric devices without Layer 3 SDA handoff configurations: {0}".format(devices_without_handoffs), "INFO")

        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during Layer 3 SDA handoff configuration retrieval".format(devices_with_errors), "WARNING")

        self.log("Completed L3 SDA hand-off info retrieval. Total devices processed: {0}".format(len(all_handoff_layer3_sda_list)), "INFO")
        self.log("Aggregated L3 SDA hand-off info: {0}".format(result), "DEBUG")

        return result

    def get_handoff_layer3_ip_info(self, filtered_fabric_devices):
        """
        Retrieve Layer 3 IP transit handoff configurations for fabric external connectivity and routing.

        This method queries the Catalyst Center SDA API to collect Layer 3 IP transit handoff configurations
        for fabric devices that enable external network connectivity beyond the SDA fabric boundary. It provides
        detailed information about IP transit connections, external routing configurations, and fabric-to-external
        network handoff settings essential for enterprise WAN integration and internet connectivity.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
               Contains only devices that have been confirmed as members of the specified fabric site.
               Each IP address represents a managed device that exists in both the network inventory
               and the fabric site configuration.

        Returns:
            list: Structured Layer 3 IP handoff information results in standardized format:
                [
                    {
                        "fabric_devices_layer3_handoffs_ip_info": [
                            {
                                "device_ip": "192.168.1.1",
                                "handoff_layer3_ip_transit_info": [handoff_records] or [] or "Error: <error_message>"
                            },
                            {
                                "device_ip": "192.168.1.2",
                                "handoff_layer3_ip_transit_info": [handoff_records] or [] or "Error: <error_message>"
                            }
                        ]
                    }
                ]
        """
        self.log("Retrieving Layer 3 IP handoff configurations for fabric external connectivity", "INFO")
        self.log("Processing Layer 3 IP handoff information for {0} devices across fabric sites".format(len(filtered_fabric_devices)), "DEBUG")

        device_identifier = self.want["fabric_devices"][0].get("device_identifier")

        all_handoff_layer3_ip_info_list = []
        processed_device_ips = set()
        devices_processed = 0
        devices_with_handoffs = 0
        devices_without_handoffs = 0
        devices_with_errors = 0

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])
            for ip, device_uuid in ip_device_uuid_map.items():
                self.log(
                    "Retrieving Layer 3 IP handoff configuration for fabric device {0}".format(ip), "DEBUG")
                processed_device_ips.add(ip)
                devices_processed += 1

                try:
                    params = {"fabric_id": fabric_id}

                    if device_identifier or fabric_id:
                        params["network_device_id"] = device_uuid
                        self.log(
                            "Added 'network_device_id' parameter for device {0}: {1}".format(ip, device_uuid),
                            "DEBUG"
                        )
                    response = self.dnac._exec(
                        family="sda",
                        function="get_fabric_devices_layer3_handoffs_with_ip_transit",
                        params=params
                    )
                    layer3_ip_handoff_data = response.get("response", [])
                    self.log(
                        "Received API response for 'get_fabric_devices_layer3_handoffs_with_ip_transit' for IP {0}: {1}".format(
                            ip, response
                        ),
                        "DEBUG"
                    )
                    if layer3_ip_handoff_data:
                        for handoff in layer3_ip_handoff_data:
                            transit_id = handoff.get("transitNetworkId")
                            handoff["transitName"] = self.get_transit_name_by_id(transit_id)
                        devices_with_handoffs += 1
                        self.log(
                            "Layer 3 IP handoff configuration found for fabric device {0} - "
                            "retrieved {1} handoff records".format(
                                ip, len(layer3_ip_handoff_data)
                            ),
                            "INFO"
                        )
                        all_handoff_layer3_ip_info_list.append({
                            "device_ip": ip,
                            "handoff_layer3_ip_transit_info": layer3_ip_handoff_data
                        })
                    else:
                        devices_without_handoffs += 1
                        self.log(
                            "No Layer 3 IP handoff configuration found for fabric device {0} - "
                            "device may not be configured for external IP connectivity".format(
                                ip
                            ),
                            "DEBUG"
                        )
                        all_handoff_layer3_ip_info_list.append({
                            "device_ip": ip,
                            "handoff_layer3_ip_transit_info": []
                        })

                except Exception as api_err:
                    devices_with_errors += 1
                    self.msg = "Failed to retrieve Layer 3 IP handoff configuration for fabric device {0}: {1}".format(ip, str(api_err))
                    all_handoff_layer3_ip_info_list.append({
                        "device_ip": ip,
                        "handoff_layer3_ip_transit_info": "Error: {0}".format(api_err)
                    })

        result = [{"fabric_devices_layer3_handoffs_ip_info": all_handoff_layer3_ip_info_list}]

        total_fabric_devices = len(filtered_fabric_devices)
        self.log(
            "Layer 3 IP handoff configuration retrieval completed - "
            "processed {0}/{1} fabric devices successfully".format(
                devices_processed,
                total_fabric_devices
            ),
            "INFO"
        )
        if devices_with_handoffs > 0:
            self.log("Fabric devices with Layer 3 IP handoff configurations: {0}".format(devices_with_handoffs), "INFO")

        if devices_without_handoffs > 0:
            self.log("Fabric devices without Layer 3 IP handoff configurations: {0}".format(devices_without_handoffs), "INFO")

        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during Layer 3 IP handoff configuration retrieval".format(devices_with_errors), "WARNING")

        self.log("Completed L3 IP hand-off info retrieval. Total devices processed: {0}".format(len(all_handoff_layer3_ip_info_list)), "INFO")
        self.log("Aggregated L3 IP hand-off info: {0}".format(result), "DEBUG")

        return result

    def get_handoff_layer2_info(self, filtered_fabric_devices):
        """
        Retrieve Layer 2 handoff configurations for fabric edge connectivity and VLAN bridging.

        This method queries the Catalyst Center SDA API to collect Layer 2 handoff configurations
        for fabric devices that enable traditional VLAN-based connectivity and bridging between
        SDA fabric and legacy network segments. It provides detailed information about Layer 2
        handoff interfaces, VLAN mappings, and bridging configurations essential for hybrid
        network environments and gradual SDA migration scenarios.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Returns:
            list: A list with a single dictionary containing Layer 2 handoff information:
                [
                    {
                        "fabric_devices_layer2_handoffs_info": [
                            {
                                "device_ip": "192.168.1.2",
                                "handoff_layer2_info": [handoff_records] or [] or "Error: <error_message>"
                            },
                            {
                                "device_ip": "192.168.1.2",
                                "handoff_layer2_info": [handoff_records] or [] or "Error: <error_message>"
                            }
                        ]
                    }
                ]
        """
        self.log("Retrieving Layer 2 handoff configurations for fabric edge connectivity", "INFO")
        self.log("Processing Layer 2 handoff information for {0} devices across fabric sites".format(len(filtered_fabric_devices)), "DEBUG")

        device_identifier = self.want["fabric_devices"][0].get("device_identifier")

        all_handoff_layer2_info_list = []
        processed_device_ips = set()
        devices_processed = 0
        devices_with_handoffs = 0
        devices_without_handoffs = 0
        devices_with_errors = 0

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])
            for ip, device_uuid in ip_device_uuid_map.items():
                self.log(
                    "Retrieving Layer 2 handoff configuration for fabric device {0} ".format(ip), "DEBUG")
                devices_processed += 1
                processed_device_ips.add(ip)

                try:
                    params = {"fabric_id": fabric_id}

                    if device_identifier or fabric_id:
                        params["network_device_id"] = device_uuid
                        self.log(
                            "Added 'network_device_id' parameter for device {0}: {1}".format(ip, device_uuid),
                            "DEBUG"
                        )
                    response = self.dnac._exec(
                        family="sda",
                        function="get_fabric_devices_layer2_handoffs",
                        params=params
                    )
                    layer2_handoff_data = response.get("response", [])
                    self.log(
                        "Received API response for 'get_fabric_devices_layer2_handoffs' for IP {0}: {1}".format(
                            ip, response
                        ),
                        "DEBUG"
                    )
                    if layer2_handoff_data:
                        for handoff in layer2_handoff_data:
                            transit_id = handoff.get("transitNetworkId")
                            handoff["transitName"] = self.get_transit_name_by_id(transit_id)
                            devices_with_handoffs += 1
                            self.log(
                                "Layer 2 handoff configuration found for fabric device {0} - "
                                "retrieved {1} handoff records".format(
                                    ip, len(layer2_handoff_data)
                                ),
                                "INFO"
                            )
                            all_handoff_layer2_info_list.append({
                                "device_ip": ip,
                                "handoff_layer2_info": layer2_handoff_data
                            })

                    else:
                        devices_without_handoffs += 1
                        self.log(
                            "No Layer 2 handoff configuration found for fabric device {0} - "
                            "device may not be configured for Layer 2 edge connectivity".format(
                                ip
                            ),
                            "DEBUG"
                        )
                        all_handoff_layer2_info_list.append({
                            "device_ip": ip,
                            "handoff_layer2_info": []
                        })

                except Exception as api_err:
                    devices_with_errors += 1
                    self.msg = "Failed to retrieve Layer 2 handoff configuration for fabric device {0}: {1}".format(ip, str(api_err))
                    self.log(self.msg, "ERROR")
                    all_handoff_layer2_info_list.append({
                        "device_ip": ip,
                        "handoff_layer2_info": "Error: {0}".format(api_err)
                    })
                    continue

        result = [{"fabric_devices_layer2_handoffs_info": all_handoff_layer2_info_list}]

        total_fabric_devices = len(filtered_fabric_devices)
        self.log(
            "Layer 2 handoff configuration retrieval completed - "
            "processed {0}/{1} fabric devices successfully".format(
                devices_processed,
                total_fabric_devices
            ),
            "INFO"
        )
        if devices_with_handoffs > 0:
            self.log("Fabric devices with Layer 2 handoff configurations: {0}".format(devices_with_handoffs), "INFO")

        if devices_without_handoffs > 0:
            self.log("Fabric devices without Layer 2 handoff configurations: {0}".format(devices_without_handoffs), "INFO")

        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during Layer 2 handoff configuration retrieval".format(devices_with_errors), "WARNING")

        self.log("Completed L2 hand-off info retrieval. Total devices processed: {0}".format(len(all_handoff_layer2_info_list)), "INFO")
        self.log("Aggregated L2 hand-off info: {0}".format(result), "DEBUG")

        return result

    def get_interface_ids_per_device(self, filtered_fabric_devices):
        """
        Retrieve interface identifiers for fabric devices to enable interface-based operations and connectivity analysis.

        This method queries the Catalyst Center Device API to collect comprehensive interface inventory
        information for each specified fabric device. It retrieves interface UUIDs and metadata that
        are essential for subsequent operations such as connected device discovery, interface health
        monitoring, and network topology mapping within SDA fabric environments.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Returns:
            dict: A dictionary mapping device IP addresses to sets of interface UUIDs:
                {
                    "192.168.1.1": {"interface-uuid-1", "interface-uuid-2", "interface-uuid-3"},
                    "192.168.1.2": {"interface-uuid-4", "interface-uuid-5"},
                }
        """
        self.log("Retrieving interface identifiers for fabric device interface inventory and management", "INFO")
        self.log(
            "Processing interface discovery for {0} fabric devices".format(
                len(filtered_fabric_devices)
            ),
            "DEBUG"
        )

        device_interfaces_map = {}
        device_interfaces_map = {}
        devices_processed = 0
        devices_with_interfaces = 0
        devices_without_interfaces = 0
        interfaces_without_ids = 0
        devices_with_errors = 0
        total_interfaces_discovered = 0

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            self.log("Processing interface discovery for device {0}/{1}: IP: {2}".format(index + 1, len(filtered_fabric_devices), ip), "DEBUG")
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])
            for ip, device_uuid in ip_device_uuid_map.items():
                devices_processed += 1
                self.log("Retrieving interface information for fabric device {0}".format(ip), "DEBUG")

                try:
                    self.log("Fetching interfaces for device: {0}".format(ip), "DEBUG")

                    response = self.dnac._exec(
                        family="devices",
                        function="get_interface_info_by_id",
                        params={"device_id": device_uuid}
                    )
                    self.log("Received API response for interface query on device {0}".format(ip), "DEBUG")
                    interface_response_data = response.get("response", [])
                    self.log(
                        "Interface query completed for device {0} - found {1} interface records".format(
                            ip,
                            len(interface_response_data)
                        ),
                        "DEBUG"
                    )
                    self.log("Received API response for 'get_interface_info_by_id' for device {0}: {1}".format(ip, response), "DEBUG")

                    interface_ids = set()
                    for interface in interface_response_data:
                        interface_id = interface.get("id")
                        if interface_id:
                            interface_ids.add(interface_id)
                        else:
                            interfaces_without_ids += 1
                            self.log(
                                "Interface record missing UUID identifier for device {0} - skipping interface".format(
                                    ip
                                ),
                                "WARNING"
                            )
                    device_interfaces_map[ip] = interface_ids
                    total_interfaces_discovered += len(interface_ids)

                    if interface_ids:
                        devices_with_interfaces += 1
                        self.log(
                            "Successfully mapped {0} interface identifiers for fabric device {1}".format(
                                len(interface_ids),
                                ip
                            ),
                            "DEBUG"
                        )
                    else:
                        devices_without_interfaces += 1
                        self.log(
                            "No interface identifiers found for fabric device {0} - "
                            "device may have no configured interfaces".format(ip),
                            "WARNING"
                        )
                    if interfaces_without_ids > 0:
                        self.log(
                            "Warning: {0} interface records for device {1} were missing "
                            "UUID identifiers".format(
                                interfaces_without_ids,
                                ip
                            ),
                            "WARNING"
                        )

                except Exception as e:
                    devices_with_errors += 1
                    self.msg = "Failed to retrieve interface information for fabric device {0}: {1}".format(ip, str(e))
                    self.log(self.msg, "ERROR")

        total_fabric_devices = len(filtered_fabric_devices)
        successful_devices = len(device_interfaces_map)

        self.log(
            "Interface identifier retrieval completed - "
            "processed {0}/{1} fabric devices successfully".format(
                successful_devices,
                total_fabric_devices
            ),
            "INFO"
        )

        if devices_with_interfaces > 0:
            self.log("Fabric devices with interface identifiers: {0}".format(devices_with_interfaces), "INFO")

        if devices_without_interfaces > 0:
            self.log("Fabric devices without interface identifiers: {0}".format(devices_without_interfaces), "INFO")

        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during interface retrieval".format(devices_with_errors), "WARNING")

        self.log("Total interface identifiers discovered across all fabric devices: {0}".format(total_interfaces_discovered), "INFO")

        return device_interfaces_map

    def get_connected_device_details_from_interfaces(self, filtered_fabric_devices):
        """
        Discover connected device topology for fabric devices through comprehensive interface-level analysis.

        This method performs extensive connected device discovery by querying each interface of specified
        fabric devices to identify neighboring devices, endpoints, and network attachments. It processes
        interface-level connectivity data to provide complete visibility into fabric device interconnections,
        attached endpoints, and network topology relationships essential for fabric network management
        and troubleshooting operations.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Returns:
            list: Structured connected device topology information in standardized format:
                [
                    {
                        "connected_device_info": [
                            {
                                "device_ip": "192.168.1.1",
                                "connected_device_details": [connected_device_records] or "Error: <message>"
                            },
                            {
                                "device_ip": "192.168.1.2",
                                "connected_device_details": [connected_device_records] or "Error: <message>"
                            }
                        ]
                    }
                ]
        """
        self.log("Discovering connected device topology for fabric device interface inventory", "INFO")
        self.log("Processing connected device discovery for {0} fabric devices".format(len(filtered_fabric_devices)), "DEBUG")

        connected_info_list = []
        devices_with_connections = 0
        devices_without_connections = 0
        devices_with_errors = 0

        self.log("Retrieving interface inventories for fabric devices to enable connected device discovery", "DEBUG")
        device_interfaces_map = self.get_interface_ids_per_device(filtered_fabric_devices)

        if not device_interfaces_map:
            self.log("No interface mappings available for fabric devices - unable to perform connected device discovery", "WARNING")
            return [{"connected_device_info": []}]

        self.log("Processing connected device discovery across {0} fabric devices with interface inventories".format(len(device_interfaces_map)), "DEBUG")

        for index, (ip_address, interface_ids) in enumerate(device_interfaces_map.items()):
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip_address])
            interface_count = len(interface_ids)
            device_id = ip_device_uuid_map[ip_address]
            interfaces_with_connections = 0
            connected_device_details = []

            for interface_id in interface_ids:
                self.log("Querying connected devices for interface {0} on device {1}".format(interface_id, ip_address), "DEBUG")
                try:
                    response = self.dnac._exec(
                        family="devices",
                        function="get_connected_device_detail",
                        params={
                            "device_uuid": device_id,
                            "interface_uuid": interface_id
                        }
                    )
                    interface_connected_data = response.get("response", {})
                    self.log("Received API response for IP {0}, interface {1}: {2}".format(ip_address, interface_id, response), "DEBUG")

                    if interface_connected_data:
                        interfaces_with_connections += 1
                        self.log("Connected device details found for {0}:{1}".format(ip_address, interface_id), "INFO")
                        connected_info_list.append({
                            "device_ip": ip_address,
                            "connected_device_details": [interface_connected_data]
                        })
                    else:
                        self.log("No connected device found for {0}:{1}".format(ip_address, interface_id), "DEBUG")
                        connected_info_list.append({
                            "device_ip": ip_address,
                            "connected_device_details": []
                        })

                except Exception as e:
                    devices_with_errors += 1
                    self.log("Failed to fetch connected device info for {0}: due to {1}".format(ip_address, str(e)), "ERROR")
                    connected_info_list.append({
                        "device_ip": ip_address,
                        "connected_device_details": "Error: {0}".format(e)
                    })

        result = [{"connected_device_info": connected_info_list}]

        total_fabric_devices = len(filtered_fabric_devices)
        successful_devices = len(connected_info_list)

        self.log(
            "Connected device topology discovery completed - "
            "processed {0}/{1} fabric devices with {2} total interfaces".format(
                successful_devices,
                total_fabric_devices,
                interface_count
            ),
            "INFO"
        )
        if devices_with_connections > 0:
            self.log("Fabric devices with connected device discoveries: {0}".format(devices_with_connections), "INFO")

        if devices_without_connections > 0:
            self.log("Fabric devices with no connected devices: {0}".format(devices_without_connections), "INFO")

        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during connected device discovery".format(devices_with_errors), "WARNING")

        self.log("Total connected devices discovered across fabric topology: {0}".format(connected_info_list), "INFO")

        self.log("Completed connected device info retrieval. Total devices processed: {0}".format(len(connected_info_list)), "INFO")
        self.log("Final aggregated connected device info: {0}".format(result), "DEBUG")

        return result

    def get_device_health_info(self, filtered_fabric_devices):
        """
        Retrieve comprehensive health metrics and performance data for specified fabric devices from Catalyst Center.

        This method queries the Catalyst Center device health API to collect detailed health information
        including CPU utilization, memory usage, device scores, and overall health status for each
        provided fabric device. It implements pagination to handle large device inventories and filters
        results to match only the specified fabric devices for targeted health monitoring.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Description:
            - Makes an API call to fetch all network device health data.
            - Filters the returned data to match the list of input fabric device IPs.
            - If health data is found, it's included in the results.
            - If not, adds a fallback message indicating no health info found for that device.

        Returns:
            list: Structured device health information results in standardized format:
                [
                    {
                        "device_health_info": [
                            {
                                "device_ip": "192.168.1.1",
                                "health_details": {health_metrics_object} or {}
                            },
                            {
                                "device_ip": "192.168.1.2",
                                "health_details": {health_metrics_object} or {}
                            }
                        ]
                    }
                ]
        """
        self.log("Retrieving comprehensive health metrics and performance data for fabric device monitoring", "INFO")
        self.log("Processing health information for {0} fabric devices from enterprise device inventory".format(len(filtered_fabric_devices)), "DEBUG")

        health_info_list = []
        processed_device_ips = set()
        health_data_list = []

        self.log("Implementing pagination to retrieve comprehensive device health inventory with 500 device limit per request", "DEBUG")
        try:
            limit = 500
            offset = 1
            total_pages_processed = 0

            while True:
                total_pages_processed += 1
                self.log("Retrieving device health data page {0} with offset: {1}, limit: {2}".format(total_pages_processed, offset, limit), "DEBUG")
                response = self.dnac._exec(
                    family="devices",
                    function="devices",
                    params={'offset': offset, 'limit': limit}
                )
                self.log("Received API response from 'devices' for device: {0}".format(response), "DEBUG")

                page_data = response.get("response", [])
                health_data_list.extend(page_data)

                if len(page_data) < limit:
                    break

                offset += limit
            self.log("Successfully retrieved health data for {0} total devices from Catalyst Center".format(len(health_data_list)), "INFO")

            devices_with_health_data = 0
            devices_without_health_data = 0

            if health_data_list:
                self.log("Filtering device health data to match {0} specified fabric devices".format(len(filtered_fabric_devices)), "DEBUG")
                for device_data in health_data_list:
                    device_ip = device_data.get("ipAddress")
                    if device_ip in filtered_fabric_devices.keys() and device_ip not in processed_device_ips:
                        devices_with_health_data += 1
                        processed_device_ips.add(device_ip)
                        self.log("Health metrics found for fabric device {0}".format(device_ip), "DEBUG")
                        health_info_list.append({
                            "device_ip": device_ip,
                            "health_details": device_data
                        })
                for fabric_device_ip in filtered_fabric_devices.keys():
                    if fabric_device_ip not in processed_device_ips:
                        devices_without_health_data += 1
                        health_info_list.append({
                            "device_ip": fabric_device_ip,
                            "health_details": {}
                        })
                        self.log("No health information found for fabric device {0}".format(fabric_device_ip), "WARNING")
            else:
                self.log("No device health data retrieved from Catalyst Center - all fabric devices will have empty health details", "WARNING")
                for fabric_device_ip in filtered_fabric_devices:
                    devices_without_health_data += 1
                    health_info_list.append({
                        "device_ip": fabric_device_ip,
                        "health_details": {}
                    })

        except Exception as api_err:
            self.msg = "Critical failure during device health information retrieval: {0}".format(str(api_err))
            health_info_list.append({
                "device_ip": fabric_device_ip,
                "health_details": "Error: {0}".format(str(api_err))
            })

        result = [{"device_health_info": health_info_list}]

        self.log("Completed health info retrieval. Total devices processed: {0}".format(len(health_info_list)), "INFO")

        total_fabric_devices = len(filtered_fabric_devices)
        self.log(
            "Device health information retrieval completed - processed {0}/{1} "
            "fabric devices successfully".format(
                len(health_info_list), total_fabric_devices
            ),
            "INFO"
        )
        if devices_with_health_data > 0:
            self.log("Fabric devices with health metrics available: {0}".format(devices_with_health_data), "INFO")

        if devices_without_health_data > 0:
            self.log("Fabric devices without health data: {0}".format(devices_without_health_data), "WARNING")

        self.log("Aggregated device-health info: {0}".format(result), "DEBUG")

        return result

    def get_dev_type(self, ip_address):
        """
        Determine device infrastructure type classification for network device analysis and management.

        This method queries the Catalyst Center device inventory to classify a network device
        as either wired or wireless infrastructure based on its device family attributes.
        The classification is essential for applying appropriate configuration templates,
        monitoring policies, and management workflows specific to device infrastructure types.

        Args:
            ip_address (str): Management IP address of the network device requiring type classification.
                Format: "192.168.1.1"
                Must be a valid, reachable device IP address in Catalyst Center inventory.

        Returns:
            str or None: Device infrastructure type classification:
                - 'wired': Traditional network infrastructure (switches, routers)
                - 'wireless': Wireless infrastructure (controllers, access points)
                - None: Device type cannot be determined, device not found, or API failure
        """
        self.log("Determining device infrastructure type classification for network device management", "INFO")
        self.log("Processing device type determination for IP address: {0}".format(ip_address), "DEBUG")

        try:
            dev_response = self.dnac_apply["exec"](
                family="devices",
                function="get_network_device_by_ip",
                params={"ip_address": ip_address},
            )

            self.log(
                "Received API response from 'get_network_device_by_ip' API for IP {0} is {1}".format(
                    ip_address, str(dev_response)
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
            self.log("Device family identified as '{0}' for infrastructure type classification".format(device_family), "DEBUG")

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
            self.msg = "The Device - {0} not present in the Cisco Catalyst Center.".format(
                ip_address
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

            return None

    def get_ssid_details(self, filtered_fabric_devices):
        """
        Fetch SSID details for fabric-enabled wireless devices from Cisco Catalyst Center.

        For each fabric device identified by IP, this method retrieves SSID (wireless network) configuration
        information if the device is a wireless WLC. It uses the provided IP-to-UUID mapping to query Catalyst Center.

        Each entry in the returned list contains the device's IP and its SSID details, if available.

        The retrieved SSID details include key fields such as:
            - ssid_name (e.g., "Corporate_WiFi")
            - wlan_profile_name
            - security_type
            - interface_mappings
            - authentication method
            - VLAN, etc. (depends on the API structure)

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "ssid_info": [
                            {
                                "device_ip": <str>,
                                "ssid_details": <list of SSID details or error string>
                            },
                        ]
                    }
                ]

        Note:
            SSID details are only applicable to wireless controllers. Non-wireless devices
            are processed but marked as not applicable for SSID configuration retrieval.
        """
        self.log("Retrieving wireless SSID configuration details for fabric wireless infrastructure management", "INFO")
        self.log("Processing SSID configuration for {0} fabric devices requiring wireless network analysis".format(len(filtered_fabric_devices)), "DEBUG")

        all_ssid_info_list = []
        devices_processed = 0
        wireless_devices_found = 0
        non_wireless_devices_found = 0
        devices_with_ssid_data = 0
        devices_without_ssid_data = 0
        devices_with_errors = 0

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])
            device_id = ip_device_uuid_map[ip]
            self.log("Processing SSID configuration for device {0}/{1}: IP: {2}".format(index + 1, len(filtered_fabric_devices), ip), "DEBUG")
            devices_processed += 1
            self.log("Processing SSID configuration analysis for fabric device {0}".format(ip), "DEBUG")
            device_type = self.get_dev_type(ip)
            self.log("Device {0} is identified as '{1}'".format(ip, device_type), "DEBUG")

            if device_type != "wireless":
                non_wireless_devices_found += 1
                self.log(
                    "Skipping SSID retrieval for device {0} - "
                    "device type '{1}' does not support SSID configuration".format(
                        ip,
                        device_type
                    ),
                    "DEBUG"
                )
                all_ssid_info_list.append({
                    "device_ip": ip,
                    "ssid_details": "The device is not wireless; therefore, SSID information retrieval is not applicable."
                })
                continue
            wireless_devices_found += 1
            self.log("Retrieving SSID configuration for wireless controller {0}".format(ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="wireless",
                    function="get_ssid_details_for_specific_wireless_controller",
                    params={"network_device_id": device_id}
                )
                ssid_data = response.get("response", [])
                self.log(
                    "Received API response from 'get_ssid_details_for_specific_wireless_controller' "
                    "for device {0}: {1}".format(ip, response),
                    "DEBUG"
                )
                if ssid_data:
                    devices_with_ssid_data += 1
                    all_ssid_info_list.append({
                        "device_ip": ip,
                        "ssid_details": ssid_data
                    })
                    self.log("SSID configuration found for wireless controller {0} - retrieved {1} SSID records".format(ip, len(ssid_data)), "INFO")
                else:
                    devices_without_ssid_data += 1
                    all_ssid_info_list.append({
                        "device_ip": ip,
                        "ssid_details": "No SSID info found"
                    })
                    self.log(
                        "No SSID configuration found for wireless controller {0} - "
                        "controller may not have configured SSIDs".format(
                            ip
                        ),
                        "DEBUG"
                    )
            except Exception as api_err:
                devices_with_errors += 1
                self.msg = "Failed to retrieve SSID configuration for wireless controller {0}: {1}".format(ip, str(api_err))
                self.log(self.msg, "ERROR")

                all_ssid_info_list.append({
                    "device_ip": ip,
                    "ssid_details": "Error: {0}".format(api_err)
                })

        result = [{"ssid_info": all_ssid_info_list}]

        total_fabric_devices = len(filtered_fabric_devices)
        self.log(
            "Wireless SSID configuration retrieval completed - "
            "processed {0}/{1} fabric devices successfully".format(
                devices_processed,
                total_fabric_devices
            ),
            "INFO"
        )
        if wireless_devices_found > 0:
            self.log("Wireless controllers identified for SSID analysis: {0}".format(wireless_devices_found), "INFO")

        if non_wireless_devices_found > 0:
            self.log("Non-wireless devices skipped for SSID analysis: {0}".format(non_wireless_devices_found), "INFO")

        if devices_with_ssid_data > 0:
            self.log("Wireless controllers with SSID configurations: {0}".format(devices_with_ssid_data), "INFO")

        if devices_without_ssid_data > 0:
            self.log("Wireless controllers without SSID configurations: {0}".format(devices_without_ssid_data), "INFO")

        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during SSID configuration retrieval".format(devices_with_errors), "WARNING")

        self.log("Completed SSID info retrieval. Total devices processed: {0}".format(len(all_ssid_info_list)), "INFO")
        self.log("Final aggregated SSID info: {0}".format(result), "DEBUG")

        return result

    def get_provision_status(self, filtered_fabric_devices):
        """
        Fetch provisioning status details for fabric-enabled devices from Cisco Catalyst Center.

        For each device identified as a fabric device, this method uses its IP-to-UUID mapping
        to retrieve provisioning status information via Catalyst Center APIs.

        Each entry in the returned list contains the device's IP and its provisioning status, if available.

        The retrieved provisioning status may include key fields such as:
            - deviceRole (e.g., Border Node, Edge Node)
            - provisioningState (e.g., provisioned, failed, in-progress)
            - fabricStatus (e.g., enabled, disabled)
            - siteHierarchy
            - fabricDomain

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.
                Each IP address represents a managed device that exists in both the network inventory
                and the fabric site configuration.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "provisioning_status_info": [
                            {
                                "device_ip": <str>,
                                "provisioning_status_details": <list of provisioning status records or error string>
                            },
                        ]
                    }
                ]
        Note:
            Provisioning status provides insights into fabric device readiness, role assignments,
            and current state within the SDA fabric infrastructure for operational monitoring.
        """
        self.log("Retrieving fabric device provisioning status for lifecycle management and health monitoring", "INFO")
        self.log("Processing provisioning status for {0} fabric devices".format(len(filtered_fabric_devices)), "DEBUG")

        all_provision_status_info_list = []
        devices_processed = 0
        devices_with_provisioning_status = 0
        devices_without_provisioning_status = 0
        devices_with_errors = 0

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            devices_processed += 1
            self.log(
                "Processing provision status info for device {0}/{1}: "
                "IP: {2})".format(index + 1, len(filtered_fabric_devices), ip),
                "DEBUG"
            )
            try:
                self.log("Fetching provision status for device: {0}".format(ip), "DEBUG")
                response = self.dnac._exec(
                    family="sda",
                    function="get_provisioned_wired_device",
                    params={"device_management_ip_address": ip}
                )
                provision_data = response
                self.log("Received API response from 'get_provisioned_wired_device' for device {0}: {1}".format(ip, response), "DEBUG")

                if provision_data:
                    devices_with_provisioning_status += 1
                    all_provision_status_info_list.append({
                        "device_ip": ip,
                        "provision_status": provision_data
                    })
                    self.log("Provisioning status found for fabric device {0} - device is provisioned in fabric".format(ip), "INFO")
                else:
                    devices_without_provisioning_status += 1
                    self.log("No provisioning status found for device IP: {0}".format(ip), "DEBUG")
                    all_provision_status_info_list.append({
                        "device_ip": ip,
                        "provision_status": {}
                    })
                    self.log("No provisioning status found for fabric device {0} - device may not be provisioned or not found".format(ip), "DEBUG")

            except Exception as api_err:
                devices_with_errors += 1
                self.msg = "Failed to retrieve provisioning status for fabric device {0}: {1}".format(ip, str(api_err))
                self.log(self.msg, "ERROR")
                all_provision_status_info_list.append({
                    "device_ip": ip,
                    "provision_status": "Error: {0}".format(api_err)
                })

        result = [{"provision_status_info": all_provision_status_info_list}]

        total_fabric_devices = len(filtered_fabric_devices)
        self.log(
            "Fabric device provisioning status retrieval completed - "
            "processed {0}/{1} fabric devices successfully".format(
                devices_processed,
                total_fabric_devices
            ),
            "INFO"
        )
        if devices_with_provisioning_status > 0:
            self.log("Fabric devices with provisioning status indicating successful fabric provisioning: {0}".format(devices_with_provisioning_status), "INFO")

        if devices_without_provisioning_status > 0:
            self.log(
                "Fabric devices without provisioning status indicating potential "
                "provisioning issues: {0}".format(
                    devices_without_provisioning_status
                ),
                "INFO"
            )

        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during provisioning status retrieval".format(devices_with_errors), "WARNING")

        self.log("Aggregated provision status info: {0}".format(result), "DEBUG")
        return result

    def get_port_details(self, filtered_fabric_devices):
        """
        Retrieve SDA port assignment configurations for fabric device onboarding and provisioning analysis.

        This method queries the Catalyst Center SDA API to collect port assignment details for fabric
        devices, providing insights into device onboarding status, port configurations, and SDA
        provisioning workflows essential for fabric lifecycle management.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.

        Returns:
            list: A list with a single dictionary containing port assignment information:
                [
                    {
                        "device_onboarding_info": [
                            {
                                "device_ip": "192.168.1.1",
                                "port_details": [port_assignment_records] or [] or "Error: <error_message>"
                           }
                       ]
                    }
                ]

        Note:
            Port assignment details include interface mappings, VLAN assignments, security group
            configurations, and SDA provisioning status for comprehensive onboarding analysis.
        """
        self.log("Retrieving fabric device onboarding information for lifecycle management and troubleshooting", "INFO")
        self.log("Processing onboarding status for {0} fabric devices across fabric sites".format(len(filtered_fabric_devices)), "DEBUG")

        device_identifier = self.want["fabric_devices"][0].get("device_identifier")

        all_onboarding_info_list = []
        devices_processed = 0
        devices_with_onboarding_data = 0
        devices_without_onboarding_data = 0
        devices_with_errors = 0

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])
            for ip, device_uuid in ip_device_uuid_map.items():
                devices_processed += 1
                self.log(
                    "Processing onboarding device detail for device {0}/{1}: "
                    "IP: {2}".format(index + 1, len(filtered_fabric_devices), ip),
                    "DEBUG"
                )
                try:
                    params = {"fabric_id": fabric_id}

                    if device_identifier or fabric_id:
                        params["network_device_id"] = device_uuid
                        self.log(
                            "Added 'network_device_id' parameter for device {0}: {1}".format(ip, device_uuid),
                            "DEBUG"
                        )
                    response = self.dnac._exec(
                        family="sda",
                        function="get_port_assignments",
                        params=params
                    )
                    onboarding_data = response.get("response", [])
                    self.log(
                        "Received API response from 'get_port_assignments' for device {0}: {1}".format(
                            ip, response
                        ),
                        "DEBUG"
                    )
                    if onboarding_data:
                        devices_with_onboarding_data += 1
                        self.log("Onboarding data found for device IP: {0}".format(ip), "INFO")
                        all_onboarding_info_list.append({
                            "device_ip": ip,
                            "port_assignment_details": onboarding_data
                        })
                    else:
                        devices_without_onboarding_data += 1
                        self.log("No onboarding data found for device IP: {0}".format(ip), "DEBUG")
                        all_onboarding_info_list.append({
                            "device_ip": ip,
                            "port_assignment_details": []
                        })
                        continue

                except Exception as api_err:
                    devices_with_errors += 1
                    self.msg = "Exception occurred while getting port assignment details for device {0}: {1}".format(ip, api_err)
                    all_onboarding_info_list.append({
                        "device_ip": ip,
                        "port_assignment_details": "Error: {0}".format(api_err)
                    })

        result = [{"port_assignment_info": all_onboarding_info_list}]

        total_fabric_devices = len(filtered_fabric_devices)
        self.log(
            "Fabric device onboarding information retrieval completed - "
            "processed {0}/{1} fabric devices successfully".format(
                devices_processed,
                total_fabric_devices
            ),
            "INFO"
        )

        if devices_with_onboarding_data > 0:
            self.log("Fabric devices with onboarding data indicating successful fabric integration: {0}".format(devices_with_onboarding_data), "INFO")

        if devices_without_onboarding_data > 0:
            self.log("Fabric devices without onboarding data indicating potential onboarding issues: {0}".format(devices_without_onboarding_data), "INFO")

        if devices_with_errors > 0:
            self.log("Warning: {0} devices encountered errors during onboarding information retrieval".format(devices_with_errors), "WARNING")

        self.log("Completed onboarding info retrieval. Total devices processed: {0}".format(len(all_onboarding_info_list)), "INFO")
        self.log("Aggregated device-onboarding info: {0}".format(result), "DEBUG")

        return result

    def get_port_channels(self, filtered_fabric_devices):
        """
        Retrieve SDA port channel configurations for fabric device interface aggregation and redundancy analysis.

        This method queries the Catalyst Center SDA API to collect port channel details for fabric
        devices, providing insights into interface aggregation configurations, VLAN assignments, and
        connected device information essential for fabric network redundancy and bandwidth management.

        Args:
            filtered_fabric_devices (dict): Mapping of device management IP addresses to their fabric IDs.
                Contains only devices that have been confirmed as members of the specified fabric site.

        Returns:
            list: A list with a single dictionary containing port channel information:
                [
                    {
                        "device_onboarding_info": [
                            {
                                "device_ip": "192.168.1.1",
                                "port_channel_details": [port_channel_records] or [] or "Error: <error_message>"
                           }
                       ]
                    }
                ]

        """
        self.log("Retrieving fabric device onboarding information for lifecycle management and troubleshooting", "INFO")
        self.log("Processing port channel details for {0} fabric devices across fabric sites".format(len(filtered_fabric_devices)), "DEBUG")

        device_identifier = self.want["fabric_devices"][0].get("device_identifier")

        self.log(
            "Port channel retrieval configuration - device_identifier specified: {0}".format(
                bool(device_identifier)
            ),
            "DEBUG"
        )

        all_port_channel_info_list = []

        statistics = {
            'devices_processed': 0,
            'devices_with_port_channels': 0,
            'devices_without_port_channels': 0,
            'devices_with_errors': 0,
            'total_port_channels_retrieved': 0,
            'total_api_calls': 0
        }

        self.log(
            "Beginning port channel data collection across {0} fabric devices".format(
                len(filtered_fabric_devices)
            ),
            "INFO"
        )

        for index, (ip, fabric_id) in enumerate(filtered_fabric_devices.items()):
            self.log(
                "Processing outer loop for device {0}/{1} - "
                "IP: {2}, Fabric ID: {3}".format(
                    index + 1, len(filtered_fabric_devices), ip, fabric_id
                ),
                "DEBUG"
            )
            ip_device_uuid_map = self.get_device_ids_from_device_ips([ip])

            if not ip_device_uuid_map or ip not in ip_device_uuid_map:
                self.log(
                    "Failed to retrieve device UUID for IP {0} - skipping port channel retrieval".format(
                        ip
                    ),
                    "WARNING"
                )
                statistics['devices_with_errors'] += 1
                all_port_channel_info_list.append({
                    "device_ip": ip,
                    "port_channel_details": "Error: Unable to retrieve device UUID"
                })
                continue

            for ip, device_uuid in ip_device_uuid_map.items():
                statistics['devices_processed'] += 1

                self.log(
                    "Processing inner loop for device {0} - UUID: {1}".format(
                        ip, device_uuid
                    ),
                    "DEBUG"
                )

                self.log(
                    "Initiating port channel data retrieval for fabric device {0}".format(ip),
                    "DEBUG"
                )
                try:
                    params = {"fabric_id": fabric_id}

                    if device_identifier or fabric_id:
                        params["network_device_id"] = device_uuid
                        self.log(
                            "Added 'network_device_id' parameter for device {0}: {1}".format(ip, device_uuid),
                            "DEBUG"
                        )
                    statistics['total_api_calls'] += 1
                    response = self.dnac._exec(
                        family="sda",
                        function="get_port_channels",
                        params=params
                    )

                    if not response or not isinstance(response, dict):
                        self.log(
                            "Invalid API response structure for device {0} - "
                            "expected dict, got: {1}".format(
                                ip, type(response).__name__
                            ),
                            "WARNING"
                        )
                        statistics['devices_with_errors'] += 1
                        all_port_channel_info_list.append({
                            "device_ip": ip,
                            "port_channel_details": "Error: Invalid API response structure"
                        })
                        continue

                    port_channel_data = response.get("response", [])
                    self.log(
                        "Received API response from 'get_port_channels' for device {0}: {1}".format(
                            ip, response
                        ),
                        "DEBUG"
                    )

                    if not isinstance(port_channel_data, list):
                        self.log(
                            "Unexpected response data type for device {0} - "
                            "expected list, got: {1}".format(
                                ip, type(port_channel_data).__name__
                            ),
                            "WARNING"
                        )
                        statistics['devices_with_errors'] += 1
                        all_port_channel_info_list.append({
                            "device_ip": ip,
                            "port_channel_details": "Error: Unexpected response data format"
                        })
                        continue
                    self.log(
                        "Received API response from 'get_port_channels' for device {0}: {1}".format(
                            ip, response
                        ),
                        "DEBUG"
                    )
                    if port_channel_data:
                        statistics['devices_with_port_channels'] += 1
                        statistics['total_port_channels_retrieved'] += len(port_channel_data)

                        self.log(
                            "Port channel configuration found for fabric device {0} - "
                            "retrieved {1} port channel records".format(
                                ip, len(port_channel_data)
                            ),
                            "INFO"
                        )

                        all_port_channel_info_list.append({
                            "device_ip": ip,
                            "port_channel_details": port_channel_data
                        })

                    else:
                        statistics['devices_without_port_channels'] += 1

                        self.log(
                            "No port channel configuration found for fabric device {0} - "
                            "device may not have configured port channels".format(ip),
                            "DEBUG"
                        )

                        all_port_channel_info_list.append({
                            "device_ip": ip,
                            "port_channel_details": []
                        })
                        continue

                except Exception as api_err:
                    devices_with_errors += 1
                    self.msg = "Exception occurred while getting port assignment details for device {0}: {1}".format(ip, api_err)
                    all_port_channel_info_list.append({
                        "device_ip": ip,
                        "port_channel_details": "Error: {0}".format(api_err)
                    })
                    continue

        result = [{"port_channel_info": all_port_channel_info_list}]

        self.log(
            "Port channel configuration retrieval completed - "
            "devices processed: {0}, with port channels: {1}, "
            "without port channels: {2}, with errors: {3}".format(
                statistics['devices_processed'],
                statistics['devices_with_port_channels'],
                statistics['devices_without_port_channels'],
                statistics['devices_with_errors']
            ),
            "INFO"
        )

        self.log(
            "Port channel retrieval statistics - "
            "total API calls: {0}, total port channels retrieved: {1}".format(
                statistics['total_api_calls'],
                statistics['total_port_channels_retrieved']
            ),
            "INFO"
        )

        if statistics['devices_with_port_channels'] > 0:
            self.log(
                "Fabric devices with port channel configurations indicating "
                "successful interface aggregation: {0}".format(
                    statistics['devices_with_port_channels']
                ),
                "INFO"
            )

        if statistics['devices_without_port_channels'] > 0:
            self.log(
                "Fabric devices without port channel configurations: {0}".format(
                    statistics['devices_without_port_channels']
                ),
                "INFO"
            )

        if statistics['devices_with_errors'] > 0:
            self.log(
                "Warning: {0} devices encountered errors during port channel "
                "configuration retrieval - check individual device logs for details".format(
                    statistics['devices_with_errors']
                ),
                "WARNING"
            )

        successful_devices = [
            entry["device_ip"] for entry in all_port_channel_info_list
            if isinstance(entry["port_channel_details"], list) and entry["port_channel_details"]
        ]

        if successful_devices:
            self.log(
                "Successfully retrieved port channel configurations for devices: {0}".format(
                    successful_devices
                ),
                "DEBUG"
            )

        self.log(
            "Port channel configuration retrieval operation completed for {0} "
            "fabric devices with {1} total device entries processed".format(
                len(filtered_fabric_devices), len(all_port_channel_info_list)
            ),
            "INFO"
        )

        self.log(
            "Final aggregated port channel information result: {0}".format(result),
            "DEBUG"
        )

        return result

    def write_device_info_to_file(self, filtered_config):
        """
        Write collected fabric device information to a specified file with comprehensive format support and error handling.

        This method provides robust file output capabilities for fabric device data with support for multiple
        formats (JSON/YAML), file modes (overwrite/append), automatic directory creation, timestamp insertion,
        and comprehensive error handling with detailed logging for operational traceability.

        Parameters:
            export_configuration (dict): Configuration dictionary containing file output specifications.
                Required structure:
                {
                    "output_output_file_info": {
                        "file_path": str,   # Absolute path without extension (required)
                        "file_format": str, # "json" or "yaml" (default: "yaml")
                        "file_mode": str,   # "w" (overwrite) or "a" (append) (default: "w")
                        "timestamp": bool   # Include download timestamp (default: False)
                    },
                    "data": dict            # Optional: specific data to write (uses self.total_response if not provided)
                }

        Returns:
            self: The current instance with updated internal state reflecting the file operation results.

        Raises:
            Exception: Critical errors during file operations, directory creation, or data serialization
                  are logged but do not raise exceptions to maintain operational continuity.
        """
        self.log("Starting Device Information File Export Operation", "INFO")

        output_file_info = filtered_config.get("output_file_info", {})
        self.log("File info received: {0}".format(output_file_info), "DEBUG")

        target_file_path = output_file_info.get("file_path")
        output_file_format = output_file_info.get("file_format", "yaml").lower().strip()
        file_write_mode = output_file_info.get("file_mode", "w").lower().strip()
        include_timestamp_flag = output_file_info.get("timestamp", False)

        if not target_file_path:
            self.log("No file_path specified in output_file_info", "ERROR")
            return self

        full_path_with_ext = "{0}.{1}".format(target_file_path, output_file_format)

        try:
            os.makedirs(os.path.dirname(full_path_with_ext), exist_ok=True)
        except Exception as e:
            self.log("Error creating directories for path: {0} — {1}".format(full_path_with_ext, e), "ERROR")
            return self

        try:
            if isinstance(self.total_response, list):
                new_data = self.total_response[:]
            else:
                new_data = [self.total_response]

            if include_timestamp_flag:
                timestamp_entry = {"Downloaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                new_data_with_timestamp = [timestamp_entry] + new_data
            else:
                new_data_with_timestamp = new_data

            if file_write_mode == "a" and os.path.exists(full_path_with_ext):
                try:
                    with open(full_path_with_ext, "r") as f:
                        if output_file_format == "json":
                            existing_data = json.load(f)
                        else:
                            existing_data = yaml.safe_load(f)

                        if existing_data is None:
                            existing_data = []
                        elif not isinstance(existing_data, list):
                            existing_data = [existing_data]

                except Exception:
                    self.log("Failed to read existing file.", "WARNING")
                    existing_data = []

                data_to_write = existing_data + new_data_with_timestamp

            else:
                data_to_write = new_data_with_timestamp

            with open(full_path_with_ext, "w") as f:
                if output_file_format == "json":
                    json.dump(data_to_write, f, indent=2)
                else:
                    yaml.dump(data_to_write, f, default_flow_style=False)

            self.log("Successfully wrote device info to file: {0}".format(full_path_with_ext), "INFO")

        except Exception as e:
            self.log("Failed to write device info to file {0}: {1}".format(full_path_with_ext, e), "ERROR")

        return self


def main():
    """ main entry point for module execution
    """
    element_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin', 'aliases': ['user']},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': True},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'config_verify': {'type': 'bool', "default": False},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'state': {'default': 'gathered', 'choices': ['gathered']}
                    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=True)
    ccc_fabric_device_info = FabricDevicesInfo(module)
    state = ccc_fabric_device_info.params.get("state")

    current_version = ccc_fabric_device_info.get_ccc_version()
    min_supported_version = "2.3.7.9"

    if ccc_fabric_device_info.compare_dnac_versions(current_version, min_supported_version) < 0:
        ccc_fabric_device_info.status = "failed"
        ccc_fabric_device_info.msg = (
            "The specified version '{0}' does not support the 'fabric device info workflow' feature. "
            "Supported version(s) start from '{1}' onwards.".format(current_version, min_supported_version)
        )
        ccc_fabric_device_info.log(ccc_fabric_device_info.msg, "ERROR")
        ccc_fabric_device_info.check_return_status()

    if state not in ccc_fabric_device_info.supported_states:
        ccc_fabric_device_info.status = "invalid"
        ccc_fabric_device_info.msg = "State {0} is invalid".format(state)
        ccc_fabric_device_info.check_return_status()

    ccc_fabric_device_info.validate_input().check_return_status()

    for config in ccc_fabric_device_info.validated_config:
        ccc_fabric_device_info.reset_values()
        ccc_fabric_device_info.get_want(config)
        ccc_fabric_device_info.get_diff_state_apply[state](config)

    module.exit_json(**ccc_fabric_device_info.result)


if __name__ == '__main__':
    main()
