# !/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ("Karthick S N", "Priyadharshini B", "Madhan Sankaranarayanan")

DOCUMENTATION = r"""
---
module: network_devices_info_workflow_manager
short_description: Gather facts about network devices from Cisco Catalyst Center (facts/info module) using flexible filters.

description:
  - Gathers detailed facts (information) about network devices managed by Cisco Catalyst Center using flexible user-defined filters.
  - Supports filtering by management IP, MAC address, hostname, serial number, software type,
    software version, role, device type, family, and site hierarchy.
  - Allows selection of specific device information types, such as device details, interfaces,
    VLANs, line cards, supervisor cards, POE, module count, connected devices, configuration,
    summary, polling interval, stack, and link mismatch details.
  - Handles query retries, timeouts, and polling intervals for robust data collection.
  - Supports output to a file using the C(output_file_info) option. Output can be JSON or YAML,
    with user-defined file path, file mode (overwrite or append), and optional timestamp.
  - If C(output_file_info) is provided, results are written to the file; otherwise, results are
    returned in the Ansible output.
  - Returns structured results for each requested information type, or an empty list if
    no devices match the filters after all retries.
  - This module is tagged as a facts/info module and is safe to use in check mode.

version_added: "6.31.0"
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Karthick S N (@karthick-s-n)
  - Priyadharshini B (@pbalaku2)
  - Madhan Sankaranarayanan (@madhansansel)

options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center after applying the playbook config.
    type: bool
    default: False
  state:
    description: The desired state of the configuration after module execution.
    type: str
    choices: ["gathered"]
    default: gathered
  config:
    description:
      - List of dictionaries specifying network device query parameters.
      - Each dictionary must contain a C(network_devices) list with at least one unique identifier
        (such as management IP, MAC address, hostname, or serial number) per device.
    type: list
    elements: dict
    required: true
    suboptions:
      network_devices:
        description:
          - Contains filters and configuration for retrieving network devices information.
          - Requires at least one device identification or filtering criterion.
        type: list
        elements: dict
        suboptions:
          site_hierarchy:
            description:
              - Site hierarchy path for filtering devices by location.
            type: str
          device_type:
            description:
              - Device type filter for specific device models.
              - Examples include "Cisco Catalyst 9300 Switch", "Cisco Catalyst 9400 Switch".
            type: str
            choices:
              - Cisco Catalyst 9300 Switch
              - Cisco Catalyst 9400 Switch
              - Cisco Catalyst 9500 Switch
              - Cisco Catalyst C9500-48Y4C Switch
              - Cisco 3800E Unified Access Point
              - Cisco Catalyst 9130AXI Unified Access Point
              - Cisco Catalyst 9800-L-C Wireless Controller
              - Cisco Catalyst 9115AXI Unified Access Point
              - Cisco Catalyst Wireless 9164I Unified Access Point
              - Cisco Wireless 9176D1 Access Point # Additional options may be found in the API documentation.
          device_role:
            description:
              - Device role filter for network function-based filtering.
              - Common roles include ACCESS, DISTRIBUTION, CORE, WAN, WLC, DATA_CENTER.
            type: str
            choices:
              - ACCESS
              - DISTRIBUTION
              - CORE
              - WAN
              - WLC
              - DATA_CENTER # Additional options may be found in the API documentation.
          device_family:
            description:
              - Device family filter for device category-based filtering.
              - Examples include "Switches and Hubs", "Routers", "Wireless Controller".
            type: str
            choices:
              - Switches and Hubs
              - Routers
              - Wireless Controller
              - Unified AP
              - Sensors # Additional options may be found in the API documentation.
          software_version:
            description:
              - Software version filter for specific software releases.
              - Format example "16.12.05", "17.6.1".
            type: str
          os_type:
            description:
              - Operating system type filter for software platform filtering.
              - Common types include IOS-XE, IOS, IOS-XR, NX-OS, ASA, FTD.
            type: str
            choices:
              - IOS-XE
              - IOS
              - IOS-XR
              - NX-OS
              - ASA
              - FTD
              - IOS-XE SD-WAN # Additional options may be found in the API documentation.
          device_identifier:
            description:
              - Optional list of device identification criteria to further filter network devices.
              - Provides granular control over which network devices have their information retrieved.
              - Multiple identification methods can be combined for comprehensive device targeting.
              - Only devices that are both network-enabled and match the identifier criteria will be processed.
              - When multiple identification parameters (ip_address, hostname, serial_number, mac_address) are specified in the same entry,
                they must all refer to the same physical device for proper validation.
              - Use separate device_identifier entries when targeting different devices with different identification methods.
            type: list
            elements: dict
            suboptions:
              ip_address:
                description:
                  - List of management IP addresses to identify specific network devices.
                  - Each IP address must correspond to a managed device in the Cisco Catalyst Center inventory.
                  - Only devices with matching IP addresses will have their information retrieved.
                  - IP addresses must be valid IPv4 addresses in dotted decimal notation.
                type: list
                elements: str
              mac_address:
                description:
                  - List of device MAC addresses to identify specific network devices.
                  - Each MAC address must correspond to a managed device in the Cisco Catalyst Center inventory.
                  - Only devices with matching MAC addresses will have their information retrieved.
                  - MAC addresses should be in standard format (e.g., "aa:bb:cc:dd:ee:ff").
                type: list
                elements: str
              serial_number:
                description:
                  - List of device serial numbers to identify specific network devices.
                  - Each serial number must match exactly as recorded in Cisco Catalyst Center device inventory.
                  - Only devices with matching serial numbers will have their information retrieved.
                  - Serial numbers are case-sensitive and must match the format used by the device manufacturer.
                type: list
                elements: str
              hostname:
                description:
                  - List of device hostnames to identify specific network devices.
                  - Each hostname must match exactly as configured in Cisco Catalyst Center device inventory.
                  - Only devices with matching hostnames will have their information retrieved.
                  - Hostnames are case-sensitive and must match the exact device hostname configuration.
                type: list
                elements: str
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
              - Applied to each individual device lookup filtering operation.
              - Higher retry counts improve reliability in environments with intermittent connectivity or high API load.
              - Total operation time is affected by retries combined with timeout and interval settings.
              - Actual retry attempts may be less than specified if timeout period is reached first.
            type: int
            default: 3
          interval:
            description:
              - Time in seconds to wait between retry attempts for device information retrieval operations.
              - Applied as a delay between failed attempts during device lookup filtering processes.
              - Combined with timeout and retries to determine total operation duration.
              - If (retries * interval) exceeds timeout, retries will continue until timeout is reached.
              - Longer intervals help reduce API load on Cisco Catalyst Center during retry operations.
              - Should be balanced with timeout settings to avoid excessively long operation times.
            type: int
            default: 10
          requested_info:
            description:
              - List of device information types to retrieve.
              - If set to ['all'], retrieves all available information categories.
              - If specific types are listed, only those will be retrieved.
              - If omitted, defaults to all information types.
            type: list
            elements: str
            choices:
              - all # Retrieves all available information of all choices below
              - device_interfaces_by_range_info #Retrieves interface details by specified range
              - device_info #Retrieves basic device details of hostname, model, serial number, OS version
              - interface_info #Retrieves interface details such as status, speed, duplex, and MAC address
              - interface_vlan_info #Retrieves VLAN information for each interface
              - line_card_info #Retrieves line card details for modular devices
              - supervisor_card_info #Retrieves supervisor card details for modular devices
              - poe_info #Retrieves Power over Ethernet (PoE) information for interfaces
              - module_count_info #Retrieves the count of installed modules
              - connected_device_info #Retrieves information about devices connected to the specified device
              - device_config_info #Retrieves the running configuration of the specified device
              - device_summary_info #Retrieves a summary of the specified device's information
              - device_polling_interval_info #Retrieves the polling interval configuration for the specified device
              - device_stack_info #Retrieves stack information for stackable devices
              - device_link_mismatch_info #Retrieves details of link mismatches speed/duplex/VLAN issues
          output_file_info:
            description:
              - Controls file output generation for network device information retrieval results.
              - When provided, saves retrieved device information to the specified file
                along with returning the data in standard Ansible module output.
              - Supports flexible file formatting, writing modes, and optional timestamp inclusion for audit purposes.
              - Enables automated reporting and data archival workflows for network device monitoring operations.
            type: dict
            suboptions:
              file_path:
                description:
                  - Absolute path to the output file without file extension.
                  - File extension is automatically appended based on the selected file format (.json or .yaml).
                  - Directory structure will be created automatically if it does not exist.
                  - Path must be writable by the user executing the Ansible playbook.
                type: str
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
                  - Useful for tracking when network device information was collected in automated workflows.
                  - Timestamp format follows "YYYY-MM-DD HH:MM:SS" standard format.
                type: bool
                default: false

requirements:
    - dnacentersdk >= 2.9.3
    - python >= 3.9.19
notes:
    - This is a facts/info module, it only retrieves information and does not modify any device or configuration.
    - Writing to a local file is for reporting/archival purposes only and does not affect the state of any managed device.
    - Safe to use in check mode.
    - SDK Methods used are
        - devices.Devices.get_device_list
        - devices.Devices.get_device_interface_vlans
        - devices.Devices.get_device_interfaces_by_specified_range
        - devices.Devices.get_linecard_details
        - devices.Devices.inventory_insight_device_link_mismatch
        - devices.Devices.get_stack_details_for_device
        - devices.Devices.get_device_config_by_id
        - devices.Devices.get_polling_interval_by_id
        - devices.Devices.get_supervisor_card_detail
        - devices.Devices.poe_details
        - devices.Devices.get_connected_device_detail
        - devices.Devices.get_interface_info_by_id
        - devices.Devices.get_module_count
        - devices.Devices.get_network_device_by_ip
        - devices.Devices.get_device_summary

    - Paths used are
        - GET/dna/intent/api/v1/network-device
        - GET/dna/intent/api/v1/network-device/{id}/vlan
        - GET/dna/intent/api/v1/interface/network-device/{deviceId}/{startIndex}/{recordsToReturn}
        - GET/dna/intent/api/v1/network-device/{deviceUuid}/line-card
        - GET/dna/intent/api/v1/network-device/insight/{siteId}/device-link
        - GET/dna/intent/api/v1/network-device/{deviceId}/stack
        - GET/dna/intent/api/v1/network-device/{networkDeviceId}/config
        - GET/dna/intent/api/v1/network-device/{id}/collection-schedule
        - GET/dna/intent/api/v1/network-device/{id}/brief
        - GET/dna/intent/api/v1/network-device/{deviceUuid}/supervisor-card
        - GET/dna/intent/api/v1/network-device/{deviceUuid}/poe
        - GET/dna/intent/api/v1/network-device/{deviceUuid}/interface/{interfaceUuid}/neighbor
        - GET/dna/intent/api/v1/interface/network-device/{deviceId}
        - GET/dna/intent/api/v1/network-device/module/count
        - GET/dna/intent/api/v1/network-device/ip-address/{ipAddress}
"""

EXAMPLES = r"""
# 1 Example Playbook to gather specific network device information from Cisco Catalyst Center
---
- name: Get Specific Network devices information on Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Gather detailed facts for specific network devices
      cisco.dnac.network_devices_info_workflow_manager:
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
        state: queried
        config:
          - network_devices:
              - site_hierarchy: Global/USA/SAN JOSE
                device_type: "Cisco Catalyst 9300 Switch"
                device_role: "ACCESS"
                device_family: "Switches and Hubs"
                software_version: "17.12.1"
                os_type: "IOS-XE"
                device_identifier:
                  - ip_address: ["204.1.2.2"]
                  - serial_number: ["FCW2137L0SB"]
                  - hostname: ["SJ-BN-9300.cisco.local"]
                  - mac_address: ["90:88:55:90:26:00"]
                timeout: 60
                retries: 3
                interval: 10
                requested_info:
                  - device_info
                  - interface_info
                  - interface_vlan_info
                  - line_card_info
                  - supervisor_card_info
                  - poe_info
                  - module_count_info
                  - connected_device_info
                  - device_interfaces_by_range_info
                  - device_config_info
                  - device_summary_info
                  - device_polling_interval_info
                  - device_stack_info
                  - device_link_mismatch_info
                output_file_info:
                  file_path: /Users/priyadharshini/Downloads/info
                  file_format: json
                  file_mode: w
                  timestamp: true

# 2 Example Playbook to gather all network device information from Cisco Catalyst Center
- name: Get All Network devices information on Cisco Catalyst Center
  hosts: localhost
  connection: local
  vars_files:
    - "credentials.yml"
  tasks:
    - name: Gather detailed facts for all network devices
      cisco.dnac.network_devices_info_workflow_manager:
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
        state: queried
        config:
          - network_devices:
              - site_hierarchy: Global/USA/SAN JOSE
                device_type: "Cisco Catalyst 9300 Switch"
                device_role: "ACCESS"
                device_family: "Switches and Hubs"
                software_version: "17.12.1"
                os_type: "IOS-XE"
                device_identifier:
                  - ip_address: ["204.1.2.2"]
                  - serial_number: ["FCW2137L0SB"]
                  - hostname: ["SJ-BN-9300.cisco.local"]
                  - mac_address: ["90:88:55:90:26:00"]
                timeout: 60
                retries: 3
                interval: 10
                requested_info:
                  - all
                output_file_info:
                  file_path: /Users/priyadharshini/Downloads/info
                  file_format: json
                  file_mode: w
                  timestamp: true
"""

RETURN = r"""

#Case 1: Successful Retrieval of Device Info
response_device_info:
    description:
      - Device information for network devices, including family, type, software version, serial number, and more.
      - Returned for each device matching the query.
    returned: always
    type: dict
    sample: {
    "response": [{
        "family": "Switches and Hubs",
        "type": "Cisco Catalyst 9300 Switch",
        "lastUpdateTime": 1750896739913,
        "macAddress": "0c:75:bd:42:db:80",
        "deviceSupportLevel": "Supported",
        "softwareType": "IOS-XE",
        "softwareVersion": "17.2.1",
        "serialNumber": "FJC2335S09F",
        "inventoryStatusDetail": "<status><general code=\"SUCCESS\"/></status>",
        "collectionInterval": "Global Default",
        "dnsResolvedManagementAddress": "204.1.2.3",
        "lastManagedResyncReasons": "Periodic",
        "managementState": "Managed",
        "pendingSyncRequestsCount": "0",
        "reasonsForDeviceResync": "Periodic",
        "reasonsForPendingSyncRequests": "",
        "syncRequestedByApp": "",
        "upTime": "63 days, 19:36:43.08",
        "roleSource": "MANUAL",
        "lastUpdated": "2025-06-26 00:12:19",
        "interfaceCount": "0",
        "apManagerInterfaceIp": "",
        "bootDateTime": "2025-04-23 04:36:19",
        "collectionStatus": "Managed",
        "hostname": "test123",
        "locationName": null,
        "managementIpAddress": "204.1.2.3",
        "platformId": "C9300-48UXM",
        "reachabilityFailureReason": "",
        "reachabilityStatus": "Reachable",
        "series": "Cisco Catalyst 9300 Series Switches",
        "snmpContact": "",
        "snmpLocation": "",
        "associatedWlcIp": "",
        "apEthernetMacAddress": null,
        "errorCode": null,
        "errorDescription": null,
        "lastDeviceResyncStartTime": "2025-06-26 00:11:45",
        "lineCardCount": "0",
        "lineCardId": "",
        "managedAtleastOnce": false,
        "memorySize": "NA",
        "tagCount": "0",
        "tunnelUdpPort": null,
        "uptimeSeconds": 5528803,
        "vendor": "Cisco",
        "waasDeviceMode": null,
        "description": "Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT9K_IOSXE),
          Version 17.2.1, RELEASE SOFTWARE (fc4) Technical Support: http://www.cisco.com/techsupport
          Copyright (c) 1986-2020 by Cisco Systems, Inc. Compiled Thu 26-Mar-20 03:29 by mcpre netconf enabled",
        "location": null,
        "role": "ACCESS",
        "instanceUuid": "e62e6405-13e4-4f1b-ae1c-580a28a96a88",
        "instanceTenantId": "66e48af26fe687300375675e",
        "id": "e62e6405-13e4-4f1b-ae1c-580a28a96a88"
    }],
    "version": "string"
    }

#Case 2: Successful Retrieval of Device Interface VLAN info
response_device_interface_vlan_info:
  description: Details of the response containing VLAN information for device interfaces.
  returned: always
  type: dict
  sample: {
    "response": [
      {
        "interfaceName": "GigabitEthernet0/1",
        "ipAddress": "192.168.10.25",
        "mask": 24,
        "networkAddress": "192.168.10.0",
        "numberOfIPs": 254,
        "prefix": "192.168.10.0/24",
        "vlanNumber": 10,
        "vlanType": "Data"
      }
    ],
    "version": "string"
  }

#Case 3: Successful Retrieval of Device Interfaces by Specified Range
response_device_interfaces_range:
  description: Details of the response containing device interface information retrieved by a specified range.
  returned: always
  type: dict
  sample: {
    "response": [
      {
        "addresses": [],
        "adminStatus": "UP",
        "className": null,
        "deviceId": "e62e6405-13e4-4f1b-ae1c-580a28a96a88",
        "duplex": "FullDuplex",
        "ifIndex": "73",
        "interfaceType": "Physical",
        "ipv4Address": null,
        "ipv4Mask": null,
        "isisSupport": "false",
        "lastIncomingPacketTime": null,
        "lastOutgoingPacketTime": 1750896368000,
        "lastUpdated": null,
        "macAddress": "0c:75:bd:42:db:c1",
        "mappedPhysicalInterfaceId": null,
        "mappedPhysicalInterfaceName": null,
        "mediaType": null,
        "mtu": "9100",
        "nativeVlanId": "1",
        "ospfSupport": "false",
        "pid": "C9300-48UXM",
        "portMode": "access",
        "portName": "AppGigabitEthernet1/0/1",
        "portType": "Ethernet Port",
        "serialNo": "FJC2335S09F",
        "series": "Cisco Catalyst 9300 Series Switches",
        "speed": "1000000",
        "status": "up",
        "vlanId": "1",
        "voiceVlan": "",
        "description": "",
        "name": null,
        "instanceUuid": "c9c638b6-4627-4a2e-be25-05f6e487bfcf",
        "instanceTenantId": "66e48af26fe687300375675e",
        "id": "c9c638b6-4627-4a2e-be25-05f6e487bfcf"
      }
    ],
    "version": "string"
  }

#Case 4: Successful Retrieval of Linecard Details
response_linecard_details:
  description: Details of the response containing linecard information for the device.
  returned: always
  type: dict
  sample: {
    "response": [
      {
        "serialno": "SN123456789",
        "partno": "PN987654321",
        "switchno": "SW-001-A1",
        "slotno": "Slot-04"
      }
    ],
    "version": "string"
  }

#Case 5: Successful Retrieval of Inventory Insight Device Link Mismatch API
response_inventory_insight_link_mismatch:
  description: Details of the response containing device link mismatch information from Inventory Insight API.
  returned: always
  type: dict
  sample: {
    "response": [
      {
        "endPortAllowedVlanIds": "10,20,30",
        "endPortNativeVlanId": "10",
        "startPortAllowedVlanIds": "10,20,30",
        "startPortNativeVlanId": "10",
        "linkStatus": "up",
        "endDeviceHostName": "switch-nyc-01",
        "endDeviceId": "device-1001",
        "endDeviceIpAddress": "192.168.1.10",
        "endPortAddress": "GigabitEthernet1/0/24",
        "endPortDuplex": "full",
        "endPortId": "endport-1001",
        "endPortMask": "255.255.255.0",
        "endPortName": "Gi1/0/24",
        "endPortPepId": "pep-ep-1001",
        "endPortSpeed": "1000Mbps",
        "startDeviceHostName": "router-dc-01",
        "startDeviceId": "device-2001",
        "startDeviceIpAddress": "192.168.1.1",
        "startPortAddress": "GigabitEthernet0/1",
        "startPortDuplex": "full",
        "startPortId": "startport-2001",
        "startPortMask": "255.255.255.0",
        "startPortName": "Gi0/1",
        "startPortPepId": "pep-sp-2001",
        "startPortSpeed": "1000Mbps",
        "lastUpdated": "2025-06-26T10:15:00Z",
        "numUpdates": 15,
        "avgUpdateFrequency": 4.0,
        "type": "ethernet-link",
        "instanceUuid": "123e4567-e89b-12d3-a456-426614174000",
        "instanceTenantId": "tenant-xyz123"
      }
    ],
    "version": "string"
  }

#Case 6: Successful Retrieval of Stack Details for Device
response_stack_details:
  description: Details of the response containing stack information for the device.
  returned: always
  type: dict
  sample: {
    "response": {
        "device_stack_info": [
        {
            "deviceId": "e62e6405-13e4-4f1b-ae1c-580a28a96a88",
            "stackSwitchInfo": [
                {
                    "hwPriority": 0,
                    "macAddress": "0c:75:bd:42:db:80",
                    "numNextReload": 1,
                    "role": "ACTIVE",
                    "softwareImage": "17.02.01",
                    "stackMemberNumber": 1,
                    "state": "READY",
                    "switchPriority": 1,
                    "entPhysicalIndex": "1000",
                    "serialNumber": "FJC2335S09F",
                    "platformId": "C9300-48UXM"
                }
            ],
            "stackPortInfo": [
                {
                    "isSynchOk": "Yes",
                    "name": "StackSub-St1-1",
                    "switchPort": "1/1",
                    "neighborPort": "NONE",
                    "nrLinkOkChanges": 0,
                    "stackCableLengthInfo": "NO_CABLE",
                    "stackPortOperStatusInfo": "DOWN",
                    "linkActive": false,
                    "linkOk": false
                },
                {
                    "isSynchOk": "Yes",
                    "name": "StackSub-St1-2",
                    "switchPort": "1/2",
                    "neighborPort": "NONE",
                    "nrLinkOkChanges": 0,
                    "stackCableLengthInfo": "NO_CABLE",
                    "stackPortOperStatusInfo": "DOWN",
                    "linkActive": false,
                    "linkOk": false
                }
            ],
            "svlSwitchInfo": null
        }
    ]
        },
    "version": "string"
  }

#Case 7: Successful Retrieval of Device Config
response_device_config:
  description: Details of the response containing the device configuration as a string.
  returned: always
  type: dict
  sample: {
    "response": "Building Configuration Operation Successful",
    "version": "string"
  }

#Case 8: Successful Retrieval of Polling Interval
response_polling_interval:
  description: Details of the response containing the polling interval value.
  returned: always
  type: dict
  sample: {
    "device_polling_interval_info": [
                86400
            ],
    "version": "string"
  }

#Case 9: Successful Retrieval of Device Summary
response_device_summary:
  description: Details of the response containing a summary of the device.
  returned: always
  type: dict
  sample: {
    "response": {
        "id": "e62e6405-13e4-4f1b-ae1c-580a28a96a88",
        "role": "ACCESS",
        "roleSource": "MANUAL"
    },
    "version": "string"
  }

#Case 10: Successful Retrieval of Supervisor Card Detail
response_supervisor_card_detail:
  description: Details of the response containing supervisor card information for the device.
  returned: always
  type: dict
  sample: {
    "response": [
      {
        "serialno": "SN1234567890",
        "partno": "PN9876543210",
        "switchno": "SW-01",
        "slotno": "3"
      }
    ],
    "version": "string"
  }

#Case 11: Successful Retrieval of POE Details
response_poe_details:
  description: Details of the response containing Power over Ethernet (POE) statistics.
  returned: always
  type: dict
  sample: {
    "response": {
        "powerAllocated": "525",
        "powerConsumed": "0",
        "powerRemaining": "525"
    },
    "version": "string"
  }

#Case 12: Successful Retrieval of Connected Device Detail
response_connected_device_detail:
  description: Details of the response containing information about a connected neighbor device.
  returned: always
  type: dict
  sample: {
    "response": {
        "neighborDevice": "DC-T-9300",
        "neighborPort": "TenGigabitEthernet1/1/8",
        "capabilities": [
            "IGMP_CONDITIONAL_FILTERING",
            "ROUTER",
            "SWITCH"
        ]
    },
    "version": "string"
  }

#Case 13: Successful Retrieval of Interface Info
response_interface_info:
  description: Details of the response containing interface information for a device.
  returned: always
  type: dict
  sample: {
    "response": [
      {
        "addresses": [],
        "adminStatus": "UP",
        "className": null,
        "deviceId": "e62e6405-13e4-4f1b-ae1c-580a28a96a88",
        "duplex": "FullDuplex",
        "ifIndex": "73",
        "interfaceType": "Physical",
        "ipv4Address": null,
        "ipv4Mask": null,
        "isisSupport": "false",
        "lastIncomingPacketTime": null,
        "lastOutgoingPacketTime": 1750896368000,
        "lastUpdated": null,
        "macAddress": "0c:75:bd:42:db:c1",
        "mappedPhysicalInterfaceId": null,
        "mappedPhysicalInterfaceName": null,
        "mediaType": null,
        "mtu": "9100",
        "nativeVlanId": "1",
        "ospfSupport": "false",
        "pid": "C9300-48UXM",
        "portMode": "access",
        "portName": "AppGigabitEthernet1/0/1",
        "portType": "Ethernet Port",
        "serialNo": "FJC2335S09F",
        "series": "Cisco Catalyst 9300 Series Switches",
        "speed": "1000000",
        "status": "up",
        "vlanId": "1",
        "voiceVlan": "",
        "description": "",
        "name": null,
        "instanceUuid": "c9c638b6-4627-4a2e-be25-05f6e487bfcf",
        "instanceTenantId": "66e48af26fe687300375675e",
        "id": "c9c638b6-4627-4a2e-be25-05f6e487bfcf"
      }
    ],
    "version": "string"
  }

#Case 14: Successful Retrieval of Module Count
response_module_count:
  description: Details of the response containing the count of modules.
  returned: always
  type: dict
  sample: {
    "module_count_info": [
                3
            ],
    "version": "string"
  }

#Case 15: Successful Retrieval of Network Device by IP
response_network_device_by_ip:
  description: Details of the response containing network device information retrieved by IP address.
  returned: always
  type: dict
  sample: {
    "response": {
        "apManagerInterfaceIp": "10.10.10.15",
        "associatedWlcIp": "10.10.10.1",
        "bootDateTime": "2025-06-20T09:30:00Z",
        "collectionInterval": "300",
        "collectionStatus": "success",
        "errorCode": "0",
        "errorDescription": "",
        "family": "Cisco Aironet",
        "hostname": "AP-Office-23",
        "id": "ap-12345",
        "instanceTenantId": "tenant-001",
        "instanceUuid": "a1b2c3d4-e5f6-7890-1234-56789abcdef0",
        "interfaceCount": "6",
        "inventoryStatusDetail": "Active",
        "lastUpdateTime": 1687700000,
        "lastUpdated": "2025-06-25T10:00:00Z",
        "lineCardCount": "1",
        "lineCardId": "lc-001",
        "location": "Building 1, Floor 2",
        "locationName": "HQ Floor 2",
        "macAddress": "00:1A:2B:3C:4D:5E",
        "managementIpAddress": "10.10.10.15",
        "memorySize": "2048MB",
        "platformId": "AIR-AP2800",
        "reachabilityFailureReason": "",
        "reachabilityStatus": "reachable",
        "role": "Access Point",
        "roleSource": "auto-discovery",
        "serialNumber": "FTX12345678",
        "series": "2800",
        "snmpContact": "admin@example.com",
        "snmpLocation": "Data Center Rack 5",
        "softwareType": "IOS-XE",
        "softwareVersion": "17.6.1",
        "tagCount": "4",
        "tunnelUdpPort": "4500",
        "type": "wireless-ap",
        "upTime": "3 days, 5 hours",
        "waasDeviceMode": "N/A",
        "dnsResolvedManagementAddress": "ap-office23.example.com",
        "apEthernetMacAddress": "00:1A:2B:3C:4D:5E",
        "vendor": "Cisco",
        "reasonsForPendingSyncRequests": "",
        "pendingSyncRequestsCount": "0",
        "reasonsForDeviceResync": "",
        "lastDeviceResyncStartTime": "2025-06-24T08:00:00Z",
        "uptimeSeconds": 277200,
        "managedAtleastOnce": true,
        "deviceSupportLevel": "Gold",
        "managementState": "Managed",
        "description": "Office wireless access point on Floor 2"
    },
    "version": "string"
  }
"""


from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
)
from ansible.module_utils.basic import AnsibleModule
import json
import time
import os
import ipaddress
try:
    import yaml
except ImportError:
    yaml = None
from datetime import datetime

from ansible_collections.cisco.dnac.plugins.module_utils.validation import (
    validate_list_of_dicts,)


class NetworkDevicesInfo(DnacBase):
    """Class containing member attributes for network_devices_info_workflow_manager module"""
    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ['gathered']

    def validate_input(self):
        """
        Validate the playbook configuration for device information retrieval and data integrity.

        This method performs strict type checks, required field validation, duplicate detection,
        and default value population to ensure the playbook configuration is correctly structured
        and ready for further processing or API interactions.

        It validates that:
        - The configuration exists and is a list.
        - Each item in the list conforms to the expected schema defined in `config_spec`.
        - Default values are applied where necessary.
        - Invalid Args are detected and reported.

        Args:
            self (object): An instance of the class handling Cisco Catalyst Center operations,
                        containing the `config` attribute to validate.

        Returns:
            self: The current instance with updated attributes:
                - self.msg (str): Status message indicating validation success or failure.
                - self.status (str): Either "success" or "failed", based on validation result.
                - self.validated_config (list): A sanitized, validated version of the playbook configuration,
                                                if validation succeeds.
    """
        self.log("Initiating comprehensive input validation for network devices information workflow configuration", "INFO")

        config_spec = {
            "network_devices": {
                "type": "list",
                "elements": "dict",
                "site_hierarchy": {
                    "type": "str",
                    "required": False
                },
                "device_type": {
                    "type": "str",
                    "required": False
                },
                "device_role": {
                    "type": "str",
                    "required": False,
                },
                "device_family": {
                    "type": "str",
                    "required": False
                },
                "software_version": {
                    "type": "str",
                    "required": False
                },
                "os_type": {
                    "type": "str",
                    "required": False,
                },
                "device_identifier": {
                    "type": "list",
                    "elements": "dict",
                    "ip_address": {
                        "type": "list",
                        "elements": "str",
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
                    },
                    "mac_address": {
                        "type": "list",
                        "elements": "str",
                        "required": False
                    }
                },
                "timeout": {
                    "type": "int",
                    "default": 120
                },
                "retries": {
                    "type": "int",
                    "default": 3
                },
                "interval": {
                    "type": "int",
                    "default": 10
                },
                "requested_info": {
                    "type": "list",
                    "elements": "str",
                    "allowed_values": [
                        "device_info",
                        "interface_info",
                        "interface_vlan_info",
                        "line_card_info",
                        "supervisor_card_info",
                        "poe_info",
                        "module_count_info",
                        "connected_device_info",
                        "device_interfaces_by_range_info",
                        "device_config_info",
                        "device_summary_info",
                        "device_polling_interval_info",
                        "device_stack_info",
                        "device_link_mismatch_info"
                    ]
                },
                "output_file_info": {
                    "type": "dict",
                    "file_path": {
                        "type": "str"
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
                self.msg = "Network devices configuration validation failed with invalid Args: {0}".format(
                    invalid_params
                )
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            self.validated_config = valid_config

            self.log("Network devices configuration validation completed successfully", "INFO")
            self.log(
                "Validated {0} network device configuration section(s) for workflow processing".format(
                    (valid_config)
                ),
                "DEBUG"
            )
            return self

        except Exception as validation_exception:
            self.msg = "Network devices configuration validation encountered an error: {0}".format(
                str(validation_exception)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def get_want(self, config):
        """
        Extracts and validates the desired network device information workflow state from playbook configuration.

        This method processes the playbook configuration to determine the desired state for network device
        information retrieval operations. It performs comprehensive validation of all configuration parameters,
        validates device identification criteria, information type requests, and file output settings to ensure
        the configuration is properly structured and meets all operational requirements before proceeding
        with device discovery and information retrieval workflows.

        Args:
            config (dict): Network device information workflow configuration dictionary.

        Returns:
            self: The current instance with updated attributes:
                - self.want: Validated configuration dictionary ready for processing
                - self.status: Validation status ("success" or "failed")
                - self.msg: Status message describing validation results
        """
        self.log("Extracting desired network devices information workflow state from playbook configuration", "DEBUG")
        self.log("Processing configuration sections for comprehensive workflow validation", "DEBUG")

        self.total_response = []

        want = {}
        network_devices = config.get("network_devices")

        want["network_devices"] = config.get("network_devices")

        device_keys = [
            "site_hierarchy", "device_type", "device_role",
            "device_family", "software_version", "os_type",
            "device_identifier"
        ]
        allowed_return_values = {
            "all",
            "device_info",
            "interface_info",
            "interface_vlan_info",
            "line_card_info",
            "supervisor_card_info",
            "poe_info",
            "module_count_info",
            "connected_device_info",
            "device_interfaces_by_range_info",
            "device_config_info",
            "device_summary_info",
            "device_polling_interval_info",
            "device_stack_info",
            "device_link_mismatch_info"
        }
        allowed_device_identifier_filters = {"ip_address", "hostname", "serial_number", "ip_address_range", "mac_address"}
        allowed_field = {
            "site_hierarchy", "device_type", "device_role", "device_family", "software_version", "os_type",
            "device_identifier", "timeout", "retries", "interval", "requested_info", "output_file_info"
        }
        allowed_output_file_info_keys = {"file_path", "file_format", "file_mode", "timestamp"}
        allowed_file_formats = {"json", "yaml"}
        allowed_file_modes = {"a", "w"}

        for config in self.config:
            if "network_devices" not in config:
                self.msg = "'network_devices' key is missing in the config block"
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        for idx, device in enumerate(config["network_devices"]):
            self.log("Processing device entry {0}: {1}".format(idx + 1, device), "DEBUG")
            for key in device:
                if key not in allowed_field:
                    self.msg = "'{0}' is not a valid key in network device entry. Allowed keys are: {1}".format(
                        key, ", ".join(sorted(allowed_field))
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if not any(device.get(key) for key in device_keys):
                self.log(
                    "Device index {0} missing required identification keys: {1}".format(
                        idx + 1, device_keys
                    ),
                    "ERROR"
                )
                self.msg = (
                    "Each network device must contain at least one of the following keys: {0}."
                    .format(", ".join(device_keys))
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
        self.log("Network devices information workflow desired state extraction completed successfully", "DEBUG")
        return self

    def get_diff_gathered(self, config):
        """
        Processes the device configuration and retrieves requested information for each network device.

        Args:
            self (object): An instance of the class interacting with Cisco Catalyst Center APIs.
            config (dict): A dictionary containing the playbook configuration.

        Returns:
            self: The current instance with the 'msg' and 'total_response' attributes populated
                based on the API responses for the requested device information.

        Description:
            This method retrieves information of for a list of network devices
            based on filters provided in the playbook. For each device in the
            input, it performs the following:

            - Determines which categories of information are requested, including:
                - device_info
                - interface_info
                - interface_vlan_info
                - line_card_info
                - supervisor_card_info
                - poe_info
                - module_count_info
                - connected_device_info
                - device_interfaces_by_range_info
                - device_config_info
                - device_summary_info
                - device_polling_interval_info
                - device_stack_info
                - device_link_mismatch_info
        """
        self.log("Starting device info retrieval for all device entries", "INFO")

        network_devices = config.get("network_devices", [])
        combined_data = {}

        for device_cfg in network_devices:
            self.log("Processing device configuration entry with Args: {0}".format(list(device_cfg.keys())), "DEBUG")
            filtered_config = {}
            for field_name, field_value in device_cfg.items():
                if field_name != "requested_info":
                    filtered_config[field_name] = field_value

            self.log("Filtered config (excluding requested_info): {0}".format(filtered_config), "DEBUG")
            self.log("Extracted device identification Args: {0}".format(list(filtered_config.keys())), "DEBUG")
            requested_info = device_cfg.get("requested_info", [])

            if not requested_info:
                all_info_requested = True
                self.log("No specific information types requested - retrieving all available information categories", "DEBUG")
            else:
                all_info_requested = "all" in requested_info
                self.log("Specific information types requested: {0}".format(requested_info), "DEBUG")

            device_info = all_info_requested or "device_info" in requested_info
            interface_info = all_info_requested or "interface_info" in requested_info
            interface_vlan_info = all_info_requested or "interface_vlan_info" in requested_info
            linecard_info = all_info_requested or "line_card_info" in requested_info
            supervisor_card_info = all_info_requested or "supervisor_card_info" in requested_info
            poe_info = all_info_requested or "poe_info" in requested_info
            module_count_info = all_info_requested or "module_count_info" in requested_info
            connected_device_info = all_info_requested or "connected_device_info" in requested_info
            device_interfaces_by_range_info = all_info_requested or "device_interfaces_by_range_info" in requested_info
            device_config_info = all_info_requested or "device_config_info" in requested_info
            device_summary_info = all_info_requested or "device_summary_info" in requested_info
            device_polling_interval_info = all_info_requested or "device_polling_interval_info" in requested_info
            device_stack_info = all_info_requested or "device_stack_info" in requested_info
            device_link_mismatch_info = all_info_requested or "device_link_mismatch_info" in requested_info

            self.log(
                """
                Requested:
                    device_info:                 {0}
                    interface_info:              {1}
                    interface_vlan_info:         {2}
                    line_card_info:              {3}
                    supervisor_card_info:        {4}
                    poe_info:                    {5}
                    module_count_info:           {6}
                    connected_device_info:       {7}
                    device_interfaces_by_range_info: {8}
                    device_config_info:          {9}
                    device_summary_info:         {10}
                    device_polling_interval_info:{11}
                    device_stack_info:           {12}
                    device_link_mismatch_info:   {13}
                """.format(
                    device_info,
                    interface_info,
                    interface_vlan_info,
                    linecard_info,
                    supervisor_card_info,
                    poe_info,
                    module_count_info,
                    connected_device_info,
                    device_interfaces_by_range_info,
                    device_config_info,
                    device_summary_info,
                    device_polling_interval_info,
                    device_stack_info,
                    device_link_mismatch_info
                ),
                "DEBUG"
            )

            device_ids = self.filter_network_devices(filtered_config)
            self.log("Filtered network devices after applying all the provided filters: {0}".format(device_ids), "DEBUG")

            if not device_ids:
                self.msg = "No network devices found for the given filters."
                self.total_response.append(self.msg)
                break
            else:
                self.total_response.append("The network devices filtered from the provided filters are: {0}".format(list(device_ids.keys())))

            if device_info:
                self.log("Retrieving device details for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                device_info_result = self.get_device_info(device_ids)
                self.total_response.append(device_info_result)
                combined_data["device_info"] = device_info_result

            if interface_info:
                self.log("Retrieving interface details for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                interface_info_result = self.get_interface_info(device_ids)
                self.total_response.append(interface_info_result)
                combined_data["interface_info"] = interface_info_result

            if interface_vlan_info:
                self.log("Retrieving VLAN details for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                interface_vlan_info_result = self.get_interface_vlan_info(device_ids)
                self.total_response.append(interface_vlan_info_result)
                combined_data["interface_vlan_info"] = interface_vlan_info_result

            if linecard_info:
                self.log("Retrieving linecard details for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                linecard_info_result = self.get_linecard_info(device_ids)
                self.total_response.append(linecard_info_result)
                combined_data["linecard_info"] = linecard_info_result

            if supervisor_card_info:
                self.log("Retrieving Supervisor card details for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                supervisor_card_info_result = self.get_supervisor_card_info(device_ids)
                self.total_response.append(supervisor_card_info_result)
                combined_data["supervisor_card_info"] = supervisor_card_info_result

            if poe_info:
                self.log("Retrieving PoE details for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                poe_info_result = self.get_poe_info(device_ids)
                self.total_response.append(poe_info_result)
                combined_data["poe_info"] = poe_info_result

            if module_count_info:
                self.log("Retrieving module count details for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                module_count_info_result = self.get_module_count_info(device_ids)
                self.total_response.append(module_count_info_result)
                combined_data["module_count_info"] = module_count_info_result

            if connected_device_info:
                self.log("Retrieving connected neighbor device information via interface for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                connected_devices_result = self.get_connected_device_details_from_interfaces(device_ids)
                self.total_response.append(connected_devices_result)
                combined_data["connected_devices_info"] = connected_devices_result

            if device_interfaces_by_range_info:
                self.log("Retrieving interface information for specified range for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                device_interfaces_by_range_info_result = self.get_interfaces_by_specified_range(device_ids)
                self.total_response.append(device_interfaces_by_range_info_result)
                combined_data["device_interfaces_by_range_info"] = device_interfaces_by_range_info_result

            if device_config_info:
                self.log("Retrieving device configuration information for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                device_config_info_result = self.get_device_config_info(device_ids)
                self.total_response.append(device_config_info_result)
                combined_data["device_config_info"] = device_config_info_result

            if device_summary_info:
                self.log("Retrieving device summary information for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                device_summary_info_result = self.get_device_summary_info(device_ids)
                self.total_response.append(device_summary_info_result)
                combined_data["device_summary_info"] = device_summary_info_result

            if device_polling_interval_info:
                self.log("Retrieving device polling interval information for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                device_polling_interval_info_result = self.get_device_polling_interval_info(device_ids)
                self.total_response.append(device_polling_interval_info_result)
                combined_data["device_polling_interval_info"] = device_polling_interval_info_result

            if device_stack_info:
                self.log("Retrieving device stack information for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                device_stack_info_result = self.get_device_stack_info(device_ids)
                self.total_response.append(device_stack_info_result)
                combined_data["device_stack_info"] = device_stack_info_result

            if device_link_mismatch_info:
                site_hierarchy = device_cfg.get("site_hierarchy")
                site_exists, site_id = self.get_site_id(site_hierarchy)
                if not site_hierarchy:
                    self.msg = "For 'device_link_mismatch_info', 'site_hierarchy' must be provided."
                    self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                else:
                    self.log("Retrieving device link mismatch details for network devices: {0}".format(list(device_ids.keys())), "DEBUG")
                    device_link_mismatch_info_result = self.get_device_link_mismatch_info(site_id, device_ids)
                    self.total_response.append(device_link_mismatch_info_result)
                    combined_data["device_link_mismatch_info"] = device_link_mismatch_info_result

        if config.get("network_devices"):
            output_file_info = config["network_devices"][0].get("output_file_info")

        if output_file_info:
            self.log("Processing file output configuration for network device information export: {0}".format(output_file_info), "INFO")
            self.write_device_info_to_file({"output_file_info": output_file_info})
            self.log("Network device information successfully written to output file", "INFO")

        if self.total_response:
            self.log("Network device information retrieval workflow completed successfully with {0} response entries".format(len(network_devices)), "INFO")
            self.msg = self.total_response
            self.set_operation_result("success", False, self.msg, "INFO")
        return self

    def get_device_id(self, filtered_config):
        """
        Retrieves device UUIDs from Cisco Catalyst Center based on device identifier Args.

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
            filtered_config (dict): Configuration dictionary containing device identification Args.

        Returns:
            dict or None: A dictionary mapping device IP addresses to their UUIDs for managed devices.
                        Returns None if no device_identifier section is found in configuration.
        """
        self.log("Starting device UUID mapping retrieval from 'device_identifier' entries", "INFO")

        self.log(
            "Processing filtered configuration with parameters: {0}".format(
                self.pprint(filtered_config)
            ),
            "DEBUG"
        )

        if not isinstance(filtered_config, dict):
            self.log(
                "Invalid filtered_config parameter - expected dict, got: {0}".format(
                    type(filtered_config).__name__
                ),
                "ERROR"
            )
            self.msg = "filtered_config parameter must be a valid dictionary"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

        device_identifiers = filtered_config.get("device_identifier", [])

        if not isinstance(device_identifiers, list):
            self.log(
                "Invalid device_identifiers format - expected list, got: {0}".format(
                    type(device_identifiers).__name__
                ),
                "ERROR"
            )
            self.msg = "device_identifier must be a list of identification criteria"
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

        if not device_identifiers:
            self.msg = "No 'device_identifier' section found in configuration. Skipping device ID retrieval."
            self.log(self.msg, "WARNING")
            return None

        param_key_map = {
            "ip_address": "managementIpAddress",
            "serial_number": "serialNumber",
            "hostname": "hostname",
            "mac_address": "macAddress",
        }

        ip_uuid_map = {}
        timeout = filtered_config.get("timeout", 120)
        retries = filtered_config.get("retries", 3)
        interval = filtered_config.get("interval", 10)

        self.log(
            "Using retry configuration - timeout: {0}s, retries: {1}, interval: {2}s".format(
                timeout, retries, interval
            ),
            "DEBUG"
        )

        is_and_logic = (
            len(device_identifiers) == 1 and
            len(device_identifiers[0].keys()) > 1
        )
        logic_type = "AND" if is_and_logic else "OR"
        self.log("Detected device_identifier logic type: {0} for {1} identifier groups".format(
            logic_type, len(device_identifiers)), "DEBUG")

        if is_and_logic:
            identifier = device_identifiers[0]
            self.log("Processing AND logic for identifiers: {0}".format(identifier), "DEBUG")

            combined_devices = None
            for key_index, (key, values) in enumerate(identifier.items(), start=1):
                self.log(
                    "Processing AND criteria {0}/{1} - key: {2}, values: {3}".format(
                        key_index, len(identifier), key, values
                    ),
                    "DEBUG"
                )
                if not values:
                    self.log(
                        "Skipping empty values for key: {0}".format(key),
                        "DEBUG"
                    )
                    continue
                if not isinstance(values, list):
                    values = [values]
                    self.log(
                        "Converted single value to list for key {0}: {1}".format(key, values),
                        "DEBUG"
                    )

                expanded_values = []

                for value in values:
                    if key == "ip_address_range":
                        self.log(
                            "Expanding IP address range: {0}".format(value),
                            "DEBUG"
                        )
                        try:
                            start_ip, end_ip = value.split("-")
                            start = ipaddress.IPv4Address(start_ip.strip())
                            end = ipaddress.IPv4Address(end_ip.strip())
                            range_ips = [
                                str(ipaddress.IPv4Address(i))
                                for i in range(int(start), int(end) + 1)
                            ]
                            expanded_values.extend(range_ips)
                            self.log(
                                "Expanded IP range '{0}' into {1} individual IP addresses".format(
                                    value, len(range_ips)
                                ),
                                "DEBUG"
                            )
                        except Exception as e:
                            self.log(
                                "Failed to expand IP range '{0}': {1}".format(value, str(e)),
                                "ERROR"
                            )
                            continue
                    else:
                        expanded_values.append(value)
                        self.log("Added individual value '{0}' to expanded list (not an IP range)".format(value), "DEBUG")

                param_key = param_key_map.get(key)
                matched_devices = []

                missing_ips = []

                for value_index, ip_or_value in enumerate(expanded_values, start=1):
                    self.log(
                        "Processing OR value {0}/{1} for key '{2}': {3}".format(
                            value_index, len(expanded_values), key, ip_or_value
                        ),
                        "DEBUG"
                    )
                    params = {param_key_map.get(key, "managementIpAddress"): ip_or_value}
                    devices = self.execute_device_lookup_with_retry(params, key, ip_or_value, timeout, retries, interval)

                    if devices:
                        matched_devices.extend(devices)
                    else:
                        missing_ips.append(ip_or_value)
                        self.log("Device not found in inventory for identifier '{0}' - adding to missing list".format(ip_or_value), "DEBUG")

                if missing_ips:
                    display_value = ", ".join(missing_ips)
                    self.msg = (
                        "No devices found for the following identifiers {0}: {1}. "
                        "Device(s) may not be present in Catalyst Center inventory."
                    ).format(key, display_value)
                    self.set_operation_result("success", False, self.msg, "INFO")
                    if self.msg not in self.total_response:
                        self.total_response.append(self.msg)

                if combined_devices is None:
                    combined_devices = matched_devices
                    self.log(
                        "Initialized combined devices with {0} devices from first key: {1}".format(
                            len(matched_devices), key
                        ),
                        "DEBUG"
                    )
                previous_count = len(combined_devices)
                combined_devices = [
                    device for device in combined_devices
                    if any(
                        device.get("instanceUuid") == matched_device.get("instanceUuid")
                        for matched_device in matched_devices
                    )
                ]
                self.log(
                    "Applied AND logic intersection - reduced from {0} to {1} devices".format(
                        previous_count, len(combined_devices)
                    ),
                    "DEBUG"
                )

            # Process final results for AND logic
            if combined_devices:
                self.log(
                    "AND logic completed successfully - found {0} devices matching all criteria".format(
                        len(combined_devices)
                    ),
                    "INFO"
                )

                for device in combined_devices:
                    uuid = device.get("instanceUuid")
                    ip = device.get("managementIpAddress")
                    if uuid and ip:
                        ip_uuid_map[ip] = uuid
                        self.log(
                            "Mapped AND logic device - IP: {0}, UUID: {1}".format(ip, uuid),
                            "DEBUG"
                        )
            else:
                self.msg = (
                    "No devices found matching all specified identifiers: {0}".format(
                        list(identifier.keys())
                    )
                )
                self.log(
                    "AND logic completed - no devices matched all criteria",
                    "WARNING"
                )

        else:
            # OR Logic: Multiple entries or single entry with one key
            self.log(
                "Processing OR logic for {0} identifier groups".format(len(device_identifiers)),
                "INFO"
            )
            for idx, identifier in enumerate(device_identifiers, start=1):
                self.log(
                    "Processing OR logic group {0}/{1}: {2}".format(
                        idx, len(device_identifiers), identifier
                    ),
                    "DEBUG"
                )

                for key, values in identifier.items():
                    if not values:
                        self.log(
                            "Skipping empty values for key: {0}".format(key),
                            "DEBUG"
                        )
                        continue
                    if not isinstance(values, list):
                        values = [values]
                        self.log(
                            "Converted single value to list for key {0}: {1}".format(key, values),
                            "DEBUG"
                        )

                    expanded_values = []

                    for value in values:
                        if key == "ip_address_range":
                            self.log(
                                "Expanding IP address range: {0}".format(value),
                                "DEBUG"
                            )
                            try:
                                start_ip, end_ip = value.split("-")
                                start = ipaddress.IPv4Address(start_ip.strip())
                                end = ipaddress.IPv4Address(end_ip.strip())
                                range_ips = [
                                    str(ipaddress.IPv4Address(i))
                                    for i in range(int(start), int(end) + 1)
                                ]
                                expanded_values.extend(range_ips)
                                self.log(
                                    "Expanded IP range '{0}' into {1} individual IP addresses".format(
                                        value, len(range_ips)
                                    ),
                                    "DEBUG"
                                )
                            except Exception as e:
                                self.log(
                                    "Failed to expand IP range '{0}': {1}".format(value, str(e)),
                                    "ERROR"
                                )
                                continue
                        else:
                            expanded_values.append(value)
                            self.log("Added individual value '{0}' to expanded list (not an IP range)".format(value), "DEBUG")

                    missing_ips = []

                    for value_index, ip_or_value in enumerate(expanded_values, start=1):
                        self.log(
                            "Processing OR value {0}/{1} for key '{2}': {3}".format(
                                value_index, len(expanded_values), key, ip_or_value
                            ),
                            "DEBUG"
                        )
                        params = {param_key_map.get(key, "managementIpAddress"): ip_or_value}
                        devices = self.execute_device_lookup_with_retry(params, key, ip_or_value, timeout, retries, interval)

                        if devices:
                            for device in devices:
                                uuid = device.get("instanceUuid")
                                ip = device.get("managementIpAddress")
                                if uuid and ip:
                                    ip_uuid_map[ip] = uuid
                        else:
                            missing_ips.append(ip_or_value)
                            self.log("Device not found in inventory for identifier '{0}' - adding to missing list".format(ip_or_value), "DEBUG")

                    if missing_ips:
                        display_value = ", ".join(missing_ips)
                        self.msg = (
                            "No devices found for the following {0}(s): {1}. "
                            "Device(s) may not be present in Catalyst Center inventory."
                        ).format(key, display_value)
                        self.set_operation_result("success", False, self.msg, "INFO")
                        if self.msg not in self.total_response:
                            self.total_response.append(self.msg)

        total_devices = len(ip_uuid_map)
        self.log(
            "Device UUID mapping completed successfully using {0} logic - mapped {1} unique devices".format(
                logic_type, total_devices
            ),
            "INFO"
        )

        if total_devices > 0:
            self.log(
                "Successfully mapped devices: {0}".format(list(ip_uuid_map.keys())),
                "DEBUG"
            )
        else:
            self.log(
                "No devices found matching the specified criteria",
                "WARNING"
            )
        self.log("Device UUID mapping completed — mapped {0} managed devices.".format(total_devices), "INFO")

        return ip_uuid_map

    def execute_device_lookup_with_retry(self, params, key, value, timeout, retries, interval):
        """
        Execute device lookup API call with comprehensive retry mechanism and timeout handling.

        Parameters:
            params (dict): API parameters for device lookup
            key (str): Filter key being processed
            value (str): Filter value being processed
            timeout (int): Maximum timeout in seconds
            retries (int): Maximum number of retry attempts
            interval (int): Wait interval between retries

        Returns:
            list: List of found devices, empty list if no devices found
        """
        attempt = 0
        start_time = time.time()

        self.log(
            "Starting device lookup with retry mechanism - key: {0}, value: {1}".format(
                key, value
            ),
            "DEBUG"
        )

        while attempt < retries or (time.time() - start_time < timeout):
            elapsed_time = time.time() - start_time
            self.log(
                "Attempt {0} for {1}={2} - elapsed time: {3:.1f}s".format(
                    attempt + 1, key, value, elapsed_time
                ),
                "DEBUG"
            )

            try:
                self.log(
                    "Executing API call with parameters: {0}".format(params),
                    "DEBUG"
                )

                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    params=params
                )

                self.log(
                    "Received API response for {0}={1}: {2}".format(
                        key, value, response
                    ),
                    "DEBUG"
                )

                devices = response.get("response", [])

                if devices:
                    self.log(
                        "Found {0} devices for {1}={2} on attempt {3}".format(
                            len(devices), key, value, attempt + 1
                        ),
                        "DEBUG"
                    )
                    return devices
                else:
                    self.log(
                        "No devices found for {0}={1} on attempt {2}".format(
                            key, value, attempt + 1
                        ),
                        "DEBUG"
                    )

            except Exception as e:
                self.log(
                    "API call failed for {0}={1} on attempt {2}: {3}".format(
                        key, value, attempt + 1, str(e)
                    ),
                    "WARNING"
                )

            attempt += 1
            time.sleep(interval)

            if elapsed_time >= timeout:
                self.log(
                    "Timeout ({0}s) reached for {1}={2}".format(timeout, key, value),
                    "WARNING"
                )
                break

        total_elapsed = time.time() - start_time
        self.log(
            "Device lookup completed for {0}={1} - no devices found, attempts: {2}, elapsed: {3:.1f}s".format(
                key, value, attempt, total_elapsed
            ),
            "DEBUG"
        )

        return []

    def get_devices_from_site(self, site_name):
        """
        Retrieves device UUIDs from a specified site hierarchy in Cisco Catalyst Center.

        This method performs comprehensive site hierarchy analysis and device discovery by processing
        different site types (global, area, building, floor) and their relationships. It handles
        both parent and child site structures, applies wildcard patterns for hierarchical site
        discovery, and collects all network devices assigned to the specified site and its sub-sites.

        Args:
            site_name (str): The hierarchical site name for device discovery.
                Format: "Global/Region/Building/Floor" or any subset thereof.
                Examples:
                    - "Global" (retrieves devices from entire hierarchy)
                    - "Global/USA/NewYork" (retrieves devices from NewYork area and sub-sites)
                    - "Global/USA/NewYork/Building1/Floor1" (retrieves devices from specific floor)
                    - "Global/Campus/Building-A" (retrieves building + floor devices)

        Returns:
            list: A list of device UUIDs for all devices assigned to the specified site hierarchy.
                Returns empty list if no devices found or site doesn't exist.
        """

        self.log("Starting device retrieval from site: {0}".format(site_name), "INFO")

        if not site_name:
            return []

        # Determine site type
        site_type = self.get_sites_type(site_name)
        if not site_type:
            self.log(
                "Unable to determine site type for: '{0}'".format(site_name),
                "WARNING"
            )
            return []

        self.log(
            "Site type determined - site: '{0}', type: '{1}'".format(site_name, site_type),
            "DEBUG"
        )

        if site_type == "building":
            site_info = self.process_building_site(site_name)

        elif site_type in ["area", "global"]:
            site_info = self.process_area_site(site_name)

        elif site_type == "floor":
            site_info = self.process_floor_site(site_name)

        else:
            self.log(
                "Unknown site type '{0}' for site '{1}'".format(site_type, site_name),
                "ERROR"
            )
            return []
        return self.fetch_devices_for_sites(site_info)

    def process_building_site(self, site_name):
        """
       Process building site hierarchy including parent site and child floors.

        Args:
            site_name (str): Building site name to process

        Returns:
            dict: Dictionary mapping site hierarchy names to site IDs
        """
        self.log(
            "Processing building hierarchy for site: '{0}'".format(site_name),
            "DEBUG"
        )

        site_info = {}

        # Get parent building site data
        self.log(
            "Fetching parent building site data for: '{0}'".format(site_name),
            "DEBUG"
        )

        parent_site_data = self.get_site(site_name)

        if parent_site_data and parent_site_data.get("response"):
            self.log(
                "Parent building site data found - processing {0} items".format(
                    len(parent_site_data.get('response', []))
                ),
                "DEBUG"
            )

            for item in parent_site_data["response"]:
                if "nameHierarchy" in item and "id" in item:
                    site_info[item["nameHierarchy"]] = item["id"]
                    self.log(
                        "Added parent site '{0}' with ID '{1}' to hierarchy".format(
                            item['nameHierarchy'], item['id']
                        ),
                        "DEBUG"
                    )
        else:
            self.log(
                "No parent site data found for building: '{0}'".format(site_name),
                "WARNING"
            )

        wildcard_site = site_name + "/.*"
        self.log(
            "Fetching child floor sites using wildcard pattern: '{0}'".format(
                wildcard_site
            ),
            "DEBUG"
        )
        child_site_data = self.get_site(wildcard_site)

        if child_site_data and child_site_data.get("response"):
            for item in child_site_data["response"]:
                if "nameHierarchy" in item and "id" in item:
                    site_info[item["nameHierarchy"]] = item["id"]
                    self.log(
                        "Added child floor site '{0}' with ID '{1}' to hierarchy".format(
                            item['nameHierarchy'], item['id']
                        ),
                        "DEBUG"
                    )
        else:
            self.log(
                "No child floor sites found under building: '{0}'".format(site_name),
                "DEBUG"
            )

        return site_info

    def process_area_site(self, site_name):
        """
        Process area or global site hierarchy including all child sites.

        Args:
            site_name (str): Area or global site name to process

        Returns:
            dict: Dictionary mapping site hierarchy names to site IDs
        """
        self.log(
            "Processing area/global hierarchy for site: '{0}'".format(site_name),
            "DEBUG"
        )

        site_info = {}

        wildcard_site = site_name + "/.*"
        child_data = self.get_site(wildcard_site)

        site_names = wildcard_site if child_data and child_data.get("response") else site_name

        site_data = self.get_site(site_names)

        for item in site_data.get("response", []):
            if "nameHierarchy" in item and "id" in item:
                site_info[item["nameHierarchy"]] = item["id"]
                self.log(
                    "Added child site '{0}' with ID '{1}' to hierarchy".format(
                        item['nameHierarchy'], item['id']
                    ),
                    "DEBUG"
                )
            else:
                self.log(
                    "No child sites found under area/global: '{0}' - using original site".format(
                        site_name
                    ),
                    "DEBUG"
                )

        return site_info

    def process_floor_site(self, site_name):
        """
        Process floor site hierarchy (single site).

        Args:
            site_name (str): Floor site name to process

        Returns:
            dict: Dictionary mapping site hierarchy names to site IDs
        """
        self.log(
            "Processing floor hierarchy for site: '{0}'".format(site_name),
            "DEBUG"
        )

        site_info = {}

        site_data = self.get_site(site_name)

        if site_data and site_data.get("response"):
            self.log(
                "Floor site data found - processing {0} items".format(
                    len(site_data.get('response', []))
                ),
                "DEBUG"
            )

            for item in site_data["response"]:
                if "nameHierarchy" in item and "id" in item:
                    site_info[item["nameHierarchy"]] = item["id"]
                    self.log(
                        "Added floor site '{0}' with ID '{1}' to hierarchy".format(
                            item['nameHierarchy'], item['id']
                        ),
                        "DEBUG"
                    )
        else:
            self.log(
                "No site data found for floor: '{0}'".format(site_name),
                "WARNING"
            )

        return site_info

    def fetch_devices_for_sites(self, site_info):
        """
        Retrieve all devices from a specific site ID using pagination.

        Args:
            site_info (dict): Dictionary mapping site hierarchy names to site IDs

        Returns:
            list: List of device IDs from the site
        """
        self.log(
            "Starting device retrieval from site '{0}'".format(
                site_info
            ),
            "DEBUG"
        )

        device_id_list = []

        for hierarchy, site_id in site_info.items():
            offset = 1
            limit = self.get_device_details_limit()

            self.log(
                "Using pagination - limit: {0} devices per request".format(limit),
                "DEBUG"
            )

            while True:
                try:
                    self.log(
                        "Fetching devices from site '{0}' - offset: {1}, limit: {2}".format(
                            site_info, offset, limit
                        ),
                        "DEBUG"
                    )
                    response = self.dnac._exec(
                        family="site_design",
                        function="get_site_assigned_network_devices",
                        params={"site_id": site_id, "offset": offset, "limit": limit},
                    )

                    devices = response.get("response", [])
                    if not devices:
                        self.log(
                            "No more devices found for site '{0}' at offset {1}".format(
                                hierarchy, offset
                            ),
                            "DEBUG",
                        )
                        break

                    for device in devices:
                        device_id = device.get("deviceId")
                        device_id_list.append(device_id)
                        self.log(
                            "Retrieved device ID '{0}' from site '{1}'".format(device_id, hierarchy),
                            "DEBUG"
                        )

                    offset += limit

                except Exception as e:
                    self.log(
                        "Exception during device retrieval from site '{0}' (ID: {1}): {2}".format(
                            hierarchy, site_id, str(e)
                        ),
                        "ERROR"
                    )
                    return None
        self.log(
            "Device retrieval completed for site '{0}' - total devices: {1}".format(
                hierarchy, len(device_id_list)
            ),
            "DEBUG"
        )

        return device_id_list

    def filter_network_devices(self, filtered_config):
        """
        Performs comprehensive network device filtering based on multiple criteria and site hierarchies.

        This method implements advanced device discovery and filtering capabilities by combining site-based
        device identification, device identifier matching, and attribute-based filtering to create a
        refined list of network devices that meet all specified criteria.

        Args:
            filtered_config (dict): Comprehensive filtering configuration dictionary.

        Returns:
            dict or None: Dictionary mapping device IP addresses to their UUIDs for devices matching all criteria.
                Returns None if no devices match the filtering criteria or if critical errors occur.
        """
        self.log("Filtering network devices based on provided Args", "INFO")

        limit = 500
        offset = 1

        site_hierarchy = filtered_config.get("site_hierarchy")
        device_type = filtered_config.get("device_type")
        device_role = filtered_config.get("device_role")
        device_family = filtered_config.get("device_family")
        software_version = filtered_config.get("software_version")
        os_type = filtered_config.get("os_type")
        device_identifier = filtered_config.get("device_identifier")

        timeout = filtered_config.get("timeout", 120)
        retries = filtered_config.get("retries", 3)
        interval = filtered_config.get("interval", 10)

        self.log(
            "Using filter configuration - timeout: {0}s, retries: {1}, interval: {2}s".format(
                timeout, retries, interval
            ),
            "DEBUG"
        )

        self.log(
            "Filter criteria - site_hierarchy: {0}, device_type: {1}, role: {2}, family: {3}".format(
                site_hierarchy, device_type, device_role, device_family
            ),
            "DEBUG"
        )

        filtered_devices = {}
        start_time = time.time()
        attempt = 0
        elapsed_time = time.time() - start_time

        while attempt < retries or (time.time() - start_time < timeout):
            try:
                self.log(
                    "Starting device discovery phase - retrieving network devices with offset {0} and limit {1}".format(
                        offset, limit
                    ),
                    "DEBUG"
                )
                self.log("Attempt {0} - Retrieving network devices with offset {1} and limit {2}".format(
                    attempt + 1, offset, limit
                ), "DEBUG")

                all_devices = []

                device_ids_in_site = []

                # Phase 1: Site-based device discovery
                if site_hierarchy:
                    self.log(
                        "Processing site hierarchy filter: {0}".format(site_hierarchy),
                        "INFO"
                    )
                    device_ids_in_site = self.get_devices_from_site(site_hierarchy)
                    self.log(
                        "Site-based device discovery completed - found {0} devices for site '{1}'".format(
                            len(device_ids_in_site), site_hierarchy
                        ),
                        "INFO"
                    )
                    self.log(
                        "Device IDs from site '{0}': {1}".format(site_hierarchy, device_ids_in_site),
                        "DEBUG"
                    )

                # Phase 2: Device identifier-based discovery
                if device_identifier:
                    self.log(
                        "Processing device identifier filter: {0}".format(device_identifier),
                        "INFO"
                    )
                    ip_uuid_map = self.get_device_id(filtered_config)
                    if ip_uuid_map:
                        device_ids_from_identifiers = list(ip_uuid_map.values())
                        self.log(
                            "Identifier-based device discovery completed - found {0} devices".format(
                                len(device_ids_from_identifiers)
                            ),
                            "INFO"
                        )

                        # Combine site and identifier filters if both are specified
                        if site_hierarchy:
                            device_ids = list(set(device_ids_from_identifiers) & set(device_ids_in_site))
                            self.log(
                                "Applied intersection of site and identifier filters - result: {0} devices".format(
                                    len(device_ids)
                                ),
                                "DEBUG"
                            )
                        else:
                            device_ids = device_ids_from_identifiers
                            self.log(
                                "Using identifier-based filter results: {0} devices".format(
                                    len(device_ids)
                                ),
                                "DEBUG"
                            )
                    else:
                        self.log(
                            "No devices found matching device identifier criteria",
                            "WARNING"
                        )
                        device_ids = []
                else:
                    device_ids = device_ids_in_site if site_hierarchy else [None]
                    self.log(
                        "Using site-based filter results or all devices: {0}".format(
                            len(device_ids) if device_ids != [None] else "all"
                        ),
                        "DEBUG"
                    )

                self.log(
                    "Device discovery completed - processing {0} device IDs for attribute filtering".format(
                        len(device_ids) if device_ids != [None] else "all devices"
                    ),
                    "INFO"
                )

                # Phase 3: Apply attribute-based filters
                for device_index, device_id in enumerate(device_ids):
                    self.log(
                        "Processing device {0}/{1} for attribute filtering - device_id: {2}".format(
                            device_index + 1, len(device_ids), device_id
                        ),
                        "DEBUG"
                    )
                    params = {"offset": offset, "limit": limit}
                    if device_id:
                        params["id"] = device_id

                    filters = {
                        "role": device_role,
                        "family": device_family,
                        "type": device_type,
                        "software_version": software_version,
                        "software_type": os_type
                    }

                    applied_filters = []
                    for key, value in filters.items():
                        if value:
                            params[key] = value
                            applied_filters.append("{0}='{1}'".format(key, value))
                            self.log(
                                "Applied {0} filter with value: '{1}'".format(key, value),
                                "DEBUG"
                            )

                    if applied_filters:
                        self.log(
                            "Executing device query with filters: {0}".format(
                                ", ".join(applied_filters)
                            ),
                            "DEBUG"
                        )
                    else:
                        self.log(
                            "Executing device query without attribute filters",
                            "DEBUG"
                        )

                    self.log(
                        "API parameters for device query: {0}".format(params),
                        "DEBUG"
                    )

                    while True:
                        self.log(
                            "Executing API call - offset: {0}, limit: {1}".format(
                                params.get("offset"), params.get("limit")
                            ),
                            "DEBUG"
                        )
                        response = self.dnac._exec(
                            family="devices",
                            function="get_device_list",
                            params=params
                        )

                        self.log("Received API response from 'get_network_devices': {0}".format(response), "DEBUG")

                        devices = response.get("response", [])

                        if devices:
                            self.log(
                                "Found {0} devices in current page".format(len(devices)),
                                "DEBUG"
                            )
                            all_devices.extend(devices)
                            device_id = devices[0].get("instanceUuid")
                            self.log(
                                "Sample device from response - UUID: {0}".format(device_id),
                                "DEBUG"
                            )

                        if len(devices) < limit:
                            self.log(
                                "Reached end of results - received {0} devices (less than limit {1})".format(
                                    len(devices), limit
                                ),
                                "DEBUG"
                            )
                            break

                        offset += limit
                        self.log(
                            "Continuing pagination - new offset: {0}".format(offset),
                            "DEBUG"
                        )
                        params["offset"] = offset

                self.log("Total network devices retrieved: {0}".format(len(all_devices)), "INFO")

                # Phase 4: Build final filtered device mapping
                devices_processed = 0
                for device in all_devices:
                    ip = device.get("managementIpAddress")
                    device_id = device.get("instanceUuid")
                    if ip and device_id:
                        filtered_devices[ip] = device_id
                        devices_processed += 1
                        self.log(
                            "Device {0} included in final results - IP: {1}, UUID: {2}".format(
                                devices_processed, ip, device_id
                            ),
                            "DEBUG"
                        )
                    else:
                        self.log(
                            "Skipping device with missing IP or UUID - IP: {0}, UUID: {1}".format(
                                ip, device_id
                            ),
                            "WARNING"
                        )

                if filtered_devices:
                    self.log(
                        "Device filtering completed successfully on attempt {0} - found {1} matching devices".format(
                            attempt + 1, len(filtered_devices)
                        ),
                        "INFO"
                    )
                    break
                else:
                    if attempt < retries and (time.time() - start_time) < timeout:
                        self.log(
                            "No devices matched criteria on attempt {0}/{1} - retrying in {2} seconds".format(
                                attempt + 1, retries, interval
                            ),
                            "WARNING"
                        )
                        time.sleep(interval)
                        attempt += 1
                    else:
                        self.log(
                            "No devices matched filtering criteria after {0} attempts".format(
                                attempt + 1
                            ),
                            "WARNING"
                        )
                        break

            except Exception as e:
                self.msg = "Error occurred while retrieving/filtering network devices: {0}".format(str(e))
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return None

        if not filtered_devices:
            self.msg = (
                "No network devices matched the provided filter criteria after {0} attempts "
                "and {1:.1f} seconds".format(attempt + 1, time.time() - start_time)
            )
            self.set_operation_result("success", False, self.msg, "INFO")
            self.log(
                "Device filtering completed with no matching devices",
                "WARNING"
            )
            return None

        total_elapsed = time.time() - start_time
        self.log(
            "Network device filtering completed successfully - "
            "found {0} devices in {1:.1f} seconds across {2} attempts".format(
                len(filtered_devices), total_elapsed, attempt + 1
            ),
            "INFO"
        )

        self.log(
            "Final filtered device mapping: {0}".format(
                dict(list(filtered_devices.items())[:5])
            ) + ("... and {0} more".format(len(filtered_devices) - 5) if len(filtered_devices) > 5 else ""),
            "DEBUG"
        )

        return filtered_devices

    def get_device_info(self, ip_uuid_map):
        """
        Fetch detailed information for a list of network devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        The retrieved device details include key fields like:
        family, type, lastUpdateTime, macAddress, softwareVersion, serialNumber, managementIpAddress,
        hostname, upTime, role, platformId, reachabilityStatus, description, instanceUuid, id
        and more, providing a comprehensive overview of each device's configuration and status.

        Executes API calls for each device ID and aggregates the retrieved data into a structured list.

        Args:
            ip_uuid_map (dict): A mapping of device IPs to their UUIDs.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "device_info": [
                            {
                                "device_ip": <str>,
                                "device_details": <list of device details, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Starting device info retrieval for device_ids: {0}".format(ip_uuid_map), "INFO")
        device_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching device info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    params={'id': device_id}
                )
                self.log(
                    "Received API response from 'get_device_info' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                device_response = response.get("response", [])
                if device_response:
                    self.log("Device details found for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "INFO")
                    device_info_list.append({
                        "device_ip": device_ip,
                        "device_details": device_response
                    })
                else:
                    self.log("No device details found for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "WARNING")
                    device_info_list.append({
                        "device_ip": device_ip,
                        "device_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting device list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                device_info_list.append({
                    "device_ip": device_ip,
                    "device_details": "Error: {0}".format(e)
                })
                continue

        result = [{"device_info": device_info_list}]

        self.log("Completed device info retrieval. Total devices processed: {0}".format(len(device_info_list)), "INFO")
        self.log("Device info result: {0}".format(result), "DEBUG")
        return result

    def get_interface_info(self, ip_uuid_map):
        """
        Fetch interface information on interfaces for specified devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves detailed interface data for each device ID provided.

        The retrieved interface details include key fields such as:
        - adminStatus (e.g., "UP")
        - duplex (e.g., "FullDuplex")
        - ifIndex (e.g., "73")
        - interfaceType (e.g., "Physical")
        - macAddress (e.g., "0c:75:bd:42:db:c1")
        - mtu (e.g., "9100")
        - nativeVlanId (e.g., "1")
        - portMode (e.g., "access")
        - portName (e.g., "AppGigabitEthernet1/0/1")
        - portType (e.g., "Ethernet Port")
        - serialNo (e.g., "FJC2335S09F")
        - speed (e.g., "1000000")
        - status (e.g., "up")
        - vlanId (e.g., "1")
        - voiceVlan (e.g., "")
        - description (e.g., "")
        - instanceUuid
        - instanceTenantId

        Args:
            ip_uuid_map (dict): A mapping of device IPs to their UUIDs.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "interface_info": [
                            {
                                "device_ip": <str>,
                                "interface_details": <list of interface details, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching interface info for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        interface_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching device interface info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_interface_info_by_id",
                    params={'device_id': device_id}
                )
                self.log(
                    "Received API response from 'get_interface_info' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                interface_data = response.get("response", [])
                if interface_data:
                    self.log("Found {0} interface records for device IP: {1}".format(len(interface_data), device_ip), "DEBUG")
                    interface_info_list.append({
                        "device_ip": device_ip,
                        "interface_details": interface_data
                    })
                else:
                    self.log("No interface details found for device IP: {0}".format(device_ip), "DEBUG")
                    interface_info_list.append({
                        "device_ip": device_ip,
                        "interface_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting device interface info list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                interface_info_list.append({
                    "device_ip": device_ip,
                    "interface_details": "Error: {0}".format(e)
                })
                continue

        result = [{"interface_info": interface_info_list}]

        self.log("Completed Device Interface info retrieval. Total devices processed: {0}".format(len(interface_info_list)), "INFO")
        self.log("Device Interface info result: {0}".format(result), "DEBUG")
        return result

    def get_interface_vlan_info(self, ip_uuid_map):
        """
        Fetch VLAN interface details for a list of devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves VLAN interface configuration data for each device ID and aggregates the results
        into a structured format. Each device's VLAN interface details include interface-specific
        VLAN assignments, configurations, and related network information.

        The retrieved VLAN interface details include key fields such as:
        - interfaceName (e.g., "GigabitEthernet0/1")
        - ipAddress (e.g., "192.168.10.25")
        - mask (e.g., 24)
        - networkAddress (e.g., "192.168.10.0")
        - numberOfIPs (e.g., 254)
        - prefix (e.g., "192.168.10.0/24")
        - vlanNumber (e.g., 10)
        - vlanType (e.g., "Data")

        Args:
            ip_uuid_map (dict): A mapping of device IPs to their UUIDs.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "interface_vlan_info": [
                            {
                                "device_ip": <str>,
                                "interface_vlan_details": <list of VLAN interface details, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching VLAN interface data for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        vlans_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching device interface vlans info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_interface_vlans",
                    params={'id': device_id}
                )
                self.log(
                    "Received API response from 'get_device_interface_vlans' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                vlan_data = response.get("response", [])
                if vlan_data:
                    self.log("Found {0} VLAN records for device IP: {1}".format(len(vlan_data), device_ip), "DEBUG")
                    vlans_info_list.append({
                        "device_ip": device_ip,
                        "interface_vlan_details": vlan_data
                    })
                else:
                    self.log("No VLAN interface data found for device IP: {0}".format(device_ip), "DEBUG")
                    vlans_info_list.append({
                        "device_ip": device_ip,
                        "interface_vlan_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting VLAN interface data for device {0} (IP: {1}): {2}".format(device_id, device_ip, e)
                vlans_info_list.append({
                    "device_ip": device_ip,
                    "interface_vlan_details": "Error: {0}".format(e)
                })
                continue

        result = [{"interface_vlan_info": vlans_info_list}]

        self.log("Completed Interface Vlan info retrieval. Total devices processed: {0}".format(len(vlans_info_list)), "INFO")
        self.log("Interface Vlan info result: {0}".format(result), "DEBUG")
        return result

    def get_linecard_info(self, ip_uuid_map):
        """
        Fetch line card details for a list of devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Queries and aggregates line card information for each provided device ID.

        The retrieved line card details include key fields such as:
        - serialno (e.g., "SN123456789")
        - partno (e.g., "PN987654321")
        - switchno (e.g., "SW-001-A1")
        - slotno (e.g., "Slot-04")

        Args:
            ip_uuid_map (dict): A mapping of device IPs to their UUIDs.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "line_card_info": [
                            {
                                "device_ip": <str>,
                                "linecard_details": <list of line card details, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching Line card data for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        linecards_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching line card info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_linecard_details",
                    params={'device_uuid': device_id}
                )
                self.log(
                    "Received API response from 'get_linecard_details' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                linecard_data = response.get("response", [])
                if linecard_data:
                    self.log("Found {0} line card records for device IP: {1}".format(len(linecard_data), device_ip), "DEBUG")
                    linecards_info_list.append({
                        "device_ip": device_ip,
                        "linecard_details": linecard_data
                    })
                else:
                    self.log("No line card details found for device IP: {0}".format(device_ip), "DEBUG")
                    linecards_info_list.append({
                        "device_ip": device_ip,
                        "linecard_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting line card info list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                linecards_info_list.append({
                    "device_ip": device_ip,
                    "linecard_details": "Error: {0}".format(e)
                })
                continue

        result = [{"line_card_info": linecards_info_list}]

        self.log("Completed Line Card info retrieval. Total devices processed: {0}".format(len(linecards_info_list)), "INFO")
        self.log("Line Card info result: {0}".format(result), "DEBUG")
        return result

    def get_supervisor_card_info(self, ip_uuid_map):
        """
        Fetch supervisor card details for a list of devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves detailed supervisor card information for each provided device ID.

        The retrieved supervisor card details include key fields such as:
        - serialno (e.g., "SN1234567890")
        - partno (e.g., "PN9876543210")
        - switchno (e.g., "SW-01")
        - slotno (e.g., "3")

        Args:
            ip_uuid_map (dict): A mapping of device IPs to their UUIDs.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "supervisor_card_info": [
                            {
                                "device_ip": <str>,
                                "supervisor_card_details": <list of supervisor card details, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching supervisor card data for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        supervisor_cards_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching supervisor card info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_supervisor_card_detail",
                    params={'device_uuid': device_id}
                )
                self.log(
                    "Received API response from 'get_supervisor_card_details' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                supervisor_cards = response.get("response", [])
                if supervisor_cards:
                    self.log("Found {0} supervisor card records for device IP: {1}".format(len(supervisor_cards), device_ip), "DEBUG")
                    supervisor_cards_info_list.append({
                        "device_ip": device_ip,
                        "supervisor_card_details": supervisor_cards
                    })
                else:
                    self.log("No supervisor card details found for device IP: {0}".format(device_ip), "DEBUG")
                    supervisor_cards_info_list.append({
                        "device_ip": device_ip,
                        "supervisor_card_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting supervisor card info list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                supervisor_cards_info_list.append({
                    "device_ip": device_ip,
                    "supervisor_card_details": "Error: {0}".format(e)
                })
                continue

        result = [{"supervisor_card_info": supervisor_cards_info_list}]

        self.log("Completed Device Supervisor Card info retrieval. Total devices processed: {0}".format(len(supervisor_cards_info_list)), "INFO")
        self.log("Device Supervisor Card info result: {0}".format(result), "DEBUG")
        return result

    def get_poe_info(self, ip_uuid_map):
        """
        Fetch Power over Ethernet (PoE) details for specified devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves PoE information for each device ID provided.

        The retrieved PoE details include key fields such as:
        - powerAllocated (e.g., "525")
        - powerConsumed (e.g., "0")
        - powerRemaining (e.g., "525")

        Args:
            ip_uuid_map (dict): Mapping of device IPs to their UUIDs.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "poe_info": [
                            {
                                "device_ip": <str>,
                                "poe_details": <list of PoE details, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching PoE data for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        poe_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching poe info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="poe_details",
                    params={'device_uuid': device_id}
                )
                self.log(
                    "Received API response from 'poe_details': {0}".format(
                        (response)
                    ),
                    "DEBUG",
                )
                poe_data = response.get("response", [])
                if poe_data:
                    self.log("Found {0} PoE records for device IP: {1}".format(len(poe_data), device_ip), "DEBUG")
                    poe_info_list.append({
                        "device_ip": device_ip,
                        "poe_details": poe_data
                    })
                else:
                    self.log("No PoE details found for device IP: {0}".format(device_ip), "DEBUG")
                    poe_info_list.append({
                        "device_ip": device_ip,
                        "poe_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting PoE Info list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                poe_info_list.append({
                    "device_ip": device_ip,
                    "poe_details": "Error: {0}".format(e)
                })
                continue

        result = [{"poe_info": poe_info_list}]

        self.log("Completed Device PoE info retrieval. Total devices processed: {0}".format(len(poe_info_list)), "INFO")
        self.log("Device PoE info result: {0}".format(result), "DEBUG")
        return result

    def get_module_count_info(self, ip_uuid_map):
        """
        Fetch module count details for specified devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves module count information for each device ID provided.

        The retrieved module count includes the key field:
            - module_count_info (int): Number of modules in the device (e.g., 3)

        Args:
            ip_uuid_map (dict): Mapping of device IPs to their UUIDs.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "module_count_info": [
                            {
                                "device_ip": <str>,
                                "module_count_details": <list of module count details, exception or empty string>
                            },
                        ]
                    }
                ]
        """

        self.log(
            "Processing module count data for {0} devices with IP-UUID mapping: {1}".format(
                len(ip_uuid_map) if ip_uuid_map else 0,
                list(ip_uuid_map.keys()) if ip_uuid_map else []
            ),
            "DEBUG"
        )

        module_counts_info_list = []
        successful_retrievals = 0
        failed_retrievals = 0

        for device_index, (device_ip, device_id) in enumerate(ip_uuid_map.items(), start=1):
            self.log(
                "Processing device {0}/{1} - IP: {2}, UUID: {3}".format(
                    device_index, len(ip_uuid_map), device_ip, device_id
                ),
                "DEBUG"
            )
            self.log("Fetching module count info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            # Validate device IP and ID
            if not device_ip or not device_id:
                self.log(
                    "Skipping device with missing IP or UUID - IP: {0}, UUID: {1}".format(
                        device_ip, device_id
                    ),
                    "WARNING"
                )
                module_counts_info_list.append({
                    "device_ip": device_ip or "unknown",
                    "module_count_details": "Error: Missing device IP or UUID"
                })
                failed_retrievals += 1
                continue

            self.log(
                "Executing module count API call for device IP: {0}, UUID: {1}".format(
                    device_ip, device_id
                ),
                "DEBUG"
            )

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_module_count",
                    params={'device_id': device_id}
                )
                self.log(
                    "Received API response from 'get_module_count' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                module_count_data = response.get("response", [])

                if module_count_data:
                    successful_retrievals += 1
                    self.log("Found {0} module count records for device IP: {1}".format(module_count_data, device_ip), "DEBUG")
                    module_counts_info_list.append({
                        "device_ip": device_ip,
                        "module_count_details": module_count_data
                    })
                else:
                    successful_retrievals += 1
                    self.log("No module count details found for device IP: {0}".format(device_ip), "DEBUG")
                    module_counts_info_list.append({
                        "device_ip": device_ip,
                        "module_count_details": []
                    })

            except Exception as e:
                failed_retrievals += 1
                self.msg = "Exception occurred while getting module count info list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                module_counts_info_list.append({
                    "device_ip": device_ip,
                    "module_count_details": "Error: {0}".format(e)
                })
                continue

        result = [{"module_count_info": module_counts_info_list}]

        self.log(
            "Module count information retrieval completed - "
            "total devices: {0}, successful: {1}, failed: {2}".format(
                len(ip_uuid_map), successful_retrievals, failed_retrievals
            ),
            "INFO"
        )

        self.log(
            "Module count retrieval result summary: {0}".format(
                {"total_devices": len(module_counts_info_list), "result_structure": "module_count_info"}
            ),
            "DEBUG"
        )
        return result

    def get_interface_ids_per_device(self, ip_uuid_map):
        """
        Retrieve interface identifiers for devices to enable interface-based operations and connectivity analysis.

        This method queries the Catalyst Center Device API to collect comprehensive interface inventory
        information for each specified device. It retrieves interface UUIDs and metadata that
        are essential for subsequent operations such as connected device discovery, interface health
        monitoring, and network topology mapping within the network.

        Args:
            ip_uuid_map (dict): Mapping of device IP addresses to their UUIDs.

        Returns:
            dict: A dictionary mapping device IP addresses to sets of interface UUIDs:
                {
                    "192.168.1.1": {"interface-uuid-1", "interface-uuid-2", "interface-uuid-3"},
                    "192.168.1.2": {"interface-uuid-4", "interface-uuid-5"},
                }
        """
        self.log("Retrieving interface identifiers for network device interface inventory and management", "INFO")
        self.log(
            "Processing interface discovery for {0} network devices".format(
                len(ip_uuid_map)
            ),
            "DEBUG"
        )

        device_interfaces_map = {}

        # Statistics tracking
        statistics = {
            'devices_processed': 0,
            'devices_with_interfaces': 0,
            'devices_without_interfaces': 0,
            'devices_with_errors': 0,
            'interfaces_without_ids': 0,
            'total_interfaces_discovered': 0
        }

        for index, (ip, device_id) in enumerate(ip_uuid_map.items()):
            statistics['devices_processed'] += 1
            self.log(
                "Processing device {0}/{1} - IP: {2}, UUID: {3}".format(
                    statistics['devices_processed'], len(ip_uuid_map), ip, device_id
                ),
                "DEBUG"
            )

            # Validate device IP and UUID
            if not ip or not device_id:
                self.log(
                    "Skipping device with missing IP or UUID - IP: {0}, UUID: {1}".format(
                        ip, device_id
                    ),
                    "WARNING"
                )
                statistics['devices_with_errors'] += 1
                continue

            try:
                self.log("Fetching interfaces for device: {0}".format(ip), "DEBUG")

                response = self.dnac._exec(
                    family="devices",
                    function="get_interface_info_by_id",
                    params={"device_id": device_id}
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
                interfaces_missing_ids = 0

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
                statistics['interfaces_without_ids'] += interfaces_missing_ids
                statistics['total_interfaces_discovered'] += len(interface_ids)

                if interface_ids:
                    statistics['devices_with_interfaces'] += 1
                    self.log(
                        "Successfully mapped {0} interface identifiers for device {1}".format(
                            len(interface_ids),
                            ip
                        ),
                        "DEBUG"
                    )
                else:
                    statistics['devices_without_interfaces'] += 1
                    self.log(
                        "No interface identifiers found for device {0} - "
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
                statistics['devices_with_errors'] += 1
                self.msg = "Failed to retrieve interface information for device {0}: {1}".format(ip, str(e))
                self.log(self.msg, "ERROR")

        total_network_devices = len(ip_uuid_map)
        successful_devices = len(device_interfaces_map)

        self.log(
            "Interface discovery statistics - "
            "devices with interfaces: {0}, "
            "devices without interfaces: {1}, "
            "devices with errors: {2}".format(
                statistics['devices_with_interfaces'],
                statistics['devices_without_interfaces'],
                statistics['devices_with_errors']
            ),
            "INFO"
        )

        if statistics['interfaces_without_ids'] > 0:
            self.log(
                "Warning: {0} interface records across all devices were missing "
                "UUID identifiers".format(statistics['interfaces_without_ids']),
                "WARNING"
            )

        self.log(
            "Total interface identifiers discovered: {0} across {1} devices".format(
                statistics['total_interfaces_discovered'], successful_devices
            ),
            "INFO"
        )
        if statistics['devices_with_interfaces'] > 0:
            self.log("Network devices with interface identifiers: {0}".format(statistics['devices_with_interfaces']), "INFO")

        if statistics['devices_without_interfaces'] > 0:
            self.log("Network devices without interface identifiers: {0}".format(statistics['devices_without_interfaces']), "INFO")

        if statistics['devices_with_errors'] > 0:
            self.log("Warning: {0} devices encountered errors during interface retrieval".format(statistics['devices_with_errors']), "WARNING")

        self.log("Total interface identifiers discovered across all network devices: {0}".format(statistics['total_interfaces_discovered']), "INFO")

        return device_interfaces_map

    def get_connected_device_details_from_interfaces(self, ip_uuid_map):
        """
        Discover connected device topology for network devices through comprehensive interface-level analysis.

        This method performs extensive connected device discovery by querying each interface of specified
        network devices to identify neighboring devices, endpoints, and network attachments. It processes
        interface-level connectivity data to provide complete visibility into network device interconnections,
        attached endpoints, and network topology relationships essential for network management
        and troubleshooting operations.

        Args:
            ip_uuid_map (dict): Mapping of device IP addresses to their UUIDs.

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
        self.log("Discovering connected device topology for device interface inventory", "INFO")
        self.log("Processing connected device discovery for {0} network devices".format(len(ip_uuid_map)), "DEBUG")

        connected_info_list = []

        statistics = {
            'devices_processed': 0,
            'devices_with_connections': 0,
            'devices_without_connections': 0,
            'devices_with_errors': 0,
            'interfaces_processed': 0,
            'interfaces_with_connections': 0,
            'total_connections_discovered': 0
        }

        self.log(
            "Phase 1: Retrieving interface inventories for network devices to enable discovery",
            "INFO"
        )
        device_interfaces_map = self.get_interface_ids_per_device(ip_uuid_map)

        if not device_interfaces_map:
            self.log(
                "No interface mappings available for network devices - "
                "unable to perform connected device discovery",
                "WARNING"
            )
            return [{"connected_device_info": []}]

        self.log(
            "Phase 1 completed: Retrieved interface mappings for {0} network devices".format(
                len(device_interfaces_map)
            ),
            "INFO"
        )

        self.log(
            "Phase 2: Processing connected device discovery across device interfaces",
            "INFO"
        )

        for index, (device_ip, interface_ids) in enumerate(device_interfaces_map.items()):
            statistics['devices_processed'] += 1
            ip_device_uuid_map = self.get_device_ids_from_device_ips([device_ip])
            device_uuid = ip_device_uuid_map[device_ip]
            interfaces_with_connections = 0

            self.log(
                "Processing device {0}/{1} - IP: {2}, UUID: {3}, interfaces: {4}".format(
                    statistics['devices_processed'], len(device_interfaces_map),
                    device_ip, device_uuid, len(interface_ids)
                ),
                "DEBUG"
            )

            # Validate device mapping
            if not device_uuid:
                self.log(
                    "Skipping device {0} - missing UUID in ip_uuid_map".format(device_ip),
                    "WARNING"
                )
                statistics['devices_with_errors'] += 1
                connected_info_list.append({
                    "device_ip": device_ip,
                    "connected_device_details": "Error: Missing device UUID in mapping"
                })
                continue

            if not interface_ids:
                self.log(
                    "Device {0} has no interfaces available for connected device discovery".format(
                        device_ip
                    ),
                    "WARNING"
                )
                statistics['devices_without_connections'] += 1
                connected_info_list.append({
                    "device_ip": device_ip,
                    "connected_device_details": []
                })
                continue

            for interface_index, interface_id in enumerate(interface_ids, start=1):
                statistics['interfaces_processed'] += 1

                self.log(
                    "Processing interface {0}/{1} for device {2} - interface_id: {3}".format(
                        interface_index, len(interface_ids), device_ip, interface_id
                    ),
                    "DEBUG"
                )
                try:
                    self.log(
                        "Executing connected device query for interface {0} on device {1}".format(
                            interface_id, device_ip
                        ),
                        "DEBUG"
                    )
                    response = self.dnac._exec(
                        family="devices",
                        function="get_connected_device_detail",
                        params={
                            "device_uuid": device_uuid,
                            "interface_uuid": interface_id
                        }
                    )
                    self.log(
                        "Received connected device API response for device {0}, interface {1}: {2}".format(
                            device_ip, interface_id, response
                        ),
                        "DEBUG"
                    )
                    interface_connected_data = response.get("response", {})

                    if interface_connected_data:
                        interfaces_with_connections += 1
                        statistics['interfaces_with_connections'] += 1
                        statistics['total_connections_discovered'] += 1
                        statistics['devices_with_connections'] += 1
                        self.log(
                            "Connected device found for device {0}, interface {1}: {2}".format(
                                device_ip, interface_id, interface_connected_data
                            ),
                            "DEBUG"
                        )
                        connected_info_list.append({
                            "device_ip": device_ip,
                            "connected_device_details": [interface_connected_data]
                        })
                    else:
                        statistics['devices_without_connections'] += 1
                        self.log(
                            "No connected device found for device {0}, interface {1}".format(
                                device_ip, interface_id
                            ),
                            "DEBUG"
                        )
                        connected_info_list.append({
                            "device_ip": device_ip,
                            "connected_device_details": []
                        })

                except Exception as e:
                    statistics['devices_with_errors'] += 1
                    self.log(
                        "Exception during connected device query for device {0}, interface {1}: {2}".format(
                            device_ip, interface_id, str(e)
                        ),
                        "ERROR"
                    )
                    connected_info_list.append({
                        "device_ip": device_ip,
                        "connected_device_details": "Error: {0}".format(e)
                    })

        result = [{"connected_device_info": connected_info_list}]

        self.log(
            "Phase 2 completed: Connected device topology discovery finished successfully",
            "INFO"
        )

        # Final statistics and comprehensive logging
        self.log(
            "Discovery statistics - devices processed: {0}, "
            "devices with connections: {1}, devices without connections: {2}, "
            "devices with errors: {3}".format(
                statistics['devices_processed'],
                statistics['devices_with_connections'],
                statistics['devices_without_connections'],
                statistics['devices_with_errors']
            ),
            "INFO"
        )
        self.log(
            "Interface processing statistics - total interfaces: {0}, "
            "interfaces with connections: {1}, total connections discovered: {2}".format(
                statistics['interfaces_processed'],
                statistics['interfaces_with_connections'],
                statistics['total_connections_discovered']
            ),
            "INFO"
        )

        if statistics['devices_with_errors'] > 0:
            self.log(
                "Warning: {0} devices encountered errors during connected device discovery".format(
                    statistics['devices_with_errors']
                ),
                "WARNING"
            )

        self.log(
            "Connected device topology discovery completed successfully - "
            "processed {0} devices with {1} total interfaces, "
            "discovered {2} total connections".format(
                statistics['devices_processed'],
                statistics['interfaces_processed'],
                statistics['total_connections_discovered']
            ),
            "INFO"
        )

        return result

    def get_interfaces_by_specified_range(self, ip_uuid_map):
        """
        Fetch interfaces by specified range details for specified devices from Cisco Catalyst Center.

        Retrieves interface details for a list of device UUIDs using the
        'Get Device Interfaces by Specified Range' API with default values.
        The API is called with a default range of start_index = 1 and
        records_to_return = 500 for each device.

        The retrieved interface details include key fields such as:
        - addresses (list): List of interface IP addresses (usually empty or detailed IPs)
        - adminStatus (str): Administrative status (e.g., "UP")
        - duplex (str): Duplex mode (e.g., "FullDuplex")
        - ifIndex (str): Interface index identifier (e.g., "73")
        - interfaceType (str): Type of interface (e.g., "Physical")
        - lastOutgoingPacketTime (int): Timestamp of last outgoing packet (epoch ms)
        - macAddress (str): MAC address of the interface (e.g., "0c:75:bd:42:db:c1")
        - mtu (str): Maximum Transmission Unit size (e.g., "9100")
        - nativeVlanId (str): Native VLAN ID (e.g., "1")
        - pid (str): Platform ID (e.g., "C9300-48UXM")
        - portMode (str): Port mode (e.g., "access")
        - portName (str): Name of the port (e.g., "AppGigabitEthernet1/0/1")
        - portType (str): Type of port (e.g., "Ethernet Port")
        - serialNo (str): Serial number of the device (e.g., "FJC2335S09F")
        - series (str): Device series (e.g., "Cisco Catalyst 9300 Series Switches")
        - speed (str): Speed in kbps (e.g., "1000000")
        - status (str): Operational status (e.g., "up")
        - vlanId (str): VLAN ID assigned (e.g., "1")
        - voiceVlan (str): Voice VLAN (usually empty)
        - description (str): Interface description (usually empty)
        - instanceUuid (str): Interface instance UUID
        - instanceTenantId (str): Tenant ID for the instance

        Args:
            ip_uuid_map (dict): Mapping of device IPs to their UUIDs.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "connected_device_info": [
                            {
                                "device_ip": <str>,
                                "connected_device_details": <list of connected device detail dictionaries, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log(
            "Processing interface range retrieval for {0} network devices: {1}".format(
                len(ip_uuid_map) if ip_uuid_map else 0,
                list(ip_uuid_map.keys()) if ip_uuid_map else []
            ),
            "DEBUG"
        )

        interface_by_range_info_list = []
        statistics = {
            'devices_processed': 0,
            'devices_with_interfaces': 0,
            'devices_without_interfaces': 0,
            'devices_with_errors': 0,
            'total_interfaces_retrieved': 0,
            'total_api_calls': 0
        }

        for device_ip, device_id in ip_uuid_map.items():
            statistics['devices_processed'] += 1
            self.log(
                "Processing device {0}/{1} - IP: {2}, UUID: {3}".format(
                    statistics['devices_processed'], len(ip_uuid_map), device_ip, device_id
                ),
                "DEBUG"
            )

            if not device_ip or not device_id:
                self.log(
                    "Skipping device with missing IP or UUID - IP: {0}, UUID: {1}".format(
                        device_ip, device_id
                    ),
                    "WARNING"
                )
                statistics['devices_with_errors'] += 1
                interface_by_range_info_list.append({
                    "device_ip": device_ip or "unknown",
                    "interface_info": "Error: Missing device IP or UUID"
                })
                continue
            start_index = 1
            records_to_return = 500
            interface_data = []

            self.log(
                "Starting paginated interface retrieval for device {0} with "
                "initial parameters - start_index: {1}, records_to_return: {2}".format(
                    device_ip, start_index, records_to_return
                ),
                "DEBUG"
            )

            while True:
                self.log(
                    "Executing interface range API call for device {0} - "
                    "requesting {1} records starting at index {2}".format(
                        device_ip, records_to_return, start_index
                    ),
                    "DEBUG"
                )
                try:
                    statistics['total_api_calls'] += 1
                    response = self.dnac._exec(
                        family="devices",
                        function="get_device_interfaces_by_specified_range",
                        params={
                            "device_id": device_id,
                            "start_index": start_index,
                            "records_to_return": records_to_return
                        }
                    )

                    self.log("Received API response from 'get_device_interfaces_by_specified_range' for device {0}: {1}".format(
                        device_ip, response), "DEBUG"
                    )

                    if not response or 'response' not in response:
                        self.log(
                            "Invalid or empty API response received for device {0}".format(device_ip),
                            "WARNING"
                        )
                        break

                    data_chunk = response['response']
                    if data_chunk:
                        chunk_size = len(data_chunk)
                        self.log(
                            "Retrieved {0} interface records for device {1} at index {2}".format(
                                chunk_size, device_ip, start_index
                            ),
                            "DEBUG"
                        )
                        interface_data.extend(data_chunk)
                        statistics['total_interfaces_retrieved'] += chunk_size

                        # Check if we've reached the end of available data
                        if chunk_size < records_to_return:
                            self.log(
                                "Reached end of interface data for device {0} - "
                                "received {1} records (less than requested {2})".format(
                                    device_ip, chunk_size, records_to_return
                                ),
                                "DEBUG"
                            )
                            break

                        # Update pagination parameters for next iteration
                        start_index += records_to_return
                        self.log(
                            "Continuing pagination for device {0} - next start_index: {1}".format(
                                device_ip, start_index
                            ),
                            "DEBUG"
                        )
                    else:
                        self.log(
                            "No interface data returned for device {0} at index {1}".format(
                                device_ip, start_index
                            ),
                            "DEBUG"
                        )
                        break

                except Exception as api_err:
                    self.log(
                        "Exception during interface range API call for device {0}: {1}".format(
                            device_ip, str(api_err)
                        ),
                        "ERROR"
                    )
                    interface_data = "Error: {0}".format(str(api_err))
                    statistics['devices_with_errors'] += 1
                    continue

            if interface_data:
                statistics['devices_with_interfaces'] += 1
                self.log(
                    "Successfully retrieved {0} total interfaces for device {1}".format(
                        len(interface_data), device_ip
                    ),
                    "INFO"
                )
                interface_by_range_info_list.append({
                    "device_ip": device_ip,
                    "interface_info": interface_data
                })
            else:
                statistics['devices_without_interfaces'] += 1
                self.log(
                    "No interfaces found for device {0}".format(device_ip),
                    "INFO"
                )
                interface_by_range_info_list.append({
                    "device_ip": device_ip,
                    "interface_info": []
                })

        result = [{"device_interfaces_by_range_info": interface_by_range_info_list}]

        # Comprehensive logging of operation results
        self.log(
            "Interface range retrieval completed successfully - "
            "devices processed: {0}, devices with interfaces: {1}, "
            "devices without interfaces: {2}, devices with errors: {3}".format(
                statistics['devices_processed'],
                statistics['devices_with_interfaces'],
                statistics['devices_without_interfaces'],
                statistics['devices_with_errors']
            ),
            "INFO"
        )

        self.log(
            "Interface retrieval statistics - "
            "total API calls: {0}, total interfaces retrieved: {1}".format(
                statistics['total_api_calls'],
                statistics['total_interfaces_retrieved']
            ),
            "INFO"
        )

        if statistics['devices_with_errors'] > 0:
            self.log(
                "Warning: {0} devices encountered errors during interface range retrieval".format(
                    statistics['devices_with_errors']
                ),
                "WARNING"
            )

        self.log(
            "Interface range data retrieval operation completed with {0} total devices processed".format(
                len(interface_by_range_info_list)
            ),
            "INFO"
        )

        return result

    def get_device_config_info(self, ip_uuid_map):
        """
        Fetch configuration data for a list of devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves the full configuration details for each specified device ID and aggregates the results.

        The configuration details include the device's running configuration, which may consist of
        multiple lines of configuration commands.

        Parameters:
            ip_uuid_map (dict): Mapping of device IPs to their UUIDs for which configuration details need to be fetched.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "device_config_info": [
                            {
                                "device_ip": <str>,
                                "device_config_details": <list of configuration lines, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching Device config data for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        device_config_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching device config info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_config_by_id",
                    params={'network_device_id': device_id}
                )
                self.log(
                    "Received API response from 'get_device_config' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                config_data = response.get("response", [])
                if config_data:
                    self.log("Found {0} configuration lines for device IP: {1}".format(len(config_data), device_ip), "DEBUG")
                    device_config_list.append({
                        "device_ip": device_ip,
                        "device_config_details": config_data
                    })
                else:
                    self.log("No device config card details found for device IP: {0}".format(device_ip), "DEBUG")
                    device_config_list.append({
                        "device_ip": device_ip,
                        "device_config_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting device config for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                device_config_list.append({
                    "device_ip": device_ip,
                    "device_config_details": "Error: {0}".format(e)
                })
                continue

        result = [{"device_config_info": device_config_list}]

        self.log("Completed Device Config info retrieval. Total devices processed: {0}".format(len(device_config_list)), "INFO")
        self.log("Device Config info result: {0}".format(result), "DEBUG")
        return result

    def get_device_summary_info(self, ip_uuid_map):
        """
        Fetch summary information of devices for a list of devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves key summary details for each device ID provided and aggregates the results.

        The retrieved device summary details include key fields such as:
        - id (e.g., "e62e6405-13e4-4f1b-ae1c-580a28a96a88")
        - role (e.g., "ACCESS")
        - roleSource (e.g., "MANUAL")

        Parameters:
            ip_uuid_map (dict): Mapping of device IPs to their UUIDs for which summary information needs to be retrieved.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "device_summary_info": [
                            {
                                "device_ip": <str>,
                                "device_summary_details": <list of summary details, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching device summary data for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        device_summary_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching device summary info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_summary",
                    params={'id': device_id}
                )
                self.log(
                    "Received API response from 'get_device_summary' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                summary_data = response.get("response", [])
                self.log("Summary data: {0}".format(summary_data), "DEBUG")
                if summary_data:
                    self.log("Found {0} summary records for device IP: {1}".format(len(summary_data), device_ip), "DEBUG")
                    device_summary_info_list.append({
                        "device_ip": device_ip,
                        "device_summary_details": summary_data
                    })
                else:
                    self.log("No device summary details found for device IP: {0}".format(device_ip), "DEBUG")
                    device_summary_info_list.append({
                        "device_ip": device_ip,
                        "device_summary_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting device summary list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                device_summary_info_list.append({
                    "device_ip": device_ip,
                    "device_summary_details": "Error: {0}".format(e)
                })
                continue

        result = [{"device_summary_info": device_summary_info_list}]

        self.log("Completed Device Summary info retrieval. Total devices processed: {0}".format(len(device_summary_info_list)), "INFO")
        self.log("Device Summary info result: {0}".format(result), "DEBUG")
        return result

    def get_device_polling_interval_info(self, ip_uuid_map):
        """
        Fetch polling interval information for a list of devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves the polling interval configuration for each specified device ID and compiles the results.

        The polling interval details include the time intervals at which the device is polled for updates,
        which can be critical for monitoring and management tasks (e.g., 86400 seconds for daily polling).

        Parameters:
            ip_uuid_map (dict): Mapping of device IPs to their UUIDs for which polling interval details need to be retrieved.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "device_polling_interval_info": [
                            {
                                "device_ip": <str>,
                                "polling_interval_details": <list of polling interval values, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching polling interval data for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        polling_intervals_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching polling intervals info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_polling_interval_by_id",
                    params={'id': device_id}
                )
                self.log(
                    "Received API response from 'get_polling_interval' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                intervals = response.get("response", [])
                if intervals:
                    self.log("Found {0} polling interval records for device IP: {1}".format((intervals), device_ip), "DEBUG")
                    polling_intervals_info_list.append({
                        "device_ip": device_ip,
                        "polling_interval_details": intervals
                    })
                else:
                    self.log("No polling interval details found for device IP: {0}".format(device_ip), "DEBUG")
                    polling_intervals_info_list.append({
                        "device_ip": device_ip,
                        "polling_interval_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting polling interval info list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                polling_intervals_info_list.append({
                    "device_ip": device_ip,
                    "polling_interval_details": "Error: {0}".format(e)
                })
                continue

        result = [{"device_polling_interval_info": polling_intervals_info_list}]

        self.log("Completed Device Polling Interval info retrieval. Total devices processed: {0}".format(len(polling_intervals_info_list)), "INFO")
        self.log("Device Polling Interval info result: {0}".format(result), "DEBUG")
        return result

    def get_device_stack_info(self, ip_uuid_map):
        """
        Fetch stack details for a list of devices from Cisco Catalyst Center.

        For each device ID, this method calls the 'get_device_list' API and aggregates the results.
        Each entry in the returned list contains the device's management IP and its details.

        Retrieves stack member information for each given device ID and compiles the results.

        The stack member info includes key fields such as:
        - stackSwitchInfo: list of dicts with fields including hwPriority, macAddress, role, softwareImage,
        stackMemberNumber, state, switchPriority, serialNumber, platformId, entPhysicalIndex
        - stackPortInfo: list of dicts with fields including isSynchOk, name, switchPort, neighborPort,
        nrLinkOkChanges, stackCableLengthInfo, stackPortOperStatusInfo, linkActive, linkOk
        - svlSwitchInfo: list of dicts with fields including macAddress, role, softwareImage,
        stackMemberNumber, state, switchPriority, serialNumber, platformId, entPhysicalIndex

        Parameters:
            ip_uuid_map (dict): Mapping of device IPs to their UUIDs for which stack details need to be retrieved.

        Returns:
            list: A list with a single dictionary:
                [
                    {
                        "device_stack_info": [
                            {
                                "device_ip": <str>,
                                "stack_details": <list of stack member details, exception or empty string>
                            },
                        ]
                    }
                ]
        """
        self.log("Fetching stack details for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        stack_info_list = []

        for device_ip, device_id in ip_uuid_map.items():
            self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
            self.log("Fetching stack info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_stack_details_for_device",
                    params={'device_id': device_id}
                )
                self.log(
                    "Received API response from 'get_stack_details' for device {0} (IP: {1}): {2}".format(
                        device_id, device_ip, response), "DEBUG")

                stack_info = response.get("response", [])
                if stack_info:
                    self.log("Found {0} stack records for device IP: {1}".format(len(stack_info), device_ip), "DEBUG")
                    stack_info_list.append({
                        "device_ip": device_ip,
                        "stack_details": stack_info
                    })
                else:
                    self.log("No stack details found for device IP: {0}".format(device_ip), "DEBUG")
                    stack_info_list.append({
                        "device_ip": device_ip,
                        "stack_details": []
                    })

            except Exception as e:
                self.msg = "Exception occurred while getting device stack info list for device_id {0}, device_ip {1}: {2}".format(device_id, device_ip, e)
                stack_info_list.append({
                    "device_ip": device_ip,
                    "stack_details": "Error: {0}".format(e)
                })
                continue

        result = [{"device_stack_info": stack_info_list}]

        self.log("Completed Stack info retrieval. Total devices processed: {0}".format(len(stack_info_list)), "INFO")
        self.log("Stack info result: {0}".format(result), "DEBUG")
        return result

    def get_device_link_mismatch_info(self, site_id, ip_uuid_map):
        """
        Fetch Inventory Insight Device Link Mismatch data for a list of site IDs.

        Retrieves mismatch data for both 'vlan' and 'speed-duplex' categories for each site.
        Aggregates all results and returns them in a structured list.

        The retrieved device link mismatch data includes key fields such as:
        - endPortAllowedVlanIds (str): Allowed VLAN IDs on the end port (e.g., "10,20,30")
        - endPortNativeVlanId (str): Native VLAN ID on the end port (e.g., "10")
        - startPortAllowedVlanIds (str): Allowed VLAN IDs on the start port (e.g., "10,20,30")
        - startPortNativeVlanId (str): Native VLAN ID on the start port (e.g., "10")
        - linkStatus (str): Current status of the link (e.g., "up")
        - endDeviceHostName (str): Hostname of the device at the end port (e.g., "switch-nyc-01")
        - endDeviceId (str): Unique ID of the device at the end port (e.g., "device-1001")
        - endDeviceIpAddress (str): IP address of the device at the end port (e.g., "192.168.1.10")
        - endPortAddress (str): Interface address of the end port (e.g., "GigabitEthernet1/0/24")
        - endPortDuplex (str): Duplex setting of the end port (e.g., "full")
        - endPortSpeed (str): Speed setting of the end port (e.g., "1000Mbps")
        - startDeviceHostName (str): Hostname of the device at the start port (e.g., "router-dc-01")
        - startDeviceId (str): Unique ID of the device at the start port (e.g., "device-2001")
        - startDeviceIpAddress (str): IP address of the device at the start port (e.g., "192.168.1.1")
        - startPortAddress (str): Interface address of the start port (e.g., "GigabitEthernet0/1")
        - startPortDuplex (str): Duplex setting of the start port (e.g., "full")
        - startPortSpeed (str): Speed setting of the start port (e.g., "1000Mbps")
        - lastUpdated (str): ISO 8601 timestamp of last update (e.g., "2025-06-26T10:15:00Z")
        - numUpdates (int): Number of updates recorded (e.g., 15)
        - avgUpdateFrequency (float): Average frequency of updates (e.g., 4.0)
        - type (str): Type of link (e.g., "ethernet-link")
        - instanceUuid (str): Unique instance UUID

        Parameters:
            site_ids (list): List of site IDs to fetch device link mismatch information.
            ip_uuid_map (dict): Mapping of device IPs to their UUIDs for which link mismatch details need to be retrieved.

        Returns:
        list: A list containing a single dictionary with structure:
            [
                {
                    "device_link_mismatch_info": [
                        {
                            "device_ip": "<device_management_ip>",
                            "vlan": [
                                {
                                    "device_ip": "<device_ip>",
                                    "link_mismatch_details": <list_of_vlan_mismatch_data_or_error_message>
                                }
                            ],
                            "speed-duplex": [
                                {
                                    "device_ip": "<device_ip>",
                                    "link_mismatch_details": <list of speed duplex mismatch data, exception or empty string>
                                }
                            ]
                        },
                    ]
                }
            ]
        """

        self.log("Fetching device link mismatch data for {0} devices: {1}".format(len(ip_uuid_map), list(ip_uuid_map.keys())), "INFO")

        link_mismatch_info = []

        for device_ip, device_id in ip_uuid_map.items():
            site_result = {
                "device_ip": device_ip,
                "vlan": [],
                "speed-duplex": []
            }

            for category in ['vlan', 'speed-duplex']:
                self.log("Processing device ID: {0} (IP: {1})".format(device_id, device_ip), "DEBUG")
                self.log("Fetching device link mismatch info for device_id: {0}, device_ip: {1}".format(device_id, device_ip), "DEBUG")

                try:
                    response = self.dnac._exec(
                        family="devices",
                        function="inventory_insight_device_link_mismatch",
                        params={
                            'site_id': site_id,
                            'category': category
                        }
                    )
                    self.log(
                        "Received API response from 'inventory_insight_device_link_mismatch': {0}".format(
                            (response)
                        ),
                        "DEBUG",
                    )
                    mismatch_data = response.get("response", [])
                    if mismatch_data:
                        self.log(
                            "Received API response for device {0}: {1}".format(device_ip, mismatch_data),
                            "DEBUG"
                        )
                        if isinstance(mismatch_data, list):
                            site_result[category].append({
                                "device_ip": device_ip,
                                "link_mismatch_details": mismatch_data
                            })

                    else:
                        self.log("No link mismatch found for device IP: {0}".format(device_ip), "DEBUG")
                        site_result[category].append({
                            "device_ip": device_ip,
                            "link_mismatch_details": []
                        })

                    if category == 'vlan':
                        self.log("VLAN Category Link Mismatch Response for site {0}: {1}".format(site_id, response), "INFO")
                    else:
                        self.log("Speed-Duplex Category Link Mismatch Response for site {0}: {1}".format(site_id, response), "INFO")

                except Exception as e:
                    self.msg = "Exception occurred while getting {0} link mismatch data for site {1}: {2}".format(category, site_id, e)
                    site_result[category].append({
                        "device_ip": device_ip,
                        "link_mismatch_details": "Error: {0}".format(e)
                    })
                    continue

            self.log(site_result["vlan"])
            self.log(site_result["speed-duplex"])
            link_mismatch_info.append(site_result)

        result = [{"device_link_mismatch_info": link_mismatch_info}]

        self.log("Completed Device Link Mismatch info retrieval. Total devices processed: {0}".format(len(link_mismatch_info)), "INFO")
        self.log("Device Link Mismatch info result: {0}".format(result), "DEBUG")

        return result

    def write_device_info_to_file(self, filtered_config):
        """
        Write collected network device information to a specified file with comprehensive format support and error handling.

        This method provides robust file output capabilities for network device data with support for multiple
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

        self.log("Extracted file parameters - Path: {0}, Format: {1}, Mode: {2}, Timestamp: {3}".format(
            target_file_path, output_file_format, file_write_mode, include_timestamp_flag), "INFO")

        if not target_file_path:
            self.log("No file_path specified in output_file_info", "ERROR")
            return self

        if file_write_mode not in {"w", "a"}:
            self.log("Invalid file_mode '{0}'. Use 'w' (overwrite) or 'a' (append).".format(file_write_mode), "ERROR")
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
                timestamp_entry = {"Downloaded at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
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
                    self.log("Failed to read existing file. Starting fresh.", "WARNING")
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
    """
    main entry point for module execution
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

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    ccc_device_info = NetworkDevicesInfo(module)
    state = ccc_device_info.params.get("state")

    current_version = ccc_device_info.get_ccc_version()
    min_supported_version = "2.3.7.9"

    if ccc_device_info.compare_dnac_versions(current_version, min_supported_version) < 0:
        ccc_device_info.status = "failed"
        ccc_device_info.msg = (
            "The specified version '{0}' does not support the 'network device info workflow' feature. "
            "Supported version(s) start from '{1}' onwards.".format(current_version, min_supported_version)
        )
        ccc_device_info.log(ccc_device_info.msg, "ERROR")
        ccc_device_info.check_return_status()

    if state not in ccc_device_info.supported_states:
        ccc_device_info.status = "invalid"
        ccc_device_info.msg = "State {0} is invalid".format(state)
        ccc_device_info.check_return_status()

    ccc_device_info.validate_input().check_return_status()

    for config in ccc_device_info.validated_config:
        ccc_device_info.reset_values()
        ccc_device_info.get_want(config).check_return_status()
        ccc_device_info.get_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_device_info.result)


if __name__ == '__main__':
    main()
