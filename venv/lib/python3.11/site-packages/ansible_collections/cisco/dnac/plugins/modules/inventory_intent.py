#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Madhan Sankaranarayanan, Abhishek Maheshwari"
DOCUMENTATION = r"""
---
module: inventory_intent
short_description: Resource module for Network Device
description:
  - Manage operations create, update and delete of the resource Network Device.
  - Adds the device with given credential.
  - Deletes the network device for the given Id.
  - Sync the devices provided as input.
version_added: '6.8.0'
extends_documentation_fragment:
  - cisco.dnac.intent_params
author: Abhishek Maheshwari (@abmahesh) Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst Center config after applying
      the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description: List of devices with credentails to perform Add/Update/Delete/Resync
      operation
    type: list
    elements: dict
    required: true
    suboptions:
      type:
        description: Select Device's type from NETWORK_DEVICE, COMPUTE_DEVICE, MERAKI_DASHBOARD,
          THIRD_PARTY_DEVICE, FIREPOWER_MANAGEMENT_SYSTEM. NETWORK_DEVICE - This refers
          to traditional networking equipment such as routers, switches, access points,
          and firewalls. These devices are responsible for routing, switching, and
          providing connectivity within the network. COMPUTE_DEVICE - These are computing
          resources such as servers, virtual machines, or containers that are part
          of the network infrastructure. Cisco Catalyst Center can integrate with
          compute devices to provide visibility and management capabilities, ensuring
          that the network and compute resources work together seamlessly to support
          applications and services. MERAKI_DASHBOARD - It is cloud-based platform
          used to manage Meraki networking devices, including wireless access points,
          switches, security appliances, and cameras. THIRD_PARTY_DEVICE - This category
          encompasses devices from vendors other than Cisco or Meraki. Cisco Catalyst
          Center is designed to support integration with third-party devices through
          open standards and APIs. This allows organizations to manage heterogeneous
          network environments efficiently using Cisco Catalyst Center's centralized
          management and automation capabilities. FIREPOWER_MANAGEMENT_SYSTEM - It
          is a centralized management console used to manage Cisco's Firepower Next-Generation
          Firewall (NGFW) devices. It provides features such as policy management,
          threat detection, and advanced security analytics.
        type: str
        default: "NETWORK_DEVICE"
      cli_transport:
        description: The essential prerequisite for adding Network devices is the
          specification of the transport protocol (either ssh or telnet) used by the
          device.
        type: str
      compute_device:
        description: Indicates whether a device is a compute device.
        type: bool
      password:
        description: Password for accessing the device and for file encryption during
          device export. Required for adding Network Device. Also needed for file
          encryption while exporting device in a csv file.
        type: str
      enable_password:
        description: Password required for enabling configurations on the device.
        type: str
      extended_discovery_info:
        description: Additional discovery information for the device.
        type: str
      http_password:
        description: HTTP password required for adding compute, Meraki, and Firepower
          Management Devices.
        type: str
      http_port:
        description: HTTP port number required for adding compute and Firepower Management
          Devices.
        type: str
      http_secure:
        description: Flag indicating HTTP security.
        type: bool
      http_username:
        description: HTTP username required for adding compute and Firepower Management
          Devices.
        type: str
      ip_address_list:
        description: A list of the IP addresses for the devices. It is required for
          tasks such as adding, updating, deleting, or resyncing devices, with Meraki
          devices being the exception.
        elements: str
        type: list
      hostnames:
        description: "A list of hostnames representing devices. Operations such as
          updating, deleting, resyncing, or rebooting can be performed as alternatives
          to using IP addresses."
        type: list
        elements: str
      serial_numbers:
        description: A list of serial numbers representing devices. Operations such
          as updating, deleting, resyncing, or rebooting can be performed as alternatives
          to using IP addresses.
        type: list
        elements: str
      mac_addresses:
        description: "A list of MAC addresses representing devices. Operations such
          as updating, deleting, resyncing, or rebooting can be performed as alternatives
          to using IP addresses."
        type: list
        elements: str
      netconf_port:
        description: Specifies the port number for connecting to devices using the
          Netconf protocol. Netconf (Network Configuration Protocol) is used for managing
          network devices. Ensure that the provided port number corresponds to the
          Netconf service port configured on your network devices. NETCONF with user
          privilege 15 is mandatory for enabling Wireless Services on Wireless capable
          devices such as Catalyst 9000 series Switches and C9800 Series Wireless
          Controllers. The NETCONF credentials are required to connect to C9800 Series
          Wireless Controllers as the majority of data collection is done using NETCONF
          for these Devices.
        type: str
      username:
        description: Username for accessing the device. Required for Adding Network
          Device.
        type: str
      snmp_auth_passphrase:
        description: SNMP authentication passphrase required for adding network, compute,
          and third-party devices.
        type: str
      snmp_auth_protocol:
        description: SNMP authentication protocol. SHA (Secure Hash Algorithm) - cryptographic
          hash function commonly used for data integrity verification and authentication
          purposes.
        type: str
        default: "SHA"
      snmp_mode:
        description: Device's snmp Mode refer to different SNMP (Simple Network Management
          Protocol) versions and their corresponding security levels. NOAUTHNOPRIV
          - This mode provides no authentication or encryption for SNMP messages.
          It means that devices communicating using SNMPv1 do not require any authentication
          (username/password) or encryption (data confidentiality). This makes it
          the least secure option. AUTHNOPRIV - This mode provides authentication
          but no encryption for SNMP messages. Authentication involves validating
          the source of the SNMP messages using a community string (similar to a password).
          However, the data transmitted between devices is not encrypted, so it's
          susceptible to eavesdropping. AUTHPRIV - This mode provides both authentication
          and encryption for SNMP messages. It offers the highest level of security
          among the three options. Authentication ensures that the source of the messages
          is genuine, and encryption ensures that the data exchanged between devices
          is confidential and cannot be intercepted by unauthorized parties.
        type: str
      snmp_priv_passphrase:
        description: SNMP private passphrase required for adding network, compute,
          and third-party devices.
        type: str
      snmp_priv_protocol:
        description: SNMP private protocol required for adding network, compute, and
          third-party devices.
        type: str
      snmp_ro_community:
        description: SNMP Read-Only community required for adding V2C devices.
        type: str
      snmp_rw_community:
        description: SNMP Read-Write community required for adding V2C devices.
        type: str
      snmp_retry:
        description: SNMP retry count.
        type: int
        default: 3
      snmp_timeout:
        description: SNMP timeout duration.
        type: int
        default: 5
      snmp_username:
        description: SNMP username required for adding network, compute, and third-party
          devices.
        type: str
      snmp_version:
        description: It is a standard protocol used for managing and monitoring network
          devices. v2 - In this communication between the SNMP manager (such as Cisco
          Catalyst) and the managed devices (such as routers, switches, or access
          points) is based on community strings.Community strings serve as form of
          authentication and they are transmitted in clear text, providing no encryption.
          v3 - It is the most secure version of SNMP, providing authentication, integrity,
          and encryption features. It allows for the use of usernames, authentication
          passwords, and encryption keys, providing stronger security compared to
          v2.
        type: str
      update_mgmt_ipaddresslist:
        description: List of updated management IP addresses for network devices.
        type: list
        elements: dict
        suboptions:
          exist_mgmt_ipaddress:
            description: Device's existing Mgmt IpAddress.
            type: str
          new_mgmt_ipaddress:
            description: Device's new Mgmt IpAddress.
            type: str
      force_sync:
        description: If forcesync is true then device sync would run in high priority
          thread if available, else the sync will fail.
        type: bool
        default: false
      device_resync:
        description: Make this as true needed for the resyncing of device.
        type: bool
        default: false
      resync_device_count:
        description: Specifies the maximum number of devices to be resynced in the
          inventory. Ensure this count does not exceed 200, as attempting to resync
          more than 200 devices may cause the 'sync_devices_using_forcesync' API to
          enter an infinite loop.
        type: int
        default: 200
      resync_max_timeout:
        description: Sets the maximum timeout for the device resync process in the
          inventory, in seconds. The default is 600 seconds, which helps prevent infinite
          loops.
        type: int
        default: 600
      reboot_device:
        description: Make this as true needed for the Rebooting of Access Points.
        type: bool
        default: false
      export_device_details_limit:
        description: Specifies the limit for updating device details or exporting
          device details/credentials to a file. The default limit is set to 500 devices.
          This limit is applied when exporting device details/credentials and editing
          device details. The maximum number of device details/credentials that can
          be exported in a single API call is 800.
        type: int
        default: 500
      credential_update:
        description: Set this to 'True' to update device credentials and other device
          details. When this parameter is 'True', ensure that the devices are present
          in Cisco Catalyst Center; only then can update operations be performed on
          the respective devices. If the parameter is 'True' and any device is not
          present, the module will attempt to add it.  If required parameters are
          missing during this addition, the module will fail and stop execution, preventing
          update operations for devices that are already present.
        type: bool
        default: false
      clean_config:
        description: Required if need to delete the Provisioned device by clearing
          current configuration.
        type: bool
        default: false
      role:
        description: Role of device which can be ACCESS, CORE, DISTRIBUTION, BORDER
          ROUTER, UNKNOWN. ALL - This role typically represents all devices within
          the network, regardless of their specific roles or functions. UNKNOWN -
          This role is assigned to devices whose roles or functions have not been
          identified or classified within Cisco Catalsyt Center. This could happen
          if the platform is unable to determine the device's role based on available
          information. ACCESS - This role typically represents switches or access
          points that serve as access points for end-user devices to connect to the
          network. These devices are often located at the edge of the network and
          provide connectivity to end-user devices. BORDER ROUTER - These are devices
          that connect different network domains or segments together. They often
          serve as gateways between different networks, such as connecting an enterprise
          network to the internet or connecting multiple branch offices. DISTRIBUTION
          - This role represents function as distribution switches or routers in hierarchical
          network designs. They aggregate traffic from access switches and route it
          toward the core of the network or toward other distribution switches. CORE
          - This role typically represents high-capacity switches or routers that
          form the backbone of the network. They handle large volumes of traffic and
          provide connectivity between different parts of network, such as connecting
          distribution switches or providing interconnection between different network
          segments.
        type: str
      add_user_defined_field:
        description: This operation will take dictionary as a parameter and in this
          we give details to create/update/delete/assign multiple UDF to a device.
        type: dict
        suboptions:
          name:
            description: Name of Global User Defined Field. Required for creating/deleting
              UDF and then assigning it to device.
            type: str
          description:
            description: Info about the global user defined field. Also used while
              updating interface details.
            type: str
          value:
            description: Value to assign to tag with or without the same user defined
              field name.
            type: str
      update_interface_details:
        description: This operation will take dictionary as a parameter and in this
          we give details to update interface details of device.
        type: dict
        suboptions:
          description:
            description: Specifies the description of the interface of the device.
            type: str
          interface_name:
            description: Specify the list of interface names to update the details
              of the device interface. (For example, GigabitEthernet1/0/11, FortyGigabitEthernet1/1/2)
            type: list
            elements: str
          vlan_id:
            description: Unique Id number assigned to a VLAN within a network used
              only while updating interface details.
            type: int
          voice_vlan_id:
            description: Identifier used to distinguish a specific VLAN that is dedicated
              to voice traffic used only while updating interface details.
            type: int
          deployment_mode:
            description: Preview/Deploy [Preview means the configuration is not pushed
              to the device. Deploy makes the configuration pushed to the device]
            type: str
            default: "Deploy"
          clear_mac_address_table:
            description: Set this to true if you need to clear the MAC address table
              for a specific device's interface. It's a boolean type, with a default
              value of False.
            type: bool
            default: false
          admin_status:
            description: Status of Interface of a device, it can be (UP/DOWN).
            type: str
      export_device_list:
        description: This operation take dictionary as parameter and export the device
          details as well as device credentials details in a csv file.
        type: dict
        suboptions:
          password:
            description: Specifies the password for the encryption of file while exporting
              the device credentails into the file.
            type: str
          site_name:
            description: Indicates the exact location where the wired device will
              be provisioned. This is a string value that should represent the complete
              hierarchical path of the site (For example, "Global/USA/San Francisco/BGL_18/floor_pnp").
            type: str
          operation_enum:
            description: enum(CREDENTIALDETAILS, DEVICEDETAILS) 0 to export Device
              Credential Details Or 1 to export Device Details. CREDENTIALDETAILS
              - Used for exporting device credentials details like snpm credntials,
              device crdentails etc. DEVICEDETAILS - Used for exporting device specific
              details like device hostname, serial number, type, family etc.
            type: str
          parameters:
            description: List of device parameters that needs to be exported to file.(For
              example, ["componentName", "SerialNumber", "Last Sync Status"])
            type: list
            elements: str
      provision_wired_device:
        description: This parameter takes a list of dictionaries. Each dictionary
          provides the IP address of a wired device and the name of the site where
          the device will be provisioned.
        type: list
        elements: dict
        suboptions:
          device_ip:
            description: Specifies the IP address of the wired device. This is a string
              value that should be in the format of standard IPv4 or IPv6 addresses.
            type: str
            version_added: 6.12.0
          site_name:
            description: Indicates the exact location where the wired device will
              be provisioned. This is a string value that should represent the complete
              hierarchical path of the site (For example, "Global/USA/San Francisco/BGL_18/floor_pnp").
            type: str
          resync_retry_count:
            description: Determines the total number of retry attempts for checking
              if the device has reached a managed state during the provisioning process.
              If unspecified, the default value is set to 200 retries.
            type: int
            default: 200
            version_added: 6.12.0
          resync_retry_interval:
            description: Sets the interval, in seconds, at which the system will recheck
              the device status throughout the provisioning process. If unspecified,
              the system will check the device status every 2 seconds by default.
            type: int
            default: 2
            version_added: 6.12.0
requirements:
  - dnacentersdk >= 2.7.2
  - python >= 3.9
seealso:
  - name: Cisco Catalyst Center documentation for Devices AddDevice2
    description: Complete reference of the AddDevice2 API.
    link: https://developer.cisco.com/docs/dna-center/#!add-device
  - name: Cisco Catalyst Center documentation for Devices DeleteDeviceById
    description: Complete reference of the DeleteDeviceById API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-device-by-id
  - name: Cisco Catalyst Center documentation for Devices SyncDevices2
    description: Complete reference of the SyncDevices2 API.
    link: https://developer.cisco.com/docs/dna-center/#!sync-devices
notes:
  - SDK Method used are devices.Devices.add_device, devices.Devices.delete_device_by_id,
    devices.Devices.sync_devices,
  - Paths used are post /dna/intent/api/v1/network-device, delete /dna/intent/api/v1/network-device/{id},
    put /dna/intent/api/v1/network-device,
  - Removed 'managementIpAddress' options in v4.3.0.
  - Renamed argument 'ip_address' to 'ip_address_list' option in v6.12.0.
  - Removed 'serial_number', 'device_added', 'role_source', options in v6.12.0.
  - Added 'add_user_defined_field', 'update_interface_details', 'export_device_list'
    options in v6.13.1.
  - Removed 'provision_wireless_device', 'reprovision_wired_device' options in v6.13.1.
  - Added the parameter 'admin_status' options in v6.13.1.
  - Removed 'device_updated' options in v6.13.1.
"""
EXAMPLES = r"""
- name: Add new device in Inventory with full credentials
  cisco.dnac.inventory_intent:
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
      - cli_transport: ssh
        compute_device: false
        password: Test@123
        enable_password: Test@1234
        extended_discovery_info: test
        http_username: "testuser"
        http_password: "test"
        http_port: "443"
        http_secure: false
        ip_address_list: ["1.1.1.1", "2.2.2.2"]
        netconf_port: 830
        snmp_auth_passphrase: "Lablab@12"
        snmp_auth_protocol: SHA
        snmp_mode: AUTHPRIV
        snmp_priv_passphrase: "Lablab@123"
        snmp_priv_protocol: AES256
        snmp_retry: 3
        snmp_timeout: 5
        snmp_username: v3Public
        snmp_version: v3
        type: NETWORK_DEVICE
        username: cisco
- name: Add new Compute device in Inventory with full credentials.Inputs needed
    for Compute Device
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        http_username: "testuser"
        http_password: "test"
        http_port: "443"
        snmp_auth_passphrase: "Lablab@12"
        snmp_auth_protocol: SHA
        snmp_mode: AUTHPRIV
        snmp_priv_passphrase: "Lablab@123"
        snmp_priv_protocol: AES256
        snmp_retry: 3
        snmp_timeout: 5
        snmp_username: v3Public
        compute_device: true
        username: cisco
        type: "COMPUTE_DEVICE"
- name: Add new Meraki device in Inventory with full credentials.Inputs needed for
    Meraki Device.
  cisco.dnac.inventory_intent:
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
      - http_password: "test"
        type: "MERAKI_DASHBOARD"
- name: Add new Firepower Management device in Inventory with full credentials.Input
    needed to add Device.
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        http_username: "testuser"
        http_password: "test"
        http_port: "443"
        type: "FIREPOWER_MANAGEMENT_SYSTEM"
- name: Add new Third Party device in Inventory with full credentials.Input needed
    to add Device.
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        snmp_auth_passphrase: "Lablab@12"
        snmp_auth_protocol: SHA
        snmp_mode: AUTHPRIV
        snmp_priv_passphrase: "Lablab@123"
        snmp_priv_protocol: AES256
        snmp_retry: 3
        snmp_timeout: 5
        snmp_username: v3Public
        type: "THIRD_PARTY_DEVICE"
- name: Update device details or credentails in Inventory
  cisco.dnac.inventory_intent:
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
      - cli_transport: telnet
        compute_device: false
        password: newtest123
        enable_password: newtest1233
        ip_address_list: ["1.1.1.1", "2.2.2.2"]
        type: NETWORK_DEVICE
        credential_update: true
- name: Update new management IP address of device in inventory
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1"]
        credential_update: true
        update_mgmt_ipaddresslist:
          - exist_mgmt_ipaddress: "1.1.1.1"
            new_mgmt_ipaddress: "12.12.12.12"
- name: Associate Wired Devices to site and Provisioned it in Inventory
  cisco.dnac.inventory_intent:
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
      - provision_wired_device:
          - device_ip: "1.1.1.1"
            site_name: "Global/USA/San Francisco/BGL_18/floor_pnp"
            resync_retry_count: 200
            resync_retry_interval: 2
          - device_ip: "2.2.2.2"
            site_name: "Global/USA/San Francisco/BGL_18/floor_test"
            resync_retry_count: 200
            resync_retry_interval: 2
- name: Update Device Role with IP Address
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        role: ACCESS
- name: Update Interface details with IP Address
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        update_interface_details:
          description: "Testing for updating interface details"
          admin_status: "UP"
          vlan_id: 23
          voice_vlan_id: 45
          deployment_mode: "Deploy"
          interface_name: ["GigabitEthernet1/0/11", FortyGigabitEthernet1/1/1]
          clear_mac_address_table: true
- name: Export Device Details in a CSV file Interface details with IP Address
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        export_device_list:
          password: "File_password"
          operation_enum: "0"
          parameters: ["componentName", "SerialNumber", "Last Sync Status"]
- name: Create Global User Defined with IP Address
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        add_user_defined_field:
          - name: Test123
            description: "Added first udf for testing"
            value: "value123"
          - name: Test321
            description: "Added second udf for testing"
            value: "value321"
- name: Resync Device with IP Addresses
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        device_resync: true
        force_sync: false
- name: Reboot AP Devices with IP Addresses
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        reboot_device: true
- name: Delete Provision/Unprovision Devices by IP Address
  cisco.dnac.inventory_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: false
    dnac_log_level: "{{dnac_log_level}}"
    state: deleted
    config:
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        clean_config: false
- name: Delete Global User Defined Field with name
  cisco.dnac.inventory_intent:
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
      - ip_address_list: ["1.1.1.1", "2.2.2.2"]
        add_user_defined_field:
          - name: Test123
          - name: Test321
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
# common approach when a module relies on optional dependencies that are not available during the validation process.
try:
    import pyzipper

    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False
    pyzipper = None

import csv
import time
from datetime import datetime
from io import BytesIO, StringIO
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)

# Defer this feature as API issue is there once it's fixed we will addresses it in upcoming release iac2.0
support_for_provisioning_wireless = False


class DnacDevice(DnacBase):
    """Class containing member attributes for Inventory intent module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]

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
            "cli_transport": {"type": "str"},
            "compute_device": {"type": "bool"},
            "enable_password": {"type": "str"},
            "extended_discovery_info": {"type": "str"},
            "http_password": {"type": "str"},
            "http_port": {"type": "str"},
            "http_secure": {"type": "bool"},
            "http_username": {"type": "str"},
            "ip_address_list": {"type": "list", "elements": "str"},
            "hostnames": {"type": "list", "elements": "str"},
            "serial_numbers": {"type": "list", "elements": "str"},
            "mac_addresses": {"type": "list", "elements": "str"},
            "netconf_port": {"type": "str"},
            "password": {"type": "str"},
            "snmp_auth_passphrase": {"type": "str"},
            "snmp_auth_protocol": {"default": "SHA", "type": "str"},
            "snmp_mode": {"type": "str"},
            "snmp_priv_passphrase": {"type": "str"},
            "snmp_priv_protocol": {"type": "str"},
            "snmp_ro_community": {"type": "str"},
            "snmp_rw_community": {"type": "str"},
            "snmp_retry": {"default": 3, "type": "int"},
            "snmp_timeout": {"default": 5, "type": "int"},
            "snmp_username": {"type": "str"},
            "snmp_version": {"type": "str"},
            "update_mgmt_ipaddresslist": {"type": "list", "elements": "dict"},
            "username": {"type": "str"},
            "role": {"type": "str"},
            "device_resync": {"type": "bool"},
            "reboot_device": {"type": "bool"},
            "credential_update": {"type": "bool"},
            "export_device_details_limit": {"default": 500, "type": "int"},
            "resync_device_count": {"default": 200, "type": "int"},
            "resync_max_timeout": {"default": 600, "type": "int"},
            "force_sync": {"type": "bool"},
            "clean_config": {"type": "bool"},
            "add_user_defined_field": {
                "type": "list",
                "elements": "dict",
                "name": {"type": "str"},
                "description": {"type": "str"},
                "value": {"type": "str"},
            },
            "update_interface_details": {
                "type": "dict",
                "description": {"type": "str"},
                "vlan_id": {"type": "int"},
                "voice_vlan_id": {"type": "int"},
                "interface_name": {"type": "list", "elements": "str"},
                "deployment_mode": {"default": "Deploy", "type": "str"},
                "clear_mac_address_table": {"default": False, "type": "bool"},
                "admin_status": {"type": "str"},
            },
            "export_device_list": {
                "type": "dict",
                "password": {"type": "str"},
                "operation_enum": {"type": "str"},
                "parameters": {"type": "list", "elements": "str"},
            },
            "provision_wired_device": {
                "type": "list",
                "elements": "dict",
                "device_ip": {"type": "str"},
                "site_name": {"type": "str"},
                "resync_retry_count": {"default": 200, "type": "int"},
                "resync_retry_interval": {"default": 2, "type": "int"},
            },
        }

        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, temp_spec)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                invalid_params)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            self.result["response"] = self.msg
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def get_device_ips_from_config_priority(self):
        """
        Retrieve device IPs based on the configuration.
        Parameters:
            -  self (object): An instance of a class used for interacting with Cisco Cisco Catalyst Center.
        Returns:
            list: A list containing device IPs.
        Description:
            This method retrieves device IPs based on the priority order specified in the configuration.
            It first checks if device IPs are available. If not, it checks hostnames, serial numbers,
            and MAC addresses in order and retrieves IPs based on availability.
            If none of the information is available, an empty list is returned.
        """
        # Retrieve device IPs from the configuration
        device_ips = self.want.get("device_params").get("ipAddress")

        if device_ips:
            return device_ips

        # If device IPs are not available, check hostnames
        device_hostnames = self.config[0].get("hostnames")
        if device_hostnames:
            device_ip_dict = self.get_device_ips_from_hostnames(
                device_hostnames)
            return self.get_list_from_dict_values(device_ip_dict)

        # If hostnames are not available, check serial numbers
        device_serial_numbers = self.config[0].get("serial_numbers")
        if device_serial_numbers:
            device_ip_dict = self.get_device_ips_from_serial_numbers(
                device_serial_numbers
            )
            return self.get_list_from_dict_values(device_ip_dict)

        # If serial numbers are not available, check MAC addresses
        device_mac_addresses = self.config[0].get("mac_addresses")
        if device_mac_addresses:
            device_ip_dict = self.get_device_ips_from_mac_addresses(
                device_mac_addresses
            )
            return self.get_list_from_dict_values(device_ip_dict)

        # If no information is available, return an empty list
        return []

    def get_existing_devices_in_ccc(self):
        """
        Check which devices already exists and retrieve the list of devices that already exist in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Cisco Catalyst Center.
        Returns:
            list: A list of management IP addresses for devices that exist in Cisco Catalyst Center.
        Description:
            Queries Cisco Catalyst Center to check which devices are already present in Cisco Catalyst Center and store
            its management IP address in the list of devices that exist.
        Example:
            To use this method, create an instance of the class and call 'get_existing_devices_in_ccc' on it,
            The method returns a list of management IP addressesfor devices that exist in Cisco Catalyst Center.
        """

        existing_devices_in_ccc = set()
        offset = 0
        limit = self.get_device_details_limit()
        initial_exec = False

        while True:
            try:
                if initial_exec:
                    response = self.dnac._exec(
                        family="devices",
                        function="get_device_list",
                        params={"offset": offset * limit, "limit": limit},
                    )
                else:
                    initial_exec = True
                    response = self.dnac._exec(
                        family="devices",
                        function="get_device_list",
                    )
                offset = offset + 1
                response = response.get("response")
                if not response:
                    self.log(
                        "There are no device details received from 'get_device_list' API.",
                        "INFO",
                    )
                    break

                self.log(
                    "Received API response from 'get_device_list': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                for ip in response:
                    device_ip = ip["managementIpAddress"]
                    existing_devices_in_ccc.add(device_ip)

            except Exception as e:
                self.status = "failed"
                self.msg = "Error while fetching device details from Cisco Catalyst Center: {0}".format(
                    str(e)
                )
                self.log(self.msg, "CRITICAL")
                self.check_return_status()
        self.log(
            "Devices present in Cisco Catalyst Center: {0}".format(
                str(existing_devices_in_ccc)
            ),
            "DEBUG",
        )
        existing_devices_in_ccc = list(existing_devices_in_ccc)

        return existing_devices_in_ccc

    def is_udf_exist(self, field_name):
        """
        Check if a Global User Defined Field exists in Cisco Catalyst Center based on its name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            field_name (str): The name of the Global User Defined Field.
        Returns:
            bool: True if the Global User Defined Field exists, False otherwise.
        Description:
            The function sends a request to Cisco Catalyst Center to retrieve all Global User Defined Fields
            with the specified name. If matching field is found, the function returns True, indicating that
            the field exists else returns False.
        """

        response = self.dnac._exec(
            family="devices",
            function="get_all_user_defined_fields",
            op_modifies=True,
            params={"name": field_name},
        )

        self.log(
            "Received API response from 'get_all_user_defined_fields': {0}".format(
                str(response)
            ),
            "DEBUG",
        )
        udf = response.get("response")

        if len(udf) == 1:
            return True

        message = "Global User Defined Field with name '{0}' doesnot exist in Cisco Catalyst Center".format(
            field_name
        )
        self.log(message, "INFO")

        return False

    def create_user_defined_field(self, udf):
        """
        Create a Global User Defined Field in Cisco Catalyst Center based on the provided configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            udf (dict): A dictionary having the payload for the creation of user defined field(UDF) in Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            The function retrieves the configuration for adding a user-defined field from the configuration object,
            sends the request to Cisco Catalyst Center to create the field, and logs the response.
        """
        try:
            response = self.dnac._exec(
                family="devices",
                function="create_user_defined_field",
                op_modifies=True,
                params=udf,
            )
            self.log(
                "Received API response from 'create_user_defined_field': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")
            field_name = udf.get("name")
            self.log(
                "Global User Defined Field with name '{0}' created successfully".format(
                    field_name
                ),
                "INFO",
            )
            self.status = "success"

        except Exception as e:
            error_message = "Error while creating Global UDF(User Defined Field) in Cisco Catalyst Center: {0}".format(
                str(e)
            )
            self.log(error_message, "ERROR")

        return self

    def add_field_to_devices(self, device_ids, udf):
        """
        Add a Global user-defined field with specified details to a list of devices in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ids (list): A list of device IDs to which the user-defined field will be added.
            udf (dict): A dictionary having the user defined field details including name and value.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            The function retrieves the details of the user-defined field from the configuration object,
            including the field name and default value then iterates over list of device IDs, creating a payload for
            each device and sending the request to Cisco Catalyst Center to add the user-defined field.
        """
        # field_details = self.config[0].get('add_user_defined_field')
        field_name = udf.get("name")
        field_value = udf.get("value", "1")
        for device_id in device_ids:
            payload = {}
            payload["name"] = field_name
            payload["value"] = field_value
            udf_param_dict = {"payload": [payload], "device_id": device_id}
            try:
                response = self.dnac._exec(
                    family="devices",
                    function="add_user_defined_field_to_device",
                    op_modifies=True,
                    params=udf_param_dict,
                )
                self.log(
                    "Received API response from 'add_user_defined_field_to_device': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                response = response.get("response")
                self.status = "success"
                self.result["changed"] = True

            except Exception as e:
                self.status = "failed"
                error_message = "Error while adding Global UDF to device in Cisco Catalyst Center: {0}".format(
                    str(e)
                )
                self.log(error_message, "ERROR")
                self.result["changed"] = False

        return self

    def trigger_export_api(self, payload_params):
        """
        Triggers the export API to generate a CSV file containing device details based on the given payload parameters.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            payload_params (dict): A dictionary containing parameters required for the export API.
        Returns:
            dict: The response from the export API, including information about the task and file ID.
                If the export is successful, the CSV file can be downloaded using the file ID.
        Description:
            The function initiates the export API in Cisco Catalyst Center to generate a CSV file containing detailed information
            about devices.The response from the API includes task details and a file ID.
        """

        response = self.dnac._exec(
            family="devices",
            function="export_device_list",
            op_modifies=True,
            params=payload_params,
        )
        self.log(
            "Received API response from 'export_device_list': {0}".format(
                str(response)
            ),
            "DEBUG",
        )
        response = response.get("response")
        task_id = response.get("taskId")

        while True:
            execution_details = self.get_task_details(task_id)

            if execution_details.get("additionalStatusURL"):
                file_id = execution_details.get(
                    "additionalStatusURL").split("/")[-1]
                break
            elif execution_details.get("isError"):
                self.status = "failed"
                failure_reason = execution_details.get("failureReason")
                if failure_reason:
                    self.msg = "Could not get the File ID because of {0} so can't export device details in csv file".format(
                        failure_reason
                    )
                else:
                    self.msg = "Could not get the File ID so can't export device details in csv file"
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg

                return response

        # With this File ID call the Download File by FileID API and process the response
        response = self.dnac._exec(
            family="file",
            function="download_a_file_by_fileid",
            op_modifies=True,
            params={"file_id": file_id},
        )
        self.log(
            "Received API response from 'download_a_file_by_fileid': {0}".format(
                str(response)
            ),
            "DEBUG",
        )

        return response

    def decrypt_and_read_csv(self, response, password):
        """
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            response (requests.Response): HTTP response object containing the encrypted CSV file.
            password (str): Password used for decrypting the CSV file.
        Returns:
            csv.DictReader: A CSV reader object for the decrypted content, allowing iteration over rows as dictionaries.
        Description:
            Decrypts and reads a CSV-like file from the given HTTP response using the provided password.
        """

        zip_data = BytesIO(response.data)

        if not HAS_PYZIPPER:
            self.msg = "pyzipper is required for this module. Install pyzipper to use this functionality."
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            self.result["response"] = self.msg
            return self

        snmp_protocol = self.config[0].get("snmp_priv_protocol", "AES128")
        encryption_dict = {
            "AES128": "pyzipper.WZ_AES128",
            "AES192": "pyzipper.WZ_AES192",
            "AES256": "pyzipper.WZ_AES",
            "CISCOAES128": "pyzipper.WZ_AES128",
            "CISCOAES192": "pyzipper.WZ_AES192",
            "CISCOAES256": "pyzipper.WZ_AES",
        }
        try:
            encryption_method = encryption_dict.get(snmp_protocol)
        except Exception as e:
            self.log(
                "Given SNMP protcol '{0}' not present".format(
                    snmp_protocol), "WARNING"
            )

        if not encryption_method:
            self.msg = "Invalid SNMP protocol '{0}' specified for encryption.".format(
                snmp_protocol
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"
            self.result["response"] = self.msg
            return self

        # Create a PyZipper object with the password
        with pyzipper.AESZipFile(
            zip_data, "r", compression=pyzipper.ZIP_LZMA, encryption=encryption_method
        ) as zip_ref:
            # Assuming there is a single file in the zip archive
            file_name = zip_ref.namelist()[0]

            # Extract the content of the file with the provided password
            file_content_binary = zip_ref.read(
                file_name, pwd=password.encode("utf-8"))

        # Now 'file_content_binary' contains the binary content of the decrypted file
        # Since the content is text, so we can decode it
        file_content_text = file_content_binary.decode("utf-8")

        # Now 'file_content_text' contains the text content of the decrypted file
        self.log(
            "Text content of decrypted file: {0}".format(
                file_content_text), "DEBUG"
        )

        # Parse the CSV-like string into a list of dictionaries
        csv_reader = csv.DictReader(StringIO(file_content_text))

        return csv_reader

    def export_device_details(self):
        """
        Export device details from Cisco Catalyst Center into a CSV file.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class with updated result, status, and log.
        Description:
            This function exports device details from Cisco Catalyst Center based on the provided IP addresses in the configuration.
            It retrieves the device UUIDs, calls the export device list API, and downloads the exported data of both device details and
            and device credentials with an encrtypted zip file with password into CSV format.
            The CSV data is then parsed and written to a file.
        """

        device_ips = self.get_device_ips_from_config_priority()
        output_file_name = ""

        if not device_ips:
            self.status = "failed"
            self.msg = "Cannot export device details as no devices are specified in the playbook"
            self.log(self.msg, "ERROR")
            self.result["response"] = self.msg
            return self

        try:
            device_uuids = self.get_device_ids(device_ips)

            if not device_uuids:
                self.status = "failed"
                self.result["changed"] = False
                self.msg = "Could not find device UUIDs for exporting device details"
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                return self

            # Now all device UUID get collected so call the export device list API
            export_device_list = self.config[0].get("export_device_list")
            password = export_device_list.get("password")

            if not self.is_valid_password(password):
                self.status = "failed"
                detailed_msg = """Invalid password. Min password length is 8 and it should contain atleast one lower case letter,
                            one uppercase letter, one digit and one special characters from -=\\;,./~!@#$%^&*()_+{}[]|:?"""
                formatted_msg = " ".join(
                    line.strip() for line in detailed_msg.splitlines()
                )
                self.msg = formatted_msg
                self.log(formatted_msg, "INFO")
                self.result["response"] = self.msg
                return self

            # Export the device data in a batch of 500 devices at a time
            start = 0
            device_batch_size = self.config[0].get(
                "export_device_details_limit", 500)
            device_data = []
            first_run = True

            while start < len(device_uuids):
                device_ids_list = device_uuids[start: start +
                                               device_batch_size]
                payload_params = {
                    "deviceUuids": device_ids_list,
                    "password": password,
                    "operationEnum": export_device_list.get("operation_enum", "0"),
                    "parameters": export_device_list.get("parameters"),
                }

                response = self.trigger_export_api(payload_params)
                self.check_return_status()

                if payload_params["operationEnum"] == "0":
                    temp_file_name = response.filename
                    if first_run:
                        output_file_name = temp_file_name.split(".")[
                            0] + ".csv"
                    csv_reader = self.decrypt_and_read_csv(response, password)
                    self.check_return_status()
                else:
                    decoded_resp = response.data.decode(encoding="utf-8")
                    self.log(
                        "Decoded response of Export Device Credential file: {0}".format(
                            str(decoded_resp)
                        ),
                        "DEBUG",
                    )
                    # Parse the CSV-like string into a list of dictionaries
                    csv_reader = csv.DictReader(StringIO(decoded_resp))
                    current_date = datetime.now()
                    formatted_date = current_date.strftime("%m-%d-%Y")
                    if first_run:
                        output_file_name = "devices-" + \
                            str(formatted_date) + ".csv"

                for row in csv_reader:
                    device_data.append(row)
                start += device_batch_size
                first_run = False

            # Write the data to a CSV file
            with open(output_file_name, "w", newline="") as csv_file:
                fieldnames = device_data[0].keys()
                csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                csv_writer.writeheader()
                csv_writer.writerows(device_data)

            self.msg = (
                "Device Details Exported Successfully to the CSV file: {0}".format(
                    output_file_name
                )
            )
            self.log(self.msg, "INFO")
            self.status = "success"
            self.result["changed"] = True
            self.result["response"] = self.msg

        except Exception as e:
            self.msg = "Error while exporting device details into CSV file for device(s): '{0}'".format(
                str(device_ips)
            )
            self.log(self.msg, "ERROR")
            self.status = "failed"

        return self

    def get_ap_devices(self, device_ips):
        """
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ip (str): The management IP address of the device for which the response is to be retrieved.
        Returns:
            list: A list containing Access Point device IP's obtained from the Cisco Catalyst Center.
        Description:
            This method communicates with Cisco Catalyst Center to retrieve the details of a device with the specified
            management IP address and check if device family matched to Unified AP. It executes the 'get_device_list'
            API call with the provided device IP address, logs the response, and returns list containing ap device ips.
        """

        ap_device_list = []
        for device_ip in device_ips:
            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=True,
                    params={"managementIpAddress": device_ip},
                )
                response = response.get("response", [])

                if response and response[0].get("family", "") == "Unified AP":
                    ap_device_list.append(device_ip)
            except Exception as e:
                error_message = "Error while getting the response of device from Cisco Catalyst Center: {0}".format(
                    str(e)
                )
                self.log(error_message, "CRITICAL")
                raise Exception(error_message)

        return ap_device_list

    def resync_devices(self):
        """
        Resync devices in Cisco Catalyst Center.
        This function performs the Resync operation for the devices specified in the playbook.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            The function expects the following parameters in the configuration:
            - "ip_address_list": List of device IP addresses to be resynced.
            - "force_sync": (Optional) Whether to force sync the devices. Defaults to "False".
        """

        # Code for triggers the resync operation using the retrieved device IDs and force sync parameter.
        device_ips = self.get_device_ips_from_config_priority()
        input_device_ips = device_ips.copy()

        for device_ip in input_device_ips:
            if device_ip not in self.have.get("device_in_dnac"):
                input_device_ips.remove(device_ip)

        ap_devices = self.get_ap_devices(input_device_ips)
        self.log(
            "AP Devices from the playbook input are: {0}".format(
                str(ap_devices)),
            "INFO",
        )

        if ap_devices:
            for ap_ip in ap_devices:
                input_device_ips.remove(ap_ip)
            self.log(
                "Following devices {0} are AP, so can't perform resync operation.".format(
                    str(ap_devices)
                ),
                "WARNING",
            )

        if not input_device_ips:
            self.msg = "Cannot perform the Resync operation as the device(s) with IP(s) {0} are not present in Cisco Catalyst Center".format(
                str(device_ips)
            )
            self.status = "success"
            self.result["changed"] = False
            self.result["response"] = self.msg
            self.log(self.msg, "WARNING")
            return self

        device_ids = self.get_device_ids(input_device_ips)
        try:
            # Resync the device in a batch of 200 devices at a time in inventory by default
            start = 0
            resync_failed_for_all_device = False
            resync_device_count = self.config[0].get(
                "resync_device_count", 200)
            resync_successful_devices, resync_failed_devices = [], []
            force_sync = self.config[0].get("force_sync", False)
            resync_task_dict = {}

            while start < len(device_ids):
                device_ids_list = device_ids[start: start +
                                             resync_device_count]
                device_ips_list = input_device_ips[start: start +
                                                   resync_device_count]
                resync_param_dict = {
                    "payload": device_ids_list,
                    "force_sync": force_sync,
                }
                self.log(
                    "Request payload for reysnc Device having the device ids: {0}".format(
                        device_ids_list
                    ),
                    "INFO",
                )
                response = self.dnac._exec(
                    family="devices",
                    function="sync_devices_using_forcesync",
                    op_modifies=True,
                    params=resync_param_dict,
                )
                self.log(
                    "Received API response from 'sync_devices_using_forcesync': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                if not response or not isinstance(response, dict):
                    self.status = "failed"
                    self.msg = "Unable to resync the device(s) {0} in the inventory as response is empty.".format(
                        device_ips_list
                    )
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    return self

                task_id = response.get("response").get("taskId")
                resync_task_dict[task_id] = device_ips_list
                start += resync_device_count

            for task_id, device_list in resync_task_dict.items():
                max_timeout = self.config[0].get("resync_max_timeout", 600)
                start_time = time.time()

                while True:

                    if (time.time() - start_time) >= max_timeout:
                        self.log(
                            """Max timeout of {0} has reached for the task id '{1}' for the device(s) '{2}' to be resynced and unexpected
                                    task status so moving out to next task id""".format(
                                max_timeout, task_id, device_list
                            ),
                            "WARNING",
                        )
                        resync_failed_devices.extend(device_list)
                        break

                    execution_details = self.get_task_details(task_id)

                    if "Synced" in execution_details.get("progress"):
                        resync_successful_devices.extend(device_list)
                        break
                    elif execution_details.get("isError"):
                        resync_failed_devices.extend(device_list)
                        break
                    time.sleep(self.params.get("dnac_task_poll_interval"))

            if resync_failed_devices and resync_successful_devices:
                self.msg = (
                    "Device(s) '{0}' have been successfully resynced in the inventory in Cisco Catalyst Center. "
                    "Some device(s) '{1}' failed."
                ).format(resync_successful_devices, resync_failed_devices)
            elif resync_failed_devices:
                resync_failed_for_all_device = True
                self.msg = (
                    "Device resynced get failed for all given device(s) '{0}'.".format(
                        resync_failed_devices
                    )
                )
            else:
                self.msg = (
                    "Device(s) '{0}' have been successfully resynced in the inventory in Cisco Catalyst Center. "
                ).format(resync_successful_devices)

            if resync_failed_for_all_device:
                self.status = "failed"
                self.log(self.msg, "ERROR")
            else:
                self.status = "success"
                self.log(self.msg, "INFO")
                self.result["changed"] = True
            self.result["response"] = self.msg
        except Exception as e:
            self.status = "failed"
            error_message = (
                "Error while resyncing device in Cisco Catalyst Center: {0}".format(
                    str(e)
                )
            )
            self.log(error_message, "ERROR")

        return self

    def reboot_access_points(self):
        """
        Reboot access points in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class with updated result, status, and log.
        Description:
            This function performs a reboot operation on access points in Cisco Catalyst Center based on the provided IP addresses
            in the configuration. It retrieves the AP devices' MAC addresses, calls the reboot access points API, and monitors
            the progress of the reboot operation.
        """

        device_ips = self.get_device_ips_from_config_priority()
        input_device_ips = device_ips.copy()

        if input_device_ips:
            ap_devices = self.get_ap_devices(input_device_ips)
            self.log(
                "AP Devices from the playbook input are: {0}".format(
                    str(ap_devices)),
                "INFO",
            )
            for device_ip in input_device_ips:
                if device_ip not in ap_devices:
                    input_device_ips.remove(device_ip)

        if not input_device_ips:
            self.msg = "No AP Devices IP given in the playbook so can't perform reboot operation"
            self.status = "success"
            self.result["changed"] = False
            self.result["response"] = self.msg
            self.log(self.msg, "WARNING")
            return self

        # Get and store the apEthernetMacAddress of given devices
        ap_mac_addresses = []
        for device_ip in input_device_ips:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params={"managementIpAddress": device_ip},
            )
            response = response.get("response")
            if not response:
                continue

            response = response[0]
            ap_mac_address = response.get("apEthernetMacAddress")

            if ap_mac_address is not None:
                ap_mac_addresses.append(ap_mac_address)

        if not ap_mac_addresses:
            self.status = "success"
            self.result["changed"] = False
            self.msg = "Cannot find the AP devices for rebooting"
            self.result["response"] = self.msg
            self.log(self.msg, "INFO")
            return self

        # Now call the Reboot Access Point API
        reboot_params = {"apMacAddresses": ap_mac_addresses}
        response = self.dnac._exec(
            family="wireless",
            function="reboot_access_points",
            op_modifies=True,
            params=reboot_params,
        )
        self.log(str(response))

        if response and isinstance(response, dict):
            task_id = response.get("response").get("taskId")

            while True:
                execution_details = self.get_task_details(task_id)

                if "url" in execution_details.get("progress"):
                    self.status = "success"
                    self.result["changed"] = True
                    self.result["response"] = execution_details
                    self.msg = "AP Device(s) {0} successfully rebooted!".format(
                        str(input_device_ips)
                    )
                    self.log(self.msg, "INFO")
                    break
                elif execution_details.get("isError"):
                    self.status = "failed"
                    failure_reason = execution_details.get("failureReason")
                    if failure_reason:
                        self.msg = (
                            "AP Device Rebooting get failed because of {0}".format(
                                failure_reason
                            )
                        )
                    else:
                        self.msg = "AP Device Rebooting get failed"
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    break

        return self

    def handle_successful_provisioning(self, device_ip, execution_details, device_type):
        """
        Handle successful provisioning of Wired/Wireless device.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - device_ip (str): The IP address of the provisioned device.
            - execution_details (str): Details of the provisioning execution.
            - device_type (str): The type or category of the provisioned device(Wired/Wireless).
        Return:
            None
        Description:
            This method updates the status, result, and logs the successful provisioning of a device.
        """

        self.status = "success"
        self.result["changed"] = True
        self.result["response"] = execution_details
        self.log(
            "{0} Device {1} provisioned successfully!!".format(
                device_type, device_ip),
            "INFO",
        )

    def handle_failed_provisioning(self, device_ip, execution_details, device_type):
        """
        Handle failed provisioning of Wired/Wireless device.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - device_ip (str): The IP address of the device that failed provisioning.
            - execution_details (dict): Details of the failed provisioning execution in key "failureReason" indicating reason for failure.
            - device_type (str): The type or category of the provisioned device(Wired/Wireless).
        Return:
            None
        Description:
            This method updates the status, result, and logs the failure of provisioning for a device.
        """

        self.status = "failed"
        failure_reason = execution_details.get(
            "failureReason", "Unknown failure reason"
        )
        self.msg = "{0} Device Provisioning failed for {1} because of {2}".format(
            device_type, device_ip, failure_reason
        )
        self.log(self.msg, "WARNING")
        self.result["response"] = self.msg

    def handle_provisioning_exception(self, device_ip, exception, device_type):
        """
        Handle an exception during the provisioning process of Wired/Wireless device..
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - device_ip (str): The IP address of the device involved in provisioning.
            - exception (Exception): The exception raised during provisioning.
            - device_type (str): The type or category of the provisioned device(Wired/Wireless).
        Return:
            None
        Description:
            This method logs an error message indicating an exception occurred during the provisioning process for a device.
        """

        error_message = "Error while Provisioning the {0} device {1} in Cisco Catalyst Center: {2}".format(
            device_type, device_ip, str(exception)
        )
        self.log(error_message, "ERROR")

    def handle_all_already_provisioned(self, device_ips, device_type):
        """
        Handle successful provisioning for all devices(Wired/Wireless).
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - device_type (str): The type or category of the provisioned device(Wired/Wireless).
        Return:
            None
        Description:
            This method updates the status, result, and logs the successful provisioning for all devices(Wired/Wireless).
        """

        self.status = "success"
        self.msg = "All the {0} Devices '{1}' given in the playbook are already Provisioned".format(
            device_type, str(device_ips)
        )
        self.log(self.msg, "INFO")
        self.result["response"] = self.msg
        self.result["changed"] = False

    def handle_all_provisioned(self, device_type):
        """
        Handle successful provisioning for all devices(Wired/Wireless).
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - device_type (str): The type or category of the provisioned devices(Wired/Wireless).
        Return:
            None
        Description:
            This method updates the status, result, and logs the successful provisioning for all devices(Wired/Wireless).
        """

        self.status = "success"
        self.result["changed"] = True
        self.log(
            "All {0} Devices provisioned successfully!!".format(
                device_type), "INFO"
        )

    def handle_all_failed_provision(self, device_type):
        """
        Handle failure of provisioning for all devices(Wired/Wireless).
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - device_type (str): The type or category of the devices(Wired/Wireless).
        Return:
            None
        Description:
            This method updates the status and logs a failure message indicating that
            provisioning failed for all devices of a specific type.
        """

        self.status = "failed"
        self.msg = "{0} Device Provisioning failed for all devices".format(
            device_type)
        self.log(self.msg, "INFO")
        self.result["response"] = self.msg

    def handle_partially_provisioned(self, provision_count, device_type):
        """
        Handle partial success in provisioning for devices(Wired/Wireless).
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - provision_count (int): The count of devices that were successfully provisioned.
            - device_type (str): The type or category of the provisioned devices(Wired/Wireless).
        Return:
            None
        Description:
            This method updates the status, result, and logs a partial success message indicating that provisioning was successful
            for a certain number of devices(Wired/Wireless).
        """

        self.status = "success"
        self.result["changed"] = True
        self.log(
            "{0} Devices provisioned successfully partially for {1} devices".format(
                device_type, provision_count
            ),
            "INFO",
        )

    def provisioned_wired_device(self):
        """
        Provision wired devices in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class with updated result, status, and log.
        Description:
            This function provisions wired devices in Cisco Catalyst Center based on the configuration provided.
            It retrieves the site name and IP addresses of the devices from the list of configuration,
            attempts to provision each device with site, and monitors the provisioning process.
        """

        provision_wired_list = self.config[0]["provision_wired_device"]
        total_devices_to_provisioned = len(provision_wired_list)
        device_ip_list = []
        provision_count, already_provision_count = 0, 0

        for prov_dict in provision_wired_list:
            managed_flag = False
            device_ip = prov_dict["device_ip"]
            device_ip_list.append(device_ip)
            site_name = prov_dict["site_name"]
            device_type = "Wired"
            resync_retry_count = prov_dict.get("resync_retry_count", 200)
            # This resync retry interval will be in seconds which will check device status at given interval
            resync_retry_interval = prov_dict.get("resync_retry_interval", 2)

            if not site_name or not device_ip:
                self.status = "failed"
                self.msg = (
                    "Site and Device IP are required for Provisioning of Wired Devices."
                )
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                return self

            provision_wired_params = {
                "deviceManagementIpAddress": device_ip,
                "siteNameHierarchy": site_name,
            }

            # Check the provisioning status of device
            device_prov_status = self.get_provision_wired_device(device_ip)
            if device_prov_status == 2:
                self.status = "success"
                already_provision_count += 1
                self.result["changed"] = False
                self.msg = "Device '{0}' is already provisioned in the Cisco Catalyst Center".format(
                    device_ip
                )
                self.log(self.msg, "INFO")
                continue
            if device_prov_status == 3:
                self.status = "failed"
                error_msg = "Cannot do Provisioning for device {0}.".format(
                    device_ip)
                self.log(error_msg, "ERROR")
                continue

            # Check till device comes into managed state
            while resync_retry_count:
                response = self.get_device_response(device_ip)
                self.log(
                    "Device is in {0} state waiting for Managed State.".format(
                        response["managementState"]
                    ),
                    "DEBUG",
                )

                if (
                    response.get("managementState") == "Managed"
                    and response.get("collectionStatus") == "Managed"
                    and response.get("hostname")
                ):
                    msg = """Device '{0}' comes to managed state and ready for provisioning with the resync_retry_count
                        '{1}' left having resync interval of {2} seconds""".format(
                        device_ip, resync_retry_count, resync_retry_interval
                    )
                    self.log(msg, "INFO")
                    managed_flag = True
                    break

                if (
                    response.get(
                        "collectionStatus") == "Partial Collection Failure"
                    or response.get("collectionStatus") == "Could Not Synchronize"
                ):
                    device_status = response.get("collectionStatus")
                    msg = """Device '{0}' comes to '{1}' state and never goes for provisioning with the resync_retry_count
                        '{2}' left having resync interval of {3} seconds""".format(
                        device_ip,
                        device_status,
                        resync_retry_count,
                        resync_retry_interval,
                    )
                    self.log(msg, "INFO")
                    managed_flag = False
                    break

                time.sleep(resync_retry_interval)
                resync_retry_count = resync_retry_count - 1

            if not managed_flag:
                self.log(
                    """Device {0} is not transitioning to the managed state, so provisioning operation cannot
                            be performed.""".format(
                        device_ip
                    ),
                    "WARNING",
                )
                continue

            try:
                response = self.dnac._exec(
                    family="sda",
                    function="provision_wired_device",
                    op_modifies=True,
                    params=provision_wired_params,
                )

                if response.get("status") == "failed":
                    description = response.get("description")
                    error_msg = (
                        "Cannot do Provisioning for device {0} beacuse of {1}".format(
                            device_ip, description
                        )
                    )
                    self.log(error_msg, "ERROR")
                    continue

                task_id = response.get("taskId")

                while True:
                    execution_details = self.get_task_details(task_id)
                    progress = execution_details.get("progress")

                    if "TASK_PROVISION" in progress:
                        self.handle_successful_provisioning(
                            device_ip, execution_details, device_type
                        )
                        provision_count += 1
                        break
                    elif execution_details.get("isError"):
                        self.handle_failed_provisioning(
                            device_ip, execution_details, device_type
                        )
                        break

            except Exception as e:
                # Not returning from here as there might be possiblity that for some devices it comes into exception
                # but for others it gets provision successfully or If some devices are already provsioned
                self.handle_provisioning_exception(device_ip, e, device_type)

        # Check If all the devices are already provsioned, return from here only
        if already_provision_count == total_devices_to_provisioned:
            self.handle_all_already_provisioned(device_ip_list, device_type)
        elif provision_count == total_devices_to_provisioned:
            self.handle_all_provisioned(device_type)
        elif provision_count == 0:
            self.handle_all_failed_provision(device_type)
        else:
            self.handle_partially_provisioned(provision_count, device_type)

        return self

    def get_wireless_param(self, prov_dict):
        """
        Get wireless provisioning parameters for a device.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            prov_dict (dict): A dictionary containing configuration parameters for wireless provisioning.
        Returns:
            wireless_param (list of dict): A list containing a dictionary with wireless provisioning parameters.
        Description:
            This function constructs a list containing a dictionary with wireless provisioning parameters based on the
            configuration provided in the playbook. It validates the managed AP locations, ensuring they are of type "floor."
            The function then queries Cisco Catalyst Center to get network device details using the provided device IP.
            If the device is not found, the function returns the class instance with appropriate status and log messages and
            returns the wireless provisioning parameters containing site information, managed AP
            locations, dynamic interfaces, and device name.
        """

        try:
            device_ip_address = prov_dict["device_ip"]
            site_name = prov_dict["site_name"]

            wireless_param = [
                {
                    "site": site_name,
                    "managedAPLocations": prov_dict["managed_ap_locations"],
                }
            ]

            for ap_loc in wireless_param[0]["managedAPLocations"]:
                if self.get_site_type(site_name=ap_loc) != "floor":
                    self.status = "failed"
                    self.msg = "Managed AP Location must be a floor"
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    return self

            wireless_param[0]["dynamicInterfaces"] = []

            for interface in prov_dict.get("dynamic_interfaces"):
                interface_dict = {
                    "interfaceIPAddress": interface.get("interface_ip_address"),
                    "interfaceNetmaskInCIDR": interface.get(
                        "interface_netmask_in_cidr"
                    ),
                    "interfaceGateway": interface.get("interface_gateway"),
                    "lagOrPortNumber": interface.get("lag_or_port_number"),
                    "vlanId": interface.get("vlan_id"),
                    "interfaceName": interface.get("interface_name"),
                }
                wireless_param[0]["dynamicInterfaces"].append(interface_dict)

            response = self.dnac_apply["exec"](
                family="devices",
                function="get_network_device_by_ip",
                params={"ip_address": device_ip_address},
            )

            if not response:
                self.status = "failed"
                self.msg = (
                    "Device Host name is not present in the Cisco Catalyst Center"
                )
                self.log(self.msg, "INFO")
                self.result["response"] = self.msg
                return self

            response = response.get("response")
            wireless_param[0]["deviceName"] = response.get("hostname")
            self.wireless_param = wireless_param
            self.status = "success"
            self.log(
                "Successfully collected all the parameters required for Wireless Provisioning",
                "DEBUG",
            )

        except Exception as e:
            self.msg = """An exception occured while fetching the details for wireless provisioning of
                device '{0}' due to - {1}""".format(
                device_ip_address, str(e)
            )
            self.log(self.msg, "ERROR")

        return self

    def get_site_type(self, site_name):
        """
        Get the type of a site in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site for which to retrieve the type.
        Returns:
            site_type (str or None): The type of the specified site, or None if the site is not found.
        Description:
            This function queries Cisco Catalyst Center to retrieve the type of a specified site. It uses the
            get_site API with the provided site name, extracts the site type from the response, and returns it.
            If the specified site is not found, the function returns None, and an appropriate log message is generated.
        """

        try:
            site_type = None
            response = self.dnac_apply["exec"](
                family="sites",
                function="get_site",
                params={"name": site_name},
            )

            if not response:
                self.msg = "Site '{0}' not found".format(site_name)
                self.log(self.msg, "INFO")
                return site_type

            self.log(
                "Received API response from 'get_site': {0}".format(
                    str(response)),
                "DEBUG",
            )
            site = response.get("response")
            site_additional_info = site[0].get("additionalInfo")

            for item in site_additional_info:
                if item["nameSpace"] == "Location":
                    site_type = item.get("attributes").get("type")

        except Exception as e:
            self.msg = "Error while fetching the site '{0}' and the specified site was not found in Cisco Catalyst Center.".format(
                site_name
            )
            self.module.fail_json(msg=self.msg, response=[self.msg])

        return site_type

    def provisioned_wireless_devices(self):
        """
        Provision Wireless devices in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class with updated result, status, and log.
        Description:
            This function performs wireless provisioning for the provided list of device IP addresses.
            It iterates through each device, retrieves provisioning parameters using the get_wireless_param function,
            and then calls the Cisco Catalyst Center API for wireless provisioning. If all devices are already provisioned,
            it returns success with a relevant message.
        """

        provision_count, already_provision_count = 0, 0
        device_type = "Wireless"
        device_ip_list = []
        provision_wireless_list = self.config[0]["provision_wireless_device"]

        for prov_dict in provision_wireless_list:
            try:
                # Collect the device parameters from the playbook to perform wireless provisioing
                self.get_wireless_param(prov_dict).check_return_status()
                device_ip = prov_dict["device_ip"]
                device_ip_list.append(device_ip)
                provisioning_params = self.wireless_param
                resync_retry_count = prov_dict.get("resync_retry_count", 200)
                # This resync retry interval will be in seconds which will check device status at given interval
                resync_retry_interval = prov_dict.get(
                    "resync_retry_interval", 2)
                managed_flag = True

                # Check till device comes into managed state
                while resync_retry_count:
                    response = self.get_device_response(device_ip)
                    self.log(
                        "Device is in {0} state waiting for Managed State.".format(
                            response["managementState"]
                        ),
                        "DEBUG",
                    )

                    if (
                        response.get("managementState") == "Managed"
                        and response.get("collectionStatus") == "Managed"
                        and response.get("hostname")
                    ):
                        msg = """Device '{0}' comes to managed state and ready for provisioning with the resync_retry_count
                            '{1}' left having resync interval of {2} seconds""".format(
                            device_ip, resync_retry_count, resync_retry_interval
                        )
                        self.log(msg, "INFO")
                        managed_flag = True
                        break

                    if (
                        response.get(
                            "collectionStatus") == "Partial Collection Failure"
                        or response.get("collectionStatus") == "Could Not Synchronize"
                    ):
                        device_status = response.get("collectionStatus")
                        msg = """Device '{0}' comes to '{1}' state and never goes for provisioning with the resync_retry_count
                            '{2}' left having resync interval of {3} seconds""".format(
                            device_ip,
                            device_status,
                            resync_retry_count,
                            resync_retry_interval,
                        )
                        self.log(msg, "INFO")
                        managed_flag = False
                        break

                    time.sleep(resync_retry_interval)
                    resync_retry_count = resync_retry_count - 1

                if not managed_flag:
                    self.log(
                        """Device {0} is not transitioning to the managed state, so provisioning operation cannot
                                be performed.""".format(
                            device_ip
                        ),
                        "WARNING",
                    )
                    continue

                # Now we have provisioning_param so we can do wireless provisioning
                response = self.dnac_apply["exec"](
                    family="wireless",
                    function="provision",
                    op_modifies=True,
                    params=provisioning_params,
                )

                if response.get("status") == "failed":
                    description = response.get("description")
                    error_msg = "Cannot do Provisioning for Wireless device {0} beacuse of {1}".format(
                        device_ip, description
                    )
                    self.log(error_msg, "ERROR")
                    continue

                task_id = response.get("taskId")

                while True:
                    execution_details = self.get_task_details(task_id)
                    progress = execution_details.get("progress")
                    if "TASK_PROVISION" in progress:
                        self.handle_successful_provisioning(
                            device_ip, execution_details, device_type
                        )
                        provision_count += 1
                        break
                    elif execution_details.get("isError"):
                        self.handle_failed_provisioning(
                            device_ip, execution_details, device_type
                        )
                        break

            except Exception as e:
                # Not returning from here as there might be possiblity that for some devices it comes into exception
                # but for others it gets provision successfully or If some devices are already provsioned
                self.handle_provisioning_exception(device_ip, e, device_type)
                if "already provisioned" in str(e):
                    self.msg = "Device '{0}' already provisioned".format(
                        device_ip)
                    self.log(self.msg, "INFO")
                    already_provision_count += 1

        # Check If all the devices are already provsioned, return from here only
        if already_provision_count == len(device_ip_list):
            self.handle_all_already_provisioned(device_ip_list, device_type)
        elif provision_count == len(device_ip_list):
            self.handle_all_provisioned(device_type)
        elif provision_count == 0:
            self.handle_all_failed_provision(device_type)
        else:
            self.handle_partially_provisioned(provision_count, device_type)

        return self

    def get_udf_id(self, field_name):
        """
        Get the ID of a Global User Defined Field in Cisco Catalyst Center based on its name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Cisco Catalyst Center.
            field_name (str): The name of the Global User Defined Field.
        Returns:
            str: The ID of the Global User Defined Field.
        Description:
            The function sends a request to Cisco Catalyst Center to retrieve all Global User Defined Fields
            with the specified name and extracts the ID of the first matching field.If successful, it returns
            the ID else returns None.
        """

        try:
            udf_id = None
            response = self.dnac._exec(
                family="devices",
                function="get_all_user_defined_fields",
                op_modifies=True,
                params={"name": field_name},
            )
            self.log(
                "Received API response from 'get_all_user_defined_fields': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            udf = response.get("response")
            if udf:
                udf_id = udf[0].get("id")

        except Exception as e:
            error_message = "Exception occurred while getting Global User Defined Fields(UDF) ID from Cisco Catalyst Center: {0}".format(
                str(e)
            )
            self.log(error_message, "ERROR")

        return udf_id

    def mandatory_parameter(self, device_to_add_in_ccc):
        """
        Check for and validate mandatory parameters for adding network devices in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Cisco Catalyst Center.
            device_to_add_in_ccc(list): List to device ip addresses to be added in Cisco Catalyst Center.
        Returns:
            dict: The input `config` dictionary if all mandatory parameters are present.
        Description:
            It will check the mandatory parameters for adding the devices in Cisco Catalyst Center.
        """

        device_type = self.config[0].get("type", "NETWORK_DEVICE")
        params_dict = {
            "NETWORK_DEVICE": ["ip_address_list", "password", "username"],
            "COMPUTE_DEVICE": [
                "ip_address_list",
                "http_username",
                "http_password",
                "http_port",
            ],
            "MERAKI_DASHBOARD": ["http_password"],
            "FIREPOWER_MANAGEMENT_SYSTEM": [
                "ip_address_list",
                "http_username",
                "http_password",
            ],
            "THIRD_PARTY_DEVICE": ["ip_address_list"],
        }

        params_list = params_dict.get(device_type, [])

        mandatory_params_absent = []
        for param in params_list:
            if param not in self.config[0]:
                mandatory_params_absent.append(param)

        if mandatory_params_absent:
            self.status = "failed"
            self.msg = "Required parameters {0} for adding devices '{1}' are not present".format(
                str(mandatory_params_absent), str(device_to_add_in_ccc)
            )
            self.result["msg"] = self.msg
            self.log(self.msg, "ERROR")
        else:
            self.status = "success"
            self.msg = "Required parameters for adding the devices '{0}' to inventory are present.".format(
                str(device_to_add_in_ccc)
            )
            self.log(self.msg, "INFO")

        return self

    def get_have(self, config):
        """
        Retrieve and check device information with Cisco Catalyst Center to determine if devices already exist.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Cisco Catalyst Center.
            config (dict): A dictionary containing the configuration details of devices to be checked.
        Returns:
            dict: A dictionary containing information about the devices in the playbook, devices that exist in
            Cisco Catalyst Center, and devices that are not present in Cisco Catalyst Center.
        Description:
            This function checks the specified devices in the playbook against the devices existing in Cisco Catalyst Center with following keys:
            - "want_device": A list of devices specified in the playbook.
            - "device_in_dnac": A list of devices that already exist in Cisco Catalyst Center.
            - "device_not_in_dnac": A list of devices that are not present in Cisco Catalyst Center.
        """

        have = {}
        want_device = self.get_device_ips_from_config_priority()

        # Get the list of device that are present in Cisco Catalyst Center
        device_in_dnac = self.get_existing_devices_in_ccc()
        device_not_in_dnac, devices_in_playbook = [], []

        for ip in want_device:
            devices_in_playbook.append(ip)
            if ip not in device_in_dnac:
                device_not_in_dnac.append(ip)

        if self.config[0].get("provision_wired_device"):
            provision_wired_list = self.config[0].get("provision_wired_device")

            for prov_dict in provision_wired_list:
                device_ip_address = prov_dict["device_ip"]
                if device_ip_address not in want_device:
                    devices_in_playbook.append(device_ip_address)
                if device_ip_address not in device_in_dnac:
                    device_not_in_dnac.append(device_ip_address)

        if support_for_provisioning_wireless:
            if self.config[0].get("provision_wireless_device"):
                provision_wireless_list = self.config[0].get(
                    "provision_wireless_device"
                )

                for prov_dict in provision_wireless_list:
                    device_ip_address = prov_dict["device_ip"]
                    if (
                        device_ip_address not in want_device
                        and device_ip_address not in devices_in_playbook
                    ):
                        devices_in_playbook.append(device_ip_address)
                    if (
                        device_ip_address not in device_in_dnac
                        and device_ip_address not in device_not_in_dnac
                    ):
                        device_not_in_dnac.append(device_ip_address)

        self.log(
            "Device(s) {0} exists in Cisco Catalyst Center".format(
                str(device_in_dnac)),
            "INFO",
        )
        have["want_device"] = want_device
        have["device_in_dnac"] = device_in_dnac
        have["device_not_in_dnac"] = device_not_in_dnac
        have["devices_in_playbook"] = devices_in_playbook

        self.have = have
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")

        return self

    def get_device_params(self, params):
        """
        Extract and store device parameters from the playbook for device processing in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            params (dict): A dictionary containing device parameters retrieved from the playbook.
        Returns:
            dict: A dictionary containing the extracted device parameters.
        Description:
            This function will extract and store parameters in dictionary for adding, updating, editing, or deleting devices Cisco Catalyst Center.
        """

        device_param = {
            "cliTransport": params.get("cli_transport"),
            "enablePassword": params.get("enable_password"),
            "password": params.get("password"),
            "ipAddress": params.get("ip_address_list"),
            "snmpAuthPassphrase": params.get("snmp_auth_passphrase"),
            "snmpAuthProtocol": params.get("snmp_auth_protocol"),
            "snmpMode": params.get("snmp_mode"),
            "snmpPrivPassphrase": params.get("snmp_priv_passphrase"),
            "snmpPrivProtocol": params.get("snmp_priv_protocol"),
            "snmpROCommunity": params.get("snmp_ro_community"),
            "snmpRwCommunity": params.get("snmp_rw_community"),
            "snmpRetry": params.get("snmp_retry"),
            "snmpTimeout": params.get("snmp_timeout"),
            "snmpUserName": params.get("snmp_username"),
            "userName": params.get("username"),
            "computeDevice": params.get("compute_device"),
            "extendedDiscoveryInfo": params.get("extended_discovery_info"),
            "httpPassword": params.get("http_password"),
            "httpPort": params.get("http_port"),
            "httpSecure": params.get("http_secure"),
            "httpUserName": params.get("http_username"),
            "netconfPort": params.get("netconf_port"),
            "snmpVersion": params.get("snmp_version"),
            "type": params.get("type"),
            "updateMgmtIPaddressList": params.get("update_mgmt_ipaddresslist"),
            "forceSync": params.get("force_sync"),
            "cleanConfig": params.get("clean_config"),
        }

        if device_param.get("updateMgmtIPaddressList"):
            device_mngmt_dict = device_param.get("updateMgmtIPaddressList")[0]
            device_param["updateMgmtIPaddressList"][0] = {}

            device_param["updateMgmtIPaddressList"][0].update(
                {
                    "existMgmtIpAddress": device_mngmt_dict.get("exist_mgmt_ipaddress"),
                    "newMgmtIpAddress": device_mngmt_dict.get("new_mgmt_ipaddress"),
                }
            )

        return device_param

    def get_device_ids(self, device_ips):
        """
        Get the list of unique device IDs for list of specified management IP addresses of devices in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ips (list): The management IP addresses of devices for which you want to retrieve the device IDs.
        Returns:
            list: The list of unique device IDs for the specified devices.
        Description:
            Queries Cisco Catalyst Center to retrieve the unique device ID associated with a device having the specified
            IP address. If the device is not found in Cisco Catalyst Center, then print the log message with error severity.
        """

        device_ids = []

        for device_ip in device_ips:
            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=True,
                    params={"managementIpAddress": device_ip},
                )

                if response:
                    self.log(
                        "Received API response from 'get_device_list': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    response = response.get("response")
                    if not response:
                        continue
                    device_id = response[0]["id"]
                    device_ids.append(device_id)

            except Exception as e:
                error_message = "Error while fetching device '{0}' from Cisco Catalyst Center: {1}".format(
                    device_ip, str(e)
                )
                self.log(error_message, "ERROR")

        return device_ids

    def get_device_ips_from_hostnames(self, hostnames):
        """
        Get the list of unique device IPs for list of specified hostnames of devices in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            hostnames (list): The hostnames of devices for which you want to retrieve the device IPs.
        Returns:
            list: The list of unique device IPs for the specified devices hostname list.
        Description:
            Queries Cisco Catalyst Center to retrieve the unique device IP's associated with a device having the specified
            list of hostnames. If a device is not found in Cisco Catalyst Center, an error log message is printed.
        """

        device_ips = []
        for hostname in hostnames:
            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=True,
                    params={"hostname": hostname},
                )
                if response:
                    self.log(
                        "Received API response from 'get_device_list': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    response = response.get("response")
                    if response:
                        device_ip = response[0]["managementIpAddress"]
                        if device_ip:
                            device_ips.append(device_ip)
            except Exception as e:
                error_message = "Exception occurred while fetching device from Cisco Catalyst Center: {0}".format(
                    str(e)
                )
                self.log(error_message, "ERROR")

        return device_ips

    def get_device_ips_from_serial_numbers(self, serial_numbers):
        """
        Get the list of unique device IPs for a specified list of serial numbers in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            serial_numbers (list): The list of serial number of devices for which you want to retrieve the device IPs.
        Returns:
            list: The list of unique device IPs for the specified devices with serial numbers.
        Description:
            Queries Cisco Catalyst Center to retrieve the unique device IPs associated with a device having the specified
            serial numbers.If a device is not found in Cisco Catalyst Center, an error log message is printed.
        """

        device_ips = []
        for serial_number in serial_numbers:
            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=True,
                    params={"serialNumber": serial_number},
                )
                if response:
                    self.log(
                        "Received API response from 'get_device_list': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    response = response.get("response")
                    if response:
                        device_ip = response[0]["managementIpAddress"]
                        if device_ip:
                            device_ips.append(device_ip)
            except Exception as e:
                error_message = "Exception occurred while fetching device from Cisco Catalyst Center - {0}".format(
                    str(e)
                )
                self.log(error_message, "ERROR")

        return device_ips

    def get_device_ips_from_mac_addresses(self, mac_addresses):
        """
        Get the list of unique device IPs for list of specified mac address of devices in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            mac_addresses (list): The list of mac address of devices for which you want to retrieve the device IPs.
        Returns:
            list: The list of unique device IPs for the specified devices.
        Description:
            Queries Cisco Catalyst Center to retrieve the unique device IPs associated with a device having the specified
            mac addresses. If a device is not found in Cisco Catalyst Center, an error log message is printed.
        """

        device_ips = []
        for mac_address in mac_addresses:
            try:
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=True,
                    params={"macAddress": mac_address},
                )
                if response:
                    self.log(
                        "Received API response from 'get_device_list': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )
                    response = response.get("response")
                    if response:
                        device_ip = response[0]["managementIpAddress"]
                        if device_ip:
                            device_ips.append(device_ip)
            except Exception as e:
                error_message = "Exception occurred while fetching device from Cisco Catalyst Center - {0}".format(
                    str(e)
                )
                self.log(error_message, "ERROR")

        return device_ips

    def get_interface_from_id_and_name(self, device_id, interface_name):
        """
        Retrieve the interface ID for a device in Cisco Catalyst Center based on device id and interface name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_id (str): The id of the device.
            interface_name (str): Name of the interface for which details need to be collected.
        Returns:
            str: The interface ID for the specified device and interface name.
        Description:
            The function sends a request to Cisco Catalyst Center to retrieve the interface information
            for the device with the provided device id and interface name and extracts the interface ID from the
            response, and returns the interface ID.
        """

        try:
            interface_detail_params = {
                "device_id": device_id, "name": interface_name}
            response = self.dnac._exec(
                family="devices",
                function="get_interface_details",
                op_modifies=True,
                params=interface_detail_params,
            )
            self.log(
                "Received API response from 'get_interface_details': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")

            if response:
                self.status = "success"
                interface_id = response["id"]
                self.log(
                    """Successfully fetched interface ID ({0}) by using device id {1} and interface name {2}.""".format(
                        interface_id, device_id, interface_name
                    ),
                    "INFO",
                )
                return interface_id

        except Exception as e:
            self.status = "failed"
            self.msg = "Failed to retrieve interface ID for interface({0}) from Cisco Catalyst Center: {1}".format(
                interface_name, str(e)
            )
            self.log(self.msg, "ERROR")
            return self

    def get_interface_from_ip(self, device_ip):
        """
        Get the interface ID for a device in Cisco Catalyst Center based on its IP address.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ip (str): The IP address of the device.
        Returns:
            str: The interface ID for the specified device.
        Description:
            The function sends a request to Cisco Catalyst Center to retrieve the interface information
            for the device with the provided IP address and extracts the interface ID from the
            response, and returns the interface ID.
        """

        try:
            response = self.dnac._exec(
                family="devices",
                function="get_interface_by_ip",
                op_modifies=True,
                params={"ip_address": device_ip},
            )
            self.log(
                "Received API response from 'get_interface_by_ip': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")

            if response:
                interface_id = response[0]["id"]
                self.log(
                    "Successfully retrieved Interface Id '{0}' for device '{1}'.".format(
                        interface_id, device_ip
                    ),
                    "DEBUG",
                )
                return interface_id

        except Exception as e:
            error_message = "Error while fetching Interface Id for device '{0}' from Cisco Catalyst Center: {1}".format(
                device_ip, str(e)
            )
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def get_device_response(self, device_ip):
        """
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ip (str): The management IP address of the device for which the response is to be retrieved.
        Returns:
            dict: A dictionary containing details of the device obtained from the Cisco Catalyst Center.
        Description:
            This method communicates with Cisco Catalyst Center to retrieve the details of a device with the specified
            management IP address. It executes the 'get_device_list' API call with the provided device IP address,
            logs the response, and returns a dictionary containing information about the device.
        """

        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params={"managementIpAddress": device_ip},
            )
            response = response.get("response")[0]

        except Exception as e:
            error_message = "Error while getting the response of device from Cisco Catalyst Center: {0}".format(
                str(e)
            )
            self.log(error_message, "ERROR")
            raise Exception(error_message)

        return response

    def check_device_role(self, device_ip):
        """
        Checks if the device role and role source for a device in Cisco Catalyst Center match the specified values in the configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ip (str): The management IP address of the device for which the device role is to be checked.
        Returns:
            bool: True if the device role and role source match the specified values, False otherwise.
        Description:
            This method retrieves the device role and role source for a device in Cisco Catalyst Center using the
            'get_device_response' method and compares the retrieved values with specified values in the configuration
            for updating device roles.
        """

        role = self.config[0].get("role")
        response = self.get_device_response(device_ip)

        return response.get("role") == role

    def check_interface_details(self, device_ip, interface_name):
        """
        Checks if the interface details for a device in Cisco Catalyst Center match the specified values in the configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ip (str): The management IP address of the device for which interface details are to be checked.
        Returns:
            bool: True if the interface details match the specified values, False otherwise.
        Description:
            This method retrieves the interface details for a device in Cisco Catalyst Center using the 'get_interface_by_ip' API call.
            It then compares the retrieved details with the specified values in the configuration for updating interface details.
            If all specified parameters match the retrieved values or are not provided in the playbook parameters, the function
            returns True, indicating successful validation.
        """
        device_id = self.get_device_ids([device_ip])

        if not device_id:
            self.log(
                """Error: Device with IP '{0}' not found in Cisco Catalyst Center.Unable to update interface details.""".format(
                    device_ip
                ),
                "ERROR",
            )
            return False

        interface_detail_params = {
            "device_id": device_id[0], "name": interface_name}
        response = self.dnac._exec(
            family="devices",
            function="get_interface_details",
            op_modifies=True,
            params=interface_detail_params,
        )
        self.log(
            "Received API response from 'get_interface_details': {0}".format(
                str(response)
            ),
            "DEBUG",
        )
        response = response.get("response")

        if not response:
            self.log(
                "No response received from the API 'get_interface_details'.", "DEBUG"
            )
            return False

        response_params = {
            "description": response.get("description"),
            "adminStatus": response.get("adminStatus"),
            "voiceVlanId": response.get("voiceVlan"),
            "vlanId": int(response.get("vlanId")),
        }

        interface_playbook_params = self.config[0].get(
            "update_interface_details")
        playbook_params = {
            "description": interface_playbook_params.get("description", ""),
            "adminStatus": interface_playbook_params.get("admin_status"),
            "voiceVlanId": interface_playbook_params.get("voice_vlan_id", ""),
            "vlanId": interface_playbook_params.get("vlan_id"),
        }

        for key, value in playbook_params.items():
            if not value:
                continue
            elif response_params[key] != value:
                return False

        return True

    def check_credential_update(self):
        """
        Checks if the credentials for devices in the configuration match the updated values in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            bool: True if the credentials match the updated values, False otherwise.
        Description:
            This method triggers the export API in Cisco Catalyst Center to obtain the updated credential details for
            the specified devices. It then decrypts and reads the CSV file containing the updated credentials,
            comparing them with the credentials specified in the configuration.
        """

        device_ips = self.get_device_ips_from_config_priority()
        device_uuids = self.get_device_ids(device_ips)
        password = "Testing@123"
        # Split the payload into 500 devices(by default) only to match the device credentials
        device_batch_size = self.config[0].get(
            "export_device_details_limit", 500)
        device_ids_list = device_uuids[0:device_batch_size]
        payload_params = {
            "deviceUuids": device_ids_list,
            "password": password,
            "operationEnum": "0",
        }
        response = self.trigger_export_api(payload_params)
        self.check_return_status()
        csv_reader = self.decrypt_and_read_csv(response, password)
        self.check_return_status()
        device_data = next(csv_reader, None)

        if not device_data:
            return False

        csv_data_dict = {
            "snmp_retry": device_data["snmp_retries"],
            "username": device_data["cli_username"],
            "password": device_data["cli_password"],
            "enable_password": device_data["cli_enable_password"],
            "snmp_username": device_data["snmpv3_user_name"],
            "snmp_auth_protocol": device_data["snmpv3_auth_type"],
        }

        config = self.config[0]
        for key in csv_data_dict:
            if key in config and csv_data_dict[key] is not None:
                if key == "snmp_retry" and int(csv_data_dict[key]) != int(config[key]):
                    return False
                elif csv_data_dict[key] != config[key]:
                    return False

        return True

    def get_provision_wired_device(self, device_ip):
        """
        Retrieves the provisioning status of a wired device with the specified management IP address in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ip (str): The management IP address of the wired device for which provisioning status is to be retrieved.
        Returns:
            bool: True if the device is provisioned successfully, False otherwise.
        Description:
            This method communicates with Cisco Catalyst Center to check the provisioning status of a wired device.
            It executes the 'get_provisioned_wired_device' API call with the provided device IP address and
            logs the response.
        """

        try:
            flag = 3
            response = self.dnac._exec(
                family="sda",
                function="get_provisioned_wired_device",
                op_modifies=True,
                params={"device_management_ip_address": device_ip},
            )

            if response.get(
                "status"
            ) == "success" and "Wired Provisioned device detail retrieved successfully." in response.get(
                "description"
            ):
                flag = 2
                self.log(
                    "Wired device '{0}' already provisioned in the Cisco Catalyst Center.".format(
                        device_ip
                    ),
                    "INFO",
                )

        except Exception as e:
            if "not provisioned to any site" in str(e):
                flag = 1

        return flag

    def clear_mac_address(self, interface_id, deploy_mode, interface_name):
        """
        Clear the MAC address table on a specific interface of a device.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            interface_id (str): The UUID of the interface where the MAC addresses will be cleared.
            deploy_mode (str): The deployment mode of the device.
            interface_name(str): The name of the interface for which the MAC addresses will be cleared.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function clears the MAC address table on a specific interface of a device.
            The 'deploy_mode' parameter specifies the deployment mode of the device.
            If the operation is successful, the function returns the response from the API call.
            If an error occurs during the operation, the function logs the error details and updates the status accordingly.
        """

        try:
            payload = {"operation": "ClearMacAddress", "payload": {}}
            clear_mac_address_payload = {
                "payload": payload,
                "interface_uuid": interface_id,
                "deployment_mode": deploy_mode,
            }
            response = self.dnac._exec(
                family="devices",
                function="clear_mac_address_table",
                op_modifies=True,
                params=clear_mac_address_payload,
            )
            self.log(
                "Received API response from 'clear_mac_address_table': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            if not (response and isinstance(response, dict)):
                self.status = "failed"
                self.msg = """Received an empty response from the API 'clear_mac_address_table'. This indicates a failure to clear
                    the Mac address table for the interface '{0}'""".format(
                    interface_name
                )
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                return self

            task_id = response.get("response").get("taskId")

            while True:
                execution_details = self.get_task_details(task_id)

                if execution_details.get("isError"):
                    self.status = "failed"
                    failure_reason = execution_details.get("failureReason")
                    if failure_reason:
                        self.msg = "Failed to clear the Mac address table for the interface '{0}' due to {1}".format(
                            interface_name, failure_reason
                        )
                    else:
                        self.msg = "Failed to clear the Mac address table for the interface '{0}'".format(
                            interface_name
                        )
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    break
                elif "clear mac address-table" in execution_details.get("data"):
                    self.status = "success"
                    self.result["changed"] = True
                    self.result["response"] = execution_details
                    self.msg = "Successfully executed the task of clearing the Mac address table for interface '{0}'".format(
                        interface_name
                    )
                    self.log(self.msg, "INFO")
                    break

        except Exception as e:
            error_msg = """An exception occurred during the process of clearing the MAC address table for interface {0}, due to -
                {1}""".format(
                interface_name, str(e)
            )
            self.log(error_msg, "WARNING")
            self.result["changed"] = False
            self.result["response"] = error_msg

        return self

    def update_interface_detail_of_device(self, device_to_update):
        """
        Update interface details for a device in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_to_update (list): A list of IP addresses of devices to be updated.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method updates interface details for devices in Cisco Catalyst Center.
            It iterates over the list of devices to be updated, retrieves interface parameters from the configuration,
            calls the update interface details API with the required parameters, and checks the execution response.
            If the update is successful, it sets the status to 'success' and logs an informational message.
        """

        # Call the Get interface details by device IP API and fetch the interface Id
        is_update_occurred = False
        response_list = []
        for device_ip in device_to_update:
            interface_params = self.config[0].get("update_interface_details")
            interface_names_list = interface_params.get("interface_name")
            for interface_name in interface_names_list:
                device_id = self.get_device_ids([device_ip])
                interface_details = self.get_interface_from_id_and_name(
                    device_id[0], interface_name
                )
                # Check if interface_details is None or does not contain the 'id' key.
                if interface_details is None or not interface_details.get("id"):
                    self.status = "failed"
                    self.msg = """Failed to retrieve interface details or the 'id' is missing for the device with identifier
                                '{0}' and interface '{1}'""".format(
                        device_id[0], interface_name
                    )
                    self.log(self.msg, "WARNING")
                    self.result["response"] = self.msg
                    return self

                interface_id = interface_details["id"]
                self.check_return_status()

                # Now we call update interface details api with required parameter
                try:
                    interface_params = self.config[0].get(
                        "update_interface_details")
                    clear_mac_address_table = interface_params.get(
                        "clear_mac_address_table", False
                    )

                    if clear_mac_address_table:
                        response = self.get_device_response(device_ip)

                        if response.get("role").upper() != "ACCESS":
                            self.msg = "The action to clear the MAC Address table is only supported for devices with the ACCESS role."
                            self.log(self.msg, "WARNING")
                            response_list.append(self.msg)
                            self.result["changed"] = False
                        else:
                            deploy_mode = interface_params.get(
                                "deployment_mode", "Deploy"
                            )
                            self.clear_mac_address(
                                interface_id, deploy_mode, interface_name
                            ).check_return_status()

                    temp_params = {
                        "description": interface_params.get("description", ""),
                        "adminStatus": interface_params.get("admin_status"),
                        "voiceVlanId": interface_params.get("voice_vlan_id"),
                        "vlanId": interface_params.get("vlan_id"),
                    }
                    payload_params = {}
                    for key, value in temp_params.items():
                        if value is not None:
                            payload_params[key] = value

                    # Check if interface need update or not here
                    interface_needs_update = False
                    for key, value in payload_params.items():
                        if key == "voiceVlanId":
                            if str(value) != interface_details["voiceVlan"]:
                                interface_needs_update = True
                        else:
                            if str(value) != str(interface_details.get(key)):
                                interface_needs_update = True

                    if not interface_needs_update:
                        self.status = "success"
                        self.result["changed"] = False
                        self.msg = """Interface details for the given interface '{0}' are already updated in the Cisco Catalyst Center for the
                                     device '{1}'.""".format(
                            interface_name, device_ip
                        )
                        self.log(self.msg, "INFO")
                        self.result["response"] = self.msg
                        continue

                    update_interface_params = {
                        "payload": payload_params,
                        "interface_uuid": interface_id,
                        "deployment_mode": interface_params.get(
                            "deployment_mode", "Deploy"
                        ),
                    }
                    response = self.dnac._exec(
                        family="devices",
                        function="update_interface_details",
                        op_modifies=True,
                        params=update_interface_params,
                    )
                    self.log(
                        "Received API response from 'update_interface_details': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )

                    if response and isinstance(response, dict):
                        response = response.get("response")
                        if not response:
                            self.status = "failed"
                            self.msg = "Failed to update the interface because the 'update_interface_details' API returned an empty response."
                            self.log(self.msg, "ERROR")
                            self.result["response"] = self.msg
                            continue

                        task_id = response.get("taskId")

                        while True:
                            execution_details = self.get_task_details(task_id)

                            if "SUCCESS" in execution_details.get("progress"):
                                self.status = "success"
                                is_update_occurred = True
                                self.msg = "Successfully updated the Interface Details for device '{0}'.".format(
                                    device_ip
                                )
                                response_list.append(self.msg)
                                self.log(self.msg, "INFO")
                                break
                            elif execution_details.get("isError"):
                                self.status = "failed"
                                failure_reason = execution_details.get(
                                    "failureReason")
                                if failure_reason:
                                    self.msg = "Interface Updation get failed because of {0}".format(
                                        failure_reason
                                    )
                                else:
                                    self.msg = "Interface Updation get failed"
                                self.log(self.msg, "ERROR")
                                self.result["response"] = self.msg
                                break

                except Exception as e:
                    error_message = "Error while updating interface details in Cisco Catalyst Center: {0}".format(
                        str(e)
                    )
                    self.log(error_message, "INFO")
                    self.status = "success"
                    self.result["changed"] = False
                    self.msg = "Port actions are only supported on user facing/access ports as it's not allowed or No Updation required"
                    self.log(self.msg, "INFO")
                    response_list.append(self.msg)

        self.result["changed"] = is_update_occurred
        self.result["response"] = response_list

        return self

    def check_managementip_execution_response(
        self, response, device_ip, new_mgmt_ipaddress
    ):
        """
        Check the execution response of a management IP update task.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            response (dict): The response received after initiating the management IP update task.
            device_ip (str): The IP address of the device for which the management IP was updated.
            new_mgmt_ipaddress (str): The new management IP address of the device.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the execution response of a management IP update task in Cisco Catalyst Center.
            It continuously queries the task details until the task is completed or an error occurs.
            If the task is successful, it sets the status to 'success' and logs an informational message.
            If the task fails, it sets the status to 'failed' and logs an error message with the failure reason, if available.
        """

        task_id = response.get("response").get("taskId")

        while True:
            execution_details = self.get_task_details(task_id)
            if execution_details.get("isError"):
                self.status = "failed"
                failure_reason = execution_details.get("failureReason")
                if failure_reason:
                    self.msg = "Device new management IP updation for device '{0}' get failed due to {1}".format(
                        device_ip, failure_reason
                    )
                else:
                    self.msg = "Device new management IP updation for device '{0}' get failed".format(
                        device_ip
                    )
                self.log(self.msg, "ERROR")
                break
            elif execution_details.get("endTime"):
                self.status = "success"
                self.result["changed"] = True
                self.msg = """Device '{0}' present in Cisco Catalyst Center and new management ip '{1}' have been
                            updated successfully""".format(
                    device_ip, new_mgmt_ipaddress
                )
                self.log(self.msg, "INFO")
                break
            self.result["response"] = self.msg

        return self

    def check_device_update_execution_response(self, response, device_ip):
        """
        Check the execution response of a device update task.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            response (dict): The response received after initiating the device update task.
            device_ip (str): The IP address of the device for which the update is performed.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the execution response of a device update task in Cisco Catalyst Center.
            It continuously queries the task details until the task is completed or an error occurs.
            If the task is successful, it sets the status to 'success' and logs an informational message.
            If the task fails, it sets the status to 'failed' and logs an error message with the failure reason, if available.
        """

        task_id = response.get("response").get("taskId")

        while True:
            execution_details = self.get_task_details(task_id)

            if execution_details.get("isError"):
                self.status = "failed"
                failure_reason = execution_details.get("failureReason")
                if failure_reason:
                    self.msg = (
                        "Device Updation for device '{0}' get failed due to {1}".format(
                            device_ip, failure_reason
                        )
                    )
                else:
                    self.msg = "Device Updation for device '{0}' get failed".format(
                        device_ip
                    )
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                self.check_return_status()
                break
            elif execution_details.get("endTime"):
                self.log(
                    "Device '{0}' present in Cisco Catalyst Center and have been updated successfully.".format(
                        device_ip
                    ),
                    "INFO",
                )
                break

        return self

    def is_device_exist_in_ccc(self, device_ip):
        """
        Check if a device with the given IP exists in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_ip (str): The IP address of the device to check.
        Returns:
            bool: True if the device exists, False otherwise.
        Description:
            This method queries Cisco Catalyst Center to check if a device with the specified
            management IP address exists. If the device exists, it returns True; otherwise,
            it returns False. If an error occurs during the process, it logs an error message
            and raises an exception.
        """

        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params={"managementIpAddress": device_ip},
            )
            response = response.get("response")
            if not response:
                self.log(
                    "Device with given IP '{0}' is not present in Cisco Catalyst Center".format(
                        device_ip
                    ),
                    "INFO",
                )
                return False

            return True

        except Exception as e:
            error_message = "Error while getting the response of device '{0}' from Cisco Catalyst Center: {1}".format(
                device_ip, str(e)
            )
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def is_device_exist_for_update(self, device_to_update):
        """
        Check if the device(s) exist in Cisco Catalyst Center for update operation.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_to_update (list): A list of device(s) to be be checked present in Cisco Catalyst Center.
        Returns:
            bool: True if at least one of the devices to be updated exists in Cisco Catalyst Center,
                False otherwise.
        Description:
            This function checks if any of the devices specified in the 'device_to_update' list
            exists in Cisco Catalyst Center. It iterates through the list of devices and compares
            each device with the list of devices present in Cisco Catalyst Center obtained from
            'self.have.get("device_in_ccc")'. If a match is found, it sets 'device_exist' to True
            and breaks the loop.
        """

        # First check if device present in Cisco Catalyst Center or not
        device_exist = False
        for device in device_to_update:
            if device in self.have.get("device_in_dnac"):
                device_exist = True
                break

        return device_exist

    def get_want(self, config):
        """
        Get all the device related information from playbook that is needed to be
        add/update/delete/resync device in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing device-related information from the playbook.
        Returns:
            dict: A dictionary containing the extracted device parameters and other relevant information.
        Description:
            Retrieve all the device-related information from the playbook needed for adding, updating, deleting,
            or resyncing devices in Cisco Catalyst Center.
        """

        want = {}
        device_params = self.get_device_params(config)
        want["device_params"] = device_params

        self.want = want
        self.msg = "Successfully collected all parameters from the playbook "
        self.status = "success"
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_diff_merged(self, config):
        """
        Merge and process differences between existing devices and desired device configuration in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the desired device configuration and relevant information from the playbook.
        Returns:
            object: An instance of the class with updated results and status based on the processing of differences.
        Description:
            The function processes the differences and, depending on the changes required, it may add, update,
            or resynchronize devices in Cisco Catalyst Center.
            The updated results and status are stored in the class instance for further use.
        """

        devices_to_add = self.have["device_not_in_dnac"]
        device_type = self.config[0].get("type", "NETWORK_DEVICE")
        device_resynced = self.config[0].get("device_resync", False)
        device_reboot = self.config[0].get("reboot_device", False)
        credential_update = self.config[0].get("credential_update", False)

        config["type"] = device_type
        config["ip_address_list"] = devices_to_add
        if device_type == "FIREPOWER_MANAGEMENT_SYSTEM":
            config["http_port"] = self.config[0].get("http_port", "443")

        if self.config[0].get("provision_wired_device"):
            provision_wired_list = self.config[0]["provision_wired_device"]
            device_not_available = []

            for prov_dict in provision_wired_list:
                device_ip = prov_dict["device_ip"]
                if device_ip not in self.have.get("device_in_dnac"):
                    device_not_available.append(device_ip)
            if device_not_available:
                self.status = "failed"
                self.msg = """Unable to Provision Wired Device(s) because the device(s) listed: {0} are not present in the
                            Cisco Catalyst Center.""".format(
                    str(device_not_available)
                )
                self.result["response"] = self.msg
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                return self

        if self.config[0].get("update_mgmt_ipaddresslist"):
            device_ip = (
                self.config[0]
                .get("update_mgmt_ipaddresslist")[0]
                .get("existMgmtIpAddress")
            )
            is_device_exists = self.is_device_exist_in_ccc(device_ip)

            if not is_device_exists:
                self.status = "failed"
                self.msg = """Unable to update the Management IP address because the device with IP '{0}' is not
                            found in Cisco Catalyst Center.""".format(
                    device_ip
                )
                self.log(self.msg, "ERROR")
                self.result["response"] = self.msg
                return self

        if self.config[0].get("update_interface_details"):
            device_to_update = self.get_device_ips_from_config_priority()
            device_exist = self.is_device_exist_for_update(device_to_update)

            if not device_exist:
                self.msg = """Unable to update interface details because the device(s) listed: {0} are not present in the
                            Cisco Catalyst Center.""".format(
                    str(device_to_update)
                )
                self.status = "failed"
                self.result["response"] = self.msg
                self.log(self.msg, "ERROR")
                return self

        if self.config[0].get("role"):
            devices_to_update_role = self.get_device_ips_from_config_priority()
            device_exist = self.is_device_exist_for_update(
                devices_to_update_role)

            if not device_exist:
                self.msg = """Unable to update device role because the device(s) listed: {0} are not present in the Cisco
                            Catalyst Center.""".format(
                    str(devices_to_update_role)
                )
                self.status = "failed"
                self.result["response"] = self.msg
                self.log(self.msg, "ERROR")
                return self

        if credential_update:
            device_to_update = self.get_device_ips_from_config_priority()
            device_exist = self.is_device_exist_for_update(device_to_update)
            update_device_ips = []

            if not device_exist:
                self.msg = """Unable to edit device credentials/details because the device(s) listed: {0} are not present in the
                            Cisco Catalyst Center.""".format(
                    str(device_to_update)
                )
                self.status = "failed"
                self.result["response"] = self.msg
                self.log(self.msg, "ERROR")
                return self

        if not config["ip_address_list"]:
            self.msg = "Devices '{0}' already present in Cisco Catalyst Center".format(
                self.have["devices_in_playbook"]
            )
            self.log(self.msg, "INFO")
            self.result["changed"] = False
            self.result["response"] = self.msg
        else:
            # To add the devices in inventory
            input_params = self.want.get("device_params")
            device_params = input_params.copy()

            if not device_params["snmpVersion"]:
                device_params["snmpVersion"] = "v3"

            device_params["ipAddress"] = config["ip_address_list"]
            if device_params["snmpVersion"] == "v2":
                params_to_remove = [
                    "snmpAuthPassphrase",
                    "snmpAuthProtocol",
                    "snmpMode",
                    "snmpPrivPassphrase",
                    "snmpPrivProtocol",
                    "snmpUserName",
                ]
                for param in params_to_remove:
                    device_params.pop(param, None)

                if not device_params["snmpROCommunity"]:
                    self.status = "failed"
                    self.msg = "Required parameter 'snmpROCommunity' for adding device with snmmp version v2 is not present"
                    self.result["response"] = self.msg
                    self.log(self.msg, "ERROR")
                    return self
            else:
                if not device_params["snmpMode"]:
                    device_params["snmpMode"] = "AUTHPRIV"

                if not device_params["cliTransport"]:
                    device_params["cliTransport"] = "ssh"

                if not device_params["snmpPrivProtocol"]:
                    device_params["snmpPrivProtocol"] = "AES128"

                if device_params["snmpPrivProtocol"] == "AES192":
                    device_params["snmpPrivProtocol"] = "CISCOAES192"
                elif device_params["snmpPrivProtocol"] == "AES256":
                    device_params["snmpPrivProtocol"] = "CISCOAES256"

                if device_params["snmpMode"] == "NOAUTHNOPRIV":
                    device_params.pop("snmpAuthPassphrase", None)
                    device_params.pop("snmpPrivPassphrase", None)
                    device_params.pop("snmpPrivProtocol", None)
                    device_params.pop("snmpAuthProtocol", None)
                elif device_params["snmpMode"] == "AUTHNOPRIV":
                    device_params.pop("snmpPrivPassphrase", None)
                    device_params.pop("snmpPrivProtocol", None)

            device_to_add_in_ccc = device_params["ipAddress"]
            self.mandatory_parameter(
                device_to_add_in_ccc).check_return_status()
            try:
                response = self.dnac._exec(
                    family="devices",
                    function="add_device",
                    op_modifies=True,
                    params=device_params,
                )
                self.log(
                    "Received API response from 'add_device': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                if response and isinstance(response, dict):
                    task_id = response.get("response").get("taskId")

                    while True:
                        execution_details = self.get_task_details(task_id)

                        if "/task/" in execution_details.get("progress"):
                            self.status = "success"
                            self.result["response"] = execution_details

                            if len(devices_to_add) > 0:
                                self.result["changed"] = True
                                self.msg = "Device(s) '{0}' added to Cisco Catalyst Center".format(
                                    str(devices_to_add)
                                )
                                self.log(self.msg, "INFO")
                                self.result["msg"] = self.msg
                                break
                            self.msg = "Device(s) '{0}' already present in Cisco Catalyst Center".format(
                                str(self.config[0].get("ip_address_list"))
                            )
                            self.log(self.msg, "INFO")
                            self.result["msg"] = self.msg
                            break
                        elif execution_details.get("isError"):
                            self.status = "failed"
                            failure_reason = execution_details.get(
                                "failureReason")
                            if failure_reason:
                                self.msg = (
                                    "Device addition get failed because of {0}".format(
                                        failure_reason
                                    )
                                )
                            else:
                                self.msg = "Device addition get failed"
                            self.log(self.msg, "ERROR")
                            self.result["msg"] = self.msg
                            return self

            except Exception as e:
                error_message = (
                    "Error while adding device in Cisco Catalyst Center: {0}".format(
                        str(e)
                    )
                )
                self.log(error_message, "ERROR")
                raise Exception(error_message)

        # Update the role of devices having the role source as Manual
        if self.config[0].get("role"):
            devices_to_update_role = self.get_device_ips_from_config_priority()
            device_role = self.config[0].get("role")
            role_update_count = 0
            role_updated_list = []
            for device_ip in devices_to_update_role:
                device_id = self.get_device_ids([device_ip])

                # Check if the same role of device is present in dnac then no need to change the state
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=True,
                    params={"managementIpAddress": device_ip},
                )
                response = response.get("response")[0]

                if response.get("role") == device_role:
                    self.status = "success"
                    self.result["changed"] = False
                    role_update_count += 1
                    log_msg = "The device role '{0}' is already set in Cisco Catalyst Center, no update is needed.".format(
                        device_role
                    )
                    self.log(log_msg, "INFO")
                    continue

                device_role_params = {
                    "role": device_role,
                    "roleSource": "MANUAL",
                    "id": device_id[0],
                }

                try:
                    response = self.dnac._exec(
                        family="devices",
                        function="update_device_role",
                        op_modifies=True,
                        params=device_role_params,
                    )
                    self.log(
                        "Received API response from 'update_device_role': {0}".format(
                            str(response)
                        ),
                        "DEBUG",
                    )

                    if response and isinstance(response, dict):
                        task_id = response.get("response").get("taskId")

                        while True:
                            execution_details = self.get_task_details(task_id)
                            progress = execution_details.get("progress")

                            if "successfully" in progress or "succesfully" in progress:
                                self.status = "success"
                                self.log(
                                    "Device '{0}' role updated successfully to '{1}'".format(
                                        device_ip, device_role
                                    ),
                                    "INFO",
                                )
                                role_updated_list.append(device_ip)
                                break
                            elif execution_details.get("isError"):
                                self.status = "failed"
                                failure_reason = execution_details.get(
                                    "failureReason")
                                if failure_reason:
                                    self.msg = "Device role updation get failed because of {0}".format(
                                        failure_reason
                                    )
                                else:
                                    self.msg = "Device role updation get failed"
                                self.log(self.msg, "ERROR")
                                self.result["response"] = self.msg
                                break

                except Exception as e:
                    error_message = "Error while updating device role '{0}' in Cisco Catalyst Center: {1}".format(
                        device_role, str(e)
                    )
                    self.log(error_message, "ERROR")

            if role_update_count == len(devices_to_update_role):
                self.status = "success"
                self.result["changed"] = False
                self.msg = """The device role '{0}' is already set in Cisco Catalyst Center, no device role update is needed for the
                  device(s) {1}.""".format(
                    device_role, str(devices_to_update_role)
                )
                self.log(self.msg, "INFO")
                self.result["response"] = self.msg

            if role_updated_list:
                self.status = "success"
                self.result["changed"] = True
                self.msg = "Device(s) '{0}' role updated successfully to '{1}'".format(
                    str(role_updated_list), device_role
                )
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")

        if credential_update:
            device_to_update = self.get_device_ips_from_config_priority()
            # Update Device details and credentails
            device_uuids = self.get_device_ids(device_to_update)
            password = "Testing@123"
            export_payload = {
                "deviceUuids": device_uuids,
                "password": password,
                "operationEnum": "0",
            }
            export_response = self.trigger_export_api(export_payload)
            self.check_return_status()
            csv_reader = self.decrypt_and_read_csv(export_response, password)
            self.check_return_status()
            device_details = {}
            start = 0
            device_batch_size = self.config[0].get(
                "export_device_details_limit", 500)

            while start < len(device_uuids):
                device_ids_list = device_uuids[start: start +
                                               device_batch_size]
                export_payload = {
                    "deviceUuids": device_ids_list,
                    "password": password,
                    "operationEnum": "0",
                }
                export_response = self.trigger_export_api(export_payload)
                self.check_return_status()
                csv_reader = self.decrypt_and_read_csv(
                    export_response, password)
                self.check_return_status()

                for row in csv_reader:
                    ip_address = row["ip_address"]
                    device_details[ip_address] = row
                start += device_batch_size

            for device_ip in device_to_update:
                playbook_params = self.want.get("device_params").copy()
                playbook_params["ipAddress"] = [device_ip]
                device_data = device_details[device_ip]
                if device_data["snmpv3_privacy_password"] == " ":
                    device_data["snmpv3_privacy_password"] = None
                if device_data["snmpv3_auth_password"] == " ":
                    device_data["snmpv3_auth_password"] = None

                if not playbook_params["snmpMode"]:
                    if device_data["snmpv3_privacy_password"]:
                        playbook_params["snmpMode"] = "AUTHPRIV"
                    elif device_data["snmpv3_auth_password"]:
                        playbook_params["snmpMode"] = "AUTHNOPRIV"
                    else:
                        playbook_params["snmpMode"] = "NOAUTHNOPRIV"

                if not playbook_params["cliTransport"]:
                    if device_data["protocol"] == "ssh2":
                        playbook_params["cliTransport"] = "ssh"
                    else:
                        playbook_params["cliTransport"] = device_data["protocol"]
                if not playbook_params["snmpPrivProtocol"]:
                    playbook_params["snmpPrivProtocol"] = device_data[
                        "snmpv3_privacy_type"
                    ]

                csv_data_dict = {
                    "username": device_data["cli_username"],
                    "password": device_data["cli_password"],
                    "enable_password": device_data["cli_enable_password"],
                    "netconf_port": device_data["netconf_port"],
                }

                if device_data["snmp_version"] == "3":
                    csv_data_dict["snmp_username"] = device_data["snmpv3_user_name"]
                    if device_data["snmpv3_privacy_password"]:
                        csv_data_dict["snmp_auth_passphrase"] = device_data[
                            "snmpv3_auth_password"
                        ]
                        csv_data_dict["snmp_priv_passphrase"] = device_data[
                            "snmpv3_privacy_password"
                        ]
                else:
                    csv_data_dict["snmp_username"] = None

                device_key_mapping = {
                    "username": "userName",
                    "password": "password",
                    "enable_password": "enablePassword",
                    "snmp_username": "snmpUserName",
                    "netconf_port": "netconfPort",
                }
                device_update_key_list = [
                    "username",
                    "password",
                    "enable_password",
                    "snmp_username",
                    "netconf_port",
                ]

                for key in device_update_key_list:
                    mapped_key = device_key_mapping[key]

                    if playbook_params[mapped_key] is None:
                        playbook_params[mapped_key] = csv_data_dict[key]

                if playbook_params["snmpMode"] == "AUTHPRIV":
                    if not playbook_params["snmpAuthPassphrase"]:
                        playbook_params["snmpAuthPassphrase"] = csv_data_dict[
                            "snmp_auth_passphrase"
                        ]
                    if not playbook_params["snmpPrivPassphrase"]:
                        playbook_params["snmpPrivPassphrase"] = csv_data_dict[
                            "snmp_priv_passphrase"
                        ]

                if playbook_params["snmpPrivProtocol"] == "AES192":
                    playbook_params["snmpPrivProtocol"] = "CISCOAES192"
                elif playbook_params["snmpPrivProtocol"] == "AES256":
                    playbook_params["snmpPrivProtocol"] = "CISCOAES256"

                if playbook_params["snmpMode"] == "NOAUTHNOPRIV":
                    playbook_params.pop("snmpAuthPassphrase", None)
                    playbook_params.pop("snmpPrivPassphrase", None)
                    playbook_params.pop("snmpPrivProtocol", None)
                    playbook_params.pop("snmpAuthProtocol", None)
                elif playbook_params["snmpMode"] == "AUTHNOPRIV":
                    playbook_params.pop("snmpPrivPassphrase", None)
                    playbook_params.pop("snmpPrivProtocol", None)

                if playbook_params["netconfPort"] == " ":
                    playbook_params["netconfPort"] = None

                if playbook_params["enablePassword"] == " ":
                    playbook_params["enablePassword"] = None

                if (
                    playbook_params["netconfPort"]
                    and playbook_params["cliTransport"] == "telnet"
                ):
                    self.log(
                        """Updating the device cli transport from ssh to telnet with netconf port '{0}' so make
                            netconf port as None to perform the device update task""".format(
                            playbook_params["netconfPort"]
                        ),
                        "DEBUG",
                    )
                    playbook_params["netconfPort"] = None

                if not playbook_params["snmpVersion"]:
                    if device_data["snmp_version"] == "3":
                        playbook_params["snmpVersion"] = "v3"
                    else:
                        playbook_params["snmpVersion"] = "v2"

                if playbook_params["snmpVersion"] == "v2":
                    params_to_remove = [
                        "snmpAuthPassphrase",
                        "snmpAuthProtocol",
                        "snmpMode",
                        "snmpPrivPassphrase",
                        "snmpPrivProtocol",
                        "snmpUserName",
                    ]
                    for param in params_to_remove:
                        playbook_params.pop(param, None)

                    if not playbook_params["snmpROCommunity"]:
                        playbook_params["snmpROCommunity"] = device_data.get(
                            "snmp_community", None
                        )
                    if not playbook_params["snmpRwCommunity"]:
                        playbook_params["snmpRwCommunity"] = device_data.get(
                            "snmp_write_community", None
                        )

                if not playbook_params["httpUserName"]:
                    playbook_params["httpUserName"] = device_data.get(
                        "http_config_username", None
                    )
                if not playbook_params["httpPassword"]:
                    playbook_params["httpPassword"] = device_data.get(
                        "http_config_password", None
                    )
                if not playbook_params["httpPort"]:
                    playbook_params["httpPort"] = device_data.get(
                        "http_port", None)

                for key, value in playbook_params.items():
                    if value == " ":
                        playbook_params[key] = None

                try:
                    if playbook_params["updateMgmtIPaddressList"]:
                        new_mgmt_ipaddress = playbook_params["updateMgmtIPaddressList"][
                            0
                        ]["newMgmtIpAddress"]
                        if new_mgmt_ipaddress in self.have["device_in_dnac"]:
                            self.status = "failed"
                            self.msg = "Device with IP address '{0}' already exists in inventory".format(
                                new_mgmt_ipaddress
                            )
                            self.log(self.msg, "ERROR")
                            self.result["response"] = self.msg
                        else:
                            self.log(
                                "Playbook parameter for updating device new management ip address: {0}".format(
                                    str(playbook_params)
                                ),
                                "DEBUG",
                            )
                            response = self.dnac._exec(
                                family="devices",
                                function="sync_devices",
                                op_modifies=True,
                                params=playbook_params,
                            )
                            self.log(
                                "Received API response from 'sync_devices': {0}".format(
                                    str(response)
                                ),
                                "DEBUG",
                            )

                            if response and isinstance(response, dict):
                                self.check_managementip_execution_response(
                                    response, device_ip, new_mgmt_ipaddress
                                )
                                self.check_return_status()

                    else:
                        self.log(
                            "Playbook parameter for updating devices: {0}".format(
                                str(playbook_params)
                            ),
                            "DEBUG",
                        )
                        response = self.dnac._exec(
                            family="devices",
                            function="sync_devices",
                            op_modifies=True,
                            params=playbook_params,
                        )
                        self.log(
                            "Received API response from 'sync_devices': {0}".format(
                                str(response)
                            ),
                            "DEBUG",
                        )

                        if response and isinstance(response, dict):
                            self.check_device_update_execution_response(
                                response, device_ip
                            )
                            update_device_ips.append(device_ip)
                            self.check_return_status()

                except Exception as e:
                    error_message = "Error while updating device in Cisco Catalyst Center: {0}".format(
                        str(e)
                    )
                    self.log(error_message, "ERROR")
                    raise Exception(error_message)

            if update_device_ips:
                self.status = "success"
                self.result["changed"] = True
                self.msg = "Device(s) '{0}' present in Cisco Catalyst Center and have been updated successfully.".format(
                    str(update_device_ips)
                )
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")

        # Update list of interface details on specific or list of devices.
        if self.config[0].get("update_interface_details"):
            device_to_update = self.get_device_ips_from_config_priority()
            self.update_interface_detail_of_device(
                device_to_update
            ).check_return_status()

        # If User defined field(UDF) not present then create it and add multiple udf to specific or list of devices
        if self.config[0].get("add_user_defined_field"):
            udf_field_list = self.config[0].get("add_user_defined_field")

            for udf in udf_field_list:
                field_name = udf.get("name")

                if field_name is None:
                    self.status = "failed"
                    self.msg = "Error: The mandatory parameter 'name' for the User Defined Field is missing. Please provide the required information."
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    return self

                # Check if the Global User defined field exist if not then create it with given field name
                udf_exist = self.is_udf_exist(field_name)

                if not udf_exist:
                    # Create the Global UDF
                    self.log(
                        "Global User Defined Field '{0}' does not present in Cisco Catalyst Center, we need to create it".format(
                            field_name
                        ),
                        "DEBUG",
                    )
                    self.create_user_defined_field(udf).check_return_status()

                # Get device Id based on config priority
                device_ips = self.get_device_ips_from_config_priority()
                device_ids = self.get_device_ids(device_ips)

                if len(device_ids) == 0:
                    self.status = "failed"
                    self.msg = """Unable to assign Global User Defined Field: No devices found in Cisco Catalyst Center.
                        Please add devices to proceed."""
                    self.log(self.msg, "INFO")
                    self.result["response"] = self.msg
                    return self

                # Now add code for adding Global UDF to device with Id
                self.add_field_to_devices(
                    device_ids, udf).check_return_status()

                self.result["changed"] = True
                self.msg = "Global User Defined Field(UDF) named '{0}' has been successfully added to the device.".format(
                    field_name
                )
                self.log(self.msg, "INFO")

        # Once Wired device get added we will assign device to site and Provisioned it
        if self.config[0].get("provision_wired_device"):
            self.provisioned_wired_device().check_return_status()

        # Once Wireless device get added we will assign device to site and Provisioned it
        # Defer this feature as API issue is there once it's fixed we will addresses it in upcoming release iac2.0
        if support_for_provisioning_wireless:
            if self.config[0].get("provision_wireless_device"):
                self.provisioned_wireless_devices().check_return_status()

        if device_resynced:
            self.resync_devices().check_return_status()

        if device_reboot:
            self.reboot_access_points().check_return_status()

        if self.config[0].get("export_device_list"):
            self.export_device_details().check_return_status()

        return self

    def get_diff_deleted(self, config):
        """
        Delete devices in Cisco Catalyst Center based on device IP Address.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center
            config (dict): A dictionary containing the list of device IP addresses to be deleted.
        Returns:
            object: An instance of the class with updated results and status based on the deletion operation.
        Description:
            This function is responsible for removing devices from the Cisco Catalyst Center inventory and
            also unprovsioned and removed wired provsion devices from the Inventory page and also delete
            the Global User Defined Field that are associated to the devices.
        """

        device_to_delete = self.get_device_ips_from_config_priority()
        self.result["msg"] = []

        if self.config[0].get("add_user_defined_field"):
            udf_field_list = self.config[0].get("add_user_defined_field")
            for udf in udf_field_list:
                field_name = udf.get("name")
                udf_id = self.get_udf_id(field_name)

                if udf_id is None:
                    self.status = "success"
                    self.msg = "Global UDF '{0}' is not present in Cisco Catalyst Center".format(
                        field_name
                    )
                    self.log(self.msg, "INFO")
                    self.result["changed"] = False
                    self.result["msg"] = self.msg
                    self.result["response"] = self.msg
                    return self

                try:
                    response = self.dnac._exec(
                        family="devices",
                        function="delete_user_defined_field",
                        op_modifies=True,
                        params={"id": udf_id},
                    )
                    if response and isinstance(response, dict):
                        self.log(
                            "Received API response from 'delete_user_defined_field': {0}".format(
                                str(response)
                            ),
                            "DEBUG",
                        )
                        task_id = response.get("response").get("taskId")

                        while True:
                            execution_details = self.get_task_details(task_id)

                            if "success" in execution_details.get("progress"):
                                self.status = "success"
                                self.msg = "Global UDF '{0}' deleted successfully from Cisco Catalyst Center".format(
                                    field_name
                                )
                                self.log(self.msg, "INFO")
                                self.result["changed"] = True
                                self.result["response"] = execution_details
                                break
                            elif execution_details.get("isError"):
                                self.status = "failed"
                                failure_reason = execution_details.get(
                                    "failureReason")
                                if failure_reason:
                                    self.msg = "Failed to delete Global User Defined Field(UDF) due to: {0}".format(
                                        failure_reason
                                    )
                                else:
                                    self.msg = "Global UDF deletion get failed."
                                self.log(self.msg, "ERROR")
                                self.result["response"] = self.msg
                                break

                except Exception as e:
                    error_message = "Error while deleting Global UDF from Cisco Catalyst Center: {0}".format(
                        str(e)
                    )
                    self.log(error_message, "ERROR")
                    raise Exception(error_message)

            return self

        for device_ip in device_to_delete:
            if device_ip not in self.have.get("device_in_dnac"):
                self.status = "success"
                self.result["changed"] = False
                self.msg = "Device '{0}' is not present in Cisco Catalyst Center so can't perform delete operation".format(
                    device_ip
                )
                self.result["msg"].append(self.msg)
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")
                continue

            try:
                provision_params = {"device_management_ip_address": device_ip}
                prov_respone = self.dnac._exec(
                    family="sda",
                    function="get_provisioned_wired_device",
                    op_modifies=True,
                    params=provision_params,
                )

                if prov_respone.get("status") == "success":
                    response = self.dnac._exec(
                        family="sda",
                        function="delete_provisioned_wired_device",
                        op_modifies=True,
                        params=provision_params,
                    )
                    executionid = response.get("executionId")

                    while True:
                        execution_details = self.get_execution_details(
                            executionid)
                        if execution_details.get("status") == "SUCCESS":
                            self.result["changed"] = True
                            self.msg = execution_details.get("bapiName")
                            self.log(self.msg, "INFO")
                            self.result["response"].append(self.msg)
                            break
                        elif execution_details.get("bapiError"):
                            self.msg = execution_details.get("bapiError")
                            self.log(self.msg, "ERROR")
                            self.result["response"].append(self.msg)
                            break
            except Exception as e:
                device_id = self.get_device_ids([device_ip])
                delete_params = {
                    "id": device_id[0],
                    "clean_config": self.config[0].get("clean_config", False),
                }
                response = self.dnac._exec(
                    family="devices",
                    function="delete_device_by_id",
                    op_modifies=True,
                    params=delete_params,
                )

                if response and isinstance(response, dict):
                    task_id = response.get("response").get("taskId")

                    while True:
                        execution_details = self.get_task_details(task_id)

                        if "success" in execution_details.get("progress"):
                            self.status = "success"
                            self.msg = "Device '{0}' was successfully deleted from Cisco Catalyst Center".format(
                                device_ip
                            )
                            self.log(self.msg, "INFO")
                            self.result["changed"] = True
                            self.result["response"] = execution_details
                            break
                        elif execution_details.get("isError"):
                            self.status = "failed"
                            failure_reason = execution_details.get(
                                "failureReason")
                            if failure_reason:
                                self.msg = "Device '{0}' deletion get failed due to: {1}".format(
                                    device_ip, failure_reason
                                )
                            else:
                                self.msg = "Device '{0}' deletion get failed.".format(
                                    device_ip
                                )
                            self.log(self.msg, "ERROR")
                            self.result["response"] = self.msg
                            break
                    self.result["msg"].append(self.msg)

        return self

    def verify_diff_merged(self, config):
        """
        Verify the merged status(Addition/Updation) of Devices in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by retrieving the current state
            (have) and desired state (want) of the configuration, logs the states, and validates whether the specified
            site exists in the Catalyst Center configuration.

            The function performs the following verifications:
            - Checks for devices added to Cisco Catalyst Center and logs the status.
            - Verifies updated device roles and logs the status.
            - Verifies updated interface details and logs the status.
            - Verifies updated device credentials and logs the status.
            - Verifies the creation of a global User Defined Field (UDF) and logs the status.
            - Verifies the provisioning of wired devices and logs the status.
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        devices_to_add = self.have["device_not_in_dnac"]
        credential_update = self.config[0].get("credential_update", False)
        device_type = self.config[0].get("type", "NETWORK_DEVICE")
        device_ips = self.get_device_ips_from_config_priority()

        if not devices_to_add:
            self.status = "success"
            msg = """Requested device(s) '{0}' have been successfully added to the Cisco Catalyst Center and their
                    addition has been verified.""".format(
                str(self.have["devices_in_playbook"])
            )
            self.log(msg, "INFO")
        else:
            self.log(
                """Playbook's input does not match with Cisco Catalyst Center, indicating that the device addition
                    task may not have executed successfully.""",
                "INFO",
            )

        if self.config[0].get("update_interface_details"):
            interface_update_flag = True
            interface_names_list = (
                self.config[0].get("update_interface_details").get(
                    "interface_name")
            )

            for device_ip in device_ips:
                for interface_name in interface_names_list:
                    if not self.check_interface_details(device_ip, interface_name):
                        interface_update_flag = False
                        break

            if interface_update_flag:
                self.status = "success"
                msg = "Interface details updated and verified successfully for devices {0}.".format(
                    device_ips
                )
                self.log(msg, "INFO")
            else:
                self.log(
                    """Playbook's input does not match with Cisco Catalyst Center, indicating that the update
                         interface details task may not have executed successfully.""",
                    "INFO",
                )

        if credential_update and device_type == "NETWORK_DEVICE":
            credential_update_flag = self.check_credential_update()

            if credential_update_flag:
                self.status = "success"
                msg = "Device credentials and details updated and verified successfully in Cisco Catalyst Center."
                self.log(msg, "INFO")
            else:
                self.log(
                    "Playbook parameter does not match with Cisco Catalyst Center, meaning device updation task not executed properly.",
                    "INFO",
                )
        elif device_type != "NETWORK_DEVICE":
            self.log(
                """Unable to compare the parameter for device type '{0}' in the playbook with the one in Cisco Catalyst Center.""".format(
                    device_type
                ),
                "WARNING",
            )

        if self.config[0].get("add_user_defined_field"):
            udf_field_list = self.config[0].get("add_user_defined_field")
            for udf in udf_field_list:
                field_name = udf.get("name")
                udf_exist = self.is_udf_exist(field_name)

                if udf_exist:
                    self.status = "success"
                    msg = "Global UDF {0} created and verified successfully".format(
                        field_name
                    )
                    self.log(msg, "INFO")
                else:
                    self.log(
                        """Mismatch between playbook parameter and Cisco Catalyst Center detected, indicating that
                            the task of creating Global UDF may not have executed successfully.""",
                        "INFO",
                    )

        if self.config[0].get("role"):
            device_role_flag = True

            for device_ip in device_ips:
                if not self.check_device_role(device_ip):
                    device_role_flag = False
                    break

            if device_role_flag:
                self.status = "success"
                msg = "Device roles updated and verified successfully."
                self.log(msg, "INFO")
            else:
                self.log(
                    """Mismatch between playbook parameter 'role' and Cisco Catalyst Center detected, indicating the
                         device role update task may not have executed successfully.""",
                    "INFO",
                )

        if self.config[0].get("provision_wired_device"):
            provision_wired_list = self.config[0].get("provision_wired_device")
            provision_wired_flag = True
            provision_device_list = []

            for prov_dict in provision_wired_list:
                device_ip = prov_dict["device_ip"]
                provision_device_list.append(device_ip)
                device_prov_status = self.get_provision_wired_device(device_ip)
                if device_prov_status == 1 or device_prov_status == 3:
                    provision_wired_flag = False
                    break

            if provision_wired_flag:
                self.status = "success"
                msg = "Wired devices {0} get provisioned and verified successfully.".format(
                    provision_device_list
                )
                self.log(msg, "INFO")
            else:
                self.log(
                    """Mismatch between playbook's input and Cisco Catalyst Center detected, indicating that
                         the provisioning task may not have executed successfully.""",
                    "INFO",
                )

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of Device and Global UDF in Cisco Catalyst Center.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified Devices or Global UDF deleted from Cisco Catalyst Center.
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")
        input_devices = self.have["want_device"]

        if self.config[0].get("add_user_defined_field"):
            udf_field_list = self.config[0].get("add_user_defined_field")
            for udf in udf_field_list:
                field_name = udf.get("name")
                udf_id = self.get_udf_id(field_name)

                if udf_id is None:
                    self.status = "success"
                    msg = """Global UDF named '{0}' has been successfully deleted from Cisco Catalyst Center and the deletion
                        has been verified.""".format(
                        field_name
                    )
                    self.log(msg, "INFO")

            return self

        device_delete_flag = True
        for device_ip in input_devices:
            if device_ip in self.have.get("device_in_dnac"):
                device_after_deletion = device_ip
                device_delete_flag = False
                break

        if device_delete_flag:
            self.status = "success"
            self.msg = "Requested device(s) '{0}' deleted from Cisco Catalyst Center and the deletion has been verified.".format(
                str(input_devices)
            )
            self.log(self.msg, "INFO")
        else:
            self.log(
                """Mismatch between playbook parameter device({0}) and Cisco Catalyst Center detected, indicating that
                     the device deletion task may not have executed successfully.""".format(
                    device_after_deletion
                ),
                "INFO",
            )

        return self


def main():
    """main entry point for module execution"""

    element_spec = {
        "dnac_host": {
            "type": "str",
            "required": True,
        },
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
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    module = AnsibleModule(argument_spec=element_spec,
                           supports_check_mode=False)

    dnac_device = DnacDevice(module)
    state = dnac_device.params.get("state")

    if state not in dnac_device.supported_states:
        dnac_device.status = "invalid"
        dnac_device.msg = "State {0} is invalid".format(state)
        dnac_device.check_return_status()

    dnac_device.validate_input().check_return_status()
    config_verify = dnac_device.params.get("config_verify")

    for config in dnac_device.validated_config:
        dnac_device.reset_values()
        dnac_device.get_want(config).check_return_status()
        dnac_device.get_have(config).check_return_status()
        dnac_device.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            dnac_device.verify_diff_state_apply[state](
                config).check_return_status()

    module.exit_json(**dnac_device.result)


if __name__ == "__main__":
    main()
