#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = (
    "Madhan Sankaranarayanan, Abhishek Maheshwari, Syed Khadeer Ahmed, Ajith Andrew J"
)
DOCUMENTATION = r"""
---
module: inventory_workflow_manager
short_description: Comprehensive network device inventory management for Cisco Catalyst Center
description:
  - Add, update, delete, and synchronize network devices in Cisco Catalyst Center inventory
  - Provision wired devices and manage device configurations across multiple sites
  - Schedule and manage device maintenance windows with flexible recurrence options
  - Handle device credentials, roles, and user-defined fields
  - Export device details and credentials with encrypted file support
  - Perform bulk operations on network devices with comprehensive error handling
version_added: '6.8.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Abhishek Maheshwari (@abmahesh)
  - Madhan Sankaranarayanan (@madhansansel)
  - Syed Khadeer Ahmed (@syed-khadeerahmed)
  - Ajith Andrew J (@ajithandrewj)
options:
  config_verify:
    description:
      - Enable verification of Cisco Catalyst Center configuration after applying playbook changes
      - When enabled, the module will validate that changes were applied correctly
    type: bool
    default: false
  state:
    description:
      - Desired state of the device inventory after module execution
      - C(merged) - Add new devices or update existing device configurations
      - C(deleted) - Remove devices from inventory (use clean_config for configuration cleanup)
    type: str
    choices: ["merged", "deleted"]
    default: "merged"
  config:
    description: List of device configurations for inventory operations
    type: list
    elements: dict
    required: true
    suboptions:
      type:
        description:
          - Device type classification for inventory management.
          - C(NETWORK_DEVICE) - This refers to traditional networking equipment
            such as routers, switches, access points, and firewalls. These devices
            are responsible for routing, switching, and providing connectivity
            within the network.
          - C(COMPUTE_DEVICE) - These are computing resources such as servers,
            virtual machines, or containers that are part of the network
            infrastructure. Cisco Catalyst Center can integrate with compute
            devices to provide visibility and management capabilities, ensuring
            that the network and compute resources work together seamlessly to
            support applications and services.
          - C(MERAKI_DASHBOARD) - It is a cloud-based platform used to manage
            Meraki networking devices, including wireless access points, switches,
            security appliances, and cameras.
          - C(THIRD_PARTY_DEVICE) - This category encompasses devices from vendors
            other than Cisco or Meraki. Cisco Catalyst Center is designed to support
            integration with third-party devices through open standards and APIs.
            This allows organizations to manage heterogeneous network environments
            efficiently using Cisco Catalyst Center's centralized management and
            automation capabilities.
          - C(FIREPOWER_MANAGEMENT_SYSTEM) - It is a centralized management
            console used to manage Cisco's Firepower Next-Generation Firewall (NGFW)
            devices. It provides features such as policy management, threat
            detection, and advanced security analytics.
        type: str
        choices: ["NETWORK_DEVICE", "COMPUTE_DEVICE", "MERAKI_DASHBOARD", "THIRD_PARTY_DEVICE", "FIREPOWER_MANAGEMENT_SYSTEM"]
        default: "NETWORK_DEVICE"

      # Connection and Transport Parameters
      cli_transport:
        description:
          - CLI transport protocol for device communication.
          - The essential prerequisite for adding Network devices is the
            specification of the transport protocol (either ssh or telnet) used
            by the device.
          - Required for NETWORK_DEVICE types.
        type: str
        choices: ["ssh", "telnet"]
      netconf_port:
        description:
          - Specifies the port number for connecting to devices using the Netconf
            protocol. Netconf (Network Configuration Protocol) is used for managing
            network devices.
          - Ensure that the provided port number corresponds to the Netconf
            service port configured on your network devices.
          - NETCONF with user privilege 15 is mandatory for enabling Wireless
            Services on Wireless capable devices such as Catalyst 9000 series
            Switches and C9800 Series Wireless Controllers.
          - The NETCONF credentials are required to connect to C9800 Series
            Wireless Controllers as the majority of data collection is done using
            NETCONF for these Devices.
          - Standard NETCONF port is 830.
        type: str

      # Device Identification Parameters
      ip_address_list:
        description:
          - List of device management IP addresses.
          - Primary method for device identification.
          - Required for most device operations (except Meraki).
        type: list
        elements: str
      hostname_list:
        description:
          - Alternative device identification using hostnames.
          - Can be used instead of IP addresses for operations.
        type: list
        elements: str
      serial_number_list:
        description:
          - Alternative device identification using serial numbers.
          - Useful for devices before IP assignment.
        type: list
        elements: str
      mac_address_list:
        description:
          - Alternative device identification using MAC addresses.
          - Helpful for network discovery scenarios.
        type: list
        elements: str

      # Authentication Parameters
      username:
        description:
          - Device access username.
          - Required for NETWORK_DEVICE additions.
        type: str
      password:
        description:
          - Device access password and file encryption key.
          - Required for NETWORK_DEVICE additions.
          - Also used for CSV export file encryption.
        type: str
      enable_password:
        description:
          - Privileged EXEC mode password.
          - Required for enabling configurations on the device.
        type: str

      # HTTP Parameters (for specific device types)
      http_username:
        description:
          - HTTP authentication username.
          - Required for COMPUTE_DEVICE and FIREPOWER_MANAGEMENT_SYSTEM.
        type: str
      http_password:
        description:
          - HTTP authentication password.
          - Required for COMPUTE_DEVICE, MERAKI_DASHBOARD, and
            FIREPOWER_MANAGEMENT_SYSTEM.
        type: str
      http_port:
        description:
          - HTTP service port.
          - Required for COMPUTE_DEVICE and FIREPOWER_MANAGEMENT_SYSTEM.
          - Common values are 80 (HTTP) or 443 (HTTPS).
        type: str
      http_secure:
        description: Flag indicating HTTP security.
        type: bool

      # SNMP Configuration Parameters
      snmp_version:
        description:
          - It is a standard protocol used for managing and monitoring network
            devices.
          - C(v2) - In this communication between the SNMP manager (such as Cisco
            Catalyst) and the managed devices (such as routers, switches, or
            access points) is based on community strings. Community strings serve
            as a form of authentication and they are transmitted in clear text,
            providing no encryption.
          - C(v3) - It is the most secure version of SNMP, providing
            authentication, integrity, and encryption features. It allows for the
            use of usernames, authentication passwords, and encryption keys,
            providing stronger security compared to v2.
        type: str
        choices: ["v2", "v3"]
      snmp_mode:
        description:
          - Device's snmp Mode refer to different SNMP (Simple Network
            Management Protocol) versions and their corresponding security levels.
          - C(NOAUTHNOPRIV) - This mode provides no authentication or encryption
            for SNMP messages. It means that devices communicating using SNMPv1
            do not require any authentication (username/password) or encryption
            (data confidentiality). This makes it the least secure option.
          - C(AUTHNOPRIV) - This mode provides authentication but no encryption
            for SNMP messages. Authentication involves validating the source of
            the SNMP messages using a community string (similar to a password).
            However, the data transmitted between devices is not encrypted, so
            it's susceptible to eavesdropping.
          - C(AUTHPRIV) - This mode provides both authentication and encryption
            for SNMP messages. It offers the highest level of security among the
            three options. Authentication ensures that the source of the messages
            is genuine, and encryption ensures that the data exchanged between
            devices is confidential and cannot be intercepted by unauthorized
            parties.
        type: str
        choices: ["NOAUTHNOPRIV", "AUTHNOPRIV", "AUTHPRIV"]
      snmp_username:
        description:
          - SNMPv3 username for authentication.
          - Required for SNMPv3 with authentication.
        type: str
      snmp_auth_passphrase:
        description:
          - SNMPv3 authentication passphrase.
          - Required for AUTHNOPRIV and AUTHPRIV modes.
        type: str
      snmp_auth_protocol:
        description:
          - SNMPv3 authentication algorithm. SHA (Secure Hash Algorithm) -
            cryptographic hash function commonly used for data integrity
            verification and authentication purposes.
        type: str
        choices: ["SHA", "MD5"]
        default: "SHA"
      snmp_priv_passphrase:
        description:
          - SNMPv3 privacy/encryption passphrase.
          - Required for AUTHPRIV mode.
        type: str
      snmp_priv_protocol:
        description:
          - SNMPv3 encryption algorithm.
          - AES variants provide different key lengths.
          - Required for adding network, compute, and third-party devices.
        type: str
        choices: ["AES128", "AES192", "AES256", "CISCOAES128", "CISCOAES192", "CISCOAES256"]
      snmp_ro_community:
        description:
          - SNMPv2c read-only community string.
          - Required for SNMPv2c devices.
        type: str
      snmp_rw_community:
        description:
          - SNMPv2c read-write community string.
          - Required for configuration changes via SNMP.
        type: str
      snmp_retry:
        description: Number of SNMP request retries before timeout.
        type: int
        default: 3
      snmp_timeout:
        description: SNMP request timeout in seconds.
        type: int
        default: 5

      # Device Management Parameters
      role:
        description:
          - Network device role assignment.
          - C(ACCESS) - This role typically represents switches or access points
            that serve as access points for end-user devices to connect to the
            network. These devices are often located at the edge of the network
            and provide connectivity to end-user devices.
          - C(DISTRIBUTION) - This role represents function as distribution
            switches or routers in hierarchical network designs. They aggregate
            traffic from access switches and route it toward the core of the
            network or toward other distribution switches.
          - C(CORE) - This role typically represents high-capacity switches or
            routers that form the backbone of the network. They handle large
            volumes of traffic and provide connectivity between different parts
            of network, such as connecting distribution switches or providing
            interconnection between different network segments.
          - C(BORDER_ROUTER) - These are devices that connect different network
            domains or segments together. They often serve as gateways between
            different networks, such as connecting an enterprise network to the
            internet or connecting multiple branch offices.
          - C(UNKNOWN) - This role is assigned to devices whose roles or functions
            have not been identified or classified within Cisco Catalyst Center.
            This could happen if the platform is unable to determine the device's
            role based on available information.
        type: str
        choices: ["ACCESS", "DISTRIBUTION", "CORE", "BORDER_ROUTER", "UNKNOWN"]
      compute_device:
        description: Indicates whether a device is a compute device.
        type: bool
      extended_discovery_info:
        description: Additional discovery information for the device.
        type: str

      # Update and Sync Parameters
      credential_update:
        description:
          - Set this to 'True' to update device credentials and other device
            details.
          - When this parameter is 'True', ensure that the devices are present in
            Cisco Catalyst Center; only then can update operations be performed
            on the respective devices.
          - If the parameter is 'True' and any device is not present, the module
            will attempt to add it. If required parameters are missing during this
            addition, the module will fail and stop execution, preventing update
            operations for devices that are already present.
        type: bool
        default: false
      device_resync:
        description:
          - Trigger device inventory synchronization.
          - Make this as true needed for the resyncing of device.
        type: bool
        default: false
      force_sync:
        description:
          - Use high-priority thread for synchronization.
          - If forcesync is true then device sync would run in high priority
            thread if available, else the sync will fail.
        type: bool
        default: false
      resync_device_count:
        description:
          - Maximum devices per resync batch.
          - Specifies the maximum number of devices to be resynced in the
            inventory.
          - Ensure this count does not exceed 200, as attempting to resync more
            than 200 devices may cause the 'sync_devices_using_forcesync' API
            to enter an infinite loop.
        type: int
        default: 200
      resync_max_timeout:
        description:
          - Maximum resync wait time in seconds.
          - Sets the maximum timeout for the device resync process in the
            inventory, in seconds.
          - The default is 600 seconds, which helps prevent infinite loops.
        type: int
        default: 600
      reboot_device:
        description:
          - Trigger device reboot (Access Points only).
          - Make this as true needed for the Rebooting of Access Points.
          - Only applicable to Unified AP devices.
        type: bool
        default: false

      # Management IP Update
      update_mgmt_ipaddresslist:
        description: Update device management IP addresses.
        type: list
        elements: dict
        suboptions:
          exist_mgmt_ipaddress:
            description: Device's existing Mgmt IpAddress.
            type: str
            required: true
          new_mgmt_ipaddress:
            description: Device's new Mgmt IpAddress.
            type: str
            required: true

      # Deletion Parameters
      clean_config:
        description:
          - Remove device configuration during deletion.
          - C(false) - Remove from inventory only (default).
          - C(true) - Remove device and clear configuration.
          - Required if need to delete the Provisioned device by clearing current
            configuration.
        type: bool
        default: false

      # User Defined Fields
      add_user_defined_field:
        description:
          - Create and assign Global User Defined Fields.
          - This operation will take dictionary as a parameter and in this we
            give details to create/update/delete/assign multiple UDF to a device.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - Global UDF name (required for create/delete/assign).
              - Name of Global User Defined Field. Required for creating/deleting
                UDF and then assigning it to device.
              - Must be unique across Catalyst Center.
            type: str
            required: true
          description:
            description: UDF description and metadata. Info about the global user
              defined field. Also used while updating interface details.
            type: str
          value:
            description:
              - Value to assign to the UDF.
              - Value to assign to tag with or without the same user defined field
                name.
            type: str

      # Interface Management
      update_interface_details:
        description:
          - Update physical interface configurations.
          - This operation will take dictionary as a parameter and in this we
            give details to update interface details of device.
        type: dict
        suboptions:
          interface_name:
            description:
              - List of interface names to update.
              - Specify the list of interface names to update the details of the
                device interface. (For example, GigabitEthernet1/0/11,
                FortyGigabitEthernet1/1/2)
            type: list
            elements: str
            required: true
          description:
            description: Interface description text. Specifies the description of
              the interface of the device.
            type: str
          vlan_id:
            description:
              - Access VLAN ID assignment.
              - Unique Id number assigned to a VLAN within a network used only
                while updating interface details.
              - Must be valid VLAN number (1-4094).
            type: int
          voice_vlan_id:
            description:
              - Voice VLAN ID for IP phone traffic.
              - Identifier used to distinguish a specific VLAN that is dedicated
                to voice traffic used only while updating interface details.
              - Separate VLAN for voice traffic optimization.
            type: int
          admin_status:
            description:
              - Administrative interface state.
              - Status of Interface of a device, it can be (UP/DOWN).
            type: str
            choices: ["UP", "DOWN"]
          deployment_mode:
            description:
              - Configuration deployment mode.
              - C(Preview) - Preview/Deploy [Preview means the configuration is
                not pushed to the device.
              - C(Deploy) - Deploy makes the configuration pushed to the device].
            type: str
            choices: ["Preview", "Deploy"]
            default: "Deploy"
          clear_mac_address_table:
            description:
              - Clear interface MAC address table.
              - Set this to true if you need to clear the MAC address table for a
                specific device's interface. It's a boolean type, with a default
                value of False.
              - Only supported on ACCESS role devices.
            type: bool
            default: false

      # Device Export
      export_device_list:
        description:
          - Export device information to encrypted CSV.
          - This operation take dictionary as parameter and export the device
            details as well as device credentials details in a csv file.
        type: dict
        suboptions:
          password:
            description:
              - CSV file encryption password.
              - Specifies the password for the encryption of file while exporting
                the device credentails into the file.
              - Must meet complexity requirements (8+ chars, mixed case, numbers,
                symbols).
            type: str
            required: true
          operation_enum:
            description:
              - Export data type.
              - C(0/CREDENTIALDETAILS) - 0 to export Device Credential Details.
                Used for exporting device credentials details like snmp credentials,
                device credentials etc.
              - C(1/DEVICEDETAILS) - 1 to export Device Details. Used for exporting
                device specific details like device hostname, serial number, type,
                family etc.
            type: str
            choices: ["0", "1", "CREDENTIALDETAILS", "DEVICEDETAILS"]
            required: true
          parameters:
            description:
              - Specific device attributes to export.
              - List of device parameters that needs to be exported to file.
                (For example, ["componentName", "SerialNumber", "Last Sync Status"])
            type: list
            elements: str
          site_name:
            description:
              - Filter devices by site location.
              - Indicates the exact location where the wired device will be
                provisioned. This is a string value that should represent the
                complete hierarchical path of the site (For example,
                "Global/USA/San Francisco/BGL_18/floor_pnp").
            type: str
      export_device_details_limit:
        description:
          - Maximum devices per export batch.
          - Specifies the limit for updating device details or exporting device
            details/credentials to a file. The default limit is set to 500 devices.
          - This limit is applied when exporting device details/credentials and
            editing device details.
          - The maximum number of device details/credentials that can be exported
            in a single API call is 800.
          - Controls memory usage for large inventories.
        type: int
        default: 500

      # Device Provisioning
      provision_wired_device:
        description:
          - Provision wired devices to network sites.
          - This parameter takes a list of dictionaries. Each dictionary provides
            the IP address of a wired device and the name of the site where the
            device will be provisioned.
        type: list
        elements: dict
        suboptions:
          device_ip:
            description:
              - IP address of device to provision.
              - Specifies the IP address of the wired device. This is a string
                value that should be in the format of standard IPv4 or IPv6
                addresses.
              - Device must exist in inventory.
            type: str
            required: true
            version_added: 6.12.0
          site_name:
            description:
              - Target site for device provisioning.
              - Indicates the exact location where the wired device will be
                provisioned. This is a string value that should represent the
                complete hierarchical path of the site (For example,
                "Global/USA/San Francisco/BGL_18/floor_pnp").
              - Must use complete hierarchical path.
            type: str
            required: true
          resync_retry_count:
            description:
              - Retry attempts for managed state verification.
              - Determines the total number of retry attempts for checking if the
                device has reached a managed state during the provisioning process.
              - If unspecified, the default value is set to 200 retries.
              - Higher values provide more reliability.
            type: int
            default: 200
            version_added: 6.12.0
          resync_retry_interval:
            description:
              - Seconds between managed state checks.
              - Sets the interval, in seconds, at which the system will recheck
                the device status throughout the provisioning process.
              - If unspecified, the system will check the device status every 2
                seconds by default.
              - Balance between responsiveness and system load.
            type: int
            default: 2
            version_added: 6.12.0

      # Maintenance Scheduling
      devices_maintenance_schedule:
        description:
          - Schedule device maintenance windows.
          - Defines the maintenance schedule for a list of devices, specifying the
            time frame and recurrence details for scheduled maintenance tasks or
            deleting them.
          - Supports one-time and recurring maintenance.
          - Requires Catalyst Center >= 2.3.7.9.
        type: list
        elements: dict
        suboptions:
          device_ips:
            description:
              - List of network device IPs.
              - This field is applicable only during the creation or deletion of
                schedules. For updates, this field is read-only, and devices
                cannot be added or removed.
            type: list
            elements: str
            required: true
          description:
            description:
              - Maintenance purpose and details.
              - A brief description of the maintenance schedule, specifying its
                purpose or any relevant details.
            type: str
          start_time:
            description:
              - Maintenance window start time.
              - The scheduled start time of the maintenance window. For one-time
                schedules, this must be later than the current time.
              - Format - "YYYY-MM-DD HH:MM:SS" (e.g., "2025-04-05 10:00:00").
              - Must be future time for new schedules.
            type: str
            required: true
          end_time:
            description:
              - Maintenance window end time.
              - The scheduled end time of the maintenance window. For one-time
                schedules, this must be later than the current time.
              - Format - "YYYY-MM-DD HH:MM:SS" (e.g., "2025-04-05 12:00:00").
              - Must be after start_time.
            type: str
            required: true
          time_zone:
            description:
              - Timezone for maintenance schedule.
              - Time zone in which the maintenance schedule is defined (for
                example, "Africa/Nairobi", "America/New_York", "Asia/Kolkata",
                "Europe/London", "Australia/Sydney", etc.).
              - See Catalyst Center documentation for complete list.
            type: str
            required: true
            choices: ["Africa/Abidjan", "Africa/Accra",
            "Africa/Addis_Ababa", "Africa/Algiers",
            "Africa/Asmara", "Africa/Bamako", "Africa/Bangui",
            "Africa/Banjul", "Africa/Bissau", "Africa/Blantyre",
            "Africa/Brazzaville", "Africa/Bujumbura",
            "Africa/Cairo", "Africa/Casablanca", "Africa/Conakry",
            "Africa/Dakar", "Africa/Dar_es_Salaam",
            "Africa/Djibouti", "Africa/Douala", "Africa/El_Aaiun",
            "Africa/Freetown", "Africa/Gaborone",
            "Africa/Harare", "Africa/Johannesburg",
            "Africa/Juba", "Africa/Kampala", "Africa/Khartoum",
            "Africa/Kigali", "Africa/Kinshasa", "Africa/Lagos",
            "Africa/Libreville", "Africa/Lome", "Africa/Luanda",
            "Africa/Lubumbashi", "Africa/Lusaka",
            "Africa/Malabo", "Africa/Maputo", "Africa/Maseru",
            "Africa/Mbabane", "Africa/Mogadishu",
            "Africa/Monrovia", "Africa/Nairobi", "Africa/Ndjamena",
            "Africa/Niamey", "Africa/Nouakchott",
            "Africa/Ouagadougou", "Africa/Porto-Novo",
            "Africa/Sao_Tome", "Africa/Tripoli", "Africa/Tunis",
            "Africa/Windhoek", "America/Adak", "America/Anchorage",
            "America/Anguilla", "America/Antigua",
            "America/Argentina/Buenos_Aires", "America/Aruba",
            "America/Asuncion", "America/Atikokan",
            "America/Barbados", "America/Belize",
            "America/Blanc-Sablon", "America/Bogota",
            "America/Cancun", "America/Caracas", "America/Cayenne",
            "America/Cayman", "America/Chicago", "America/Costa_Rica",
            "America/Curacao", "America/Danmarkshavn",
            "America/Denver", "America/Dominica",
            "America/Edmonton", "America/El_Salvador",
            "America/Grand_Turk", "America/Grenada",
            "America/Guadeloupe", "America/Guatemala",
            "America/Guayaquil", "America/Guyana",
            "America/Halifax", "America/Havana", "America/Hermosillo",
            "America/Jamaica", "America/Kralendijk",
            "America/La_Paz", "America/Lima", "America/Los_Angeles",
            "America/Lower_Princes", "America/Managua",
            "America/Manaus", "America/Marigot", "America/Martinique",
            "America/Mexico_City", "America/Miquelon",
            "America/Montevideo", "America/Montserrat",
            "America/Nassau", "America/New_York",
            "America/Noronha", "America/Nuuk", "America/Ojinaga",
            "America/Panama", "America/Paramaribo",
            "America/Phoenix", "America/Port-au-Prince",
            "America/Port_of_Spain", "America/Puerto_Rico",
            "America/Punta_Arenas", "America/Regina",
            "America/Rio_Branco", "America/Santiago",
            "America/Santo_Domingo", "America/Sao_Paulo",
            "America/Scoresbysund", "America/St_Barthelemy",
            "America/St_Johns", "America/St_Kitts",
            "America/St_Lucia", "America/St_Thomas",
            "America/St_Vincent", "America/Tegucigalpa",
            "America/Thule", "America/Tijuana", "America/Toronto",
            "America/Tortola", "America/Vancouver",
            "America/Whitehorse", "America/Winnipeg",
            "Antarctica/Casey", "Antarctica/Davis",
            "Antarctica/DumontDUrville", "Antarctica/Mawson",
            "Antarctica/McMurdo", "Antarctica/Palmer",
            "Antarctica/Syowa", "Antarctica/Troll",
            "Antarctica/Vostok", "Arctic/Longyearbyen",
            "Asia/Aden", "Asia/Almaty", "Asia/Amman",
            "Asia/Ashgabat", "Asia/Baghdad", "Asia/Bahrain",
            "Asia/Baku", "Asia/Bangkok", "Asia/Beirut",
            "Asia/Bishkek", "Asia/Brunei", "Asia/Calcutta",
            "Asia/Chita", "Asia/Colombo", "Asia/Damascus",
            "Asia/Dhaka", "Asia/Dili", "Asia/Dubai",
            "Asia/Dushanbe", "Asia/Hebron", "Asia/Ho_Chi_Minh",
            "Asia/Hong_Kong", "Asia/Hovd", "Asia/Irkutsk",
            "Asia/Jakarta", "Asia/Jayapura", "Asia/Jerusalem",
            "Asia/Kabul", "Asia/Kamchatka", "Asia/Karachi",
            "Asia/Kathmandu", "Asia/Kuala_Lumpur",
            "Asia/Kuwait", "Asia/Macau", "Asia/Makassar",
            "Asia/Manila", "Asia/Muscat", "Asia/Nicosia",
            "Asia/Novosibirsk", "Asia/Omsk", "Asia/Phnom_Penh",
            "Asia/Pyongyang", "Asia/Qatar", "Asia/Qyzylorda",
            "Asia/Riyadh", "Asia/Sakhalin", "Asia/Seoul",
            "Asia/Shanghai", "Asia/Singapore", "Asia/Taipei",
            "Asia/Tashkent", "Asia/Tbilisi", "Asia/Tehran",
            "Asia/Thimphu", "Asia/Tokyo", "Asia/Ulaanbaatar",
            "Asia/Urumqi", "Asia/Vientiane", "Asia/Vladivostok",
            "Asia/Yangon", "Asia/Yekaterinburg", "Asia/Yerevan",
            "Atlantic/Azores", "Atlantic/Bermuda",
            "Atlantic/Canary", "Atlantic/Cape_Verde",
            "Atlantic/Faroe", "Atlantic/Reykjavik",
            "Atlantic/South_Georgia", "Atlantic/St_Helena",
            "Atlantic/Stanley", "Australia/Adelaide",
            "Australia/Brisbane", "Australia/Darwin",
            "Australia/Eucla", "Australia/Lord_Howe",
            "Australia/Perth", "Australia/Sydney",
            "Europe/Amsterdam", "Europe/Andorra",
            "Europe/Athens", "Europe/Belgrade", "Europe/Berlin",
            "Europe/Bratislava", "Europe/Brussels",
            "Europe/Bucharest", "Europe/Budapest",
            "Europe/Chisinau", "Europe/Copenhagen",
            "Europe/Dublin", "GMT", "Europe/Gibraltar",
            "Europe/Guernsey", "Europe/Helsinki",
            "Europe/Isle_of_Man", "Europe/Istanbul",
            "Europe/Jersey", "Europe/Kaliningrad",
            "Europe/Kyiv", "Europe/Lisbon", "Europe/Ljubljana",
            "Europe/London", "Europe/Luxembourg",
            "Europe/Madrid", "Europe/Malta", "Europe/Mariehamn",
            "Europe/Minsk", "Europe/Monaco", "Europe/Moscow",
            "Europe/Oslo", "Europe/Paris", "Europe/Podgorica",
            "Europe/Prague", "Europe/Riga", "Europe/Rome",
            "Europe/Samara", "Europe/San_Marino",
            "Europe/Sarajevo", "Europe/Simferopol",
            "Europe/Skopje", "Europe/Sofia", "Europe/Stockholm",
            "Europe/Tallinn", "Europe/Tirane", "Europe/Vaduz",
            "Europe/Vatican", "Europe/Vienna", "Europe/Vilnius",
            "Europe/Warsaw", "Europe/Zagreb", "Europe/Zurich",
            "Indian/Antananarivo", "Indian/Chagos",
            "Indian/Christmas", "Indian/Cocos", "Indian/Comoro",
            "Indian/Kerguelen", "Indian/Mahe", "Indian/Maldives",
            "Indian/Mauritius", "Indian/Mayotte",
            "Indian/Reunion", "Pacific/Apia", "Pacific/Auckland",
            "Pacific/Bougainville", "Pacific/Chatham",
            "Pacific/Chuuk", "Pacific/Easter", "Pacific/Efate",
            "Pacific/Fakaofo", "Pacific/Fiji", "Pacific/Funafuti",
            "Pacific/Galapagos", "Pacific/Gambier",
            "Pacific/Guadalcanal", "Pacific/Guam",
            "Pacific/Honolulu", "Pacific/Kiritimati",
            "Pacific/Kosrae", "Pacific/Majuro", "Pacific/Marquesas",
            "Pacific/Midway", "Pacific/Nauru", "Pacific/Niue",
            "Pacific/Norfolk", "Pacific/Noumea", "Pacific/Pago_Pago",
            "Pacific/Palau", "Pacific/Pitcairn", "Pacific/Port_Moresby",
            "Pacific/Rarotonga", "Pacific/Saipan",
            "Pacific/Tahiti", "Pacific/Tarawa", "Pacific/Tongatapu",
            "Pacific/Wake", "Pacific/Wallis"]
          recurrence_end_time:
            description:
              - End time for recurring maintenance.
              - The timestamp indicating when the recurring maintenance schedule
                should end. It must be greater than both the maintenance end
                date/time and the current time.
              - Format - "YYYY-MM-DD HH:MM:SS".
            type: str
          recurrence_interval:
            description:
              - Days between recurring maintenance windows.
              - Interval for recurrence in days. The interval must be longer than
                the duration of the maintenance schedules and must be within the
                range 1 to 365 (inclusive).
            type: int
requirements:
  - dnacentersdk >= 2.7.2
  - python >= 3.9
seealso:
  - name: Cisco Catalyst Center API Documentation
    description: Complete API reference for device management.
    link: https://developer.cisco.com/docs/dna-center/
  - name: Device Management API
    description: Specific documentation for device operations.
    link: https://developer.cisco.com/docs/dna-center/#!add-device
  - name: Cisco Catalyst Center documentation for Devices DeleteDeviceById
    description: Complete reference of the DeleteDeviceById API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-device-by-id
  - name: Cisco Catalyst Center documentation for Devices SyncDevices2
    description: Complete reference of the SyncDevices2 API.
    link: https://developer.cisco.com/docs/dna-center/#!sync-devices
  - name: Site Design and Hierarchy
    description: Site management for device provisioning.
    link: https://developer.cisco.com/docs/dna-center/#!sites
notes:
  # Version Compatibility
  - Minimum Catalyst Center version 2.3.5.3 required for inventory workflow features.
  - Device maintenance scheduling requires Catalyst Center >= 2.3.7.9.
  - Enhanced provisioning features available in Catalyst Center >= 2.3.5.3.

  # API Methods and Endpoints
  - Primary SDK Methods - devices.Devices.add_device, devices.Devices.delete_device_by_id, devices.Devices.sync_devices.
  - REST Endpoints - POST /dna/intent/api/v1/network-device, DELETE /dna/intent/api/v1/network-device/{id}, PUT /dna/intent/api/v1/network-device.

  # Parameter Changes and Deprecations
  - Parameter 'ip_address' renamed to 'ip_address_list' in v6.12.0.
  - Removed 'managementIpAddress' options in v4.3.0.
  - Removed parameters in v6.12.0 'serial_number', 'device_added', 'role_source'.
  - Added in v6.13.1 - 'add_user_defined_field', 'update_interface_details', 'export_device_list', 'admin_status'.
  - Removed in v6.13.1 - 'provision_wireless_device', 'reprovision_wired_device', 'device_updated'.

  # Security and Best Practices
  - Use strong passwords for device access and file encryption (8+ characters,
    mixed case, numbers, symbols).
  - Enable SNMP v3 with AUTHPRIV mode for secure device monitoring.
  - Regularly rotate device credentials and update in Catalyst Center.
  - Use HTTPS (http_secure=true) for web-based device management.

  # Performance and Limitations
  - Maximum 200 devices per resync operation to prevent API timeouts.
  - Export operations limited to 800 devices per API call.
  - Maintenance scheduling supports up to 365-day recurrence intervals.
  - Use appropriate batch sizes for large-scale operations.

  # Device Type Specific Requirements
  - NETWORK_DEVICE - Requires username, password, and transport protocol.
  - COMPUTE_DEVICE - Requires http_username, http_password, and http_port.
  - MERAKI_DASHBOARD -  Requires only http_password (API key).
  - FIREPOWER_MANAGEMENT_SYSTEM - Requires http_username, http_password, http_port.
  - THIRD_PARTY_DEVICE - Requires SNMP configuration for monitoring.

  # Operational Considerations
  - Device deletion with clean_config=false retains device configuration. To delete a
    device along with its configuration, the 'clean_config' flag must be explicitly
    set to True.
  - Interface updates only supported on user-facing/access ports.
  - MAC address table clearing restricted to ACCESS role devices.
  - Timezone specification recommended for maintenance scheduling accuracy. For a list
    of supported time zones, please refer to the relevant documentation detailing all
    available options.
  - Verify device reachability before bulk operations.

  # Error Handling and Troubleshooting
  - Monitor task status for long-running operations.
  - Check device management state before provisioning.
  - Validate site hierarchy before device-to-site assignments.
  - Ensure proper SNMP/NETCONF connectivity for device management.
  - Review Catalyst Center logs for detailed error information.

"""
EXAMPLES = r"""
---
- name: Add new device in Inventory with full credentials
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        cli_transport: ssh
        compute_device: false
        password: Test@123
        enable_password: Test@1234
        extended_discovery_info: test
        http_username: "testuser"
        http_password: "test"
        http_port: "443"
        http_secure: false
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
- name: Add new Compute device in Inventory with full
    credentials.Inputs needed for Compute Device
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
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
        password: Lablab@123
        enable_password: Cisco@123
        type: "COMPUTE_DEVICE"
- name: Add new Compute device in Inventory with minimal configuration
    credentials.Inputs needed for Compute Device
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        compute_device: true
        type: "COMPUTE_DEVICE"
        http_username: "testuser"
        http_password: "test"
        http_port: "443"
        snmp_version: v2  # Based on device snmp version field required
        snmp_ro_community: Private@123  # Based on device snmp version field required
- name: Add new Meraki device in Inventory with full
    credentials.Inputs needed for Meraki Device.
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - http_password: "test"
        type: "MERAKI_DASHBOARD"
- name: Add new Firepower Management device in Inventory
    with full credentials.Input needed to add Device.
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        http_username: "testuser"
        http_password: "test"
        http_port: "443"
        type: "FIREPOWER_MANAGEMENT_SYSTEM"
- name: Add new Third Party device in Inventory with
    full credentials.Input needed to add Device.
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        snmp_auth_passphrase: "Lablab@12"
        snmp_auth_protocol: SHA
        snmp_mode: AUTHPRIV
        snmp_priv_passphrase: "Lablab@123"
        snmp_priv_protocol: AES256
        snmp_retry: 3
        snmp_timeout: 5
        snmp_username: v3Public
        type: "THIRD_PARTY_DEVICE"
        username: v3Public
        password: "Lablab@123"
- name: Update device details or credentails in Inventory
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        cli_transport: telnet
        compute_device: false
        password: newtest123
        enable_password: newtest1233
        type: NETWORK_DEVICE
        credential_update: true
- name: Update new management IP address of device in
    inventory
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        credential_update: true
        update_mgmt_ipaddresslist:
          - exist_mgmt_ipaddress: "1.1.1.1"
            new_mgmt_ipaddress: "12.12.12.12"
- name: Associate Wired Devices to site and Provisioned
    it in Inventory
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
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
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        role: ACCESS
- name: Update Interface details with IP Address
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        update_interface_details:
          description: "Testing for updating interface
            details"
          admin_status: "UP"
          vlan_id: 23
          voice_vlan_id: 45
          deployment_mode: "Deploy"
          interface_name: ["GigabitEthernet1/0/11", FortyGigabitEthernet1/1/1]
          clear_mac_address_table: true
- name: Export Device Details in a CSV file Interface
    details with IP Address
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        export_device_list:
          password: "File_password"
          operation_enum: "0"
          parameters: ["componentName", "SerialNumber", "Last Sync Status"]
- name: Create Global User Defined with IP Address
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        add_user_defined_field:
          - name: Test123
            description: "Added first udf for testing"
            value: "value123"
          - name: Test321
            description: "Added second udf for testing"
            value: "value321"
- name: Resync Device with IP Addresses
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        device_resync: true
        force_sync: false
- name: Reboot AP Devices with IP Addresses
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        reboot_device: true
- name: Schedule the maintenance for the devices for
    one time.
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - devices_maintenance_schedule:
          - device_ips:
              - "204.1.2.2"
              - "204.1.2.3"
            description: "Schedule maintenance for 2
              devices"
            start_time: "2025-04-05 10:30:00"
            end_time: "2025-04-05 11:30:00"
            time_zone: "Asia/Kolkata"
- name: Schedule the maintenance for the devices with
    recurrence interval and recurrence end time.
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - devices_maintenance_schedule:
          - device_ips:
              - "204.1.2.2"
              - "204.1.2.3"
            description: "Schedule maintenance for 2
              devices"
            start_time: "2025-04-05 10:30:00"
            end_time: "2025-04-05 11:30:00"
            time_zone: "Asia/Kolkata"
            recurrence_end_time: "2025-04-10 11:40:00"
            recurrence_interval: 2
- name: Update the maintenance schedule for the devices.
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: merged
    config:
      - devices_maintenance_schedule:
          - device_ips:
              - "204.1.2.2"
              - "204.1.2.3"
            description: "Updated description for maintenance
              of 2 devices"
            start_time: "2025-04-05 10:30:00"
            end_time: "2025-04-05 11:30:00"
            time_zone: "Asia/Kolkata"
            recurrence_end_time: "2025-04-10 11:40:00"
            recurrence_interval: 1
- name: Delete Provision/Unprovision Devices by IP Address
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: false
    dnac_log_level: "{{ dnac_log_level }}"
    state: deleted
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        clean_config: false
- name: Delete Provision/Unprovision network devices
    along with configuration
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log: false
    dnac_log_level: "{{ dnac_log_level }}"
    state: deleted
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        clean_config: true
- name: Delete Global User Defined Field with name
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: deleted
    config:
      - ip_address_list:
          - "204.1.2.2"
          - "204.1.2.3"
        add_user_defined_field:
          - name: "Test123"
- name: Delete the maintenance schedule for the devices.
  cisco.dnac.inventory_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_port: "{{ dnac_port }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: false
    state: deleted
    config:
      - devices_maintenance_schedule:
          - device_ips:
              - "204.1.2.2"
              - "204.1.2.3"
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
    import pytz

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


class Inventory(DnacBase):
    """Class containing member attributes for inventory workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        (
            self.device_already_provisioned,
            self.provisioned_device,
            self.device_list,
            self.devices_already_present,
        ) = ([], [], [], [])
        (
            self.deleted_devices,
            self.provisioned_device_deleted,
            self.no_device_to_delete,
        ) = ([], [], [])
        self.response_list, self.role_updated_list, self.device_role_name = [], [], []
        self.udf_added, self.udf_deleted = [], []
        (
            self.maintenance_scheduled,
            self.maintenance_updated,
            self.no_update_in_maintenance,
        ) = ([], [], [])
        self.maintenance_deleted, self.no_maintenance_schedule = [], []
        (
            self.ip_address_for_update,
            self.updated_ip,
            self.update_device_ips,
            self.device_already_present,
        ) = ([], [], [], [])
        self.output_file_name, self.device_not_exist = [], []
        (
            self.resync_successful_devices,
            self.device_not_exist_to_resync,
            self.device_role_ip_already_updated,
        ) = ([], [], [])
        self.cred_updated_not_required, self.device_role_already_updated = [], []
        self.ap_rebooted_successfully = []

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
            "hostname_list": {"type": "list", "elements": "str"},
            "mac_address_list": {"type": "list", "elements": "str"},
            "netconf_port": {"type": "str"},
            "password": {"type": "str"},
            "serial_number_list": {"type": "list", "elements": "str"},
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
            "devices_maintenance_schedule": {
                "type": "list",
                "elements": "dict",
                "device_ips": {"type": "list", "elements": "str", "required": True},
                "description": {"type": "str"},
                "start_time": {"type": "str"},
                "time_zone": {"type": "str"},
                "end_time": {"type": "str"},
                "recurrence_interval": {"type": "int"},
                "recurrence_end_time": {"type": "str"},
            },
        }

        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
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
        device_hostnames = self.config[0].get("hostname_list")
        if device_hostnames:
            device_ip_dict = self.get_device_ips_from_hostnames(device_hostnames)
            return self.get_list_from_dict_values(device_ip_dict)

        # If hostnames are not available, check serial numbers
        device_serial_numbers = self.config[0].get("serial_number_list")
        if device_serial_numbers:
            device_ip_dict = self.get_device_ips_from_serial_numbers(
                device_serial_numbers
            )
            return self.get_list_from_dict_values(device_ip_dict)

        # If serial numbers are not available, check MAC addresses
        device_mac_addresses = self.config[0].get("mac_address_list")
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
                self.log(
                    "Received API response from 'get_device_list': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                if not response:
                    self.log(
                        "There are no device details received from 'get_device_list' API.",
                        "INFO",
                    )
                    break

                response = response.get("response")
                if not response:
                    self.log(
                        "There are no device details received from 'get_device_list' API.",
                        "INFO",
                    )
                    break
                for ip in response:
                    device_ip = ip["managementIpAddress"]
                    existing_devices_in_ccc.add(device_ip)

            except Exception as e:
                self.status = "failed"
                self.msg = "Error while fetching device details from Cisco Catalyst Center: {0}".format(
                    str(e)
                )
                self.log(self.msg, "CRITICAL")
                self.result["response"] = self.msg
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

        message = "Global User Defined Field with name '{0}' does not exist in Cisco Catalyst Center".format(
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
                file_id = execution_details.get("additionalStatusURL").split("/")[-1]
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
                "Given SNMP protcol '{0}' not present".format(snmp_protocol), "WARNING"
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
            file_content_binary = zip_ref.read(file_name, pwd=password.encode("utf-8"))

        # Now 'file_content_binary' contains the binary content of the decrypted file
        # Since the content is text, so we can decode it
        file_content_text = file_content_binary.decode("utf-8")

        # Now 'file_content_text' contains the text content of the decrypted file
        self.log(
            "Text content of decrypted file: {0}".format(file_content_text), "DEBUG"
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

            # Export the device data in a batch of 500 devices at a time by default
            start = 0
            device_batch_size = self.config[0].get("export_device_details_limit", 500)
            device_data = []
            first_run = True

            while start < len(device_uuids):
                device_ids_list = device_uuids[start : start + device_batch_size]
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
                        output_file_name = temp_file_name.split(".")[0] + ".csv"
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
                        output_file_name = "devices-" + str(formatted_date) + ".csv"

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
            self.output_file_name.append(output_file_name)
            self.log(self.msg, "INFO")
            self.status = "success"
            self.result["changed"] = True
            self.result["response"] = self.msg

        except Exception as e:
            self.msg = "Error while exporting device details into CSV file for device(s): '{0}'".format(
                str(device_ips)
            )
            self.log(self.msg + str(e), "ERROR")
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
                self.log(
                    "Received API response from 'get_device_list': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
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
            if device_ip not in self.have.get("device_in_ccc"):
                input_device_ips.remove(device_ip)

        ap_devices = self.get_ap_devices(input_device_ips)
        self.log(
            "AP Devices from the playbook input are: {0}".format(str(ap_devices)),
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
            resync_device_count = self.config[0].get("resync_device_count", 200)
            resync_successful_devices, resync_failed_devices = [], []
            force_sync = self.config[0].get("force_sync", False)
            resync_task_dict = {}

            while start < len(device_ids):
                device_ids_list = device_ids[start : start + resync_device_count]
                device_ips_list = input_device_ips[start : start + resync_device_count]
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
                self.resync_successful_devices = resync_successful_devices
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
                "AP Devices from the playbook input are: {0}".format(str(ap_devices)),
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
        ap_mac_address_list = []
        for device_ip in input_device_ips:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params={"managementIpAddress": device_ip},
            )
            self.log(
                "Received API response from 'get_device_list': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")
            if not response:
                continue

            response = response[0]
            ap_mac_address = response.get("apEthernetMacAddress")

            if ap_mac_address is not None:
                ap_mac_address_list.append(ap_mac_address)

        if not ap_mac_address_list:
            self.status = "success"
            self.result["changed"] = False
            self.msg = "Cannot find the AP devices for rebooting"
            self.result["response"] = self.msg
            self.log(self.msg, "INFO")
            return self

        # Now call the Reboot Access Point API
        reboot_params = {"apMacAddresses": ap_mac_address_list}
        response = self.dnac._exec(
            family="wireless",
            function="reboot_access_points",
            op_modifies=True,
            params=reboot_params,
        )
        self.log(
            "Received API response from 'reboot_access_points': {0}".format(
                str(response)
            ),
            "DEBUG",
        )

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
                    self.ap_rebooted_successfully = input_device_ips
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
        self.log(
            "{0} Device {1} provisioned successfully!!".format(device_type, device_ip),
            "INFO",
        )
        self.provisioned_device.append(device_ip)
        devices = self.provisioned_device
        self.msg = "{0} Device(s) {1} provisioned successfully!!".format(
            device_type, devices
        )
        self.result["response"] = self.msg

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
        self.msg = (
            "All {0} Devices provisioned successfully!!".format(device_type),
            "INFO",
        )
        self.log(self.msg, "INFO")
        self.result["response"] = self.msg

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
        self.msg = "{0} Device Provisioning failed for all devices".format(device_type)
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

    def wait_for_device_to_be_managed_v1(self, device_ip, max_retries, retry_interval):
        """
        Waits for the device to reach a managed state.
        Parameters:
            device_ip (str): The IP address of the device to check.
            max_retries (int): The maximum number of retries to check the device state.
            retry_interval (int): The interval in seconds between retries.
        Returns:
            bool: True if the device reaches a managed state, False otherwise.
            device_ip: The IP address of the device.
        Description:
            This method polls the device at the specified IP address to determine
            if it has reached a managed state. It retries the check a specified
            number of times, waiting a set interval between each attempt.
            If the device reaches a managed state within the allowed retries,
            it returns True; otherwise, it returns False.
        """
        retries_left = max_retries

        while retries_left > 0:
            device_response = self.get_device_response(device_ip)
            management_state = device_response.get("managementState")
            collection_status = device_response.get("collectionStatus")
            self.log(
                "Device is in {0} state, waiting for Managed State.".format(
                    management_state
                ),
                "DEBUG",
            )

            if management_state == "Managed" and collection_status == "Managed":
                msg = (
                    "Device '{0}' reached Managed state with {1} retries left.".format(
                        device_ip, retries_left
                    )
                )
                self.log(msg, "INFO")
                return True, device_ip

            if collection_status in [
                "Partial Collection Failure",
                "Could Not Synchronize",
            ]:
                msg = "Device '{0}' reached '{1}' state. Retries left: {2}.".format(
                    device_ip, collection_status, retries_left
                )
                self.log(msg, "INFO")
                return False, device_ip

            time.sleep(retry_interval)
            retries_left -= 1

        self.log(
            "Device '{0}' did not transition to the Managed state within the retry limit.".format(
                device_ip
            ),
            "WARNING",
        )
        return False, device_ip

    def provisioned_wired_device(self):
        """
        Main function to provision wired devices in Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class with updated result, status, and log.
            bool: True if the provisioning is successful, False otherwise.
            str: A message indicating the result of the provisioning process.
        Description:
            This method handles the provisioning of wired devices within the Cisco
            Catalyst Center. It manages the necessary configurations and ensures
            that the devices are set up correctly. Any errors encountered during
            the provisioning process will be logged, and a corresponding message
            will be returned to inform the user of the outcome.
        """

        provision_wired_list = self.config[0]["provision_wired_device"]
        total_devices = len(provision_wired_list)
        device_ip_list = []
        self.provision_count, self.already_provisioned_count = 0, 0

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
            self.log("Processing with Catalyst version <= 2.3.5.3", "DEBUG")
            for device_info in provision_wired_list:
                device_ip = device_info["device_ip"]
                site_name_hierarchy = device_info["site_name"]
                self.log(
                    "Processing device with IP: {0} at site: {1}".format(
                        device_ip, site_name_hierarchy
                    ),
                    "DEBUG",
                )
                device_ip_list.append(device_ip)
                self.log(
                    "Appended device IP {0} to device_ip_list".format(device_ip),
                    "DEBUG",
                )
                device_type = "Wired"
                self.log("Device type set to {0}".format(device_type), "DEBUG")
                resync_retry_count = device_info.get("resync_retry_count", 200)
                resync_retry_interval = device_info.get("resync_retry_interval", 2)
                self.log(
                    "Resync retry count: {0}, Resync retry interval: {1} seconds".format(
                        resync_retry_count, resync_retry_interval
                    ),
                    "DEBUG",
                )
                device_status = self.get_provision_wired_device(device_ip)

                if device_status == 2:  # Already provisioned
                    self.log_device_already_provisioned(device_ip)
                    continue
                elif device_status == 3:  # Error in provisioning
                    self.status = "failed"
                    error_msg = "Cannot do Provisioning for device {0}.".format(
                        device_ip
                    )
                    self.log(error_msg, "ERROR")
                    continue

                # Check if device reaches managed state
                self.log(
                    "Checking if device {0} reaches managed state.".format(device_ip),
                    "DEBUG",
                )
                managed_flag = self.wait_for_device_managed_state(
                    device_ip, resync_retry_count, resync_retry_interval
                )
                if not managed_flag:
                    self.log(
                        "Device {0} is not transitioning to the managed state,so provisioning operation cannot be performed.".format(
                            device_ip
                        ),
                        "WARNING",
                    )
                    continue

                self.log(
                    "Device {0} has successfully reached the managed state. Proceeding with provisioning operation.".format(
                        device_ip
                    ),
                    "INFO",
                )
                self.provision_wired_device_v1(
                    device_ip, site_name_hierarchy, device_type
                )

        else:
            device_ip_in_managed_state = []
            device_ip_not_in_managed_state = []
            self.log("Starting to process the provisioned wired list.", "DEBUG")
            for device_info in provision_wired_list:
                device_ip = device_info["device_ip"]
                site_name_hierarchy = device_info["site_name"]
                device_ip_list.append(device_ip)
                self.log(
                    "Processing device {0} at site {1}".format(
                        device_ip, site_name_hierarchy
                    ),
                    "DEBUG",
                )
                device_type = "Wired"
                resync_retry_count = device_info.get("resync_retry_count", 200)
                resync_retry_interval = device_info.get("resync_retry_interval", 2)
                self.log(
                    "Retry count: {0}, Retry interval: {1} seconds for device {2}".format(
                        resync_retry_count, resync_retry_interval, device_ip
                    ),
                    "DEBUG",
                )

                # Check if device reaches managed state
                managed_flag, device_ip_info = self.wait_for_device_to_be_managed_v1(
                    device_ip, resync_retry_count, resync_retry_interval
                )
                if not managed_flag:
                    device_ip_not_in_managed_state.append(device_ip_info)
                    self.log(
                        "Device {0} did not transition to the managed state, so provisioning cannot be performed.".format(
                            device_ip
                        ),
                        "WARNING",
                    )
                    continue

                self.log(
                    "Device {0} reached managed state. Adding to the managed state list.".format(
                        device_ip
                    ),
                    "INFO",
                )
                device_ip_in_managed_state.append(device_ip_info)

            self.log("Initiating provisioning for devices in managed state.", "DEBUG")
            self.provision_wired_device_v2(
                device_ip,
                site_name_hierarchy,
                device_ip_in_managed_state,
                provision_wired_list,
            )

        # Handle final provisioning results
        self.handle_final_provisioning_result(
            total_devices,
            self.provision_count,
            self.already_provisioned_count,
            device_ip_list,
            device_type,
        )
        return self

    def log_device_already_provisioned(self, device_ip):
        """
        Logs a message indicating that the device is already provisioned.
        Parameters:
            device_ip (str): The IP address of the already provisioned device.
        Returns:
            None
        Description:
            This method logs an informational message stating that the device
            with the specified IP address has already been provisioned. It
            helps in tracking the provisioning status of devices in the Cisco
            Catalyst Center.
        """
        self.status = "success"
        self.already_provisioned_count += 1
        self.result["changed"] = False
        self.msg = (
            "Device '{0}' is already provisioned in the Cisco Catalyst Center.".format(
                device_ip
            )
        )
        self.device_already_provisioned.append(device_ip)
        self.log(self.msg, "INFO")

    def wait_for_device_managed_state(self, device_ip, retry_count, retry_interval):
        """
        Waits for the device to reach a managed state.
        Parameters:
            device_ip (str): The IP address of the device to check.
            retry_count (int): The number of times to retry checking the device state.
            retry_interval (int): The interval in seconds between retries.
        Returns:
            bool: True if the device reaches a managed state, False otherwise.
        Description:
            This method polls the device at the specified IP address to determine
            if it has reached a managed state. It retries the check a specified
            number of times, waiting a set interval between each attempt.
            If the device reaches a managed state within the allowed retries,
            it returns True; otherwise, it returns False.
        """

        while retry_count > 0:
            response = self.get_device_response(device_ip)
            self.log(
                "Device is in {0} state, waiting for Managed State.".format(
                    response.get("managementState")
                ),
                "DEBUG",
            )

            if (
                response.get("managementState") == "Managed"
                and response.get("collectionStatus") == "Managed"
            ):
                msg = (
                    "Device '{0}' reached Managed state with {1} retries left.".format(
                        device_ip, retry_count
                    )
                )
                self.log(msg, "INFO")
                return True

            elif response.get("collectionStatus") in [
                "Partial Collection Failure",
                "Could Not Synchronize",
            ]:
                msg = "Device '{0}' reached '{1}' state. Retries left: {2}.".format(
                    device_ip, response.get("collectionStatus"), retry_count
                )
                self.log(msg, "INFO")
                return False

            time.sleep(retry_interval)
            retry_count -= 1

        self.log(
            "Device '{0}' did not transition to the Managed state within the retry limit.".format(
                device_ip
            ),
            "WARNING",
        )
        return False

    def provision_wired_device_v1(self, device_ip, site_name_hierarchy, device_type):
        """
        Provisions a device for versions <= 2.3.5.6.
        Parameters:
            device_ip (str): The IP address of the device to provision.
            site_name_hierarchy (str): The name of the site where the device will be provisioned.
            device_type (str): The type of device being provisioned.
        Description:
            This method provisions a device with the specified IP address,
            site name, and device type for software versions 2.3.5.6 or earlier.
            It handles the necessary configurations and returns a success status.
        """

        provision_params = {
            "deviceManagementIpAddress": device_ip,
            "siteNameHierarchy": site_name_hierarchy,
        }
        try:
            response = self.dnac._exec(
                family="sda",
                function="provision_wired_device",
                op_modifies=True,
                params=provision_params,
            )
            self.log(
                "Received API response from 'provision_wired_device': {0}".format(
                    response
                ),
                "DEBUG",
            )

            if response:
                self.check_execution_response_status(
                    response, "provision_wired_device"
                ).check_return_status()
                self.provision_count += 1
                self.provisioned_device.append(device_ip)

        except Exception as e:
            self.handle_provisioning_exception(device_ip, e, device_type)

    def provision_wired_device_v2(
        self,
        device_ip,
        site_name_hierarchy,
        device_ip_in_managed_state,
        provision_wired_list,
    ):
        """
        Provisions bulk devices for versions > 2.3.5.6.
        Parameters:
            device_ip_in_managed_state (list): List of device IPs currently in a managed state.
            provision_wired_list (list): List of dictionaries containing device and site information.

        Description:
            This method provisions multiple devices with the specified IP addresses and site names
            for software versions greater than 2.3.5.6. It performs the necessary configurations
            in a single API call to improve efficiency.
        """
        try:
            self.log(
                "Starting provisioning process for devices in managed state.", "DEBUG"
            )
            self.log(
                "Managed state devices: {0}".format(device_ip_in_managed_state), "DEBUG"
            )
            self.log("Provision wired list: {0}".format(provision_wired_list), "DEBUG")

            site_data = {}
            device_data = {}

            # Collect site and device information
            for item in provision_wired_list:
                site_name = item["site_name"]
                site_exist, site_id = self.get_site_id(site_name)
                self.log(
                    "Checked site '{0}', exists: {1}, site ID: {2}".format(
                        site_name, site_exist, site_id
                    ),
                    "DEBUG",
                )
                if site_exist:
                    site_data[site_name] = site_id

                device_ip = item["device_ip"]
                device_ids = self.get_device_ids([device_ip])
                self.log(
                    "Device IP '{0}' mapped to device IDs: {1}".format(
                        device_ip, device_ids
                    ),
                    "DEBUG",
                )
                if device_ids:
                    device_data[device_ip] = device_ids[0]

            devices_to_assign_and_provision = []
            device_already_provisioned = []
            for device_ip in device_ip_in_managed_state:
                provision_item = next(
                    (
                        item
                        for item in provision_wired_list
                        if item["device_ip"] == device_ip
                    ),
                    None,
                )
                if provision_item:
                    site_name = provision_item["site_name"]
                    site_id = site_data.get(site_name)
                    device_id = device_data.get(device_ip)
                    self.log(
                        "Processing device '{0}' for site '{1}', site ID: {2}, device ID: {3}".format(
                            device_ip, site_name, site_id, device_id
                        ),
                        "DEBUG",
                    )

                    if site_id and device_id:
                        is_device_assigned_to_a_site, device_site_name = (
                            self.is_device_assigned_to_site(device_id)
                        )

                        if not is_device_assigned_to_a_site:
                            self.log(
                                "Assigning device '{0}' to site '{1}'.".format(
                                    device_ip, site_name
                                ),
                                "INFO",
                            )
                            self.assign_device_to_site([device_id], site_name, site_id)

                        elif device_site_name != site_name:
                            self.msg = (
                                "Error in provisioning wired device '{0}' - the device is already associated "
                                "with Site '{1}' and cannot be re-associated with Site '{2}'.".format(
                                    device_ip, device_site_name, site_name
                                )
                            )
                            self.set_operation_result(
                                "failed", False, self.msg, "ERROR"
                            ).check_return_status()

                        is_device_provisioned = self.is_device_provisioned(
                            device_id, device_ip
                        )
                        self.log(
                            "Device '{0}' is provisioned: {1}".format(
                                device_ip, is_device_provisioned
                            ),
                            "DEBUG",
                        )

                        if not is_device_provisioned:
                            devices_to_assign_and_provision.append(
                                {
                                    "device_ip": device_ip,
                                    "device_id": device_id,
                                    "site_id": site_id,
                                }
                            )
                        else:
                            device_already_provisioned.append(device_ip)
                            self.log_device_already_provisioned(device_ip)

            device_ips_to_provision = [
                device["device_ip"] for device in devices_to_assign_and_provision
            ]
            self.log(
                "Devices to provision: {0}".format(device_ips_to_provision), "INFO"
            )
            if devices_to_assign_and_provision:
                payload = [
                    {
                        "siteId": device["site_id"],
                        "networkDeviceId": device["device_id"],
                    }
                    for device in devices_to_assign_and_provision
                ]
                device_ips_to_provision = [
                    device["device_ip"] for device in devices_to_assign_and_provision
                ]
                self.provision_device(payload, device_ips_to_provision)
                self.provisioned_device.extend(device_ips_to_provision)

        except Exception as e:
            self.handle_provisioning_exception(device_ip, e, "Wired")

    def is_device_assigned_to_site(self, uuid):
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

            if not site_api_response or not isinstance(site_api_response, dict):
                self.log(
                    "Invalid API response for device UUID: {0}. Response: {1}".format(
                        uuid, site_api_response
                    ),
                    "ERROR",
                )
                return False, None

            self.log(
                "API response received for 'get_site_assigned_network_device': {0}".format(
                    site_api_response
                ),
                "DEBUG",
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

    def is_device_provisioned(self, device_id, device_ip):
        """
        Checks if a device is provisioned.
        Parameters:
            device_id (str): The ID of the device to check.
        Returns:
            bool: True if the device is provisioned, False otherwise.
        Description:
            This method checks the provisioning status of the device with the
            specified device ID. It queries the Cisco Catalyst Center to determine
            if the device is currently provisioned and returns the appropriate
            status.
        """
        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
            try:
                prov_response = self.dnac._exec(
                    family="sda",
                    function="get_provisioned_wired_device",
                    params={"device_management_ip_address": device_ip},
                )
                self.log(
                    "Received API response from 'get_provisioned_wired_device': {0}".format(
                        str(prov_response)
                    ),
                    "DEBUG",
                )

                if prov_response:
                    return True

            except Exception as e:
                self.log(
                    "Exception occurred during 'get_provisioned_wired_device': {0}".format(
                        str(e)
                    ),
                    "ERROR",
                )
                return False
        else:
            try:
                api_response = self.dnac._exec(
                    family="sda",
                    function="get_provisioned_devices",
                    params={"networkDeviceId": device_id},
                )
                is_provisioned = api_response.get("response")
                self.log(
                    "API response from 'get_provisioned_devices': {}".format(
                        is_provisioned
                    ),
                    "DEBUG",
                )

                if is_provisioned:
                    return True
                return False

            except Exception as e:
                self.log(
                    "Exception occurred during 'get_provisioned_devices': {0}".format(
                        str(e)
                    ),
                    "ERROR",
                )

    def provision_device(self, provision_params, device_ip):
        """
        Provisions a device for versions > 2.3.5.3.
        Parameters:
            site_name (str): The name of the site where the device will be provisioned.
            provision_params (dict): A dictionary containing provisioning parameters.
        Returns:
            self (object): An instance of the class after the provision operation is performed.
        Description:
            This method provisions a device at the specified site using the
            given provisioning parameters for software versions greater than 2.3.5.3.
            It handles all necessary configurations and returns a success status.
        """

        try:
            response = self.dnac._exec(
                family="sda",
                function="provision_devices",
                op_modifies=True,
                params={"payload": provision_params},
            )
            self.log(
                "Received API response from 'provision_devices': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            self.check_tasks_response_status(response, api_name="provision_device")

            if self.status not in ["failed", "exited"]:
                self.log(
                    "Wired Device '{0}' provisioning completed successfully.".format(
                        device_ip
                    ),
                    "INFO",
                )
                self.provision_count += 1

        except Exception as e:
            self.log(
                "Exception occurred during provisioning: {0}".format(str(e)), "ERROR"
            )

        return self

    def handle_final_provisioning_result(
        self,
        total_devices,
        provision_count,
        already_provisioned_count,
        device_ip_list,
        device_type,
    ):
        """
        Handles the final results of the provisioning process.
        Parameters:
            total_devices (int): The total number of devices intended for provisioning.
            provision_count (int): The number of devices successfully provisioned.
            already_provisioned_count (int): The number of devices that were already provisioned.
            device_ip_list (list): A list of IP addresses of the devices processed.
            device_type (str): The type of device being provisioned.

        Description:
            This method processes the final results of the provisioning task,
            including logging the total number of devices, the count of successfully
            provisioned devices, and those that were already provisioned. It helps
            in summarizing the provisioning operation for reporting purposes.
        """

        if already_provisioned_count == total_devices:
            self.handle_all_already_provisioned(device_ip_list, device_type)
        elif provision_count == total_devices:
            self.handle_all_provisioned(device_type)
        elif provision_count == 0:
            self.handle_all_failed_provision(device_type)
        else:
            self.handle_partially_provisioned(provision_count, device_type)

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
                if self.get_sites_type(site_name=ap_loc) != "floor":
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
            self.log(
                "Received API response from 'get_network_device_by_ip': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
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
                resync_retry_interval = prov_dict.get("resync_retry_interval", 2)
                managed_flag = True

                # Check till device comes into managed state
                while resync_retry_count:
                    response = self.get_device_response(device_ip)
                    self.log(
                        "Device is in {0} state waiting for Managed State.".format(
                            response.get("managementState")
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
                        response.get("collectionStatus") == "Partial Collection Failure"
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
                self.log(
                    "Received API response from 'provision': {0}".format(str(response)),
                    "DEBUG",
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
                    self.msg = "Device '{0}' already provisioned".format(device_ip)
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
            self.log(self.msg, "ERROR")
            self.result["response"] = self.msg
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
            - "device_in_ccc": A list of devices that already exist in Cisco Catalyst Center.
            - "device_not_in_ccc": A list of devices that are not present in Cisco Catalyst Center.
        """

        have = {}
        want_device = self.get_device_ips_from_config_priority()

        # Get the list of device that are present in Cisco Catalyst Center
        device_in_ccc = self.get_existing_devices_in_ccc()
        device_not_in_ccc, devices_in_playbook = [], []

        for ip in want_device:
            devices_in_playbook.append(ip)
            if ip not in device_in_ccc:
                device_not_in_ccc.append(ip)

        if self.config[0].get("provision_wired_device"):
            provision_wired_list = self.config[0].get("provision_wired_device")

            for prov_dict in provision_wired_list:
                device_ip = prov_dict.get("device_ip")
                site_name = prov_dict.get("site_name")

                missing_params = []
                if not site_name:
                    missing_params.append("site_name")
                if not device_ip:
                    missing_params.append("device_ip")

                if missing_params:
                    self.status = "failed"
                    self.msg = "Missing parameters: '{0}'. Site and Device IP are required for Provisioning of Wired Devices.".format(
                        ", ".join(missing_params)
                    )
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    return self

                device_ip_address = prov_dict["device_ip"]
                if device_ip_address not in want_device:
                    devices_in_playbook.append(device_ip_address)
                if device_ip_address not in device_in_ccc:
                    device_not_in_ccc.append(device_ip_address)

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
                        device_ip_address not in device_in_ccc
                        and device_ip_address not in device_not_in_ccc
                    ):
                        device_not_in_ccc.append(device_ip_address)

        self.log(
            "Device(s) {0} exists in Cisco Catalyst Center".format(str(device_in_ccc)),
            "INFO",
        )
        have["want_device"] = want_device
        have["device_in_ccc"] = device_in_ccc
        have["device_not_in_ccc"] = device_not_in_ccc
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

                self.log(
                    "Received API response from 'get_device_list': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                if response:
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
            interface_detail_params = {"device_id": device_id, "name": interface_name}
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
                    "Successfully fetched interface ID ({0}) by using device id {1} and interface name {2}.".format(
                        interface_id, device_id, interface_name
                    ),
                    "INFO",
                )
                return response

        except Exception as e:
            self.status = "failed"
            self.msg = "Failed to retrieve interface ID for interface({0}) from Cisco Catalyst Center: {1}".format(
                interface_name, str(e)
            )
            self.result["response"] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

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
            self.log(
                "Received API response from 'get_device_list': {0}".format(
                    str(response)
                ),
                "DEBUG",
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

        interface_detail_params = {"device_id": device_id[0], "name": interface_name}
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

        interface_playbook_params = self.config[0].get("update_interface_details")
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
        device_batch_size = self.config[0].get("export_device_details_limit", 500)
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
            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.6") >= 0:
                response = self.dnac._exec(
                    family="sda",
                    function="get_provisioned_wired_device",
                    op_modifies=True,
                    params={"device_management_ip_address": device_ip},
                )
                self.log(
                    "Received API response from 'get_provisioned_wired_devices': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                if response.get(
                    "status"
                ) == "success" and "retrieved successfully" in response.get(
                    "description"
                ):
                    flag = 2
                    self.log(
                        "Wired device '{0}' already provisioned in the Cisco Catalyst Center.".format(
                            device_ip
                        ),
                        "INFO",
                    )
            else:
                device_ids = self.get_device_ids([device_ip])
                device_id = device_ids[0]
                if not device_ids:
                    self.log("No device ID found for IP {0}".format(device_ip), "ERROR")
                self.log(
                    "Device ID for IP {0}: {1}".format(device_ip, device_id), "DEBUG"
                )
                response = self.dnac._exec(
                    family="sda",
                    function="get_provisioned_devices",
                    op_modifies=True,
                    params={"networkDeviceId": device_id},
                )
                self.log(
                    "Received API response from 'get_provision_devices': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                response = response.get("response")
                if response:
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
                    interface_params = self.config[0].get("update_interface_details")
                    clear_mac_address_table = interface_params.get(
                        "clear_mac_address_table", False
                    )

                    if clear_mac_address_table:
                        response = self.get_device_response(device_ip)

                        if response.get("role").upper() != "ACCESS":
                            self.msg = "The action to clear the MAC Address table is only supported for devices with the ACCESS role."
                            self.log(self.msg, "WARNING")

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
                        self.response_list.append(self.msg)
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
                                self.response_list.append(self.msg)
                                self.log(self.msg, "INFO")
                                break
                            elif execution_details.get("isError"):
                                self.status = "failed"
                                failure_reason = execution_details.get("failureReason")
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
                    self.response_list.append(self.msg)

        self.result["changed"] = is_update_occurred

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
                self.ip_address_for_update.append(device_ip)
                self.updated_ip.append(new_mgmt_ipaddress)
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

        return device_ip

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
            self.log(
                "Received API response from 'get_device_list': {0}".format(
                    str(response)
                ),
                "DEBUG",
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
            if device in self.have.get("device_in_ccc"):
                device_exist = True
                break

        return device_exist

    def get_schedule_and_unscheduled_device_ids(
        self, network_device_ids, device_ip_id_map
    ):
        """
        Categorize network devices based on their maintenance schedule in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            network_device_ids (list): A list of network device IDs to check for scheduled maintenance.
            device_ip_id_map (dict): A mapping of device IDs to their corresponding IP addresses.

        Returns:
            tuple: A tuple containing:
                - schedule_device_ids (list): List of device IDs that have a scheduled maintenance window.
                - unscheduled_device_ids (list): List of device IDs that do not have a scheduled maintenance window.

        Description:
            This function checks whether the given network devices have scheduled maintenance in Cisco Catalyst Center.
            It iterates through 'network_device_ids', retrieves the maintenance schedule using the
            'retrieve_scheduled_maintenance_windows_for_network_devices' API call, and logs the response.
            Devices with scheduled maintenance are added to 'schedule_device_ids', while those without are added
            to 'unscheduled_device_ids'. If an error occurs during the API call, an error message is logged
            and the operation result is set to 'failed'.
        """

        schedule_device_ids, unscheduled_device_ids = [], []
        self.log(
            "Start checking and collecting the device ids for which maintenance is schedule or not..",
            "DEBUG",
        )
        for device_id in network_device_ids:
            try:
                device_ip = device_ip_id_map.get(device_id)
                response = self.dnac._exec(
                    family="devices",
                    function="retrieve_scheduled_maintenance_windows_for_network_devices",
                    op_modifies=True,
                    params={"network_device_ids": device_id},
                )
                self.log(
                    "Received API response from 'retrieve_scheduled_maintenance_windows_for_network_devices' for the "
                    "device '{0}': {1}".format(device_ip, str(response)),
                    "DEBUG",
                )
                response = response.get("response")
                if not response:
                    self.log(
                        "No maintenance scheduled for device '{0}'.".format(device_ip),
                        "INFO",
                    )
                    unscheduled_device_ids.append(device_id)
                    continue

                is_update_device = False
                for resp in response:
                    maintenance_schedule = resp.get('maintenanceSchedule')
                    if maintenance_schedule is None:
                        self.log("No maintenanceSchedule found in response for device '{0}'".format(device_ip), "WARNING")
                        continue

                    status = maintenance_schedule.get('status')
                    if status in ["UPCOMING", "IN_PROGRESS"]:
                        self.log(
                            "Device maintenance schedule status is '{0}', "
                            "so added the device '{1}' to update the maintenance schedule".format(
                                status, device_ip
                            ), "INFO"
                        )
                        schedule_device_ids.append(device_id)
                        is_update_device = True
                        break

                    self.log(
                        "Device '{0}' maintenance schedule status is '{1}', no action taken in this loop"
                        .format(
                            device_ip, status
                        ), "INFO"
                    )

                # If no update flagged, check for completed maintenance to schedule new maintenance
                if not is_update_device:
                    self.log("No update flagged for device '{0}', checking for completed maintenance.".format(device_ip), "DEBUG")
                    for resp in response:
                        maintenance_schedule = resp.get('maintenanceSchedule')
                        if maintenance_schedule is None:
                            self.log("No maintenanceSchedule found in response for device '{0}'".format(device_ip), "WARNING")
                            continue

                        status = maintenance_schedule.get('status')
                        if status == "COMPLETED":
                            self.log(
                                "Maintenance scheduled for the given device '{0}' is already completed. Scheduling new maintenance.".format(
                                    device_ip
                                ), "INFO"
                            )
                            unscheduled_device_ids.append(device_id)
                            break

                        self.log(
                            "Device '{0}' maintenance schedule status is '{1}', no action taken in this loop".format(
                                device_ip, status
                            ), "DEBUG"
                        )
            except Exception as e:
                self.msg = """Error while fetching the maintenance schedule for the device '{0}' present in
                        Cisco Catalyst Center: {1}""".format(
                    device_ip, str(e)
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")

        return schedule_device_ids, unscheduled_device_ids

    def get_device_maintenance_details(self, device_id, device_ip):
        """
        Retrieve the scheduled maintenance details for a specific network device in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_id (str): The unique identifier of the network device.
            device_ip (str): The IP address of the network device.

        Returns:
            dict or None:
                - A dictionary containing the maintenance details if available.
                - None if no maintenance details are found or an error occurs.

        Description:
            This function retrieves the scheduled maintenance details for a given network device using
            the 'retrieve_scheduled_maintenance_windows_for_network_devices' API call. The response is
            logged for debugging. If no maintenance details are found, it returns None. In case of an
            exception, an error message is logged, and the operation result is marked as 'failed'.
        """
        try:
            response = self.dnac._exec(
                family="devices",
                function="retrieve_scheduled_maintenance_windows_for_network_devices",
                op_modifies=True,
                params={"network_device_ids": device_id},
            )
            self.log(
                "Received API response from 'retrieve_scheduled_maintenance_windows_for_network_devices' for the "
                "device '{0}': {1}".format(device_ip, str(response)),
                "DEBUG",
            )
            response = response.get("response")
            if not response:
                self.msg = (
                    "No maintenance details retrieved for network device '{0}'.".format(
                        device_ip
                    )
                )
                return None

            state = self.params.get('state')
            if state == "deleted":
                return response

            for resp in response:
                maintenance_schedule = resp.get('maintenanceSchedule')
                if not maintenance_schedule:
                    self.log("No maintenanceSchedule found in response for device '{0}'".format(device_ip), "WARNING")
                    continue

                status = maintenance_schedule.get('status')
                if status in ["UPCOMING", "IN_PROGRESS"]:
                    self.log(
                        "Device maintenance schedule status is '{0}', "
                        "so added the device '{1}' to update the maintenance schedule".format(
                            status, device_ip
                        ), "INFO"
                    )
                    return resp

            self.log(
                "No devices found with maintenance status UPCOMING or IN_PROGRESS for"
                " device '{0}'".format(device_ip), "INFO"
            )
        except Exception as e:
            self.msg = """Error while fetching the maintenance schedule for the device '{0}' present in
                    Cisco Catalyst Center: {1}""".format(
                device_ip, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return response[0]

    def to_epoch_timezone(
        self, time_str, timezone, date_time_format="%Y-%m-%d %H:%M:%S"
    ):
        """
        Convert a given datetime string to an epoch timestamp in milliseconds for a specified timezone.

        Args:
            self (object): An instance of a class used for time-related operations.
            time_str (str): The datetime string to be converted.
            timezone (str): The timezone in which the datetime should be interpreted.
            date_time_format (str, optional): The expected format of 'time_str'. Defaults to "%Y-%m-%d %H:%M:%S".

        Returns:
            int: The epoch timestamp in milliseconds corresponding to the given datetime in the specified timezone.

        Description:
            This function converts a given datetime string into an epoch timestamp (milliseconds) based on the provided
            timezone. It first attempts to parse 'time_str' using the specified format. If the format is incorrect,
            an error is logged, and execution is halted. If the given timezone is an abbreviation, it is converted
            to its full form using 'self.get_timezone_with_abbreviation()'. The function then localizes the parsed
            datetime to the specified timezone and returns the corresponding epoch timestamp in milliseconds.

        Error Handling:
            - If 'time_str' is in an invalid format, an error is logged, and execution is halted.
            - If the given timezone is invalid, an error is logged, and execution is halted.
        """

        try:
            dt = datetime.strptime(time_str, date_time_format)
        except ValueError:
            self.msg = "Invalid datetime format: '{0}' given in the playbook. Please provide in the given format: {1}".format(
                time_str, date_time_format
            )
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        try:
            local_tz = pytz.timezone(timezone)
        except pytz.UnknownTimeZoneError:
            self.msg = "Invalid timezone: '{0}' given in the playbook.".format(timezone)
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        epoch_date_time = local_tz.localize(dt)

        return int(epoch_date_time.timestamp() * 1000)

    def get_current_time_in_timezone(self, timezone):
        """
        Retrieve the current epoch timestamp in milliseconds for a specified timezone.

        Args:
            self (object): An instance of a class used for time-related operations.
            timezone (str): The timezone for which the current time should be retrieved.

        Returns:
            int: The current epoch timestamp in milliseconds for the specified timezone.

        Description:
            This function returns the current epoch timestamp (milliseconds) based on the provided timezone.
            If the given timezone is an abbreviation, it is converted to its full form using
            'self.get_timezone_with_abbreviation()'. The function then retrieves the current time in
            the specified timezone and converts it to an epoch timestamp.

        Error Handling:
            - If the provided timezone is invalid, an error is logged, and execution is halted.
        """

        try:
            local_tz = pytz.timezone(timezone)
        except pytz.UnknownTimeZoneError:
            self.msg = "Invalid timezone: '{0}' given in the playbook.".format(timezone)
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        local_time = datetime.now(local_tz)
        epoch_curr_time = int(local_time.timestamp() * 1000)

        return epoch_curr_time

    def validate_device_maintenance_params(self, devices_maintenance):
        """
        Validate the parameters required for scheduling device maintenance in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for device maintenance scheduling.
            devices_maintenance (dict): A dictionary containing maintenance scheduling parameters, including
                - device_ips (list): List of device IPs for maintenance.
                - start_time (str): Start time of the maintenance window.
                - end_time (str): End time of the maintenance window.
                - time_zone (str): Time zone in which the maintenance schedule is defined.
                - recurrence_end_time (str, optional): The end time for recurring maintenance (if applicable).
                - recurrence_interval (int, optional): The recurrence interval in days (if applicable).

        Returns:
            self: The instance of the class with updated validation status.

        Description:
            This function performs the following validations:
            1. Ensures that required parameters ('device_ips', 'start_time', 'end_time', 'time_zone') are present.
            2. Converts 'start_time' and 'end_time' to epoch timestamps.
            3. Ensures 'start_time' and 'end_time' are greater than the current time.
            4. If 'recurrence_end_time' is provided:
                - Ensures 'recurrence_interval' is also provided and falls within the range (0,365) days.
                - Validates that the interval is longer than the maintenance duration.
                - Ensures 'recurrence_end_time' is later than 'end_time' and the current time.

        Error Handling:
            - Logs an error and terminates execution if any required parameter is missing.
            - Logs an error if timestamps or recurrence parameters are invalid.
            - Handles unexpected exceptions and logs an appropriate error message.
        """

        if not devices_maintenance or not isinstance(devices_maintenance, dict):
            self.msg = "Invalid devices_maintenance parameter. Expected a dictionary."
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        self.log(
            "Starting device maintenance parameter validation for {0} device(s)".format(
                len(devices_maintenance.get("device_ips", []))
            ),
            "INFO"
        )

        try:
            # Define required parameters with their descriptions
            required_params = {
                "device_ips": "List of device IP addresses for maintenance scheduling",
                "start_time": "Maintenance window start time in YYYY-MM-DD HH:MM:SS format",
                "end_time": "Maintenance window end time in YYYY-MM-DD HH:MM:SS format",
                "time_zone": "Time zone identifier for the maintenance schedule"
            }

            self.log(
                "Validating presence of required parameters: {0}".format(list(required_params.keys())),
                "DEBUG"
            )

            # Validate required parameters presence and format
            missing_params = []
            for param_name, description in required_params.items():
                value = devices_maintenance.get(param_name)
                if value is None or (isinstance(value, (list, str)) and not value):
                    self.log(
                        "Required parameter '{0}' ({1}) is missing or empty".format(param_name, description),
                        "ERROR"
                    )
                    missing_params.append(param_name)

            if missing_params:
                device_ips = devices_maintenance.get("device_ips", [])
                self.msg = (
                    "Required parameter(s) {0} are missing from playbook for scheduling device maintenance "
                    "for device(s): {1}".format(missing_params, device_ips)
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            self.log("All required parameters are present and valid", "DEBUG")

            # Extract validated parameters
            device_ips = devices_maintenance["device_ips"]
            start_time = devices_maintenance["start_time"]
            end_time = devices_maintenance["end_time"]
            time_zone = devices_maintenance["time_zone"]

            self.log(
                "Validating time parameters - start_time: {0}, end_time: {1}, timezone: {2}".format(
                    start_time, end_time, time_zone
                ),
                "DEBUG"
            )

            # Validate time parameters
            self._validate_time_parameters(start_time, end_time, time_zone)

            # Validate recurrence parameters if provided
            recurrence_end_time = devices_maintenance.get("recurrence_end_time")
            recurrence_interval = devices_maintenance.get("recurrence_interval")

            if recurrence_end_time or recurrence_interval:
                self._validate_recurrence_parameters(
                    start_time, end_time, time_zone,
                    recurrence_end_time, recurrence_interval
                )

            self.log("Device maintenance parameters validated successfully", "INFO")

        except Exception as e:
            self.msg = f"Validation failed for device maintenance parameters: {str(e)}"
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        return self

    def _validate_time_parameters(self, start_time, end_time, time_zone):
        """
        Validate time parameters and their relationships.

        Args:
            start_time (str): Maintenance start time
            end_time (str): Maintenance end time
            time_zone (str): Time zone for the schedule

        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        """
        self.log(
            "Starting time parameter validation for maintenance schedule",
            "INFO"
        )
        self.log(
            "Validating time parameters - start_time: {0}, end_time: {1}, timezone: {2}".format(
                start_time, end_time, time_zone
            ),
            "DEBUG"
        )

        # Convert times to epoch timestamps
        epoch_start_time = self.to_epoch_timezone(start_time, time_zone)
        epoch_end_time = self.to_epoch_timezone(end_time, time_zone)
        epoch_current_time = self.get_current_time_in_timezone(time_zone)

        # Validate time relationships
        time_validations = [
            (
                epoch_start_time < epoch_current_time,
                "start_time must be greater than the current time"
            ),
            (
                epoch_end_time < epoch_current_time,
                "end_time must be greater than the current time"
            ),
            (
                epoch_end_time <= epoch_start_time,
                "end_time must be greater than start_time"
            )
        ]

        for condition, error_msg in time_validations:
            if condition:
                self.msg = f"Time validation failed: {error_msg}"
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

        self.log(
            "Time parameter validation completed successfully",
            "DEBUG"
        )

        return self

    def _validate_recurrence_parameters(self, start_time, end_time, time_zone,
                                        recurrence_end_time, recurrence_interval):
        """
        Validate recurrence-related parameters.

        Args:
            start_time (str): Maintenance start time
            end_time (str): Maintenance end time
            time_zone (str): Time zone for the schedule
            recurrence_end_time (str): End time for recurring maintenance
            recurrence_interval (int): Recurrence interval in days

        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        """
        self.log(
            "Starting recurrence parameter validation for maintenance schedule",
            "INFO"
        )
        self.log(
            "Validating recurrence parameters - start_time: {0}, end_time: {1}, timezone: {2}, "
            "recurrence_end_time: {3}, recurrence_interval: {4}".format(
                start_time, end_time, time_zone, recurrence_end_time, recurrence_interval
            ),
            "DEBUG"
        )

        # Both recurrence parameters must be provided together
        if recurrence_interval and not recurrence_end_time:
            self.msg = "Parameter 'recurrence_end_time' is required when 'recurrence_interval' is specified"
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        if recurrence_end_time and not recurrence_interval:
            self.msg = "Parameter 'recurrence_interval' is required when 'recurrence_end_time' is specified"
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        if not (recurrence_end_time and recurrence_interval):
            return  # No recurrence parameters to validate

        # Validate recurrence interval range
        if not isinstance(recurrence_interval, int) or not (1 <= recurrence_interval <= 365):
            self.msg = f"Invalid 'recurrence_interval': {recurrence_interval}. Must be an integer between 1 and 365 days"
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        # Calculate maintenance duration and validate against interval
        epoch_start_time = self.to_epoch_timezone(start_time, time_zone)
        epoch_end_time = self.to_epoch_timezone(end_time, time_zone)
        epoch_recurr_end_time = self.to_epoch_timezone(recurrence_end_time, time_zone)
        epoch_current_time = self.get_current_time_in_timezone(time_zone)

        # Validate maintenance duration vs recurrence interval
        schedule_duration_days = (epoch_end_time - epoch_start_time) / (24 * 3600 * 1000)
        if recurrence_interval <= schedule_duration_days:
            self.msg = (
                f"Recurrence interval ({recurrence_interval} days) must be longer than "
                f"the maintenance duration ({schedule_duration_days:.2f} days)"
            )
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        # Validate recurrence end time relationships
        recurrence_validations = [
            (
                epoch_recurr_end_time < epoch_end_time,
                f"recurrence_end_time ({recurrence_end_time}) must be later than "
                f"maintenance end_time ({end_time})"
            ),
            (
                epoch_recurr_end_time < epoch_current_time,
                f"recurrence_end_time ({recurrence_end_time}) must be later than current time"
            )
        ]

        for condition, error_msg in recurrence_validations:
            if condition:
                self.msg = f"Recurrence validation failed: {error_msg}"
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

        self.log("Recurrence parameters validated successfully", "DEBUG")
        return self

    def create_schedule_maintenance_payload(
        self, devices_maintenance, unscheduled_device_ids, device_ips
    ):
        """
        Creates a payload for scheduling device maintenance in the Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            devices_maintenance (dict): Dictionary containing maintenance schedule details
            unscheduled_device_ids (list): List of device IDs that are not currently scheduled for maintenance.
            device_ips (list): List of IP addresses of the devices being scheduled.

        Returns:
            dict: A dictionary containing the formatted payload for scheduling maintenance.

        Description:
            This function constructs a payload that includes the start time, end time, time zone,
            device details, and optional recurrence information for scheduling a maintenance window.
        """

        start_time = devices_maintenance.get("start_time")
        end_time = devices_maintenance.get("end_time")
        time_zone = devices_maintenance.get("time_zone")
        epoch_start_time = self.to_epoch_timezone(start_time, time_zone)
        epoch_end_time = self.to_epoch_timezone(end_time, time_zone)

        payload = {
            "description": devices_maintenance.get("description"),
            "maintenanceSchedule": {
                "startTime": epoch_start_time,
                "endTime": epoch_end_time,
            },
            "networkDeviceIds": unscheduled_device_ids,
        }

        recurrence_end_time = devices_maintenance.get("recurrence_end_time")
        if recurrence_end_time:
            recurr_epoch_end_time = self.to_epoch_timezone(
                recurrence_end_time, time_zone
            )
            payload["maintenanceSchedule"]["recurrence"] = {
                "recurrenceEndTime": recurr_epoch_end_time,
                "interval": devices_maintenance.get("recurrence_interval"),
            }

        self.log(
            "Constructed maintenance schedule payload for device(s) {0}: {1}".format(
                device_ips, payload
            ),
            "INFO",
        )

        return payload

    def schedule_maintenance_for_devices(self, maintenance_payload, device_ips):
        """
        Schedules maintenance for specified network devices in the Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            maintenance_payload (dict): Payload containing maintenance schedule details.
            device_ips (list): List of IP addresses of the devices to be scheduled for maintenance.

        Returns:
            self: The instance of the class, updated with operation results.

        Description:
            This function triggers an API call to create a maintenance schedule for the given devices
            using the provided payload and monitors the task execution status.
        """

        try:
            self.log(
                "Proceeding with maintenance scheduling for the devices {0}.".format(
                    device_ips
                ),
                "INFO",
            )
            payload = {"payload": maintenance_payload}
            self.log(
                "Constructed payload for scheduling the maintenance: {0}".format(
                    payload
                ),
                "DEBUG",
            )
            task_name = "create_maintenance_schedule_for_network_devices"
            self.log(
                "Triggering '{0}' API call with payload.".format(task_name), "DEBUG"
            )
            task_id = self.get_taskid_post_api_call("devices", task_name, payload)

            if not task_id:
                self.msg = "Failed to retrieve task ID for '{0}'. Device maintenance scheduling aborted.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Received task ID: {0}. Monitoring task status.".format(task_id),
                "DEBUG",
            )
            success_msg = (
                "Maintenance schedule successfully for the device(s): {0}.".format(
                    device_ips
                )
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occured while scheduling the maintenance for the device(s) '{0}' in the Cisco Catalyst "
                "Center: {1}"
            ).format(device_ips, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def device_maintenance_needs_update(
        self, devices_maintenance, schedule_details, device_ip
    ):
        """
        Determine whether the maintenance schedule of a device requires an update.

        Args:
            self (object): An instance of a class used for device maintenance scheduling.
            devices_maintenance (dict): A dictionary containing maintenance scheduling parameters, including:
                - start_time (str, optional): The desired start time for maintenance.
                - end_time (str, optional): The desired end time for maintenance.
                - time_zone (str, optional): The timezone in which the maintenance schedule is defined.
                - description (str, optional): A description of the maintenance schedule.
                - recurrence_end_time (str, optional): The end time for a recurring maintenance schedule.
                - recurrence_interval (int, optional): The recurrence interval in days.
            schedule_details (dict): The current maintenance schedule details from Cisco Catalyst Center.
            device_ip (str): The IP address of the device being checked.

        Returns:
            bool: True if the maintenance schedule for the device needs to be updated, False otherwise.

        Description:
            This function compares the provided maintenance parameters with the existing schedule in Cisco Catalyst Center.
            If any discrepancy is found, the function logs the mismatch and returns True, indicating that an update is needed.
            If no updates are required, it logs an informational message and returns False.

        Error Handling:
            - If an exception occurs during the comparison process, an error is logged, and execution is halted.
            - If 'recurrence_end_time' is provided but the device is currently scheduled as a one-time maintenance, a
                warning is logged, and an update is required.
        """

        try:
            start_time = devices_maintenance.get("start_time")
            end_time = devices_maintenance.get("end_time")
            time_zone = devices_maintenance.get("time_zone")
            description = devices_maintenance.get("description")

            if description and description != schedule_details.get("description"):
                self.log(
                    "Mismatch in the parameter 'description' so maintenance schedule for the device {0} "
                    "needs update".format(device_ip), "INFO"
                )
                return True

            if start_time and time_zone:
                epoch_start_time = self.to_epoch_timezone(start_time, time_zone)
                start_time_in_ccc = schedule_details.get("maintenanceSchedule").get(
                    "startTime"
                )
                if epoch_start_time != start_time_in_ccc:
                    self.log(
                        "Mismatch in the parameter 'start_time' so maintenance schedule for the device {0} "
                        "needs update".format(device_ip),
                        "INFO",
                    )
                    return True

            if end_time and time_zone:
                epoch_end_time = self.to_epoch_timezone(end_time, time_zone)
                end_time_in_ccc = schedule_details.get("maintenanceSchedule").get(
                    "endTime"
                )
                if epoch_end_time != end_time_in_ccc:
                    self.log(
                        "Mismatch in the parameter 'end_time' so maintenance schedule for the device {0} "
                        "needs update".format(device_ip),
                        "INFO",
                    )
                    return True

            recurrence_end_time = devices_maintenance.get("recurrence_end_time")
            if recurrence_end_time:
                maintenance_recurrence = schedule_details.get(
                    "maintenanceSchedule"
                ).get("recurrence")
                if not maintenance_recurrence:
                    self.log(
                        "Parameter 'recurrence_end_time' is given in the playbook but the device {0} is currently "
                        "scheduled for one-time maintenance. Cannot change the maintenance type from once to "
                        "recurring.".format(device_ip),
                        "WARNING",
                    )
                    return True

                recurrence_end_time_in_ccc = maintenance_recurrence.get(
                    "recurrenceEndTime"
                )
                recurr_epoch_end_time = self.to_epoch_timezone(
                    recurrence_end_time, time_zone
                )
                if recurr_epoch_end_time != recurrence_end_time_in_ccc:
                    self.log(
                        "Mismatch in the parameter 'recurrence_end_time' so maintenance schedule for the device {0} "
                        "needs update".format(device_ip),
                        "INFO",
                    )
                    return True

                recurrence_interval = devices_maintenance.get("recurrence_interval")
                recurrence_interval_in_ccc = maintenance_recurrence.get("interval")
                if (
                    recurrence_interval
                    and recurrence_interval != recurrence_interval_in_ccc
                ):
                    self.log(
                        "Mismatch in the parameter 'recurrence_interval' so maintenance schedule for the device {0} "
                        "needs update".format(device_ip),
                        "INFO",
                    )
                    return True

        except Exception as e:
            self.msg = (
                "An exception occured while checking the scheduling the maintenance for the device '{0}' "
                " needs update or not in the Cisco Catalyst Center: {1}"
            ).format(device_ip, str(e))
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        self.log(
            "There is no update required for the given schedule maintenance of device {0}.".format(
                device_ip
            ),
            "INFO",
        )

        return False

    def is_recurrence_type_changed(self, devices_maintenance, schedule_details):
        """
        Check if the recurrence type of the maintenance schedule has changed.

        Args:
            self (object): An instance of a class used for device maintenance scheduling.
            devices_maintenance (dict): A dictionary containing maintenance scheduling parameters
            schedule_details (dict): Dictionary containing current schedule details.

        Returns:
            bool: True if the maintenance type has changed from one-time to recurring, False otherwise.

        Description:
            This function checks if the provided maintenance schedule includes a 'recurrence_end_time'
            while the existing schedule in Cisco Catalyst Center does not have recurrence enabled.
            If recurrence was not previously set, it logs a warning and returns True, indicating a
            change in recurrence type, which is not allowed.

        Error Handling:
            - Logs a warning if an attempt is made to change the maintenance type from one-time to recurring.
        """

        recurrence_end_time = devices_maintenance.get("recurrence_end_time")
        recurrence_type_in_ccc = schedule_details.get("maintenanceSchedule").get(
            "recurrence"
        )
        if recurrence_end_time and recurrence_type_in_ccc is None:
            self.log(
                "Parameter 'recurrence_end_time' is provided but the system schedule is set for one-time only. "
                "Changing maintenance type from one-time to recurring is not allowed.",
                "WARNING",
            )
            return True

        return False

    def get_update_payload_for_maintenance(
        self, devices_maintenance, schedule_details, device_ip
    ):
        """
        Generates an updated payload for scheduling or modifying device maintenance.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            devices_maintenance (dict): Dictionary containing maintenance details such as
                'start_time', 'end_time', 'time_zone', 'recurrence_end_time', and 'recurrence_interval'.
            schedule_details (dict): Dictionary containing existing schedule details, including
                schedule ID, description, maintenance schedule, and network device IDs.
            device_ip (str): The IP address of the device for which the maintenance schedule is being updated.

        Returns:
            dict: Updated payload containing maintenance schedule information.

        Description:
            This function constructs a maintenance schedule payload by incorporating the given device
            maintenance details and existing schedule information. It converts provided timestamps
            into epoch format and validates recurrence parameters if applicable.
        """

        start_time = devices_maintenance.get("start_time")
        end_time = devices_maintenance.get("end_time")
        time_zone = devices_maintenance.get("time_zone")
        maintenance_schedule = schedule_details.get("maintenanceSchedule") or {}
        schedule_payload = {
            "id": schedule_details.get("id"),
            "description": devices_maintenance.get("description") or schedule_details.get("description", " "),
            "maintenanceSchedule": {
                "startTime": maintenance_schedule.get("startTime"),
                "endTime": maintenance_schedule.get("endTime"),
            },
            "networkDeviceIds": schedule_details.get("networkDeviceIds"),
        }
        if start_time and time_zone:
            epoch_start_time = self.to_epoch_timezone(start_time, time_zone)
            schedule_payload["maintenanceSchedule"]["startTime"] = epoch_start_time
            self.log(
                "Converted start_time '{0}' to epoch '{1}' using timezone '{2}'.".format(
                    start_time, epoch_start_time, time_zone
                ),
                "DEBUG",
            )

        if end_time and time_zone:
            epoch_end_time = self.to_epoch_timezone(end_time, time_zone)
            schedule_payload["maintenanceSchedule"]["endTime"] = epoch_end_time
            self.log(
                "Converted end_time '{0}' to epoch '{1}' using timezone '{2}'.".format(
                    end_time, epoch_end_time, time_zone
                ),
                "DEBUG",
            )

        recurrence_end_time = devices_maintenance.get("recurrence_end_time")
        if recurrence_end_time:
            ep_end_time = schedule_payload["maintenanceSchedule"]["endTime"]
            epoch_current_time = self.get_current_time_in_timezone(time_zone)
            self.log(
                "Validating end_time '{0}' against current time '{1}'.".format(
                    ep_end_time, epoch_current_time
                ),
                "DEBUG",
            )
            if ep_end_time < epoch_current_time:
                self.msg = (
                    "Given 'end_time' {0} is less than the current date/time {1}. It should be"
                    " greater than the current date/time.".format(
                        ep_end_time, epoch_current_time
                    )
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            recurr_epoch_end_time = self.to_epoch_timezone(
                recurrence_end_time, time_zone
            )
            self.log(
                "Validating recurrence_end_time '{0}' against end_time '{1}'.".format(
                    recurr_epoch_end_time, ep_end_time
                ),
                "DEBUG",
            )
            if recurr_epoch_end_time < ep_end_time:
                self.msg = (
                    "Given 'recurrence_end_time' {0} is less than device maintenance end date/time {1}. "
                    "It should be greater than maintenance end date/time.".format(
                        recurr_epoch_end_time, ep_end_time
                    )
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            interval = devices_maintenance.get("recurrence_interval")
            schedule_payload["maintenanceSchedule"]["recurrence"] = {
                "recurrenceEndTime": recurr_epoch_end_time,
                "interval": interval
                or maintenance_schedule.get("recurrence").get("interval"),
            }
            self.log(
                "Added recurrence to payload: {0}".format(
                    schedule_payload["maintenanceSchedule"]["recurrence"]
                ),
                "DEBUG",
            )
            ep_start_time = schedule_payload["maintenanceSchedule"]["startTime"]
            recur_interval = schedule_payload["maintenanceSchedule"]["recurrence"][
                "interval"
            ]
            schedule_duration_days = (ep_end_time - ep_start_time) / (24 * 3600 * 1000)
            self.log(
                "Validating recurrence interval '{0}' against schedule window '{1}' days.".format(
                    recur_interval, schedule_duration_days
                ),
                "DEBUG",
            )
            if recur_interval < schedule_duration_days:
                self.msg = (
                    "The interval must be longer than the duration of the schedules."
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

        if not schedule_payload.get("maintenanceSchedule").get(
            "recurrence"
        ) and schedule_details.get("maintenanceSchedule").get("recurrence"):
            schedule_payload["maintenanceSchedule"]["recurrence"] = (
                maintenance_schedule.get("recurrence")
            )
            self.log(
                "No recurrence provided in devices_maintenance. Using existing recurrence from schedule details.",
                "DEBUG",
            )

        self.log(
            "Payload for updating the scheduled maintenance of device {0}: {1}".format(
                device_ip, schedule_payload
            ),
            "INFO",
        )

        return schedule_payload

    def exit_maintenance_window(self, schedule_details):
        """
        Exits the maintenance window for a given device schedule by updating its end time.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            schedule_details (dict): Dictionary containing maintenance schedule details,
                including 'id', 'description', 'maintenanceSchedule', and 'networkDeviceIds'.

        Returns:
            self: Returns the current instance after performing the update.

        Description:
            This function constructs a payload to update the maintenance schedule by setting the
            `endTime` to `-1`, signaling the termination of the maintenance window. It then triggers
            an API call to update the schedule and monitors the task status.
        """

        try:
            exit_window_payload = {
                "description": schedule_details.get("description"),
                "maintenanceSchedule": schedule_details.get("maintenanceSchedule"),
                "networkDeviceIds": schedule_details.get("networkDeviceIds"),
            }
            exit_window_payload["maintenanceSchedule"]["endTime"] = -1
            update_payload = {
                "id": schedule_details.get("id"),
                "payload": exit_window_payload,
            }
            self.log(
                "Constructed payload for updating the maintenance schedule: {0}".format(
                    update_payload
                ),
                "DEBUG",
            )
            task_name = "updates_the_maintenance_schedule_information"
            self.log(
                "Triggering '{0}' API call to update the maintenance window.".format(
                    task_name
                ),
                "DEBUG",
            )
            task_id = self.get_taskid_post_api_call(
                "devices", task_name, update_payload
            )

            if not task_id:
                self.msg = "Failed to retrieve task ID for '{0}'. Exiting the maintenance schedule window aborted.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Received task ID: {0}. Monitoring task status.".format(task_id),
                "DEBUG",
            )
            success_msg = "Exited the maintenance schedule window successfully."
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occurred while trying to exit the maintenance schedule window: {0}"
            ).format(str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def update_schedule_maintenance(self, update_schedule_payload, device_ip):
        """
        Update the maintenance schedule for a specific network device.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            update_schedule_payload (dict): The payload containing updated maintenance schedule details.
            device_ip (str): The IP address of the device for which the maintenance schedule is being updated.

        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Description:
            This function updates the maintenance schedule for a specified device in Cisco Catalyst Center.
            It constructs the necessary payload, triggers the API call to update the schedule, and retrieves
            the task ID associated with the operation. The function then monitors the task's status and logs
            appropriate messages. If the task ID cannot be retrieved, the update process is aborted.
        """

        try:
            self.log(
                "Starting maintenance schedule update for device '{0}'.".format(
                    device_ip
                ),
                "INFO",
            )
            schedule_id = update_schedule_payload.get("id")
            update_schedule_payload.pop("id")
            payload = {"payload": update_schedule_payload, "id": schedule_id}
            self.log(
                "Constructed payload for updating the maintenance schedule: {0}".format(
                    payload
                ),
                "DEBUG",
            )
            task_name = "updates_the_maintenance_schedule_information"
            self.log(
                "Triggering '{0}' API call to update maintenance schedule.".format(
                    task_name
                ),
                "DEBUG",
            )
            task_id = self.get_taskid_post_api_call("devices", task_name, payload)

            if not task_id:
                self.msg = (
                    "Failed to retrieve task ID after '{0}' API call. "
                    "Maintenance schedule update for device '{1}' aborted.".format(
                        task_name, device_ip
                    )
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Received task ID: {0}. Monitoring task status.".format(task_id),
                "DEBUG",
            )
            success_msg = (
                "Maintenance schedule updated successfully for the device: {0}.".format(
                    device_ip
                )
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occured while updating the maintenance schedule for the device '{0}' in the Cisco Catalyst "
                "Center: {1}"
            ).format(device_ip, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def delete_maintenance_schedule(self, schedule_id):
        """
        Delete a maintenance schedule from Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            schedule_id (str): The unique identifier of the maintenance schedule to be deleted.

        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.

        Description:
            This function deletes a specified maintenance schedule from Cisco Catalyst Center.
            It constructs a request payload containing the schedule ID and triggers an API call
            to delete the schedule. The function retrieves the task ID associated with the
            deletion process and monitors the task's status. If the task ID cannot be retrieved,
            the deletion process is aborted.
        """

        try:
            self.log(
                "Starting maintenance schedule deletion for schedule ID '{0}'.".format(
                    schedule_id
                ),
                "INFO",
            )
            payload = {"id": schedule_id}
            self.log(
                "Constructed payload for deleting the maintenance schedule: {0}".format(
                    payload
                ),
                "DEBUG",
            )
            task_name = "delete_maintenance_schedule"
            task_id = self.get_taskid_post_api_call("devices", task_name, payload)

            if not task_id:
                self.msg = (
                    "Unable to retrieve the task ID after '{0}' API call. "
                    "Maintenance schedule deletion aborted.".format(task_name)
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Maintenance schedule deleted successfully from the Cisco Catalyst Center",
                "INFO",
            )

            success_msg = "Maintenance schedule deleted successfully from the Cisco Catalyst Center"
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = "An exception occurred while deleting the maintenance schedule with ID '{0}': {1}".format(
                schedule_id, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

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

    def parse_for_add_network_device_params(self, device_params):
        """
        Parse the network device parameters from the provided dictionary.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_params (dict): A dictionary containing device parameters.

        Returns:
            dict: A dictionary containing parsed network device parameters.

        Description:
            This function extracts and formats the network device parameters from the provided dictionary.
            It ensures that all required fields are present and correctly formatted for further processing.
        """
        self.log("Parsing network device parameters for: {0}".format(
            self.pprint(device_params)), "INFO")

        if not device_params["snmpVersion"]:
            device_params["snmpVersion"] = "v3"

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
                msg = "Required parameter 'snmpROCommunity' for adding device with snmmp version v2 is not present"
                self.log(msg, "ERROR")
                self.fail_and_exit(msg)
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

        return device_params

    def parse_for_add_compute_device_params(self, device_params):
        """
        Filter unnecessary params for compute device parameters from the provided dictionary.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_params (dict): A dictionary containing device parameters.

        Returns:
            dict: A dictionary containing parsed compute device parameters.

        Description:
            This function extracts and formats the compute device parameters from the provided dictionary.
            It ensures that all required fields are present and correctly formatted for further processing.
        """
        self.log("Parsing compute device parameters for: {0}".format(
            self.pprint(device_params)), "INFO")

        params_to_remove = [
            "snmpAuthPassphrase",
            "snmpAuthProtocol",
            "snmpMode",
            "snmpPrivPassphrase",
            "snmpPrivProtocol",
            "snmpROCommunity",
            "snmpRwCommunity",
            "snmpRetry",
            "snmpTimeout",
            "snmpUserName",
            "snmpVersion",
            "netconfPort"
        ]
        for param in params_to_remove:
            device_params.pop(param, None)

        return device_params

    def add_inventory_device(self, device_params, devices_to_add, device_to_add_in_ccc):
        """
        Add a new network device to the inventory in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            device_params (dict): A dictionary containing the parameters for the new device.
            devices_to_add (list): A list of devices to be added.

        Returns:
            object: An instance of the class with updated results and status.
        """
        self.log("Adding device to inventory: {0}".format(str(device_params)), "INFO")

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

            if not response or not isinstance(response, dict):
                self.msg = "Failed to add device(s) '{0}' to Cisco Catalyst Center".format(
                    str(self.config[0].get("ip_address_list"))
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            task_id = response.get("response").get("taskId")
            if not task_id:
                self.msg = "Failed to retrieve task ID for device(s) '{0}'".format(
                    str(self.config[0].get("ip_address_list"))
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            resync_retry_count = int(self.payload.get("dnac_api_task_timeout"))
            resync_retry_interval = int(self.payload.get("dnac_task_poll_interval"))
            while resync_retry_count > 0:
                execution_details = self.get_task_details(task_id)

                if "/task/" in execution_details.get("progress"):
                    self.status = "success"
                    self.result["response"] = execution_details

                    if len(devices_to_add) > 0:
                        self.device_list.append(devices_to_add)
                        self.result["changed"] = True
                        self.msg = "Device(s) '{0}' added to Cisco Catalyst Center".format(
                            str(devices_to_add)
                        )
                        self.log(self.msg, "INFO")
                        self.result["msg"] = self.msg
                        self.result["response"] = self.msg
                        break
                    self.msg = "Device(s) '{0}' already present in Cisco Catalyst Center".format(
                        str(self.config[0].get("ip_address_list"))
                    )
                    self.log(self.msg, "INFO")
                    self.result["msg"] = self.msg
                    break
                elif execution_details.get("isError"):
                    self.status = "failed"
                    failure_reason = execution_details.get("failureReason")
                    if failure_reason:
                        self.msg = "Device addition for the device(s) '{0}' get failed because of {1}.".format(
                            device_to_add_in_ccc, failure_reason
                        )
                    else:
                        self.msg = "Device addition get failed for the device(s): '{0}'.".format(
                            device_to_add_in_ccc
                        )
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    break

                self.log(
                    "Pauses execution for {0} seconds.".format(resync_retry_interval),
                    "INFO",
                )
                time.sleep(resync_retry_interval)
                resync_retry_count = resync_retry_count - resync_retry_interval
            return self
        except Exception as e:
            error_message = (
                "Error while adding device in Cisco Catalyst Center: {0}".format(
                    str(e)
                )
            )
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def parse_for_update_network_device_params(self, playbook_params, device_data, device_ip):
        """
        Parse the network device parameters for updating an existing device in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            playbook_params (dict): A dictionary containing playbook parameters.
            device_data (dict): A dictionary containing device data.
            device_ip (str): The IP address of the device to be updated.

        Returns:
            dict: A dictionary containing parsed network device parameters for update.

        Description:
            This function extracts and formats the network device parameters from the provided dictionary
            for updating an existing device in Cisco Catalyst Center.
        """
        self.log("Parsing network device parameters for update: {0}".format(
            self.pprint(playbook_params)), "INFO")

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

        if playbook_params.get("snmpVersion") not in ["v2", "v3"]:
            if device_data["snmp_version"] == "3":
                playbook_params["snmpVersion"] = "v3"
            else:
                playbook_params["snmpVersion"] = "v2"

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
            elif device_data["snmpv3_auth_password"]:
                csv_data_dict["snmp_auth_passphrase"] = device_data[
                    "snmpv3_auth_password"
                ]
        else:
            csv_data_dict["snmp_username"] = None

        device_username = device_data.get("cli_username")
        device_password = device_data.get("cli_password")
        cli_enable_password = device_data.get("cli_enable_password")
        device_netconf_port = device_data.get("netconf_port")
        device_snmp_username = device_data.get("snmpv3_user_name")

        playbook_username = playbook_params.get("userName")
        playbook_password = playbook_params.get("password")
        playbook_enable_password = playbook_params.get("enablePassword")
        playbook_netconf_port = playbook_params.get("netconfPort")
        playbook_snmp_username = playbook_params.get("snmpUserName")

        if (
            (
                playbook_username is not None
                or playbook_password is not None
                or playbook_enable_password is not None
                or playbook_netconf_port is not None
                or playbook_snmp_username is not None
            )
            and (
                device_username == playbook_username
                or playbook_username is None
            )
            and (
                device_password == playbook_password
                or playbook_password is None
            )
            and (
                cli_enable_password == playbook_enable_password
                or playbook_enable_password is None
            )
            and (
                device_netconf_port == playbook_netconf_port
                or playbook_netconf_port is None
            )
            and (
                device_snmp_username == playbook_snmp_username
                or playbook_snmp_username is None
            )
        ):
            self.log(
                "Credentials for device {0} do not require an update.".format(
                    device_ip
                ),
                "DEBUG",
            )
            self.cred_updated_not_required.append(device_ip)
            return None

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
        elif playbook_params["snmpMode"] == "AUTHNOPRIV":
            if not playbook_params["snmpAuthPassphrase"]:
                playbook_params["snmpAuthPassphrase"] = csv_data_dict[
                    "snmp_auth_passphrase"
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

        return playbook_params

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
        devices_to_add = self.have["device_not_in_ccc"]
        device_type = self.config[0].get("type", "NETWORK_DEVICE")
        device_resynced = config.get("device_resync", False)
        device_reboot = config.get("reboot_device", False)
        credential_update = config.get("credential_update", False)

        config["type"] = device_type
        config["ip_address_list"] = devices_to_add
        if device_type == "FIREPOWER_MANAGEMENT_SYSTEM":
            config["http_port"] = self.config[0].get("http_port", "443")

        if self.config[0].get("provision_wired_device"):

            provision_wired_list = self.config[0]["provision_wired_device"]

            device_not_available = []

            for prov_dict in provision_wired_list:
                device_ip = prov_dict["device_ip"]
                site_name = prov_dict["site_name"]
                site_exist, site_id = self.get_site_id(site_name)
                if not site_exist:
                    self.status = "failed"
                    self.msg = (
                        "Unable to Provision Wired Device(s) because the site(s) listed: '{0}' are not present in the"
                        "Cisco Catalyst Center."
                    ).format(str(site_name))
                    self.result["response"] = self.msg
                    self.log(self.msg, "ERROR")
                    return self
                if device_ip not in self.have.get("device_in_ccc"):
                    device_not_available.append(device_ip)
            if device_not_available:
                self.status = "failed"
                self.msg = """Unable to Provision Wired Device(s) because the device(s) listed: {0} are not present in the
                            Cisco Catalyst Center.""".format(
                    str(device_not_available)
                )
                self.result["response"] = self.msg
                self.log(self.msg, "ERROR")
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
                return self

        if self.config[0].get("device_resync"):
            is_device_exists = self.is_device_exist_in_ccc(config["ip_address_list"])
            if not is_device_exists:
                self.device_not_exist_to_resync.append(config["ip_address_list"])

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
            device_exist = self.is_device_exist_for_update(devices_to_update_role)

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

            if not device_exist:
                self.msg = """Unable to edit device credentials/details because the device(s) listed: {0} are not present in the
                            Cisco Catalyst Center.""".format(
                    str(device_to_update)
                )
                self.status = "failed"
                self.result["response"] = self.msg
                self.log(self.msg, "ERROR")
                return self

        if device_reboot:
            device_to_update = self.get_device_ips_from_config_priority()
            device_exist = self.is_device_exist_for_update(device_to_update)

            if not device_exist:
                self.device_not_exist.append(device_to_update)
                self.msg = (
                    "Unable to reboot device because the device(s) listed: {0} are not present in the"
                    " Cisco Catalyst Center."
                ).format(str(device_to_update))
                self.status = "ok"
                self.result["response"] = self.msg
                self.log(self.msg, "ERROR")
                return self

        if (
            not config["ip_address_list"]
            and config.get("snmp_version")
            and config.get("snmp_mode")
        ):
            self.device_already_present.append(
                ", ".join(self.have["devices_in_playbook"])
            )

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

            if device_type == "NETWORK_DEVICE":
                self.parse_for_add_network_device_params(device_params)
            elif device_type == "COMPUTE_DEVICE":
                self.parse_for_add_compute_device_params(device_params)

            device_params["ipAddress"] = config["ip_address_list"]
            device_to_add_in_ccc = device_params["ipAddress"]

            if not self.config[0].get("device_resync"):
                self.mandatory_parameter(device_to_add_in_ccc).check_return_status()

            self.add_inventory_device(device_params, devices_to_add, device_to_add_in_ccc)

        # Update the role of devices having the role source as Manual
        if config.get("role"):
            devices_to_update_role = self.get_device_ips_from_config_priority()
            device_role = config.get("role")
            role_update_count = 0
            for device_ip in devices_to_update_role:
                device_id = self.get_device_ids([device_ip])

                # Check if the same role of device is present in dnac then no need to change the state
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=True,
                    params={"managementIpAddress": device_ip},
                )
                self.log(
                    "Received API response from 'get_device_list': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                response = response.get("response")[0]

                if response.get("role") == device_role:
                    self.status = "success"
                    self.result["changed"] = False
                    self.device_role_already_updated.append(device_role)
                    self.device_role_ip_already_updated.append(device_ip)
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
                                self.role_updated_list.append(device_ip)
                                self.device_role_name.append(device_role)
                                break
                            elif execution_details.get("isError"):
                                self.status = "failed"
                                failure_reason = execution_details.get("failureReason")
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

            if self.role_updated_list:
                self.status = "success"
                self.result["changed"] = True
                self.msg = "Device(s) '{0}' role updated successfully to '{1}'".format(
                    self.role_updated_list, device_role
                )
                self.result["msg"] = self.msg
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")

        if credential_update:
            device_to_update = self.get_device_ips_from_config_priority()
            update_device_ips = []

            # Update Device details and credentails
            device_uuids = self.get_device_ids(device_to_update)
            password = "Testing@123"
            start = 0
            device_batch_size = self.config[0].get("export_device_details_limit", 500)
            device_details = {}

            while start < len(device_uuids):
                device_ids_list = device_uuids[start : start + device_batch_size]
                export_payload = {
                    "deviceUuids": device_ids_list,
                    "password": password,
                    "operationEnum": "0",
                }
                export_response = self.trigger_export_api(export_payload)
                self.check_return_status()
                csv_reader = self.decrypt_and_read_csv(export_response, password)
                self.check_return_status()

                for row in csv_reader:
                    ip_address = row["ip_address"]
                    device_details[ip_address] = row
                start += device_batch_size

            for device_ip in device_to_update:
                playbook_params = self.want.get("device_params").copy()
                playbook_params["ipAddress"] = [device_ip]
                device_data = device_details[device_ip]

                if device_type == "NETWORK_DEVICE":
                    parse_status = self.parse_for_update_network_device_params(
                        playbook_params, device_data, device_ip
                    )
                    if not parse_status:
                        self.log(
                            "Credentials for device {0} do not require an update.".format(
                                device_ip
                            ),
                            "DEBUG",
                        )
                        continue

                if not playbook_params["httpUserName"]:
                    playbook_params["httpUserName"] = device_data.get(
                        "http_config_username", None
                    )
                if not playbook_params["httpPassword"]:
                    playbook_params["httpPassword"] = device_data.get(
                        "http_config_password", None
                    )
                if not playbook_params["httpPort"]:
                    playbook_params["httpPort"] = device_data.get("http_port", None)

                for key, value in playbook_params.items():
                    if value == " ":
                        playbook_params[key] = None

                try:
                    if playbook_params["updateMgmtIPaddressList"]:
                        new_mgmt_ipaddress = playbook_params["updateMgmtIPaddressList"][
                            0
                        ]["newMgmtIpAddress"]
                        if new_mgmt_ipaddress in self.have["device_in_ccc"]:
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
                            self.update_device_ips.append(device_ip)
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

        if self.config[0].get("update_interface_details"):
            device_to_update = self.get_device_ips_from_config_priority()
            self.update_interface_detail_of_device(
                device_to_update
            ).check_return_status()

        # If User defined field(UDF) not present then create it and add multiple udf to specific or list of devices
        self.log(self.config[0])
        if self.config[0].get("add_user_defined_field"):
            udf_field_list = self.config[0].get("add_user_defined_field")
            self.log("udf_field_list")
            self.log(udf_field_list)
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
                self.log(udf_exist)
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

                if not device_ids:
                    self.status = "failed"
                    self.msg = """Unable to assign Global User Defined Field: No devices found in Cisco Catalyst Center.
                        Please add devices to proceed."""
                    self.result["changed"] = False
                    self.result["response"] = self.msg
                    self.log(self.msg, "INFO")
                    return self

                # Now add code for adding Global UDF to device with Id
                self.add_field_to_devices(device_ids, udf).check_return_status()

                self.result["changed"] = True
                self.msg = "Global User Defined Field(UDF) named '{0}' has been successfully added to the device.".format(
                    field_name
                )
                self.udf_added.append(field_name)
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

        devices_maintenance = self.config[0].get("devices_maintenance_schedule")
        if not devices_maintenance:
            self.log("No device maintenance schedule provided in the playbook.", "INFO")
            return self

        if self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") < 0:
            self.log(
                "Creating/Updating the device maintenance schedule starts from '2.3.7.9' onwards. Please upgrade "
                "the Cisco Catalyst Center to '2.3.7.9' in order to leverage the device maintenance schedule feature.",
                "WARNING",
            )
            return self

        self.log(
            "Proceeding with the device maintenance scheduling process...", "DEBUG"
        )
        updated_network_ids = []
        for maintenance_config in devices_maintenance:
            network_device_ips = maintenance_config.get("device_ips")
            if not network_device_ips:
                self.msg = (
                    "Required parameter 'device_ips' must be provided in the playbook in order to create/update schedule "
                    "maintenance for network devices."
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            if not maintenance_config.get("time_zone"):
                self.msg = (
                    "Required parameter 'time_zone' must be provided in the playbook in order to create/update schedule "
                    "maintenance for network devices."
                )
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            network_device_ids = self.get_device_ids(network_device_ips)
            device_ip_id_map = self.get_device_ips_from_device_ids(network_device_ids)
            # Find out the devices for which maintenance already schedule and not schedule yet
            schedule_device_ids, unscheduled_device_ids = (
                self.get_schedule_and_unscheduled_device_ids(
                    network_device_ids, device_ip_id_map
                )
            )

            if unscheduled_device_ids:
                device_ips = []
                for device_id in unscheduled_device_ids:
                    ip = device_ip_id_map[device_id]
                    device_ips.append(ip)

                self.log(
                    "Start scheduling the maintenance schedule for the device(s): {0}".format(
                        device_ips
                    ),
                    "INFO",
                )
                self.validate_device_maintenance_params(maintenance_config)
                maintenance_payload = self.create_schedule_maintenance_payload(
                    maintenance_config, unscheduled_device_ids, device_ips
                )
                self.schedule_maintenance_for_devices(
                    maintenance_payload, device_ips
                ).check_return_status()
                self.log(
                    "Maintenance schedule successfully for the device(s): {0}.".format(
                        device_ips
                    ),
                    "INFO",
                )
                self.maintenance_scheduled.extend(device_ips)

            if schedule_device_ids:
                for device_id in schedule_device_ids:
                    device_ip = device_ip_id_map[device_id]
                    schedule_details = self.get_device_maintenance_details(
                        device_id, device_ip
                    )
                    if not schedule_details:
                        self.log(
                            "No schedule maintenance details found for the device {0}".format(
                                device_ip
                            ),
                            "WARNING",
                        )
                        continue

                    status = schedule_details.get("maintenanceSchedule").get("status")
                    if status not in ["UPCOMING", "IN_PROGRESS"]:
                        self.msg = (
                            "Device maintenance schedule status is neither 'UPCOMING' nor 'IN_PROGRESS' "
                            "so unable to update the maintenance schedule for the given device: {0}".format(
                                device_ip
                            )
                        )
                        self.log(self.msg, "ERROR")
                        self.fail_and_exit(self.msg)

                    self.log(
                        "Check whether device maintenance needs update or not for the device: {0}".format(
                            device_ip
                        ),
                        "DEBUG",
                    )
                    is_need_update = self.device_maintenance_needs_update(
                        maintenance_config, schedule_details, device_ip
                    )
                    if is_need_update:
                        status = schedule_details.get("maintenanceSchedule").get(
                            "status"
                        )
                        if status == "IN_PROGRESS":
                            self.log(
                                "Since the schedule maintenance for the device {0} was going on, the user needs to exit the "
                                "maintenance window by setting the `endTime` to -1.".format(
                                    device_ip
                                ),
                                "INFO",
                            )
                            self.exit_maintenance_window(
                                schedule_details
                            ).check_return_status()
                            self.log(
                                "Exit the maintenance schedule window successfully...",
                                "INFO",
                            )

                        self.log(
                            "Checking for the change in the maintenance schedule from recurring to once or vice versa..",
                            "DEBUG",
                        )
                        is_schedule_type_change = self.is_recurrence_type_changed(
                            maintenance_config, schedule_details
                        )
                        if is_schedule_type_change or status == "IN_PROGRESS":
                            self.log(
                                "Maintenance schedule type has been changed so need to delete the current schedule "
                                "and create the new device maintenance schedule.",
                                "INFO",
                            )
                            device_ids = schedule_details.get("networkDeviceIds")
                            ips_list = []
                            for device_id in device_ids:
                                ip = device_ip_id_map[device_id]
                                ips_list.append(ip)

                            schedule_id = schedule_details.get("id")
                            self.delete_maintenance_schedule(
                                schedule_id
                            ).check_return_status()
                            self.log(
                                "Maintenance schedule deleted successfully and now we have to create the new one...",
                                "INFO",
                            )

                            create_schedule_payload = (
                                self.get_update_payload_for_maintenance(
                                    maintenance_config, schedule_details, device_ip
                                )
                            )
                            self.schedule_maintenance_for_devices(
                                create_schedule_payload, ips_list
                            ).check_return_status()
                            self.log(
                                "Maintenance scheduled successfully for the device(s): {0}.".format(
                                    ips_list
                                ),
                                "INFO",
                            )

                            self.maintenance_scheduled.extend(ips_list)
                            self.maintenance_scheduled = list(
                                set(self.maintenance_scheduled)
                            )
                        else:
                            update_schedule_payload = (
                                self.get_update_payload_for_maintenance(
                                    maintenance_config, schedule_details, device_ip
                                )
                            )
                            self.update_schedule_maintenance(
                                update_schedule_payload, device_ip
                            ).check_return_status()
                            self.log(
                                "Maintenance schedule updated successfully for the device: {0}.".format(
                                    device_ip
                                ),
                                "INFO",
                            )
                            updated_network_ids.extend(
                                schedule_details.get("networkDeviceIds")
                            )
                    else:
                        self.log(
                            "There is no update required for the given schedule maintenance of device {0}.".format(
                                device_ip
                            ),
                            "INFO",
                        )
                        self.no_update_in_maintenance.append(device_ip)

                if updated_network_ids:
                    updated_network_ids = list(set(updated_network_ids))
                    for device_id in updated_network_ids:
                        device_ip = device_ip_id_map.get(device_id)
                        self.log(
                            "Maintenance schedule updated successfully for the device: {0}.".format(
                                device_ip
                            ),
                            "INFO",
                        )
                        self.maintenance_updated.append(device_ip)
                        if device_ip in self.no_update_in_maintenance:
                            self.log(
                                "Remove the device ip {0} from no schedule maintenance updates list".format(
                                    device_ip
                                ),
                                "INFO",
                            )
                            self.no_update_in_maintenance.remove(device_ip)

            if self.maintenance_scheduled and self.no_update_in_maintenance:
                for device_ip in self.no_update_in_maintenance:
                    self.log(
                        "Remove the device ip {0} from no schedule maintenance creation list".format(
                            device_ip
                        ),
                        "INFO",
                    )
                    self.no_update_in_maintenance.remove(device_ip)

        return self

    def get_diff_deleted(self, config):
        """
        Main function to delete devices in Cisco Catalyst Center based on device IP address.
        Parameters:
            config (dict): The configuration settings for the deletion process.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method compares the provided configuration against the current
            devices in the Cisco Catalyst Center and deletes devices based on
            their IP addresses. It returns a success status indicating whether
            the deletion process was completed successfully.
        """

        device_to_delete = self.get_device_ips_from_config_priority()

        # Handle Global User Defined Fields (UDF) Deletion
        if self.config[0].get("add_user_defined_field"):
            return self.delete_user_defined_fields()

        # Loop over devices to delete them
        latest_testbed = (
            self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0
        )
        for device_ip in device_to_delete:
            if device_ip not in self.have.get("device_in_ccc"):
                self.status = "success"
                self.result["changed"] = False
                self.msg = "Device '{0}' is not present in Cisco Catalyst Center so can't perform delete operation".format(
                    device_ip
                )
                self.no_device_to_delete.append(device_ip)
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")
                continue
            device_ids = self.get_device_ids([device_ip])
            device_id = device_ids[0]

            if latest_testbed:
                self.delete_device_with_or_without_cleanup_config(
                    device_ip, device_id
                ).check_return_status()
                self.deleted_devices.append(device_ip)
                continue

            is_device_provisioned = self.is_device_provisioned(device_id, device_ip)
            if not is_device_provisioned:
                self.handle_device_deletion(device_ip)
                continue

            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
                self.delete_provisioned_device_v1(device_ip)
                continue
            else:
                self.delete_provisioned_device_v2(device_ip)
                continue

        devices_maintenance = self.config[0].get("devices_maintenance_schedule")
        if (
            devices_maintenance
            and self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") >= 0
        ):
            schedule_ids = []
            for schedule in devices_maintenance:
                device_ips = schedule.get("device_ips")
                if not device_ips:
                    self.msg = (
                        "Unable to delete schedule maintenance for the devices as required parameter 'device_ips' is not given "
                        "in the playbook"
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                for device_ip in device_ips:
                    network_device_id = self.get_device_ids([device_ip])
                    if not network_device_id:
                        self.log(
                            "No network device with IP '{0}' present in Cisco Catalyst Center."
                            .format(device_ip), "WARNING"
                        )
                        continue

                    schedule_details = self.get_device_maintenance_details(
                        network_device_id[0], device_ip
                    )
                    if not schedule_details:
                        self.log(
                            "No schedule maintenance details found for the device {0}".format(
                                device_ip
                            ),
                            "WARNING",
                        )
                        self.no_maintenance_schedule.append(device_ip)
                        continue

                    for schedule in schedule_details:
                        schedule_id = schedule.get("id")
                        if not schedule_id:
                            self.log(
                                "No schedule ID found for the device {0}.".format(device_ip),
                                "INFO",
                            )
                            continue
                        schedule_ids.append(schedule_id)
                        self.log(
                            "Appended schedule ID '{0}' for device '{1}'.".format(schedule_id, device_ip),
                            "DEBUG"
                        )
                    self.maintenance_deleted.append(device_ip)
                    self.log(
                        "Device '{0}' added to maintenance deleted list.".format(device_ip),
                        "INFO"
                    )

            schedule_ids = list(set(schedule_ids))
            for schedule_id in schedule_ids:
                self.delete_maintenance_schedule(schedule_id).check_return_status()
                self.log(
                    "Maintenance schedule deleted successfully and now we have to create the new one...",
                    "INFO",
                )
        elif (
            devices_maintenance
            and self.compare_dnac_versions(self.get_ccc_version(), "2.3.7.9") < 0
        ):
            self.log(
                "Deleting the device maintenance schedule starts from '2.3.7.9' onwards. Please upgrade "
                "the Cisco Catalyst Center to '2.3.7.9' in order to leverage the device maintenance schedule"
                " deletion feature.",
                "WARNING",
            )

        return self

    def delete_user_defined_fields(self):
        """
        Deletes User Defined Fields (UDF) in Cisco Catalyst Center.
        Returns:
            self (object): An instance of the class after the deleting UFD operation is performed.
        Description:
            This method removes user-defined fields from the Cisco Catalyst Center.
            It ensures that any custom fields that are no longer needed are
            deleted to maintain a clean and organized configuration.
        """

        udf_field_list = self.config[0].get("add_user_defined_field")
        for udf in udf_field_list:
            field_name = udf.get("name")
            udf_id = self.get_udf_id(field_name)

            if udf_id is None:
                self.status = "success"
                self.msg = (
                    "Global UDF '{0}' is not present in Cisco Catalyst Center".format(
                        field_name
                    )
                )
                self.log(self.msg, "INFO")
                self.result["changed"] = False
                self.result["msg"] = self.msg
                continue

            try:
                # Execute API call to delete UDF
                response = self.dnac._exec(
                    family="devices",
                    function="delete_user_defined_field",
                    op_modifies=True,
                    params={"id": udf_id},
                )
                self.log(
                    "Received API response from 'delete_user_defined_field': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )

                # Check for task ID in the response and monitor its progress
                if response and isinstance(response, dict):
                    task_id = response.get("response", {}).get("taskId")

                    while True:
                        execution_details = self.get_task_details(task_id)

                        # If the task is successful, update status and log the result
                        if "success" in execution_details.get("progress"):
                            self.status = "success"
                            self.msg = "Global UDF '{0}' deleted successfully from Cisco Catalyst Center".format(
                                field_name
                            )
                            self.udf_deleted.append(field_name)
                            self.log(self.msg, "INFO")
                            self.result["changed"] = True
                            self.result["response"] = execution_details
                            break
                        # If there's an error, log and handle it
                        elif execution_details.get("isError"):
                            self.status = "failed"
                            failure_reason = execution_details.get("failureReason")
                            if failure_reason:
                                self.msg = "Failed to delete Global User Defined Field (UDF) '{0}' due to: {1}".format(
                                    field_name, failure_reason
                                )
                            else:
                                self.msg = "Global UDF '{0}' deletion failed.".format(
                                    field_name
                                )
                            self.log(self.msg, "ERROR")
                            self.result["response"] = self.msg
                            break

            except Exception as e:
                error_message = "Error while deleting Global UDF '{0}' from Cisco Catalyst Center: {1}".format(
                    field_name, str(e)
                )
                self.log(error_message, "ERROR")
                raise Exception(error_message)

        return self

    def delete_provisioned_device_v1(self, device_ip):
        """
        Deletes provisioned devices for versions <= 2.3.5.3.

        Parameters:
            device_ip (str): The IP address of the device to be deleted.

        Description:
            This method deletes a provisioned device with the specified IP address
            for software versions 2.3.5.3 or earlier. It performs the necessary
            validations and API calls to ensure the device is removed from the
            Cisco Catalyst Center.
        """
        try:
            provision_params = {"device_management_ip_address": device_ip}
            response = self.dnac._exec(
                family="sda",
                function="delete_provisioned_wired_device",
                op_modifies=True,
                params=provision_params,
            )
            if response:
                response = {"response": response}
                self.log(
                    "Received API response from 'delete_provisioned_wired_device': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                validation_string = "deleted successfully"
                self.check_task_response_status(
                    response, validation_string, "delete_provisioned_wired_device"
                )
                self.provisioned_device_deleted.append(device_ip)

        except Exception as e:
            self.status = "failed"
            self.msg = "Failed to delete the provisioned device - ({0}) from Cisco Catalyst Center due to - {1}".format(
                device_ip, str(e)
            )
            self.result["response"] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def delete_provisioned_device_v2(self, device_ip):
        """
        Deletes provisioned devices for versions > 2.3.5.3.

        Parameters:
            device_ip (str): The IP address of the device to be deleted.

        Description:
            This method deletes a provisioned device with the specified IP address
            for software versions greater than 2.3.5.3. It ensures that the device
            is properly removed from the Cisco Catalyst Center, handling any
            required validations and API interactions.
        """
        try:
            device_ids = self.get_device_ids([device_ip])
            device_id = device_ids[0]
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
                self.provisioned_device_deleted.append(device_ip)

        except Exception as e:
            self.status = "failed"
            self.msg = "Failed to delete the provisioned device - ({0}) from Cisco Catalyst Center due to - {1}".format(
                device_ip, str(e)
            )
            self.result["response"] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def handle_device_deletion(self, device_ip):
        """
        Handles exceptions that occur during the deletion of a device.

        Parameters:
            device_ip (str): The IP address of the device that is being deleted.
            e (Exception): The exception that was raised during the deletion process.
        Returns:
            None
        Description:
            This method logs an error message related to the exception that occurred
            during the deletion of the specified device. It captures relevant details
            of the exception to aid in troubleshooting and ensures proper logging of
            the error scenario.
        """
        try:
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

            self.log(
                "Received API response from 'deleted_device_by_id': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            if self.compare_dnac_versions(self.get_ccc_version(), "2.3.5.3") <= 0:
                validation_string = "network device deleted successfully"
                self.check_task_response_status(
                    response, validation_string, "deleted_device_by_id"
                )
                self.deleted_devices.append(device_ip)
            else:
                self.check_tasks_response_status(
                    response, api_name="deleted_device_by_id"
                )
                if self.status not in ["failed", "exited"]:
                    self.deleted_devices.append(device_ip)

        except Exception as e:
            self.status = "failed"
            self.msg = "Failed to delete the device - ({0}) from Cisco Catalyst Center due to - {1}".format(
                device_ip, str(e)
            )
            self.result["response"] = self.msg
            self.log(self.msg, "ERROR")
            self.check_return_status()

    def delete_device_with_or_without_cleanup_config(self, device_ip, device_id):
        """
        Deletes a network device from the Cisco Catalyst Center, with or without configuration cleanup.

        Args:
            device_ip (str): IP address of the device to be deleted.
            device_id (str): Unique identifier of the device in the Cisco Catalyst Center.

        Returns:
            self: Returns the current instance after performing the delete operation.

        Description:
            This function determines whether to perform a configuration cleanup before deleting the
            device, based on the `clean_config` parameter in the configuration. It then triggers
            the appropriate API call to delete the device and monitors the task status.
        """

        try:
            clean_up = self.config[0].get("clean_config", False)
            if clean_up:
                task_name = "delete_network_device_with_configuration_cleanup"
            else:
                task_name = "delete_a_network_device_without_configuration_cleanup"

            delete_param = {"id": device_id}
            task_id = self.get_taskid_post_api_call("devices", task_name, delete_param)
            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Device '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                device_ip
            )
            self.log(
                "Task ID '{0}' received. Checking task status.".format(task_id), "DEBUG"
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.log(
                "Completed the process to deleting the device {0}.".format(device_ip),
                "INFO",
            )

        except Exception as e:
            self.msg = "Failed to delete the device - ({0}) from Cisco Catalyst Center due to - {1}".format(
                device_ip, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

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
        self.log("verify starts here verify diff merged")
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        devices_to_add = self.have["device_not_in_ccc"]
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
                self.config[0].get("update_interface_details").get("interface_name")
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

        devices_maintenance = self.config[0].get("devices_maintenance_schedule")
        if devices_maintenance:
            for schedule in devices_maintenance:
                device_ips = schedule.get("device_ips")
                network_device_ids = self.get_device_ids(device_ips)
                schedule_details = self.get_device_maintenance_details(
                    network_device_ids[0], device_ips[0]
                )
                if schedule_details:
                    self.log(
                        "Requested maintenance schedule for the device(s) '{0}' created/updated from Cisco Catalyst "
                        "Center and the deletion has been verified.".format(device_ips),
                        "INFO",
                    )
                else:
                    self.log(
                        "Mismatch between playbook parameter for creating/updating the maintenance schedule for"
                        "  the device(s) {0}, indicating that the maintenance schedule creation/updation task may "
                        "not have executed successfully.".format(device_ips),
                        "WARNING",
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
            if device_ip in self.have.get("device_in_ccc"):
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

        devices_maintenance = self.config[0].get("devices_maintenance_schedule")
        if devices_maintenance:
            for schedule in devices_maintenance:
                device_ips = schedule.get("device_ips")
                network_device_ids = self.get_device_ids(device_ips)
                schedule_details = self.get_device_maintenance_details(
                    network_device_ids[0], device_ips[0]
                )
                if not schedule_details:
                    self.log(
                        "Requested maintenance schedule for the device(s) '{0}' deleted from Cisco Catalyst Center "
                        " and the deletion has been verified.".format(device_ips),
                        "INFO",
                    )
                else:
                    self.log(
                        "Mismatch between playbook parameter for deleting the maintenance schedule for the device(s) {0}"
                        ", indicating that the maintenance schedule deletion task may not have executed successfully.".format(
                            device_ips
                        ),
                        "WARNING",
                    )

        return self

    def update_inventory_profile_messages(self):
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
        result_msg_list_not_changed = []
        result_msg_list_changed = []

        if self.provisioned_device:
            provisioned_device = "device(s) '{0}' provisioned successfully in Cisco Catalyst Center.".format(
                "', '".join(self.provisioned_device)
            )
            result_msg_list_changed.append(provisioned_device)

        if self.device_already_provisioned:
            self.log(self.device_already_provisioned)
            device_already_provisioned = (
                "device(s) '{0}' already provisioned in Cisco Catalyst Center.".format(
                    "', '".join(self.device_already_provisioned)
                )
            )
            result_msg_list_not_changed.append(device_already_provisioned)

        if self.device_list:
            flat_devices = []
            for sublist in self.device_list:
                for ip in sublist:
                    flat_devices.append(ip)
            device_lists_message = (
                "device(s) '{0}' added successfully in Cisco Catalyst Center.".format(
                    "', '".join(flat_devices)
                )
            )
            result_msg_list_changed.append(device_lists_message)

        if self.devices_already_present:
            self.log(self.devices_already_present)
            flat_devices = []
            for sublist in self.devices_already_present:
                for ip in sublist:
                    flat_devices.append(ip)
            devices_already_present = (
                "device(s) '{0}' already present in Cisco Catalyst Center.".format(
                    "', '".join(flat_devices)
                )
            )
            result_msg_list_not_changed.append(devices_already_present)

        if self.provisioned_device_deleted:
            provisioned_device_deleted = (
                "provisioned device(s) '{0}' successfully deleted in Cisco Catalyst"
                " Center."
            ).format("', '".join(self.provisioned_device_deleted))
            result_msg_list_changed.append(provisioned_device_deleted)

        if self.deleted_devices:
            deleted_devices = (
                "device(s) '{0}' successfully deleted in Cisco Catalyst Center".format(
                    "', '".join(self.deleted_devices)
                )
            )
            result_msg_list_changed.append(deleted_devices)

        if self.no_device_to_delete:
            deleted_devices = (
                "device(s) '{0}' is not present in Cisco Catalyst Center so can't perform delete"
                " operation"
            ).format("', '".join(self.no_device_to_delete))
            result_msg_list_not_changed.append(deleted_devices)

        if self.cred_updated_not_required:
            cred_updated_not_required = (
                "device(s) '{0}' doesn't need any update for credintials" " operation"
            ).format("', '".join(self.cred_updated_not_required))
            result_msg_list_not_changed.append(cred_updated_not_required)

        if self.device_already_present:
            device_already_present = (
                "device(s) '{0}' already present in the cisco catalyst" " center"
            ).format("', '".join(self.device_already_present))
            result_msg_list_not_changed.append(device_already_present)

        if self.device_not_exist:
            devices = ", ".join(map(str, self.device_not_exist))
            device_not_exist = (
                "Unable to reboot device because the device(s) listed: {0} are not present in the"
                " Cisco Catalyst Center."
            ).format(str(devices))
            result_msg_list_not_changed.append(device_not_exist)

        if self.device_not_exist_to_resync:
            devices = ", ".join(map(str, self.device_not_exist_to_resync))
            device_not_exist = (
                "Unable to resync device because the device(s) listed: {0} are not present in the Cisco Catalyst Center."
            ).format(str(devices))
            result_msg_list_not_changed.append(device_not_exist)

        if self.device_role_ip_already_updated:
            devices = ", ".join(map(str, self.device_role_ip_already_updated))
            device_role_ip_already_updated = (
                "Unable to update the device role because the device(s) listed: {0} are already with"
                " the desiered device role."
            ).format(str(devices))
            result_msg_list_not_changed.append(device_role_ip_already_updated)

        if self.response_list:
            response_list_for_update = "{0}".format(", ".join(self.response_list))
            result_msg_list_changed.append(response_list_for_update)

        if self.role_updated_list:
            role_updated_list = (
                "Device(s) '{0}' role updated successfully to '{1}'".format(
                    self.role_updated_list, self.device_role_name
                )
            )
            result_msg_list_changed.append(role_updated_list)

        if self.udf_added:
            udf_added = "Global User Defined Field(UDF) named '{0}' has been successfully added to the device.".format(
                "', '".join(self.udf_added)
            )
            result_msg_list_changed.append(udf_added)

        if self.ap_rebooted_successfully:
            ap_rebooted_successfully = "AP Device(s) {0} successfully rebooted!".format(
                "', '".join(self.ap_rebooted_successfully)
            )
            result_msg_list_changed.append(ap_rebooted_successfully)

        if self.udf_deleted:
            udf_deleted = "Global User Defined Field(UDF) named '{0}' has been successfully deleted to the device.".format(
                "', '".join(self.udf_deleted)
            )
            result_msg_list_changed.append(udf_deleted)

        if self.updated_ip:
            ip_address_for_update = "', '".join(self.ip_address_for_update)
            updated_ip = "', '".join(self.updated_ip)
            updated_ip_msg = (
                "Device '{0}' found in Cisco Catalyst Center. The new management IP '{1}' has"
                "been updated successfully."
            ).format(ip_address_for_update, updated_ip)
            result_msg_list_changed.append(updated_ip_msg)

        if self.output_file_name:
            output_file_name = (
                "Device Details Exported Successfully to the CSV file: {0}".format(
                    "', '".join(self.output_file_name)
                )
            )
            result_msg_list_changed.append(output_file_name)

        if self.update_device_ips:
            updated_ips = "Device(s) '{0}' present in Cisco Catalyst Center and have been updated successfully.".format(
                str(self.update_device_ips)
            )
            result_msg_list_changed.append(updated_ips)

        if self.resync_successful_devices:
            devices = ", ".join(map(str, self.resync_successful_devices))
            resync_successful_devices = "Device(s) '{0}' have been successfully resynced in the inventory in Cisco Catalyst Center.".format(
                str(devices)
            )
            result_msg_list_changed.append(resync_successful_devices)

        if self.maintenance_scheduled:
            scheduled_msg = "Device maintenance scheduled successfully for the devices {0} in Cisco Catalyst Center.".format(
                self.maintenance_scheduled
            )
            result_msg_list_changed.append(scheduled_msg)

        if self.maintenance_updated:
            schedule_update_msg = "Device maintenance scheduled updated successfully for the devices: {0}.".format(
                self.maintenance_updated
            )
            result_msg_list_changed.append(schedule_update_msg)

        if self.no_update_in_maintenance:
            no_update_msg = "Maintenance schedule not required any update for the devices {0} in Cisco Catalyst Center.".format(
                self.no_update_in_maintenance
            )
            result_msg_list_not_changed.append(no_update_msg)

        if self.maintenance_deleted:
            self.maintenance_deleted = list(set(self.maintenance_deleted))
            del_scheduled_msg = "Maintenance schedule deleted successfully for the devices {0} in Cisco Catalyst Center.".format(
                self.maintenance_deleted
            )
            result_msg_list_changed.append(del_scheduled_msg)

        if self.no_maintenance_schedule:
            self.no_maintenance_schedule = list(set(self.no_maintenance_schedule))
            absent_scheduled_msg = "Maintenance schedule for the devices {0} not present in the Catalyst Center.".format(
                self.no_maintenance_schedule
            )
            result_msg_list_not_changed.append(absent_scheduled_msg)

        if result_msg_list_not_changed and result_msg_list_changed:
            self.result["changed"] = True
            self.msg = "{0}, {1}".format(
                " ".join(result_msg_list_not_changed), " ".join(result_msg_list_changed)
            )
        elif result_msg_list_not_changed:
            self.msg = " ".join(result_msg_list_not_changed)
        elif result_msg_list_changed:
            self.result["changed"] = True
            self.msg = " ".join(result_msg_list_changed)
        else:
            self.msg = "No changes were made. No inventory actions were performed in Cisco Catalyst Center."

        self.log(self.msg, "INFO")

        self.result["msg"] = self.msg
        self.result["response"] = self.msg

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

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    ccc_device = Inventory(module)
    state = ccc_device.params.get("state")

    if ccc_device.compare_dnac_versions(ccc_device.get_ccc_version(), "2.3.5.3") < 0:
        ccc_device.msg = (
            "The specified version '{0}' does not support the inventory workflow feature. "
            "Supported versions start from '2.3.5.3' onwards.".format(
                ccc_device.get_ccc_version()
            )
        )
        ccc_device.status = "failed"
        ccc_device.check_return_status()

    if state not in ccc_device.supported_states:
        ccc_device.status = "invalid"
        ccc_device.msg = "State {0} is invalid".format(state)
        ccc_device.check_return_status()

    ccc_device.validate_input().check_return_status()
    config_verify = ccc_device.params.get("config_verify")

    for config in ccc_device.validated_config:
        ccc_device.reset_values()
        ccc_device.get_want(config).check_return_status()
        ccc_device.get_have(config).check_return_status()
        ccc_device.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_device.verify_diff_state_apply[state](config).check_return_status()

    ccc_device.update_inventory_profile_messages().check_return_status()

    module.exit_json(**ccc_device.result)


if __name__ == "__main__":
    main()
