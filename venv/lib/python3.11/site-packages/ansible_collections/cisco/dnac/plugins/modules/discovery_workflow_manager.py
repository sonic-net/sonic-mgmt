#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Abinash Mishra, Phan Nguyen, Madhan Sankaranarayanan"
DOCUMENTATION = r"""
---
module: discovery_workflow_manager
short_description: A resource module for handling device
  discovery tasks.
description:
  - Manages device discovery using IP address, address
    range, CDP, and LLDP, including deletion of discovered
    devices.
  - API to discover a device or multiple devices
  - API to delete a discovery of a device or multiple
    devices
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Abinash Mishra (@abimishr) Phan Nguyen (@phannguy)
  Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
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
      discovery_name:
        description: Name of the discovery task
        type: str
        required: true
      discovery_type:
        description: Determines the method of device
          discovery. Here are the available options.
          - SINGLE discovers a single device using a
          single IP address. - RANGE discovers multiple
          devices within a single IP address range.
          - MULTI RANGE discovers devices across multiple
          IP address ranges. - CDP  uses Cisco Discovery
          Protocol to discover devices in subsequent
          layers of the given IP address. - LLDP uses
          Link Layer Discovery Protocol to discover
          devices in subsequent layers of the specified
          IP address. - CIDR discovers devices based
          on subnet filtering using Classless Inter-Domain
          Routing.
        type: str
        required: true
        choices: ['SINGLE', 'RANGE', 'MULTI RANGE',
          'CDP', 'LLDP', 'CIDR']
      ip_address_list:
        description: List of IP addresses to be discovered.
          For CDP/LLDP/SINGLE based discovery, we should
          pass a list with single element like - 10.197.156.22.
          For CIDR based discovery, we should pass a
          list with single element like - 10.197.156.22/22.
          For RANGE based discovery, we should pass
          a list with single element and range like
          - 10.197.156.1-10.197.156.100. For MULTI RANGE
          based discovery, we should pass a list with
          multiple elements like - 10.197.156.1-10.197.156.100
          and in next line - 10.197.157.1-10.197.157.100.
          Maximum of 8 IP address ranges are allowed.
        type: list
        elements: str
        required: true
      ip_filter_list:
        description: List of IP adddrsess that needs
          to get filtered out from the IP addresses
          passed.
        type: list
        elements: str
      cdp_level:
        description: Total number of levels that are
          there in cdp's method of discovery
        type: int
        default: 16
      lldp_level:
        description: Total number of levels that are
          there in lldp's method of discovery
        type: int
        default: 16
      preferred_mgmt_ip_method:
        description: Preferred method for the management
          of the IP (None/UseLoopBack)
        type: str
        default: None
      use_global_credentials:
        description:
          - Determines if device discovery should utilize
            pre-configured global credentials.
          - Setting to True employs the predefined global
            credentials for discovery tasks. This is
            the default setting.
          - Setting to False requires manually provided,
            device-specific credentials for discovery,
            as global credentials will be bypassed.
        type: bool
        default: true
      discovery_specific_credentials:
        description: Credentials specifically created
          by the user for performing device discovery.
        type: dict
        suboptions:
          cli_credentials_list:
            description: List of CLI credentials to
              be used during device discovery.
            type: list
            elements: dict
            suboptions:
              username:
                description: Username for CLI authentication,
                  mandatory when using CLI credentials.
                type: str
              password:
                description: Password for CLI authentication,
                  mandatory when using CLI credential.
                type: str
              enable_password:
                description: Enable password for CLI
                  authentication, mandatory when using
                  CLI credential.
                type: str
          http_read_credential:
            description: HTTP read credential is used
              for authentication purposes and specifically
              utilized to grant read-only access to
              certain resources from the device.
            type: dict
            suboptions:
              username:
                description: Username for HTTP(S) Read
                  authentication, mandatory when using
                  HTTP credentials.
                type: str
              password:
                description: Password for HTTP(S) Read
                  authentication, mandatory when using
                  HTTP credentials.
                type: str
              port:
                description: Port for HTTP(S) Read authentication,
                  mandatory for using HTTP credentials.
                type: int
              secure:
                description: Flag for HTTP(S) Read authentication,
                  not mandatory when using HTTP credentials.
                type: bool
          http_write_credential:
            description: HTTP write credential is used
              for authentication purposes and grants
              Cisco Catalyst Center the ability to alter
              configurations, update software, or perform
              other modifications on a network device.
            type: dict
            suboptions:
              username:
                description: Username for HTTP(S) Write
                  authentication, mandatory when using
                  HTTP credentials.
                type: str
              password:
                description: Password for HTTP(S) Write
                  authentication, mandatory when using
                  HTTP credentials.
                type: str
              port:
                description: Port for HTTP(S) Write
                  authentication, mandatory when using
                  HTTP credentials.
                type: int
              secure:
                description: Flag for HTTP(S) Write
                  authentication, not mandatory when
                  using HTTP credentials.
                type: bool
          snmp_v2_read_credential:
            description:
              - The SNMP v2 credentials to be created
                and used for contacting a device via
                SNMP protocol in read mode.
              - SNMP v2 also delivers data encryptions,
                but it uses data types.
            type: dict
            suboptions:
              description:
                description: Name/Description of the
                  SNMP read credential to be used for
                  creation of snmp_v2_read_credential.
                type: str
              community:
                description: SNMP V2 Read community
                  string enables Cisco Catalyst Center
                  to extract read-only data from device.
                type: str
          snmp_v2_write_credential:
            description:
              - The SNMP v2 credentials to be created
                and used for contacting a device via
                SNMP protocol in read and write mode.
              - SNMP v2 also delivers data encryptions,
                but it uses data types.
            type: dict
            suboptions:
              description:
                description: Name/Description of the
                  SNMP write credential to be used for
                  creation of snmp_v2_write_credential.
                type: str
              community:
                description: SNMP V2 Write community
                  string is used to extract data and
                  alter device configurations.
                type: str
          snmp_v3_credential:
            description:
              - The SNMP v3 credentials to be created
                and used for contacting a device via
                SNMP protocol in read and write mode.
              - SNMPv3 is the most secure version of
                SNMP, allowing users to fully encrypt
                transmissions, keeping us safe from
                external attackers.
            type: dict
            suboptions:
              username:
                description: Username of the SNMP v3
                  protocol to be used.
                type: str
              snmp_mode:
                description:
                  - Mode of SNMP which determines the
                    encryption level of our community
                    string.
                  - AUTHPRIV mode uses both Authentication
                    and Encryption.
                  - AUTHNOPRIV mode uses Authentication
                    but no Encryption.
                  - NOAUTHNOPRIV mode does not use either
                    Authentication or Encryption.
                type: str
                choices: ['AUTHPRIV', 'AUTHNOPRIV',
                  'NOAUTHNOPRIV']
              auth_password:
                description:
                  - Authentication Password of the SNMP
                    v3 protocol to be used.
                  - Must be of length greater than 7
                    characters.
                  - Not required for NOAUTHNOPRIV snmp_mode.
                type: str
              auth_type:
                description:
                  - Authentication type of the SNMP
                    v3 protocol to be used.
                  - SHA uses Secure Hash Algorithm (SHA)
                    as your authentication protocol.
                  - MD5 uses Message Digest 5 (MD5)
                    as your authentication protocol
                    and is not recommended.
                  - Not required for NOAUTHNOPRIV snmp_mode.
                type: str
                choices: ['SHA', 'MD5']
              privacy_type:
                description:
                  - Privacy type/protocol of the SNMP
                    v3 protocol to be used in AUTHPRIV
                    SNMP mode
                  - Not required for AUTHNOPRIV and
                    NOAUTHNOPRIV snmp_mode.
                type: str
                choices: ['AES128', 'AES192', 'AES256']
              privacy_password:
                description:
                  - Privacy password of the SNMP v3
                    protocol to be used in AUTHPRIV
                    SNMP mode
                  - Not required for AUTHNOPRIV and
                    NOAUTHNOPRIV snmp_mode.
                type: str
          net_conf_port:
            description:
              - To be used when network contains IOS
                XE-based wireless controllers.
              - This is used for discovery and the enabling
                of wireless services on the controllers.
              - Requires valid SSH credentials to work.
              - Avoid standard ports like 22, 80, and
                8080.
            type: str
      global_credentials:
        description:
          - Set of various credential types, including
            CLI, SNMP, HTTP, and NETCONF, that a user
            has pre-configured in the Device Credentials
            section of the Cisco Catalyst Center.
          - If user doesn't pass any global credentials
            in the playbook, then by default, we will
            use all the global credentials present in
            the Cisco Catalyst Center of each type for
            performing discovery. (Max 5 allowed)
        type: dict
        version_added: 6.12.0
        suboptions:
          cli_credentials_list:
            description:
              - Accepts a list of global CLI credentials
                for use in device discovery.
              - It's recommended to create device credentials
                with both a unique username and a clear
                description.
            type: list
            elements: dict
            suboptions:
              username:
                description: Username required for CLI
                  authentication and is mandatory when
                  using global CLI credentials.
                type: str
              description:
                description: Name of the CLI credential,
                  mandatory when using global CLI credentials.
                type: str
          http_read_credential_list:
            description:
              - List of global HTTP Read credentials
                that will be used in the process of
                discovering devices.
              - It's recommended to create device credentials
                with both a unique username and a clear
                description for easy identification.
            type: list
            elements: dict
            suboptions:
              username:
                description: Username for HTTP Read
                  authentication, mandatory when using
                  global HTTP credentials.
                type: str
              description:
                description: Name of the HTTP Read credential,
                  mandatory when using  global HTTP
                  credentials.
                type: str
          http_write_credential_list:
            description:
              - List of global HTTP Write credentials
                that will be used in the process of
                discovering devices.
              - It's recommended to create device credentials
                with both a unique username and a clear
                description for easy identification.
            type: list
            elements: dict
            suboptions:
              username:
                description: Username for HTTP Write
                  authentication, mandatory when using
                  global HTTP credentials.
                type: str
              description:
                description: Name of the HTTP Write
                  credential, mandatory when using  global
                  HTTP credentials.
                type: str
          snmp_v2_read_credential_list:
            description:
              - List of Global SNMP V2 Read credentials
                to be used during device discovery.
              - It's recommended to create device credentials
                with a clear description for easy identification.
            type: list
            elements: dict
            suboptions:
              description:
                description: Name of the SNMP Read credential,
                  mandatory when using  global SNMP
                  credentials.
                type: str
          snmp_v2_write_credential_list:
            description:
              - List of Global SNMP V2 Write credentials
                to be used during device discovery.
              - It's recommended to create device credentials
                with a clear description for easy identification.
            type: list
            elements: dict
            suboptions:
              description:
                description: Name of the SNMP Write
                  credential, mandatory when using global
                  SNMP credentials.
                type: str
          snmp_v3_credential_list:
            description:
              - List of Global SNMP V3 credentials to
                be used during device discovery, giving
                read and write mode.
              - It's recommended to create device credentials
                with both a unique username and a clear
                description for easy identification.
            type: list
            elements: dict
            suboptions:
              username:
                description: Username for SNMP V3 authentication,
                  mandatory when using global SNMP credentials.
                type: str
              description:
                description: Name of the SNMP V3 credential,
                  mandatory when using global SNMP credentials.
                type: str
          net_conf_port_list:
            description:
              - List of Global Net conf ports to be
                used during device discovery.
              - It's recommended to create device credentials
                with unique description.
            type: list
            elements: dict
            suboptions:
              description:
                description: Name of the Net Conf Port
                  credential, mandatory when using global
                  Net conf port.
                type: str
      start_index:
        description: Start index for the header in fetching
          SNMP v2 credentials
        type: int
        default: 1
      records_to_return:
        description: Number of records to return for
          the header in fetching global v2 credentials
        type: int
        default: 100
      protocol_order:
        description: Determines the order in which device
          connections will be attempted. Here are the
          options - "telnet" Only telnet connections
          will be tried. - "ssh, telnet" SSH (Secure
          Shell) will be attempted first, followed by
          telnet if SSH fails.
        type: str
        default: ssh
      retry:
        description: Number of times to try establishing
          connection to device
        type: int
      timeout:
        description: Time to wait for device response
          in seconds
        type: int
      delete_all:
        description: Parameter to delete all the discoveries
          at one go
        type: bool
        default: false
requirements:
  - dnacentersdk == 2.6.10
  - python >= 3.9
notes:
  - SDK Method used are
    discovery.Discovery.get_all_global_credentials,
    discovery.Discovery.start_discovery,
    task.Task.get_task_by_id,
    discovery.Discovery.get_discoveries_by_range,
    discovery.Discovery.get_discovered_network_devices_by_discovery_id',
    discovery.Discovery.delete_discovery_by_id discovery.Discovery.delete_all_discovery
    discovery.Discovery.get_count_of_all_discovery_jobs
  - Paths used are
    get /dna/intent/api/v2/global-credential
    post /dna/intent/api/v1/discovery get /dna/intent/api/v1/task/{taskId}
    get /dna/intent/api/v1/discovery/{startIndex}/{recordsToReturn}
    get /dna/intent/api/v1/discovery/{id}/network-device
    delete /dna/intent/api/v1/discovery/{id} delete
    /dna/intent/api/v1/delete get /dna/intent/api/v1/discovery/count
  - Removed 'global_cli_len' option in v6.12.0.
"""
EXAMPLES = r"""
---
- name: Execute discovery of devices with both global
    credentials and discovery specific credentials
  cisco.dnac.discovery_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config_verify: true
    config:
      - discovery_name: Discovery with both global and
          job specific credentials
        discovery_type: RANGE
        ip_address_list:
          - 201.1.1.1-201.1.1.100
        ip_filter_list:
          - 201.1.1.2
          - 201.1.1.10
        discovery_specific_credentials:
          cli_credentials_list:
            - username: cisco
              password: Cisco123
              enable_password: Cisco123
          http_read_credential:
            username: cisco
            password: Cisco123
            port: 443
            secure: true
          http_write_credential:
            username: cisco
            password: Cisco123
            port: 443
            secure: true
          snmp_v2_read_credential:
            description: snmp_v2-new
            community: Cisco123
          snmp_v2_write_credential:
            description: snmp_v2-new
            community: Cisco123
          snmp_v3_credential:
            username: v3Public2
            snmp_mode: AUTHPRIV
            auth_type: SHA
            auth_password: Lablab123
            privacy_type: AES256
            privacy_password: Lablab123
          net_conf_port: 750
        global_credentials:
          cli_credentials_list:
            - description: ISE
              username: cisco
            - description: CLI1234
              username: cli
          http_read_credential_list:
            - description: HTTP Read
              username: HTTP_Read
          http_write_credential_list:
            - description: HTTP Write
              username: HTTP_Write
          snmp_v3_credential_list:
            - description: snmpV3
              username: snmpV3
          snmp_v2_read_credential_list:
            - description: snmpV2_read
          snmp_v2_write_credential_list:
            - description: snmpV2_write
          net_conf_port_list:
            - description: Old_one
        start_index: 1
        records_to_return: 100
        protocol_order: ssh
        retry: 5
        timeout: 3
- name: Execute discovery of devices with discovery
    specific credentials only
  cisco.dnac.discovery_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config_verify: true
    config:
      - discovery_name: Single with discovery specific
          credentials only
        discovery_type: SINGLE
        ip_address_list:
          - 204.1.1.10
        discovery_specific_credentials:
          cli_credentials_list:
            - username: cisco
              password: Cisco123
              enable_password: Cisco123
          http_read_credential:
            username: cisco
            password: Cisco123
            port: 443
            secure: true
          http_write_credential:
            username: cisco
            password: Cisco123
            port: 443
            secure: true
          snmp_v2_read_credential:
            description: snmp_v2-new
            community: Cisco123
          snmp_v2_write_credential:
            description: snmp_v2-new
            community: Cisco123
          snmp_v3_credential:
            username: v3Public2
            snmp_mode: AUTHPRIV
            auth_type: SHA
            auth_password: Lablab123
            privacy_type: AES256
            privacy_password: Lablab123
          net_conf_port: 750
        use_global_credentials: false
        start_index: 1
        records_to_return: 100
        protocol_order: ssh
        retry: 5
        timeout: 3
- name: Execute discovery of devices with global credentials
    only
  cisco.dnac.discovery_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config_verify: true
    config:
      - discovery_name: CDP with global credentials
          only
        discovery_type: CDP
        ip_address_list:
          - 204.1.1.1
        cdp_level: 16
        global_credentials:
          cli_credentials_list:
            - description: ISE
              username: cisco
            - description: CLI1234
              username: cli
          http_read_credential_list:
            - description: HTTP Read
              username: HTTP_Read
          http_write_credential_list:
            - description: HTTP Write
              username: HTTP_Write
          snmp_v3_credential_list:
            - description: snmpV3
              username: snmpV3
          snmp_v2_read_credential_list:
            - description: snmpV2_read
          snmp_v2_write_credential_list:
            - description: snmpV2_write
          net_conf_port_list:
            - description: Old_one
        start_index: 1
        records_to_return: 100
        protocol_order: ssh
        retry: 5
        timeout: 3
- name: Execute discovery of devices with all the global
    credentials (max 5 allowed)
  cisco.dnac.discovery_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config_verify: true
    config:
      - discovery_name: CIDR with all global credentials
        discovery_type: CIDR
        ip_address_list:
          - 204.1.2.0/24
        ip_filter_list:
          - 204.1.2.10
        preferred_mgmt_ip_method: None
        start_index: 1
        records_to_return: 100
        protocol_order: telnet
        retry: 10
        timeout: 3
        use_global_credentials: true
- name: Delete disovery by name
  cisco.dnac.discovery_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: deleted
    config_verify: true
    config:
      - discovery_name: Single discovery
"""
RETURN = r"""
#Case_1: When the device(s) are discovered successfully.
response_1:
  description: A dictionary with the response returned by the Cisco Catalyst Center Python SDK
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
#Case_2: Given device details or SNMP mode are not provided
response_2:
  description: A list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }
#Case_3: Error while deleting a discovery
response_3:
  description: A string with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": String,
      "msg": String
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
import time
import re


class Discovery(DnacBase):
    def __init__(self, module):
        """
        Initialize an instance of the class. It also initializes an empty
        list for 'creds_ids_list' attribute.

        Parameters:
          - module: The module associated with the class instance.

        Returns:
          The method does not return a value. Instead, it initializes the
          following instance attributes:
          - self.creds_ids_list: An empty list that will be used to store
                                 credentials IDs.
        """

        super().__init__(module)
        self.creds_ids_list = []
        self.supported_states = ["merged", "deleted"]

    def validate_input(self, state=None):
        """
        Validate the fields provided in the playbook.  Checks the
        configuration provided in the playbook against a predefined
        specification to ensure it adheres to the expected structure
        and data types.

        Returns:
          The method returns an instance of the class with updated attributes:
          - self.msg: A message describing the validation result.
          - self.status: The status of the validation (either 'success' or 'failed').
          - self.validated_config: If successful, a validated version of the
                                   'config' parameter.
        Example:
          To use this method, create an instance of the class and call
          'validate_input' on it.If the validation succeeds, 'self.status'
          will be 'success'and 'self.validated_config' will contain the
          validated configuration. If it fails, 'self.status' will be
          'failed', and 'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.msg = "config not available in playbook for validation"
            self.status = "success"
            return self

        discovery_spec = {
            "cdp_level": {"type": "int", "required": False, "default": 16},
            "start_index": {"type": "int", "required": False, "default": 1},
            "records_to_return": {"type": "int", "required": False, "default": 100},
            "discovery_specific_credentials": {"type": "dict", "required": False},
            "ip_filter_list": {"type": "list", "required": False, "elements": "str"},
            "lldp_level": {"type": "int", "required": False, "default": 16},
            "discovery_name": {"type": "str", "required": True},
            "netconf_port": {"type": "str", "required": False},
            "preferred_mgmt_ip_method": {
                "type": "str",
                "required": False,
                "default": "None",
            },
            "retry": {"type": "int", "required": False},
            "timeout": {"type": "str", "required": False},
            "global_credentials": {"type": "dict", "required": False},
            "protocol_order": {"type": "str", "required": False, "default": "ssh"},
            "use_global_credentials": {
                "type": "bool",
                "required": False,
                "default": True,
            },
        }

        if state == "merged":
            discovery_spec["ip_address_list"] = {
                "type": "list",
                "required": True,
                "elements": "str",
            }
            discovery_spec["discovery_type"] = {"type": "str", "required": True}

        elif state == "deleted":
            if self.config[0].get("delete_all") is True:
                self.validated_config = [{"delete_all": True}]
                self.msg = (
                    "Sucessfully collected input for deletion of all the discoveries"
                )
                self.log(self.msg, "WARNING")
                return self

        # Validate discovery params
        valid_discovery, invalid_params = validate_list_of_dicts(
            self.config, discovery_spec
        )
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.log(str(self.msg), "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_discovery
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_discovery)
        )
        self.log(str(self.msg), "INFO")
        self.status = "success"
        return self

    def validate_ip4_address_list(self):
        """
        Validates each ip adress paased in the IP_address_list passed by the user before preprocessing it
        """

        ip_address_list = self.validated_config[0].get("ip_address_list")
        for ip in ip_address_list:
            if "/" in ip:
                ip = ip.split("/")[0]
            if "-" in ip:
                if len(ip.split("-")) == 2:
                    ip1, ip2 = ip.split("-")
                    if self.is_valid_ipv4(ip1) is False:
                        msg = "IP address {0} is not valid".format(ip1)
                        self.log(msg, "CRITICAL")
                        self.module.fail_json(msg=msg)
                    if self.is_valid_ipv4(ip2) is False:
                        msg = "IP address {0} is not valid".format(ip2)
                        self.log(msg, "CRITICAL")
                        self.module.fail_json(msg=msg)
                    ip1_parts = list(map(int, ip1.split(".")))
                    ip2_parts = list(map(int, ip2.split(".")))
                    for part in range(4):
                        if ip1_parts[part] > ip2_parts[part]:
                            msg = "Incorrect range passed: {0}. Please pass correct IP address range".format(
                                ip
                            )
                            self.log(msg, "CRITICAL")
                            self.module.fail_json(msg=msg)
                else:
                    msg = "Provided range '{0}' is incorrect. IP address range should have only upper and lower limit values".format(
                        ip
                    )
                    self.log(msg, "CRITICAL")
                    self.module.fail_json(msg=msg)
            if self.is_valid_ipv4(ip) is False and "-" not in ip:
                msg = "IP address {0} is not valid".format(ip)
                self.log(msg, "CRITICAL")
                self.module.fail_json(msg=msg)
        self.log("All the IP addresses passed are correct", "INFO")

    def get_creds_ids_list(self):
        """
        Retrieve the list of credentials IDs associated with class instance.

        Returns:
          The method returns the list of credentials IDs:
          - self.creds_ids_list: The list of credentials IDs associated with
                                 the class instance.
        """

        self.log(
            "Credential Ids list passed is {0}".format(str(self.creds_ids_list)), "INFO"
        )
        return self.creds_ids_list

    def handle_global_credentials(self, response=None):
        """
        Method to convert values for create_params API when global paramters
        are passed as input.

        Parameters:
            - response: The response collected from the get_all_global_credentials API

        Returns:
            - global_credentials_all  : The dictionary containing list of IDs of various types of
                                    Global credentials.
        """

        global_credentials = self.validated_config[0].get("global_credentials")
        global_credentials_all = {}

        cli_credentials_list = global_credentials.get("cli_credentials_list")
        if cli_credentials_list:
            if not isinstance(cli_credentials_list, list):
                msg = "Global CLI credentials must be passed as a list"
                self.discovery_specific_cred_failure(msg=msg)
            if response.get("cliCredential") is None:
                msg = "Global CLI credentials are not present in the Cisco Catalyst Center"
                self.discovery_specific_cred_failure(msg=msg)
            if len(cli_credentials_list) > 0:
                global_credentials_all["cliCredential"] = []
                cred_len = len(cli_credentials_list)
                if cred_len > 5:
                    cred_len = 5
                for cli_cred in cli_credentials_list:
                    if cli_cred.get("description") and cli_cred.get("username"):
                        for cli in response.get("cliCredential"):
                            if cli.get("description") == cli_cred.get(
                                "description"
                            ) and cli.get("username") == cli_cred.get("username"):
                                global_credentials_all["cliCredential"].append(
                                    cli.get("id")
                                )
                        global_credentials_all["cliCredential"] = (
                            global_credentials_all["cliCredential"][:cred_len]
                        )
                    else:
                        msg = "Kindly ensure you include both the description and the username for the Global CLI credential to discover the devices"
                        self.discovery_specific_cred_failure(msg=msg)

        http_read_credential_list = global_credentials.get("http_read_credential_list")
        if http_read_credential_list:
            if not isinstance(http_read_credential_list, list):
                msg = "Global HTTP read credentials must be passed as a list"
                self.discovery_specific_cred_failure(msg=msg)
            if response.get("httpsRead") is None:
                msg = "Global HTTP read credentials are not present in the Cisco Catalyst Center"
                self.discovery_specific_cred_failure(msg=msg)
            if len(http_read_credential_list) > 0:
                global_credentials_all["httpsRead"] = []
                cred_len = len(http_read_credential_list)
                if cred_len > 5:
                    cred_len = 5
                for http_cred in http_read_credential_list:
                    if http_cred.get("description") and http_cred.get("username"):
                        for http in response.get("httpsRead"):
                            if http.get("description") == http.get(
                                "description"
                            ) and http.get("username") == http.get("username"):
                                global_credentials_all["httpsRead"].append(
                                    http.get("id")
                                )
                        global_credentials_all["httpsRead"] = global_credentials_all[
                            "httpsRead"
                        ][:cred_len]
                    else:
                        msg = "Kindly ensure you include both the description and the username for the Global HTTP Read credential to discover the devices"
                        self.discovery_specific_cred_failure(msg=msg)

        http_write_credential_list = global_credentials.get(
            "http_write_credential_list"
        )
        if http_write_credential_list:
            if not isinstance(http_write_credential_list, list):
                msg = "Global HTTP write credentials must be passed as a list"
                self.discovery_specific_cred_failure(msg=msg)
            if response.get("httpsWrite") is None:
                msg = "Global HTTP write credentials are not present in the Cisco Catalyst Center"
                self.discovery_specific_cred_failure(msg=msg)
            if len(http_write_credential_list) > 0:
                global_credentials_all["httpsWrite"] = []
                cred_len = len(http_write_credential_list)
                if cred_len > 5:
                    cred_len = 5
                for http_cred in http_write_credential_list:
                    if http_cred.get("description") and http_cred.get("username"):
                        for http in response.get("httpsWrite"):
                            if http.get("description") == http.get(
                                "description"
                            ) and http.get("username") == http.get("username"):
                                global_credentials_all["httpsWrite"].append(
                                    http.get("id")
                                )
                        global_credentials_all["httpsWrite"] = global_credentials_all[
                            "httpsWrite"
                        ][:cred_len]
                    else:
                        msg = "Kindly ensure you include both the description and the username for the Global HTTP Write credential to discover the devices"
                        self.discovery_specific_cred_failure(msg=msg)

        snmp_v2_read_credential_list = global_credentials.get(
            "snmp_v2_read_credential_list"
        )
        if snmp_v2_read_credential_list:
            if not isinstance(snmp_v2_read_credential_list, list):
                msg = "Global SNMPv2 read credentials must be passed as a list"
                self.discovery_specific_cred_failure(msg=msg)
            if response.get("snmpV2cRead") is None:
                msg = "Global SNMPv2 read credentials are not present in the Cisco Catalyst Center"
                self.discovery_specific_cred_failure(msg=msg)
            if len(snmp_v2_read_credential_list) > 0:
                global_credentials_all["snmpV2cRead"] = []
                cred_len = len(snmp_v2_read_credential_list)
                if cred_len > 5:
                    cred_len = 5
                for snmp_cred in snmp_v2_read_credential_list:
                    if snmp_cred.get("description"):
                        for snmp in response.get("snmpV2cRead"):
                            if snmp.get("description") == snmp_cred.get("description"):
                                global_credentials_all["snmpV2cRead"].append(
                                    snmp.get("id")
                                )
                        global_credentials_all["snmpV2cRead"] = global_credentials_all[
                            "snmpV2cRead"
                        ][:cred_len]
                    else:
                        msg = "Kindly ensure you include the description for the Global SNMPv2 Read \
                                credential to discover the devices"
                        self.discovery_specific_cred_failure(msg=msg)

        snmp_v2_write_credential_list = global_credentials.get(
            "snmp_v2_write_credential_list"
        )
        if snmp_v2_write_credential_list:
            if not isinstance(snmp_v2_write_credential_list, list):
                msg = "Global SNMPv2 write credentials must be passed as a list"
                self.discovery_specific_cred_failure(msg=msg)
            if response.get("snmpV2cWrite") is None:
                msg = "Global SNMPv2 write credentials are not present in the Cisco Catalyst Center"
                self.discovery_specific_cred_failure(msg=msg)
            if len(snmp_v2_write_credential_list) > 0:
                global_credentials_all["snmpV2cWrite"] = []
                cred_len = len(snmp_v2_write_credential_list)
                if cred_len > 5:
                    cred_len = 5
                for snmp_cred in snmp_v2_write_credential_list:
                    if snmp_cred.get("description"):
                        for snmp in response.get("snmpV2cWrite"):
                            if snmp.get("description") == snmp_cred.get("description"):
                                global_credentials_all["snmpV2cWrite"].append(
                                    snmp.get("id")
                                )
                        global_credentials_all["snmpV2cWrite"] = global_credentials_all[
                            "snmpV2cWrite"
                        ][:cred_len]
                    else:
                        msg = "Kindly ensure you include the description for the Global SNMPV2 write credential to discover the devices"
                        self.discovery_specific_cred_failure(msg=msg)

        snmp_v3_credential_list = global_credentials.get("snmp_v3_credential_list")
        if snmp_v3_credential_list:
            if not isinstance(snmp_v3_credential_list, list):
                msg = "Global SNMPv3 write credentials must be passed as a list"
                self.discovery_specific_cred_failure(msg=msg)
            if response.get("snmpV3") is None:
                msg = "Global SNMPv3 credentials are not present in the Cisco Catalyst Center"
                self.discovery_specific_cred_failure(msg=msg)
            if len(snmp_v3_credential_list) > 0:
                global_credentials_all["snmpV3"] = []
                cred_len = len(snmp_v3_credential_list)
                if cred_len > 5:
                    cred_len = 5
                for snmp_cred in snmp_v3_credential_list:
                    if snmp_cred.get("description") and snmp_cred.get("username"):
                        for snmp in response.get("snmpV3"):
                            if snmp.get("description") == snmp_cred.get(
                                "description"
                            ) and snmp.get("username") == snmp_cred.get("username"):
                                global_credentials_all["snmpV3"].append(snmp.get("id"))
                        global_credentials_all["snmpV3"] = global_credentials_all[
                            "snmpV3"
                        ][:cred_len]
                    else:
                        msg = "Kindly ensure you include both the description and the username for the Global SNMPv3 \
                                to discover the devices"
                        self.discovery_specific_cred_failure(msg=msg)

        net_conf_port_list = global_credentials.get("net_conf_port_list")
        if net_conf_port_list:
            if not isinstance(net_conf_port_list, list):
                msg = "Global net Conf Ports be passed as a list"
                self.discovery_specific_cred_failure(msg=msg)
            if response.get("netconfCredential") is None:
                msg = (
                    "Global netconf ports are not present in the Cisco Catalyst Center"
                )
                self.discovery_specific_cred_failure(msg=msg)
            if len(net_conf_port_list) > 0:
                global_credentials_all["netconfCredential"] = []
                cred_len = len(net_conf_port_list)
                if cred_len > 5:
                    cred_len = 5
                for port in net_conf_port_list:
                    if port.get("description"):
                        for netconf in response.get("netconfCredential"):
                            if port.get("description") == netconf.get("description"):
                                global_credentials_all["netconfCredential"].append(
                                    netconf.get("id")
                                )
                        global_credentials_all["netconfCredential"] = (
                            global_credentials_all["netconfCredential"][:cred_len]
                        )
                    else:
                        msg = "Please provide valid description of the Global Netconf port to be used"
                        self.discovery_specific_cred_failure(msg=msg)

        self.log(
            "Fetched Global credentials IDs are {0}".format(global_credentials_all),
            "INFO",
        )
        return global_credentials_all

    def get_ccc_global_credentials_v2_info(self):
        """
        Retrieve the global credentials information (version 2).
        It applies the 'get_all_global_credentials' function and extracts
        the IDs of the credentials. If no credentials are found, the
        function fails with a message.

        Returns:
          This method does not return a value. However, updates the attributes:
          - self.creds_ids_list: The list of credentials IDs is extended with
                                 the IDs extracted from the response.
          - self.result: A dictionary that is updated with the credentials IDs.
        """

        response = self.dnac_apply["exec"](
            family="discovery",
            function="get_all_global_credentials",
            params=self.validated_config[0].get("headers"),
            op_modifies=True,
        )
        response = response.get("response")
        self.log(
            "The Global credentials response from 'get all global credentials v2' API is {0}".format(
                str(response)
            ),
            "DEBUG",
        )
        global_credentials_all = {}
        global_credentials = self.validated_config[0].get("global_credentials")
        if global_credentials:
            global_credentials_all = self.handle_global_credentials(response=response)

        global_cred_set = set(global_credentials_all.keys())
        response_cred_set = set(response.keys())
        diff_keys = response_cred_set.difference(global_cred_set)

        for key in diff_keys:
            global_credentials_all[key] = []
            if response[key] is None:
                response[key] = []
            total_len = len(response[key])
            if total_len > 5:
                total_len = 5
            for element in response.get(key):
                global_credentials_all[key].append(element.get("id"))
            global_credentials_all[key] = global_credentials_all[key][:total_len]

        if global_credentials_all == {}:
            msg = "Not found any global credentials to perform discovery"
            self.log(msg, "WARNING")

        return global_credentials_all

    def get_devices_list_info(self):
        """
        Retrieve the list of devices from the validated configuration.
        It then updates the result attribute with this list.

        Returns:
          - ip_address_list: The list of devices extracted from the
                          'validated_config' attribute.
        """
        ip_address_list = self.validated_config[0].get("ip_address_list")
        self.result.update(dict(devices_info=ip_address_list))
        self.log(
            "Details of the device list passed: {0}".format(str(ip_address_list)),
            "INFO",
        )
        return ip_address_list

    def preprocess_device_discovery(self, ip_address_list=None):
        """
        Preprocess the devices' information. Extract the IP addresses from
        the list of devices and perform additional processing based on the
        'discovery_type' in the validated configuration.

        Parameters:
          - ip_address_list: The list of devices' IP addresses intended for preprocessing.
                             If not provided, an empty list will be used.

        Returns:
          - ip_address_list: It returns IP address list for the API to process. The value passed
                             for single, CDP, LLDP, CIDR, Range and Multi Range varies depending
                             on the need.
        """

        if ip_address_list is None:
            ip_address_list = []
        discovery_type = self.validated_config[0].get("discovery_type")
        self.log(
            "Discovery type passed for the discovery is {0}".format(discovery_type),
            "INFO",
        )
        if discovery_type in ["SINGLE", "CDP", "LLDP"]:
            if len(ip_address_list) == 1:
                ip_address_list = ip_address_list[0]
            else:
                self.preprocess_device_discovery_handle_error()
        elif discovery_type == "CIDR":
            if len(ip_address_list) == 1:
                cidr_notation = ip_address_list[0]
                if int(cidr_notation.split("/")[1]) not in range(20, 31):
                    msg = "Prefix length should be between 20 and 30"
                    self.log(msg, "CRITICAL")
                    self.module.fail_json(msg=msg)
                if len(cidr_notation.split("/")) == 2:
                    ip_address_list = cidr_notation
                else:
                    ip_address_list = "{0}/30".format(cidr_notation)
                    self.log(
                        "CIDR notation is being used for discovery and it requires a prefix length to be specified, such as 1.1.1.1/24.\
                        As no prefix length was provided, it will default to 30.",
                        "WARNING",
                    )
            else:
                self.preprocess_device_discovery_handle_error()
        elif discovery_type == "RANGE":
            if len(ip_address_list) == 1:
                if len(str(ip_address_list[0]).split("-")) == 2:
                    ip_address_list = ip_address_list[0]
                else:
                    ip_address_list = "{0}-{1}".format(
                        ip_address_list[0], ip_address_list[0]
                    )
            else:
                self.preprocess_device_discovery_handle_error()
        else:
            if len(ip_address_list) > 8:
                msg = "Maximum of 8 IP ranges are allowed."
                self.log(msg, "CRITICAL")
                self.module.fail_json(msg=msg)
            new_ip_collected = []
            for ip in ip_address_list:
                if len(str(ip).split("-")) != 2:
                    ip_collected = "{0}-{0}".format(ip)
                    new_ip_collected.append(ip_collected)
                else:
                    new_ip_collected.append(ip)
            ip_address_list = ",".join(new_ip_collected)
        self.log(
            "Collected IP address/addresses are {0}".format(str(ip_address_list)),
            "INFO",
        )
        return str(ip_address_list)

    def preprocess_device_discovery_handle_error(self):
        """
        Method for failing discovery based on the length of list of IP Addresses passed
        for performing discovery.
        """

        self.log("IP Address list's length is longer than 1", "ERROR")
        self.module.fail_json(
            msg="IP Address list's length is longer than 1", response=[]
        )

    def discovery_specific_cred_failure(self, msg=None):
        """
        Method for failing discovery if there is any discrepancy in the credentials
        passed by the user
        """

        self.log(msg, "CRITICAL")
        self.module.fail_json(msg=msg)

    def handle_discovery_specific_credentials(self, new_object_params=None):
        """
        Method to convert values for create_params API when discovery specific paramters
        are passed as input.

        Parameters:
            - new_object_params: The dictionary storing various parameters for calling the
                                 start discovery API

        Returns:
            - new_object_params: The dictionary storing various parameters for calling the
                                 start discovery API in an updated fashion
        """

        discovery_specific_credentials = self.validated_config[0].get(
            "discovery_specific_credentials"
        )
        cli_credentials_list = discovery_specific_credentials.get(
            "cli_credentials_list"
        )
        http_read_credential = discovery_specific_credentials.get(
            "http_read_credential"
        )
        http_write_credential = discovery_specific_credentials.get(
            "http_write_credential"
        )
        snmp_v2_read_credential = discovery_specific_credentials.get(
            "snmp_v2_read_credential"
        )
        snmp_v2_write_credential = discovery_specific_credentials.get(
            "snmp_v2_write_credential"
        )
        snmp_v3_credential = discovery_specific_credentials.get("snmp_v3_credential")
        net_conf_port = discovery_specific_credentials.get("net_conf_port")

        if cli_credentials_list:
            if not isinstance(cli_credentials_list, list):
                msg = "Device Specific ClI credentials must be passed as a list"
                self.discovery_specific_cred_failure(msg=msg)
            if len(cli_credentials_list) > 0:
                username_list = []
                password_list = []
                enable_password_list = []
                for cli_cred in cli_credentials_list:
                    if (
                        cli_cred.get("username")
                        and cli_cred.get("password")
                        and cli_cred.get("enable_password")
                    ):
                        username_list.append(cli_cred.get("username"))
                        password_list.append(cli_cred.get("password"))
                        enable_password_list.append(cli_cred.get("enable_password"))
                    else:
                        msg = "username, password and enable_password must be passed toether for creating CLI credentials"
                        self.discovery_specific_cred_failure(msg=msg)
                new_object_params["userNameList"] = username_list
                new_object_params["passwordList"] = password_list
                new_object_params["enablePasswordList"] = enable_password_list

        if http_read_credential:
            if not (
                http_read_credential.get("password")
                and isinstance(http_read_credential.get("password"), str)
            ):
                msg = (
                    "The password for the HTTP read credential must be of string type."
                )
                self.discovery_specific_cred_failure(msg=msg)
            if not (
                http_read_credential.get("username")
                and isinstance(http_read_credential.get("username"), str)
            ):
                msg = (
                    "The username for the HTTP read credential must be of string type."
                )
                self.discovery_specific_cred_failure(msg=msg)
            if not (
                http_read_credential.get("port")
                and isinstance(http_read_credential.get("port"), int)
            ):
                msg = "The port for the HTTP read Credential must be of integer type."
                self.discovery_specific_cred_failure(msg=msg)
            if not isinstance(http_read_credential.get("secure"), bool):
                msg = "Secure for HTTP read Credential must be of type boolean."
                self.discovery_specific_cred_failure(msg=msg)
            new_object_params["httpReadCredential"] = http_read_credential

        if http_write_credential:
            if not (
                http_write_credential.get("password")
                and isinstance(http_write_credential.get("password"), str)
            ):
                msg = (
                    "The password for the HTTP write credential must be of string type."
                )
                self.discovery_specific_cred_failure(msg=msg)
            if not (
                http_write_credential.get("username")
                and isinstance(http_write_credential.get("username"), str)
            ):
                msg = (
                    "The username for the HTTP write credential must be of string type."
                )
                self.discovery_specific_cred_failure(msg=msg)
            if not (
                http_write_credential.get("port")
                and isinstance(http_write_credential.get("port"), int)
            ):
                msg = "The port for the HTTP write Credential must be of integer type."
                self.discovery_specific_cred_failure(msg=msg)
            if not isinstance(http_write_credential.get("secure"), bool):
                msg = "Secure for HTTP write Credential must be of type boolean."
                self.discovery_specific_cred_failure(msg=msg)
            new_object_params["httpWriteCredential"] = http_write_credential

        if snmp_v2_read_credential:
            if not (snmp_v2_read_credential.get("description")) and isinstance(
                snmp_v2_read_credential.get("description"), str
            ):
                msg = "Name/description for the SNMP v2 read credential must be of string type"
                self.discovery_specific_cred_failure(msg=msg)
            if not (snmp_v2_read_credential.get("community")) and isinstance(
                snmp_v2_read_credential.get("community"), str
            ):
                msg = "The community string must be of string type"
                self.discovery_specific_cred_failure(msg=msg)
            new_object_params["snmpRoCommunityDesc"] = snmp_v2_read_credential.get(
                "description"
            )
            new_object_params["snmpROCommunity"] = snmp_v2_read_credential.get(
                "community"
            )
            new_object_params["snmpVersion"] = "v2"

        if snmp_v2_write_credential:
            if not (snmp_v2_write_credential.get("description")) and isinstance(
                snmp_v2_write_credential.get("description"), str
            ):
                msg = "Name/description for the SNMP v2 write credential must be of string type"
                self.discovery_specific_cred_failure(msg=msg)
            if not (snmp_v2_write_credential.get("community")) and isinstance(
                snmp_v2_write_credential.get("community"), str
            ):
                msg = "The community string must be of string type"
                self.discovery_specific_cred_failure(msg=msg)
            new_object_params["snmpRwCommunityDesc"] = snmp_v2_write_credential.get(
                "description"
            )
            new_object_params["snmpRwCommunity"] = snmp_v2_write_credential.get(
                "community"
            )
            new_object_params["snmpVersion"] = "v2"

        if snmp_v3_credential:
            if not (snmp_v3_credential.get("username")) and isinstance(
                snmp_v3_credential.get("username"), str
            ):
                msg = "Username of SNMP v3 protocol must be of string type"
                self.discovery_specific_cred_failure(msg=msg)
            if not (snmp_v3_credential.get("snmp_mode")) and isinstance(
                snmp_v3_credential.get("snmp_mode"), str
            ):
                msg = "Mode of SNMP is madantory to use SNMPv3 protocol and must be of string type"
                self.discovery_specific_cred_failure(msg=msg)
                if (
                    snmp_v3_credential.get("snmp_mode")
                ) == "AUTHPRIV" or snmp_v3_credential.get("snmp_mode") == "AUTHNOPRIV":
                    if not (snmp_v3_credential.get("auth_password")) and isinstance(
                        snmp_v3_credential.get("auth_password"), str
                    ):
                        msg = "Authorization password must be of string type"
                        self.discovery_specific_cred_failure(msg=msg)
                    if not (snmp_v3_credential.get("auth_type")) and isinstance(
                        snmp_v3_credential.get("auth_type"), str
                    ):
                        msg = "Authorization type must be of string type"
                        self.discovery_specific_cred_failure(msg=msg)
                    if snmp_v3_credential.get("snmp_mode") == "AUTHPRIV":
                        if not (snmp_v3_credential.get("privacy_type")) and isinstance(
                            snmp_v3_credential.get("privacy_type"), str
                        ):
                            msg = "Privacy type must be of string type"
                            self.discovery_specific_cred_failure(msg=msg)
                        if not (
                            snmp_v3_credential.get("privacy_password")
                        ) and isinstance(
                            snmp_v3_credential.get("privacy_password"), str
                        ):
                            msg = "Privacy password must be of string type"
                            self.discovery_specific_cred_failure(msg=msg)
            new_object_params["snmpUserName"] = snmp_v3_credential.get("username")
            new_object_params["snmpMode"] = snmp_v3_credential.get("snmp_mode")
            new_object_params["snmpAuthPassphrase"] = snmp_v3_credential.get(
                "auth_password"
            )
            new_object_params["snmpAuthProtocol"] = snmp_v3_credential.get("auth_type")
            new_object_params["snmpPrivProtocol"] = snmp_v3_credential.get(
                "privacy_type"
            )
            new_object_params["snmpPrivPassphrase"] = snmp_v3_credential.get(
                "privacy_password"
            )
            new_object_params["snmpVersion"] = "v3"

        if net_conf_port:
            new_object_params["netconfPort"] = str(net_conf_port)

        return new_object_params

    def create_params(self, ip_address_list=None):
        """
        Create a new parameter object based on the validated configuration,
        credential IDs, and IP address list.

        Parameters:
          - credential_ids: The list of credential IDs to include in the
                            parameters. If not provided, an empty list is used.
          - ip_address_list: The list of IP addresses to include in the
                             parameters. If not provided, None is used.

        Returns:
          - new_object_params: A dictionary containing the newly created
                               parameters.
        """

        credential_ids = []

        new_object_params = {}
        new_object_params["cdpLevel"] = self.validated_config[0].get("cdp_level")
        new_object_params["discoveryType"] = self.validated_config[0].get(
            "discovery_type"
        )
        new_object_params["ipAddressList"] = ip_address_list
        new_object_params["ipFilterList"] = self.validated_config[0].get(
            "ip_filter_list"
        )
        new_object_params["lldpLevel"] = self.validated_config[0].get("lldp_level")
        new_object_params["name"] = self.validated_config[0].get("discovery_name")
        new_object_params["preferredMgmtIPMethod"] = self.validated_config[0].get(
            "preferred_mgmt_ip_method"
        )
        new_object_params["protocolOrder"] = self.validated_config[0].get(
            "protocol_order"
        )
        new_object_params["retry"] = self.validated_config[0].get("retry")
        new_object_params["timeout"] = self.validated_config[0].get("timeout")

        if self.validated_config[0].get("discovery_specific_credentials"):
            self.handle_discovery_specific_credentials(
                new_object_params=new_object_params
            )

        global_cred_flag = self.validated_config[0].get("use_global_credentials")
        global_credentials_all = {}

        if global_cred_flag is True:
            global_credentials_all = self.get_ccc_global_credentials_v2_info()
            for global_cred_list in global_credentials_all.values():
                credential_ids.extend(global_cred_list)
            new_object_params["globalCredentialIdList"] = credential_ids

        self.log(
            "All the global credentials used for the discovery task are {0}".format(
                str(global_credentials_all)
            ),
            "DEBUG",
        )

        if not (
            new_object_params.get("snmpUserName")
            or new_object_params.get("snmpRoCommunityDesc")
            or new_object_params.get("snmpRwCommunityDesc")
            or global_credentials_all.get("snmpV2cRead")
            or global_credentials_all.get("snmpV2cWrite")
            or global_credentials_all.get("snmpV3")
        ):
            msg = (
                "Please provide atleast one valid SNMP credential to perform Discovery"
            )
            self.discovery_specific_cred_failure(msg=msg)

        if not (
            new_object_params.get("userNameList")
            or global_credentials_all.get("cliCredential")
        ):
            msg = "Please provide atleast one valid CLI credential to perform Discovery"
            self.discovery_specific_cred_failure(msg=msg)

        self.log(
            "The payload/object created for calling the start discovery API is {0}".format(
                str(new_object_params)
            ),
            "INFO",
        )

        return new_object_params

    def create_discovery(self, ip_address_list=None):
        """
        Start a new discovery process in the Cisco Catalyst Center. It creates the
        parameters required for the discovery and then calls the
        'start_discovery' function. The result of the discovery process
        is added to the 'result' attribute.

        Parameters:
          - credential_ids: The list of credential IDs to include in the
                            discovery. If not provided, an empty list is used.
          - ip_address_list: The list of IP addresses to include in the
                             discovery. If not provided, None is used.

        Returns:
          - task_id: The ID of the task created for the discovery process.
        """

        result = self.dnac_apply["exec"](
            family="discovery",
            function="start_discovery",
            params=self.create_params(ip_address_list=ip_address_list),
            op_modifies=True,
        )

        self.log(
            "The response received post discovery creation API called is {0}".format(
                str(result)
            ),
            "DEBUG",
        )

        self.result.update(dict(discovery_result=result))
        self.log(
            "Task Id of the API task created is {0}".format(
                result.response.get("taskId")
            ),
            "INFO",
        )
        return result.response.get("taskId")

    def get_merged_task_status(self, task_id=None):
        """
        Monitor the status of a task of creation of dicovery in the Cisco Catalyst Center.
        It checks the task status periodically until the task is no longer 'In Progress'
        or other states. If the task encounters an error or fails, it immediately fails the
        module and returns False.

        Parameters:
          - task_id: The ID of the task to monitor.

        Returns:
          - result: True if the task completed successfully, False otherwise.
        """

        result = False
        params = dict(task_id=task_id)
        while True:
            response = self.dnac_apply["exec"](
                family="task",
                function="get_task_by_id",
                params=params,
                op_modifies=True,
            )
            response = response.response
            self.log(
                "Task status for the task id {0} is {1}, is_error: {2}".format(
                    str(task_id), str(response), str(response.get("isError"))
                ),
                "INFO",
            )
            if response.get("isError") or re.search(
                "failed", response.get("progress"), flags=re.IGNORECASE
            ):
                msg = (
                    "Discovery task with id {0} has not completed - Reason: {1}".format(
                        task_id, response.get("failureReason")
                    )
                )
                self.log(msg, "CRITICAL")
                self.module.fail_json(msg=msg)
                return False

            self.log(
                "Task status for the task id (before checking status) {0} is {1}".format(
                    str(task_id), str(response)
                ),
                "INFO",
            )
            progress = response.get("progress")
            try:
                progress_value = int(progress)
                result = True
                self.log("The discovery process is completed", "INFO")
                self.result.update(dict(discovery_task=response))
                return result
            except Exception:
                self.log(
                    "The progress status is {0}, continue to check the status after 3 seconds. Putting into sleep for 3 seconds".format(
                        progress
                    )
                )
                time.sleep(3)

    def get_deleted_task_status(self, task_id=None):
        """
        Monitor the status of a task of deletion of dicovery in the Cisco Catalyst Center.
        It checks the itask status periodically until the task is 'Discovery deleted successfully'.
        If the task encounters an error or fails, it immediately fails the module and returns False.

        Parameters:
          - task_id: The ID of the task to monitor.

        Returns:
          - result: True if the task completed successfully, False otherwise.
        """

        result = False
        params = dict(task_id=task_id)
        while True:
            response = self.dnac_apply["exec"](
                family="task",
                function="get_task_by_id",
                params=params,
                op_modifies=True,
            )
            response = response.response
            self.log(
                "Task status for the task id {0} is {1}, is_error: {2}".format(
                    str(task_id), str(response), str(response.get("isError"))
                ),
                "INFO",
            )
            if response.get("isError") or re.search(
                "failed", response.get("progress"), flags=re.IGNORECASE
            ):
                msg = (
                    "Discovery task with id {0} has not completed - Reason: {1}".format(
                        task_id, response.get("failureReason")
                    )
                )
                self.log(msg, "CRITICAL")
                self.module.fail_json(msg=msg)
                return False

            self.log(
                "Task status for the task id (before checking status) {0} is {1}".format(
                    str(task_id), str(response)
                ),
                "INFO",
            )
            progress = response.get("progress")
            if re.search("Discovery deleted successfully.", response.get("progress")):
                result = True
                self.log("The discovery process is completed", "INFO")
                self.result.update(dict(discovery_task=response))
                return result

            self.log(
                "The progress status is {0}, continue to check the status after 3 seconds. Putting into sleep for 3 seconds".format(
                    progress
                )
            )
            time.sleep(3)

    def lookup_discovery_by_range_via_name(self):
        """
        Retrieve a specific discovery by name from a range of
        discoveries in the Cisco Catalyst Center.

        Returns:
          - discovery: The discovery with the specified name from the range
                       of discoveries. If no matching discovery is found, it
                       returns None.
        """
        start_index = self.validated_config[0].get("start_index")
        records_to_return = self.validated_config[0].get("records_to_return")

        response = {"response": []}
        if records_to_return > 500:
            num_intervals = records_to_return // 500
            for num in range(0, num_intervals + 1):
                params = dict(
                    start_index=1 + num * 500,
                    records_to_return=500,
                    headers=self.validated_config[0].get("headers"),
                )
                response_part = self.dnac_apply["exec"](
                    family="discovery",
                    function="get_discoveries_by_range",
                    params=params,
                    op_modifies=True,
                )
                response["response"].extend(response_part["response"])
        else:
            params = dict(
                start_index=self.validated_config[0].get("start_index"),
                records_to_return=self.validated_config[0].get("records_to_return"),
                headers=self.validated_config[0].get("headers"),
            )

            response = self.dnac_apply["exec"](
                family="discovery",
                function="get_discoveries_by_range",
                params=params,
                op_modifies=True,
            )
        self.log(
            "Response of the get discoveries via range API is {0}".format(
                str(response)
            ),
            "DEBUG",
        )

        return next(
            filter(
                lambda x: x["name"] == self.validated_config[0].get("discovery_name"),
                response.get("response"),
            ),
            None,
        )

    def get_discoveries_by_range_until_success(self):
        """
        Continuously retrieve a specific discovery by name from a range of
        discoveries in the Cisco Catalyst Center until the discovery is complete.

        Returns:
          - discovery: The completed discovery with the specified name from
                       the range of discoveries. If the discovery is not
                       found or not completed, the function fails the module
                       and returns None.
        """

        result = False
        aborted = False
        discovery = self.lookup_discovery_by_range_via_name()

        if not discovery:
            msg = "Cannot find any discovery task with name {0} -- Discovery result: {1}".format(
                str(self.validated_config[0].get("discovery_name")), str(discovery)
            )
            self.log(msg, "INFO")
            self.module.fail_json(msg=msg)

        while True:
            discovery = self.lookup_discovery_by_range_via_name()
            discovery_condition = discovery.get("discoveryCondition")
            if discovery_condition == "Complete":
                result = True
                break
            elif discovery_condition == "Aborted":
                aborted = True
                break
            time.sleep(3)

        if not result:
            if aborted is True:
                msg = (
                    "Discovery with name {0} is aborted by the user on the GUI".format(
                        str(self.validated_config[0].get("discovery_name"))
                    )
                )
                self.log(msg, "CRITICAL")
                self.module.fail_json(msg=msg)
            else:
                msg = "Cannot find any discovery task with name {0} -- Discovery result: {1}".format(
                    str(self.validated_config[0].get("discovery_name")), str(discovery)
                )
                self.log(msg, "CRITICAL")
                self.module.fail_json(msg=msg)

        self.result.update(dict(discovery_range=discovery))
        return discovery

    def get_discovery_device_info(self, discovery_id=None, task_id=None):
        """
        Retrieve the information of devices discovered by a specific discovery
        process in the Cisco Catalyst Center. It checks the reachability status of the
        devices periodically until all devices are reachable or until a
        maximum of 3 attempts.

        Parameters:
          - discovery_id: ID of the discovery process to retrieve devices from.
          - task_id: ID of the task associated with the discovery process.

        Returns:
          - result: True if all devices are reachable, False otherwise.
        """

        params = dict(
            id=discovery_id,
            task_id=task_id,
            headers=self.validated_config[0].get("headers"),
        )
        result = False
        count = 0
        while True:
            response = self.dnac_apply["exec"](
                family="discovery",
                function="get_discovered_network_devices_by_discovery_id",
                params=params,
                op_modifies=True,
            )
            devices = response.response

            self.log(
                "Retrieved device details using the API 'get_discovered_network_devices_by_discovery_id': {0}".format(
                    str(devices)
                ),
                "DEBUG",
            )
            if all(res.get("reachabilityStatus") == "Success" for res in devices):
                result = True
                self.log("All devices in the range are reachable", "INFO")
                break

            elif any(res.get("reachabilityStatus") == "Success" for res in devices):
                result = True
                self.log("Some devices in the range are reachable", "INFO")
                break

            elif all(res.get("reachabilityStatus") != "Success" for res in devices):
                result = True
                self.log(
                    "All devices are not reachable, but discovery is completed",
                    "WARNING",
                )
                break

            count += 1
            if count == 3:
                break

            time.sleep(3)

        if not result:
            msg = "Discovery network device with id {0} has not completed".format(
                discovery_id
            )
            self.log(msg, "CRITICAL")
            self.module.fail_json(msg=msg)

        self.log(
            "Discovery network device with id {0} got completed".format(discovery_id),
            "INFO",
        )
        self.result.update(dict(discovery_device_info=devices))
        return result

    def get_exist_discovery(self):
        """
        Retrieve an existing discovery by its name from a range of discoveries.

        Returns:
          - discovery: The discovery with the specified name from the range of
                       discoveries. If no matching discovery is found, it
                       returns None and updates the 'exist_discovery' entry in
                       the result dictionary to None.
        """
        discovery = self.lookup_discovery_by_range_via_name()
        if not discovery:
            self.result.update(dict(exist_discovery=discovery))
            return None

        have = dict(exist_discovery=discovery)
        self.have = have
        self.result.update(dict(exist_discovery=discovery))
        return discovery

    def delete_exist_discovery(self, params):
        """
        Delete an existing discovery in the Cisco Catalyst Center by its ID.

        Parameters:
          - params: A dictionary containing the parameters for the delete
                    operation, including the ID of the discovery to delete.

        Returns:
          - task_id: The ID of the task created for the delete operation.
        """

        response = self.dnac_apply["exec"](
            family="discovery",
            function="delete_discovery_by_id",
            params=params,
            op_modifies=True,
        )

        self.log(
            "Response collected from API 'delete_discovery_by_id': {0}".format(
                str(response)
            ),
            "DEBUG",
        )
        self.result.update(dict(delete_discovery=response))
        self.log(
            "Task Id of the deletion task is {0}".format(
                response.response.get("taskId")
            ),
            "INFO",
        )
        return response.response.get("taskId")

    def get_diff_merged(self):
        """
        Retrieve the information of devices discovered by a specific discovery
        process in the Cisco Catalyst Center, delete existing discoveries if they exist,
        and create a new discovery. The function also updates various
        attributes of the class instance.

        Returns:
          - self: The instance of the class with updated attributes.
        """

        self.validate_ip4_address_list()
        devices_list_info = self.get_devices_list_info()
        ip_address_list = self.preprocess_device_discovery(devices_list_info)
        exist_discovery = self.get_exist_discovery()
        if exist_discovery:
            params = dict(id=exist_discovery.get("id"))
            discovery_task_id = self.delete_exist_discovery(params=params)
            complete_discovery = self.get_deleted_task_status(task_id=discovery_task_id)

        discovery_task_id = self.create_discovery(ip_address_list=ip_address_list)
        complete_discovery = self.get_merged_task_status(task_id=discovery_task_id)
        discovery_task_info = self.get_discoveries_by_range_until_success()
        result = self.get_discovery_device_info(
            discovery_id=discovery_task_info.get("id")
        )
        self.result["changed"] = True
        self.result["msg"] = "Discovery Created Successfully"
        self.result["diff"] = self.validated_config
        self.result["response"] = discovery_task_id
        self.result.update(dict(msg="Discovery Created Successfully"))
        self.log(self.result["msg"], "INFO")
        return self

    def get_diff_deleted(self):
        """
        Delete an existing discovery in the Cisco Catalyst Center by its name, and
        updates various attributes of the class instance. If no
        discovery with the specified name is found, the function
        updates the 'msg' attribute with an appropriate message.

        Returns:
          - self: The instance of the class with updated attributes.
        """

        if self.validated_config[0].get("delete_all"):
            count_discoveries = self.dnac_apply["exec"](
                family="discovery",
                function="get_count_of_all_discovery_jobs",
            )
            if count_discoveries.get("response") == 0:
                msg = "There are no discoveries present in the Discovery Dashboard for deletion"
                self.result["msg"] = msg
                self.log(msg, "WARNING")
                self.result["response"] = self.validated_config[0]
                return self

            delete_all_response = self.dnac_apply["exec"](
                family="discovery",
                function="delete_all_discovery",
            )
            discovery_task_id = delete_all_response.get("response").get("taskId")
            self.result["changed"] = True
            self.result["msg"] = "All of the Discoveries Deleted Successfully"
            self.result["diff"] = self.validated_config

        else:
            exist_discovery = self.get_exist_discovery()
            if not exist_discovery:
                self.result["msg"] = "Discovery {0} Not Found".format(
                    self.validated_config[0].get("discovery_name")
                )
                self.log(self.result["msg"], "ERROR")
                return self

            params = dict(id=exist_discovery.get("id"))
            discovery_task_id = self.delete_exist_discovery(params=params)
            complete_discovery = self.get_deleted_task_status(task_id=discovery_task_id)
            self.result["changed"] = True
            self.result["msg"] = "Successfully deleted discovery"
            self.result["diff"] = self.validated_config
            self.result["response"] = discovery_task_id

        self.log(self.result["msg"], "INFO")
        return self

    def verify_diff_merged(self, config):
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
            Center configuration's Discovery Database.
        """

        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(config)), "INFO")
        # Code to validate Cisco Catalyst Center config for merged state
        discovery_task_info = self.get_discoveries_by_range_until_success()
        discovery_id = discovery_task_info.get("id")
        params = dict(id=discovery_id)
        response = self.dnac_apply["exec"](
            family="discovery",
            function="get_discovery_by_id",
            params=params,
            op_modifies=True,
        )
        discovery_name = config.get("discovery_name")
        if response:
            self.log(
                "Requested Discovery with name {0} is completed".format(discovery_name),
                "INFO",
            )

        else:
            self.log(
                "Requested Discovery with name {0} is not completed".format(
                    discovery_name
                ),
                "WARNING",
            )
        self.status = "success"

        return self

    def verify_diff_deleted(self, config):
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
            Discovery Database.
        """

        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(config)), "INFO")
        # Code to validate Cisco Catalyst Center config for deleted state
        if config.get("delete_all") is True:
            count_discoveries = self.dnac_apply["exec"](
                family="discovery",
                function="get_count_of_all_discovery_jobs",
            )
            if count_discoveries == 0:
                self.log("All discoveries are deleted", "INFO")
            else:
                self.log("All discoveries are not deleted", "WARNING")
            self.status = "success"
            return self

        discovery_task_info = self.lookup_discovery_by_range_via_name()
        discovery_name = config.get("discovery_name")
        if discovery_task_info:
            self.log(
                "Requested Discovery with name {0} is present".format(discovery_name),
                "WARNING",
            )

        else:
            self.log(
                "Requested Discovery with name {0} is not present and deleted".format(
                    discovery_name
                ),
                "INFO",
            )
        self.status = "success"

        return self


def main():
    """main entry point for module execution"""

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
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    ccc_discovery = Discovery(module)
    ccc_version = ccc_discovery.get_ccc_version()
    if ccc_discovery.compare_dnac_versions(ccc_version, "2.3.5.3") < 0:
        ccc_discovery.msg = (
            "Discovery Workflow Manager is not supported in Cisco Catalyst Center version '{0}'. "
            "Supported versions start from '2.3.5.3'.".format(ccc_version)
        )
        ccc_discovery.set_operation_result(
            "failed", False, ccc_discovery.msg, "ERROR"
        ).check_return_status()

    config_verify = ccc_discovery.params.get("config_verify")

    state = ccc_discovery.params.get("state")
    if state not in ccc_discovery.supported_states:
        ccc_discovery.status = "invalid"
        ccc_discovery.msg = "State {0} is invalid".format(state)
        ccc_discovery.check_return_status()

    ccc_discovery.validate_input(state=state).check_return_status()
    for config in ccc_discovery.validated_config:
        ccc_discovery.reset_values()
        ccc_discovery.get_diff_state_apply[state]().check_return_status()
        if config_verify:
            ccc_discovery.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_discovery.result)


if __name__ == "__main__":
    main()
