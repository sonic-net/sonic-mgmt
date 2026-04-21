#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to perform operations on device credentials in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ["Muthu Rakesh, Madhan Sankaranarayanan, Megha Kandari"]
DOCUMENTATION = r"""
---
module: device_credential_workflow_manager
short_description: Resource module for Global Device
  Credentials and Assigning Credentials to sites.
description:
  - Manage operations on Global Device Credentials,
    Assigning Credentials to sites and Sync Credentials
    to site device.
  - API to create global device credentials.
  - API to update global device credentials.
  - API to delete global device credentials.
  - API to assign the device credential to the site.
  - API to sync the device credential to the site. Sync
    functionality is applicable for Catalyst Center
    version 2.3.7.6 and later.
version_added: '6.7.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Muthu Rakesh (@MUTHU-RAKESH-27) Madhan Sankaranarayanan
  (@madhansansel) Megha Kandari (@kandarimegha)
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
      - List of details of global device credentials
        and site names.
    type: list
    elements: dict
    required: true
    suboptions:
      global_credential_details:
        description:
          - Manages global-level device credentials (create, update, or delete).
          - This is only for credential lifecycle operations (e.g., storing CLI, SNMP, HTTP credentials centrally).
          - To assign credentials to a site, use the C(assign_credentials_to_site) parameter.
          - To apply (sync) assigned credentials to devices under a site, use the C(apply_credentials_to_site) parameter.
        type: dict
        suboptions:
          cli_credential:
            description: Global Credential V2's cliCredential.
            type: list
            elements: dict
            suboptions:
              description:
                description: Description. Required for
                  creating the credential.
                type: str
              enable_password:
                description:
                  - cli_credential credential Enable
                    Password.
                  - Password cannot contain spaces or
                    angle brackets (< >)
                type: str
              id:
                description: Credential Id. Use this
                  for updating the device credential.
                type: str
              password:
                description:
                  - cli_credential credential Password.
                  - Required for creating/updating the
                    credential.
                  - Password cannot contain spaces or
                    angle brackets (< >).
                type: str
              username:
                description:
                  - cli_credential credential Username.
                  - Username cannot contain spaces or
                    angle brackets (< >).
                type: str
              old_description:
                description: Old Description. Use this
                  for updating the description/Username.
                type: str
              old_username:
                description: Old Username. Use this
                  for updating the description/Username.
                type: str
          https_read:
            description: Global Credential V2's httpsRead.
            type: list
            elements: dict
            suboptions:
              id:
                description: Credential Id. Use this
                  for updating the device credential.
                type: str
              name:
                description: Name. Required for creating
                  the credential.
                type: str
              password:
                description:
                  - https_read credential Password.
                  - Required for creating/updating the
                    credential.
                  - Password cannot contain spaces or
                    angle brackets (< >).
                type: str
              port:
                description: Port. Default port is 443.
                type: int
              username:
                description:
                  - https_read credential Username.
                  - Username cannot contain spaces or
                    angle brackets (< >).
                type: str
              old_description:
                description: Old Description. Use this
                  for updating the description/Username.
                type: str
              old_username:
                description: Old Username. Use this
                  for updating the description/Username.
                type: str
          https_write:
            description: Global Credential V2's httpsWrite.
            type: list
            elements: dict
            suboptions:
              id:
                description: Credential Id. Use this
                  for updating the device credential.
                type: str
              name:
                description: Name. Required for creating
                  the credential.
                type: str
              password:
                description:
                  - https_write credential Password.
                  - Required for creating/updating the
                    credential.
                  - Password cannot contain spaces or
                    angle brackets (< >).
                type: str
              port:
                description: Port. Default port is 443.
                type: int
              username:
                description:
                  - https_write credential Username.
                  - Username cannot contain spaces or
                    angle brackets (< >).
                type: str
              old_description:
                description: Old Description. Use this
                  for updating the description/Username.
                type: str
              old_username:
                description: Old Username. Use this
                  for updating the description/Username.
                type: str
          snmp_v2c_read:
            description: Global Credential V2's snmpV2cRead.
            type: list
            elements: dict
            suboptions:
              description:
                description: Description. Required for
                  creating the credential.
                type: str
              id:
                description: Credential Id. Use this
                  for updating the device credential.
                type: str
              read_community:
                description:
                  - snmp_v2c_read Read Community.
                  - Password cannot contain spaces or
                    angle brackets (< >).
                type: str
              old_description:
                description: Old Description. Use this
                  for updating the description.
                type: str
          snmp_v2c_write:
            description: Global Credential V2's snmpV2cWrite.
            type: list
            elements: dict
            suboptions:
              description:
                description: Description. Required for
                  creating the credential.
                type: str
              id:
                description: Credential Id. Use this
                  for updating the device credential.
                type: str
              write_community:
                description:
                  - snmp_v2c_write Write Community.
                  - Password cannot contain spaces or
                    angle brackets (< >).
                type: str
              old_description:
                description: Old Description. Use this
                  for updating the description.
                type: str
          snmp_v3:
            description: Global Credential V2's snmpV3.
            type: list
            elements: dict
            suboptions:
              auth_password:
                description:
                  - snmp_v3 Auth Password.
                  - Password must contain minimum 8
                    characters.
                  - Password cannot contain spaces or
                    angle brackets (< >).
                type: str
              auth_type:
                description: Auth Type. ["SHA", "MD5"].
                type: str
              description:
                description:
                  - snmp_v3 Description.
                  - Should be unique from other snmp_v3
                    credentials.
                type: str
              id:
                description: Credential Id. Use this
                  for updating the device credential.
                type: str
              privacy_password:
                description:
                  - snmp_v3 Privacy Password.
                  - Password must contain minimum 8
                    characters.
                  - Password cannot contain spaces or
                    angle brackets (< >).
                type: str
              privacy_type:
                description: Privacy Type. ["AES128",
                  "AES192", "AES256"].
                type: str
              snmp_mode:
                description: Snmp Mode. ["AUTHPRIV",
                  "AUTHNOPRIV", "NOAUTHNOPRIV"].
                type: str
              username:
                description:
                  - snmp_v3 credential Username.
                  - Username cannot contain spaces or
                    angle brackets (< >).
                type: str
              old_description:
                description: Old Description. Use this
                  for updating the description.
                type: str
      assign_credentials_to_site:
        description:
          - Assign Device Credentials to Site.
          - Starting from version 2.3.7.6, all credential
            parameters are mandatory.
          - If any parameter is missing, it will automatically
            inherit the value from the parent site—except
            for the Global site.
          - The unset option (passing {}) is only applicable
            for the Global site and not for other sites.
        type: dict
        suboptions:
          cli_credential:
            description: CLI Credential.
            type: dict
            suboptions:
              description:
                description: CLI Credential Description.
                type: str
              username:
                description: CLI Credential Username.
                type: str
              id:
                description: CLI Credential Id. Use
                  (Description, Username) or Id.
                type: str
          https_read:
            description: HTTP(S) Read Credential
            type: dict
            suboptions:
              description:
                description: HTTP(S) Read Credential
                  Description.
                type: str
              username:
                description: HTTP(S) Read Credential
                  Username.
                type: str
              id:
                description: HTTP(S) Read Credential
                  Id. Use (Description, Username) or
                  Id.
                type: str
          https_write:
            description: HTTP(S) Write Credential
            type: dict
            suboptions:
              description:
                description: HTTP(S) Write Credential
                  Description.
                type: str
              username:
                description: HTTP(S) Write Credential
                  Username.
                type: str
              id:
                description: HTTP(S) Write Credential
                  Id. Use (Description, Username) or
                  Id.
                type: str
          site_name:
            description: Site Name to assign credential.
            type: list
            elements: str
          snmp_v2c_read:
            description: SNMPv2c Read Credential
            type: dict
            suboptions:
              description:
                description: SNMPv2c Read Credential
                  Description.
                type: str
              id:
                description: SNMPv2c Read Credential
                  Id. Use Description or Id.
                type: str
          snmp_v2c_write:
            description: SNMPv2c Write Credential
            type: dict
            suboptions:
              description:
                description: SNMPv2c Write Credential
                  Description.
                type: str
              id:
                description: SNMPv2c Write Credential
                  Id. Use Description or Id.
                type: str
          snmp_v3:
            description: snmp_v3 Credential
            type: dict
            suboptions:
              description:
                description: snmp_v3 Credential Description.
                type: str
              id:
                description: snmp_v3 Credential Id.
                  Use Description or Id.
                type: str
      apply_credentials_to_site:
        description: Sync Device Credentials to Site
          devices. Applicable for Catalyst Center version
          2.3.7.6 and later. The credentials will only
          be applied if devices are present at the site
          and the provided credentials are already assigned
          but not yet synced to the specified site.
        type: dict
        suboptions:
          cli_credential:
            description: CLI Credential.
            type: dict
            suboptions:
              description:
                description: CLI Credential Description.
                type: str
              username:
                description: CLI Credential Username.
                type: str
              id:
                description: CLI Credential Id. Use
                  (Description, Username) or Id.
                type: str
          site_name:
            description: Site Name to apply credential.
            type: list
            elements: str
          snmp_v2c_read:
            description: SNMPv2c Read Credential
            type: dict
            suboptions:
              description:
                description: SNMPv2c Read Credential
                  Description.
                type: str
              id:
                description: SNMPv2c Read Credential
                  Id. Use Description or Id.
                type: str
          snmp_v2c_write:
            description: SNMPv2c Write Credential
            type: dict
            suboptions:
              description:
                description: SNMPv2c Write Credential
                  Description.
                type: str
              id:
                description: SNMPv2c Write Credential
                  Id. Use Description or Id.
                type: str
          snmp_v3:
            description: snmp_v3 Credential
            type: dict
            suboptions:
              description:
                description: snmp_v3 Credential Description.
                type: str
              id:
                description: snmp_v3 Credential Id.
                  Use Description or Id.
                type: str
requirements:
  - dnacentersdk >= 2.7.2
  - python >= 3.9
seealso:
  - name: Cisco Catalyst Center documentation for Discovery
      CreateGlobalCredentialsV2
    description: Complete reference of the CreateGlobalCredentialsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-global-credentials-v-2
  - name: Cisco Catalyst Center documentation for Discovery
      DeleteGlobalCredentialV2
    description: Complete reference of the DeleteGlobalCredentialV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-global-credential-v-2
  - name: Cisco Catalyst Center documentation for Discovery
      UpdateGlobalCredentialsV2
    description: Complete reference of the UpdateGlobalCredentialsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-global-credentials-v-2
  - name: Cisco Catalyst Center documentation for Network
      Settings AssignDeviceCredentialToSiteV2
    description: Complete reference of the AssignDeviceCredentialToSiteV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!assign-device-credential-to-site-v-2
  - name: Cisco Catalyst Center documentation for Network
      Settings updateDeviceCredentialSettingsForASite_
    description: Complete reference of the updateDeviceCredentialSettingsForASite
      API.
    link: https://developer.cisco.com/docs/dna-center/update-device-credential-settings-for-a-site
  - name: Cisco Catalyst Center documentation for Network
      Settings syncNetworkDevicesCredential
    description: Complete reference of the syncNetworkDevicesCredential
      API.
    link: https://developer.cisco.com/docs/dna-center/sync-network-devices-credential
notes:
  - SDK Method used are
    discovery.Discovery.create_global_credentials,
    discovery.Discovery.delete_global_credential,
    discovery.Discovery.update_global_credentials_v2,
    network_settings.NetworkSettings.assign_device_credential_to_site,
    network_settings.NetworkSettings.get_device_credential_settings_for_a_site,
    network_settings.NetworkSettings.update_device_credential_settings_for_a_site,
    network_settings.NetworkSettings.sync_network_devices_credential,
    network_settings.NetworkSettings.get_network_devices_credentials_sync_status,
    site.Sites.get_site_assigned_network_devices,
    site.Sites.get_sites
  - Paths used are
    post /dna/intent/api/v2/global-credential,
    delete /dna/intent/api/v2/global-credential/{id},
    put /dna/intent/api/v2/global-credential,
    post /dna/intent/api/v2/credential-to-site/{siteId},
    get /dna/intent/api/v1/sites/${id}/deviceCredentials,
    post /dna/intent/api/v1/sites/deviceCredentials/apply,
    post /dna/intent/api/v1/sites/${id}/deviceCredentials,
    get /dna/intent/api/v1/sites/${id}/deviceCredentials/status,
    get /dna/intent/api/v1/networkDevices/assignedToSite,
    get /dna/intent/api/v1/sites,
"""
EXAMPLES = r"""
---
- name: Create Credentials and assign it to a site.
  cisco.dnac.device_credential_workflow_manager:
  dnac_host: "{{ dnac_host }}"
  dnac_port: "{{ dnac_port }}"
  dnac_username: "{{ dnac_username }}"
  dnac_password: "{{ dnac_password }}"
  dnac_verify: "{{ dnac_verify }}"
  dnac_debug: "{{ dnac_debug }}"
  dnac_log: true
  dnac_log_level: "{{ dnac_log_level }}"
  state: merged
  config_verify: true
  config:
    - global_credential_details:
        cli_credential:
          - description: CLI1
            username: cli1
            password: '12345'
            enable_password: '12345'
        snmp_v2c_read:
          - description: SNMPv2c Read1
            read_community: '123456'
        snmp_v2c_write:
          - description: SNMPv2c Write1
            write_community: '123456'
        snmp_v3:
          - auth_password: '12345678'
            auth_type: SHA
            snmp_mode: AUTHPRIV
            privacy_password: '12345678'
            privacy_type: AES128
            username: snmpV31
            description: snmpV31
        https_read:
          - description: HTTP Read1
            username: HTTP Read1
            password: '12345'
            port: 443
        https_write:
          - description: HTTP Write1
            username: HTTP Write1
            password: '12345'
            port: 443
      assign_credentials_to_site:
        Sync: true
        cli_credential:
          description: CLI6
          username: cli6
        snmp_v2c_read:
          description: SNMPv2c Read1
        snmp_v2c_write:
          description: SNMPv2c Write1
        snmp_v3:
          description: snmpV31
        https_read:
          description: HTTP Read1
          username: HTTP_Read1
        https_write:
          description: HTTP Write1
          username: HTTP_Write1
        site_name:
          - Global/USA
- name: Create Multiple Credentials.
  cisco.dnac.device_credential_workflow_manager:
  dnac_host: "{{ dnac_host }}"
  dnac_port: "{{ dnac_port }}"
  dnac_username: "{{ dnac_username }}"
  dnac_password: "{{ dnac_password }}"
  dnac_verify: "{{ dnac_verify }}"
  dnac_debug: "{{ dnac_debug }}"
  dnac_log: true
  dnac_log_level: "{{ dnac_log_level }}"
  state: merged
  config_verify: true
  config:
    - global_credential_details:
        cli_credential:
          - description: CLI1
            username: cli1
            password: '12345'
            enable_password: '12345'
          - description: CLI2
            username: cli2
            password: '12345'
            enable_password: '12345'
        snmp_v2c_read:
          - description: SNMPv2c Read1
            read_community: '123456'
          - description: SNMPv2c Read2
            read_community: '123456'
        snmp_v2c_write:
          - description: SNMPv2c Write1
            write_community: '123456'
          - description: SNMPv2c Write2
            write_community: '123456'
        snmp_v3:
          - auth_password: '12345678'
            auth_type: SHA
            snmp_mode: AUTHPRIV
            privacy_password: '12345678'
            privacy_type: AES128
            username: snmpV31
            description: snmpV31
          - auth_password: '12345678'
            auth_type: SHA
            snmp_mode: AUTHPRIV
            privacy_password: '12345678'
            privacy_type: AES128
            username: snmp
            description: snmp
        https_read:
          - description: HTTP Read1
            username: HTTP Read1
            password: '12345'
            port: 443
          - description: HTTP Read2
            username: HTTP Read2
            password: '12345'
            port: 443
        https_write:
          - description: HTTP Write1
            username: HTTP Write1
            password: '12345'
            port: 443
          - description: HTTP Write2
            username: HTTP Write2
            password: '12345'
            port: 443
- name: Update global device credentials
  cisco.dnac.device_credential_workflow_manager:
  dnac_host: "{{ dnac_host }}"
  dnac_port: "{{ dnac_port }}"
  dnac_username: "{{ dnac_username }}"
  dnac_password: "{{ dnac_password }}"
  dnac_verify: "{{ dnac_verify }}"
  dnac_debug: "{{ dnac_debug }}"
  dnac_log: true
  dnac_log_level: "{{ dnac_log_level }}"
  state: merged
  config_verify: true
  config:
    - global_credential_details:
        cli_credential:
          - description: CLI1
            username: cli1
            password: '12345'
            enable_password: '12345'
        snmp_v2c_read:
          - description: SNMPv2c Read1
            read_community: '123456'
        snmp_v2c_write:
          - description: SNMPv2c Write1
            write_community: '123456'
        snmp_v3:
          - auth_password: '12345678'
            auth_type: SHA
            snmp_mode: AUTHPRIV
            privacy_password: '12345678'
            privacy_type: AES128
            username: snmpV31
            description: snmpV31
        https_read:
          - description: HTTP Read1
            username: HTTP Read1
            password: '12345'
            port: 443
        https_write:
          - description: HTTP_Write1
            username: HTTP_Write1
            password: '12345'
            port: 443
- name: Update multiple global device credentials
  cisco.dnac.device_credential_workflow_manager:
  dnac_host: "{{ dnac_host }}"
  dnac_port: "{{ dnac_port }}"
  dnac_username: "{{ dnac_username }}"
  dnac_password: "{{ dnac_password }}"
  dnac_verify: "{{ dnac_verify }}"
  dnac_debug: "{{ dnac_debug }}"
  dnac_log: true
  dnac_log_level: "{{ dnac_log_level }}"
  state: merged
  config_verify: true
  config:
    - global_credential_details:
        cli_credential:
          - description: CLI1
            username: cli1
            password: '12345'
            enable_password: '12345'
          - description: CLI2
            username: cli2
            password: '12345'
            enable_password: '12345'
        snmp_v2c_read:
          - description: SNMPv2c Read1
            read_community: '123456'
          - description: SNMPv2c Read2
            read_community: '123458'
        snmp_v2c_write:
          - description: SNMPv2c write1
            write_community: '123456'
          - description: SNMPv2c Write1
            write_community: '123466'
        snmp_v3:
          - auth_password: '12345678'
            auth_type: SHA
            snmp_mode: AUTHPRIV
            privacy_password: '12345678'
            privacy_type: AES128
            username: snmpV31
            description: snmpV31
          - auth_password: '12345678'
            auth_type: SHA
            snmp_mode: AUTHPRIV
            privacy_password: '12345644'
            privacy_type: AES128
            username: snmpV32
            description: snmpV32
        https_read:
          - description: HTTP Read1
            username: HTTP Read1
            password: '12345'
            port: 443
          - description: HTTP Read2
            username: HTTP Read2
            password: '12345'
            port: 443
        https_write:
          - description: HTTP_Write1
            username: HTTP_Write1
            password: '12345'
            port: 443
          - description: HTTP_Write2
            username: HTTP_Write2
            password: '12345'
            port: 443
- name: Update global device credential name/description
    using old name and description.
  cisco.dnac.device_credential_workflow_manager:
  dnac_host: "{{ dnac_host }}"
  dnac_port: "{{ dnac_port }}"
  dnac_username: "{{ dnac_username }}"
  dnac_password: "{{ dnac_password }}"
  dnac_verify: "{{ dnac_verify }}"
  dnac_debug: "{{ dnac_debug }}"
  dnac_log: true
  dnac_log_level: "{{ dnac_log_level }}"
  state: merged
  config_verify: true
  config:
    - global_credential_details:
        cli_credential:
          - description: CLI1
            username: cli1
            password: '12345'
            enable_password: '12345'
            old_description: CLI
            old_username: cli
        snmp_v2c_read:
          - description: SNMPv2c Read1
            read_community: '123456'
            old_description: SNMPv2c Read
        snmp_v2c_write:
          - description: SNMPv2c write1
            write_community: '123456'
            old_description: SNMPv2c write
        snmp_v3:
          - auth_password: '12345678'
            auth_type: SHA
            snmp_mode: AUTHPRIV
            privacy_password: '12345678'
            privacy_type: AES128
            username: snmpV31
            description: snmpV31
            old_description: snmp
        https_read:
          - description: HTTP Read1
            username: HTTP Read1
            password: '12345'
            port: 443
            old_description: HTTP Read
            old_username: HTTP Read
        https_write:
          - description: HTTP_Write1
            username: HTTP_Write1
            password: '12345'
            port: 443
            old_description: HTTP_Write
            old_username: HTTP_Write
- name: Assign Credentials to sites using old description
    and username.
  cisco.dnac.device_credential_workflow_manager:
  dnac_host: "{{ dnac_host }}"
  dnac_port: "{{ dnac_port }}"
  dnac_username: "{{ dnac_username }}"
  dnac_password: "{{ dnac_password }}"
  dnac_verify: "{{ dnac_verify }}"
  dnac_debug: "{{ dnac_debug }}"
  dnac_log: true
  dnac_log_level: "{{ dnac_log_level }}"
  state: merged
  config_verify: true
  config:
    - assign_credentials_to_site:
        cli_credential:
          description: CLI6
          username: cli6
        snmp_v2c_read:
          description: SNMPv2c Read1
        snmp_v2c_write:
          description: SNMPv2c Write1
        snmp_v3:
          description: snmpV31
        https_read:
          description: HTTP Read1
          username: HTTP_Read1
        https_write:
          description: HTTP Write1
          username: HTTP_Write1
        site_name:
          - Global/USA
- name: Sync global device credentials to a site.
  cisco.dnac.device_credential_workflow_manager:
  dnac_host: "{{ dnac_host }}"
  dnac_port: "{{ dnac_port }}"
  dnac_username: "{{ dnac_username }}"
  dnac_password: "{{ dnac_password }}"
  dnac_verify: "{{ dnac_verify }}"
  dnac_version: "{{dnac_version}}"
  dnac_debug: "{{ dnac_debug }}"
  dnac_log_level: "{{ dnac_log_level }}"
  dnac_log: true
  state: merged
  config_verify: true
  config:
    - apply_credentials_to_site:
        cli_credential:
          description: CLI5
          username: cli5
        snmp_v2c_read:
          description: SNMPv2c Read2
        snmp_v2c_write:
          description: SNMPv2c Write1
        snmp_v3:
          description: snmp
        site_name:
          - Global/Vietnam/halong/Hanoi
- name: Delete credentials
  cisco.dnac.device_credential_workflow_manager:
  dnac_host: "{{ dnac_host }}"
  dnac_port: "{{ dnac_port }}"
  dnac_username: "{{ dnac_username }}"
  dnac_password: "{{ dnac_password }}"
  dnac_verify: "{{ dnac_verify }}"
  dnac_debug: "{{ dnac_debug }}"
  dnac_log: true
  state: deleted
  config_verify: true
  config:
    - global_credential_details:
        cli_credential:
          - description: CLI1
            username: cli1
        snmp_v2c_read:
          - description: SNMPv2c Read1  # use this for deletion
        snmp_v2c_write:
          - description: SNMPv2c Write1  # use this for deletion
        snmp_v3:
          - description: snmpV31
        https_read:
          - description: HTTP Read1
            username: HTTP_Read1
        https_write:
          - description: HTTP Write1
            username: HTTP_Write1
"""
RETURN = r"""
# Case_1: Successful creation/updation/deletion of global device credentials
dnac_response1:
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
# Case_2: Successful assignment/sync of global device credentials to a site.
dnac_response2:
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


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
)


class DeviceCredential(DnacBase):
    """Class containing member attributes for device_credential_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.result["response"] = [
            {"global_credential": {}, "assign_credential": {}, "apply_credential": {}}
        ]

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
                - self.validated_config: If successful, a validated version of 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
            If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
            will contain the validated configuration. If it fails, 'self.status' will be 'failed',
            'self.msg' will describe the validation issues.

        """

        if not self.config:
            self.msg = "config not available in playbook for validation"
            self.status = "success"
            return self

        # temp_spec is the specification for the expected structure of configuration parameters
        temp_spec = {
            "global_credential_details": {
                "type": "dict",
                "cli_credential": {
                    "type": "list",
                    "description": {"type": "str"},
                    "username": {"type": "str"},
                    "password": {"type": "str"},
                    "enable_password": {"type": "str"},
                    "old_description": {"type": "str"},
                    "old_username": {"type": "str"},
                    "id": {"type": "str"},
                },
                "snmp_v2c_read": {
                    "type": "list",
                    "description": {"type": "str"},
                    "read_community": {"type": "str"},
                    "old_description": {"type": "str"},
                    "id": {"type": "str"},
                },
                "snmp_v2c_write": {
                    "type": "list",
                    "description": {"type": "str"},
                    "write_community": {"type": "str"},
                    "old_description": {"type": "str"},
                    "id": {"type": "str"},
                },
                "snmp_v3": {
                    "type": "list",
                    "description": {"type": "str"},
                    "username": {"type": "str"},
                    "snmp_mode": {"type": "str"},
                    "auth_type": {"type": "str"},
                    "auth_password": {"type": "str"},
                    "privacy_type": {"type": "str"},
                    "privacy_password": {"type": "str"},
                    "old_description": {"type": "str"},
                    "id": {"type": "str"},
                },
                "https_read": {
                    "type": "list",
                    "description": {"type": "str"},
                    "username": {"type": "str"},
                    "password": {"type": "str"},
                    "port": {"type": "int"},
                    "old_description": {"type": "str"},
                    "old_username": {"type": "str"},
                    "id": {"type": "str"},
                },
                "https_write": {
                    "type": "list",
                    "description": {"type": "str"},
                    "username": {"type": "str"},
                    "password": {"type": "str"},
                    "port": {"type": "int"},
                    "old_description": {"type": "str"},
                    "old_username": {"type": "str"},
                    "id": {"type": "str"},
                },
            },
            "assign_credentials_to_site": {
                "type": "dict",
                "cli_credential": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "username": {"type": "str"},
                    "id": {"type": "str"},
                },
                "snmp_v2c_read": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "username": {"type": "str"},
                    "id": {"type": "str"},
                },
                "snmp_v2c_write": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "id": {"type": "str"},
                },
                "snmp_v3": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "id": {"type": "str"},
                },
                "https_read": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "username": {"type": "str"},
                    "id": {"type": "str"},
                },
                "https_write": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "username": {"type": "str"},
                    "id": {"type": "str"},
                },
                "site_name": {"type": "list", "elements": "str"},
            },
            "apply_credentials_to_site": {
                "type": "dict",
                "cli_credential": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "username": {"type": "str"},
                    "id": {"type": "str"},
                },
                "snmp_v2c_read": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "username": {"type": "str"},
                    "id": {"type": "str"},
                },
                "snmp_v2c_write": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "id": {"type": "str"},
                },
                "snmp_v3": {
                    "type": "dict",
                    "description": {"type: 'str'"},
                    "id": {"type": "str"},
                },
                "site_name": {"type": "list", "elements": "str"},
            },
        }

        # Validate playbook params against the specification (temp_spec)
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.status = "failed"
            return self

        self.validated_config = valid_temp
        self.log(
            "Successfully validated playbook config params: {0}".format(valid_temp),
            "INFO",
        )
        self.msg = "Successfully validated input from the playbook"
        self.status = "success"
        return self

    def get_global_credentials_params(self):
        """
        Get the current Global Device Credentials from Cisco Catalyst Center.

        Parameters:
            self - The current object details.

        Returns:
            global_credentials (dict) - All global device credentials details.
        """

        try:
            global_credentials = self.dnac._exec(
                family="discovery",
                function="get_all_global_credentials",
            )
            global_credentials = global_credentials.get("response")
            self.log(
                "All global device credentials details: {0}".format(global_credentials),
                "DEBUG",
            )
        except Exception as msg:
            self.msg = "Exception occurred while getting global device credentials: {0}".format(
                msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return global_credentials

    def get_cli_params(self, cli_details):
        """
        Format the CLI parameters for the CLI credential configuration in Cisco Catalyst Center.

        Parameters:
            cli_details (list of dict) - Cisco Catalyst Center details containing CLI Credentials.

        Returns:
            cli_credential (list of dict) - Processed CLI credential data
            in the format suitable for the Cisco Catalyst Center config.
        """

        cli_credential = []

        for item in cli_details:
            if item is None:
                cli_credential.append(None)
            else:
                value = {
                    "username": item.get("username"),
                    "description": item.get("description"),
                    "id": item.get("id"),
                }
                cli_credential.append(value)
        return cli_credential

    def get_snmp_v2c_read_params(self, snmp_v2c_read_details):
        """
        Format the snmp_v2c_read parameters for the snmp_v2c_read
        credential configuration in Cisco Catalyst Center.

        Parameters:
            snmp_v2c_read_details (list of dict) - Cisco Catalyst Center
            Details containing snmp_v2c_read Credentials.

        Returns:
            snmp_v2c_read (list of dict) - Processed snmp_v2c_read credential
            data in the format suitable for the Cisco Catalyst Center config.
        """

        snmp_v2c_read = []

        for item in snmp_v2c_read_details:
            if item is None:
                snmp_v2c_read.append(None)
            else:
                value = {"description": item.get("description"), "id": item.get("id")}
                snmp_v2c_read.append(value)
        return snmp_v2c_read

    def get_snmp_v2c_write_params(self, snmp_v2c_write_details):
        """
        Format the snmp_v2c_write parameters for the snmp_v2c_write
        credential configuration in Cisco Catalyst Center.

        Parameters:
            snmp_v2c_write_details (list of dict) - Cisco Catalyst Center
            Details containing snmp_v2c_write Credentials.

        Returns:
            snmp_v2c_write (list of dict) - Processed snmp_v2c_write credential
            data in the format suitable for the Cisco Catalyst Center config.
        """

        snmp_v2c_write = []

        for item in snmp_v2c_write_details:
            if item is None:
                snmp_v2c_write.append(None)
            else:
                value = {"description": item.get("description"), "id": item.get("id")}
                snmp_v2c_write.append(value)
        return snmp_v2c_write

    def get_https_read_params(self, https_read_details):
        """
        Format the https_read parameters for the https_read
        credential configuration in Cisco Catalyst Center.

        Parameters:
            https_read_details (list of dict) - Cisco Catalyst Center
            Details containing https_read Credentials.

        Returns:
            https_read (list of dict) - Processed https_read credential
            data in the format suitable for the Cisco Catalyst Center config.
        """

        https_read = []

        for item in https_read_details:
            if item is None:
                https_read.append(None)
            else:
                value = {
                    "description": item.get("description"),
                    "username": item.get("username"),
                    "port": item.get("port"),
                    "id": item.get("id"),
                }
                https_read.append(value)
        return https_read

    def get_https_write_params(self, https_write_details):
        """
        Format the https_write parameters for the https_write
        credential configuration in Cisco Catalyst Center.

        Parameters:
            https_write_details (list of dict) - Cisco Catalyst Center
            Details containing https_write Credentials.

        Returns:
            https_write (list of dict) - Processed https_write credential
            data in the format suitable for the Cisco Catalyst Center config.
        """

        https_write = []

        for item in https_write_details:
            if item is None:
                https_write.append(None)
            else:
                value = {
                    "description": item.get("description"),
                    "username": item.get("username"),
                    "port": item.get("port"),
                    "id": item.get("id"),
                }
                https_write.append(value)
        return https_write

    def get_snmp_v3_params(self, snmp_v3_details):
        """
        Format the snmp_v3 parameters for the snmp_v3 credential configuration in Cisco Catalyst Center.

        Parameters:
            snmp_v3_details (list of dict) - Cisco Catalyst Center details containing snmp_v3 Credentials.

        Returns:
            snmp_v3 (list of dict) - Processed snmp_v3 credential
            data in the format suitable for the Cisco Catalyst Center config.
        """

        snmp_v3 = []

        for item in snmp_v3_details:
            if item is None:
                snmp_v3.append(None)
            else:
                value = {
                    "username": item.get("username"),
                    "description": item.get("description"),
                    "snmpMode": item.get("snmpMode"),
                    "id": item.get("id"),
                }
                if value.get("snmpMode") == "AUTHNOPRIV":
                    value["authType"] = item.get("authType")
                elif value.get("snmpMode") == "AUTHPRIV":
                    value.update(
                        {
                            "authType": item.get("authType"),
                            "privacyType": item.get("privacyType"),
                        }
                    )
                snmp_v3.append(value)
        return snmp_v3

    def get_cli_credentials(self, credential_details, global_credentials):
        """
        Get the current CLI Credential from
        Cisco Catalyst Center based on the provided playbook details.
        Check this API using the check_return_status.

        Parameters:
            credential_details (dict) - Playbook details containing Global Device Credentials.
            global_credentials (dict) - All global device credentials details.

        Returns:
            cli_details (List) - The current CLI credentials.
        """

        # playbook CLI Credential details
        all_cli = credential_details.get("cli_credential")
        # All CLI details from Cisco Catalyst Center
        global_cli_details = global_credentials.get("cliCredential")

        # Cisco Catalyst Center details for the CLI Credential given in the playbook
        cli_details = []

        if all_cli and global_cli_details:
            for cli_credential in all_cli:
                cli_detail = None
                cli_id = cli_credential.get("id")
                if cli_id:
                    cli_detail = get_dict_result(global_cli_details, "id", cli_id)
                    if not cli_detail:
                        self.msg = "CLI credential ID is invalid"
                        self.status = "failed"
                        return self.check_return_status()

                cli_description = cli_credential.get("description")
                cli_username = cli_credential.get("username")
                if cli_description and cli_username and (not cli_detail):
                    for item in global_cli_details:
                        if (
                            item.get("description") == cli_description
                            and item.get("username") == cli_username
                        ):
                            if cli_detail:
                                self.msg = (
                                    "There are multiple CLI credentials with the same description and username. "
                                    + "Kindly provide the ID for the global device credentials."
                                )
                                self.status = "failed"
                                return self.check_return_status()
                            cli_detail = item

                if not cli_detail:
                    cli_old_description = cli_credential.get("old_description")
                    cli_old_username = cli_credential.get("old_username")
                    if cli_old_description and cli_old_username and (not cli_detail):
                        for item in global_cli_details:
                            if (
                                item.get("description") == cli_old_description
                                and item.get("username") == cli_old_username
                            ):
                                if cli_detail:
                                    self.msg = (
                                        "There are multiple CLI credentials with the same old_description and old_username. "
                                        + "Kindly provide the ID for the global device credentials."
                                    )
                                    self.status = "failed"
                                    return self.check_return_status()
                                cli_detail = item
                        if not cli_detail:
                            self.msg = "CLI credential old_description or old_username is invalid"
                            self.status = "failed"
                            return self.check_return_status()

                cli_details.append(cli_detail)

        return cli_details

    def get_snmp_v2c_read_credentials(self, credential_details, global_credentials):
        """
        Get the current snmp_v2c_read Credential from
        Cisco Catalyst Center based on the provided playbook details.
        Check this API using the check_return_status.

        Parameters:
            credential_details (dict) - Playbook details containing Global Device Credentials.
            global_credentials (dict) - All global device credentials details.

        Returns:
            snmp_v2c_read_details (List) - The current snmp_v2c_read.
        """

        # Playbook snmp_v2c_read Credential details
        all_snmp_v2c_read = credential_details.get("snmp_v2c_read")

        # All snmp_v2c_read details from the Cisco Catalyst Center
        global_snmp_v2c_read_details = global_credentials.get("snmpV2cRead")

        # Cisco Catalyst Center details for the snmp_v2c_read Credential given in the playbook
        snmp_v2c_read_details = []

        if all_snmp_v2c_read and global_snmp_v2c_read_details:
            for snmp_v2c_read_credential in all_snmp_v2c_read:
                snmp_v2c_read_detail = None
                snmp_v2c_read_id = snmp_v2c_read_credential.get("id")
                if snmp_v2c_read_id:
                    snmp_v2c_read_detail = get_dict_result(
                        global_snmp_v2c_read_details, "id", snmp_v2c_read_id
                    )
                    if not snmp_v2c_read_detail:
                        self.msg = "snmp_v2c_read credential ID is invalid"
                        self.status = "failed"
                        return self.check_return_status()

                snmp_v2c_read_description = snmp_v2c_read_credential.get("description")
                if snmp_v2c_read_description and (not snmp_v2c_read_detail):
                    snmp_v2c_read_detail = get_dict_result(
                        global_snmp_v2c_read_details,
                        "description",
                        snmp_v2c_read_description,
                    )

                if not snmp_v2c_read_detail:
                    snmp_v2c_read_old_description = snmp_v2c_read_credential.get(
                        "old_description"
                    )
                    if snmp_v2c_read_old_description and (not snmp_v2c_read_detail):
                        snmp_v2c_read_detail = get_dict_result(
                            global_snmp_v2c_read_details,
                            "description",
                            snmp_v2c_read_old_description,
                        )
                        if not snmp_v2c_read_detail:
                            self.msg = (
                                "snmp_v2c_read credential old_description is invalid"
                            )
                            self.status = "failed"
                            return self.check_return_status()

                snmp_v2c_read_details.append(snmp_v2c_read_detail)
        return snmp_v2c_read_details

    def get_snmp_v2c_write_credentials(self, credential_details, global_credentials):
        """
        Get the current snmp_v2c_write Credential from
        Cisco Catalyst Center based on the provided playbook details.
        Check this API using the check_return_status.

        Parameters:
            credential_details (dict) - Playbook details containing Global Device Credentials.
            global_credentials (dict) - All global device credentials details.

        Returns:
            snmp_v2c_write_details (List) - The current snmp_v2c_write.
        """

        # Playbook snmp_v2c_write Credential details
        all_snmp_v2c_write = credential_details.get("snmp_v2c_write")

        # All snmp_v2c_write details from the Cisco Catalyst Center
        global_snmp_v2c_write_details = global_credentials.get("snmpV2cWrite")

        # Cisco Catalyst Center details for the snmp_v2c_write Credential given in the playbook
        snmp_v2c_write_details = []

        if all_snmp_v2c_write and global_snmp_v2c_write_details:
            for snmp_v2c_write_credential in all_snmp_v2c_write:
                snmp_v2c_write_detail = None
                snmp_v2c_write_id = snmp_v2c_write_credential.get("id")
                if snmp_v2c_write_id:
                    snmp_v2c_write_detail = get_dict_result(
                        global_snmp_v2c_write_details, "id", snmp_v2c_write_id
                    )
                    if not snmp_v2c_write_detail:
                        self.msg = "snmp_v2c_write credential ID is invalid"
                        self.status = "failed"
                        return self.check_return_status()

                snmp_v2c_write_description = snmp_v2c_write_credential.get(
                    "description"
                )

                if snmp_v2c_write_description and (not snmp_v2c_write_detail):
                    snmp_v2c_write_detail = get_dict_result(
                        global_snmp_v2c_write_details,
                        "description",
                        snmp_v2c_write_description,
                    )

                if not snmp_v2c_write_detail:
                    snmp_v2c_write_old_description = snmp_v2c_write_credential.get(
                        "old_description"
                    )
                    if snmp_v2c_write_old_description and (not snmp_v2c_write_detail):
                        snmp_v2c_write_detail = get_dict_result(
                            global_snmp_v2c_write_details,
                            "description",
                            snmp_v2c_write_old_description,
                        )
                        if not snmp_v2c_write_detail:
                            self.msg = (
                                "snmp_v2c_write credential old_description is invalid "
                            )
                            self.status = "failed"
                            return self.check_return_status()

                snmp_v2c_write_details.append(snmp_v2c_write_detail)
        return snmp_v2c_write_details

    def get_https_read_credentials(self, credential_details, global_credentials):
        """
        Get the current https_read Credential from
        Cisco Catalyst Center based on the provided playbook details.
        Check this API using the check_return_status.

        Parameters:
            credential_details (dict) - Playbook details containing Global Device Credentials.
            global_credentials (dict) - All global device credentials details.

        Returns:
            https_read_details (List) - The current https_read.
        """

        # Playbook https_read Credential details
        all_https_read = credential_details.get("https_read")

        # All https_read details from the Cisco Catalyst Center
        global_https_read_details = global_credentials.get("httpsRead")

        # Cisco Catalyst Center details for the https_read Credential given in the playbook
        https_read_details = []

        if all_https_read and global_https_read_details:
            for https_read_credential in all_https_read:
                https_read__detail = None
                https_read_id = https_read_credential.get("id")
                if https_read_id:
                    https_read__detail = get_dict_result(
                        global_https_read_details, "id", https_read_id
                    )
                    if not https_read__detail:
                        self.msg = "https_read credential Id is invalid"
                        self.status = "failed"
                        return self.check_return_status()

                https_read_description = https_read_credential.get("description")
                https_read_username = https_read_credential.get("username")

                if (
                    https_read_description
                    and https_read_username
                    and (not https_read__detail)
                ):
                    for item in global_https_read_details:
                        if (
                            item.get("description") == https_read_description
                            and item.get("username") == https_read_username
                        ):
                            if https_read__detail:
                                self.msg = (
                                    "There are multiple https_read credentials with the same description and username. "
                                    + "Kindly provide the ID for the global device credentials."
                                )
                                self.status = "failed"
                                return self.check_return_status()
                            https_read__detail = item

                if not https_read__detail:
                    https_read_old_description = https_read_credential.get(
                        "old_description"
                    )
                    https_read_old_username = https_read_credential.get("old_username")
                    if (
                        https_read_old_description
                        and https_read_old_username
                        and (not https_read__detail)
                    ):
                        for item in global_https_read_details:
                            if (
                                item.get("description") == https_read_old_description
                                and item.get("username") == https_read_old_username
                            ):
                                if https_read__detail:
                                    self.msg = (
                                        "There are multiple https_read credentials with the same old_description and old_username. "
                                        + "Kindly provide the ID for the global device credentials."
                                    )
                                    self.status = "failed"
                                    return self.check_return_status()
                                https_read__detail = item
                        if not https_read__detail:
                            self.msg = "https_read credential old_description or old_username is invalid"
                            self.status = "failed"
                            return self.check_return_status()

                https_read_details.append(https_read__detail)
        return https_read_details

    def get_https_write_credentials(self, credential_details, global_credentials):
        """
        Get the current https_write Credential from
        Cisco Catalyst Center based on the provided playbook details.
        Check this API using the check_return_status.

        Parameters:
            credential_details (dict) - Playbook details containing Global Device Credentials.
            global_credentials (dict) - All global device credentials details.

        Returns:
            https_write_details (List) - The current https_write.
        """

        # Playbook https_write Credential details
        all_https_write = credential_details.get("https_write")

        # All https_write details from the Cisco Catalyst Center
        global_https_write_details = global_credentials.get("httpsWrite")

        # Cisco Catalyst Center details for the https_write Credential given in the playbook
        https_write_details = []

        if all_https_write and global_https_write_details:
            for https_write_credential in all_https_write:
                https_write_detail = None
                https_write_id = https_write_credential.get("id")
                if https_write_id:
                    https_write_detail = get_dict_result(
                        global_https_write_details, "id", https_write_id
                    )
                    if not https_write_detail:
                        self.msg = "https_write credential Id is invalid"
                        self.status = "failed"
                        return self.check_return_status()

                https_write_description = https_write_credential.get("description")
                https_write_username = https_write_credential.get("username")
                if (
                    https_write_description
                    and https_write_username
                    and (not https_write_detail)
                ):
                    for item in global_https_write_details:
                        if (
                            item.get("description") == https_write_description
                            and item.get("username") == https_write_username
                        ):
                            if https_write_detail:
                                self.msg = (
                                    "There are multiple https_write credentials with the same description and username. "
                                    + "Kindly provide the ID for the global device credentials."
                                )
                                self.status = "failed"
                                return self.check_return_status()
                            https_write_detail = item

                if not https_write_detail:
                    https_write_old_description = https_write_credential.get(
                        "old_description"
                    )
                    https_write_old_username = https_write_credential.get(
                        "old_username"
                    )
                    if (
                        https_write_old_description
                        and https_write_old_username
                        and (not https_write_detail)
                    ):
                        for item in global_https_write_details:
                            if (
                                item.get("description") == https_write_old_description
                                and item.get("username") == https_write_old_username
                            ):
                                if https_write_detail:
                                    self.msg = (
                                        "There are multiple https_write credentials with the same old_description and old_username. "
                                        + "Kindly provide the ID for the global device credentials."
                                    )
                                    self.status = "failed"
                                    return self.check_return_status()
                                https_write_detail = item

                        if not https_write_detail:
                            self.msg = (
                                "https_write credential old_description or "
                                + "old_username is invalid"
                            )
                            self.status = "failed"
                            return self.check_return_status()

                https_write_details.append(https_write_detail)
        return https_write_details

    def get_snmp_v3_credentials(self, credential_details, global_credentials):
        """
        Get the current snmp_v3 Credential from
        Cisco Catalyst Center based on the provided playbook details.
        Check this API using the check_return_status.

        Parameters:
            credential_details (dict) - Playbook details containing Global Device Credentials.
            global_credentials (dict) - All global device credentials details.

        Returns:
            snmp_v3_details (List) - The current snmp_v3.
        """

        # Playbook snmp_v3 Credential details
        all_snmp_v3 = credential_details.get("snmp_v3")

        # All snmp_v3 details from the Cisco Catalyst Center
        global_snmp_v3_details = global_credentials.get("snmpV3")

        # Cisco Catalyst Center details for the snmp_v3 Credential given in the playbook
        snmp_v3_details = []

        if all_snmp_v3 and global_snmp_v3_details:
            for snmp_v3_credential in all_snmp_v3:
                snmp_v3_detail = None
                snmp_v3_id = snmp_v3_credential.get("id")
                if snmp_v3_id:
                    snmp_v3_detail = get_dict_result(
                        global_snmp_v3_details, "id", snmp_v3_id
                    )
                    if not snmp_v3_detail:
                        self.msg = "snmp_v3 credential id is invalid"
                        self.status = "failed"
                        return self.check_return_status()

                snmp_v3_description = snmp_v3_credential.get("description")

                if snmp_v3_description and (not snmp_v3_detail):
                    snmp_v3_detail = get_dict_result(
                        global_snmp_v3_details, "description", snmp_v3_description
                    )

                if not snmp_v3_detail:
                    snmp_v3_old_description = snmp_v3_credential.get("old_description")
                    if snmp_v3_old_description and (not snmp_v3_detail):
                        snmp_v3_detail = get_dict_result(
                            global_snmp_v3_details,
                            "description",
                            snmp_v3_old_description,
                        )
                        if not snmp_v3_detail:
                            self.msg = "snmp_v3 credential old_description is invalid"
                            self.status = "failed"
                            return self.check_return_status()

                snmp_v3_details.append(snmp_v3_detail)
        return snmp_v3_details

    def get_have_device_credentials(self, credential_details):
        """
        Get the current Global Device Credentials from
        Cisco Catalyst Center based on the provided playbook details.
        Check this API using the check_return_status.

        Parameters:
            credential_details (dict) - Playbook details containing Global Device Credentials.

        Returns:
            self - The current object with updated information.
        """

        global_credentials = self.get_global_credentials_params()
        cli_details = self.get_cli_credentials(credential_details, global_credentials)
        snmp_v2c_read_details = self.get_snmp_v2c_read_credentials(
            credential_details, global_credentials
        )
        snmp_v2c_write_details = self.get_snmp_v2c_write_credentials(
            credential_details, global_credentials
        )
        https_read_details = self.get_https_read_credentials(
            credential_details, global_credentials
        )
        https_write_details = self.get_https_write_credentials(
            credential_details, global_credentials
        )
        snmp_v3_details = self.get_snmp_v3_credentials(
            credential_details, global_credentials
        )
        self.have.update({"global_credential": {}})

        if cli_details:
            cli_credential = self.get_cli_params(cli_details)
            self.have.get("global_credential").update({"cliCredential": cli_credential})

        if snmp_v2c_read_details:
            snmp_v2c_read = self.get_snmp_v2c_read_params(snmp_v2c_read_details)
            self.have.get("global_credential").update({"snmpV2cRead": snmp_v2c_read})

        if snmp_v2c_write_details:
            snmp_v2c_write = self.get_snmp_v2c_write_params(snmp_v2c_write_details)
            self.have.get("global_credential").update({"snmpV2cWrite": snmp_v2c_write})

        if https_read_details:
            https_read = self.get_https_read_params(https_read_details)
            self.have.get("global_credential").update({"httpsRead": https_read})

        if https_write_details:
            https_write = self.get_https_write_params(https_write_details)
            self.have.get("global_credential").update({"httpsWrite": https_write})

        if snmp_v3_details:
            snmp_v3 = self.get_snmp_v3_params(snmp_v3_details)
            self.have.get("global_credential").update({"snmpV3": snmp_v3})

        self.log(
            "Global device credential details: {0}".format(
                self.have.get("global_credential")
            ),
            "DEBUG",
        )
        self.msg = "Collected the Global Device Credential Details from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_have(self, config):
        """
        Get the current Global Device Credentials and
        Device Credentials assigned to a site in Cisco Catalyst Center.

        Parameters:
            config (dict) - Playbook details containing Global Device
            Credentials configurations and Device Credentials should
            be assigned to a site.

        Returns:
            self - The current object with updated information of Global
            Device Credentials and Device Credentials assigned to a site.
        """

        if config.get("global_credential_details") is not None:
            credential_details = config.get("global_credential_details")
            self.get_have_device_credentials(credential_details).check_return_status()

        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.msg = "Successfully retrieved the details from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_want_device_credentials(self, credential_details):
        """
        Get the Global Device Credentials from the playbook.
        Check this API using the check_return_status.

        Parameters:
            credential_details (dict) - Playbook details containing Global Device Credentials.

        Returns:
            self - The current object with updated information of
            Global Device Credentials from the playbook.
        """

        want = {"want_create": {}, "want_update": {}}

        if credential_details.get("cli_credential"):
            cli = credential_details.get("cli_credential")
            have_cli_ptr = 0
            create_cli_ptr = 0
            update_cli_ptr = 0
            values = ["password", "description", "username", "id"]
            have_cli_credential = self.have.get("global_credential").get(
                "cliCredential"
            )

            for item in cli:
                if not have_cli_credential or have_cli_credential[have_cli_ptr] is None:
                    if want.get("want_create").get("cliCredential") is None:
                        want.get("want_create").update({"cliCredential": []})
                    create_credential = want.get("want_create").get("cliCredential")
                    create_credential.append({})
                    for i in range(0, 3):
                        if item.get(values[i]):
                            create_credential[create_cli_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            self.msg = (
                                values[i]
                                + " is mandatory for creating cli_credential "
                                + str(have_cli_ptr)
                            )
                            self.status = "failed"
                            return self

                    if item.get("enable_password"):
                        create_credential[create_cli_ptr].update(
                            {"enablePassword": item.get("enable_password")}
                        )
                    create_cli_ptr = create_cli_ptr + 1
                else:
                    if want.get("want_update").get("cliCredential") is None:
                        want.get("want_update").update({"cliCredential": []})
                    update_credential = want.get("want_update").get("cliCredential")
                    update_credential.append({})
                    if item.get("password"):
                        update_credential[update_cli_ptr].update(
                            {"password": item.get("password")}
                        )
                    else:
                        self.msg = (
                            "password is mandatory for updating cli_credential "
                            + str(have_cli_ptr)
                        )
                        self.status = "failed"
                        return self

                    for i in range(1, 4):
                        if item.get(values[i]):
                            update_credential[update_cli_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            update_credential[update_cli_ptr].update(
                                {
                                    values[i]: self.have.get("global_credential")
                                    .get("cliCredential")[have_cli_ptr]
                                    .get(values[i])
                                }
                            )

                    if item.get("enable_password"):
                        update_credential[update_cli_ptr].update(
                            {"enablePassword": item.get("enable_password")}
                        )
                    update_cli_ptr = update_cli_ptr + 1
                have_cli_ptr = have_cli_ptr + 1

        if credential_details.get("snmp_v2c_read"):
            snmp_v2c_read = credential_details.get("snmp_v2c_read")
            have_snmpv2cread_ptr = 0
            create_snmpv2cread_ptr = 0
            update_snmpv2cread_ptr = 0
            values = ["read_community", "description", "id"]
            keys = ["readCommunity", "description", "id"]
            have_snmp_v2c_read = self.have.get("global_credential").get("snmpV2cRead")

            for item in snmp_v2c_read:
                if (
                    not have_snmp_v2c_read
                    or have_snmp_v2c_read[have_snmpv2cread_ptr] is None
                ):
                    if want.get("want_create").get("snmpV2cRead") is None:
                        want.get("want_create").update({"snmpV2cRead": []})
                    create_credential = want.get("want_create").get("snmpV2cRead")
                    create_credential.append({})
                    for i in range(0, 2):
                        if item.get(values[i]):
                            create_credential[create_snmpv2cread_ptr].update(
                                {keys[i]: item.get(values[i])}
                            )
                        else:
                            self.msg = (
                                values[i]
                                + " is mandatory for creating snmp_v2c_read "
                                + str(have_snmpv2cread_ptr)
                            )
                            self.status = "failed"
                            return self
                    create_snmpv2cread_ptr = create_snmpv2cread_ptr + 1
                else:
                    if want.get("want_update").get("snmpV2cRead") is None:
                        want.get("want_update").update({"snmpV2cRead": []})
                    update_credential = want.get("want_update").get("snmpV2cRead")
                    update_credential.append({})
                    if item.get("read_community"):
                        update_credential[update_snmpv2cread_ptr].update(
                            {"readCommunity": item.get("read_community")}
                        )
                    else:
                        self.msg = (
                            "read_community is mandatory for updating snmp_v2c_read "
                            + str(have_snmpv2cread_ptr)
                        )
                        self.status = "failed"
                        return self
                    for i in range(1, 3):
                        if item.get(values[i]):
                            update_credential[update_snmpv2cread_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            update_credential[update_snmpv2cread_ptr].update(
                                {
                                    values[i]: self.have.get("global_credential")
                                    .get("snmpV2cRead")[have_snmpv2cread_ptr]
                                    .get(values[i])
                                }
                            )
                    update_snmpv2cread_ptr = update_snmpv2cread_ptr + 1
                have_snmpv2cread_ptr = have_snmpv2cread_ptr + 1

        if credential_details.get("snmp_v2c_write"):
            snmp_v2c_write = credential_details.get("snmp_v2c_write")
            have_snmpv2cwrite_ptr = 0
            create_snmpv2cwrite_ptr = 0
            update_snmpv2cwrite_ptr = 0
            values = ["write_community", "description", "id"]
            keys = ["writeCommunity", "description", "id"]
            have_snmp_v2c_write = self.have.get("global_credential").get("snmpV2cWrite")

            for item in snmp_v2c_write:
                if (
                    not have_snmp_v2c_write
                    or have_snmp_v2c_write[have_snmpv2cwrite_ptr] is None
                ):
                    if want.get("want_create").get("snmpV2cWrite") is None:
                        want.get("want_create").update({"snmpV2cWrite": []})
                    create_credential = want.get("want_create").get("snmpV2cWrite")
                    create_credential.append({})
                    for i in range(0, 2):
                        if item.get(values[i]):
                            create_credential[create_snmpv2cwrite_ptr].update(
                                {keys[i]: item.get(values[i])}
                            )
                        else:
                            self.msg = (
                                values[i]
                                + " is mandatory for creating snmp_v2c_write "
                                + str(have_snmpv2cwrite_ptr)
                            )
                            self.status = "failed"
                            return self
                    create_snmpv2cwrite_ptr = create_snmpv2cwrite_ptr + 1
                else:
                    if want.get("want_update").get("snmpV2cWrite") is None:
                        want.get("want_update").update({"snmpV2cWrite": []})
                    update_credential = want.get("want_update").get("snmpV2cWrite")
                    update_credential.append({})
                    if item.get("write_community"):
                        update_credential[update_snmpv2cwrite_ptr].update(
                            {"writeCommunity": item.get("write_community")}
                        )
                    else:
                        self.msg = (
                            "write_community is mandatory for updating snmp_v2c_write "
                            + str(have_snmpv2cwrite_ptr)
                        )
                        self.status = "failed"
                        return self
                    for i in range(1, 3):
                        if item.get(values[i]):
                            update_credential[update_snmpv2cwrite_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            update_credential[update_snmpv2cwrite_ptr].update(
                                {
                                    values[i]: self.have.get("global_credential")
                                    .get("snmpV2cWrite")[have_snmpv2cwrite_ptr]
                                    .get(values[i])
                                }
                            )
                    update_snmpv2cwrite_ptr = update_snmpv2cwrite_ptr + 1
                have_snmpv2cwrite_ptr = have_snmpv2cwrite_ptr + 1

        if credential_details.get("https_read"):
            https_read = credential_details.get("https_read")
            have_httpsread_ptr = 0
            create_httpsread_ptr = 0
            update_httpsread_ptr = 0
            values = ["password", "description", "username", "id", "port"]
            have_https_read = self.have.get("global_credential").get("httpsRead")

            for item in https_read:
                self.log(
                    "Global credentials details: {0}".format(
                        self.have.get("global_credential")
                    ),
                    "DEBUG",
                )
                if not have_https_read or have_https_read[have_httpsread_ptr] is None:
                    if want.get("want_create").get("httpsRead") is None:
                        want.get("want_create").update({"httpsRead": []})
                    create_credential = want.get("want_create").get("httpsRead")
                    create_credential.append({})
                    for i in range(0, 3):
                        if item.get(values[i]):
                            create_credential[create_httpsread_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            self.msg = (
                                values[i]
                                + " is mandatory for creating https_read "
                                + str(have_httpsread_ptr)
                            )
                            self.status = "failed"
                            return self
                    if item.get("port"):
                        create_credential[create_httpsread_ptr].update(
                            {"port": item.get("port")}
                        )
                    else:
                        create_credential[create_httpsread_ptr].update({"port": "443"})
                    create_httpsread_ptr = create_httpsread_ptr + 1
                else:
                    if want.get("want_update").get("httpsRead") is None:
                        want.get("want_update").update({"httpsRead": []})
                    update_credential = want.get("want_update").get("httpsRead")
                    update_credential.append({})
                    if item.get("password"):
                        update_credential[update_httpsread_ptr].update(
                            {"password": item.get("password")}
                        )
                    else:
                        self.msg = (
                            "The password is mandatory for updating https_read "
                            + str(have_httpsread_ptr)
                        )
                        self.status = "failed"
                        return self
                    for i in range(1, 5):
                        if item.get(values[i]):
                            update_credential[update_httpsread_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            update_credential[update_httpsread_ptr].update(
                                {
                                    values[i]: self.have.get("global_credential")
                                    .get("httpsRead")[have_httpsread_ptr]
                                    .get(values[i])
                                }
                            )
                    update_httpsread_ptr = update_httpsread_ptr + 1
                have_httpsread_ptr = have_httpsread_ptr + 1

        if credential_details.get("https_write"):
            https_write = credential_details.get("https_write")
            have_httpswrite_ptr = 0
            create_httpswrite_ptr = 0
            update_httpswrite_ptr = 0
            values = ["password", "description", "username", "id", "port"]
            have_https_write = self.have.get("global_credential").get("httpsWrite")

            for item in https_write:
                if (
                    not have_https_write
                    or have_https_write[have_httpswrite_ptr] is None
                ):
                    if want.get("want_create").get("httpsWrite") is None:
                        want.get("want_create").update({"httpsWrite": []})
                    create_credential = want.get("want_create").get("httpsWrite")
                    create_credential.append({})
                    for i in range(0, 3):
                        if item.get(values[i]):
                            create_credential[create_httpswrite_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            self.msg = (
                                values[i]
                                + " is mandatory for creating https_write "
                                + str(have_httpswrite_ptr)
                            )
                            self.status = "failed"
                            return self
                    if item.get("port"):
                        create_credential[create_httpswrite_ptr].update(
                            {"port": item.get("port")}
                        )
                    else:
                        create_credential[create_httpswrite_ptr].update({"port": "443"})
                    create_httpswrite_ptr = create_httpswrite_ptr + 1
                else:
                    if want.get("want_update").get("httpsWrite") is None:
                        want.get("want_update").update({"httpsWrite": []})
                    update_credential = want.get("want_update").get("httpsWrite")
                    update_credential.append({})
                    if item.get("password"):
                        update_credential[update_httpswrite_ptr].update(
                            {"password": item.get("password")}
                        )
                    else:
                        self.msg = (
                            "The password is mandatory for updating https_write "
                            + str(have_httpswrite_ptr)
                        )
                        self.status = "failed"
                        return self
                    for i in range(1, 5):
                        if item.get(values[i]):
                            update_credential[update_httpswrite_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            update_credential[update_httpswrite_ptr].update(
                                {
                                    values[i]: self.have.get("global_credential")
                                    .get("httpsWrite")[have_httpswrite_ptr]
                                    .get(values[i])
                                }
                            )
                    update_httpswrite_ptr = update_httpswrite_ptr + 1
                have_httpswrite_ptr = have_httpswrite_ptr + 1

        if credential_details.get("snmp_v3"):
            snmp_v3 = credential_details.get("snmp_v3")
            have_snmpv3_ptr = 0
            create_snmpv3_ptr = 0
            update_snmpv3_ptr = 0
            values = ["description", "username", "id"]
            have_snmp_v3 = self.have.get("global_credential").get("snmpV3")

            for item in snmp_v3:
                if not have_snmp_v3 or have_snmp_v3[have_snmpv3_ptr] is None:
                    if want.get("want_create").get("snmpV3") is None:
                        want.get("want_create").update({"snmpV3": []})
                    create_credential = want.get("want_create").get("snmpV3")
                    create_credential.append({})
                    for i in range(0, 2):
                        if item.get(values[i]):
                            create_credential[create_snmpv3_ptr].update(
                                {values[i]: item.get(values[i])}
                            )
                        else:
                            self.msg = (
                                values[i]
                                + " is mandatory for creating snmp_v3 "
                                + str(have_snmpv3_ptr)
                            )
                            self.status = "failed"
                            return self
                    if item.get("snmp_mode"):
                        create_credential[create_snmpv3_ptr].update(
                            {"snmpMode": item.get("snmp_mode")}
                        )
                    else:
                        create_credential[create_snmpv3_ptr].update(
                            {"snmpMode": "AUTHPRIV"}
                        )
                    if (
                        create_credential[create_snmpv3_ptr].get("snmpMode")
                        == "AUTHNOPRIV"
                        or create_credential[create_snmpv3_ptr].get("snmpMode")
                        == "AUTHPRIV"
                    ):
                        auths = ["auth_password", "auth_type"]
                        keys = {
                            "auth_password": "authPassword",
                            "auth_type": "authType",
                        }
                        for auth in auths:
                            if item.get(auth):
                                create_credential[create_snmpv3_ptr].update(
                                    {keys[auth]: item.get(auth)}
                                )
                            else:
                                self.msg = (
                                    auth
                                    + " is mandatory for creating snmp_v3 "
                                    + str(have_snmpv3_ptr)
                                )
                                self.status = "failed"
                                return self
                        if len(item.get("auth_password")) < 8:
                            self.msg = "auth_password length should be greater than 8"
                            self.status = "failed"
                            return self
                        self.log(
                            "snmp_mode: {0}".format(
                                create_credential[create_snmpv3_ptr].get("snmpMode")
                            ),
                            "DEBUG",
                        )
                    if (
                        create_credential[create_snmpv3_ptr].get("snmpMode")
                        == "AUTHPRIV"
                    ):
                        privs = ["privacy_password", "privacy_type"]
                        key = {
                            "privacy_password": "privacyPassword",
                            "privacy_type": "privacyType",
                        }
                        for priv in privs:
                            if item.get(priv):
                                create_credential[create_snmpv3_ptr].update(
                                    {key[priv]: item.get(priv)}
                                )
                            else:
                                self.msg = (
                                    priv
                                    + " is mandatory for creating snmp_v3 "
                                    + str(have_snmpv3_ptr)
                                )
                                self.status = "failed"
                                return self
                        if len(item.get("privacy_password")) < 8:
                            self.msg = "privacy_password should be greater than 8"
                            self.status = "failed"
                            return self
                    elif (
                        create_credential[create_snmpv3_ptr].get("snmpMode")
                        != "NOAUTHNOPRIV"
                    ):
                        self.msg = "snmp_mode in snmpV3 is not ['AUTHPRIV', 'AUTHNOPRIV', 'NOAUTHNOPRIV']"
                        self.status = "failed"
                        return self
                    create_snmpv3_ptr = create_snmpv3_ptr + 1
                else:
                    if want.get("want_update").get("snmpV3") is None:
                        want.get("want_update").update({"snmpV3": []})
                    update_credential = want.get("want_update").get("snmpV3")
                    update_credential.append({})
                    for value in values:
                        if item.get(value):
                            update_credential[update_snmpv3_ptr].update(
                                {value: item.get(value)}
                            )
                        else:
                            update_credential[update_snmpv3_ptr].update(
                                {
                                    value: self.have.get("global_credential")
                                    .get("snmpV3")[have_snmpv3_ptr]
                                    .get(value)
                                }
                            )
                    if item.get("snmp_mode"):
                        update_credential[update_snmpv3_ptr].update(
                            {"snmpMode": item.get("snmp_mode")}
                        )
                    if (
                        update_credential[update_snmpv3_ptr].get("snmpMode")
                        == "AUTHNOPRIV"
                        or update_credential[update_snmpv3_ptr].get("snmpMode")
                        == "AUTHPRIV"
                    ):
                        if item.get("auth_type"):
                            update_credential[update_snmpv3_ptr].update(
                                {"authType": item.get("auth_type")}
                            )
                        elif (
                            self.have.get("global_credential")
                            .get("snmpMode")[have_snmpv3_ptr]
                            .get("authType")
                        ):
                            update_credential[update_snmpv3_ptr].update(
                                {
                                    "authType": self.have.get("global_credential")
                                    .get("snmpMode")[have_snmpv3_ptr]
                                    .get("authType")
                                }
                            )
                        else:
                            self.msg = (
                                "auth_type is required for updating snmp_v3 "
                                + str(have_snmpv3_ptr)
                            )
                            self.status = "failed"
                            return self
                        if item.get("auth_password"):
                            update_credential[update_snmpv3_ptr].update(
                                {"authPassword": item.get("auth_password")}
                            )
                        else:
                            self.msg = (
                                "auth_password is required for updating snmp_v3 "
                                + str(have_snmpv3_ptr)
                            )
                            self.status = "failed"
                            return self
                        if len(item.get("auth_password")) < 8:
                            self.msg = "auth_password length should be greater than 8"
                            self.status = "failed"
                            return self
                    elif (
                        update_credential[update_snmpv3_ptr].get("snmpMode")
                        == "AUTHPRIV"
                    ):
                        if item.get("privacy_type"):
                            update_credential[update_snmpv3_ptr].update(
                                {"privacyType": item.get("privacy_type")}
                            )
                        elif (
                            self.have.get("global_credential")
                            .get("snmpMode")[have_snmpv3_ptr]
                            .get("privacyType")
                        ):
                            update_credential[update_snmpv3_ptr].update(
                                {
                                    "privacyType": self.have.get("global_credential")
                                    .get("snmpMode")[have_snmpv3_ptr]
                                    .get("privacyType")
                                }
                            )
                        else:
                            self.msg = (
                                "privacy_type is required for updating snmp_v3 "
                                + str(have_snmpv3_ptr)
                            )
                            self.status = "failed"
                            return self
                        if item.get("privacy_password"):
                            update_credential[update_snmpv3_ptr].update(
                                {"privacyPassword": item.get("privacy_password")}
                            )
                        else:
                            self.msg = (
                                "privacy_password is required for updating snmp_v3 "
                                + str(have_snmpv3_ptr)
                            )
                            self.status = "failed"
                            return self
                        if len(item.get("privacy_password")) < 8:
                            self.msg = (
                                "privacy_password length should be greater than 8"
                            )
                            self.status = "failed"
                            return self
                    update_snmpv3_ptr = update_snmpv3_ptr + 1
                have_snmpv3_ptr = have_snmpv3_ptr + 1
        self.want.update(want)
        self.msg = "Collected the Global Credentials from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_want_assign_credentials(self, assign_credentials):
        """
        Get the Credentials to be assigned to a site from the playbook.
        Check this API using the check_return_status.

        Parameters:
            assign_credentials (dict) - Playbook details containing
            credentials that need to be assigned to a site.

        Returns:
            self - The current object with updated information of credentials
            that need to be assigned to a site from the playbook.
        """
        want = {"assign_credentials": {}}

        current_ccc_version_as_int = self.get_ccc_version_as_integer()
        site_names = assign_credentials.get("site_name")

        if not site_names:
            self.msg = (
                "The 'site_name' is required parameter for 'assign_credentials_to_site'"
            )
            self.status = "failed"
            return self

        site_ids = []
        for site_name in site_names:
            site_exists, current_site_id = self.get_site_id(site_name)
            if not current_site_id:
                self.msg = "The site_name '{0}' is invalid in 'assign_credentials_to_site'".format(
                    site_name
                )
                self.status = "failed"
                return self
            site_ids.append(current_site_id)

        want.update({"site_id": site_ids})
        global_credentials = self.get_global_credentials_params()
        cli_credential = assign_credentials.get("cli_credential")

        if cli_credential:
            cli_id = cli_credential.get("id")
            cli_description = cli_credential.get("description")
            cli_username = cli_credential.get("username")

            if cli_id or cli_description and cli_username:
                # All CLI details from the Cisco Catalyst Center
                global_cli_details = global_credentials.get("cliCredential")

                if not global_cli_details:
                    self.msg = "Global CLI credential is not available"
                    self.status = "failed"
                    return self
                cli_detail = None

                if cli_id:
                    cli_detail = get_dict_result(global_cli_details, "id", cli_id)
                    if not cli_detail:
                        self.msg = "The ID for the CLI credential is not valid."
                        self.status = "failed"
                        return self
                elif cli_description and cli_username:
                    for item in global_cli_details:
                        if (
                            item.get("description") == cli_description
                            and item.get("username") == cli_username
                        ):
                            cli_detail = item
                    if not cli_detail:
                        self.msg = "The username and description of the CLI credential are invalid"
                        self.status = "failed"
                        return self

                if current_ccc_version_as_int <= self.get_ccc_version_as_int_from_str(
                    "2.3.5.3"
                ):
                    want.get("assign_credentials").update(
                        {"cliId": cli_detail.get("id")}
                    )
                else:
                    want.get("assign_credentials").update(
                        {"cliCredentialsId": {"credentialsId": cli_detail.get("id")}}
                    )

        snmp_v2c_read = assign_credentials.get("snmp_v2c_read")
        if snmp_v2c_read:
            snmp_v2c_read_id = snmp_v2c_read.get("id")
            snmp_v2c_read_description = snmp_v2c_read.get("description")

            if snmp_v2c_read_id or snmp_v2c_read_description:
                # All snmp_v2c_read details from the Cisco Catalyst Center
                global_snmp_v2c_read_details = global_credentials.get("snmpV2cRead")
                if not global_snmp_v2c_read_details:
                    self.msg = "Global snmp_v2c_read credential is not available"
                    self.status = "failed"
                    return self
                snmp_v2c_read_detail = None

                if snmp_v2c_read_id:
                    snmp_v2c_read_detail = get_dict_result(
                        global_snmp_v2c_read_details, "id", snmp_v2c_read_id
                    )
                    if not snmp_v2c_read_detail:
                        self.msg = (
                            "The ID of the snmp_v2c_read credential is not valid."
                        )
                        self.status = "failed"
                        return self
                elif snmp_v2c_read_description:
                    for item in global_snmp_v2c_read_details:
                        if item.get("description") == snmp_v2c_read_description:
                            snmp_v2c_read_detail = item
                    if not snmp_v2c_read_detail:
                        self.msg = "The username and description for the snmp_v2c_read credential are invalid."
                        self.status = "failed"
                        return self

                if current_ccc_version_as_int <= self.get_ccc_version_as_int_from_str(
                    "2.3.5.3"
                ):
                    want.get("assign_credentials").update(
                        {"snmpV2ReadId": snmp_v2c_read_detail.get("id")}
                    )
                else:
                    want.get("assign_credentials").update(
                        {
                            "snmpv2cReadCredentialsId": {
                                "credentialsId": snmp_v2c_read_detail.get("id")
                            }
                        }
                    )

        snmp_v2c_write = assign_credentials.get("snmp_v2c_write")
        if snmp_v2c_write:
            snmp_v2c_write_id = snmp_v2c_write.get("id")
            snmp_v2c_write_description = snmp_v2c_write.get("description")
            if snmp_v2c_write_id or snmp_v2c_write_description:
                # All snmp_v2c_write details from the Cisco Catalyst Center
                global_snmp_v2c_write_details = global_credentials.get("snmpV2cWrite")

                if not global_snmp_v2c_write_details:
                    self.msg = "Global snmp_v2c_write Credential is not available"
                    self.status = "failed"
                    return self
                snmp_v2c_write_detail = None

                if snmp_v2c_write_id:
                    snmp_v2c_write_detail = get_dict_result(
                        global_snmp_v2c_write_details, "id", snmp_v2c_write_id
                    )
                    if not snmp_v2c_write_detail:
                        self.msg = "The ID of the snmp_v2c_write credential is invalid."
                        self.status = "failed"
                        return self
                elif snmp_v2c_write_description:
                    for item in global_snmp_v2c_write_details:
                        if item.get("description") == snmp_v2c_write_description:
                            snmp_v2c_write_detail = item

                    if not snmp_v2c_write_detail:
                        self.msg = "The username and description of the snmp_v2c_write credential are invalid."
                        self.status = "failed"
                        return self

                if current_ccc_version_as_int <= self.get_ccc_version_as_int_from_str(
                    "2.3.5.3"
                ):
                    want.get("assign_credentials").update(
                        {"snmpV2WriteId": snmp_v2c_write_detail.get("id")}
                    )
                else:
                    want.get("assign_credentials").update(
                        {
                            "snmpv2cWriteCredentialsId": {
                                "credentialsId": snmp_v2c_write_detail.get("id")
                            }
                        }
                    )

        https_read = assign_credentials.get("https_read")
        if https_read:
            https_read_id = https_read.get("id")
            https_read_description = https_read.get("description")
            https_read_username = https_read.get("username")

            if https_read_id or https_read_description and https_read_username:
                # All httpRead details from the Cisco Catalyst Center
                global_https_read_details = global_credentials.get("httpsRead")
                if not global_https_read_details:
                    self.msg = "Global https_read Credential is not available."
                    self.status = "failed"
                    return self
                https_read_detail = None

                if https_read_id:
                    https_read_detail = get_dict_result(
                        global_https_read_details, "id", https_read_id
                    )
                    if not https_read_detail:
                        self.msg = "The ID of the https_read credential is not valid."
                        self.status = "failed"
                        return self
                elif https_read_description and https_read_username:
                    for item in global_https_read_details:
                        if (
                            item.get("description") == https_read_description
                            and item.get("username") == https_read_username
                        ):
                            https_read_detail = item

                    if not https_read_detail:
                        self.msg = "The description and username for the https_read credential are invalid."
                        self.status = "failed"
                        return self

                if current_ccc_version_as_int <= self.get_ccc_version_as_int_from_str(
                    "2.3.5.3"
                ):
                    want.get("assign_credentials").update(
                        {"httpRead": https_read_detail.get("id")}
                    )
                else:
                    want.get("assign_credentials").update(
                        {
                            "httpReadCredentialsId": {
                                "credentialsId": https_read_detail.get("id")
                            }
                        }
                    )

        https_write = assign_credentials.get("https_write")
        if https_write:
            https_write_id = https_write.get("id")
            https_write_description = https_write.get("description")
            https_write_username = https_write.get("username")

            if https_write_id or https_write_description and https_write_username:
                # All httpWrite details from the Cisco Catalyst Center
                global_https_write_details = global_credentials.get("httpsWrite")
                if not global_https_write_details:
                    self.msg = "Global https_write credential is not available."
                    self.status = "failed"
                    return self
                https_write_detail = None

                if https_write_id:
                    https_write_detail = get_dict_result(
                        global_https_write_details, "id", https_write_id
                    )
                    if not https_write_detail:
                        self.msg = "The ID of the https_write credential is not valid."
                        self.status = "failed"
                        return self
                elif https_write_description and https_write_username:
                    for item in global_https_write_details:
                        if (
                            item.get("description") == https_write_description
                            and item.get("username") == https_write_username
                        ):
                            https_write_detail = item

                    if not https_write_detail:
                        self.msg = "The description and username for the https_write credential are invalid."
                        self.status = "failed"
                        return self

                if current_ccc_version_as_int <= self.get_ccc_version_as_int_from_str(
                    "2.3.5.3"
                ):
                    want.get("assign_credentials").update(
                        {"httpWrite": https_write_detail.get("id")}
                    )
                else:
                    want.get("assign_credentials").update(
                        {
                            "httpWriteCredentialsId": {
                                "credentialsId": https_write_detail.get("id")
                            }
                        }
                    )

        snmp_v3 = assign_credentials.get("snmp_v3")
        if snmp_v3:
            snmp_v3_id = snmp_v3.get("id")
            snmp_v3_description = snmp_v3.get("description")
            if snmp_v3_id or snmp_v3_description:
                # All snmp_v3 details from the Cisco Catalyst Center
                global_snmp_v3_details = global_credentials.get("snmpV3")

                if not global_snmp_v3_details:
                    self.msg = "Global snmp_v3 Credential is not available."
                    self.status = "failed"
                    return self
                snmp_v3_detail = None

                if snmp_v3_id:
                    snmp_v3_detail = get_dict_result(
                        global_snmp_v3_details, "id", snmp_v3_id
                    )
                    if not snmp_v3_detail:
                        self.msg = "The ID of the snmp_v3 credential is not valid."
                        self.status = "failed"
                        return self
                elif snmp_v3_description:
                    for item in global_snmp_v3_details:
                        if item.get("description") == snmp_v3_description:
                            snmp_v3_detail = item

                    if not snmp_v3_detail:
                        self.msg = "The username and description for the snmp_v3 credential are missing or invalid."
                        self.status = "failed"
                        return self

                if current_ccc_version_as_int <= self.get_ccc_version_as_int_from_str(
                    "2.3.5.3"
                ):
                    want.get("assign_credentials").update(
                        {"snmpV3Id": snmp_v3_detail.get("id")}
                    )
                else:
                    want.get("assign_credentials").update(
                        {
                            "snmpv3CredentialsId": {
                                "credentialsId": snmp_v3_detail.get("id")
                            }
                        }
                    )

        self.log("Desired State (want): {0}".format(want), "INFO")
        self.want.update(want)
        self.msg = "Collected the Credentials needed to be assigned from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_want_apply_credentials(self, apply_credentials):
        """
        Get the Credentials to be applied to a site from the playbook.
        Check this API using the check_return_status.

        Parameters:
            apply_credentials (dict) - Playbook details containing
            credentials that need to be applied to a site.

        Returns:
            self - The current object with updated information of credentials
            that need to be applied to a site from the playbook.
        """
        want = {"apply_credentials": {}}

        site_names = apply_credentials.get("site_name")
        if not site_names:
            self.msg = (
                "The 'site_name' is required parameter for 'apply_credentials_to_site'"
            )
            self.status = "failed"
            return self

        site_ids = []
        for site_name in site_names:
            site_exists, current_site_id = self.get_site_id(site_name)
            if not current_site_id:
                self.msg = "The site_name '{0}' is invalid in 'apply_credentials_to_site'".format(
                    site_name
                )
                self.status = "failed"
                return self
            site_ids.append(current_site_id)

        want.update({"site_id": site_ids})
        want.update({"site_name": site_names})
        global_credentials = self.get_global_credentials_params()
        cli_credential = apply_credentials.get("cli_credential")

        if cli_credential:
            cli_id = cli_credential.get("id")
            cli_description = cli_credential.get("description")
            cli_username = cli_credential.get("username")
            if cli_id or cli_description and cli_username:
                # All CLI details from the Cisco Catalyst Center
                global_cli_details = global_credentials.get("cliCredential")

                if not global_cli_details:
                    self.msg = "Global CLI credential is not available"
                    self.status = "failed"
                    return self
                cli_detail = None

                if cli_id:
                    cli_detail = get_dict_result(global_cli_details, "id", cli_id)
                    if not cli_detail:
                        self.msg = "The ID for the CLI credential is not valid."
                        self.status = "failed"
                        return self
                elif cli_description and cli_username:
                    for item in global_cli_details:
                        if (
                            item.get("description") == cli_description
                            and item.get("username") == cli_username
                        ):
                            cli_detail = item
                    if not cli_detail:
                        self.msg = "The username and description of the CLI credential are invalid"
                        self.status = "failed"
                        return self

                want["apply_credentials"]["cliId"] = cli_detail.get("id")

        snmp_v2c_read = apply_credentials.get("snmp_v2c_read")

        if snmp_v2c_read:
            snmp_v2c_read_id = snmp_v2c_read.get("id")
            snmp_v2c_read_description = snmp_v2c_read.get("description")
            if snmp_v2c_read_id or snmp_v2c_read_description:
                # All snmp_v2c_read details from the Cisco Catalyst Center
                global_snmp_v2c_read_details = global_credentials.get("snmpV2cRead")

                if not global_snmp_v2c_read_details:
                    self.msg = "Global snmp_v2c_read credential is not available"
                    self.status = "failed"
                    return self
                snmp_v2c_read_detail = None

                if snmp_v2c_read_id:
                    snmp_v2c_read_detail = get_dict_result(
                        global_snmp_v2c_read_details, "id", snmp_v2c_read_id
                    )
                    if not snmp_v2c_read_detail:
                        self.msg = (
                            "The ID of the snmp_v2c_read credential is not valid."
                        )
                        self.status = "failed"
                        return self
                elif snmp_v2c_read_description:
                    for item in global_snmp_v2c_read_details:
                        if item.get("description") == snmp_v2c_read_description:
                            snmp_v2c_read_detail = item
                    if not snmp_v2c_read_detail:
                        self.msg = "The username and description for the snmp_v2c_read credential are invalid."
                        self.status = "failed"
                        return self

                want["apply_credentials"]["snmpV2ReadId"] = snmp_v2c_read_detail.get(
                    "id"
                )

        snmp_v2c_write = apply_credentials.get("snmp_v2c_write")

        if snmp_v2c_write:
            snmp_v2c_write_id = snmp_v2c_write.get("id")
            snmp_v2c_write_description = snmp_v2c_write.get("description")
            if snmp_v2c_write_id or snmp_v2c_write_description:
                # All snmp_v2c_write details from the Cisco Catalyst Center
                global_snmp_v2c_write_details = global_credentials.get("snmpV2cWrite")

                if not global_snmp_v2c_write_details:
                    self.msg = "Global snmp_v2c_write Credential is not available"
                    self.status = "failed"
                    return self
                snmp_v2c_write_detail = None

                if snmp_v2c_write_id:
                    snmp_v2c_write_detail = get_dict_result(
                        global_snmp_v2c_write_details, "id", snmp_v2c_write_id
                    )
                    if not snmp_v2c_write_detail:
                        self.msg = "The ID of the snmp_v2c_write credential is invalid."
                        self.status = "failed"
                        return self
                elif snmp_v2c_write_description:
                    for item in global_snmp_v2c_write_details:
                        if item.get("description") == snmp_v2c_write_description:
                            snmp_v2c_write_detail = item
                    if not snmp_v2c_write_detail:
                        self.msg = "The username and description of the snmp_v2c_write credential are invalid."
                        self.status = "failed"
                        return self

                want["apply_credentials"]["snmpV2WriteId"] = snmp_v2c_write_detail.get(
                    "id"
                )

        snmp_v3 = apply_credentials.get("snmp_v3")

        if snmp_v3:
            snmp_v3_id = snmp_v3.get("id")
            snmp_v3_description = snmp_v3.get("description")
            if snmp_v3_id or snmp_v3_description:
                # All snmp_v3 details from the Cisco Catalyst Center
                global_snmp_v3_details = global_credentials.get("snmpV3")

                if not global_snmp_v3_details:
                    self.msg = "Global snmp_v3 Credential is not available."
                    self.status = "failed"
                    return self
                snmp_v3_detail = None

                if snmp_v3_id:
                    snmp_v3_detail = get_dict_result(
                        global_snmp_v3_details, "id", snmp_v3_id
                    )
                    if not snmp_v3_detail:
                        self.msg = "The ID of the snmp_v3 credential is not valid."
                        self.status = "failed"
                        return self
                elif snmp_v3_description:
                    for item in global_snmp_v3_details:
                        if item.get("description") == snmp_v3_description:
                            snmp_v3_detail = item
                    if not snmp_v3_detail:
                        self.msg = "The username and description for the snmp_v3 credential are missing or invalid."
                        self.status = "failed"
                        return self

                want["apply_credentials"]["snmpV3Id"] = snmp_v3_detail.get("id")

        self.log("Desired State (want): {0}".format(want), "INFO")
        self.want.update(want)
        self.msg = "Collected the Credentials needed to be applied from the Cisco Catalyst Center"
        self.status = "success"
        return self

    def get_want(self, config):
        """
        Get the current Global Device Credentials and Device
        Credentials assigned to a site form the playbook.

        Parameters:
            config (dict) - Playbook details containing Global Device
            Credentials configurations and Device Credentials should
            be assigned to a site.

        Returns:
            self - The current object with updated information of Global
            Device Credentials and Device Credentials assigned to a site.
        """

        if config.get("global_credential_details"):
            credential_details = config.get("global_credential_details")
            self.get_want_device_credentials(credential_details).check_return_status()

        if config.get("assign_credentials_to_site"):
            assign_credentials = config.get("assign_credentials_to_site")
            self.get_want_assign_credentials(assign_credentials).check_return_status()

        if config.get("apply_credentials_to_site"):
            apply_credentials = config.get("apply_credentials_to_site")
            self.get_want_apply_credentials(apply_credentials).check_return_status()

        self.log("Desired State (want): {0}".format(self.want), "INFO")
        self.msg = "Successfully retrieved details from the playbook"
        self.status = "success"
        return self

    def create_device_credentials(self):
        """
        Create Global Device Credential to the Cisco Catalyst
        Center based on the provided playbook details.
        Check the return value of the API with check_return_status().

        Parameters:
            self

        Returns:
            self
        """

        result_global_credential = self.result.get("response")[0].get(
            "global_credential"
        )
        want_create = self.want.get("want_create")
        if not want_create:
            result_global_credential.update(
                {
                    "No Creation": {
                        "response": "No Response",
                        "msg": "No Creation is available",
                    }
                }
            )
            return self

        credential_params = want_create
        self.log(
            "Creating global credential API input parameters: {0}".format(
                credential_params
            ),
            "DEBUG",
        )
        response = self.dnac._exec(
            family="discovery",
            function="create_global_credentials",
            op_modifies=True,
            params=credential_params,
        )
        self.log(
            "Received API response from 'create_global_credentials': {0}".format(
                response
            ),
            "DEBUG",
        )

        if self.get_ccc_version_as_integer() <= self.get_ccc_version_as_int_from_str(
            "2.3.5.3"
        ):
            validation_string = "global credential addition performed"
            self.check_task_response_status(
                response, validation_string, "create_global_credentials"
            ).check_return_status()
        else:
            self.check_tasks_response_status(
                response, "create_global_credentials"
            ).check_return_status()

        self.log("Global credential created successfully", "INFO")
        result_global_credential.update(
            {
                "Creation": {
                    "response": credential_params,
                    "msg": "Global Credential Created Successfully",
                }
            }
        )
        self.msg = "Global Device Credential Created Successfully"
        self.status = "success"
        return self

    def update_device_credentials(self):
        """
        Update Device Credential to the Cisco Catalyst Center based on the provided playbook details.
        Check the return value of the API with check_return_status().

        Parameters:
            self

        Returns:
            self
        """

        result_global_credential = self.result.get("response")[0].get(
            "global_credential"
        )

        # Get the result global credential and want_update from the current object
        want_update = self.want.get("want_update")
        # If no credentials to update, update the result and return
        if not want_update:
            result_global_credential.update(
                {
                    "No Updation": {
                        "response": "No Response",
                        "msg": "No Updation is available",
                    }
                }
            )
            self.msg = "No Updation is available"
            self.status = "success"
            return self
        i = 0
        flag = True
        values = [
            "cliCredential",
            "snmpV2cRead",
            "snmpV2cWrite",
            "httpsRead",
            "httpsWrite",
            "snmpV3",
        ]
        final_response = []
        self.log(
            "Desired State for global device credentials updation: {0}".format(
                want_update
            ),
            "DEBUG",
        )
        while flag:
            flag = False
            credential_params = {}
            for value in values:
                if want_update.get(value) and i < len(want_update.get(value)):
                    flag = True
                    credential_params.update({value: want_update.get(value)[i]})
            i = i + 1
            if credential_params:
                final_response.append(credential_params)
                response = self.dnac._exec(
                    family="discovery",
                    function="update_global_credentials_v2",
                    op_modifies=True,
                    params=credential_params,
                )
                self.log(
                    "Received API response for 'update_global_credentials_v2': {0}".format(
                        response
                    ),
                    "DEBUG",
                )

                if (
                    self.get_ccc_version_as_integer()
                    <= self.get_ccc_version_as_int_from_str("2.3.5.3")
                ):
                    validation_string = "global credential update performed"
                    self.check_task_response_status(
                        response, validation_string, "update_global_credentials_v2"
                    ).check_return_status()
                else:
                    self.check_tasks_response_status(
                        response, "update_global_credentials_v2"
                    ).check_return_status()

        self.log(
            "Updating device credential API input parameters: {0}".format(
                final_response
            ),
            "DEBUG",
        )
        self.log("Global device credential updated successfully", "INFO")
        result_global_credential.update(
            {
                "Updation": {
                    "response": final_response,
                    "msg": "Global Device Credential Updated Successfully",
                }
            }
        )
        self.msg = "Global Device Credential Updated Successfully"
        self.status = "success"
        return self

    def get_credential_value(self, input_value, global_value):
        """
        Determines the appropriate credential value to use for assignment.

        This method is used to resolve a credential field by prioritizing the following:
        - If the `input_value` is explicitly an empty dictionary `{}`, return `{}` as-is.
        - If the `input_value` is `None`, return the `global_value` if it exists.
        - Otherwise, return the `input_value`.

        This is useful when assigning credentials with fallbacks from global defaults,
        while still respecting explicit requests to nullify a field using `{}`.

        Parameters:
            input_value (any): The credential value provided in the input (can be a string, dict, or None).
            global_value (any): The global/default credential value to fall back on if `input_value` is None.

        Returns:
            any: The resolved credential value to use (could be `input_value`, `global_value`, or `{}`).
        """

        # Explicitly return the empty dictionary if input_value is {}
        if input_value == {}:
            return {}

        # If input_value is None, fall back to global_value (or return {} if global_value is None)
        if input_value is None:
            return global_value if global_value is not None else {}

        # Otherwise, return the input_value as-is
        return input_value

    def assign_device_cred_to_global_site(
        self, global_site_id, credential_params_template, result_assign_credential
    ):
        """
        Assigns device credentials to a given site. If the site is the global site, it fetches and assigns global credentials.
        Otherwise, it assigns credentials specific to the site based on the provided template.

        Parameters:
            self: Instance of the class.
            global_site_id (str): ID of the global site for reference.
            credential_params_template (dict): Template containing credential parameters.
            result_assign_credential (dict): Dictionary to store the result of the credential assignment.

        Returns:
            self: Updated instance with assignment status and messages.
        """

        self.log(
            "Starting the process to assign device credentials to the global site. "
            "Global Site ID: {} | Initial Credential Parameters: {}".format(
                global_site_id, self.pprint(credential_params_template)
            ),
            "INFO",
        )
        final_response = []
        self.log(self.pprint(credential_params_template))
        self.log(
            "Fetching assigned device credentials for the global site (ID: {}).".format(
                global_site_id
            ),
            "INFO",
        )
        global_cred = copy.deepcopy(self.get_assigned_device_credential(global_site_id))
        self.log(
            "Global credentials retrieved: {}".format(self.pprint(global_cred)), "DEBUG"
        )
        credential_params = copy.deepcopy(
            credential_params_template
        )  # Reset for each iteration
        self.log(
            "Initialized credential parameters for processing: {}".format(
                self.pprint(credential_params)
            ),
            "DEBUG",
        )
        # List of credential types to handle
        credential_types = [
            "cliCredentialsId",
            "snmpv2cReadCredentialsId",
            "snmpv2cWriteCredentialsId",
            "httpReadCredentialsId",
            "httpWriteCredentialsId",
            "snmpv3CredentialsId",
        ]

        # Process each credential type
        for cred_type in credential_types:
            if credential_params.get(cred_type) is None:  # If not provided in the input
                self.log(
                    "Credential '{}' is not provided in the input. Checking global credentials...".format(
                        cred_type
                    ),
                    "DEBUG",
                )

                global_value = global_cred.get(
                    cred_type
                )  # Fetch from global credentials
                if global_value:
                    self.log(
                        "Found global value for '{}': {}".format(
                            cred_type, global_value
                        ),
                        "DEBUG",
                    )
                    credential_params[cred_type] = global_value
                else:
                    self.log(
                        "No global value found for '{}'. Setting it to an empty dictionary.".format(
                            cred_type
                        ),
                        "DEBUG",
                    )
                    credential_params[cred_type] = {}

        # Add site ID to parameters
        credential_params["id"] = global_site_id

        # Append final response for logging
        final_response.append(copy.deepcopy(credential_params))
        self.log(
            "Calling API to update device credentials for the global site (ID: {}).".format(
                global_site_id
            ),
            "INFO",
        )
        response = self.dnac._exec(
            family="network_settings",
            function="update_device_credential_settings_for_a_site",
            op_modifies=True,
            params=credential_params,
        )
        self.log(
            "Received API response for 'update_device_credential_settings_for_a_site': {}".format(
                response
            ),
            "DEBUG",
        )
        self.check_tasks_response_status(
            response, "update_device_credential_settings_for_a_site"
        ).check_return_status()
        self.log(
            "Desired State for assign credentials to a site: {}".format(
                self.pprint(final_response)
            ),
            "DEBUG",
        )
        result_assign_credential.update(
            {
                "Assign Credentials": {
                    "response": final_response,
                    "msg": "Device Credential Assigned to global site is Successfully",
                }
            }
        )
        self.msg = "Global Credential is assigned Successfully"
        self.status = "success"
        self.log(
            "Process to assign device credentials to the global site completed successfully.",
            "INFO",
        )
        return self

    def assign_credentials_to_site(self):
        """
        Assign Global Device Credential to the Cisco Catalyst
        Center based on the provided playbook details.
        Check the return value of the API with check_return_status().

        Parameters:
            self

        Returns:
            self
        """

        current_version = self.get_ccc_version()
        result_assign_credential = self.result.get("response")[0].get(
            "assign_credential"
        )
        credential_params_template = copy.deepcopy(
            self.want.get("assign_credentials")
        )  # Store original template
        final_response = []
        self.log(
            "Starting device credential assignment process. Initial input parameters: {0}".format(
                credential_params_template
            ),
            "INFO",
        )

        site_ids = self.want.get("site_id")
        if self.compare_dnac_versions(current_version, "2.3.7.6") >= 0:

            site_exists, global_site_id = self.get_site_id("Global")
            if global_site_id in site_ids:

                self.log(
                    "Global site detected in site IDs. Processing global credential assignment.",
                    "INFO",
                )
                assign_credentials_to_site = self.config[0][
                    "assign_credentials_to_site"
                ].copy()
                if "site_name" in assign_credentials_to_site:

                    site_names = assign_credentials_to_site.pop("site_name")
                    self.log(
                        "Removed 'site_name' from credential assignment configuration: {0}".format(
                            site_names
                        ),
                        "DEBUG",
                    )
                self.log(
                    "Global site credential parameters: {0}".format(
                        assign_credentials_to_site
                    ),
                    "DEBUG",
                )
                # Skip if credential_params is empty
                if not assign_credentials_to_site:
                    self.log(
                        "No credentials defined for global site. Skipping assignment.",
                        "INFO",
                    )
                    result_assign_credential.update(
                        {
                            "No Assign Credentials": {
                                "response": "No Response",
                                "msg": "No Assignment is available for Global site",
                            }
                        }
                    )
                    self.msg = "No Assignment is available for Global site"
                    self.status = "success"
                    return self

                site_ids.remove(global_site_id)
                self.assign_device_cred_to_global_site(
                    global_site_id, credential_params_template, result_assign_credential
                )

        # Skip if credential_params is empty
        if not credential_params_template:
            self.log(
                "No credentials defined in the template. Exiting assignment process.",
                "WARNING",
            )
            result_assign_credential.update(
                {
                    "No Assign Credentials": {
                        "response": "No Response",
                        "msg": "No Assignment is available",
                    }
                }
            )
            self.msg = "No Assignment is available"
            self.status = "success"
            return self

        for site_id in site_ids:
            self.log(
                "Processing credential assignment for site ID: {0}".format(site_id),
                "INFO",
            )
            if self.compare_dnac_versions(current_version, "2.3.5.3") <= 0:
                credential_params_template.update({"site_id": site_id})
                final_response.append(copy.deepcopy(credential_params_template))
                response = self.dnac._exec(
                    family="network_settings",
                    function="assign_device_credential_to_site",
                    op_modifies=True,
                    params=credential_params_template,
                )
                self.log(
                    "Received API response for 'assign_device_credential_to_site': {0}".format(
                        response
                    ),
                    "DEBUG",
                )
                validation_string = "desired common settings operation successful"
                self.check_task_response_status(
                    response, validation_string, "assign_device_credential_to_site"
                ).check_return_status()
            else:
                credential_params = copy.deepcopy(
                    credential_params_template
                )  # Reset for each iteration
                self.log(
                    "Credentials for site {}: {}".format(site_id, credential_params)
                )
                credential_params.update({"id": site_id})
                final_response.append(copy.deepcopy(credential_params))
                response = self.dnac._exec(
                    family="network_settings",
                    function="update_device_credential_settings_for_a_site",
                    op_modifies=True,
                    params=credential_params,
                )
                self.log(
                    "Received API response for 'update_device_credential_settings_for_a_site': {0}".format(
                        response
                    ),
                    "DEBUG",
                )
                self.check_tasks_response_status(
                    response, "update_device_credential_settings_for_a_site"
                ).check_return_status()
        if final_response:
            self.log(
                "Device credentials successfully assigned to sites: {0}".format(
                    site_ids
                ),
                "INFO",
            )
            self.log(
                "Final desired state for credentials: {0}".format(final_response),
                "DEBUG",
            )
            result_assign_credential.update(
                {
                    "Assign Credentials": {
                        "response": final_response,
                        "msg": "Device Credential Assigned to a site is Successfully",
                    }
                }
            )
        self.msg = "Global Credential is assigned Successfully"
        self.status = "success"
        return self

    def get_network_devices_credentials_sync_status(self, site_id):
        """
        Retrieve network devices credentials sync status from Cisco Catalyst Center.

        Parameters:
            self - The current object with updated Global Device Credential information.

        Returns:
            sync_status - Response for all network devices credential's sync status.
        """

        try:
            sync_status = self.dnac._exec(
                family="network_settings",
                function="get_network_devices_credentials_sync_status",
                params={"id": site_id},
            )
            sync_status = sync_status.get("response")
            self.log(
                "All global device credentials sync details: {0}".format(sync_status),
                "DEBUG",
            )
        except Exception as msg:
            self.msg = "Exception occurred while getting global device credentials sync status: {0}".format(
                msg
            )
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return self.check_return_status()

        return sync_status

    def get_assigned_device_credential(self, site_id):
        """
        Retrieve device credential configurations for a site from Cisco Catalyst Center.

        Parameters:
            self - The current object with updated Global Device Credential information.
            site_id (str): The ID of the site for which to retrieve device credential settings.

        Returns:
            site_credential_response - The device credential settings for the specified site,
            including both inherited credentials and the site's own customized credentials.
        """
        self.log(
            "Retrieving device credential settings for site ID: {0}".format(site_id),
            "DEBUG",
        )
        credential_settings = self.dnac._exec(
            family="network_settings",
            function="get_device_credential_settings_for_a_site",
            params={"_inherited": True, "id": site_id},
        )

        self.log("Received API response: {0}".format(credential_settings), "DEBUG")
        site_credential_response = credential_settings.get("response")
        self.log(
            "Device credential settings details: {0}".format(site_credential_response),
            "DEBUG",
        )

        return site_credential_response

    def get_devices_in_site(self, site_name, site_id):
        """
        Retrieve the list of device IDs assigned to a site in Cisco Catalyst Center.

        This method fetches all sites matching the provided `site_name` pattern and
        retrieves the device IDs assigned to each of these sites.

        Parameters:
            site_name (str): The name or pattern of the site(s) to search for.
            site_id (str): The ID of the site (though this parameter is not directly used in the function).

        Returns:
            list: A list of device IDs (str) assigned to the matched sites.
        """
        device_id_list = []
        site_names = site_name + ".*"
        self.log(
            "Fetching sites with the name pattern: {0}".format(site_names), "DEBUG"
        )
        get_site_names = self.get_site(site_names)
        self.log("Fetched site names: {0}".format(str(get_site_names)), "DEBUG")
        site_info = {}

        for item in get_site_names["response"]:
            if "nameHierarchy" in item and "id" in item:
                site_info[item["nameHierarchy"]] = item["id"]
                self.log("Site info mapping: {0}".format(site_info), "DEBUG")

        for site_name, site_id in site_info.items():
            try:
                self.log(
                    "Fetching devices for site ID: {0} (Site: {1})".format(
                        site_id, site_name
                    ),
                    "DEBUG",
                )
                response = self.dnac._exec(
                    family="site_design",
                    function="get_site_assigned_network_devices",
                    params={"site_id": site_id},
                )
                self.log(
                    "Received API response from 'get_site_assigned_network_devices': {0}".format(
                        str(response)
                    ),
                    "DEBUG",
                )
                devices = response.get("response")
                if not devices:
                    self.log(
                        "No devices found for site - '{0}'.".format(site_name),
                        "WARNING",
                    )
                    continue

                for device in devices:
                    device_id = device.get("deviceId")
                    if device_id:
                        device_id_list.append(device_id)
                        self.log(
                            "Added device ID {0} for site '{1}'".format(
                                device_id, site_name
                            ),
                            "DEBUG",
                        )

            except Exception as e:
                self.log(
                    "Unable to fetch the device(s) associated to the site '{0}' due to '{1}'".format(
                        site_name, str(e)
                    ),
                    "WARNING",
                )

        return device_id_list

    def apply_credentials_to_site(self):
        """
        Apply Global Device Credential to the Cisco Catalyst
        Center based on the provided playbook details.
        Check the return value of the API with check_return_status().

        Parameters:
            self - The current object with updated Global Device Credential information.

        Returns:
            self - The current object with updated Global Device Credential information.

        """
        site_ids = self.want.get("site_id")
        site_names = self.want.get("site_name")

        for site_id, site_name in zip(site_ids, site_names):
            if (
                self.get_ccc_version_as_integer()
                >= self.get_ccc_version_as_int_from_str("2.3.7.6")
            ):
                result_apply_credential = self.result.get("response")[0].get(
                    "apply_credential"
                )
                credential_params = self.want.get("apply_credentials")
                final_response = []
                self.log(
                    "Applying device credential to site API input parameters: {0}".format(
                        credential_params
                    ),
                    "DEBUG",
                )

                if not credential_params:
                    result_apply_credential.update(
                        {
                            "No Apply Credentials": {
                                "response": "No Response",
                                "msg": "No device credential id is available",
                            }
                        }
                    )
                    self.msg = "No device credential id is available"
                    self.status = "success"
                    return self

                device_id_list = self.get_devices_in_site(site_name, site_id)
                if not device_id_list:
                    result_apply_credential.update(
                        {
                            "No Apply Credentials": {
                                "response": "No Response",
                                "msg": "No device available in the site",
                            }
                        }
                    )
                    self.msg = "No device available in the site: '{0}' with site id {1}".format(
                        site_name, site_id
                    )
                    self.log(self.msg, "WARNING")
                    self.status = "exited"
                    return self

                cred_sync_status = self.get_network_devices_credentials_sync_status(
                    site_id
                )
                credential_mapping = {
                    "cli": "cliId",
                    "snmpV2Read": "snmpV2ReadId",
                    "snmpV2Write": "snmpV2WriteId",
                    "snmpV3": "snmpV3Id",
                }

                not_synced_ids, assigned_site_ids = [], []

                for status_key, param_key in credential_mapping.items():
                    if param_key in credential_params:
                        status_list = cred_sync_status.get(status_key, [])
                        for status in status_list:
                            if status.get("status") != "Synced":
                                if (
                                    credential_params.get(param_key)
                                    and credential_params.get(param_key)
                                    not in not_synced_ids
                                ):
                                    not_synced_ids.append(credential_params[param_key])

                assigned_device_credential = self.get_assigned_device_credential(
                    site_id
                )

                for value in assigned_device_credential.values():
                    if isinstance(value, dict) and "credentialsId" in value:
                        assigned_site_ids.append(value.get("credentialsId"))

                valid_sync_cred_ids, invalid_sync_cred_ids = [], []

                for id in not_synced_ids:
                    if id in assigned_site_ids:
                        valid_sync_cred_ids.append(id)
                    else:
                        invalid_sync_cred_ids.append(id)
                self.log(
                    "Credential IDs {0} not assigned to site, so Sync not possible.".format(
                        invalid_sync_cred_ids
                    ),
                    "INFO",
                )

                if not valid_sync_cred_ids:
                    result_apply_credential.update(
                        {
                            "Applied Credentials": {
                                "response": final_response,
                                "msg": "Either the provided credentials are already synchronized or they are not assigned to the device.",
                            }
                        }
                    )
                    self.msg = "Provided credentials category is/are already synced: {0}".format(
                        credential_params
                    )
                    self.log(self.msg, "WARNING")
                    self.status = "skipped"
                    return self

                for credential_id in valid_sync_cred_ids:
                    param = {"deviceCredentialId": credential_id, "siteId": site_id}
                    self.log(
                        "Credential {0} to be synced with {1} site id.".format(
                            credential_id, site_id
                        ),
                        "INFO",
                    )
                    final_response.append(copy.deepcopy(param))
                    response = self.dnac._exec(
                        family="network_settings",
                        function="sync_network_devices_credential",
                        op_modifies=True,
                        params=param,
                    )
                    self.log(
                        "Received API response for 'sync_network_devices_credential': {0}".format(
                            response
                        ),
                        "DEBUG",
                    )
                    self.check_tasks_response_status(
                        response, "sync_network_devices_credential"
                    ).check_return_status()

                    self.log(
                        "Device credential applied to site {0} successfully.".format(
                            site_id
                        ),
                        "INFO",
                    )
                    self.log(
                        "Desired State for applying credentials to a site: {0}".format(
                            final_response
                        ),
                        "DEBUG",
                    )
                    result_apply_credential.update(
                        {
                            "Applied Credentials": {
                                "response": final_response,
                                "msg": "Successfully applied credential.",
                            }
                        }
                    )
                self.msg = "Global Credential is applied Successfully"
                self.status = "success"
            else:
                self.msg = (
                    "Cisco Catalyst Center version '{0}' doesn't support apply credentials to site feature.".format(
                        self.payload.get("dnac_version")
                    ),
                    "ERROR",
                )
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

        return self

    def get_diff_merged(self, config):
        """
        Update or Create Global Device Credential and assign device
        credential to a site in Cisco Catalyst Center based on the playbook provided.

        Parameters:
            config (list of dict) - Playbook details containing Global
            Device Credential and assign credentials to a site information.

        Returns:
            self
        """

        if config.get("global_credential_details") is not None:
            self.create_device_credentials().check_return_status()

        if config.get("global_credential_details") is not None:
            self.update_device_credentials().check_return_status()

        if config.get("assign_credentials_to_site") is not None:
            self.assign_credentials_to_site().check_return_status()

        if config.get("apply_credentials_to_site") is not None:
            self.apply_credentials_to_site().check_return_status()

        return self

    def delete_device_credential(self, config):
        """
        Delete Global Device Credential in Cisco Catalyst Center based on the playbook details.
        Check the return value of the API with check_return_status().

        Parameters:
            config (dict) - Playbook details containing Global Device Credential information.
            self - The current object details.

        Returns:
            self
        """

        result_global_credential = self.result.get("response")[0].get(
            "global_credential"
        )
        have_values = self.have.get("global_credential")
        final_response = {}
        self.log(
            "Global device credentials to be deleted: {0}".format(have_values), "DEBUG"
        )
        credential_mapping = {
            "cliCredential": "cli_credential",
            "snmpV2cRead": "snmp_v2c_read",
            "snmpV2cWrite": "snmp_v2c_write",
            "snmpV3": "snmp_v3",
            "httpsRead": "https_read",
            "httpsWrite": "https_write",
        }
        failed_status = False
        changed_status = False
        for item in have_values:
            config_itr = -1
            final_response.update({item: []})
            for value in have_values.get(item):
                config_itr = config_itr + 1
                description = (
                    config.get("global_credential_details")
                    .get(credential_mapping.get(item))[config_itr]
                    .get("description")
                )

                if value is None:
                    self.log("Credential Name: {0}".format(item), "DEBUG")
                    self.log(
                        "Credential Item: {0}".format(
                            config.get("global_credential_details").get(
                                credential_mapping.get(item)
                            )
                        ),
                        "DEBUG",
                    )
                    final_response.get(item).append(
                        {
                            "description": description,
                            "response": "Global credential not found",
                        }
                    )
                    continue

                _id = have_values.get(item)[config_itr].get("id")
                changed_status = True
                response = self.dnac._exec(
                    family="discovery",
                    function="delete_global_credential",
                    op_modifies=True,
                    params={"id": _id},
                )
                self.log(
                    "Received API response for 'delete_global_credential': {0}".format(
                        response
                    ),
                    "DEBUG",
                )
                validation_string = "global credential deleted successfully"
                response = response.get("response")

                if response.get("errorcode") is not None:
                    self.msg = response.get("response").get("detail")
                    self.status = "failed"
                    return self

                task_id = response.get("taskId")
                while True:
                    task_details = self.get_task_details(task_id)
                    self.log(
                        "Getting task details from task ID {0}: {1}".format(
                            task_id, task_details
                        ),
                        "DEBUG",
                    )

                    if task_details.get("isError") is True:
                        if task_details.get("failureReason"):
                            failure_msg = str(task_details.get("failureReason"))
                        else:
                            failure_msg = str(task_details.get("progress"))
                        self.status = "failed"
                        break

                    if validation_string in task_details.get("progress").lower():
                        self.status = "success"
                        break

                    self.log(
                        "progress set to {0} for taskid: {1}".format(
                            task_details.get("progress"), task_id
                        ),
                        "DEBUG",
                    )

                if self.status == "failed":
                    failed_status = True
                    final_response.get(item).append(
                        {"description": description, "failure_response": failure_msg}
                    )
                else:
                    final_response.get(item).append(
                        {
                            "description": description,
                            "response": "Global credential deleted successfully",
                        }
                    )

        self.log(
            "Deleting device credential API input parameters: {0}".format(
                final_response
            ),
            "DEBUG",
        )
        result_global_credential.update(
            {
                "Deletion": {
                    "response": final_response,
                }
            }
        )

        if failed_status is True:
            self.msg = "Global device credentials are not deleted."
            self.module.fail_json(msg=self.msg, response=final_response)
        else:
            self.result["changed"] = changed_status
            self.msg = "Global Device Credentials Deleted Successfully"
            result_global_credential.get("Deletion").update({"msg": self.msg})
            self.log(str(self.msg), "INFO")
            self.status = "success"

        return self

    def get_diff_deleted(self, config):
        """
        Delete Global Device Credential in Cisco Catalyst Center based on the playbook details.

        Parameters:
            config (dict) - Playbook details containing Global Device Credential information.
            self - The current object details.

        Returns:
            self
        """

        if config.get("global_credential_details") is not None:
            self.delete_device_credential(config).check_return_status()

        return self

    def verify_diff_merged(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self
        """

        self.get_have(config)
        self.get_want(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Desired State (want): {0}".format(self.want), "INFO")

        if config.get("global_credential_details") is not None:
            if self.want.get("want_create"):
                self.msg = "Global Device Credentials config is not applied to the Cisco Catalyst Center"
                self.status = "failed"
                return self

            if self.want.get("want_update"):
                credential_types = [
                    "cliCredential",
                    "snmpV2cRead",
                    "snmpV2cWrite",
                    "httpsRead",
                    "httpsWrite",
                    "snmpV3",
                ]
                value_mapping = {
                    "cliCredential": ["username", "description", "id"],
                    "snmpV2cRead": ["description", "id"],
                    "snmpV2cWrite": ["description", "id"],
                    "httpsRead": ["description", "username", "port", "id"],
                    "httpsWrite": ["description", "username", "port", "id"],
                    "snmpV3": ["username", "description", "snmpMode", "id"],
                }

                for credential_type in credential_types:
                    if self.want.get(credential_type):
                        want_credential = self.want.get(credential_type)
                        if self.have.get(credential_type):
                            have_credential = self.have.get(credential_type)
                        values = value_mapping.get(credential_type)
                        for value in values:
                            equality = have_credential.get(
                                value
                            ) is want_credential.get(value)
                            if not have_credential or not equality:
                                self.msg = "{0} config is not applied ot the Cisco Catalyst Center".format(
                                    credential_type
                                )
                                self.status = "failed"
                                return self

            self.log("Successfully validated global device credential", "INFO")
            self.result.get("response")[0].get("global_credential").update(
                {"Validation": "Success"}
            )

        if config.get("assign_credentials_to_site") is not None:
            self.log(
                "Successfully validated the assign device credential to site", "INFO"
            )
            self.result.get("response")[0].get("assign_credential").update(
                {"Validation": "Success"}
            )

        if config.get("apply_credentials_to_site") is not None:
            self.log(
                "Successfully validated the assign device credential to site", "INFO"
            )
            self.result.get("response")[0].get("apply_credential").update(
                {"Validation": "Success"}
            )

        self.msg = "Successfully validated the global device credential, assigned and applied device credential to site."
        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is deleted (delete).

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Desired State (want): {0}".format(self.want), "INFO")

        if config.get("global_credential_details") is not None:
            have_global_credential = self.have.get("global_credential")
            credential_types = [
                "cliCredential",
                "snmpV2cRead",
                "snmpV2cWrite",
                "httpsRead",
                "httpsWrite",
                "snmpV3",
            ]
            for credential_type in credential_types:
                have_global_credential_type = have_global_credential.get(
                    credential_type
                )
                if have_global_credential_type is not None:
                    for item in have_global_credential_type:
                        if item is not None:
                            self.msg = (
                                "The configuration for deleting the global device credentials "
                                + "is not being applied to the current configuration"
                            )
                            self.status = "failed"
                            return self

            self.log(
                "Successfully validated absence of global device credential.", "INFO"
            )
            self.result.get("response")[0].get("global_credential").update(
                {"Validation": "Success"}
            )

        self.msg = "Successfully validated the absence of Global Device Credential."
        self.status = "success"
        return self

    def reset_values(self):
        """
        Reset all neccessary attributes to default values

        Parameters:
            self

        Returns:
            self
        """

        self.have.clear()
        self.want.clear()
        return self


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
    ccc_credential = DeviceCredential(module)
    state = ccc_credential.params.get("state")
    MIN_SUPPORTED_VERSION = "2.3.5.3"
    current_version = ccc_credential.get_ccc_version()

    if ccc_credential.compare_dnac_versions(current_version, MIN_SUPPORTED_VERSION) < 0:
        ccc_credential.msg = """The specified version '{0}' does not support the device_credential_workflow features.
        Supported versions start from '2.3.5.3' onwards. """.format(
            ccc_credential.get_ccc_version()
        )
        ccc_credential.status = "failed"
        ccc_credential.check_return_status()

    config_verify = ccc_credential.params.get("config_verify")
    if state not in ccc_credential.supported_states:
        ccc_credential.status = "invalid"
        ccc_credential.msg = "State {0} is invalid".format(state)
        ccc_credential.check_return_status()

    ccc_credential.validate_input().check_return_status()

    for config in ccc_credential.config:
        ccc_credential.reset_values()
        ccc_credential.get_have(config).check_return_status()
        if state != "deleted":
            ccc_credential.get_want(config).check_return_status()
        ccc_credential.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_credential.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_credential.result)


if __name__ == "__main__":
    main()
