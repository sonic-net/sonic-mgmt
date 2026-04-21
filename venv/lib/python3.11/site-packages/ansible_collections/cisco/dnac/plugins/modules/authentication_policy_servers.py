#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: authentication_policy_servers
short_description: Resource module for Authentication
  Policy Servers
description:
  - Manage operations create, update and delete of the
    resource Authentication Policy Servers. - > API
    to add AAA/ISE server access configuration. Protocol
    can be configured as either RADIUS OR TACACS OR
    RADIUS_TACACS. If configuring Cisco ISE server,
    after configuration, use "Cisco ISE Server Integration
    Status" Intent API to check the integration status.
    Based on integration status, if require use 'Accept
    Cisco ISE Server Certificate for Cisco ISE Server
    Integration' Intent API to accept the Cisco ISE
    certificate for Cisco ISE server integration, then
    use again "Cisco ISE Server Integration Status"
    Intent API to check the integration status.
  - API to delete AAA/ISE server access configuration.
    - > API to edit AAA/ISE server access configuration.
    After edit, use "Cisco ISE Server Integration Status"
    Intent API to check the integration status.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  accountingPort:
    description: Accounting port of RADIUS server. It
      is required for RADIUS server. The range is from
      1 to 65535. E.g. 1813.
    type: int
  authenticationPort:
    description: Authentication port of RADIUS server.
      It is required for RADIUS server. The range is
      from 1 to 65535. E.g. 1812.
    type: int
  ciscoIseDtos:
    description: Authentication Policy Servers's ciscoIseDtos.
    elements: dict
    suboptions:
      description:
        description: Description about the Cisco ISE
          server.
        type: str
      fqdn:
        description: Fully-qualified domain name of
          the Cisco ISE server. E.g. Xi-62.my.com.
        type: str
      ipAddress:
        description: IP Address of the Cisco ISE Server.
        type: str
      password:
        description: Password of the Cisco ISE server.
        type: str
      sshkey:
        description: SSH key of the Cisco ISE server.
        type: str
      subscriberName:
        description: Subscriber name of the Cisco ISE
          server. E.g. Pxgrid_client_1662589467.
        type: str
      userName:
        description: User name of the Cisco ISE server.
        type: str
    type: list
  encryptionKey:
    description: Encryption key used to encrypt shared
      secret.
    type: str
  encryptionScheme:
    description: Type of encryption scheme for additional
      security.
    type: str
  externalCiscoIseIpAddrDtos:
    description: Authentication Policy Servers's externalCiscoIseIpAddrDtos.
    elements: dict
    suboptions:
      externalCiscoIseIpAddresses:
        description: Authentication Policy Servers's
          externalCiscoIseIpAddresses.
        elements: dict
        suboptions:
          externalIpAddress:
            description: External IP Address.
            type: str
        type: list
      type:
        description: Type.
        type: str
    type: list
  id:
    description: Id path parameter. Authentication and
      Policy Server Identifier. Use 'Get Authentication
      and Policy Servers' intent API to find the identifier.
    type: str
  ipAddress:
    description: IP address of authentication and policy
      server.
    type: str
  isIseEnabled:
    description: Value true for Cisco ISE Server. Default
      value is false.
    type: bool
  messageKey:
    description: Message key used to encrypt shared
      secret.
    type: str
  port:
    description: Port of TACACS server. It is required
      for TACACS server. The range is from 1 to 65535.
    type: int
  protocol:
    description: Type of protocol for authentication
      and policy server. If already saved with RADIUS,
      can update to RADIUS_TACACS. If already saved
      with TACACS, can update to RADIUS_TACACS.
    type: str
  pxgridEnabled:
    description: Value true for enable, false for disable.
      Default value is true.
    type: bool
  retries:
    description: Number of communication retries between
      devices and authentication and policy server.
      The range is from 1 to 3.
    type: str
  role:
    description: Role of authentication and policy server.
      E.g. Primary, secondary.
    type: str
  sharedSecret:
    description: Shared secret between devices and authentication
      and policy server.
    type: str
  timeoutSeconds:
    description: Number of seconds before timing out
      between devices and authentication and policy
      server. The range is from 2 to 20.
    type: str
  useDnacCertForPxgrid:
    description: Value true to use Catalyst Center certificate
      for Pxgrid. Default value is false.
    type: bool
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for System
      Settings AddAuthenticationAndPolicyServerAccessConfiguration
    description: Complete reference of the AddAuthenticationAndPolicyServerAccessConfiguration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-authentication-and-policy-server-access-configuration
  - name: Cisco DNA Center documentation for System
      Settings DeleteAuthenticationAndPolicyServerAccessConfiguration
    description: Complete reference of the DeleteAuthenticationAndPolicyServerAccessConfiguration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-authentication-and-policy-server-access-configuration
  - name: Cisco DNA Center documentation for System
      Settings EditAuthenticationAndPolicyServerAccessConfiguration
    description: Complete reference of the EditAuthenticationAndPolicyServerAccessConfiguration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!edit-authentication-and-policy-server-access-configuration
notes:
  - SDK Method used are
    system_settings.SystemSettings.add_authentication_and_policy_server_access_configuration,
    system_settings.SystemSettings.delete_authentication_and_policy_server_access_configuration,
    system_settings.SystemSettings.edit_authentication_and_policy_server_access_configuration,
  - Paths used are
    post /dna/intent/api/v1/authentication-policy-servers,
    delete /dna/intent/api/v1/authentication-policy-servers/{id},
    put /dna/intent/api/v1/authentication-policy-servers/{id},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.authentication_policy_servers:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    accountingPort: 0
    authenticationPort: 0
    ciscoIseDtos:
      - description: string
        fqdn: string
        ipAddress: string
        password: string
        sshkey: string
        subscriberName: string
        userName: string
    encryptionKey: string
    encryptionScheme: string
    externalCiscoIseIpAddrDtos:
      - externalCiscoIseIpAddresses:
          - externalIpAddress: string
        type: string
    ipAddress: string
    isIseEnabled: true
    messageKey: string
    port: 0
    protocol: string
    pxgridEnabled: true
    retries: string
    role: string
    sharedSecret: string
    timeoutSeconds: string
    useDnacCertForPxgrid: true
- name: Delete by id
  cisco.dnac.authentication_policy_servers:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
- name: Update by id
  cisco.dnac.authentication_policy_servers:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    accountingPort: 0
    authenticationPort: 0
    ciscoIseDtos:
      - fqdn: string
        password: string
        sshkey: string
        userName: string
    externalCiscoIseIpAddrDtos:
      - externalCiscoIseIpAddresses:
          - externalIpAddress: string
        type: string
    id: string
    port: 0
    protocol: string
    pxgridEnabled: true
    retries: string
    timeoutSeconds: string
    useDnacCertForPxgrid: true
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
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
