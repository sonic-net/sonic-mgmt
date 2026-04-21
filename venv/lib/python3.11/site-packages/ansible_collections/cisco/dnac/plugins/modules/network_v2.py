#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_v2
short_description: Resource module for Network V2
description:
  - Manage operations create and update of the resource
    Network V2. - > API to create network settings for
    DHCP, Syslog, SNMP, NTP, Network AAA, Client and
    Endpoint AAA, and/or DNS center server settings.
    - > API to update network settings for DHCP, Syslog,
    SNMP, NTP, Network AAA, Client and Endpoint AAA,
    and/or DNS center server settings.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  settings:
    description: Network V2's settings.
    suboptions:
      clientAndEndpoint_aaa:
        description: Network V2's clientAndEndpoint_aaa.
        suboptions:
          ipAddress:
            description: IP address for ISE serve (eg
              1.1.1.4).
            type: str
          network:
            description: IP address for AAA or ISE server
              (eg 2.2.2.1).
            type: str
          protocol:
            description: Protocol for AAA or ISE serve
              (eg RADIUS).
            type: str
          servers:
            description: Server type AAA or ISE server
              (eg AAA).
            type: str
          sharedSecret:
            description: Shared secret for ISE server.
            type: str
        type: dict
      dhcpServer:
        description: DHCP Server IP (eg 1.1.1.1).
        elements: str
        type: list
      dnsServer:
        description: Network V2's dnsServer.
        suboptions:
          domainName:
            description: Domain Name of DHCP (eg; cisco).
            type: str
          primaryIpAddress:
            description: Primary IP Address for DHCP
              (eg 2.2.2.2).
            type: str
          secondaryIpAddress:
            description: Secondary IP Address for DHCP
              (eg 3.3.3.3).
            type: str
        type: dict
      messageOfTheday:
        description: Network V2's messageOfTheday.
        suboptions:
          bannerMessage:
            description: Massage for Banner message
              (eg; Good day).
            type: str
          retainExistingBanner:
            description: Retain existing Banner Message
              (eg "true" or "false").
            type: str
        type: dict
      netflowcollector:
        description: Network V2's netflowcollector.
        suboptions:
          ipAddress:
            description: IP Address for NetFlow collector
              (eg 3.3.3.1).
            type: str
          port:
            description: Port for NetFlow Collector
              (eg; 443).
            type: float
        type: dict
      network_aaa:
        description: Network V2's network_aaa.
        suboptions:
          ipAddress:
            description: IP address for AAA and ISE
              server (eg 1.1.1.1).
            type: str
          network:
            description: IP Address for AAA or ISE server
              (eg 2.2.2.2).
            type: str
          protocol:
            description: Protocol for AAA or ISE serve
              (eg RADIUS).
            type: str
          servers:
            description: Server type for AAA Network
              (eg AAA).
            type: str
          sharedSecret:
            description: Shared secret for ISE Server.
            type: str
        type: dict
      ntpServer:
        description: IP address for NTP server (eg 1.1.1.2).
        elements: str
        type: list
      snmpServer:
        description: Network V2's snmpServer.
        suboptions:
          configureDnacIP:
            description: Configuration DNAC IP for SNMP
              Server (eg true).
            type: bool
          ipAddresses:
            description: IP Address for SNMP Server
              (eg 4.4.4.1).
            elements: str
            type: list
        type: dict
      syslogServer:
        description: Network V2's syslogServer.
        suboptions:
          configureDnacIP:
            description: Configuration DNAC IP for syslog
              server (eg true).
            type: bool
          ipAddresses:
            description: IP Address for syslog server
              (eg 4.4.4.4).
            elements: str
            type: list
        type: dict
      timezone:
        description: Input for time zone (eg Africa/Abidjan).
        type: str
    type: dict
  siteId:
    description: SiteId path parameter. Site Id to which
      site details to associate with the network settings.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings CreateNetworkV2
    description: Complete reference of the CreateNetworkV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-network-v-2
  - name: Cisco DNA Center documentation for Network
      Settings UpdateNetworkV2
    description: Complete reference of the UpdateNetworkV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-network-v-2
notes:
  - SDK Method used are
    network_settings.NetworkSettings.create_network_v2,
    network_settings.NetworkSettings.update_network_v2,
  - Paths used are
    post /dna/intent/api/v2/network/{siteId},
    put /dna/intent/api/v2/network/{siteId},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    settings:
      clientAndEndpoint_aaa:
        ipAddress: string
        network: string
        protocol: string
        servers: string
        sharedSecret: string
      dhcpServer:
        - string
      dnsServer:
        domainName: string
        primaryIpAddress: string
        secondaryIpAddress: string
      messageOfTheday:
        bannerMessage: string
        retainExistingBanner: string
      netflowcollector:
        ipAddress: string
        port: 0
      network_aaa:
        ipAddress: string
        network: string
        protocol: string
        servers: string
        sharedSecret: string
      ntpServer:
        - string
      snmpServer:
        configureDnacIP: true
        ipAddresses:
          - string
      syslogServer:
        configureDnacIP: true
        ipAddresses:
          - string
      timezone: string
    siteId: string
- name: Update by id
  cisco.dnac.network_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    settings:
      clientAndEndpoint_aaa:
        ipAddress: string
        network: string
        protocol: string
        servers: string
        sharedSecret: string
      dhcpServer:
        - string
      dnsServer:
        domainName: string
        primaryIpAddress: string
        secondaryIpAddress: string
      messageOfTheday:
        bannerMessage: string
        retainExistingBanner: string
      netflowcollector:
        ipAddress: string
        port: 0
      network_aaa:
        ipAddress: string
        network: string
        protocol: string
        servers: string
        sharedSecret: string
      ntpServer:
        - string
      snmpServer:
        configureDnacIP: true
        ipAddresses:
          - string
      syslogServer:
        configureDnacIP: true
        ipAddresses:
          - string
      timezone: string
    siteId: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "taskId": "string",
      "url": "string"
    }
"""
