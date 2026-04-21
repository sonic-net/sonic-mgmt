#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_create
short_description: Resource module for Network Create
description:
  - Manage operation create of the resource Network
    Create. - > API to create a network for DHCP, Syslog,
    SNMP, NTP, Network AAA, Client and EndPoint AAA,
    and/or DNS center server settings.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  settings:
    description: Network Create's settings.
    suboptions:
      clientAndEndpoint_aaa:
        description: Network Create's clientAndEndpoint_aaa.
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
        description: Network Create's dnsServer.
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
        description: Network Create's messageOfTheday.
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
        description: Network Create's netflowcollector.
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
        description: Network Create's network_aaa.
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
        description: Network Create's snmpServer.
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
        description: Network Create's syslogServer.
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
    description: SiteId path parameter. Site id to which
      site details to associate with the network settings.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings CreateNetwork
    description: Complete reference of the CreateNetwork
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-network
notes:
  - SDK Method used are
    network_settings.NetworkSettings.create_network,
  - Paths used are
    post /dna/intent/api/v1/network/{siteId},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: '{{my_headers | from_json}}'
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
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
