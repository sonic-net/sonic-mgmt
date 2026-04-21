#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_update
short_description: Resource module for Network Update
description:
  - Manage operation update of the resource Network
    Update. - > API to update network settings for DHCP,
    Syslog, SNMP, NTP, Network AAA, Client and EndPoint
    AAA, and/or DNS server settings.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  settings:
    description: Network Update's settings.
    suboptions:
      clientAndEndpoint_aaa:
        description: Network Update's clientAndEndpoint_aaa.
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
        description: Network Update's dnsServer.
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
        description: Network Update's messageOfTheday.
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
        description: Network Update's netflowcollector.
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
        description: Network Update's network_aaa.
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
        description: Network Update's snmpServer.
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
        description: Network Update's syslogServer.
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
    description: SiteId path parameter. Site id to update
      the network settings which is associated with
      the site.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings UpdateNetwork
    description: Complete reference of the UpdateNetwork
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-network
notes:
  - SDK Method used are
    network_settings.NetworkSettings.update_network,
  - Paths used are
    put /dna/intent/api/v1/network/{siteId},
"""

EXAMPLES = r"""
---
- name: Update by id
  cisco.dnac.network_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
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
