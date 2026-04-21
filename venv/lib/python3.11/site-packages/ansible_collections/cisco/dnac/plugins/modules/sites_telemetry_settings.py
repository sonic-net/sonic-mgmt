#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_telemetry_settings
short_description: Resource module for Sites Telemetry
  Settings
description:
  - Manage operation update of the resource Sites Telemetry
    Settings. - > Sets telemetry settings for the given
    site; `null` values indicate that the setting will
    be inherited from the parent site.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  applicationVisibility:
    description: Sites Telemetry Settings's applicationVisibility.
    suboptions:
      collector:
        description: Sites Telemetry Settings's collector.
        suboptions:
          address:
            description: IP Address. If collection type
              is 'TelemetryBrokerOrUDPDirector', this
              field value is mandatory otherwise it
              is optional. Examples "250.162.252.170",
              "2001 db8 3c4d 15 1a2f 1a2b".
            type: str
          collectorType:
            description: Collector Type.
            type: str
          port:
            description: Min 1; Max 65535. If collection
              type is 'TelemetryBrokerOrUDPDirector',
              this field value is mandatory otherwise
              it is optional.
            type: int
        type: dict
      enableOnWiredAccessDevices:
        description: Enable Netflow Application Telemetry
          and Controller Based Application Recognition
          (CBAR) by default upon network device site
          assignment for wired access devices.
        type: bool
    type: dict
  id:
    description: Id path parameter. Site Id, retrievable
      from the `id` attribute in `/dna/intent/api/v1/sites`.
    type: str
  snmpTraps:
    description: Sites Telemetry Settings's snmpTraps.
    suboptions:
      externalTrapServers:
        description: External SNMP trap servers. Example
          "250.162.252.170","2001 db8 3c4d 15 1a2f 1a2b".
        elements: str
        type: list
      useBuiltinTrapServer:
        description: Enable this server as a destination
          server for SNMP traps and messages from your
          network.
        type: bool
    type: dict
  syslogs:
    description: Sites Telemetry Settings's syslogs.
    suboptions:
      externalSyslogServers:
        description: External syslog servers. Example
          "250.162.252.170", "2001 db8 3c4d 15 1a2f
          1a2b".
        elements: str
        type: list
      useBuiltinSyslogServer:
        description: Enable this server as a destination
          server for syslog messages.
        type: bool
    type: dict
  wiredDataCollection:
    description: Sites Telemetry Settings's wiredDataCollection.
    suboptions:
      enableWiredDataCollection:
        description: Track the presence, location, and
          movement of wired endpoints in the network.
          Traffic received from endpoints is used to
          extract and store their identity information
          (MAC address and IP address). Other features,
          such as IEEE 802.1X, web authentication, Cisco
          Security Groups (formerly TrustSec), SD-Access,
          and Assurance, depend on this identity information
          to operate properly. Wired Endpoint Data Collection
          enables Device Tracking policies on devices
          assigned to the Access role in Inventory.
        type: bool
    type: dict
  wirelessTelemetry:
    description: Sites Telemetry Settings's wirelessTelemetry.
    suboptions:
      enableWirelessTelemetry:
        description: Enables Streaming Telemetry on
          your wireless controllers in order to determine
          the health of your wireless controller, access
          points and wireless clients.
        type: bool
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings SetTelemetrySettingsForASite
    description: Complete reference of the SetTelemetrySettingsForASite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!set-telemetry-settings-for-a-site
notes:
  - SDK Method used are
    network_settings.NetworkSettings.set_telemetry_settings_for_a_site,
  - Paths used are
    put /dna/intent/api/v1/sites/{id}/telemetrySettings,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sites_telemetry_settings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    applicationVisibility:
      collector:
        address: string
        collectorType: string
        port: 0
      enableOnWiredAccessDevices: true
    id: string
    snmpTraps:
      externalTrapServers:
        - string
      useBuiltinTrapServer: true
    syslogs:
      externalSyslogServers:
        - string
      useBuiltinSyslogServer: true
    wiredDataCollection:
      enableWiredDataCollection: true
    wirelessTelemetry:
      enableWirelessTelemetry: true
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "url": "string",
        "taskId": "string"
      }
    }
"""
